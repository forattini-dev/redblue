//! TCP Relay Implementation
//!
//! Provides bidirectional data relay for TCP connections using non-blocking I/O.
//!
//! # Design
//!
//! Uses `select()`-style multiplexing to efficiently relay data between two streams
//! without spawning additional threads per connection.
//!
//! ```text
//! Client Stream ─────► Buffer A ─────► Server Stream
//!                        8KB
//!
//! Server Stream ─────► Buffer B ─────► Client Stream
//!                        8KB
//! ```

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::modules::proxy::FlowStats;
use crate::debug;

/// Default buffer size for relay (8KB)
const BUFFER_SIZE: usize = 8192;

/// Relay timeout for select-style polling
const POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum idle time before closing connection
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Bidirectional TCP relay between two streams
///
/// Relays data between `client` and `server` streams until one side closes
/// or an error occurs. Returns the total bytes transferred in each direction.
///
/// # Arguments
///
/// * `client` - Client-side TCP stream
/// * `server` - Server-side TCP stream
/// * `flow_stats` - Optional flow statistics tracker
///
/// # Returns
///
/// Tuple of (bytes_client_to_server, bytes_server_to_client)
pub fn relay_bidirectional(
    client: &mut TcpStream,
    server: &mut TcpStream,
    flow_stats: &Arc<FlowStats>,
) -> io::Result<(u64, u64)> {
    // Set non-blocking mode for both streams
    client.set_nonblocking(true)?;
    server.set_nonblocking(true)?;

    // Set read timeouts for idle detection
    client.set_read_timeout(Some(POLL_TIMEOUT))?;
    server.set_read_timeout(Some(POLL_TIMEOUT))?;

    let mut buf_c2s = [0u8; BUFFER_SIZE];
    let mut buf_s2c = [0u8; BUFFER_SIZE];

    let mut bytes_c2s: u64 = 0;
    let mut bytes_s2c: u64 = 0;

    let mut client_closed = false;
    let mut server_closed = false;

    let mut idle_count = 0u32;
    let max_idle_iterations = (IDLE_TIMEOUT.as_millis() / POLL_TIMEOUT.as_millis()) as u32;

    loop {
        let mut activity = false;

        // Read from client, write to server
        if !client_closed {
            match client.read(&mut buf_c2s) {
                Ok(0) => {
                    client_closed = true;
                    // Shutdown server write side
                    let _ = server.shutdown(std::net::Shutdown::Write);
                }
                Ok(n) => {
                    activity = true;
                    if let Err(e) = server.write_all(&buf_c2s[..n]) {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            server_closed = true;
                        }
                    } else {
                        bytes_c2s += n as u64;
                        flow_stats.add_sent(n as u64);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data available, continue
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    // Timeout, continue
                }
                Err(_) => {
                    client_closed = true;
                }
            }
        }

        // Read from server, write to client
        if !server_closed {
            match server.read(&mut buf_s2c) {
                Ok(0) => {
                    server_closed = true;
                    // Shutdown client write side
                    let _ = client.shutdown(std::net::Shutdown::Write);
                }
                Ok(n) => {
                    activity = true;
                    if let Err(e) = client.write_all(&buf_s2c[..n]) {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            client_closed = true;
                        }
                    } else {
                        bytes_s2c += n as u64;
                        flow_stats.add_received(n as u64);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data available, continue
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    // Timeout, continue
                }
                Err(_) => {
                    server_closed = true;
                }
            }
        }

        // Check termination conditions
        if client_closed && server_closed {
            break;
        }

        // Idle timeout detection
        if activity {
            idle_count = 0;
        } else {
            idle_count += 1;
            if idle_count >= max_idle_iterations {
                debug!("Connection idle timeout after {} seconds", IDLE_TIMEOUT.as_secs());
                break;
            }
        }

        // Small sleep to prevent busy-waiting
        if !activity {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    Ok((bytes_c2s, bytes_s2c))
}

/// One-way TCP relay (copy from reader to writer)
///
/// Copies all data from `reader` to `writer` until EOF or error.
///
/// # Arguments
///
/// * `reader` - Source stream to read from
/// * `writer` - Destination stream to write to
///
/// # Returns
///
/// Total bytes copied
pub fn relay_one_way<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<u64> {
    let mut buf = [0u8; BUFFER_SIZE];
    let mut total: u64 = 0;

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                writer.write_all(&buf[..n])?;
                total += n as u64;
            }
            Err(e) => return Err(e),
        }
    }

    writer.flush()?;
    Ok(total)
}

/// Relay with data inspection callback
///
/// Like `relay_bidirectional` but allows inspection/modification of data.
///
/// # Arguments
///
/// * `client` - Client-side TCP stream
/// * `server` - Server-side TCP stream
/// * `on_client_data` - Callback for data from client (can modify)
/// * `on_server_data` - Callback for data from server (can modify)
///
/// # Returns
///
/// Tuple of (bytes_client_to_server, bytes_server_to_client)
pub fn relay_with_inspection<F1, F2>(
    client: &mut TcpStream,
    server: &mut TcpStream,
    mut on_client_data: F1,
    mut on_server_data: F2,
) -> io::Result<(u64, u64)>
where
    F1: FnMut(&[u8]) -> Vec<u8>,
    F2: FnMut(&[u8]) -> Vec<u8>,
{
    client.set_nonblocking(true)?;
    server.set_nonblocking(true)?;

    let mut buf = [0u8; BUFFER_SIZE];
    let mut bytes_c2s: u64 = 0;
    let mut bytes_s2c: u64 = 0;

    let mut client_closed = false;
    let mut server_closed = false;

    loop {
        // Client -> Server
        if !client_closed {
            match client.read(&mut buf) {
                Ok(0) => {
                    client_closed = true;
                    let _ = server.shutdown(std::net::Shutdown::Write);
                }
                Ok(n) => {
                    let data = on_client_data(&buf[..n]);
                    if !data.is_empty() {
                        server.write_all(&data)?;
                        bytes_c2s += data.len() as u64;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => client_closed = true,
            }
        }

        // Server -> Client
        if !server_closed {
            match server.read(&mut buf) {
                Ok(0) => {
                    server_closed = true;
                    let _ = client.shutdown(std::net::Shutdown::Write);
                }
                Ok(n) => {
                    let data = on_server_data(&buf[..n]);
                    if !data.is_empty() {
                        client.write_all(&data)?;
                        bytes_s2c += data.len() as u64;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => server_closed = true,
            }
        }

        if client_closed && server_closed {
            break;
        }

        std::thread::sleep(Duration::from_millis(1));
    }

    Ok((bytes_c2s, bytes_s2c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_relay_one_way() {
        let mut reader = Cursor::new(b"Hello, World!".to_vec());
        let mut writer = Vec::new();

        let bytes = relay_one_way(&mut reader, &mut writer).unwrap();

        assert_eq!(bytes, 13);
        assert_eq!(writer, b"Hello, World!");
    }

    #[test]
    fn test_relay_one_way_empty() {
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::new();

        let bytes = relay_one_way(&mut reader, &mut writer).unwrap();

        assert_eq!(bytes, 0);
        assert!(writer.is_empty());
    }

    #[test]
    fn test_relay_one_way_large() {
        let data = vec![0xAB; 100_000];
        let mut reader = Cursor::new(data.clone());
        let mut writer = Vec::new();

        let bytes = relay_one_way(&mut reader, &mut writer).unwrap();

        assert_eq!(bytes, 100_000);
        assert_eq!(writer, data);
    }
}
