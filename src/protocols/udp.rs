/// UDP Protocol Utilities
///
/// Provides raw UDP socket functionality for:
/// - Sending and receiving UDP packets
/// - UDP listener (server mode)
/// - UDP client
/// - Hex dump capabilities
/// - Timeout handling
///
/// This module provides the foundation for tools like netcat (nc) UDP mode
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// UDP client for sending and receiving datagrams
pub struct UdpClient {
    socket: UdpSocket,
    timeout: Duration,
}

impl UdpClient {
    /// Create a new UDP client bound to any available local port
    pub fn new() -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        Ok(Self {
            socket,
            timeout: Duration::from_secs(5),
        })
    }

    /// Create UDP client bound to a specific local address/port
    pub fn bind(local_addr: &str) -> Result<Self, String> {
        let socket = UdpSocket::bind(local_addr)
            .map_err(|e| format!("Failed to bind to {}: {}", local_addr, e))?;

        Ok(Self {
            socket,
            timeout: Duration::from_secs(5),
        })
    }

    /// Set read/write timeout
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        self.socket
            .set_write_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;
        self.timeout = timeout;
        Ok(())
    }

    /// Send data to a remote address
    pub fn send_to(&self, data: &[u8], addr: &str) -> Result<usize, String> {
        let remote_addr = addr
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {}: {}", addr, e))?
            .next()
            .ok_or_else(|| format!("Could not resolve address: {}", addr))?;

        self.socket
            .send_to(data, remote_addr)
            .map_err(|e| format!("Failed to send data: {}", e))
    }

    /// Receive data from any source
    pub fn recv(&self) -> Result<(Vec<u8>, String), String> {
        let mut buf = vec![0u8; 65535]; // Max UDP packet size

        match self.socket.recv_from(&mut buf) {
            Ok((size, src_addr)) => {
                buf.truncate(size);
                Ok((buf, src_addr.to_string()))
            }
            Err(e) => Err(format!("Failed to receive data: {}", e)),
        }
    }

    /// Connect to a specific remote address (filters incoming packets)
    pub fn connect(&mut self, addr: &str) -> Result<(), String> {
        let remote_addr = addr
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {}: {}", addr, e))?
            .next()
            .ok_or_else(|| format!("Could not resolve address: {}", addr))?;

        self.socket
            .connect(remote_addr)
            .map_err(|e| format!("Failed to connect: {}", e))
    }

    /// Send data (requires previous connect())
    pub fn send(&self, data: &[u8]) -> Result<usize, String> {
        self.socket
            .send(data)
            .map_err(|e| format!("Failed to send: {}", e))
    }

    /// Receive data from connected address
    pub fn recv_connected(&self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 65535];

        match self.socket.recv(&mut buf) {
            Ok(size) => {
                buf.truncate(size);
                Ok(buf)
            }
            Err(e) => Err(format!("Failed to receive: {}", e)),
        }
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<String, String> {
        self.socket
            .local_addr()
            .map(|a| a.to_string())
            .map_err(|e| format!("Failed to get local address: {}", e))
    }
}

impl Default for UdpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create UDP client")
    }
}

/// UDP listener/server
pub struct UdpServer {
    socket: UdpSocket,
    timeout: Option<Duration>,
}

impl UdpServer {
    /// Create a new UDP server listening on the specified address
    pub fn bind(addr: &str) -> Result<Self, String> {
        let socket =
            UdpSocket::bind(addr).map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        Ok(Self {
            socket,
            timeout: None,
        })
    }

    /// Set read timeout
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), String> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(|e| format!("Failed to set timeout: {}", e))?;
        self.timeout = timeout;
        Ok(())
    }

    /// Receive a datagram
    pub fn recv_from(&self) -> Result<(Vec<u8>, String), String> {
        let mut buf = vec![0u8; 65535];

        match self.socket.recv_from(&mut buf) {
            Ok((size, src_addr)) => {
                buf.truncate(size);
                Ok((buf, src_addr.to_string()))
            }
            Err(e) => Err(format!("Failed to receive: {}", e)),
        }
    }

    /// Send a datagram to a specific address
    pub fn send_to(&self, data: &[u8], addr: &str) -> Result<usize, String> {
        let remote_addr = addr
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {}: {}", addr, e))?
            .next()
            .ok_or_else(|| format!("Could not resolve address: {}", addr))?;

        self.socket
            .send_to(data, remote_addr)
            .map_err(|e| format!("Failed to send: {}", e))
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<String, String> {
        self.socket
            .local_addr()
            .map(|a| a.to_string())
            .map_err(|e| format!("Failed to get local address: {}", e))
    }
}

/// Format bytes as hex dump
pub fn hex_dump(data: &[u8]) -> String {
    let mut output = String::new();
    let chunk_size = 16;

    for (offset, chunk) in data.chunks(chunk_size).enumerate() {
        // Offset
        output.push_str(&format!("{:08x}  ", offset * chunk_size));

        // Hex bytes
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                output.push(' '); // Extra space in the middle
            }
            output.push_str(&format!("{:02x} ", byte));
        }

        // Padding for incomplete lines
        if chunk.len() < chunk_size {
            for i in chunk.len()..chunk_size {
                if i == 8 {
                    output.push(' ');
                }
                output.push_str("   ");
            }
        }

        // ASCII representation
        output.push_str(" |");
        for byte in chunk {
            let c = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            output.push(c);
        }
        output.push_str("|\n");
    }

    output
}

/// Format bytes as printable string (replace non-printable with '.')
pub fn to_printable(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Simple UDP echo test
pub fn udp_echo(
    host: &str,
    port: u16,
    message: &[u8],
    timeout_secs: u64,
) -> Result<Vec<u8>, String> {
    let mut client = UdpClient::new()?;
    client.set_timeout(Duration::from_secs(timeout_secs))?;

    let addr = format!("{}:{}", host, port);
    client.send_to(message, &addr)?;

    let (response, _src) = client.recv()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_client_creation() {
        let client = UdpClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_udp_server_bind() {
        // Try to bind to a random high port
        let server = UdpServer::bind("127.0.0.1:0");
        assert!(server.is_ok());
    }

    #[test]
    fn test_hex_dump() {
        let data = b"Hello, World!\x00\x01\x02";
        let dump = hex_dump(data);

        assert!(dump.contains("48 65 6c 6c")); // "Hell" in hex
        assert!(dump.contains("Hello, World!"));
    }

    #[test]
    fn test_to_printable() {
        let data = b"Hello\x00World\x01!";
        let printable = to_printable(data);

        assert_eq!(printable, "Hello.World.!");
    }

    #[test]
    fn test_udp_localhost_echo() {
        // Create server
        let server = UdpServer::bind("127.0.0.1:0").expect("Failed to bind server");
        let server_addr = server.local_addr().expect("Failed to get server address");

        // Create client
        let client = UdpClient::new().expect("Failed to create client");

        // Send message
        let message = b"test message";
        client
            .send_to(message, &server_addr)
            .expect("Failed to send");

        // Receive on server
        let (received, client_addr) = server.recv_from().expect("Failed to receive");
        assert_eq!(received, message);

        // Echo back
        server
            .send_to(&received, &client_addr)
            .expect("Failed to echo");

        // Receive echo on client
        let (echo, _) = client.recv().expect("Failed to receive echo");
        assert_eq!(echo, message);
    }
}
