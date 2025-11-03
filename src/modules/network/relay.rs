/// Port Forwarding / Relay (socat-style)
///
/// Implements bidirectional relay between two endpoints:
/// - TCP to TCP forwarding
/// - UDP to UDP forwarding
/// - TCP to UDP relay
/// - UDP to TCP relay
/// - Fork mode (multiple simultaneous connections)
///
/// Replaces: socat (port forwarding features)
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

/// Relay endpoint type
#[derive(Debug, Clone, PartialEq)]
pub enum EndpointType {
    TcpListen(u16),          // Listen on TCP port
    TcpConnect(String, u16), // Connect to TCP host:port
    UdpListen(u16),          // Listen on UDP port
    UdpConnect(String, u16), // Connect to UDP host:port
}

/// Relay configuration
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub source: EndpointType,
    pub destination: EndpointType,
    pub fork: bool, // Allow multiple simultaneous connections
    pub verbose: bool,
    pub timeout: Duration,
}

impl RelayConfig {
    pub fn new(source: EndpointType, destination: EndpointType) -> Self {
        Self {
            source,
            destination,
            fork: false,
            verbose: false,
            timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    pub fn with_fork(mut self, fork: bool) -> Self {
        self.fork = fork;
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Port forwarder / relay
pub struct Relay {
    config: RelayConfig,
}

impl Relay {
    pub fn new(config: RelayConfig) -> Self {
        Self { config }
    }

    /// Start the relay
    pub fn run(&self) -> Result<(), String> {
        if self.config.verbose {
            eprintln!(
                "[+] Starting relay: {:?} -> {:?}",
                self.config.source, self.config.destination
            );
        }

        match (&self.config.source, &self.config.destination) {
            (EndpointType::TcpListen(sport), EndpointType::TcpConnect(dhost, dport)) => {
                self.relay_tcp_to_tcp(*sport, dhost, *dport)
            }
            (EndpointType::TcpListen(sport), EndpointType::UdpConnect(dhost, dport)) => {
                self.relay_tcp_to_udp(*sport, dhost, *dport)
            }
            (EndpointType::UdpListen(sport), EndpointType::TcpConnect(dhost, dport)) => {
                self.relay_udp_to_tcp(*sport, dhost, *dport)
            }
            (EndpointType::UdpListen(sport), EndpointType::UdpConnect(dhost, dport)) => {
                self.relay_udp_to_udp(*sport, dhost, *dport)
            }
            _ => Err("Invalid relay configuration".to_string()),
        }
    }

    /// TCP to TCP relay (most common case)
    fn relay_tcp_to_tcp(&self, sport: u16, dhost: &str, dport: u16) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", sport);
        let listener =
            TcpListener::bind(&addr).map_err(|e| format!("Failed to bind {}: {}", addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Listening on {} (TCP)", addr);
            eprintln!("[+] Forwarding to {}:{} (TCP)", dhost, dport);
        }

        if self.config.fork {
            // Fork mode: handle multiple simultaneous connections
            self.relay_tcp_to_tcp_fork(listener, dhost, dport)
        } else {
            // Single connection mode
            self.relay_tcp_to_tcp_single(listener, dhost, dport)
        }
    }

    /// TCP to TCP relay - single connection
    fn relay_tcp_to_tcp_single(
        &self,
        listener: TcpListener,
        dhost: &str,
        dport: u16,
    ) -> Result<(), String> {
        let (client_stream, client_addr) = listener
            .accept()
            .map_err(|e| format!("Failed to accept connection: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] Connection from {}", client_addr);
        }

        // Connect to destination
        let dest_addr = format!("{}:{}", dhost, dport);
        let dest_stream = TcpStream::connect(&dest_addr)
            .map_err(|e| format!("Failed to connect to {}: {}", dest_addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Connected to {}", dest_addr);
        }

        // Set timeouts
        client_stream
            .set_read_timeout(Some(self.config.timeout))
            .ok();
        dest_stream.set_read_timeout(Some(self.config.timeout)).ok();

        // Bidirectional relay
        self.bidirectional_copy(client_stream, dest_stream)?;

        if self.config.verbose {
            eprintln!("[+] Connection closed");
        }

        Ok(())
    }

    /// TCP to TCP relay - fork mode (multiple connections)
    fn relay_tcp_to_tcp_fork(
        &self,
        listener: TcpListener,
        dhost: &str,
        dport: u16,
    ) -> Result<(), String> {
        let dhost = dhost.to_string();
        let verbose = self.config.verbose;
        let timeout = self.config.timeout;

        loop {
            match listener.accept() {
                Ok((client_stream, client_addr)) => {
                    if verbose {
                        eprintln!("[+] Connection from {}", client_addr);
                    }

                    let dhost_clone = dhost.clone();
                    thread::spawn(move || {
                        // Connect to destination
                        let dest_addr = format!("{}:{}", dhost_clone, dport);
                        match TcpStream::connect(&dest_addr) {
                            Ok(dest_stream) => {
                                if verbose {
                                    eprintln!("[+] Connected to {} for {}", dest_addr, client_addr);
                                }

                                // Set timeouts
                                client_stream.set_read_timeout(Some(timeout)).ok();
                                dest_stream.set_read_timeout(Some(timeout)).ok();

                                // Relay
                                if let Err(e) =
                                    bidirectional_copy_static(client_stream, dest_stream)
                                {
                                    if verbose {
                                        eprintln!("[!] Relay error for {}: {}", client_addr, e);
                                    }
                                }

                                if verbose {
                                    eprintln!("[+] Connection from {} closed", client_addr);
                                }
                            }
                            Err(e) => {
                                if verbose {
                                    eprintln!("[!] Failed to connect to {}: {}", dest_addr, e);
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[!] Accept error: {}", e);
                }
            }
        }
    }

    /// TCP to UDP relay
    fn relay_tcp_to_udp(&self, sport: u16, dhost: &str, dport: u16) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", sport);
        let listener =
            TcpListener::bind(&addr).map_err(|e| format!("Failed to bind {}: {}", addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Listening on {} (TCP)", addr);
            eprintln!("[+] Forwarding to {}:{} (UDP)", dhost, dport);
        }

        let (mut tcp_stream, client_addr) = listener
            .accept()
            .map_err(|e| format!("Failed to accept: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] Connection from {}", client_addr);
        }

        // Create UDP socket
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to create UDP socket: {}", e))?;
        let dest_addr = format!("{}:{}", dhost, dport);
        udp_socket
            .connect(&dest_addr)
            .map_err(|e| format!("Failed to connect UDP: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] UDP connected to {}", dest_addr);
        }

        // Relay TCP -> UDP
        let mut buf = vec![0u8; 65536];
        loop {
            match tcp_stream.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if let Err(e) = udp_socket.send(&buf[..n]) {
                        return Err(format!("UDP send failed: {}", e));
                    }
                }
                Err(e) => return Err(format!("TCP read failed: {}", e)),
            }
        }

        Ok(())
    }

    /// UDP to TCP relay
    fn relay_udp_to_tcp(&self, sport: u16, dhost: &str, dport: u16) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", sport);
        let udp_socket =
            UdpSocket::bind(&addr).map_err(|e| format!("Failed to bind UDP {}: {}", addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Listening on {} (UDP)", addr);
            eprintln!("[+] Forwarding to {}:{} (TCP)", dhost, dport);
        }

        // Wait for first UDP packet
        let mut buf = vec![0u8; 65536];
        let (n, udp_peer) = udp_socket
            .recv_from(&mut buf)
            .map_err(|e| format!("UDP recv failed: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] UDP packet from {}", udp_peer);
        }

        // Connect to TCP destination
        let dest_addr = format!("{}:{}", dhost, dport);
        let mut tcp_stream = TcpStream::connect(&dest_addr)
            .map_err(|e| format!("Failed to connect to {}: {}", dest_addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Connected to {} (TCP)", dest_addr);
        }

        // Send first packet
        tcp_stream
            .write_all(&buf[..n])
            .map_err(|e| format!("TCP write failed: {}", e))?;

        // Continue relaying UDP -> TCP
        loop {
            match udp_socket.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if let Err(e) = tcp_stream.write_all(&buf[..n]) {
                        return Err(format!("TCP write failed: {}", e));
                    }
                }
                Err(e) => return Err(format!("UDP recv failed: {}", e)),
            }
        }
    }

    /// UDP to UDP relay
    fn relay_udp_to_udp(&self, sport: u16, dhost: &str, dport: u16) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", sport);
        let src_socket =
            UdpSocket::bind(&addr).map_err(|e| format!("Failed to bind UDP {}: {}", addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Listening on {} (UDP)", addr);
            eprintln!("[+] Forwarding to {}:{} (UDP)", dhost, dport);
        }

        // Create destination socket
        let dest_socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to create UDP socket: {}", e))?;
        let dest_addr = format!("{}:{}", dhost, dport);
        dest_socket
            .connect(&dest_addr)
            .map_err(|e| format!("Failed to connect UDP: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] UDP forwarding active");
        }

        // Relay UDP packets
        let mut buf = vec![0u8; 65536];
        loop {
            match src_socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    if self.config.verbose {
                        eprintln!("[+] UDP packet from {} ({} bytes)", peer, n);
                    }
                    if let Err(e) = dest_socket.send(&buf[..n]) {
                        return Err(format!("UDP send failed: {}", e));
                    }
                }
                Err(e) => return Err(format!("UDP recv failed: {}", e)),
            }
        }
    }

    /// Bidirectional copy between two TCP streams
    fn bidirectional_copy(&self, stream1: TcpStream, stream2: TcpStream) -> Result<(), String> {
        bidirectional_copy_static(stream1, stream2)
    }
}

/// Static bidirectional copy function (for use in threads)
fn bidirectional_copy_static(mut stream1: TcpStream, mut stream2: TcpStream) -> Result<(), String> {
    let mut s1_clone = stream1
        .try_clone()
        .map_err(|e| format!("Failed to clone stream: {}", e))?;
    let mut s2_clone = stream2
        .try_clone()
        .map_err(|e| format!("Failed to clone stream: {}", e))?;

    // Thread 1: stream1 -> stream2
    let handle1 = thread::spawn(move || {
        let mut buf = vec![0u8; 8192];
        loop {
            match s1_clone.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if stream2.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Thread 2: stream2 -> stream1
    let handle2 = thread::spawn(move || {
        let mut buf = vec![0u8; 8192];
        loop {
            match s2_clone.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if stream1.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Wait for both threads
    handle1.join().ok();
    handle2.join().ok();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_config() {
        let config = RelayConfig::new(
            EndpointType::TcpListen(8080),
            EndpointType::TcpConnect("localhost".to_string(), 80),
        );
        assert_eq!(config.source, EndpointType::TcpListen(8080));
        assert!(!config.fork);
    }

    #[test]
    fn test_endpoint_types() {
        let tcp_listen = EndpointType::TcpListen(8080);
        let tcp_connect = EndpointType::TcpConnect("example.com".to_string(), 80);
        assert_eq!(tcp_listen, EndpointType::TcpListen(8080));
        assert_ne!(tcp_listen, tcp_connect);
    }
}
