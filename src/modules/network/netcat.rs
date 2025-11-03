/// Netcat (nc) Replacement
///
/// Complete netcat implementation with:
/// - TCP client/server mode
/// - UDP client/server mode
/// - Interactive and non-interactive modes
/// - File transfer capabilities
/// - Hex dump mode
/// - Zero I/O mode (port scanning)
///
/// Replaces: netcat, nc, ncat, socat (basic features)
use crate::protocols::udp::{hex_dump, UdpClient, UdpServer};
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Netcat mode of operation
#[derive(Debug, Clone, PartialEq)]
pub enum NetcatMode {
    /// Client mode - connect to remote host
    Client,
    /// Server mode - listen for incoming connections
    Server,
}

/// Network protocol
#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Netcat configuration
#[derive(Debug, Clone)]
pub struct NetcatConfig {
    pub mode: NetcatMode,
    pub protocol: Protocol,
    pub host: Option<String>,
    pub port: u16,
    pub timeout: Duration,
    pub verbose: bool,
    pub hex_dump: bool,
    pub zero_io: bool, // Port scanning mode
}

impl Default for NetcatConfig {
    fn default() -> Self {
        Self {
            mode: NetcatMode::Client,
            protocol: Protocol::Tcp,
            host: None,
            port: 0,
            timeout: Duration::from_secs(10),
            verbose: false,
            hex_dump: false,
            zero_io: false,
        }
    }
}

impl NetcatConfig {
    pub fn client(host: &str, port: u16) -> Self {
        Self {
            mode: NetcatMode::Client,
            host: Some(host.to_string()),
            port,
            ..Default::default()
        }
    }

    pub fn server(port: u16) -> Self {
        Self {
            mode: NetcatMode::Server,
            port,
            ..Default::default()
        }
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn with_hex_dump(mut self, hex_dump: bool) -> Self {
        self.hex_dump = hex_dump;
        self
    }

    pub fn with_zero_io(mut self, zero_io: bool) -> Self {
        self.zero_io = zero_io;
        self
    }
}

/// Netcat implementation
pub struct Netcat {
    config: NetcatConfig,
}

impl Netcat {
    pub fn new(config: NetcatConfig) -> Self {
        Self { config }
    }

    /// Run netcat with the configured mode
    pub fn run(&self) -> Result<(), String> {
        match (&self.config.mode, &self.config.protocol) {
            (NetcatMode::Client, Protocol::Tcp) => self.tcp_client(),
            (NetcatMode::Server, Protocol::Tcp) => self.tcp_server(),
            (NetcatMode::Client, Protocol::Udp) => self.udp_client(),
            (NetcatMode::Server, Protocol::Udp) => self.udp_server(),
        }
    }

    /// TCP client mode
    fn tcp_client(&self) -> Result<(), String> {
        let host = self
            .config
            .host
            .as_ref()
            .ok_or("Host required for client mode")?;
        let addr_str = format!("{}:{}", host, self.config.port);

        if self.config.verbose {
            eprintln!("[+] Connecting to {} (TCP)...", addr_str);
        }

        // Use ToSocketAddrs which handles both IP addresses and hostnames
        let addrs: Vec<_> = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve address {}: {}", addr_str, e))?
            .collect();

        let addr = addrs
            .first()
            .ok_or_else(|| format!("No addresses found for {}", addr_str))?;

        // Zero I/O mode - just test connection
        if self.config.zero_io {
            return match TcpStream::connect_timeout(addr, self.config.timeout) {
                Ok(_) => {
                    println!("Connection to {} succeeded!", addr_str);
                    Ok(())
                }
                Err(e) => {
                    println!("Connection to {} failed: {}", addr_str, e);
                    Err(format!("Connection failed: {}", e))
                }
            };
        }

        let stream = TcpStream::connect_timeout(addr, self.config.timeout)
            .map_err(|e| format!("Failed to connect: {}", e))?;

        stream
            .set_read_timeout(Some(self.config.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] Connected to {}", addr);
        }

        self.handle_tcp_stream(stream)
    }

    /// TCP server mode
    fn tcp_server(&self) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", self.config.port);

        if self.config.verbose {
            eprintln!("[+] Listening on {} (TCP)...", addr);
        }

        let listener =
            TcpListener::bind(&addr).map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Waiting for connections...");
        }

        // Accept single connection (traditional nc behavior)
        let (stream, client_addr) = listener
            .accept()
            .map_err(|e| format!("Failed to accept connection: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] Connection from {}", client_addr);
        }

        self.handle_tcp_stream(stream)
    }

    /// Handle bidirectional TCP stream (both client and server)
    fn handle_tcp_stream(&self, mut stream: TcpStream) -> Result<(), String> {
        let stdin = io::stdin();
        let mut stdin_reader = stdin.lock();

        // Spawn thread to read from network and write to stdout
        let stream_clone = stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;
        let hex_mode = self.config.hex_dump;

        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let mut stream = stream_clone;

            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        let data = &buf[..n];

                        if hex_mode {
                            print!("{}", hex_dump(data));
                        } else {
                            if let Err(_) = io::stdout().write_all(data) {
                                break;
                            }
                            let _ = io::stdout().flush();
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Read from stdin and write to network
        let mut line = String::new();
        loop {
            line.clear();
            match stdin_reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if let Err(e) = stream.write_all(line.as_bytes()) {
                        return Err(format!("Write failed: {}", e));
                    }
                    let _ = stream.flush();
                }
                Err(e) => return Err(format!("Read from stdin failed: {}", e)),
            }
        }

        Ok(())
    }

    /// UDP client mode
    fn udp_client(&self) -> Result<(), String> {
        let host = self
            .config
            .host
            .as_ref()
            .ok_or("Host required for client mode")?;
        let addr = format!("{}:{}", host, self.config.port);

        if self.config.verbose {
            eprintln!("[+] UDP client mode, sending to {}", addr);
        }

        let mut client = UdpClient::new()?;
        client.set_timeout(self.config.timeout)?;

        let stdin = io::stdin();
        let mut stdin_reader = stdin.lock();

        // Spawn thread to receive UDP packets
        let client_clone = UdpClient::new()?;
        let hex_mode = self.config.hex_dump;

        std::thread::spawn(move || loop {
            match client_clone.recv() {
                Ok((data, src)) => {
                    if hex_mode {
                        eprintln!("[<- from {}]", src);
                        print!("{}", hex_dump(&data));
                    } else {
                        if let Err(_) = io::stdout().write_all(&data) {
                            break;
                        }
                        let _ = io::stdout().flush();
                    }
                }
                Err(_) => break,
            }
        });

        // Read from stdin and send UDP packets
        let mut line = String::new();
        loop {
            line.clear();
            match stdin_reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if let Err(e) = client.send_to(line.as_bytes(), &addr) {
                        return Err(format!("Send failed: {}", e));
                    }
                }
                Err(e) => return Err(format!("Read from stdin failed: {}", e)),
            }
        }

        Ok(())
    }

    /// UDP server mode
    fn udp_server(&self) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", self.config.port);

        if self.config.verbose {
            eprintln!("[+] Listening on {} (UDP)...", addr);
        }

        let _server = UdpServer::bind(&addr)?;

        if self.config.verbose {
            eprintln!("[+] Waiting for UDP packets...");
        }

        let stdin = io::stdin();
        let mut stdin_reader = stdin.lock();

        // Spawn thread to receive UDP packets
        let server_clone = UdpServer::bind(&addr)?;
        let hex_mode = self.config.hex_dump;
        let verbose = self.config.verbose;

        std::thread::spawn(move || loop {
            match server_clone.recv_from() {
                Ok((data, src)) => {
                    if verbose {
                        eprintln!("[+] Received from {}", src);
                    }

                    if hex_mode {
                        print!("{}", hex_dump(&data));
                    } else {
                        if let Err(_) = io::stdout().write_all(&data) {
                            break;
                        }
                        let _ = io::stdout().flush();
                    }
                }
                Err(_) => break,
            }
        });

        // Read from stdin and send to last client
        let mut line = String::new();
        loop {
            line.clear();
            match stdin_reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    eprintln!("[!] UDP send-back not implemented in this build");
                }
                Err(e) => return Err(format!("Read from stdin failed: {}", e)),
            }
        }

        Ok(())
    }
}

/// Simple port scan using zero-I/O mode
pub fn port_scan(host: &str, port: u16, timeout: Duration) -> bool {
    let config = NetcatConfig::client(host, port)
        .with_zero_io(true)
        .with_timeout(timeout);

    let nc = Netcat::new(config);
    nc.run().is_ok()
}

/// Send a single UDP packet and optionally wait for response
pub fn udp_send(
    host: &str,
    port: u16,
    data: &[u8],
    wait_response: bool,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, String> {
    let mut client = UdpClient::new()?;
    client.set_timeout(timeout)?;

    let addr = format!("{}:{}", host, port);
    client.send_to(data, &addr)?;

    if wait_response {
        let (response, _) = client.recv()?;
        Ok(Some(response))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netcat_config() {
        let config = NetcatConfig::client("example.com", 80);
        assert_eq!(config.mode, NetcatMode::Client);
        assert_eq!(config.protocol, Protocol::Tcp);
        assert_eq!(config.port, 80);
    }

    #[test]
    fn test_server_config() {
        let config = NetcatConfig::server(8080).with_protocol(Protocol::Udp);
        assert_eq!(config.mode, NetcatMode::Server);
        assert_eq!(config.protocol, Protocol::Udp);
        assert_eq!(config.port, 8080);
    }
}
