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
use crate::modules::network::twofish::TwofishCBC;
use crate::protocols::udp::{hex_dump, UdpClient, UdpServer};
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
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

/// IP version preference
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpVersion {
    Any,    // Try both IPv4 and IPv6 (default)
    V4Only, // Force IPv4 only (-4)
    V6Only, // Force IPv6 only (-6)
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
    pub zero_io: bool,                  // Port scanning mode
    pub keep_open: bool,                // Accept multiple connections (-k)
    pub source_port: Option<u16>,       // Source port binding (-p)
    pub exec_command: Option<String>,   // Execute command on connection (-e)
    pub ip_version: IpVersion,          // IPv4/IPv6 preference (-4/-6)
    pub encryption_key: Option<String>, // Cryptcat encryption password
    pub delay_ms: Option<u64>,          // Delay between lines in ms (-i)
    pub per_line_delay: bool,           // Apply delay only after newlines (not every write)
    pub idle_timeout: Option<Duration>, // Idle timeout (-w)
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
            keep_open: false,
            source_port: None,
            exec_command: None,
            ip_version: IpVersion::Any,
            encryption_key: None,
            delay_ms: None,
            per_line_delay: false,
            idle_timeout: None,
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

    pub fn with_keep_open(mut self, keep_open: bool) -> Self {
        self.keep_open = keep_open;
        self
    }

    pub fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    pub fn with_exec(mut self, cmd: String) -> Self {
        self.exec_command = Some(cmd);
        self
    }

    pub fn with_ip_version(mut self, version: IpVersion) -> Self {
        self.ip_version = version;
        self
    }

    pub fn with_encryption(mut self, password: String) -> Self {
        self.encryption_key = Some(password);
        self
    }

    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = Some(delay_ms);
        self
    }

    pub fn with_per_line_delay(mut self, per_line: bool) -> Self {
        self.per_line_delay = per_line;
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
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
        let all_addrs: Vec<_> = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve address {}: {}", addr_str, e))?
            .collect();

        // Filter addresses based on IP version preference
        let addrs: Vec<_> = match self.config.ip_version {
            IpVersion::V4Only => all_addrs.into_iter().filter(|a| a.is_ipv4()).collect(),
            IpVersion::V6Only => all_addrs.into_iter().filter(|a| a.is_ipv6()).collect(),
            IpVersion::Any => all_addrs,
        };

        if addrs.is_empty() {
            return Err(match self.config.ip_version {
                IpVersion::V4Only => format!("No IPv4 addresses found for {}", addr_str),
                IpVersion::V6Only => format!("No IPv6 addresses found for {}", addr_str),
                IpVersion::Any => format!("No addresses found for {}", addr_str),
            });
        }

        let addr = addrs.first().unwrap();

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

        // Connect with optional source port binding
        let stream = if let Some(source_port) = self.config.source_port {
            if self.config.verbose {
                eprintln!(
                    "[*] Source port binding: {} (requires OS-level socket control)",
                    source_port
                );
            }

            // Note: Source port binding requires raw socket creation with bind() before connect()
            // This is implemented using libc for Unix systems
            #[cfg(unix)]
            {
                self.tcp_connect_with_source_port(addr, source_port)?
            }

            #[cfg(not(unix))]
            {
                eprintln!("[!] Warning: Source port binding not supported on this platform");
                TcpStream::connect_timeout(addr, self.config.timeout)
                    .map_err(|e| format!("Failed to connect: {}", e))?
            }
        } else {
            // Normal connection without source port binding
            TcpStream::connect_timeout(addr, self.config.timeout)
                .map_err(|e| format!("Failed to connect: {}", e))?
        };

        stream
            .set_read_timeout(Some(self.config.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] Connected to {}", addr);
        }

        self.handle_tcp_stream(stream)
    }

    /// Helper: Connect with specific source port (Unix only)
    #[cfg(unix)]
    fn tcp_connect_with_source_port(
        &self,
        addr: &SocketAddr,
        source_port: u16,
    ) -> Result<TcpStream, String> {
        use std::os::unix::io::FromRawFd;

        // Create raw socket
        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };

        if socket_fd < 0 {
            return Err("Failed to create socket".to_string());
        }

        // Bind to source port
        let bind_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, source_port);
        let bind_result = unsafe {
            let addr_ptr = &bind_addr as *const _ as *const libc::sockaddr;
            libc::bind(
                socket_fd,
                addr_ptr,
                std::mem::size_of::<std::net::SocketAddrV4>() as u32,
            )
        };

        if bind_result < 0 {
            unsafe {
                libc::close(socket_fd);
            }
            return Err(format!("Failed to bind source port {}", source_port));
        }

        // Connect to destination
        let connect_result = unsafe {
            let addr_ptr = addr as *const _ as *const libc::sockaddr;
            let addr_len = match addr {
                SocketAddr::V4(_) => std::mem::size_of::<std::net::SocketAddrV4>(),
                SocketAddr::V6(_) => std::mem::size_of::<std::net::SocketAddrV6>(),
            };
            libc::connect(socket_fd, addr_ptr, addr_len as u32)
        };

        if connect_result < 0 {
            unsafe {
                libc::close(socket_fd);
            }
            return Err("Failed to connect".to_string());
        }

        // Convert to TcpStream
        let stream = unsafe { TcpStream::from_raw_fd(socket_fd) };
        Ok(stream)
    }

    /// TCP server mode
    fn tcp_server(&self) -> Result<(), String> {
        let addr = match self.config.ip_version {
            IpVersion::V4Only => format!("0.0.0.0:{}", self.config.port),
            IpVersion::V6Only => format!("[::]:{}", self.config.port),
            IpVersion::Any => format!("[::]:{}", self.config.port), // Dual-stack on most systems
        };

        if self.config.verbose {
            eprintln!("[+] Listening on {} (TCP)...", addr);
        }

        let listener =
            TcpListener::bind(&addr).map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Waiting for connections...");
        }

        // Keep-open mode: accept multiple connections
        if self.config.keep_open {
            loop {
                match listener.accept() {
                    Ok((stream, client_addr)) => {
                        if self.config.verbose {
                            eprintln!("[+] Connection from {}", client_addr);
                        }

                        if let Err(e) = self.handle_tcp_stream(stream) {
                            if self.config.verbose {
                                eprintln!("[!] Connection error: {}", e);
                            }
                        }

                        if self.config.verbose {
                            eprintln!("[*] Connection closed, waiting for next...");
                        }
                    }
                    Err(e) => {
                        if self.config.verbose {
                            eprintln!("[!] Accept failed: {}", e);
                        }
                    }
                }
            }
        } else {
            // Accept single connection (traditional nc behavior)
            let (stream, client_addr) = listener
                .accept()
                .map_err(|e| format!("Failed to accept connection: {}", e))?;

            if self.config.verbose {
                eprintln!("[+] Connection from {}", client_addr);
            }

            self.handle_tcp_stream(stream)
        }
    }

    /// Handle bidirectional TCP stream (both client and server)
    fn handle_tcp_stream(&self, mut stream: TcpStream) -> Result<(), String> {
        // Exec mode: spawn command and redirect I/O
        if let Some(ref cmd) = self.config.exec_command {
            return self.handle_exec_mode(stream, cmd);
        }

        // Check if encryption is enabled
        if let Some(ref password) = self.config.encryption_key {
            return self.handle_encrypted_stream(stream, password);
        }

        let stdin = io::stdin();
        let mut stdin_reader = stdin.lock();

        // Spawn thread to read from network and write to stdout
        let stream_clone = stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;
        let hex_mode = self.config.hex_dump;
        let delay_ms = self.config.delay_ms;
        let idle_timeout = self.config.idle_timeout;

        // Set idle timeout if specified
        if let Some(timeout) = idle_timeout {
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|e| format!("Failed to set idle timeout: {}", e))?;
        }

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

                        // Apply delay if configured
                        if let Some(delay) = delay_ms {
                            std::thread::sleep(Duration::from_millis(delay));
                        }
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        // Idle timeout reached
                        eprintln!("[!] Idle timeout reached");
                        break;
                    }
                    Err(_) => break,
                }
            }
        });

        // Read from stdin and write to network
        let mut buf = [0u8; 4096];
        loop {
            match stdin_reader.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let data = &buf[..n];

                    // Write data to stream
                    if let Err(e) = stream.write_all(data) {
                        return Err(format!("Write failed: {}", e));
                    }
                    let _ = stream.flush();

                    // Apply delay if configured
                    if let Some(delay) = self.config.delay_ms {
                        if self.config.per_line_delay {
                            // Only delay if we just sent a newline
                            if data.contains(&b'\n') {
                                std::thread::sleep(Duration::from_millis(delay));
                            }
                        } else {
                            // Delay after every write
                            std::thread::sleep(Duration::from_millis(delay));
                        }
                    }
                }
                Err(e) => return Err(format!("Read from stdin failed: {}", e)),
            }
        }

        Ok(())
    }

    /// Handle encrypted TCP stream (Cryptcat mode)
    fn handle_encrypted_stream(&self, mut stream: TcpStream, password: &str) -> Result<(), String> {
        if self.config.verbose {
            eprintln!("[*] Cryptcat mode: Twofish-128 encryption enabled");
            eprintln!("[*] Using password-derived key and IV");
        }

        // Create separate cipher instances for each direction
        // Each direction gets its own independent CBC chain
        let cipher_send = Arc::new(Mutex::new(TwofishCBC::new(password)));
        let cipher_recv = Arc::new(Mutex::new(TwofishCBC::new(password)));

        let stdin = io::stdin();
        let mut stdin_reader = stdin.lock();

        // Spawn thread to read encrypted data from network and decrypt to stdout
        let stream_clone = stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;
        let cipher_recv_clone = Arc::clone(&cipher_recv);
        let hex_mode = self.config.hex_dump;
        let delay_ms = self.config.delay_ms;
        let idle_timeout = self.config.idle_timeout;
        let verbose = self.config.verbose;

        // Set idle timeout if specified
        if let Some(timeout) = idle_timeout {
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|e| format!("Failed to set idle timeout: {}", e))?;
        }

        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let mut stream = stream_clone;
            let mut accumulated = Vec::new();
            let mut total_received = 0u64;

            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        if verbose {
                            eprintln!(
                                "[*] Connection closed by peer (received {} bytes encrypted)",
                                total_received
                            );
                        }
                        break;
                    }
                    Ok(n) => {
                        total_received += n as u64;
                        if verbose && total_received % 4096 == 0 {
                            eprintln!("[*] Received {} bytes (encrypted)", total_received);
                        }

                        // Accumulate encrypted data
                        accumulated.extend_from_slice(&buf[..n]);

                        // Decrypt in blocks of 16 bytes (Twofish block size)
                        while accumulated.len() >= 16 {
                            let block_size = (accumulated.len() / 16) * 16;
                            let to_decrypt = accumulated.drain(..block_size).collect::<Vec<_>>();

                            let decrypted =
                                match cipher_recv_clone.lock().unwrap().decrypt(&to_decrypt) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        eprintln!("[!] Decryption error: {}", e);
                                        break;
                                    }
                                };

                            if hex_mode {
                                print!("{}", hex_dump(&decrypted));
                            } else {
                                if let Err(_) = io::stdout().write_all(&decrypted) {
                                    break;
                                }
                                let _ = io::stdout().flush();
                            }

                            // Apply delay if configured
                            if let Some(delay) = delay_ms {
                                std::thread::sleep(Duration::from_millis(delay));
                            }
                        }
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        eprintln!("[!] Idle timeout reached");
                        break;
                    }
                    Err(e) => {
                        if verbose {
                            eprintln!("[!] Read error: {}", e);
                        }
                        break;
                    }
                }
            }
        });

        // Read from stdin, encrypt, and write to network
        let mut buf = vec![0u8; 4096];
        let mut total_sent = 0u64;

        loop {
            match stdin_reader.read(&mut buf) {
                Ok(0) => {
                    if self.config.verbose {
                        eprintln!("[*] EOF on stdin (sent {} bytes encrypted)", total_sent);
                    }
                    break;
                }
                Ok(n) => {
                    let plaintext = &buf[..n];

                    // Encrypt data
                    let ciphertext = cipher_send.lock().unwrap().encrypt(plaintext);
                    total_sent += ciphertext.len() as u64;

                    if self.config.verbose && total_sent % 4096 == 0 {
                        eprintln!("[*] Sent {} bytes (encrypted)", total_sent);
                    }

                    if let Err(e) = stream.write_all(&ciphertext) {
                        return Err(format!("Write failed: {}", e));
                    }
                    let _ = stream.flush();

                    // Apply delay if configured
                    if let Some(delay) = self.config.delay_ms {
                        std::thread::sleep(Duration::from_millis(delay));
                    }
                }
                Err(e) => return Err(format!("Read from stdin failed: {}", e)),
            }
        }

        Ok(())
    }

    /// Handle exec mode: spawn command and redirect I/O through network stream
    fn handle_exec_mode(&self, stream: TcpStream, cmd: &str) -> Result<(), String> {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        use std::process::{Command, Stdio};

        if self.config.verbose {
            eprintln!("[*] Executing command: {}", cmd);
        }

        // Parse command (simple split on spaces)
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Empty command".to_string());
        }

        let prog = parts[0];
        let args = &parts[1..];

        // Get raw file descriptor from stream
        let stream_fd = stream.into_raw_fd();

        // Spawn process with stdin/stdout/stderr redirected to network stream
        let result = unsafe {
            Command::new(prog)
                .args(args)
                .stdin(Stdio::from_raw_fd(stream_fd))
                .stdout(Stdio::from_raw_fd(stream_fd))
                .stderr(Stdio::from_raw_fd(stream_fd))
                .spawn()
        };

        match result {
            Ok(mut child) => {
                if self.config.verbose {
                    eprintln!("[+] Spawned process: PID {}", child.id());
                }

                // Wait for process to finish
                match child.wait() {
                    Ok(status) => {
                        if self.config.verbose {
                            eprintln!("[*] Process exited: {}", status);
                        }
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to wait for process: {}", e)),
                }
            }
            Err(e) => Err(format!("Failed to spawn command '{}': {}", cmd, e)),
        }
    }

    /// UDP client mode
    fn udp_client(&self) -> Result<(), String> {
        // Check if encryption is enabled
        if let Some(ref password) = self.config.encryption_key {
            return self.udp_client_encrypted(password);
        }

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
        // Check if encryption is enabled
        if let Some(ref password) = self.config.encryption_key {
            return self.udp_server_encrypted(password);
        }

        let addr = match self.config.ip_version {
            IpVersion::V4Only => format!("0.0.0.0:{}", self.config.port),
            IpVersion::V6Only => format!("[::]:{}", self.config.port),
            IpVersion::Any => format!("[::]:{}", self.config.port), // Dual-stack on most systems
        };

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

    /// UDP client mode with encryption
    fn udp_client_encrypted(&self, password: &str) -> Result<(), String> {
        let host = self
            .config
            .host
            .as_ref()
            .ok_or("Host required for client mode")?;
        let addr = format!("{}:{}", host, self.config.port);

        if self.config.verbose {
            eprintln!("[+] UDP client mode (encrypted), sending to {}", addr);
            eprintln!("[*] Cryptcat mode: Twofish-128 encryption enabled");
        }

        let mut client = UdpClient::new()?;
        client.set_timeout(self.config.timeout)?;

        let cipher_send = Arc::new(Mutex::new(TwofishCBC::new(password)));
        let cipher_recv = Arc::new(Mutex::new(TwofishCBC::new(password)));

        let stdin = io::stdin();
        let mut stdin_reader = stdin.lock();

        // Spawn thread to receive and decrypt UDP packets
        let client_clone = UdpClient::new()?;
        let cipher_recv_clone = Arc::clone(&cipher_recv);
        let hex_mode = self.config.hex_dump;
        let verbose = self.config.verbose;

        std::thread::spawn(move || loop {
            match client_clone.recv() {
                Ok((encrypted_data, src)) => {
                    // Decrypt packet
                    match cipher_recv_clone.lock().unwrap().decrypt(&encrypted_data) {
                        Ok(plaintext) => {
                            if hex_mode {
                                eprintln!("[<- from {} (encrypted)]", src);
                                print!("{}", hex_dump(&plaintext));
                            } else {
                                if let Err(_) = io::stdout().write_all(&plaintext) {
                                    break;
                                }
                                let _ = io::stdout().flush();
                            }
                        }
                        Err(e) => {
                            if verbose {
                                eprintln!("[!] Decryption error from {}: {}", src, e);
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        });

        // Read from stdin, encrypt, and send UDP packets
        let mut line = String::new();
        loop {
            line.clear();
            match stdin_reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Encrypt data
                    let ciphertext = cipher_send.lock().unwrap().encrypt(line.as_bytes());

                    if let Err(e) = client.send_to(&ciphertext, &addr) {
                        return Err(format!("Send failed: {}", e));
                    }

                    // Apply delay if configured
                    if let Some(delay) = self.config.delay_ms {
                        std::thread::sleep(Duration::from_millis(delay));
                    }
                }
                Err(e) => return Err(format!("Read from stdin failed: {}", e)),
            }
        }

        Ok(())
    }

    /// UDP server mode with encryption
    fn udp_server_encrypted(&self, password: &str) -> Result<(), String> {
        let addr = match self.config.ip_version {
            IpVersion::V4Only => format!("0.0.0.0:{}", self.config.port),
            IpVersion::V6Only => format!("[::]:{}", self.config.port),
            IpVersion::Any => format!("[::]:{}", self.config.port),
        };

        if self.config.verbose {
            eprintln!("[+] Listening on {} (UDP, encrypted)...", addr);
            eprintln!("[*] Cryptcat mode: Twofish-128 encryption enabled");
        }

        let server = Arc::new(UdpServer::bind(&addr)?);

        if self.config.verbose {
            eprintln!("[+] Waiting for encrypted UDP packets...");
        }

        let cipher_send = Arc::new(Mutex::new(TwofishCBC::new(password)));
        let cipher_recv = Arc::new(Mutex::new(TwofishCBC::new(password)));

        let stdin = io::stdin();
        let mut stdin_reader = stdin.lock();

        // Spawn thread to receive and decrypt UDP packets
        let server_clone = Arc::clone(&server);
        let cipher_recv_clone = Arc::clone(&cipher_recv);
        let destination_addr = Arc::new(Mutex::new(None::<String>));
        let destination_addr_clone = Arc::clone(&destination_addr);
        let hex_mode = self.config.hex_dump;
        let verbose = self.config.verbose;

        std::thread::spawn(move || loop {
            match server_clone.recv_from() {
                Ok((encrypted_data, src)) => {
                    // Remember latest source so the server can reply to it
                    if let Ok(mut dest_lock) = destination_addr_clone.lock() {
                        *dest_lock = Some(src.clone());
                    }

                    // Decrypt packet
                    match cipher_recv_clone.lock().unwrap().decrypt(&encrypted_data) {
                        Ok(plaintext) => {
                            if hex_mode {
                                eprintln!("[<- from {} (encrypted)]", src);
                                print!("{}", hex_dump(&plaintext));
                            } else {
                                if let Err(_) = io::stdout().write_all(&plaintext) {
                                    break;
                                }
                                let _ = io::stdout().flush();
                            }
                        }
                        Err(e) => {
                            if verbose {
                                eprintln!("[!] Decryption error from {}: {}", src, e);
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        });

        // Read from stdin, encrypt, and send UDP packets
        let mut line = String::new();
        loop {
            line.clear();
            match stdin_reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Encrypt data
                    let ciphertext = cipher_send.lock().unwrap().encrypt(line.as_bytes());

                    let destination =
                        { destination_addr.lock().ok().and_then(|guard| guard.clone()) };

                    if let Some(dest) = destination {
                        if let Err(e) = server.send_to(&ciphertext, &dest) {
                            if self.config.verbose {
                                eprintln!(
                                    "[!] Failed to send encrypted UDP packet to {}: {}",
                                    dest, e
                                );
                            }
                        } else if self.config.hex_dump {
                            eprintln!("[-> to {} (encrypted)]", dest);
                            eprintln!("{}", hex_dump(&ciphertext));
                        }
                    } else if self.config.verbose {
                        eprintln!("[!] No UDP client observed yet; waiting for incoming packet before replying");
                    }

                    // Apply delay if configured
                    if let Some(delay) = self.config.delay_ms {
                        std::thread::sleep(Duration::from_millis(delay));
                    }
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
