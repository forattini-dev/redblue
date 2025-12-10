//! SOCKS5 Protocol Implementation (RFC 1928)
//!
//! Implements the SOCKS Protocol Version 5 from scratch for proxy relay.
//!
//! # Protocol Overview
//!
//! ```text
//! Client                                Server
//!   |                                      |
//!   |------ Method Selection Request ----->|  (Version, NMethods, Methods)
//!   |<----- Method Selection Response -----|  (Version, Method)
//!   |                                      |
//!   |------ [Authentication if needed] --->|  (Username/Password)
//!   |<----- [Authentication Response] -----|  (Status)
//!   |                                      |
//!   |------ Connection Request ----------->|  (Version, Cmd, Addr, Port)
//!   |<----- Connection Response -----------|  (Version, Reply, Addr, Port)
//!   |                                      |
//!   |<============ Data Relay ============>|
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use redblue::modules::proxy::socks5::Socks5Server;
//!
//! let server = Socks5Server::bind("127.0.0.1:1080").await?;
//! server.run().await?;
//! ```

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use super::{Address, ProxyContext, ProxyError, ProxyResult, Protocol};
use crate::{debug, info, error};

/// SOCKS5 version constant
pub const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMethod {
    /// No authentication required
    NoAuth = 0x00,
    /// GSSAPI authentication
    GssApi = 0x01,
    /// Username/password authentication (RFC 1929)
    UsernamePassword = 0x02,
    /// No acceptable methods
    NoAcceptable = 0xFF,
}

impl From<u8> for AuthMethod {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::NoAuth,
            0x01 => Self::GssApi,
            0x02 => Self::UsernamePassword,
            _ => Self::NoAcceptable,
        }
    }
}

/// SOCKS5 command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Establish TCP/IP stream connection
    Connect = 0x01,
    /// Establish TCP/IP port binding
    Bind = 0x02,
    /// Associate UDP port
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = ProxyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            _ => Err(ProxyError::Protocol(format!("Invalid command: {:#x}", value))),
        }
    }
}

/// SOCKS5 address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    /// IPv4 address
    IPv4 = 0x01,
    /// Domain name
    Domain = 0x03,
    /// IPv6 address
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = ProxyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::IPv4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::IPv6),
            _ => Err(ProxyError::Protocol(format!(
                "Invalid address type: {:#x}",
                value
            ))),
        }
    }
}

/// SOCKS5 reply codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    /// Succeeded
    Succeeded = 0x00,
    /// General SOCKS server failure
    GeneralFailure = 0x01,
    /// Connection not allowed by ruleset
    ConnectionNotAllowed = 0x02,
    /// Network unreachable
    NetworkUnreachable = 0x03,
    /// Host unreachable
    HostUnreachable = 0x04,
    /// Connection refused
    ConnectionRefused = 0x05,
    /// TTL expired
    TtlExpired = 0x06,
    /// Command not supported
    CommandNotSupported = 0x07,
    /// Address type not supported
    AddressTypeNotSupported = 0x08,
}

/// Method selection request from client
#[derive(Debug)]
pub struct MethodSelectionRequest {
    pub version: u8,
    pub methods: Vec<AuthMethod>,
}

impl MethodSelectionRequest {
    /// Read method selection request from stream
    pub fn read_from(stream: &mut TcpStream) -> ProxyResult<Self> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header)?;

        let version = header[0];
        let nmethods = header[1] as usize;

        if version != SOCKS5_VERSION {
            return Err(ProxyError::Protocol(format!(
                "Invalid SOCKS version: {}, expected {}",
                version, SOCKS5_VERSION
            )));
        }

        if nmethods == 0 {
            return Err(ProxyError::Protocol("No methods provided".to_string()));
        }

        let mut methods_raw = vec![0u8; nmethods];
        stream.read_exact(&mut methods_raw)?;

        let methods = methods_raw.into_iter().map(AuthMethod::from).collect();

        Ok(Self { version, methods })
    }

    /// Check if method is supported
    pub fn supports(&self, method: AuthMethod) -> bool {
        self.methods.contains(&method)
    }
}

/// Method selection response to client
#[derive(Debug)]
pub struct MethodSelectionResponse {
    pub version: u8,
    pub method: AuthMethod,
}

impl MethodSelectionResponse {
    pub fn new(method: AuthMethod) -> Self {
        Self {
            version: SOCKS5_VERSION,
            method,
        }
    }

    /// Write response to stream
    pub fn write_to(&self, stream: &mut TcpStream) -> ProxyResult<()> {
        let buf = [self.version, self.method as u8];
        stream.write_all(&buf)?;
        stream.flush()?;
        Ok(())
    }
}

/// Username/password authentication request (RFC 1929)
#[derive(Debug)]
pub struct AuthRequest {
    pub version: u8,
    pub username: String,
    pub password: String,
}

impl AuthRequest {
    /// Read auth request from stream
    pub fn read_from(stream: &mut TcpStream) -> ProxyResult<Self> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header)?;

        let version = header[0];
        if version != 0x01 {
            return Err(ProxyError::Protocol(format!(
                "Invalid auth version: {:#x}",
                version
            )));
        }

        let ulen = header[1] as usize;
        let mut username_buf = vec![0u8; ulen];
        stream.read_exact(&mut username_buf)?;
        let username =
            String::from_utf8(username_buf).map_err(|_| ProxyError::Auth("Invalid username encoding".to_string()))?;

        let mut plen_buf = [0u8; 1];
        stream.read_exact(&mut plen_buf)?;
        let plen = plen_buf[0] as usize;

        let mut password_buf = vec![0u8; plen];
        stream.read_exact(&mut password_buf)?;
        let password =
            String::from_utf8(password_buf).map_err(|_| ProxyError::Auth("Invalid password encoding".to_string()))?;

        Ok(Self {
            version,
            username,
            password,
        })
    }
}

/// Authentication response
#[derive(Debug)]
pub struct AuthResponse {
    pub version: u8,
    pub status: u8, // 0x00 = success, any other = failure
}

impl AuthResponse {
    pub fn success() -> Self {
        Self {
            version: 0x01,
            status: 0x00,
        }
    }

    pub fn failure() -> Self {
        Self {
            version: 0x01,
            status: 0x01,
        }
    }

    pub fn write_to(&self, stream: &mut TcpStream) -> ProxyResult<()> {
        let buf = [self.version, self.status];
        stream.write_all(&buf)?;
        stream.flush()?;
        Ok(())
    }
}

/// Connection request from client
#[derive(Debug)]
pub struct ConnectionRequest {
    pub version: u8,
    pub command: Command,
    pub address: Address,
}

impl ConnectionRequest {
    /// Read connection request from stream
    pub fn read_from(stream: &mut TcpStream) -> ProxyResult<Self> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;

        let version = header[0];
        if version != SOCKS5_VERSION {
            return Err(ProxyError::Protocol(format!(
                "Invalid SOCKS version: {}",
                version
            )));
        }

        let command = Command::try_from(header[1])?;
        let _reserved = header[2]; // Must be 0x00
        let addr_type = AddressType::try_from(header[3])?;

        let address = match addr_type {
            AddressType::IPv4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr)?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port)?;
                let port = u16::from_be_bytes(port);
                Address::Socket(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
                    port,
                )))
            }
            AddressType::Domain => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len)?;
                let len = len[0] as usize;

                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain)?;
                let domain = String::from_utf8(domain)
                    .map_err(|_| ProxyError::Protocol("Invalid domain encoding".to_string()))?;

                let mut port = [0u8; 2];
                stream.read_exact(&mut port)?;
                let port = u16::from_be_bytes(port);

                Address::Domain(domain, port)
            }
            AddressType::IPv6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr)?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port)?;
                let port = u16::from_be_bytes(port);
                Address::Socket(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(addr),
                    port,
                    0,
                    0,
                )))
            }
        };

        Ok(Self {
            version,
            command,
            address,
        })
    }
}

/// Connection response to client
#[derive(Debug)]
pub struct ConnectionResponse {
    pub version: u8,
    pub reply: Reply,
    pub bind_addr: Address,
}

impl ConnectionResponse {
    pub fn success(bind_addr: Address) -> Self {
        Self {
            version: SOCKS5_VERSION,
            reply: Reply::Succeeded,
            bind_addr,
        }
    }

    pub fn error(reply: Reply) -> Self {
        Self {
            version: SOCKS5_VERSION,
            reply,
            bind_addr: Address::Socket(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                0,
            ))),
        }
    }

    /// Write response to stream
    pub fn write_to(&self, stream: &mut TcpStream) -> ProxyResult<()> {
        let mut buf = Vec::with_capacity(32);

        buf.push(self.version);
        buf.push(self.reply as u8);
        buf.push(0x00); // Reserved

        match &self.bind_addr {
            Address::Socket(SocketAddr::V4(addr)) => {
                buf.push(AddressType::IPv4 as u8);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::Socket(SocketAddr::V6(addr)) => {
                buf.push(AddressType::IPv6 as u8);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::Domain(domain, port) => {
                buf.push(AddressType::Domain as u8);
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        stream.write_all(&buf)?;
        stream.flush()?;
        Ok(())
    }
}

/// SOCKS5 authentication configuration
#[derive(Debug, Clone)]
pub struct Socks5Auth {
    /// Map of username -> password
    pub credentials: std::collections::HashMap<String, String>,
}

impl Socks5Auth {
    pub fn new() -> Self {
        Self {
            credentials: std::collections::HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.credentials.insert(username.into(), password.into());
    }

    pub fn validate(&self, username: &str, password: &str) -> bool {
        self.credentials
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }
}

impl Default for Socks5Auth {
    fn default() -> Self {
        Self::new()
    }
}

/// SOCKS5 server configuration
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Authentication configuration (None = no auth)
    pub auth: Option<Socks5Auth>,
    /// Connection timeout
    pub timeout: Duration,
    /// Allow UDP associate
    pub allow_udp: bool,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:1080".parse().unwrap(),
            auth: None,
            timeout: Duration::from_secs(30),
            allow_udp: true,
        }
    }
}

/// SOCKS5 proxy server
pub struct Socks5Server {
    config: Socks5Config,
    ctx: Arc<ProxyContext>,
}

impl Socks5Server {
    /// Create new SOCKS5 server with default config
    pub fn new(ctx: Arc<ProxyContext>) -> Self {
        Self {
            config: Socks5Config::default(),
            ctx,
        }
    }

    /// Create server with custom config
    pub fn with_config(config: Socks5Config, ctx: Arc<ProxyContext>) -> Self {
        Self { config, ctx }
    }

    /// Bind to address and create server
    pub fn bind(addr: SocketAddr, ctx: Arc<ProxyContext>) -> ProxyResult<Self> {
        let mut config = Socks5Config::default();
        config.listen_addr = addr;
        Ok(Self::with_config(config, ctx))
    }

    /// Run the SOCKS5 server (blocking)
    pub fn run(&self) -> ProxyResult<()> {
        let listener = TcpListener::bind(self.config.listen_addr)?;
        listener.set_nonblocking(false)?;

        info!("SOCKS5 server listening on {}", self.config.listen_addr);

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let ctx = self.ctx.clone();
                    let config = self.config.clone();
                    let peer_addr = stream.peer_addr().ok();

                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(stream, config, ctx, peer_addr) {
                            debug!("SOCKS5 connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle a single SOCKS5 connection
    fn handle_connection(
        mut stream: TcpStream,
        config: Socks5Config,
        ctx: Arc<ProxyContext>,
        peer_addr: Option<SocketAddr>,
    ) -> ProxyResult<()> {
        stream.set_read_timeout(Some(config.timeout))?;
        stream.set_write_timeout(Some(config.timeout))?;

        // Step 1: Method selection
        let method_req = MethodSelectionRequest::read_from(&mut stream)?;

        let selected_method = if config.auth.is_some() {
            if method_req.supports(AuthMethod::UsernamePassword) {
                AuthMethod::UsernamePassword
            } else {
                AuthMethod::NoAcceptable
            }
        } else if method_req.supports(AuthMethod::NoAuth) {
            AuthMethod::NoAuth
        } else {
            AuthMethod::NoAcceptable
        };

        MethodSelectionResponse::new(selected_method).write_to(&mut stream)?;

        if selected_method == AuthMethod::NoAcceptable {
            return Err(ProxyError::Auth("No acceptable authentication method".to_string()));
        }

        // Step 2: Authentication (if required)
        if selected_method == AuthMethod::UsernamePassword {
            let auth_req = AuthRequest::read_from(&mut stream)?;
            let auth = config.auth.as_ref().unwrap();

            if auth.validate(&auth_req.username, &auth_req.password) {
                AuthResponse::success().write_to(&mut stream)?;
                debug!("User '{}' authenticated", auth_req.username);
            } else {
                AuthResponse::failure().write_to(&mut stream)?;
                return Err(ProxyError::Auth(format!(
                    "Invalid credentials for user '{}'",
                    auth_req.username
                )));
            }
        }

        // Step 3: Connection request
        let conn_req = ConnectionRequest::read_from(&mut stream)?;

        match conn_req.command {
            Command::Connect => {
                Self::handle_connect(stream, conn_req.address, ctx, peer_addr)
            }
            Command::Bind => {
                ConnectionResponse::error(Reply::CommandNotSupported).write_to(&mut stream)?;
                Err(ProxyError::Protocol("BIND command not supported".to_string()))
            }
            Command::UdpAssociate => {
                if config.allow_udp {
                    Self::handle_udp_associate(stream, ctx, peer_addr)
                } else {
                    ConnectionResponse::error(Reply::CommandNotSupported).write_to(&mut stream)?;
                    Err(ProxyError::Protocol("UDP ASSOCIATE not allowed".to_string()))
                }
            }
        }
    }

    /// Handle CONNECT command (TCP relay)
    fn handle_connect(
        mut client: TcpStream,
        target: Address,
        ctx: Arc<ProxyContext>,
        peer_addr: Option<SocketAddr>,
    ) -> ProxyResult<()> {
        let conn_id = ctx.id_generator.next_tcp();

        info!(
            "[{}] CONNECT {} -> {}",
            conn_id,
            peer_addr.map(|a| a.to_string()).unwrap_or_default(),
            target
        );

        // Resolve address if domain
        let target_addr = match &target {
            Address::Socket(addr) => *addr,
            Address::Domain(domain, port) => {
                use std::net::ToSocketAddrs;
                format!("{}:{}", domain, port)
                    .to_socket_addrs()
                    .map_err(|_| ProxyError::ResolutionFailed(domain.clone()))?
                    .next()
                    .ok_or_else(|| ProxyError::ResolutionFailed(domain.clone()))?
            }
        };

        // Connect to target
        let mut server = match TcpStream::connect_timeout(&target_addr, Duration::from_secs(10)) {
            Ok(stream) => stream,
            Err(e) => {
                let reply = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                    std::io::ErrorKind::TimedOut => Reply::HostUnreachable,
                    _ => Reply::GeneralFailure,
                };
                ConnectionResponse::error(reply).write_to(&mut client)?;
                return Err(ProxyError::Io(e));
            }
        };

        // Get bound address
        let bind_addr = server
            .local_addr()
            .map(Address::Socket)
            .unwrap_or_else(|_| Address::from_socket("0.0.0.0:0".parse().unwrap()));

        // Send success response
        ConnectionResponse::success(bind_addr).write_to(&mut client)?;

        // Update stats
        ctx.flow_stats.connection_opened(Protocol::Tcp);

        // Start relay
        let result = super::relay::tcp::relay_bidirectional(
            &mut client,
            &mut server,
            &ctx.flow_stats,
        );

        ctx.flow_stats.connection_closed();

        match result {
            Ok((sent, recv)) => {
                info!("[{}] Closed: {} bytes sent, {} bytes received", conn_id, sent, recv);
                Ok(())
            }
            Err(e) => {
                debug!("[{}] Relay error: {}", conn_id, e);
                Err(ProxyError::Io(e))
            }
        }
    }

    /// Handle UDP ASSOCIATE command - Full relay implementation
    fn handle_udp_associate(
        mut client: TcpStream,
        ctx: Arc<ProxyContext>,
        peer_addr: Option<SocketAddr>,
    ) -> ProxyResult<()> {
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let conn_id = ctx.id_generator.next_udp();
        let client_ip = peer_addr.map(|a| a.ip());

        info!(
            "[{}] UDP ASSOCIATE from {}",
            conn_id,
            peer_addr.map(|a| a.to_string()).unwrap_or_default()
        );

        // Bind UDP socket for relay
        let udp_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        udp_socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let udp_addr = udp_socket.local_addr()?;

        // Send response with UDP relay address
        ConnectionResponse::success(Address::Socket(udp_addr)).write_to(&mut client)?;

        ctx.flow_stats.connection_opened(Protocol::Udp);

        // Flag to signal shutdown
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        // Thread to monitor TCP connection (controls UDP lifetime)
        let tcp_monitor = thread::spawn(move || {
            let mut buf = [0u8; 1];
            client.set_read_timeout(Some(Duration::from_millis(500))).ok();
            loop {
                match client.read(&mut buf) {
                    Ok(0) => break, // Client closed
                    Ok(_) => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(_) => break,
                }
            }
            running_clone.store(false, Ordering::Relaxed);
        });

        // UDP relay loop
        let mut buf = [0u8; 65535];
        let mut client_addr: Option<SocketAddr> = None;
        // Map destination -> dedicated socket for that destination
        let mut dest_sockets: HashMap<SocketAddr, std::net::UdpSocket> = HashMap::new();

        while running.load(Ordering::Relaxed) {
            // Receive from client or any destination
            match udp_socket.recv_from(&mut buf) {
                Ok((n, from_addr)) => {
                    // Check if this is from our client
                    let is_from_client = client_ip.map(|ip| from_addr.ip() == ip).unwrap_or(true);

                    if is_from_client && client_addr.is_none() {
                        client_addr = Some(from_addr);
                        debug!("[{}] UDP client registered: {}", conn_id, from_addr);
                    }

                    if is_from_client {
                        // Parse SOCKS5 UDP header and forward to destination
                        if let Some((dest, payload)) = Self::parse_udp_request(&buf[..n]) {
                            debug!("[{}] UDP {} -> {} ({} bytes)", conn_id, from_addr, dest, payload.len());

                            // Get or create socket for this destination
                            let dest_socket = dest_sockets.entry(dest).or_insert_with(|| {
                                let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
                                sock.set_read_timeout(Some(Duration::from_millis(100))).ok();
                                sock.connect(&dest).ok();
                                sock
                            });

                            // Forward to destination
                            if let Err(e) = dest_socket.send(payload) {
                                debug!("[{}] UDP send error: {}", conn_id, e);
                            }

                            ctx.flow_stats.add_sent(payload.len() as u64);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    debug!("[{}] UDP recv error: {}", conn_id, e);
                }
            }

            // Check for responses from destinations
            for (dest, sock) in dest_sockets.iter() {
                let mut resp_buf = [0u8; 65535];
                match sock.recv(&mut resp_buf) {
                    Ok(n) if n > 0 => {
                        if let Some(client) = client_addr {
                            // Wrap response in SOCKS5 UDP header
                            let response = Self::build_udp_response(*dest, &resp_buf[..n]);
                            debug!("[{}] UDP {} <- {} ({} bytes)", conn_id, client, dest, n);

                            if let Err(e) = udp_socket.send_to(&response, client) {
                                debug!("[{}] UDP response error: {}", conn_id, e);
                            }

                            ctx.flow_stats.add_received(n as u64);
                        }
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => {}
                }
            }
        }

        // Cleanup
        let _ = tcp_monitor.join();
        ctx.flow_stats.connection_closed();
        info!("[{}] UDP ASSOCIATE closed ({} destinations)", conn_id, dest_sockets.len());

        Ok(())
    }

    /// Parse SOCKS5 UDP request header
    /// Format: +----+------+------+----------+----------+----------+
    ///         |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    ///         +----+------+------+----------+----------+----------+
    ///         | 2  |  1   |  1   | Variable |    2     | Variable |
    fn parse_udp_request(data: &[u8]) -> Option<(SocketAddr, &[u8])> {
        if data.len() < 10 {
            return None;
        }

        // RSV (2 bytes) + FRAG (1 byte)
        let _rsv = u16::from_be_bytes([data[0], data[1]]);
        let frag = data[2];

        // We don't support fragmentation
        if frag != 0 {
            return None;
        }

        let atyp = data[3];
        let (addr, header_len) = match atyp {
            0x01 => {
                // IPv4
                if data.len() < 10 {
                    return None;
                }
                let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                let port = u16::from_be_bytes([data[8], data[9]]);
                (SocketAddr::V4(SocketAddrV4::new(ip, port)), 10)
            }
            0x04 => {
                // IPv6
                if data.len() < 22 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[20], data[21]]);
                (SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)), 22)
            }
            0x03 => {
                // Domain name - resolve it
                let domain_len = data[4] as usize;
                if data.len() < 7 + domain_len {
                    return None;
                }
                let domain = std::str::from_utf8(&data[5..5 + domain_len]).ok()?;
                let port = u16::from_be_bytes([data[5 + domain_len], data[6 + domain_len]]);

                // Resolve domain
                use std::net::ToSocketAddrs;
                let addr_str = format!("{}:{}", domain, port);
                let addr = addr_str.to_socket_addrs().ok()?.next()?;
                (addr, 7 + domain_len)
            }
            _ => return None,
        };

        Some((addr, &data[header_len..]))
    }

    /// Build SOCKS5 UDP response header
    fn build_udp_response(from: SocketAddr, data: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(10 + data.len());

        // RSV (2 bytes)
        response.push(0x00);
        response.push(0x00);

        // FRAG (1 byte)
        response.push(0x00);

        match from {
            SocketAddr::V4(addr) => {
                response.push(0x01); // ATYP = IPv4
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                response.push(0x04); // ATYP = IPv6
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        // Data
        response.extend_from_slice(data);

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_from_u8() {
        assert_eq!(AuthMethod::from(0x00), AuthMethod::NoAuth);
        assert_eq!(AuthMethod::from(0x02), AuthMethod::UsernamePassword);
        assert_eq!(AuthMethod::from(0x99), AuthMethod::NoAcceptable);
    }

    #[test]
    fn test_command_try_from() {
        assert_eq!(Command::try_from(0x01).unwrap(), Command::Connect);
        assert_eq!(Command::try_from(0x02).unwrap(), Command::Bind);
        assert_eq!(Command::try_from(0x03).unwrap(), Command::UdpAssociate);
        assert!(Command::try_from(0x99).is_err());
    }

    #[test]
    fn test_socks5_auth() {
        let mut auth = Socks5Auth::new();
        auth.add_user("admin", "secret");

        assert!(auth.validate("admin", "secret"));
        assert!(!auth.validate("admin", "wrong"));
        assert!(!auth.validate("unknown", "secret"));
    }

    #[test]
    fn test_connection_response_serialization() {
        let resp = ConnectionResponse::success(Address::from_socket(
            "192.168.1.1:8080".parse().unwrap(),
        ));
        assert_eq!(resp.reply, Reply::Succeeded);
    }
}
