//! Proxy Module - TCP/UDP/TLS Relay & MITM Interception
//!
//! This module provides comprehensive proxy capabilities for penetration testing:
//! - SOCKS5 proxy (RFC 1928)
//! - HTTP CONNECT proxy
//! - Transparent proxy (TPROXY/redirect)
//! - MITM TLS interception
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Proxy Server                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
//! │  │  SOCKS5  │  │   HTTP   │  │ Transp.  │  │   MITM   │   │
//! │  │  Server  │  │  Proxy   │  │  Proxy   │  │  Proxy   │   │
//! │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
//! │       └──────────────┴──────────────┴──────────────┘        │
//! │                         │                                   │
//! │              ┌──────────▼──────────┐                       │
//! │              │   Connection Pool   │                       │
//! │              │  + Flow Statistics  │                       │
//! │              └──────────┬──────────┘                       │
//! │                         │                                   │
//! │       ┌─────────────────┼─────────────────┐                │
//! │       ▼                 ▼                 ▼                │
//! │  ┌─────────┐      ┌─────────┐      ┌─────────┐            │
//! │  │TCP Relay│      │UDP Relay│      │TLS Term.│            │
//! │  └─────────┘      └─────────┘      └─────────┘            │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```bash
//! # Start SOCKS5 proxy
//! rb proxy socks5 start --port 1080
//!
//! # Start HTTP proxy
//! rb proxy http start --port 8080
//!
//! # Start MITM proxy (intercepts TLS)
//! rb proxy mitm start --port 8080 --ca-cert ca.pem
//! ```

pub mod acl;
pub mod http;
#[cfg(not(target_os = "windows"))]
pub mod mitm;
pub mod relay;
pub mod shell;
pub mod socks5;
pub mod stream;
pub mod tracking;
pub mod transparent;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Connection identifier (unique per connection)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Create new TCP connection ID (even numbers)
    pub fn new_tcp(id: u64) -> Self {
        Self(id << 1)
    }

    /// Create new UDP connection ID (odd numbers)
    pub fn new_udp(id: u64) -> Self {
        Self((id << 1) | 1)
    }

    /// Check if this is a TCP connection
    pub fn is_tcp(&self) -> bool {
        self.0 & 1 == 0
    }

    /// Check if this is a UDP connection
    pub fn is_udp(&self) -> bool {
        self.0 & 1 == 1
    }

    /// Get the raw ID value
    pub fn raw(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto = if self.is_tcp() { "TCP" } else { "UDP" };
        write!(f, "{}:{}", proto, self.0 >> 1)
    }
}

/// Connection ID generator (thread-safe)
pub struct ConnectionIdGenerator {
    next_tcp: AtomicU64,
    next_udp: AtomicU64,
}

impl ConnectionIdGenerator {
    pub fn new() -> Self {
        Self {
            next_tcp: AtomicU64::new(0),
            next_udp: AtomicU64::new(0),
        }
    }

    pub fn next_tcp(&self) -> ConnectionId {
        let id = self.next_tcp.fetch_add(1, Ordering::Relaxed);
        ConnectionId::new_tcp(id)
    }

    pub fn next_udp(&self) -> ConnectionId {
        let id = self.next_udp.fetch_add(1, Ordering::Relaxed);
        ConnectionId::new_udp(id)
    }
}

impl Default for ConnectionIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Target address (can be IP or domain)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// IPv4 or IPv6 socket address
    Socket(SocketAddr),
    /// Domain name with port
    Domain(String, u16),
}

impl Address {
    /// Create from socket address
    pub fn from_socket(addr: SocketAddr) -> Self {
        Self::Socket(addr)
    }

    /// Create from domain and port
    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Self::Domain(domain.into(), port)
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        match self {
            Self::Socket(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    /// Get host string
    pub fn host(&self) -> String {
        match self {
            Self::Socket(addr) => addr.ip().to_string(),
            Self::Domain(domain, _) => domain.clone(),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(addr) => write!(f, "{}", addr),
            Self::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

/// Connection protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is active and relaying data
    Active,
    /// Connection is closing
    Closing,
    /// Connection is closed
    Closed,
}

/// Process information (for connection tracking)
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: Option<String>,
}

/// Connection information
#[derive(Debug)]
pub struct ConnectionInfo {
    pub id: ConnectionId,
    pub src_addr: SocketAddr,
    pub dst_addr: Address,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub started_at: Instant,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub process_info: Option<ProcessInfo>,
}

impl ConnectionInfo {
    pub fn new(
        id: ConnectionId,
        src_addr: SocketAddr,
        dst_addr: Address,
        protocol: Protocol,
    ) -> Self {
        Self {
            id,
            src_addr,
            dst_addr,
            protocol,
            state: ConnectionState::Connecting,
            started_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            process_info: None,
        }
    }

    /// Add bytes sent
    pub fn add_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add bytes received
    pub fn add_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get total bytes sent
    pub fn total_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    pub fn total_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get connection duration
    pub fn duration(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

/// Flow statistics for the proxy
#[derive(Debug, Default)]
pub struct FlowStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub total_bytes_sent: AtomicU64,
    pub total_bytes_received: AtomicU64,
    pub tcp_connections: AtomicU64,
    pub udp_connections: AtomicU64,
}

impl FlowStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn connection_opened(&self, protocol: Protocol) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        match protocol {
            Protocol::Tcp => self.tcp_connections.fetch_add(1, Ordering::Relaxed),
            Protocol::Udp => self.udp_connections.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_sent(&self, bytes: u64) {
        self.total_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_received(&self, bytes: u64) {
        self.total_bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn summary(&self) -> FlowStatsSummary {
        FlowStatsSummary {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
            total_bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
            tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            udp_connections: self.udp_connections.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of flow statistics
#[derive(Debug, Clone)]
pub struct FlowStatsSummary {
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub tcp_connections: u64,
    pub udp_connections: u64,
}

/// Proxy server context (shared across all handlers)
pub struct ProxyContext {
    pub id_generator: ConnectionIdGenerator,
    pub flow_stats: Arc<FlowStats>,
    pub acl: Option<Arc<acl::AccessControl>>,
}

impl ProxyContext {
    pub fn new() -> Self {
        Self {
            id_generator: ConnectionIdGenerator::new(),
            flow_stats: Arc::new(FlowStats::new()),
            acl: None,
        }
    }

    pub fn with_acl(mut self, acl: acl::AccessControl) -> Self {
        self.acl = Some(Arc::new(acl));
        self
    }
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Proxy error types
#[derive(Debug)]
pub enum ProxyError {
    /// IO error
    Io(std::io::Error),
    /// Protocol error
    Protocol(String),
    /// Authentication error
    Auth(String),
    /// Connection refused by ACL
    AccessDenied(String),
    /// Connection timeout
    Timeout,
    /// Address resolution failed
    ResolutionFailed(String),
    /// TLS error
    Tls(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            Self::Auth(msg) => write!(f, "Authentication error: {}", msg),
            Self::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
            Self::Timeout => write!(f, "Connection timeout"),
            Self::ResolutionFailed(host) => write!(f, "Failed to resolve: {}", host),
            Self::Tls(msg) => write!(f, "TLS error: {}", msg),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Result type for proxy operations
pub type ProxyResult<T> = Result<T, ProxyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_tcp() {
        let id = ConnectionId::new_tcp(42);
        assert!(id.is_tcp());
        assert!(!id.is_udp());
        assert_eq!(format!("{}", id), "TCP:42");
    }

    #[test]
    fn test_connection_id_udp() {
        let id = ConnectionId::new_udp(42);
        assert!(!id.is_tcp());
        assert!(id.is_udp());
        assert_eq!(format!("{}", id), "UDP:42");
    }

    #[test]
    fn test_connection_id_generator() {
        let gen = ConnectionIdGenerator::new();
        let tcp1 = gen.next_tcp();
        let tcp2 = gen.next_tcp();
        let udp1 = gen.next_udp();

        assert!(tcp1.is_tcp());
        assert!(tcp2.is_tcp());
        assert!(udp1.is_udp());
        assert_ne!(tcp1, tcp2);
    }

    #[test]
    fn test_address_display() {
        let socket = Address::from_socket("127.0.0.1:8080".parse().unwrap());
        assert_eq!(format!("{}", socket), "127.0.0.1:8080");

        let domain = Address::from_domain("example.com", 443);
        assert_eq!(format!("{}", domain), "example.com:443");
    }

    #[test]
    fn test_flow_stats() {
        let stats = FlowStats::new();
        stats.connection_opened(Protocol::Tcp);
        stats.connection_opened(Protocol::Udp);
        stats.add_sent(100);
        stats.add_received(200);

        let summary = stats.summary();
        assert_eq!(summary.total_connections, 2);
        assert_eq!(summary.active_connections, 2);
        assert_eq!(summary.tcp_connections, 1);
        assert_eq!(summary.udp_connections, 1);
        assert_eq!(summary.total_bytes_sent, 100);
        assert_eq!(summary.total_bytes_received, 200);
    }
}
