//! Transparent Proxy - Intercept traffic at the network level
//!
//! This module provides transparent proxy functionality using:
//! - SO_ORIGINAL_DST (Linux NAT redirect mode)
//! - TPROXY (Linux full transparent mode)
//!
//! # How it works
//!
//! ## NAT Redirect Mode (simpler, requires only -j REDIRECT)
//!
//! Traffic is redirected to the proxy port using iptables NAT:
//! ```bash
//! # Redirect all TCP traffic to port 8080
//! iptables -t nat -A PREROUTING -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-port 8080
//!
//! # Or only specific ports
//! iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
//! iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
//! ```
//!
//! The proxy uses SO_ORIGINAL_DST to retrieve the original destination.
//!
//! ## TPROXY Mode (advanced, preserves source IP)
//!
//! ```bash
//! # Mark packets
//! iptables -t mangle -A PREROUTING -p tcp -j TPROXY \
//!     --tproxy-mark 0x1/0x1 --on-port 8080
//!
//! # Route marked packets locally
//! ip rule add fwmark 1 lookup 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//! ```
//!
//! TPROXY mode requires:
//! - IP_TRANSPARENT socket option
//! - CAP_NET_ADMIN capability
//! - Proper routing rules

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::{Address, ConnectionId, FlowStats, Protocol, ProxyContext, ProxyError, ProxyResult};

/// SO_ORIGINAL_DST socket option (Linux specific)
#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: libc::c_int = 80;

/// SO_ORIGINAL_DST for IPv6
#[cfg(target_os = "linux")]
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

/// SOL_IP level
#[cfg(target_os = "linux")]
const SOL_IP: libc::c_int = 0;

/// SOL_IPV6 level
#[cfg(target_os = "linux")]
const SOL_IPV6: libc::c_int = 41;

/// IP_TRANSPARENT option (for TPROXY)
#[cfg(target_os = "linux")]
const IP_TRANSPARENT: libc::c_int = 19;

/// Transparent proxy mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentMode {
    /// NAT redirect mode (uses SO_ORIGINAL_DST)
    Redirect,
    /// TPROXY mode (preserves source IP)
    TProxy,
}

/// Transparent proxy configuration
#[derive(Debug, Clone)]
pub struct TransparentConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Proxy mode
    pub mode: TransparentMode,
    /// Connection timeout
    pub timeout: Duration,
    /// Buffer size for relay
    pub buffer_size: usize,
    /// Whether to intercept TLS (for MITM)
    pub mitm_tls: bool,
}

impl Default for TransparentConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            mode: TransparentMode::Redirect,
            timeout: Duration::from_secs(30),
            buffer_size: 65536,
            mitm_tls: false,
        }
    }
}

impl TransparentConfig {
    /// Create new config with listen address
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            ..Default::default()
        }
    }

    /// Set proxy mode
    pub fn with_mode(mut self, mode: TransparentMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable TLS MITM
    pub fn with_mitm_tls(mut self, enabled: bool) -> Self {
        self.mitm_tls = enabled;
        self
    }
}

/// Transparent proxy server
pub struct TransparentProxy {
    config: TransparentConfig,
    ctx: Arc<ProxyContext>,
    running: Arc<AtomicBool>,
}

impl TransparentProxy {
    /// Create new transparent proxy
    pub fn new(config: TransparentConfig) -> Self {
        Self {
            config,
            ctx: Arc::new(ProxyContext::new()),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create with custom context
    pub fn with_context(config: TransparentConfig, ctx: Arc<ProxyContext>) -> Self {
        Self {
            config,
            ctx,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check if proxy is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the proxy
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get flow stats
    pub fn stats(&self) -> Arc<FlowStats> {
        self.ctx.flow_stats.clone()
    }

    /// Run the transparent proxy
    #[cfg(target_os = "linux")]
    pub fn run(&self) -> ProxyResult<()> {
        let listener = TcpListener::bind(self.config.listen_addr)?;
        listener.set_nonblocking(true)?;

        // For TPROXY mode, set IP_TRANSPARENT
        if self.config.mode == TransparentMode::TProxy {
            set_transparent(&listener)?;
        }

        self.running.store(true, Ordering::Relaxed);

        while self.running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((client, client_addr)) => {
                    // Get original destination
                    let orig_dst = match get_original_dst(&client) {
                        Ok(dst) => dst,
                        Err(e) => {
                            eprintln!("Failed to get original destination: {}", e);
                            continue;
                        }
                    };

                    // Skip if destination is the proxy itself
                    if orig_dst == self.config.listen_addr {
                        continue;
                    }

                    let ctx = self.ctx.clone();
                    let config = self.config.clone();
                    let running = self.running.clone();

                    thread::spawn(move || {
                        if let Err(e) =
                            handle_connection(client, client_addr, orig_dst, ctx, config, running)
                        {
                            eprintln!("Connection error: {}", e);
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    eprintln!("Accept error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Not supported on non-Linux
    #[cfg(not(target_os = "linux"))]
    pub fn run(&self) -> ProxyResult<()> {
        Err(ProxyError::Protocol(
            "Transparent proxy is only supported on Linux".to_string(),
        ))
    }
}

/// Get the original destination address using SO_ORIGINAL_DST
#[cfg(target_os = "linux")]
fn get_original_dst(stream: &TcpStream) -> ProxyResult<SocketAddr> {
    let fd = stream.as_raw_fd();

    // Try IPv4 first
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 {
        let port = u16::from_be(addr.sin_port);
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        return Ok(SocketAddr::new(IpAddr::V4(ip), port));
    }

    // Try IPv6
    let mut addr6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr6 as *mut _ as *mut libc::c_void,
            &mut len6,
        )
    };

    if ret == 0 {
        let port = u16::from_be(addr6.sin6_port);
        let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
        return Ok(SocketAddr::new(IpAddr::V6(ip), port));
    }

    Err(ProxyError::Protocol(
        "Failed to get original destination (is iptables REDIRECT/TPROXY configured?)".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn get_original_dst(_stream: &TcpStream) -> ProxyResult<SocketAddr> {
    Err(ProxyError::Protocol(
        "SO_ORIGINAL_DST is only available on Linux".to_string(),
    ))
}

/// Set IP_TRANSPARENT socket option (for TPROXY)
#[cfg(target_os = "linux")]
fn set_transparent(listener: &TcpListener) -> ProxyResult<()> {
    let fd = listener.as_raw_fd();
    let one: libc::c_int = 1;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_IP,
            IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(ProxyError::Protocol(format!(
            "Failed to set IP_TRANSPARENT: {} (requires CAP_NET_ADMIN)",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_transparent(_listener: &TcpListener) -> ProxyResult<()> {
    Err(ProxyError::Protocol(
        "IP_TRANSPARENT is only available on Linux".to_string(),
    ))
}

/// Handle a transparent proxy connection
fn handle_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    orig_dst: SocketAddr,
    ctx: Arc<ProxyContext>,
    config: TransparentConfig,
    running: Arc<AtomicBool>,
) -> ProxyResult<()> {
    let conn_id = ctx.id_generator.next_tcp();
    ctx.flow_stats.connection_opened(Protocol::Tcp);

    // Connect to original destination
    let mut server = TcpStream::connect_timeout(&orig_dst, config.timeout)?;
    server.set_read_timeout(Some(config.timeout))?;
    server.set_write_timeout(Some(config.timeout))?;
    client.set_read_timeout(Some(config.timeout))?;
    client.set_write_timeout(Some(config.timeout))?;

    // Relay data bidirectionally
    let result = relay_tcp(
        &mut client,
        &mut server,
        config.buffer_size,
        &ctx.flow_stats,
        running,
    );

    ctx.flow_stats.connection_closed();

    result
}

/// Relay TCP data between two streams
fn relay_tcp(
    client: &mut TcpStream,
    server: &mut TcpStream,
    buffer_size: usize,
    stats: &FlowStats,
    running: Arc<AtomicBool>,
) -> ProxyResult<()> {
    // Clone streams for bidirectional relay
    let mut client_read = client.try_clone()?;
    let mut server_read = server.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut server_write = server.try_clone()?;

    // Set non-blocking for relay
    client_read.set_nonblocking(true)?;
    server_read.set_nonblocking(true)?;

    let stats_c2s = Arc::new(AtomicBool::new(true));
    let stats_s2c = stats_c2s.clone();
    let running_c2s = running.clone();
    let running_s2c = Arc::new(AtomicBool::new(true));

    // Client to server relay thread
    let c2s_handle = thread::spawn(move || -> io::Result<u64> {
        let mut buffer = vec![0u8; buffer_size];
        let mut total = 0u64;

        while running_c2s.load(Ordering::Relaxed) {
            match client_read.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    server_write.write_all(&buffer[..n])?;
                    total += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(e),
            }
        }

        stats_c2s.store(false, Ordering::Relaxed);
        Ok(total)
    });

    // Server to client relay
    let mut buffer = vec![0u8; buffer_size];
    let mut total_received = 0u64;

    while running.load(Ordering::Relaxed) && running_s2c.load(Ordering::Relaxed) {
        match server_read.read(&mut buffer) {
            Ok(0) => break, // EOF
            Ok(n) => {
                if client_write.write_all(&buffer[..n]).is_err() {
                    break;
                }
                total_received += n as u64;
                stats.add_received(n as u64);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Check if client->server is still active
                if !stats_s2c.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => break,
        }
    }

    // Wait for client->server thread
    if let Ok(sent) = c2s_handle.join().unwrap_or(Ok(0)) {
        stats.add_sent(sent);
    }

    Ok(())
}

/// Generate iptables rules for transparent proxy
pub fn generate_iptables_rules(port: u16, mode: TransparentMode) -> Vec<String> {
    match mode {
        TransparentMode::Redirect => vec![
            format!("# NAT Redirect mode - redirect TCP to transparent proxy"),
            format!("iptables -t nat -A PREROUTING -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-port {}", port),
            format!(""),
            format!("# Or redirect specific ports only:"),
            format!("# iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {}", port),
            format!("# iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {}", port),
            format!(""),
            format!("# To remove:"),
            format!("# iptables -t nat -D PREROUTING -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-port {}", port),
        ],
        TransparentMode::TProxy => vec![
            format!("# TPROXY mode - full transparent proxy with preserved source IP"),
            format!("# Requires CAP_NET_ADMIN capability"),
            format!(""),
            format!("# Create routing table for marked packets"),
            format!("ip rule add fwmark 1 lookup 100"),
            format!("ip route add local 0.0.0.0/0 dev lo table 100"),
            format!(""),
            format!("# Mark and redirect TCP packets"),
            format!("iptables -t mangle -A PREROUTING -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port {}", port),
            format!(""),
            format!("# For UDP (optional):"),
            format!("# iptables -t mangle -A PREROUTING -p udp -j TPROXY --tproxy-mark 0x1/0x1 --on-port {}", port),
            format!(""),
            format!("# To remove:"),
            format!("# iptables -t mangle -D PREROUTING -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port {}", port),
            format!("# ip rule del fwmark 1 lookup 100"),
            format!("# ip route del local 0.0.0.0/0 dev lo table 100"),
        ],
    }
}

/// Generate nftables rules for transparent proxy
pub fn generate_nftables_rules(port: u16, mode: TransparentMode) -> Vec<String> {
    match mode {
        TransparentMode::Redirect => vec![
            format!("# nftables NAT Redirect mode"),
            format!("nft add table ip nat"),
            format!("nft add chain ip nat prerouting {{ type nat hook prerouting priority -100 \\; }}"),
            format!("nft add rule ip nat prerouting tcp dport {{ 80, 443 }} redirect to :{}", port),
            format!(""),
            format!("# To remove:"),
            format!("# nft delete table ip nat"),
        ],
        TransparentMode::TProxy => vec![
            format!("# nftables TPROXY mode"),
            format!("nft add table ip mangle"),
            format!("nft add chain ip mangle prerouting {{ type filter hook prerouting priority -150 \\; }}"),
            format!("nft add rule ip mangle prerouting tcp dport {{ 80, 443 }} tproxy to :{} mark set 1", port),
            format!(""),
            format!("# Routing (same as iptables):"),
            format!("ip rule add fwmark 1 lookup 100"),
            format!("ip route add local 0.0.0.0/0 dev lo table 100"),
            format!(""),
            format!("# To remove:"),
            format!("# nft delete table ip mangle"),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = TransparentConfig::default();
        assert_eq!(config.listen_addr.port(), 8080);
        assert_eq!(config.mode, TransparentMode::Redirect);
        assert_eq!(config.buffer_size, 65536);
    }

    #[test]
    fn test_config_builder() {
        let config = TransparentConfig::new("0.0.0.0:9999".parse().unwrap())
            .with_mode(TransparentMode::TProxy)
            .with_timeout(Duration::from_secs(60))
            .with_mitm_tls(true);

        assert_eq!(config.listen_addr.port(), 9999);
        assert_eq!(config.mode, TransparentMode::TProxy);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert!(config.mitm_tls);
    }

    #[test]
    fn test_generate_iptables_redirect() {
        let rules = generate_iptables_rules(8080, TransparentMode::Redirect);
        assert!(rules.iter().any(|r| r.contains("REDIRECT")));
        assert!(rules.iter().any(|r| r.contains("8080")));
    }

    #[test]
    fn test_generate_iptables_tproxy() {
        let rules = generate_iptables_rules(8080, TransparentMode::TProxy);
        assert!(rules.iter().any(|r| r.contains("TPROXY")));
        assert!(rules.iter().any(|r| r.contains("fwmark")));
    }

    #[test]
    fn test_generate_nftables() {
        let rules = generate_nftables_rules(8080, TransparentMode::Redirect);
        assert!(rules.iter().any(|r| r.contains("nft")));
        assert!(rules.iter().any(|r| r.contains("redirect")));
    }
}
