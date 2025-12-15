//! DNS Server Implementation
//!
//! A DNS server with hijacking capabilities for MITM attacks.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::cache::{CacheEntry, DnsCache};
use super::resolver::UpstreamResolver;
use super::rules::{DnsRule, RuleMatch, RulesEngine};

/// DNS record types
pub mod record_type {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const ANY: u16 = 255;
}

/// DNS response codes
pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const FORMERR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;
}

/// DNS server configuration
#[derive(Debug, Clone)]
pub struct DnsServerConfig {
    /// Bind address for UDP
    pub bind_udp: SocketAddr,
    /// Bind address for TCP
    pub bind_tcp: SocketAddr,
    /// Upstream resolver
    pub upstream: String,
    /// Secondary upstream (fallback)
    pub upstream_secondary: Option<String>,
    /// Enable caching
    pub enable_cache: bool,
    /// Enable TCP server
    pub enable_tcp: bool,
    /// Query timeout
    pub timeout: Duration,
    /// Log queries
    pub log_queries: bool,
}

impl Default for DnsServerConfig {
    fn default() -> Self {
        Self {
            bind_udp: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53),
            bind_tcp: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53),
            upstream: "8.8.8.8".to_string(),
            upstream_secondary: Some("1.1.1.1".to_string()),
            enable_cache: true,
            enable_tcp: true,
            timeout: Duration::from_secs(5),
            log_queries: false,
        }
    }
}

impl DnsServerConfig {
    /// Set bind address
    pub fn with_bind(mut self, addr: &str) -> Self {
        if let Ok(addr) = addr.parse() {
            self.bind_udp = addr;
            self.bind_tcp = addr;
        }
        self
    }

    /// Set upstream DNS server
    pub fn with_upstream(mut self, upstream: &str) -> Self {
        self.upstream = upstream.to_string();
        self
    }

    /// Add a DNS hijacking rule
    pub fn with_rule(self, _rule: DnsRule) -> Self {
        // Rules are added via DnsServer::add_rule()
        self
    }

    /// Enable/disable caching
    pub fn with_cache(mut self, enable: bool) -> Self {
        self.enable_cache = enable;
        self
    }

    /// Enable/disable TCP
    pub fn with_tcp(mut self, enable: bool) -> Self {
        self.enable_tcp = enable;
        self
    }

    /// Enable query logging
    pub fn with_logging(mut self, enable: bool) -> Self {
        self.log_queries = enable;
        self
    }
}

/// DNS server statistics
#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    pub queries_received: u64,
    pub queries_forwarded: u64,
    pub queries_cached: u64,
    pub queries_hijacked: u64,
    pub queries_blocked: u64,
    pub errors: u64,
}

/// DNS Server
pub struct DnsServer {
    config: DnsServerConfig,
    rules: Arc<RulesEngine>,
    cache: Arc<DnsCache>,
    resolver: Arc<UpstreamResolver>,
    running: Arc<AtomicBool>,
    stats: Arc<std::sync::RwLock<ServerStats>>,
}

impl DnsServer {
    /// Create new DNS server
    pub fn new(config: DnsServerConfig) -> Self {
        let resolver = if let Some(ref secondary) = config.upstream_secondary {
            UpstreamResolver::with_fallback(&config.upstream, secondary)
                .unwrap_or_else(|_| UpstreamResolver::default())
        } else {
            UpstreamResolver::new(&config.upstream).unwrap_or_else(|_| UpstreamResolver::default())
        };

        Self {
            config,
            rules: Arc::new(RulesEngine::new()),
            cache: Arc::new(DnsCache::new()),
            resolver: Arc::new(resolver),
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(std::sync::RwLock::new(ServerStats::default())),
        }
    }

    /// Add a hijacking rule
    pub fn add_rule(&mut self, rule: DnsRule) {
        if let Some(rules) = Arc::get_mut(&mut self.rules) {
            rules.add_rule(rule);
        }
    }

    /// Add multiple rules
    pub fn add_rules(&mut self, rules: Vec<DnsRule>) {
        if let Some(engine) = Arc::get_mut(&mut self.rules) {
            engine.add_rules(rules);
        }
    }

    /// Get server statistics
    pub fn stats(&self) -> ServerStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop the server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Run the DNS server
    pub fn run(&self) -> Result<(), String> {
        self.running.store(true, Ordering::SeqCst);

        // Start UDP server
        let udp_socket = UdpSocket::bind(self.config.bind_udp)
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        udp_socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();

        // Start TCP server if enabled
        let tcp_listener = if self.config.enable_tcp {
            Some(
                TcpListener::bind(self.config.bind_tcp)
                    .map_err(|e| format!("Failed to bind TCP socket: {}", e))?,
            )
        } else {
            None
        };

        if let Some(ref listener) = tcp_listener {
            listener.set_nonblocking(true).ok();
        }

        println!(
            "[DNS] Server listening on UDP {} (TCP: {})",
            self.config.bind_udp,
            if self.config.enable_tcp {
                self.config.bind_tcp.to_string()
            } else {
                "disabled".to_string()
            }
        );
        println!(
            "[DNS] Upstream: {} (fallback: {})",
            self.config.upstream,
            self.config.upstream_secondary.as_deref().unwrap_or("none")
        );
        println!("[DNS] Rules: {}", self.rules.len());

        // Main loop
        while self.running.load(Ordering::SeqCst) {
            // Handle UDP queries
            let mut buffer = [0u8; 512];
            match udp_socket.recv_from(&mut buffer) {
                Ok((len, src)) => {
                    let query = buffer[..len].to_vec();
                    let socket = udp_socket.try_clone().ok();
                    let server = self.clone_internals();

                    thread::spawn(move || {
                        if let Some(socket) = socket {
                            server.handle_udp_query(&socket, &query, src);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Timeout, continue
                }
                Err(e) => {
                    if self.config.log_queries {
                        eprintln!("[DNS] UDP receive error: {}", e);
                    }
                }
            }

            // Handle TCP connections
            if let Some(ref listener) = tcp_listener {
                match listener.accept() {
                    Ok((stream, _src)) => {
                        let server = self.clone_internals();
                        thread::spawn(move || {
                            server.handle_tcp_connection(stream);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No connection, continue
                    }
                    Err(e) => {
                        if self.config.log_queries {
                            eprintln!("[DNS] TCP accept error: {}", e);
                        }
                    }
                }
            }
        }

        println!("[DNS] Server stopped");
        Ok(())
    }

    /// Clone internals for thread handling
    fn clone_internals(&self) -> DnsServerInner {
        DnsServerInner {
            config: self.config.clone(),
            rules: Arc::clone(&self.rules),
            cache: Arc::clone(&self.cache),
            resolver: Arc::clone(&self.resolver),
            stats: Arc::clone(&self.stats),
        }
    }
}

/// Internal server state for thread handling
struct DnsServerInner {
    config: DnsServerConfig,
    rules: Arc<RulesEngine>,
    cache: Arc<DnsCache>,
    resolver: Arc<UpstreamResolver>,
    stats: Arc<std::sync::RwLock<ServerStats>>,
}

impl DnsServerInner {
    /// Handle UDP query
    fn handle_udp_query(&self, socket: &UdpSocket, query: &[u8], src: SocketAddr) {
        self.increment_stat(|s| s.queries_received += 1);

        match self.process_query(query) {
            Ok(response) => {
                if let Err(e) = socket.send_to(&response, src) {
                    if self.config.log_queries {
                        eprintln!("[DNS] Failed to send response: {}", e);
                    }
                    self.increment_stat(|s| s.errors += 1);
                }
            }
            Err(e) => {
                if self.config.log_queries {
                    eprintln!("[DNS] Query processing error: {}", e);
                }
                self.increment_stat(|s| s.errors += 1);

                // Send SERVFAIL
                if let Ok(response) = self.build_error_response(query, rcode::SERVFAIL) {
                    let _ = socket.send_to(&response, src);
                }
            }
        }
    }

    /// Handle TCP connection
    fn handle_tcp_connection(&self, mut stream: TcpStream) {
        stream.set_read_timeout(Some(self.config.timeout)).ok();
        stream.set_write_timeout(Some(self.config.timeout)).ok();

        loop {
            // Read length prefix
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).is_err() {
                break;
            }

            let query_len = u16::from_be_bytes(len_buf) as usize;
            if query_len > 65535 || query_len < 12 {
                break;
            }

            // Read query
            let mut query = vec![0u8; query_len];
            if stream.read_exact(&mut query).is_err() {
                break;
            }

            self.increment_stat(|s| s.queries_received += 1);

            // Process query
            let response = match self.process_query(&query) {
                Ok(r) => r,
                Err(_) => match self.build_error_response(&query, rcode::SERVFAIL) {
                    Ok(r) => r,
                    Err(_) => break,
                },
            };

            // Send response with length prefix
            let len_bytes = (response.len() as u16).to_be_bytes();
            if stream.write_all(&len_bytes).is_err() {
                break;
            }
            if stream.write_all(&response).is_err() {
                break;
            }
        }
    }

    /// Process a DNS query
    fn process_query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        // Parse query
        let (domain, qtype) = self.parse_query(query)?;

        if self.config.log_queries {
            println!("[DNS] Query: {} (type {})", domain, qtype);
        }

        // Check rules
        match self.rules.match_domain(&domain, qtype) {
            RuleMatch::Override(ip) => {
                if self.config.log_queries {
                    println!("[DNS] Hijack: {} -> {}", domain, ip);
                }
                self.increment_stat(|s| s.queries_hijacked += 1);
                return self.build_override_response(query, &domain, qtype, ip);
            }
            RuleMatch::Block => {
                if self.config.log_queries {
                    println!("[DNS] Block: {}", domain);
                }
                self.increment_stat(|s| s.queries_blocked += 1);
                return self.build_error_response(query, rcode::NXDOMAIN);
            }
            RuleMatch::Redirect(target) => {
                if self.config.log_queries {
                    println!("[DNS] Redirect: {} -> {}", domain, target);
                }
                // Resolve the target domain instead
                return self.forward_query_for_domain(query, &target, qtype);
            }
            RuleMatch::Forward(upstream) => {
                if self.config.log_queries {
                    println!("[DNS] Forward: {} via {}", domain, upstream);
                }
                return self.forward_to_specific(query, &upstream);
            }
            RuleMatch::Allow | RuleMatch::None => {
                // Continue to cache/forward
            }
        }

        // Check cache
        if self.config.enable_cache {
            if let Some(entry) = self.cache.get(&domain, qtype) {
                if self.config.log_queries {
                    println!("[DNS] Cache hit: {}", domain);
                }
                self.increment_stat(|s| s.queries_cached += 1);
                return self.build_cached_response(query, &entry);
            }
        }

        // Forward to upstream
        self.increment_stat(|s| s.queries_forwarded += 1);
        let response = self.resolver.resolve(query)?;

        // Cache the response
        if self.config.enable_cache {
            self.cache_response(&domain, qtype, &response);
        }

        Ok(response)
    }

    /// Parse DNS query to extract domain and type
    fn parse_query(&self, query: &[u8]) -> Result<(String, u16), String> {
        if query.len() < 12 {
            return Err("Query too short".to_string());
        }

        // Skip header (12 bytes), parse QNAME
        let mut pos = 12;
        let mut domain_parts = Vec::new();

        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + len > query.len() {
                return Err("Invalid domain name".to_string());
            }
            let part = String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]).to_string();
            domain_parts.push(part);
            pos += 1 + len;
        }

        if pos + 4 > query.len() {
            return Err("Missing QTYPE/QCLASS".to_string());
        }

        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
        let domain = domain_parts.join(".");

        Ok((domain, qtype))
    }

    /// Build override response with hijacked IP
    fn build_override_response(
        &self,
        query: &[u8],
        domain: &str,
        qtype: u16,
        ip: IpAddr,
    ) -> Result<Vec<u8>, String> {
        let mut response = Vec::with_capacity(512);

        // Copy transaction ID
        response.extend_from_slice(&query[0..2]);

        // Flags: QR=1, AA=1, RD=1, RA=1, RCODE=0
        response.push(0x84); // QR=1, Opcode=0, AA=1, TC=0, RD=0
        response.push(0x00); // RA=0, Z=0, RCODE=0

        // QDCOUNT = 1
        response.push(0x00);
        response.push(0x01);

        // ANCOUNT = 1
        response.push(0x00);
        response.push(0x01);

        // NSCOUNT = 0
        response.push(0x00);
        response.push(0x00);

        // ARCOUNT = 0
        response.push(0x00);
        response.push(0x00);

        // Copy question section
        self.encode_domain(&mut response, domain);
        response.extend_from_slice(&qtype.to_be_bytes());
        response.push(0x00);
        response.push(0x01); // IN class

        // Answer section
        self.encode_domain(&mut response, domain);

        match ip {
            IpAddr::V4(ipv4) => {
                response.extend_from_slice(&record_type::A.to_be_bytes());
                response.push(0x00);
                response.push(0x01); // IN class
                response.extend_from_slice(&300u32.to_be_bytes()); // TTL
                response.push(0x00);
                response.push(0x04); // RDLENGTH
                response.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                response.extend_from_slice(&record_type::AAAA.to_be_bytes());
                response.push(0x00);
                response.push(0x01); // IN class
                response.extend_from_slice(&300u32.to_be_bytes()); // TTL
                response.push(0x00);
                response.push(0x10); // RDLENGTH
                response.extend_from_slice(&ipv6.octets());
            }
        }

        Ok(response)
    }

    /// Build error response
    fn build_error_response(&self, query: &[u8], rcode: u8) -> Result<Vec<u8>, String> {
        if query.len() < 12 {
            return Err("Query too short".to_string());
        }

        let mut response = Vec::with_capacity(query.len());

        // Copy transaction ID
        response.extend_from_slice(&query[0..2]);

        // Flags: QR=1, RA=1, RCODE=rcode
        response.push(0x80 | ((query[2] & 0x78) >> 3)); // QR=1, preserve opcode
        response.push(rcode);

        // Copy counts (no answers)
        response.extend_from_slice(&query[4..6]); // QDCOUNT
        response.push(0x00);
        response.push(0x00); // ANCOUNT
        response.push(0x00);
        response.push(0x00); // NSCOUNT
        response.push(0x00);
        response.push(0x00); // ARCOUNT

        // Copy question section
        if query.len() > 12 {
            response.extend_from_slice(&query[12..]);
        }

        Ok(response)
    }

    /// Build response from cached entry
    fn build_cached_response(&self, query: &[u8], entry: &CacheEntry) -> Result<Vec<u8>, String> {
        // For simplicity, we'll rebuild the response
        // In a production system, we'd cache the full response
        if let Some(ip) = entry.addresses.first() {
            let (domain, qtype) = self.parse_query(query)?;
            return self.build_override_response(query, &domain, qtype, *ip);
        }

        // Forward if no cached IP
        self.resolver.resolve(query)
    }

    /// Forward query for a different domain (redirect)
    fn forward_query_for_domain(
        &self,
        query: &[u8],
        target_domain: &str,
        qtype: u16,
    ) -> Result<Vec<u8>, String> {
        // Build new query for target domain
        let mut new_query = Vec::with_capacity(512);

        // Copy transaction ID and flags
        new_query.extend_from_slice(&query[0..12]);

        // Encode target domain
        self.encode_domain(&mut new_query, target_domain);

        // Add QTYPE and QCLASS
        new_query.extend_from_slice(&qtype.to_be_bytes());
        new_query.push(0x00);
        new_query.push(0x01); // IN class

        // Forward modified query
        let response = self.resolver.resolve(&new_query)?;

        // Return response with original transaction ID
        let mut final_response = response;
        if final_response.len() >= 2 && query.len() >= 2 {
            final_response[0] = query[0];
            final_response[1] = query[1];
        }

        Ok(final_response)
    }

    /// Forward to specific upstream server
    fn forward_to_specific(&self, query: &[u8], upstream: &str) -> Result<Vec<u8>, String> {
        let resolver = UpstreamResolver::new(upstream)?;
        resolver.resolve(query)
    }

    /// Encode domain name in DNS format
    fn encode_domain(&self, buffer: &mut Vec<u8>, domain: &str) {
        for part in domain.split('.') {
            buffer.push(part.len() as u8);
            buffer.extend_from_slice(part.as_bytes());
        }
        buffer.push(0x00); // Null terminator
    }

    /// Cache response
    fn cache_response(&self, domain: &str, qtype: u16, response: &[u8]) {
        // Parse response to extract IPs and TTL
        if response.len() < 12 {
            return;
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            // Negative cache
            self.cache.insert_negative(domain, qtype);
            return;
        }

        // Find answer section (skip header + question)
        let mut pos = 12;

        // Skip question section
        while pos < response.len() && response[pos] != 0 {
            let len = response[pos] as usize;
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
        if pos < response.len() && response[pos] == 0 {
            pos += 1;
        }
        pos += 4; // Skip QTYPE and QCLASS

        // Parse answers
        let mut entry = CacheEntry::new(qtype, 300); // Default TTL

        for _ in 0..ancount {
            if pos >= response.len() {
                break;
            }

            // Skip name (handle compression)
            while pos < response.len() {
                let b = response[pos];
                if b == 0 {
                    pos += 1;
                    break;
                }
                if b & 0xC0 == 0xC0 {
                    pos += 2;
                    break;
                }
                pos += 1 + (b as usize);
            }

            if pos + 10 > response.len() {
                break;
            }

            let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let ttl = u32::from_be_bytes([
                response[pos + 4],
                response[pos + 5],
                response[pos + 6],
                response[pos + 7],
            ]);
            let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > response.len() {
                break;
            }

            entry.ttl = entry.ttl.max(ttl);

            // Extract IP address
            match rtype {
                record_type::A if rdlength == 4 => {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        response[pos],
                        response[pos + 1],
                        response[pos + 2],
                        response[pos + 3],
                    ));
                    entry.add_address(ip);
                }
                record_type::AAAA if rdlength == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&response[pos..pos + 16]);
                    let ip = IpAddr::V6(octets.into());
                    entry.add_address(ip);
                }
                _ => {}
            }

            pos += rdlength;
        }

        if !entry.addresses.is_empty() {
            self.cache.insert(domain, qtype, entry);
        }
    }

    /// Increment a stat
    fn increment_stat<F>(&self, f: F)
    where
        F: FnOnce(&mut ServerStats),
    {
        if let Ok(mut stats) = self.stats.write() {
            f(&mut stats);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = DnsServerConfig::default();
        assert_eq!(config.bind_udp.port(), 53);
        assert!(config.enable_cache);
        assert!(config.enable_tcp);
    }

    #[test]
    fn test_server_creation() {
        let config = DnsServerConfig::default();
        let mut server = DnsServer::new(config);
        server.add_rule(DnsRule::block("*.ads.com"));
        assert!(!server.is_running());
    }
}
