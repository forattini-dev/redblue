//! Upstream DNS Resolver
//!
//! Forwards DNS queries to upstream DNS servers.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// Upstream DNS resolver
#[derive(Debug, Clone)]
pub struct UpstreamResolver {
    /// Primary upstream server
    pub primary: SocketAddr,
    /// Secondary upstream server (fallback)
    pub secondary: Option<SocketAddr>,
    /// Query timeout
    pub timeout: Duration,
    /// Use TCP for queries
    pub use_tcp: bool,
    /// Retry count
    pub retries: u32,
}

impl UpstreamResolver {
    /// Create new resolver with default settings
    pub fn new(primary: &str) -> Result<Self, String> {
        let addr = parse_dns_addr(primary)?;
        Ok(Self {
            primary: addr,
            secondary: None,
            timeout: Duration::from_secs(5),
            use_tcp: false,
            retries: 2,
        })
    }

    /// Create resolver with primary and secondary servers
    pub fn with_fallback(primary: &str, secondary: &str) -> Result<Self, String> {
        let mut resolver = Self::new(primary)?;
        resolver.secondary = Some(parse_dns_addr(secondary)?);
        Ok(resolver)
    }

    /// Set query timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Use TCP for queries
    pub fn with_tcp(mut self, use_tcp: bool) -> Self {
        self.use_tcp = use_tcp;
        self
    }

    /// Set retry count
    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Resolve a DNS query
    pub fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut last_error = String::new();

        // Try primary server
        for attempt in 0..=self.retries {
            match self.query_server(self.primary, query) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = format!("Primary server failed (attempt {}): {}", attempt + 1, e);
                }
            }
        }

        // Try secondary server if available
        if let Some(secondary) = self.secondary {
            for attempt in 0..=self.retries {
                match self.query_server(secondary, query) {
                    Ok(response) => return Ok(response),
                    Err(e) => {
                        last_error =
                            format!("Secondary server failed (attempt {}): {}", attempt + 1, e);
                    }
                }
            }
        }

        Err(last_error)
    }

    /// Query a specific DNS server
    fn query_server(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
        if self.use_tcp {
            self.query_tcp(server, query)
        } else {
            self.query_udp(server, query)
        }
    }

    /// Query using UDP
    fn query_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Bind error: {}", e))?;

        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout error: {}", e))?;

        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout error: {}", e))?;

        socket
            .send_to(query, server)
            .map_err(|e| format!("Send error: {}", e))?;

        let mut buffer = vec![0u8; 4096];
        let (len, _) = socket
            .recv_from(&mut buffer)
            .map_err(|e| format!("Receive error: {}", e))?;

        buffer.truncate(len);
        Ok(buffer)
    }

    /// Query using TCP
    fn query_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut stream = TcpStream::connect_timeout(&server, self.timeout)
            .map_err(|e| format!("Connect error: {}", e))?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout error: {}", e))?;

        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout error: {}", e))?;

        // TCP DNS uses 2-byte length prefix
        let len = query.len() as u16;
        let len_bytes = len.to_be_bytes();

        stream
            .write_all(&len_bytes)
            .map_err(|e| format!("Write length error: {}", e))?;

        stream
            .write_all(query)
            .map_err(|e| format!("Write query error: {}", e))?;

        // Read response length
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("Read length error: {}", e))?;

        let response_len = u16::from_be_bytes(len_buf) as usize;
        if response_len > 65535 {
            return Err("Response too large".to_string());
        }

        // Read response
        let mut response = vec![0u8; response_len];
        stream
            .read_exact(&mut response)
            .map_err(|e| format!("Read response error: {}", e))?;

        Ok(response)
    }
}

impl Default for UpstreamResolver {
    fn default() -> Self {
        Self::with_fallback("8.8.8.8:53", "1.1.1.1:53")
            .expect("Default DNS servers should be valid")
    }
}

/// Parse DNS server address (host:port or just host)
fn parse_dns_addr(addr: &str) -> Result<SocketAddr, String> {
    // If already has port
    if addr.contains(':') && !addr.starts_with('[') {
        addr.parse()
            .map_err(|e| format!("Invalid address '{}': {}", addr, e))
    } else {
        // Add default DNS port
        let with_port = if addr.contains('[') {
            // IPv6 without port: [::1] -> [::1]:53
            format!("{}:53", addr)
        } else {
            // IPv4 or hostname: 8.8.8.8 -> 8.8.8.8:53
            format!("{}:53", addr)
        };
        with_port
            .parse()
            .map_err(|e| format!("Invalid address '{}': {}", addr, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_addr() {
        assert_eq!(
            parse_dns_addr("8.8.8.8").unwrap(),
            "8.8.8.8:53".parse().unwrap()
        );
        assert_eq!(
            parse_dns_addr("8.8.8.8:5353").unwrap(),
            "8.8.8.8:5353".parse().unwrap()
        );
        assert_eq!(
            parse_dns_addr("1.1.1.1").unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
    }

    #[test]
    fn test_resolver_default() {
        let resolver = UpstreamResolver::default();
        assert_eq!(resolver.primary.port(), 53);
        assert!(resolver.secondary.is_some());
    }
}
