/// Proxy Support (SOCKS4/5, HTTP CONNECT)
///
/// Implements proxy protocols for tunneling connections through intermediaries.
/// Essential for pentesting through pivoted networks.
///
/// Features:
/// - SOCKS4 proxy client
/// - SOCKS5 proxy client (with authentication)
/// - HTTP CONNECT proxy
/// - DNS resolution through proxy
///
/// Replaces: ncat --proxy, proxychains
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

/// Proxy type
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyType {
    Socks4,
    Socks5,
    Http,
}

/// Proxy authentication
#[derive(Debug, Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub auth: Option<ProxyAuth>,
    pub timeout: Duration,
}

impl ProxyConfig {
    pub fn new(proxy_type: ProxyType, host: &str, port: u16) -> Self {
        Self {
            proxy_type,
            proxy_host: host.to_string(),
            proxy_port: port,
            auth: None,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_auth(mut self, username: &str, password: &str) -> Self {
        self.auth = Some(ProxyAuth {
            username: username.to_string(),
            password: password.to_string(),
        });
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Proxy client
pub struct ProxyClient {
    config: ProxyConfig,
}

impl ProxyClient {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Connect to target through proxy
    pub fn connect(&self, target_host: &str, target_port: u16) -> Result<TcpStream, String> {
        match self.config.proxy_type {
            ProxyType::Socks4 => self.connect_socks4(target_host, target_port),
            ProxyType::Socks5 => self.connect_socks5(target_host, target_port),
            ProxyType::Http => self.connect_http(target_host, target_port),
        }
    }

    /// SOCKS4 connection
    fn connect_socks4(&self, target_host: &str, target_port: u16) -> Result<TcpStream, String> {
        // Connect to proxy
        let proxy_addr = format!("{}:{}", self.config.proxy_host, self.config.proxy_port);
        let mut stream = TcpStream::connect(&proxy_addr)
            .map_err(|e| format!("Failed to connect to SOCKS4 proxy: {}", e))?;

        stream
            .set_read_timeout(Some(self.config.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.config.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        // Resolve target host to IP
        let target_ip = resolve_host(target_host)?;

        // Build SOCKS4 request
        let mut request = vec![
            0x04,                     // SOCKS version 4
            0x01,                     // CONNECT command
            (target_port >> 8) as u8, // Port high byte
            target_port as u8,        // Port low byte
        ];

        // IP address (4 bytes)
        match target_ip {
            IpAddr::V4(ipv4) => {
                request.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(_) => {
                return Err("SOCKS4 does not support IPv6".to_string());
            }
        }

        // User ID (empty)
        request.push(0x00);

        // Send request
        stream
            .write_all(&request)
            .map_err(|e| format!("Failed to send SOCKS4 request: {}", e))?;

        // Read response
        let mut response = [0u8; 8];
        stream
            .read_exact(&mut response)
            .map_err(|e| format!("Failed to read SOCKS4 response: {}", e))?;

        // Check response
        if response[0] != 0x00 {
            return Err(format!("Invalid SOCKS4 response version: {}", response[0]));
        }

        match response[1] {
            0x5A => Ok(stream), // Request granted
            0x5B => Err("SOCKS4: Request rejected or failed".to_string()),
            0x5C => Err("SOCKS4: Client not reachable".to_string()),
            0x5D => Err("SOCKS4: User ID mismatch".to_string()),
            code => Err(format!("SOCKS4: Unknown response code: {}", code)),
        }
    }

    /// SOCKS5 connection
    fn connect_socks5(&self, target_host: &str, target_port: u16) -> Result<TcpStream, String> {
        // Connect to proxy
        let proxy_addr = format!("{}:{}", self.config.proxy_host, self.config.proxy_port);
        let mut stream = TcpStream::connect(&proxy_addr)
            .map_err(|e| format!("Failed to connect to SOCKS5 proxy: {}", e))?;

        stream
            .set_read_timeout(Some(self.config.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.config.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        // 1. Send greeting
        let mut greeting = vec![0x05]; // SOCKS version 5

        if self.config.auth.is_some() {
            // Support both no auth and username/password
            greeting.push(0x02); // 2 methods
            greeting.push(0x00); // No authentication
            greeting.push(0x02); // Username/password
        } else {
            greeting.push(0x01); // 1 method
            greeting.push(0x00); // No authentication
        }

        stream
            .write_all(&greeting)
            .map_err(|e| format!("Failed to send SOCKS5 greeting: {}", e))?;

        // Read greeting response
        let mut greeting_response = [0u8; 2];
        stream
            .read_exact(&mut greeting_response)
            .map_err(|e| format!("Failed to read SOCKS5 greeting response: {}", e))?;

        if greeting_response[0] != 0x05 {
            return Err(format!("Invalid SOCKS5 version: {}", greeting_response[0]));
        }

        // 2. Handle authentication
        match greeting_response[1] {
            0x00 => {
                // No authentication required
            }
            0x02 => {
                // Username/password authentication
                let auth = self
                    .config
                    .auth
                    .as_ref()
                    .ok_or("SOCKS5 proxy requires authentication but none provided")?;

                self.socks5_auth(&mut stream, auth)?;
            }
            0xFF => return Err("SOCKS5: No acceptable authentication methods".to_string()),
            method => return Err(format!("SOCKS5: Unknown auth method: {}", method)),
        }

        // 3. Send CONNECT request
        let mut request = Vec::new();
        request.push(0x05); // SOCKS version 5
        request.push(0x01); // CONNECT command
        request.push(0x00); // Reserved

        // Address type and address
        if let Ok(ip) = target_host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ipv4) => {
                    request.push(0x01); // IPv4
                    request.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    request.push(0x04); // IPv6
                    request.extend_from_slice(&ipv6.octets());
                }
            }
        } else {
            // Domain name
            request.push(0x03); // Domain name
            request.push(target_host.len() as u8);
            request.extend_from_slice(target_host.as_bytes());
        }

        // Port
        request.push((target_port >> 8) as u8);
        request.push(target_port as u8);

        stream
            .write_all(&request)
            .map_err(|e| format!("Failed to send SOCKS5 CONNECT request: {}", e))?;

        // Read response
        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .map_err(|e| format!("Failed to read SOCKS5 response: {}", e))?;

        if response[0] != 0x05 {
            return Err(format!("Invalid SOCKS5 response version: {}", response[0]));
        }

        match response[1] {
            0x00 => {
                // Success - read rest of response (bind address)
                let atyp = response[3];
                let skip_len = match atyp {
                    0x01 => 4 + 2, // IPv4 + port
                    0x03 => {
                        let mut len_buf = [0u8; 1];
                        stream.read_exact(&mut len_buf).ok();
                        len_buf[0] as usize + 2
                    } // Domain + port
                    0x04 => 16 + 2, // IPv6 + port
                    _ => 0,
                };

                let mut skip_buf = vec![0u8; skip_len];
                stream.read_exact(&mut skip_buf).ok();

                Ok(stream)
            }
            0x01 => Err("SOCKS5: General SOCKS server failure".to_string()),
            0x02 => Err("SOCKS5: Connection not allowed by ruleset".to_string()),
            0x03 => Err("SOCKS5: Network unreachable".to_string()),
            0x04 => Err("SOCKS5: Host unreachable".to_string()),
            0x05 => Err("SOCKS5: Connection refused".to_string()),
            0x06 => Err("SOCKS5: TTL expired".to_string()),
            0x07 => Err("SOCKS5: Command not supported".to_string()),
            0x08 => Err("SOCKS5: Address type not supported".to_string()),
            code => Err(format!("SOCKS5: Unknown response code: {}", code)),
        }
    }

    /// SOCKS5 username/password authentication
    fn socks5_auth(&self, stream: &mut TcpStream, auth: &ProxyAuth) -> Result<(), String> {
        let mut auth_request = Vec::new();
        auth_request.push(0x01); // Auth version

        // Username
        auth_request.push(auth.username.len() as u8);
        auth_request.extend_from_slice(auth.username.as_bytes());

        // Password
        auth_request.push(auth.password.len() as u8);
        auth_request.extend_from_slice(auth.password.as_bytes());

        stream
            .write_all(&auth_request)
            .map_err(|e| format!("Failed to send SOCKS5 auth: {}", e))?;

        // Read auth response
        let mut auth_response = [0u8; 2];
        stream
            .read_exact(&mut auth_response)
            .map_err(|e| format!("Failed to read SOCKS5 auth response: {}", e))?;

        if auth_response[0] != 0x01 {
            return Err(format!("Invalid SOCKS5 auth version: {}", auth_response[0]));
        }

        if auth_response[1] != 0x00 {
            return Err("SOCKS5: Authentication failed".to_string());
        }

        Ok(())
    }

    /// HTTP CONNECT proxy
    fn connect_http(&self, target_host: &str, target_port: u16) -> Result<TcpStream, String> {
        // Connect to proxy
        let proxy_addr = format!("{}:{}", self.config.proxy_host, self.config.proxy_port);
        let mut stream = TcpStream::connect(&proxy_addr)
            .map_err(|e| format!("Failed to connect to HTTP proxy: {}", e))?;

        stream
            .set_read_timeout(Some(self.config.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.config.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        // Build CONNECT request
        let mut request = format!("CONNECT {}:{} HTTP/1.1\r\n", target_host, target_port);
        request.push_str(&format!("Host: {}:{}\r\n", target_host, target_port));

        // Add authentication if provided
        if let Some(auth) = &self.config.auth {
            let credentials = format!("{}:{}", auth.username, auth.password);
            let encoded = base64_encode(credentials.as_bytes());
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        request.push_str("\r\n");

        // Send request
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("Failed to send HTTP CONNECT request: {}", e))?;

        // Read response
        let mut response = String::new();
        let mut buf = [0u8; 1];
        let mut headers_done = false;

        while !headers_done {
            stream
                .read_exact(&mut buf)
                .map_err(|e| format!("Failed to read HTTP response: {}", e))?;

            response.push(buf[0] as char);

            if response.ends_with("\r\n\r\n") {
                headers_done = true;
            }
        }

        // Parse status line
        let first_line = response.lines().next().ok_or("Empty HTTP response")?;
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() < 2 {
            return Err("Invalid HTTP response".to_string());
        }

        let status_code = parts[1];

        if status_code == "200" {
            Ok(stream)
        } else {
            Err(format!("HTTP CONNECT failed: {}", first_line))
        }
    }
}

/// Resolve hostname to IP address
fn resolve_host(host: &str) -> Result<IpAddr, String> {
    // Try parsing as IP first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // DNS resolution
    use std::net::ToSocketAddrs;

    let addr = format!("{}:0", host);
    let mut addrs = addr
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {}: {}", host, e))?;

    addrs
        .next()
        .map(|s| s.ip())
        .ok_or_else(|| format!("No IP address found for {}", host))
}

/// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b1 = data[i];
        let b2 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b3 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        result.push(CHARS[(b1 >> 2) as usize] as char);
        result.push(CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);

        if i + 1 < data.len() {
            result.push(CHARS[(((b2 & 0x0F) << 2) | (b3 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(CHARS[(b3 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_proxy_config() {
        let config = ProxyConfig::new(ProxyType::Socks5, "127.0.0.1", 1080)
            .with_auth("user", "pass")
            .with_timeout(Duration::from_secs(5));

        assert_eq!(config.proxy_type, ProxyType::Socks5);
        assert_eq!(config.proxy_host, "127.0.0.1");
        assert_eq!(config.proxy_port, 1080);
        assert!(config.auth.is_some());
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b"hello world"), "aGVsbG8gd29ybGQ=");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn test_resolve_host() {
        // Should parse IP directly
        let ip = resolve_host("127.0.0.1").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // DNS resolution (localhost should always work)
        let ip = resolve_host("localhost").unwrap();
        assert!(ip.is_loopback());
    }
}
