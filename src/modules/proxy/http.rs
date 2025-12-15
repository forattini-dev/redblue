//! HTTP CONNECT Proxy Implementation
//!
//! Implements HTTP CONNECT method for tunneling TCP connections through HTTP.
//!
//! # Protocol Overview
//!
//! ```text
//! Client                              Proxy                              Target
//!   |                                   |                                   |
//!   |-- CONNECT host:port HTTP/1.1 ---->|                                   |
//!   |                                   |---- TCP Connect ----------------->|
//!   |<-- HTTP/1.1 200 Connection OK ----|<---- Connected -------------------|
//!   |                                   |                                   |
//!   |<=============== Bidirectional TCP Relay ============================>|
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use redblue::modules::proxy::http::HttpProxy;
//!
//! let proxy = HttpProxy::bind("127.0.0.1:8080").await?;
//! proxy.run().await?;
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use super::{Protocol, ProxyContext, ProxyError, ProxyResult};
use crate::{debug, error, info};

/// HTTP proxy authentication
#[derive(Debug, Clone)]
pub struct HttpAuth {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
}

impl HttpAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Encode credentials for Basic authentication
    pub fn encode_basic(&self) -> String {
        let credentials = format!("{}:{}", self.username, self.password);
        let mut encoded = Vec::new();
        {
            // Simple base64 encoding (no external crate)
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let bytes = credentials.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                let b0 = bytes[i];
                let b1 = bytes.get(i + 1).copied().unwrap_or(0);
                let b2 = bytes.get(i + 2).copied().unwrap_or(0);

                encoded.push(alphabet[(b0 >> 2) as usize]);
                encoded.push(alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);

                if i + 1 < bytes.len() {
                    encoded.push(alphabet[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]);
                } else {
                    encoded.push(b'=');
                }

                if i + 2 < bytes.len() {
                    encoded.push(alphabet[(b2 & 0x3f) as usize]);
                } else {
                    encoded.push(b'=');
                }

                i += 3;
            }
        }
        String::from_utf8(encoded).unwrap()
    }
}

/// HTTP proxy configuration
#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Authentication (None = no auth required)
    pub auth: Option<HttpAuth>,
    /// Connection timeout
    pub timeout: Duration,
    /// Upstream proxy (for chaining)
    pub upstream: Option<UpstreamProxy>,
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            auth: None,
            timeout: Duration::from_secs(30),
            upstream: None,
        }
    }
}

/// Upstream proxy configuration (for proxy chaining)
#[derive(Debug, Clone)]
pub enum UpstreamProxy {
    /// HTTP CONNECT proxy
    Http {
        addr: SocketAddr,
        auth: Option<HttpAuth>,
    },
    /// SOCKS5 proxy
    Socks5 {
        addr: SocketAddr,
        auth: Option<(String, String)>,
    },
}

/// Parsed HTTP CONNECT request
#[derive(Debug)]
struct ConnectRequest {
    host: String,
    port: u16,
    http_version: String,
    headers: Vec<(String, String)>,
}

impl ConnectRequest {
    /// Parse CONNECT request from stream
    fn parse(stream: &mut TcpStream) -> ProxyResult<Self> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;

        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() != 3 {
            return Err(ProxyError::Protocol(
                "Invalid HTTP request line".to_string(),
            ));
        }

        let method = parts[0];
        if method.to_uppercase() != "CONNECT" {
            return Err(ProxyError::Protocol(format!(
                "Expected CONNECT, got {}",
                method
            )));
        }

        let target = parts[1];
        let http_version = parts[2].to_string();

        // Parse host:port
        let (host, port) = if let Some(colon_pos) = target.rfind(':') {
            let host = target[..colon_pos].to_string();
            let port: u16 = target[colon_pos + 1..]
                .parse()
                .map_err(|_| ProxyError::Protocol("Invalid port".to_string()))?;
            (host, port)
        } else {
            return Err(ProxyError::Protocol(
                "Missing port in CONNECT target".to_string(),
            ));
        };

        // Parse headers
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.push((name, value));
            }
        }

        Ok(Self {
            host,
            port,
            http_version,
            headers,
        })
    }

    /// Get Proxy-Authorization header value
    fn get_proxy_auth(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Proxy-Authorization"))
            .map(|(_, value)| value.as_str())
    }
}

/// HTTP CONNECT proxy server
pub struct HttpProxy {
    config: HttpProxyConfig,
    ctx: Arc<ProxyContext>,
}

impl HttpProxy {
    /// Create new HTTP proxy with default config
    pub fn new(ctx: Arc<ProxyContext>) -> Self {
        Self {
            config: HttpProxyConfig::default(),
            ctx,
        }
    }

    /// Create proxy with custom config
    pub fn with_config(config: HttpProxyConfig, ctx: Arc<ProxyContext>) -> Self {
        Self { config, ctx }
    }

    /// Bind to address and create proxy
    pub fn bind(addr: SocketAddr, ctx: Arc<ProxyContext>) -> ProxyResult<Self> {
        let mut config = HttpProxyConfig::default();
        config.listen_addr = addr;
        Ok(Self::with_config(config, ctx))
    }

    /// Run the HTTP proxy server (blocking)
    pub fn run(&self) -> ProxyResult<()> {
        let listener = TcpListener::bind(self.config.listen_addr)?;

        info!("HTTP proxy listening on {}", self.config.listen_addr);

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let ctx = self.ctx.clone();
                    let config = self.config.clone();
                    let peer_addr = stream.peer_addr().ok();

                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(stream, config, ctx, peer_addr) {
                            debug!("HTTP proxy error: {}", e);
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

    /// Handle a single HTTP proxy connection
    fn handle_connection(
        mut client: TcpStream,
        config: HttpProxyConfig,
        ctx: Arc<ProxyContext>,
        peer_addr: Option<SocketAddr>,
    ) -> ProxyResult<()> {
        client.set_read_timeout(Some(config.timeout))?;
        client.set_write_timeout(Some(config.timeout))?;

        // Parse CONNECT request
        let request = ConnectRequest::parse(&mut client)?;

        let conn_id = ctx.id_generator.next_tcp();

        info!(
            "[{}] CONNECT {} -> {}:{}",
            conn_id,
            peer_addr.map(|a| a.to_string()).unwrap_or_default(),
            request.host,
            request.port
        );

        // Check authentication if required
        if let Some(ref auth) = config.auth {
            let expected = format!("Basic {}", auth.encode_basic());
            match request.get_proxy_auth() {
                Some(provided) if provided == expected => {
                    debug!("[{}] Authentication successful", conn_id);
                }
                _ => {
                    Self::send_response(&mut client, 407, "Proxy Authentication Required")?;
                    return Err(ProxyError::Auth("Authentication required".to_string()));
                }
            }
        }

        // Connect to target (or upstream proxy)
        let mut server = match config.upstream {
            Some(UpstreamProxy::Http { addr, auth }) => {
                Self::connect_via_http_proxy(&request, addr, auth.as_ref())?
            }
            Some(UpstreamProxy::Socks5 { addr, auth }) => {
                Self::connect_via_socks5(&request, addr, auth.as_ref())?
            }
            None => Self::connect_direct(&request)?,
        };

        // Send success response
        Self::send_response(&mut client, 200, "Connection Established")?;

        // Update stats
        ctx.flow_stats.connection_opened(Protocol::Tcp);

        // Start relay
        let result =
            super::relay::tcp::relay_bidirectional(&mut client, &mut server, &ctx.flow_stats);

        ctx.flow_stats.connection_closed();

        match result {
            Ok((sent, recv)) => {
                info!(
                    "[{}] Closed: {} bytes sent, {} bytes received",
                    conn_id, sent, recv
                );
                Ok(())
            }
            Err(e) => {
                debug!("[{}] Relay error: {}", conn_id, e);
                Err(ProxyError::Io(e))
            }
        }
    }

    /// Connect directly to target
    fn connect_direct(request: &ConnectRequest) -> ProxyResult<TcpStream> {
        let target_addr = format!("{}:{}", request.host, request.port);
        use std::net::ToSocketAddrs;

        let addr = target_addr
            .to_socket_addrs()
            .map_err(|_| ProxyError::ResolutionFailed(request.host.clone()))?
            .next()
            .ok_or_else(|| ProxyError::ResolutionFailed(request.host.clone()))?;

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
        Ok(stream)
    }

    /// Connect via upstream HTTP proxy
    fn connect_via_http_proxy(
        request: &ConnectRequest,
        proxy_addr: SocketAddr,
        auth: Option<&HttpAuth>,
    ) -> ProxyResult<TcpStream> {
        let mut stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(10))?;

        // Send CONNECT to upstream
        let mut req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            request.host, request.port, request.host, request.port
        );

        if let Some(auth) = auth {
            req.push_str(&format!(
                "Proxy-Authorization: Basic {}\r\n",
                auth.encode_basic()
            ));
        }

        req.push_str("\r\n");
        stream.write_all(req.as_bytes())?;

        // Read response
        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        if !response_line.contains("200") {
            return Err(ProxyError::Protocol(format!(
                "Upstream proxy error: {}",
                response_line.trim()
            )));
        }

        // Skip headers
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.trim().is_empty() {
                break;
            }
        }

        Ok(stream)
    }

    /// Connect via SOCKS5 proxy
    fn connect_via_socks5(
        request: &ConnectRequest,
        proxy_addr: SocketAddr,
        auth: Option<&(String, String)>,
    ) -> ProxyResult<TcpStream> {
        let mut stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(10))?;

        // SOCKS5 handshake
        let methods = if auth.is_some() {
            vec![0x00, 0x02] // No auth + username/password
        } else {
            vec![0x00] // No auth only
        };

        let mut greeting = vec![0x05, methods.len() as u8];
        greeting.extend(&methods);
        stream.write_all(&greeting)?;

        // Read method selection
        let mut response = [0u8; 2];
        stream.read_exact(&mut response)?;

        if response[0] != 0x05 {
            return Err(ProxyError::Protocol("Invalid SOCKS5 response".to_string()));
        }

        // Handle authentication if selected
        if response[1] == 0x02 {
            let (username, password) =
                auth.ok_or_else(|| ProxyError::Auth("SOCKS5 requires authentication".to_string()))?;

            let mut auth_req = vec![0x01, username.len() as u8];
            auth_req.extend(username.as_bytes());
            auth_req.push(password.len() as u8);
            auth_req.extend(password.as_bytes());
            stream.write_all(&auth_req)?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp)?;

            if auth_resp[1] != 0x00 {
                return Err(ProxyError::Auth("SOCKS5 authentication failed".to_string()));
            }
        } else if response[1] == 0xFF {
            return Err(ProxyError::Auth(
                "No acceptable SOCKS5 auth method".to_string(),
            ));
        }

        // Send CONNECT request
        let mut connect_req = vec![
            0x05, // Version
            0x01, // CONNECT
            0x00, // Reserved
            0x03, // Domain name
            request.host.len() as u8,
        ];
        connect_req.extend(request.host.as_bytes());
        connect_req.extend(&request.port.to_be_bytes());
        stream.write_all(&connect_req)?;

        // Read response
        let mut connect_resp = [0u8; 10];
        stream.read_exact(&mut connect_resp)?;

        if connect_resp[1] != 0x00 {
            return Err(ProxyError::Protocol(format!(
                "SOCKS5 connect failed: {}",
                connect_resp[1]
            )));
        }

        Ok(stream)
    }

    /// Send HTTP response
    fn send_response(stream: &mut TcpStream, status: u16, reason: &str) -> ProxyResult<()> {
        let response = format!("HTTP/1.1 {} {}\r\n\r\n", status, reason);
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_auth_basic_encode() {
        let auth = HttpAuth::new("Aladdin", "open sesame");
        let encoded = auth.encode_basic();
        assert_eq!(encoded, "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn test_http_auth_simple() {
        let auth = HttpAuth::new("user", "pass");
        let encoded = auth.encode_basic();
        assert_eq!(encoded, "dXNlcjpwYXNz");
    }
}
