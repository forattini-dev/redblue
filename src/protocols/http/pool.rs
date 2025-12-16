use crate::protocols::http::body::{analyze_headers, chunked_body_complete, BodyStrategy};
#[cfg(not(target_os = "windows"))]
use crate::protocols::tls_impersonator::TlsProfile;
#[cfg(not(target_os = "windows"))]
use boring::ssl::{
    Ssl, SslContext, SslMethod, SslSessionCacheMode, SslStream, SslVerifyMode, SslVersion,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Stub TlsProfile for Windows
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy)]
pub enum TlsProfile {
    Chrome120,
    Firefox120,
    Safari16,
}

/// Wrapper around either a raw TCP stream or a negotiated TLS 1.3 client
#[cfg(not(target_os = "windows"))]
pub enum PooledStream {
    Plain(TcpStream),
    Tls(SslStream<TcpStream>),
}

/// On Windows, only plain HTTP is supported (no TLS)
#[cfg(target_os = "windows")]
pub enum PooledStream {
    Plain(TcpStream),
}

#[cfg(not(target_os = "windows"))]
impl std::fmt::Debug for PooledStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PooledStream::Plain(stream) => f
                .debug_struct("PooledStream::Plain")
                .field("peer_addr", &stream.peer_addr().ok())
                .finish(),
            PooledStream::Tls(stream) => f
                .debug_struct("PooledStream::Tls")
                .field("peer_addr", &stream.get_ref().peer_addr().ok())
                .finish(),
        }
    }
}

#[cfg(target_os = "windows")]
impl std::fmt::Debug for PooledStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PooledStream::Plain(stream) => f
                .debug_struct("PooledStream::Plain")
                .field("peer_addr", &stream.peer_addr().ok())
                .finish(),
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl PooledStream {
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            PooledStream::Plain(stream) => stream.set_read_timeout(timeout),
            PooledStream::Tls(stream) => stream.get_mut().set_read_timeout(timeout),
        }
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            PooledStream::Plain(stream) => stream.set_write_timeout(timeout),
            PooledStream::Tls(stream) => stream.get_mut().set_write_timeout(timeout),
        }
    }

    pub fn peek(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PooledStream::Plain(stream) => stream.peek(buf),
            PooledStream::Tls(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "peek not supported for TLS streams",
            )),
        }
    }
}

#[cfg(target_os = "windows")]
impl PooledStream {
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            PooledStream::Plain(stream) => stream.set_read_timeout(timeout),
        }
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            PooledStream::Plain(stream) => stream.set_write_timeout(timeout),
        }
    }

    pub fn peek(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PooledStream::Plain(stream) => stream.peek(buf),
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl Read for PooledStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PooledStream::Plain(stream) => stream.read(buf),
            PooledStream::Tls(stream) => stream.read(buf),
        }
    }
}

#[cfg(target_os = "windows")]
impl Read for PooledStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PooledStream::Plain(stream) => stream.read(buf),
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl Write for PooledStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            PooledStream::Plain(stream) => stream.write(buf),
            PooledStream::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            PooledStream::Plain(stream) => stream.flush(),
            PooledStream::Tls(stream) => stream.flush(),
        }
    }
}

#[cfg(target_os = "windows")]
impl Write for PooledStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            PooledStream::Plain(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            PooledStream::Plain(stream) => stream.flush(),
        }
    }
}

#[derive(Debug)]
struct PooledConnection {
    stream: PooledStream,
    last_used: Instant,
}

/// Thread-safe connection pool keyed by host/port/protocol
#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
pub struct ConnectionPool {
    pools: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    /// Cached SSL contexts per host (enables TLS session resumption)
    ssl_contexts: Arc<Mutex<HashMap<String, SslContext>>>,
    max_idle_per_host: usize,
    idle_timeout: Duration,
}

/// Thread-safe connection pool keyed by host/port/protocol (Windows - no TLS support)
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct ConnectionPool {
    pools: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    max_idle_per_host: usize,
    idle_timeout: Duration,
}

#[cfg(not(target_os = "windows"))]
impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            pools: Arc::new(Mutex::new(HashMap::new())),
            ssl_contexts: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: 10,
            idle_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_max_idle(mut self, max: usize) -> Self {
        self.max_idle_per_host = max;
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Get or create an SSL context for the given host with session caching enabled
    fn get_or_create_ssl_context(
        &self,
        host: &str,
        _profile: Option<TlsProfile>,
    ) -> Result<SslContext, String> {
        let mut contexts = self.ssl_contexts.lock().unwrap();

        if let Some(ctx) = contexts.get(host) {
            return Ok(ctx.clone());
        }

        // Create new SSL context with session caching enabled
        let mut builder = SslContext::builder(SslMethod::tls_client())
            .map_err(|e| format!("SSL context creation failed: {}", e))?;

        // Enable client-side session caching (TLS session resumption)
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        // Set TLS version constraints
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| format!("Failed to set min TLS version: {}", e))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("Failed to set max TLS version: {}", e))?;

        // Disable certificate verification (matching existing behavior)
        builder.set_verify(SslVerifyMode::NONE);

        let ctx = builder.build();
        contexts.insert(host.to_string(), ctx.clone());
        Ok(ctx)
    }

    pub fn get_connection(
        &self,
        host: &str,
        port: u16,
        use_tls: bool,
    ) -> Result<PooledStream, String> {
        let key = format!(
            "{}:{}:{}",
            if use_tls { "https" } else { "http" },
            host,
            port
        );

        {
            let mut pools = self.pools.lock().unwrap();
            if let Some(pool) = pools.get_mut(&key) {
                let now = Instant::now();
                pool.retain(|conn| now.duration_since(conn.last_used) < self.idle_timeout);

                if let Some(pooled) = pool.pop() {
                    if Self::is_alive(&pooled.stream) {
                        return Ok(pooled.stream);
                    }
                }
            }
        }

        if use_tls {
            // Use cached SSL context for session resumption
            let ctx = self.get_or_create_ssl_context(host, None)?;
            let addr = format!("{}:{}", host, port);
            let tcp_stream = TcpStream::connect(&addr)
                .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
            let default_timeout = Duration::from_secs(30);
            let _ = tcp_stream.set_read_timeout(Some(default_timeout));
            let _ = tcp_stream.set_write_timeout(Some(default_timeout));

            // Create SSL instance from cached context (enables session reuse)
            let mut ssl =
                Ssl::new(&ctx).map_err(|e| format!("Failed to create SSL instance: {}", e))?;
            ssl.set_hostname(host)
                .map_err(|e| format!("Failed to set SNI hostname: {}", e))?;

            let ssl_stream = ssl
                .connect(tcp_stream)
                .map_err(|e| format!("TLS handshake failed: {}", e))?;
            Ok(PooledStream::Tls(ssl_stream))
        } else {
            let addr = format!("{}:{}", host, port);
            let tcp_stream = TcpStream::connect(&addr)
                .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
            Ok(PooledStream::Plain(tcp_stream))
        }
    }

    pub fn return_connection(&self, stream: PooledStream, host: &str, port: u16, use_tls: bool) {
        let key = format!(
            "{}:{}:{}",
            if use_tls { "https" } else { "http" },
            host,
            port
        );

        let mut pools = self.pools.lock().unwrap();
        let pool = pools.entry(key).or_insert_with(Vec::new);

        if pool.len() < self.max_idle_per_host {
            pool.push(PooledConnection {
                stream,
                last_used: Instant::now(),
            });
        }
    }

    fn is_alive(stream: &PooledStream) -> bool {
        match stream {
            PooledStream::Plain(tcp_stream) => {
                if let Ok(cloned) = tcp_stream.try_clone() {
                    let _ = cloned.set_read_timeout(Some(Duration::from_millis(1)));
                    let _ = cloned.set_nonblocking(true);

                    let mut buf = [0u8; 1];
                    match cloned.peek(&mut buf) {
                        Ok(0) => false,
                        Ok(_) => true,
                        Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
                    }
                } else {
                    false
                }
            }
            PooledStream::Tls(_) => true,
        }
    }

    pub fn clear(&self) {
        let mut pools = self.pools.lock().unwrap();
        pools.clear();
    }

    pub fn stats(&self) -> PoolStats {
        let pools = self.pools.lock().unwrap();
        let total_connections: usize = pools.values().map(|p| p.len()).sum();
        let hosts = pools.len();

        PoolStats {
            total_connections,
            hosts,
        }
    }
}

#[cfg(target_os = "windows")]
impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            pools: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: 10,
            idle_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_max_idle(mut self, max: usize) -> Self {
        self.max_idle_per_host = max;
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    pub fn get_connection(
        &self,
        host: &str,
        port: u16,
        use_tls: bool,
    ) -> Result<PooledStream, String> {
        if use_tls {
            return Err("HTTPS/TLS is not supported on Windows. Use HTTP instead.".to_string());
        }

        let key = format!("http:{}:{}", host, port);

        {
            let mut pools = self.pools.lock().unwrap();
            if let Some(pool) = pools.get_mut(&key) {
                let now = Instant::now();
                pool.retain(|conn| now.duration_since(conn.last_used) < self.idle_timeout);

                if let Some(pooled) = pool.pop() {
                    if Self::is_alive(&pooled.stream) {
                        return Ok(pooled.stream);
                    }
                }
            }
        }

        let addr = format!("{}:{}", host, port);
        let tcp_stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
        Ok(PooledStream::Plain(tcp_stream))
    }

    pub fn return_connection(&self, stream: PooledStream, host: &str, port: u16, use_tls: bool) {
        let key = format!(
            "{}:{}:{}",
            if use_tls { "https" } else { "http" },
            host,
            port
        );

        let mut pools = self.pools.lock().unwrap();
        let pool = pools.entry(key).or_insert_with(Vec::new);

        if pool.len() < self.max_idle_per_host {
            pool.push(PooledConnection {
                stream,
                last_used: Instant::now(),
            });
        }
    }

    fn is_alive(stream: &PooledStream) -> bool {
        match stream {
            PooledStream::Plain(tcp_stream) => {
                if let Ok(cloned) = tcp_stream.try_clone() {
                    let _ = cloned.set_read_timeout(Some(Duration::from_millis(1)));
                    let _ = cloned.set_nonblocking(true);

                    let mut buf = [0u8; 1];
                    match cloned.peek(&mut buf) {
                        Ok(0) => false,
                        Ok(_) => true,
                        Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
                    }
                } else {
                    false
                }
            }
        }
    }

    pub fn clear(&self) {
        let mut pools = self.pools.lock().unwrap();
        pools.clear();
    }

    pub fn stats(&self) -> PoolStats {
        let pools = self.pools.lock().unwrap();
        let total_connections: usize = pools.values().map(|p| p.len()).sum();
        let hosts = pools.len();

        PoolStats {
            total_connections,
            hosts,
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct PoolStats {
    pub total_connections: usize,
    pub hosts: usize,
}

pub struct PooledHttpClient {
    pub pool: Arc<ConnectionPool>,
    pub timeout: Duration,
    pub keep_alive: bool,
}

pub struct PooledResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub ttfb: Duration,
}

pub struct PooledError {
    pub message: String,
    pub ttfb: Option<Duration>,
}

impl PooledHttpClient {
    pub fn new(pool: Arc<ConnectionPool>) -> Self {
        Self {
            pool,
            timeout: Duration::from_secs(30),
            keep_alive: true,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_keep_alive(mut self, keep_alive: bool) -> Self {
        self.keep_alive = keep_alive;
        self
    }

    pub fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String> {
        let start = Instant::now();
        match self.request("GET", url, start, None) {
            Ok(resp) => Ok((resp.status, resp.body)),
            Err(err) => Err(err.message),
        }
    }

    pub fn request(
        &self,
        method: &str,
        url: &str,
        start: Instant,
        body: Option<&Arc<Vec<u8>>>,
    ) -> Result<PooledResponse, PooledError> {
        let (host, port, path, use_tls) = Self::parse_url(url).map_err(|e| PooledError {
            message: e,
            ttfb: None,
        })?;
        let mut stream = self
            .pool
            .get_connection(&host, port, use_tls)
            .map_err(|e| PooledError {
                message: e,
                ttfb: None,
            })?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| PooledError {
                message: format!("Failed to set read timeout: {}", e),
                ttfb: None,
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| PooledError {
                message: format!("Failed to set write timeout: {}", e),
                ttfb: None,
            })?;

        let connection_header = if self.keep_alive {
            "Connection: keep-alive"
        } else {
            "Connection: close"
        };

        let mut request = format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: RedBlue/1.0\r\n\
             Accept: */*\r\n\
             {}\r\n",
            method, path, host, connection_header
        );

        let mut body_slice: Option<&[u8]> = None;
        if let Some(payload) = body {
            body_slice = Some(payload.as_slice());
            request.push_str(&format!("Content-Length: {}\r\n", payload.len()));
            request.push_str("Content-Type: application/octet-stream\r\n");
        }

        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .map_err(|e| PooledError {
                message: format!("Failed to send request: {}", e),
                ttfb: None,
            })?;

        if let Some(bytes) = body_slice {
            stream.write_all(bytes).map_err(|e| PooledError {
                message: format!("Failed to send request body: {}", e),
                ttfb: None,
            })?;
        }

        let mut buffer = Vec::with_capacity(16384);
        let mut temp_buf = [0u8; 8192];
        let mut header_end: Option<usize> = None;
        let mut body_strategy = BodyStrategy::Unknown;
        let mut allow_reuse = self.keep_alive;
        let mut header_parsed = false;
        let mut ttfb: Option<Duration> = None;
        let mut timed_out = false;

        loop {
            match stream.read(&mut temp_buf) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);

                    if ttfb.is_none() && n > 0 {
                        ttfb = Some(start.elapsed());
                    }

                    if header_end.is_none() {
                        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                        }
                    }

                    if let Some(end) = header_end {
                        if !header_parsed {
                            let (strategy, can_reuse) = analyze_headers(&buffer[..end]);
                            body_strategy = strategy;
                            header_parsed = true;
                            if !can_reuse {
                                allow_reuse = false;
                            }
                        }

                        match body_strategy {
                            BodyStrategy::ContentLength(expected) => {
                                let body_len = buffer.len().saturating_sub(end);
                                if body_len >= expected {
                                    break;
                                }
                            }
                            BodyStrategy::Chunked => {
                                if chunked_body_complete(&buffer[end..]) {
                                    break;
                                }
                            }
                            BodyStrategy::Unknown => {
                                if buffer.len() > 1_000_000 {
                                    break;
                                }
                            }
                        }
                    }

                    if buffer.len() > 1_000_000 {
                        timed_out = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    timed_out = true;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    timed_out = true;
                    break;
                }
                Err(e) => {
                    return Err(PooledError {
                        message: format!("Read error: {}", e),
                        ttfb,
                    })
                }
            }
        }

        if let Some(end) = header_end {
            match body_strategy {
                BodyStrategy::ContentLength(expected) => {
                    let mut remaining = expected.saturating_sub(buffer.len().saturating_sub(end));
                    while remaining > 0 {
                        match stream.read(&mut temp_buf) {
                            Ok(0) => {
                                allow_reuse = false;
                                timed_out = true;
                                break;
                            }
                            Ok(n) => {
                                buffer.extend_from_slice(&temp_buf[..n]);
                                remaining = remaining.saturating_sub(n);
                                if ttfb.is_none() && n > 0 {
                                    ttfb = Some(start.elapsed());
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                timed_out = true;
                                break;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                                timed_out = true;
                                break;
                            }
                            Err(e) => {
                                return Err(PooledError {
                                    message: format!("Read error: {}", e),
                                    ttfb,
                                })
                            }
                        }
                    }

                    if buffer.len().saturating_sub(end) < expected {
                        allow_reuse = false;
                        timed_out = true;
                    }
                }
                BodyStrategy::Chunked => {
                    if !chunked_body_complete(&buffer[end..]) {
                        match Self::drain_chunked(&mut stream, &mut buffer, end, &mut temp_buf) {
                            Ok(true) => {} // Continue
                            Ok(false) => {
                                allow_reuse = false;
                                timed_out = true;
                            }
                            Err(e) => {
                                let ttfb_current = ttfb.unwrap_or_else(|| start.elapsed());
                                return Err(PooledError {
                                    message: e,
                                    ttfb: Some(ttfb_current),
                                });
                            }
                        }
                    }
                }
                BodyStrategy::Unknown => {} // No specific body handling needed
            }
        }

        let status_code =
            Self::parse_status_code(&buffer).map_err(|e| PooledError { message: e, ttfb })?;

        let ttfb_duration = ttfb.unwrap_or_else(|| start.elapsed());

        if timed_out {
            return Err(PooledError {
                message: "Body read timeout".to_string(),
                ttfb: Some(ttfb_duration),
            });
        }

        if self.keep_alive && allow_reuse && status_code < 400 {
            self.pool.return_connection(stream, &host, port, use_tls);
        }

        Ok(PooledResponse {
            status: status_code,
            body: buffer,
            ttfb: ttfb_duration,
        })
    }

    fn parse_url(url: &str) -> Result<(String, u16, String, bool), String> {
        let url = url.trim();

        let (rest, use_tls) = if let Some(stripped) = url.strip_prefix("https://") {
            (stripped, true)
        } else if let Some(stripped) = url.strip_prefix("http://") {
            (stripped, false)
        } else {
            (url, false)
        };

        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        let host_port = parts[0];
        let path = if parts.len() > 1 {
            format!("/{}", parts[1])
        } else {
            "/".to_string()
        };

        let default_port = if use_tls { 443 } else { 80 };
        let (host, port) = if let Some(colon) = host_port.rfind(':') {
            let host_part = &host_port[..colon];
            let port_part = &host_port[colon + 1..];
            let port = port_part
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", port_part))?;
            (host_part.to_string(), port)
        } else {
            (host_port.to_string(), default_port)
        };

        Ok((host, port, path, use_tls))
    }

    fn parse_status_code(response: &[u8]) -> Result<u16, String> {
        let response_str = String::from_utf8_lossy(response);
        let first_line = response_str.lines().next().ok_or("Empty response")?;

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("Invalid HTTP response".to_string());
        }

        parts[1]
            .parse::<u16>()
            .map_err(|_| format!("Invalid status code: {}", parts[1]))
    }

    fn drain_chunked(
        stream: &mut PooledStream,
        buffer: &mut Vec<u8>,
        body_start: usize,
        temp_buf: &mut [u8],
    ) -> Result<bool, String> {
        loop {
            if chunked_body_complete(&buffer[body_start..]) {
                return Ok(true);
            }

            match stream.read(temp_buf) {
                Ok(0) => return Ok(false),
                Ok(n) => buffer.extend_from_slice(&temp_buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Ok(false),
                Err(e) => return Err(format!("Read error: {}", e)),
            }

            if buffer.len() > 1_000_000 {
                return Ok(false);
            }
        }
    }
}
