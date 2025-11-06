use crate::protocols::http::build_default_ssl_connector;
use openssl::ssl::SslStream;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Wrapper around either a raw TCP stream or a negotiated TLS 1.3 client
pub enum PooledStream {
    Plain(TcpStream),
    Tls(SslStream<TcpStream>),
}

impl PooledStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            PooledStream::Plain(stream) => stream.set_read_timeout(timeout),
            PooledStream::Tls(stream) => stream.get_mut().set_read_timeout(timeout),
        }
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            PooledStream::Plain(stream) => stream.set_write_timeout(timeout),
            PooledStream::Tls(stream) => stream.get_mut().set_write_timeout(timeout),
        }
    }

    fn peek(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PooledStream::Plain(stream) => stream.peek(buf),
            PooledStream::Tls(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "peek not supported for TLS streams",
            )),
        }
    }
}

impl Read for PooledStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PooledStream::Plain(stream) => stream.read(buf),
            PooledStream::Tls(stream) => stream.read(buf),
        }
    }
}

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

struct PooledConnection {
    stream: PooledStream,
    last_used: Instant,
}

enum BodyStrategy {
    ContentLength(usize),
    Chunked,
    Unknown,
}

/// Thread-safe connection pool keyed by host/port/protocol
pub struct ConnectionPool {
    pools: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    max_idle_per_host: usize,
    idle_timeout: Duration,
}

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
            let connector =
                build_default_ssl_connector().map_err(|e| format!("TLS setup failed: {}", e))?;
            let addr = format!("{}:{}", host, port);
            let tcp_stream = TcpStream::connect(&addr)
                .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
            let default_timeout = Duration::from_secs(30);
            let _ = tcp_stream.set_read_timeout(Some(default_timeout));
            let _ = tcp_stream.set_write_timeout(Some(default_timeout));
            let ssl_stream = connector
                .connect(host, tcp_stream)
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
    pool: Arc<ConnectionPool>,
    timeout: Duration,
    keep_alive: bool,
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
        let (host, port, path, use_tls) = Self::parse_url(url)?;
        let mut stream = self.pool.get_connection(&host, port, use_tls)?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let connection_header = if self.keep_alive {
            "Connection: keep-alive"
        } else {
            "Connection: close"
        };

        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: RedBlue/1.0\r\n\
             Accept: */*\r\n\
             {}\r\n\
             \r\n",
            path, host, connection_header
        );

        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let mut buffer = Vec::with_capacity(16384);
        let mut temp_buf = [0u8; 8192];
        let mut header_end: Option<usize> = None;
        let mut body_strategy = BodyStrategy::Unknown;
        let mut allow_reuse = self.keep_alive;
        let mut header_parsed = false;

        loop {
            match stream.read(&mut temp_buf) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);

                    if header_end.is_none() {
                        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                        }
                    }

                    if let Some(end) = header_end {
                        if !header_parsed {
                            let (strategy, can_reuse) = Self::analyze_headers(&buffer[..end]);
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
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => return Err(format!("Read error: {}", e)),
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
                                break;
                            }
                            Ok(n) => {
                                buffer.extend_from_slice(&temp_buf[..n]);
                                remaining = remaining.saturating_sub(n);
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                break;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                                break;
                            }
                            Err(e) => return Err(format!("Read error: {}", e)),
                        }
                    }

                    if buffer.len().saturating_sub(end) < expected {
                        allow_reuse = false;
                    }
                }
                BodyStrategy::Chunked => {
                    if !chunked_body_complete(&buffer[end..]) {
                        if !Self::drain_chunked(&mut stream, &mut buffer, end, &mut temp_buf)? {
                            allow_reuse = false;
                        }
                    }
                }
                BodyStrategy::Unknown => {}
            }
        }

        let status_code = Self::parse_status_code(&buffer)?;

        if self.keep_alive && allow_reuse && status_code < 400 {
            self.pool.return_connection(stream, &host, port, use_tls);
        }

        Ok((status_code, buffer))
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

    fn analyze_headers(buffer: &[u8]) -> (BodyStrategy, bool) {
        let header_text = String::from_utf8_lossy(buffer);
        let mut strategy = BodyStrategy::Unknown;
        let mut can_reuse = true;

        for line in header_text.lines().skip(1) {
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim().to_ascii_lowercase();
                let value = line[colon + 1..].trim().to_ascii_lowercase();

                if key == "content-length" {
                    if let Ok(len) = value.parse::<usize>() {
                        strategy = BodyStrategy::ContentLength(len);
                    }
                } else if key == "connection" {
                    if value.contains("close") {
                        can_reuse = false;
                    }
                } else if key == "transfer-encoding" {
                    if value.contains("chunked") {
                        strategy = BodyStrategy::Chunked;
                    } else {
                        can_reuse = false;
                    }
                }
            }
        }

        (strategy, can_reuse)
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

fn chunked_body_complete(data: &[u8]) -> bool {
    let mut index = 0usize;
    loop {
        let line_end = match find_crlf(data, index) {
            Some(pos) => pos,
            None => return false,
        };
        let line = &data[index..line_end];
        let line_str = match str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let size_part = line_str.split(';').next().map(|s| s.trim()).unwrap_or("");
        let chunk_size = match usize::from_str_radix(size_part, 16) {
            Ok(size) => size,
            Err(_) => return false,
        };

        index = line_end + 2;
        if chunk_size == 0 {
            let trailer = &data.get(index..).unwrap_or(&[]);
            if let Some(pos) = trailer.windows(4).position(|w| w == b"\r\n\r\n") {
                return index + pos + 4 <= data.len();
            }
            return false;
        }

        let chunk_end = index + chunk_size;
        if data.len() < chunk_end + 2 {
            return false;
        }
        if &data[chunk_end..chunk_end + 2] != b"\r\n" {
            return false;
        }
        index = chunk_end + 2;
    }
}

fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    data.get(start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|pos| start + pos)
}
