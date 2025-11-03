/// Connection pool for reusing TCP connections
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Connection pool entry
struct PooledConnection {
    stream: TcpStream,
    last_used: std::time::Instant,
}

/// Thread-safe connection pool
pub struct ConnectionPool {
    pools: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    max_idle_per_host: usize,
    idle_timeout: Duration,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            pools: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: 10, // Max 10 idle connections per host
            idle_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_max_idle(mut self, max: usize) -> Self {
        self.max_idle_per_host = max;
        self
    }

    /// Get a connection from the pool or create a new one
    pub fn get_connection(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        let key = format!("{}:{}", host, port);

        // Try to get from pool first
        {
            let mut pools = self.pools.lock().unwrap();
            if let Some(pool) = pools.get_mut(&key) {
                // Remove expired connections
                let now = std::time::Instant::now();
                pool.retain(|conn| now.duration_since(conn.last_used) < self.idle_timeout);

                // Get a connection if available
                if let Some(pooled) = pool.pop() {
                    // Test if connection is still alive
                    if Self::is_alive(&pooled.stream) {
                        return Ok(pooled.stream);
                    }
                    // Connection dead, continue to create new one
                }
            }
        }

        // Create new connection
        let addr = format!("{}:{}", host, port);
        TcpStream::connect(&addr).map_err(|e| format!("Failed to connect to {}: {}", addr, e))
    }

    /// Return a connection to the pool
    pub fn return_connection(&self, stream: TcpStream, host: &str, port: u16) {
        let key = format!("{}:{}", host, port);
        let mut pools = self.pools.lock().unwrap();

        let pool = pools.entry(key).or_insert_with(Vec::new);

        // Only keep if under limit
        if pool.len() < self.max_idle_per_host {
            pool.push(PooledConnection {
                stream,
                last_used: std::time::Instant::now(),
            });
        }
        // else: drop the stream (connection will close)
    }

    /// Check if a TCP connection is still alive
    fn is_alive(stream: &TcpStream) -> bool {
        // Clone the stream to peek
        if let Ok(cloned) = stream.try_clone() {
            // Set very short timeout for peek
            let _ = cloned.set_read_timeout(Some(Duration::from_millis(1)));
            let _ = cloned.set_nonblocking(true);

            // Try to peek - if connection is closed, this will fail
            let mut buf = [0u8; 1];
            match cloned.peek(&mut buf) {
                Ok(0) => false, // Connection closed
                Ok(_) => true,  // Data available (shouldn't happen for idle connections)
                Err(e) => {
                    // WouldBlock means connection is alive but no data
                    e.kind() == std::io::ErrorKind::WouldBlock
                }
            }
        } else {
            false
        }
    }

    /// Clear all connections from pool
    pub fn clear(&self) {
        let mut pools = self.pools.lock().unwrap();
        pools.clear();
    }

    /// Get pool statistics
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

/// HTTP client with connection pooling
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

    /// Perform HTTP GET with connection pooling
    pub fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String> {
        let (host, port, path) = Self::parse_url(url)?;

        // Get connection from pool
        let mut stream = self.pool.get_connection(&host, port)?;

        // Set timeout
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        // Build HTTP/1.1 request with Keep-Alive
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

        // Send request
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("Failed to send request: {}", e))?;

        // Read response (pre-allocate larger buffer to reduce reallocations)
        let mut buffer = Vec::with_capacity(16384); // 16KB pre-allocated
        let mut temp_buf = [0u8; 8192]; // 8KB temp buffer (doubled from 4KB)

        loop {
            match stream.read(&mut temp_buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);

                    // Check if we have complete response headers
                    if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                        // For now, read a bit more for body
                        // In production, would parse Content-Length
                        if buffer.len() > 200 {
                            break;
                        }
                    }

                    if buffer.len() > 1_000_000 {
                        // 1MB limit
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => return Err(format!("Read error: {}", e)),
            }
        }

        // Parse status code
        let status_code = Self::parse_status_code(&buffer)?;

        // Return connection to pool if keep-alive
        if self.keep_alive && status_code < 400 {
            self.pool.return_connection(stream, &host, port);
        }
        // else: connection will be dropped and closed

        Ok((status_code, buffer))
    }

    fn parse_url(url: &str) -> Result<(String, u16, String), String> {
        let url = url.trim();

        // Remove http:// or https://
        let url = if url.starts_with("http://") {
            &url[7..]
        } else if url.starts_with("https://") {
            return Err("HTTPS not supported in pooled client yet".to_string());
        } else {
            url
        };

        // Split host and path
        let parts: Vec<&str> = url.splitn(2, '/').collect();
        let host_port = parts[0];
        let path = if parts.len() > 1 {
            format!("/{}", parts[1])
        } else {
            "/".to_string()
        };

        // Parse host and port
        let (host, port) = if host_port.contains(':') {
            let hp: Vec<&str> = host_port.splitn(2, ':').collect();
            let port = hp[1]
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", hp[1]))?;
            (hp[0].to_string(), port)
        } else {
            (host_port.to_string(), 80)
        };

        Ok((host, port, path))
    }

    fn parse_status_code(response: &[u8]) -> Result<u16, String> {
        let response_str = String::from_utf8_lossy(response);
        let first_line = response_str.lines().next().ok_or("Empty response")?;

        // Parse "HTTP/1.1 200 OK"
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("Invalid HTTP response".to_string());
        }

        parts[1]
            .parse::<u16>()
            .map_err(|_| format!("Invalid status code: {}", parts[1]))
    }
}
