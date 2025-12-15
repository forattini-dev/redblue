//! HTTP Server Implementation
//!
//! Multi-threaded HTTP server for static file serving.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::embedded::EmbeddedFiles;
use super::mime::MimeType;

/// Route handler type
pub type RouteHandler = Box<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>;

/// HTTP server configuration
#[derive(Clone)]
pub struct HttpServerConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Root directory for file serving
    pub root_dir: PathBuf,
    /// Enable directory listing
    pub dir_listing: bool,
    /// Enable CORS headers
    pub cors: bool,
    /// Request timeout
    pub timeout: Duration,
    /// Enable logging
    pub log_requests: bool,
    /// Number of worker threads
    pub workers: usize,
    /// Serve embedded files (hook.js, etc.)
    pub serve_embedded: bool,
    /// Serve self-binary at /rb
    pub serve_self: bool,
    /// Dynamic routes
    pub routes: HashMap<String, Arc<RouteHandler>>,
}

impl fmt::Debug for HttpServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpServerConfig")
            .field("listen_addr", &self.listen_addr)
            .field("root_dir", &self.root_dir)
            .field("dir_listing", &self.dir_listing)
            .field("cors", &self.cors)
            .field("timeout", &self.timeout)
            .field("log_requests", &self.log_requests)
            .field("workers", &self.workers)
            .field("serve_embedded", &self.serve_embedded)
            .field("serve_self", &self.serve_self)
            .field("routes", &format!("{} routes", self.routes.len()))
            .finish()
    }
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            root_dir: PathBuf::from("."),
            dir_listing: true,
            cors: true,
            timeout: Duration::from_secs(30),
            log_requests: true,
            workers: 4,
            serve_embedded: true,
            serve_self: true,
            routes: HashMap::new(),
        }
    }
}

impl HttpServerConfig {
    /// Create default config
    pub fn new() -> Self {
        Self::default()
    }

    /// Create config with listen address
    pub fn with_addr(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            ..Default::default()
        }
    }

    /// Set port
    pub fn port(mut self, port: u16) -> Self {
        self.listen_addr.set_port(port);
        self
    }

    /// Set host
    pub fn host(mut self, host: &str) -> Self {
        if let Ok(addr) = format!("{}:{}", host, self.listen_addr.port()).parse() {
            self.listen_addr = addr;
        }
        self
    }

    /// Set root directory
    pub fn root_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.root_dir = dir.into();
        self
    }

    /// Set root directory (alias)
    pub fn with_root_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.root_dir = dir.into();
        self
    }

    /// Set index file
    pub fn index_file(self, _name: &str) -> Self {
        // Index file is always index.html for now
        self
    }

    /// Enable/disable directory listing
    pub fn with_dir_listing(mut self, enabled: bool) -> Self {
        self.dir_listing = enabled;
        self
    }

    /// Disable directory listing
    pub fn disable_dir_listing(mut self) -> Self {
        self.dir_listing = false;
        self
    }

    /// Enable/disable CORS
    pub fn with_cors(mut self, enabled: bool) -> Self {
        self.cors = enabled;
        self
    }

    /// Enable CORS for all origins
    pub fn cors_all(mut self) -> Self {
        self.cors = true;
        self
    }

    /// Enable serving self binary at /rb
    pub fn serve_self(mut self) -> Self {
        self.serve_self = true;
        self
    }

    /// Enable/disable request logging
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_requests = enabled;
        self
    }

    /// Set number of worker threads
    pub fn with_workers(mut self, n: usize) -> Self {
        self.workers = n.max(1);
        self
    }

    /// Add a dynamic route handler
    pub fn add_route<F>(mut self, path: &str, handler: F) -> Self
    where
        F: Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    {
        self.routes
            .insert(path.to_string(), Arc::new(Box::new(handler)));
        self
    }
}

/// Server statistics
#[derive(Debug, Default)]
pub struct ServerStats {
    pub requests_total: AtomicU64,
    pub requests_ok: AtomicU64,
    pub requests_not_found: AtomicU64,
    pub requests_error: AtomicU64,
    pub bytes_sent: AtomicU64,
}

impl ServerStats {
    pub fn new() -> Self {
        Self::default()
    }
}

/// HTTP Server
#[derive(Clone)]
pub struct HttpServer {
    pub config: HttpServerConfig,
    stats: Arc<ServerStats>,
    running: Arc<AtomicBool>,
    bound_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl HttpServer {
    /// Create new HTTP server
    pub fn new(config: HttpServerConfig) -> Self {
        Self {
            config,
            stats: Arc::new(ServerStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            bound_addr: Arc::new(Mutex::new(None)),
        }
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the server
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get server statistics
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Get the bound address (useful if port 0 was used)
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.bound_addr.lock().unwrap()
    }

    /// Run the server
    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr)?;
        listener.set_nonblocking(true)?;

        // Update bound address
        if let Ok(addr) = listener.local_addr() {
            *self.bound_addr.lock().unwrap() = Some(addr);
        }

        self.running.store(true, Ordering::Relaxed);

        if self.config.log_requests {
            let addr = self.local_addr().unwrap_or(self.config.listen_addr);
            eprintln!("[HTTP] Server listening on http://{}", addr);
            eprintln!("[HTTP] Serving files from {:?}", self.config.root_dir);
            if self.config.cors {
                eprintln!("[HTTP] CORS enabled (Access-Control-Allow-Origin: *)");
            }
            if !self.config.routes.is_empty() {
                eprintln!(
                    "[HTTP] Active routes: {:?}",
                    self.config.routes.keys().collect::<Vec<_>>()
                );
            }
        }

        while self.running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, addr)) => {
                    let config = self.config.clone();
                    let stats = self.stats.clone();
                    let running = self.running.clone();

                    thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, addr, &config, &stats) {
                            if config.log_requests {
                                eprintln!("[HTTP] Error handling {}: {}", addr, e);
                            }
                            stats.requests_error.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    if self.config.log_requests {
                        eprintln!("[HTTP] Accept error: {}", e);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single HTTP connection
fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    config: &HttpServerConfig,
    stats: &ServerStats,
) -> io::Result<()> {
    stream.set_read_timeout(Some(config.timeout))?;
    stream.set_write_timeout(Some(config.timeout))?;

    stats.requests_total.fetch_add(1, Ordering::Relaxed);

    // Parse request
    let request = match parse_request(&mut stream) {
        Ok(req) => req,
        Err(e) => {
            // If we can't even parse headers, likely garbage or SSL handshake attempt on plain HTTP
            return Err(e);
        }
    };

    if config.log_requests {
        eprintln!(
            "[HTTP] {} {} {} {}",
            addr.ip(),
            request.method,
            request.path,
            request.version
        );
    }

    // Handle CORS preflight
    if request.method == "OPTIONS" && config.cors {
        send_cors_preflight(&mut stream, config)?;
        return Ok(());
    }

    // Check dynamic routes first
    if let Some(handler) = config.routes.get(&request.path) {
        let response = handler(&request);

        let bytes = send_response(
            &mut stream,
            response.status_code,
            response
                .headers
                .get("Content-Type")
                .map(|s| s.as_str())
                .unwrap_or("text/plain"),
            &response.body,
            config,
            request.method == "HEAD",
        )?;
        stats.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        stats.requests_ok.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }

    // Only handle GET and HEAD for static files
    if request.method != "GET" && request.method != "HEAD" {
        send_error(&mut stream, 405, "Method Not Allowed", config)?;
        return Ok(());
    }

    // Decode URL path
    let decoded_path = url_decode(&request.path);
    let clean_path = sanitize_path(&decoded_path);

    // Try embedded files first
    if config.serve_embedded {
        if let Some((content, mime)) = EmbeddedFiles::get(&clean_path) {
            let bytes = send_response(
                &mut stream,
                200,
                mime,
                content.as_bytes(),
                config,
                request.method == "HEAD",
            )?;
            stats.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
            stats.requests_ok.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    // Serve self-binary at /rb
    if config.serve_self && (clean_path == "/rb" || clean_path == "rb") {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Ok(data) = fs::read(&exe_path) {
                let bytes = send_response(
                    &mut stream,
                    200,
                    "application/octet-stream",
                    &data,
                    config,
                    request.method == "HEAD",
                )?;
                stats.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
                stats.requests_ok.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }
    }

    // Build filesystem path
    let fs_path = config.root_dir.join(clean_path.trim_start_matches('/'));

    // Check if path exists
    if !fs_path.exists() {
        send_error(&mut stream, 404, "Not Found", config)?;
        stats.requests_not_found.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }

    // Handle directory
    if fs_path.is_dir() {
        // Try index.html
        let index_path = fs_path.join("index.html");
        if index_path.exists() {
            return serve_file(
                &mut stream,
                &index_path,
                config,
                stats,
                request.method == "HEAD",
            );
        }

        // Directory listing
        if config.dir_listing {
            let html = generate_directory_listing(&fs_path, &clean_path)?;
            let bytes = send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                html.as_bytes(),
                config,
                request.method == "HEAD",
            )?;
            stats.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
            stats.requests_ok.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        } else {
            send_error(&mut stream, 403, "Forbidden", config)?;
            return Ok(());
        }
    }

    // Serve file
    serve_file(
        &mut stream,
        &fs_path,
        config,
        stats,
        request.method == "HEAD",
    )
}

/// Serve a file
fn serve_file(
    stream: &mut TcpStream,
    path: &Path,
    config: &HttpServerConfig,
    stats: &ServerStats,
    head_only: bool,
) -> io::Result<()> {
    let mime = MimeType::from_path(path);
    let data = fs::read(path)?;

    let bytes = send_response(stream, 200, &mime.as_str(), &data, config, head_only)?;
    stats.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    stats.requests_ok.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// HTTP request
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status_code: u16, body: Vec<u8>) -> Self {
        Self {
            status_code,
            headers: HashMap::new(),
            body,
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }
}

/// Parse HTTP request
fn parse_request(stream: &mut TcpStream) -> io::Result<HttpRequest> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();

    // Read request line
    reader.read_line(&mut line)?;
    let parts: Vec<&str> = line.trim().split_whitespace().collect();

    if parts.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid request line",
        ));
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();
    let version = parts[2].to_string();

    // Parse headers
    let mut headers = HashMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    // Read body if content-length matches
    let mut body = Vec::new();
    if let Some(len_str) = headers.get("content-length") {
        if let Ok(len) = len_str.parse::<usize>() {
            if len > 0 {
                body.resize(len, 0);
                reader.read_exact(&mut body)?;
            }
        }
    }

    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
        body,
    })
}

/// Send HTTP response
fn send_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    config: &HttpServerConfig,
    head_only: bool,
) -> io::Result<usize> {
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let mut response = format!(
        "HTTP/1.1 {} {}\n\
         Content-Type: {}\n\
         Content-Length: {}\n\
         Connection: close\n\
         Server: redblue\n",
        status,
        status_text,
        content_type,
        body.len()
    );

    // Add CORS headers
    if config.cors {
        response.push_str("Access-Control-Allow-Origin: *\r\n");
        response.push_str("Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n");
        response.push_str("Access-Control-Allow-Headers: *\r\n");
    }

    response.push_str("\r\n");

    stream.write_all(response.as_bytes())?;

    if !head_only {
        stream.write_all(body)?;
    }

    stream.flush()?;

    Ok(response.len() + if head_only { 0 } else { body.len() })
}

/// Send error response
fn send_error(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
    config: &HttpServerConfig,
) -> io::Result<()> {
    let body = if status == 404 {
        EmbeddedFiles::not_found_html().to_string()
    } else {
        format!(
            "<!DOCTYPE html><html><head><title>{} {}</title></head>\n             <body><h1>{} {}</h1></body></html>",
            status, message, status, message
        )
    };

    send_response(
        stream,
        status,
        "text/html; charset=utf-8",
        body.as_bytes(),
        config,
        false,
    )?;
    Ok(())
}

/// Send CORS preflight response
fn send_cors_preflight(stream: &mut TcpStream, config: &HttpServerConfig) -> io::Result<()> {
    let response = "HTTP/1.1 204 No Content\r\n\
                    Access-Control-Allow-Origin: *\r\n\
                    Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n\
                    Access-Control-Allow-Headers: *\r\n\
                    Access-Control-Max-Age: 86400\r\n\
                    Connection: close\r\n\
                    \r\n";
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// URL decode
fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

/// Sanitize path to prevent directory traversal
fn sanitize_path(path: &str) -> String {
    // Split path and filter dangerous components
    let parts: Vec<&str> = path
        .split('/')
        .filter(|p| !p.is_empty() && *p != "." && *p != "..")
        .collect();

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Generate directory listing HTML
fn generate_directory_listing(dir: &Path, url_path: &str) -> io::Result<String> {
    let template = EmbeddedFiles::directory_listing_template();

    let mut entries = String::new();
    let mut items: Vec<_> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();

    // Sort: directories first, then alphabetically
    items.sort_by(|a, b| {
        let a_dir = a.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let b_dir = b.file_type().map(|t| t.is_dir()).unwrap_or(false);
        match (a_dir, b_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.file_name().cmp(&b.file_name()),
        }
    });

    for entry in items {
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata()?;
        let is_dir = meta.is_dir();

        let display_name = if is_dir {
            format!("{}/", name)
        } else {
            name.clone()
        };

        let href = format!(
            "{}{} {}",
            url_path.trim_end_matches('/'),
            if url_path.ends_with('/') { "" } else { "/" },
            &name
        );

        let size = if is_dir {
            "-".to_string()
        } else {
            format_size(meta.len())
        };

        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| format_timestamp(d.as_secs()))
            .unwrap_or_else(|| "-".to_string());

        let class = if is_dir { "dir" } else { "file" };

        entries.push_str(&format!(
            "            <tr><td><a href=\"{}\" class=\"{} \">{}</a></td><td class=\"size\">{}</td><td class=\"date\">{}</td></tr>\n",
            href, class, display_name, size, modified
        ));
    }

    let parent = if url_path != "/" {
        let parent_path = Path::new(url_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());
        format!(
            "<p class=\"parent\"><a href=\"{}\">../</a> (parent directory)</p>",
            parent_path
        )
    } else {
        String::new()
    };

    Ok(template
        .replace("{{PATH}}", url_path)
        .replace("{{PARENT}}", &parent)
        .replace("{{ENTRIES}}", &entries))
}

/// Format file size
fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size >= GB {
        format!("{:.1} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.1} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.1} KB", size as f64 / KB as f64)
    } else {
        format!("{} B", size)
    }
}

/// Format timestamp
fn format_timestamp(secs: u64) -> String {
    // Simple timestamp formatting without external deps
    let days = secs / 86400;
    let years = 1970 + (days / 365); // Approximation
    let month_day = days % 365;
    let month = month_day / 30 + 1;
    let day = month_day % 30 + 1;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        years, month, day, hours, mins
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("test%2Fpath"), "test/path");
        assert_eq!(url_decode("normal"), "normal");
    }

    #[test]
    fn test_sanitize_path() {
        assert_eq!(sanitize_path("/"), "/");
        assert_eq!(sanitize_path("/foo/bar"), "/foo/bar");
        assert_eq!(sanitize_path("/../../../etc/passwd"), "/etc/passwd");
        assert_eq!(sanitize_path("/foo/../bar"), "/foo/bar");
        assert_eq!(sanitize_path("./test"), "/test");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(100), "100 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_config_builder() {
        let config = HttpServerConfig::with_addr("0.0.0.0:9999".parse().unwrap())
            .with_root_dir("/var/www")
            .with_cors(false)
            .with_dir_listing(false)
            .with_workers(8);

        assert_eq!(config.listen_addr.port(), 9999);
        assert_eq!(config.root_dir, PathBuf::from("/var/www"));
        assert!(!config.cors);
        assert!(!config.dir_listing);
        assert_eq!(config.workers, 8);
    }
}
