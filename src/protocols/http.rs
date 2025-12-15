/// HTTP/1.1 Protocol Implementation from Scratch
/// RFC 2616 - Hypertext Transfer Protocol
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config;
use crate::protocols::tls_impersonator::TlsProfile;
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

mod body;
pub mod pool;
use self::{
    body::{analyze_headers, chunked_body_complete, decode_chunked_body, find_crlf, BodyStrategy},
    pool::{ConnectionPool, PooledStream},
};

/// Middleware layer that can intercept, modify, or short-circuit HTTP dispatches.
pub trait HttpMiddleware: Send + Sync {
    fn handle(
        &self,
        options: HttpDispatchOptions,
        ctx: &MiddlewareContext,
    ) -> Result<HttpDispatchResult, HttpSendError>;
}

/// Simple logging middleware that prints method/path/status for each request.
pub struct LoggingMiddleware;

impl HttpMiddleware for LoggingMiddleware {
    fn handle(
        &self,
        options: HttpDispatchOptions,
        ctx: &MiddlewareContext,
    ) -> Result<HttpDispatchResult, HttpSendError> {
        let method = options.request.method.clone();
        let path = options.request.path.clone();
        let started = Instant::now();
        let result = ctx.next(options);
        match &result {
            Ok(res) => {
                println!(
                    "[http] {} {} -> {} ({:?})",
                    method,
                    path,
                    res.response.status_code,
                    started.elapsed()
                );
            }
            Err(err) => {
                println!("[http] {} {} failed: {}", method, path, err.message);
            }
        }
        result
    }
}

pub struct MiddlewareContext<'a> {
    dispatcher: &'a HttpDispatcher,
    index: usize,
}

impl<'a> MiddlewareContext<'a> {
    pub fn next(&self, options: HttpDispatchOptions) -> Result<HttpDispatchResult, HttpSendError> {
        self.dispatcher.run_middlewares(self.index + 1, options)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    host: String,
    port: u16,
    scheme: Scheme,
    pub tls_profile: Option<TlsProfile>,
}

impl HttpRequest {
    pub fn new(method: &str, url: &str) -> Self {
        let parsed = Self::parse_url(url);

        let mut headers = HashMap::new();
        let host_header = if parsed.port != parsed.scheme.default_port() {
            format!("{}:{}", parsed.host, parsed.port)
        } else {
            parsed.host.clone()
        };
        headers.insert("Host".to_string(), host_header);
        headers.insert("User-Agent".to_string(), "RedBlue-Tool/0.1".to_string());
        headers.insert("Accept".to_string(), "*/*".to_string());
        headers.insert("Connection".to_string(), "close".to_string());

        Self {
            method: method.to_string(),
            path: parsed.path,
            version: "HTTP/1.1".to_string(),
            headers,
            body: Vec::new(),
            host: parsed.host,
            port: parsed.port,
            scheme: parsed.scheme,
            tls_profile: None,
        }
    }

    pub fn get(url: &str) -> Self {
        Self::new("GET", url)
    }

    pub fn post(url: &str) -> Self {
        Self::new("POST", url)
    }

    pub fn head(url: &str) -> Self {
        Self::new("HEAD", url)
    }

    pub fn put(url: &str) -> Self {
        Self::new("PUT", url)
    }

    pub fn delete(url: &str) -> Self {
        Self::new("DELETE", url)
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_tls_profile(mut self, profile: TlsProfile) -> Self {
        self.tls_profile = Some(profile);
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.headers
            .insert("Content-Length".to_string(), body.len().to_string());
        self.body = body;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-allocate buffer with estimated size
        // Request line (~50) + headers (~200) + body length
        let estimated_size = 250 + self.body.len();
        let mut request = Vec::with_capacity(estimated_size);

        // Request line
        let request_line = format!("{} {} {}\r\n", self.method, self.path, self.version);
        request.extend_from_slice(request_line.as_bytes());

        // Headers
        for (key, value) in &self.headers {
            let header_line = format!("{}: {}\r\n", key, value);
            request.extend_from_slice(header_line.as_bytes());
        }

        // Empty line
        request.extend_from_slice(b"\r\n");

        // Body
        request.extend_from_slice(&self.body);

        request
    }

    pub fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.to_bytes()).to_string()
    }

    fn parse_url(url: &str) -> ParsedUrl {
        let (scheme, remainder) = if let Some(rest) = url.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else if let Some(rest) = url.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else {
            (Scheme::Http, url)
        };

        let (host_port, path) = match remainder.find('/') {
            Some(idx) => (&remainder[..idx], &remainder[idx..]),
            None => (remainder, "/"),
        };

        let (host, port) = if host_port.starts_with('[') {
            if let Some(end_bracket) = host_port.find(']') {
                let host = host_port[1..end_bracket].to_string();
                let port = host_port[end_bracket + 1..]
                    .strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or_else(|| scheme.default_port());
                (host, port)
            } else {
                (host_port.to_string(), scheme.default_port())
            }
        } else if let Some(colon) = host_port.rfind(':') {
            let host = host_port[..colon].to_string();
            let port = host_port[colon + 1..]
                .parse::<u16>()
                .unwrap_or_else(|_| scheme.default_port());
            (host, port)
        } else {
            (host_port.to_string(), scheme.default_port())
        };

        let path = if path.is_empty() { "/" } else { path }.to_string();

        ParsedUrl {
            scheme,
            host,
            port,
            path,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_https(&self) -> bool {
        self.scheme == Scheme::Https
    }

    /// Build the full URL from scheme, host, port, and path
    pub fn full_url(&self) -> String {
        let scheme_str = if self.scheme == Scheme::Https {
            "https"
        } else {
            "http"
        };
        let default_port = self.scheme.default_port();

        if self.port == default_port {
            format!("{}://{}{}", scheme_str, self.host, self.path)
        } else {
            format!("{}://{}:{}{}", scheme_str, self.host, self.port, self.path)
        }
    }

    /// Parse an HTTP request from bytes (Server-side helper)
    pub fn parse(data: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(data);
        let mut lines = text.lines();

        // Request line: GET /path HTTP/1.1
        let request_line = lines.next()?;
        let parts: Vec<_> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let version = parts[2].to_string();

        let mut headers = HashMap::new();
        let mut host = "localhost".to_string();
        let mut port = 80;

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim().to_string();
                let value = line[colon + 1..].trim().to_string();
                if key.eq_ignore_ascii_case("host") {
                    host = value.clone();
                    // Try to parse port from host header
                    if let Some(colon_idx) = host.find(':') {
                        if let Ok(p) = host[colon_idx + 1..].parse() {
                            port = p;
                        }
                    }
                }
                headers.insert(key, value);
            }
        }

        let body_sep = data.windows(4).position(|w| w == b"\r\n\r\n");
        let body = if let Some(pos) = body_sep {
            data[pos + 4..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            method,
            path,
            version,
            headers,
            body,
            host,
            port,
            scheme: Scheme::Http,
            tls_profile: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        let separator = data
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| "Malformed HTTP response: missing header separator".to_string())?;

        let header_bytes = &data[..separator];
        let mut body = data[separator + 4..].to_vec();

        let head = parse_response_head(header_bytes)?;

        let is_chunked = head
            .headers
            .get("Transfer-Encoding")
            .map(|value| value.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);

        if is_chunked {
            body = decode_chunked_body(&body)?;
        }

        Ok(Self {
            version: head.version,
            status_code: head.status_code,
            status_text: head.status_text,
            headers: head.headers,
            body,
        })
    }

    /// Alias for from_bytes (compatibility)
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::from_bytes(data)
    }

    pub fn body_as_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
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

    /// Create a simple response (Server-side helper)
    pub fn simple(status_code: u16, status_text: &str, body: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Content-Length".to_string(), body.len().to_string());
        headers.insert("Content-Type".to_string(), "text/plain".to_string());
        headers.insert("Server".to_string(), "RedBlue/0.1".to_string());
        headers.insert("Connection".to_string(), "close".to_string());

        Self {
            version: "HTTP/1.1".to_string(),
            status_code,
            status_text: status_text.to_string(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponseHead {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
}

fn parse_response_head(header_bytes: &[u8]) -> Result<HttpResponseHead, String> {
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.split("\r\n").filter(|line| !line.is_empty());

    let status_line = lines.next().ok_or("Empty response")?;
    let status_parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if status_parts.len() < 2 {
        return Err("Invalid status line".to_string());
    }

    let version = status_parts[0].to_string();
    let status_code = status_parts[1]
        .parse::<u16>()
        .map_err(|_| "Invalid status code")?;
    let status_text = if status_parts.len() > 2 {
        status_parts[2..].join(" ")
    } else {
        String::new()
    };

    let mut headers = HashMap::new();
    for line in lines {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    Ok(HttpResponseHead {
        version,
        status_code,
        status_text,
        headers,
    })
}

pub trait HttpResponseHandler {
    fn on_head(&mut self, _head: &HttpResponseHead) -> Result<(), String> {
        Ok(())
    }

    fn on_chunk(&mut self, _chunk: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn on_complete(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct HttpSendError {
    pub message: String,
    pub ttfb: Option<Duration>,
}

impl From<String> for HttpSendError {
    fn from(message: String) -> Self {
        Self {
            message,
            ttfb: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HttpDispatchMetrics {
    pub ttfb: Duration,
}

pub struct HttpDispatchResult {
    pub response: HttpResponse,
    pub metrics: HttpDispatchMetrics,
}

struct ReadOutcome {
    buffer: Vec<u8>,
    ttfb: Duration,
    reusable: bool,
}

#[derive(Debug, Clone)]
pub struct HttpDispatchOptions {
    pub request: HttpRequest,
    pub keep_alive: bool,
    pub idempotent: bool,
    pub blocking: bool,
    pub headers_timeout: Option<Duration>,
    pub body_timeout: Option<Duration>,
    pub max_response_bytes: Option<usize>,
    pub expect_continue: bool,
    pub max_retries: Option<usize>,
    pub tls_profile: Option<TlsProfile>,
}

impl HttpDispatchOptions {
    pub fn new(request: HttpRequest) -> Self {
        let tls_profile = request.tls_profile;
        let method = request.method.to_ascii_uppercase();
        Self {
            request,
            keep_alive: true,
            idempotent: matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE"),
            blocking: method.as_str() != "HEAD",
            headers_timeout: None,
            body_timeout: None,
            max_response_bytes: None,
            expect_continue: false,
            max_retries: None,
            tls_profile,
        }
    }

    pub fn with_keep_alive(mut self, keep_alive: bool) -> Self {
        self.keep_alive = keep_alive;
        self
    }

    pub fn with_headers_timeout(mut self, timeout: Duration) -> Self {
        self.headers_timeout = Some(timeout);
        self
    }

    pub fn with_body_timeout(mut self, timeout: Duration) -> Self {
        self.body_timeout = Some(timeout);
        self
    }

    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = Some(limit);
        self
    }

    pub fn with_max_retries(mut self, retries: usize) -> Self {
        self.max_retries = Some(retries);
        self
    }
}

impl From<HttpRequest> for HttpDispatchOptions {
    fn from(request: HttpRequest) -> Self {
        Self::new(request)
    }
}

fn resolve_timeout(input: Option<Duration>, default_value: Duration) -> Option<Duration> {
    match input {
        Some(duration) if duration.is_zero() => None,
        Some(duration) => Some(duration),
        None => Some(default_value),
    }
}

#[derive(Clone)]
pub struct HttpDispatcher {
    request_delay_ms: u64,
    connect_timeout: Duration,
    default_headers_timeout: Duration,
    default_body_timeout: Duration,
    default_max_response_bytes: usize,
    default_max_retries: usize,
    keep_alive_default: bool,
    pool: Arc<ConnectionPool>,
    middlewares: Vec<Arc<dyn HttpMiddleware>>,
}

impl std::fmt::Debug for HttpDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDispatcher")
            .field("request_delay_ms", &self.request_delay_ms)
            .field("connect_timeout", &self.connect_timeout)
            .field("default_headers_timeout", &self.default_headers_timeout)
            .field("default_body_timeout", &self.default_body_timeout)
            .field(
                "default_max_response_bytes",
                &self.default_max_response_bytes,
            )
            .field("default_max_retries", &self.default_max_retries)
            .field("keep_alive_default", &self.keep_alive_default)
            .field("pool", &self.pool)
            .field(
                "middlewares",
                &format!("{} middlewares", self.middlewares.len()),
            )
            .finish()
    }
}

impl HttpDispatcher {
    pub fn new() -> Self {
        let cfg = config::get();
        let timeout = Duration::from_secs(cfg.web.timeout_secs.max(1));
        Self {
            request_delay_ms: cfg.network.request_delay_ms,
            connect_timeout: timeout,
            default_headers_timeout: timeout,
            default_body_timeout: timeout,
            default_max_response_bytes: 1_000_000,
            default_max_retries: cfg.network.max_retries,
            keep_alive_default: true,
            pool: Arc::new(ConnectionPool::new()),
            middlewares: Vec::new(),
        }
    }

    pub fn with_uniform_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self.default_headers_timeout = timeout;
        self.default_body_timeout = timeout;
        self
    }

    pub fn with_connection_pool(mut self, pool: Arc<ConnectionPool>) -> Self {
        self.pool = pool;
        self
    }

    pub fn with_keep_alive_default(mut self, keep_alive: bool) -> Self {
        self.keep_alive_default = keep_alive;
        self
    }

    pub fn with_middleware(mut self, middleware: Arc<dyn HttpMiddleware>) -> Self {
        self.middlewares.push(middleware);
        self
    }

    /// Set the default max response bytes limit
    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.default_max_response_bytes = limit;
        self
    }

    fn run_middlewares(
        &self,
        index: usize,
        options: HttpDispatchOptions,
    ) -> Result<HttpDispatchResult, HttpSendError> {
        if index >= self.middlewares.len() {
            return self.dispatch_inner(options);
        }

        let ctx = MiddlewareContext {
            dispatcher: self,
            index,
        };
        self.middlewares[index].handle(options, &ctx)
    }

    pub fn dispatch(
        &self,
        options: HttpDispatchOptions,
    ) -> Result<HttpDispatchResult, HttpSendError> {
        self.run_middlewares(0, options)
    }

    pub fn dispatch_with_handler<H: HttpResponseHandler>(
        &self,
        mut options: HttpDispatchOptions,
        handler: &mut H,
    ) -> Result<(HttpResponseHead, HttpDispatchMetrics), HttpSendError> {
        if self.request_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.request_delay_ms));
        }

        let headers_timeout =
            resolve_timeout(options.headers_timeout, self.default_headers_timeout);
        let body_timeout = resolve_timeout(options.body_timeout, self.default_body_timeout);
        let max_response_bytes = match options.max_response_bytes {
            Some(0) => None,
            Some(limit) => Some(limit),
            None => Some(self.default_max_response_bytes),
        };
        let connection_value = if options.keep_alive {
            "keep-alive".to_string()
        } else {
            "close".to_string()
        };
        options
            .request
            .headers
            .insert("Connection".to_string(), connection_value);

        let request = options.request;
        let request_bytes = request.to_bytes();
        let mut attempts = 0usize;
        let max_retries = options.max_retries.unwrap_or(self.default_max_retries);

        loop {
            match self.dispatch_once_with_handler(
                &request,
                &request_bytes,
                headers_timeout,
                body_timeout,
                max_response_bytes,
                options.keep_alive,
                handler,
            ) {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if !options.idempotent || attempts >= max_retries {
                        return Err(err);
                    }
                    attempts += 1;
                }
            }
        }
    }

    fn dispatch_inner(
        &self,
        mut options: HttpDispatchOptions,
    ) -> Result<HttpDispatchResult, HttpSendError> {
        if self.request_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.request_delay_ms));
        }

        let headers_timeout =
            resolve_timeout(options.headers_timeout, self.default_headers_timeout);
        let body_timeout = resolve_timeout(options.body_timeout, self.default_body_timeout);
        let max_response_bytes = match options.max_response_bytes {
            Some(0) => None,
            Some(limit) => Some(limit),
            None => Some(self.default_max_response_bytes),
        };
        let max_retries = options.max_retries.unwrap_or(self.default_max_retries);

        let connection_value = if options.keep_alive {
            "keep-alive".to_string()
        } else {
            "close".to_string()
        };
        options
            .request
            .headers
            .insert("Connection".to_string(), connection_value);

        let request = options.request;
        let request_bytes = request.to_bytes();

        let mut attempts = 0usize;
        loop {
            match self.dispatch_once(
                &request,
                &request_bytes,
                headers_timeout,
                body_timeout,
                max_response_bytes,
                options.keep_alive,
            ) {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if !options.idempotent || attempts >= max_retries {
                        return Err(err);
                    }
                    attempts += 1;
                }
            }
        }
    }

    fn dispatch_once(
        &self,
        request: &HttpRequest,
        request_bytes: &[u8],
        headers_timeout: Option<Duration>,
        body_timeout: Option<Duration>,
        max_response_bytes: Option<usize>,
        keep_alive_requested: bool,
    ) -> Result<HttpDispatchResult, HttpSendError> {
        let host = request.host().to_string();
        let port = request.port();
        let use_tls = request.is_https();

        let mut stream = self
            .pool
            .get_connection(&host, port, use_tls)
            .map_err(HttpSendError::from)?;
        stream
            .set_write_timeout(Some(self.connect_timeout))
            .map_err(|e| HttpSendError::from(format!("Failed to set write timeout: {}", e)))?;

        let start = Instant::now();
        stream
            .write_all(request_bytes)
            .map_err(|e| HttpSendError::from(format!("Write failed: {}", e)))?;
        stream
            .flush()
            .map_err(|e| HttpSendError::from(format!("Failed to flush request: {}", e)))?;

        let read_outcome = read_response_with_ttfb(
            &mut stream,
            start,
            headers_timeout,
            body_timeout,
            max_response_bytes,
            keep_alive_requested,
        )?;

        let response =
            HttpResponse::from_bytes(&read_outcome.buffer).map_err(|e| HttpSendError {
                message: e,
                ttfb: Some(read_outcome.ttfb),
            })?;

        if keep_alive_requested && read_outcome.reusable && response.status_code < 400 {
            self.pool.return_connection(stream, &host, port, use_tls);
        }

        Ok(HttpDispatchResult {
            response,
            metrics: HttpDispatchMetrics {
                ttfb: read_outcome.ttfb,
            },
        })
    }

    fn dispatch_once_with_handler<H: HttpResponseHandler>(
        &self,
        request: &HttpRequest,
        request_bytes: &[u8],
        headers_timeout: Option<Duration>,
        body_timeout: Option<Duration>,
        max_response_bytes: Option<usize>,
        keep_alive_requested: bool,
        handler: &mut H,
    ) -> Result<(HttpResponseHead, HttpDispatchMetrics), HttpSendError> {
        let host = request.host().to_string();
        let port = request.port();
        let use_tls = request.is_https();

        let mut stream = self
            .pool
            .get_connection(&host, port, use_tls)
            .map_err(HttpSendError::from)?;
        stream
            .set_write_timeout(Some(self.connect_timeout))
            .map_err(|e| HttpSendError::from(format!("Failed to set write timeout: {}", e)))?;

        let start = Instant::now();
        stream
            .write_all(request_bytes)
            .map_err(|e| HttpSendError::from(format!("Write failed: {}", e)))?;
        stream
            .flush()
            .map_err(|e| HttpSendError::from(format!("Failed to flush request: {}", e)))?;

        let (head, metrics, allow_reuse) = read_response_streaming(
            &mut stream,
            start,
            headers_timeout,
            body_timeout,
            max_response_bytes,
            handler,
        )?;

        if keep_alive_requested && allow_reuse && head.status_code < 400 {
            self.pool.return_connection(stream, &host, port, use_tls);
        }

        Ok((head, metrics))
    }
}

#[derive(Debug)]
pub struct HttpClient {
    dispatcher: HttpDispatcher,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            dispatcher: HttpDispatcher::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.dispatcher = self.dispatcher.with_uniform_timeout(timeout);
        self
    }

    pub fn with_keep_alive(mut self, keep_alive: bool) -> Self {
        self.dispatcher = self.dispatcher.with_keep_alive_default(keep_alive);
        self
    }

    /// Set the maximum response bytes limit for all requests
    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.dispatcher = self.dispatcher.with_max_response_bytes(limit);
        self
    }

    pub fn with_middleware(mut self, middleware: Arc<dyn HttpMiddleware>) -> Self {
        self.dispatcher = self.dispatcher.with_middleware(middleware);
        self
    }

    pub fn send_with_handler<H: HttpResponseHandler>(
        &self,
        request: &HttpRequest,
        handler: &mut H,
    ) -> Result<(HttpResponseHead, HttpDispatchMetrics), HttpSendError> {
        let options = HttpDispatchOptions::from(request.clone());
        self.dispatcher.dispatch_with_handler(options, handler)
    }

    pub fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
        self.send_with_metrics(request)
            .map(|(resp, _)| resp)
            .map_err(|err| err.message)
    }

    pub fn send_with_metrics(
        &self,
        request: &HttpRequest,
    ) -> Result<(HttpResponse, Duration), HttpSendError> {
        let options = HttpDispatchOptions::from(request.clone());
        let result = self.dispatcher.dispatch(options)?;
        Ok((result.response, result.metrics.ttfb))
    }

    pub fn get(&self, url: &str) -> Result<HttpResponse, String> {
        let request = HttpRequest::get(url);
        self.send(&request)
    }

    /// GET request with custom headers
    pub fn get_with_headers(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, String> {
        let mut request = HttpRequest::get(url);
        for (key, value) in headers {
            request = request.with_header(key, value);
        }
        self.send(&request)
    }

    pub fn post(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, String> {
        let request = HttpRequest::post(url).with_body(body);
        self.send(&request)
    }

    /// POST request with custom headers
    pub fn post_with_headers(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, String> {
        let mut request = HttpRequest::post(url).with_body(body);
        for (key, value) in headers {
            request = request.with_header(key, value);
        }
        self.send(&request)
    }

    /// HEAD request - returns only headers, no body
    pub fn head(&self, url: &str) -> Result<HttpResponse, String> {
        let request = HttpRequest::head(url);
        self.send(&request)
    }

    /// Set timeout (mutating version)
    /// Note: This creates a new dispatcher with the timeout, which is slightly inefficient
    /// but avoids requiring Default on HttpDispatcher
    pub fn set_timeout(&mut self, timeout: Duration) {
        // Create new dispatcher with timeout
        let new_dispatcher = HttpDispatcher::new().with_uniform_timeout(timeout);
        self.dispatcher = new_dispatcher;
    }

    /// Set user agent header for all requests
    /// Note: This creates a middleware that adds the User-Agent header
    pub fn set_user_agent(&mut self, user_agent: &str) {
        // Store user agent in dispatcher as a default header
        // For now, we'll just note this is a no-op since HttpDispatcher doesn't support this yet
        // The caller should add User-Agent to individual requests instead
        let _ = user_agent; // Suppress unused warning - this is intentionally a no-op placeholder
    }

    /// POST with content type and raw body
    pub fn post_raw(
        &self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<HttpResponse, String> {
        let request = HttpRequest::post(url)
            .with_body(body.to_vec())
            .with_header("Content-Type", content_type);
        self.send(&request)
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn read_response_with_ttfb(
    stream: &mut PooledStream,
    start: Instant,
    headers_timeout: Option<Duration>,
    body_timeout: Option<Duration>,
    max_response_bytes: Option<usize>,
    keep_alive_requested: bool,
) -> Result<ReadOutcome, HttpSendError> {
    stream
        .set_read_timeout(headers_timeout)
        .map_err(|e| HttpSendError::from(format!("Failed to set read timeout: {}", e)))?;

    let mut buffer = Vec::with_capacity(16384);
    let mut temp_buf = [0u8; 8192];
    let mut ttfb: Option<Duration> = None;
    let mut header_end: Option<usize> = None;
    let mut body_timeout_applied = body_timeout.is_none();
    let mut strategy = BodyStrategy::Unknown;
    let mut strategy_set = false;
    let mut body_complete = false;
    let mut reusable = keep_alive_requested;

    loop {
        if body_complete {
            break;
        }

        match stream.read(&mut temp_buf) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                buffer.extend_from_slice(&temp_buf[..n]);
                if ttfb.is_none() && n > 0 {
                    ttfb = Some(start.elapsed());
                }

                if let Some(limit) = max_response_bytes {
                    if buffer.len() > limit {
                        return Err(HttpSendError {
                            message: format!(
                                "Response exceeded configured limit of {} bytes",
                                limit
                            ),
                            ttfb,
                        });
                    }
                }

                if header_end.is_none() {
                    if let Some(pos) = find_header_end(&buffer) {
                        header_end = Some(pos);
                        let (detected_strategy, can_reuse) = analyze_headers(&buffer[..pos]);
                        strategy = detected_strategy;
                        strategy_set = true;
                        if !can_reuse {
                            reusable = false;
                        }
                        if !body_timeout_applied {
                            stream.set_read_timeout(body_timeout).map_err(|e| {
                                HttpSendError::from(format!(
                                    "Failed to set body read timeout: {}",
                                    e
                                ))
                            })?;
                            body_timeout_applied = true;
                        }
                        if matches!(strategy, BodyStrategy::Unknown) {
                            reusable = false;
                        }
                    }
                }

                if let Some(end) = header_end {
                    match strategy {
                        BodyStrategy::ContentLength(expected) => {
                            let body_len = buffer.len().saturating_sub(end);
                            if body_len >= expected {
                                body_complete = true;
                            }
                        }
                        BodyStrategy::Chunked => {
                            if chunked_body_complete(&buffer[end..]) {
                                body_complete = true;
                            }
                        }
                        BodyStrategy::Unknown => {}
                    }
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                let stage = if header_end.is_some() {
                    "Body"
                } else {
                    "Header"
                };
                return Err(HttpSendError {
                    message: format!("{} read timeout", stage),
                    ttfb,
                });
            }
            Err(e) => {
                return Err(HttpSendError {
                    message: format!("Read failed: {}", e),
                    ttfb,
                })
            }
        }
    }

    if buffer.is_empty() {
        return Err(HttpSendError {
            message: "Connection closed before response was received".to_string(),
            ttfb,
        });
    }

    let header_end_pos = match header_end {
        Some(pos) => pos,
        None => {
            return Err(HttpSendError {
                message: "Malformed HTTP response: missing headers".to_string(),
                ttfb,
            })
        }
    };

    if !strategy_set {
        strategy_set = true;
        strategy = BodyStrategy::Unknown;
        reusable = false;
    }

    match strategy {
        BodyStrategy::ContentLength(expected) => {
            let body_len = buffer.len().saturating_sub(header_end_pos);
            if body_len < expected {
                return Err(HttpSendError {
                    message: "Connection closed before full response body was received".to_string(),
                    ttfb,
                });
            }
            body_complete = true;
        }
        BodyStrategy::Chunked => {
            if !chunked_body_complete(&buffer[header_end_pos..]) {
                return Err(HttpSendError {
                    message: "Chunked response terminated early".to_string(),
                    ttfb,
                });
            }
            body_complete = true;
        }
        BodyStrategy::Unknown => {
            body_complete = true;
            reusable = false;
        }
    }

    let ttfb = ttfb.unwrap_or_else(|| start.elapsed());
    Ok(ReadOutcome {
        buffer,
        ttfb,
        reusable: reusable && body_complete && !matches!(strategy, BodyStrategy::Unknown),
    })
}

fn read_response_streaming<H: HttpResponseHandler>(
    stream: &mut PooledStream,
    start: Instant,
    headers_timeout: Option<Duration>,
    body_timeout: Option<Duration>,
    max_response_bytes: Option<usize>,
    handler: &mut H,
) -> Result<(HttpResponseHead, HttpDispatchMetrics, bool), HttpSendError> {
    stream
        .set_read_timeout(headers_timeout)
        .map_err(|e| HttpSendError::from(format!("Failed to set read timeout: {}", e)))?;

    let mut buffer = Vec::with_capacity(16384);
    let mut temp_buf = [0u8; 8192];
    let mut ttfb: Option<Duration> = None;
    let mut header_end: Option<usize> = None;

    loop {
        if let Some(end) = header_end {
            let header_bytes = &buffer[..end - 4];
            let head = parse_response_head(header_bytes).map_err(HttpSendError::from)?;
            handler.on_head(&head).map_err(HttpSendError::from)?;

            stream.set_read_timeout(body_timeout).map_err(|e| {
                HttpSendError::from(format!("Failed to set body read timeout: {}", e))
            })?;

            let (strategy, can_reuse) = analyze_headers(header_bytes);
            let mut allow_reuse = can_reuse && !matches!(strategy, BodyStrategy::Unknown);
            let mut total_bytes: usize = 0;
            let mut body_buffer = buffer.split_off(end);
            let mut body_pos = 0usize;

            match strategy {
                BodyStrategy::ContentLength(mut remaining) => {
                    while remaining > 0 {
                        if body_pos < body_buffer.len() {
                            let available = (body_buffer.len() - body_pos).min(remaining);
                            let chunk = &body_buffer[body_pos..body_pos + available];
                            handler.on_chunk(chunk).map_err(HttpSendError::from)?;
                            total_bytes += available;
                            if let Some(limit) = max_response_bytes {
                                if total_bytes > limit {
                                    return Err(HttpSendError::from(format!(
                                        "Response exceeded configured limit of {} bytes",
                                        limit
                                    )));
                                }
                            }
                            body_pos += available;
                            remaining -= available;
                            if body_pos == body_buffer.len() {
                                body_buffer.clear();
                            }
                        } else {
                            let read_bytes = stream
                                .read(&mut temp_buf)
                                .map_err(|e| HttpSendError::from(format!("Read failed: {}", e)))?;
                            if read_bytes == 0 {
                                return Err(HttpSendError::from(
                                    "Connection closed before full response body was received"
                                        .to_string(),
                                ));
                            }
                            handler
                                .on_chunk(&temp_buf[..read_bytes])
                                .map_err(HttpSendError::from)?;
                            total_bytes += read_bytes;
                            remaining = remaining.saturating_sub(read_bytes);
                            if let Some(limit) = max_response_bytes {
                                if total_bytes > limit {
                                    return Err(HttpSendError::from(format!(
                                        "Response exceeded configured limit of {} bytes",
                                        limit
                                    )));
                                }
                            }
                        }
                    }
                }
                BodyStrategy::Chunked => {
                    allow_reuse = allow_reuse
                        && stream_chunked_body(
                            stream,
                            handler,
                            &mut body_buffer,
                            &mut body_pos,
                            &mut total_bytes,
                            max_response_bytes,
                            &mut temp_buf,
                        )?;
                }
                BodyStrategy::Unknown => {
                    if body_pos < body_buffer.len() {
                        handler
                            .on_chunk(&body_buffer[body_pos..])
                            .map_err(HttpSendError::from)?;
                        total_bytes += body_buffer.len() - body_pos;
                        if let Some(limit) = max_response_bytes {
                            if total_bytes > limit {
                                return Err(HttpSendError::from(format!(
                                    "Response exceeded configured limit of {} bytes",
                                    limit
                                )));
                            }
                        }
                        body_buffer.clear();
                    }
                    loop {
                        let read_bytes = stream
                            .read(&mut temp_buf)
                            .map_err(|e| HttpSendError::from(format!("Read failed: {}", e)))?;
                        if read_bytes == 0 {
                            break;
                        }
                        handler
                            .on_chunk(&temp_buf[..read_bytes])
                            .map_err(HttpSendError::from)?;
                        total_bytes += read_bytes;
                        if let Some(limit) = max_response_bytes {
                            if total_bytes > limit {
                                return Err(HttpSendError::from(format!(
                                    "Response exceeded configured limit of {} bytes",
                                    limit
                                )));
                            }
                        }
                    }
                    allow_reuse = false;
                }
            }

            handler.on_complete().map_err(HttpSendError::from)?;

            let ttfb = ttfb.unwrap_or_else(|| start.elapsed());
            return Ok((head, HttpDispatchMetrics { ttfb }, allow_reuse));
        }

        let read = stream.read(&mut temp_buf).map_err(|e| {
            HttpSendError::from(format!("Read failed while reading headers: {}", e))
        })?;
        if read == 0 {
            return Err(HttpSendError::from(
                "Connection closed before response was received".to_string(),
            ));
        }
        buffer.extend_from_slice(&temp_buf[..read]);
        if ttfb.is_none() {
            ttfb = Some(start.elapsed());
        }
        if let Some(pos) = find_header_end(&buffer) {
            header_end = Some(pos);
        }
        if let Some(limit) = max_response_bytes {
            if buffer.len() > limit {
                return Err(HttpSendError::from(format!(
                    "Response exceeded configured limit of {} bytes",
                    limit
                )));
            }
        }
    }
}

fn stream_chunked_body<H: HttpResponseHandler>(
    stream: &mut PooledStream,
    handler: &mut H,
    buffer: &mut Vec<u8>,
    pos: &mut usize,
    total_bytes: &mut usize,
    max_response_bytes: Option<usize>,
    temp_buf: &mut [u8; 8192],
) -> Result<bool, HttpSendError> {
    loop {
        let chunk_size = loop {
            if let Some(line_end) = find_crlf(buffer, *pos) {
                let line = &buffer[*pos..line_end];
                let line_str = std::str::from_utf8(line)
                    .map_err(|_| HttpSendError::from("Invalid chunk header".to_string()))?;
                let size_part = line_str.split(';').next().map(|s| s.trim()).unwrap_or("");
                let chunk_size = usize::from_str_radix(size_part, 16)
                    .map_err(|_| HttpSendError::from("Invalid chunk size".to_string()))?;
                *pos = line_end + 2;
                break chunk_size;
            } else {
                let read = stream.read(temp_buf).map_err(|e| {
                    HttpSendError::from(format!("Read failed during chunk header: {}", e))
                })?;
                if read == 0 {
                    return Err(HttpSendError::from(
                        "Connection closed while reading chunk header".to_string(),
                    ));
                }
                buffer.extend_from_slice(&temp_buf[..read]);
            }
        };

        if chunk_size == 0 {
            loop {
                if let Some(line_end) = find_crlf(buffer, *pos) {
                    if line_end == *pos {
                        *pos = line_end + 2;
                        return Ok(true);
                    }
                    *pos = line_end + 2;
                } else {
                    let read = stream.read(temp_buf).map_err(|e| {
                        HttpSendError::from(format!("Read failed during chunk trailer: {}", e))
                    })?;
                    if read == 0 {
                        return Err(HttpSendError::from(
                            "Connection closed while reading chunk trailer".to_string(),
                        ));
                    }
                    buffer.extend_from_slice(&temp_buf[..read]);
                }
            }
        }

        while buffer.len() - *pos < chunk_size + 2 {
            let read = stream.read(temp_buf).map_err(|e| {
                HttpSendError::from(format!("Read failed during chunk data: {}", e))
            })?;
            if read == 0 {
                return Err(HttpSendError::from(
                    "Connection closed while reading chunk data".to_string(),
                ));
            }
            buffer.extend_from_slice(&temp_buf[..read]);
        }

        let chunk = &buffer[*pos..*pos + chunk_size];
        handler.on_chunk(chunk).map_err(HttpSendError::from)?;
        *total_bytes += chunk_size;
        if let Some(limit) = max_response_bytes {
            if *total_bytes > limit {
                return Err(HttpSendError::from(format!(
                    "Response exceeded configured limit of {} bytes",
                    limit
                )));
            }
        }

        *pos += chunk_size;
        if &buffer[*pos..*pos + 2] != b"\r\n" {
            return Err(HttpSendError::from(
                "Malformed chunk ending (missing CRLF)".to_string(),
            ));
        }
        *pos += 2;

        if *pos > 4096 {
            buffer.drain(..*pos);
            *pos = 0;
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

pub(crate) fn build_default_ssl_connector() -> Result<SslConnector, String> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| format!("Failed to create TLS connector: {}", e))?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1))
        .map_err(|e| format!("Failed to set min TLS version: {}", e))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| format!("Failed to set max TLS version: {}", e))?;
    builder.set_verify(SslVerifyMode::NONE);
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_parse_url() {
        let parsed = HttpRequest::parse_url("http://example.com/path");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.path, "/path");
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.scheme, Scheme::Http);
    }

    #[test]
    fn test_request_creation() {
        let req = HttpRequest::get("http://example.com/test");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/test");
        assert_eq!(req.host(), "example.com");
        assert_eq!(req.port(), 80);
        assert_eq!(req.headers.get("Host").unwrap(), "example.com");
    }

    #[test]
    fn test_request_to_bytes() {
        let req = HttpRequest::get("http://example.com");
        let bytes = req.to_bytes();
        let request_str = String::from_utf8(bytes).unwrap();
        assert!(request_str.starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_https_parse_url() {
        let parsed = HttpRequest::parse_url("https://example.com/login");
        assert_eq!(parsed.scheme, Scheme::Https);
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/login");
    }

    #[test]
    fn test_parse_url_with_port() {
        let parsed = HttpRequest::parse_url("http://example.com:8080/api");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.path, "/api");
    }

    #[test]
    fn test_http_response_body_split() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello";
        let response = HttpResponse::from_bytes(raw).expect("parse failed");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.headers.get("Content-Type").unwrap(), "text/plain");
        assert_eq!(response.body_as_string(), "Hello");
    }

    #[test]
    fn test_chunked_response_decoding() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let response = HttpResponse::from_bytes(raw).expect("chunked parse failed");
        assert_eq!(response.body_as_string(), "Wikipedia");
        assert_eq!(
            response.headers.get("Transfer-Encoding").unwrap(),
            "chunked"
        );
    }

    #[test]
    fn test_middleware_short_circuit() {
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        struct ShortCircuitMiddleware {
            log: Arc<Mutex<Vec<&'static str>>>,
        }

        impl HttpMiddleware for ShortCircuitMiddleware {
            fn handle(
                &self,
                mut options: HttpDispatchOptions,
                _ctx: &MiddlewareContext,
            ) -> Result<HttpDispatchResult, HttpSendError> {
                self.log.lock().unwrap().push("middleware-hit");
                options
                    .request
                    .headers
                    .insert("X-Test".into(), "middleware".into());
                Ok(HttpDispatchResult {
                    response: HttpResponse {
                        version: "HTTP/1.1".into(),
                        status_code: 418,
                        status_text: "Teapot".into(),
                        headers: options.request.headers.clone(),
                        body: b"teapot".to_vec(),
                    },
                    metrics: HttpDispatchMetrics {
                        ttfb: Duration::from_millis(1),
                    },
                })
            }
        }

        let log = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = HttpDispatcher::new()
            .with_middleware(Arc::new(ShortCircuitMiddleware { log: log.clone() }));
        let options = HttpDispatchOptions::from(HttpRequest::get("http://example.com"));
        let result = dispatcher.dispatch(options).expect("middleware result");

        assert_eq!(result.response.status_code, 418);
        assert_eq!(
            result.response.headers.get("X-Test").map(|s| s.as_str()),
            Some("middleware")
        );
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_send_with_handler_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nHello World";
                let _ = stream.write_all(response);
            }
        });

        struct CollectHandler {
            data: Vec<u8>,
        }

        impl HttpResponseHandler for CollectHandler {
            fn on_head(&mut self, head: &HttpResponseHead) -> Result<(), String> {
                assert_eq!(head.status_code, 200);
                Ok(())
            }

            fn on_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
                self.data.extend_from_slice(chunk);
                Ok(())
            }
        }

        let mut handler = CollectHandler { data: Vec::new() };
        let client = HttpClient::new().with_keep_alive(false);
        let request = HttpRequest::get(&format!("http://{}", addr));
        let (_, _) = client
            .send_with_handler(&request, &mut handler)
            .expect("streaming request");
        assert_eq!(handler.data, b"Hello World");
    }

    #[test]
    fn test_send_with_handler_chunked() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
                let _ = stream.write_all(response);
            }
        });

        struct CollectHandler {
            data: Vec<u8>,
        }

        impl HttpResponseHandler for CollectHandler {
            fn on_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
                self.data.extend_from_slice(chunk);
                Ok(())
            }
        }

        let mut handler = CollectHandler { data: Vec::new() };
        let client = HttpClient::new().with_keep_alive(false);
        let request = HttpRequest::get(&format!("http://{}", addr));
        let (_, _) = client
            .send_with_handler(&request, &mut handler)
            .expect("chunked request");
        assert_eq!(handler.data, b"Hello World");
    }
}
