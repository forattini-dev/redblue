//! HTTP/2 Protocol Implementation (RFC 7540)
//!
//! Binary framing protocol with multiplexing, header compression, and flow control.
//! Implemented from scratch using ONLY Rust std and OpenSSL for TLS.
//!
//! Architecture inspired by (but NOT using code from):
//! - ureq: Connection pooling and blocking I/O patterns
//! - reqwest: HTTP/3 architecture analysis
//!
//! All implementations follow RFCs:
//! - RFC 7540: HTTP/2
//! - RFC 7541: HPACK (Header Compression)

pub mod connection;
pub mod framing;
pub mod hpack;
pub mod huffman;
#[path = "shared-pool.rs"]
pub mod shared_pool;
pub mod stream;

pub use connection::{Http2Client, Http2Response, Http2ResponseHandler, Http2ResponseHead};
pub use shared_pool::{SharedHttp2Pool, SharedHttp2PoolConfig, SharedHttp2PoolStats};
pub use framing::{Frame, FrameType};
pub use hpack::Header;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
pub use stream::{Stream, StreamId, StreamManager};

/// HTTP/2 connection preface (client magic string)
/// RFC 7540 Section 3.5
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 ALPN protocol identifier (wire format with length prefix)
/// Format: [length byte][protocol bytes]
/// For "h2": 0x02 (length=2), followed by "h2"
pub const ALPN_H2: &[u8] = b"\x02h2";

/// Default initial window size (65535 bytes)
/// RFC 7540 Section 6.9.2
pub const DEFAULT_WINDOW_SIZE: u32 = 65535;

/// Maximum frame size (16KB default, up to 16MB)
/// RFC 7540 Section 4.2
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

/// HTTP/2 request builder
#[derive(Debug, Clone)]
pub struct Http2Request {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path: String,
    pub headers: Vec<Header>,
    pub body: Option<Vec<u8>>,
}

impl Http2Request {
    pub fn new(method: &str, url: &str) -> Result<Self, String> {
        let parsed = ParsedHttp2Url::parse(url)?;
        Ok(Self {
            method: method.to_string(),
            scheme: parsed.scheme,
            host: parsed.host.clone(),
            port: parsed.port,
            authority: parsed.authority,
            path: parsed.path,
            headers: Vec::new(),
            body: None,
        })
    }

    pub fn get(url: &str) -> Result<Self, String> {
        Self::new("GET", url)
    }

    pub fn post(url: &str) -> Result<Self, String> {
        Self::new("POST", url)
    }

    pub fn with_headers(mut self, headers: Vec<Header>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_body(mut self, body: Option<Vec<u8>>) -> Self {
        self.body = body;
        self
    }
}

struct ParsedHttp2Url {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    authority: String,
}

impl ParsedHttp2Url {
    fn parse(url: &str) -> Result<Self, String> {
        let (scheme, remainder) = if let Some(rest) = url.strip_prefix("https://") {
            ("https".to_string(), rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            ("http".to_string(), rest)
        } else {
            return Err("HTTP/2 requires http:// or https:// URL".to_string());
        };

        let (authority, path_part) = match remainder.find('/') {
            Some(idx) => (&remainder[..idx], &remainder[idx..]),
            None => (remainder, "/"),
        };

        let path = if path_part.is_empty() {
            "/".to_string()
        } else {
            path_part.to_string()
        };

        let default_port = if scheme == "https" { 443 } else { 80 };
        let (host, port) = if let Some(idx) = authority.rfind(':') {
            let host_part = &authority[..idx];
            let port_part = &authority[idx + 1..];
            let parsed_port = port_part
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", port_part))?;
            (host_part.to_string(), parsed_port)
        } else {
            (authority.to_string(), default_port)
        };

        Ok(Self {
            scheme,
            host,
            port,
            authority: authority.to_string(),
            path,
        })
    }
}

/// Middleware abstraction for HTTP/2 dispatch.
pub trait Http2Middleware: Send + Sync {
    fn handle(
        &self,
        request: Http2Request,
        ctx: &Http2MiddlewareContext,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String>;
}

pub struct Http2MiddlewareContext<'a> {
    dispatcher: &'a Http2Dispatcher,
    index: usize,
}

impl<'a> Http2MiddlewareContext<'a> {
    pub fn next(
        &self,
        request: Http2Request,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        self.dispatcher
            .run_middlewares(self.index + 1, request, handler)
    }
}

pub struct Http2Dispatcher {
    middlewares: Vec<Arc<dyn Http2Middleware>>,
    pool: Arc<Mutex<HashMap<String, Http2Client>>>,
}

impl Http2Dispatcher {
    pub fn new() -> Self {
        Self {
            middlewares: Vec::new(),
            pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_middleware(mut self, middleware: Arc<dyn Http2Middleware>) -> Self {
        self.middlewares.push(middleware);
        self
    }

    pub fn send_with_handler(
        &self,
        request: Http2Request,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        self.run_middlewares(0, request, handler)
    }

    fn run_middlewares(
        &self,
        index: usize,
        request: Http2Request,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        if index >= self.middlewares.len() {
            return self.dispatch_inner(request, handler);
        }

        let ctx = Http2MiddlewareContext {
            dispatcher: self,
            index,
        };
        self.middlewares[index].handle(request, &ctx, handler)
    }

    fn dispatch_inner(
        &self,
        request: Http2Request,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        let key = format!("{}:{}", request.host, request.port);
        let mut client = self
            .take_client(&key)?
            .unwrap_or(Http2Client::connect(&request.host, request.port)?);

        let result = client.send_request_with_handler(
            &request.method,
            &request.path,
            &request.authority,
            request.headers.clone(),
            request.body.clone(),
            handler,
        );

        self.return_client(key, client);
        result
    }

    fn take_client(&self, key: &str) -> Result<Option<Http2Client>, String> {
        let mut pool = self
            .pool
            .lock()
            .map_err(|_| "HTTP/2 connection pool poisoned".to_string())?;
        Ok(pool.remove(key))
    }

    fn return_client(&self, key: String, client: Http2Client) {
        if let Ok(mut pool) = self.pool.lock() {
            pool.insert(key, client);
        }
    }
}

/// Logging middleware for HTTP/2 dispatches.
pub struct Http2LoggingMiddleware;

impl Http2Middleware for Http2LoggingMiddleware {
    fn handle(
        &self,
        request: Http2Request,
        ctx: &Http2MiddlewareContext,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        let started = Instant::now();
        let result = ctx.next(request.clone(), handler);
        match &result {
            Ok((head, _)) => {
                println!(
                    "[http2] {} {} -> {} ({:?})",
                    request.method,
                    request.path,
                    head.status,
                    started.elapsed()
                );
            }
            Err(err) => {
                println!(
                    "[http2] {} {} failed: {}",
                    request.method, request.path, err
                );
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_preface() {
        assert_eq!(CONNECTION_PREFACE.len(), 24);
        assert!(CONNECTION_PREFACE.starts_with(b"PRI * HTTP/2.0"));
    }
}
