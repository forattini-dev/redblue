use std::collections::HashMap;
/// HTTP/1.1 Protocol Implementation from Scratch
/// RFC 2616 - Hypertext Transfer Protocol
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// use super::https::HttpsConnection; // Temporarily disabled
use crate::config;
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
        }
    }

    pub fn get(url: &str) -> Self {
        Self::new("GET", url)
    }

    pub fn post(url: &str) -> Self {
        Self::new("POST", url)
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
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
        let body = data[separator + 4..].to_vec();

        let header_str = String::from_utf8_lossy(header_bytes);
        let mut lines = header_str.split("\r\n").filter(|line| !line.is_empty());

        // Parse status line
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

        // Parse headers
        let mut headers = HashMap::new();

        for line in lines {
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        Ok(Self {
            version,
            status_code,
            status_text,
            headers,
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
}

pub struct HttpClient {
    timeout: Duration,
    request_delay_ms: u64,
}

impl HttpClient {
    pub fn new() -> Self {
        let cfg = config::get();
        let secs = cfg.web.timeout_secs.max(1);
        Self {
            timeout: Duration::from_secs(secs),
            request_delay_ms: cfg.network.request_delay_ms,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
        // Handle HTTPS requests
        if request.is_https() {
            return self.send_https(request);
        }

        let addr = format!("{}:{}", request.host(), request.port());

        // Connect
        if self.request_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.request_delay_ms));
        }
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        // Send request
        let request_bytes = request.to_bytes();
        stream
            .write_all(&request_bytes)
            .map_err(|e| format!("Write failed: {}", e))?;

        // Read response (pre-allocate 16KB buffer for typical responses)
        let mut buffer = Vec::with_capacity(16384);
        stream
            .read_to_end(&mut buffer)
            .map_err(|e| format!("Read failed: {}", e))?;

        HttpResponse::from_bytes(&buffer)
    }

    pub fn get(&self, url: &str) -> Result<HttpResponse, String> {
        let request = HttpRequest::get(url);
        self.send(&request)
    }

    pub fn post(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, String> {
        let request = HttpRequest::post(url).with_body(body);
        self.send(&request)
    }

    fn send_https(&self, _request: &HttpRequest) -> Result<HttpResponse, String> {
        Err("HTTPS temporarily disabled - TLS implementation incomplete".to_string())
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
