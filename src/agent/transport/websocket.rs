//! WebSocket Transport for C2 communication
//!
//! Provides full-duplex communication channel using WebSocket protocol.
//! Useful for real-time command execution and interactive sessions.

use crate::agent::transport::{Transport, TransportConfig, TransportError, TransportResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// WebSocket opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WsOpcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl TryFrom<u8> for WsOpcode {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(format!("Invalid opcode: 0x{:02X}", value)),
        }
    }
}

/// WebSocket frame
#[derive(Debug, Clone)]
pub struct WsFrame {
    pub fin: bool,
    pub opcode: WsOpcode,
    pub mask: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

impl WsFrame {
    /// Create new binary frame
    pub fn binary(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: WsOpcode::Binary,
            mask: Some(Self::generate_mask()),
            payload: data,
        }
    }

    /// Create close frame
    pub fn close() -> Self {
        Self {
            fin: true,
            opcode: WsOpcode::Close,
            mask: Some(Self::generate_mask()),
            payload: Vec::new(),
        }
    }

    /// Create pong frame
    pub fn pong(data: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: WsOpcode::Pong,
            mask: Some(Self::generate_mask()),
            payload: data,
        }
    }

    /// Generate random mask key
    fn generate_mask() -> [u8; 4] {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let nanos = now.subsec_nanos();
        [
            ((nanos >> 24) & 0xFF) as u8,
            ((nanos >> 16) & 0xFF) as u8,
            ((nanos >> 8) & 0xFF) as u8,
            (nanos & 0xFF) as u8,
        ]
    }

    /// Serialize frame to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // First byte: FIN + opcode
        let first = if self.fin { 0x80 } else { 0x00 } | (self.opcode as u8);
        bytes.push(first);

        // Second byte: MASK + payload length
        let len = self.payload.len();
        let mask_bit = if self.mask.is_some() { 0x80 } else { 0x00 };

        if len <= 125 {
            bytes.push(mask_bit | (len as u8));
        } else if len <= 65535 {
            bytes.push(mask_bit | 126);
            bytes.push((len >> 8) as u8);
            bytes.push((len & 0xFF) as u8);
        } else {
            bytes.push(mask_bit | 127);
            for i in (0..8).rev() {
                bytes.push(((len >> (i * 8)) & 0xFF) as u8);
            }
        }

        // Mask key
        if let Some(mask) = &self.mask {
            bytes.extend_from_slice(mask);
        }

        // Payload (masked if mask is present)
        if let Some(mask) = &self.mask {
            for (i, byte) in self.payload.iter().enumerate() {
                bytes.push(byte ^ mask[i % 4]);
            }
        } else {
            bytes.extend_from_slice(&self.payload);
        }

        bytes
    }

    /// Parse frame from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), String> {
        if data.len() < 2 {
            return Err("Frame too short".into());
        }

        let first = data[0];
        let second = data[1];

        let fin = (first & 0x80) != 0;
        let opcode = WsOpcode::try_from(first & 0x0F)?;
        let masked = (second & 0x80) != 0;
        let mut payload_len = (second & 0x7F) as usize;
        let mut offset = 2;

        // Extended payload length
        if payload_len == 126 {
            if data.len() < 4 {
                return Err("Frame too short for extended length".into());
            }
            payload_len = ((data[2] as usize) << 8) | (data[3] as usize);
            offset = 4;
        } else if payload_len == 127 {
            if data.len() < 10 {
                return Err("Frame too short for 64-bit length".into());
            }
            payload_len = 0;
            for i in 0..8 {
                payload_len = (payload_len << 8) | (data[2 + i] as usize);
            }
            offset = 10;
        }

        // Mask key
        let mask = if masked {
            if data.len() < offset + 4 {
                return Err("Frame too short for mask".into());
            }
            let m = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            offset += 4;
            Some(m)
        } else {
            None
        };

        // Payload
        if data.len() < offset + payload_len {
            return Err("Frame too short for payload".into());
        }

        let mut payload = data[offset..offset + payload_len].to_vec();

        // Unmask if needed
        if let Some(m) = &mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= m[i % 4];
            }
        }

        let total_len = offset + payload_len;

        Ok((
            Self {
                fin,
                opcode,
                mask,
                payload,
            },
            total_len,
        ))
    }
}

/// WebSocket transport configuration
#[derive(Debug, Clone)]
pub struct WebSocketTransportConfig {
    /// Base configuration
    pub base: TransportConfig,
    /// WebSocket URL (ws:// or wss://)
    pub url: String,
    /// Path component
    pub path: String,
    /// Origin header
    pub origin: Option<String>,
    /// Ping interval for keepalive
    pub ping_interval: Duration,
    /// Auto-reconnect on disconnect
    pub auto_reconnect: bool,
    /// Max message size
    pub max_message_size: usize,
}

impl Default for WebSocketTransportConfig {
    fn default() -> Self {
        Self {
            base: TransportConfig::default(),
            url: "ws://localhost:8080".into(),
            path: "/ws".into(),
            origin: None,
            ping_interval: Duration::from_secs(30),
            auto_reconnect: true,
            max_message_size: 16 * 1024 * 1024, // 16MB
        }
    }
}

impl WebSocketTransportConfig {
    /// Create config with URL
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            ..Default::default()
        }
    }

    /// Set path
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    /// Set origin header
    pub fn with_origin(mut self, origin: &str) -> Self {
        self.origin = Some(origin.to_string());
        self
    }

    /// Set ping interval
    pub fn with_ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Enable auto-reconnect
    pub fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }
}

/// WebSocket Transport implementation
pub struct WebSocketTransport {
    /// Configuration
    config: WebSocketTransportConfig,
    /// TCP connection
    stream: Option<TcpStream>,
    /// Connection status
    connected: bool,
    /// WebSocket key used in handshake
    ws_key: String,
}

impl WebSocketTransport {
    /// Create new WebSocket transport
    pub fn new(config: WebSocketTransportConfig) -> Self {
        Self {
            config,
            stream: None,
            connected: false,
            ws_key: Self::generate_key(),
        }
    }

    /// Create with URL
    pub fn with_url(url: &str) -> Self {
        Self::new(WebSocketTransportConfig::new(url))
    }

    /// Generate random WebSocket key
    fn generate_key() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let nanos = now.subsec_nanos();

        // Generate 16 random bytes
        let mut bytes = [0u8; 16];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((nanos.wrapping_mul((i as u32 + 1) * 1337)) % 256) as u8;
        }

        // Base64 encode
        Self::base64_encode(&bytes)
    }

    /// Simple base64 encoding
    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();

        for chunk in data.chunks(3) {
            let n = match chunk.len() {
                3 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32),
                2 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8),
                1 => (chunk[0] as u32) << 16,
                _ => continue,
            };

            result.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            result.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);

            if chunk.len() >= 2 {
                result.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }

            if chunk.len() >= 3 {
                result.push(ALPHABET[(n & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }

        result
    }

    /// Parse URL into host and port
    fn parse_url(&self) -> Result<(String, u16, bool), String> {
        let url = &self.config.url;
        let (scheme, rest) = if url.starts_with("wss://") {
            ("wss", &url[6..])
        } else if url.starts_with("ws://") {
            ("ws", &url[5..])
        } else {
            return Err("Invalid WebSocket URL scheme".into());
        };

        let use_tls = scheme == "wss";
        let default_port = if use_tls { 443 } else { 80 };

        // Extract host:port
        let (host, port) = if let Some(colon_idx) = rest.find(':') {
            let host = &rest[..colon_idx];
            let port_str = rest[colon_idx + 1..].split('/').next().unwrap_or("");
            let port = port_str.parse().unwrap_or(default_port);
            (host.to_string(), port)
        } else {
            let host = rest.split('/').next().unwrap_or(rest);
            (host.to_string(), default_port)
        };

        Ok((host, port, use_tls))
    }

    /// Perform WebSocket handshake
    fn handshake(&mut self) -> TransportResult<()> {
        let (host, port, _use_tls) = self
            .parse_url()
            .map_err(|e| TransportError::ConnectionFailed(e))?;

        // Connect TCP
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        stream
            .set_read_timeout(Some(self.config.base.io_timeout))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        stream
            .set_write_timeout(Some(self.config.base.io_timeout))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        self.stream = Some(stream);

        // Send WebSocket upgrade request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             {}\r\n",
            self.config.path,
            host,
            self.ws_key,
            self.config
                .origin
                .as_ref()
                .map(|o| format!("Origin: {}\r\n", o))
                .unwrap_or_default()
        );

        if let Some(ref mut stream) = self.stream {
            stream
                .write_all(request.as_bytes())
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

            // Read response
            let mut response = [0u8; 1024];
            let n = stream
                .read(&mut response)
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

            let response_str = String::from_utf8_lossy(&response[..n]);

            // Check for 101 Switching Protocols
            if !response_str.contains("101") || !response_str.to_lowercase().contains("upgrade") {
                return Err(TransportError::ConnectionFailed(format!(
                    "WebSocket handshake failed: {}",
                    response_str
                )));
            }

            self.connected = true;
            Ok(())
        } else {
            Err(TransportError::Disconnected)
        }
    }

    /// Send a WebSocket frame
    fn send_frame(&mut self, frame: &WsFrame) -> TransportResult<()> {
        if let Some(ref mut stream) = self.stream {
            let bytes = frame.to_bytes();
            stream
                .write_all(&bytes)
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
            Ok(())
        } else {
            Err(TransportError::Disconnected)
        }
    }

    /// Receive a WebSocket frame
    fn recv_frame(&mut self) -> TransportResult<WsFrame> {
        if let Some(ref mut stream) = self.stream {
            // Read frame header
            let mut buffer = vec![0u8; 16384];
            let mut total_read = 0;

            loop {
                let n = stream
                    .read(&mut buffer[total_read..])
                    .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

                if n == 0 {
                    self.connected = false;
                    return Err(TransportError::Disconnected);
                }

                total_read += n;

                // Try to parse frame
                match WsFrame::from_bytes(&buffer[..total_read]) {
                    Ok((frame, _)) => return Ok(frame),
                    Err(_) if total_read < buffer.len() => continue,
                    Err(e) => return Err(TransportError::InvalidData(e)),
                }
            }
        } else {
            Err(TransportError::Disconnected)
        }
    }
}

impl Transport for WebSocketTransport {
    fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        // Connect if not connected
        if !self.connected {
            self.handshake()?;
        }

        // Validate message size
        if data.len() > self.config.max_message_size {
            return Err(TransportError::InvalidData(format!(
                "Message too large: {} bytes (max {})",
                data.len(),
                self.config.max_message_size
            )));
        }

        // Send binary frame
        let frame = WsFrame::binary(data.to_vec());
        self.send_frame(&frame)?;

        // Receive response
        loop {
            let response_frame = self.recv_frame()?;

            match response_frame.opcode {
                WsOpcode::Binary | WsOpcode::Text => {
                    return Ok(response_frame.payload);
                }
                WsOpcode::Ping => {
                    // Respond with pong
                    let pong = WsFrame::pong(response_frame.payload);
                    self.send_frame(&pong)?;
                }
                WsOpcode::Close => {
                    self.connected = false;
                    return Err(TransportError::Disconnected);
                }
                _ => continue,
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn reconnect(&mut self) -> TransportResult<()> {
        self.close();
        self.ws_key = Self::generate_key();
        self.handshake()
    }

    fn name(&self) -> &str {
        "websocket"
    }

    fn current_endpoint(&self) -> String {
        format!("{}{}", self.config.url, self.config.path)
    }

    fn close(&mut self) {
        if self.connected {
            if let Some(ref mut stream) = self.stream {
                // Send close frame (best effort)
                let close = WsFrame::close();
                let _ = stream.write_all(&close.to_bytes());
            }
        }
        self.stream = None;
        self.connected = false;
    }
}

/// WebSocket transport profiles
pub struct WebSocketProfileBuilder;

impl WebSocketProfileBuilder {
    /// Standard WebSocket connection
    pub fn standard(url: &str) -> WebSocketTransport {
        WebSocketTransport::with_url(url)
    }

    /// WebSocket with custom path (common for API endpoints)
    pub fn api_endpoint(url: &str, path: &str) -> WebSocketTransport {
        let config = WebSocketTransportConfig::new(url).with_path(path);
        WebSocketTransport::new(config)
    }

    /// WebSocket mimicking browser connection
    pub fn browser(url: &str, origin: &str) -> WebSocketTransport {
        let config = WebSocketTransportConfig::new(url).with_origin(origin);
        WebSocketTransport::new(config)
    }

    /// High-frequency keepalive (for unstable connections)
    pub fn keepalive(url: &str) -> WebSocketTransport {
        let config = WebSocketTransportConfig::new(url)
            .with_ping_interval(Duration::from_secs(10))
            .with_auto_reconnect(true);
        WebSocketTransport::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_frame_binary() {
        let frame = WsFrame::binary(b"Hello".to_vec());
        assert!(frame.fin);
        assert_eq!(frame.opcode, WsOpcode::Binary);
        assert!(frame.mask.is_some());
    }

    #[test]
    fn test_ws_frame_serialize_deserialize() {
        let original = WsFrame {
            fin: true,
            opcode: WsOpcode::Binary,
            mask: None, // Server frames are not masked
            payload: b"Test payload".to_vec(),
        };

        let bytes = original.to_bytes();
        let (parsed, len) = WsFrame::from_bytes(&bytes).unwrap();

        assert_eq!(len, bytes.len());
        assert_eq!(parsed.fin, original.fin);
        assert_eq!(parsed.opcode, original.opcode);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_ws_frame_masked() {
        let frame = WsFrame::binary(b"Test".to_vec());
        let bytes = frame.to_bytes();

        // Masked frame should be different from unmasked
        let unmasked = WsFrame {
            fin: true,
            opcode: WsOpcode::Binary,
            mask: None,
            payload: b"Test".to_vec(),
        };
        let unmasked_bytes = unmasked.to_bytes();

        assert_ne!(bytes.len(), unmasked_bytes.len()); // Mask adds 4 bytes
    }

    #[test]
    fn test_ws_frame_extended_length() {
        // Test 16-bit length
        let payload = vec![0u8; 200];
        let frame = WsFrame::binary(payload.clone());
        let bytes = frame.to_bytes();

        let (parsed, _) = WsFrame::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payload.len(), 200);
    }

    #[test]
    fn test_base64_encode() {
        // Test vectors
        assert_eq!(WebSocketTransport::base64_encode(b""), "");
        assert_eq!(WebSocketTransport::base64_encode(b"f"), "Zg==");
        assert_eq!(WebSocketTransport::base64_encode(b"fo"), "Zm8=");
        assert_eq!(WebSocketTransport::base64_encode(b"foo"), "Zm9v");
        assert_eq!(WebSocketTransport::base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(WebSocketTransport::base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(WebSocketTransport::base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_url_parsing() {
        let transport = WebSocketTransport::with_url("ws://localhost:8080");
        let (host, port, tls) = transport.parse_url().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert!(!tls);

        let transport = WebSocketTransport::with_url("wss://secure.example.com");
        let (host, port, tls) = transport.parse_url().unwrap();
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn test_websocket_transport_name() {
        let transport = WebSocketTransport::with_url("ws://localhost");
        assert_eq!(transport.name(), "websocket");
    }

    #[test]
    fn test_websocket_profiles() {
        let standard = WebSocketProfileBuilder::standard("ws://localhost");
        assert!(!standard.connected);

        let api = WebSocketProfileBuilder::api_endpoint("ws://localhost", "/api/ws");
        assert_eq!(api.config.path, "/api/ws");

        let browser = WebSocketProfileBuilder::browser("ws://localhost", "https://example.com");
        assert_eq!(browser.config.origin, Some("https://example.com".into()));
    }
}
