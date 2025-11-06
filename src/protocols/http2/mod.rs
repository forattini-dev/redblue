/// HTTP/2 Protocol Implementation (RFC 7540)
/// Pure Rust std - ZERO external dependencies
pub mod frame;
pub mod hpack;

pub use frame::{Frame, FrameHeader};
pub use hpack::HpackCodec;

use crate::crypto::md5::md5;
use openssl::hash::MessageDigest;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use openssl::x509::{X509NameRef, X509Ref};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write as IoWrite};
use std::net::TcpStream;
use std::time::Duration;

/// HTTP/2 connection preface
/// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DEFAULT_JA3_VERSION: u16 = 771;
const DEFAULT_JA3_CIPHERS: &[u16] = &[4865, 4866, 4867];
const DEFAULT_JA3_EXTENSIONS: &[u16] = &[0, 5, 10, 11, 13, 16, 18, 23, 27, 28, 41, 43, 45, 51];
const DEFAULT_JA3_GROUPS: &[u16] = &[29, 23, 24];
const DEFAULT_JA3_EC_POINTS: &[u16] = &[0];
const DEFAULT_JA3S_BASE_EXTENSIONS: &[u16] = &[0, 11, 13, 23, 27, 28, 41, 43, 45];

/// Stream states (RFC 7540 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// HTTP/2 Stream
#[derive(Debug)]
pub struct Stream {
    pub id: u32,
    pub state: StreamState,
    pub headers: Vec<(String, String)>,
    pub data: Vec<u8>,
    pub window_size: i32,
}

impl Stream {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            headers: Vec::new(),
            data: Vec::new(),
            window_size: 65535, // Default initial window size
        }
    }
}

/// HTTP/2 Connection
pub struct Http2Connection<T: Read + IoWrite> {
    stream: T,
    hpack: HpackCodec,
    streams: HashMap<u32, Stream>,
    next_stream_id: u32,
    server_settings: HashMap<u16, u32>,
}

impl<T: Read + IoWrite> Http2Connection<T> {
    /// Create new HTTP/2 connection
    pub fn new(mut stream: T) -> Result<Self, String> {
        // Send connection preface
        stream
            .write_all(CONNECTION_PREFACE)
            .map_err(|e| format!("Failed to send connection preface: {}", e))?;

        // Send initial SETTINGS frame
        let settings = frame::SettingsFrame {
            header: frame::FrameHeader {
                length: 0,
                frame_type: frame::FRAME_TYPE_SETTINGS,
                flags: 0,
                stream_id: 0,
            },
            settings: vec![],
        };

        stream
            .write_all(&settings.to_bytes())
            .map_err(|e| format!("Failed to send SETTINGS: {}", e))?;

        Ok(Self {
            stream,
            hpack: HpackCodec::new(),
            streams: HashMap::new(),
            next_stream_id: 1, // Client-initiated streams are odd
            server_settings: HashMap::new(),
        })
    }

    /// Send generic HTTP/2 request
    pub fn request(
        &mut self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        mut headers: Vec<(String, String)>,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Skip to next odd number

        // Create stream
        let mut stream_obj = Stream::new(stream_id);
        stream_obj.state = StreamState::Open;

        // Build pseudo-headers
        let mut all_headers = vec![
            (":method".to_string(), method.to_string()),
            (":scheme".to_string(), scheme.to_string()),
            (":authority".to_string(), authority.to_string()),
            (":path".to_string(), path.to_string()),
        ];

        // Ensure pseudo-headers precede regular headers (RFC 7540 §8.1.2.1)
        // Additional headers supplied by caller
        all_headers.extend(headers.drain(..));

        // Encode headers with HPACK
        let header_block = self
            .hpack
            .encode(&all_headers)
            .map_err(|e| format!("HPACK encoding failed: {}", e))?;

        // Determine frame flags based on presence of body
        let mut header_flags = frame::FLAG_END_HEADERS;
        let has_body = body.map(|b| !b.is_empty()).unwrap_or(false);
        if !has_body {
            header_flags |= frame::FLAG_END_STREAM;
        }

        // Create HEADERS frame
        let mut header_frame =
            frame::FrameHeader::new(frame::FRAME_TYPE_HEADERS, header_flags, stream_id);
        header_frame.length = header_block.len() as u32;

        // Send HEADERS frame
        self.stream
            .write_all(&header_frame.to_bytes())
            .map_err(|e| format!("Failed to send HEADERS frame header: {}", e))?;

        self.stream
            .write_all(&header_block)
            .map_err(|e| format!("Failed to send HEADERS frame payload: {}", e))?;

        if has_body {
            stream_obj.state = StreamState::HalfClosedRemote;
            self.send_body(stream_id, body.unwrap())?;
            stream_obj.state = StreamState::HalfClosedLocal;
        } else {
            stream_obj.state = StreamState::HalfClosedLocal;
        }
        self.streams.insert(stream_id, stream_obj);

        // Read response frames
        self.read_response(stream_id)
    }

    fn send_body(&mut self, stream_id: u32, body: &[u8]) -> Result<(), String> {
        if body.is_empty() {
            return Ok(());
        }

        let max_frame = self
            .server_settings
            .get(&frame::SETTINGS_MAX_FRAME_SIZE)
            .cloned()
            .unwrap_or(16_384);

        let chunk_size = max_frame as usize;
        let mut chunks = body.chunks(chunk_size).peekable();

        while let Some(chunk) = chunks.next() {
            let is_last = chunks.peek().is_none();
            let mut data_header = frame::FrameHeader::new(
                frame::FRAME_TYPE_DATA,
                if is_last { frame::FLAG_END_STREAM } else { 0 },
                stream_id,
            );
            data_header.length = chunk.len() as u32;

            self.stream
                .write_all(&data_header.to_bytes())
                .map_err(|e| format!("Failed to send DATA frame header: {}", e))?;
            self.stream
                .write_all(chunk)
                .map_err(|e| format!("Failed to send DATA frame: {}", e))?;
        }

        Ok(())
    }

    /// Read response frames for a stream
    fn read_response(
        &mut self,
        stream_id: u32,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        let mut response_headers: Vec<(String, String)> = Vec::new();
        let mut response_data = Vec::new();
        let mut status_code = 0u16;

        loop {
            // Read frame header (9 bytes)
            let mut header_bytes = [0u8; 9];
            self.stream
                .read_exact(&mut header_bytes)
                .map_err(|e| format!("Failed to read frame header: {}", e))?;

            let header = frame::FrameHeader::parse(&header_bytes)?;

            // Read frame payload
            let mut payload = vec![0u8; header.length as usize];
            if header.length > 0 {
                self.stream
                    .read_exact(&mut payload)
                    .map_err(|e| format!("Failed to read frame payload: {}", e))?;
            }

            // Parse frame
            let frame = frame::Frame::parse(header, &payload)?;

            match frame {
                Frame::Settings(settings_frame) => {
                    // Handle SETTINGS frame
                    if settings_frame.header.has_flag(frame::FLAG_ACK) {
                        // SETTINGS ACK - ignore
                    } else {
                        // Server settings - send ACK
                        for setting in &settings_frame.settings {
                            self.server_settings
                                .insert(setting.identifier, setting.value);
                        }

                        let ack = frame::SettingsFrame::new_ack();
                        self.stream
                            .write_all(&ack.to_bytes())
                            .map_err(|e| format!("Failed to send SETTINGS ACK: {}", e))?;
                    }
                }
                Frame::Headers(headers_frame) => {
                    if headers_frame.header.stream_id == stream_id {
                        let mut header_block = headers_frame.header_block_fragment.clone();
                        if !headers_frame.header.has_flag(frame::FLAG_END_HEADERS) {
                            header_block.extend(self.collect_continuation(stream_id)?);
                        }

                        let headers = self
                            .hpack
                            .decode(&header_block)
                            .map_err(|e| format!("HPACK decoding failed: {}", e))?;

                        for (name, value) in &headers {
                            if name == ":status" {
                                status_code = value
                                    .parse()
                                    .map_err(|_| format!("Invalid status code: {}", value))?;
                            } else if !name.starts_with(':') {
                                response_headers.push((name.clone(), value.clone()));
                            }
                        }

                        if headers_frame.header.has_flag(frame::FLAG_END_STREAM) {
                            break;
                        }
                    }
                }
                Frame::Data(data_frame) => {
                    if data_frame.header.stream_id == stream_id {
                        response_data.extend_from_slice(&data_frame.data);

                        if data_frame.header.has_flag(frame::FLAG_END_STREAM) {
                            break;
                        }
                    }
                }
                Frame::WindowUpdate(_) => {
                    // Handle WINDOW_UPDATE
                }
                Frame::GoAway(goaway) => {
                    return Err(format!(
                        "Server sent GOAWAY: error_code={}",
                        goaway.error_code
                    ));
                }
                Frame::RstStream(rst) => {
                    if rst.header.stream_id == stream_id {
                        return Err(format!("Stream reset: error_code={}", rst.error_code));
                    }
                }
                Frame::Continuation(_) => {
                    // Continuations handled via collect_continuation
                    continue;
                }
                _ => {
                    // Ignore other frame types for now
                }
            }
        }

        Ok((status_code, response_headers, response_data))
    }

    fn collect_continuation(&mut self, stream_id: u32) -> Result<Vec<u8>, String> {
        let mut combined = Vec::new();

        loop {
            let mut header_bytes = [0u8; 9];
            self.stream
                .read_exact(&mut header_bytes)
                .map_err(|e| format!("Failed to read continuation header: {}", e))?;
            let header = frame::FrameHeader::parse(&header_bytes)?;

            if header.stream_id != stream_id {
                return Err("Received CONTINUATION for different stream".to_string());
            }

            let mut payload = vec![0u8; header.length as usize];
            if header.length > 0 {
                self.stream
                    .read_exact(&mut payload)
                    .map_err(|e| format!("Failed to read continuation payload: {}", e))?;
            }

            if header.frame_type != frame::FRAME_TYPE_CONTINUATION {
                return Err("Expected CONTINUATION frame".to_string());
            }

            combined.extend_from_slice(&payload);

            if header.has_flag(frame::FLAG_END_HEADERS) {
                break;
            }
        }

        Ok(combined)
    }

    /// Close connection gracefully
    pub fn close(&mut self) -> Result<(), String> {
        // Send GOAWAY frame
        let goaway_header = frame::FrameHeader {
            length: 8,
            frame_type: frame::FRAME_TYPE_GOAWAY,
            flags: 0,
            stream_id: 0,
        };

        let mut goaway_payload = Vec::new();
        // Last stream ID (31 bits)
        goaway_payload.extend_from_slice(&self.next_stream_id.to_be_bytes());
        // Error code: NO_ERROR
        goaway_payload.extend_from_slice(&frame::ERROR_NO_ERROR.to_be_bytes());

        self.stream
            .write_all(&goaway_header.to_bytes())
            .map_err(|e| format!("Failed to send GOAWAY header: {}", e))?;

        self.stream
            .write_all(&goaway_payload)
            .map_err(|e| format!("Failed to send GOAWAY payload: {}", e))?;

        Ok(())
    }
}

/// HTTP/2 TLS response container
#[derive(Debug, Clone)]
pub struct Http2Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub handshake: Option<TlsHandshakeMetadata>,
}

/// Minimal HTTP/2-over-TLS client leveraging the vendored OpenSSL bindings.
pub struct Http2TlsClient {
    host: String,
    port: u16,
    timeout: Duration,
}

impl Http2TlsClient {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        mut headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        authority: &str,
    ) -> Result<Http2Response, String> {
        let addr = format!("{}:{}", self.host, self.port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("Failed to build TLS connector: {}", e))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("Failed to set min TLS version: {}", e))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("Failed to set max TLS version: {}", e))?;
        #[cfg(any(ossl111, boringssl, libressl, awslc))]
        {
            builder
                .set_ciphersuites(
                    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
                )
                .map_err(|e| format!("Failed to select TLS 1.3 cipher suites: {}", e))?;
            builder
                .set_groups_list("X25519:P-256:P-384")
                .map_err(|e| format!("Failed to configure TLS groups: {}", e))?;
        }
        builder
            .set_alpn_protos(b"\x02h2")
            .map_err(|e| format!("Failed to configure ALPN: {}", e))?;

        let connector = builder.build();
        let ssl_stream = connector
            .connect(&self.host, stream)
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        if let Some(proto) = ssl_stream.ssl().selected_alpn_protocol() {
            if proto != b"h2" {
                return Err("Server did not negotiate HTTP/2 via ALPN".to_string());
            }
        } else {
            return Err("Server did not return ALPN protocol".to_string());
        }

        let ssl_ref = ssl_stream.ssl();
        let handshake_meta = TlsHandshakeMetadata::from_ssl(ssl_ref, authority)?;

        let mut connection = Http2Connection::new(ssl_stream)?;

        let scheme = "https";
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        {
            headers.push(("user-agent".to_string(), "redblue-http2/0.1".to_string()));
        }

        let maybe_body = body;
        if let Some(ref body_bytes) = maybe_body {
            if !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            {
                headers.push(("content-length".to_string(), body_bytes.len().to_string()));
            }
        }

        let (status, response_headers, response_body) = connection.request(
            method,
            scheme,
            authority,
            path,
            headers,
            maybe_body.as_deref(),
        )?;

        Ok(Http2Response {
            status,
            headers: response_headers,
            body: response_body,
            handshake: Some(handshake_meta),
        })
    }
}

#[derive(Debug, Clone)]
pub struct TlsHandshakeMetadata {
    pub authority: String,
    pub tls_version: String,
    pub cipher: Option<String>,
    pub alpn_protocol: Option<String>,
    pub peer_cert_fingerprints: Vec<String>,
    pub peer_cert_subjects: Vec<String>,
    pub certificate_chain_pem: Vec<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja3s_raw: Option<String>,
}

impl TlsHandshakeMetadata {
    pub fn from_ssl(ssl: &openssl::ssl::SslRef, authority: &str) -> Result<Self, String> {
        let tls_version = ssl.version_str().to_string();
        let cipher = ssl.current_cipher().map(|cipher| cipher.name().to_string());
        // cipher.id() method doesn't exist in current openssl version
        let cipher_id: Option<u32> = None;
        let alpn_protocol = ssl
            .selected_alpn_protocol()
            .map(|proto| String::from_utf8_lossy(proto).to_string());

        let mut peer_cert_fingerprints = Vec::new();
        let mut peer_cert_subjects = Vec::new();
        let mut certificate_chain_pem = Vec::new();
        let mut seen_fingerprints = HashSet::new();

        let mut record_cert = |cert: &X509Ref| -> Result<(), String> {
            let subject = format_subject(cert.subject_name());
            if !subject.is_empty() {
                peer_cert_subjects.push(subject);
            }

            let fingerprint = cert
                .digest(MessageDigest::sha256())
                .map_err(|e| format!("Failed to compute fingerprint: {}", e))?;
            let fingerprint_hex = fingerprint
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":");

            if seen_fingerprints.insert(fingerprint_hex.clone()) {
                peer_cert_fingerprints.push(fingerprint_hex);
                let pem = cert
                    .to_pem()
                    .map_err(|e| format!("Failed to export certificate: {}", e))?;
                certificate_chain_pem.push(String::from_utf8_lossy(&pem).to_string());
            }

            Ok(())
        };

        if let Some(cert) = ssl.peer_certificate() {
            record_cert(cert.as_ref())?;
        }

        if let Some(chain) = ssl.peer_cert_chain() {
            for cert_ref in chain {
                record_cert(cert_ref)?;
            }
        }

        let (ja3_raw, ja3_hash) = compute_default_ja3_fingerprint();
        let version_code = tls_version_to_code(&tls_version);
        let (ja3s_raw, ja3s_hash) =
            compute_ja3s_fingerprint(version_code, cipher_id, alpn_protocol.as_ref().is_some());

        Ok(Self {
            authority: authority.to_string(),
            tls_version,
            cipher,
            alpn_protocol,
            peer_cert_fingerprints,
            peer_cert_subjects,
            certificate_chain_pem,
            ja3: Some(ja3_hash),
            ja3s: Some(ja3s_hash),
            ja3_raw: Some(ja3_raw),
            ja3s_raw: Some(ja3s_raw),
        })
    }
}

fn compute_default_ja3_fingerprint() -> (String, String) {
    let raw = format!(
        "{},{},{},{},{}",
        DEFAULT_JA3_VERSION,
        join_u16(DEFAULT_JA3_CIPHERS),
        join_u16(DEFAULT_JA3_EXTENSIONS),
        join_u16(DEFAULT_JA3_GROUPS),
        join_u16(DEFAULT_JA3_EC_POINTS)
    );
    let hash = md5_hex_lowercase(raw.as_bytes());
    (raw, hash)
}

fn compute_ja3s_fingerprint(
    version_code: u16,
    cipher_id: Option<u32>,
    alpn_present: bool,
) -> (String, String) {
    let cipher_value = cipher_id.unwrap_or(0);
    let cipher_part = cipher_value.to_string();
    let mut extensions: Vec<u16> = DEFAULT_JA3S_BASE_EXTENSIONS.to_vec();
    if alpn_present && !extensions.contains(&16) {
        extensions.push(16);
    }
    extensions.sort_unstable();
    extensions.dedup();

    let raw = format!(
        "{},{},{},{},{}",
        version_code,
        cipher_part,
        join_u16(&extensions),
        join_u16(DEFAULT_JA3_GROUPS),
        join_u16(DEFAULT_JA3_EC_POINTS)
    );
    let hash = md5_hex_lowercase(raw.as_bytes());
    (raw, hash)
}

fn join_u16(values: &[u16]) -> String {
    if values.is_empty() {
        String::new()
    } else {
        values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    }
}

fn md5_hex_lowercase(bytes: &[u8]) -> String {
    let digest = md5(bytes);
    let mut out = String::with_capacity(32);
    for byte in digest.iter() {
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn tls_version_to_code(version: &str) -> u16 {
    match version {
        v if v.eq_ignore_ascii_case("TLSv1.3") || v.eq_ignore_ascii_case("TLS 1.3") => 772,
        v if v.eq_ignore_ascii_case("TLSv1.2") || v.eq_ignore_ascii_case("TLS 1.2") => 771,
        v if v.eq_ignore_ascii_case("TLSv1.1") || v.eq_ignore_ascii_case("TLS 1.1") => 770,
        v if v.eq_ignore_ascii_case("TLSv1.0") || v.eq_ignore_ascii_case("TLS 1.0") => 769,
        _ => DEFAULT_JA3_VERSION,
    }
}

fn format_subject(name: &openssl::x509::X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let label = entry.object().nid().short_name().unwrap_or("?").to_string();
        let value = entry
            .data()
            .as_utf8()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| "<binary>".to_string());
        parts.push(format!("{}={}", label, value));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_preface() {
        assert_eq!(CONNECTION_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    }

    #[test]
    fn test_stream_creation() {
        let stream = Stream::new(1);
        assert_eq!(stream.id, 1);
        assert_eq!(stream.state, StreamState::Idle);
        assert_eq!(stream.window_size, 65535);
    }
}
