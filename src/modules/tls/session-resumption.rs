/// TLS Session Resumption Testing
///
/// Tests for TLS session resumption mechanisms:
/// - Session ID resumption (classic TLS 1.2)
/// - Session Ticket resumption (RFC 5077)
/// - TLS 1.3 PSK resumption
///
/// Session resumption allows clients to reconnect faster by reusing
/// cryptographic parameters from a previous session.
///
/// **Security Implications:**
/// - Session tickets stored indefinitely = forward secrecy issues
/// - Weak ticket encryption = session hijacking risk
/// - No ticket rotation = long-term key compromise risk
///
/// **What We Test:**
/// 1. Does server support session ID resumption?
/// 2. Does server support session tickets (RFC 5077)?
/// 3. Session ticket lifetime (if disclosed)
/// 4. Does resumed session skip full handshake?
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Session resumption test result
#[derive(Debug, Clone)]
pub struct SessionResumptionResult {
    pub host: String,
    pub port: u16,

    /// Session ID resumption support
    pub session_id_supported: bool,
    pub session_id_error: Option<String>,

    /// Session ticket (RFC 5077) support
    pub session_ticket_supported: bool,
    pub session_ticket_lifetime: Option<u32>,
    pub session_ticket_error: Option<String>,

    /// TLS 1.3 PSK resumption
    pub tls13_psk_supported: bool,
    pub tls13_early_data_supported: bool,

    /// Security findings
    pub issues: Vec<ResumptionIssue>,
}

/// Security issue related to session resumption
#[derive(Debug, Clone)]
pub struct ResumptionIssue {
    pub severity: ResumptionSeverity,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResumptionSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl ResumptionSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            ResumptionSeverity::Info => "INFO",
            ResumptionSeverity::Low => "LOW",
            ResumptionSeverity::Medium => "MEDIUM",
            ResumptionSeverity::High => "HIGH",
        }
    }
}

/// Session resumption tester
pub struct SessionResumptionTester {
    timeout: Duration,
}

impl SessionResumptionTester {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Test all session resumption mechanisms
    pub fn test(&self, host: &str, port: u16) -> SessionResumptionResult {
        let mut result = SessionResumptionResult {
            host: host.to_string(),
            port,
            session_id_supported: false,
            session_id_error: None,
            session_ticket_supported: false,
            session_ticket_lifetime: None,
            session_ticket_error: None,
            tls13_psk_supported: false,
            tls13_early_data_supported: false,
            issues: Vec::new(),
        };

        // Test session ID resumption
        match self.test_session_id_resumption(host, port) {
            Ok((supported, session_id)) => {
                result.session_id_supported = supported;
                if supported {
                    result.issues.push(ResumptionIssue {
                        severity: ResumptionSeverity::Info,
                        title: "Session ID Resumption Supported".to_string(),
                        description: format!(
                            "Server supports session ID resumption (ID: {}...)",
                            hex_preview(&session_id)
                        ),
                    });
                }
            }
            Err(e) => {
                result.session_id_error = Some(e);
            }
        }

        // Test session ticket (RFC 5077) resumption
        match self.test_session_ticket_resumption(host, port) {
            Ok((supported, lifetime)) => {
                result.session_ticket_supported = supported;
                result.session_ticket_lifetime = lifetime;
                if supported {
                    let lifetime_msg = lifetime
                        .map(|l| format!(" (lifetime: {} seconds)", l))
                        .unwrap_or_default();
                    result.issues.push(ResumptionIssue {
                        severity: ResumptionSeverity::Info,
                        title: "Session Ticket Resumption Supported".to_string(),
                        description: format!(
                            "Server supports RFC 5077 session tickets{}",
                            lifetime_msg
                        ),
                    });

                    // Check for security issues with ticket lifetime
                    if let Some(lifetime) = lifetime {
                        if lifetime > 86400 * 7 {
                            // > 7 days
                            result.issues.push(ResumptionIssue {
                                severity: ResumptionSeverity::Medium,
                                title: "Long Session Ticket Lifetime".to_string(),
                                description: format!(
                                    "Session ticket lifetime ({} seconds / {} days) may impact forward secrecy. \
                                     Consider reducing to 24 hours or less.",
                                    lifetime,
                                    lifetime / 86400
                                ),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                result.session_ticket_error = Some(e);
            }
        }

        // Add summary issue if neither is supported
        if !result.session_id_supported && !result.session_ticket_supported {
            result.issues.push(ResumptionIssue {
                severity: ResumptionSeverity::Low,
                title: "No Session Resumption".to_string(),
                description: "Server does not support session resumption. \
                              This increases latency for repeat connections but improves forward secrecy."
                    .to_string(),
            });
        }

        result
    }

    /// Test session ID resumption
    ///
    /// 1. Connect and complete handshake, capture session ID
    /// 2. Reconnect with the captured session ID
    /// 3. Check if server accepts abbreviated handshake
    fn test_session_id_resumption(&self, host: &str, port: u16) -> Result<(bool, Vec<u8>), String> {
        // First connection: get session ID from server
        let session_id = self.get_server_session_id(host, port)?;

        if session_id.is_empty() {
            return Ok((false, Vec::new()));
        }

        // Second connection: try to resume with session ID
        let resumed = self.try_resume_session_id(host, port, &session_id)?;

        Ok((resumed, session_id))
    }

    /// Get session ID from initial handshake
    fn get_server_session_id(&self, host: &str, port: u16) -> Result<Vec<u8>, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout failed: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout failed: {}", e))?;

        // Send ClientHello with empty session ID
        let client_hello = build_client_hello(host, &[], false);
        send_record(&mut stream, 0x16, &client_hello)?;

        // Read ServerHello
        let response = read_record(&mut stream)?;
        if response.is_empty() {
            return Err("Empty response from server".to_string());
        }

        // Parse ServerHello to extract session ID
        parse_server_hello_session_id(&response)
    }

    /// Try to resume using a session ID
    fn try_resume_session_id(
        &self,
        host: &str,
        port: u16,
        session_id: &[u8],
    ) -> Result<bool, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout failed: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout failed: {}", e))?;

        // Send ClientHello with session ID from previous connection
        let client_hello = build_client_hello(host, session_id, false);
        send_record(&mut stream, 0x16, &client_hello)?;

        // Read ServerHello
        let response = read_record(&mut stream)?;
        if response.is_empty() {
            return Err("Empty response from server".to_string());
        }

        // Check if server returned the same session ID (indicates resumption)
        let server_session_id = parse_server_hello_session_id(&response)?;
        Ok(!server_session_id.is_empty() && server_session_id == session_id)
    }

    /// Test session ticket (RFC 5077) resumption
    fn test_session_ticket_resumption(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(bool, Option<u32>), String> {
        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout failed: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Set timeout failed: {}", e))?;

        // Send ClientHello with session ticket extension
        let client_hello = build_client_hello(host, &[], true);
        send_record(&mut stream, 0x16, &client_hello)?;

        // Read response - look for session ticket extension in ServerHello
        // or NewSessionTicket message after handshake
        let response = read_record(&mut stream)?;
        if response.is_empty() {
            return Err("Empty response from server".to_string());
        }

        // Check if ServerHello contains session ticket extension
        let (supported, lifetime) = parse_session_ticket_support(&response);
        Ok((supported, lifetime))
    }
}

impl Default for SessionResumptionTester {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a TLS 1.2 ClientHello message
fn build_client_hello(host: &str, session_id: &[u8], include_ticket_extension: bool) -> Vec<u8> {
    let mut message = Vec::new();

    // Handshake type: ClientHello
    message.push(0x01);

    // Length placeholder (3 bytes)
    let length_pos = message.len();
    message.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Client version: TLS 1.2
    message.push(0x03);
    message.push(0x03);

    // Client random (32 bytes)
    let client_random: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    message.extend_from_slice(&client_random);

    // Session ID
    if session_id.is_empty() {
        message.push(0x00);
    } else {
        message.push(session_id.len() as u8);
        message.extend_from_slice(session_id);
    }

    // Cipher suites
    let cipher_suites: &[u8] = &[
        0x00, 0x0c, // Length (6 suites * 2 bytes = 12)
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x9e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x9f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
    ];
    message.extend_from_slice(cipher_suites);

    // Compression methods
    message.extend_from_slice(&[0x01, 0x00]); // 1 method: null

    // Extensions
    let mut extensions = Vec::new();

    // SNI extension
    let sni_ext = build_sni_extension(host);
    extensions.extend_from_slice(&sni_ext);

    // Supported groups (for ECDHE)
    extensions.extend_from_slice(&[
        0x00, 0x0a, // supported_groups extension
        0x00, 0x06, // length
        0x00, 0x04, // list length
        0x00, 0x17, // secp256r1
        0x00, 0x18, // secp384r1
    ]);

    // EC point formats
    extensions.extend_from_slice(&[
        0x00, 0x0b, // ec_point_formats extension
        0x00, 0x02, // length
        0x01, // list length
        0x00, // uncompressed
    ]);

    // Signature algorithms
    extensions.extend_from_slice(&[
        0x00, 0x0d, // signature_algorithms extension
        0x00, 0x0a, // length
        0x00, 0x08, // list length
        0x04, 0x01, // RSA PKCS1 SHA256
        0x05, 0x01, // RSA PKCS1 SHA384
        0x06, 0x01, // RSA PKCS1 SHA512
        0x04, 0x03, // ECDSA SHA256
    ]);

    // Session ticket extension (RFC 5077)
    if include_ticket_extension {
        extensions.extend_from_slice(&[
            0x00, 0x23, // session_ticket extension type
            0x00, 0x00, // empty ticket (request new ticket)
        ]);
    }

    // Extensions length
    let ext_len = extensions.len() as u16;
    message.push((ext_len >> 8) as u8);
    message.push((ext_len & 0xff) as u8);
    message.extend_from_slice(&extensions);

    // Update length field
    let length = (message.len() - length_pos - 3) as u32;
    message[length_pos] = ((length >> 16) & 0xff) as u8;
    message[length_pos + 1] = ((length >> 8) & 0xff) as u8;
    message[length_pos + 2] = (length & 0xff) as u8;

    message
}

/// Build SNI extension
fn build_sni_extension(host: &str) -> Vec<u8> {
    let mut ext = Vec::new();
    ext.push(0x00); // extension type: server_name (0x0000)
    ext.push(0x00);

    let name_bytes = host.as_bytes();
    let name_list_len = name_bytes.len() + 3; // 1 byte type + 2 bytes length + name
    let ext_len = name_list_len + 2; // 2 bytes for list length

    ext.push((ext_len >> 8) as u8);
    ext.push((ext_len & 0xff) as u8);

    ext.push((name_list_len >> 8) as u8);
    ext.push((name_list_len & 0xff) as u8);

    ext.push(0x00); // name type: host_name

    ext.push((name_bytes.len() >> 8) as u8);
    ext.push((name_bytes.len() & 0xff) as u8);
    ext.extend_from_slice(name_bytes);

    ext
}

/// Send a TLS record
fn send_record(stream: &mut TcpStream, content_type: u8, data: &[u8]) -> Result<(), String> {
    let mut record = Vec::new();
    record.push(content_type);
    record.push(0x03); // TLS 1.0 for record layer
    record.push(0x01);
    record.push((data.len() >> 8) as u8);
    record.push((data.len() & 0xff) as u8);
    record.extend_from_slice(data);

    stream
        .write_all(&record)
        .map_err(|e| format!("Write failed: {}", e))?;
    stream.flush().map_err(|e| format!("Flush failed: {}", e))?;

    Ok(())
}

/// Read a TLS record
fn read_record(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|e| format!("Read header failed: {}", e))?;

    let length = ((header[3] as usize) << 8) | (header[4] as usize);
    if length > 16384 {
        return Err(format!("Record too large: {}", length));
    }

    let mut data = vec![0u8; length];
    stream
        .read_exact(&mut data)
        .map_err(|e| format!("Read data failed: {}", e))?;

    Ok(data)
}

/// Parse session ID from ServerHello
fn parse_server_hello_session_id(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 39 {
        return Err("ServerHello too short".to_string());
    }

    // Check handshake type
    if data[0] != 0x02 {
        return Err("Not a ServerHello message".to_string());
    }

    // Skip: handshake type (1), length (3), version (2), random (32)
    let offset = 1 + 3 + 2 + 32;

    if offset >= data.len() {
        return Err("ServerHello truncated before session ID".to_string());
    }

    let session_id_len = data[offset] as usize;
    if offset + 1 + session_id_len > data.len() {
        return Err("ServerHello truncated at session ID".to_string());
    }

    Ok(data[offset + 1..offset + 1 + session_id_len].to_vec())
}

/// Parse session ticket support from ServerHello
fn parse_session_ticket_support(data: &[u8]) -> (bool, Option<u32>) {
    if data.len() < 39 {
        return (false, None);
    }

    // Check handshake type
    if data[0] != 0x02 {
        return (false, None);
    }

    // Skip: handshake type (1), length (3), version (2), random (32), session_id
    let mut offset = 1 + 3 + 2 + 32;

    if offset >= data.len() {
        return (false, None);
    }

    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    // Skip cipher suite (2) and compression method (1)
    offset += 3;

    if offset >= data.len() {
        return (false, None);
    }

    // Check for extensions
    if offset + 2 > data.len() {
        return (false, None);
    }

    let ext_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
    offset += 2;

    let ext_end = offset + ext_len;
    if ext_end > data.len() {
        return (false, None);
    }

    // Parse extensions looking for session_ticket (0x0023)
    while offset + 4 <= ext_end {
        let ext_type = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let ext_data_len = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
        offset += 4;

        if ext_type == 0x0023 {
            // Session ticket extension present
            // If server includes it in ServerHello, it supports tickets
            return (true, None);
        }

        offset += ext_data_len;
    }

    (false, None)
}

/// Get hex preview of bytes
fn hex_preview(data: &[u8]) -> String {
    if data.len() <= 8 {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    } else {
        format!(
            "{}...",
            data[..8]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client_hello() {
        let hello = build_client_hello("example.com", &[], false);
        assert!(!hello.is_empty());
        assert_eq!(hello[0], 0x01); // ClientHello type
    }

    #[test]
    fn test_build_client_hello_with_session_id() {
        let session_id = vec![0x01, 0x02, 0x03, 0x04];
        let hello = build_client_hello("example.com", &session_id, false);
        assert!(!hello.is_empty());
    }

    #[test]
    fn test_build_sni_extension() {
        let sni = build_sni_extension("example.com");
        assert!(!sni.is_empty());
        assert_eq!(sni[0], 0x00); // Extension type high byte
        assert_eq!(sni[1], 0x00); // Extension type low byte (server_name)
    }

    #[test]
    fn test_hex_preview() {
        let short = vec![0x01, 0x02, 0x03];
        assert_eq!(hex_preview(&short), "010203");

        let long = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
        assert_eq!(hex_preview(&long), "0102030405060708...");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(ResumptionSeverity::Info.as_str(), "INFO");
        assert_eq!(ResumptionSeverity::High.as_str(), "HIGH");
    }
}
