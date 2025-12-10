/// TLS/SSL Support (from scratch)
///
/// Implements TLS 1.2/1.3 handshake and encryption for secure communication.
/// This is a SIMPLIFIED implementation for netcat usage - NOT a full TLS library.
///
/// Features:
/// - TLS 1.2 client handshake
/// - Basic cipher suite support
/// - Certificate verification (optional)
/// - Encrypted data transfer
///
/// Replaces: ncat --ssl
use crate::crypto::aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::crypto::hmac::{hmac_sha1, hmac_sha256};
use crate::crypto::md5;
use crate::crypto::prf::Tls12PrfAlgorithm;
use crate::crypto::rsa::extract_public_key_from_cert;
use crate::crypto::sha1;
use crate::crypto::sha256;
use crate::crypto::sha384;
use crate::crypto::tls13_keyschedule::Tls13KeySchedule;
use crate::crypto::x25519::{x25519, x25519_public_key};
use crate::crypto::{aes, prf, BigInt, Tls13HashAlgorithm};
use crate::protocols::asn1::Asn1Object;
use crate::protocols::gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};
use crate::protocols::p256::P256Point;
use crate::protocols::x509::X509Certificate;
use std::cmp::Ordering;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    fn to_bytes(self) -> (u8, u8) {
        match self {
            TlsVersion::Tls10 => (0x03, 0x01),
            TlsVersion::Tls11 => (0x03, 0x02),
            TlsVersion::Tls12 => (0x03, 0x03),
            TlsVersion::Tls13 => (0x03, 0x03),
        }
    }

    fn record_version(self) -> (u8, u8) {
        match self {
            TlsVersion::Tls10 => (0x03, 0x01),
            TlsVersion::Tls11 => (0x03, 0x02),
            TlsVersion::Tls12 => (0x03, 0x03),
            TlsVersion::Tls13 => (0x03, 0x03),
        }
    }
}

/// Cipher suite
#[derive(Debug, Clone, Copy)]
pub enum CipherSuite {
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyExchange {
    Rsa,
    Ecdhe,
}

enum EcdheParameters {
    P256 { server_public: P256Point },
    X25519 { server_public: [u8; 32] },
}

#[derive(Debug, Clone, Copy)]
enum Tls13NamedGroup {
    X25519 = 0x001D,
}

impl Tls13NamedGroup {
    fn as_u16(self) -> u16 {
        self as u16
    }
}

#[allow(dead_code)]
struct Tls13ClientKeyShare {
    group: Tls13NamedGroup,
    private_key: [u8; 32],
    public_key: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct Tls13NewSessionTicket {
    lifetime: u32,
    age_add: u32,
    nonce: Vec<u8>,
    ticket: Vec<u8>,
    extensions: Vec<u8>,
}

const P256_ORDER_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

const TLS13_SERVER_CERT_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

#[derive(Debug, Clone, Copy)]
enum MacAlgorithm {
    Sha1,
    Sha256,
}

impl MacAlgorithm {
    fn mac_len(self) -> usize {
        match self {
            MacAlgorithm::Sha1 => 20,
            MacAlgorithm::Sha256 => 32,
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub version: TlsVersion,
    pub verify_cert: bool,
    pub cipher_suites: Vec<CipherSuite>,
    pub timeout: Duration,
    pub debug: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            version: TlsVersion::Tls12,
            verify_cert: false, // Disabled for pentesting
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            ],
            timeout: Duration::from_secs(10),
            debug: false,
        }
    }
}

impl TlsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_version(mut self, version: TlsVersion) -> Self {
        self.version = version;
        self.cipher_suites = match version {
            TlsVersion::Tls13 => vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            TlsVersion::Tls12 => vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            ],
            TlsVersion::Tls11 | TlsVersion::Tls10 => {
                vec![CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA]
            }
        };
        self
    }

    pub fn with_verify(mut self, verify: bool) -> Self {
        self.verify_cert = verify;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }
}

/// TLS handshake record types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            20 => Some(ContentType::ChangeCipherSpec),
            21 => Some(ContentType::Alert),
            22 => Some(ContentType::Handshake),
            23 => Some(ContentType::ApplicationData),
            _ => None,
        }
    }
}

/// TLS handshake message types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    KeyUpdate = 24,
}

impl HandshakeType {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(HandshakeType::HelloRequest),
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            4 => Some(HandshakeType::NewSessionTicket),
            5 => Some(HandshakeType::EndOfEarlyData),
            8 => Some(HandshakeType::EncryptedExtensions),
            11 => Some(HandshakeType::Certificate),
            12 => Some(HandshakeType::ServerKeyExchange),
            13 => Some(HandshakeType::CertificateRequest),
            14 => Some(HandshakeType::ServerHelloDone),
            15 => Some(HandshakeType::CertificateVerify),
            16 => Some(HandshakeType::ClientKeyExchange),
            20 => Some(HandshakeType::Finished),
            24 => Some(HandshakeType::KeyUpdate),
            _ => None,
        }
    }
}

/// TLS stream wrapper
pub struct TlsStream {
    stream: TcpStream,
    config: TlsConfig,
    handshake_complete: bool,
    read_buffer: Vec<u8>,
    buffer_pos: usize,
    // Crypto state
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    negotiated_cipher_suite: Option<CipherSuite>, // Cipher suite chosen by server
    server_certificate: Option<Vec<u8>>,          // Server's X.509 certificate (DER)
    server_x509: Option<X509Certificate>,         // Parsed server certificate
    pre_master_secret: Option<Vec<u8>>,           // Pre-master secret for key derivation
    master_secret: Option<[u8; 48]>,
    client_write_key: Option<Vec<u8>>, // Variable size (16 or 32 bytes)
    server_write_key: Option<Vec<u8>>, // Variable size (16 or 32 bytes)
    client_write_mac: Option<Vec<u8>>, // Variable size (0, 20, or 32 bytes)
    server_write_mac: Option<Vec<u8>>, // Variable size (0, 20, or 32 bytes)
    client_write_iv: Option<Vec<u8>>,  // Variable size (4 or 16 bytes)
    server_write_iv: Option<Vec<u8>>,  // Variable size (4 or 16 bytes)
    ecdhe_params: Option<EcdheParameters>,
    client_encryption_active: bool,
    server_encryption_active: bool,
    client_sequence: u64,
    server_sequence: u64,
    // Handshake transcript for Finished message
    handshake_messages: Vec<u8>, // All handshake messages (for verify_data calculation)
    tls13_client_key_share: Option<Tls13ClientKeyShare>,
    tls13_key_schedule: Option<Tls13KeySchedule>,
    tls13_certificate_request_context: Option<Vec<u8>>,
    #[allow(dead_code)]
    tls13_new_session_tickets: Vec<Tls13NewSessionTicket>,
}

impl TlsStream {
    fn record_version(&self) -> (u8, u8) {
        self.config.version.record_version()
    }

    fn debug_hex(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len() * 2);
        for byte in data {
            out.push_str(&format!("{:02x}", byte));
        }
        out
    }

    fn debug_log(&self, label: &str, data: &[u8]) {
        if self.config.debug {
            eprintln!("[tls12][debug] {}: {}", label, Self::debug_hex(data));
        }
    }

    /// Create new TLS stream (client mode)
    pub fn connect(host: &str, port: u16, config: TlsConfig) -> Result<Self, String> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        stream
            .set_read_timeout(Some(config.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(config.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        // Generate client random (32 bytes)
        let client_random = generate_random_32();

        let mut tls = Self {
            stream,
            config,
            handshake_complete: false,
            read_buffer: Vec::new(),
            buffer_pos: 0,
            client_random,
            server_random: None,
            negotiated_cipher_suite: None,
            server_certificate: None,
            server_x509: None,
            pre_master_secret: None,
            master_secret: None,
            client_write_key: None,
            server_write_key: None,
            client_write_mac: None,
            server_write_mac: None,
            client_write_iv: None,
            server_write_iv: None,
            ecdhe_params: None,
            client_encryption_active: false,
            server_encryption_active: false,
            client_sequence: 0,
            server_sequence: 0,
            handshake_messages: Vec::new(),
            tls13_client_key_share: None,
            tls13_key_schedule: None,
            tls13_certificate_request_context: None,
            tls13_new_session_tickets: Vec::new(),
        };

        tls.handshake(host)?;
        Ok(tls)
    }

    /// Perform TLS handshake
    fn handshake(&mut self, host: &str) -> Result<(), String> {
        match self.config.version {
            TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 => self.handshake_tls12(host),
            TlsVersion::Tls13 => self.handshake_tls13(host),
        }
    }

    fn handshake_tls12(&mut self, host: &str) -> Result<(), String> {
        self.send_client_hello(host)?;
        let _server_hello = self.receive_server_hello()?;
        let _certificate = self.receive_certificate()?;
        self.receive_server_key_exchange_and_done()?;
        self.send_client_key_exchange()?;
        self.derive_session_keys()?;
        self.send_change_cipher_spec()?;
        self.send_finished()?;
        self.receive_change_cipher_spec()?;
        self.receive_finished()?;
        self.handshake_complete = true;
        Ok(())
    }

    fn activate_tls13_handshake_keys(&mut self) -> Result<(), String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated for TLS 1.3 handshake")?;

        if !cipher_suite_is_tls13(cipher) {
            return Err(format!(
                "TLS 1.3 handshake negotiated non-TLS1.3 cipher {:?}",
                cipher
            ));
        }

        let schedule = self
            .tls13_key_schedule
            .as_ref()
            .ok_or("TLS 1.3 key schedule not initialized")?;

        let server_secret = schedule
            .server_handshake_traffic_secret
            .as_ref()
            .ok_or("Server handshake traffic secret missing")?;
        let client_secret = schedule
            .client_handshake_traffic_secret
            .as_ref()
            .ok_or("Client handshake traffic secret missing")?;

        let (_, key_len, iv_len) = cipher_suite_key_sizes(cipher);
        let (server_key, server_iv) = schedule
            .derive_traffic_keys(server_secret, key_len as u16, iv_len as u16)
            .map_err(|e| format!("Failed to derive server traffic keys: {}", e))?;
        let (client_key, client_iv) = schedule
            .derive_traffic_keys(client_secret, key_len as u16, iv_len as u16)
            .map_err(|e| format!("Failed to derive client traffic keys: {}", e))?;

        self.server_write_key = Some(server_key);
        self.server_write_iv = Some(server_iv);
        self.client_write_key = Some(client_key);
        self.client_write_iv = Some(client_iv);
        self.server_write_mac = None;
        self.client_write_mac = None;

        self.server_encryption_active = true;
        self.client_encryption_active = true;
        self.server_sequence = 0;
        self.client_sequence = 0;

        Ok(())
    }

    fn handshake_tls13(&mut self, host: &str) -> Result<(), String> {
        self.send_client_hello(host)?;
        let server_hello = self.receive_tls13_server_hello()?;
        self.process_tls13_server_hello(&server_hello)?;

        self.receive_tls13_encrypted_handshake()?;
        self.send_tls13_client_auth_responses()?;
        self.send_tls13_finished()?;
        self.activate_tls13_application_keys()?;
        self.handshake_complete = true;

        Ok(())
    }

    /// Send ClientHello message
    fn send_client_hello(&mut self, host: &str) -> Result<(), String> {
        let mut hello = Vec::new();

        // TLS version (configurable)
        let (version_major, version_minor) = self.config.version.to_bytes();
        hello.push(version_major);
        hello.push(version_minor);

        // Random (32 bytes) - use stored client_random
        hello.extend_from_slice(&self.client_random);

        // Session ID (empty for now)
        hello.push(0x00);

        // Cipher suites
        let cipher_count = self.config.cipher_suites.len() as u16;
        hello.push(((cipher_count * 2) >> 8) as u8);
        hello.push((cipher_count * 2) as u8);
        for cipher in &self.config.cipher_suites {
            let cipher_id = cipher_suite_id(*cipher);
            hello.push((cipher_id >> 8) as u8);
            hello.push(cipher_id as u8);
        }

        // Compression methods (none)
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let mut extensions = Vec::new();

        // Server Name Indication (SNI)
        let sni_ext = build_sni_extension(host);
        extensions.extend_from_slice(&sni_ext);

        if matches!(self.config.version, TlsVersion::Tls12 | TlsVersion::Tls13) {
            // Signature algorithms (advertise RSA variants we implement)
            extensions.extend_from_slice(&build_signature_algorithms_extension());
        }

        // Advertise elliptic curves and point formats for ECDHE
        extensions.extend_from_slice(&build_supported_groups_extension());
        extensions.extend_from_slice(&build_ec_point_formats_extension());

        if self.config.version == TlsVersion::Tls13 {
            extensions.extend_from_slice(&build_supported_versions_extension());
            let (key_share_ext, key_share_state) = build_tls13_key_share_extension();
            extensions.extend_from_slice(&key_share_ext);
            self.tls13_client_key_share = Some(key_share_state);
        }

        // Add extensions length
        hello.push((extensions.len() >> 8) as u8);
        hello.push(extensions.len() as u8);
        hello.extend_from_slice(&extensions);

        // Wrap in handshake record
        let handshake = wrap_handshake(HandshakeType::ClientHello, &hello);

        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&handshake);
        // Key schedule transcript will be synchronized once the cipher suite is known.

        // Wrap in TLS record
        self.send_record(ContentType::Handshake, &handshake, false)?;

        Ok(())
    }

    /// Receive ServerHello
    fn receive_server_hello(&mut self) -> Result<Vec<u8>, String> {
        let (content_type, record) = self.receive_tls_record()?;

        if content_type != ContentType::Handshake {
            if content_type == ContentType::Alert && record.len() >= 2 {
                return Err(format!(
                    "Server sent alert during ServerHello: level={}, description={}",
                    record[0], record[1]
                ));
            }
            return Err(format!("Expected Handshake record, got {:?}", content_type));
        }

        if record.is_empty() {
            return Err("Empty ServerHello".to_string());
        }

        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&record);

        // Parse ServerHello to extract server_random and cipher suite
        // Format: HandshakeType (1) + Length (3) + Version (2) + Random (32) + SessionID length (1) + SessionID (0-32) + CipherSuite (2) + Compression (1) + Extensions...

        if record.len() < 38 {
            return Err("ServerHello too short".to_string());
        }

        // Extract server_random (offset 6, 32 bytes)
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&record[6..38]);
        self.server_random = Some(server_random);

        // Extract session ID length (offset 38)
        let session_id_len = record[38] as usize;

        if record.len() < 38 + 1 + session_id_len + 2 {
            return Err("ServerHello too short for cipher suite".to_string());
        }

        // Extract cipher suite (2 bytes after session ID)
        let cipher_offset = 39 + session_id_len;
        let cipher_id = u16::from_be_bytes([record[cipher_offset], record[cipher_offset + 1]]);

        // Parse and store the negotiated cipher suite
        let cipher = cipher_suite_from_id(cipher_id)?;
        self.negotiated_cipher_suite = Some(cipher);

        Ok(record)
    }

    fn receive_tls13_server_hello(&mut self) -> Result<Vec<u8>, String> {
        let (content_type, record) = self.receive_tls_record()?;

        if content_type != ContentType::Handshake {
            if content_type == ContentType::Alert && record.len() >= 2 {
                return Err(format!(
                    "Server sent alert during TLS 1.3 ServerHello: level={}, description={}",
                    record[0], record[1]
                ));
            }
            return Err(format!(
                "Expected TLS 1.3 ServerHello handshake record, got {:?}",
                content_type
            ));
        }

        if record.is_empty() {
            return Err("Empty TLS 1.3 ServerHello".to_string());
        }

        self.handshake_messages.extend_from_slice(&record);
        if let Some(schedule) = self.tls13_key_schedule.as_mut() {
            schedule.add_to_transcript(&record);
        }

        Ok(record)
    }

    fn process_tls13_server_hello(&mut self, record: &[u8]) -> Result<(), String> {
        if record.len() < 4 {
            return Err("TLS 1.3 ServerHello too short".to_string());
        }

        if record[0] != HandshakeType::ServerHello as u8 {
            return Err(format!(
                "Unexpected handshake type in TLS 1.3 ServerHello: {}",
                record[0]
            ));
        }

        let body_len =
            ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
        if record.len() < 4 + body_len {
            return Err("TLS 1.3 ServerHello truncated".to_string());
        }

        let body = &record[4..4 + body_len];
        if body.len() < 38 {
            return Err("TLS 1.3 ServerHello body too short".to_string());
        }

        let mut offset = 0;

        let _legacy_version = u16::from_be_bytes([body[offset], body[offset + 1]]);
        offset += 2;

        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&body[offset..offset + 32]);
        offset += 32;
        self.server_random = Some(server_random);

        if offset >= body.len() {
            return Err("TLS 1.3 ServerHello missing session ID length".to_string());
        }
        let session_id_len = body[offset] as usize;
        offset += 1;

        if offset + session_id_len + 3 > body.len() {
            return Err("TLS 1.3 ServerHello truncated after session ID".to_string());
        }
        offset += session_id_len;

        let cipher_suite_id = u16::from_be_bytes([body[offset], body[offset + 1]]);
        offset += 2;
        let _legacy_compression_method = body[offset];
        offset += 1;

        if offset + 2 > body.len() {
            return Err("TLS 1.3 ServerHello missing extensions length".to_string());
        }
        let extensions_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;

        if offset + extensions_len > body.len() {
            return Err("TLS 1.3 ServerHello extensions truncated".to_string());
        }
        let extensions = &body[offset..offset + extensions_len];

        let negotiated = cipher_suite_from_id(cipher_suite_id)?;
        self.negotiated_cipher_suite = Some(negotiated);

        if self.config.version == TlsVersion::Tls13 {
            let hash_alg = match negotiated {
                CipherSuite::TLS_AES_256_GCM_SHA384
                | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Tls13HashAlgorithm::Sha384,
                _ => Tls13HashAlgorithm::Sha256,
            };

            let mut schedule = Tls13KeySchedule::new(hash_alg);
            schedule.set_transcript(&self.handshake_messages);
            self.tls13_key_schedule = Some(schedule);
        }

        let mut supported_version = None;
        let mut server_key_share_group = None;
        let mut server_key_share_bytes: Option<Vec<u8>> = None;

        let mut ext_offset = 0;
        while ext_offset + 4 <= extensions.len() {
            let ext_type = u16::from_be_bytes([extensions[ext_offset], extensions[ext_offset + 1]]);
            let ext_len =
                u16::from_be_bytes([extensions[ext_offset + 2], extensions[ext_offset + 3]])
                    as usize;
            ext_offset += 4;

            if ext_offset + ext_len > extensions.len() {
                return Err("TLS 1.3 ServerHello extension truncated".to_string());
            }

            let ext_body = &extensions[ext_offset..ext_offset + ext_len];
            match ext_type {
                0x002b => {
                    if ext_body.len() != 2 {
                        return Err(
                            "Invalid supported_versions extension in TLS 1.3 ServerHello"
                                .to_string(),
                        );
                    }
                    supported_version = Some(u16::from_be_bytes([ext_body[0], ext_body[1]]));
                }
                0x0033 => {
                    if ext_body.len() < 4 {
                        return Err(
                            "Invalid key_share extension in TLS 1.3 ServerHello".to_string()
                        );
                    }

                    let mut body = ext_body;
                    if ext_body.len() >= 2
                        && (ext_body.len() - 2)
                            == u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize
                    {
                        body = &ext_body[2..];
                    }

                    if body.len() < 4 {
                        return Err(
                            "Invalid key_share extension body in TLS 1.3 ServerHello".to_string()
                        );
                    }
                    let group = u16::from_be_bytes([body[0], body[1]]);
                    let key_len = u16::from_be_bytes([body[2], body[3]]) as usize;
                    if body.len() < 4 + key_len {
                        return Err("Key share data truncated in TLS 1.3 ServerHello".to_string());
                    }
                    server_key_share_group = Some(group);
                    server_key_share_bytes = Some(body[4..4 + key_len].to_vec());
                }
                _ => {}
            }

            ext_offset += ext_len;
        }

        if ext_offset != extensions.len() {
            return Err("TLS 1.3 ServerHello extension parsing mismatch".to_string());
        }

        let supported_version = supported_version.ok_or_else(|| {
            "TLS 1.3 ServerHello missing supported_versions extension".to_string()
        })?;
        if supported_version != 0x0304 {
            return Err(format!(
                "Server selected unsupported TLS version: 0x{:04X}",
                supported_version
            ));
        }

        let server_key_bytes = server_key_share_bytes
            .ok_or_else(|| "TLS 1.3 ServerHello missing key_share extension".to_string())?;
        if server_key_bytes.len() != 32 {
            return Err(format!(
                "Unexpected TLS 1.3 server key share length: {}",
                server_key_bytes.len()
            ));
        }

        let mut server_public = [0u8; 32];
        server_public.copy_from_slice(&server_key_bytes);
        self.ecdhe_params = Some(EcdheParameters::X25519 { server_public });

        let client_share = self.tls13_client_key_share.as_ref().ok_or_else(|| {
            "TLS 1.3 client key share missing; ClientHello may not have been prepared correctly"
                .to_string()
        })?;

        if server_key_share_group != Some(Tls13NamedGroup::X25519.as_u16()) {
            return Err("Server selected unsupported key share group for TLS 1.3".to_string());
        }

        let shared_secret = x25519(&client_share.private_key, &server_public);
        if let Some(schedule) = self.tls13_key_schedule.as_mut() {
            schedule.derive_handshake_secret(&shared_secret);
            schedule.derive_handshake_traffic_secrets();
        }

        self.activate_tls13_handshake_keys()?;

        Ok(())
    }

    fn receive_tls13_encrypted_handshake(&mut self) -> Result<(), String> {
        let mut server_finished = false;

        while !server_finished {
            let (content_type, payload) = self.receive_tls_record()?;

            match content_type {
                ContentType::ChangeCipherSpec => continue, // Compatibility mode; ignore
                ContentType::Alert => {
                    if payload.len() >= 2 {
                        return Err(format!(
                            "Server sent TLS 1.3 alert: level={}, description={}",
                            payload[0], payload[1]
                        ));
                    }
                    return Err("Server sent TLS 1.3 alert".to_string());
                }
                ContentType::Handshake | ContentType::ApplicationData => {
                    if payload.is_empty() {
                        continue;
                    }

                    let mut offset = 0;
                    while offset + 4 <= payload.len() {
                        let msg_type = payload[offset];
                        let msg_len = ((payload[offset + 1] as usize) << 16)
                            | ((payload[offset + 2] as usize) << 8)
                            | (payload[offset + 3] as usize);
                        let total_len = 4 + msg_len;

                        if offset + total_len > payload.len() {
                            return Err("TLS 1.3 handshake message truncated in encrypted flight"
                                .to_string());
                        }

                        let message = &payload[offset..offset + total_len];
                        let handshake_type =
                            HandshakeType::from_byte(msg_type).ok_or_else(|| {
                                format!("Unknown TLS 1.3 handshake message type {}", msg_type)
                            })?;

                        match handshake_type {
                            HandshakeType::EncryptedExtensions => {
                                self.handshake_messages.extend_from_slice(message);
                                if let Some(schedule) = self.tls13_key_schedule.as_mut() {
                                    schedule.add_to_transcript(message);
                                }
                            }
                            HandshakeType::Certificate => {
                                self.handshake_messages.extend_from_slice(message);
                                if let Some(schedule) = self.tls13_key_schedule.as_mut() {
                                    schedule.add_to_transcript(message);
                                }
                                self.parse_tls13_certificate(message)?;
                            }
                            HandshakeType::CertificateVerify => {
                                let schedule =
                                    self.tls13_key_schedule.as_ref().ok_or_else(|| {
                                        "TLS 1.3 key schedule missing for CertificateVerify"
                                            .to_string()
                                    })?;
                                let transcript_hash = schedule.get_handshake_hash_value();
                                if message.len() < 8 {
                                    return Err(
                                        "TLS 1.3 CertificateVerify message too short".to_string()
                                    );
                                }
                                let signature_scheme = u16::from_be_bytes([message[4], message[5]]);
                                let sig_len = u16::from_be_bytes([message[6], message[7]]) as usize;
                                if message.len() < 8 + sig_len {
                                    return Err(
                                        "TLS 1.3 CertificateVerify signature truncated".to_string()
                                    );
                                }
                                let signature = &message[8..8 + sig_len];
                                let signed_data = build_tls13_certificate_verify_input(
                                    TLS13_SERVER_CERT_VERIFY_CONTEXT,
                                    &transcript_hash,
                                );
                                self.verify_tls13_certificate_verify(
                                    signature_scheme,
                                    &signed_data,
                                    signature,
                                )?;

                                self.handshake_messages.extend_from_slice(message);
                                if let Some(schedule) = self.tls13_key_schedule.as_mut() {
                                    schedule.add_to_transcript(message);
                                }
                            }
                            HandshakeType::CertificateRequest => {
                                self.parse_tls13_certificate_request(message)?;
                            }
                            HandshakeType::NewSessionTicket => {
                                self.parse_tls13_new_session_ticket(message)?;
                            }
                            HandshakeType::Finished => {
                                let verify_data = &message[4..];
                                let expected = {
                                    let schedule =
                                        self.tls13_key_schedule.as_ref().ok_or_else(|| {
                                            "TLS 1.3 key schedule missing for server Finished"
                                                .to_string()
                                        })?;
                                    schedule.server_finished_verify_data()?
                                };

                                if verify_data != expected {
                                    return Err(
                                        "Server Finished verify data mismatch in TLS 1.3 handshake"
                                            .to_string(),
                                    );
                                }

                                self.handshake_messages.extend_from_slice(message);
                                if let Some(schedule) = self.tls13_key_schedule.as_mut() {
                                    schedule.add_to_transcript(message);
                                    schedule.derive_master_secret();
                                    schedule.derive_application_traffic_secrets();
                                }

                                server_finished = true;
                            }
                            HandshakeType::KeyUpdate => {
                                return Err(
                                    "Server sent TLS 1.3 KeyUpdate; key updates are not implemented yet"
                                        .to_string(),
                                );
                            }
                            other => {
                                return Err(format!(
                                    "Unsupported TLS 1.3 handshake message {:?}",
                                    other
                                ));
                            }
                        }

                        offset += total_len;
                        if server_finished {
                            break;
                        }
                    }

                    if offset != payload.len() && !server_finished {
                        return Err("Extra bytes in TLS 1.3 handshake record".to_string());
                    }
                }
                other => {
                    return Err(format!(
                        "Unexpected TLS 1.3 record content type {:?} during handshake",
                        other
                    ));
                }
            }
        }

        Ok(())
    }

    fn parse_tls13_certificate(&mut self, message: &[u8]) -> Result<(), String> {
        if message.len() < 5 {
            return Err("TLS 1.3 Certificate message too short".to_string());
        }

        let mut offset = 4;
        if offset >= message.len() {
            return Err("TLS 1.3 Certificate missing request context length".to_string());
        }

        let context_len = message[offset] as usize;
        offset += 1;
        if offset + context_len > message.len() {
            return Err("TLS 1.3 Certificate request context truncated".to_string());
        }
        offset += context_len;

        if offset + 3 > message.len() {
            return Err("TLS 1.3 Certificate missing certificate list length".to_string());
        }

        let cert_list_len = ((message[offset] as usize) << 16)
            | ((message[offset + 1] as usize) << 8)
            | (message[offset + 2] as usize);
        offset += 3;

        if offset + cert_list_len > message.len() {
            return Err("TLS 1.3 Certificate list truncated".to_string());
        }

        if cert_list_len < 3 {
            return Err("TLS 1.3 Certificate list empty".to_string());
        }

        if offset + 3 > message.len() {
            return Err("TLS 1.3 Certificate missing certificate length".to_string());
        }
        let cert_len = ((message[offset] as usize) << 16)
            | ((message[offset + 1] as usize) << 8)
            | (message[offset + 2] as usize);
        offset += 3;

        if offset + cert_len > message.len() {
            return Err("TLS 1.3 certificate data truncated".to_string());
        }

        let cert_der = message[offset..offset + cert_len].to_vec();
        if self.config.verify_cert {
            let parsed = X509Certificate::from_der(&cert_der)
                .map_err(|e| format!("Failed to parse TLS 1.3 server certificate: {}", e))?;
            self.server_x509 = Some(parsed);
        }
        self.server_certificate = Some(cert_der);

        Ok(())
    }

    fn parse_tls13_certificate_request(&mut self, message: &[u8]) -> Result<(), String> {
        if message.len() < 5 {
            return Err("TLS 1.3 CertificateRequest too short".to_string());
        }
        if message[0] != HandshakeType::CertificateRequest as u8 {
            return Err("Unexpected TLS 1.3 CertificateRequest handshake type".to_string());
        }

        let mut offset = 4; // skip handshake header

        if offset >= message.len() {
            return Err("TLS 1.3 CertificateRequest missing context length".to_string());
        }
        let context_len = message[offset] as usize;
        offset += 1;
        if offset + context_len > message.len() {
            return Err("TLS 1.3 CertificateRequest context truncated".to_string());
        }
        let context = message[offset..offset + context_len].to_vec();
        offset += context_len;

        if offset + 2 > message.len() {
            return Err("TLS 1.3 CertificateRequest missing signature schemes length".to_string());
        }
        let sig_algs_len = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        if offset + sig_algs_len > message.len() {
            return Err("TLS 1.3 CertificateRequest signature schemes truncated".to_string());
        }
        offset += sig_algs_len;

        if offset + 2 > message.len() {
            return Err("TLS 1.3 CertificateRequest missing extensions length".to_string());
        }
        let extensions_len = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        if offset + extensions_len > message.len() {
            return Err("TLS 1.3 CertificateRequest extensions truncated".to_string());
        }
        offset += extensions_len;

        if offset != message.len() {
            return Err("TLS 1.3 CertificateRequest has extra bytes".to_string());
        }

        self.tls13_certificate_request_context = Some(context);
        Ok(())
    }

    fn parse_tls13_new_session_ticket(&mut self, message: &[u8]) -> Result<(), String> {
        if message.len() < 10 {
            return Err("TLS 1.3 NewSessionTicket too short".to_string());
        }
        if message[0] != HandshakeType::NewSessionTicket as u8 {
            return Err("Expected NewSessionTicket handshake type".to_string());
        }

        let mut offset = 4; // skip handshake header

        if offset + 4 > message.len() {
            return Err("TLS 1.3 NewSessionTicket missing lifetime".to_string());
        }
        let lifetime = u32::from_be_bytes([
            message[offset],
            message[offset + 1],
            message[offset + 2],
            message[offset + 3],
        ]);
        offset += 4;

        if offset + 4 > message.len() {
            return Err("TLS 1.3 NewSessionTicket missing age_add".to_string());
        }
        let age_add = u32::from_be_bytes([
            message[offset],
            message[offset + 1],
            message[offset + 2],
            message[offset + 3],
        ]);
        offset += 4;

        if offset >= message.len() {
            return Err("TLS 1.3 NewSessionTicket missing nonce length".to_string());
        }
        let nonce_len = message[offset] as usize;
        offset += 1;
        if offset + nonce_len > message.len() {
            return Err("TLS 1.3 NewSessionTicket nonce truncated".to_string());
        }
        let nonce = message[offset..offset + nonce_len].to_vec();
        offset += nonce_len;

        if offset + 2 > message.len() {
            return Err("TLS 1.3 NewSessionTicket missing ticket length".to_string());
        }
        let ticket_len = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        if offset + ticket_len > message.len() {
            return Err("TLS 1.3 NewSessionTicket ticket truncated".to_string());
        }
        let ticket = message[offset..offset + ticket_len].to_vec();
        offset += ticket_len;

        if offset + 2 > message.len() {
            return Err("TLS 1.3 NewSessionTicket missing extensions length".to_string());
        }
        let extensions_len = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        if offset + extensions_len > message.len() {
            return Err("TLS 1.3 NewSessionTicket extensions truncated".to_string());
        }
        let extensions = message[offset..offset + extensions_len].to_vec();
        offset += extensions_len;

        if offset != message.len() {
            return Err("TLS 1.3 NewSessionTicket has extra bytes".to_string());
        }

        self.tls13_new_session_tickets.push(Tls13NewSessionTicket {
            lifetime,
            age_add,
            nonce,
            ticket,
            extensions,
        });

        Ok(())
    }

    fn verify_tls13_certificate_verify(
        &mut self,
        signature_scheme: u16,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        if !self.config.verify_cert {
            return Ok(());
        }

        let cert_der = self
            .server_certificate
            .as_ref()
            .ok_or_else(|| "Server certificate not available for verification".to_string())?;

        let cert_x509 = self.server_x509.as_ref();

        match signature_scheme {
            0x0403 => {
                let cert = cert_x509.ok_or_else(|| {
                    "Parsed server certificate unavailable for ECDSA verification".to_string()
                })?;

                let alg_oid = cert.subject_public_key_info.algorithm.algorithm.as_str();
                if alg_oid != "1.2.840.10045.2.1" {
                    return Err(format!(
                        "Server certificate uses unsupported public key algorithm {}",
                        alg_oid
                    ));
                }

                let curve_oid = cert
                    .subject_public_key_info
                    .algorithm
                    .parameters_oid
                    .as_deref()
                    .unwrap_or_default();
                if curve_oid != "1.2.840.10045.3.1.7" {
                    return Err(format!(
                        "Server certificate ECDSA curve {} not supported (expect P-256)",
                        curve_oid
                    ));
                }

                let public_key_bytes = &cert.subject_public_key_info.public_key;
                let point = P256Point::from_uncompressed_bytes(public_key_bytes)
                    .map_err(|e| format!("Invalid P-256 public key: {}", e))?;

                verify_ecdsa_p256_signature(&point, signed_data, signature)
                    .map_err(|e| format!("ECDSA verification failed: {}", e))
            }
            0x0401 => {
                let rsa = extract_public_key_from_cert(cert_der)
                    .map_err(|e| format!("Failed to extract RSA public key: {}", e))?;
                let hash = sha256::sha256(signed_data);
                let digest = build_digest_info_sha256(&hash);
                if digest.is_empty() {
                    return Err("Failed to build SHA-256 DigestInfo".to_string());
                }
                rsa.verify_pkcs1_v15(&digest, signature)
                    .map_err(|e| format!("RSA PKCS#1 verification failed: {}", e))
            }
            0x0501 => {
                let rsa = extract_public_key_from_cert(cert_der)
                    .map_err(|e| format!("Failed to extract RSA public key: {}", e))?;
                let hash = sha384::sha384(signed_data);
                let digest = build_digest_info_sha384(&hash);
                if digest.is_empty() {
                    return Err("Failed to build SHA-384 DigestInfo".to_string());
                }
                rsa.verify_pkcs1_v15(&digest, signature)
                    .map_err(|e| format!("RSA PKCS#1 verification failed: {}", e))
            }
            0x0804 => {
                let rsa = extract_public_key_from_cert(cert_der)
                    .map_err(|e| format!("Failed to extract RSA public key: {}", e))?;
                let hash = sha256::sha256(signed_data);
                rsa.verify_pss_sha256(&hash, signature)
                    .map_err(|e| format!("RSA-PSS verification failed: {}", e))
            }
            0x0805 => {
                let rsa = extract_public_key_from_cert(cert_der)
                    .map_err(|e| format!("Failed to extract RSA public key: {}", e))?;
                let hash = sha384::sha384(signed_data);
                rsa.verify_pss_sha384(&hash, signature)
                    .map_err(|e| format!("RSA-PSS verification failed: {}", e))
            }
            // ECDSA and SHA-512 variants are not yet implemented
            0x0403 | 0x0503 | 0x0603 | 0x0601 | 0x0806 => Err(format!(
                "TLS 1.3 signature scheme 0x{:04X} is not supported yet",
                signature_scheme
            )),
            other => Err(format!(
                "Server used unsupported TLS 1.3 signature scheme 0x{:04X}",
                other
            )),
        }
    }

    fn send_tls13_client_auth_responses(&mut self) -> Result<(), String> {
        if let Some(context) = self.tls13_certificate_request_context.take() {
            self.send_tls13_empty_certificate(&context)?;
        }
        Ok(())
    }

    fn send_tls13_empty_certificate(&mut self, request_context: &[u8]) -> Result<(), String> {
        if request_context.len() > u8::MAX as usize {
            return Err("TLS 1.3 certificate_request_context too long".to_string());
        }

        let mut body = Vec::with_capacity(1 + request_context.len() + 3);
        body.push(request_context.len() as u8);
        body.extend_from_slice(request_context);
        body.extend_from_slice(&[0x00, 0x00, 0x00]); // Empty certificate_list

        let handshake = wrap_handshake(HandshakeType::Certificate, &body);
        self.handshake_messages.extend_from_slice(&handshake);
        if let Some(schedule) = self.tls13_key_schedule.as_mut() {
            schedule.add_to_transcript(&handshake);
        }

        self.send_record(ContentType::Handshake, &handshake, true)
    }

    fn send_tls13_finished(&mut self) -> Result<(), String> {
        let verify_data = {
            let schedule = self
                .tls13_key_schedule
                .as_ref()
                .ok_or_else(|| "TLS 1.3 key schedule not initialized".to_string())?;
            schedule.client_finished_verify_data()?
        };

        let handshake = wrap_handshake(HandshakeType::Finished, &verify_data);
        self.handshake_messages.extend_from_slice(&handshake);
        if let Some(schedule) = self.tls13_key_schedule.as_mut() {
            schedule.add_to_transcript(&handshake);
        }

        self.send_record(ContentType::Handshake, &handshake, true)?;

        Ok(())
    }

    fn activate_tls13_application_keys(&mut self) -> Result<(), String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated for TLS 1.3 application data")?;

        if !cipher_suite_is_tls13(cipher) {
            return Err(format!(
                "TLS 1.3 application data negotiated non-TLS1.3 cipher {:?}",
                cipher
            ));
        }

        let schedule = self
            .tls13_key_schedule
            .as_ref()
            .ok_or("TLS 1.3 key schedule not initialized for application data")?;

        let server_secret = schedule
            .server_application_traffic_secret
            .as_ref()
            .ok_or("Server application traffic secret missing")?;
        let client_secret = schedule
            .client_application_traffic_secret
            .as_ref()
            .ok_or("Client application traffic secret missing")?;

        let (_, key_len, iv_len) = cipher_suite_key_sizes(cipher);
        let (server_key, server_iv) = schedule
            .derive_traffic_keys(server_secret, key_len as u16, iv_len as u16)
            .map_err(|e| format!("Failed to derive server application keys: {}", e))?;
        let (client_key, client_iv) = schedule
            .derive_traffic_keys(client_secret, key_len as u16, iv_len as u16)
            .map_err(|e| format!("Failed to derive client application keys: {}", e))?;

        self.server_write_key = Some(server_key);
        self.server_write_iv = Some(server_iv);
        self.client_write_key = Some(client_key);
        self.client_write_iv = Some(client_iv);
        self.server_write_mac = None;
        self.client_write_mac = None;
        self.server_sequence = 0;
        self.client_sequence = 0;

        Ok(())
    }

    /// Receive Certificate
    fn receive_certificate(&mut self) -> Result<Vec<u8>, String> {
        let (content_type, record) = self.receive_tls_record()?;

        if content_type != ContentType::Handshake {
            if content_type == ContentType::Alert && record.len() >= 2 {
                return Err(format!(
                    "Server sent alert during Certificate: level={}, description={}",
                    record[0], record[1]
                ));
            }
            return Err(format!("Expected Handshake record, got {:?}", content_type));
        }

        if record.is_empty() {
            return Err("Empty Certificate".to_string());
        }

        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&record);

        // Parse Certificate message:
        // HandshakeType (1 byte) = 11 (Certificate)
        // Length (3 bytes)
        // Certificates length (3 bytes)
        // Certificate 1 length (3 bytes)
        // Certificate 1 data (DER)
        // ... (more certificates)

        if record.len() < 7 {
            return Err("Certificate message too short".to_string());
        }

        // Skip handshake type and length (4 bytes)
        let mut offset = 4;

        // Parse certificates length (3 bytes)
        let certs_len = ((record[offset] as usize) << 16)
            | ((record[offset + 1] as usize) << 8)
            | (record[offset + 2] as usize);
        offset += 3;

        if offset + certs_len > record.len() {
            return Err("Invalid certificates length".to_string());
        }

        // Parse first certificate (server certificate)
        if offset + 3 > record.len() {
            return Err("No certificate data".to_string());
        }

        let cert_len = ((record[offset] as usize) << 16)
            | ((record[offset + 1] as usize) << 8)
            | (record[offset + 2] as usize);
        offset += 3;

        if offset + cert_len > record.len() {
            return Err("Invalid certificate length".to_string());
        }

        // Extract the certificate DER data
        let cert_der = record[offset..offset + cert_len].to_vec();

        // Store the certificate for later use in ClientKeyExchange
        self.server_certificate = Some(cert_der.clone());
        if self.config.verify_cert {
            let parsed = X509Certificate::from_der(&cert_der)
                .map_err(|e| format!("Failed to parse server certificate: {}", e))?;
            self.server_x509 = Some(parsed);
        }

        Ok(record)
    }

    /// Receive optional ServerKeyExchange and the mandatory ServerHelloDone message
    fn receive_server_key_exchange_and_done(&mut self) -> Result<(), String> {
        let (content_type, record) = self.receive_tls_record()?;
        if content_type != ContentType::Handshake {
            return Err("Expected Handshake record".to_string());
        }
        if record.is_empty() {
            return Err("Empty handshake record from server".to_string());
        }

        let message_type = record[0];
        if message_type == HandshakeType::ServerKeyExchange as u8 {
            // Include ServerKeyExchange in transcript before parsing parameters
            self.handshake_messages.extend_from_slice(&record);
            self.parse_server_key_exchange(&record)?;

            // Next message must be ServerHelloDone
            let (ct, server_done) = self.receive_tls_record()?;
            if ct != ContentType::Handshake || server_done.is_empty() {
                return Err(format!(
                    "Expected ServerHelloDone after ServerKeyExchange, got {:?}",
                    ct
                ));
            }
            if server_done[0] != HandshakeType::ServerHelloDone as u8 {
                return Err(format!(
                    "Expected ServerHelloDone, got handshake type 0x{:02X}",
                    server_done[0]
                ));
            }
            self.handshake_messages.extend_from_slice(&server_done);
        } else if message_type == HandshakeType::ServerHelloDone as u8 {
            self.handshake_messages.extend_from_slice(&record);
        } else {
            return Err(format!(
                "Unexpected handshake message type 0x{:02X} from server",
                message_type
            ));
        }

        Ok(())
    }

    /// Parse ECDHE ServerKeyExchange and cache server public parameters
    fn parse_server_key_exchange(&mut self, record: &[u8]) -> Result<(), String> {
        if record.len() < 4 + 1 + 2 + 1 {
            return Err("ServerKeyExchange too short".to_string());
        }

        let mut offset = 4; // Skip handshake type + length

        let curve_type = record[offset];
        offset += 1;
        if curve_type != 3 {
            return Err(format!(
                "Unsupported curve type {} in ServerKeyExchange",
                curve_type
            ));
        }

        let named_curve = u16::from_be_bytes([record[offset], record[offset + 1]]);
        offset += 2;
        let public_len = record[offset] as usize;
        offset += 1;
        if offset + public_len > record.len() {
            return Err("Truncated ECDHE public key in ServerKeyExchange".to_string());
        }
        let public_bytes = &record[offset..offset + public_len];
        offset += public_len;

        let ecdhe_params = match named_curve {
            23 => {
                let server_point = P256Point::from_uncompressed_bytes(public_bytes)
                    .map_err(|e| format!("Failed to parse server ECDHE public key: {}", e))?;
                self.debug_log("server_ec_public", public_bytes);
                EcdheParameters::P256 {
                    server_public: server_point,
                }
            }
            0x001d => {
                if public_len != 32 {
                    return Err(format!(
                        "Invalid X25519 public key length {} in ServerKeyExchange",
                        public_len
                    ));
                }
                let mut server_public = [0u8; 32];
                server_public.copy_from_slice(public_bytes);
                self.debug_log("server_x25519_public", &server_public);
                EcdheParameters::X25519 { server_public }
            }
            other => {
                return Err(format!(
                    "Unsupported named curve 0x{:04X} in ServerKeyExchange",
                    other
                ))
            }
        };
        self.ecdhe_params = Some(ecdhe_params);

        // Skip signature algorithm (2 bytes) and signature vector (2 + len)
        if offset + 2 > record.len() {
            return Err("Missing signature algorithm in ServerKeyExchange".to_string());
        }
        // hash + signature algorithm bytes
        offset += 2;

        if offset + 2 > record.len() {
            return Err("Missing signature length in ServerKeyExchange".to_string());
        }
        let sig_len = u16::from_be_bytes([record[offset], record[offset + 1]]) as usize;
        offset += 2;
        if offset + sig_len > record.len() {
            return Err("Truncated signature in ServerKeyExchange".to_string());
        }

        // We currently skip signature verification but we still ensure bounds are valid.
        Ok(())
    }

    /// Send ClientKeyExchange
    fn send_client_key_exchange(&mut self) -> Result<(), String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated")?;

        match cipher_suite_key_exchange(cipher) {
            KeyExchange::Rsa => self.send_client_key_exchange_rsa(),
            KeyExchange::Ecdhe => self.send_client_key_exchange_ecdhe(),
        }
    }

    fn send_client_key_exchange_rsa(&mut self) -> Result<(), String> {
        // Generate random pre-master secret (48 bytes)
        // Format: 0x03 0x03 (TLS 1.2) + 46 random bytes
        let mut pre_master_secret = [0u8; 48];
        let (major, minor) = self.config.version.to_bytes();
        pre_master_secret[0] = major;
        pre_master_secret[1] = minor;

        // Fill rest with random data
        let random_bytes = generate_random_bytes(46);
        pre_master_secret[2..].copy_from_slice(&random_bytes);

        // Store pre-master secret for key derivation
        self.pre_master_secret = Some(pre_master_secret.to_vec());

        // Get server's certificate
        let cert_der = self
            .server_certificate
            .as_ref()
            .ok_or("No server certificate received")?;

        // Extract RSA public key from certificate
        let public_key = extract_public_key_from_cert(cert_der)?;

        // Encrypt pre-master secret with server's public key using PKCS#1 v1.5
        let encrypted_pms = public_key.encrypt_pkcs1v15(&pre_master_secret)?;

        // Build ClientKeyExchange message
        // For RSA: just the encrypted pre-master secret (with length prefix for TLS 1.0+)
        let mut key_exchange = Vec::new();

        // Add length prefix (2 bytes) for TLS 1.0+
        key_exchange.push((encrypted_pms.len() >> 8) as u8);
        key_exchange.push(encrypted_pms.len() as u8);
        key_exchange.extend_from_slice(&encrypted_pms);

        let handshake = wrap_handshake(HandshakeType::ClientKeyExchange, &key_exchange);

        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&handshake);

        self.send_record(ContentType::Handshake, &handshake, false)?;

        Ok(())
    }

    fn send_client_key_exchange_ecdhe(&mut self) -> Result<(), String> {
        let params = self
            .ecdhe_params
            .as_ref()
            .ok_or("Server ECDHE parameters not received")?;

        let (public_bytes, shared_secret) = match params {
            EcdheParameters::P256 { server_public } => {
                let (private_key, public_bytes) = generate_p256_keypair();
                let shared_secret = compute_p256_shared_secret(&private_key, server_public);
                self.debug_log("client_p256_private", &private_key);
                (public_bytes, shared_secret.to_vec())
            }
            EcdheParameters::X25519 { server_public } => {
                let mut private = [0u8; 32];
                let random = generate_random_bytes(32);
                private.copy_from_slice(&random[..32]);
                self.debug_log("client_x25519_private", &private);
                let public_key = x25519_public_key(&private);
                let shared = x25519(&private, server_public);
                (public_key.to_vec(), shared.to_vec())
            }
        };

        self.debug_log("client_ec_public", &public_bytes);
        self.debug_log("ecdhe_shared_secret", &shared_secret);

        self.pre_master_secret = Some(shared_secret);

        let handshake = wrap_handshake(HandshakeType::ClientKeyExchange, &{
            let mut body = Vec::with_capacity(1 + public_bytes.len());
            body.push(public_bytes.len() as u8);
            body.extend_from_slice(&public_bytes);
            body
        });

        self.handshake_messages.extend_from_slice(&handshake);
        self.send_record(ContentType::Handshake, &handshake, false)?;

        Ok(())
    }

    /// Send ChangeCipherSpec
    fn send_change_cipher_spec(&mut self) -> Result<(), String> {
        let ccs = vec![0x01];
        self.send_record(ContentType::ChangeCipherSpec, &ccs, false)?;
        self.client_encryption_active = true;
        self.client_sequence = 0;

        Ok(())
    }

    /// Send Finished
    fn send_finished(&mut self) -> Result<(), String> {
        // Get master secret
        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or("No master secret available")?;

        let verify_data = match self.config.version {
            TlsVersion::Tls12 => {
                let cipher = self
                    .negotiated_cipher_suite
                    .ok_or("No cipher suite negotiated")?;
                let prf_alg = cipher_suite_prf_algorithm(cipher);
                let handshake_hash = tls12_handshake_hash(&self.handshake_messages, prf_alg);
                let verify_data_full = prf::prf_tls12_with_hash(
                    master_secret,
                    b"client finished",
                    &handshake_hash,
                    12,
                    prf_alg,
                );
                verify_data_full[..12].to_vec()
            }
            TlsVersion::Tls11 | TlsVersion::Tls10 => {
                let md5_hash = md5(&self.handshake_messages);
                let sha1_hash = sha1::sha1(&self.handshake_messages);
                let mut seed = Vec::with_capacity(md5_hash.len() + sha1_hash.len());
                seed.extend_from_slice(&md5_hash);
                seed.extend_from_slice(&sha1_hash);
                let verify_data_full = prf::prf_tls10(master_secret, b"client finished", &seed, 12);
                verify_data_full[..12].to_vec()
            }
            TlsVersion::Tls13 => unreachable!("TLS 1.3 uses dedicated Finished path"),
        };

        let handshake = wrap_handshake(HandshakeType::Finished, &verify_data);
        self.handshake_messages.extend_from_slice(&handshake);

        self.send_record(ContentType::Handshake, &handshake, true)?;
        Ok(())
    }

    /// Receive ChangeCipherSpec
    fn receive_change_cipher_spec(&mut self) -> Result<(), String> {
        let (content_type, payload) = self.receive_tls_record()?;
        if content_type != ContentType::ChangeCipherSpec {
            if content_type == ContentType::Alert && payload.len() >= 2 {
                return Err(format!(
                    "Server sent alert instead of ChangeCipherSpec: level={}, description={}",
                    payload[0], payload[1]
                ));
            }
            return Err(format!(
                "Expected ChangeCipherSpec record, got {:?}",
                content_type
            ));
        }
        self.server_encryption_active = true;
        self.server_sequence = 0;
        Ok(())
    }

    /// Receive Finished
    fn receive_finished(&mut self) -> Result<(), String> {
        let (content_type, record) = self.receive_tls_record()?;
        if content_type != ContentType::Handshake {
            return Err("Expected encrypted Finished handshake".to_string());
        }

        if record.is_empty() || record[0] != HandshakeType::Finished as u8 {
            return Err("Server did not send Finished".to_string());
        }

        if record.len() < 4 {
            return Err("Finished handshake too short".to_string());
        }

        let verify_len =
            ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
        if record.len() < 4 + verify_len {
            return Err("Finished verify data truncated".to_string());
        }

        let verify_data = &record[4..4 + verify_len];

        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or("No master secret available")?;

        let expected = match self.config.version {
            TlsVersion::Tls12 => {
                let cipher = self
                    .negotiated_cipher_suite
                    .ok_or("No cipher suite negotiated")?;
                let prf_alg = cipher_suite_prf_algorithm(cipher);
                let handshake_hash = tls12_handshake_hash(&self.handshake_messages, prf_alg);
                prf::prf_tls12_with_hash(
                    master_secret,
                    b"server finished",
                    &handshake_hash,
                    verify_len,
                    prf_alg,
                )
            }
            TlsVersion::Tls11 | TlsVersion::Tls10 => {
                let md5_hash = md5(&self.handshake_messages);
                let sha1_hash = sha1::sha1(&self.handshake_messages);
                let mut seed = Vec::with_capacity(md5_hash.len() + sha1_hash.len());
                seed.extend_from_slice(&md5_hash);
                seed.extend_from_slice(&sha1_hash);
                prf::prf_tls10(master_secret, b"server finished", &seed, verify_len)
            }
            TlsVersion::Tls13 => unreachable!("TLS 1.3 uses dedicated Finished handling"),
        };

        if !constant_time_eq(verify_data, &expected) {
            return Err("Server Finished verify_data mismatch".to_string());
        }

        self.handshake_messages.extend_from_slice(&record);
        Ok(())
    }

    /// Derive session keys from pre-master secret
    fn derive_session_keys(&mut self) -> Result<(), String> {
        // Get negotiated cipher suite
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated")?;

        if !cipher_suite_is_supported(cipher) {
            return Err(format!(
                "Cipher suite {:?} not yet implemented for TLS 1.2 handshake",
                cipher
            ));
        }

        // Get server_random
        let server_random = self.server_random.ok_or("Server random not received")?;

        // Get pre-master secret (generated and encrypted in send_client_key_exchange)
        let pre_master = self
            .pre_master_secret
            .as_ref()
            .ok_or("Pre-master secret not generated")?;

        // Derive master secret
        let master_secret = match self.config.version {
            TlsVersion::Tls10 | TlsVersion::Tls11 => {
                prf::derive_master_secret_tls10(pre_master, &self.client_random, &server_random)
            }
            TlsVersion::Tls12 => {
                let prf_alg = cipher_suite_prf_algorithm(cipher);
                prf::derive_master_secret_tls12_with_hash(
                    pre_master,
                    &self.client_random,
                    &server_random,
                    prf_alg,
                )
            }
            TlsVersion::Tls13 => unreachable!("TLS 1.3 should not use legacy key derivation"),
        };
        self.master_secret = Some(master_secret);
        self.debug_log("master_secret", &master_secret);

        // Get key sizes for this cipher suite
        let (mac_size, key_size, iv_size) = cipher_suite_key_sizes(cipher);

        // Calculate total key material needed
        // client_write_MAC_key + server_write_MAC_key + client_write_key + server_write_key + client_write_IV + server_write_IV
        let total_size = 2 * (mac_size + key_size + iv_size);

        // Derive key material
        let key_material = match self.config.version {
            TlsVersion::Tls10 | TlsVersion::Tls11 => prf::derive_keys_tls10(
                &master_secret,
                &server_random,
                &self.client_random,
                total_size,
            ),
            TlsVersion::Tls12 => {
                let prf_alg = cipher_suite_prf_algorithm(cipher);
                prf::derive_keys_tls12_with_hash(
                    &master_secret,
                    &server_random,
                    &self.client_random,
                    total_size,
                    prf_alg,
                )
            }
            TlsVersion::Tls13 => unreachable!("TLS 1.3 should not use legacy key derivation"),
        };
        self.debug_log("key_material", &key_material);

        // Extract keys from key_block
        let mut offset = 0;

        // client_write_MAC_key
        if mac_size > 0 {
            let client_write_mac = key_material[offset..offset + mac_size].to_vec();
            self.client_write_mac = Some(client_write_mac);
            offset += mac_size;
        } else {
            self.client_write_mac = Some(Vec::new()); // GCM doesn't use separate MAC
        }

        // server_write_MAC_key
        if mac_size > 0 {
            let server_write_mac = key_material[offset..offset + mac_size].to_vec();
            self.server_write_mac = Some(server_write_mac);
            offset += mac_size;
        } else {
            self.server_write_mac = Some(Vec::new()); // GCM doesn't use separate MAC
        }

        // client_write_key
        let client_write_key = key_material[offset..offset + key_size].to_vec();
        self.client_write_key = Some(client_write_key);
        offset += key_size;

        // server_write_key
        let server_write_key = key_material[offset..offset + key_size].to_vec();
        self.server_write_key = Some(server_write_key);
        offset += key_size;

        // client_write_IV
        let client_write_iv = key_material[offset..offset + iv_size].to_vec();
        self.client_write_iv = Some(client_write_iv);
        offset += iv_size;

        // server_write_IV
        let server_write_iv = key_material[offset..offset + iv_size].to_vec();
        self.server_write_iv = Some(server_write_iv);

        if let Some(ref key) = self.client_write_key {
            self.debug_log("client_write_key", key);
        }
        if let Some(ref key) = self.server_write_key {
            self.debug_log("server_write_key", key);
        }
        if let Some(ref iv) = self.client_write_iv {
            self.debug_log("client_write_iv", iv);
        }
        if let Some(ref iv) = self.server_write_iv {
            self.debug_log("server_write_iv", iv);
        }

        Ok(())
    }

    /// Receive TLS record
    fn send_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        encrypt: bool,
    ) -> Result<(), String> {
        let record = if encrypt {
            self.encrypt_record(content_type, payload)?
        } else {
            wrap_tls_record(content_type, payload, self.record_version())
        };

        self.stream
            .write_all(&record)
            .map_err(|e| format!("Failed to send record: {}", e))
    }

    fn encrypt_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated")?;

        if !cipher_suite_is_supported(cipher) {
            return Err(format!(
                "Cipher suite {:?} not supported for TLS write path",
                cipher
            ));
        }

        let record_version = self.record_version();

        if cipher_suite_is_tls13(cipher) {
            let key_bytes = self
                .client_write_key
                .as_ref()
                .ok_or("TLS 1.3 client write key not available")?;
            let iv = self
                .client_write_iv
                .as_ref()
                .ok_or("TLS 1.3 client write IV not available")?;
            if iv.len() != 12 {
                return Err("TLS 1.3 expected 12-byte IV for client records".to_string());
            }

            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(iv);
            let seq_bytes = self.client_sequence.to_be_bytes();
            for (i, b) in seq_bytes.iter().enumerate() {
                nonce[12 - 8 + i] ^= b;
            }

            let mut inner = Vec::with_capacity(payload.len() + 1);
            inner.extend_from_slice(payload);
            inner.push(content_type as u8);

            let ciphertext_len = inner.len() + 16;
            if ciphertext_len > u16::MAX as usize {
                return Err("TLS 1.3 record too large for AEAD length field".to_string());
            }

            let outer_type = ContentType::ApplicationData;
            let mut aad = Vec::with_capacity(5);
            aad.push(outer_type as u8);
            aad.push(record_version.0);
            aad.push(record_version.1);
            aad.push((ciphertext_len >> 8) as u8);
            aad.push((ciphertext_len & 0xff) as u8);

            let ciphertext = match key_bytes.len() {
                16 => {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&key_bytes[..16]);
                    aes128_gcm_encrypt(&key, &nonce, &inner, &aad)
                }
                32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes[..32]);
                    aes256_gcm_encrypt(&key, &nonce, &aad, &inner)
                }
                other => {
                    return Err(format!(
                        "Unsupported AES-GCM key size {} for cipher {:?}",
                        other, cipher
                    ))
                }
            };

            let mut record = Vec::with_capacity(5 + ciphertext.len());
            record.push(outer_type as u8);
            record.push(record_version.0);
            record.push(record_version.1);
            record.push((ciphertext.len() >> 8) as u8);
            record.push((ciphertext.len() & 0xff) as u8);
            record.extend_from_slice(&ciphertext);

            self.client_sequence = self.client_sequence.wrapping_add(1);

            return Ok(record);
        } else if cipher_suite_is_gcm(cipher) {
            let key_bytes = self
                .client_write_key
                .as_ref()
                .ok_or("Client write key not available")?;
            let fixed_iv = self
                .client_write_iv
                .as_ref()
                .ok_or("Client write IV not available")?;

            if fixed_iv.len() != 4 {
                return Err("Invalid fixed IV length for GCM cipher".to_string());
            }

            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&fixed_iv[..4]);
            let explicit_nonce = self.client_sequence.to_be_bytes();
            nonce[4..].copy_from_slice(&explicit_nonce);

            let plaintext_len = payload.len();
            if plaintext_len > u16::MAX as usize {
                return Err("TLS record too large for AEAD length field".to_string());
            }

            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.client_sequence.to_be_bytes());
            aad.push(content_type as u8);
            aad.push(record_version.0);
            aad.push(record_version.1);
            aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

            self.debug_log("gcm_client_nonce", &nonce);
            self.debug_log("gcm_client_aad", &aad);
            self.debug_log("gcm_client_plain", payload);

            let ciphertext = match key_bytes.len() {
                16 => {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&key_bytes[..16]);
                    aes128_gcm_encrypt(&key, &nonce, payload, &aad)
                }
                32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes[..32]);
                    aes256_gcm_encrypt(&key, &nonce, &aad, payload)
                }
                other => {
                    return Err(format!(
                        "Unsupported AES-GCM key size {} for cipher {:?}",
                        other, cipher
                    ))
                }
            };

            let mut fragment = Vec::with_capacity(explicit_nonce.len() + ciphertext.len());
            fragment.extend_from_slice(&explicit_nonce);
            fragment.extend_from_slice(&ciphertext);

            let payload_len = fragment.len() as u16;
            let mut record = Vec::with_capacity(5 + fragment.len());
            record.push(content_type as u8);
            record.push(record_version.0);
            record.push(record_version.1);
            record.push((payload_len >> 8) as u8);
            record.push(payload_len as u8);
            record.extend_from_slice(&fragment);

            self.client_sequence = self.client_sequence.wrapping_add(1);

            Ok(record)
        } else if cipher_suite_is_cbc(cipher) {
            let mac_algo = cipher_suite_mac_algorithm(cipher)?;
            let mac_key = self
                .client_write_mac
                .as_ref()
                .ok_or("Client write MAC key not available")?;
            let enc_key = self
                .client_write_key
                .as_ref()
                .ok_or("Client write key not available")?;

            if enc_key.len() != 16 {
                return Err(format!(
                    "Unsupported AES key size {} for cipher {:?}",
                    enc_key.len(),
                    cipher
                ));
            }

            let mut key_array = [0u8; 16];
            key_array.copy_from_slice(enc_key);

            let explicit_iv_mode =
                matches!(self.config.version, TlsVersion::Tls11 | TlsVersion::Tls12);
            let mac = compute_record_mac(
                mac_algo,
                mac_key,
                self.client_sequence,
                content_type,
                record_version,
                payload,
            );

            let mut fragment = Vec::with_capacity(payload.len() + mac.len());
            fragment.extend_from_slice(payload);
            fragment.extend_from_slice(&mac);

            let (ciphertext, explicit_iv) = if explicit_iv_mode {
                let explicit_iv = generate_random_bytes(16);
                let mut iv_array = [0u8; 16];
                iv_array.copy_from_slice(&explicit_iv);
                let ciphertext = aes::aes128_cbc_encrypt(&key_array, &iv_array, &fragment);
                (ciphertext, Some(explicit_iv))
            } else {
                let iv_vec = self
                    .client_write_iv
                    .as_ref()
                    .ok_or("Client write IV not available")?;
                if iv_vec.len() != 16 {
                    return Err("Invalid client IV length for TLS 1.0 CBC".to_string());
                }
                let mut iv_array = [0u8; 16];
                iv_array.copy_from_slice(&iv_vec[..16]);
                let ciphertext = aes::aes128_cbc_encrypt(&key_array, &iv_array, &fragment);
                if ciphertext.len() < 16 {
                    return Err("TLS 1.0 CBC ciphertext too short".to_string());
                }
                let last_block = &ciphertext[ciphertext.len() - 16..];
                self.client_write_iv = Some(last_block.to_vec());
                (ciphertext, None)
            };

            let explicit_len = explicit_iv.as_ref().map_or(0, |v| v.len());
            let payload_len = explicit_len + ciphertext.len();

            let mut record = Vec::with_capacity(5 + payload_len);
            record.push(content_type as u8);
            record.push(record_version.0);
            record.push(record_version.1);
            record.push((payload_len >> 8) as u8);
            record.push(payload_len as u8);
            if let Some(explicit_iv) = explicit_iv {
                record.extend_from_slice(&explicit_iv);
            }
            record.extend_from_slice(&ciphertext);

            self.client_sequence = self.client_sequence.wrapping_add(1);

            Ok(record)
        } else {
            Err(format!(
                "Cipher suite {:?} is not implemented for encryption",
                cipher
            ))
        }
    }

    fn decrypt_record_payload(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated")?;

        if !cipher_suite_is_supported(cipher) {
            return Err(format!(
                "Cipher suite {:?} not supported for TLS read path",
                cipher
            ));
        }

        let record_version = self.record_version();

        if cipher_suite_is_tls13(cipher) {
            return self.decrypt_tls13_record(content_type, payload);
        } else if cipher_suite_is_gcm(cipher) {
            if payload.len() < 8 + 16 {
                return Err("TLS GCM record too short".to_string());
            }

            let fixed_iv = self
                .server_write_iv
                .as_ref()
                .ok_or("Server write IV not available")?;
            if fixed_iv.len() != 4 {
                return Err("Invalid fixed IV length for GCM cipher".to_string());
            }

            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&fixed_iv[..4]);
            let explicit_nonce = &payload[..8];
            nonce[4..].copy_from_slice(explicit_nonce);

            let ciphertext = &payload[8..];
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.server_sequence.to_be_bytes());
            aad.push(content_type as u8);
            aad.push(record_version.0);
            aad.push(record_version.1);
            if ciphertext.len() < 16 {
                return Err("TLS GCM record missing authentication tag".to_string());
            }
            let plaintext_len = ciphertext.len() - 16;
            if plaintext_len > u16::MAX as usize {
                return Err("TLS record too large for AEAD length field".to_string());
            }
            aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

            self.debug_log("gcm_server_nonce", &nonce);
            self.debug_log("gcm_server_aad", &aad);
            self.debug_log("gcm_server_cipher", ciphertext);

            let key_bytes = self
                .server_write_key
                .as_ref()
                .ok_or("Server write key not available")?;

            let plaintext = match key_bytes.len() {
                16 => {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&key_bytes[..16]);
                    aes128_gcm_decrypt(&key, &nonce, ciphertext, &aad)
                        .map_err(|e| format!("AES-128-GCM decrypt failed: {}", e))?
                }
                32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes[..32]);
                    aes256_gcm_decrypt(&key, &nonce, &aad, ciphertext)
                        .map_err(|e| format!("AES-256-GCM decrypt failed: {}", e))?
                }
                other => {
                    return Err(format!(
                        "Unsupported AES-GCM key size {} for cipher {:?}",
                        other, cipher
                    ))
                }
            };

            self.server_sequence = self.server_sequence.wrapping_add(1);
            return Ok(plaintext);
        }

        if !cipher_suite_is_cbc(cipher) {
            return Err(format!(
                "Cipher suite {:?} is not implemented for decryption",
                cipher
            ));
        }

        let mac_algo = cipher_suite_mac_algorithm(cipher)?;
        let mac_key = self
            .server_write_mac
            .as_ref()
            .ok_or("Server write MAC key not available")?;
        let enc_key = self
            .server_write_key
            .as_ref()
            .ok_or("Server write key not available")?;

        if enc_key.len() != 16 {
            return Err(format!(
                "Unsupported AES key size {} for cipher {:?}",
                enc_key.len(),
                cipher
            ));
        }

        let mut key_array = [0u8; 16];
        key_array.copy_from_slice(enc_key);

        let explicit_iv_mode = matches!(self.config.version, TlsVersion::Tls11 | TlsVersion::Tls12);
        let (ciphertext, mut iv_array_opt) = if explicit_iv_mode {
            if payload.len() < 16 {
                return Err("TLS record payload too short for explicit IV".to_string());
            }
            let explicit_iv = &payload[..16];
            let mut iv_array = [0u8; 16];
            iv_array.copy_from_slice(explicit_iv);
            (&payload[16..], Some(iv_array))
        } else {
            let iv_vec = self
                .server_write_iv
                .as_ref()
                .ok_or("Server write IV not available")?;
            if iv_vec.len() != 16 {
                return Err("Invalid server IV length for TLS 1.0 CBC".to_string());
            }
            let mut iv_array = [0u8; 16];
            iv_array.copy_from_slice(&iv_vec[..16]);
            (payload, Some(iv_array))
        };

        let mut iv_array = iv_array_opt.expect("IV should always be set");
        if ciphertext.is_empty() {
            return Err("TLS record missing ciphertext".to_string());
        }

        let plaintext = aes::aes128_cbc_decrypt(&key_array, &iv_array, ciphertext)?;
        let mac_len = mac_algo.mac_len();
        if plaintext.len() < mac_len {
            return Err("TLS plaintext shorter than MAC length".to_string());
        }

        let data_len = plaintext.len() - mac_len;
        let (data, received_mac) = plaintext.split_at(data_len);

        let expected_mac = compute_record_mac(
            mac_algo,
            mac_key,
            self.server_sequence,
            content_type,
            record_version,
            data,
        );

        if !constant_time_eq(&expected_mac, received_mac) {
            return Err("TLS record MAC mismatch".to_string());
        }

        if !explicit_iv_mode {
            if ciphertext.len() < 16 {
                return Err("TLS 1.0 CBC ciphertext too short".to_string());
            }
            let last_block = &ciphertext[ciphertext.len() - 16..];
            self.server_write_iv = Some(last_block.to_vec());
        }

        self.server_sequence = self.server_sequence.wrapping_add(1);

        Ok(data.to_vec())
    }

    fn decrypt_tls13_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        if payload.len() < 16 {
            return Err("TLS 1.3 record too short".to_string());
        }

        let record_version = self.record_version();

        let key = self
            .server_write_key
            .as_ref()
            .ok_or("TLS 1.3 server write key not available")?;
        let iv = self
            .server_write_iv
            .as_ref()
            .ok_or("TLS 1.3 server write IV not available")?;
        if iv.len() != 12 {
            return Err("TLS 1.3 expected 12-byte IV".to_string());
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv);
        let seq_bytes = self.server_sequence.to_be_bytes();
        for (i, b) in seq_bytes.iter().enumerate() {
            nonce[12 - 8 + i] ^= b;
        }

        let aad_len = payload.len();
        if aad_len > u16::MAX as usize {
            return Err("TLS 1.3 ciphertext length exceeds maximum record size".to_string());
        }

        let mut aad = Vec::with_capacity(5);
        aad.push(content_type as u8);
        aad.push(record_version.0);
        aad.push(record_version.1);
        aad.push((aad_len >> 8) as u8);
        aad.push((aad_len & 0xff) as u8);

        let mut output = match key.len() {
            16 => {
                let mut key_array = [0u8; 16];
                key_array.copy_from_slice(&key[..16]);
                aes128_gcm_decrypt(&key_array, &nonce, payload, &aad)?
            }
            32 => {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key[..32]);
                aes256_gcm_decrypt(&key_array, &nonce, &aad, payload)?
            }
            other => return Err(format!("TLS 1.3 unsupported GCM key length {}", other)),
        };

        self.server_sequence = self.server_sequence.wrapping_add(1);

        if output.is_empty() {
            return Err("TLS 1.3 plaintext empty".to_string());
        }
        let inner_type = output
            .pop()
            .ok_or("TLS 1.3 plaintext missing content type".to_string())?;

        if output.last() == Some(&0) && matches!(inner_type, 20 | 21 | 22 | 23) {
            while output.last() == Some(&0) {
                output.pop();
            }
        }

        let result: Vec<u8> = match inner_type {
            21 => {
                if output.len() >= 2 {
                    Err(format!(
                        "Server sent TLS 1.3 alert: level={}, description={}",
                        output[0], output[1]
                    ))
                } else {
                    Err("Server sent TLS 1.3 alert".to_string())
                }
            }
            23 => Ok(output),
            20 => Ok(Vec::new()),
            22 => Ok(output),
            other => Err(format!("Unexpected TLS 1.3 inner content type: {}", other)),
        }?;

        Ok(result)
    }

    fn read_tls_record_internal(&mut self) -> std::io::Result<(ContentType, (u8, u8), Vec<u8>)> {
        let mut header = [0u8; 5];
        self.stream.read_exact(&mut header)?;

        let content_type = ContentType::from_byte(header[0]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown TLS content type {}", header[0]),
            )
        })?;

        let version = (header[1], header[2]);
        let length = ((header[3] as usize) << 8) | (header[4] as usize);

        let mut payload = vec![0u8; length];
        self.stream.read_exact(&mut payload)?;

        Ok((content_type, version, payload))
    }

    fn receive_tls_record(&mut self) -> Result<(ContentType, Vec<u8>), String> {
        let (content_type, _version, payload) = self
            .read_tls_record_internal()
            .map_err(|e| format!("Failed to read TLS record: {}", e))?;

        if self.server_encryption_active
            && matches!(
                content_type,
                ContentType::Handshake | ContentType::ApplicationData
            )
        {
            let plaintext = self.decrypt_record_payload(content_type, &payload)?;
            Ok((content_type, plaintext))
        } else {
            Ok((content_type, payload))
        }
    }

    /// Get inner TCP stream for bidirectional copying
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.handshake_complete {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS handshake not complete",
            ));
        }

        // If we have buffered data, return it first
        if self.buffer_pos < self.read_buffer.len() {
            let remaining = self.read_buffer.len() - self.buffer_pos;
            let to_copy = buf.len().min(remaining);
            buf[..to_copy]
                .copy_from_slice(&self.read_buffer[self.buffer_pos..self.buffer_pos + to_copy]);
            self.buffer_pos += to_copy;

            // Clear buffer if fully consumed
            if self.buffer_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.buffer_pos = 0;
            }

            return Ok(to_copy);
        }

        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            let (content_type, _version, payload) = match self.read_tls_record_internal() {
                Ok(record) => record,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            };

            let data = if self.server_encryption_active
                && matches!(
                    content_type,
                    ContentType::Handshake | ContentType::ApplicationData
                ) {
                self.decrypt_record_payload(content_type, &payload)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            } else {
                payload
            };

            match content_type {
                ContentType::ApplicationData => {
                    if data.is_empty() {
                        continue;
                    }

                    let to_copy = buf.len().min(data.len());
                    buf[..to_copy].copy_from_slice(&data[..to_copy]);

                    if data.len() > to_copy {
                        self.read_buffer = data[to_copy..].to_vec();
                        self.buffer_pos = 0;
                    }

                    return Ok(to_copy);
                }
                ContentType::Handshake => {
                    if !data.is_empty() {
                        self.handshake_messages.extend_from_slice(&data);
                    }
                    continue;
                }
                ContentType::ChangeCipherSpec => {
                    self.server_encryption_active = true;
                    self.server_sequence = 0;
                    continue;
                }
                ContentType::Alert => {
                    if data.len() >= 2 {
                        let level = data[0];
                        let description = data[1];
                        let kind = if level == 2 {
                            std::io::ErrorKind::ConnectionAborted
                        } else {
                            std::io::ErrorKind::Other
                        };
                        return Err(std::io::Error::new(
                            kind,
                            format!(
                                "TLS alert received: level={}, description={}",
                                level, description
                            ),
                        ));
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "TLS alert received",
                    ));
                }
            }
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.handshake_complete {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS handshake not complete",
            ));
        }

        if buf.is_empty() {
            return Ok(0);
        }

        if !self.client_encryption_active {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "TLS cipher not activated",
            ));
        }

        const MAX_FRAGMENT: usize = 16_384; // 2^14 per RFC 5246 section 6.2.1
        let mut offset = 0;
        while offset < buf.len() {
            let end = (offset + MAX_FRAGMENT).min(buf.len());
            let chunk = &buf[offset..end];
            self.send_record(ContentType::ApplicationData, chunk, true)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            offset = end;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// TLS 1.3 CertificateVerify helpers
fn verify_ecdsa_p256_signature(
    point: &P256Point,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let (r, s) = parse_ecdsa_signature(signature)?;
    let order = BigInt::from_bytes_be(&P256_ORDER_BYTES);

    if r.is_zero() || r.cmp(&order) != Ordering::Less {
        return Err("ECDSA signature 'r' out of range".to_string());
    }
    if s.is_zero() || s.cmp(&order) != Ordering::Less {
        return Err("ECDSA signature 's' out of range".to_string());
    }

    let hash_bytes = sha256::sha256(message);
    let hash = BigInt::from_bytes_be(&hash_bytes).mod_reduce(&order);
    let s_inv = s
        .mod_inv(&order)
        .ok_or_else(|| "ECDSA signature is not invertible".to_string())?;

    let u1 = hash.mod_mul(&s_inv, &order);
    let u2 = r.mod_mul(&s_inv, &order);

    let u1_bytes = bigint_to_32_bytes(&u1);
    let u2_bytes = bigint_to_32_bytes(&u2);

    let generator = P256Point::generator();
    let point1 = generator.scalar_mul(&u1_bytes);
    let point2 = point.scalar_mul(&u2_bytes);
    let sum = point1.add(&point2);

    if sum.is_infinity {
        return Err("ECDSA verification produced point at infinity".to_string());
    }

    let x_bytes = sum.x.to_bytes();
    let x = BigInt::from_bytes_be(&x_bytes).mod_reduce(&order);
    let r_mod = r.mod_reduce(&order);

    if x.cmp(&r_mod) == Ordering::Equal {
        Ok(())
    } else {
        Err("ECDSA signature verification failed".to_string())
    }
}

fn parse_ecdsa_signature(signature: &[u8]) -> Result<(BigInt, BigInt), String> {
    let (obj, consumed) = Asn1Object::from_der(signature)?;
    if consumed != signature.len() {
        return Err("Trailing data in ECDSA signature".to_string());
    }
    let seq = obj.as_sequence()?;
    if seq.len() != 2 {
        return Err("ECDSA signature must contain r and s".to_string());
    }
    let r_bytes = seq[0].as_integer()?;
    let s_bytes = seq[1].as_integer()?;
    Ok((
        BigInt::from_bytes_be(r_bytes),
        BigInt::from_bytes_be(s_bytes),
    ))
}

fn bigint_to_32_bytes(value: &BigInt) -> [u8; 32] {
    let mut bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

fn build_tls13_certificate_verify_input(context: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    input.extend(std::iter::repeat(0x20).take(64));
    input.extend_from_slice(context);
    input.push(0x00);
    input.extend_from_slice(transcript_hash);
    input
}

fn build_digest_info_sha256(hash: &[u8]) -> Vec<u8> {
    if hash.len() != 32 {
        return Vec::new();
    }
    const PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let mut digest_info = Vec::with_capacity(PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&PREFIX);
    digest_info.extend_from_slice(hash);
    digest_info
}

fn build_digest_info_sha384(hash: &[u8]) -> Vec<u8> {
    if hash.len() != 48 {
        return Vec::new();
    }
    const PREFIX: [u8; 19] = [
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    let mut digest_info = Vec::with_capacity(PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&PREFIX);
    digest_info.extend_from_slice(hash);
    digest_info
}

/// Wrap data in TLS record
fn wrap_tls_record(content_type: ContentType, data: &[u8], version: (u8, u8)) -> Vec<u8> {
    let mut record = Vec::new();

    // Content type
    record.push(content_type as u8);

    // Version
    record.push(version.0);
    record.push(version.1);

    // Length
    let length = data.len() as u16;
    record.push((length >> 8) as u8);
    record.push(length as u8);

    // Data
    record.extend_from_slice(data);

    record
}

/// Wrap data in handshake message
fn wrap_handshake(msg_type: HandshakeType, data: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::new();

    // Message type
    handshake.push(msg_type as u8);

    // Length (24-bit)
    let length = data.len() as u32;
    handshake.push((length >> 16) as u8);
    handshake.push((length >> 8) as u8);
    handshake.push(length as u8);

    // Data
    handshake.extend_from_slice(data);

    handshake
}

/// Build SNI extension
fn build_sni_extension(host: &str) -> Vec<u8> {
    let mut ext = Vec::new();

    // Extension type (0x0000 = SNI)
    ext.push(0x00);
    ext.push(0x00);

    // Extension length
    let name_len = host.len() as u16;
    let ext_len = name_len + 5;
    ext.push((ext_len >> 8) as u8);
    ext.push(ext_len as u8);

    // Server name list length
    let list_len = name_len + 3;
    ext.push((list_len >> 8) as u8);
    ext.push(list_len as u8);

    // Server name type (0 = host_name)
    ext.push(0x00);

    // Server name length
    ext.push((name_len >> 8) as u8);
    ext.push(name_len as u8);

    // Server name
    ext.extend_from_slice(host.as_bytes());

    ext
}

/// Build signature_algorithms extension advertising RSA support
fn build_signature_algorithms_extension() -> Vec<u8> {
    // SignatureScheme codes defined in RFC 5246 / RFC 8446
    // We list RSA PKCS#1 variants from strongest to weakest.
    const ALGORITHMS: [u16; 10] = [
        0x0804, // rsa_pss_rsae_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0603, // ecdsa_secp521r1_sha512
        0x0601, // rsa_pkcs1_sha512
        0x0501, // rsa_pkcs1_sha384
        0x0401, // rsa_pkcs1_sha256
        0x0201, // rsa_pkcs1_sha1 (legacy fallback)
    ];

    let list_len = (ALGORITHMS.len() * 2) as u16;
    let mut ext = Vec::new();

    // Extension type (0x000d = signature_algorithms)
    ext.push(0x00);
    ext.push(0x0d);

    // Extension length (2 bytes for vector length + algorithms)
    let body_len = list_len + 2;
    ext.push((body_len >> 8) as u8);
    ext.push(body_len as u8);

    // Vector length (in bytes)
    ext.push((list_len >> 8) as u8);
    ext.push(list_len as u8);

    for alg in ALGORITHMS {
        ext.push((alg >> 8) as u8);
        ext.push(alg as u8);
    }

    ext
}

fn build_supported_versions_extension() -> Vec<u8> {
    // Advertise TLS 1.3 first, then fall back to TLS 1.2
    const VERSIONS: &[(u8, u8)] = &[(0x03, 0x04), (0x03, 0x03)];

    let mut ext = Vec::new();
    ext.push(0x00);
    ext.push(0x2b); // supported_versions

    // Body = length (u8) + versions (2 bytes each)
    let body_len = 1 + VERSIONS.len() * 2;
    ext.push((body_len >> 8) as u8);
    ext.push(body_len as u8);

    let mut body = Vec::with_capacity(body_len);
    body.push((VERSIONS.len() * 2) as u8);
    for &(major, minor) in VERSIONS {
        body.push(major);
        body.push(minor);
    }
    ext.extend_from_slice(&body);
    ext
}

fn build_tls13_key_share_extension() -> (Vec<u8>, Tls13ClientKeyShare) {
    let mut private_key = generate_random_32();
    clamp_x25519_scalar(&mut private_key);
    let public_key = x25519_public_key(&private_key);

    let mut share = Vec::new();
    share.extend_from_slice(&Tls13NamedGroup::X25519.as_u16().to_be_bytes());
    share.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    share.extend_from_slice(&public_key);

    let mut body = Vec::new();
    body.extend_from_slice(&(share.len() as u16).to_be_bytes());
    body.extend_from_slice(&share);

    let mut ext = Vec::new();
    ext.push(0x00);
    ext.push(0x33); // key_share
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(&body);

    (
        ext,
        Tls13ClientKeyShare {
            group: Tls13NamedGroup::X25519,
            private_key,
            public_key: public_key.to_vec(),
        },
    )
}

fn build_supported_groups_extension() -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x0a]); // Extension type: supported_groups

    // Body length = vector length field (2 bytes) + data (2 bytes per group)
    ext.extend_from_slice(&[0x00, 0x08]);

    // Vector length in bytes
    ext.extend_from_slice(&[0x00, 0x06]);

    // Named Groups: X25519, secp256r1, secp384r1
    ext.extend_from_slice(&[0x00, 0x1d]); // X25519
    ext.extend_from_slice(&[0x00, 0x17]);
    ext.extend_from_slice(&[0x00, 0x18]);

    ext
}

fn build_ec_point_formats_extension() -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x0b]); // Extension type: ec_point_formats

    // Body length = formats length field (1 byte) + data (1 byte)
    ext.extend_from_slice(&[0x00, 0x02]);

    // Number of point formats
    ext.push(0x01);

    // Format: uncompressed (0)
    ext.push(0x00);

    ext
}

/// Get cipher suite ID
fn cipher_suite_id(cipher: CipherSuite) -> u16 {
    match cipher {
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => 0x002F,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xC02F,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xC030,
        CipherSuite::TLS_AES_128_GCM_SHA256 => 0x1301,
        CipherSuite::TLS_AES_256_GCM_SHA384 => 0x1302,
    }
}

/// Parse cipher suite from ID
fn cipher_suite_from_id(id: u16) -> Result<CipherSuite, String> {
    match id {
        0x002F => Ok(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA),
        0x0035 => Ok(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA),
        0xC02F => Ok(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        0xC030 => Ok(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        0x1301 => Ok(CipherSuite::TLS_AES_128_GCM_SHA256),
        0x1302 => Ok(CipherSuite::TLS_AES_256_GCM_SHA384),
        _ => Err(format!("Unsupported cipher suite: 0x{:04X}", id)),
    }
}

fn cipher_suite_mac_algorithm(cipher: CipherSuite) -> Result<MacAlgorithm, String> {
    match cipher {
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => Ok(MacAlgorithm::Sha1),
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => Ok(MacAlgorithm::Sha1),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Ok(MacAlgorithm::Sha256),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Ok(MacAlgorithm::Sha256),
        CipherSuite::TLS_AES_128_GCM_SHA256 => Ok(MacAlgorithm::Sha256),
        CipherSuite::TLS_AES_256_GCM_SHA384 => Ok(MacAlgorithm::Sha256),
    }
}

fn cipher_suite_is_supported(cipher: CipherSuite) -> bool {
    matches!(
        cipher,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | CipherSuite::TLS_AES_128_GCM_SHA256
            | CipherSuite::TLS_AES_256_GCM_SHA384
    )
}

fn cipher_suite_is_gcm(cipher: CipherSuite) -> bool {
    matches!(
        cipher,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | CipherSuite::TLS_AES_128_GCM_SHA256
            | CipherSuite::TLS_AES_256_GCM_SHA384
    )
}

fn cipher_suite_is_cbc(cipher: CipherSuite) -> bool {
    matches!(
        cipher,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA | CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA
    )
}

fn cipher_suite_key_exchange(cipher: CipherSuite) -> KeyExchange {
    match cipher {
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA | CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => {
            KeyExchange::Rsa
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_AES_128_GCM_SHA256
        | CipherSuite::TLS_AES_256_GCM_SHA384 => KeyExchange::Ecdhe,
    }
}

fn cipher_suite_is_tls13(cipher: CipherSuite) -> bool {
    matches!(
        cipher,
        CipherSuite::TLS_AES_128_GCM_SHA256 | CipherSuite::TLS_AES_256_GCM_SHA384
    )
}

fn compute_record_mac(
    algo: MacAlgorithm,
    key: &[u8],
    sequence: u64,
    content_type: ContentType,
    version: (u8, u8),
    data: &[u8],
) -> Vec<u8> {
    let mut mac_input = Vec::with_capacity(13 + data.len());
    mac_input.extend_from_slice(&sequence.to_be_bytes());
    mac_input.push(content_type as u8);
    mac_input.push(version.0);
    mac_input.push(version.1);
    mac_input.extend_from_slice(&(data.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(data);

    match algo {
        MacAlgorithm::Sha1 => hmac_sha1(key, &mac_input).to_vec(),
        MacAlgorithm::Sha256 => hmac_sha256(key, &mac_input).to_vec(),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn generate_p256_keypair() -> ([u8; 32], Vec<u8>) {
    loop {
        let mut private = [0u8; 32];
        let random = generate_random_bytes(32);
        private.copy_from_slice(&random[..32]);

        if scalar_is_zero(&private) || !scalar_is_less_than_order(&private) {
            continue;
        }

        let public_point = P256Point::generator().scalar_mul(&private);
        if public_point.is_infinity {
            continue;
        }

        return (private, public_point.to_uncompressed_bytes());
    }
}

fn compute_p256_shared_secret(private: &[u8; 32], peer: &P256Point) -> [u8; 32] {
    peer.scalar_mul(private).x.to_bytes()
}

fn scalar_is_zero(scalar: &[u8; 32]) -> bool {
    scalar.iter().all(|&b| b == 0)
}

fn scalar_is_less_than_order(scalar: &[u8; 32]) -> bool {
    for (a, b) in scalar.iter().zip(P256_ORDER_BYTES.iter()) {
        if a < b {
            return true;
        } else if a > b {
            return false;
        }
    }
    false
}

/// Get key material sizes for a cipher suite
/// Returns: (mac_key_size, enc_key_size, iv_size)
fn cipher_suite_key_sizes(cipher: CipherSuite) -> (usize, usize, usize) {
    match cipher {
        // TLS_RSA_WITH_AES_128_CBC_SHA: HMAC-SHA1 (20 bytes) + AES-128 (16 bytes) + IV (16 bytes)
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => (20, 16, 16),
        // TLS_RSA_WITH_AES_256_CBC_SHA: HMAC-SHA1 (20 bytes) + AES-256 (32 bytes) + IV (16 bytes)
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => (20, 32, 16),
        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: No MAC (GCM mode) + AES-128 (16 bytes) + fixed IV (4 bytes)
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => (0, 16, 4),
        // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: No MAC (GCM mode) + AES-256 (32 bytes) + fixed IV (4 bytes)
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => (0, 32, 4),
        // TLS 1.3 AES-GCM suites use 16-byte key or 32-byte key with 12-byte IV
        CipherSuite::TLS_AES_128_GCM_SHA256 => (0, 16, 12),
        CipherSuite::TLS_AES_256_GCM_SHA384 => (0, 32, 12),
    }
}

fn cipher_suite_prf_algorithm(cipher: CipherSuite) -> Tls12PrfAlgorithm {
    match cipher {
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Tls12PrfAlgorithm::Sha384,
        CipherSuite::TLS_AES_256_GCM_SHA384 => Tls12PrfAlgorithm::Sha384,
        _ => Tls12PrfAlgorithm::Sha256,
    }
}

fn tls12_handshake_hash(messages: &[u8], hash: Tls12PrfAlgorithm) -> Vec<u8> {
    match hash {
        Tls12PrfAlgorithm::Sha256 => sha256::sha256(messages).to_vec(),
        Tls12PrfAlgorithm::Sha384 => sha384::sha384(messages).to_vec(),
    }
}

/// Generate random byte (simple PRNG for now)
fn rand_byte() -> u8 {
    use std::time::SystemTime;

    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    ((nanos >> 8) ^ nanos) as u8
}

fn clamp_x25519_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Generate 32 random bytes
fn generate_random_32() -> [u8; 32] {
    let mut random = [0u8; 32];
    for byte in &mut random {
        *byte = rand_byte();
    }
    random
}

/// Generate n random bytes
fn generate_random_bytes(n: usize) -> Vec<u8> {
    let mut random = vec![0u8; n];
    for byte in &mut random {
        *byte = rand_byte();
    }
    random
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config() {
        let config = TlsConfig::new()
            .with_version(TlsVersion::Tls13)
            .with_verify(true)
            .with_timeout(Duration::from_secs(5));

        assert_eq!(config.version, TlsVersion::Tls13);
        assert!(config.verify_cert);
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_wrap_tls_record() {
        let data = vec![1, 2, 3, 4];
        let record = wrap_tls_record(ContentType::Handshake, &data, (0x03, 0x01));

        assert_eq!(record[0], ContentType::Handshake as u8);
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x01);
        assert_eq!(record[3], 0x00); // Length high byte
        assert_eq!(record[4], 0x04); // Length low byte
        assert_eq!(&record[5..], &data[..]);
    }

    #[test]
    fn test_wrap_handshake() {
        let data = vec![1, 2, 3];
        let handshake = wrap_handshake(HandshakeType::ClientHello, &data);

        assert_eq!(handshake[0], HandshakeType::ClientHello as u8);
        assert_eq!(handshake[1], 0x00); // Length byte 1
        assert_eq!(handshake[2], 0x00); // Length byte 2
        assert_eq!(handshake[3], 0x03); // Length byte 3
        assert_eq!(&handshake[4..], &data[..]);
    }

    #[test]
    fn test_cipher_suite_id() {
        assert_eq!(
            cipher_suite_id(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA),
            0x002F
        );
        assert_eq!(
            cipher_suite_id(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            0xC02F
        );
    }

    #[test]
    fn test_build_sni_extension() {
        let ext = build_sni_extension("example.com");

        assert_eq!(ext[0], 0x00); // Extension type (SNI)
        assert_eq!(ext[1], 0x00);
        // Check that hostname is present
        assert!(ext
            .windows("example.com".len())
            .any(|w| w == b"example.com"));
    }

    #[test]
    fn test_signature_algorithms_extension_includes_rsa_sha256() {
        let ext = build_signature_algorithms_extension();

        // Expect signature_algorithms type (0x000d)
        assert_eq!(&ext[..2], &[0x00, 0x0d]);

        // Vector length
        let list_len = ((ext[4] as usize) << 8) | (ext[5] as usize);
        assert!(list_len >= 8);

        // Ensure rsa_pkcs1_sha256 (0x0401) is advertised
        let mut found = false;
        let mut offset = 6;
        while offset + 1 < ext.len() && offset < 6 + list_len {
            if ext[offset] == 0x04 && ext[offset + 1] == 0x01 {
                found = true;
                break;
            }
            offset += 2;
        }

        assert!(found, "rsa_pkcs1_sha256 missing from signature_algorithms");
    }

    #[test]
    fn test_tls12_sha1_mac_length() {
        let mac = compute_record_mac(
            MacAlgorithm::Sha1,
            &[0u8; 20],
            0,
            ContentType::ApplicationData,
            (0x03, 0x03),
            b"hello",
        );
        assert_eq!(mac.len(), 20);
    }

    #[test]
    #[ignore] // Run with: cargo test --release test_tls12_google_connection -- --ignored --nocapture
    fn test_tls12_google_connection() {
        use std::io::{Read, Write};

        println!("\n🔐 Testing TLS 1.2 connection to google.com...");

        // Connect and handshake
        println!("⏳ Establishing connection...");
        let config = TlsConfig::new()
            .with_version(TlsVersion::Tls12)
            .with_verify(false);

        let mut stream = TlsStream::connect("google.com", 443, config)
            .expect("Failed to establish TLS 1.2 connection");

        println!("✅ TLS 1.2 handshake complete!");

        // Send HTTP request
        println!("📤 Sending HTTP GET request...");
        let request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .expect("Failed to send request");

        // Read response
        println!("📥 Reading response...");
        let mut response = Vec::new();
        let mut buffer = [0u8; 4096];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buffer[..n]);
                    if response.len() > 1024 {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionAborted => break,
                Err(e) => panic!("Read failed: {}", e),
            }
        }

        // Verify response
        let response_str = String::from_utf8_lossy(&response);
        println!("📄 Response: {} bytes", response.len());

        assert!(
            response_str.contains("HTTP/1.1") || response_str.contains("HTTP/1.0"),
            "Invalid HTTP response"
        );

        println!("✅ TLS 1.2 test PASSED!");
    }
}
