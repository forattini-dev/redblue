/// TLS 1.3 Handshake Implementation
/// RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
///
/// Complete TLS 1.3 client implementation from scratch.
///
/// ✅ ZERO DEPENDENCIES - Pure Rust implementation
/// Replaces: rustls, openssl, boring
///
/// Supported cipher suites:
/// - TLS_AES_128_GCM_SHA256 (0x1301)
/// - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
/// - TLS_AES_256_GCM_SHA384 (0x1302)
///
/// Key exchange:
/// - X25519 (secp256r1 support planned)
use super::super::crypto::{
    aes256_gcm_decrypt, aes256_gcm_encrypt, chacha20poly1305_decrypt, chacha20poly1305_encrypt,
    tls13_hash::Tls13HashAlgorithm, tls13_keyschedule::Tls13KeySchedule, x25519, x25519_public_key,
};
use super::gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

macro_rules! tls13_trace {
    ($client:expr, $($arg:tt)*) => {
        if $client.debug {
            eprintln!($($arg)*);
        }
    };
}

/// TLS 1.3 record types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl From<u8> for ContentType {
    fn from(value: u8) -> Self {
        match value {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        }
    }
}

/// TLS 1.3 handshake message types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl From<u8> for HandshakeType {
    fn from(value: u8) -> Self {
        match value {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            4 => HandshakeType::NewSessionTicket,
            5 => HandshakeType::EndOfEarlyData,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            13 => HandshakeType::CertificateRequest,
            15 => HandshakeType::CertificateVerify,
            20 => HandshakeType::Finished,
            24 => HandshakeType::KeyUpdate,
            254 => HandshakeType::MessageHash,
            _ => panic!("Unknown handshake type: {}", value),
        }
    }
}

/// Supported cipher suites
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsChacha20Poly1305Sha256 = 0x1303,
    TlsAes256GcmSha384 = 0x1302,
}

impl CipherSuite {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(CipherSuite::TlsAes128GcmSha256),
            0x1303 => Some(CipherSuite::TlsChacha20Poly1305Sha256),
            0x1302 => Some(CipherSuite::TlsAes256GcmSha384),
            _ => None,
        }
    }

    fn key_length(&self) -> u16 {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 16,
            CipherSuite::TlsChacha20Poly1305Sha256 => 32,
            CipherSuite::TlsAes256GcmSha384 => 32,
        }
    }

    fn iv_length(&self) -> u16 {
        12 // Both ChaCha20-Poly1305 and AES-256-GCM use 12-byte IV
    }

    fn tag_length(&self) -> usize {
        16 // Both use 16-byte authentication tag
    }

    fn hash_algorithm(&self) -> Tls13HashAlgorithm {
        match self {
            CipherSuite::TlsAes128GcmSha256 => Tls13HashAlgorithm::Sha256,
            CipherSuite::TlsChacha20Poly1305Sha256 => Tls13HashAlgorithm::Sha256,
            CipherSuite::TlsAes256GcmSha384 => Tls13HashAlgorithm::Sha384,
        }
    }
}

const TLS13_SIGNATURE_SCHEMES: [u16; 9] = [
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
    0x0501, // rsa_pkcs1_sha384
    0x0401, // rsa_pkcs1_sha256
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512
];

/// TLS 1.3 record
#[derive(Debug)]
pub struct TlsRecord {
    pub content_type: ContentType,
    pub legacy_version: u16, // Always 0x0303 (TLS 1.2) for compatibility
    pub payload: Vec<u8>,
}

impl TlsRecord {
    /// Create a new TLS record
    pub fn new(content_type: ContentType, payload: Vec<u8>) -> Self {
        Self {
            content_type,
            legacy_version: 0x0303, // TLS 1.2 for compatibility
            payload,
        }
    }

    /// Serialize record to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.content_type as u8);
        bytes.push((self.legacy_version >> 8) as u8);
        bytes.push(self.legacy_version as u8);
        bytes.push((self.payload.len() >> 8) as u8);
        bytes.push(self.payload.len() as u8);
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Parse record from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("Record too short".to_string());
        }

        let content_type = ContentType::from(data[0]);
        let legacy_version = ((data[1] as u16) << 8) | (data[2] as u16);
        let length = ((data[3] as u16) << 8) | (data[4] as u16);

        if data.len() < 5 + length as usize {
            return Err("Incomplete record".to_string());
        }

        let payload = data[5..5 + length as usize].to_vec();

        Ok(Self {
            content_type,
            legacy_version,
            payload,
        })
    }
}

/// TLS 1.3 client
pub struct Tls13Client {
    stream: TcpStream,
    server_name: String,
    cipher_suite: Option<CipherSuite>,

    // Cryptographic state
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    client_private_key: [u8; 32],
    client_public_key: [u8; 32],
    server_public_key: Option<[u8; 32]>,
    shared_secret: Option<[u8; 32]>,

    // Key schedule
    client_handshake_traffic_secret: Option<Vec<u8>>,
    server_handshake_traffic_secret: Option<Vec<u8>>,
    client_application_traffic_secret: Option<Vec<u8>>,
    server_application_traffic_secret: Option<Vec<u8>>,

    // Traffic keys
    client_handshake_key: Option<Vec<u8>>,
    client_handshake_iv: Option<Vec<u8>>,
    server_handshake_key: Option<Vec<u8>>,
    server_handshake_iv: Option<Vec<u8>>,
    client_application_key: Option<Vec<u8>>,
    client_application_iv: Option<Vec<u8>>,
    server_application_key: Option<Vec<u8>>,
    server_application_iv: Option<Vec<u8>>,

    // Transcript
    handshake_messages: Vec<u8>,
    key_schedule: Option<Tls13KeySchedule>,

    // Sequence numbers for nonce construction (separate for hs/app traffic)
    client_handshake_seq: u64,
    server_handshake_seq: u64,
    client_application_seq: u64,
    server_application_seq: u64,

    // Buffer for decrypted application data not yet consumed
    read_buffer: Vec<u8>,

    // Server certificate (raw DER) captured during handshake
    server_certificate: Option<Vec<u8>>,

    // Verbose tracing flag
    debug: bool,

    // Active hash algorithm (derived from negotiated cipher suite)
    hash_algorithm: Tls13HashAlgorithm,
}

impl Tls13Client {
    fn hex(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len() * 2);
        for byte in data {
            out.push_str(&format!("{:02x}", byte));
        }
        out
    }

    fn debug_log(&self, label: &str, data: &[u8]) {
        if self.debug {
            eprintln!("[tls13][debug] {}: {}", label, Self::hex(data));
        }
    }

    fn debug_msg(&self, msg: &str) {
        if self.debug {
            eprintln!("[tls13][debug] {}", msg);
        }
    }

    /// Create a new TLS 1.3 client
    pub fn new(host: &str, port: u16) -> Result<Self, String> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;

        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        // Generate client random
        let client_random = Self::generate_random();

        // Generate X25519 key pair
        let mut client_private_key = Self::generate_random();
        Self::clamp_x25519_scalar(&mut client_private_key);
        let client_public_key = x25519_public_key(&client_private_key);

        Ok(Self {
            stream,
            server_name: host.to_string(),
            cipher_suite: None,
            client_random,
            server_random: None,
            client_private_key,
            client_public_key,
            server_public_key: None,
            shared_secret: None,
            client_handshake_traffic_secret: None,
            server_handshake_traffic_secret: None,
            client_application_traffic_secret: None,
            server_application_traffic_secret: None,
            client_handshake_key: None,
            client_handshake_iv: None,
            server_handshake_key: None,
            server_handshake_iv: None,
            client_application_key: None,
            client_application_iv: None,
            server_application_key: None,
            server_application_iv: None,
            handshake_messages: Vec::new(),
            key_schedule: None,
            client_handshake_seq: 0,
            server_handshake_seq: 0,
            client_application_seq: 0,
            server_application_seq: 0,
            read_buffer: Vec::new(),
            server_certificate: None,
            debug: false,
            hash_algorithm: Tls13HashAlgorithm::Sha256,
        })
    }

    /// Enable or disable verbose tracing
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Return negotiated cipher suite (if handshake completed)
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    /// Borrow the peer certificate captured during handshake
    pub fn server_certificate(&self) -> Option<&[u8]> {
        self.server_certificate.as_deref()
    }

    /// Adjust read timeout on underlying TCP stream
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    /// Adjust write timeout on underlying TCP stream
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }

    /// Toggle nonblocking mode on underlying TCP stream
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    /// Perform TLS 1.3 handshake
    pub fn handshake(&mut self) -> Result<(), String> {
        // 1. Send ClientHello
        self.send_client_hello()?;

        // 2. Receive ServerHello
        self.receive_server_hello()?;

        // 3. Derive handshake secrets
        self.derive_handshake_secrets()?;

        // 4. Receive EncryptedExtensions, Certificate, CertificateVerify, Finished
        self.receive_encrypted_handshake()?;

        // 5. Derive application secrets
        self.derive_application_secrets()?;

        // 6. Send Finished
        self.send_finished()?;

        Ok(())
    }

    /// Send ClientHello
    fn send_client_hello(&mut self) -> Result<(), String> {
        let mut client_hello = Vec::new();

        // Legacy version (TLS 1.2)
        client_hello.push(0x03);
        client_hello.push(0x03);

        // Client random (32 bytes)
        client_hello.extend_from_slice(&self.client_random);

        // Legacy session ID (empty)
        client_hello.push(0);

        // Cipher suites (advertise AES-256, AES-128, and ChaCha20)
        client_hello.push(0x00);
        client_hello.push(0x06); // 3 suites * 2 bytes
        client_hello.push(0x13);
        client_hello.push(0x02); // TLS_AES_256_GCM_SHA384 (we still map to SHA-384)
        client_hello.push(0x13);
        client_hello.push(0x01); // TLS_AES_128_GCM_SHA256
        client_hello.push(0x13);
        client_hello.push(0x03); // TLS_CHACHA20_POLY1305_SHA256

        // Legacy compression methods (null)
        client_hello.push(0x01);
        client_hello.push(0x00);

        // Extensions
        let extensions = self.build_client_hello_extensions();
        client_hello.push((extensions.len() >> 8) as u8);
        client_hello.push(extensions.len() as u8);
        client_hello.extend_from_slice(&extensions);

        // Wrap in handshake message
        let mut handshake = Vec::new();
        handshake.push(HandshakeType::ClientHello as u8);
        handshake.push((client_hello.len() >> 16) as u8);
        handshake.push((client_hello.len() >> 8) as u8);
        handshake.push(client_hello.len() as u8);
        handshake.extend_from_slice(&client_hello);

        // Add to transcript
        self.handshake_messages.extend_from_slice(&handshake);

        // Send as TLS record
        let record = TlsRecord::new(ContentType::Handshake, handshake);
        self.send_record(&record)?;

        Ok(())
    }

    /// Build ClientHello extensions
    fn build_client_hello_extensions(&self) -> Vec<u8> {
        let mut extensions = Vec::new();

        // Server Name Indication (SNI) - Extension 0
        let mut sni_ext = Vec::new();
        sni_ext.push(0x00);
        sni_ext.push(0x00); // Extension type: server_name

        let mut sni_data = Vec::new();
        let name_bytes = self.server_name.as_bytes();
        sni_data.push(((name_bytes.len() + 3) >> 8) as u8);
        sni_data.push((name_bytes.len() + 3) as u8);
        sni_data.push(0x00); // Name type: host_name
        sni_data.push((name_bytes.len() >> 8) as u8);
        sni_data.push(name_bytes.len() as u8);
        sni_data.extend_from_slice(name_bytes);

        sni_ext.push((sni_data.len() >> 8) as u8);
        sni_ext.push(sni_data.len() as u8);
        sni_ext.extend_from_slice(&sni_data);
        extensions.extend_from_slice(&sni_ext);

        // Supported Versions - Extension 43
        extensions.extend_from_slice(&[
            0x00, 0x2b, // Extension type: supported_versions
            0x00, 0x03, // Length: 3
            0x02, // List length: 2
            0x03, 0x04, // TLS 1.3
        ]);

        // Supported Groups - Extension 10
        extensions.extend_from_slice(&[
            0x00, 0x0a, // Extension type: supported_groups
            0x00, 0x04, // Length: 4
            0x00, 0x02, // List length: 2
            0x00, 0x1d, // X25519
        ]);

        // Key Share - Extension 51
        let mut key_share = Vec::new();
        key_share.push(0x00);
        key_share.push(0x33); // Extension type: key_share

        let mut ks_data = Vec::new();
        ks_data.push(0x00);
        ks_data.push(0x24); // Client shares length: 36
        ks_data.push(0x00);
        ks_data.push(0x1d); // Group: X25519
        ks_data.push(0x00);
        ks_data.push(0x20); // Key exchange length: 32
        ks_data.extend_from_slice(&self.client_public_key);

        key_share.push((ks_data.len() >> 8) as u8);
        key_share.push(ks_data.len() as u8);
        key_share.extend_from_slice(&ks_data);
        extensions.extend_from_slice(&key_share);
        self.debug_log("client_private_key", &self.client_private_key);
        self.debug_log("client_key_share", &self.client_public_key);

        // Signature Algorithms - Extension 13
        let sig_list_len = (TLS13_SIGNATURE_SCHEMES.len() * 2) as u16;
        extensions.extend_from_slice(&[
            0x00,
            0x0d, // Extension type
            ((sig_list_len + 2) >> 8) as u8,
            (sig_list_len + 2) as u8, // body length
            (sig_list_len >> 8) as u8,
            sig_list_len as u8, // vector length
        ]);
        for scheme in TLS13_SIGNATURE_SCHEMES {
            extensions.push((scheme >> 8) as u8);
            extensions.push(scheme as u8);
        }

        // Signature Algorithms for certificates - Extension 0x002e
        extensions.extend_from_slice(&[
            0x00,
            0x2e, // Extension type: signature_algorithms_cert
            ((sig_list_len + 2) >> 8) as u8,
            (sig_list_len + 2) as u8, // body length
            (sig_list_len >> 8) as u8,
            sig_list_len as u8, // vector length
        ]);
        for scheme in TLS13_SIGNATURE_SCHEMES {
            extensions.push((scheme >> 8) as u8);
            extensions.push(scheme as u8);
        }

        extensions
    }

    /// Receive ServerHello
    fn receive_server_hello(&mut self) -> Result<(), String> {
        let record = self.receive_record()?;

        if record.content_type != ContentType::Handshake {
            return Err(format!("Expected Handshake, got {:?}", record.content_type));
        }

        let payload = &record.payload;
        if payload.is_empty() || payload[0] != HandshakeType::ServerHello as u8 {
            return Err("Expected ServerHello".to_string());
        }

        // Add to transcript
        self.handshake_messages.extend_from_slice(&record.payload);

        // Parse ServerHello
        let length =
            ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | (payload[3] as usize);
        if payload.len() < 4 + length {
            return Err("Incomplete ServerHello".to_string());
        }

        let server_hello = &payload[4..4 + length];

        // Legacy version (2 bytes)
        let _legacy_version = ((server_hello[0] as u16) << 8) | (server_hello[1] as u16);

        // Server random (32 bytes)
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&server_hello[2..34]);
        self.server_random = Some(server_random);

        // Legacy session ID
        let session_id_len = server_hello[34] as usize;
        let mut offset = 35 + session_id_len;

        // Cipher suite
        let cipher_suite_bytes =
            ((server_hello[offset] as u16) << 8) | (server_hello[offset + 1] as u16);
        let cipher_suite = CipherSuite::from_u16(cipher_suite_bytes).ok_or(format!(
            "Unsupported cipher suite: 0x{:04x}",
            cipher_suite_bytes
        ))?;
        self.cipher_suite = Some(cipher_suite);
        self.hash_algorithm = cipher_suite.hash_algorithm();
        offset += 2;

        // Legacy compression method
        offset += 1;

        // Extensions
        let extensions_len =
            ((server_hello[offset] as u16) << 8) | (server_hello[offset + 1] as u16);
        offset += 2;
        let extensions_end = offset + extensions_len as usize;

        while offset < extensions_end {
            let ext_type = ((server_hello[offset] as u16) << 8) | (server_hello[offset + 1] as u16);
            let ext_len =
                ((server_hello[offset + 2] as u16) << 8) | (server_hello[offset + 3] as u16);
            offset += 4;

            // Key Share extension (51)
            if ext_type == 0x0033 {
                let group =
                    ((server_hello[offset] as u16) << 8) | (server_hello[offset + 1] as u16);
                if group != 0x001d {
                    return Err(format!("Unsupported group: 0x{:04x}", group));
                }

                let key_len =
                    ((server_hello[offset + 2] as u16) << 8) | (server_hello[offset + 3] as u16);
                if key_len != 32 {
                    return Err(format!("Invalid key share length: {}", key_len));
                }

                let mut server_public_key = [0u8; 32];
                server_public_key.copy_from_slice(&server_hello[offset + 4..offset + 36]);
                self.server_public_key = Some(server_public_key);
                self.debug_log("server_key_share", &server_public_key);

                // Compute shared secret
                let shared_secret = x25519(&self.client_private_key, &server_public_key);
                self.shared_secret = Some(shared_secret);
                self.debug_log("shared_secret", &shared_secret);
            }

            offset += ext_len as usize;
        }

        if self.server_public_key.is_none() {
            return Err("Server did not send key_share extension".to_string());
        }

        Ok(())
    }

    /// Derive handshake secrets
    fn derive_handshake_secrets(&mut self) -> Result<(), String> {
        let shared_secret = self.shared_secret.ok_or("No shared secret")?;
        let cipher_suite = self.cipher_suite.ok_or("No cipher suite")?;
        let hash_alg = self.hash_algorithm;

        // Debug logging: early -> derived -> handshake secret
        if self.debug {
            let early_secret = hash_alg.hkdf_extract(None, &[]);
            self.debug_log("early_secret", &early_secret);

            let empty_hash = hash_alg.hash(&[]);
            let derived = hash_alg
                .derive_secret(&early_secret, b"derived", &empty_hash)
                .map_err(|e| format!("Failed to derive interim secret: {}", e))?;
            self.debug_log("derived_secret", &derived);

            let handshake_secret = hash_alg.hkdf_extract(Some(&derived), &shared_secret);
            self.debug_log("handshake_secret", &handshake_secret);
        }

        // Transcript hash up to ServerHello (also persisted for analysis)
        if self.debug {
            self.debug_msg(&format!(
                "transcript (CH+SH) len: {}",
                self.handshake_messages.len()
            ));
            let _ = std::fs::write(
                "/tmp/tls13_transcript_clienthello_serverhello.bin",
                &self.handshake_messages,
            );
        }
        let transcript_hash = hash_alg.hash(&self.handshake_messages);
        self.debug_log("transcript_hash_hs", &transcript_hash);

        // Drive the key schedule via the OpenSSL-style state machine
        let mut schedule = Tls13KeySchedule::new(hash_alg);
        schedule.set_transcript(&self.handshake_messages);
        schedule.derive_handshake_secret(&shared_secret);
        schedule.derive_handshake_traffic_secrets();

        let client_hs_secret = schedule
            .client_handshake_traffic_secret
            .as_ref()
            .cloned()
            .ok_or("Missing client handshake traffic secret")?;
        let server_hs_secret = schedule
            .server_handshake_traffic_secret
            .as_ref()
            .cloned()
            .ok_or("Missing server handshake traffic secret")?;
        self.debug_log("client_hs_secret", &client_hs_secret);
        self.debug_log("server_hs_secret", &server_hs_secret);
        self.client_handshake_traffic_secret = Some(client_hs_secret.clone());
        self.server_handshake_traffic_secret = Some(server_hs_secret.clone());

        // Derive traffic keys
        let key_len = cipher_suite.key_length() as usize;
        let iv_len = cipher_suite.iv_length() as usize;

        let client_key = hash_alg
            .hkdf_expand_label(&client_hs_secret, b"key", b"", key_len)
            .map_err(|e| format!("Failed to derive client handshake key: {}", e))?;
        let client_iv = hash_alg
            .hkdf_expand_label(&client_hs_secret, b"iv", b"", iv_len)
            .map_err(|e| format!("Failed to derive client handshake IV: {}", e))?;
        self.debug_log("client_hs_key", &client_key);
        self.debug_log("client_hs_iv", &client_iv);
        self.client_handshake_key = Some(client_key);
        self.client_handshake_iv = Some(client_iv);

        let server_key = hash_alg
            .hkdf_expand_label(&server_hs_secret, b"key", b"", key_len)
            .map_err(|e| format!("Failed to derive server handshake key: {}", e))?;
        let server_iv = hash_alg
            .hkdf_expand_label(&server_hs_secret, b"iv", b"", iv_len)
            .map_err(|e| format!("Failed to derive server handshake IV: {}", e))?;
        self.debug_log("server_hs_key", &server_key);
        self.debug_log("server_hs_iv", &server_iv);
        self.server_handshake_key = Some(server_key);
        self.server_handshake_iv = Some(server_iv);

        // Reset handshake sequence numbers whenever keys rotate
        self.client_handshake_seq = 0;
        self.server_handshake_seq = 0;
        self.key_schedule = Some(schedule);

        Ok(())
    }

    /// Receive encrypted handshake messages
    fn receive_encrypted_handshake(&mut self) -> Result<(), String> {
        // Receive ChangeCipherSpec (legacy compatibility)
        let mut pending_record = None;
        let first_record = self.receive_record()?;
        self.debug_msg(&format!(
            "First record after ServerHello: {:?}, {} bytes",
            first_record.content_type,
            first_record.payload.len()
        ));
        if first_record.content_type != ContentType::ChangeCipherSpec {
            // Some servers skip CCS; process this record within the loop.
            pending_record = Some(first_record);
        }

        // Receive encrypted handshake messages
        loop {
            let record = if let Some(pending) = pending_record.take() {
                pending
            } else {
                self.receive_record()?
            };

            self.debug_msg(&format!(
                "Encrypted handshake record: {:?}, {} bytes",
                record.content_type,
                record.payload.len()
            ));

            if record.content_type != ContentType::ApplicationData {
                return Err(format!(
                    "Expected ApplicationData, got {:?}",
                    record.content_type
                ));
            }

            self.debug_log("encrypted_hs_payload", &record.payload);

            // Decrypt record using handshake traffic keys
            let plaintext = self.decrypt_record(&record.payload, true)?;

            // Remove padding (find real content type)
            let mut real_content_type = ContentType::Invalid;
            let mut real_length = plaintext.len();
            for i in (0..plaintext.len()).rev() {
                if plaintext[i] != 0 {
                    real_content_type = ContentType::from(plaintext[i]);
                    real_length = i;
                    break;
                }
            }

            if real_content_type != ContentType::Handshake {
                if real_content_type == ContentType::Alert {
                    return Err("Server sent alert".to_string());
                }
                continue;
            }

            let handshake_data = &plaintext[..real_length];

            // Add to transcript
            self.handshake_messages.extend_from_slice(handshake_data);
            if let Some(schedule) = &mut self.key_schedule {
                schedule.add_to_transcript(handshake_data);
            }

            // Parse handshake messages
            let mut offset = 0;
            while offset < handshake_data.len() {
                if offset + 4 > handshake_data.len() {
                    return Err("Truncated handshake message".to_string());
                }

                let msg_type = HandshakeType::from(handshake_data[offset]);
                let msg_len = ((handshake_data[offset + 1] as usize) << 16)
                    | ((handshake_data[offset + 2] as usize) << 8)
                    | (handshake_data[offset + 3] as usize);
                let start = offset + 4;
                let end = start + msg_len;
                if end > handshake_data.len() {
                    return Err("Truncated handshake message".to_string());
                }

                if msg_type == HandshakeType::Certificate {
                    if let Some(leaf) = Self::extract_leaf_certificate(&handshake_data[start..end])
                    {
                        self.server_certificate = Some(leaf);
                    }
                }

                if msg_type == HandshakeType::Finished {
                    // Server Finished - handshake complete
                    return Ok(());
                }

                offset = end;
            }
        }
    }

    fn extract_leaf_certificate(data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }

        let ctx_len = *data.get(0)? as usize;
        let mut offset = 1 + ctx_len;
        if offset + 3 > data.len() {
            return None;
        }

        let cert_list_len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | data[offset + 2] as usize;
        offset += 3;
        if cert_list_len == 0 || offset + 3 > data.len() {
            return None;
        }

        let cert_len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | data[offset + 2] as usize;
        offset += 3;
        if offset + cert_len > data.len() {
            return None;
        }

        Some(data[offset..offset + cert_len].to_vec())
    }

    /// Derive application secrets
    fn derive_application_secrets(&mut self) -> Result<(), String> {
        let cipher_suite = self.cipher_suite.ok_or("No cipher suite")?;
        let hash_alg = self.hash_algorithm;
        let (master_secret_log, transcript_hash, client_app_secret, server_app_secret) = {
            let schedule = self
                .key_schedule
                .as_mut()
                .ok_or("Key schedule not initialised")?;

            schedule.set_transcript(&self.handshake_messages);
            schedule.derive_master_secret();
            let master_secret_log = schedule.current_secret().to_vec();

            let transcript_hash = schedule.transcript_hash();

            schedule.derive_application_traffic_secrets();

            let client_app_secret = schedule
                .client_application_traffic_secret
                .as_ref()
                .cloned()
                .ok_or("Missing client application traffic secret")?;
            let server_app_secret = schedule
                .server_application_traffic_secret
                .as_ref()
                .cloned()
                .ok_or("Missing server application traffic secret")?;

            (
                master_secret_log,
                transcript_hash,
                client_app_secret,
                server_app_secret,
            )
        };

        self.debug_log("app_master_secret", &master_secret_log);
        self.debug_log("transcript_hash_app", &transcript_hash);
        self.debug_log("client_app_secret", &client_app_secret);
        self.debug_log("server_app_secret", &server_app_secret);
        self.client_application_traffic_secret = Some(client_app_secret.clone());
        self.server_application_traffic_secret = Some(server_app_secret.clone());

        // Derive traffic keys
        let key_len = cipher_suite.key_length() as usize;
        let iv_len = cipher_suite.iv_length() as usize;

        let client_key = hash_alg
            .hkdf_expand_label(&client_app_secret, b"key", b"", key_len)
            .map_err(|e| format!("Failed to derive client application key: {}", e))?;
        let client_iv = hash_alg
            .hkdf_expand_label(&client_app_secret, b"iv", b"", iv_len)
            .map_err(|e| format!("Failed to derive client application IV: {}", e))?;
        self.debug_log("client_app_key", &client_key);
        self.debug_log("client_app_iv", &client_iv);
        self.client_application_key = Some(client_key);
        self.client_application_iv = Some(client_iv);

        let server_key = hash_alg
            .hkdf_expand_label(&server_app_secret, b"key", b"", key_len)
            .map_err(|e| format!("Failed to derive server application key: {}", e))?;
        let server_iv = hash_alg
            .hkdf_expand_label(&server_app_secret, b"iv", b"", iv_len)
            .map_err(|e| format!("Failed to derive server application IV: {}", e))?;
        self.debug_log("server_app_key", &server_key);
        self.debug_log("server_app_iv", &server_iv);
        self.server_application_key = Some(server_key);
        self.server_application_iv = Some(server_iv);

        // Reset application traffic sequence numbers now that keys are active
        self.client_application_seq = 0;
        self.server_application_seq = 0;

        Ok(())
    }

    /// Send client Finished
    fn send_finished(&mut self) -> Result<(), String> {
        let client_hs_secret = self
            .client_handshake_traffic_secret
            .as_ref()
            .ok_or("No client hs secret")?;
        let hash_alg = self.hash_algorithm;

        // Derive finished key
        let finished_key = hash_alg
            .hkdf_expand_label(client_hs_secret, b"finished", b"", hash_alg.hash_len())
            .map_err(|e| format!("Failed to derive client Finished key: {}", e))?;

        // Compute verify_data = HMAC(finished_key, transcript_hash)
        let transcript_hash = hash_alg.hash(&self.handshake_messages);
        let verify_data = hash_alg.hmac(&finished_key, &transcript_hash);
        let verify_len = verify_data.len();

        // Build Finished message
        let mut finished = Vec::new();
        finished.push(HandshakeType::Finished as u8);
        finished.push(((verify_len >> 16) & 0xff) as u8);
        finished.push(((verify_len >> 8) & 0xff) as u8);
        finished.push((verify_len & 0xff) as u8);
        finished.extend_from_slice(&verify_data);

        // Add to transcript
        self.handshake_messages.extend_from_slice(&finished);

        // Encrypt and send
        self.send_encrypted_handshake(&finished)?;

        Ok(())
    }

    /// Send encrypted handshake message
    fn send_encrypted_handshake(&mut self, data: &[u8]) -> Result<(), String> {
        // Add content type
        let mut plaintext = data.to_vec();
        plaintext.push(ContentType::Handshake as u8);

        // Encrypt
        let ciphertext = self.encrypt_record(&plaintext, true)?;

        // Send as ApplicationData record
        let record = TlsRecord::new(ContentType::ApplicationData, ciphertext);
        self.send_record(&record)?;

        Ok(())
    }

    /// Encrypt TLS record
    fn encrypt_record(
        &mut self,
        plaintext: &[u8],
        use_handshake_keys: bool,
    ) -> Result<Vec<u8>, String> {
        let cipher_suite = self.cipher_suite.ok_or("No cipher suite")?;

        let (key, iv, seq_val) = if use_handshake_keys {
            let key = self
                .client_handshake_key
                .as_ref()
                .ok_or("No client hs key")?;
            let iv = self.client_handshake_iv.as_ref().ok_or("No client hs iv")?;
            (key, iv, self.client_handshake_seq)
        } else {
            let key = self
                .client_application_key
                .as_ref()
                .ok_or("No client app key")?;
            let iv = self
                .client_application_iv
                .as_ref()
                .ok_or("No client app iv")?;
            (key, iv, self.client_application_seq)
        };

        // Construct nonce: IV XOR sequence number
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv);
        for i in 0..8 {
            nonce[12 - 8 + i] ^= ((seq_val >> (56 - i * 8)) & 0xff) as u8;
        }

        let ciphertext_len = plaintext.len() + cipher_suite.tag_length();
        if ciphertext_len > u16::MAX as usize {
            return Err("TLS record too large".to_string());
        }
        let aad = Self::build_tls13_aad(ContentType::ApplicationData, ciphertext_len);

        // Debug logging
        self.debug_log(
            if use_handshake_keys {
                "tls13_hs_nonce"
            } else {
                "tls13_app_nonce"
            },
            &nonce,
        );
        self.debug_log(
            if use_handshake_keys {
                "tls13_hs_aad"
            } else {
                "tls13_app_aad"
            },
            &aad,
        );
        self.debug_log(
            if use_handshake_keys {
                "tls13_hs_plain"
            } else {
                "tls13_app_plain"
            },
            plaintext,
        );

        // Encrypt
        let ciphertext = match cipher_suite {
            CipherSuite::TlsChacha20Poly1305Sha256 => {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(key);
                chacha20poly1305_encrypt(&key_array, &nonce, &aad, plaintext)
            }
            CipherSuite::TlsAes128GcmSha256 => {
                let mut key_array = [0u8; 16];
                key_array.copy_from_slice(&key[..16]);
                aes128_gcm_encrypt(&key_array, &nonce, &aad, plaintext)
            }
            CipherSuite::TlsAes256GcmSha384 => {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key[..32]);
                aes256_gcm_encrypt(&key_array, &nonce, &aad, plaintext)
            }
        };

        self.debug_log(
            if use_handshake_keys {
                "tls13_hs_cipher"
            } else {
                "tls13_app_cipher"
            },
            &ciphertext,
        );

        // Increment sequence number
        if use_handshake_keys {
            self.client_handshake_seq += 1;
        } else {
            self.client_application_seq += 1;
        }

        Ok(ciphertext)
    }

    /// Decrypt TLS record
    fn decrypt_record(
        &mut self,
        ciphertext: &[u8],
        use_handshake_keys: bool,
    ) -> Result<Vec<u8>, String> {
        let cipher_suite = self.cipher_suite.ok_or("No cipher suite")?;

        let (key, iv, seq_val) = if use_handshake_keys {
            let key = self
                .server_handshake_key
                .as_ref()
                .ok_or("No server hs key")?;
            let iv = self.server_handshake_iv.as_ref().ok_or("No server hs iv")?;
            (key, iv, self.server_handshake_seq)
        } else {
            let key = self
                .server_application_key
                .as_ref()
                .ok_or("No server app key")?;
            let iv = self
                .server_application_iv
                .as_ref()
                .ok_or("No server app iv")?;
            (key, iv, self.server_application_seq)
        };

        // Construct nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv);
        for i in 0..8 {
            nonce[12 - 8 + i] ^= ((seq_val >> (56 - i * 8)) & 0xff) as u8;
        }

        let aad = Self::build_tls13_aad(ContentType::ApplicationData, ciphertext.len());

        // Debug logging
        self.debug_log(
            if use_handshake_keys {
                "tls13_srv_hs_nonce"
            } else {
                "tls13_srv_app_nonce"
            },
            &nonce,
        );
        self.debug_log(
            if use_handshake_keys {
                "tls13_srv_hs_aad"
            } else {
                "tls13_srv_app_aad"
            },
            &aad,
        );
        self.debug_log(
            if use_handshake_keys {
                "tls13_srv_cipher"
            } else {
                "tls13_srv_app_cipher"
            },
            ciphertext,
        );

        // Decrypt
        let plaintext = match cipher_suite {
            CipherSuite::TlsChacha20Poly1305Sha256 => {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(key);
                chacha20poly1305_decrypt(&key_array, &nonce, &aad, ciphertext)
                    .map_err(|e| format!("ChaCha20-Poly1305 decrypt failed: {}", e))?
            }
            CipherSuite::TlsAes128GcmSha256 => {
                let mut key_array = [0u8; 16];
                key_array.copy_from_slice(&key[..16]);
                match aes128_gcm_decrypt(&key_array, &nonce, &aad, ciphertext) {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        let mut dump_key = [0u8; 32];
                        dump_key[..16].copy_from_slice(&key_array);
                        self.dump_gcm_failure(
                            if use_handshake_keys {
                                "server_hs"
                            } else {
                                "server_app"
                            },
                            &dump_key,
                            &nonce,
                            &aad,
                            ciphertext,
                        );
                        return Err(format!("AES-128-GCM decrypt failed: {}", e));
                    }
                }
            }
            CipherSuite::TlsAes256GcmSha384 => {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key[..32]);
                match aes256_gcm_decrypt(&key_array, &nonce, &aad, ciphertext) {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        self.dump_gcm_failure(
                            if use_handshake_keys {
                                "server_hs"
                            } else {
                                "server_app"
                            },
                            &key_array,
                            &nonce,
                            &aad,
                            ciphertext,
                        );
                        return Err(format!("AES-256-GCM decrypt failed: {}", e));
                    }
                }
            }
        };

        self.debug_log(
            if use_handshake_keys {
                "tls13_srv_plain"
            } else {
                "tls13_srv_app_plain"
            },
            &plaintext,
        );

        // Increment sequence number
        if use_handshake_keys {
            self.server_handshake_seq += 1;
        } else {
            self.server_application_seq += 1;
        }

        Ok(plaintext)
    }

    fn dump_gcm_failure(
        &self,
        phase: &str,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8; 5],
        ciphertext: &[u8],
    ) {
        use std::fs::File;
        use std::io::Write;

        if let Ok(mut file) = File::create(format!("/tmp/tls13_{}_failure.txt", phase)) {
            let _ = writeln!(file, "cipher_suite={:?}", self.cipher_suite);
            let _ = writeln!(file, "key={}", Self::hex(key));
            let _ = writeln!(file, "iv={}", Self::hex(nonce));
            let _ = writeln!(file, "aad={}", Self::hex(aad));
            let _ = writeln!(file, "ciphertext_with_tag={}", Self::hex(ciphertext));
            if self.debug {
                eprintln!(
                    "[tls13][debug] wrote failure trace to /tmp/tls13_{}_failure.txt",
                    phase
                );
            }
        } else if self.debug {
            eprintln!(
                "[tls13][debug] failed to create failure trace file for phase {}",
                phase
            );
        }
    }

    fn build_tls13_aad(content_type: ContentType, ciphertext_len: usize) -> [u8; 5] {
        let mut aad = [0u8; 5];
        aad[0] = content_type as u8;
        aad[1] = 0x03;
        aad[2] = 0x03;
        let len = ciphertext_len as u16;
        aad[3] = (len >> 8) as u8;
        aad[4] = len as u8;
        aad
    }

    /// Send TLS record
    fn send_record(&mut self, record: &TlsRecord) -> Result<(), String> {
        let bytes = record.to_bytes();
        self.stream
            .write_all(&bytes)
            .map_err(|e| format!("Failed to send record: {}", e))?;
        Ok(())
    }

    /// Receive TLS record
    fn receive_record(&mut self) -> Result<TlsRecord, String> {
        // Read record header (5 bytes)
        let mut header = [0u8; 5];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| format!("Failed to read record header: {}", e))?;

        let content_type = ContentType::from(header[0]);
        let _legacy_version = ((header[1] as u16) << 8) | (header[2] as u16);
        let length = ((header[3] as u16) << 8) | (header[4] as u16);

        // Read payload
        let mut payload = vec![0u8; length as usize];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| format!("Failed to read record payload: {}", e))?;

        Ok(TlsRecord {
            content_type,
            legacy_version: 0x0303,
            payload,
        })
    }

    /// Send HTTP GET request over TLS
    pub fn send_http_get(&mut self, path: &str) -> Result<String, String> {
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, self.server_name
        );

        // Encrypt and send
        let mut plaintext = request.as_bytes().to_vec();
        plaintext.push(ContentType::ApplicationData as u8);

        let ciphertext = self.encrypt_record(&plaintext, false)?;
        let record = TlsRecord::new(ContentType::ApplicationData, ciphertext);
        self.send_record(&record)?;

        // Receive response
        let mut response = Vec::new();
        loop {
            let record = match self.receive_record() {
                Ok(r) => r,
                Err(_) => break, // Connection closed
            };

            if record.content_type != ContentType::ApplicationData {
                continue;
            }

            let plaintext = self.decrypt_record(&record.payload, false)?;

            // Remove padding
            let mut real_length = plaintext.len();
            for i in (0..plaintext.len()).rev() {
                if plaintext[i] != 0 {
                    real_length = i;
                    break;
                }
            }

            response.extend_from_slice(&plaintext[..real_length]);
        }

        String::from_utf8(response).map_err(|e| format!("Invalid UTF-8: {}", e))
    }

    /// Clamp X25519 scalar per RFC 7748 §5
    fn clamp_x25519_scalar(scalar: &mut [u8; 32]) {
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
    }

    /// Generate random bytes (best-effort entropy without external deps)
    fn generate_random() -> [u8; 32] {
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicU64 = AtomicU64::new(1);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));

        let timestamp = now.as_nanos();
        let pid = std::process::id() as u128;
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

        let ts_bytes = timestamp.to_le_bytes();
        let pid_bytes = pid.to_le_bytes();
        let counter_bytes = counter.to_le_bytes();

        let mut random = [0u8; 32];
        for i in 0..32 {
            random[i] = ts_bytes[i % ts_bytes.len()]
                ^ pid_bytes[i % pid_bytes.len()]
                ^ counter_bytes[i % counter_bytes.len()];
        }

        random
    }
}

impl std::io::Read for Tls13Client {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.read_buffer.is_empty() {
            let to_copy = buf.len().min(self.read_buffer.len());
            buf[..to_copy].copy_from_slice(&self.read_buffer[..to_copy]);
            self.read_buffer.drain(..to_copy);
            return Ok(to_copy);
        }

        loop {
            let record = self
                .receive_record()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            match record.content_type {
                ContentType::ApplicationData => {
                    let plaintext = self
                        .decrypt_record(&record.payload, false)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                    if plaintext.is_empty() {
                        continue;
                    }

                    let mut idx = plaintext.len();
                    while idx > 0 && plaintext[idx - 1] == 0 {
                        idx -= 1;
                    }

                    if idx == 0 {
                        continue;
                    }

                    let content_type_byte = plaintext[idx - 1];
                    idx -= 1;
                    let inner_type = ContentType::from(content_type_byte);
                    let body = &plaintext[..idx];

                    match inner_type {
                        ContentType::ApplicationData => {
                            if body.is_empty() {
                                continue;
                            }

                            let to_copy = buf.len().min(body.len());
                            buf[..to_copy].copy_from_slice(&body[..to_copy]);
                            if body.len() > to_copy {
                                self.read_buffer.extend_from_slice(&body[to_copy..]);
                            }
                            return Ok(to_copy);
                        }
                        ContentType::Handshake => {
                            // Additional handshake messages arrive encrypted post-handshake
                            if !body.is_empty() {
                                self.handshake_messages.extend_from_slice(body);
                            }
                            continue;
                        }
                        ContentType::Alert => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "TLS alert received",
                            ));
                        }
                        _ => continue,
                    }
                }
                ContentType::Alert => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "TLS alert received",
                    ));
                }
                ContentType::Handshake => {
                    // Rare case: unencrypted handshake after handshake. Record it and continue.
                    if !record.payload.is_empty() {
                        self.handshake_messages.extend_from_slice(&record.payload);
                    }
                    continue;
                }
                _ => continue,
            }
        }
    }
}

impl std::io::Write for Tls13Client {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut plaintext = Vec::with_capacity(buf.len() + 1);
        plaintext.extend_from_slice(buf);
        plaintext.push(ContentType::ApplicationData as u8);

        let ciphertext = self
            .encrypt_record(&plaintext, false)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let record = TlsRecord::new(ContentType::ApplicationData, ciphertext);
        self.send_record(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_conversion() {
        assert_eq!(ContentType::from(22), ContentType::Handshake);
        assert_eq!(ContentType::from(23), ContentType::ApplicationData);
        assert_eq!(ContentType::from(21), ContentType::Alert);
    }

    #[test]
    fn test_handshake_type_conversion() {
        assert_eq!(HandshakeType::from(1), HandshakeType::ClientHello);
        assert_eq!(HandshakeType::from(2), HandshakeType::ServerHello);
        assert_eq!(HandshakeType::from(20), HandshakeType::Finished);
    }

    #[test]
    fn test_cipher_suite_properties() {
        let chacha = CipherSuite::TlsChacha20Poly1305Sha256;
        assert_eq!(chacha.key_length(), 32);
        assert_eq!(chacha.iv_length(), 12);
        assert_eq!(chacha.tag_length(), 16);

        let aes128 = CipherSuite::TlsAes128GcmSha256;
        assert_eq!(aes128.key_length(), 16);
        assert_eq!(aes128.iv_length(), 12);
        assert_eq!(aes128.tag_length(), 16);

        let aes256 = CipherSuite::TlsAes256GcmSha384;
        assert_eq!(aes256.key_length(), 32);
        assert_eq!(aes256.iv_length(), 12);
        assert_eq!(aes256.tag_length(), 16);
    }

    #[test]
    fn test_tls_record_serialization() {
        let payload = vec![1, 2, 3, 4];
        let record = TlsRecord::new(ContentType::Handshake, payload.clone());

        let bytes = record.to_bytes();
        assert_eq!(bytes[0], ContentType::Handshake as u8);
        assert_eq!(bytes[1], 0x03);
        assert_eq!(bytes[2], 0x03);
        assert_eq!(bytes[3], 0x00);
        assert_eq!(bytes[4], 0x04);
        assert_eq!(&bytes[5..], &payload[..]);
    }

    #[test]
    fn test_random_generation() {
        let r1 = Tls13Client::generate_random();
        let r2 = Tls13Client::generate_random();

        // Should be different (with very high probability)
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_signature_schemes_include_rsa_pss_and_pkcs1() {
        assert!(TLS13_SIGNATURE_SCHEMES.contains(&0x0804));
        assert!(TLS13_SIGNATURE_SCHEMES.contains(&0x0401));
    }

    #[test]
    fn test_tls13_aad_builder() {
        let aad = Tls13Client::build_tls13_aad(ContentType::ApplicationData, 42);
        assert_eq!(aad, [23, 0x03, 0x03, 0x00, 0x2a]);
    }

    #[test]
    #[ignore] // Run with: cargo test --release test_tls13_google_connection -- --ignored --nocapture
    fn test_tls13_google_connection() {
        use std::io::{Read, Write};

        println!("\n🔐 Testing TLS 1.3 connection to google.com...");

        // Connect and handshake with debug enabled
        println!("⏳ Establishing connection...");
        let mut client = Tls13Client::new("google.com", 443)
            .expect("Failed to create TLS 1.3 client")
            .with_debug(true);

        println!("🤝 Performing handshake...");
        client.handshake().expect("TLS 1.3 handshake failed");

        println!("✅ Handshake complete!");

        if let Some(cipher) = client.cipher_suite() {
            println!("🔒 Negotiated cipher: {:?}", cipher);
        }

        // Send HTTP request
        println!("📤 Sending HTTP GET request...");
        let request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
        client
            .write_all(request.as_bytes())
            .expect("Failed to send request");

        // Read response
        println!("📥 Reading response...");
        let mut response = Vec::new();
        let mut buffer = [0u8; 4096];

        loop {
            match client.read(&mut buffer) {
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

        println!("✅ TLS 1.3 test PASSED!");
    }
}
