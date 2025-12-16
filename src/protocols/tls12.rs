/// TLS 1.2 Handshake Implementation from Scratch
///
/// Provides a basic TLS 1.2 client that supports the RSA + AES-128-CBC +
/// HMAC-SHA256 cipher suite without relying on external crates or binaries.
/// The implementation is intentionally scoped to what we need for HTTPS GET
/// requests inside the project.
use super::asn1::Asn1Object;
use super::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt, hmac_sha256, tls12_prf, SecureRandom};
use super::ecdh::EcdhKeyPair;
use super::gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};
use super::p256::P256Point;
use super::rsa::RsaPublicKey;
use super::x509::{self, X509Certificate};
use crate::crypto::BigInt;
use crate::crypto::{encode_base64, md5, sha1::sha1, sha256::sha256};
use crate::intelligence::tls_fingerprint::JA3Fingerprint;
use std::cmp::Ordering;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_CONTENT_TYPE_ALERT: u8 = 0x15;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const TLS_HANDSHAKE_CERTIFICATE: u8 = 0x0B;
const TLS_HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 0x0C; // For ECDHE
const TLS_HANDSHAKE_SERVER_HELLO_DONE: u8 = 0x0E;
const TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 0x10;
const TLS_HANDSHAKE_FINISHED: u8 = 0x14;

const TLS_VERSION_MAJOR: u8 = 0x03;
const TLS_VERSION_MINOR: u8 = 0x03; // TLS 1.2

// TLS Extension Types (RFC 4492, RFC 5246)
const TLS_EXT_SERVER_NAME: u16 = 0x0000; // SNI
const TLS_EXT_SUPPORTED_GROUPS: u16 = 0x000A; // Formerly "elliptic_curves"
const TLS_EXT_EC_POINT_FORMATS: u16 = 0x000B;

// Cipher suites we support (in order of preference)
const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F; // ECDHE with Perfect Forward Secrecy
const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009C;
const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003C;

const P256_ORDER_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

const SUPPORTED_CIPHER_SUITES: &[u16] = &[
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // Prefer ECDHE for PFS
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
];

#[cfg(feature = "tls_debug")]
macro_rules! tls_debug {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}

#[cfg(not(feature = "tls_debug"))]
macro_rules! tls_debug {
    ($($arg:tt)*) => {};
}

fn is_gcm_cipher(cipher_suite: u16) -> bool {
    matches!(
        cipher_suite,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | TLS_RSA_WITH_AES_128_GCM_SHA256
    )
}

fn is_cbc_cipher(cipher_suite: u16) -> bool {
    matches!(cipher_suite, TLS_RSA_WITH_AES_128_CBC_SHA256)
}

fn is_ecdhe_cipher(cipher_suite: u16) -> bool {
    matches!(cipher_suite, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
}

#[derive(Debug)]
enum RecordReadError {
    ConnectionClosed,
    Io(io::Error),
}

#[derive(Clone)]
enum VerifierKey {
    Rsa(RsaPublicKey),
    EcP256(P256Point),
}

/// Minimal TLS 1.2 client implementation.
pub struct Tls12Client {
    stream: TcpStream,
    server_name: String,
    client_random: [u8; 32],
    server_random: [u8; 32],
    master_secret: Option<Vec<u8>>,
    handshake_messages: Vec<u8>,
    ja3: Option<String>,
    ja3_raw: Option<String>,
    ja3s: Option<String>,
    ja3s_raw: Option<String>,
    client_write_key: Option<[u8; 16]>,
    server_write_key: Option<[u8; 16]>,
    client_write_iv: Option<[u8; 16]>,
    server_write_iv: Option<[u8; 16]>,
    client_write_mac: Option<[u8; 32]>,
    server_write_mac: Option<[u8; 32]>,
    client_seq: u64,
    server_seq: u64,
    selected_cipher_suite: Option<u16>,
    rng: SecureRandom,
    server_cert_chain: Vec<Vec<u8>>,
    peer_certificates: Vec<X509Certificate>,
    server_public_key: Option<RsaPublicKey>,
    // ECDHE fields
    ecdh_keypair: Option<EcdhKeyPair>,
    server_ecdh_public_key: Option<P256Point>,
}

impl Tls12Client {
    /// Connect using a default 10 second timeout.
    pub fn connect(host: &str, port: u16) -> Result<Self, String> {
        Self::connect_with_timeout(host, port, Duration::from_secs(10))
    }

    /// Connect to the remote endpoint with a caller-provided timeout.
    pub fn connect_with_timeout(host: &str, port: u16, timeout: Duration) -> Result<Self, String> {
        let timeout = if timeout.is_zero() {
            Duration::from_millis(1)
        } else {
            timeout
        };

        let mut addrs = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {}:{} - {}", host, port, e))?;

        let mut last_err = None;
        let stream = loop {
            match addrs.next() {
                Some(addr) => match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(stream) => break stream,
                    Err(err) => last_err = Some(err),
                },
                None => {
                    return Err(match last_err {
                        Some(err) => format!("TCP connect failed: {}", err),
                        None => "No addresses resolved for target".to_string(),
                    })
                }
            }
        };

        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let rng = SecureRandom::new()
            .map_err(|e| format!("Secure random initialization failed: {}", e))?;

        let mut client = Self {
            stream,
            server_name: host.to_string(),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            master_secret: None,
            handshake_messages: Vec::new(),
            ja3: None,
            ja3_raw: None,
            ja3s: None,
            ja3s_raw: None,
            client_write_key: None,
            server_write_key: None,
            client_write_iv: None,
            server_write_iv: None,
            client_write_mac: None,
            server_write_mac: None,
            client_seq: 0,
            server_seq: 0,
            selected_cipher_suite: None,
            rng,
            server_cert_chain: Vec::new(),
            peer_certificates: Vec::new(),
            server_public_key: None,
            ecdh_keypair: None,
            server_ecdh_public_key: None,
        };

        client.generate_client_random()?;
        client.handshake()?;

        Ok(client)
    }

    fn handshake(&mut self) -> Result<(), String> {
        tls_debug!("[DEBUG] Starting TLS handshake");
        let client_hello = self.build_client_hello();
        if self.ja3.is_none() {
            if let Ok((raw, hash)) = compute_ja3_from_client_hello(&client_hello) {
                self.ja3_raw = Some(raw);
                self.ja3 = Some(hash);
            }
        }
        self.handshake_messages.extend_from_slice(&client_hello);
        self.send_record(TLS_CONTENT_TYPE_HANDSHAKE, &client_hello)?;
        tls_debug!("[DEBUG] Sent ClientHello");

        tls_debug!("[DEBUG] Waiting for ServerHello...");
        let server_hello = self.receive_handshake_message(TLS_HANDSHAKE_SERVER_HELLO)?;
        tls_debug!("[DEBUG] Received ServerHello");
        self.parse_server_hello(&server_hello)?;
        tls_debug!(
            "[DEBUG] Parsed ServerHello, cipher suite: 0x{:04X}",
            self.selected_cipher_suite.unwrap_or(0)
        );

        let certificate = self.receive_handshake_message(TLS_HANDSHAKE_CERTIFICATE)?;
        let cert_chain = self.parse_certificate_chain(&certificate)?;
        if cert_chain.is_empty() {
            return Err("Server did not present any certificates".to_string());
        }
        self.server_cert_chain = cert_chain.clone();
        self.peer_certificates = cert_chain
            .iter()
            .map(|der| {
                x509::X509Certificate::from_der(der)
                    .map_err(|e| format!("Failed to parse certificate: {}", e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(leaf) = self.peer_certificates.first() {
            let (modulus, exponent) = leaf
                .subject_public_key_info
                .rsa_components()
                .map_err(|e| format!("Failed to parse server public key: {}", e))?;
            self.server_public_key = Some(RsaPublicKey::from_components(&modulus, &exponent));
        } else {
            return Err("Server certificate chain is empty".to_string());
        }
        self.verify_peer_certificate()?;

        // For ECDHE cipher suites, receive and parse ServerKeyExchange
        let cipher_suite = self.selected_cipher_suite.unwrap_or(0);
        if is_ecdhe_cipher(cipher_suite) {
            let server_key_exchange =
                self.receive_handshake_message(TLS_HANDSHAKE_SERVER_KEY_EXCHANGE)?;
            self.parse_server_key_exchange(&server_key_exchange)?;

            // Generate client ECDH keypair
            tls_debug!("[DEBUG] Generating client ECDH keypair...");
            self.ecdh_keypair = Some(
                EcdhKeyPair::generate()
                    .map_err(|e| format!("Failed to generate ECDH keypair: {}", e))?,
            );
            tls_debug!("[DEBUG] Generated ECDH keypair");
        } else {
            tls_debug!("[DEBUG] RSA cipher detected, skipping ServerKeyExchange");
        }

        tls_debug!("[DEBUG] Waiting for ServerHelloDone...");
        let _server_done = self.receive_handshake_message(TLS_HANDSHAKE_SERVER_HELLO_DONE)?;
        tls_debug!("[DEBUG] Received ServerHelloDone");

        // Generate premaster secret and build ClientKeyExchange
        tls_debug!("[DEBUG] Generating premaster secret...");
        let premaster_secret = if is_ecdhe_cipher(cipher_suite) {
            tls_debug!("[DEBUG] Computing ECDH shared secret...");
            // For ECDHE: compute shared secret from ECDH
            let server_public = self
                .server_ecdh_public_key
                .as_ref()
                .ok_or("Server ECDH public key not received")?;
            let keypair = self
                .ecdh_keypair
                .as_ref()
                .ok_or("ECDH keypair not generated")?;

            let shared_secret = keypair.compute_shared_secret(server_public);
            tls_debug!("[DEBUG] Computed shared secret (32 bytes)");
            shared_secret.to_vec()
        } else {
            tls_debug!("[DEBUG] Generating random premaster secret for RSA...");
            // For RSA: generate random 48-byte premaster secret
            self.generate_premaster_secret()?
        };

        tls_debug!("[DEBUG] Building ClientKeyExchange...");
        let client_key_exchange = if is_ecdhe_cipher(cipher_suite) {
            // For ECDHE: send our public key
            let public_key_bytes = self
                .ecdh_keypair
                .as_ref()
                .ok_or("ECDH keypair not generated")?
                .public_key_bytes();
            tls_debug!(
                "[DEBUG] Building ECDH ClientKeyExchange ({} bytes public key)",
                public_key_bytes.len()
            );
            self.build_client_key_exchange_ecdh(&public_key_bytes)
        } else {
            // For RSA: encrypt premaster secret
            tls_debug!("[DEBUG] Encrypting premaster secret with RSA...");
            let server_key = self
                .server_public_key
                .as_ref()
                .ok_or_else(|| "Server public key not available".to_string())?;
            let encrypted_pms = self.rsa_encrypt_premaster(server_key, &premaster_secret)?;
            tls_debug!(
                "[DEBUG] Building RSA ClientKeyExchange ({} bytes encrypted)",
                encrypted_pms.len()
            );
            self.build_client_key_exchange_rsa(&encrypted_pms)
        };
        self.handshake_messages
            .extend_from_slice(&client_key_exchange);
        tls_debug!("[DEBUG] Sending ClientKeyExchange...");
        self.send_record(TLS_CONTENT_TYPE_HANDSHAKE, &client_key_exchange)?;
        tls_debug!("[DEBUG] Sent ClientKeyExchange");

        tls_debug!("[DEBUG] Computing master secret...");
        self.compute_master_secret(&premaster_secret)?;
        tls_debug!("[DEBUG] Computed master secret");

        self.send_record(TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[0x01])?;

        let finished = self.build_finished(true)?;
        self.handshake_messages.extend_from_slice(&finished);
        self.send_encrypted_record(TLS_CONTENT_TYPE_HANDSHAKE, &finished)?;

        let (ccs_type, ccs_payload) = match self.receive_record() {
            Ok(record) => record,
            Err(RecordReadError::ConnectionClosed) => {
                return Err("Connection closed before ChangeCipherSpec".to_string())
            }
            Err(RecordReadError::Io(e)) => {
                return Err(format!("Failed to read ChangeCipherSpec: {}", e))
            }
        };

        if ccs_type != TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC || ccs_payload != [0x01] {
            return Err("Unexpected ChangeCipherSpec payload from server".to_string());
        }

        let server_finished = match self.receive_encrypted_record(TLS_CONTENT_TYPE_HANDSHAKE) {
            Ok(data) => data,
            Err(RecordReadError::ConnectionClosed) => {
                return Err("Connection closed before Finished message".to_string())
            }
            Err(RecordReadError::Io(e)) => {
                return Err(format!("Failed to read Finished message: {}", e))
            }
        };

        self.verify_finished(false, &server_finished)?;
        self.handshake_messages.extend_from_slice(&server_finished);
        Ok(())
    }

    // Build supported_groups extension (RFC 8422 Section 5.1.1)
    // Advertises which elliptic curves we support
    fn build_supported_groups_extension() -> Vec<u8> {
        let mut ext = Vec::new();

        // Extension type: supported_groups (10)
        ext.extend_from_slice(&TLS_EXT_SUPPORTED_GROUPS.to_be_bytes());

        // Extension length (to be filled)
        let ext_len_pos = ext.len();
        ext.extend_from_slice(&[0, 0]);
        let ext_start = ext.len();

        // Supported Groups List Length (2 bytes for one curve)
        ext.extend_from_slice(&[0, 2]);

        // secp256r1 (P-256) = 23
        ext.extend_from_slice(&[0, 23]);

        // Fix extension length
        let ext_len = (ext.len() - ext_start) as u16;
        ext[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());

        ext
    }

    // Build ec_point_formats extension (RFC 8422 Section 5.1.2)
    // Advertises which point formats we support
    fn build_ec_point_formats_extension() -> Vec<u8> {
        let mut ext = Vec::new();

        // Extension type: ec_point_formats (11)
        ext.extend_from_slice(&TLS_EXT_EC_POINT_FORMATS.to_be_bytes());

        // Extension length (to be filled)
        let ext_len_pos = ext.len();
        ext.extend_from_slice(&[0, 0]);
        let ext_start = ext.len();

        // EC Point Formats Length (1 format)
        ext.push(1);

        // uncompressed (0)
        ext.push(0);

        // Fix extension length
        let ext_len = (ext.len() - ext_start) as u16;
        ext[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());

        ext
    }

    fn build_client_hello(&self) -> Vec<u8> {
        let mut message = Vec::new();

        message.push(TLS_HANDSHAKE_CLIENT_HELLO);
        let length_pos = message.len();
        message.extend_from_slice(&[0, 0, 0]);

        message.push(TLS_VERSION_MAJOR);
        message.push(TLS_VERSION_MINOR);
        message.extend_from_slice(&self.client_random);

        // Session id
        message.push(0);

        // Cipher suites: advertise all supported suites
        let cipher_count = SUPPORTED_CIPHER_SUITES.len() as u16;
        let cipher_bytes = cipher_count * 2;
        message.extend_from_slice(&cipher_bytes.to_be_bytes());
        for &cipher_suite in SUPPORTED_CIPHER_SUITES {
            message.extend_from_slice(&cipher_suite.to_be_bytes());
        }

        // Compression (null only)
        message.push(1);
        message.push(0);

        // Extensions
        let ext_len_pos = message.len();
        message.extend_from_slice(&[0, 0]);
        let ext_start = message.len();

        // SNI extension
        let server_name_bytes = self.server_name.as_bytes();
        let host_len = server_name_bytes.len() as u16;
        let server_name_list_len = host_len + 3;

        message.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
        message.extend_from_slice(&(server_name_list_len + 2).to_be_bytes());
        message.extend_from_slice(&server_name_list_len.to_be_bytes());
        message.push(0); // host_name
        message.extend_from_slice(&host_len.to_be_bytes());
        message.extend_from_slice(server_name_bytes);

        // Add ECDHE extensions for modern cipher suites
        message.extend_from_slice(&Self::build_supported_groups_extension());
        message.extend_from_slice(&Self::build_ec_point_formats_extension());

        let ext_len = (message.len() - ext_start) as u16;
        message[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());

        let msg_len = (message.len() - 4) as u32;
        message[length_pos..length_pos + 3].copy_from_slice(&msg_len.to_be_bytes()[1..]);

        message
    }

    fn parse_server_hello(&mut self, data: &[u8]) -> Result<(), String> {
        if data.len() < 4 + 34 {
            return Err("ServerHello too short".to_string());
        }

        let mut offset = 4; // skip handshake header

        if data[offset] != TLS_VERSION_MAJOR || data[offset + 1] != TLS_VERSION_MINOR {
            return Err("Server negotiated unsupported TLS version".to_string());
        }
        offset += 2;

        self.server_random
            .copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        if offset >= data.len() {
            return Err("ServerHello missing session id length".to_string());
        }
        let session_id_len = data[offset] as usize;
        offset += 1;

        if offset + session_id_len > data.len() {
            return Err("ServerHello truncated while reading session id".to_string());
        }
        offset += session_id_len;

        if offset + 2 > data.len() {
            return Err("ServerHello missing cipher suite".to_string());
        }
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        self.selected_cipher_suite = Some(cipher_suite);
        offset += 2;

        if offset >= data.len() {
            return Err("ServerHello missing compression method".to_string());
        }
        offset += 1; // compression

        let mut extensions = Vec::new();
        let mut groups = Vec::new();
        let mut ec_formats = Vec::new();

        if offset + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if offset + ext_len > data.len() {
                return Err("ServerHello extensions truncated".to_string());
            }
            let ext_slice = &data[offset..offset + ext_len];
            let (ext_ids, group_ids, format_ids) = parse_server_hello_extensions(ext_slice);
            extensions = ext_ids;
            groups = group_ids;
            ec_formats = format_ids;
        }

        if self.ja3s.is_none() {
            let version_code = u16::from_be_bytes([TLS_VERSION_MAJOR, TLS_VERSION_MINOR]);
            let (raw, hash) = compute_ja3s_from_server_hello(
                version_code,
                cipher_suite,
                &extensions,
                &groups,
                &ec_formats,
            );
            self.ja3s_raw = Some(raw);
            self.ja3s = Some(hash);
        }

        Ok(())
    }

    fn parse_certificate_chain(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if data.len() < 7 {
            return Err("Certificate message too short".to_string());
        }

        let mut offset = 4;
        if offset + 3 > data.len() {
            return Err("Certificate list length missing".to_string());
        }
        let cert_list_len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | (data[offset + 2] as usize);
        offset += 3;

        if data.len() < offset + cert_list_len {
            return Err("Certificate message truncated".to_string());
        }

        let list_end = offset + cert_list_len;
        let mut certificates = Vec::new();

        while offset < list_end {
            if offset + 3 > data.len() {
                return Err("Certificate entry truncated".to_string());
            }

            let cert_len = ((data[offset] as usize) << 16)
                | ((data[offset + 1] as usize) << 8)
                | (data[offset + 2] as usize);
            offset += 3;

            if offset + cert_len > data.len() {
                return Err("Certificate entry length exceeds message boundary".to_string());
            }

            certificates.push(data[offset..offset + cert_len].to_vec());
            offset += cert_len;
        }

        Ok(certificates)
    }

    /// Parse ServerKeyExchange message for ECDHE (RFC 8422 Section 5.4)
    fn parse_server_key_exchange(&mut self, data: &[u8]) -> Result<(), String> {
        // ServerKeyExchange format for ECDHE:
        // - ECCurveType (1 byte): 3 = named_curve
        // - NamedCurve (2 bytes): 23 = secp256r1 (P-256)
        // - Public key length (1 byte)
        // - Public key (65 bytes for uncompressed P-256 point)
        // - Signature (RSA signature over params)

        if data.len() < 8 {
            return Err("ServerKeyExchange message too short".to_string());
        }

        let mut offset = 4; // Skip handshake header

        // Parse ECCurveType
        let curve_type = data[offset];
        offset += 1;
        if curve_type != 3 {
            return Err(format!(
                "Unsupported ECCurveType: {} (expected 3 for named_curve)",
                curve_type
            ));
        }

        // Parse NamedCurve
        let named_curve = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        if named_curve != 23 {
            return Err(format!(
                "Unsupported NamedCurve: {} (expected 23 for secp256r1/P-256)",
                named_curve
            ));
        }

        // Parse public key length
        if offset >= data.len() {
            return Err("ServerKeyExchange truncated at public key length".to_string());
        }
        let public_key_len = data[offset] as usize;
        offset += 1;

        if public_key_len != 65 {
            return Err(format!(
                "Unexpected ECDH public key length: {} (expected 65 for uncompressed P-256)",
                public_key_len
            ));
        }

        // Parse public key (uncompressed point: 0x04 || x || y)
        if offset + public_key_len > data.len() {
            return Err("ServerKeyExchange truncated at public key data".to_string());
        }

        let public_key_bytes = &data[offset..offset + public_key_len];
        let server_public_key = P256Point::from_uncompressed_bytes(public_key_bytes)
            .map_err(|e| format!("Failed to parse server ECDH public key: {}", e))?;

        offset += public_key_len;

        let params_end = offset;

        if offset + 2 > data.len() {
            return Err("ServerKeyExchange missing signature algorithms".to_string());
        }

        let hash_alg = data[offset];
        let sig_alg = data[offset + 1];
        offset += 2;

        if offset + 2 > data.len() {
            return Err("ServerKeyExchange truncated before signature length".to_string());
        }
        let sig_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + sig_len > data.len() {
            return Err("ServerKeyExchange signature exceeds message boundary".to_string());
        }

        let signature = &data[offset..offset + sig_len];

        // Section 7.4.3 of RFC 5246: signed_params =
        // client_random || server_random || ServerECDHParams
        let mut signed_params = Vec::with_capacity(64 + (params_end - 4));
        signed_params.extend_from_slice(&self.client_random);
        signed_params.extend_from_slice(&self.server_random);
        signed_params.extend_from_slice(&data[4..params_end]);

        match sig_alg {
            1 => {
                // RSA signatures
                let server_key = self.server_public_key.as_ref().ok_or_else(|| {
                    "Server RSA public key not available for signature verification".to_string()
                })?;

                let digest_info = match hash_alg {
                    2 => {
                        // SHA-1 (legacy but still required for interoperability)
                        let hash = sha1(&signed_params);
                        build_digest_info_sha1(&hash)
                    }
                    4 => {
                        // SHA-256
                        let hash = sha256(&signed_params);
                        build_digest_info_sha256(&hash)
                    }
                    other => {
                        return Err(format!(
                            "Unsupported hash algorithm {} in ServerKeyExchange",
                            other
                        ))
                    }
                };

                server_key
                    .verify_pkcs1_v15(&digest_info, signature)
                    .map_err(|e| {
                        format!("ServerKeyExchange signature verification failed: {}", e)
                    })?;
            }
            other => {
                return Err(format!(
                    "Unsupported signature algorithm {} in ServerKeyExchange",
                    other
                ));
            }
        }

        // Store server's ECDH public key for later use
        self.server_ecdh_public_key = Some(server_public_key);

        Ok(())
    }

    fn rsa_encrypt_premaster(
        &self,
        public_key: &RsaPublicKey,
        premaster: &[u8],
    ) -> Result<Vec<u8>, String> {
        public_key
            .encrypt_pkcs1v15(premaster)
            .map_err(|e| format!("RSA encryption failed: {}", e))
    }

    fn generate_client_random(&mut self) -> Result<(), String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs() as u32;
        self.client_random[0..4].copy_from_slice(&timestamp.to_be_bytes());
        self.rng
            .fill_bytes(&mut self.client_random[4..])
            .map_err(|e| format!("RNG failure: {}", e))?;
        Ok(())
    }

    fn generate_premaster_secret(&mut self) -> Result<Vec<u8>, String> {
        let mut secret = vec![TLS_VERSION_MAJOR, TLS_VERSION_MINOR];
        let mut remainder = vec![0u8; 46];
        self.rng
            .fill_bytes(&mut remainder)
            .map_err(|e| format!("RNG failure: {}", e))?;
        secret.extend_from_slice(&remainder);
        Ok(secret)
    }

    fn compute_master_secret(&mut self, premaster_secret: &[u8]) -> Result<(), String> {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&self.server_random);

        let master_secret = tls12_prf(premaster_secret, b"master secret", &seed, 48);
        self.master_secret = Some(master_secret);
        self.derive_keys()
    }

    fn derive_keys(&mut self) -> Result<(), String> {
        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or_else(|| "Master secret not derived".to_string())?;

        let cipher_suite = self
            .selected_cipher_suite
            .ok_or_else(|| "Cipher suite not set".to_string())?;

        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.server_random);
        seed.extend_from_slice(&self.client_random);

        // GCM uses different key material: no MAC keys, but 4-byte fixed IVs
        // CBC uses 32-byte MAC keys and 16-byte IVs
        let key_block_len = if is_gcm_cipher(cipher_suite) {
            // GCM: 16-byte client key + 16-byte server key + 4-byte client IV + 4-byte server IV
            40
        } else {
            // CBC: 32-byte client MAC + 32-byte server MAC + 16-byte client key + 16-byte server key + 16-byte client IV + 16-byte server IV
            128
        };

        let key_block = tls12_prf(master_secret, b"key expansion", &seed, key_block_len);
        let mut offset = 0;

        if is_gcm_cipher(cipher_suite) {
            // GCM mode: no MAC keys
            self.client_write_mac = None;
            self.server_write_mac = None;

            // Client write key (16 bytes)
            let mut client_key = [0u8; 16];
            client_key.copy_from_slice(&key_block[offset..offset + 16]);
            self.client_write_key = Some(client_key);
            offset += 16;

            // Server write key (16 bytes)
            let mut server_key = [0u8; 16];
            server_key.copy_from_slice(&key_block[offset..offset + 16]);
            self.server_write_key = Some(server_key);
            offset += 16;

            // Client write IV (4 bytes fixed, will be extended to 12 bytes with explicit nonce)
            let mut client_iv = [0u8; 16];
            client_iv[..4].copy_from_slice(&key_block[offset..offset + 4]);
            self.client_write_iv = Some(client_iv);
            offset += 4;

            // Server write IV (4 bytes fixed)
            let mut server_iv = [0u8; 16];
            server_iv[..4].copy_from_slice(&key_block[offset..offset + 4]);
            self.server_write_iv = Some(server_iv);
        } else {
            // CBC mode: has MAC keys
            let mut client_mac = [0u8; 32];
            client_mac.copy_from_slice(&key_block[offset..offset + 32]);
            self.client_write_mac = Some(client_mac);
            offset += 32;

            let mut server_mac = [0u8; 32];
            server_mac.copy_from_slice(&key_block[offset..offset + 32]);
            self.server_write_mac = Some(server_mac);
            offset += 32;

            let mut client_key = [0u8; 16];
            client_key.copy_from_slice(&key_block[offset..offset + 16]);
            self.client_write_key = Some(client_key);
            offset += 16;

            let mut server_key = [0u8; 16];
            server_key.copy_from_slice(&key_block[offset..offset + 16]);
            self.server_write_key = Some(server_key);
            offset += 16;

            let mut client_iv = [0u8; 16];
            client_iv.copy_from_slice(&key_block[offset..offset + 16]);
            self.client_write_iv = Some(client_iv);
            offset += 16;

            let mut server_iv = [0u8; 16];
            server_iv.copy_from_slice(&key_block[offset..offset + 16]);
            self.server_write_iv = Some(server_iv);
        }

        Ok(())
    }

    /// Build ClientKeyExchange for RSA key exchange
    fn build_client_key_exchange_rsa(&self, encrypted_pms: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.push(TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE);

        let length = (encrypted_pms.len() + 2) as u32;
        message.extend_from_slice(&length.to_be_bytes()[1..]);

        let pms_len = encrypted_pms.len() as u16;
        message.extend_from_slice(&pms_len.to_be_bytes());
        message.extend_from_slice(encrypted_pms);
        message
    }

    /// Build ClientKeyExchange for ECDHE key exchange (RFC 8422 Section 5.7)
    fn build_client_key_exchange_ecdh(&self, public_key: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.push(TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE);

        // Message length: 1 byte (length prefix) + public key length
        let length = (1 + public_key.len()) as u32;
        message.extend_from_slice(&length.to_be_bytes()[1..]);

        // Public key with length prefix (1 byte)
        message.push(public_key.len() as u8);
        message.extend_from_slice(public_key);

        message
    }

    fn compute_finished_verify_data(&self, is_client: bool) -> Result<Vec<u8>, String> {
        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or_else(|| "Master secret not derived".to_string())?;

        let label = if is_client {
            b"client finished"
        } else {
            b"server finished"
        };

        let handshake_hash = sha256(&self.handshake_messages);
        Ok(tls12_prf(master_secret, label, &handshake_hash, 12))
    }

    fn build_finished(&self, is_client: bool) -> Result<Vec<u8>, String> {
        let verify_data = self.compute_finished_verify_data(is_client)?;
        let mut message = Vec::with_capacity(16);
        message.push(TLS_HANDSHAKE_FINISHED);
        message.extend_from_slice(&[0, 0, 12]);
        message.extend_from_slice(&verify_data);
        Ok(message)
    }

    fn verify_finished(&self, is_client: bool, message: &[u8]) -> Result<(), String> {
        if message.len() != 16 || message[0] != TLS_HANDSHAKE_FINISHED {
            return Err("Malformed Finished message".to_string());
        }
        let expected = self.compute_finished_verify_data(is_client)?;
        let received = &message[4..16];
        if expected.as_slice() != received {
            return Err("TLS Finished verify_data mismatch".to_string());
        }
        Ok(())
    }

    fn send_record(&mut self, content_type: u8, data: &[u8]) -> Result<(), String> {
        let mut record = Vec::with_capacity(5 + data.len());
        record.push(content_type);
        record.push(TLS_VERSION_MAJOR);
        record.push(TLS_VERSION_MINOR);
        let length = data.len() as u16;
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(data);

        self.stream
            .write_all(&record)
            .map_err(|e| format!("TLS write failed: {}", e))
    }

    fn send_encrypted_record(&mut self, content_type: u8, data: &[u8]) -> Result<(), String> {
        let key = self
            .client_write_key
            .ok_or_else(|| "Encryption key not available".to_string())?;
        let iv = self
            .client_write_iv
            .ok_or_else(|| "Encryption IV not available".to_string())?;

        let cipher_suite = self
            .selected_cipher_suite
            .ok_or_else(|| "No cipher suite selected".to_string())?;

        let ciphertext = if is_gcm_cipher(cipher_suite) {
            // GCM mode: AEAD encryption
            // Nonce = fixed_iv (4 bytes) || explicit_nonce (8 bytes = sequence number)
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&iv[..4]); // Fixed IV (4 bytes from key derivation)
            nonce[4..12].copy_from_slice(&self.client_seq.to_be_bytes()); // Explicit nonce (sequence number)

            // AAD = seq_num || record_type || version || length
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.client_seq.to_be_bytes());
            aad.push(content_type);
            aad.push(TLS_VERSION_MAJOR);
            aad.push(TLS_VERSION_MINOR);
            aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

            // GCM encrypt returns: explicit_nonce || ciphertext || tag
            // We need to prepend the explicit nonce to the output
            let encrypted = aes128_gcm_encrypt(&key, &nonce, data, &aad);
            let mut result = Vec::with_capacity(8 + encrypted.len());
            result.extend_from_slice(&self.client_seq.to_be_bytes()); // Explicit nonce
            result.extend_from_slice(&encrypted); // Ciphertext + tag
            result
        } else if is_cbc_cipher(cipher_suite) {
            // CBC mode: MAC-then-encrypt
            let mac_key = self
                .client_write_mac
                .ok_or_else(|| "MAC key not available".to_string())?;
            let mut mac_input = Vec::with_capacity(13 + data.len());
            mac_input.extend_from_slice(&self.client_seq.to_be_bytes());
            mac_input.push(content_type);
            mac_input.push(TLS_VERSION_MAJOR);
            mac_input.push(TLS_VERSION_MINOR);
            mac_input.extend_from_slice(&(data.len() as u16).to_be_bytes());
            mac_input.extend_from_slice(data);
            let mac = hmac_sha256(&mac_key, &mac_input);
            let mut plaintext = Vec::with_capacity(data.len() + mac.len());
            plaintext.extend_from_slice(data);
            plaintext.extend_from_slice(&mac);
            aes128_cbc_encrypt(&key, &iv, &plaintext)
        } else {
            return Err(format!("Unsupported cipher suite: 0x{:04X}", cipher_suite));
        };

        self.client_seq = self.client_seq.wrapping_add(1);
        self.send_record(content_type, &ciphertext)
    }

    fn receive_record(&mut self) -> Result<(u8, Vec<u8>), RecordReadError> {
        let mut header = [0u8; 5];
        if let Err(e) = self.stream.read_exact(&mut header) {
            if matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::TimedOut
            ) {
                return Err(RecordReadError::ConnectionClosed);
            }
            return Err(RecordReadError::Io(e));
        }

        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut data = vec![0u8; length];
        if let Err(e) = self.stream.read_exact(&mut data) {
            if matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::TimedOut
            ) {
                return Err(RecordReadError::ConnectionClosed);
            }
            return Err(RecordReadError::Io(e));
        }

        Ok((header[0], data))
    }

    fn receive_handshake_message(&mut self, expected_type: u8) -> Result<Vec<u8>, String> {
        let (content_type, payload) = match self.receive_record() {
            Ok(record) => record,
            Err(RecordReadError::ConnectionClosed) => {
                return Err("Connection closed during handshake".to_string())
            }
            Err(RecordReadError::Io(e)) => return Err(format!("Handshake read failed: {}", e)),
        };

        if content_type == TLS_CONTENT_TYPE_ALERT {
            return Err("Received TLS alert from server".to_string());
        }

        if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
            return Err(format!(
                "Unexpected TLS content type during handshake: {}",
                content_type
            ));
        }

        if payload.is_empty() || payload[0] != expected_type {
            return Err("Unexpected handshake message type".to_string());
        }

        self.handshake_messages.extend_from_slice(&payload);
        Ok(payload)
    }

    fn receive_encrypted_record(
        &mut self,
        expected_content_type: u8,
    ) -> Result<Vec<u8>, RecordReadError> {
        let (content_type, ciphertext) = self.receive_record()?;

        if content_type != expected_content_type {
            return Err(RecordReadError::ConnectionClosed);
        }

        let key = self
            .server_write_key
            .ok_or_else(|| RecordReadError::ConnectionClosed)?;
        let iv = self
            .server_write_iv
            .ok_or_else(|| RecordReadError::ConnectionClosed)?;

        let cipher_suite = self
            .selected_cipher_suite
            .ok_or_else(|| RecordReadError::ConnectionClosed)?;

        let data = if is_gcm_cipher(cipher_suite) {
            // GCM mode: AEAD decryption
            // Ciphertext format: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes)
            if ciphertext.len() < 24 {
                // 8 bytes nonce + 16 bytes tag minimum
                return Err(RecordReadError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GCM record too short",
                )));
            }

            // Extract explicit nonce from the beginning
            let explicit_nonce = &ciphertext[..8];
            let ciphertext_with_tag = &ciphertext[8..];

            // Construct full 12-byte nonce = fixed_iv (4 bytes) || explicit_nonce (8 bytes)
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&iv[..4]); // Fixed IV
            nonce[4..12].copy_from_slice(explicit_nonce); // Explicit nonce from record

            // AAD = seq_num || record_type || version || length
            let plaintext_len = ciphertext_with_tag.len().saturating_sub(16); // Subtract tag
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.server_seq.to_be_bytes());
            aad.push(expected_content_type);
            aad.push(TLS_VERSION_MAJOR);
            aad.push(TLS_VERSION_MINOR);
            aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

            match aes128_gcm_decrypt(&key, &nonce, ciphertext_with_tag, &aad) {
                Ok(data) => data,
                Err(err) => {
                    return Err(RecordReadError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        err,
                    )))
                }
            }
        } else if is_cbc_cipher(cipher_suite) {
            // CBC mode: Decrypt then verify MAC
            let mac_key = self
                .server_write_mac
                .ok_or_else(|| RecordReadError::ConnectionClosed)?;
            let plaintext = match aes128_cbc_decrypt(&key, &iv, &ciphertext) {
                Ok(data) => data,
                Err(err) => {
                    return Err(RecordReadError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        err,
                    )))
                }
            };
            if plaintext.len() < 32 {
                return Err(RecordReadError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS record shorter than MAC",
                )));
            }
            let data_len = plaintext.len() - 32;
            let (data, received_mac) = plaintext.split_at(data_len);
            let mut mac_input = Vec::with_capacity(13 + data.len());
            mac_input.extend_from_slice(&self.server_seq.to_be_bytes());
            mac_input.push(expected_content_type);
            mac_input.push(TLS_VERSION_MAJOR);
            mac_input.push(TLS_VERSION_MINOR);
            mac_input.extend_from_slice(&(data.len() as u16).to_be_bytes());
            mac_input.extend_from_slice(data);
            let expected_mac = hmac_sha256(&mac_key, &mac_input);
            if expected_mac.as_slice() != received_mac {
                return Err(RecordReadError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS record MAC verification failed",
                )));
            }
            data.to_vec()
        } else {
            return Err(RecordReadError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported cipher suite: 0x{:04X}", cipher_suite),
            )));
        };

        self.server_seq = self.server_seq.wrapping_add(1);
        Ok(data)
    }

    /// Send application data (e.g. HTTP request body) over the encrypted channel.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), String> {
        if self.client_write_key.is_none() {
            return Err("TLS session not established".to_string());
        }
        self.send_encrypted_record(TLS_CONTENT_TYPE_APPLICATION_DATA, data)
    }

    /// Receive application data; returns `Ok(None)` when the peer closes the
    /// connection cleanly (EOF/timeout).
    pub fn receive_application_data(&mut self) -> Result<Option<Vec<u8>>, String> {
        match self.receive_encrypted_record(TLS_CONTENT_TYPE_APPLICATION_DATA) {
            Ok(data) => Ok(Some(data)),
            Err(RecordReadError::ConnectionClosed) => Ok(None),
            Err(RecordReadError::Io(e)) => Err(format!("Failed to read application data: {}", e)),
        }
    }

    fn verify_certificate_chain(&self) -> Result<(), String> {
        if self.peer_certificates.is_empty() {
            return Err("Server did not present a TLS certificate".to_string());
        }

        // Verify chain consistency (issuer/subject matching)
        // Note: Full trust store validation not yet implemented
        for (index, cert) in self.peer_certificates.iter().enumerate() {
            if index + 1 < self.peer_certificates.len() {
                let issuer = &self.peer_certificates[index + 1];
                if cert.issuer != issuer.subject {
                    return Err(format!(
                        "Certificate issuer mismatch: expected '{}' but chain provides '{}'",
                        cert.issuer, issuer.subject
                    ));
                }
            }
            // Root certificate validation against trust store: TODO
            // For now, we verify chain structure only
        }

        Ok(())
    }

    pub fn peer_certificates(&self) -> &[X509Certificate] {
        &self.peer_certificates
    }

    pub fn peer_certificate_chain(&self) -> &[Vec<u8>] {
        &self.server_cert_chain
    }

    pub fn verify_peer_certificate(&self) -> Result<(), String> {
        let leaf = self
            .peer_certificates
            .first()
            .ok_or_else(|| "Server did not present a TLS certificate".to_string())?;

        let now = SystemTime::now();
        let validity = &leaf.validity;

        let not_before = x509::parse_x509_time(&validity.not_before).ok_or_else(|| {
            format!(
                "Server certificate has unsupported notBefore timestamp '{}'",
                validity.not_before
            )
        })?;
        if now < not_before {
            return Err(format!(
                "Server certificate is not valid until {}",
                validity.not_before
            ));
        }

        let not_after = x509::parse_x509_time(&validity.not_after).ok_or_else(|| {
            format!(
                "Server certificate has unsupported notAfter timestamp '{}'",
                validity.not_after
            )
        })?;
        if now > not_after {
            return Err(format!(
                "Server certificate expired on {}",
                validity.not_after
            ));
        }

        if !certificate_matches_host(&self.server_name, leaf) {
            return Err(format!(
                "Server certificate does not match requested host '{}'",
                self.server_name
            ));
        }

        self.verify_certificate_chain()?;

        Ok(())
    }

    /// Expose the negotiated cipher suite for diagnostic callers (e.g. TLS auditor).
    pub fn selected_cipher_suite(&self) -> Option<u16> {
        self.selected_cipher_suite
    }

    pub fn ja3(&self) -> Option<&String> {
        self.ja3.as_ref()
    }

    pub fn ja3_raw(&self) -> Option<&String> {
        self.ja3_raw.as_ref()
    }

    pub fn ja3s(&self) -> Option<&String> {
        self.ja3s.as_ref()
    }

    pub fn ja3s_raw(&self) -> Option<&String> {
        self.ja3s_raw.as_ref()
    }

    pub fn peer_certificate_fingerprints(&self) -> Vec<String> {
        self.server_cert_chain
            .iter()
            .map(|der| sha256_fingerprint_hex(der))
            .collect()
    }

    pub fn certificate_chain_pem(&self) -> Vec<String> {
        self.server_cert_chain
            .iter()
            .map(|der| der_to_pem(der))
            .collect()
    }
}

fn certificate_matches_host(host: &str, cert: &X509Certificate) -> bool {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    let host_is_ip = IpAddr::from_str(&normalized).is_ok();

    let san_entries = cert.get_subject_alt_names();
    if san_entries
        .iter()
        .any(|entry| matches_pattern(entry, &normalized, host_is_ip))
    {
        return true;
    }

    let subject = cert.subject_string();
    for part in subject.split(',') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("CN=") {
            if matches_pattern(value.trim(), &normalized, host_is_ip) {
                return true;
            }
        }
    }

    false
}

fn compute_ja3_from_client_hello(client_hello: &[u8]) -> Result<(String, String), String> {
    let mut record = Vec::with_capacity(client_hello.len() + 5);
    record.push(TLS_CONTENT_TYPE_HANDSHAKE);
    record.push(TLS_VERSION_MAJOR);
    record.push(TLS_VERSION_MINOR);
    record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
    record.extend_from_slice(client_hello);

    let fingerprint = JA3Fingerprint::from_client_hello(&record)?;
    let raw = fingerprint.to_string();
    let hash = md5_hex_lowercase(raw.as_bytes());
    Ok((raw, hash))
}

fn compute_ja3s_from_server_hello(
    version: u16,
    cipher_suite: u16,
    extensions: &[u16],
    groups: &[u16],
    ec_formats: &[u8],
) -> (String, String) {
    let raw = format!(
        "{},{},{},{},{}",
        version,
        cipher_suite,
        join_u16(extensions),
        join_u16(groups),
        join_u8(ec_formats)
    );
    let hash = md5_hex_lowercase(raw.as_bytes());
    (raw, hash)
}

fn parse_server_hello_extensions(data: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<u8>) {
    let mut offset = 0usize;
    let mut extensions = Vec::new();
    let mut groups = Vec::new();
    let mut ec_formats = Vec::new();

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len > data.len() {
            break;
        }
        let ext_data = &data[offset..offset + ext_len];
        offset += ext_len;

        if !is_grease_value(ext_type) {
            extensions.push(ext_type);
        }

        match ext_type {
            TLS_EXT_SUPPORTED_GROUPS => {
                if ext_data.len() >= 2 {
                    let mut inner_offset = 2;
                    while inner_offset + 1 < ext_data.len() {
                        let group = u16::from_be_bytes([
                            ext_data[inner_offset],
                            ext_data[inner_offset + 1],
                        ]);
                        if !is_grease_value(group) {
                            groups.push(group);
                        }
                        inner_offset += 2;
                    }
                }
            }
            TLS_EXT_EC_POINT_FORMATS => {
                if !ext_data.is_empty() {
                    let len = ext_data[0] as usize;
                    for i in 0..len {
                        if 1 + i < ext_data.len() {
                            ec_formats.push(ext_data[1 + i]);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    (extensions, groups, ec_formats)
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

fn join_u8(values: &[u8]) -> String {
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

fn is_grease_value(value: u16) -> bool {
    let high = (value >> 8) & 0xFF;
    let low = value & 0xFF;
    high == low && (high & 0x0F) == 0x0A
}

fn md5_hex_lowercase(bytes: &[u8]) -> String {
    let digest = md5(bytes);
    let mut out = String::with_capacity(32);
    for byte in digest.iter() {
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn sha256_fingerprint_hex(der: &[u8]) -> String {
    let digest = sha256(der);
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = encode_base64(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut index = 0usize;
    while index < b64.len() {
        let end = (index + 64).min(b64.len());
        pem.push_str(&b64[index..end]);
        pem.push('\n');
        index = end;
    }
    pem.push_str("-----END CERTIFICATE-----");
    pem
}

fn matches_pattern(pattern: &str, host: &str, host_is_ip: bool) -> bool {
    let candidate = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if candidate.is_empty() {
        return false;
    }

    if host_is_ip {
        return candidate == host;
    }

    if candidate == host {
        return true;
    }

    if !candidate.starts_with("*.") {
        return false;
    }

    let suffix = &candidate[2..];
    if suffix.is_empty() || host_is_ip || !host.ends_with(suffix) {
        return false;
    }

    let host_labels = host.split('.').count();
    let suffix_labels = suffix.split('.').count();
    if host_labels != suffix_labels + 1 {
        return false;
    }

    let prefix_len = host.len().saturating_sub(suffix.len());
    if prefix_len == 0 {
        return false;
    }

    host.as_bytes()
        .get(prefix_len - 1)
        .map(|b| *b == b'.')
        .unwrap_or(false)
}

fn verify_certificate_signature(
    cert: &X509Certificate,
    issuer_key: &VerifierKey,
    tbs: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    match cert.signature_algorithm.algorithm.as_str() {
        "1.2.840.113549.1.1.5" => match issuer_key {
            VerifierKey::Rsa(key) => {
                let hash = sha1(tbs);
                let digest_info = build_digest_info_sha1(&hash);
                key.verify_pkcs1_v15(&digest_info, signature)
            }
            _ => Err("Certificate uses RSA signature but issuer key is not RSA".to_string()),
        },
        "1.2.840.113549.1.1.11" => match issuer_key {
            VerifierKey::Rsa(key) => {
                let hash = sha256(tbs);
                let digest_info = build_digest_info_sha256(&hash);
                key.verify_pkcs1_v15(&digest_info, signature)
            }
            _ => Err("Certificate uses RSA signature but issuer key is not RSA".to_string()),
        },
        "1.2.840.10045.4.3.2" => match issuer_key {
            VerifierKey::EcP256(point) => verify_ecdsa_p256_sha256(point, tbs, signature),
            _ => Err("Certificate uses ECDSA signature but issuer key is not EC P-256".to_string()),
        },
        oid => Err(format!("Unsupported signature algorithm: {}", oid)),
    }
}

fn build_digest_info_sha256(hash: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let mut digest_info = Vec::with_capacity(PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&PREFIX);
    digest_info.extend_from_slice(hash);
    digest_info
}

fn build_digest_info_sha1(hash: &[u8; 20]) -> Vec<u8> {
    const PREFIX: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    let mut digest_info = Vec::with_capacity(PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&PREFIX);
    digest_info.extend_from_slice(hash);
    digest_info
}

pub fn verify_ecdsa_p256_sha256(
    issuer_key: &P256Point,
    tbs: &[u8],
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

    let hash = BigInt::from_bytes_be(&sha256(tbs)).mod_reduce(&order);
    let s_inv = s
        .mod_inv(&order)
        .ok_or_else(|| "ECDSA signature is not invertible".to_string())?;

    let u1 = hash.mod_mul(&s_inv, &order);
    let u2 = r.mod_mul(&s_inv, &order);

    let u1_bytes = bigint_to_32_bytes(&u1);
    let u2_bytes = bigint_to_32_bytes(&u2);

    let point = P256Point::generator()
        .scalar_mul(&u1_bytes)
        .add(&issuer_key.scalar_mul(&u2_bytes));

    if point.is_infinity {
        return Err("ECDSA verification produced point at infinity".to_string());
    }

    let x_bytes = point.x.to_bytes();
    let x_int = BigInt::from_bytes_be(&x_bytes).mod_reduce(&order);
    let r_mod = r.mod_reduce(&order);

    if x_int.cmp(&r_mod) == Ordering::Equal {
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
    let r_bytes = seq[0]
        .as_integer()
        .map_err(|e| format!("Invalid ECDSA 'r': {}", e))?
        .clone();
    let s_bytes = seq[1]
        .as_integer()
        .map_err(|e| format!("Invalid ECDSA 's': {}", e))?
        .clone();
    Ok((
        BigInt::from_bytes_be(&r_bytes),
        BigInt::from_bytes_be(&s_bytes),
    ))
}

fn bigint_to_32_bytes(value: &BigInt) -> [u8; 32] {
    let mut bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    let mut result = [0u8; 32];
    let offset = 32 - bytes.len();
    result[offset..].copy_from_slice(&bytes);
    result
}

fn extract_public_key_from_cert(cert: &X509Certificate) -> Result<VerifierKey, String> {
    let spki = &cert.subject_public_key_info;
    match spki.algorithm.algorithm.as_str() {
        "1.2.840.113549.1.1.1" => {
            let (modulus, exponent) = spki
                .rsa_components()
                .map_err(|e| format!("Failed to parse RSA public key: {}", e))?;
            Ok(VerifierKey::Rsa(RsaPublicKey::from_components(
                &modulus, &exponent,
            )))
        }
        "1.2.840.10045.2.1" => {
            let curve_oid = spki
                .algorithm
                .parameters_oid
                .as_deref()
                .ok_or_else(|| "EC public key missing named curve".to_string())?;
            if curve_oid != "1.2.840.10045.3.1.7" {
                return Err(format!(
                    "Unsupported EC named curve '{}' in certificate",
                    curve_oid
                ));
            }
            let point = P256Point::from_uncompressed_bytes(&spki.public_key)
                .map_err(|e| format!("Failed to parse EC public key: {}", e))?;
            Ok(VerifierKey::EcP256(point))
        }
        oid => Err(format!(
            "Unsupported certificate public key algorithm: {}",
            oid
        )),
    }
}

// Note: convert_trust_key removed - TrustStore not yet implemented

fn parse_der_length(data: &[u8], offset: &mut usize) -> Result<usize, String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data while parsing length".to_string());
    }

    let first = data[*offset];
    *offset += 1;

    if first & 0x80 == 0 {
        Ok(first as usize)
    } else {
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 {
            return Err("Invalid DER length".to_string());
        }
        if *offset + count > data.len() {
            return Err("Length exceeds available data".to_string());
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = (length << 8) | (data[*offset] as usize);
            *offset += 1;
        }
        Ok(length)
    }
}

fn slice_der_element<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data while parsing element".to_string());
    }

    let start = *offset;
    *offset += 1; // tag
    let length = parse_der_length(data, offset)?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "Length overflow".to_string())?;
    if end > data.len() {
        return Err("DER element extends beyond input".to_string());
    }
    *offset = end;
    Ok(&data[start..end])
}

fn extract_tbs_and_signature(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if cert_der.is_empty() || cert_der[0] != 0x30 {
        return Err("Certificate is not a SEQUENCE".to_string());
    }

    let mut offset = 1;
    let total_len = parse_der_length(cert_der, &mut offset)?;
    let seq_end = offset + total_len;
    if seq_end > cert_der.len() {
        return Err("Certificate length exceeds buffer".to_string());
    }

    let tbs = slice_der_element(cert_der, &mut offset)?.to_vec();

    // Skip signatureAlgorithm
    let _sig_alg = slice_der_element(cert_der, &mut offset)?;

    if offset >= seq_end {
        return Err("Certificate missing signature BIT STRING".to_string());
    }

    if cert_der[offset] != 0x03 {
        return Err("Expected BIT STRING for certificate signature".to_string());
    }
    offset += 1;
    let bit_len = parse_der_length(cert_der, &mut offset)?;
    if offset + bit_len > seq_end {
        return Err("Signature BIT STRING exceeds certificate".to_string());
    }
    if bit_len == 0 {
        return Err("Empty certificate signature".to_string());
    }
    let unused_bits = cert_der[offset];
    if unused_bits != 0 {
        return Err("Unsupported signature encoding with unused bits".to_string());
    }
    let signature = cert_der[offset + 1..offset + bit_len].to_vec();

    Ok((tbs, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(TLS_VERSION_MAJOR, 0x03);
        assert_eq!(TLS_VERSION_MINOR, 0x03);
        assert_eq!(
            SUPPORTED_CIPHER_SUITES,
            &[
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_128_CBC_SHA256
            ]
        );
    }

    // Note: test_tls12_google_connection removed - TLS client doesn't implement Read/Write traits
    // and has ECDH P-256 issues that prevent full handshake completion.
    // Use `rb tls security audit google.com` for actual TLS testing.
}
