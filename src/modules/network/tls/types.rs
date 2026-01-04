//! TLS types and configuration
//!
//! Contains all the basic types, enums, and configuration structs for TLS.

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
    pub fn to_bytes(self) -> (u8, u8) {
        match self {
            TlsVersion::Tls10 => (0x03, 0x01),
            TlsVersion::Tls11 => (0x03, 0x02),
            TlsVersion::Tls12 => (0x03, 0x03),
            TlsVersion::Tls13 => (0x03, 0x03),
        }
    }

    pub fn record_version(self) -> (u8, u8) {
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
    TlsRsaWithAes128CbcSha,
    TlsRsaWithAes256CbcSha,
    TlsEcdheRsaWithAes128GcmSha256,
    TlsEcdheRsaWithAes256GcmSha384,
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
}

/// Key exchange algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchange {
    Rsa,
    Ecdhe,
}

use crate::protocols::p256::P256Point;

/// ECDHE parameters from ServerKeyExchange
pub enum EcdheParameters {
    P256 { server_public: P256Point },
    X25519 { server_public: [u8; 32] },
}

/// TLS 1.3 named groups
#[derive(Debug, Clone, Copy)]
pub enum Tls13NamedGroup {
    X25519 = 0x001D,
}

impl Tls13NamedGroup {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// TLS 1.3 client key share
#[allow(dead_code)]
pub struct Tls13ClientKeyShare {
    pub group: Tls13NamedGroup,
    pub private_key: [u8; 32],
    pub public_key: Vec<u8>,
}

/// TLS 1.3 new session ticket
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Tls13NewSessionTicket {
    pub lifetime: u32,
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub extensions: Vec<u8>,
}

/// MAC algorithm
#[derive(Debug, Clone, Copy)]
pub enum MacAlgorithm {
    Sha1,
    Sha256,
}

impl MacAlgorithm {
    pub fn mac_len(self) -> usize {
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
            verify_cert: true,
            cipher_suites: vec![
                CipherSuite::TlsEcdheRsaWithAes256GcmSha384,
                CipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                CipherSuite::TlsRsaWithAes128CbcSha,
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
                CipherSuite::TlsAes128GcmSha256,
                CipherSuite::TlsAes256GcmSha384,
                CipherSuite::TlsEcdheRsaWithAes256GcmSha384,
                CipherSuite::TlsEcdheRsaWithAes128GcmSha256,
            ],
            TlsVersion::Tls12 => vec![
                CipherSuite::TlsEcdheRsaWithAes256GcmSha384,
                CipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                CipherSuite::TlsRsaWithAes128CbcSha,
            ],
            TlsVersion::Tls11 | TlsVersion::Tls10 => {
                vec![CipherSuite::TlsRsaWithAes128CbcSha]
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

/// TLS content type
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn from_u8(val: u8) -> Option<ContentType> {
        match val {
            20 => Some(ContentType::ChangeCipherSpec),
            21 => Some(ContentType::Alert),
            22 => Some(ContentType::Handshake),
            23 => Some(ContentType::ApplicationData),
            _ => None,
        }
    }
}

/// TLS handshake type
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
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
    pub fn from_u8(val: u8) -> Option<HandshakeType> {
        match val {
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            4 => Some(HandshakeType::NewSessionTicket),
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

/// P256 curve order bytes for scalar validation
pub const P256_ORDER_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// TLS 1.3 server certificate verify context
pub const TLS13_SERVER_CERT_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
