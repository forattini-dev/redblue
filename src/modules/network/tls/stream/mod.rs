//! TlsStream implementation
//!
//! Core TLS stream implementing TLS 1.2/1.3 handshake and encrypted data transfer.
//! Implements std::io::Read and std::io::Write for transparent encrypted I/O.
//!
//! # Architecture
//!
//! The TLS stream is organized into submodules:
//! - **handshake**: Common handshake functions (ClientHello, ServerHello)
//! - **tls12**: TLS 1.2 specific handshake handlers
//! - **tls13**: TLS 1.3 specific handshake handlers
//! - **record**: Record layer encryption/decryption
//! - **io**: Read/Write trait implementations
//!
//! # Example
//!
//! ```ignore
//! use redblue::modules::network::tls::TlsStream;
//! use redblue::modules::network::tls::TlsConfig;
//!
//! let config = TlsConfig::default();
//! let mut stream = TlsStream::connect("example.com", 443, config)?;
//!
//! // Use std::io::Read and std::io::Write
//! stream.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?;
//! let mut response = Vec::new();
//! stream.read_to_end(&mut response)?;
//! ```

mod handshake;
mod io;
mod record;
mod tls12;
mod tls13;

use super::helpers::{bigint_to_32_bytes, generate_random_32};
use super::types::{
  CipherSuite, EcdheParameters, Tls13ClientKeyShare, Tls13NewSessionTicket, TlsConfig, TlsVersion,
  P256_ORDER_BYTES,
};

use crate::crypto::sha256;
use crate::crypto::tls13_keyschedule::Tls13KeySchedule;
use crate::crypto::BigInt;
use crate::protocols::p256::P256Point;
use crate::protocols::x509::X509Certificate;

use std::cmp::Ordering;
use std::net::TcpStream;

/// TLS stream wrapper providing encrypted I/O
///
/// Holds all state required for TLS encryption:
/// - Connection state (handshake complete, encryption active)
/// - Cryptographic keys and IVs
/// - Sequence numbers for record layer
/// - Handshake transcript
pub struct TlsStream {
  pub(super) stream: TcpStream,
  pub(super) config: TlsConfig,
  pub(super) server_name: String,
  pub(super) handshake_complete: bool,
  pub(super) read_buffer: Vec<u8>,
  pub(super) buffer_pos: usize,

  // Client random value
  pub(super) client_random: [u8; 32],

  // Server parameters from ServerHello
  pub(super) server_random: Option<[u8; 32]>,
  pub(super) negotiated_cipher_suite: Option<CipherSuite>,

  // Server certificate
  pub(super) server_certificate: Option<Vec<u8>>,
  pub(super) server_x509: Option<X509Certificate>,

  // Key material
  pub(super) pre_master_secret: Option<Vec<u8>>,
  pub(super) master_secret: Option<[u8; 48]>,

  // Traffic keys
  pub(super) client_write_key: Option<Vec<u8>>,
  pub(super) server_write_key: Option<Vec<u8>>,
  pub(super) client_write_mac: Option<Vec<u8>>,
  pub(super) server_write_mac: Option<Vec<u8>>,
  pub(super) client_write_iv: Option<Vec<u8>>,
  pub(super) server_write_iv: Option<Vec<u8>>,

  // ECDHE parameters
  pub(super) ecdhe_params: Option<EcdheParameters>,

  // Encryption state
  pub(super) client_encryption_active: bool,
  pub(super) server_encryption_active: bool,
  pub(super) client_sequence: u64,
  pub(super) server_sequence: u64,

  // Handshake transcript for Finished message
  pub(super) handshake_messages: Vec<u8>,

  // TLS 1.3 specific state
  pub(super) tls13_client_key_share: Option<Tls13ClientKeyShare>,
  pub(super) tls13_key_schedule: Option<Tls13KeySchedule>,
  pub(super) tls13_certificate_request_context: Option<Vec<u8>>,
  #[allow(dead_code)]
  pub(super) tls13_new_session_tickets: Vec<Tls13NewSessionTicket>,
}

impl TlsStream {
  /// Get record layer version bytes
  ///
  /// TLS 1.3 uses TLS 1.0 (0x0301) for the record layer version for
  /// compatibility with middleboxes.
  pub(super) fn record_version(&self) -> (u8, u8) {
    self.config.version.record_version()
  }

  /// Format bytes as hex string for debugging
  fn debug_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
      out.push_str(&format!("{:02x}", byte));
    }
    out
  }

  /// Log debug information if debug mode is enabled
  pub(super) fn debug_log(&self, label: &str, data: &[u8]) {
    if self.config.debug {
      eprintln!("[tls12][debug] {}: {}", label, Self::debug_hex(data));
    }
  }

  /// Create new TLS stream (client mode)
  ///
  /// Establishes a TCP connection and performs the TLS handshake.
  ///
  /// # Arguments
  ///
  /// * `host` - Server hostname (used for SNI)
  /// * `port` - Server port
  /// * `config` - TLS configuration
  ///
  /// # Returns
  ///
  /// A connected and handshaked TLS stream ready for encrypted I/O.
  pub fn connect(host: &str, port: u16, config: TlsConfig) -> Result<Self, String> {
    let addr = format!("{}:{}", host, port);
    let stream =
      TcpStream::connect(&addr).map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

    stream
      .set_read_timeout(Some(config.timeout))
      .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    stream
      .set_write_timeout(Some(config.timeout))
      .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    let client_random = generate_random_32();

    let mut tls = Self {
      stream,
      config,
      server_name: host.to_string(),
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
  ///
  /// Dispatches to TLS 1.2 or TLS 1.3 handshake based on configuration.
  fn handshake(&mut self, host: &str) -> Result<(), String> {
    match self.config.version {
      TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 => self.handshake_tls12(host),
      TlsVersion::Tls13 => self.handshake_tls13(host),
    }
  }

  pub(super) fn verify_peer_certificate(&self) -> Result<(), String> {
    if !self.config.verify_cert {
      return Ok(());
    }

    let cert = self
      .server_x509
      .as_ref()
      .ok_or_else(|| "Server certificate not parsed for verification".to_string())?;
    cert.is_valid_at(std::time::SystemTime::now())?;

    if !cert.matches_host(&self.server_name) {
      return Err(format!(
        "Server certificate does not match requested host '{}'",
        self.server_name
      ));
    }

    Ok(())
  }
}

/// Verify ECDSA P-256 signature
///
/// Used for TLS 1.3 CertificateVerify message verification.
/// Implements ECDSA signature verification using P-256 curve.
///
/// # Arguments
///
/// * `point` - Public key point on P-256 curve
/// * `message` - Message that was signed
/// * `signature` - DER-encoded ECDSA signature (r, s)
pub(super) fn verify_ecdsa_p256_signature(
  point: &P256Point,
  message: &[u8],
  signature: &[u8],
) -> Result<(), String> {
  use super::helpers::parse_ecdsa_signature;

  let (r, s) = parse_ecdsa_signature(signature)?;
  let order = BigInt::from_bytes_be(&P256_ORDER_BYTES);

  // Validate r and s are in valid range
  if r.is_zero() || r.cmp(&order) != Ordering::Less {
    return Err("ECDSA signature 'r' out of range".to_string());
  }
  if s.is_zero() || s.cmp(&order) != Ordering::Less {
    return Err("ECDSA signature 's' out of range".to_string());
  }

  // Hash the message
  let hash_bytes = sha256::sha256(message);
  let hash = BigInt::from_bytes_be(&hash_bytes).mod_reduce(&order);

  // Compute s^-1 mod n
  let s_inv = s
    .mod_inv(&order)
    .ok_or_else(|| "ECDSA signature is not invertible".to_string())?;

  // Compute u1 = hash * s^-1 mod n
  // Compute u2 = r * s^-1 mod n
  let u1 = hash.mod_mul(&s_inv, &order);
  let u2 = r.mod_mul(&s_inv, &order);

  let u1_bytes = bigint_to_32_bytes(&u1);
  let u2_bytes = bigint_to_32_bytes(&u2);

  // Compute R = u1*G + u2*Q
  let generator = P256Point::generator();
  let point1 = generator.scalar_mul(&u1_bytes);
  let point2 = point.scalar_mul(&u2_bytes);
  let sum = point1.add(&point2);

  if sum.is_infinity {
    return Err("ECDSA verification produced point at infinity".to_string());
  }

  // Verify x coordinate of R equals r
  let x_bytes = sum.x.to_bytes();
  let x = BigInt::from_bytes_be(&x_bytes).mod_reduce(&order);
  let r_mod = r.mod_reduce(&order);

  if x.cmp(&r_mod) == Ordering::Equal {
    Ok(())
  } else {
    Err("ECDSA signature verification failed".to_string())
  }
}

// Re-export TlsStream for public API
pub use self::TlsStream as TlsStreamImpl;
