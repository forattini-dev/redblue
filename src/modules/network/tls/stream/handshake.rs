//! Common handshake functions for TLS 1.2 and TLS 1.3
//!
//! These functions are shared between TLS versions:
//! - `send_client_hello`: Build and send ClientHello with extensions
//! - `receive_server_hello`: Parse ServerHello response

use super::super::cipher::cipher_suite_id;
use super::super::extensions::{
  build_ec_point_formats_extension, build_signature_algorithms_extension, build_sni_extension,
  build_supported_groups_extension, build_supported_versions_extension,
  build_tls13_key_share_extension,
};
use super::super::helpers::wrap_handshake;
use super::super::types::{ContentType, HandshakeType, TlsVersion};

use super::TlsStream;

impl TlsStream {
  /// Send ClientHello message
  ///
  /// Builds the ClientHello handshake message with:
  /// - Protocol version
  /// - Client random (32 bytes)
  /// - Cipher suites (from config)
  /// - Extensions (SNI, signature algorithms, supported groups, etc.)
  /// - TLS 1.3 specific: supported_versions, key_share
  pub(super) fn send_client_hello(&mut self, host: &str) -> Result<(), String> {
    let mut hello = Vec::new();

    // TLS version (configurable)
    let (version_major, version_minor) = self.config.version.to_bytes();
    hello.push(version_major);
    hello.push(version_minor);

    // Random (32 bytes)
    hello.extend_from_slice(&self.client_random);

    // Session ID (empty)
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
      extensions.extend_from_slice(&build_signature_algorithms_extension());
    }

    // Elliptic curves and point formats for ECDHE
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

    // Add to handshake transcript
    self.handshake_messages.extend_from_slice(&handshake);

    // Wrap in TLS record
    self.send_record(ContentType::Handshake, &handshake, false)?;

    Ok(())
  }

  /// Receive ServerHello (TLS 1.2)
  ///
  /// Parses the ServerHello handshake message and extracts:
  /// - Server random (32 bytes)
  /// - Session ID length
  /// - Selected cipher suite
  pub(super) fn receive_server_hello(&mut self) -> Result<Vec<u8>, String> {
    use super::super::cipher::cipher_suite_from_id;

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

    // Add to handshake transcript
    self.handshake_messages.extend_from_slice(&record);

    if record.len() < 38 {
      return Err("ServerHello too short".to_string());
    }

    // Extract server_random (offset 6, 32 bytes)
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&record[6..38]);
    self.server_random = Some(server_random);

    // Extract session ID length
    let session_id_len = record[38] as usize;

    if record.len() < 38 + 1 + session_id_len + 2 {
      return Err("ServerHello too short for cipher suite".to_string());
    }

    // Extract cipher suite
    let cipher_offset = 39 + session_id_len;
    let cipher_id = u16::from_be_bytes([record[cipher_offset], record[cipher_offset + 1]]);

    let cipher = cipher_suite_from_id(cipher_id)?;
    self.negotiated_cipher_suite = Some(cipher);

    Ok(record)
  }
}
