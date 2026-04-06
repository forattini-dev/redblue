//! TLS extension building
//!
//! Functions for building TLS handshake extensions (SNI, signature algorithms, etc.)

use super::helpers::{clamp_x25519_scalar, generate_random_32};
use super::types::{Tls13ClientKeyShare, Tls13NamedGroup};
use crate::crypto::x25519::x25519_public_key;

/// Build SNI extension
pub fn build_sni_extension(host: &str) -> Vec<u8> {
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
pub fn build_signature_algorithms_extension() -> Vec<u8> {
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

/// Build supported_versions extension for TLS 1.3/1.2
pub fn build_supported_versions_extension() -> Vec<u8> {
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

/// Build TLS 1.3 key_share extension with X25519 public key
pub fn build_tls13_key_share_extension() -> (Vec<u8>, Tls13ClientKeyShare) {
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

/// Build supported_groups extension
pub fn build_supported_groups_extension() -> Vec<u8> {
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

/// Build ec_point_formats extension
pub fn build_ec_point_formats_extension() -> Vec<u8> {
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
