//! TLS helper functions
//!
//! Utility functions for TLS operations - record wrapping, MAC computation, crypto helpers.

use super::types::{ContentType, HandshakeType, MacAlgorithm, P256_ORDER_BYTES};
use crate::crypto::hmac::{hmac_sha1, hmac_sha256};
use crate::crypto::prf::Tls12PrfAlgorithm;
use crate::crypto::sha256;
use crate::crypto::sha384;
use crate::crypto::BigInt;
use crate::protocols::asn1::Asn1Object;
use crate::protocols::p256::P256Point;

/// Wrap data in TLS record
pub fn wrap_tls_record(content_type: ContentType, data: &[u8], version: (u8, u8)) -> Vec<u8> {
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
pub fn wrap_handshake(msg_type: HandshakeType, data: &[u8]) -> Vec<u8> {
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

/// Compute record MAC for TLS 1.2 CBC suites
pub fn compute_record_mac(
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

/// Constant-time comparison for MAC verification
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  let mut diff = 0u8;
  for (x, y) in a.iter().zip(b.iter()) {
    diff |= x ^ y;
  }
  diff == 0
}

/// Generate P256 keypair for ECDHE
pub fn generate_p256_keypair() -> ([u8; 32], Vec<u8>) {
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

/// Compute P256 shared secret
pub fn compute_p256_shared_secret(private: &[u8; 32], peer: &P256Point) -> [u8; 32] {
  peer.scalar_mul(private).x.to_bytes()
}

/// Check if scalar is zero
pub fn scalar_is_zero(scalar: &[u8; 32]) -> bool {
  scalar.iter().all(|&b| b == 0)
}

/// Check if scalar is less than P256 curve order
pub fn scalar_is_less_than_order(scalar: &[u8; 32]) -> bool {
  for (a, b) in scalar.iter().zip(P256_ORDER_BYTES.iter()) {
    if a < b {
      return true;
    } else if a > b {
      return false;
    }
  }
  false
}

/// Compute TLS 1.2 handshake hash
pub fn tls12_handshake_hash(messages: &[u8], hash: Tls12PrfAlgorithm) -> Vec<u8> {
  match hash {
    Tls12PrfAlgorithm::Sha256 => sha256::sha256(messages).to_vec(),
    Tls12PrfAlgorithm::Sha384 => sha384::sha384(messages).to_vec(),
  }
}

/// Generate a random byte (simple PRNG)
pub fn rand_byte() -> u8 {
  use std::time::SystemTime;

  let nanos = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap()
    .as_nanos();

  ((nanos >> 8) ^ nanos) as u8
}

/// Clamp X25519 scalar per RFC 7748
pub fn clamp_x25519_scalar(scalar: &mut [u8; 32]) {
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
}

/// Generate 32 random bytes
pub fn generate_random_32() -> [u8; 32] {
  let mut random = [0u8; 32];
  for byte in &mut random {
    *byte = rand_byte();
  }
  random
}

/// Generate n random bytes
pub fn generate_random_bytes(n: usize) -> Vec<u8> {
  let mut random = vec![0u8; n];
  for byte in &mut random {
    *byte = rand_byte();
  }
  random
}

/// Parse ECDSA signature from DER format
pub fn parse_ecdsa_signature(signature: &[u8]) -> Result<(BigInt, BigInt), String> {
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

/// Convert BigInt to 32-byte array
pub fn bigint_to_32_bytes(value: &BigInt) -> [u8; 32] {
  let mut bytes = value.to_bytes_be();
  if bytes.len() > 32 {
    bytes = bytes[bytes.len() - 32..].to_vec();
  }
  let mut out = [0u8; 32];
  let start = 32 - bytes.len();
  out[start..].copy_from_slice(&bytes);
  out
}

/// Build TLS 1.3 CertificateVerify input
pub fn build_tls13_certificate_verify_input(context: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
  let mut input = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
  input.extend(std::iter::repeat(0x20).take(64));
  input.extend_from_slice(context);
  input.push(0x00);
  input.extend_from_slice(transcript_hash);
  input
}

/// Build DigestInfo for SHA-256 (PKCS#1 v1.5 signature verification)
pub fn build_digest_info_sha256(hash: &[u8]) -> Vec<u8> {
  if hash.len() != 32 {
    return Vec::new();
  }
  const PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
  ];
  let mut digest_info = Vec::with_capacity(PREFIX.len() + hash.len());
  digest_info.extend_from_slice(&PREFIX);
  digest_info.extend_from_slice(hash);
  digest_info
}

/// Build DigestInfo for SHA-384 (PKCS#1 v1.5 signature verification)
pub fn build_digest_info_sha384(hash: &[u8]) -> Vec<u8> {
  if hash.len() != 48 {
    return Vec::new();
  }
  const PREFIX: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
  ];
  let mut digest_info = Vec::with_capacity(PREFIX.len() + hash.len());
  digest_info.extend_from_slice(&PREFIX);
  digest_info.extend_from_slice(hash);
  digest_info
}
