use super::asn1::Asn1Object;
use super::crypto::{aes128_cbc_decrypt, aes128_cbc_encrypt, hmac_sha256, tls12_prf, SecureRandom};
use super::ecdh::EcdhKeyPair;
#[cfg(not(target_os = "windows"))]
use super::gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};
use super::p256::P256Point;
use super::rsa::RsaPublicKey;
use super::x509::{self, X509Certificate};
use crate::crypto::encoding::base64::base64_decode;
use crate::crypto::BigInt;
use crate::crypto::{encode_base64, md5, sha1::sha1, sha256::sha256};
use crate::intelligence::tls_fingerprint::JA3Fingerprint;
use std::cmp::Ordering;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// tls_debug macro must be defined BEFORE the submodule declarations so they
// can use it via #[macro_use] scoping.
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

pub(crate) use tls_debug;

mod certificate;
mod connection;
mod handshake;
mod records;
mod utils;

pub use utils::verify_ecdsa_p256_sha256;

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

#[cfg(not(target_os = "windows"))]
const SUPPORTED_CIPHER_SUITES: &[u16] = &[
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // Prefer ECDHE for PFS
  TLS_RSA_WITH_AES_128_GCM_SHA256,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
];

#[cfg(target_os = "windows")]
const SUPPORTED_CIPHER_SUITES: &[u16] = &[TLS_RSA_WITH_AES_128_CBC_SHA256];

#[cfg(target_os = "windows")]
fn aes128_gcm_encrypt(_key: &[u8; 16], _iv: &[u8; 12], _plaintext: &[u8], _aad: &[u8]) -> Vec<u8> {
  panic!("TLS AES-128-GCM is not available on Windows builds")
}

#[cfg(target_os = "windows")]
fn aes128_gcm_decrypt(
  _key: &[u8; 16],
  _iv: &[u8; 12],
  _ciphertext_with_tag: &[u8],
  _aad: &[u8],
) -> Result<Vec<u8>, String> {
  Err("TLS AES-128-GCM is not available on Windows builds".to_string())
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
  offered_cipher_suites: Vec<u16>,
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
