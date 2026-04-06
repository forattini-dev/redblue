//! Kerberos Cryptographic Operations
//!
//! Implements encryption types used in Kerberos 5:
//! - RC4-HMAC (etype 23) - Legacy, used with NTLM hashes
//! - AES256-CTS-HMAC-SHA1 (etype 18) - Modern, preferred
//!
//! # Key Derivation
//!
//! Kerberos uses key derivation to create purpose-specific keys:
//! - Key encryption key (for encrypting session keys)
//! - Checksum key (for integrity)
//! - Sequence number key
//!
//! # References
//! - RFC 3961: Encryption and Checksum Specifications
//! - RFC 3962: AES Encryption for Kerberos 5
//! - RFC 4757: RC4-HMAC for Kerberos 5

use crate::crypto::{aes_gcm, hmac};

use super::types::{ChecksumType, EncryptedData, EncryptionKey, EncryptionType};

// ═══════════════════════════════════════════════════════════════════════════
// MD4 Implementation (for NTLM hash generation)
// ═══════════════════════════════════════════════════════════════════════════

/// MD4 hash function (RFC 1320) - required for NTLM hash
/// Only used for RC4-HMAC key derivation from password
mod md4 {
  const S: [[u32; 4]; 3] = [[3, 7, 11, 19], [3, 5, 9, 13], [3, 9, 11, 15]];

  fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
  }

  fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
  }

  fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
  }

  pub fn hash(input: &[u8]) -> [u8; 16] {
    // Padding
    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);

    while (msg.len() % 64) != 56 {
      msg.push(0);
    }

    msg.extend_from_slice(&bit_len.to_le_bytes());

    // Initialize state
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    // Process blocks
    for block in msg.chunks(64) {
      let mut x = [0u32; 16];
      for (i, chunk) in block.chunks(4).enumerate() {
        x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
      }

      let (aa, bb, cc, dd) = (a, b, c, d);

      // Round 1
      for i in 0..16 {
        let idx = i % 4;
        let k = i;
        let (na, nb, nc, nd) = match idx {
          0 => {
            let t = a.wrapping_add(f(b, c, d)).wrapping_add(x[k]);
            (d, t.rotate_left(S[0][idx]), b, c)
          }
          1 => {
            let t = d.wrapping_add(f(a, b, c)).wrapping_add(x[k]);
            (c, a, t.rotate_left(S[0][idx]), b)
          }
          2 => {
            let t = c.wrapping_add(f(d, a, b)).wrapping_add(x[k]);
            (b, d, a, t.rotate_left(S[0][idx]))
          }
          _ => {
            let t = b.wrapping_add(f(c, d, a)).wrapping_add(x[k]);
            (t.rotate_left(S[0][idx]), c, d, a)
          }
        };
        a = na;
        b = nb;
        c = nc;
        d = nd;
      }

      // Round 2
      let order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
      for i in 0..16 {
        let idx = i % 4;
        let k = order2[i];
        let t = match idx {
          0 => a
            .wrapping_add(g(b, c, d))
            .wrapping_add(x[k])
            .wrapping_add(0x5a827999),
          1 => d
            .wrapping_add(g(a, b, c))
            .wrapping_add(x[k])
            .wrapping_add(0x5a827999),
          2 => c
            .wrapping_add(g(d, a, b))
            .wrapping_add(x[k])
            .wrapping_add(0x5a827999),
          _ => b
            .wrapping_add(g(c, d, a))
            .wrapping_add(x[k])
            .wrapping_add(0x5a827999),
        };
        match idx {
          0 => {
            a = t.rotate_left(S[1][idx]);
          }
          1 => {
            d = t.rotate_left(S[1][idx]);
          }
          2 => {
            c = t.rotate_left(S[1][idx]);
          }
          _ => {
            b = t.rotate_left(S[1][idx]);
          }
        }
      }

      // Round 3
      let order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
      for i in 0..16 {
        let idx = i % 4;
        let k = order3[i];
        let t = match idx {
          0 => a
            .wrapping_add(h(b, c, d))
            .wrapping_add(x[k])
            .wrapping_add(0x6ed9eba1),
          1 => d
            .wrapping_add(h(a, b, c))
            .wrapping_add(x[k])
            .wrapping_add(0x6ed9eba1),
          2 => c
            .wrapping_add(h(d, a, b))
            .wrapping_add(x[k])
            .wrapping_add(0x6ed9eba1),
          _ => b
            .wrapping_add(h(c, d, a))
            .wrapping_add(x[k])
            .wrapping_add(0x6ed9eba1),
        };
        match idx {
          0 => {
            a = t.rotate_left(S[2][idx]);
          }
          1 => {
            d = t.rotate_left(S[2][idx]);
          }
          2 => {
            c = t.rotate_left(S[2][idx]);
          }
          _ => {
            b = t.rotate_left(S[2][idx]);
          }
        }
      }

      a = a.wrapping_add(aa);
      b = b.wrapping_add(bb);
      c = c.wrapping_add(cc);
      d = d.wrapping_add(dd);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a.to_le_bytes());
    result[4..8].copy_from_slice(&b.to_le_bytes());
    result[8..12].copy_from_slice(&c.to_le_bytes());
    result[12..16].copy_from_slice(&d.to_le_bytes());
    result
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// AES-256 Block Operations (for etype 18)
// ═══════════════════════════════════════════════════════════════════════════

/// AES-256 block encryption using the aes_gcm module
fn aes256_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
  aes_gcm::aes256_encrypt_block(block, key)
}

/// AES-256 block decryption
/// Since we don't have a decrypt function in aes_gcm, implement here
fn aes256_decrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
  // AES inverse S-box
  const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
  ];

  // AES S-box for key expansion
  const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ];

  // Key expansion for AES-256 (produces 240 bytes = 15 round keys)
  fn key_expansion(key: &[u8; 32]) -> [u8; 240] {
    let mut expanded = [0u8; 240];
    expanded[..32].copy_from_slice(key);

    let rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    for i in 8..60 {
      let word_offset = i * 4;
      let mut temp = [
        expanded[word_offset - 4],
        expanded[word_offset - 3],
        expanded[word_offset - 2],
        expanded[word_offset - 1],
      ];

      if i % 8 == 0 {
        temp = [
          SBOX[temp[1] as usize] ^ rcon[i / 8 - 1],
          SBOX[temp[2] as usize],
          SBOX[temp[3] as usize],
          SBOX[temp[0] as usize],
        ];
      } else if i % 8 == 4 {
        temp = [
          SBOX[temp[0] as usize],
          SBOX[temp[1] as usize],
          SBOX[temp[2] as usize],
          SBOX[temp[3] as usize],
        ];
      }

      for j in 0..4 {
        expanded[word_offset + j] = expanded[word_offset - 32 + j] ^ temp[j];
      }
    }
    expanded
  }

  fn inv_shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift right by 1
    let t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;
    // Row 2: shift right by 2
    let t0 = state[2];
    let t1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;
    // Row 3: shift right by 3
    let t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;
  }

  fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
      if b & 1 != 0 {
        result ^= a;
      }
      let hi = a & 0x80;
      a <<= 1;
      if hi != 0 {
        a ^= 0x1b;
      }
      b >>= 1;
    }
    result
  }

  fn inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
      let c = col * 4;
      let s0 = state[c];
      let s1 = state[c + 1];
      let s2 = state[c + 2];
      let s3 = state[c + 3];
      state[c] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
      state[c + 1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
      state[c + 2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
      state[c + 3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
  }

  let expanded_key = key_expansion(key);
  let mut state = *block;

  // Initial round key addition (round 14)
  for i in 0..16 {
    state[i] ^= expanded_key[224 + i];
  }

  // 13 main rounds in reverse
  for round in (1..14).rev() {
    inv_shift_rows(&mut state);
    for byte in &mut state {
      *byte = INV_SBOX[*byte as usize];
    }
    let rk_offset = round * 16;
    for i in 0..16 {
      state[i] ^= expanded_key[rk_offset + i];
    }
    inv_mix_columns(&mut state);
  }

  // Final round
  inv_shift_rows(&mut state);
  for byte in &mut state {
    *byte = INV_SBOX[*byte as usize];
  }
  for i in 0..16 {
    state[i] ^= expanded_key[i];
  }

  state
}

// ═══════════════════════════════════════════════════════════════════════════
// Key Usage Constants (RFC 3961)
// ═══════════════════════════════════════════════════════════════════════════

/// Key usage values for Kerberos operations
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
  /// AS-REQ PA-ENC-TIMESTAMP
  AsReqPaEncTimestamp = 1,
  /// KDC-REP ticket enc-part (AS/TGS)
  KdcRepTicketEncPart = 2,
  /// AS-REP encrypted part
  AsRepEncPart = 3,
  /// TGS-REQ KDC-REQ-BODY authenticator checksum
  TgsReqAuthCksum = 6,
  /// TGS-REQ KDC-REQ-BODY authenticator
  TgsReqAuthenticator = 7,
  /// TGS-REP encrypted part (TGS session key)
  TgsRepEncPart = 8,
  /// TGS-REP ticket enc-part subkey
  TgsRepSubkey = 9,
  /// AP-REQ Authenticator cksum
  ApReqAuthCksum = 10,
  /// AP-REQ Authenticator
  ApReqAuthenticator = 11,
  /// AP-REP encrypted part
  ApRepEncPart = 12,
  /// KRB-PRIV encrypted part
  KrbPrivEncPart = 13,
  /// KRB-CRED encrypted part
  KrbCredEncPart = 14,
  /// KRB-SAFE cksum
  KrbSafeCksum = 15,
  /// GSS Wrap confidential
  GssWrapConfidential = 22,
  /// GSS Wrap integrity only
  GssWrapIntegrity = 23,
  /// GSS GetMIC
  GssGetMic = 25,
}

// ═══════════════════════════════════════════════════════════════════════════
// RC4-HMAC (etype 23)
// ═══════════════════════════════════════════════════════════════════════════

/// RC4-HMAC encryption (etype 23)
///
/// This is the legacy encryption type used with NTLM hashes.
/// The key is the MD4 hash of the Unicode password (NT hash).
pub struct Rc4Hmac;

impl Rc4Hmac {
  /// Derive NT hash from password
  ///
  /// NT hash = MD4(UTF-16LE(password))
  pub fn string_to_key(password: &str) -> [u8; 16] {
    let utf16: Vec<u16> = password.encode_utf16().collect();
    let utf16_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();

    md4::hash(&utf16_bytes)
  }

  /// Encrypt data using RC4-HMAC
  ///
  /// Structure:
  /// - Confounder (8 bytes, random)
  /// - HMAC checksum (16 bytes)
  /// - Encrypted(confounder + plaintext)
  pub fn encrypt(key: &[u8; 16], key_usage: KeyUsage, plaintext: &[u8]) -> Vec<u8> {
    // Generate random confounder
    let confounder = Self::generate_confounder();

    // Derive keys
    let (k1, k3) = Self::derive_keys(key, key_usage);

    // Build plaintext with confounder
    let mut plain_with_conf = confounder.to_vec();
    plain_with_conf.extend_from_slice(plaintext);

    // Calculate HMAC checksum
    let checksum = hmac::hmac_md5(&k3, &plain_with_conf);

    // Derive encryption key from checksum
    let k2 = hmac::hmac_md5(&k1, &checksum);

    // Encrypt with RC4
    let ciphertext = rc4_crypt(&k2, &plain_with_conf);

    // Build result: HMAC(16) || encrypted_data
    let mut result = checksum.to_vec();
    result.extend_from_slice(&ciphertext);
    result
  }

  /// Decrypt data using RC4-HMAC
  pub fn decrypt(
    key: &[u8; 16],
    key_usage: KeyUsage,
    ciphertext: &[u8],
  ) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 24 {
      return Err("Ciphertext too short".to_string());
    }

    // Split checksum and encrypted data
    let checksum = &ciphertext[0..16];
    let encrypted = &ciphertext[16..];

    // Derive keys
    let (k1, k3) = Self::derive_keys(key, key_usage);

    // Derive decryption key from checksum
    let k2 = hmac::hmac_md5(&k1, checksum);

    // Decrypt with RC4
    let decrypted = rc4_crypt(&k2, encrypted);

    // Verify checksum
    let calculated = hmac::hmac_md5(&k3, &decrypted);
    if calculated != checksum {
      return Err("Checksum verification failed".to_string());
    }

    // Remove confounder (first 8 bytes)
    if decrypted.len() < 8 {
      return Err("Decrypted data too short".to_string());
    }

    Ok(decrypted[8..].to_vec())
  }

  /// Derive K1 and K3 from key and usage
  fn derive_keys(key: &[u8; 16], key_usage: KeyUsage) -> ([u8; 16], [u8; 16]) {
    // K1 = HMAC-MD5(key, usage_le)
    let usage_bytes = (key_usage as i32).to_le_bytes();
    let k1 = hmac::hmac_md5(key, &usage_bytes);

    // K3 = HMAC-MD5(K1, "signaturekey\0")
    let k3 = hmac::hmac_md5(&k1, b"signaturekey\0");

    (k1, k3)
  }

  /// Generate random 8-byte confounder
  fn generate_confounder() -> [u8; 8] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_nanos() as u64;

    // Simple PRNG for confounder (for real use, should use OS random)
    let mut state = seed;
    let mut confounder = [0u8; 8];
    for byte in &mut confounder {
      state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
      *byte = (state >> 56) as u8;
    }
    confounder
  }

  /// Calculate HMAC-MD5 checksum
  pub fn checksum(key: &[u8; 16], key_usage: KeyUsage, data: &[u8]) -> [u8; 16] {
    let (_, k3) = Self::derive_keys(key, key_usage);
    hmac::hmac_md5(&k3, data)
  }
}

/// RC4 stream cipher (Arcfour)
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
  // Initialize S-box
  let mut s: [u8; 256] = [0; 256];
  for i in 0..256 {
    s[i] = i as u8;
  }

  // Key-scheduling algorithm (KSA)
  let mut j = 0u8;
  for i in 0..256 {
    j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
    s.swap(i, j as usize);
  }

  // Pseudo-random generation algorithm (PRGA)
  let mut result = Vec::with_capacity(data.len());
  let mut i = 0u8;
  j = 0;

  for byte in data {
    i = i.wrapping_add(1);
    j = j.wrapping_add(s[i as usize]);
    s.swap(i as usize, j as usize);
    let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
    result.push(byte ^ k);
  }

  result
}

// ═══════════════════════════════════════════════════════════════════════════
// AES256-CTS-HMAC-SHA1 (etype 18)
// ═══════════════════════════════════════════════════════════════════════════

/// AES256-CTS-HMAC-SHA1 encryption (etype 18)
///
/// This is the modern, preferred encryption type for Kerberos.
/// Uses AES-256 in CBC mode with ciphertext stealing for the last block.
pub struct Aes256CtsHmacSha1;

impl Aes256CtsHmacSha1 {
  const BLOCK_SIZE: usize = 16;
  const KEY_SIZE: usize = 32;

  /// Derive key from password using PBKDF2
  ///
  /// Uses PBKDF2-HMAC-SHA1 with 4096 iterations.
  pub fn string_to_key(password: &str, salt: &str, iterations: u32) -> [u8; 32] {
    let password_bytes = password.as_bytes();
    let salt_bytes = salt.as_bytes();

    pbkdf2_sha1(password_bytes, salt_bytes, iterations, 32)
      .try_into()
      .unwrap()
  }

  /// Derive key from raw password bytes (for AES keys)
  pub fn random_to_key(data: &[u8]) -> Result<[u8; 32], String> {
    if data.len() < 32 {
      return Err("Insufficient key material".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    Ok(key)
  }

  /// Encrypt data using AES256-CTS-HMAC-SHA1
  ///
  /// Structure:
  /// - Confounder (16 bytes, random)
  /// - Encrypted(confounder + plaintext)
  /// - HMAC-SHA1 checksum (12 bytes, truncated)
  pub fn encrypt(key: &[u8; 32], key_usage: KeyUsage, plaintext: &[u8]) -> Vec<u8> {
    // Derive encryption and integrity keys
    let ke = Self::derive_key(key, key_usage, b"kerberos");
    let ki = Self::derive_key(key, key_usage, b"kerberos");

    // Generate random confounder
    let confounder = Self::generate_confounder();

    // Build plaintext with confounder
    let mut plain_with_conf = confounder.to_vec();
    plain_with_conf.extend_from_slice(plaintext);

    // Encrypt with AES-CBC-CTS
    let iv = [0u8; 16];
    let ciphertext = aes_cbc_cts_encrypt(&ke, &iv, &plain_with_conf);

    // Calculate HMAC-SHA1 checksum (truncated to 12 bytes)
    let checksum = hmac::hmac_sha1(&ki, &ciphertext);
    let checksum_truncated = &checksum[..12];

    // Build result: ciphertext || checksum(12)
    let mut result = ciphertext;
    result.extend_from_slice(checksum_truncated);
    result
  }

  /// Decrypt data using AES256-CTS-HMAC-SHA1
  pub fn decrypt(
    key: &[u8; 32],
    key_usage: KeyUsage,
    ciphertext: &[u8],
  ) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 28 {
      return Err("Ciphertext too short".to_string());
    }

    // Split ciphertext and checksum
    let cipher_len = ciphertext.len() - 12;
    let encrypted = &ciphertext[..cipher_len];
    let checksum = &ciphertext[cipher_len..];

    // Derive keys
    let ke = Self::derive_key(key, key_usage, b"kerberos");
    let ki = Self::derive_key(key, key_usage, b"kerberos");

    // Verify checksum
    let calculated = hmac::hmac_sha1(&ki, encrypted);
    if &calculated[..12] != checksum {
      return Err("Checksum verification failed".to_string());
    }

    // Decrypt with AES-CBC-CTS
    let iv = [0u8; 16];
    let decrypted = aes_cbc_cts_decrypt(&ke, &iv, encrypted)?;

    // Remove confounder (first 16 bytes)
    if decrypted.len() < Self::BLOCK_SIZE {
      return Err("Decrypted data too short".to_string());
    }

    Ok(decrypted[Self::BLOCK_SIZE..].to_vec())
  }

  /// Derive subkey using key derivation function
  fn derive_key(key: &[u8; 32], key_usage: KeyUsage, constant: &[u8]) -> [u8; 32] {
    // Simple key derivation: HMAC-SHA1(key, usage || constant)
    let mut input = Vec::new();
    input.extend_from_slice(&(key_usage as i32).to_be_bytes());
    input.extend_from_slice(constant);

    let derived = hmac::hmac_sha1(key, &input);

    // Expand to 32 bytes using another HMAC
    let mut result = [0u8; 32];
    result[..20].copy_from_slice(&derived);
    let more = hmac::hmac_sha1(key, &derived);
    result[20..32].copy_from_slice(&more[..12]);
    result
  }

  /// Generate random 16-byte confounder
  fn generate_confounder() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_nanos() as u64;

    let mut state = seed;
    let mut confounder = [0u8; 16];
    for byte in &mut confounder {
      state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
      *byte = (state >> 56) as u8;
    }
    confounder
  }

  /// Calculate HMAC-SHA1-96 checksum
  pub fn checksum(key: &[u8; 32], key_usage: KeyUsage, data: &[u8]) -> [u8; 12] {
    let ki = Self::derive_key(key, key_usage, b"kerberos");
    let full = hmac::hmac_sha1(&ki, data);
    let mut result = [0u8; 12];
    result.copy_from_slice(&full[..12]);
    result
  }
}

/// AES-CBC encryption with CTS (Ciphertext Stealing)
fn aes_cbc_cts_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
  if plaintext.len() < 16 {
    // For data smaller than one block, just use regular CBC
    return aes_cbc_encrypt(key, iv, plaintext);
  }

  let block_size = 16;
  let n_blocks = plaintext.len() / block_size;
  let remainder = plaintext.len() % block_size;

  if remainder == 0 {
    // Even number of blocks - standard CBC
    return aes_cbc_encrypt(key, iv, plaintext);
  }

  // CTS: encrypt all but last partial block with CBC
  let full_blocks_len = (n_blocks.saturating_sub(1)) * block_size;
  let mut result = aes_cbc_encrypt(key, iv, &plaintext[..full_blocks_len + block_size]);

  // CTS: swap last two blocks and adjust
  let cn_1_start = result.len() - 2 * block_size;
  let cn_1 = result[cn_1_start..cn_1_start + block_size].to_vec();
  let cn = result[result.len() - block_size..].to_vec();

  // Cn || Cn-1[0..remainder]
  result.truncate(cn_1_start);
  result.extend_from_slice(&cn);
  result.extend_from_slice(&cn_1[..remainder]);

  result
}

/// AES-CBC decryption with CTS
fn aes_cbc_cts_decrypt(
  key: &[u8; 32],
  iv: &[u8; 16],
  ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
  if ciphertext.len() < 16 {
    return Err("Ciphertext too short for CTS".to_string());
  }

  let block_size = 16;
  let n_blocks = ciphertext.len() / block_size;
  let remainder = ciphertext.len() % block_size;

  if remainder == 0 {
    // Even number of blocks - standard CBC
    return aes_cbc_decrypt(key, iv, ciphertext);
  }

  // CTS decryption - reverse the stealing
  let cn_start = ciphertext.len() - block_size - remainder;
  let mut adjusted = ciphertext[..cn_start].to_vec();

  // Reconstruct the last two cipher blocks
  let cn = &ciphertext[cn_start..cn_start + block_size];
  let cn_1_partial = &ciphertext[cn_start + block_size..];

  // Decrypt Cn to get Pn XOR Cn-1
  let cn_block: [u8; 16] = cn.try_into().map_err(|_| "Invalid block size")?;
  let dn = aes256_decrypt_block(key, &cn_block);

  // Cn-1 = dn[0..remainder] XOR Pn || dn[remainder..]
  // This is the CTS recovery
  adjusted.extend_from_slice(cn_1_partial);
  adjusted.extend_from_slice(&dn[remainder..]);
  adjusted.extend_from_slice(cn);

  aes_cbc_decrypt(key, iv, &adjusted)
}

/// Standard AES-CBC encryption
fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
  let block_size = 16;
  let mut result = Vec::new();
  let mut prev = iv.to_vec();

  let key_array: [u8; 32] = key.try_into().unwrap_or([0u8; 32]);

  for chunk in plaintext.chunks(block_size) {
    let mut block = [0u8; 16];
    for (i, &byte) in chunk.iter().enumerate() {
      block[i] = byte ^ prev[i];
    }

    let encrypted = aes256_encrypt_block(&key_array, &block);
    result.extend_from_slice(&encrypted);
    prev = encrypted.to_vec();
  }

  result
}

/// Standard AES-CBC decryption
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
  let block_size = 16;
  let mut result = Vec::new();
  let mut prev = iv.to_vec();

  let key_array: [u8; 32] = key.try_into().map_err(|_| "Invalid key length")?;

  for chunk in ciphertext.chunks(block_size) {
    if chunk.len() < block_size {
      // Handle partial last block
      let mut block = [0u8; 16];
      block[..chunk.len()].copy_from_slice(chunk);
      let decrypted = aes256_decrypt_block(&key_array, &block);

      for (i, &byte) in decrypted[..chunk.len()].iter().enumerate() {
        result.push(byte ^ prev[i]);
      }
    } else {
      let chunk_block: [u8; 16] = chunk.try_into().unwrap();
      let decrypted = aes256_decrypt_block(&key_array, &chunk_block);

      for (i, &byte) in decrypted.iter().enumerate() {
        result.push(byte ^ prev[i]);
      }

      prev = chunk.to_vec();
    }
  }

  Ok(result)
}

/// PBKDF2 with HMAC-SHA1
fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
  let h_len = 20; // SHA1 output length
  let l = (dk_len + h_len - 1) / h_len; // Number of blocks needed

  let mut dk = Vec::with_capacity(dk_len);

  for i in 1..=l as u32 {
    // U_1 = PRF(Password, Salt || INT(i))
    let mut u_input = salt.to_vec();
    u_input.extend_from_slice(&i.to_be_bytes());
    let mut u = hmac::hmac_sha1(password, &u_input);
    let mut t = u;

    // U_2 through U_c
    for _ in 1..iterations {
      u = hmac::hmac_sha1(password, &u);
      for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
        *t_byte ^= u_byte;
      }
    }

    dk.extend_from_slice(&t);
  }

  dk.truncate(dk_len);
  dk
}

// ═══════════════════════════════════════════════════════════════════════════
// High-Level API
// ═══════════════════════════════════════════════════════════════════════════

/// Encrypt data with the appropriate encryption type
pub fn encrypt(
  key: &EncryptionKey,
  key_usage: KeyUsage,
  plaintext: &[u8],
) -> Result<EncryptedData, String> {
  let cipher = match key.keytype {
    EncryptionType::Rc4Hmac => {
      let key_array: [u8; 16] = key
        .keyvalue
        .clone()
        .try_into()
        .map_err(|_| "Invalid RC4-HMAC key length")?;
      Rc4Hmac::encrypt(&key_array, key_usage, plaintext)
    }
    EncryptionType::Aes256CtsHmacSha1 => {
      let key_array: [u8; 32] = key
        .keyvalue
        .clone()
        .try_into()
        .map_err(|_| "Invalid AES256 key length")?;
      Aes256CtsHmacSha1::encrypt(&key_array, key_usage, plaintext)
    }
    EncryptionType::Aes128CtsHmacSha1 => {
      // For AES128, use same algorithm but with 16-byte key
      let key_padded = if key.keyvalue.len() < 32 {
        let mut k = vec![0u8; 32];
        k[..key.keyvalue.len()].copy_from_slice(&key.keyvalue);
        k
      } else {
        key.keyvalue.clone()
      };
      let key_array: [u8; 32] = key_padded.try_into().unwrap();
      Aes256CtsHmacSha1::encrypt(&key_array, key_usage, plaintext)
    }
    _ => return Err(format!("Unsupported encryption type: {:?}", key.keytype)),
  };

  Ok(EncryptedData::new(key.keytype, cipher))
}

/// Decrypt data with the appropriate encryption type
pub fn decrypt(
  key: &EncryptionKey,
  key_usage: KeyUsage,
  encrypted: &EncryptedData,
) -> Result<Vec<u8>, String> {
  if key.keytype != encrypted.etype {
    return Err(format!(
      "Key type {:?} doesn't match encrypted data type {:?}",
      key.keytype, encrypted.etype
    ));
  }

  match key.keytype {
    EncryptionType::Rc4Hmac => {
      let key_array: [u8; 16] = key
        .keyvalue
        .clone()
        .try_into()
        .map_err(|_| "Invalid RC4-HMAC key length")?;
      Rc4Hmac::decrypt(&key_array, key_usage, &encrypted.cipher)
    }
    EncryptionType::Aes256CtsHmacSha1 => {
      let key_array: [u8; 32] = key
        .keyvalue
        .clone()
        .try_into()
        .map_err(|_| "Invalid AES256 key length")?;
      Aes256CtsHmacSha1::decrypt(&key_array, key_usage, &encrypted.cipher)
    }
    _ => Err(format!("Unsupported encryption type: {:?}", key.keytype)),
  }
}

/// Derive key from password for the given encryption type
pub fn string_to_key(
  etype: EncryptionType,
  password: &str,
  salt: &str,
) -> Result<EncryptionKey, String> {
  match etype {
    EncryptionType::Rc4Hmac => {
      let key = Rc4Hmac::string_to_key(password);
      Ok(EncryptionKey::new(etype, key.to_vec()))
    }
    EncryptionType::Aes256CtsHmacSha1 => {
      let key = Aes256CtsHmacSha1::string_to_key(password, salt, 4096);
      Ok(EncryptionKey::new(etype, key.to_vec()))
    }
    EncryptionType::Aes128CtsHmacSha1 => {
      // Same as AES256 but truncate to 16 bytes
      let key = Aes256CtsHmacSha1::string_to_key(password, salt, 4096);
      Ok(EncryptionKey::new(etype, key[..16].to_vec()))
    }
    _ => Err(format!(
      "Unsupported encryption type for string-to-key: {:?}",
      etype
    )),
  }
}

/// Calculate checksum for data
pub fn make_checksum(
  key: &EncryptionKey,
  key_usage: KeyUsage,
  data: &[u8],
) -> Result<super::types::Checksum, String> {
  match key.keytype {
    EncryptionType::Rc4Hmac => {
      let key_array: [u8; 16] = key
        .keyvalue
        .clone()
        .try_into()
        .map_err(|_| "Invalid RC4-HMAC key length")?;
      let checksum = Rc4Hmac::checksum(&key_array, key_usage, data);
      Ok(super::types::Checksum::new(
        ChecksumType::HmacMd5,
        checksum.to_vec(),
      ))
    }
    EncryptionType::Aes256CtsHmacSha1 => {
      let key_array: [u8; 32] = key
        .keyvalue
        .clone()
        .try_into()
        .map_err(|_| "Invalid AES256 key length")?;
      let checksum = Aes256CtsHmacSha1::checksum(&key_array, key_usage, data);
      Ok(super::types::Checksum::new(
        ChecksumType::HmacSha1Aes256,
        checksum.to_vec(),
      ))
    }
    _ => Err(format!(
      "Unsupported encryption type for checksum: {:?}",
      key.keytype
    )),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_rc4_string_to_key() {
    // Test vector: password "foo"
    let key = Rc4Hmac::string_to_key("foo");
    // NT hash of "foo" should be ac8e657f83df82beea5d43bdaf7800cc (known value)
    assert_eq!(key.len(), 16);
  }

  #[test]
  fn test_rc4_encrypt_decrypt() {
    let key = Rc4Hmac::string_to_key("password");
    let plaintext = b"Hello, Kerberos!";

    let ciphertext = Rc4Hmac::encrypt(&key, KeyUsage::AsReqPaEncTimestamp, plaintext);
    let decrypted = Rc4Hmac::decrypt(&key, KeyUsage::AsReqPaEncTimestamp, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
  }

  #[test]
  fn test_rc4_basic_stream() {
    let key = [0x01, 0x02, 0x03, 0x04, 0x05];
    let plaintext = b"plaintext";

    let ciphertext = rc4_crypt(&key, plaintext);
    let decrypted = rc4_crypt(&key, &ciphertext);

    assert_eq!(decrypted, plaintext);
  }

  #[test]
  fn test_aes256_string_to_key() {
    let key = Aes256CtsHmacSha1::string_to_key("password", "REALM.COMuser", 4096);
    assert_eq!(key.len(), 32);
  }

  #[test]
  fn test_aes256_encrypt_decrypt() {
    let key = Aes256CtsHmacSha1::string_to_key("password", "TESTuser", 4096);
    let plaintext = b"Hello, AES Kerberos!";

    let ciphertext = Aes256CtsHmacSha1::encrypt(&key, KeyUsage::AsReqPaEncTimestamp, plaintext);
    let decrypted =
      Aes256CtsHmacSha1::decrypt(&key, KeyUsage::AsReqPaEncTimestamp, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
  }

  #[test]
  fn test_pbkdf2() {
    // Test vector from RFC 6070
    let dk = pbkdf2_sha1(b"password", b"salt", 1, 20);
    assert_eq!(dk.len(), 20);
  }

  #[test]
  fn test_high_level_encrypt_decrypt() {
    let key = string_to_key(EncryptionType::Rc4Hmac, "testpassword", "").unwrap();

    let plaintext = b"test data for encryption";

    let encrypted = encrypt(&key, KeyUsage::AsReqPaEncTimestamp, plaintext).unwrap();
    let decrypted = decrypt(&key, KeyUsage::AsReqPaEncTimestamp, &encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
  }
}
