//! Cipher suite utilities
//!
//! Functions for working with TLS cipher suites - identification, key sizes, etc.

use super::types::{CipherSuite, KeyExchange, MacAlgorithm};
use crate::crypto::prf::Tls12PrfAlgorithm;

/// Get cipher suite ID
pub fn cipher_suite_id(cipher: CipherSuite) -> u16 {
    match cipher {
        CipherSuite::TlsRsaWithAes128CbcSha => 0x002F,
        CipherSuite::TlsRsaWithAes256CbcSha => 0x0035,
        CipherSuite::TlsEcdheRsaWithAes128GcmSha256 => 0xC02F,
        CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => 0xC030,
        CipherSuite::TlsAes128GcmSha256 => 0x1301,
        CipherSuite::TlsAes256GcmSha384 => 0x1302,
    }
}

/// Parse cipher suite from ID
pub fn cipher_suite_from_id(id: u16) -> Result<CipherSuite, String> {
    match id {
        0x002F => Ok(CipherSuite::TlsRsaWithAes128CbcSha),
        0x0035 => Ok(CipherSuite::TlsRsaWithAes256CbcSha),
        0xC02F => Ok(CipherSuite::TlsEcdheRsaWithAes128GcmSha256),
        0xC030 => Ok(CipherSuite::TlsEcdheRsaWithAes256GcmSha384),
        0x1301 => Ok(CipherSuite::TlsAes128GcmSha256),
        0x1302 => Ok(CipherSuite::TlsAes256GcmSha384),
        _ => Err(format!("Unsupported cipher suite: 0x{:04X}", id)),
    }
}

/// Get MAC algorithm for cipher suite
pub fn cipher_suite_mac_algorithm(cipher: CipherSuite) -> Result<MacAlgorithm, String> {
    match cipher {
        CipherSuite::TlsRsaWithAes128CbcSha => Ok(MacAlgorithm::Sha1),
        CipherSuite::TlsRsaWithAes256CbcSha => Ok(MacAlgorithm::Sha1),
        CipherSuite::TlsEcdheRsaWithAes128GcmSha256 => Ok(MacAlgorithm::Sha256),
        CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => Ok(MacAlgorithm::Sha256),
        CipherSuite::TlsAes128GcmSha256 => Ok(MacAlgorithm::Sha256),
        CipherSuite::TlsAes256GcmSha384 => Ok(MacAlgorithm::Sha256),
    }
}

/// Check if cipher suite is supported
pub fn cipher_suite_is_supported(cipher: CipherSuite) -> bool {
    matches!(
        cipher,
        CipherSuite::TlsRsaWithAes128CbcSha
            | CipherSuite::TlsEcdheRsaWithAes128GcmSha256
            | CipherSuite::TlsEcdheRsaWithAes256GcmSha384
            | CipherSuite::TlsAes128GcmSha256
            | CipherSuite::TlsAes256GcmSha384
    )
}

/// Check if cipher suite uses GCM mode
pub fn cipher_suite_is_gcm(cipher: CipherSuite) -> bool {
    matches!(
        cipher,
        CipherSuite::TlsEcdheRsaWithAes128GcmSha256
            | CipherSuite::TlsEcdheRsaWithAes256GcmSha384
            | CipherSuite::TlsAes128GcmSha256
            | CipherSuite::TlsAes256GcmSha384
    )
}

/// Check if cipher suite uses CBC mode
pub fn cipher_suite_is_cbc(cipher: CipherSuite) -> bool {
    matches!(
        cipher,
        CipherSuite::TlsRsaWithAes128CbcSha | CipherSuite::TlsRsaWithAes256CbcSha
    )
}

/// Check if cipher suite is TLS 1.3
pub fn cipher_suite_is_tls13(cipher: CipherSuite) -> bool {
    matches!(
        cipher,
        CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsAes256GcmSha384
    )
}

/// Get key exchange algorithm for cipher suite
pub fn cipher_suite_key_exchange(cipher: CipherSuite) -> KeyExchange {
    match cipher {
        CipherSuite::TlsRsaWithAes128CbcSha | CipherSuite::TlsRsaWithAes256CbcSha => {
            KeyExchange::Rsa
        }
        CipherSuite::TlsEcdheRsaWithAes128GcmSha256
        | CipherSuite::TlsEcdheRsaWithAes256GcmSha384
        | CipherSuite::TlsAes128GcmSha256
        | CipherSuite::TlsAes256GcmSha384 => KeyExchange::Ecdhe,
    }
}

/// Get key material sizes for a cipher suite
/// Returns: (mac_key_size, enc_key_size, iv_size)
pub fn cipher_suite_key_sizes(cipher: CipherSuite) -> (usize, usize, usize) {
    match cipher {
        // TlsRsaWithAes128CbcSha: HMAC-SHA1 (20 bytes) + AES-128 (16 bytes) + IV (16 bytes)
        CipherSuite::TlsRsaWithAes128CbcSha => (20, 16, 16),
        // TlsRsaWithAes256CbcSha: HMAC-SHA1 (20 bytes) + AES-256 (32 bytes) + IV (16 bytes)
        CipherSuite::TlsRsaWithAes256CbcSha => (20, 32, 16),
        // TlsEcdheRsaWithAes128GcmSha256: No MAC (GCM mode) + AES-128 (16 bytes) + fixed IV (4 bytes)
        CipherSuite::TlsEcdheRsaWithAes128GcmSha256 => (0, 16, 4),
        // TlsEcdheRsaWithAes256GcmSha384: No MAC (GCM mode) + AES-256 (32 bytes) + fixed IV (4 bytes)
        CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => (0, 32, 4),
        // TLS 1.3 AES-GCM suites use 16-byte key or 32-byte key with 12-byte IV
        CipherSuite::TlsAes128GcmSha256 => (0, 16, 12),
        CipherSuite::TlsAes256GcmSha384 => (0, 32, 12),
    }
}

/// Get PRF algorithm for cipher suite
pub fn cipher_suite_prf_algorithm(cipher: CipherSuite) -> Tls12PrfAlgorithm {
    match cipher {
        CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => Tls12PrfAlgorithm::Sha384,
        CipherSuite::TlsAes256GcmSha384 => Tls12PrfAlgorithm::Sha384,
        _ => Tls12PrfAlgorithm::Sha256,
    }
}
