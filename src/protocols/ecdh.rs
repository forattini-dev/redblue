//! Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
//!
//! Implements ECDH key agreement using P-256 curve for TLS.
//! This provides Perfect Forward Secrecy (PFS) for TLS connections.
//!
//! Protocol:
//! 1. Client generates ephemeral key pair (private_key, public_key)
//! 2. Server generates ephemeral key pair (private_key, public_key)
//! 3. Both exchange public keys
//! 4. Both compute shared secret = private_key * other_public_key
//! 5. Shared secret is used as premaster secret in TLS
//!
//! References:
//! - RFC 4492: Elliptic Curve Cryptography (ECC) Cipher Suites for TLS
//! - RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for TLS 1.2 and Earlier

use super::crypto::SecureRandom;
use super::p256::P256Point;

/// Order of the NIST P-256 curve
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// ECDH key pair for ephemeral key exchange
pub struct EcdhKeyPair {
    /// Private key (scalar)
    private_key: [u8; 32],
    /// Public key (point on curve)
    pub public_key: P256Point,
}

impl EcdhKeyPair {
    /// Generate a new random ECDH key pair
    pub fn generate() -> Result<Self, String> {
        let mut rng = SecureRandom::new()?;
        let mut private_key = [0u8; 32];

        loop {
            rng.fill_bytes(&mut private_key)
                .map_err(|e| format!("RNG failure: {}", e))?;

            if is_valid_scalar(&private_key) {
                break;
            }
        }

        // Compute public key = private_key * G
        let generator = P256Point::generator();
        let public_key = generator.scalar_mul(&private_key);

        Ok(EcdhKeyPair {
            private_key,
            public_key,
        })
    }

    /// Compute shared secret with peer's public key
    /// Returns the x-coordinate of the shared point as the premaster secret
    pub fn compute_shared_secret(&self, peer_public_key: &P256Point) -> [u8; 32] {
        // Compute shared point = private_key * peer_public_key
        let shared_point = peer_public_key.scalar_mul(&self.private_key);

        // Return x-coordinate as shared secret (standard for ECDH)
        shared_point.x.to_bytes()
    }

    /// Get public key in uncompressed format (0x04 || x || y)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_uncompressed_bytes()
    }
}

fn is_valid_scalar(scalar: &[u8; 32]) -> bool {
    if scalar.iter().all(|&b| b == 0) {
        return false;
    }

    for (a, b) in scalar.iter().zip(P256_ORDER.iter()) {
        if a < b {
            return true;
        } else if a > b {
            return false;
        }
    }

    // Equal to the group order is invalid
    false
}

/// Named curve identifiers for TLS (RFC 4492)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedCurve {
    /// NIST P-256 (secp256r1)
    Secp256r1 = 23,
    /// NIST P-384 (secp384r1)
    Secp384r1 = 24,
    /// NIST P-521 (secp521r1)
    Secp521r1 = 25,
}

impl NamedCurve {
    /// Parse named curve from TLS wire format (u16)
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            23 => Some(NamedCurve::Secp256r1),
            24 => Some(NamedCurve::Secp384r1),
            25 => Some(NamedCurve::Secp521r1),
            _ => None,
        }
    }

    /// Convert to TLS wire format (u16)
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_key_generation() {
        let keypair = EcdhKeyPair::generate().unwrap();
        assert!(!keypair.public_key.is_infinity);

        let public_bytes = keypair.public_key_bytes();
        assert_eq!(public_bytes.len(), 65);
        assert_eq!(public_bytes[0], 0x04); // Uncompressed format
    }

    #[test]
    fn test_ecdh_shared_secret() {
        // Alice generates key pair
        let alice = EcdhKeyPair::generate().unwrap();

        // Bob generates key pair
        let bob = EcdhKeyPair::generate().unwrap();

        // Both compute shared secret
        let alice_shared = alice.compute_shared_secret(&bob.public_key);
        let bob_shared = bob.compute_shared_secret(&alice.public_key);

        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_named_curve_conversion() {
        assert_eq!(NamedCurve::Secp256r1.to_u16(), 23);
        assert_eq!(NamedCurve::from_u16(23), Some(NamedCurve::Secp256r1));
        assert_eq!(NamedCurve::from_u16(999), None);
    }

    #[test]
    fn test_scalar_validation() {
        let zero = [0u8; 32];
        assert!(!super::is_valid_scalar(&zero));

        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(super::is_valid_scalar(&one));

        assert!(!super::is_valid_scalar(&P256_ORDER));
    }
}
