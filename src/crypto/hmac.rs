/// HMAC (Hash-based Message Authentication Code)
/// RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
///
/// Generic HMAC implementation that works with any hash function
use super::sha256::{sha256, Sha256};

pub struct Hmac {
    key: Vec<u8>,
}

impl Hmac {
    /// Create HMAC instance with given key
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Compute HMAC-SHA256
    pub fn sha256(&self, message: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.key, message)
    }
}

/// HMAC-SHA256 implementation
/// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64; // SHA-256 block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Prepare key
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        // If key is longer than block size, hash it first
        let hashed_key = sha256(key);
        key_block[..32].copy_from_slice(&hashed_key);
    } else {
        // Otherwise use key directly and pad with zeros
        key_block[..key.len()].copy_from_slice(key);
    }

    // Create inner and outer padded keys
    let mut ipad_key = [0u8; BLOCK_SIZE];
    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] = key_block[i] ^ IPAD;
        opad_key[i] = key_block[i] ^ OPAD;
    }

    // Inner hash: H((K' ⊕ ipad) || message)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad_key);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H((K' ⊕ opad) || inner_hash)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad_key);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        // Test Case 1 from RFC 4231
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case2() {
        // Test Case 2 from RFC 4231
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        let result = hmac_sha256(key, data);
        assert_eq!(result, expected);
    }
}
