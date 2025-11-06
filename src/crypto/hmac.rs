/// HMAC (Hash-based Message Authentication Code)
/// RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
///
/// Generic HMAC implementation that works with any hash function
use super::md5::md5;
use super::sha1::{sha1, Sha1};
use super::sha256::sha256;
use super::sha384::{sha384, Sha384};

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
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_input.extend_from_slice(&ipad_key);
    inner_input.extend_from_slice(message);
    let inner_hash = sha256(&inner_input);

    // Outer hash: H((K' ⊕ opad) || inner_hash)
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 32);
    outer_input.extend_from_slice(&opad_key);
    outer_input.extend_from_slice(&inner_hash);
    sha256(&outer_input)
}

/// HMAC-SHA1 implementation (RFC 2202)
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64; // SHA-1 block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Prepare key
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed_key = sha1(key);
        key_block[..20].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // Create inner/outer pads
    let mut ipad_key = [0u8; BLOCK_SIZE];
    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] = key_block[i] ^ IPAD;
        opad_key[i] = key_block[i] ^ OPAD;
    }

    // Inner hash
    let mut inner = Sha1::new();
    inner.update(&ipad_key);
    inner.update(message);
    let inner_hash = inner.finalize();

    // Outer hash
    let mut outer = Sha1::new();
    outer.update(&opad_key);
    outer.update(&inner_hash);
    outer.finalize()
}

/// HMAC-MD5 implementation (used by TLS 1.0/1.1 PRF)
pub fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    const BLOCK_SIZE: usize = 64; // MD5 block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed_key = md5(key);
        key_block[..16].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad_key = [0u8; BLOCK_SIZE];
    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] = key_block[i] ^ IPAD;
        opad_key[i] = key_block[i] ^ OPAD;
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&ipad_key);
    inner.extend_from_slice(message);
    let inner_hash = md5(&inner);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + inner_hash.len());
    outer.extend_from_slice(&opad_key);
    outer.extend_from_slice(&inner_hash);

    md5(&outer)
}

/// HMAC-SHA384 implementation
pub fn hmac_sha384(key: &[u8], message: &[u8]) -> [u8; 48] {
    const BLOCK_SIZE: usize = 128; // SHA-384 block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed_key = sha384(key);
        key_block[..48].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad_key = [0u8; BLOCK_SIZE];
    let mut opad_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] = key_block[i] ^ IPAD;
        opad_key[i] = key_block[i] ^ OPAD;
    }

    let mut inner_hasher = Sha384::new();
    inner_hasher.update(&ipad_key);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha384::new();
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

    #[test]
    fn test_hmac_sha1_rfc2202_case1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        let result = hmac_sha1(&key, data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha1_rfc2202_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
            0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        let result = hmac_sha1(key, data);
        assert_eq!(result, expected);
    }
}
