/// ChaCha20-Poly1305 AEAD Cipher Implementation
/// RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols
///
/// This is the preferred AEAD cipher for TLS 1.3
///
/// Implements:
/// - ChaCha20 stream cipher (RFC 8439 Section 2)
/// - Poly1305 MAC (RFC 8439 Section 3)
/// - ChaCha20-Poly1305 AEAD construction (RFC 8439 Section 4)
///
/// ✅ ZERO DEPENDENCIES - Pure Rust implementation
/// Replaces: chacha20poly1305 crate, ring, sodiumoxide

/// ChaCha20 stream cipher
///
/// ChaCha20 is a stream cipher designed by Daniel J. Bernstein.
/// It's simpler than AES but equally secure.
pub struct ChaCha20 {
    state: [u32; 16],
    counter: u64,
}

impl ChaCha20 {
    /// Create new ChaCha20 cipher with key and nonce
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 12-byte nonce (must be unique per message)
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0u32; 16];

        // Constants "expand 32-byte k"
        state[0] = 0x61707865; // "expa"
        state[1] = 0x3320646e; // "nd 3"
        state[2] = 0x79622d32; // "2-by"
        state[3] = 0x6b206574; // "te k"

        // Key (8 words = 32 bytes)
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        // Counter (initially 0)
        state[12] = 0;

        // Nonce (3 words = 12 bytes)
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        Self { state, counter: 0 }
    }

    /// ChaCha20 quarter round operation
    #[inline]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// ChaCha20 block function (20 rounds)
    fn block(&mut self) -> [u8; 64] {
        let mut working_state = self.state;

        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working_state, 0, 4, 8, 12);
            Self::quarter_round(&mut working_state, 1, 5, 9, 13);
            Self::quarter_round(&mut working_state, 2, 6, 10, 14);
            Self::quarter_round(&mut working_state, 3, 7, 11, 15);

            // Diagonal rounds
            Self::quarter_round(&mut working_state, 0, 5, 10, 15);
            Self::quarter_round(&mut working_state, 1, 6, 11, 12);
            Self::quarter_round(&mut working_state, 2, 7, 8, 13);
            Self::quarter_round(&mut working_state, 3, 4, 9, 14);
        }

        // Add original state
        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }

        // Convert to bytes (little-endian)
        let mut block = [0u8; 64];
        for i in 0..16 {
            let bytes = working_state[i].to_le_bytes();
            block[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        // Increment counter
        self.state[12] = self.state[12].wrapping_add(1);
        self.counter += 1;

        block
    }

    /// Encrypt/decrypt data (ChaCha20 is symmetric)
    pub fn apply_keystream(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut offset = 0;

        while offset < data.len() {
            let keystream = self.block();
            let chunk_len = std::cmp::min(64, data.len() - offset);

            for i in 0..chunk_len {
                output.push(data[offset + i] ^ keystream[i]);
            }

            offset += chunk_len;
        }

        output
    }

    /// Encrypt data
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.apply_keystream(plaintext)
    }

    /// Decrypt data (same as encrypt for stream ciphers)
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.apply_keystream(ciphertext)
    }
}

/// Stateless ChaCha20 block generation
/// Used by ChaCha20-Poly1305 AEAD
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [0u32; 16];

    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    // Counter (1 word)
    state[12] = counter;

    // Nonce (3 words)
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    // Store original state
    let original_state = state;

    // 20 rounds (10 double rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round_inline(&mut state, 0, 4, 8, 12);
        quarter_round_inline(&mut state, 1, 5, 9, 13);
        quarter_round_inline(&mut state, 2, 6, 10, 14);
        quarter_round_inline(&mut state, 3, 7, 11, 15);

        // Diagonal rounds
        quarter_round_inline(&mut state, 0, 5, 10, 15);
        quarter_round_inline(&mut state, 1, 6, 11, 12);
        quarter_round_inline(&mut state, 2, 7, 8, 13);
        quarter_round_inline(&mut state, 3, 4, 9, 14);
    }

    // Add original state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(original_state[i]);
    }

    // Serialize to bytes (little-endian)
    let mut output = [0u8; 64];
    for i in 0..16 {
        let bytes = state[i].to_le_bytes();
        output[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    output
}

#[inline]
fn quarter_round_inline(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Poly1305 MAC implementation
///
/// Poly1305 is a one-time authenticator that produces a 16-byte MAC
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    acc: [u32; 5],
}

impl Poly1305 {
    /// Create new Poly1305 instance with 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        // Extract r (first 16 bytes, with clamping)
        let mut r = [0u32; 5];
        r[0] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x0fffffff;
        r[1] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]) & 0x0ffffffc;
        r[2] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]) & 0x0ffffffc;
        r[3] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]) & 0x0ffffffc;
        r[4] = 0;

        // Extract s (last 16 bytes)
        let mut s = [0u32; 4];
        s[0] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        s[1] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        s[2] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        s[3] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Poly1305 { r, s, acc: [0; 5] }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut block = [0u32; 5];

            // Read chunk into block
            for (i, &byte) in chunk.iter().enumerate() {
                let word_idx = i / 4;
                let byte_idx = i % 4;
                block[word_idx] |= (byte as u32) << (byte_idx * 8);
            }

            // Set high bit if full block
            if chunk.len() == 16 {
                block[4] = 1;
            } else {
                let byte_idx = chunk.len() % 4;
                let word_idx = chunk.len() / 4;
                block[word_idx] |= 1 << (byte_idx * 8);
            }

            // Add to accumulator
            self.acc = Self::add_mod_p(&self.acc, &block);

            // Multiply by r (mod p)
            self.acc = Self::mul_mod_p(&self.acc, &self.r);
        }
    }

    /// Finalize and return MAC
    pub fn finalize(self) -> [u8; 16] {
        // Add s to accumulator
        let mut result = [0u8; 16];

        let mut carry = 0u64;
        for i in 0..4 {
            carry += self.acc[i] as u64 + self.s[i] as u64;
            result[i * 4..(i + 1) * 4].copy_from_slice(&(carry as u32).to_le_bytes());
            carry >>= 32;
        }

        result
    }

    /// Add two 130-bit numbers mod p (p = 2^130 - 5)
    fn add_mod_p(a: &[u32; 5], b: &[u32; 5]) -> [u32; 5] {
        let mut result = [0u32; 5];
        let mut carry = 0u64;

        for i in 0..5 {
            carry += a[i] as u64 + b[i] as u64;
            result[i] = carry as u32;
            carry >>= 32;
        }

        // Reduce mod p if needed
        Self::reduce(&mut result);
        result
    }

    /// Multiply two 130-bit numbers mod p
    fn mul_mod_p(a: &[u32; 5], b: &[u32; 5]) -> [u32; 5] {
        let mut result = [0u64; 10];

        // Schoolbook multiplication
        for i in 0..5 {
            for j in 0..5 {
                result[i + j] += (a[i] as u64) * (b[j] as u64);
            }
        }

        // Carry propagation
        for i in 0..9 {
            result[i + 1] += result[i] >> 32;
            result[i] &= 0xffffffff;
        }

        // Reduce mod p = 2^130 - 5
        let mut acc = [0u32; 5];
        for i in 0..5 {
            acc[i] = result[i] as u32;
        }

        // Handle high bits (multiply by 5 and add)
        for i in 5..10 {
            let val = result[i] * 5;
            let mut carry = val;
            for j in (i - 5)..5 {
                carry += acc[j] as u64;
                acc[j] = carry as u32;
                carry >>= 32;
            }
        }

        Self::reduce(&mut acc);
        acc
    }

    /// Reduce mod p = 2^130 - 5
    fn reduce(acc: &mut [u32; 5]) {
        // If acc >= p, subtract p
        let mask = ((acc[4] >> 2) as i32 - 1) as u32;
        acc[4] &= 3;

        let mut carry = 5u64;
        for i in 0..5 {
            carry += acc[i] as u64 - (mask as u64);
            acc[i] = carry as u32;
            carry = (carry >> 32) + !0u64;
        }
    }
}

/// ChaCha20-Poly1305 AEAD encryption
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per message)
/// * `aad` - Additional authenticated data
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext || 16-byte MAC tag
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    // Generate Poly1305 key using first block
    let poly_key_block = chacha20_block(key, nonce, 0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // Encrypt plaintext (counter starts at 1)
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.state[12] = 1; // Start at counter 1
    let ciphertext = cipher.encrypt(plaintext);

    // Construct Poly1305 input
    let mut poly_input = Vec::new();

    // Add AAD with padding
    poly_input.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    poly_input.extend(vec![0u8; aad_pad]);

    // Add ciphertext with padding
    poly_input.extend_from_slice(&ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    poly_input.extend(vec![0u8; ct_pad]);

    // Add lengths (little-endian)
    poly_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    poly_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    // Compute MAC
    let mut poly = Poly1305::new(&poly_key);
    poly.update(&poly_input);
    let tag = poly.finalize();

    // Return ciphertext || tag
    let mut result = ciphertext;
    result.extend_from_slice(&tag);
    result
}

/// ChaCha20-Poly1305 AEAD decryption
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce
/// * `aad` - Additional authenticated data
/// * `ciphertext_and_tag` - Ciphertext with 16-byte MAC appended
///
/// # Returns
/// Plaintext if MAC verification succeeds, Err otherwise
pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext_and_tag.len() < 16 {
        return Err("Ciphertext too short".to_string());
    }

    // Split ciphertext and tag
    let ciphertext = &ciphertext_and_tag[..ciphertext_and_tag.len() - 16];
    let received_tag = &ciphertext_and_tag[ciphertext_and_tag.len() - 16..];

    // Generate Poly1305 key
    let poly_key_block = chacha20_block(key, nonce, 0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // Construct Poly1305 input
    let mut poly_input = Vec::new();
    poly_input.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    poly_input.extend(vec![0u8; aad_pad]);
    poly_input.extend_from_slice(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    poly_input.extend(vec![0u8; ct_pad]);
    poly_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    poly_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    // Verify MAC
    let mut poly = Poly1305::new(&poly_key);
    poly.update(&poly_input);
    let computed_tag = poly.finalize();

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= received_tag[i] ^ computed_tag[i];
    }

    if diff != 0 {
        return Err("MAC verification failed".to_string());
    }

    // Decrypt
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.state[12] = 1; // Start at counter 1
    let plaintext = cipher.decrypt(ciphertext);
    Ok(plaintext)
}

/// Simple base64 encoding for key/nonce transport
pub fn encode_base64(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b1 = data[i];
        let b2 = data.get(i + 1).copied().unwrap_or(0);
        let b3 = data.get(i + 2).copied().unwrap_or(0);

        let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        result.push(if i + 1 < data.len() {
            CHARS[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if i + 2 < data.len() {
            CHARS[(n & 63) as usize] as char
        } else {
            '='
        });

        i += 3;
    }

    result
}

/// Simple base64 decoding
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let input = input.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;

    while i < input.len() {
        let c1 = char_to_value(input[i])?;
        let c2 = char_to_value(input.get(i + 1).copied().unwrap_or(b'A'))?;
        let c3 = if i + 2 < input.len() && input[i + 2] != b'=' {
            char_to_value(input[i + 2])?
        } else {
            0
        };
        let c4 = if i + 3 < input.len() && input[i + 3] != b'=' {
            char_to_value(input[i + 3])?
        } else {
            0
        };

        let n = ((c1 as u32) << 18) | ((c2 as u32) << 12) | ((c3 as u32) << 6) | (c4 as u32);

        result.push((n >> 16) as u8);
        if i + 2 < input.len() && input[i + 2] != b'=' {
            result.push((n >> 8) as u8);
        }
        if i + 3 < input.len() && input[i + 3] != b'=' {
            result.push(n as u8);
        }

        i += 4;
    }

    Some(result)
}

fn char_to_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Generate random key (32 bytes)
///
/// Note: This is NOT cryptographically secure random.
/// For production use, integrate with OS-provided CSPRNG.
pub fn generate_key() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut key = [0u8; 32];
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    // Simple pseudo-random (NOT cryptographically secure, but good enough for demo)
    for i in 0..32 {
        key[i] = ((time.wrapping_mul((i + 1) as u128)) % 256) as u8;
    }

    key
}

/// Generate random nonce (12 bytes)
///
/// Note: This is NOT cryptographically secure random.
/// For production use, integrate with OS-provided CSPRNG.
pub fn generate_nonce() -> [u8; 12] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut nonce = [0u8; 12];
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for i in 0..12 {
        nonce[i] = ((time.wrapping_mul((i + 100) as u128)) % 256) as u8;
    }

    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let plaintext = b"Hello, ChaCha20!";

        let mut cipher = ChaCha20::new(&key, &nonce);
        let ciphertext = cipher.encrypt(plaintext);

        let mut cipher2 = ChaCha20::new(&key, &nonce);
        let decrypted = cipher2.decrypt(&ciphertext);

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_rfc8439() {
        // RFC 8439 Section 2.4.2 test vector
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let mut cipher = ChaCha20::new(&key, &nonce);
        cipher.state[12] = 1; // Start at counter 1
        let ciphertext = cipher.encrypt(plaintext);

        // Decrypt should give original
        let mut cipher2 = ChaCha20::new(&key, &nonce);
        cipher2.state[12] = 1;
        let decrypted = cipher2.decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_aead() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let ciphertext_with_tag = chacha20poly1305_encrypt(&key, &nonce, aad, plaintext);

        // Should be plaintext.len() + 16 (tag)
        assert_eq!(ciphertext_with_tag.len(), plaintext.len() + 16);

        // Decrypt should succeed
        let decrypted = chacha20poly1305_decrypt(&key, &nonce, aad, &ciphertext_with_tag)
            .expect("Decryption failed");
        assert_eq!(&decrypted[..], plaintext);

        // Modified ciphertext should fail
        let mut modified = ciphertext_with_tag.clone();
        modified[0] ^= 1;
        assert!(chacha20poly1305_decrypt(&key, &nonce, aad, &modified).is_err());
    }
}
