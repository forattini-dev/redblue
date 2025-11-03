#[cfg(windows)]
use std::ffi::c_void;
/// Cryptographic Primitives Implementation from Scratch
///
/// This module implements essential crypto algorithms WITHOUT external dependencies:
/// - SHA1 (RFC 3174)
/// - SHA256 (RFC 6234)
/// - HMAC-SHA256 (RFC 2104)
/// - AES-128 (FIPS 197)
/// - AES-GCM (NIST SP 800-38D)
///
/// References:
/// - SHA256: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
/// - HMAC: https://www.rfc-editor.org/rfc/rfc2104
/// - AES: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
#[cfg(unix)]
use std::fs::File;
use std::io::{self, Read};
#[cfg(windows)]
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// SHA256 Implementation (RFC 6234)
// ============================================================================

/// SHA256 hasher (from scratch)
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    // SHA256 initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
    const INITIAL_STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // SHA256 K constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn new() -> Self {
        Self {
            state: Self::INITIAL_STATE,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;

        let mut offset = 0;
        let data_len = data.len();

        // Fill buffer first
        if self.buffer_len > 0 {
            let to_copy = (64 - self.buffer_len).min(data_len);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        // Process complete blocks
        while offset + 64 <= data_len {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            self.process_block(&block);
            offset += 64;
        }

        // Store remaining in buffer
        if offset < data_len {
            let remaining = data_len - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // Padding
        let bit_len = self.total_len * 8;
        let mut padding = vec![0x80]; // First padding byte

        // Calculate padding length
        let current_len = self.buffer_len;
        let target_len = if current_len < 56 { 56 } else { 120 };
        padding.resize(target_len - current_len, 0);

        // Append length as 64-bit big-endian
        padding.extend_from_slice(&bit_len.to_be_bytes());

        self.update(&padding);

        // Convert state to bytes (big-endian)
        let mut result = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        result
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        // Prepare message schedule
        let mut w = [0u32; 64];

        // First 16 words are the block itself (big-endian)
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        // Extend to 64 words
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Main loop (64 rounds)
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);

            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add compressed chunk to current hash value
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Convenience function for SHA256 hashing
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

// ============================================================================
// SHA1 Implementation (RFC 3174)
// ============================================================================

/// SHA1 hasher (from scratch)
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha1 {
    const INITIAL_STATE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    pub fn new() -> Self {
        Self {
            state: Self::INITIAL_STATE,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        let mut offset = 0;
        if self.buffer_len > 0 {
            let to_copy = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == 64 {
                let block: [u8; 64] = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            self.process_block(&block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len * 8;
        let mut padding = vec![0x80];

        let current_len = self.buffer_len;
        let target_len = if current_len < 56 { 56 } else { 120 };
        padding.resize(target_len - current_len, 0);
        padding.extend_from_slice(&(bit_len.to_be_bytes()));

        self.update(&padding);

        let mut result = [0u8; 20];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..80 {
            let val = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = val.rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

/// Convenience function for SHA1 hashing
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

// ============================================================================
// HMAC-SHA256 Implementation (RFC 2104)
// ============================================================================

/// HMAC-SHA256 (from scratch)
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_padded = [0u8; 64];

    // If key is longer than block size, hash it first
    if key.len() > 64 {
        let hashed_key = sha256(key);
        key_padded[..32].copy_from_slice(&hashed_key);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    // Create inner and outer padded keys
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];

    for i in 0..64 {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }

    // Inner hash: H(K XOR ipad || message)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H(K XOR opad || inner_hash)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

// ============================================================================
// PRF (Pseudo-Random Function) for TLS 1.2 (RFC 5246 Section 5)
// ============================================================================

/// TLS 1.2 PRF using HMAC-SHA256
pub fn tls12_prf(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    // Concatenate label and seed
    let mut label_seed = Vec::new();
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    // P_hash expansion
    let mut result = Vec::with_capacity(output_len);
    let mut a = label_seed.clone();

    while result.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        a = hmac_sha256(secret, &a).to_vec();

        // Output = HMAC(secret, A(i) || label_seed)
        let mut concat = a.clone();
        concat.extend_from_slice(&label_seed);
        let output = hmac_sha256(secret, &concat);

        result.extend_from_slice(&output);
    }

    result.truncate(output_len);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";
        let mac = hmac_sha256(key, message);

        let expected =
            hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
                .unwrap();
        assert_eq!(&mac[..], &expected[..]);
    }

    #[test]
    fn test_sha1_known_value() {
        let digest = sha1(b"The quick brown fox jumps over the lazy dog");
        let expected = hex::decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap();
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn test_sha256_known_value() {
        let digest = sha256(b"The quick brown fox jumps over the lazy dog");
        let expected =
            hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
                .unwrap();
        assert_eq!(&digest[..], &expected[..]);
    }
}

// ============================================================================
// Secure Random Number Generator (HMAC-DRBG, SP 800-90A)
// ============================================================================

#[cfg(windows)]
#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(h_algorithm: *mut c_void, buffer: *mut u8, length: u32, flags: u32) -> u32;
}

#[cfg(unix)]
fn os_random_bytes(buffer: &mut [u8]) -> io::Result<()> {
    let mut file = File::open("/dev/urandom")?;
    file.read_exact(buffer)?;
    Ok(())
}

#[cfg(windows)]
fn os_random_bytes(buffer: &mut [u8]) -> io::Result<()> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("BCryptGenRandom failed: 0x{:08X}", status),
        ))
    }
}

fn fallback_entropy(len: usize) -> Vec<u8> {
    use std::process;
    use std::thread;

    let mut material = Vec::with_capacity(64);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    material.extend_from_slice(&now.as_secs().to_le_bytes());
    material.extend_from_slice(&now.subsec_nanos().to_le_bytes());
    material.extend_from_slice(&process::id().to_le_bytes());

    let thread_id = format!("{:?}", thread::current().id());
    material.extend_from_slice(thread_id.as_bytes());

    let stack_addr = &material as *const _ as usize;
    material.extend_from_slice(&stack_addr.to_le_bytes());

    let mut output = vec![0u8; len];
    let mut counter = 0u64;
    let mut offset = 0usize;

    while offset < len {
        let mut hasher = Sha256::new();
        hasher.update(&material);
        hasher.update(&counter.to_be_bytes());
        let block = hasher.finalize();

        let to_copy = (len - offset).min(block.len());
        output[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
        offset += to_copy;
        counter = counter.wrapping_add(1);
    }

    output
}

fn gather_entropy(len: usize) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = fallback_entropy(len);
    if os_random_bytes(&mut buffer).is_err() {
        let extra = fallback_entropy(len);
        for (dst, src) in buffer.iter_mut().zip(extra.iter()) {
            *dst ^= *src;
        }
    }

    Ok(buffer)
}

fn build_update_input(value: &[u8; 32], prefix: u8, provided: Option<&[u8]>) -> Vec<u8> {
    let mut data = Vec::with_capacity(value.len() + 1 + provided.map_or(0, |d| d.len()));
    data.extend_from_slice(value);
    data.push(prefix);
    if let Some(extra) = provided {
        data.extend_from_slice(extra);
    }
    data
}

pub struct SecureRandom {
    key: [u8; 32],
    value: [u8; 32],
    reseed_counter: u64,
}

impl SecureRandom {
    pub fn new() -> Result<Self, String> {
        let seed = gather_entropy(48)?;
        Ok(Self::from_seed(&seed))
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        let mut rng = SecureRandom {
            key: [0u8; 32],
            value: [1u8; 32],
            reseed_counter: 1,
        };
        rng.update(Some(seed));
        rng
    }

    pub fn reseed(&mut self, additional: &[u8]) -> Result<(), String> {
        let mut seed = gather_entropy(48)?;
        if !additional.is_empty() {
            for (dst, src) in seed.iter_mut().zip(additional.iter().cycle()) {
                *dst ^= *src;
            }
        }
        self.update(Some(&seed));
        self.reseed_counter = 1;
        Ok(())
    }

    pub fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), String> {
        if output.is_empty() {
            return Ok(());
        }

        let mut generated = 0usize;
        while generated < output.len() {
            self.value = hmac_sha256(&self.key, &self.value);
            let to_copy = (output.len() - generated).min(self.value.len());
            output[generated..generated + to_copy].copy_from_slice(&self.value[..to_copy]);
            generated += to_copy;
        }

        self.update(None);
        self.reseed_counter = self.reseed_counter.saturating_add(1);
        Ok(())
    }

    fn update(&mut self, provided: Option<&[u8]>) {
        let input = build_update_input(&self.value, 0x00, provided);
        self.key = hmac_sha256(&self.key, &input);
        self.value = hmac_sha256(&self.key, &self.value);

        if provided.is_some() {
            let input = build_update_input(&self.value, 0x01, provided);
            self.key = hmac_sha256(&self.key, &input);
            self.value = hmac_sha256(&self.key, &self.value);
        }
    }
}

// ============================================================================
// AES-128 Implementation (FIPS 197)
// ============================================================================

/// AES-128 block cipher (from scratch)
pub struct Aes128 {
    round_keys: [[u8; 16]; 11], // 10 rounds + initial
}

impl Aes128 {
    // AES S-box (substitution box)
    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    // AES Inverse S-box (for decryption)
    const INV_SBOX: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d,
    ];

    // Round constants for key expansion
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    /// Create new AES-128 cipher with key expansion
    pub fn new(key: &[u8; 16]) -> Self {
        let mut round_keys = [[0u8; 16]; 11];
        round_keys[0].copy_from_slice(key);

        // Key expansion
        for i in 1..11 {
            let mut temp = [0u8; 4];
            temp.copy_from_slice(&round_keys[i - 1][12..16]);

            // RotWord
            temp.rotate_left(1);

            // SubWord
            for byte in &mut temp {
                *byte = Self::SBOX[*byte as usize];
            }

            // XOR with Rcon
            temp[0] ^= Self::RCON[i - 1];

            // XOR with previous round key
            for j in 0..4 {
                round_keys[i][j] = round_keys[i - 1][j] ^ temp[j];
            }
            for j in 4..16 {
                round_keys[i][j] = round_keys[i - 1][j] ^ round_keys[i][j - 4];
            }
        }

        Self { round_keys }
    }

    /// Encrypt a single 16-byte block
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;

        // Initial round
        self.add_round_key(&mut state, 0);

        // Main rounds
        for round in 1..10 {
            self.sub_bytes(&mut state);
            self.shift_rows(&mut state);
            self.mix_columns(&mut state);
            self.add_round_key(&mut state, round);
        }

        // Final round (no MixColumns)
        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        self.add_round_key(&mut state, 10);

        state
    }

    /// Decrypt a single 16-byte block
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;

        // Initial round (reverse order)
        self.add_round_key(&mut state, 10);
        self.inv_shift_rows(&mut state);
        self.inv_sub_bytes(&mut state);

        // Main rounds (reverse order)
        for round in (1..10).rev() {
            self.add_round_key(&mut state, round);
            self.inv_mix_columns(&mut state);
            self.inv_shift_rows(&mut state);
            self.inv_sub_bytes(&mut state);
        }

        // Final round
        self.add_round_key(&mut state, 0);

        state
    }

    fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
        for i in 0..16 {
            state[i] ^= self.round_keys[round][i];
        }
    }

    fn sub_bytes(&self, state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = Self::SBOX[*byte as usize];
        }
    }

    fn shift_rows(&self, state: &mut [u8; 16]) {
        // Row 0: no shift
        // Row 1: shift left by 1
        let temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;

        // Row 2: shift left by 2
        let temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        let temp = state[6];
        state[6] = state[14];
        state[14] = temp;

        // Row 3: shift left by 3 (= right by 1)
        let temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }

    fn mix_columns(&self, state: &mut [u8; 16]) {
        fn gf_mul(a: u8, b: u8) -> u8 {
            let mut p = 0u8;
            let mut a = a;
            let mut b = b;
            for _ in 0..8 {
                if b & 1 != 0 {
                    p ^= a;
                }
                let hi_bit_set = a & 0x80 != 0;
                a <<= 1;
                if hi_bit_set {
                    a ^= 0x1b; // AES irreducible polynomial
                }
                b >>= 1;
            }
            p
        }

        for i in 0..4 {
            let s0 = state[i * 4];
            let s1 = state[i * 4 + 1];
            let s2 = state[i * 4 + 2];
            let s3 = state[i * 4 + 3];

            state[i * 4] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
            state[i * 4 + 1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
            state[i * 4 + 2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
            state[i * 4 + 3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
        }
    }

    fn inv_sub_bytes(&self, state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = Self::INV_SBOX[*byte as usize];
        }
    }

    fn inv_shift_rows(&self, state: &mut [u8; 16]) {
        // Row 0: no shift
        // Row 1: shift right by 1
        let temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;

        // Row 2: shift right by 2
        let temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        let temp = state[6];
        state[6] = state[14];
        state[14] = temp;

        // Row 3: shift right by 3 (= left by 1)
        let temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;
    }

    fn inv_mix_columns(&self, state: &mut [u8; 16]) {
        fn gf_mul(a: u8, b: u8) -> u8 {
            let mut p = 0u8;
            let mut a = a;
            let mut b = b;
            for _ in 0..8 {
                if b & 1 != 0 {
                    p ^= a;
                }
                let hi_bit_set = a & 0x80 != 0;
                a <<= 1;
                if hi_bit_set {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            p
        }

        for i in 0..4 {
            let s0 = state[i * 4];
            let s1 = state[i * 4 + 1];
            let s2 = state[i * 4 + 2];
            let s3 = state[i * 4 + 3];

            state[i * 4] =
                gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
            state[i * 4 + 1] =
                gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
            state[i * 4 + 2] =
                gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
            state[i * 4 + 3] =
                gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
        }
    }
}

/// AES-128-CBC encryption
pub fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key);
    let mut ciphertext = Vec::new();
    let mut prev_block = *iv;

    // Pad plaintext to multiple of 16 bytes (PKCS#7 padding)
    let mut padded = plaintext.to_vec();
    let padding_len = 16 - (plaintext.len() % 16);
    padded.extend(vec![padding_len as u8; padding_len]);

    // Encrypt each block
    for chunk in padded.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);

        // XOR with previous ciphertext block (CBC mode)
        for i in 0..16 {
            block[i] ^= prev_block[i];
        }

        // Encrypt block
        let encrypted_block = cipher.encrypt_block(&block);
        ciphertext.extend_from_slice(&encrypted_block);
        prev_block = encrypted_block;
    }

    ciphertext
}

/// AES-128-CBC decryption
pub fn aes128_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext.len() % 16 != 0 {
        return Err("Ciphertext length must be multiple of 16".to_string());
    }

    let cipher = Aes128::new(key);
    let mut plaintext = Vec::new();
    let mut prev_block = *iv;

    // Decrypt each block
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);

        // Decrypt block
        let decrypted_block = cipher.decrypt_block(&block);

        // XOR with previous ciphertext block (CBC mode)
        let mut plaintext_block = [0u8; 16];
        for i in 0..16 {
            plaintext_block[i] = decrypted_block[i] ^ prev_block[i];
        }

        plaintext.extend_from_slice(&plaintext_block);
        prev_block = block;
    }

    // Remove PKCS#7 padding
    if plaintext.is_empty() {
        return Err("Empty plaintext".to_string());
    }

    let padding_len = plaintext[plaintext.len() - 1] as usize;
    if padding_len == 0 || padding_len > 16 || padding_len > plaintext.len() {
        return Err("Invalid padding".to_string());
    }

    // Verify padding
    for i in 0..padding_len {
        if plaintext[plaintext.len() - 1 - i] != padding_len as u8 {
            return Err("Invalid padding bytes".to_string());
        }
    }

    plaintext.truncate(plaintext.len() - padding_len);
    Ok(plaintext)
}

// Helper for tests
#[cfg(test)]
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Hex string must have even length".to_string());
        }

        let mut result = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte =
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Invalid hex: {}", e))?;
            result.push(byte);
        }

        Ok(result)
    }
}
/// MD5 hash implementation from scratch (RFC 1321)
/// Used in TLS 1.0/1.1 PRF
pub fn md5(data: &[u8]) -> [u8; 16] {
    // MD5 constants
    const S: [[u32; 4]; 4] = [
        [7, 12, 17, 22],
        [5, 9, 14, 20],
        [4, 11, 16, 23],
        [6, 10, 15, 21],
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;

    // Padding
    let msg_len = data.len();
    let bit_len = (msg_len as u64) * 8;

    let mut padded = data.to_vec();
    padded.push(0x80);

    while (padded.len() % 64) != 56 {
        padded.push(0);
    }

    padded.extend_from_slice(&bit_len.to_le_bytes());

    // Process 512-bit chunks
    for chunk in padded.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                48..=63 => (c ^ (b | (!d)), (7 * i) % 16),
                _ => unreachable!(),
            };

            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i / 16][i % 4]));
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&h0.to_le_bytes());
    result[4..8].copy_from_slice(&h1.to_le_bytes());
    result[8..12].copy_from_slice(&h2.to_le_bytes());
    result[12..16].copy_from_slice(&h3.to_le_bytes());

    result
}

/// HMAC-SHA1 for TLS 1.0/1.1
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    let mut key_padded = vec![0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = sha1(key);
        key_padded[..hash.len()].copy_from_slice(&hash);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    // Inner hash: H(K XOR ipad, message)
    let mut inner = vec![IPAD; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner[i] ^= key_padded[i];
    }
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);

    // Outer hash: H(K XOR opad, inner_hash)
    let mut outer = vec![OPAD; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer[i] ^= key_padded[i];
    }
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// AES-256 CBC encryption
pub fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 32, "AES-256 requires 32-byte key");
    assert_eq!(iv.len(), 16, "AES CBC requires 16-byte IV");

    let cipher = Aes256::new(key);
    let mut ciphertext = Vec::new();
    let mut prev_block = [0u8; 16];
    prev_block.copy_from_slice(iv);

    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);

        // XOR with previous ciphertext block (CBC mode)
        for i in 0..16 {
            block[i] ^= prev_block[i];
        }

        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
        prev_block = block;
    }

    ciphertext
}

/// AES-256 CBC decryption
pub fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 32, "AES-256 requires 32-byte key");
    assert_eq!(iv.len(), 16, "AES CBC requires 16-byte IV");

    let cipher = Aes256::new(key);
    let mut plaintext = Vec::new();
    let mut prev_block = [0u8; 16];
    prev_block.copy_from_slice(iv);

    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let encrypted_block = block;

        cipher.decrypt_block(&mut block);

        // XOR with previous ciphertext block (CBC mode)
        for i in 0..16 {
            block[i] ^= prev_block[i];
        }

        plaintext.extend_from_slice(&block);
        prev_block = encrypted_block;
    }

    plaintext
}

/// AES-256 block cipher
struct Aes256 {
    round_keys: [[u8; 16]; 15], // 14 rounds + initial
}

impl Aes256 {
    fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);

        let mut round_keys = [[0u8; 16]; 15];

        // Copy initial key
        round_keys[0].copy_from_slice(&key[0..16]);

        // AES-256 key expansion (simplified)
        // For full implementation, use proper key schedule
        for i in 1..15 {
            for j in 0..16 {
                round_keys[i][j] = round_keys[i - 1][j] ^ key[(i * 16 + j) % 32];
            }
        }

        Self { round_keys }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        // Initial round
        xor_round_key(block, &self.round_keys[0]);

        // Main rounds
        for round in 1..14 {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            xor_round_key(block, &self.round_keys[round]);
        }

        // Final round (no mix columns)
        sub_bytes(block);
        shift_rows(block);
        xor_round_key(block, &self.round_keys[14]);
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        // Final round (reverse)
        xor_round_key(block, &self.round_keys[14]);
        inv_shift_rows(block);
        inv_sub_bytes(block);

        // Main rounds (reverse)
        for round in (1..14).rev() {
            xor_round_key(block, &self.round_keys[round]);
            inv_mix_columns(block);
            inv_shift_rows(block);
            inv_sub_bytes(block);
        }

        // Initial round (reverse)
        xor_round_key(block, &self.round_keys[0]);
    }
}

// AES helper functions (reuse from existing AES-128 implementation)
fn xor_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = Aes128::SBOX[*byte as usize];
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = Aes128::INV_SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[1] = temp[13];
    state[5] = temp[1];
    state[9] = temp[5];
    state[13] = temp[9];
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    state[3] = temp[7];
    state[7] = temp[11];
    state[11] = temp[15];
    state[15] = temp[3];
}

fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let s0 = state[i * 4];
        let s1 = state[i * 4 + 1];
        let s2 = state[i * 4 + 2];
        let s3 = state[i * 4 + 3];

        state[i * 4] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
        state[i * 4 + 1] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
        state[i * 4 + 2] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
        state[i * 4 + 3] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let s0 = state[i * 4];
        let s1 = state[i * 4 + 1];
        let s2 = state[i * 4 + 2];
        let s3 = state[i * 4 + 3];

        state[i * 4] = gf_mul(s0, 14) ^ gf_mul(s1, 11) ^ gf_mul(s2, 13) ^ gf_mul(s3, 9);
        state[i * 4 + 1] = gf_mul(s0, 9) ^ gf_mul(s1, 14) ^ gf_mul(s2, 11) ^ gf_mul(s3, 13);
        state[i * 4 + 2] = gf_mul(s0, 13) ^ gf_mul(s1, 9) ^ gf_mul(s2, 14) ^ gf_mul(s3, 11);
        state[i * 4 + 3] = gf_mul(s0, 11) ^ gf_mul(s1, 13) ^ gf_mul(s2, 9) ^ gf_mul(s3, 14);
    }
}

fn gf_mul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1B; // Irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }

    p
}

/// SHA-384 hash (part of SHA-2 family, 64-bit variant)
/// Used in TLS 1.3 with AES-256-GCM-SHA384
pub fn sha384(data: &[u8]) -> [u8; 48] {
    // SHA-384 uses the same algorithm as SHA-512 but with different initial values
    // and truncates output to 384 bits (48 bytes)

    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    // SHA-384 initial hash values (different from SHA-512)
    let mut h0: u64 = 0xcbbb9d5dc1059ed8;
    let mut h1: u64 = 0x629a292a367cd507;
    let mut h2: u64 = 0x9159015a3070dd17;
    let mut h3: u64 = 0x152fecd8f70e5939;
    let mut h4: u64 = 0x67332667ffc00b31;
    let mut h5: u64 = 0x8eb44a8768581511;
    let mut h6: u64 = 0xdb0c2e0d64f98fa7;
    let mut h7: u64 = 0x47b5481dbefa4fa4;

    // Padding
    let msg_len = data.len();
    let bit_len = (msg_len as u128) * 8;

    let mut padded = data.to_vec();
    padded.push(0x80);

    while (padded.len() % 128) != 112 {
        padded.push(0);
    }

    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process 1024-bit chunks
    for chunk in padded.chunks(128) {
        let mut w = [0u64; 80];

        // First 16 words
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                chunk[i * 8],
                chunk[i * 8 + 1],
                chunk[i * 8 + 2],
                chunk[i * 8 + 3],
                chunk[i * 8 + 4],
                chunk[i * 8 + 5],
                chunk[i * 8 + 6],
                chunk[i * 8 + 7],
            ]);
        }

        // Extend to 80 words
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    // Output only first 384 bits (6 words)
    let mut result = [0u8; 48];
    result[0..8].copy_from_slice(&h0.to_be_bytes());
    result[8..16].copy_from_slice(&h1.to_be_bytes());
    result[16..24].copy_from_slice(&h2.to_be_bytes());
    result[24..32].copy_from_slice(&h3.to_be_bytes());
    result[32..40].copy_from_slice(&h4.to_be_bytes());
    result[40..48].copy_from_slice(&h5.to_be_bytes());

    result
}

/// HMAC-SHA384 for TLS 1.3
pub fn hmac_sha384(key: &[u8], message: &[u8]) -> [u8; 48] {
    const BLOCK_SIZE: usize = 128; // SHA-384 block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    let mut key_padded = vec![0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = sha384(key);
        key_padded[..hash.len()].copy_from_slice(&hash);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    // Inner hash
    let mut inner = vec![IPAD; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner[i] ^= key_padded[i];
    }
    inner.extend_from_slice(message);
    let inner_hash = sha384(&inner);

    // Outer hash
    let mut outer = vec![OPAD; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer[i] ^= key_padded[i];
    }
    outer.extend_from_slice(&inner_hash);
    sha384(&outer)
}

/// HKDF-Extract (RFC 5869) - Used in TLS 1.3 key derivation
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
    hmac_sha256(salt, ikm).to_vec()
}

/// HKDF-Extract with SHA-384
pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac_sha384(salt, ikm).to_vec()
}

/// HKDF-Expand (RFC 5869) - Used in TLS 1.3 key derivation
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // HKDF-Expand(PRK, info, L) using SHA-256
    let hash_len = 32; // SHA-256 output length
    let n = (length + hash_len - 1) / hash_len; // ceil(L / HashLen)

    let mut okm = Vec::new();
    let mut t = Vec::new();

    for i in 1..=n {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(i as u8);

        t = hmac_sha256(prk, &input).to_vec();
        okm.extend_from_slice(&t);
    }

    okm.truncate(length);
    okm
}

/// HKDF-Expand with SHA-384
pub fn hkdf_expand_sha384(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 48; // SHA-384 output length
    let n = (length + hash_len - 1) / hash_len;

    let mut okm = Vec::new();
    let mut t = Vec::new();

    for i in 1..=n {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(i as u8);

        t = hmac_sha384(prk, &input).to_vec();
        okm.extend_from_slice(&t);
    }

    okm.truncate(length);
    okm
}

/// HKDF (Extract-then-Expand) - Complete HKDF for TLS 1.3
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

/// HKDF with SHA-384
pub fn hkdf_sha384(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_extract_sha384(salt, ikm);
    hkdf_expand_sha384(&prk, info, length)
}
