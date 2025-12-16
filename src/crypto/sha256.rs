/// SHA-256 implementation
///
/// On non-Windows platforms: Uses OpenSSL (boring) for performance and hardware acceleration.
/// On Windows: Uses pure Rust implementation (no external dependencies).

// Use boring on non-Windows platforms
#[cfg(not(target_os = "windows"))]
mod boring_impl {
    use boring::hash::{hash, MessageDigest};
    use boring::sha;

    /// Compute SHA-256 hash of data (one-shot)
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let result = hash(MessageDigest::sha256(), data).expect("SHA-256 hash failed");
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// Incremental SHA-256 hasher
    #[derive(Clone)]
    pub struct Sha256 {
        hasher: sha::Sha256,
    }

    impl Sha256 {
        pub fn new() -> Self {
            Sha256 {
                hasher: sha::Sha256::new(),
            }
        }

        pub fn update(&mut self, data: &[u8]) {
            self.hasher.update(data);
        }

        pub fn finalize(self) -> [u8; 32] {
            self.hasher.finish()
        }
    }
}

// Pure Rust implementation for Windows
#[cfg(target_os = "windows")]
mod pure_impl {
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

    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[inline]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline]
    fn bsig0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline]
    fn bsig1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline]
    fn ssig0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline]
    fn ssig1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn process_block(state: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 64];

        // Prepare message schedule
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = ssig1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(ssig0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(bsig1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    /// Compute SHA-256 hash of data (one-shot)
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Incremental SHA-256 hasher
    #[derive(Clone)]
    pub struct Sha256 {
        state: [u32; 8],
        buffer: [u8; 64],
        buffer_len: usize,
        total_len: u64,
    }

    impl Sha256 {
        pub fn new() -> Self {
            Sha256 {
                state: H0,
                buffer: [0u8; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }

        pub fn update(&mut self, data: &[u8]) {
            let mut offset = 0;
            self.total_len += data.len() as u64;

            // Fill buffer if we have leftover
            if self.buffer_len > 0 {
                let to_copy = std::cmp::min(64 - self.buffer_len, data.len());
                self.buffer[self.buffer_len..self.buffer_len + to_copy]
                    .copy_from_slice(&data[..to_copy]);
                self.buffer_len += to_copy;
                offset = to_copy;

                if self.buffer_len == 64 {
                    let block = self.buffer;
                    process_block(&mut self.state, &block);
                    self.buffer_len = 0;
                }
            }

            // Process full blocks
            while offset + 64 <= data.len() {
                process_block(&mut self.state, &data[offset..offset + 64]);
                offset += 64;
            }

            // Save remaining
            if offset < data.len() {
                let remaining = data.len() - offset;
                self.buffer[..remaining].copy_from_slice(&data[offset..]);
                self.buffer_len = remaining;
            }
        }

        pub fn finalize(mut self) -> [u8; 32] {
            // Padding
            let bit_len = self.total_len * 8;
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;

            if self.buffer_len > 56 {
                // Need two blocks
                self.buffer[self.buffer_len..64].fill(0);
                let block = self.buffer;
                process_block(&mut self.state, &block);
                self.buffer_len = 0;
                self.buffer.fill(0);
            } else {
                self.buffer[self.buffer_len..56].fill(0);
            }

            // Append length
            self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
            process_block(&mut self.state, &self.buffer);

            // Output
            let mut output = [0u8; 32];
            for (i, &word) in self.state.iter().enumerate() {
                output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
            }
            output
        }
    }
}

// Re-export the appropriate implementation
#[cfg(not(target_os = "windows"))]
pub use boring_impl::*;

#[cfg(target_os = "windows")]
pub use pure_impl::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(result, expected);

        let mut hasher = Sha256::new();
        let result_inc = hasher.finalize();
        assert_eq!(result_inc, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let result = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(result, expected);

        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let result_inc = hasher.finalize();
        assert_eq!(result_inc, expected);
    }

    #[test]
    fn test_sha256_longer() {
        let data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let result = sha256(data);
        let expected = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(result, expected);

        let mut hasher = Sha256::new();
        hasher.update(data);
        let result_inc = hasher.finalize();
        assert_eq!(result_inc, expected);
    }

    #[test]
    fn test_sha256_million_a() {
        let data = vec![b'a'; 1_000_000];
        let result = sha256(&data);
        let expected = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];
        assert_eq!(result, expected);

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result_inc = hasher.finalize();
        assert_eq!(result_inc, expected);
    }
}
