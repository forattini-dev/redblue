//! SHA-1 hash implementation (FIPS PUB 180-4)
//! Minimal, dependency-free digest used for TLS 1.0/1.1/1.2 CBC HMACs.

pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    length_bits: u64,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buffer: [0u8; 64],
            buffer_len: 0,
            length_bits: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;
            self.length_bits = self.length_bits.wrapping_add(8);

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        // Append 0x80 byte
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough space for length, process block
        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
        }

        // Pad with zeros up to last 8 bytes
        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        // Append message length in bits (big endian)
        self.buffer[56..64].copy_from_slice(&self.length_bits.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        // Produce digest
        let mut digest = [0u8; 20];
        for (i, chunk) in digest.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&self.state[i].to_be_bytes());
        }
        digest
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];

        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for (i, &word) in w.iter().enumerate() {
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
                .wrapping_add(word);
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

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_empty() {
        let digest = sha1(b"");
        assert_eq!(
            digest,
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn test_sha1_abc() {
        let digest = sha1(b"abc");
        assert_eq!(
            digest,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }
}
