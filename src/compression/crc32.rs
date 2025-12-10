/// CRC32 implementation (IEEE 802.3 polynomial)
/// Used for gzip file integrity verification (RFC 1952)

/// CRC32 lookup table for fast computation
/// Polynomial: 0xEDB88320 (reversed representation of 0x04C11DB7)
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// CRC32 hasher for streaming checksum computation
pub struct Crc32 {
    state: u32,
    len: usize,
}

impl Crc32 {
    /// Create a new CRC32 hasher
    pub fn new() -> Self {
        Self {
            state: 0xFFFFFFFF,
            len: 0,
        }
    }

    /// Update the CRC with more data
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.state ^ byte as u32) & 0xFF) as usize;
            self.state = (self.state >> 8) ^ CRC32_TABLE[index];
        }
        self.len += data.len();
    }

    /// Finalize and return the CRC32 checksum
    #[inline]
    pub fn finalize(&self) -> u32 {
        self.state ^ 0xFFFFFFFF
    }

    /// Get the number of bytes processed
    pub fn len(&self) -> usize {
        self.len
    }

    /// Reset the hasher state
    pub fn reset(&mut self) {
        self.state = 0xFFFFFFFF;
        self.len = 0;
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute CRC32 of a byte slice in one shot
pub fn crc32(data: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(&[]), 0x00000000);
    }

    #[test]
    fn test_crc32_hello() {
        // "hello" should produce CRC32 = 0x3610A686
        let result = crc32(b"hello");
        assert_eq!(result, 0x3610A686);
    }

    #[test]
    fn test_crc32_streaming() {
        let mut hasher = Crc32::new();
        hasher.update(b"hel");
        hasher.update(b"lo");
        assert_eq!(hasher.finalize(), crc32(b"hello"));
    }

    #[test]
    fn test_crc32_check_value() {
        // Standard test: CRC32 of "123456789" = 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }
}
