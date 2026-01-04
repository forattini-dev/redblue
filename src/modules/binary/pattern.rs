//! De Bruijn Pattern Generation
//!
//! Generates cyclic patterns for finding buffer overflow offsets.

/// De Bruijn pattern generator
pub struct PatternGenerator {
    /// Alphabet for pattern generation
    alphabet: Vec<u8>,
    /// Pattern length
    length: usize,
}

impl PatternGenerator {
    /// Create pattern generator with default alphabet
    pub fn new(length: usize) -> Self {
        // Default alphabet: uppercase, lowercase, digits
        let mut alphabet = Vec::new();
        alphabet.extend(b'A'..=b'Z');
        alphabet.extend(b'a'..=b'z');
        alphabet.extend(b'0'..=b'9');

        Self { alphabet, length }
    }

    /// Create with custom alphabet
    pub fn with_alphabet(length: usize, alphabet: Vec<u8>) -> Self {
        Self { alphabet, length }
    }

    /// Generate De Bruijn pattern
    pub fn generate(&self) -> Vec<u8> {
        let n = 4; // 4-byte subsequences for unique patterns
        let k = self.alphabet.len();

        if k == 0 {
            return Vec::new();
        }

        // Generate De Bruijn sequence
        let mut sequence = self.de_bruijn(k, n);

        // Truncate to requested length
        sequence.truncate(self.length);

        sequence
    }

    /// Generate De Bruijn sequence using FKM algorithm
    fn de_bruijn(&self, k: usize, n: usize) -> Vec<u8> {
        let mut a = vec![0usize; k * n];

        fn db(
            t: usize,
            p: usize,
            n: usize,
            k: usize,
            a: &mut Vec<usize>,
            sequence: &mut Vec<usize>,
        ) {
            if t > n {
                if n % p == 0 {
                    for i in 1..=p {
                        sequence.push(a[i]);
                    }
                }
            } else {
                a[t] = a[t - p];
                db(t + 1, p, n, k, a, sequence);
                for j in (a[t - p] + 1)..k {
                    a[t] = j;
                    db(t + 1, t, n, k, a, sequence);
                }
            }
        }

        let mut indices = Vec::new();
        db(1, 1, n, k, &mut a, &mut indices);

        // Convert indices to bytes
        indices
            .iter()
            .map(|&i| self.alphabet[i % self.alphabet.len()])
            .collect()
    }

    /// Generate pattern as string
    pub fn generate_string(&self) -> String {
        String::from_utf8_lossy(&self.generate()).to_string()
    }
}

/// Pattern offset finder
pub struct Pattern;

impl Pattern {
    /// Generate pattern of given length
    pub fn create(length: usize) -> Vec<u8> {
        PatternGenerator::new(length).generate()
    }

    /// Generate pattern as string
    pub fn create_string(length: usize) -> String {
        PatternGenerator::new(length).generate_string()
    }

    /// Find offset of substring in pattern
    pub fn find_offset(pattern: &str) -> Option<usize> {
        // Generate a large pattern to search in
        let full_pattern = Self::create_string(20000);
        full_pattern.find(pattern)
    }

    /// Find offset from hex value (little-endian)
    pub fn find_offset_le(value: u32) -> Option<usize> {
        let bytes = value.to_le_bytes();
        let pattern = String::from_utf8_lossy(&bytes).to_string();
        Self::find_offset(&pattern)
    }

    /// Find offset from hex value (big-endian)
    pub fn find_offset_be(value: u32) -> Option<usize> {
        let bytes = value.to_be_bytes();
        let pattern = String::from_utf8_lossy(&bytes).to_string();
        Self::find_offset(&pattern)
    }

    /// Find offset from hex string
    pub fn find_offset_hex(hex: &str) -> Option<(usize, &'static str)> {
        // Parse hex string
        let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
        let value = u32::from_str_radix(hex, 16).ok()?;

        // Try little-endian first (most common)
        if let Some(offset) = Self::find_offset_le(value) {
            return Some((offset, "little-endian"));
        }

        // Try big-endian
        if let Some(offset) = Self::find_offset_be(value) {
            return Some((offset, "big-endian"));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_generation() {
        let pattern = Pattern::create(100);
        assert_eq!(pattern.len(), 100);
    }

    #[test]
    fn test_pattern_uniqueness() {
        let pattern = Pattern::create_string(1000);

        // Check that 4-byte substrings are unique
        let mut seen = std::collections::HashSet::new();
        for i in 0..pattern.len().saturating_sub(3) {
            let sub = &pattern[i..i + 4];
            assert!(seen.insert(sub.to_string()), "Duplicate substring: {}", sub);
        }
    }

    #[test]
    fn test_find_offset() {
        let pattern = Pattern::create_string(200);

        // Find a known substring
        let sub = &pattern[50..54];
        let offset = Pattern::find_offset(sub);
        assert_eq!(offset, Some(50));
    }

    #[test]
    fn test_find_offset_hex() {
        // Generate pattern and get value at offset 100
        let pattern = Pattern::create(200);
        if pattern.len() >= 104 {
            let bytes: [u8; 4] = pattern[100..104].try_into().unwrap();
            let value = u32::from_le_bytes(bytes);

            let result = Pattern::find_offset_le(value);
            assert_eq!(result, Some(100));
        }
    }
}
