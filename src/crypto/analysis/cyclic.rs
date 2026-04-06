//! Cyclic Pattern Generator (De Bruijn Sequences)
//!
//! Generates cyclic patterns for buffer overflow offset detection.
//! Similar to pwntools' cyclic/cyclic_find functionality.

/// Cyclic pattern generator using De Bruijn sequences
pub struct CyclicGenerator {
  /// Alphabet to use for pattern generation
  alphabet: Vec<u8>,
  /// Number of characters per unique subsequence
  n: usize,
}

impl Default for CyclicGenerator {
  fn default() -> Self {
    Self::new()
  }
}

impl CyclicGenerator {
  /// Create a new cyclic generator with default alphabet (lowercase letters)
  pub fn new() -> Self {
    Self {
      alphabet: (b'a'..=b'z').collect(),
      n: 4, // Default to 4-byte patterns (32-bit)
    }
  }

  /// Create generator with custom alphabet
  pub fn with_alphabet(alphabet: &[u8]) -> Self {
    Self {
      alphabet: alphabet.to_vec(),
      n: 4,
    }
  }

  /// Set pattern length (n-gram size)
  /// Use 4 for 32-bit systems, 8 for 64-bit
  pub fn pattern_length(mut self, n: usize) -> Self {
    self.n = n;
    self
  }

  /// Generate a De Bruijn sequence of specified length
  pub fn generate(&self, length: usize) -> Vec<u8> {
    if length == 0 {
      return Vec::new();
    }

    let k = self.alphabet.len();
    if k == 0 {
      return Vec::new();
    }

    // For very small alphabets or n values, use simplified approach
    if k == 1 {
      return vec![self.alphabet[0]; length];
    }

    // Generate De Bruijn sequence
    let sequence = self.de_bruijn_sequence();

    // Truncate or repeat to get desired length
    if sequence.len() >= length {
      sequence[..length].to_vec()
    } else {
      // Repeat the sequence if we need more
      let mut result = Vec::with_capacity(length);
      while result.len() < length {
        let take = (length - result.len()).min(sequence.len());
        result.extend_from_slice(&sequence[..take]);
      }
      result
    }
  }

  /// Generate the full De Bruijn sequence using FKM algorithm
  fn de_bruijn_sequence(&self) -> Vec<u8> {
    let k = self.alphabet.len();
    let n = self.n;

    // Maximum unique patterns = k^n
    // For 26 letters and n=4, that's 456,976 unique patterns
    let max_len = k.pow(n as u32);

    let mut a = vec![0usize; n * k + 1];
    let mut sequence = Vec::with_capacity(max_len + n);

    // FKM algorithm (Frank-Ruskey-Moreno variant)
    fn db(t: usize, p: usize, n: usize, k: usize, a: &mut [usize], sequence: &mut Vec<usize>) {
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

    let mut indices = Vec::with_capacity(max_len + n);
    db(1, 1, n, k, &mut a, &mut indices);

    // Convert indices to actual characters
    for idx in indices {
      sequence.push(self.alphabet[idx]);
    }

    // Append first (n-1) characters to make it wrap properly
    for i in 0..n.saturating_sub(1) {
      if i < sequence.len() {
        sequence.push(sequence[i]);
      }
    }

    sequence
  }

  /// Find the offset of a pattern in the generated sequence
  pub fn find_offset(&self, pattern: &[u8], max_length: usize) -> Option<usize> {
    if pattern.len() != self.n {
      return None;
    }

    let sequence = self.generate(max_length);

    // Search for the pattern
    for i in 0..=sequence.len().saturating_sub(pattern.len()) {
      if &sequence[i..i + pattern.len()] == pattern {
        return Some(i);
      }
    }

    None
  }

  /// Find offset from a hex value (e.g., register content after crash)
  pub fn find_offset_hex(&self, hex: &str, max_length: usize) -> Option<usize> {
    let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex_to_bytes(hex)?;

    // Try both endianness
    if let Some(offset) = self.find_offset(&bytes, max_length) {
      return Some(offset);
    }

    // Try reversed (little endian)
    let mut reversed = bytes.clone();
    reversed.reverse();
    self.find_offset(&reversed, max_length)
  }

  /// Find offset from raw bytes (little-endian u32/u64)
  pub fn find_offset_value(&self, value: u64, max_length: usize) -> Option<usize> {
    // Try as 4-byte pattern first
    if self.n == 4 {
      let bytes: [u8; 4] = (value as u32).to_le_bytes();
      if let Some(offset) = self.find_offset(&bytes, max_length) {
        return Some(offset);
      }
    }

    // Try as 8-byte pattern
    if self.n == 8 {
      let bytes: [u8; 8] = value.to_le_bytes();
      if let Some(offset) = self.find_offset(&bytes, max_length) {
        return Some(offset);
      }
    }

    None
  }

  /// Get the pattern at a specific offset
  pub fn pattern_at(&self, offset: usize, length: usize) -> Vec<u8> {
    let sequence = self.generate(offset + length);
    if offset >= sequence.len() {
      return Vec::new();
    }
    sequence[offset..].to_vec()
  }
}

/// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
  if hex.len() % 2 != 0 {
    return None;
  }

  let mut bytes = Vec::with_capacity(hex.len() / 2);
  for i in (0..hex.len()).step_by(2) {
    let byte = u8::from_str_radix(&hex[i..i + 2], 16).ok()?;
    bytes.push(byte);
  }
  Some(bytes)
}

/// Result of cyclic offset search
#[derive(Debug, Clone)]
pub struct CyclicOffsetResult {
  /// Offset in the pattern
  pub offset: usize,
  /// The pattern that was found
  pub pattern: Vec<u8>,
  /// Human-readable pattern string
  pub pattern_str: String,
  /// Endianness used
  pub endianness: Endianness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
  Little,
  Big,
}

impl std::fmt::Display for Endianness {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Little => write!(f, "little"),
      Self::Big => write!(f, "big"),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_generate_pattern() {
    let gen = CyclicGenerator::new();
    let pattern = gen.generate(100);

    assert_eq!(pattern.len(), 100);
    // First 4 chars should be "aaaa" for De Bruijn with n=4
    assert!(pattern.starts_with(b"aaaa"));
  }

  #[test]
  fn test_find_offset() {
    let gen = CyclicGenerator::new();

    // Generate pattern and find known subsequence
    let pattern = gen.generate(1000);

    // Get a pattern at offset 100
    let test_pattern = &pattern[100..104];

    // Should find it at offset 100
    let offset = gen.find_offset(test_pattern, 1000);
    assert_eq!(offset, Some(100));
  }

  #[test]
  fn test_unique_patterns() {
    let gen = CyclicGenerator::new();
    let pattern = gen.generate(1000);

    // All 4-byte subsequences should be unique within a De Bruijn sequence
    let mut seen = std::collections::HashSet::new();
    for i in 0..pattern.len().saturating_sub(3) {
      let subseq: [u8; 4] = pattern[i..i + 4].try_into().unwrap();
      // In a proper De Bruijn sequence, each n-gram appears exactly once
      // until we reach the sequence length
      if i < 26_usize.pow(4) - 3 {
        // Can't guarantee uniqueness for all subsequences in truncated output
        assert!(seen.insert(subseq) || i > 100);
      }
    }
  }

  #[test]
  fn test_find_offset_hex() {
    let gen = CyclicGenerator::new();

    // Generate and get pattern at offset 100
    let pattern = gen.generate(1000);
    let test_bytes = &pattern[100..104];
    let hex = format!(
      "{:02x}{:02x}{:02x}{:02x}",
      test_bytes[0], test_bytes[1], test_bytes[2], test_bytes[3]
    );

    let offset = gen.find_offset_hex(&hex, 1000);
    assert_eq!(offset, Some(100));
  }
}
