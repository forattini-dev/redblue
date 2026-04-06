//! Base32 Codec
//!
//! Implements Base32 encoding per RFC 4648.

use super::{Codec, CodecError};

/// Standard Base32 alphabet
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 hex alphabet (extended hex)
const BASE32_HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Base32 codec with configurable alphabet
pub struct Base32Codec {
  name: &'static str,
  description: &'static str,
  alphabet: &'static [u8; 32],
  with_padding: bool,
}

impl Base32Codec {
  /// Create standard Base32 codec
  pub fn new() -> Self {
    Self {
      name: "base32",
      description: "Base32 encoding (RFC 4648)",
      alphabet: BASE32_ALPHABET,
      with_padding: true,
    }
  }

  /// Create Base32 hex codec
  pub fn hex() -> Self {
    Self {
      name: "base32hex",
      description: "Base32 hex encoding (RFC 4648)",
      alphabet: BASE32_HEX_ALPHABET,
      with_padding: true,
    }
  }

  fn decode_char(&self, c: char) -> Result<u8, CodecError> {
    let c = c.to_ascii_uppercase();
    self
      .alphabet
      .iter()
      .position(|&b| b == c as u8)
      .map(|p| p as u8)
      .ok_or(CodecError::InvalidCharacter(c))
  }
}

impl Default for Base32Codec {
  fn default() -> Self {
    Self::new()
  }
}

impl Codec for Base32Codec {
  fn name(&self) -> &'static str {
    self.name
  }

  fn description(&self) -> &'static str {
    self.description
  }

  fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    if input.is_empty() {
      return Ok(Vec::new());
    }

    let mut result = Vec::with_capacity((input.len() + 4) / 5 * 8);

    for chunk in input.chunks(5) {
      let mut buffer = 0u64;
      for (i, &byte) in chunk.iter().enumerate() {
        buffer |= (byte as u64) << (32 - i * 8);
      }

      let output_chars = match chunk.len() {
        1 => 2,
        2 => 4,
        3 => 5,
        4 => 7,
        5 => 8,
        _ => unreachable!(),
      };

      for i in 0..output_chars {
        let index = ((buffer >> (35 - i * 5)) & 0x1F) as usize;
        result.push(self.alphabet[index]);
      }

      if self.with_padding {
        for _ in output_chars..8 {
          result.push(b'=');
        }
      }
    }

    Ok(result)
  }

  fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let s =
      std::str::from_utf8(input).map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))?;

    // Remove whitespace and padding
    let s: String = s
      .chars()
      .filter(|c| !c.is_whitespace())
      .collect::<String>()
      .trim_end_matches('=')
      .to_string();

    if s.is_empty() {
      return Ok(Vec::new());
    }

    let mut result = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer = 0u64;
    let mut bits_collected = 0;

    for c in s.chars() {
      let value = self.decode_char(c)?;
      buffer = (buffer << 5) | value as u64;
      bits_collected += 5;

      if bits_collected >= 8 {
        bits_collected -= 8;
        result.push((buffer >> bits_collected) as u8);
        buffer &= (1 << bits_collected) - 1;
      }
    }

    Ok(result)
  }

  fn detect(&self, input: &[u8]) -> f64 {
    let s = match std::str::from_utf8(input) {
      Ok(s) => s.trim().to_uppercase(),
      Err(_) => return 0.0,
    };

    if s.is_empty() {
      return 0.0;
    }

    let stripped = s.trim_end_matches('=');

    // Check if all characters are valid Base32
    let valid = stripped.chars().all(|c| self.alphabet.contains(&(c as u8)));

    if !valid {
      return 0.0;
    }

    let mut confidence: f64 = 0.4;

    // Length check (multiple of 8 with padding)
    if s.len() % 8 == 0 {
      confidence += 0.2;
    }

    // All uppercase suggests Base32
    if stripped.chars().all(|c| !c.is_lowercase()) {
      confidence += 0.1;
    }

    // Standard Base32 has limited character set (A-Z, 2-7)
    let uses_standard = stripped.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
    if uses_standard && self.alphabet == BASE32_ALPHABET {
      confidence += 0.2;
    }

    confidence.min(1.0_f64)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_base32_encode() {
    let codec = Base32Codec::new();
    assert_eq!(codec.encode(b"").unwrap(), b"");
    assert_eq!(codec.encode(b"f").unwrap(), b"MY======");
    assert_eq!(codec.encode(b"fo").unwrap(), b"MZXQ====");
    assert_eq!(codec.encode(b"foo").unwrap(), b"MZXW6===");
    assert_eq!(codec.encode(b"foob").unwrap(), b"MZXW6YQ=");
    assert_eq!(codec.encode(b"fooba").unwrap(), b"MZXW6YTB");
    assert_eq!(codec.encode(b"foobar").unwrap(), b"MZXW6YTBOI======");
  }

  #[test]
  fn test_base32_decode() {
    let codec = Base32Codec::new();
    assert_eq!(codec.decode(b"").unwrap(), b"");
    assert_eq!(codec.decode(b"MY======").unwrap(), b"f");
    assert_eq!(codec.decode(b"MZXQ====").unwrap(), b"fo");
    assert_eq!(codec.decode(b"MZXW6===").unwrap(), b"foo");
    assert_eq!(codec.decode(b"MZXW6YQ=").unwrap(), b"foob");
    assert_eq!(codec.decode(b"MZXW6YTB").unwrap(), b"fooba");
    assert_eq!(codec.decode(b"MZXW6YTBOI======").unwrap(), b"foobar");
  }

  #[test]
  fn test_base32_case_insensitive() {
    let codec = Base32Codec::new();
    assert_eq!(codec.decode(b"mzxw6ytb").unwrap(), b"fooba");
    assert_eq!(codec.decode(b"MzXw6YtB").unwrap(), b"fooba");
  }

  #[test]
  fn test_base32_roundtrip() {
    let codec = Base32Codec::new();
    let original = b"Hello World!";
    let encoded = codec.encode(original).unwrap();
    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(decoded, original);
  }

  #[test]
  fn test_base32_detect() {
    let codec = Base32Codec::new();
    assert!(codec.detect(b"MZXW6YTBOI======") > 0.5);
    assert!(codec.detect(b"NBSWY3DP") > 0.5);
    assert!(codec.detect(b"xyz!@#$") < 0.5); // invalid base32 chars
  }
}
