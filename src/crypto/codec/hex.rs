//! Hex Codec
//!
//! Implements hexadecimal encoding.

use super::{Codec, CodecError};

/// Hex codec
pub struct HexCodec {
  uppercase: bool,
}

impl HexCodec {
  /// Create hex codec (lowercase output)
  pub fn new() -> Self {
    Self { uppercase: false }
  }

  /// Create hex codec with uppercase output
  pub fn uppercase() -> Self {
    Self { uppercase: true }
  }

  fn decode_nibble(c: char) -> Result<u8, CodecError> {
    match c {
      '0'..='9' => Ok(c as u8 - b'0'),
      'a'..='f' => Ok(c as u8 - b'a' + 10),
      'A'..='F' => Ok(c as u8 - b'A' + 10),
      _ => Err(CodecError::InvalidCharacter(c)),
    }
  }
}

impl Default for HexCodec {
  fn default() -> Self {
    Self::new()
  }
}

impl Codec for HexCodec {
  fn name(&self) -> &'static str {
    "hex"
  }

  fn description(&self) -> &'static str {
    "Hexadecimal encoding"
  }

  fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut result = Vec::with_capacity(input.len() * 2);
    let hex_chars: &[u8; 16] = if self.uppercase {
      b"0123456789ABCDEF"
    } else {
      b"0123456789abcdef"
    };

    for &byte in input {
      result.push(hex_chars[(byte >> 4) as usize]);
      result.push(hex_chars[(byte & 0x0F) as usize]);
    }

    Ok(result)
  }

  fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let s =
      std::str::from_utf8(input).map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))?;

    // Remove common prefixes and whitespace
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s = s.strip_prefix("0X").unwrap_or(s);
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();

    if s.is_empty() {
      return Ok(Vec::new());
    }

    if s.len() % 2 != 0 {
      return Err(CodecError::InvalidLength);
    }

    let mut result = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();

    for pair in chars.chunks(2) {
      let high = Self::decode_nibble(pair[0])?;
      let low = Self::decode_nibble(pair[1])?;
      result.push((high << 4) | low);
    }

    Ok(result)
  }

  fn detect(&self, input: &[u8]) -> f64 {
    let s = match std::str::from_utf8(input) {
      Ok(s) => s.trim(),
      Err(_) => return 0.0,
    };

    if s.is_empty() {
      return 0.0;
    }

    // Handle 0x prefix
    let s = s
      .strip_prefix("0x")
      .or_else(|| s.strip_prefix("0X"))
      .unwrap_or(s);
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();

    // Check if all characters are valid hex
    let valid = s.chars().all(|c| c.is_ascii_hexdigit());
    if !valid {
      return 0.0;
    }

    let mut confidence: f64 = 0.4;

    // Even length is required for hex
    if s.len() % 2 == 0 {
      confidence += 0.2;
    } else {
      return 0.2; // Odd length is suspicious
    }

    // Hex strings are often lowercase or uppercase consistently
    let all_lower = s
      .chars()
      .filter(|c| c.is_alphabetic())
      .all(|c| c.is_lowercase());
    let all_upper = s
      .chars()
      .filter(|c| c.is_alphabetic())
      .all(|c| c.is_uppercase());
    if all_lower || all_upper {
      confidence += 0.1;
    }

    // Common hex lengths (hash-like)
    let common_lengths = [32, 40, 64, 128]; // MD5, SHA1, SHA256, SHA512
    if common_lengths.contains(&s.len()) {
      confidence += 0.2;
    }

    confidence.min(1.0_f64)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_hex_encode() {
    let codec = HexCodec::new();
    assert_eq!(codec.encode(b"").unwrap(), b"");
    assert_eq!(codec.encode(b"A").unwrap(), b"41");
    assert_eq!(codec.encode(b"ABC").unwrap(), b"414243");
    assert_eq!(codec.encode(b"Hello").unwrap(), b"48656c6c6f");
    assert_eq!(codec.encode(&[0x00, 0xFF]).unwrap(), b"00ff");
  }

  #[test]
  fn test_hex_encode_uppercase() {
    let codec = HexCodec::uppercase();
    assert_eq!(codec.encode(b"Hello").unwrap(), b"48656C6C6F");
  }

  #[test]
  fn test_hex_decode() {
    let codec = HexCodec::new();
    assert_eq!(codec.decode(b"").unwrap(), b"");
    assert_eq!(codec.decode(b"41").unwrap(), b"A");
    assert_eq!(codec.decode(b"414243").unwrap(), b"ABC");
    assert_eq!(codec.decode(b"48656c6c6f").unwrap(), b"Hello");
    assert_eq!(codec.decode(b"48656C6C6F").unwrap(), b"Hello"); // Mixed case
  }

  #[test]
  fn test_hex_decode_with_prefix() {
    let codec = HexCodec::new();
    assert_eq!(codec.decode(b"0x414243").unwrap(), b"ABC");
    assert_eq!(codec.decode(b"0X414243").unwrap(), b"ABC");
  }

  #[test]
  fn test_hex_roundtrip() {
    let codec = HexCodec::new();
    let original = b"The quick brown fox";
    let encoded = codec.encode(original).unwrap();
    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(decoded, original);
  }

  #[test]
  fn test_hex_invalid() {
    let codec = HexCodec::new();
    assert!(codec.decode(b"41G").is_err()); // Invalid char
    assert!(codec.decode(b"414").is_err()); // Odd length
  }

  #[test]
  fn test_hex_detect() {
    let codec = HexCodec::new();
    assert!(codec.detect(b"414243") > 0.5);
    assert!(codec.detect(b"0x414243") > 0.5);
    assert!(codec.detect(b"ghijk") < 0.1); // Not hex
  }
}
