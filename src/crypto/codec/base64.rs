//! Base64 Codec
//!
//! Implements Base64 and Base64URL encoding per RFC 4648.

use super::{Codec, CodecError};

/// Standard Base64 alphabet
const BASE64_ALPHABET: &[u8; 64] =
  b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64URL alphabet (URL-safe)
const BASE64URL_ALPHABET: &[u8; 64] =
  b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 codec with configurable alphabet
pub struct Base64Codec {
  name: &'static str,
  description: &'static str,
  alphabet: &'static [u8; 64],
  with_padding: bool,
  url_safe: bool,
}

impl Base64Codec {
  /// Create standard Base64 codec
  pub fn new() -> Self {
    Self {
      name: "base64",
      description: "Base64 encoding (RFC 4648)",
      alphabet: BASE64_ALPHABET,
      with_padding: true,
      url_safe: false,
    }
  }

  /// Create URL-safe Base64 codec
  pub fn url_safe() -> Self {
    Self {
      name: "base64url",
      description: "Base64URL encoding (URL-safe, no padding)",
      alphabet: BASE64URL_ALPHABET,
      with_padding: false,
      url_safe: true,
    }
  }

  fn decode_char(&self, c: char) -> Result<u8, CodecError> {
    match c {
      'A'..='Z' => Ok(c as u8 - b'A'),
      'a'..='z' => Ok(c as u8 - b'a' + 26),
      '0'..='9' => Ok(c as u8 - b'0' + 52),
      '+' if !self.url_safe => Ok(62),
      '-' if self.url_safe => Ok(62),
      '/' if !self.url_safe => Ok(63),
      '_' if self.url_safe => Ok(63),
      _ => Err(CodecError::InvalidCharacter(c)),
    }
  }
}

impl Default for Base64Codec {
  fn default() -> Self {
    Self::new()
  }
}

impl Codec for Base64Codec {
  fn name(&self) -> &'static str {
    self.name
  }

  fn description(&self) -> &'static str {
    self.description
  }

  fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut result = Vec::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
      let b0 = chunk[0] as u32;
      let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
      let b2 = chunk.get(2).copied().unwrap_or(0) as u32;

      let combined = (b0 << 16) | (b1 << 8) | b2;

      result.push(self.alphabet[((combined >> 18) & 0x3F) as usize]);
      result.push(self.alphabet[((combined >> 12) & 0x3F) as usize]);

      if chunk.len() > 1 {
        result.push(self.alphabet[((combined >> 6) & 0x3F) as usize]);
      } else if self.with_padding {
        result.push(b'=');
      }

      if chunk.len() > 2 {
        result.push(self.alphabet[(combined & 0x3F) as usize]);
      } else if self.with_padding {
        result.push(b'=');
      }
    }

    Ok(result)
  }

  fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    // Convert to string for easier processing
    let s =
      std::str::from_utf8(input).map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))?;

    // Remove whitespace and padding
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = s.trim_end_matches('=');

    if s.is_empty() {
      return Ok(Vec::new());
    }

    let mut result = Vec::with_capacity(s.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits_collected = 0;

    for c in s.chars() {
      let value = self.decode_char(c)?;
      buffer = (buffer << 6) | value as u32;
      bits_collected += 6;

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
      Ok(s) => s.trim(),
      Err(_) => return 0.0,
    };

    if s.is_empty() {
      return 0.0;
    }

    // Check if all characters are valid Base64
    let valid_chars = if self.url_safe {
      |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '='
    } else {
      |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
    };

    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let valid_count = stripped.chars().filter(|&c| valid_chars(c)).count();

    if valid_count != stripped.len() {
      return 0.0;
    }

    // Check length (should be multiple of 4 with padding, or valid without)
    let without_padding = stripped.trim_end_matches('=');
    let padding_count = stripped.len() - without_padding.len();

    // Invalid padding
    if padding_count > 2 {
      return 0.0;
    }

    // Base64 characteristics
    let mut confidence: f64 = 0.5;

    // Proper length suggests Base64
    if stripped.len() % 4 == 0 {
      confidence += 0.2;
    }

    // Has proper padding
    if padding_count > 0 && (without_padding.len() + padding_count) % 4 == 0 {
      confidence += 0.2;
    }

    // Mix of upper, lower, digits suggests Base64
    let has_upper = stripped.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = stripped.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = stripped.chars().any(|c| c.is_ascii_digit());
    if has_upper && has_lower && has_digit {
      confidence += 0.1;
    }

    confidence.min(1.0_f64)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_base64_encode() {
    let codec = Base64Codec::new();
    assert_eq!(codec.encode(b"").unwrap(), b"");
    assert_eq!(codec.encode(b"f").unwrap(), b"Zg==");
    assert_eq!(codec.encode(b"fo").unwrap(), b"Zm8=");
    assert_eq!(codec.encode(b"foo").unwrap(), b"Zm9v");
    assert_eq!(codec.encode(b"foobar").unwrap(), b"Zm9vYmFy");
    assert_eq!(codec.encode(b"Hello World").unwrap(), b"SGVsbG8gV29ybGQ=");
  }

  #[test]
  fn test_base64_decode() {
    let codec = Base64Codec::new();
    assert_eq!(codec.decode(b"").unwrap(), b"");
    assert_eq!(codec.decode(b"Zg==").unwrap(), b"f");
    assert_eq!(codec.decode(b"Zm8=").unwrap(), b"fo");
    assert_eq!(codec.decode(b"Zm9v").unwrap(), b"foo");
    assert_eq!(codec.decode(b"Zm9vYmFy").unwrap(), b"foobar");
    assert_eq!(codec.decode(b"SGVsbG8gV29ybGQ=").unwrap(), b"Hello World");
  }

  #[test]
  fn test_base64_roundtrip() {
    let codec = Base64Codec::new();
    let original = b"The quick brown fox jumps over the lazy dog";
    let encoded = codec.encode(original).unwrap();
    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(decoded, original);
  }

  #[test]
  fn test_base64url() {
    let codec = Base64Codec::url_safe();
    // Data that produces + and / in standard Base64
    let data = vec![0xfb, 0xff, 0xfe];
    let encoded = codec.encode(&data).unwrap();
    let encoded_str = String::from_utf8(encoded.clone()).unwrap();

    assert!(!encoded_str.contains('+'));
    assert!(!encoded_str.contains('/'));
    assert!(!encoded_str.contains('='));

    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(decoded, data);
  }

  #[test]
  fn test_base64_detect() {
    let codec = Base64Codec::new();

    // Valid Base64
    assert!(codec.detect(b"SGVsbG8=") > 0.5);
    assert!(codec.detect(b"Zm9vYmFy") > 0.5);

    // Invalid
    assert!(codec.detect(b"!!!") < 0.1);
    assert!(codec.detect(b"\x00\x01\x02") < 0.1);
  }
}
