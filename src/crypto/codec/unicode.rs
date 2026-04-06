//! Unicode Escape Codec
//!
//! Implements Unicode escape sequences (\uXXXX, \xXX).

use super::{Codec, CodecError};

/// Unicode escape codec
pub struct UnicodeCodec;

impl UnicodeCodec {
  /// Create Unicode codec
  pub fn new() -> Self {
    Self
  }
}

impl Default for UnicodeCodec {
  fn default() -> Self {
    Self::new()
  }
}

impl Codec for UnicodeCodec {
  fn name(&self) -> &'static str {
    "unicode"
  }

  fn description(&self) -> &'static str {
    "Unicode escape sequences (\\uXXXX, \\xXX)"
  }

  fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let s =
      std::str::from_utf8(input).map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))?;

    let mut result = String::with_capacity(s.len() * 6);

    for c in s.chars() {
      if c.is_ascii() && !c.is_ascii_control() {
        result.push(c);
      } else if (c as u32) < 0x100 {
        // Use \xXX for bytes
        result.push_str(&format!("\\x{:02X}", c as u32));
      } else if (c as u32) < 0x10000 {
        // Use \uXXXX for BMP
        result.push_str(&format!("\\u{:04X}", c as u32));
      } else {
        // Use \UXXXXXXXX for non-BMP (or surrogate pairs)
        let code = c as u32;
        // Split into surrogate pair for JavaScript compatibility
        let high = ((code - 0x10000) >> 10) + 0xD800;
        let low = ((code - 0x10000) & 0x3FF) + 0xDC00;
        result.push_str(&format!("\\u{:04X}\\u{:04X}", high, low));
      }
    }

    Ok(result.into_bytes())
  }

  fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let s =
      std::str::from_utf8(input).map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))?;

    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
      if c == '\\' {
        match chars.peek() {
          Some('u') => {
            chars.next();
            // Parse \uXXXX
            let hex: String = chars.by_ref().take(4).collect();
            if hex.len() != 4 {
              return Err(CodecError::IncompleteSequence);
            }
            let code = u32::from_str_radix(&hex, 16)
              .map_err(|_| CodecError::InvalidInput("Invalid hex in \\u".into()))?;

            // Check for surrogate pair
            if (0xD800..=0xDBFF).contains(&code) {
              // High surrogate - look for low surrogate
              if chars.next() == Some('\\') && chars.next() == Some('u') {
                let low_hex: String = chars.by_ref().take(4).collect();
                if low_hex.len() == 4 {
                  if let Ok(low) = u32::from_str_radix(&low_hex, 16) {
                    if (0xDC00..=0xDFFF).contains(&low) {
                      // Valid surrogate pair
                      let full = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                      if let Some(decoded) = char::from_u32(full) {
                        result.push(decoded);
                        continue;
                      }
                    }
                  }
                }
              }
              // Invalid surrogate, output as-is
              if let Some(decoded) = char::from_u32(code) {
                result.push(decoded);
              }
            } else if let Some(decoded) = char::from_u32(code) {
              result.push(decoded);
            } else {
              return Err(CodecError::InvalidInput(format!(
                "Invalid Unicode code point: U+{:04X}",
                code
              )));
            }
          }
          Some('U') => {
            chars.next();
            // Parse \UXXXXXXXX
            let hex: String = chars.by_ref().take(8).collect();
            if hex.len() != 8 {
              return Err(CodecError::IncompleteSequence);
            }
            let code = u32::from_str_radix(&hex, 16)
              .map_err(|_| CodecError::InvalidInput("Invalid hex in \\U".into()))?;
            if let Some(decoded) = char::from_u32(code) {
              result.push(decoded);
            } else {
              return Err(CodecError::InvalidInput(format!(
                "Invalid Unicode code point: U+{:08X}",
                code
              )));
            }
          }
          Some('x') => {
            chars.next();
            // Parse \xXX
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() != 2 {
              return Err(CodecError::IncompleteSequence);
            }
            let byte = u8::from_str_radix(&hex, 16)
              .map_err(|_| CodecError::InvalidInput("Invalid hex in \\x".into()))?;
            result.push(byte as char);
          }
          Some('n') => {
            chars.next();
            result.push('\n');
          }
          Some('r') => {
            chars.next();
            result.push('\r');
          }
          Some('t') => {
            chars.next();
            result.push('\t');
          }
          Some('\\') => {
            chars.next();
            result.push('\\');
          }
          Some('"') => {
            chars.next();
            result.push('"');
          }
          Some('\'') => {
            chars.next();
            result.push('\'');
          }
          Some('0') => {
            chars.next();
            result.push('\0');
          }
          _ => {
            result.push('\\');
          }
        }
      } else {
        result.push(c);
      }
    }

    Ok(result.into_bytes())
  }

  fn detect(&self, input: &[u8]) -> f64 {
    let s = match std::str::from_utf8(input) {
      Ok(s) => s,
      Err(_) => return 0.0,
    };

    if s.is_empty() {
      return 0.0;
    }

    // Count unicode escape sequences
    let mut escape_count = 0;
    let mut valid_escapes = 0;
    let mut i = 0;
    let chars: Vec<char> = s.chars().collect();

    while i < chars.len() {
      if chars[i] == '\\' && i + 1 < chars.len() {
        escape_count += 1;
        match chars.get(i + 1) {
          Some('u') if i + 5 < chars.len() => {
            let hex: String = chars[i + 2..i + 6].iter().collect();
            if hex.chars().all(|c| c.is_ascii_hexdigit()) {
              valid_escapes += 1;
              i += 6;
              continue;
            }
          }
          Some('x') if i + 3 < chars.len() => {
            let hex: String = chars[i + 2..i + 4].iter().collect();
            if hex.chars().all(|c| c.is_ascii_hexdigit()) {
              valid_escapes += 1;
              i += 4;
              continue;
            }
          }
          Some('n' | 'r' | 't' | '\\' | '"' | '\'' | '0') => {
            valid_escapes += 1;
            i += 2;
            continue;
          }
          _ => {}
        }
      }
      i += 1;
    }

    if escape_count == 0 {
      return 0.0;
    }

    let ratio = valid_escapes as f64 / escape_count as f64;
    let density = escape_count as f64 / s.len() as f64;

    (ratio * 0.5 + density * 5.0).min(1.0)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_unicode_encode() {
    let codec = UnicodeCodec::new();
    assert_eq!(codec.encode(b"hello").unwrap(), b"hello");
    assert_eq!(codec.encode(b"\n").unwrap(), b"\\x0A");
  }

  #[test]
  fn test_unicode_encode_non_ascii() {
    let codec = UnicodeCodec::new();
    let encoded = codec.encode("café".as_bytes()).unwrap();
    let encoded_str = String::from_utf8(encoded).unwrap();
    assert!(encoded_str.contains("\\u00E9") || encoded_str.contains("caf"));
  }

  #[test]
  fn test_unicode_encode_emoji() {
    let codec = UnicodeCodec::new();
    let encoded = codec.encode("😀".as_bytes()).unwrap();
    let encoded_str = String::from_utf8(encoded).unwrap();
    // Emoji encoded as surrogate pair
    assert!(encoded_str.contains("\\uD83D\\uDE00"));
  }

  #[test]
  fn test_unicode_decode() {
    let codec = UnicodeCodec::new();
    assert_eq!(codec.decode(b"hello").unwrap(), b"hello");
    assert_eq!(codec.decode(b"\\x41").unwrap(), b"A");
    assert_eq!(codec.decode(b"\\u0041").unwrap(), b"A");
    assert_eq!(codec.decode(b"\\n\\r\\t").unwrap(), b"\n\r\t");
  }

  #[test]
  fn test_unicode_decode_chinese() {
    let codec = UnicodeCodec::new();
    let decoded = codec.decode(b"\\u4E16\\u754C").unwrap();
    assert_eq!(decoded, "世界".as_bytes());
  }

  #[test]
  fn test_unicode_decode_surrogate_pair() {
    let codec = UnicodeCodec::new();
    let decoded = codec.decode(b"\\uD83D\\uDE00").unwrap();
    assert_eq!(decoded, "😀".as_bytes());
  }

  #[test]
  fn test_unicode_roundtrip() {
    let codec = UnicodeCodec::new();
    let original = "Hello 世界 🌍".as_bytes();
    let encoded = codec.encode(original).unwrap();
    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(decoded, original);
  }

  #[test]
  fn test_unicode_detect() {
    let codec = UnicodeCodec::new();
    assert!(codec.detect(b"\\u0041\\u0042") > 0.5);
    assert!(codec.detect(b"\\x41\\x42") > 0.5);
    assert!(codec.detect(b"hello") < 0.1);
  }
}
