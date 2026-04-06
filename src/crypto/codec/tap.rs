//! Tap Code Codec
//!
//! The tap code (also known as knock code) is a way to encode messages
//! using a 5x5 grid (Polybius square). K is merged with C.
//!
//! Each letter is represented by two numbers: row and column.
//! Format: row.col (e.g., A = 1.1, B = 1.2, ...)
//!
//! The 5x5 grid (C=K):
//!   1 2 3 4 5
//! 1 A B C D E
//! 2 F G H I J
//! 3 L M N O P
//! 4 Q R S T U
//! 5 V W X Y Z

use super::{Codec, CodecError};

/// Tap code grid (K merged with C)
const TAP_GRID: [[char; 5]; 5] = [
  ['A', 'B', 'C', 'D', 'E'],
  ['F', 'G', 'H', 'I', 'J'],
  ['L', 'M', 'N', 'O', 'P'],
  ['Q', 'R', 'S', 'T', 'U'],
  ['V', 'W', 'X', 'Y', 'Z'],
];

/// Tap code codec
pub struct TapCodec;

impl TapCodec {
  /// Create new Tap codec
  pub fn new() -> Self {
    Self
  }

  /// Find the grid position of a character
  fn find_position(c: char) -> Option<(usize, usize)> {
    let c = c.to_ascii_uppercase();
    // K is represented as C
    let c = if c == 'K' { 'C' } else { c };

    for row in 0..5 {
      for col in 0..5 {
        if TAP_GRID[row][col] == c {
          return Some((row + 1, col + 1)); // 1-indexed
        }
      }
    }
    None
  }

  /// Get character at grid position (1-indexed)
  fn get_char(row: usize, col: usize) -> Option<char> {
    if row >= 1 && row <= 5 && col >= 1 && col <= 5 {
      Some(TAP_GRID[row - 1][col - 1])
    } else {
      None
    }
  }
}

impl Default for TapCodec {
  fn default() -> Self {
    Self::new()
  }
}

impl Codec for TapCodec {
  fn name(&self) -> &'static str {
    "tap"
  }

  fn description(&self) -> &'static str {
    "Tap code (5x5 grid, K=C, format: row.col)"
  }

  fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let text = std::str::from_utf8(input)
      .map_err(|_| CodecError::InvalidInput("Invalid UTF-8".to_string()))?;

    let mut result = Vec::new();
    let mut first = true;

    for c in text.chars() {
      if c.is_ascii_whitespace() {
        if !first {
          result.extend_from_slice(b" / ");
          first = true;
        }
      } else if let Some((row, col)) = Self::find_position(c) {
        if !first {
          result.push(b' ');
        }
        result.extend_from_slice(format!("{}.{}", row, col).as_bytes());
        first = false;
      }
      // Skip unrecognized characters
    }

    Ok(result)
  }

  fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let text = std::str::from_utf8(input)
      .map_err(|_| CodecError::InvalidInput("Invalid UTF-8".to_string()))?;

    let mut result = String::new();

    // Split by word separator first
    for word in text.split('/') {
      if !result.is_empty() && !result.ends_with(' ') {
        result.push(' ');
      }

      // Split by letter separator
      for tap in word.split_whitespace() {
        if tap.is_empty() {
          continue;
        }

        // Parse row.col format
        let parts: Vec<&str> = tap.split('.').collect();
        if parts.len() != 2 {
          return Err(CodecError::InvalidInput(format!(
            "Invalid tap code format: {} (expected row.col)",
            tap
          )));
        }

        let row: usize = parts[0]
          .parse()
          .map_err(|_| CodecError::InvalidInput(format!("Invalid row number: {}", parts[0])))?;

        let col: usize = parts[1]
          .parse()
          .map_err(|_| CodecError::InvalidInput(format!("Invalid column number: {}", parts[1])))?;

        if let Some(c) = Self::get_char(row, col) {
          result.push(c);
        } else {
          return Err(CodecError::InvalidInput(format!(
            "Invalid grid position: {}.{}",
            row, col
          )));
        }
      }
    }

    Ok(result.into_bytes())
  }

  fn detect(&self, input: &[u8]) -> f64 {
    if let Ok(text) = std::str::from_utf8(input) {
      let tokens: Vec<&str> = text.split(|c| c == ' ' || c == '/').collect();
      if tokens.is_empty() {
        return 0.0;
      }

      let mut valid_taps = 0;
      let mut total_tokens = 0;

      for token in tokens {
        if token.is_empty() {
          continue;
        }
        total_tokens += 1;

        // Check if it's a valid row.col format
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 2 {
          if let (Ok(row), Ok(col)) = (parts[0].parse::<usize>(), parts[1].parse::<usize>()) {
            if row >= 1 && row <= 5 && col >= 1 && col <= 5 {
              valid_taps += 1;
            }
          }
        }
      }

      if total_tokens == 0 {
        return 0.0;
      }

      let ratio = valid_taps as f64 / total_tokens as f64;
      if ratio > 0.8 {
        return 0.9 * ratio;
      }

      0.0
    } else {
      0.0
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_encode_hello() {
    let codec = TapCodec::new();
    let result = codec.encode(b"HELLO").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    // H=2.3, E=1.5, L=3.1, L=3.1, O=3.4
    assert_eq!(result_str, "2.3 1.5 3.1 3.1 3.4");
  }

  #[test]
  fn test_decode_hello() {
    let codec = TapCodec::new();
    let result = codec.decode(b"2.3 1.5 3.1 3.1 3.4").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    assert_eq!(result_str, "HELLO");
  }

  #[test]
  fn test_encode_with_k() {
    // K should be encoded as C (1.3)
    let codec = TapCodec::new();
    let result = codec.encode(b"K").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    assert_eq!(result_str, "1.3"); // Same as C
  }

  #[test]
  fn test_decode_k_as_c() {
    let codec = TapCodec::new();
    // Position 1.3 is C (K is merged)
    let result = codec.decode(b"1.3").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    assert_eq!(result_str, "C");
  }

  #[test]
  fn test_word_separator() {
    let codec = TapCodec::new();
    let result = codec.encode(b"AB CD").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    // A=1.1, B=1.2 / C=1.3, D=1.4
    assert_eq!(result_str, "1.1 1.2 / 1.3 1.4");
  }

  #[test]
  fn test_decode_word_separator() {
    let codec = TapCodec::new();
    let result = codec.decode(b"1.1 1.2 / 1.3 1.4").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    assert_eq!(result_str, "AB CD");
  }

  #[test]
  fn test_roundtrip() {
    let codec = TapCodec::new();
    let original = b"THE QUICK BROWN FOX";
    let encoded = codec.encode(original).unwrap();
    let decoded = codec.decode(&encoded).unwrap();

    // Note: K becomes C when decoded
    let expected = b"THE QUICC BROWN FOX";
    assert_eq!(decoded, expected.to_vec());
  }

  #[test]
  fn test_all_letters() {
    let codec = TapCodec::new();
    // All letters except K (merged with C)
    let alphabet = b"ABCDEFGHIJLMNOPQRSTUVWXYZ";
    let encoded = codec.encode(alphabet).unwrap();
    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(decoded, alphabet.to_vec());
  }

  #[test]
  fn test_detect_tap() {
    let codec = TapCodec::new();
    assert!(codec.detect(b"1.1 1.2 1.3") > 0.8);
    assert!(codec.detect(b"2.3 1.5 3.1 3.1 3.4") > 0.8);
    assert!(codec.detect(b"Hello World") < 0.1);
  }

  #[test]
  fn test_invalid_format() {
    let codec = TapCodec::new();
    let result = codec.decode(b"1.1.1");
    assert!(result.is_err());
  }

  #[test]
  fn test_invalid_position() {
    let codec = TapCodec::new();
    let result = codec.decode(b"6.1"); // Row 6 doesn't exist
    assert!(result.is_err());
  }
}
