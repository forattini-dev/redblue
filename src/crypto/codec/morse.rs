//! Morse Code Codec
//!
//! Encodes and decodes text using International Morse Code.
//! Letters are separated by spaces, words by slashes.

use super::{Codec, CodecError};

/// Morse code mapping table (letter -> morse)
const MORSE_TABLE: [(char, &str); 36] = [
  ('A', ".-"),
  ('B', "-..."),
  ('C', "-.-."),
  ('D', "-.."),
  ('E', "."),
  ('F', "..-."),
  ('G', "--."),
  ('H', "...."),
  ('I', ".."),
  ('J', ".---"),
  ('K', "-.-"),
  ('L', ".-.."),
  ('M', "--"),
  ('N', "-."),
  ('O', "---"),
  ('P', ".--."),
  ('Q', "--.-"),
  ('R', ".-."),
  ('S', "..."),
  ('T', "-"),
  ('U', "..-"),
  ('V', "...-"),
  ('W', ".--"),
  ('X', "-..-"),
  ('Y', "-.--"),
  ('Z', "--.."),
  ('0', "-----"),
  ('1', ".----"),
  ('2', "..---"),
  ('3', "...--"),
  ('4', "....-"),
  ('5', "....."),
  ('6', "-...."),
  ('7', "--..."),
  ('8', "---.."),
  ('9', "----."),
];

/// Morse code codec
pub struct MorseCodec;

impl MorseCodec {
  /// Create new Morse codec
  pub fn new() -> Self {
    Self
  }

  /// Convert a character to Morse code
  fn char_to_morse(c: char) -> Option<&'static str> {
    let c = c.to_ascii_uppercase();
    for (letter, morse) in MORSE_TABLE.iter() {
      if *letter == c {
        return Some(morse);
      }
    }
    None
  }

  /// Convert Morse code to a character
  fn morse_to_char(morse: &str) -> Option<char> {
    for (letter, code) in MORSE_TABLE.iter() {
      if *code == morse {
        return Some(*letter);
      }
    }
    None
  }
}

impl Default for MorseCodec {
  fn default() -> Self {
    Self::new()
  }
}

impl Codec for MorseCodec {
  fn name(&self) -> &'static str {
    "morse"
  }

  fn description(&self) -> &'static str {
    "International Morse Code (letters=space, words=/)"
  }

  fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let text = std::str::from_utf8(input)
      .map_err(|_| CodecError::InvalidInput("Invalid UTF-8".to_string()))?;

    let mut result = Vec::new();
    let mut first_in_word = true;

    for c in text.chars() {
      if c.is_ascii_whitespace() {
        // Word separator
        if !first_in_word {
          result.extend_from_slice(b" / ");
          first_in_word = true;
        }
      } else if let Some(morse) = Self::char_to_morse(c) {
        if !first_in_word {
          result.push(b' ');
        }
        result.extend_from_slice(morse.as_bytes());
        first_in_word = false;
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
      for morse_char in word.split_whitespace() {
        if morse_char.is_empty() {
          continue;
        }
        if let Some(c) = Self::morse_to_char(morse_char) {
          result.push(c);
        } else {
          return Err(CodecError::InvalidInput(format!(
            "Invalid Morse code: {}",
            morse_char
          )));
        }
      }
    }

    Ok(result.into_bytes())
  }

  fn detect(&self, input: &[u8]) -> f64 {
    if let Ok(text) = std::str::from_utf8(input) {
      // Check if it looks like Morse code
      let chars: Vec<char> = text.chars().collect();
      if chars.is_empty() {
        return 0.0;
      }

      // Count dots, dashes, spaces, and slashes
      let mut dots = 0;
      let mut dashes = 0;
      let mut spaces = 0;
      let mut slashes = 0;
      let mut other = 0;

      for c in chars.iter() {
        match c {
          '.' => dots += 1,
          '-' => dashes += 1,
          ' ' => spaces += 1,
          '/' => slashes += 1,
          _ => other += 1,
        }
      }

      let total = chars.len() as f64;
      let morse_chars = (dots + dashes + spaces + slashes) as f64;

      // If mostly dots/dashes/spaces/slashes, likely Morse
      if other == 0 && dots + dashes > 0 {
        return 0.95;
      }

      // Calculate ratio of Morse-like characters
      let ratio = morse_chars / total;
      if ratio > 0.8 && other < chars.len() / 10 {
        return ratio * 0.8;
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
  fn test_encode_sos() {
    let codec = MorseCodec::new();
    let result = codec.encode(b"SOS").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    assert_eq!(result_str, "... --- ...");
  }

  #[test]
  fn test_decode_sos() {
    let codec = MorseCodec::new();
    let result = codec.decode(b"... --- ...").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    assert_eq!(result_str, "SOS");
  }

  #[test]
  fn test_encode_hello_world() {
    let codec = MorseCodec::new();
    let result = codec.encode(b"HELLO WORLD").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    // HELLO = .... . .-.. .-.. ---
    // WORLD = .-- --- .-. .-.. -..
    assert_eq!(result_str, ".... . .-.. .-.. --- / .-- --- .-. .-.. -..");
  }

  #[test]
  fn test_decode_hello_world() {
    let codec = MorseCodec::new();
    let result = codec
      .decode(b".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
      .unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    assert_eq!(result_str, "HELLO WORLD");
  }

  #[test]
  fn test_roundtrip() {
    let codec = MorseCodec::new();
    let original = b"THE QUICK BROWN FOX";
    let encoded = codec.encode(original).unwrap();
    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(decoded, original.to_vec());
  }

  #[test]
  fn test_numbers() {
    let codec = MorseCodec::new();
    let result = codec.encode(b"12345").unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();
    assert_eq!(result_str, ".---- ..--- ...-- ....- .....");
  }

  #[test]
  fn test_detect_morse() {
    let codec = MorseCodec::new();
    assert!(codec.detect(b"... --- ...") > 0.9);
    assert!(codec.detect(b".... . .-.. .-.. ---") > 0.9);
    assert!(codec.detect(b"Hello World") < 0.1);
  }

  #[test]
  fn test_invalid_morse() {
    let codec = MorseCodec::new();
    let result = codec.decode(b"....----");
    assert!(result.is_err());
  }

  #[test]
  fn test_case_insensitive() {
    let codec = MorseCodec::new();
    let upper = codec.encode(b"HELLO").unwrap();
    let lower = codec.encode(b"hello").unwrap();
    assert_eq!(upper, lower);
  }
}
