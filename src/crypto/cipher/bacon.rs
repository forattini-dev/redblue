//! Bacon Cipher
//!
//! Bacon's cipher uses 5-bit binary representation for each letter.
//! Each letter is encoded as a sequence of 5 'a' or 'b' characters.
//! I/J and U/V share the same encoding (24-letter alphabet).

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// Bacon cipher encoding table (5-bit binary)
/// Note: I=J and U=V (24-letter alphabet)
const BACON_TABLE: [(&str, char); 24] = [
  ("aaaaa", 'A'), // 0
  ("aaaab", 'B'), // 1
  ("aaaba", 'C'), // 2
  ("aaabb", 'D'), // 3
  ("aabaa", 'E'), // 4
  ("aabab", 'F'), // 5
  ("aabba", 'G'), // 6
  ("aabbb", 'H'), // 7
  ("abaaa", 'I'), // 8 (also J)
  ("abaab", 'K'), // 9
  ("ababa", 'L'), // 10
  ("ababb", 'M'), // 11
  ("abbaa", 'N'), // 12
  ("abbab", 'O'), // 13
  ("abbba", 'P'), // 14
  ("abbbb", 'Q'), // 15
  ("baaaa", 'R'), // 16
  ("baaab", 'S'), // 17
  ("baaba", 'T'), // 18
  ("baabb", 'U'), // 19 (also V)
  ("babaa", 'W'), // 20
  ("babab", 'X'), // 21
  ("babba", 'Y'), // 22
  ("babbb", 'Z'), // 23
];

/// Bacon cipher
pub struct BaconCipher;

impl BaconCipher {
  /// Create Bacon cipher
  pub fn new() -> Self {
    Self
  }

  /// Get the bacon code for a character
  fn char_to_bacon(c: char) -> Option<&'static str> {
    let c = c.to_ascii_uppercase();
    // Handle I/J and U/V equivalence
    let c = match c {
      'J' => 'I',
      'V' => 'U',
      _ => c,
    };

    for (code, letter) in BACON_TABLE.iter() {
      if *letter == c {
        return Some(code);
      }
    }
    None
  }

  /// Get the character for a bacon code
  fn bacon_to_char(code: &str) -> Option<char> {
    let code = code.to_lowercase();
    for (bacon, letter) in BACON_TABLE.iter() {
      if *bacon == code {
        return Some(*letter);
      }
    }
    None
  }

  /// Encode text to Bacon cipher
  fn encode_text(text: &str) -> String {
    let mut result = Vec::new();

    for c in text.chars() {
      if c.is_ascii_alphabetic() {
        if let Some(code) = Self::char_to_bacon(c) {
          result.push(code.to_string());
        }
      }
    }

    result.join(" ")
  }

  /// Decode Bacon cipher to text
  fn decode_text(text: &str) -> Result<String, CipherError> {
    let mut result = String::new();

    // Remove spaces and validate
    let clean: String = text
      .chars()
      .filter(|c| *c == 'a' || *c == 'b' || *c == 'A' || *c == 'B')
      .collect();

    if clean.len() % 5 != 0 {
      return Err(CipherError::InvalidInput(format!(
        "Bacon cipher requires input length divisible by 5, got {}",
        clean.len()
      )));
    }

    for chunk in clean.as_bytes().chunks(5) {
      let code = std::str::from_utf8(chunk)
        .map_err(|_| CipherError::InvalidInput("Invalid UTF-8".to_string()))?
        .to_lowercase();

      if let Some(c) = Self::bacon_to_char(&code) {
        result.push(c);
      } else {
        return Err(CipherError::InvalidInput(format!(
          "Invalid Bacon code: {}",
          code
        )));
      }
    }

    Ok(result)
  }

  /// Extract Bacon message from steganographic text
  /// Uppercase = 'b', Lowercase = 'a'
  pub fn decode_steganographic(text: &str) -> Result<String, CipherError> {
    let mut binary = String::new();

    for c in text.chars() {
      if c.is_ascii_alphabetic() {
        if c.is_ascii_uppercase() {
          binary.push('b');
        } else {
          binary.push('a');
        }
      }
    }

    Self::decode_text(&binary)
  }

  /// Encode text into steganographic carrier
  /// Returns the carrier text with hidden message encoded in case
  pub fn encode_steganographic(plaintext: &str, carrier: &str) -> Result<String, CipherError> {
    let bacon = Self::encode_text(plaintext).replace(' ', "");
    let bacon_chars: Vec<char> = bacon.chars().collect();

    let mut result = String::new();
    let mut bacon_idx = 0;

    for c in carrier.chars() {
      if c.is_ascii_alphabetic() && bacon_idx < bacon_chars.len() {
        if bacon_chars[bacon_idx] == 'b' {
          result.push(c.to_ascii_uppercase());
        } else {
          result.push(c.to_ascii_lowercase());
        }
        bacon_idx += 1;
      } else {
        result.push(c);
      }
    }

    if bacon_idx < bacon_chars.len() {
      return Err(CipherError::InvalidInput(
        "Carrier text too short for message".to_string(),
      ));
    }

    Ok(result)
  }
}

impl Default for BaconCipher {
  fn default() -> Self {
    Self::new()
  }
}

impl Cipher for BaconCipher {
  fn name(&self) -> &'static str {
    "bacon"
  }

  fn description(&self) -> &'static str {
    "Bacon's 5-bit binary cipher (I=J, U=V)"
  }

  fn encrypt(&self, plaintext: &[u8], _key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let text = std::str::from_utf8(plaintext)
      .map_err(|_| CipherError::InvalidInput("Invalid UTF-8".to_string()))?;

    let encoded = Self::encode_text(text);
    Ok(encoded.into_bytes())
  }

  fn decrypt(&self, ciphertext: &[u8], _key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let text = std::str::from_utf8(ciphertext)
      .map_err(|_| CipherError::InvalidInput("Invalid UTF-8".to_string()))?;

    let decoded = Self::decode_text(text)?;
    Ok(decoded.into_bytes())
  }

  fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
    // Bacon cipher has no key, just try to decode
    if let Ok(text) = std::str::from_utf8(ciphertext) {
      // Try standard decode
      if let Ok(decoded) = Self::decode_text(text) {
        return vec![CrackResult {
          plaintext: decoded,
          key: CipherKey::None,
          confidence: 0.9,
        }];
      }

      // Try steganographic decode
      if let Ok(decoded) = Self::decode_steganographic(text) {
        return vec![CrackResult {
          plaintext: decoded,
          key: CipherKey::None,
          confidence: 0.7,
        }];
      }
    }

    vec![]
  }

  fn requires_key(&self) -> bool {
    false
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_encode_hello() {
    let cipher = BaconCipher::new();
    let result = cipher.encrypt(b"HELLO", &CipherKey::None).unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();

    // HELLO = aabbb aabaa ababa ababa abbab
    assert_eq!(result_str, "aabbb aabaa ababa ababa abbab");
  }

  #[test]
  fn test_decode_hello() {
    let cipher = BaconCipher::new();
    let result = cipher
      .decrypt(b"aabbb aabaa ababa ababa abbab", &CipherKey::None)
      .unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();

    assert_eq!(result_str, "HELLO");
  }

  #[test]
  fn test_ij_equivalence() {
    // J should encode the same as I
    let cipher = BaconCipher::new();
    let i_result = cipher.encrypt(b"I", &CipherKey::None).unwrap();
    let j_result = cipher.encrypt(b"J", &CipherKey::None).unwrap();

    assert_eq!(i_result, j_result);
  }

  #[test]
  fn test_uv_equivalence() {
    // V should encode the same as U
    let cipher = BaconCipher::new();
    let u_result = cipher.encrypt(b"U", &CipherKey::None).unwrap();
    let v_result = cipher.encrypt(b"V", &CipherKey::None).unwrap();

    assert_eq!(u_result, v_result);
  }

  #[test]
  fn test_steganographic_decode() {
    // Needs exactly 5 or 10 characters for valid decode
    // "Hello" -> lowercase = aaaaa = 'A'
    let result = BaconCipher::decode_steganographic("hello").unwrap();
    assert_eq!(result, "A");

    // "HELLO" -> uppercase = bbbbb (invalid), try mixed
    // "helloHELLO" = aaaaa bbbbb = A, Z (bbbbb would be after Z, actually babbb = Z)
    let result2 = BaconCipher::decode_steganographic("helloworld").unwrap(); // 10 chars = 2 letters
    assert_eq!(result2.len(), 2);
  }

  #[test]
  fn test_roundtrip() {
    let cipher = BaconCipher::new();
    let original = b"TESTMESSAGE";

    let encoded = cipher.encrypt(original, &CipherKey::None).unwrap();
    let decoded = cipher.decrypt(&encoded, &CipherKey::None).unwrap();

    assert_eq!(original.to_vec(), decoded);
  }

  #[test]
  fn test_all_letters() {
    let cipher = BaconCipher::new();

    // Encode all letters
    let all = b"ABCDEFGHIKLMNOPQRSTUWXYZ"; // No J or V (they map to I and U)
    let encoded = cipher.encrypt(all, &CipherKey::None).unwrap();
    let decoded = cipher.decrypt(&encoded, &CipherKey::None).unwrap();

    assert_eq!(all.to_vec(), decoded);
  }
}
