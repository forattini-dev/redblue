//! Vigenère Cipher
//!
//! Polyalphabetic substitution cipher using a keyword.

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// English letter frequency for analysis
const ENGLISH_FREQ: [f64; 26] = [
  0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
  0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
  0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

/// Vigenère cipher
pub struct VigenereCipher;

impl VigenereCipher {
  pub fn new() -> Self {
    Self
  }

  /// Shift a character by another character
  fn shift(c: char, key_char: char, decrypt: bool) -> char {
    if c.is_ascii_alphabetic() {
      let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
      let shift =
        (key_char.to_ascii_uppercase() as i32 - 'A' as i32) * if decrypt { -1 } else { 1 };
      let shifted = (c as u8 as i32 - base as i32 + shift + 26) % 26;
      (base + shifted as u8) as char
    } else {
      c
    }
  }

  /// Calculate Index of Coincidence
  fn index_of_coincidence(text: &str) -> f64 {
    let mut freq = [0u32; 26];
    let mut n = 0u32;

    for c in text.chars() {
      if c.is_ascii_alphabetic() {
        freq[(c.to_ascii_lowercase() as u8 - b'a') as usize] += 1;
        n += 1;
      }
    }

    if n <= 1 {
      return 0.0;
    }

    let sum: u32 = freq.iter().map(|&f| f * (f.saturating_sub(1))).sum();
    sum as f64 / (n * (n - 1)) as f64
  }

  /// Kasiski examination to find probable key lengths
  fn kasiski_key_lengths(text: &str) -> Vec<usize> {
    let chars: Vec<char> = text.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let mut distances = Vec::new();

    // Find repeated trigrams
    for i in 0..chars.len().saturating_sub(2) {
      let trigram: String = chars[i..i + 3].iter().collect();
      for j in i + 3..chars.len().saturating_sub(2) {
        let other: String = chars[j..j + 3].iter().collect();
        if trigram == other {
          distances.push(j - i);
        }
      }
    }

    // Find common factors
    let mut factors: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for d in distances {
      for f in 2..=d.min(20) {
        if d % f == 0 {
          *factors.entry(f).or_insert(0) += 1;
        }
      }
    }

    let mut lengths: Vec<_> = factors.into_iter().collect();
    lengths.sort_by(|a, b| b.1.cmp(&a.1));
    lengths.into_iter().take(5).map(|(k, _)| k).collect()
  }

  /// Chi-squared score against English
  fn chi_squared(freq: &[f64; 26]) -> f64 {
    let mut chi = 0.0;
    for i in 0..26 {
      let expected = ENGLISH_FREQ[i];
      if expected > 0.0 {
        chi += (freq[i] - expected).powi(2) / expected;
      }
    }
    chi
  }

  /// Find best key character for a column
  fn find_best_key_char(column: &[char]) -> char {
    let mut best_shift = 0;
    let mut best_score = f64::MAX;

    for shift in 0..26 {
      let mut freq = [0.0; 26];
      let mut count = 0.0;

      for &c in column {
        let shifted = ((c.to_ascii_lowercase() as u8 - b'a' + 26 - shift) % 26) as usize;
        freq[shifted] += 1.0;
        count += 1.0;
      }

      if count > 0.0 {
        for f in &mut freq {
          *f /= count;
        }
        let score = Self::chi_squared(&freq);
        if score < best_score {
          best_score = score;
          best_shift = shift;
        }
      }
    }

    (b'A' + best_shift) as char
  }
}

impl Default for VigenereCipher {
  fn default() -> Self {
    Self::new()
  }
}

impl Cipher for VigenereCipher {
  fn name(&self) -> &'static str {
    "vigenere"
  }

  fn description(&self) -> &'static str {
    "Vigenère cipher (polyalphabetic substitution)"
  }

  fn encrypt(&self, plaintext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let key_text = key
      .as_text()
      .ok_or_else(|| CipherError::InvalidKey("Expected text key".into()))?;

    if key_text.is_empty() {
      return Err(CipherError::InvalidKey("Key cannot be empty".into()));
    }

    let text = std::str::from_utf8(plaintext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let key_chars: Vec<char> = key_text
      .chars()
      .filter(|c| c.is_ascii_alphabetic())
      .collect();

    if key_chars.is_empty() {
      return Err(CipherError::InvalidKey(
        "Key must contain alphabetic characters".into(),
      ));
    }

    let mut key_index = 0;
    let result: String = text
      .chars()
      .map(|c| {
        if c.is_ascii_alphabetic() {
          let shifted = Self::shift(c, key_chars[key_index % key_chars.len()], false);
          key_index += 1;
          shifted
        } else {
          c
        }
      })
      .collect();

    Ok(result.into_bytes())
  }

  fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let key_text = key
      .as_text()
      .ok_or_else(|| CipherError::InvalidKey("Expected text key".into()))?;

    if key_text.is_empty() {
      return Err(CipherError::InvalidKey("Key cannot be empty".into()));
    }

    let text = std::str::from_utf8(ciphertext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let key_chars: Vec<char> = key_text
      .chars()
      .filter(|c| c.is_ascii_alphabetic())
      .collect();

    if key_chars.is_empty() {
      return Err(CipherError::InvalidKey(
        "Key must contain alphabetic characters".into(),
      ));
    }

    let mut key_index = 0;
    let result: String = text
      .chars()
      .map(|c| {
        if c.is_ascii_alphabetic() {
          let shifted = Self::shift(c, key_chars[key_index % key_chars.len()], true);
          key_index += 1;
          shifted
        } else {
          c
        }
      })
      .collect();

    Ok(result.into_bytes())
  }

  fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
    let text = match std::str::from_utf8(ciphertext) {
      Ok(t) => t,
      Err(_) => return vec![],
    };

    let chars: Vec<char> = text
      .chars()
      .filter(|c| c.is_ascii_alphabetic())
      .map(|c| c.to_ascii_uppercase())
      .collect();

    if chars.len() < 20 {
      return vec![]; // Too short to crack reliably
    }

    // Try different key lengths
    let mut results = Vec::new();
    let key_lengths = Self::kasiski_key_lengths(text);

    for &key_len in key_lengths.iter().chain(&[3, 4, 5, 6, 7, 8]) {
      if key_len < 2 || key_len > chars.len() / 3 {
        continue;
      }

      // Split into columns
      let mut columns: Vec<Vec<char>> = vec![Vec::new(); key_len];
      for (i, &c) in chars.iter().enumerate() {
        columns[i % key_len].push(c);
      }

      // Find best key character for each column
      let key: String = columns
        .iter()
        .map(|col| Self::find_best_key_char(col))
        .collect();

      // Decrypt and score
      if let Ok(decrypted) = self.decrypt(ciphertext, &CipherKey::Text(key.clone())) {
        if let Ok(plaintext) = String::from_utf8(decrypted) {
          let ioc = Self::index_of_coincidence(&plaintext);
          // English IoC is around 0.067
          let confidence = ((ioc - 0.038) / (0.067 - 0.038)).clamp(0.0, 1.0);

          results.push(CrackResult {
            plaintext,
            key: CipherKey::Text(key),
            confidence,
          });
        }
      }
    }

    // Sort by confidence
    results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    results.truncate(5);
    results
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_vigenere_encrypt() {
    let cipher = VigenereCipher::new();
    let key = CipherKey::Text("LEMON".into());

    assert_eq!(
      cipher.encrypt(b"ATTACKATDAWN", &key).unwrap(),
      b"LXFOPVEFRNHR"
    );
  }

  #[test]
  fn test_vigenere_decrypt() {
    let cipher = VigenereCipher::new();
    let key = CipherKey::Text("LEMON".into());

    assert_eq!(
      cipher.decrypt(b"LXFOPVEFRNHR", &key).unwrap(),
      b"ATTACKATDAWN"
    );
  }

  #[test]
  fn test_vigenere_roundtrip() {
    let cipher = VigenereCipher::new();
    let key = CipherKey::Text("SECRET".into());
    let original = b"The quick brown fox jumps over the lazy dog";

    let encrypted = cipher.encrypt(original, &key).unwrap();
    let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
    assert_eq!(decrypted, original);
  }

  #[test]
  fn test_vigenere_preserves_case() {
    let cipher = VigenereCipher::new();
    let key = CipherKey::Text("KEY".into());

    let encrypted = cipher.encrypt(b"Hello World", &key).unwrap();
    let encrypted_str = String::from_utf8(encrypted.clone()).unwrap();

    // First char should be uppercase, space preserved
    assert!(encrypted_str.chars().next().unwrap().is_uppercase());
    assert!(encrypted_str.contains(' '));
  }

  #[test]
  fn test_vigenere_preserves_non_alpha() {
    let cipher = VigenereCipher::new();
    let key = CipherKey::Text("KEY".into());

    let result = cipher.encrypt(b"Hello, World! 123", &key).unwrap();
    let result_str = String::from_utf8(result).unwrap();

    assert!(result_str.contains(", "));
    assert!(result_str.contains("! 123"));
  }
}
