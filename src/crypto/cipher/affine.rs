//! Affine Cipher
//!
//! Substitution cipher using linear function: E(x) = (ax + b) mod 26
//! Where 'a' must be coprime with 26.

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// English letter frequency for analysis
const ENGLISH_FREQ: [f64; 26] = [
  0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
  0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
  0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

/// Values of 'a' that are coprime with 26
const VALID_A_VALUES: [i32; 12] = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

/// Affine cipher
pub struct AffineCipher;

impl AffineCipher {
  pub fn new() -> Self {
    Self
  }

  /// Check if 'a' is coprime with 26
  fn is_valid_a(a: i32) -> bool {
    VALID_A_VALUES.contains(&(((a % 26) + 26) % 26))
  }

  /// Calculate modular multiplicative inverse of 'a' mod 26
  fn mod_inverse(a: i32) -> Option<i32> {
    let a = ((a % 26) + 26) % 26;
    for x in 1..26 {
      if (a * x) % 26 == 1 {
        return Some(x);
      }
    }
    None
  }

  /// Encrypt a single character: E(x) = (ax + b) mod 26
  fn encrypt_char(c: char, a: i32, b: i32) -> char {
    if c.is_ascii_alphabetic() {
      let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
      let x = (c as u8 - base) as i32;
      let encrypted = ((a * x + b) % 26 + 26) % 26;
      (base + encrypted as u8) as char
    } else {
      c
    }
  }

  /// Decrypt a single character: D(y) = a^-1(y - b) mod 26
  fn decrypt_char(c: char, a_inv: i32, b: i32) -> char {
    if c.is_ascii_alphabetic() {
      let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
      let y = (c as u8 - base) as i32;
      let decrypted = ((a_inv * (y - b)) % 26 + 26) % 26;
      (base + decrypted as u8) as char
    } else {
      c
    }
  }

  /// Calculate chi-squared score against English
  fn chi_squared(text: &str) -> f64 {
    let mut freq = [0.0; 26];
    let mut total = 0.0;

    for c in text.chars() {
      if c.is_ascii_alphabetic() {
        let idx = (c.to_ascii_lowercase() as u8 - b'a') as usize;
        freq[idx] += 1.0;
        total += 1.0;
      }
    }

    if total == 0.0 {
      return f64::MAX;
    }

    let mut chi = 0.0;
    for i in 0..26 {
      let observed = freq[i] / total;
      let expected = ENGLISH_FREQ[i];
      if expected > 0.0 {
        chi += (observed - expected).powi(2) / expected;
      }
    }

    chi
  }
}

impl Default for AffineCipher {
  fn default() -> Self {
    Self::new()
  }
}

impl Cipher for AffineCipher {
  fn name(&self) -> &'static str {
    "affine"
  }

  fn description(&self) -> &'static str {
    "Affine cipher (E(x) = ax + b mod 26)"
  }

  fn encrypt(&self, plaintext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let (a, b) = key
      .as_affine()
      .ok_or_else(|| CipherError::InvalidKey("Expected affine key (a, b)".into()))?;

    if !Self::is_valid_a(a) {
      return Err(CipherError::InvalidKey(format!(
        "'a' ({}) must be coprime with 26. Valid values: {:?}",
        a, VALID_A_VALUES
      )));
    }

    let text = std::str::from_utf8(plaintext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let result: String = text.chars().map(|c| Self::encrypt_char(c, a, b)).collect();
    Ok(result.into_bytes())
  }

  fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let (a, b) = key
      .as_affine()
      .ok_or_else(|| CipherError::InvalidKey("Expected affine key (a, b)".into()))?;

    let a_inv = Self::mod_inverse(a).ok_or_else(|| {
      CipherError::InvalidKey(format!(
        "'a' ({}) must be coprime with 26. Valid values: {:?}",
        a, VALID_A_VALUES
      ))
    })?;

    let text = std::str::from_utf8(ciphertext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let result: String = text
      .chars()
      .map(|c| Self::decrypt_char(c, a_inv, b))
      .collect();
    Ok(result.into_bytes())
  }

  fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
    let text = match std::str::from_utf8(ciphertext) {
      Ok(t) => t,
      Err(_) => return vec![],
    };

    let mut results = Vec::new();

    // Try all valid combinations of a and b
    for &a in &VALID_A_VALUES {
      if let Some(a_inv) = Self::mod_inverse(a) {
        for b in 0..26 {
          let decrypted: String = text
            .chars()
            .map(|c| Self::decrypt_char(c, a_inv, b))
            .collect();

          let score = Self::chi_squared(&decrypted);
          results.push((a, b, decrypted, score));
        }
      }
    }

    // Sort by chi-squared (lower is better)
    results.sort_by(|x, y| x.3.partial_cmp(&y.3).unwrap());

    // Convert to CrackResult with confidence
    let max_score = results.last().map(|r| r.3).unwrap_or(1.0);
    results
      .into_iter()
      .take(10)
      .map(|(a, b, plaintext, score)| {
        let confidence = if max_score > 0.0 {
          (1.0 - score / max_score).max(0.0)
        } else {
          0.0
        };
        CrackResult {
          plaintext,
          key: CipherKey::Affine(a, b),
          confidence,
        }
      })
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_affine_encrypt() {
    let cipher = AffineCipher::new();

    // a=5, b=8 is a common example
    let key = CipherKey::Affine(5, 8);
    assert_eq!(cipher.encrypt(b"AFFINE", &key).unwrap(), b"IHHWVC");
  }

  #[test]
  fn test_affine_decrypt() {
    let cipher = AffineCipher::new();
    let key = CipherKey::Affine(5, 8);

    assert_eq!(cipher.decrypt(b"IHHWVC", &key).unwrap(), b"AFFINE");
  }

  #[test]
  fn test_affine_roundtrip() {
    let cipher = AffineCipher::new();
    let key = CipherKey::Affine(7, 11);
    let original = b"The quick brown fox jumps over the lazy dog";

    let encrypted = cipher.encrypt(original, &key).unwrap();
    let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
    assert_eq!(decrypted, original);
  }

  #[test]
  fn test_affine_invalid_a() {
    let cipher = AffineCipher::new();

    // a=2 is not coprime with 26
    let key = CipherKey::Affine(2, 5);
    assert!(cipher.encrypt(b"TEST", &key).is_err());
  }

  #[test]
  fn test_affine_caesar_equivalence() {
    // Affine with a=1 is equivalent to Caesar
    let cipher = AffineCipher::new();
    let key = CipherKey::Affine(1, 3);

    assert_eq!(cipher.encrypt(b"HELLO", &key).unwrap(), b"KHOOR");
  }

  #[test]
  fn test_affine_atbash_equivalence() {
    // Affine with a=25, b=25 is equivalent to Atbash
    let cipher = AffineCipher::new();
    let key = CipherKey::Affine(25, 25);

    assert_eq!(cipher.encrypt(b"ABC", &key).unwrap(), b"ZYX");
  }

  #[test]
  fn test_affine_preserves_case() {
    let cipher = AffineCipher::new();
    let key = CipherKey::Affine(5, 8);

    let result = cipher.encrypt(b"Hello World", &key).unwrap();
    let result_str = String::from_utf8(result).unwrap();

    assert!(result_str.chars().next().unwrap().is_uppercase());
    assert!(result_str.contains(' '));
  }

  #[test]
  fn test_affine_crack() {
    let cipher = AffineCipher::new();
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let key = CipherKey::Affine(5, 8);
    let ciphertext = cipher.encrypt(plaintext, &key).unwrap();

    let results = cipher.crack(&ciphertext);
    assert!(!results.is_empty());

    // Best result should have high confidence
    let best = &results[0];
    assert!(best.confidence > 0.5);
  }
}
