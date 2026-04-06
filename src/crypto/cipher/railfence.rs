//! Rail Fence Cipher
//!
//! Transposition cipher that writes text in a zigzag pattern across rails.

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// English letter frequency for scoring
const ENGLISH_FREQ: [f64; 26] = [
  0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
  0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
  0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

/// Rail Fence cipher (zigzag transposition)
pub struct RailFenceCipher;

impl RailFenceCipher {
  pub fn new() -> Self {
    Self
  }

  /// Calculate the rail index for a given position
  fn get_rail(pos: usize, rails: usize) -> usize {
    if rails == 1 {
      return 0;
    }
    let cycle = 2 * (rails - 1);
    let pos_in_cycle = pos % cycle;
    if pos_in_cycle < rails {
      pos_in_cycle
    } else {
      cycle - pos_in_cycle
    }
  }

  /// Score text based on English character frequency
  fn score_english(text: &str) -> f64 {
    let mut score = 0.0;
    let mut count = 0;

    for c in text.chars() {
      if c.is_ascii_alphabetic() {
        let idx = (c.to_ascii_lowercase() as u8 - b'a') as usize;
        score += ENGLISH_FREQ[idx];
        count += 1;
      } else if c == ' ' {
        score += 0.1;
        count += 1;
      } else if c.is_ascii_punctuation() {
        score += 0.01;
        count += 1;
      }
    }

    if count > 0 {
      score / count as f64
    } else {
      0.0
    }
  }
}

impl Default for RailFenceCipher {
  fn default() -> Self {
    Self::new()
  }
}

impl Cipher for RailFenceCipher {
  fn name(&self) -> &'static str {
    "railfence"
  }

  fn description(&self) -> &'static str {
    "Rail Fence cipher (zigzag transposition)"
  }

  fn encrypt(&self, plaintext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let rails = key
      .as_rails()
      .ok_or_else(|| CipherError::InvalidKey("Expected rails count".into()))?;

    if rails < 2 {
      return Err(CipherError::InvalidKey("Rails must be at least 2".into()));
    }

    let text = std::str::from_utf8(plaintext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
      return Ok(Vec::new());
    }

    // Build rails
    let mut fence: Vec<Vec<char>> = vec![Vec::new(); rails];

    for (i, &c) in chars.iter().enumerate() {
      let rail = Self::get_rail(i, rails);
      fence[rail].push(c);
    }

    // Read off rails
    let result: String = fence.into_iter().flatten().collect();
    Ok(result.into_bytes())
  }

  fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let rails = key
      .as_rails()
      .ok_or_else(|| CipherError::InvalidKey("Expected rails count".into()))?;

    if rails < 2 {
      return Err(CipherError::InvalidKey("Rails must be at least 2".into()));
    }

    let text = std::str::from_utf8(ciphertext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();

    if len == 0 {
      return Ok(Vec::new());
    }

    // Calculate how many chars go in each rail
    let mut rail_lengths = vec![0usize; rails];
    for i in 0..len {
      let rail = Self::get_rail(i, rails);
      rail_lengths[rail] += 1;
    }

    // Split ciphertext into rails
    let mut fence: Vec<Vec<char>> = Vec::with_capacity(rails);
    let mut pos = 0;
    for &rail_len in &rail_lengths {
      fence.push(chars[pos..pos + rail_len].to_vec());
      pos += rail_len;
    }

    // Read in zigzag order
    let mut rail_indices = vec![0usize; rails];
    let mut result = String::with_capacity(len);

    for i in 0..len {
      let rail = Self::get_rail(i, rails);
      result.push(fence[rail][rail_indices[rail]]);
      rail_indices[rail] += 1;
    }

    Ok(result.into_bytes())
  }

  fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
    let text = match std::str::from_utf8(ciphertext) {
      Ok(t) => t,
      Err(_) => return vec![],
    };

    if text.len() < 4 {
      return vec![]; // Too short
    }

    let mut results = Vec::new();
    let max_rails = text.len().min(20);

    for rails in 2..=max_rails {
      if let Ok(decrypted) = self.decrypt(ciphertext, &CipherKey::Rails(rails)) {
        if let Ok(plaintext) = String::from_utf8(decrypted) {
          let score = Self::score_english(&plaintext);
          results.push((rails, plaintext, score));
        }
      }
    }

    // Sort by score (higher is better)
    results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());

    // Convert to CrackResult
    let max_score = results.first().map(|r| r.2).unwrap_or(0.0);
    results
      .into_iter()
      .take(5)
      .map(|(rails, plaintext, score)| {
        let confidence = if max_score > 0.0 {
          (score / max_score).min(1.0)
        } else {
          0.0
        };
        CrackResult {
          plaintext,
          key: CipherKey::Rails(rails),
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
  fn test_railfence_encrypt() {
    let cipher = RailFenceCipher::new();
    let key = CipherKey::Rails(3);

    // Classic example: WEAREDISCOVEREDFLEEATONCE
    // Rail 0: W . . . E . . . C . . . R . . . L . . . T . . . E
    // Rail 1: . E . R . D . S . O . E . E . F . E . A . O . C .
    // Rail 2: . . A . . . I . . . V . . . D . . . E . . . N . .
    // Result: WECRLTEERDSOEEFEAOCAIVDEN
    assert_eq!(
      cipher.encrypt(b"WEAREDISCOVEREDFLEEATONCE", &key).unwrap(),
      b"WECRLTEERDSOEEFEAOCAIVDEN"
    );
  }

  #[test]
  fn test_railfence_decrypt() {
    let cipher = RailFenceCipher::new();
    let key = CipherKey::Rails(3);

    assert_eq!(
      cipher.decrypt(b"WECRLTEERDSOEEFEAOCAIVDEN", &key).unwrap(),
      b"WEAREDISCOVEREDFLEEATONCE"
    );
  }

  #[test]
  fn test_railfence_roundtrip() {
    let cipher = RailFenceCipher::new();

    for rails in 2..=5 {
      let key = CipherKey::Rails(rails);
      let original = b"The quick brown fox jumps over the lazy dog";

      let encrypted = cipher.encrypt(original, &key).unwrap();
      let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
      assert_eq!(decrypted, original, "Failed for rails={}", rails);
    }
  }

  #[test]
  fn test_railfence_invalid_rails() {
    let cipher = RailFenceCipher::new();

    // Rails must be at least 2
    let key = CipherKey::Rails(1);
    assert!(cipher.encrypt(b"TEST", &key).is_err());
  }

  #[test]
  fn test_railfence_two_rails() {
    let cipher = RailFenceCipher::new();
    let key = CipherKey::Rails(2);

    // With 2 rails: HELLO -> HLO + EL -> HLOEL
    // H . L . O
    // . E . L .
    let result = cipher.encrypt(b"HELLO", &key).unwrap();
    assert_eq!(result, b"HLOEL");
  }

  #[test]
  fn test_railfence_preserves_case_and_special() {
    let cipher = RailFenceCipher::new();
    let key = CipherKey::Rails(3);

    let original = b"Hello, World! 123";
    let encrypted = cipher.encrypt(original, &key).unwrap();
    let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

    assert_eq!(decrypted, original);
  }

  #[test]
  fn test_railfence_crack() {
    let cipher = RailFenceCipher::new();
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let key = CipherKey::Rails(4);
    let ciphertext = cipher.encrypt(plaintext, &key).unwrap();

    let results = cipher.crack(&ciphertext);
    assert!(!results.is_empty());

    // One of the results should be the original
    let found = results
      .iter()
      .any(|r| r.plaintext.to_lowercase() == String::from_utf8_lossy(plaintext).to_lowercase());
    assert!(found, "Failed to crack rail fence cipher");
  }
}
