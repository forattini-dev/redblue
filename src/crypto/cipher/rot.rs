//! ROT Ciphers
//!
//! ROT13, ROT47, and ROT5 implementations.

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// ROT13 cipher (letters only)
pub struct Rot13Cipher;

impl Rot13Cipher {
  pub fn new() -> Self {
    Self
  }

  fn rotate(c: char) -> char {
    if c.is_ascii_alphabetic() {
      let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
      let rotated = (c as u8 - base + 13) % 26;
      (base + rotated) as char
    } else {
      c
    }
  }
}

impl Default for Rot13Cipher {
  fn default() -> Self {
    Self::new()
  }
}

impl Cipher for Rot13Cipher {
  fn name(&self) -> &'static str {
    "rot13"
  }

  fn description(&self) -> &'static str {
    "ROT13 cipher (rotate letters by 13)"
  }

  fn encrypt(&self, plaintext: &[u8], _key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let text = std::str::from_utf8(plaintext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let result: String = text.chars().map(Self::rotate).collect();
    Ok(result.into_bytes())
  }

  fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    // ROT13 is self-inverse
    self.encrypt(ciphertext, key)
  }

  fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
    // ROT13 has only one possible decryption
    if let Ok(decrypted) = self.decrypt(ciphertext, &CipherKey::None) {
      if let Ok(plaintext) = String::from_utf8(decrypted) {
        return vec![CrackResult {
          plaintext,
          key: CipherKey::None,
          confidence: 1.0,
        }];
      }
    }
    vec![]
  }

  fn requires_key(&self) -> bool {
    false
  }
}

/// ROT47 cipher (ASCII printable range)
pub struct Rot47Cipher;

impl Rot47Cipher {
  pub fn new() -> Self {
    Self
  }

  fn rotate(c: char) -> char {
    if c as u32 >= 33 && c as u32 <= 126 {
      let rotated = ((c as u32 - 33 + 47) % 94) + 33;
      char::from_u32(rotated).unwrap_or(c)
    } else {
      c
    }
  }
}

impl Default for Rot47Cipher {
  fn default() -> Self {
    Self::new()
  }
}

impl Cipher for Rot47Cipher {
  fn name(&self) -> &'static str {
    "rot47"
  }

  fn description(&self) -> &'static str {
    "ROT47 cipher (rotate ASCII printable by 47)"
  }

  fn encrypt(&self, plaintext: &[u8], _key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let text = std::str::from_utf8(plaintext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let result: String = text.chars().map(Self::rotate).collect();
    Ok(result.into_bytes())
  }

  fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    // ROT47 is self-inverse
    self.encrypt(ciphertext, key)
  }

  fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
    if let Ok(decrypted) = self.decrypt(ciphertext, &CipherKey::None) {
      if let Ok(plaintext) = String::from_utf8(decrypted) {
        return vec![CrackResult {
          plaintext,
          key: CipherKey::None,
          confidence: 1.0,
        }];
      }
    }
    vec![]
  }

  fn requires_key(&self) -> bool {
    false
  }
}

/// ROT5 cipher (digits only)
pub struct Rot5Cipher;

impl Rot5Cipher {
  pub fn new() -> Self {
    Self
  }

  fn rotate(c: char) -> char {
    if c.is_ascii_digit() {
      let rotated = (c as u8 - b'0' + 5) % 10;
      (b'0' + rotated) as char
    } else {
      c
    }
  }
}

impl Default for Rot5Cipher {
  fn default() -> Self {
    Self::new()
  }
}

impl Cipher for Rot5Cipher {
  fn name(&self) -> &'static str {
    "rot5"
  }

  fn description(&self) -> &'static str {
    "ROT5 cipher (rotate digits by 5)"
  }

  fn encrypt(&self, plaintext: &[u8], _key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let text = std::str::from_utf8(plaintext)
      .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

    let result: String = text.chars().map(Self::rotate).collect();
    Ok(result.into_bytes())
  }

  fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    // ROT5 is self-inverse
    self.encrypt(ciphertext, key)
  }

  fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
    if let Ok(decrypted) = self.decrypt(ciphertext, &CipherKey::None) {
      if let Ok(plaintext) = String::from_utf8(decrypted) {
        return vec![CrackResult {
          plaintext,
          key: CipherKey::None,
          confidence: 1.0,
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
  fn test_rot13() {
    let cipher = Rot13Cipher::new();
    let key = CipherKey::None;

    assert_eq!(cipher.encrypt(b"Hello", &key).unwrap(), b"Uryyb");
    assert_eq!(cipher.decrypt(b"Uryyb", &key).unwrap(), b"Hello");

    // Self-inverse
    let text = b"The quick brown fox";
    let encrypted = cipher.encrypt(text, &key).unwrap();
    let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
    assert_eq!(decrypted, text);
  }

  #[test]
  fn test_rot47() {
    let cipher = Rot47Cipher::new();
    let key = CipherKey::None;

    assert_eq!(cipher.encrypt(b"Hello!", &key).unwrap(), b"w6==@P");
    assert_eq!(cipher.decrypt(b"w6==@P", &key).unwrap(), b"Hello!");
  }

  #[test]
  fn test_rot5() {
    let cipher = Rot5Cipher::new();
    let key = CipherKey::None;

    assert_eq!(cipher.encrypt(b"12345", &key).unwrap(), b"67890");
    assert_eq!(cipher.decrypt(b"67890", &key).unwrap(), b"12345");
    assert_eq!(cipher.encrypt(b"PIN: 1234", &key).unwrap(), b"PIN: 6789");
  }
}
