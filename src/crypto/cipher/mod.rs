//! Cipher Module - Classical Cipher Registry
//!
//! Provides a unified interface for classical cipher operations.
//! All ciphers implement the `Cipher` trait for consistent handling.

mod affine;
mod atbash;
mod bacon;
mod caesar;
mod playfair;
mod railfence;
mod rot;
mod vigenere;
mod xor;

use std::collections::HashMap;

pub use affine::AffineCipher;
pub use atbash::AtbashCipher;
pub use bacon::BaconCipher;
pub use caesar::CaesarCipher;
pub use playfair::PlayfairCipher;
pub use railfence::RailFenceCipher;
pub use rot::{Rot13Cipher, Rot47Cipher, Rot5Cipher};
pub use vigenere::VigenereCipher;
pub use xor::XorCipher;

/// Error types for cipher operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
  /// Invalid key for this cipher
  InvalidKey(String),
  /// Invalid input
  InvalidInput(String),
  /// Key required but not provided
  KeyRequired,
  /// Cannot crack this ciphertext
  CrackFailed,
  /// Unknown cipher name
  UnknownCipher(String),
}

impl std::fmt::Display for CipherError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
      Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
      Self::KeyRequired => write!(f, "Key required for this cipher"),
      Self::CrackFailed => write!(f, "Could not crack ciphertext"),
      Self::UnknownCipher(name) => write!(f, "Unknown cipher: {}", name),
    }
  }
}

impl std::error::Error for CipherError {}

/// Key type for different ciphers
#[derive(Debug, Clone)]
pub enum CipherKey {
  /// Shift value (Caesar, ROT)
  Shift(i32),
  /// Text key (Vigenère)
  Text(String),
  /// Byte key (XOR)
  Bytes(Vec<u8>),
  /// Affine cipher parameters (a, b)
  Affine(i32, i32),
  /// No key needed (Atbash, ROT13)
  None,
  /// Rail count for Rail Fence
  Rails(usize),
}

impl CipherKey {
  /// Get shift value
  pub fn as_shift(&self) -> Option<i32> {
    match self {
      Self::Shift(n) => Some(*n),
      _ => None,
    }
  }

  /// Get text key
  pub fn as_text(&self) -> Option<&str> {
    match self {
      Self::Text(s) => Some(s),
      _ => None,
    }
  }

  /// Get bytes key
  pub fn as_bytes(&self) -> Option<&[u8]> {
    match self {
      Self::Bytes(b) => Some(b),
      _ => None,
    }
  }

  /// Get affine parameters
  pub fn as_affine(&self) -> Option<(i32, i32)> {
    match self {
      Self::Affine(a, b) => Some((*a, *b)),
      _ => None,
    }
  }

  /// Get rails count
  pub fn as_rails(&self) -> Option<usize> {
    match self {
      Self::Rails(n) => Some(*n),
      _ => None,
    }
  }
}

/// Result of cracking a cipher
#[derive(Debug, Clone)]
pub struct CrackResult {
  /// Decrypted plaintext
  pub plaintext: String,
  /// Key used
  pub key: CipherKey,
  /// Confidence score (0.0 - 1.0)
  pub confidence: f64,
}

/// Common interface for classical ciphers
pub trait Cipher: Send + Sync {
  /// Unique identifier for this cipher
  fn name(&self) -> &'static str;

  /// Human-readable description
  fn description(&self) -> &'static str;

  /// Encrypt plaintext
  fn encrypt(&self, plaintext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError>;

  /// Decrypt ciphertext
  fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError>;

  /// Attempt to crack without key (brute force, frequency analysis)
  /// Returns multiple possible results sorted by confidence
  fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult>;

  /// Check if this cipher requires a key
  fn requires_key(&self) -> bool {
    true
  }
}

/// Registry for managing cipher instances
pub struct CipherRegistry {
  ciphers: HashMap<&'static str, Box<dyn Cipher>>,
}

impl Default for CipherRegistry {
  fn default() -> Self {
    Self::new()
  }
}

impl CipherRegistry {
  /// Create a new registry with all built-in ciphers
  pub fn new() -> Self {
    let mut registry = Self {
      ciphers: HashMap::new(),
    };

    // Register all built-in ciphers
    registry.register(Box::new(CaesarCipher::new()));
    registry.register(Box::new(Rot13Cipher::new()));
    registry.register(Box::new(Rot47Cipher::new()));
    registry.register(Box::new(Rot5Cipher::new()));
    registry.register(Box::new(VigenereCipher::new()));
    registry.register(Box::new(XorCipher::new()));
    registry.register(Box::new(AtbashCipher::new()));
    registry.register(Box::new(AffineCipher::new()));
    registry.register(Box::new(RailFenceCipher::new()));
    registry.register(Box::new(BaconCipher::new()));
    registry.register(Box::new(PlayfairCipher::new()));

    registry
  }

  /// Register a cipher
  pub fn register(&mut self, cipher: Box<dyn Cipher>) {
    self.ciphers.insert(cipher.name(), cipher);
  }

  /// Get a cipher by name
  pub fn get(&self, name: &str) -> Option<&dyn Cipher> {
    self.ciphers.get(name).map(|c| c.as_ref())
  }

  /// List all registered cipher names
  pub fn list(&self) -> Vec<&'static str> {
    let mut names: Vec<_> = self.ciphers.keys().copied().collect();
    names.sort();
    names
  }

  /// Try to crack with all ciphers, return best results
  pub fn crack_all(&self, ciphertext: &[u8]) -> Vec<(String, CrackResult)> {
    let mut results: Vec<_> = self
      .ciphers
      .iter()
      .flat_map(|(name, cipher)| {
        cipher
          .crack(ciphertext)
          .into_iter()
          .map(|r| (name.to_string(), r))
      })
      .collect();

    // Sort by confidence descending
    results.sort_by(|a, b| b.1.confidence.partial_cmp(&a.1.confidence).unwrap());
    results
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_registry_creation() {
    let registry = CipherRegistry::new();
    assert!(registry.get("caesar").is_some());
    assert!(registry.get("rot13").is_some());
    assert!(registry.get("xor").is_some());
    assert!(registry.get("bacon").is_some());
    assert!(registry.get("playfair").is_some());
    assert!(registry.get("nonexistent").is_none());
  }

  #[test]
  fn test_registry_list() {
    let registry = CipherRegistry::new();
    let names = registry.list();
    assert!(names.contains(&"caesar"));
    assert!(names.contains(&"rot13"));
    assert!(names.contains(&"vigenere"));
  }

  #[test]
  fn test_cipher_key_types() {
    let shift = CipherKey::Shift(3);
    assert_eq!(shift.as_shift(), Some(3));
    assert!(shift.as_text().is_none());

    let text = CipherKey::Text("KEY".into());
    assert_eq!(text.as_text(), Some("KEY"));
    assert!(text.as_shift().is_none());

    let bytes = CipherKey::Bytes(vec![0x42]);
    assert_eq!(bytes.as_bytes(), Some(&[0x42][..]));
  }
}
