//! Atbash Cipher
//!
//! Simple substitution cipher that reverses the alphabet (A↔Z, B↔Y, etc.)

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// Atbash cipher (alphabet reversal)
pub struct AtbashCipher;

impl AtbashCipher {
    pub fn new() -> Self {
        Self
    }

    /// Reverse a character in the alphabet
    fn reverse(c: char) -> char {
        if c.is_ascii_alphabetic() {
            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
            let offset = c as u8 - base;
            let reversed = 25 - offset;
            (base + reversed) as char
        } else {
            c
        }
    }
}

impl Default for AtbashCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl Cipher for AtbashCipher {
    fn name(&self) -> &'static str {
        "atbash"
    }

    fn description(&self) -> &'static str {
        "Atbash cipher (alphabet reversal: A↔Z, B↔Y)"
    }

    fn encrypt(&self, plaintext: &[u8], _key: &CipherKey) -> Result<Vec<u8>, CipherError> {
        let text = std::str::from_utf8(plaintext)
            .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

        let result: String = text.chars().map(Self::reverse).collect();
        Ok(result.into_bytes())
    }

    fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
        // Atbash is self-inverse
        self.encrypt(ciphertext, key)
    }

    fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
        // Atbash has only one possible decryption
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
    fn test_atbash_basic() {
        let cipher = AtbashCipher::new();
        let key = CipherKey::None;

        // A -> Z, B -> Y, etc.
        assert_eq!(cipher.encrypt(b"ABC", &key).unwrap(), b"ZYX");
        assert_eq!(cipher.encrypt(b"XYZ", &key).unwrap(), b"CBA");
        assert_eq!(cipher.encrypt(b"HELLO", &key).unwrap(), b"SVOOL");
    }

    #[test]
    fn test_atbash_self_inverse() {
        let cipher = AtbashCipher::new();
        let key = CipherKey::None;

        let original = b"The quick brown fox";
        let encrypted = cipher.encrypt(original, &key).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_atbash_preserves_case() {
        let cipher = AtbashCipher::new();
        let key = CipherKey::None;

        let result = cipher.encrypt(b"Hello World", &key).unwrap();
        let result_str = String::from_utf8(result).unwrap();

        // First char should be uppercase (H -> S)
        assert!(result_str.chars().next().unwrap().is_uppercase());
        // Sixth char (W) should also be uppercase (W -> D)
        assert!(result_str.chars().nth(6).unwrap().is_uppercase());
    }

    #[test]
    fn test_atbash_preserves_non_alpha() {
        let cipher = AtbashCipher::new();
        let key = CipherKey::None;

        let result = cipher.encrypt(b"Hello, World! 123", &key).unwrap();
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains(", "));
        assert!(result_str.contains("! 123"));
    }
}
