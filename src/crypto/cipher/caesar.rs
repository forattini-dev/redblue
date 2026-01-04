//! Caesar Cipher
//!
//! Simple substitution cipher that shifts letters by a fixed amount.

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// English letter frequency (for cracking)
const ENGLISH_FREQ: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

/// Caesar cipher
pub struct CaesarCipher;

impl CaesarCipher {
    /// Create Caesar cipher
    pub fn new() -> Self {
        Self
    }

    /// Shift a character
    fn shift_char(c: char, shift: i32) -> char {
        if c.is_ascii_alphabetic() {
            let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
            let shifted = (c as u8 - base) as i32 + shift;
            let normalized = ((shifted % 26) + 26) % 26;
            (base + normalized as u8) as char
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

impl Default for CaesarCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl Cipher for CaesarCipher {
    fn name(&self) -> &'static str {
        "caesar"
    }

    fn description(&self) -> &'static str {
        "Caesar cipher (shift substitution)"
    }

    fn encrypt(&self, plaintext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
        let shift = key
            .as_shift()
            .ok_or_else(|| CipherError::InvalidKey("Expected shift value".into()))?;

        let text = std::str::from_utf8(plaintext)
            .map_err(|_| CipherError::InvalidInput("Not valid UTF-8".into()))?;

        let result: String = text.chars().map(|c| Self::shift_char(c, shift)).collect();
        Ok(result.into_bytes())
    }

    fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
        let shift = key
            .as_shift()
            .ok_or_else(|| CipherError::InvalidKey("Expected shift value".into()))?;

        // Decrypt is encrypt with negative shift
        self.encrypt(ciphertext, &CipherKey::Shift(-shift))
    }

    fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
        let text = match std::str::from_utf8(ciphertext) {
            Ok(t) => t,
            Err(_) => return vec![],
        };

        let mut results: Vec<(i32, String, f64)> = (0..26)
            .map(|shift| {
                let decrypted: String = text.chars().map(|c| Self::shift_char(c, -shift)).collect();
                let score = Self::chi_squared(&decrypted);
                (shift, decrypted, score)
            })
            .collect();

        // Sort by chi-squared (lower is better)
        results.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap());

        // Convert to CrackResult with confidence
        let max_score = results.last().map(|r| r.2).unwrap_or(1.0);
        results
            .into_iter()
            .map(|(shift, plaintext, score)| {
                let confidence = if max_score > 0.0 {
                    (1.0 - score / max_score).max(0.0)
                } else {
                    0.0
                };
                CrackResult {
                    plaintext,
                    key: CipherKey::Shift(shift),
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
    fn test_caesar_encrypt() {
        let cipher = CaesarCipher::new();
        let key = CipherKey::Shift(3);

        assert_eq!(cipher.encrypt(b"HELLO", &key).unwrap(), b"KHOOR");
        assert_eq!(cipher.encrypt(b"hello", &key).unwrap(), b"khoor");
        assert_eq!(
            cipher.encrypt(b"Hello World!", &key).unwrap(),
            b"Khoor Zruog!"
        );
    }

    #[test]
    fn test_caesar_decrypt() {
        let cipher = CaesarCipher::new();
        let key = CipherKey::Shift(3);

        assert_eq!(cipher.decrypt(b"KHOOR", &key).unwrap(), b"HELLO");
        assert_eq!(
            cipher.decrypt(b"Khoor Zruog!", &key).unwrap(),
            b"Hello World!"
        );
    }

    #[test]
    fn test_caesar_roundtrip() {
        let cipher = CaesarCipher::new();
        let key = CipherKey::Shift(13);
        let original = b"The quick brown fox jumps over the lazy dog";

        let encrypted = cipher.encrypt(original, &key).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_caesar_crack() {
        let cipher = CaesarCipher::new();
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let key = CipherKey::Shift(7);
        let ciphertext = cipher.encrypt(plaintext, &key).unwrap();

        let results = cipher.crack(&ciphertext);
        assert!(!results.is_empty());

        // Best result should be shift 7 with high confidence
        let best = &results[0];
        assert_eq!(best.key.as_shift(), Some(7));
        assert!(best.confidence > 0.5);
    }

    #[test]
    fn test_caesar_preserves_case() {
        let cipher = CaesarCipher::new();
        let key = CipherKey::Shift(1);

        assert_eq!(cipher.encrypt(b"AaBb", &key).unwrap(), b"BbCc");
    }

    #[test]
    fn test_caesar_preserves_non_alpha() {
        let cipher = CaesarCipher::new();
        let key = CipherKey::Shift(1);

        assert_eq!(
            cipher.encrypt(b"Hello, World! 123", &key).unwrap(),
            b"Ifmmp, Xpsme! 123"
        );
    }
}
