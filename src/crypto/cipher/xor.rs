//! XOR Cipher
//!
//! Single-byte and multi-byte XOR encryption.

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// English letter frequency for scoring
const ENGLISH_FREQ: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

/// XOR cipher
pub struct XorCipher;

impl XorCipher {
    pub fn new() -> Self {
        Self
    }

    /// Score text based on English character frequency
    fn score_english(data: &[u8]) -> f64 {
        let mut score = 0.0;
        let mut count = 0;

        for &byte in data {
            if byte.is_ascii_alphabetic() {
                let idx = (byte.to_ascii_lowercase() - b'a') as usize;
                score += ENGLISH_FREQ[idx];
                count += 1;
            } else if byte == b' ' {
                score += 0.1; // Spaces are common
                count += 1;
            } else if byte.is_ascii_punctuation() {
                score += 0.01;
                count += 1;
            } else if !byte.is_ascii() || byte.is_ascii_control() {
                score -= 0.5; // Penalize non-printable
                count += 1;
            }
        }

        if count > 0 {
            score / count as f64
        } else {
            0.0
        }
    }

    /// Calculate Hamming distance between two byte slices
    fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones() as usize)
            .sum()
    }

    /// Find probable key length using Hamming distance
    fn find_key_length(data: &[u8], max_len: usize) -> Vec<(usize, f64)> {
        let mut scores = Vec::new();

        for key_len in 2..=max_len.min(data.len() / 4) {
            let chunks: Vec<&[u8]> = data.chunks(key_len).take(4).collect();
            if chunks.len() < 4 {
                continue;
            }

            let mut total_distance = 0.0;
            let mut count = 0;

            for i in 0..chunks.len() {
                for j in i + 1..chunks.len() {
                    let len = chunks[i].len().min(chunks[j].len());
                    if len > 0 {
                        let dist = Self::hamming_distance(&chunks[i][..len], &chunks[j][..len]);
                        total_distance += dist as f64 / len as f64;
                        count += 1;
                    }
                }
            }

            if count > 0 {
                let normalized = total_distance / count as f64;
                scores.push((key_len, normalized));
            }
        }

        scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        scores
    }

    /// Crack single-byte XOR
    fn crack_single_byte(data: &[u8]) -> Option<(u8, Vec<u8>, f64)> {
        let mut best_key = 0u8;
        let mut best_score = f64::MIN;
        let mut best_result = Vec::new();

        for key in 0..=255u8 {
            let decrypted: Vec<u8> = data.iter().map(|b| b ^ key).collect();
            let score = Self::score_english(&decrypted);

            if score > best_score {
                best_score = score;
                best_key = key;
                best_result = decrypted;
            }
        }

        if best_score > 0.0 {
            Some((best_key, best_result, best_score))
        } else {
            None
        }
    }
}

impl Default for XorCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl Cipher for XorCipher {
    fn name(&self) -> &'static str {
        "xor"
    }

    fn description(&self) -> &'static str {
        "XOR cipher (single or repeating key)"
    }

    fn encrypt(&self, plaintext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
        let key_bytes = key
            .as_bytes()
            .ok_or_else(|| CipherError::InvalidKey("Expected byte key".into()))?;

        if key_bytes.is_empty() {
            return Err(CipherError::InvalidKey("Key cannot be empty".into()));
        }

        let result: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
            .collect();

        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
        // XOR is self-inverse
        self.encrypt(ciphertext, key)
    }

    fn crack(&self, ciphertext: &[u8]) -> Vec<CrackResult> {
        let mut results = Vec::new();

        // Try single-byte XOR first
        if let Some((key, decrypted, score)) = Self::crack_single_byte(ciphertext) {
            if let Ok(plaintext) = String::from_utf8(decrypted) {
                results.push(CrackResult {
                    plaintext,
                    key: CipherKey::Bytes(vec![key]),
                    confidence: (score * 10.0).min(1.0),
                });
            }
        }

        // Try repeating key XOR with detected key lengths
        if ciphertext.len() >= 16 {
            let key_lengths = Self::find_key_length(ciphertext, 20);

            for (key_len, _) in key_lengths.iter().take(3) {
                // Split into transposed blocks
                let mut transposed: Vec<Vec<u8>> = vec![Vec::new(); *key_len];
                for (i, &byte) in ciphertext.iter().enumerate() {
                    transposed[i % key_len].push(byte);
                }

                // Crack each block as single-byte XOR
                let mut key = Vec::with_capacity(*key_len);
                let mut total_score = 0.0;

                for block in &transposed {
                    if let Some((k, _, score)) = Self::crack_single_byte(block) {
                        key.push(k);
                        total_score += score;
                    } else {
                        key.push(0);
                    }
                }

                if key.len() == *key_len {
                    // Decrypt with recovered key
                    if let Ok(decrypted) = self.decrypt(ciphertext, &CipherKey::Bytes(key.clone()))
                    {
                        if let Ok(plaintext) = String::from_utf8(decrypted) {
                            let confidence = (total_score / *key_len as f64 * 10.0).min(1.0);
                            results.push(CrackResult {
                                plaintext,
                                key: CipherKey::Bytes(key),
                                confidence,
                            });
                        }
                    }
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
    fn test_xor_single_byte() {
        let cipher = XorCipher::new();
        let key = CipherKey::Bytes(vec![0x42]);

        let plaintext = b"Hello World";
        let encrypted = cipher.encrypt(plaintext, &key).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xor_multi_byte() {
        let cipher = XorCipher::new();
        let key = CipherKey::Bytes(b"KEY".to_vec());

        let plaintext = b"Hello World";
        let encrypted = cipher.encrypt(plaintext, &key).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xor_self_inverse() {
        let cipher = XorCipher::new();
        let key = CipherKey::Bytes(vec![0xAB, 0xCD, 0xEF]);
        let data = b"Test data for XOR";

        let encrypted = cipher.encrypt(data, &key).unwrap();
        let double_encrypted = cipher.encrypt(&encrypted, &key).unwrap();

        assert_eq!(double_encrypted, data);
    }

    #[test]
    fn test_xor_crack_single_byte() {
        let cipher = XorCipher::new();
        let key = CipherKey::Bytes(vec![0x42]);
        let plaintext = b"The quick brown fox jumps over the lazy dog";

        let encrypted = cipher.encrypt(plaintext, &key).unwrap();
        let results = cipher.crack(&encrypted);

        // Should find at least one result
        assert!(!results.is_empty());

        // One of the results should be the original plaintext
        let found = results.iter().any(|r| r.plaintext.as_bytes() == plaintext);
        assert!(
            found,
            "Expected to find the original plaintext in crack results"
        );
    }
}
