//! String and Data Obfuscation
//!
//! Techniques to obfuscate strings and data to avoid signature detection:
//! - XOR obfuscation with variable keys
//! - Base64-like encoding
//! - String splitting and reconstruction
//!
//! # Example
//! ```rust
//! use redblue::modules::evasion::obfuscate;
//!
//! let key = 0x42;
//! let original = "secret command";
//! let obfuscated = obfuscate::xor_obfuscate(original, key);
//! let recovered = obfuscate::xor_deobfuscate(&obfuscated, key);
//! assert_eq!(original, recovered);
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

/// XOR obfuscate a string with a single-byte key
pub fn xor_obfuscate(s: &str, key: u8) -> Vec<u8> {
    s.bytes().map(|b| b ^ key).collect()
}

/// XOR deobfuscate data with a single-byte key
pub fn xor_deobfuscate(data: &[u8], key: u8) -> String {
    String::from_utf8_lossy(&data.iter().map(|b| b ^ key).collect::<Vec<u8>>()).to_string()
}

/// XOR obfuscate with a multi-byte key (rolling XOR)
pub fn xor_obfuscate_multi(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// XOR deobfuscate with a multi-byte key (rolling XOR)
pub fn xor_deobfuscate_multi(data: &[u8], key: &[u8]) -> Vec<u8> {
    // XOR is symmetric, so we use the same function
    xor_obfuscate_multi(data, key)
}

/// Generate a pseudo-random key based on a seed
pub fn generate_key(seed: u64, length: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(length);
    let mut state = seed;

    for _ in 0..length {
        // Simple LCG-style PRNG
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        key.push((state >> 24) as u8);
    }

    key
}

/// Obfuscate data with a time-based key (changes each second)
pub fn time_based_obfuscate(data: &[u8]) -> (Vec<u8>, u64) {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let key = generate_key(seed, 16);
    let obfuscated = xor_obfuscate_multi(data, &key);

    (obfuscated, seed)
}

/// Deobfuscate data that was obfuscated with time_based_obfuscate
pub fn time_based_deobfuscate(data: &[u8], seed: u64) -> Vec<u8> {
    let key = generate_key(seed, 16);
    xor_deobfuscate_multi(data, &key)
}

/// Split a string into chunks that are harder to detect
pub fn split_string(s: &str, chunk_size: usize) -> Vec<String> {
    s.chars()
        .collect::<Vec<char>>()
        .chunks(chunk_size)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

/// Reconstruct a string from chunks
pub fn join_chunks(chunks: &[String]) -> String {
    chunks.concat()
}

/// Reverse a string (simple obfuscation)
pub fn reverse_string(s: &str) -> String {
    s.chars().rev().collect()
}

/// ROT13-style encoding (shift by n characters)
pub fn rot_encode(s: &str, shift: u8) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                (((c as u8 - b'a' + shift) % 26) + b'a') as char
            } else if c.is_ascii_uppercase() {
                (((c as u8 - b'A' + shift) % 26) + b'A') as char
            } else {
                c
            }
        })
        .collect()
}

/// ROT decode (shift back)
pub fn rot_decode(s: &str, shift: u8) -> String {
    rot_encode(s, 26 - (shift % 26))
}

/// Simple base64-like encoding (without external crates)
const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        result.push(BASE64_CHARS[b0 >> 2] as char);
        result.push(BASE64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(BASE64_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(BASE64_CHARS[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Base64 decode
pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let chars: Vec<char> = s.chars().filter(|c| *c != '=').collect();

    let decode_char = |c: char| -> Result<u8, String> {
        BASE64_CHARS
            .iter()
            .position(|&b| b == c as u8)
            .map(|p| p as u8)
            .ok_or_else(|| format!("Invalid base64 character: {}", c))
    };

    let mut i = 0;
    while i < chars.len() {
        let v0 = decode_char(chars[i])?;
        let v1 = if i + 1 < chars.len() {
            decode_char(chars[i + 1])?
        } else {
            0
        };
        let v2 = if i + 2 < chars.len() {
            decode_char(chars[i + 2])?
        } else {
            0
        };
        let v3 = if i + 3 < chars.len() {
            decode_char(chars[i + 3])?
        } else {
            0
        };

        result.push((v0 << 2) | (v1 >> 4));
        if i + 2 < chars.len() {
            result.push((v1 << 4) | (v2 >> 2));
        }
        if i + 3 < chars.len() {
            result.push((v2 << 6) | v3);
        }

        i += 4;
    }

    Ok(result)
}

/// Obfuscated string builder for compile-time-like obfuscation
#[derive(Clone)]
pub struct ObfuscatedString {
    data: Vec<u8>,
    key: u8,
}

impl ObfuscatedString {
    /// Create a new obfuscated string
    pub fn new(s: &str) -> Self {
        let key = Self::derive_key(s);
        let data = xor_obfuscate(s, key);
        Self { data, key }
    }

    /// Create with a specific key
    pub fn with_key(s: &str, key: u8) -> Self {
        let data = xor_obfuscate(s, key);
        Self { data, key }
    }

    /// Get the original string
    pub fn get(&self) -> String {
        xor_deobfuscate(&self.data, self.key)
    }

    /// Derive a key from the string content
    fn derive_key(s: &str) -> u8 {
        let mut key: u8 = 0x5A;
        for b in s.bytes() {
            key = key.wrapping_add(b).rotate_left(3);
        }
        if key == 0 {
            key = 0x42;
        }
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_roundtrip() {
        let original = "Hello, World!";
        let key = 0x42;
        let obfuscated = xor_obfuscate(original, key);
        let recovered = xor_deobfuscate(&obfuscated, key);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_xor_multi_roundtrip() {
        let original = b"Secret message";
        let key = b"mykey";
        let obfuscated = xor_obfuscate_multi(original, key);
        let recovered = xor_deobfuscate_multi(&obfuscated, key);
        assert_eq!(original.to_vec(), recovered);
    }

    #[test]
    fn test_time_based_roundtrip() {
        let original = b"Time-based secret";
        let (obfuscated, seed) = time_based_obfuscate(original);
        let recovered = time_based_deobfuscate(&obfuscated, seed);
        assert_eq!(original.to_vec(), recovered);
    }

    #[test]
    fn test_split_join() {
        let original = "Hello World";
        let chunks = split_string(original, 3);
        let recovered = join_chunks(&chunks);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_rot13() {
        let original = "Hello";
        let encoded = rot_encode(original, 13);
        let decoded = rot_decode(&encoded, 13);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Test data";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn test_obfuscated_string() {
        let original = "secret command";
        let obs = ObfuscatedString::new(original);
        assert_eq!(original, obs.get());
    }

    #[test]
    fn test_generate_key() {
        let key1 = generate_key(12345, 16);
        let key2 = generate_key(12345, 16);
        let key3 = generate_key(54321, 16);

        assert_eq!(key1.len(), 16);
        assert_eq!(key1, key2); // Same seed = same key
        assert_ne!(key1, key3); // Different seed = different key
    }
}
