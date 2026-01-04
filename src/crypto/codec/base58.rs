//! Base58 Encoding/Decoding
//!
//! Pure Rust implementation of Base58 encoding using Bitcoin alphabet.
//! Used for Bitcoin addresses, IPFS hashes, and other cryptocurrency systems.

use super::{Codec, CodecError};

/// Bitcoin's Base58 alphabet (no 0, O, I, l to avoid confusion)
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Reverse lookup table for decoding
fn base58_decode_table() -> [i8; 128] {
    let mut table = [-1i8; 128];
    for (i, &c) in BASE58_ALPHABET.iter().enumerate() {
        table[c as usize] = i as i8;
    }
    table
}

/// Base58 codec (Bitcoin alphabet)
pub struct Base58Codec {
    /// Whether to include checksum (Base58Check)
    with_checksum: bool,
}

impl Base58Codec {
    /// Create new Base58 codec
    pub fn new() -> Self {
        Self {
            with_checksum: false,
        }
    }

    /// Create Base58Check codec (with checksum)
    pub fn with_checksum() -> Self {
        Self {
            with_checksum: true,
        }
    }

    /// Encode bytes to Base58
    fn encode_base58(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }

        // Count leading zeros (they become '1' characters)
        let leading_zeros = input.iter().take_while(|&&b| b == 0).count();

        // Convert to base58
        // We need to work with arbitrary precision arithmetic
        // Use a simple approach: repeatedly divide by 58
        let mut bytes = input.to_vec();
        let mut result = Vec::with_capacity(input.len() * 137 / 100 + 1);

        while !bytes.is_empty() && !bytes.iter().all(|&b| b == 0) {
            let mut remainder = 0u32;
            let mut new_bytes = Vec::with_capacity(bytes.len());

            for &byte in &bytes {
                let value = (remainder << 8) | byte as u32;
                let digit = value / 58;
                remainder = value % 58;

                if !new_bytes.is_empty() || digit > 0 {
                    new_bytes.push(digit as u8);
                }
            }

            result.push(BASE58_ALPHABET[remainder as usize]);
            bytes = new_bytes;
        }

        // Add leading '1's for leading zeros
        for _ in 0..leading_zeros {
            result.push(b'1');
        }

        // Reverse the result
        result.reverse();
        result
    }

    /// Decode Base58 to bytes
    fn decode_base58(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        let decode_table = base58_decode_table();

        // Count leading '1's (they become leading zeros)
        let leading_ones = input.iter().take_while(|&&c| c == b'1').count();

        // Convert from base58
        let mut bytes = Vec::new();

        for &c in &input[leading_ones..] {
            if c >= 128 {
                return Err(CodecError::InvalidCharacter(c as char));
            }

            let value = decode_table[c as usize];
            if value < 0 {
                return Err(CodecError::InvalidCharacter(c as char));
            }

            // Multiply existing number by 58 and add new digit
            let mut carry = value as u32;
            for byte in bytes.iter_mut().rev() {
                let v = (*byte as u32) * 58 + carry;
                *byte = (v & 0xFF) as u8;
                carry = v >> 8;
            }

            while carry > 0 {
                bytes.insert(0, (carry & 0xFF) as u8);
                carry >>= 8;
            }
        }

        // Add leading zeros
        let mut result = vec![0u8; leading_ones];
        result.extend(bytes);

        Ok(result)
    }
}

impl Default for Base58Codec {
    fn default() -> Self {
        Self::new()
    }
}

impl Codec for Base58Codec {
    fn name(&self) -> &'static str {
        if self.with_checksum {
            "base58check"
        } else {
            "base58"
        }
    }

    fn description(&self) -> &'static str {
        if self.with_checksum {
            "Base58Check encoding (Bitcoin addresses)"
        } else {
            "Base58 encoding (Bitcoin alphabet)"
        }
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        if self.with_checksum {
            // Base58Check: append 4-byte checksum (double SHA-256)
            let checksum = double_sha256_checksum(input);
            let mut with_checksum = input.to_vec();
            with_checksum.extend_from_slice(&checksum[..4]);
            Ok(self.encode_base58(&with_checksum))
        } else {
            Ok(self.encode_base58(input))
        }
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        let decoded = self.decode_base58(input)?;

        if self.with_checksum {
            // Verify checksum
            if decoded.len() < 4 {
                return Err(CodecError::InvalidInput("Too short for Base58Check".into()));
            }

            let payload = &decoded[..decoded.len() - 4];
            let checksum = &decoded[decoded.len() - 4..];
            let expected_checksum = double_sha256_checksum(payload);

            if checksum != &expected_checksum[..4] {
                return Err(CodecError::InvalidInput(
                    "Base58Check checksum mismatch".into(),
                ));
            }

            Ok(payload.to_vec())
        } else {
            Ok(decoded)
        }
    }

    fn detect(&self, input: &[u8]) -> f64 {
        if input.is_empty() {
            return 0.0;
        }

        // Check if all characters are valid Base58
        let decode_table = base58_decode_table();
        let valid_chars = input
            .iter()
            .all(|&c| c < 128 && (c == b'1' || decode_table[c as usize] >= 0));

        if !valid_chars {
            return 0.0;
        }

        // Base58 strings often start with specific prefixes
        // and don't contain 0, O, I, l
        let has_invalid = input
            .iter()
            .any(|&c| c == b'0' || c == b'O' || c == b'I' || c == b'l');
        if has_invalid {
            return 0.0;
        }

        // Higher confidence for typical Base58 lengths (Bitcoin addresses are 25-34 chars)
        let len = input.len();
        if (25..=34).contains(&len) {
            0.8
        } else if len >= 10 {
            0.5
        } else {
            0.3
        }
    }
}

/// Double SHA-256 for checksum (used in Bitcoin)
fn double_sha256_checksum(data: &[u8]) -> [u8; 32] {
    use crate::crypto::sha256::sha256;
    let first_hash = sha256(data);
    sha256(&first_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base58_encode_decode() {
        let codec = Base58Codec::new();

        // Test vectors
        let tests = [
            (b"".to_vec(), b"".to_vec()),
            (vec![0], b"1".to_vec()),
            (vec![0, 0], b"11".to_vec()),
            (b"Hello World".to_vec(), b"JxF12TrwUP45BMd".to_vec()),
        ];

        for (input, expected) in tests {
            let encoded = codec.encode(&input).unwrap();
            assert_eq!(encoded, expected, "Encode failed for {:?}", input);

            let decoded = codec.decode(&encoded).unwrap();
            assert_eq!(decoded, input, "Decode failed for {:?}", expected);
        }
    }

    #[test]
    fn test_base58_roundtrip() {
        let codec = Base58Codec::new();

        let test_data = [
            b"test".to_vec(),
            b"The quick brown fox".to_vec(),
            vec![0, 1, 2, 3, 4, 5],
            vec![0, 0, 0, 1, 2, 3],
            vec![255, 254, 253],
        ];

        for data in test_data {
            let encoded = codec.encode(&data).unwrap();
            let decoded = codec.decode(&encoded).unwrap();
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn test_base58_invalid_chars() {
        let codec = Base58Codec::new();

        // These characters are not in Base58 alphabet
        assert!(codec.decode(b"invalid0").is_err()); // '0' not in alphabet
        assert!(codec.decode(b"invalidO").is_err()); // 'O' not in alphabet
        assert!(codec.decode(b"invalidI").is_err()); // 'I' not in alphabet
        assert!(codec.decode(b"invalidl").is_err()); // 'l' not in alphabet
    }

    #[test]
    fn test_base58check() {
        let codec = Base58Codec::with_checksum();

        let data = b"Hello";
        let encoded = codec.encode(data).unwrap();
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
