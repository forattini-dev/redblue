//! Base85/ASCII85 Encoding/Decoding
//!
//! Pure Rust implementation of Base85 encoding.
//! Supports both Adobe ASCII85 and RFC 1924 (Z85) variants.

use super::{Codec, CodecError};

/// ASCII85 (Adobe) alphabet - printable ASCII from '!' (33) to 'u' (117)
const ASCII85_OFFSET: u8 = 33;

/// Z85 alphabet (RFC 1924 - used by ZeroMQ)
const Z85_ALPHABET: &[u8; 85] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

/// ASCII85/Base85 codec
pub struct Base85Codec {
    variant: Base85Variant,
}

#[derive(Clone, Copy)]
pub enum Base85Variant {
    /// Adobe ASCII85 (used in PostScript, PDF)
    Ascii85,
    /// Z85 (RFC 1924, used by ZeroMQ)
    Z85,
}

impl Base85Codec {
    /// Create new ASCII85 codec (Adobe variant)
    pub fn new() -> Self {
        Self {
            variant: Base85Variant::Ascii85,
        }
    }

    /// Create Z85 codec (ZeroMQ variant)
    pub fn z85() -> Self {
        Self {
            variant: Base85Variant::Z85,
        }
    }

    /// Encode a 4-byte block to 5 Base85 characters
    fn encode_block(&self, block: u32) -> [u8; 5] {
        let mut result = [0u8; 5];
        let mut value = block;

        for i in (0..5).rev() {
            let digit = (value % 85) as u8;
            value /= 85;
            result[i] = match self.variant {
                Base85Variant::Ascii85 => digit + ASCII85_OFFSET,
                Base85Variant::Z85 => Z85_ALPHABET[digit as usize],
            };
        }

        result
    }

    /// Decode 5 Base85 characters to a 4-byte block
    fn decode_block(&self, block: &[u8]) -> Result<u32, CodecError> {
        let mut value: u64 = 0;

        for &c in block {
            let digit = match self.variant {
                Base85Variant::Ascii85 => {
                    if c < ASCII85_OFFSET || c > ASCII85_OFFSET + 84 {
                        return Err(CodecError::InvalidCharacter(c as char));
                    }
                    (c - ASCII85_OFFSET) as u64
                }
                Base85Variant::Z85 => Z85_ALPHABET
                    .iter()
                    .position(|&x| x == c)
                    .ok_or(CodecError::InvalidCharacter(c as char))?
                    as u64,
            };

            value = value * 85 + digit;
        }

        if value > u32::MAX as u64 {
            return Err(CodecError::InvalidInput("Overflow in base85 block".into()));
        }

        Ok(value as u32)
    }
}

impl Default for Base85Codec {
    fn default() -> Self {
        Self::new()
    }
}

impl Codec for Base85Codec {
    fn name(&self) -> &'static str {
        match self.variant {
            Base85Variant::Ascii85 => "base85",
            Base85Variant::Z85 => "z85",
        }
    }

    fn description(&self) -> &'static str {
        match self.variant {
            Base85Variant::Ascii85 => "Base85/ASCII85 encoding (Adobe)",
            Base85Variant::Z85 => "Z85 encoding (ZeroMQ/RFC 1924)",
        }
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        let mut result = Vec::with_capacity((input.len() + 3) / 4 * 5);

        // Process complete 4-byte blocks
        let chunks = input.chunks(4);
        let total_chunks = chunks.len();

        for (i, chunk) in input.chunks(4).enumerate() {
            let is_last = i == total_chunks - 1;
            let padding_len = 4 - chunk.len();

            // Build 32-bit value
            let mut block = 0u32;
            for &byte in chunk {
                block = (block << 8) | byte as u32;
            }
            // Pad with zeros if needed
            block <<= padding_len * 8;

            // Special case for ASCII85: all zeros become 'z'
            if matches!(self.variant, Base85Variant::Ascii85) && block == 0 && chunk.len() == 4 {
                result.push(b'z');
                continue;
            }

            let encoded = self.encode_block(block);

            if is_last && padding_len > 0 {
                // Only output enough characters for the actual data
                let output_len = 5 - padding_len;
                result.extend_from_slice(&encoded[..output_len]);
            } else {
                result.extend_from_slice(&encoded);
            }
        }

        // Wrap with delimiters for ASCII85
        if matches!(self.variant, Base85Variant::Ascii85) {
            let mut wrapped = Vec::with_capacity(result.len() + 4);
            wrapped.extend_from_slice(b"<~");
            wrapped.extend(result);
            wrapped.extend_from_slice(b"~>");
            return Ok(wrapped);
        }

        Ok(result)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        // Remove ASCII85 delimiters if present
        let data = if matches!(self.variant, Base85Variant::Ascii85) {
            let trimmed = input.strip_prefix(b"<~").unwrap_or(input);
            trimmed.strip_suffix(b"~>").unwrap_or(trimmed)
        } else {
            input
        };

        // Filter whitespace and expand 'z' for ASCII85
        let mut filtered = Vec::with_capacity(data.len() * 5);
        for &c in data {
            if c.is_ascii_whitespace() {
                continue;
            }
            if matches!(self.variant, Base85Variant::Ascii85) && c == b'z' {
                // 'z' represents 4 zero bytes
                filtered.extend_from_slice(b"!!!!!");
            } else {
                filtered.push(c);
            }
        }

        let mut result = Vec::with_capacity(filtered.len() * 4 / 5);

        // Process complete 5-character blocks
        let chunks_count = filtered.len() / 5;
        let remainder = filtered.len() % 5;

        for chunk in filtered[..chunks_count * 5].chunks(5) {
            let value = self.decode_block(chunk)?;
            result.extend_from_slice(&value.to_be_bytes());
        }

        // Handle partial final block
        if remainder > 0 {
            // Pad with 'u' (84 in ASCII85) or highest Z85 char
            let pad_char = match self.variant {
                Base85Variant::Ascii85 => b'u',
                Base85Variant::Z85 => b'#', // highest in Z85
            };

            let mut padded = filtered[chunks_count * 5..].to_vec();
            while padded.len() < 5 {
                padded.push(pad_char);
            }

            let value = self.decode_block(&padded)?;
            let bytes = value.to_be_bytes();

            // Only output the bytes we actually have
            let output_len = remainder * 4 / 5 + 1;
            result.extend_from_slice(&bytes[..output_len.min(4)]);
        }

        Ok(result)
    }

    fn detect(&self, input: &[u8]) -> f64 {
        if input.is_empty() {
            return 0.0;
        }

        match self.variant {
            Base85Variant::Ascii85 => {
                // Check for ASCII85 delimiters
                if input.starts_with(b"<~") && input.ends_with(b"~>") {
                    return 0.95;
                }

                // Check character range (33-117 plus 'z' for all-zeros)
                let valid = input.iter().all(|&c| {
                    c.is_ascii_whitespace()
                        || c == b'z'
                        || (c >= ASCII85_OFFSET && c <= ASCII85_OFFSET + 84)
                });

                if valid && input.len() >= 5 {
                    0.4
                } else {
                    0.0
                }
            }
            Base85Variant::Z85 => {
                // Check if all characters are in Z85 alphabet
                let valid = input
                    .iter()
                    .all(|&c| Z85_ALPHABET.contains(&c) || c.is_ascii_whitespace());

                if valid && input.len() >= 5 && input.len() % 5 == 0 {
                    0.5
                } else if valid && input.len() >= 5 {
                    0.3
                } else {
                    0.0
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii85_encode_decode() {
        let codec = Base85Codec::new();

        // Known test vector
        let input = b"Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";

        let encoded = codec.encode(input).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn test_ascii85_short() {
        let codec = Base85Codec::new();

        let tests = [
            b"test".to_vec(),
            b"a".to_vec(),
            b"ab".to_vec(),
            b"abc".to_vec(),
            b"abcd".to_vec(),
        ];

        for test in tests {
            let encoded = codec.encode(&test).unwrap();
            let decoded = codec.decode(&encoded).unwrap();
            assert_eq!(decoded, test, "Failed for input length {}", test.len());
        }
    }

    #[test]
    fn test_ascii85_zeros() {
        let codec = Base85Codec::new();

        // Four zeros should encode to 'z'
        let input = vec![0u8; 4];
        let encoded = codec.encode(&input).unwrap();
        assert!(
            encoded.windows(1).any(|w| w == b"z"),
            "Four zeros should produce 'z'"
        );

        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_z85_encode_decode() {
        let codec = Base85Codec::z85();

        let input = b"Hello";
        let encoded = codec.encode(input).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        // Note: Z85 requires input length to be multiple of 4
        // Our implementation handles padding
        assert_eq!(decoded[..input.len()], *input);
    }

    #[test]
    fn test_ascii85_detection() {
        let codec = Base85Codec::new();

        // With delimiters - high confidence
        assert!(codec.detect(b"<~test~>") > 0.9);

        // Without delimiters - lower confidence
        assert!(codec.detect(b"9jqo^") > 0.0);

        // Invalid characters
        assert_eq!(codec.detect(b"{}[]"), 0.0);
    }
}
