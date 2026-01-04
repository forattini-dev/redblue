//! URL Codec
//!
//! Implements URL percent encoding per RFC 3986.

use super::{Codec, CodecError};

/// URL codec
pub struct UrlCodec {
    /// If true, encode spaces as + instead of %20
    plus_for_space: bool,
}

impl UrlCodec {
    /// Create URL codec (standard percent encoding)
    pub fn new() -> Self {
        Self {
            plus_for_space: false,
        }
    }

    /// Create URL codec with + for spaces (form encoding)
    pub fn form() -> Self {
        Self {
            plus_for_space: true,
        }
    }

    /// Check if character is unreserved per RFC 3986
    fn is_unreserved(c: u8) -> bool {
        matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
    }

    fn decode_hex_pair(high: char, low: char) -> Result<u8, CodecError> {
        let high = match high {
            '0'..='9' => high as u8 - b'0',
            'a'..='f' => high as u8 - b'a' + 10,
            'A'..='F' => high as u8 - b'A' + 10,
            _ => return Err(CodecError::InvalidCharacter(high)),
        };
        let low = match low {
            '0'..='9' => low as u8 - b'0',
            'a'..='f' => low as u8 - b'a' + 10,
            'A'..='F' => low as u8 - b'A' + 10,
            _ => return Err(CodecError::InvalidCharacter(low)),
        };
        Ok((high << 4) | low)
    }
}

impl Default for UrlCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Codec for UrlCodec {
    fn name(&self) -> &'static str {
        "url"
    }

    fn description(&self) -> &'static str {
        "URL percent encoding (RFC 3986)"
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        let mut result = Vec::with_capacity(input.len() * 3);

        for &byte in input {
            if Self::is_unreserved(byte) {
                result.push(byte);
            } else if byte == b' ' && self.plus_for_space {
                result.push(b'+');
            } else {
                result.push(b'%');
                result.push(b"0123456789ABCDEF"[(byte >> 4) as usize]);
                result.push(b"0123456789ABCDEF"[(byte & 0x0F) as usize]);
            }
        }

        Ok(result)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        let s = std::str::from_utf8(input)
            .map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))?;

        let mut result = Vec::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let high = chars.next().ok_or(CodecError::IncompleteSequence)?;
                let low = chars.next().ok_or(CodecError::IncompleteSequence)?;
                result.push(Self::decode_hex_pair(high, low)?);
            } else if c == '+' {
                result.push(b' ');
            } else {
                let mut buf = [0u8; 4];
                let bytes = c.encode_utf8(&mut buf);
                result.extend_from_slice(bytes.as_bytes());
            }
        }

        Ok(result)
    }

    fn detect(&self, input: &[u8]) -> f64 {
        let s = match std::str::from_utf8(input) {
            Ok(s) => s,
            Err(_) => return 0.0,
        };

        if s.is_empty() {
            return 0.0;
        }

        // Count percent-encoded sequences
        let mut percent_count = 0;
        let mut valid_sequences = 0;
        let mut i = 0;
        let chars: Vec<char> = s.chars().collect();

        while i < chars.len() {
            if chars[i] == '%' {
                percent_count += 1;
                if i + 2 < chars.len() {
                    if chars[i + 1].is_ascii_hexdigit() && chars[i + 2].is_ascii_hexdigit() {
                        valid_sequences += 1;
                        i += 3;
                        continue;
                    }
                }
            }
            i += 1;
        }

        if percent_count == 0 {
            // No percent signs - could still be URL-safe string
            let has_plus = s.contains('+');
            if has_plus {
                return 0.3; // Might be form-encoded
            }
            return 0.0;
        }

        // All percent sequences should be valid
        if valid_sequences != percent_count {
            return 0.1;
        }

        // More percent sequences = higher confidence
        let ratio = percent_count as f64 / s.len() as f64;
        let confidence = 0.5 + ratio * 2.0;
        confidence.min(1.0_f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        let codec = UrlCodec::new();
        assert_eq!(codec.encode(b"hello").unwrap(), b"hello");
        assert_eq!(codec.encode(b"hello world").unwrap(), b"hello%20world");
        assert_eq!(codec.encode(b"foo=bar").unwrap(), b"foo%3Dbar");
        assert_eq!(codec.encode(b"a&b").unwrap(), b"a%26b");
        assert_eq!(codec.encode(b"100%").unwrap(), b"100%25");
    }

    #[test]
    fn test_url_encode_form() {
        let codec = UrlCodec::form();
        assert_eq!(codec.encode(b"hello world").unwrap(), b"hello+world");
    }

    #[test]
    fn test_url_decode() {
        let codec = UrlCodec::new();
        assert_eq!(codec.decode(b"hello").unwrap(), b"hello");
        assert_eq!(codec.decode(b"hello%20world").unwrap(), b"hello world");
        assert_eq!(codec.decode(b"hello+world").unwrap(), b"hello world");
        assert_eq!(codec.decode(b"foo%3Dbar").unwrap(), b"foo=bar");
        assert_eq!(codec.decode(b"100%25").unwrap(), b"100%");
    }

    #[test]
    fn test_url_roundtrip() {
        let codec = UrlCodec::new();
        let original = b"Hello World! Special: @#$%^&*()";
        let encoded = codec.encode(original).unwrap();
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_url_unicode() {
        let codec = UrlCodec::new();
        let original = "café".as_bytes();
        let encoded = codec.encode(original).unwrap();
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_url_detect() {
        let codec = UrlCodec::new();
        assert!(codec.detect(b"hello%20world") > 0.5);
        assert!(codec.detect(b"foo%3Dbar%26baz") > 0.5);
        assert!(codec.detect(b"hello") < 0.1);
    }
}
