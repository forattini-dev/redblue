//! Base64 Encoding/Decoding
//!
//! Implements Base64 (RFC 4648) and Base64URL encoding from scratch.

/// Standard Base64 alphabet
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64URL alphabet (URL-safe)
const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes to Base64
pub fn base64_encode(data: &[u8]) -> String {
    encode_with_alphabet(data, BASE64_ALPHABET, true)
}

/// Encode bytes to Base64 without padding
pub fn base64_encode_no_padding(data: &[u8]) -> String {
    encode_with_alphabet(data, BASE64_ALPHABET, false)
}

/// Encode bytes to Base64URL (URL-safe)
pub fn base64url_encode(data: &[u8]) -> String {
    encode_with_alphabet(data, BASE64URL_ALPHABET, false)
}

/// Decode Base64 to bytes
pub fn base64_decode(s: &str) -> Result<Vec<u8>, Base64Error> {
    decode_with_alphabet(s, false)
}

/// Decode Base64URL to bytes
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, Base64Error> {
    decode_with_alphabet(s, true)
}

/// Base64 decode error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base64Error {
    InvalidCharacter(char),
    InvalidLength,
    InvalidPadding,
}

impl std::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCharacter(c) => write!(f, "Invalid Base64 character: '{}'", c),
            Self::InvalidLength => write!(f, "Invalid Base64 length"),
            Self::InvalidPadding => write!(f, "Invalid Base64 padding"),
        }
    }
}

impl std::error::Error for Base64Error {}

/// Encode with specified alphabet
fn encode_with_alphabet(data: &[u8], alphabet: &[u8; 64], with_padding: bool) -> String {
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;

        let combined = (b0 << 16) | (b1 << 8) | b2;

        result.push(alphabet[((combined >> 18) & 0x3F) as usize] as char);
        result.push(alphabet[((combined >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(alphabet[((combined >> 6) & 0x3F) as usize] as char);
        } else if with_padding {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(alphabet[(combined & 0x3F) as usize] as char);
        } else if with_padding {
            result.push('=');
        }
    }

    result
}

/// Decode with auto-detection of standard vs URL alphabet
fn decode_with_alphabet(s: &str, url_safe: bool) -> Result<Vec<u8>, Base64Error> {
    // Remove whitespace and padding
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = s.trim_end_matches('=');

    if s.is_empty() {
        return Ok(Vec::new());
    }

    let mut result = Vec::with_capacity(s.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits_collected = 0;

    for c in s.chars() {
        let value = decode_char(c, url_safe)?;
        buffer = (buffer << 6) | value as u32;
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            result.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }

    Ok(result)
}

/// Decode single Base64 character
fn decode_char(c: char, url_safe: bool) -> Result<u8, Base64Error> {
    match c {
        'A'..='Z' => Ok(c as u8 - b'A'),
        'a'..='z' => Ok(c as u8 - b'a' + 26),
        '0'..='9' => Ok(c as u8 - b'0' + 52),
        '+' if !url_safe => Ok(62),
        '-' if url_safe => Ok(62),
        '/' if !url_safe => Ok(63),
        '_' if url_safe => Ok(63),
        _ => Err(Base64Error::InvalidCharacter(c)),
    }
}

/// Encode bytes to Base64 with line wrapping (64 chars per line)
pub fn base64_encode_wrapped(data: &[u8], line_length: usize) -> String {
    let encoded = base64_encode(data);
    let mut result = String::with_capacity(encoded.len() + encoded.len() / line_length);

    for (i, c) in encoded.chars().enumerate() {
        if i > 0 && i % line_length == 0 {
            result.push('\n');
        }
        result.push(c);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_base64_decode_no_padding() {
        assert_eq!(base64_decode("Zg").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8").unwrap(), b"fo");
    }

    #[test]
    fn test_base64url() {
        // Test data that produces + and / in standard Base64
        let data = vec![0xfb, 0xff, 0xfe];
        let standard = base64_encode(&data);
        let url_safe = base64url_encode(&data);

        assert!(standard.contains('+') || standard.contains('/'));
        assert!(!url_safe.contains('+'));
        assert!(!url_safe.contains('/'));

        // Verify roundtrip
        assert_eq!(base64url_decode(&url_safe).unwrap(), data);
    }

    #[test]
    fn test_base64_wrapped() {
        let data = vec![0u8; 100];
        let wrapped = base64_encode_wrapped(&data, 64);
        for line in wrapped.lines() {
            assert!(line.len() <= 64);
        }
    }

    #[test]
    fn test_invalid_character() {
        let result = base64_decode("abc!");
        assert!(matches!(result, Err(Base64Error::InvalidCharacter('!'))));
    }
}
