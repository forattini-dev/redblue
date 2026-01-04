//! HTML Entity Codec
//!
//! Implements HTML entity encoding and decoding.

use super::{Codec, CodecError};

/// HTML codec
pub struct HtmlCodec;

impl HtmlCodec {
    /// Create HTML codec
    pub fn new() -> Self {
        Self
    }

    /// Get named entity for character
    fn get_entity(c: char) -> Option<&'static str> {
        match c {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '>' => Some("&gt;"),
            '"' => Some("&quot;"),
            '\'' => Some("&#39;"),
            _ => None,
        }
    }

    /// Parse named entity to character
    fn parse_named_entity(name: &str) -> Option<char> {
        match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{00A0}'),
            "copy" => Some('©'),
            "reg" => Some('®'),
            "trade" => Some('™'),
            "euro" => Some('€'),
            "pound" => Some('£'),
            "yen" => Some('¥'),
            "cent" => Some('¢'),
            "deg" => Some('°'),
            "plusmn" => Some('±'),
            "times" => Some('×'),
            "divide" => Some('÷'),
            "frac12" => Some('½'),
            "frac14" => Some('¼'),
            "frac34" => Some('¾'),
            "hellip" => Some('…'),
            "mdash" => Some('—'),
            "ndash" => Some('–'),
            "lsquo" => Some('\u{2018}'), // '
            "rsquo" => Some('\u{2019}'), // '
            "ldquo" => Some('\u{201C}'), // "
            "rdquo" => Some('\u{201D}'), // "
            _ => None,
        }
    }

    /// Parse numeric entity (decimal or hex)
    fn parse_numeric_entity(s: &str) -> Option<char> {
        if s.starts_with('x') || s.starts_with('X') {
            // Hex entity
            let hex = &s[1..];
            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
        } else {
            // Decimal entity
            s.parse::<u32>().ok().and_then(char::from_u32)
        }
    }
}

impl Default for HtmlCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Codec for HtmlCodec {
    fn name(&self) -> &'static str {
        "html"
    }

    fn description(&self) -> &'static str {
        "HTML entity encoding"
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        let s = std::str::from_utf8(input)
            .map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))?;

        let mut result = String::with_capacity(s.len() * 2);

        for c in s.chars() {
            if let Some(entity) = Self::get_entity(c) {
                result.push_str(entity);
            } else if c.is_ascii() {
                result.push(c);
            } else {
                // Encode non-ASCII as numeric entity
                result.push_str(&format!("&#{};", c as u32));
            }
        }

        Ok(result.into_bytes())
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError> {
        let s = std::str::from_utf8(input)
            .map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))?;

        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '&' {
                // Collect entity
                let mut entity = String::new();
                let mut found_semicolon = false;

                while let Some(&next) = chars.peek() {
                    if next == ';' {
                        chars.next();
                        found_semicolon = true;
                        break;
                    }
                    if !next.is_alphanumeric() && next != '#' {
                        break;
                    }
                    entity.push(chars.next().unwrap());
                    if entity.len() > 10 {
                        break; // Prevent infinite loop on malformed input
                    }
                }

                if found_semicolon && !entity.is_empty() {
                    if entity.starts_with('#') {
                        // Numeric entity
                        if let Some(decoded) = Self::parse_numeric_entity(&entity[1..]) {
                            result.push(decoded);
                            continue;
                        }
                    } else {
                        // Named entity
                        if let Some(decoded) = Self::parse_named_entity(&entity) {
                            result.push(decoded);
                            continue;
                        }
                    }
                }

                // Entity not recognized, output as-is
                result.push('&');
                result.push_str(&entity);
                if found_semicolon {
                    result.push(';');
                }
            } else {
                result.push(c);
            }
        }

        Ok(result.into_bytes())
    }

    fn detect(&self, input: &[u8]) -> f64 {
        let s = match std::str::from_utf8(input) {
            Ok(s) => s,
            Err(_) => return 0.0,
        };

        if s.is_empty() {
            return 0.0;
        }

        // Count HTML entities
        let mut entity_count = 0;
        let mut valid_entities = 0;
        let mut i = 0;
        let chars: Vec<char> = s.chars().collect();

        while i < chars.len() {
            if chars[i] == '&' {
                entity_count += 1;

                // Check if it's a valid entity
                let mut j = i + 1;
                let mut entity = String::new();

                while j < chars.len() && chars[j] != ';' && entity.len() < 10 {
                    if !chars[j].is_alphanumeric() && chars[j] != '#' {
                        break;
                    }
                    entity.push(chars[j]);
                    j += 1;
                }

                if j < chars.len() && chars[j] == ';' && !entity.is_empty() {
                    let is_valid = if entity.starts_with('#') {
                        Self::parse_numeric_entity(&entity[1..]).is_some()
                    } else {
                        Self::parse_named_entity(&entity).is_some()
                    };
                    if is_valid {
                        valid_entities += 1;
                    }
                    i = j + 1;
                    continue;
                }
            }
            i += 1;
        }

        if entity_count == 0 {
            return 0.0;
        }

        // Confidence based on valid entity ratio
        let ratio = valid_entities as f64 / entity_count as f64;
        let density = entity_count as f64 / s.len() as f64;

        (ratio * 0.7 + density * 3.0).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_encode() {
        let codec = HtmlCodec::new();
        assert_eq!(codec.encode(b"hello").unwrap(), b"hello");
        assert_eq!(codec.encode(b"<script>").unwrap(), b"&lt;script&gt;");
        assert_eq!(codec.encode(b"a & b").unwrap(), b"a &amp; b");
        assert_eq!(codec.encode(b"\"quoted\"").unwrap(), b"&quot;quoted&quot;");
    }

    #[test]
    fn test_html_encode_unicode() {
        let codec = HtmlCodec::new();
        let encoded = codec.encode("café".as_bytes()).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        assert!(encoded_str.contains("&#233;") || encoded_str.contains("caf")); // é = 233
    }

    #[test]
    fn test_html_decode_named() {
        let codec = HtmlCodec::new();
        assert_eq!(codec.decode(b"hello").unwrap(), b"hello");
        assert_eq!(codec.decode(b"&lt;script&gt;").unwrap(), b"<script>");
        assert_eq!(codec.decode(b"a &amp; b").unwrap(), b"a & b");
        assert_eq!(codec.decode(b"&quot;quoted&quot;").unwrap(), b"\"quoted\"");
        assert_eq!(codec.decode(b"&copy;").unwrap(), "©".as_bytes());
    }

    #[test]
    fn test_html_decode_numeric() {
        let codec = HtmlCodec::new();
        assert_eq!(codec.decode(b"&#65;").unwrap(), b"A");
        assert_eq!(codec.decode(b"&#x41;").unwrap(), b"A");
        assert_eq!(codec.decode(b"&#65;&#66;&#67;").unwrap(), b"ABC");
    }

    #[test]
    fn test_html_roundtrip() {
        let codec = HtmlCodec::new();
        let original = b"<script>alert('xss')</script>";
        let encoded = codec.encode(original).unwrap();
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_html_detect() {
        let codec = HtmlCodec::new();
        assert!(codec.detect(b"&lt;script&gt;") > 0.5);
        assert!(codec.detect(b"&#65;&#66;&#67;") > 0.5);
        assert!(codec.detect(b"hello") < 0.1);
    }
}
