//! Codec Module - Encoding/Decoding Registry
//!
//! Provides a unified interface for encoding and decoding operations.
//! All codecs implement the `Codec` trait for consistent handling.

mod base32;
mod base58;
mod base64;
mod base85;
mod hex;
mod html;
mod morse;
mod tap;
mod unicode;
mod url;

use std::collections::HashMap;

pub use base32::Base32Codec;
pub use base58::Base58Codec;
pub use base64::Base64Codec;
pub use base85::Base85Codec;
pub use hex::HexCodec;
pub use html::HtmlCodec;
pub use morse::MorseCodec;
pub use tap::TapCodec;
pub use unicode::UnicodeCodec;
pub use url::UrlCodec;

/// Error types for codec operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Invalid input for this codec
    InvalidInput(String),
    /// Invalid character encountered
    InvalidCharacter(char),
    /// Invalid padding
    InvalidPadding,
    /// Invalid length for this encoding
    InvalidLength,
    /// Incomplete sequence
    IncompleteSequence,
    /// Unknown codec name
    UnknownCodec(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::InvalidCharacter(c) => write!(f, "Invalid character: '{}'", c),
            Self::InvalidPadding => write!(f, "Invalid padding"),
            Self::InvalidLength => write!(f, "Invalid length"),
            Self::IncompleteSequence => write!(f, "Incomplete sequence"),
            Self::UnknownCodec(name) => write!(f, "Unknown codec: {}", name),
        }
    }
}

impl std::error::Error for CodecError {}

/// Common interface for all encoding/decoding operations
pub trait Codec: Send + Sync {
    /// Unique identifier for this codec
    fn name(&self) -> &'static str;

    /// Human-readable description
    fn description(&self) -> &'static str;

    /// Encode raw bytes to encoded format
    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError>;

    /// Decode encoded format back to raw bytes
    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, CodecError>;

    /// Check if input looks like valid encoded data for this codec
    /// Returns confidence score between 0.0 and 1.0
    fn detect(&self, input: &[u8]) -> f64;

    /// Encode and return as string (convenience method)
    fn encode_to_string(&self, input: &[u8]) -> Result<String, CodecError> {
        let encoded = self.encode(input)?;
        String::from_utf8(encoded).map_err(|_| CodecError::InvalidInput("Not valid UTF-8".into()))
    }

    /// Decode from string (convenience method)
    fn decode_from_string(&self, input: &str) -> Result<Vec<u8>, CodecError> {
        self.decode(input.as_bytes())
    }
}

/// Detection result from registry
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub codec_name: String,
    pub confidence: f64,
}

/// Registry for managing codec instances
pub struct CodecRegistry {
    codecs: HashMap<&'static str, Box<dyn Codec>>,
}

impl Default for CodecRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CodecRegistry {
    /// Create a new registry with all built-in codecs
    pub fn new() -> Self {
        let mut registry = Self {
            codecs: HashMap::new(),
        };

        // Register all built-in codecs
        registry.register(Box::new(Base64Codec::new()));
        registry.register(Box::new(Base64Codec::url_safe()));
        registry.register(Box::new(Base32Codec::new()));
        registry.register(Box::new(Base32Codec::hex()));
        registry.register(Box::new(Base58Codec::new()));
        registry.register(Box::new(Base58Codec::with_checksum()));
        registry.register(Box::new(Base85Codec::new()));
        registry.register(Box::new(Base85Codec::z85()));
        registry.register(Box::new(HexCodec::new()));
        registry.register(Box::new(UrlCodec::new()));
        registry.register(Box::new(HtmlCodec::new()));
        registry.register(Box::new(UnicodeCodec::new()));
        registry.register(Box::new(MorseCodec::new()));
        registry.register(Box::new(TapCodec::new()));

        registry
    }

    /// Register a codec
    pub fn register(&mut self, codec: Box<dyn Codec>) {
        self.codecs.insert(codec.name(), codec);
    }

    /// Get a codec by name
    pub fn get(&self, name: &str) -> Option<&dyn Codec> {
        self.codecs.get(name).map(|c| c.as_ref())
    }

    /// List all registered codec names
    pub fn list(&self) -> Vec<&'static str> {
        let mut names: Vec<_> = self.codecs.keys().copied().collect();
        names.sort();
        names
    }

    /// Detect all possible encodings for input, sorted by confidence
    pub fn detect_all(&self, input: &[u8]) -> Vec<DetectionResult> {
        let mut results: Vec<_> = self
            .codecs
            .iter()
            .map(|(name, codec)| DetectionResult {
                codec_name: name.to_string(),
                confidence: codec.detect(input),
            })
            .filter(|r| r.confidence > 0.0)
            .collect();

        // Sort by confidence descending
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        results
    }

    /// Try to decode with the most likely codec
    pub fn auto_decode(&self, input: &[u8]) -> Option<(String, Vec<u8>)> {
        let detections = self.detect_all(input);
        for detection in detections {
            if let Some(codec) = self.get(&detection.codec_name) {
                if let Ok(decoded) = codec.decode(input) {
                    return Some((detection.codec_name, decoded));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = CodecRegistry::new();
        assert!(registry.get("base64").is_some());
        assert!(registry.get("hex").is_some());
        assert!(registry.get("morse").is_some());
        assert!(registry.get("tap").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_registry_list() {
        let registry = CodecRegistry::new();
        let names = registry.list();
        assert!(names.contains(&"base64"));
        assert!(names.contains(&"hex"));
    }

    #[test]
    fn test_detect_all() {
        let registry = CodecRegistry::new();

        // Base64 encoded "Hello"
        let input = b"SGVsbG8=";
        let results = registry.detect_all(input);

        // Base64 should be detected with high confidence
        assert!(!results.is_empty());
        let base64_result = results.iter().find(|r| r.codec_name == "base64");
        assert!(base64_result.is_some());
        assert!(base64_result.unwrap().confidence > 0.5);
    }

    #[test]
    fn test_auto_decode() {
        let registry = CodecRegistry::new();

        // Base64 encoded "Hello"
        let input = b"SGVsbG8=";
        let result = registry.auto_decode(input);

        assert!(result.is_some());
        let (codec_name, decoded) = result.unwrap();
        // Should be detected as base64 or base64url (both decode the same)
        assert!(codec_name == "base64" || codec_name == "base64url");
        assert_eq!(decoded, b"Hello");
    }
}
