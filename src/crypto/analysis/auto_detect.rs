//! Auto-Detection
//!
//! Automatically detect encoding and cipher types.

use crate::crypto::cipher::CipherRegistry;
use crate::crypto::codec::CodecRegistry;

/// Detection result
#[derive(Debug, Clone)]
pub struct Detection {
  /// Detected type name
  pub name: String,
  /// Category (encoding, cipher, hash)
  pub category: String,
  /// Confidence score (0.0 - 1.0)
  pub confidence: f64,
  /// Suggested decoding/decryption
  pub decoded: Option<String>,
}

/// Auto-detector for encodings and ciphers
pub struct AutoDetector {
  codec_registry: CodecRegistry,
  cipher_registry: CipherRegistry,
}

impl Default for AutoDetector {
  fn default() -> Self {
    Self::new()
  }
}

impl AutoDetector {
  /// Create new auto-detector
  pub fn new() -> Self {
    Self {
      codec_registry: CodecRegistry::new(),
      cipher_registry: CipherRegistry::new(),
    }
  }

  /// Detect all possible encodings/ciphers
  pub fn detect(&self, input: &[u8]) -> Vec<Detection> {
    let mut results = Vec::new();

    // Try all codecs
    for name in self.codec_registry.list() {
      if let Some(codec) = self.codec_registry.get(name) {
        let confidence = codec.detect(input);
        if confidence > 0.1 {
          let decoded = codec
            .decode(input)
            .ok()
            .and_then(|d| String::from_utf8(d).ok());

          results.push(Detection {
            name: name.to_string(),
            category: "encoding".to_string(),
            confidence,
            decoded,
          });
        }
      }
    }

    // Try all cipher cracks
    let crack_results = self.cipher_registry.crack_all(input);
    for (cipher_name, crack_result) in crack_results.iter().take(5) {
      if crack_result.confidence > 0.3 {
        results.push(Detection {
          name: cipher_name.clone(),
          category: "cipher".to_string(),
          confidence: crack_result.confidence,
          decoded: Some(crack_result.plaintext.clone()),
        });
      }
    }

    // Sort by confidence
    results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    results
  }

  /// Detect and decode recursively (like Ciphey)
  pub fn magic(&self, input: &[u8], max_depth: usize) -> Vec<Vec<Detection>> {
    let mut paths = Vec::new();
    self.magic_recursive(input, max_depth, Vec::new(), &mut paths);

    // Sort paths by total confidence
    paths.sort_by(|a, b| {
      let conf_a: f64 = a.iter().map(|d| d.confidence).product();
      let conf_b: f64 = b.iter().map(|d| d.confidence).product();
      conf_b.partial_cmp(&conf_a).unwrap()
    });

    paths
  }

  fn magic_recursive(
    &self,
    input: &[u8],
    depth: usize,
    path: Vec<Detection>,
    results: &mut Vec<Vec<Detection>>,
  ) {
    if depth == 0 {
      if !path.is_empty() {
        results.push(path);
      }
      return;
    }

    let detections = self.detect(input);

    // If nothing detected with high confidence, save current path
    if detections.is_empty() || detections[0].confidence < 0.5 {
      if !path.is_empty() {
        results.push(path);
      }
      return;
    }

    // Try top detections
    for detection in detections.iter().take(3) {
      if let Some(decoded) = &detection.decoded {
        let mut new_path = path.clone();
        new_path.push(detection.clone());

        // Check if decoded looks like plaintext
        if Self::is_likely_plaintext(decoded) {
          results.push(new_path);
        } else {
          // Recurse
          self.magic_recursive(decoded.as_bytes(), depth - 1, new_path, results);
        }
      }
    }
  }

  /// Check if text is likely plaintext
  fn is_likely_plaintext(text: &str) -> bool {
    if text.is_empty() {
      return false;
    }

    let printable_ratio = text
      .chars()
      .filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace())
      .count() as f64
      / text.len() as f64;

    let space_ratio = text.chars().filter(|c| *c == ' ').count() as f64 / text.len() as f64;

    // Plaintext should be mostly printable with some spaces
    printable_ratio > 0.95 && space_ratio > 0.05 && space_ratio < 0.3
  }

  /// Quick check for common patterns
  pub fn quick_detect(&self, input: &str) -> Option<Detection> {
    let input = input.trim();

    // Base64
    if input.len() % 4 == 0
      && input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
      if let Some(codec) = self.codec_registry.get("base64") {
        if let Ok(decoded) = codec.decode(input.as_bytes()) {
          if let Ok(text) = String::from_utf8(decoded.clone()) {
            return Some(Detection {
              name: "base64".to_string(),
              category: "encoding".to_string(),
              confidence: 0.9,
              decoded: Some(text),
            });
          }
        }
      }
    }

    // Hex
    if input.len() % 2 == 0 && input.chars().all(|c| c.is_ascii_hexdigit()) {
      if let Some(codec) = self.codec_registry.get("hex") {
        if let Ok(decoded) = codec.decode(input.as_bytes()) {
          if let Ok(text) = String::from_utf8(decoded.clone()) {
            if text
              .chars()
              .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            {
              return Some(Detection {
                name: "hex".to_string(),
                category: "encoding".to_string(),
                confidence: 0.8,
                decoded: Some(text),
              });
            }
          }
        }
      }
    }

    // ROT13 (all letters)
    if input
      .chars()
      .all(|c| c.is_ascii_alphabetic() || c.is_ascii_whitespace())
    {
      if let Some(cipher) = self.cipher_registry.get("rot13") {
        let results = cipher.crack(input.as_bytes());
        if let Some(result) = results.first() {
          return Some(Detection {
            name: "rot13".to_string(),
            category: "cipher".to_string(),
            confidence: 0.5, // Lower since we can't verify without language model
            decoded: Some(result.plaintext.clone()),
          });
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
  fn test_detect_base64() {
    let detector = AutoDetector::new();
    let encoded = "SGVsbG8gV29ybGQ="; // "Hello World" in base64

    let results = detector.detect(encoded.as_bytes());
    assert!(!results.is_empty());

    let base64_result = results.iter().find(|r| r.name == "base64");
    assert!(base64_result.is_some());
    assert_eq!(
      base64_result.unwrap().decoded.as_deref(),
      Some("Hello World")
    );
  }

  #[test]
  fn test_quick_detect_hex() {
    let detector = AutoDetector::new();
    let encoded = "48656c6c6f"; // "Hello" in hex

    let result = detector.quick_detect(encoded);
    assert!(result.is_some());
    let detection = result.unwrap();
    assert_eq!(detection.name, "hex");
    assert_eq!(detection.decoded.as_deref(), Some("Hello"));
  }

  #[test]
  fn test_magic_decode() {
    let detector = AutoDetector::new();
    // "Hello" -> hex -> base64
    let double_encoded = "NDg2NTZjNmM2Zg=="; // base64(hex("Hello"))

    let paths = detector.magic(double_encoded.as_bytes(), 3);
    // Should find at least one path that decodes
    assert!(!paths.is_empty());
  }
}
