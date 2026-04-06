//! Simhash Implementation for Response Fingerprinting
//!
//! Generates locality-sensitive hashes for HTTP response bodies.
//! Similar responses produce similar hashes, enabling efficient deduplication.

use std::collections::HashMap;

/// A 64-bit Simhash fingerprint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Simhash(pub u64);

impl Simhash {
  /// Create a simhash from a pre-computed value
  pub const fn new(hash: u64) -> Self {
    Self(hash)
  }

  /// Create a simhash of zero (null hash)
  pub const fn zero() -> Self {
    Self(0)
  }

  /// Get the raw hash value
  pub fn value(&self) -> u64 {
    self.0
  }

  /// Calculate the Hamming distance between two simhashes
  ///
  /// The Hamming distance is the number of bit positions where
  /// the corresponding bits differ. A smaller distance means
  /// more similar content.
  pub fn hamming_distance(&self, other: &Simhash) -> u32 {
    (self.0 ^ other.0).count_ones()
  }

  /// Check if two simhashes are similar within a threshold
  ///
  /// threshold: maximum number of different bits (typically 0-10)
  /// - 0: exact match
  /// - 3: very similar (recommended for soft-404 detection)
  /// - 5: somewhat similar
  /// - 10: loosely similar
  pub fn is_similar(&self, other: &Simhash, threshold: u32) -> bool {
    self.hamming_distance(other) <= threshold
  }

  /// Calculate similarity percentage (0.0 - 1.0)
  pub fn similarity(&self, other: &Simhash) -> f64 {
    let distance = self.hamming_distance(other);
    1.0 - (distance as f64 / 64.0)
  }

  /// Convert to hexadecimal string representation
  pub fn to_hex(&self) -> String {
    format!("{:016x}", self.0)
  }

  /// Parse from hexadecimal string
  pub fn from_hex(hex: &str) -> Option<Self> {
    u64::from_str_radix(hex, 16).ok().map(Simhash)
  }
}

impl std::fmt::Display for Simhash {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{:016x}", self.0)
  }
}

impl From<u64> for Simhash {
  fn from(value: u64) -> Self {
    Self(value)
  }
}

impl From<Simhash> for u64 {
  fn from(hash: Simhash) -> Self {
    hash.0
  }
}

/// Configuration for simhash calculation
#[derive(Debug, Clone)]
pub struct SimhashConfig {
  /// Shingle (n-gram) size for feature extraction
  pub shingle_size: usize,
  /// Whether to normalize whitespace before hashing
  pub normalize_whitespace: bool,
  /// Whether to lowercase content before hashing
  pub lowercase: bool,
  /// Whether to remove HTML tags before hashing
  pub strip_html: bool,
  /// Minimum content length to hash (shorter content uses simple hash)
  pub min_content_length: usize,
}

impl Default for SimhashConfig {
  fn default() -> Self {
    Self {
      shingle_size: 4, // 4-gram shingles work well for HTTP responses
      normalize_whitespace: true,
      lowercase: true,
      strip_html: true,
      min_content_length: 16,
    }
  }
}

impl SimhashConfig {
  /// Configuration for HTML response comparison
  pub fn for_html() -> Self {
    Self {
      strip_html: true,
      shingle_size: 3,
      ..Default::default()
    }
  }

  /// Configuration for JSON response comparison
  pub fn for_json() -> Self {
    Self {
      strip_html: false,
      shingle_size: 4,
      lowercase: false, // JSON keys are case-sensitive
      ..Default::default()
    }
  }

  /// Configuration for raw text comparison
  pub fn for_text() -> Self {
    Self {
      strip_html: false,
      shingle_size: 5,
      ..Default::default()
    }
  }
}

/// Simhash calculator
pub struct SimhashCalculator {
  config: SimhashConfig,
}

impl SimhashCalculator {
  /// Create a new calculator with the given configuration
  pub fn new(config: SimhashConfig) -> Self {
    Self { config }
  }

  /// Create a calculator with default configuration
  pub fn with_defaults() -> Self {
    Self::new(SimhashConfig::default())
  }

  /// Calculate the simhash of content
  pub fn hash(&self, content: &str) -> Simhash {
    let processed = self.preprocess(content);

    // For very short content, use a simple hash
    if processed.len() < self.config.min_content_length {
      return Simhash(self.simple_hash(&processed));
    }

    // Extract shingles (n-grams)
    let shingles = self.extract_shingles(&processed);

    if shingles.is_empty() {
      return Simhash(self.simple_hash(&processed));
    }

    // Calculate simhash using weighted bit vectors
    self.calculate_simhash(&shingles)
  }

  /// Hash multiple contents and find common fingerprint
  pub fn hash_multiple(&self, contents: &[&str]) -> Simhash {
    if contents.is_empty() {
      return Simhash::zero();
    }
    if contents.len() == 1 {
      return self.hash(contents[0]);
    }

    // Calculate individual hashes and combine
    let hashes: Vec<Simhash> = contents.iter().map(|c| self.hash(c)).collect();

    // Combine by voting on each bit position
    let mut bit_votes = [0i32; 64];
    for hash in &hashes {
      for bit in 0..64 {
        if (hash.0 >> bit) & 1 == 1 {
          bit_votes[bit] += 1;
        } else {
          bit_votes[bit] -= 1;
        }
      }
    }

    // Construct combined hash
    let mut combined: u64 = 0;
    for bit in 0..64 {
      if bit_votes[bit] > 0 {
        combined |= 1u64 << bit;
      }
    }

    Simhash(combined)
  }

  /// Preprocess content according to configuration
  fn preprocess(&self, content: &str) -> String {
    let mut processed = content.to_string();

    // Strip HTML tags if configured
    if self.config.strip_html {
      processed = self.strip_html_tags(&processed);
    }

    // Lowercase if configured
    if self.config.lowercase {
      processed = processed.to_lowercase();
    }

    // Normalize whitespace if configured
    if self.config.normalize_whitespace {
      processed = self.normalize_whitespace(&processed);
    }

    processed
  }

  /// Strip HTML tags from content
  fn strip_html_tags(&self, html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let mut tag_name = String::new();

    for c in html.chars() {
      if c == '<' {
        in_tag = true;
        tag_name.clear();
      } else if c == '>' {
        let tag_lower = tag_name.to_lowercase();
        if tag_lower.starts_with("script") {
          in_script = true;
        } else if tag_lower.starts_with("/script") {
          in_script = false;
        } else if tag_lower.starts_with("style") {
          in_style = true;
        } else if tag_lower.starts_with("/style") {
          in_style = false;
        }
        in_tag = false;
      } else if in_tag {
        tag_name.push(c);
      } else if !in_script && !in_style {
        result.push(c);
      }
    }

    result
  }

  /// Normalize whitespace (collapse multiple spaces, trim)
  fn normalize_whitespace(&self, text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut last_was_space = true; // Start true to trim leading space

    for c in text.chars() {
      if c.is_whitespace() {
        if !last_was_space {
          result.push(' ');
          last_was_space = true;
        }
      } else {
        result.push(c);
        last_was_space = false;
      }
    }

    // Trim trailing space
    if result.ends_with(' ') {
      result.pop();
    }

    result
  }

  /// Extract shingles (n-grams) from text
  fn extract_shingles(&self, text: &str) -> Vec<u64> {
    let chars: Vec<char> = text.chars().collect();
    let n = self.config.shingle_size;

    if chars.len() < n {
      return vec![];
    }

    let mut shingles = Vec::with_capacity(chars.len() - n + 1);
    let mut shingle_set = std::collections::HashSet::new();

    for i in 0..=(chars.len() - n) {
      let shingle: String = chars[i..i + n].iter().collect();
      let hash = self.fnv1a_hash(shingle.as_bytes());

      // Deduplicate shingles
      if shingle_set.insert(hash) {
        shingles.push(hash);
      }
    }

    shingles
  }

  /// Calculate simhash from shingles using weighted bit vectors
  fn calculate_simhash(&self, shingles: &[u64]) -> Simhash {
    // Initialize bit vector with weights
    let mut v = [0i32; 64];

    for &shingle_hash in shingles {
      for i in 0..64 {
        if (shingle_hash >> i) & 1 == 1 {
          v[i] += 1;
        } else {
          v[i] -= 1;
        }
      }
    }

    // Convert to simhash: bit is 1 if weight is positive
    let mut hash: u64 = 0;
    for i in 0..64 {
      if v[i] > 0 {
        hash |= 1u64 << i;
      }
    }

    Simhash(hash)
  }

  /// FNV-1a hash for shingles (fast, good distribution)
  fn fnv1a_hash(&self, data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for byte in data {
      hash ^= *byte as u64;
      hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
  }

  /// Simple hash for short content
  fn simple_hash(&self, content: &str) -> u64 {
    self.fnv1a_hash(content.as_bytes())
  }
}

/// Builder for SimhashCalculator
pub struct SimhashBuilder {
  config: SimhashConfig,
}

impl SimhashBuilder {
  /// Create a new builder with default configuration
  pub fn new() -> Self {
    Self {
      config: SimhashConfig::default(),
    }
  }

  /// Set shingle size
  pub fn shingle_size(mut self, size: usize) -> Self {
    self.config.shingle_size = size.max(1);
    self
  }

  /// Enable/disable whitespace normalization
  pub fn normalize_whitespace(mut self, enable: bool) -> Self {
    self.config.normalize_whitespace = enable;
    self
  }

  /// Enable/disable lowercase conversion
  pub fn lowercase(mut self, enable: bool) -> Self {
    self.config.lowercase = enable;
    self
  }

  /// Enable/disable HTML stripping
  pub fn strip_html(mut self, enable: bool) -> Self {
    self.config.strip_html = enable;
    self
  }

  /// Set minimum content length for full simhash calculation
  pub fn min_content_length(mut self, length: usize) -> Self {
    self.config.min_content_length = length;
    self
  }

  /// Build the calculator
  pub fn build(self) -> SimhashCalculator {
    SimhashCalculator::new(self.config)
  }
}

impl Default for SimhashBuilder {
  fn default() -> Self {
    Self::new()
  }
}

/// Simhash index for efficient near-duplicate lookup
///
/// Uses multiple hash tables with different bit masks to enable
/// fast lookup of similar hashes.
pub struct SimhashIndex {
  /// Hash tables for different bit regions (for LSH)
  tables: Vec<HashMap<u32, Vec<usize>>>,
  /// Stored simhashes
  hashes: Vec<Simhash>,
  /// Number of bands for LSH
  bands: usize,
}

impl SimhashIndex {
  /// Create a new index
  ///
  /// bands: number of bands for LSH (more bands = more precise, slower)
  /// Typical values: 4-8
  pub fn new(bands: usize) -> Self {
    let bands = bands.max(1).min(16);
    Self {
      tables: (0..bands).map(|_| HashMap::new()).collect(),
      hashes: Vec::new(),
      bands,
    }
  }

  /// Create index with default settings (4 bands)
  pub fn with_defaults() -> Self {
    Self::new(4)
  }

  /// Add a simhash to the index
  pub fn insert(&mut self, hash: Simhash) -> usize {
    let idx = self.hashes.len();
    self.hashes.push(hash);

    // Insert into each band's table
    let bits_per_band = 64 / self.bands;
    // Pre-compute band hashes to avoid borrow conflict
    let band_hashes: Vec<u32> = (0..self.bands)
      .map(|band_idx| Self::extract_band_static(hash.0, band_idx, bits_per_band))
      .collect();

    for (band_idx, table) in self.tables.iter_mut().enumerate() {
      let band_hash = band_hashes[band_idx];
      table.entry(band_hash).or_insert_with(Vec::new).push(idx);
    }

    idx
  }

  /// Find similar hashes within the given threshold
  pub fn find_similar(&self, hash: Simhash, threshold: u32) -> Vec<(usize, Simhash, u32)> {
    // Get candidates from LSH tables
    let candidates = self.get_candidates(hash);

    // Filter by actual hamming distance
    let mut results = Vec::new();
    for &idx in &candidates {
      let stored_hash = self.hashes[idx];
      let distance = hash.hamming_distance(&stored_hash);
      if distance <= threshold {
        results.push((idx, stored_hash, distance));
      }
    }

    // Sort by distance
    results.sort_by_key(|&(_, _, d)| d);
    results
  }

  /// Check if a similar hash exists
  pub fn contains_similar(&self, hash: Simhash, threshold: u32) -> bool {
    let candidates = self.get_candidates(hash);

    for &idx in &candidates {
      if hash.hamming_distance(&self.hashes[idx]) <= threshold {
        return true;
      }
    }

    false
  }

  /// Get all stored hashes
  pub fn hashes(&self) -> &[Simhash] {
    &self.hashes
  }

  /// Get the number of stored hashes
  pub fn len(&self) -> usize {
    self.hashes.len()
  }

  /// Check if the index is empty
  pub fn is_empty(&self) -> bool {
    self.hashes.is_empty()
  }

  /// Clear all stored hashes
  pub fn clear(&mut self) {
    self.hashes.clear();
    for table in &mut self.tables {
      table.clear();
    }
  }

  /// Get candidate indices from LSH tables
  fn get_candidates(&self, hash: Simhash) -> Vec<usize> {
    let mut candidates = std::collections::HashSet::new();
    let bits_per_band = 64 / self.bands;

    for (band_idx, table) in self.tables.iter().enumerate() {
      let band_hash = self.extract_band(hash.0, band_idx, bits_per_band);
      if let Some(indices) = table.get(&band_hash) {
        candidates.extend(indices);
      }
    }

    candidates.into_iter().collect()
  }

  /// Extract a band of bits from a hash
  fn extract_band(&self, hash: u64, band_idx: usize, bits_per_band: usize) -> u32 {
    Self::extract_band_static(hash, band_idx, bits_per_band)
  }

  fn extract_band_static(hash: u64, band_idx: usize, bits_per_band: usize) -> u32 {
    let shift = band_idx * bits_per_band;
    let mask = (1u64 << bits_per_band) - 1;
    ((hash >> shift) & mask) as u32
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_identical_content() {
    let calc = SimhashCalculator::with_defaults();

    let content = "This is a test document with some content for hashing purposes.";
    let hash1 = calc.hash(content);
    let hash2 = calc.hash(content);

    assert_eq!(hash1, hash2);
    assert_eq!(hash1.hamming_distance(&hash2), 0);
  }

  #[test]
  fn test_similar_content() {
    let calc = SimhashCalculator::with_defaults();

    let content1 = "This is a test document with some content for hashing purposes.";
    let content2 = "This is a test document with some different content for hashing.";

    let hash1 = calc.hash(content1);
    let hash2 = calc.hash(content2);

    // Similar content should have low hamming distance (< 10)
    let distance = hash1.hamming_distance(&hash2);
    assert!(
      distance < 15,
      "Distance {} is too high for similar content",
      distance
    );
  }

  #[test]
  fn test_different_content() {
    let calc = SimhashCalculator::with_defaults();

    let content1 = "This is a test document about programming and software development.";
    let content2 = "The quick brown fox jumps over the lazy dog near the riverbank.";

    let hash1 = calc.hash(content1);
    let hash2 = calc.hash(content2);

    // Very different content should have high hamming distance
    let distance = hash1.hamming_distance(&hash2);
    assert!(
      distance > 10,
      "Distance {} is too low for different content",
      distance
    );
  }

  #[test]
  fn test_html_stripping() {
    let calc = SimhashCalculator::with_defaults();

    let html1 = "<html><body><p>Hello World</p></body></html>";
    let html2 = "<div class='test'><span>Hello World</span></div>";

    let hash1 = calc.hash(html1);
    let hash2 = calc.hash(html2);

    // After stripping HTML, both contain "Hello World"
    // They should be very similar
    let distance = hash1.hamming_distance(&hash2);
    assert!(
      distance < 5,
      "Distance {} is too high after HTML stripping",
      distance
    );
  }

  #[test]
  fn test_similarity_threshold() {
    let hash1 = Simhash::new(0b1111_1111);
    let hash2 = Simhash::new(0b1111_1110); // 1 bit different
    let hash3 = Simhash::new(0b1111_0000); // 4 bits different

    assert!(hash1.is_similar(&hash2, 1));
    assert!(hash1.is_similar(&hash2, 3));
    assert!(!hash1.is_similar(&hash3, 3));
    assert!(hash1.is_similar(&hash3, 5));
  }

  #[test]
  fn test_simhash_index() {
    let calc = SimhashCalculator::with_defaults();
    let mut index = SimhashIndex::with_defaults();

    let content1 = "This is the first document about testing and development.";
    let content2 = "This is the second document about testing and development.";
    let content3 = "Completely different unrelated content about something else entirely.";

    let hash1 = calc.hash(content1);
    let hash2 = calc.hash(content2);
    let hash3 = calc.hash(content3);

    index.insert(hash1);
    index.insert(hash2);
    index.insert(hash3);

    // hash1 and hash2 should be similar
    let similar = index.find_similar(hash1, 10);
    assert!(!similar.is_empty());
  }

  #[test]
  fn test_hex_conversion() {
    let hash = Simhash::new(0xDEADBEEF12345678);
    let hex = hash.to_hex();
    let parsed = Simhash::from_hex(&hex).unwrap();

    assert_eq!(hash, parsed);
    assert_eq!(hex, "deadbeef12345678");
  }

  #[test]
  fn test_builder() {
    let calc = SimhashBuilder::new()
      .shingle_size(5)
      .strip_html(false)
      .lowercase(false)
      .build();

    let hash = calc.hash("TEST CONTENT");
    assert_ne!(hash.value(), 0);
  }
}
