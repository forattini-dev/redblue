//! Word Extractor for Intelligent Discovery Engine
//!
//! Extracts meaningful words from HTTP responses for TF-IDF learning.
//! Handles HTML text, URL paths, form fields, and JavaScript identifiers.

use std::collections::HashSet;

/// Result of word extraction from a response
#[derive(Debug, Clone)]
pub struct ExtractionResult {
  /// Words extracted from HTML text content
  pub text_words: Vec<String>,
  /// Words extracted from URL paths and segments
  pub path_words: Vec<String>,
  /// Words extracted from form field names
  pub form_fields: Vec<String>,
  /// Words extracted from JavaScript identifiers
  pub js_identifiers: Vec<String>,
  /// All unique words combined
  pub all_words: Vec<String>,
}

impl ExtractionResult {
  /// Create an empty extraction result
  pub fn empty() -> Self {
    Self {
      text_words: Vec::new(),
      path_words: Vec::new(),
      form_fields: Vec::new(),
      js_identifiers: Vec::new(),
      all_words: Vec::new(),
    }
  }

  /// Total number of unique words extracted
  pub fn total_unique(&self) -> usize {
    self.all_words.len()
  }

  /// Check if the extraction found any words
  pub fn is_empty(&self) -> bool {
    self.all_words.is_empty()
  }
}

/// Configuration for word extraction
#[derive(Debug, Clone)]
pub struct ExtractorConfig {
  /// Minimum word length to consider
  pub min_word_length: usize,
  /// Maximum word length to consider
  pub max_word_length: usize,
  /// Whether to extract from HTML text
  pub extract_text: bool,
  /// Whether to extract from URL paths
  pub extract_paths: bool,
  /// Whether to extract from form fields
  pub extract_forms: bool,
  /// Whether to extract from JavaScript
  pub extract_javascript: bool,
  /// Whether to lowercase all words
  pub lowercase: bool,
  /// Custom stop words to filter out
  pub stop_words: HashSet<String>,
}

impl Default for ExtractorConfig {
  fn default() -> Self {
    Self {
      min_word_length: 3,
      max_word_length: 64,
      extract_text: true,
      extract_paths: true,
      extract_forms: true,
      extract_javascript: true,
      lowercase: true,
      stop_words: Self::default_stop_words(),
    }
  }
}

impl ExtractorConfig {
  /// Default stop words (common English words that don't help with discovery)
  fn default_stop_words() -> HashSet<String> {
    [
      // Common HTML words
      "the",
      "and",
      "for",
      "are",
      "but",
      "not",
      "you",
      "all",
      "can",
      "had",
      "her",
      "was",
      "one",
      "our",
      "out",
      "has",
      "his",
      "how",
      "its",
      "let",
      "may",
      "new",
      "now",
      "old",
      "see",
      "way",
      "who",
      "did",
      "get",
      "got",
      "him",
      "she",
      "too",
      "use",
      "any",
      "each",
      "from",
      "have",
      "been",
      "call",
      "come",
      "could",
      "first",
      "into",
      "just",
      "know",
      "like",
      "long",
      "look",
      "make",
      "many",
      "more",
      "most",
      "only",
      "other",
      "over",
      "part",
      "some",
      "such",
      "take",
      "than",
      "that",
      "them",
      "then",
      "there",
      "these",
      "they",
      "this",
      "time",
      "very",
      "what",
      "when",
      "which",
      "will",
      "with",
      "would",
      "your",
      "about",
      // Common web words
      "http",
      "https",
      "www",
      "html",
      "htm",
      "php",
      "asp",
      "aspx",
      "jsp",
      "click",
      "here",
      "page",
      "home",
      "site",
      "link",
      "menu",
      "search",
      "content",
      "copyright",
      "reserved",
      "rights",
      "privacy",
      "terms",
      "contact",
      "about",
      "help",
      "login",
      "logout",
      "register",
      "submit",
      // Common JavaScript words
      "function",
      "return",
      "var",
      "let",
      "const",
      "true",
      "false",
      "null",
      "undefined",
      "typeof",
      "instanceof",
      "new",
      "this",
      "class",
      "export",
      "import",
      "from",
      "default",
      "extends",
      "super",
      "static",
      "async",
      "await",
      "try",
      "catch",
      "finally",
      "throw",
      "if",
      "else",
      "switch",
      "case",
      "break",
      "continue",
      "for",
      "while",
      "do",
      "in",
      "of",
      "document",
      "window",
      "console",
      "log",
      "error",
      "warn",
      "info",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
  }

  /// Create config optimized for directory discovery
  pub fn for_directories() -> Self {
    Self {
      extract_paths: true,
      extract_forms: true,
      extract_javascript: true,
      extract_text: false, // Text often has noise for dir discovery
      ..Default::default()
    }
  }

  /// Create config optimized for parameter discovery
  pub fn for_parameters() -> Self {
    Self {
      extract_forms: true,
      extract_javascript: true,
      extract_paths: true,
      extract_text: false,
      ..Default::default()
    }
  }

  /// Create config for maximum word extraction
  pub fn comprehensive() -> Self {
    Self::default()
  }
}

/// Word extractor for HTTP responses
pub struct WordExtractor {
  config: ExtractorConfig,
}

impl WordExtractor {
  /// Create a new word extractor with the given configuration
  pub fn new(config: ExtractorConfig) -> Self {
    Self { config }
  }

  /// Create a word extractor with default configuration
  pub fn with_defaults() -> Self {
    Self::new(ExtractorConfig::default())
  }

  /// Extract words from an HTTP response body
  pub fn extract(&self, body: &str) -> ExtractionResult {
    let mut result = ExtractionResult::empty();
    let mut all_words = HashSet::new();

    // Extract from HTML text content
    if self.config.extract_text {
      let text_words = self.extract_html_text(body);
      for word in &text_words {
        all_words.insert(word.clone());
      }
      result.text_words = text_words;
    }

    // Extract from URL paths found in the content
    if self.config.extract_paths {
      let path_words = self.extract_url_paths(body);
      for word in &path_words {
        all_words.insert(word.clone());
      }
      result.path_words = path_words;
    }

    // Extract from form field names
    if self.config.extract_forms {
      let form_fields = self.extract_form_fields(body);
      for word in &form_fields {
        all_words.insert(word.clone());
      }
      result.form_fields = form_fields;
    }

    // Extract from JavaScript identifiers
    if self.config.extract_javascript {
      let js_ids = self.extract_javascript_identifiers(body);
      for word in &js_ids {
        all_words.insert(word.clone());
      }
      result.js_identifiers = js_ids;
    }

    // Combine all unique words
    result.all_words = all_words.into_iter().collect();
    result
  }

  /// Extract text content from HTML (strip tags)
  fn extract_html_text(&self, html: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let mut current_word = String::new();
    let mut tag_name = String::new();

    let chars: Vec<char> = html.chars().collect();
    let mut i = 0;

    while i < chars.len() {
      let c = chars[i];

      if c == '<' {
        // Flush current word
        if !current_word.is_empty() && !in_script && !in_style {
          if let Some(word) = self.normalize_word(&current_word) {
            words.push(word);
          }
          current_word.clear();
        }
        in_tag = true;
        tag_name.clear();
      } else if c == '>' {
        in_tag = false;

        // Check for script/style tags
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
      } else if in_tag {
        tag_name.push(c);
      } else if !in_script && !in_style {
        if c.is_alphanumeric() || c == '_' || c == '-' {
          current_word.push(c);
        } else if !current_word.is_empty() {
          if let Some(word) = self.normalize_word(&current_word) {
            words.push(word);
          }
          current_word.clear();
        }
      }

      i += 1;
    }

    // Don't forget the last word
    if !current_word.is_empty() && !in_script && !in_style {
      if let Some(word) = self.normalize_word(&current_word) {
        words.push(word);
      }
    }

    words
  }

  /// Extract words from URL paths in the content
  fn extract_url_paths(&self, content: &str) -> Vec<String> {
    let mut words = Vec::new();

    // Look for href and src attributes
    for pattern in &[
      "href=\"",
      "href='",
      "src=\"",
      "src='",
      "action=\"",
      "action='",
    ] {
      let mut search_start = 0;
      while let Some(start) = content[search_start..].find(pattern) {
        let abs_start = search_start + start + pattern.len();
        let quote = if pattern.ends_with('"') { '"' } else { '\'' };

        if let Some(end) = content[abs_start..].find(quote) {
          let url = &content[abs_start..abs_start + end];
          let path_words = self.extract_words_from_path(url);
          words.extend(path_words);
        }
        search_start = abs_start;
      }
    }

    words
  }

  /// Extract words from a URL path
  fn extract_words_from_path(&self, path: &str) -> Vec<String> {
    let mut words = Vec::new();

    // Remove protocol and domain if present
    let path = if let Some(idx) = path.find("://") {
      let after_proto = &path[idx + 3..];
      if let Some(slash_idx) = after_proto.find('/') {
        &after_proto[slash_idx..]
      } else {
        return words;
      }
    } else {
      path
    };

    // Split by path separator and common delimiters
    for segment in path.split(&['/', '-', '_', '.', '?', '&', '='][..]) {
      if let Some(word) = self.normalize_word(segment) {
        words.push(word);
      }
    }

    words
  }

  /// Extract form field names
  fn extract_form_fields(&self, content: &str) -> Vec<String> {
    let mut words = Vec::new();

    // Look for name attributes in form elements
    for pattern in &["name=\"", "name='", "id=\"", "id='"] {
      let mut search_start = 0;
      while let Some(start) = content[search_start..].find(pattern) {
        let abs_start = search_start + start + pattern.len();
        let quote = if pattern.ends_with('"') { '"' } else { '\'' };

        if let Some(end) = content[abs_start..].find(quote) {
          let field_name = &content[abs_start..abs_start + end];

          // Split camelCase and snake_case
          let extracted = self.split_identifier(field_name);
          for word in extracted {
            if let Some(normalized) = self.normalize_word(&word) {
              words.push(normalized);
            }
          }
        }
        search_start = abs_start;
      }
    }

    words
  }

  /// Extract JavaScript identifiers
  fn extract_javascript_identifiers(&self, content: &str) -> Vec<String> {
    let mut words = Vec::new();

    // Find JavaScript sections
    let mut in_script = false;
    let mut script_content = String::new();

    let content_lower = content.to_lowercase();
    let mut i = 0;
    let chars: Vec<char> = content.chars().collect();

    while i < chars.len() {
      if i + 7 <= chars.len() {
        let slice: String = chars[i..i + 7].iter().collect();
        if slice.to_lowercase() == "<script" {
          // Find the end of opening tag
          if let Some(tag_end) = content[i..].find('>') {
            i += tag_end + 1;
            in_script = true;
            continue;
          }
        }
      }

      if i + 9 <= chars.len() {
        let slice: String = chars[i..i + 9].iter().collect();
        if slice.to_lowercase() == "</script>" {
          // Process script content
          let js_words = self.extract_js_identifiers_from_script(&script_content);
          words.extend(js_words);
          script_content.clear();
          in_script = false;
          i += 9;
          continue;
        }
      }

      if in_script {
        script_content.push(chars[i]);
      }

      i += 1;
    }

    // Also look for inline JavaScript patterns
    let js_patterns = self.extract_inline_js_patterns(content);
    words.extend(js_patterns);

    words
  }

  /// Extract identifiers from JavaScript code
  fn extract_js_identifiers_from_script(&self, js: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut string_char = ' ';
    let mut prev_char = ' ';

    for c in js.chars() {
      // Handle string literals
      if (c == '"' || c == '\'' || c == '`') && prev_char != '\\' {
        if in_string && c == string_char {
          in_string = false;
        } else if !in_string {
          in_string = true;
          string_char = c;
        }
      }

      if !in_string {
        if c.is_alphanumeric() || c == '_' || c == '$' {
          current.push(c);
        } else if !current.is_empty() {
          // Skip if starts with number
          if !current
            .chars()
            .next()
            .map(|c| c.is_numeric())
            .unwrap_or(true)
          {
            let extracted = self.split_identifier(&current);
            for word in extracted {
              if let Some(normalized) = self.normalize_word(&word) {
                words.push(normalized);
              }
            }
          }
          current.clear();
        }
      }

      prev_char = c;
    }

    // Don't forget the last identifier
    if !current.is_empty()
      && !current
        .chars()
        .next()
        .map(|c| c.is_numeric())
        .unwrap_or(true)
    {
      let extracted = self.split_identifier(&current);
      for word in extracted {
        if let Some(normalized) = self.normalize_word(&word) {
          words.push(normalized);
        }
      }
    }

    words
  }

  /// Extract JavaScript-like patterns from non-script content
  fn extract_inline_js_patterns(&self, content: &str) -> Vec<String> {
    let mut words = Vec::new();

    // Look for onclick, onload, etc. handlers
    for event in &[
      "onclick", "onload", "onsubmit", "onchange", "oninput", "onfocus", "onblur",
    ] {
      let pattern = format!("{}=\"", event);
      let mut search_start = 0;

      while let Some(start) = content[search_start..].to_lowercase().find(&pattern) {
        let abs_start = search_start + start + pattern.len();
        if let Some(end) = content[abs_start..].find('"') {
          let handler = &content[abs_start..abs_start + end];
          let js_words = self.extract_js_identifiers_from_script(handler);
          words.extend(js_words);
        }
        search_start = abs_start;
      }
    }

    // Look for data attributes that might contain JSON
    let mut search_start = 0;
    while let Some(start) = content[search_start..].find("data-") {
      let abs_start = search_start + start;

      // Find the attribute value
      if let Some(eq) = content[abs_start..].find("=\"") {
        let val_start = abs_start + eq + 2;
        if let Some(val_end) = content[val_start..].find('"') {
          let attr_name = &content[abs_start + 5..abs_start + eq];
          let attr_value = &content[val_start..val_start + val_end];

          // Extract from attribute name
          for word in self.split_identifier(attr_name) {
            if let Some(normalized) = self.normalize_word(&word) {
              words.push(normalized);
            }
          }

          // Try to extract words from value (might be JSON)
          let value_words = self.extract_json_keys(attr_value);
          words.extend(value_words);
        }
      }
      search_start = abs_start + 1;
    }

    words
  }

  /// Extract keys from JSON-like content
  fn extract_json_keys(&self, content: &str) -> Vec<String> {
    let mut words = Vec::new();

    // Simple pattern: "key": or 'key':
    for pattern in &["\":", "':", "\":"] {
      let mut search_start = 0;
      while let Some(pos) = content[search_start..].find(pattern) {
        let abs_pos = search_start + pos;
        // Find the start of the key
        let key_start = content[..abs_pos].rfind(['"', '\'']);
        if let Some(start) = key_start {
          let key = &content[start + 1..abs_pos];
          for word in self.split_identifier(key) {
            if let Some(normalized) = self.normalize_word(&word) {
              words.push(normalized);
            }
          }
        }
        search_start = abs_pos + 1;
      }
    }

    words
  }

  /// Split camelCase and snake_case identifiers into words
  fn split_identifier(&self, id: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_was_lower = false;

    for c in id.chars() {
      if c == '_' || c == '-' {
        if !current.is_empty() {
          words.push(current.clone());
          current.clear();
        }
        prev_was_lower = false;
      } else if c.is_uppercase() && prev_was_lower {
        // CamelCase boundary
        if !current.is_empty() {
          words.push(current.clone());
          current.clear();
        }
        current.push(c);
        prev_was_lower = false;
      } else {
        current.push(c);
        prev_was_lower = c.is_lowercase();
      }
    }

    if !current.is_empty() {
      words.push(current);
    }

    // Also include the full identifier
    if words.len() > 1 {
      words.push(id.to_string());
    }

    words
  }

  /// Normalize a word: lowercase, filter by length, check stop words
  fn normalize_word(&self, word: &str) -> Option<String> {
    // Filter by length
    if word.len() < self.config.min_word_length || word.len() > self.config.max_word_length {
      return None;
    }

    // Check for numeric-only strings
    if word.chars().all(|c| c.is_numeric()) {
      return None;
    }

    // Lowercase if configured
    let normalized = if self.config.lowercase {
      word.to_lowercase()
    } else {
      word.to_string()
    };

    // Check stop words
    if self.config.stop_words.contains(&normalized) {
      return None;
    }

    Some(normalized)
  }
}

/// Builder for WordExtractor
pub struct ExtractorBuilder {
  config: ExtractorConfig,
}

impl ExtractorBuilder {
  /// Create a new builder with default configuration
  pub fn new() -> Self {
    Self {
      config: ExtractorConfig::default(),
    }
  }

  /// Set minimum word length
  pub fn min_length(mut self, len: usize) -> Self {
    self.config.min_word_length = len;
    self
  }

  /// Set maximum word length
  pub fn max_length(mut self, len: usize) -> Self {
    self.config.max_word_length = len;
    self
  }

  /// Enable/disable text extraction
  pub fn extract_text(mut self, enable: bool) -> Self {
    self.config.extract_text = enable;
    self
  }

  /// Enable/disable path extraction
  pub fn extract_paths(mut self, enable: bool) -> Self {
    self.config.extract_paths = enable;
    self
  }

  /// Enable/disable form field extraction
  pub fn extract_forms(mut self, enable: bool) -> Self {
    self.config.extract_forms = enable;
    self
  }

  /// Enable/disable JavaScript extraction
  pub fn extract_javascript(mut self, enable: bool) -> Self {
    self.config.extract_javascript = enable;
    self
  }

  /// Add custom stop words
  pub fn add_stop_words(mut self, words: &[&str]) -> Self {
    for word in words {
      self.config.stop_words.insert(word.to_string());
    }
    self
  }

  /// Build the extractor
  pub fn build(self) -> WordExtractor {
    WordExtractor::new(self.config)
  }
}

impl Default for ExtractorBuilder {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_html_text_extraction() {
    let extractor = WordExtractor::with_defaults();
    let html = "<html><body><h1>Welcome to AdminPanel</h1><p>Dashboard content</p></body></html>";
    let result = extractor.extract(html);

    assert!(result.text_words.contains(&"welcome".to_string()));
    assert!(result.text_words.contains(&"dashboard".to_string()));
  }

  #[test]
  fn test_path_extraction() {
    let extractor = WordExtractor::with_defaults();
    let html = r#"<a href="/admin/dashboard">Link</a>"#;
    let result = extractor.extract(html);

    assert!(result.path_words.contains(&"admin".to_string()));
    assert!(result.path_words.contains(&"dashboard".to_string()));
  }

  #[test]
  fn test_form_field_extraction() {
    let extractor = WordExtractor::with_defaults();
    let html = r#"<input name="userEmail" id="passwordField">"#;
    let result = extractor.extract(html);

    assert!(result.form_fields.contains(&"user".to_string()));
    assert!(result.form_fields.contains(&"email".to_string()));
    assert!(result.form_fields.contains(&"password".to_string()));
  }

  #[test]
  fn test_javascript_extraction() {
    let extractor = WordExtractor::with_defaults();
    let html = r#"<script>function loadUserData() { return apiEndpoint; }</script>"#;
    let result = extractor.extract(html);

    assert!(result.js_identifiers.contains(&"load".to_string()));
    assert!(result.js_identifiers.contains(&"user".to_string()));
    assert!(result.js_identifiers.contains(&"data".to_string()));
    assert!(result.js_identifiers.contains(&"endpoint".to_string()));
  }

  #[test]
  fn test_stop_words_filtered() {
    let extractor = WordExtractor::with_defaults();
    let html = "<p>The function will return the value</p>";
    let result = extractor.extract(html);

    // Stop words should be filtered
    assert!(!result.text_words.contains(&"the".to_string()));
    assert!(!result.text_words.contains(&"function".to_string()));
    assert!(!result.text_words.contains(&"return".to_string()));
  }

  #[test]
  fn test_builder_pattern() {
    let extractor = ExtractorBuilder::new()
      .min_length(4)
      .extract_text(true)
      .extract_paths(false)
      .build();

    let html = "<a href='/abc'>test</a>";
    let result = extractor.extract(html);

    // 'abc' is too short (min 4)
    assert!(!result.all_words.contains(&"abc".to_string()));
    // 'test' is exactly 4 chars
    assert!(result.all_words.contains(&"test".to_string()));
  }
}
