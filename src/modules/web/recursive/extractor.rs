//! Link Extractor for Recursive Content Discovery
//!
//! Extracts URLs from HTTP responses for recursive scanning.
//! Handles href, src attributes, JavaScript URLs, and form actions.

use std::collections::HashSet;

/// Extracted link information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtractedLink {
  /// The extracted URL (may be relative or absolute)
  pub url: String,
  /// Source of the link (href, src, js, form, etc.)
  pub source: LinkSource,
  /// Anchor text or alt text (if available)
  pub text: Option<String>,
}

impl ExtractedLink {
  /// Create a new extracted link
  pub fn new(url: impl Into<String>, source: LinkSource) -> Self {
    Self {
      url: url.into(),
      source,
      text: None,
    }
  }

  /// Create with anchor text
  pub fn with_text(url: impl Into<String>, source: LinkSource, text: impl Into<String>) -> Self {
    Self {
      url: url.into(),
      source,
      text: Some(text.into()),
    }
  }
}

/// Source type of the extracted link
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkSource {
  /// <a href="...">
  Href,
  /// <script src="..."> or <link href="...">
  Resource,
  /// <img src="...">
  Image,
  /// <form action="...">
  Form,
  /// JavaScript URL (window.location, fetch, etc.)
  JavaScript,
  /// <meta http-equiv="refresh" content="...">
  Meta,
  /// HTML comments containing URLs
  Comment,
  /// Data attribute (data-url, data-href, etc.)
  DataAttribute,
}

impl LinkSource {
  /// Check if this source type is typically a navigation link
  pub fn is_navigation(&self) -> bool {
    matches!(self, LinkSource::Href | LinkSource::Form | LinkSource::Meta)
  }

  /// Check if this source type is typically a resource link
  pub fn is_resource(&self) -> bool {
    matches!(self, LinkSource::Resource | LinkSource::Image)
  }
}

/// Configuration for link extraction
#[derive(Debug, Clone)]
pub struct ExtractorConfig {
  /// Extract href attributes
  pub extract_href: bool,
  /// Extract src attributes
  pub extract_src: bool,
  /// Extract form actions
  pub extract_forms: bool,
  /// Extract JavaScript URLs
  pub extract_javascript: bool,
  /// Extract from meta refresh tags
  pub extract_meta: bool,
  /// Extract from HTML comments
  pub extract_comments: bool,
  /// Extract from data attributes
  pub extract_data_attrs: bool,
  /// Include resource links (CSS, JS files)
  pub include_resources: bool,
  /// Include image links
  pub include_images: bool,
  /// URL patterns to exclude (substring match)
  pub exclude_patterns: Vec<String>,
  /// URL extensions to exclude
  pub exclude_extensions: Vec<String>,
}

impl Default for ExtractorConfig {
  fn default() -> Self {
    Self {
      extract_href: true,
      extract_src: true,
      extract_forms: true,
      extract_javascript: true,
      extract_meta: true,
      extract_comments: false, // Often noisy
      extract_data_attrs: true,
      include_resources: false, // Usually not needed for directory discovery
      include_images: false,    // Usually not needed
      exclude_patterns: vec![
        "javascript:".into(),
        "mailto:".into(),
        "tel:".into(),
        "data:".into(),
        "#".into(), // Fragment-only links
      ],
      exclude_extensions: vec![
        "jpg".into(),
        "jpeg".into(),
        "png".into(),
        "gif".into(),
        "svg".into(),
        "ico".into(),
        "webp".into(),
        "css".into(),
        "js".into(),
        "woff".into(),
        "woff2".into(),
        "ttf".into(),
        "eot".into(),
        "mp3".into(),
        "mp4".into(),
        "webm".into(),
        "pdf".into(),
      ],
    }
  }
}

impl ExtractorConfig {
  /// Configuration for comprehensive extraction
  pub fn comprehensive() -> Self {
    Self {
      extract_comments: true,
      include_resources: true,
      include_images: true,
      exclude_extensions: vec![], // Include all
      ..Default::default()
    }
  }

  /// Configuration for directory discovery (minimal, focused)
  pub fn for_directories() -> Self {
    Self::default()
  }

  /// Configuration for JavaScript analysis
  pub fn for_javascript() -> Self {
    Self {
      extract_href: false,
      extract_src: true,
      extract_forms: false,
      extract_javascript: true,
      extract_meta: false,
      extract_comments: true,
      extract_data_attrs: true,
      include_resources: true,
      ..Default::default()
    }
  }
}

/// Link extractor for HTTP responses
pub struct LinkExtractor {
  config: ExtractorConfig,
}

impl LinkExtractor {
  /// Create a new link extractor with the given configuration
  pub fn new(config: ExtractorConfig) -> Self {
    Self { config }
  }

  /// Create with default configuration
  pub fn with_defaults() -> Self {
    Self::new(ExtractorConfig::default())
  }

  /// Extract all links from HTML content
  pub fn extract(&self, html: &str) -> Vec<ExtractedLink> {
    let mut links = HashSet::new();

    // Extract href attributes
    if self.config.extract_href {
      self.extract_href_links(html, &mut links);
    }

    // Extract src attributes
    if self.config.extract_src {
      self.extract_src_links(html, &mut links);
    }

    // Extract form actions
    if self.config.extract_forms {
      self.extract_form_links(html, &mut links);
    }

    // Extract JavaScript URLs
    if self.config.extract_javascript {
      self.extract_js_links(html, &mut links);
    }

    // Extract meta refresh
    if self.config.extract_meta {
      self.extract_meta_links(html, &mut links);
    }

    // Extract from comments
    if self.config.extract_comments {
      self.extract_comment_links(html, &mut links);
    }

    // Extract from data attributes
    if self.config.extract_data_attrs {
      self.extract_data_attr_links(html, &mut links);
    }

    // Filter and return
    links
      .into_iter()
      .filter(|l| self.should_include(l))
      .collect()
  }

  /// Extract links from href attributes
  fn extract_href_links(&self, html: &str, links: &mut HashSet<ExtractedLink>) {
    // <a href="...">
    for (url, text) in self.extract_attribute_with_text(html, "href", Some("a")) {
      if let Some(text) = text {
        links.insert(ExtractedLink::with_text(url, LinkSource::Href, text));
      } else {
        links.insert(ExtractedLink::new(url, LinkSource::Href));
      }
    }

    // <link href="..."> for stylesheets etc.
    if self.config.include_resources {
      for (url, _) in self.extract_attribute_with_text(html, "href", Some("link")) {
        links.insert(ExtractedLink::new(url, LinkSource::Resource));
      }
    }
  }

  /// Extract links from src attributes
  fn extract_src_links(&self, html: &str, links: &mut HashSet<ExtractedLink>) {
    // Generic src extraction
    for (url, tag) in self.extract_attribute_with_tag(html, "src") {
      let tag_lower = tag.to_lowercase();
      let source = if tag_lower == "img" {
        if !self.config.include_images {
          continue;
        }
        LinkSource::Image
      } else if tag_lower == "script" || tag_lower == "link" {
        if !self.config.include_resources {
          continue;
        }
        LinkSource::Resource
      } else if tag_lower == "iframe" || tag_lower == "frame" {
        LinkSource::Href // Frames are navigation
      } else {
        LinkSource::Resource
      };

      links.insert(ExtractedLink::new(url, source));
    }
  }

  /// Extract links from form actions
  fn extract_form_links(&self, html: &str, links: &mut HashSet<ExtractedLink>) {
    for (url, _) in self.extract_attribute_with_text(html, "action", Some("form")) {
      links.insert(ExtractedLink::new(url, LinkSource::Form));
    }
  }

  /// Extract URLs from JavaScript code
  fn extract_js_links(&self, html: &str, links: &mut HashSet<ExtractedLink>) {
    // Extract from <script> tags
    let script_urls = self.extract_urls_from_scripts(html);
    for url in script_urls {
      links.insert(ExtractedLink::new(url, LinkSource::JavaScript));
    }

    // Extract from inline event handlers
    let inline_urls = self.extract_inline_js_urls(html);
    for url in inline_urls {
      links.insert(ExtractedLink::new(url, LinkSource::JavaScript));
    }
  }

  /// Extract URLs from <script> tags
  fn extract_urls_from_scripts(&self, html: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let html_lower = html.to_lowercase();
    let mut search_start = 0;

    while let Some(start) = html_lower[search_start..].find("<script") {
      let abs_start = search_start + start;

      // Find end of opening tag
      let tag_end = html[abs_start..].find('>');
      if tag_end.is_none() {
        break;
      }
      let content_start = abs_start + tag_end.unwrap() + 1;

      // Find closing tag
      let script_end = html_lower[content_start..].find("</script>");
      if script_end.is_none() {
        break;
      }
      let content_end = content_start + script_end.unwrap();

      let script_content = &html[content_start..content_end];
      let extracted = self.extract_urls_from_js(script_content);
      urls.extend(extracted);

      search_start = content_end;
    }

    urls
  }

  /// Extract URLs from JavaScript code
  fn extract_urls_from_js(&self, js: &str) -> Vec<String> {
    let mut urls = Vec::new();

    // Common patterns:
    // - fetch('/api/...
    // - XMLHttpRequest.open('GET', '/api/...
    // - window.location = '/page'
    // - href: '/link'
    // - url: '/endpoint'
    // - '/path/to/resource'

    let patterns = [
      (r#"fetch\s*\(\s*["']"#, r#"["']"#),
      (r#"\.open\s*\(\s*["'][^"']*["']\s*,\s*["']"#, r#"["']"#),
      (r#"location\s*=\s*["']"#, r#"["']"#),
      (r#"location\.href\s*=\s*["']"#, r#"["']"#),
      (r#"href\s*:\s*["']"#, r#"["']"#),
      (r#"url\s*:\s*["']"#, r#"["']"#),
      (r#"src\s*:\s*["']"#, r#"["']"#),
      (r#"redirect\s*\(\s*["']"#, r#"["']"#),
      (r#"navigate\s*\(\s*["']"#, r#"["']"#),
    ];

    for (start_pattern, end_quote) in patterns {
      let mut search_pos = 0;
      while let Some(match_start) = self.find_pattern(js, start_pattern, search_pos) {
        let url_start = match_start + self.pattern_len(start_pattern);
        if url_start >= js.len() {
          break;
        }

        // Find closing quote
        if let Some(url_end) = js[url_start..].find(|c| c == '"' || c == '\'') {
          let url = &js[url_start..url_start + url_end];
          if self.is_valid_path(url) {
            urls.push(url.to_string());
          }
        }
        search_pos = url_start;
      }
    }

    // Also extract string literals that look like paths
    let path_strings = self.extract_path_strings(js);
    urls.extend(path_strings);

    urls
  }

  /// Extract string literals that look like URL paths
  fn extract_path_strings(&self, js: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut in_string = false;
    let mut string_char = '"';
    let mut current_string = String::new();
    let mut escape_next = false;

    for c in js.chars() {
      if escape_next {
        if in_string {
          current_string.push(c);
        }
        escape_next = false;
        continue;
      }

      if c == '\\' {
        escape_next = true;
        if in_string {
          current_string.push(c);
        }
        continue;
      }

      if (c == '"' || c == '\'' || c == '`') && !in_string {
        in_string = true;
        string_char = c;
        current_string.clear();
      } else if c == string_char && in_string {
        // End of string
        if self.looks_like_path(&current_string) {
          urls.push(current_string.clone());
        }
        in_string = false;
      } else if in_string {
        current_string.push(c);
      }
    }

    urls
  }

  /// Check if a string looks like a URL path
  fn looks_like_path(&self, s: &str) -> bool {
    // Must start with /
    if !s.starts_with('/') {
      return false;
    }

    // Must be reasonable length
    if s.len() < 2 || s.len() > 200 {
      return false;
    }

    // Must not be just /
    if s == "/" {
      return false;
    }

    // Must contain mostly valid URL chars
    let valid_chars = s
      .chars()
      .all(|c| c.is_alphanumeric() || "/-_.?&=#%".contains(c));
    if !valid_chars {
      return false;
    }

    // Should not look like a regex or code
    if s.contains(".*") || s.contains("\\") || s.contains("${") {
      return false;
    }

    true
  }

  /// Extract URLs from inline event handlers
  fn extract_inline_js_urls(&self, html: &str) -> Vec<String> {
    let mut urls = Vec::new();

    let events = [
      "onclick",
      "onload",
      "onsubmit",
      "onchange",
      "onmouseover",
      "onfocus",
    ];

    for event in events {
      let pattern = format!("{}=\"", event);
      let mut search_start = 0;

      while let Some(start) = html.to_lowercase()[search_start..].find(&pattern) {
        let abs_start = search_start + start + pattern.len();
        if let Some(end) = html[abs_start..].find('"') {
          let handler = &html[abs_start..abs_start + end];
          let extracted = self.extract_urls_from_js(handler);
          urls.extend(extracted);
        }
        search_start = abs_start;
      }
    }

    urls
  }

  /// Extract links from meta refresh tags
  fn extract_meta_links(&self, html: &str, links: &mut HashSet<ExtractedLink>) {
    // <meta http-equiv="refresh" content="0;url=/page">
    let pattern = "http-equiv=\"refresh\"";
    let mut search_start = 0;

    while let Some(start) = html.to_lowercase()[search_start..].find(pattern) {
      let abs_start = search_start + start;

      // Find content attribute
      if let Some(content_start) = html[abs_start..].to_lowercase().find("content=\"") {
        let url_search_start = abs_start + content_start + 9;
        if let Some(content_end) = html[url_search_start..].find('"') {
          let content = &html[url_search_start..url_search_start + content_end];

          // Parse "seconds;url=..." format
          if let Some(url_pos) = content.to_lowercase().find("url=") {
            let url = &content[url_pos + 4..];
            links.insert(ExtractedLink::new(url.trim(), LinkSource::Meta));
          }
        }
      }

      search_start = abs_start + pattern.len();
    }
  }

  /// Extract links from HTML comments
  fn extract_comment_links(&self, html: &str, links: &mut HashSet<ExtractedLink>) {
    let mut search_start = 0;

    while let Some(start) = html[search_start..].find("<!--") {
      let abs_start = search_start + start + 4;
      if let Some(end) = html[abs_start..].find("-->") {
        let comment = &html[abs_start..abs_start + end];

        // Look for URLs in comments
        let comment_urls = self.extract_urls_from_text(comment);
        for url in comment_urls {
          links.insert(ExtractedLink::new(url, LinkSource::Comment));
        }
      }
      search_start = abs_start;
    }
  }

  /// Extract links from data- attributes
  fn extract_data_attr_links(&self, html: &str, links: &mut HashSet<ExtractedLink>) {
    let data_attrs = [
      "data-url",
      "data-href",
      "data-src",
      "data-action",
      "data-target",
    ];

    for attr in data_attrs {
      for (url, _) in self.extract_attribute_with_text(html, attr, None) {
        links.insert(ExtractedLink::new(url, LinkSource::DataAttribute));
      }
    }
  }

  /// Extract attribute values with optional tag filter
  fn extract_attribute_with_text(
    &self,
    html: &str,
    attr: &str,
    tag_filter: Option<&str>,
  ) -> Vec<(String, Option<String>)> {
    let mut results = Vec::new();
    let pattern = format!("{}=\"", attr);
    let pattern_single = format!("{}='", attr);

    for pat in [&pattern, &pattern_single] {
      let quote = if pat.ends_with('"') { '"' } else { '\'' };
      let mut search_start = 0;

      while let Some(attr_pos) = html.to_lowercase()[search_start..].find(&pat.to_lowercase()) {
        let abs_attr_pos = search_start + attr_pos;

        // Check tag filter if specified
        if let Some(tag) = tag_filter {
          // Find the opening < before this attribute
          let tag_start = html[..abs_attr_pos].rfind('<');
          if let Some(ts) = tag_start {
            let tag_text = &html[ts + 1..abs_attr_pos];
            let actual_tag = tag_text.split_whitespace().next().unwrap_or("");
            if actual_tag.to_lowercase() != tag.to_lowercase() {
              search_start = abs_attr_pos + pat.len();
              continue;
            }
          }
        }

        let url_start = abs_attr_pos + pat.len();
        if let Some(url_end) = html[url_start..].find(quote) {
          let url = html[url_start..url_start + url_end].to_string();

          // Try to extract anchor text for <a> tags
          let text = if tag_filter == Some("a") {
            self.extract_anchor_text(&html[url_start + url_end..])
          } else {
            None
          };

          if !url.is_empty() {
            results.push((url, text));
          }
        }
        search_start = url_start;
      }
    }

    results
  }

  /// Extract attribute values with tag name
  fn extract_attribute_with_tag(&self, html: &str, attr: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let pattern = format!("{}=\"", attr);
    let pattern_single = format!("{}='", attr);

    for pat in [&pattern, &pattern_single] {
      let quote = if pat.ends_with('"') { '"' } else { '\'' };
      let mut search_start = 0;

      while let Some(attr_pos) = html.to_lowercase()[search_start..].find(&pat.to_lowercase()) {
        let abs_attr_pos = search_start + attr_pos;

        // Find the tag name
        let tag_start = html[..abs_attr_pos].rfind('<');
        let tag_name = if let Some(ts) = tag_start {
          let tag_text = &html[ts + 1..abs_attr_pos];
          tag_text.split_whitespace().next().unwrap_or("").to_string()
        } else {
          String::new()
        };

        let url_start = abs_attr_pos + pat.len();
        if let Some(url_end) = html[url_start..].find(quote) {
          let url = html[url_start..url_start + url_end].to_string();
          if !url.is_empty() {
            results.push((url, tag_name.clone()));
          }
        }
        search_start = url_start;
      }
    }

    results
  }

  /// Extract anchor text from after the href attribute
  fn extract_anchor_text(&self, html_after_href: &str) -> Option<String> {
    // Find closing > of the <a> tag
    let tag_close = html_after_href.find('>')?;
    let after_tag = &html_after_href[tag_close + 1..];

    // Find </a>
    let anchor_end = after_tag.to_lowercase().find("</a>")?;
    let content = &after_tag[..anchor_end];

    // Strip HTML tags from content
    let text = self.strip_tags(content);
    let trimmed = text.trim();

    if trimmed.is_empty() {
      None
    } else {
      Some(trimmed.to_string())
    }
  }

  /// Strip HTML tags from text
  fn strip_tags(&self, html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;

    for c in html.chars() {
      if c == '<' {
        in_tag = true;
      } else if c == '>' {
        in_tag = false;
      } else if !in_tag {
        result.push(c);
      }
    }

    result
  }

  /// Extract URLs from plain text
  fn extract_urls_from_text(&self, text: &str) -> Vec<String> {
    let mut urls = Vec::new();

    // Look for path-like strings
    for word in text.split_whitespace() {
      if self.is_valid_path(word) {
        urls.push(word.to_string());
      }
    }

    urls
  }

  /// Check if a string is a valid URL path
  fn is_valid_path(&self, s: &str) -> bool {
    // Must start with / or be a relative path
    if !s.starts_with('/') && !s.starts_with("./") && !s.starts_with("../") {
      // Check if it's a full URL
      if !s.starts_with("http://") && !s.starts_with("https://") {
        return false;
      }
    }

    // Reasonable length
    if s.len() < 2 || s.len() > 500 {
      return false;
    }

    true
  }

  /// Check if a link should be included based on config
  fn should_include(&self, link: &ExtractedLink) -> bool {
    let url_lower = link.url.to_lowercase();
    let allow_excluded_extension = match link.source {
      LinkSource::Image => self.config.include_images,
      LinkSource::Resource => self.config.include_resources,
      _ => false,
    };

    // Check exclude patterns
    for pattern in &self.config.exclude_patterns {
      if url_lower.contains(&pattern.to_lowercase()) {
        return false;
      }
    }

    // Check exclude extensions
    if !allow_excluded_extension {
      if let Some(ext) = self.get_extension(&link.url) {
        if self
          .config
          .exclude_extensions
          .iter()
          .any(|e| e.eq_ignore_ascii_case(&ext))
        {
          return false;
        }
      }
    }

    true
  }

  /// Get file extension from URL
  fn get_extension(&self, url: &str) -> Option<String> {
    // Remove query string
    let path = url.split('?').next()?;

    // Get last segment
    let filename = path.rsplit('/').next()?;

    // Get extension
    if let Some(dot_pos) = filename.rfind('.') {
      let ext = &filename[dot_pos + 1..];
      if !ext.is_empty() && ext.len() <= 10 {
        return Some(ext.to_lowercase());
      }
    }

    None
  }

  /// Simple pattern matching helper
  fn find_pattern(&self, text: &str, pattern: &str, start: usize) -> Option<usize> {
    // This is a simplified pattern matcher
    // For production, would use proper regex
    let search = pattern
      .replace(r"\s*", "")
      .replace(r"\(", "(")
      .replace(r#"["']"#, "\"");

    text[start..].find(&search).map(|pos| start + pos)
  }

  /// Get pattern length (simplified)
  fn pattern_len(&self, pattern: &str) -> usize {
    pattern
      .replace(r"\s*", "")
      .replace(r"\(", "(")
      .replace(r#"["']"#, "\"")
      .len()
  }
}

/// Builder for LinkExtractor
pub struct LinkExtractorBuilder {
  config: ExtractorConfig,
}

impl LinkExtractorBuilder {
  /// Create a new builder
  pub fn new() -> Self {
    Self {
      config: ExtractorConfig::default(),
    }
  }

  /// Enable/disable href extraction
  pub fn extract_href(mut self, enable: bool) -> Self {
    self.config.extract_href = enable;
    self
  }

  /// Enable/disable src extraction
  pub fn extract_src(mut self, enable: bool) -> Self {
    self.config.extract_src = enable;
    self
  }

  /// Enable/disable form extraction
  pub fn extract_forms(mut self, enable: bool) -> Self {
    self.config.extract_forms = enable;
    self
  }

  /// Enable/disable JavaScript extraction
  pub fn extract_javascript(mut self, enable: bool) -> Self {
    self.config.extract_javascript = enable;
    self
  }

  /// Include resource links
  pub fn include_resources(mut self, enable: bool) -> Self {
    self.config.include_resources = enable;
    self
  }

  /// Include image links
  pub fn include_images(mut self, enable: bool) -> Self {
    self.config.include_images = enable;
    self
  }

  /// Add exclude pattern
  pub fn exclude_pattern(mut self, pattern: impl Into<String>) -> Self {
    self.config.exclude_patterns.push(pattern.into());
    self
  }

  /// Add exclude extension
  pub fn exclude_extension(mut self, ext: impl Into<String>) -> Self {
    self.config.exclude_extensions.push(ext.into());
    self
  }

  /// Build the extractor
  pub fn build(self) -> LinkExtractor {
    LinkExtractor::new(self.config)
  }
}

impl Default for LinkExtractorBuilder {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_href_extraction() {
    let extractor = LinkExtractor::with_defaults();
    let html = r#"
            <a href="/admin">Admin</a>
            <a href="/dashboard">Dashboard</a>
            <a href="javascript:void(0)">Invalid</a>
        "#;

    let links = extractor.extract(html);

    assert!(links.iter().any(|l| l.url == "/admin"));
    assert!(links.iter().any(|l| l.url == "/dashboard"));
    // javascript: should be excluded
    assert!(!links.iter().any(|l| l.url.contains("javascript:")));
  }

  #[test]
  fn test_form_extraction() {
    let extractor = LinkExtractor::with_defaults();
    let html = r#"<form action="/login" method="POST"><input type="submit"></form>"#;

    let links = extractor.extract(html);

    assert!(links
      .iter()
      .any(|l| l.url == "/login" && l.source == LinkSource::Form));
  }

  #[test]
  fn test_javascript_extraction() {
    let extractor = LinkExtractor::with_defaults();
    let html = r#"
            <script>
                fetch('/api/users');
                window.location = '/redirect';
            </script>
        "#;

    let links = extractor.extract(html);

    assert!(links.iter().any(|l| l.url == "/api/users"));
    assert!(links.iter().any(|l| l.url == "/redirect"));
  }

  #[test]
  fn test_extension_filtering() {
    let extractor = LinkExtractor::with_defaults();
    let html = r#"
            <a href="/page.html">Page</a>
            <a href="/image.png">Image</a>
            <a href="/style.css">Style</a>
        "#;

    let links = extractor.extract(html);

    // .html should be included
    assert!(links.iter().any(|l| l.url == "/page.html"));
    // .png and .css should be excluded by default
    assert!(!links.iter().any(|l| l.url == "/image.png"));
    assert!(!links.iter().any(|l| l.url == "/style.css"));
  }

  #[test]
  fn test_data_attribute_extraction() {
    let extractor = LinkExtractor::with_defaults();
    let html = r#"<div data-url="/api/endpoint" data-href="/page"></div>"#;

    let links = extractor.extract(html);

    assert!(links.iter().any(|l| l.url == "/api/endpoint"));
    assert!(links.iter().any(|l| l.url == "/page"));
  }

  #[test]
  fn test_builder() {
    let extractor = LinkExtractorBuilder::new()
      .extract_href(true)
      .extract_javascript(false)
      .include_images(true)
      .build();

    let html = r#"
            <a href="/page">Link</a>
            <img src="/image.png">
        "#;

    let links = extractor.extract(html);

    assert!(links.iter().any(|l| l.url == "/page"));
    // Images included with builder config
    assert!(links.iter().any(|l| l.url == "/image.png"));
  }
}
