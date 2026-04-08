//! Path/directory enumeration for web targets
//!
//! Combines passive discovery (robots.txt, sitemap.xml, security.txt) with
//! active brute-force probing to enumerate paths and directories on a web
//! server.  Uses the shared parallel infrastructure for concurrent requests
//! and OPSEC-aware jitter to avoid burst detection.
//!
//! Replaces: dirsearch, dirb, gobuster dir, feroxbuster (passive+active modes)

use crate::modules::common::parallel;
use crate::protocols::http::{HttpClient, HttpRequest};
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How a path was discovered.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PathSource {
  /// Extracted from robots.txt (Allow / Disallow directives)
  Robots,
  /// Extracted from sitemap.xml or referenced sitemap files
  Sitemap,
  /// Extracted from /.well-known/security.txt
  SecurityTxt,
  /// Found via HTML link extraction on fetched pages
  HtmlLink,
  /// Found via JavaScript source extraction
  JsExtract,
  /// Discovered through active brute-force probing
  Brute,
}

/// A single discovered path with metadata.
#[derive(Debug, Clone)]
pub struct DiscoveredPath {
  /// Full URL (base + path)
  pub url: String,
  /// The path component (e.g. "/admin/")
  pub path: String,
  /// HTTP status code returned
  pub status: u16,
  /// Response body size in bytes
  pub size: usize,
  /// Content-Type header value
  pub content_type: String,
  /// Redirect target if status is 3xx
  pub redirect_to: Option<String>,
  /// How this path was found
  pub source: PathSource,
  /// Recursion depth (0 = top-level)
  pub depth: usize,
}

/// Configuration for path enumeration.
#[derive(Debug, Clone)]
pub struct PathEnumConfig {
  /// Number of concurrent threads for active probing
  pub threads: usize,
  /// HTTP request timeout
  pub timeout: Duration,
  /// File extensions to append (e.g. ["php", "html", "js"])
  pub extensions: Vec<String>,
  /// Whether to recurse into discovered directories
  pub recursive: bool,
  /// Maximum recursion depth
  pub max_depth: usize,
  /// Enable active brute-force probing
  pub brute: bool,
  /// Path to a custom wordlist file (None = use embedded)
  pub wordlist: Option<String>,
  /// Maximum jitter in milliseconds between requests
  pub jitter_ms: u64,
  /// Only show these status codes (empty = show all non-filtered)
  pub show_status: Vec<u16>,
  /// Hide these status codes
  pub hide_status: Vec<u16>,
}

impl Default for PathEnumConfig {
  fn default() -> Self {
    Self {
      threads: 10,
      timeout: Duration::from_secs(10),
      extensions: Vec::new(),
      recursive: false,
      max_depth: 3,
      brute: false,
      wordlist: None,
      jitter_ms: 0,
      show_status: Vec::new(),
      hide_status: vec![404],
    }
  }
}

// ---------------------------------------------------------------------------
// PathEnumerator
// ---------------------------------------------------------------------------

pub struct PathEnumerator {
  client: HttpClient,
  config: PathEnumConfig,
}

impl PathEnumerator {
  pub fn new(config: PathEnumConfig) -> Self {
    let client = HttpClient::new().with_timeout(config.timeout);
    Self { client, config }
  }

  /// Run full enumeration: passive discovery first, then optionally active
  /// brute-force.  Results are deduplicated by path.
  pub fn enumerate(&self, base_url: &str) -> Vec<DiscoveredPath> {
    let base = base_url.trim_end_matches('/');
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    // Phase 1: passive discovery (always runs)
    for item in self.passive_discovery(base) {
      if seen.insert(item.path.clone()) {
        results.push(item);
      }
    }

    // Phase 2: active brute-force (only when enabled)
    if self.config.brute || self.config.wordlist.is_some() {
      for item in self.active_discovery(base) {
        if seen.insert(item.path.clone()) {
          results.push(item);
        }
      }
    }

    // Apply status filters
    results
      .into_iter()
      .filter(|r| self.should_show(r.status))
      .collect()
  }

  // -------------------------------------------------------------------------
  // Phase 1: Passive discovery
  // -------------------------------------------------------------------------

  /// Passive discovery: parse robots.txt, sitemap.xml, and security.txt.
  /// These are read-only fetches of well-known files that every crawler is
  /// expected to request.
  fn passive_discovery(&self, base_url: &str) -> Vec<DiscoveredPath> {
    let mut results = Vec::new();
    results.extend(self.parse_robots_txt(base_url));
    results.extend(self.parse_sitemap(base_url));
    results.extend(self.parse_security_txt(base_url));
    results
  }

  /// Parse robots.txt for Disallow/Allow paths and Sitemap references.
  fn parse_robots_txt(&self, base_url: &str) -> Vec<DiscoveredPath> {
    let url = format!("{}/robots.txt", base_url);
    let response = match self.client.get(&url) {
      Ok(r) if r.status_code == 200 => r,
      _ => return Vec::new(),
    };

    let body = response.body_as_string();
    let mut results = Vec::new();
    let mut sitemap_urls = Vec::new();

    for line in body.lines() {
      let line = line.trim();

      // Skip comments and empty lines
      if line.is_empty() || line.starts_with('#') {
        continue;
      }

      // Extract Disallow / Allow paths
      if let Some(path) = Self::extract_robots_directive(line, "Disallow:") {
        if !path.is_empty() {
          results.push(self.make_discovered(base_url, &path, PathSource::Robots, 0, 0));
        }
      } else if let Some(path) = Self::extract_robots_directive(line, "Allow:") {
        if !path.is_empty() {
          results.push(self.make_discovered(base_url, &path, PathSource::Robots, 0, 0));
        }
      } else if let Some(sitemap) = Self::extract_robots_directive(line, "Sitemap:") {
        if !sitemap.is_empty() {
          sitemap_urls.push(sitemap.to_string());
        }
      }
    }

    // Follow Sitemap references found in robots.txt
    for sitemap_url in sitemap_urls {
      results.extend(self.parse_sitemap_url(&sitemap_url, 0));
    }

    results
  }

  /// Extract the value after a robots.txt directive (case-insensitive match).
  fn extract_robots_directive<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    let lower = line.to_ascii_lowercase();
    let directive_lower = directive.to_ascii_lowercase();
    if lower.starts_with(&directive_lower) {
      let value = line[directive.len()..].trim();
      // Strip inline comments
      let value = match value.find('#') {
        Some(idx) => value[..idx].trim(),
        None => value,
      };
      if value.is_empty() {
        None
      } else {
        Some(value)
      }
    } else {
      None
    }
  }

  /// Parse sitemap.xml (or a sitemap index) at the default location.
  fn parse_sitemap(&self, base_url: &str) -> Vec<DiscoveredPath> {
    let url = format!("{}/sitemap.xml", base_url);
    self.parse_sitemap_url(&url, 0)
  }

  /// Parse a sitemap at an arbitrary URL.  Handles both `<urlset>` (leaf
  /// sitemaps with `<loc>` entries) and `<sitemapindex>` (index files that
  /// reference other sitemaps).  Recursion depth is capped at 3 to avoid
  /// infinite loops.
  fn parse_sitemap_url(&self, url: &str, depth: usize) -> Vec<DiscoveredPath> {
    if depth > 3 {
      return Vec::new();
    }

    let response = match self.client.get(url) {
      Ok(r) if r.status_code == 200 => r,
      _ => return Vec::new(),
    };

    let body = response.body_as_string();
    let mut results = Vec::new();
    let mut child_sitemaps = Vec::new();

    // Extract all <loc>...</loc> values
    let locs = Self::extract_xml_tag_values(&body, "loc");

    // Determine if this is a sitemap index (contains <sitemapindex>) or a
    // regular urlset
    let is_index = body.contains("<sitemapindex") || body.contains("<sitemapindex>");

    for loc in locs {
      if is_index {
        // This is a sitemap index: the <loc> values point to child sitemaps
        child_sitemaps.push(loc);
      } else {
        // Regular sitemap: extract the path from the full URL
        let path = Self::url_to_path(&loc);
        if !path.is_empty() {
          results.push(self.make_discovered("", &loc, PathSource::Sitemap, 0, 0));
        }
      }
    }

    // Recursively fetch child sitemaps
    for child_url in child_sitemaps {
      results.extend(self.parse_sitemap_url(&child_url, depth + 1));
    }

    results
  }

  /// Minimal XML tag value extractor.  Finds all occurrences of
  /// `<tag>value</tag>` and returns the inner values.  This is intentionally
  /// simple -- we don't need a full XML parser for sitemap files.
  fn extract_xml_tag_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let mut values = Vec::new();
    let mut search_from = 0;

    while let Some(start) = xml[search_from..].find(&open) {
      let abs_start = search_from + start + open.len();
      if let Some(end) = xml[abs_start..].find(&close) {
        let value = xml[abs_start..abs_start + end].trim();
        if !value.is_empty() {
          values.push(value.to_string());
        }
        search_from = abs_start + end + close.len();
      } else {
        break;
      }
    }

    values
  }

  /// Fetch and parse /.well-known/security.txt for URLs and interesting
  /// fields (Contact, Policy, Acknowledgments, etc.).
  fn parse_security_txt(&self, base_url: &str) -> Vec<DiscoveredPath> {
    // Try well-known path first, then root fallback
    let urls = [
      format!("{}/.well-known/security.txt", base_url),
      format!("{}/security.txt", base_url),
    ];

    for url in &urls {
      if let Ok(response) = self.client.get(url) {
        if response.status_code == 200 {
          return self.parse_security_txt_body(base_url, &response.body_as_string());
        }
      }
    }

    Vec::new()
  }

  /// Parse the body of a security.txt file, extracting URLs from all fields.
  fn parse_security_txt_body(&self, base_url: &str, body: &str) -> Vec<DiscoveredPath> {
    let mut results = Vec::new();

    for line in body.lines() {
      let line = line.trim();
      if line.is_empty() || line.starts_with('#') {
        continue;
      }

      // Fields that commonly contain URLs
      let url_fields = [
        "Contact:",
        "Policy:",
        "Acknowledgments:",
        "Hiring:",
        "Canonical:",
      ];

      for field in &url_fields {
        if line
          .to_ascii_lowercase()
          .starts_with(&field.to_ascii_lowercase())
        {
          let value = line[field.len()..].trim();
          if value.starts_with("http://") || value.starts_with("https://") {
            let path = Self::url_to_path(value);
            if !path.is_empty() {
              results.push(self.make_discovered(base_url, &path, PathSource::SecurityTxt, 0, 0));
            }
          }
        }
      }

      // Also pick up bare URLs on their own line
      if line.starts_with("http://") || line.starts_with("https://") {
        let path = Self::url_to_path(line);
        if !path.is_empty() {
          results.push(self.make_discovered(base_url, &path, PathSource::SecurityTxt, 0, 0));
        }
      }
    }

    results
  }

  // -------------------------------------------------------------------------
  // Phase 2: Active brute-force
  // -------------------------------------------------------------------------

  /// Active brute-force discovery using wordlists and the parallel
  /// infrastructure.  Calibrates a soft-404 baseline first, then probes
  /// every word (plus extension variants) concurrently.
  fn active_discovery(&self, base_url: &str) -> Vec<DiscoveredPath> {
    let words = self.load_wordlist();
    let baseline = self.calibrate_baseline(base_url);
    let results: Mutex<Vec<DiscoveredPath>> = Mutex::new(Vec::new());

    // Build the full path list: each word + extension variants
    let mut paths = Vec::new();
    for word in &words {
      paths.push(word.clone());
      for ext in &self.config.extensions {
        paths.push(format!("{}.{}", word, ext));
      }
    }

    let base = base_url.to_string();
    let bl = baseline.unwrap_or((404, 0));

    parallel::run_with_jitter(self.config.threads, self.config.jitter_ms, &paths, |path| {
      if let Some(result) = self.probe_path(&base, path) {
        if !self.is_soft_404(result.status, result.size, &bl) {
          results.lock().unwrap().push(result);
        }
      }
    });

    results.into_inner().unwrap()
  }

  /// Auto-calibrate the soft-404 baseline by requesting a path that is
  /// extremely unlikely to exist.  Returns (status_code, body_size) of the
  /// "not found" response so we can detect custom error pages that return
  /// 200 OK.
  fn calibrate_baseline(&self, base_url: &str) -> Option<(u16, usize)> {
    // Use a random-looking path that no real site would have
    let canary_paths = ["/__rb_404_calibration_a1b2c3", "/__rb_nonexistent_d4e5f6g7"];

    let mut baselines = Vec::new();

    for canary in &canary_paths {
      let url = format!("{}{}", base_url, canary);
      if let Ok(response) = self.client.get(&url) {
        baselines.push((response.status_code, response.body.len()));
      }
    }

    if baselines.is_empty() {
      return None;
    }

    // If both canaries return the same status and similar size, use that
    // as the baseline.  Otherwise fall back to the first result.
    if baselines.len() >= 2 && baselines[0].0 == baselines[1].0 {
      let avg_size = (baselines[0].1 + baselines[1].1) / 2;
      Some((baselines[0].0, avg_size))
    } else {
      Some(baselines[0])
    }
  }

  /// Load the wordlist -- either from a user-supplied file or from the
  /// embedded default lists.
  fn load_wordlist(&self) -> Vec<String> {
    if let Some(ref path) = self.config.wordlist {
      std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
    } else {
      let dirs = include_str!("../../wordlists/embedded/directories-common.txt");
      let files = include_str!("../../wordlists/embedded/files-common.txt");
      dirs
        .lines()
        .chain(files.lines())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
    }
  }

  /// Probe a single path and return a `DiscoveredPath` if the server
  /// responds (regardless of status code -- filtering happens upstream).
  fn probe_path(&self, base_url: &str, path: &str) -> Option<DiscoveredPath> {
    let normalized = if path.starts_with('/') {
      path.to_string()
    } else {
      format!("/{}", path)
    };

    let url = format!("{}{}", base_url, normalized);
    let request = HttpRequest::get(&url);

    match self.client.send_no_redirect(&request) {
      Ok(response) => {
        let content_type = response
          .headers
          .get("Content-Type")
          .or_else(|| response.headers.get("content-type"))
          .cloned()
          .unwrap_or_default();

        let redirect_to = if (300..400).contains(&response.status_code) {
          response
            .headers
            .get("Location")
            .or_else(|| response.headers.get("location"))
            .cloned()
        } else {
          None
        };

        Some(DiscoveredPath {
          url,
          path: normalized,
          status: response.status_code,
          size: response.body.len(),
          content_type,
          redirect_to,
          source: PathSource::Brute,
          depth: 0,
        })
      }
      Err(_) => None,
    }
  }

  /// Heuristic soft-404 detection.  Compares the response against the
  /// calibrated baseline.  A response is considered a soft-404 if it has
  /// the same status code as the baseline and the body size is within 10%
  /// (plus a small absolute tolerance of 50 bytes).
  fn is_soft_404(&self, status: u16, size: usize, baseline: &(u16, usize)) -> bool {
    if status == baseline.0 {
      let size_diff = (size as i64 - baseline.1 as i64).unsigned_abs() as usize;
      // Allow 10% size variation plus 50 bytes absolute tolerance
      size_diff < baseline.1 / 10 + 50
    } else {
      false
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /// Check whether a status code should be included in results based on
  /// the show/hide filter configuration.
  fn should_show(&self, status: u16) -> bool {
    // If show_status is set, only include those codes
    if !self.config.show_status.is_empty() {
      return self.config.show_status.contains(&status);
    }
    // Otherwise, exclude codes in hide_status
    !self.config.hide_status.contains(&status)
  }

  /// Build a `DiscoveredPath` from minimal info (used by passive discovery
  /// where we don't actually fetch the path).
  fn make_discovered(
    &self,
    base_url: &str,
    path: &str,
    source: PathSource,
    status: u16,
    size: usize,
  ) -> DiscoveredPath {
    let normalized = if path.starts_with("http://") || path.starts_with("https://") {
      // It's a full URL -- extract path component
      let extracted = Self::url_to_path(path);
      DiscoveredPath {
        url: path.to_string(),
        path: extracted,
        status,
        size,
        content_type: String::new(),
        redirect_to: None,
        source,
        depth: 0,
      }
    } else {
      let norm = if path.starts_with('/') {
        path.to_string()
      } else {
        format!("/{}", path)
      };
      DiscoveredPath {
        url: format!("{}{}", base_url, norm),
        path: norm,
        status,
        size,
        content_type: String::new(),
        redirect_to: None,
        source,
        depth: 0,
      }
    };

    normalized
  }

  /// Extract the path component from a full URL.
  /// e.g. "https://example.com/blog/post" -> "/blog/post"
  fn url_to_path(url: &str) -> String {
    // Strip scheme
    let without_scheme = if let Some(pos) = url.find("://") {
      &url[pos + 3..]
    } else {
      url
    };

    // Find start of path (first '/' after host)
    match without_scheme.find('/') {
      Some(pos) => without_scheme[pos..].to_string(),
      None => "/".to_string(),
    }
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_robots_txt_disallow() {
    let body = "\
User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Allow: /api/public/
Disallow: /secret
";

    let mut paths = Vec::new();
    for line in body.lines() {
      let line = line.trim();
      if let Some(path) = PathEnumerator::extract_robots_directive(line, "Disallow:") {
        if !path.is_empty() {
          paths.push(path.to_string());
        }
      }
    }

    assert_eq!(paths.len(), 3);
    assert!(paths.contains(&"/admin/".to_string()));
    assert!(paths.contains(&"/api/internal/".to_string()));
    assert!(paths.contains(&"/secret".to_string()));
  }

  #[test]
  fn test_parse_robots_txt_allow() {
    let body = "\
User-agent: *
Allow: /api/public/
Allow: /images/
";

    let mut paths = Vec::new();
    for line in body.lines() {
      let line = line.trim();
      if let Some(path) = PathEnumerator::extract_robots_directive(line, "Allow:") {
        if !path.is_empty() {
          paths.push(path.to_string());
        }
      }
    }

    assert_eq!(paths.len(), 2);
    assert!(paths.contains(&"/api/public/".to_string()));
    assert!(paths.contains(&"/images/".to_string()));
  }

  #[test]
  fn test_parse_robots_txt_sitemap_ref() {
    let body = "\
User-agent: *
Disallow: /admin/
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap-news.xml
";

    let mut sitemaps = Vec::new();
    for line in body.lines() {
      let line = line.trim();
      if let Some(url) = PathEnumerator::extract_robots_directive(line, "Sitemap:") {
        if !url.is_empty() {
          sitemaps.push(url.to_string());
        }
      }
    }

    assert_eq!(sitemaps.len(), 2);
    assert!(sitemaps.contains(&"https://example.com/sitemap.xml".to_string()));
    assert!(sitemaps.contains(&"https://example.com/sitemap-news.xml".to_string()));
  }

  #[test]
  fn test_robots_directive_case_insensitive() {
    assert!(PathEnumerator::extract_robots_directive("disallow: /admin/", "Disallow:").is_some());
    assert!(PathEnumerator::extract_robots_directive("DISALLOW: /admin/", "Disallow:").is_some());
    assert!(
      PathEnumerator::extract_robots_directive("Disallow: /admin/", "Disallow:") == Some("/admin/")
    );
  }

  #[test]
  fn test_robots_directive_with_inline_comment() {
    let result =
      PathEnumerator::extract_robots_directive("Disallow: /secret # this is hidden", "Disallow:");
    assert_eq!(result, Some("/secret"));
  }

  #[test]
  fn test_parse_sitemap_loc() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/page1</loc></url>
  <url><loc>https://example.com/page2</loc></url>
  <url><loc>https://example.com/blog/post-1</loc></url>
</urlset>"#;

    let locs = PathEnumerator::extract_xml_tag_values(xml, "loc");
    assert_eq!(locs.len(), 3);
    assert_eq!(locs[0], "https://example.com/page1");
    assert_eq!(locs[1], "https://example.com/page2");
    assert_eq!(locs[2], "https://example.com/blog/post-1");
  }

  #[test]
  fn test_parse_sitemap_index() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
</sitemapindex>"#;

    let locs = PathEnumerator::extract_xml_tag_values(xml, "loc");
    assert_eq!(locs.len(), 2);
    assert!(xml.contains("<sitemapindex"));
  }

  #[test]
  fn test_parse_xml_empty_tags() {
    let xml = "<root><loc></loc><loc>value</loc></root>";
    let locs = PathEnumerator::extract_xml_tag_values(xml, "loc");
    // Empty <loc></loc> is skipped, only "value" is returned
    assert_eq!(locs.len(), 1);
    assert_eq!(locs[0], "value");
  }

  #[test]
  fn test_load_embedded_wordlist() {
    let config = PathEnumConfig::default();
    let enumerator = PathEnumerator::new(config);
    let words = enumerator.load_wordlist();

    // Should load entries from both embedded files (excluding comments/blanks)
    assert!(!words.is_empty(), "embedded wordlist must not be empty");
    // Should not contain comment lines
    assert!(
      !words.iter().any(|w| w.starts_with('#')),
      "comments must be filtered"
    );
    // Should not contain blank lines
    assert!(
      !words.iter().any(|w| w.is_empty()),
      "blank lines must be filtered"
    );
    // Sanity: should contain well-known paths
    assert!(
      words.iter().any(|w| w == "admin"),
      "should contain 'admin' from directories list"
    );
    assert!(
      words.iter().any(|w| w == "robots.txt"),
      "should contain 'robots.txt' from files list"
    );
  }

  #[test]
  fn test_load_file_wordlist() {
    let dir = std::env::temp_dir();
    let path = dir.join("rb-test-wordlist.txt");
    std::fs::write(
      &path,
      "# comment\nadmin\nlogin\n\napi\n# another comment\ndashboard\n",
    )
    .unwrap();

    let config = PathEnumConfig {
      wordlist: Some(path.to_string_lossy().to_string()),
      ..PathEnumConfig::default()
    };
    let enumerator = PathEnumerator::new(config);
    let words = enumerator.load_wordlist();

    assert_eq!(words, vec!["admin", "login", "api", "dashboard"]);

    // Clean up
    let _ = std::fs::remove_file(&path);
  }

  #[test]
  fn test_soft_404_detection() {
    let config = PathEnumConfig::default();
    let enumerator = PathEnumerator::new(config);
    let baseline = (200, 5000); // Soft-404 returns 200 with ~5000 bytes

    // Exact match -- clearly a soft-404
    assert!(enumerator.is_soft_404(200, 5000, &baseline));

    // Within 10% + 50 tolerance
    assert!(enumerator.is_soft_404(200, 5040, &baseline));
    assert!(enumerator.is_soft_404(200, 4960, &baseline));

    // Outside tolerance
    assert!(!enumerator.is_soft_404(200, 6000, &baseline));

    // Different status code -- not a soft-404
    assert!(!enumerator.is_soft_404(301, 5000, &baseline));
    assert!(!enumerator.is_soft_404(403, 5000, &baseline));

    // Standard 404 baseline
    let baseline_404 = (404, 0);
    assert!(enumerator.is_soft_404(404, 20, &baseline_404));
    assert!(!enumerator.is_soft_404(200, 20, &baseline_404));
  }

  #[test]
  fn test_extension_expansion() {
    // Verify extension expansion logic without network
    let extensions = vec!["php".to_string(), "html".to_string(), "js".to_string()];
    let words = vec!["admin".to_string(), "login".to_string()];

    let mut paths = Vec::new();
    for word in &words {
      paths.push(word.clone());
      for ext in &extensions {
        paths.push(format!("{}.{}", word, ext));
      }
    }

    assert_eq!(paths.len(), 8); // 2 words * (1 base + 3 extensions)
    assert_eq!(
      paths,
      vec![
        "admin",
        "admin.php",
        "admin.html",
        "admin.js",
        "login",
        "login.php",
        "login.html",
        "login.js",
      ]
    );
  }

  #[test]
  fn test_default_config() {
    let config = PathEnumConfig::default();
    assert_eq!(config.threads, 10);
    assert_eq!(config.timeout, Duration::from_secs(10));
    assert!(config.extensions.is_empty());
    assert!(!config.recursive);
    assert_eq!(config.max_depth, 3);
    assert!(!config.brute);
    assert!(config.wordlist.is_none());
    assert_eq!(config.jitter_ms, 0);
    assert!(config.show_status.is_empty());
    assert_eq!(config.hide_status, vec![404]);
  }

  #[test]
  fn test_passive_only_by_default() {
    // With default config (brute=false, wordlist=None), active discovery
    // should NOT run.  We verify this by checking that the config gate
    // would block it.
    let config = PathEnumConfig::default();
    assert!(!config.brute);
    assert!(config.wordlist.is_none());
    // The enumerate() method checks: if self.config.brute || self.config.wordlist.is_some()
    // With defaults both are false/None, so active_discovery is skipped.
  }

  #[test]
  fn test_status_filter_show() {
    let config = PathEnumConfig {
      show_status: vec![200, 301],
      hide_status: Vec::new(),
      ..PathEnumConfig::default()
    };
    let enumerator = PathEnumerator::new(config);

    assert!(enumerator.should_show(200));
    assert!(enumerator.should_show(301));
    assert!(!enumerator.should_show(403));
    assert!(!enumerator.should_show(404));
    assert!(!enumerator.should_show(500));
  }

  #[test]
  fn test_status_filter_hide() {
    let config = PathEnumConfig {
      show_status: Vec::new(),
      hide_status: vec![404, 403],
      ..PathEnumConfig::default()
    };
    let enumerator = PathEnumerator::new(config);

    assert!(enumerator.should_show(200));
    assert!(enumerator.should_show(301));
    assert!(!enumerator.should_show(403));
    assert!(!enumerator.should_show(404));
    assert!(enumerator.should_show(500));
  }

  #[test]
  fn test_status_filter_show_takes_precedence() {
    // When show_status is set, hide_status is ignored
    let config = PathEnumConfig {
      show_status: vec![200],
      hide_status: vec![200], // contradicts show, but show wins
      ..PathEnumConfig::default()
    };
    let enumerator = PathEnumerator::new(config);

    assert!(enumerator.should_show(200));
    assert!(!enumerator.should_show(301));
  }

  #[test]
  fn test_url_to_path() {
    assert_eq!(
      PathEnumerator::url_to_path("https://example.com/blog/post"),
      "/blog/post"
    );
    assert_eq!(PathEnumerator::url_to_path("http://example.com/"), "/");
    assert_eq!(PathEnumerator::url_to_path("https://example.com"), "/");
    assert_eq!(
      PathEnumerator::url_to_path("https://example.com:8080/api/v1"),
      "/api/v1"
    );
    assert_eq!(
      PathEnumerator::url_to_path("/already/a/path"),
      "/already/a/path"
    );
  }

  #[test]
  fn test_make_discovered_full_url() {
    let config = PathEnumConfig::default();
    let enumerator = PathEnumerator::new(config);

    let result = enumerator.make_discovered(
      "https://example.com",
      "https://example.com/blog/post",
      PathSource::Sitemap,
      200,
      1024,
    );

    assert_eq!(result.url, "https://example.com/blog/post");
    assert_eq!(result.path, "/blog/post");
    assert_eq!(result.source, PathSource::Sitemap);
  }

  #[test]
  fn test_make_discovered_relative_path() {
    let config = PathEnumConfig::default();
    let enumerator = PathEnumerator::new(config);

    let result =
      enumerator.make_discovered("https://example.com", "/admin/", PathSource::Robots, 0, 0);

    assert_eq!(result.url, "https://example.com/admin/");
    assert_eq!(result.path, "/admin/");
  }

  #[test]
  fn test_make_discovered_bare_path() {
    let config = PathEnumConfig::default();
    let enumerator = PathEnumerator::new(config);

    let result =
      enumerator.make_discovered("https://example.com", "admin", PathSource::Brute, 200, 512);

    assert_eq!(result.url, "https://example.com/admin");
    assert_eq!(result.path, "/admin");
  }

  #[test]
  fn test_security_txt_body_parsing() {
    let body = "\
# Security contact
Contact: https://example.com/security
Policy: https://example.com/security-policy
Hiring: https://example.com/careers
Acknowledgments: https://example.com/thanks

# Not a URL
Preferred-Languages: en
";

    let config = PathEnumConfig::default();
    let enumerator = PathEnumerator::new(config);
    let results = enumerator.parse_security_txt_body("https://example.com", body);

    let paths: Vec<&str> = results.iter().map(|r| r.path.as_str()).collect();
    assert!(paths.contains(&"/security"));
    assert!(paths.contains(&"/security-policy"));
    assert!(paths.contains(&"/careers"));
    assert!(paths.contains(&"/thanks"));
    assert_eq!(results.len(), 4);
    assert!(results.iter().all(|r| r.source == PathSource::SecurityTxt));
  }
}
