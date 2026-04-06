//! Recursive Scanner Coordinator
//!
//! Coordinates recursive content discovery by integrating the fuzzer
//! with link extraction, queue management, and scope enforcement.

use super::extractor::{ExtractedLink, ExtractorConfig, LinkExtractor, LinkSource};
use super::queue::{DiscoverySource, QueueConfig, QueuedUrl, RecursionQueue};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Result of scanning a single URL
#[derive(Debug, Clone)]
pub struct ScanResult {
  /// The scanned URL
  pub url: String,
  /// HTTP status code
  pub status_code: u16,
  /// Content length
  pub content_length: usize,
  /// Number of links extracted
  pub links_extracted: usize,
  /// Whether this was filtered (soft-404, duplicate, etc.)
  pub filtered: bool,
  /// Filter reason if filtered
  pub filter_reason: Option<String>,
  /// Recursion depth at which this was discovered
  pub depth: usize,
  /// Time taken to scan
  pub duration: Duration,
}

/// Discovered resource during scanning
#[derive(Debug, Clone)]
pub struct DiscoveredResource {
  /// The discovered URL
  pub url: String,
  /// HTTP status code
  pub status_code: u16,
  /// Content type
  pub content_type: Option<String>,
  /// Content length
  pub content_length: usize,
  /// Recursion depth
  pub depth: usize,
  /// Parent URL that led to this discovery
  pub parent: Option<String>,
  /// Discovery source
  pub source: String,
}

/// Configuration for recursive scanning
#[derive(Debug, Clone)]
pub struct RecursiveScanConfig {
  /// Queue configuration
  pub queue: QueueConfig,
  /// Link extractor configuration
  pub extractor: ExtractorConfig,
  /// Status codes to recurse into (extract links from)
  pub recurse_status_codes: Vec<u16>,
  /// Whether to extract links from responses
  pub extract_links: bool,
  /// Whether to add extracted links to queue
  pub follow_links: bool,
  /// Status codes to consider as "found"
  pub success_status_codes: Vec<u16>,
  /// Maximum concurrent requests (not implemented in scanner, handled externally)
  pub max_concurrent: usize,
  /// Request timeout
  pub timeout: Duration,
  /// Whether to discover directories from paths
  pub discover_directories: bool,
}

impl Default for RecursiveScanConfig {
  fn default() -> Self {
    Self {
      queue: QueueConfig::default(),
      extractor: ExtractorConfig::default(),
      recurse_status_codes: vec![200, 301, 302, 307, 308],
      extract_links: true,
      follow_links: true,
      success_status_codes: vec![200, 201, 204, 301, 302, 307, 308, 401, 403],
      max_concurrent: 10,
      timeout: Duration::from_secs(10),
      discover_directories: true,
    }
  }
}

impl RecursiveScanConfig {
  /// Configuration for shallow discovery
  pub fn shallow() -> Self {
    Self {
      queue: QueueConfig::shallow(),
      ..Default::default()
    }
  }

  /// Configuration for deep discovery
  pub fn deep() -> Self {
    Self {
      queue: QueueConfig::deep(),
      ..Default::default()
    }
  }

  /// Configuration for non-recursive (links only from seed)
  pub fn non_recursive() -> Self {
    Self {
      queue: QueueConfig {
        max_depth: 0,
        ..Default::default()
      },
      follow_links: false,
      ..Default::default()
    }
  }
}

/// Statistics for recursive scanning
#[derive(Debug, Clone, Default)]
pub struct RecursiveScanStats {
  /// Total requests made
  pub requests_made: usize,
  /// Successful responses (matching success codes)
  pub successful: usize,
  /// Filtered responses
  pub filtered: usize,
  /// Error responses (connection errors, timeouts)
  pub errors: usize,
  /// Total links extracted
  pub links_extracted: usize,
  /// Total unique URLs discovered
  pub urls_discovered: usize,
  /// URLs by status code
  pub by_status_code: HashMap<u16, usize>,
  /// URLs by depth
  pub by_depth: HashMap<usize, usize>,
  /// Scan duration
  pub duration: Duration,
  /// Requests per second (average)
  pub requests_per_second: f64,
}

/// Recursive scanner state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerState {
  /// Scanner is idle
  Idle,
  /// Scanner is running
  Running,
  /// Scanner is paused
  Paused,
  /// Scanner is complete
  Complete,
  /// Scanner encountered a fatal error
  Error,
}

/// Recursive scanner for content discovery
///
/// This is a coordinator that manages the scanning state and queue.
/// The actual HTTP requests should be performed by the caller.
pub struct RecursiveScanner {
  config: RecursiveScanConfig,
  queue: RecursionQueue,
  extractor: LinkExtractor,
  /// Current scanner state
  state: ScannerState,
  /// Scan start time
  start_time: Option<Instant>,
  /// Statistics
  stats: RecursiveScanStats,
  /// Discovered resources
  discovered: Vec<DiscoveredResource>,
  /// URL graph (parent -> children)
  graph: HashMap<String, Vec<String>>,
}

impl RecursiveScanner {
  /// Create a new recursive scanner
  pub fn new(config: RecursiveScanConfig) -> Self {
    let queue = RecursionQueue::new(config.queue.clone());
    let extractor = LinkExtractor::new(config.extractor.clone());

    Self {
      config,
      queue,
      extractor,
      state: ScannerState::Idle,
      start_time: None,
      stats: RecursiveScanStats::default(),
      discovered: Vec::new(),
      graph: HashMap::new(),
    }
  }

  /// Create with default configuration
  pub fn with_defaults() -> Self {
    Self::new(RecursiveScanConfig::default())
  }

  /// Add a seed URL to start scanning from
  pub fn add_seed(&mut self, url: &str) {
    self.queue.add_seed(url);
  }

  /// Start the scanner
  pub fn start(&mut self) {
    self.state = ScannerState::Running;
    self.start_time = Some(Instant::now());
  }

  /// Pause the scanner
  pub fn pause(&mut self) {
    if self.state == ScannerState::Running {
      self.state = ScannerState::Paused;
    }
  }

  /// Resume the scanner
  pub fn resume(&mut self) {
    if self.state == ScannerState::Paused {
      self.state = ScannerState::Running;
    }
  }

  /// Stop the scanner
  pub fn stop(&mut self) {
    self.state = ScannerState::Complete;
    self.update_stats_duration();
  }

  /// Get the current state
  pub fn state(&self) -> ScannerState {
    self.state
  }

  /// Get the next URL to scan
  ///
  /// Returns None if there are no more URLs or scanner is not running.
  pub fn next_url(&mut self) -> Option<QueuedUrl> {
    if self.state != ScannerState::Running {
      return None;
    }

    let url = self.queue.next();

    if url.is_none() && !self.queue.has_pending() {
      self.state = ScannerState::Complete;
      self.update_stats_duration();
    }

    url
  }

  /// Process a scan result
  ///
  /// This should be called after scanning each URL to:
  /// 1. Extract links from the response
  /// 2. Add discovered URLs to the queue
  /// 3. Update statistics
  pub fn process_result(
    &mut self,
    url: &str,
    depth: usize,
    status_code: u16,
    body: &str,
    content_type: Option<&str>,
    duration: Duration,
    filtered: bool,
    filter_reason: Option<String>,
  ) -> ScanResult {
    self.stats.requests_made += 1;
    *self.stats.by_status_code.entry(status_code).or_insert(0) += 1;
    *self.stats.by_depth.entry(depth).or_insert(0) += 1;

    let mut links_extracted = 0;

    // Track as discovered if successful
    if self.config.success_status_codes.contains(&status_code) && !filtered {
      self.stats.successful += 1;

      let discovered = DiscoveredResource {
        url: url.to_string(),
        status_code,
        content_type: content_type.map(|s| s.to_string()),
        content_length: body.len(),
        depth,
        parent: None, // Would need to track this
        source: "fuzzer".to_string(),
      };
      self.discovered.push(discovered);
      self.stats.urls_discovered += 1;
    }

    if filtered {
      self.stats.filtered += 1;
    }

    // Extract and follow links if configured
    if self.config.extract_links && self.config.recurse_status_codes.contains(&status_code) {
      let links = self.extractor.extract(body);
      links_extracted = links.len();
      self.stats.links_extracted += links.len();

      if self.config.follow_links && depth < self.config.queue.max_depth {
        self.add_extracted_links(url, depth, &links);
      }
    }

    // Discover directories from the URL path
    if self.config.discover_directories {
      self.discover_directories_from_url(url, depth);
    }

    ScanResult {
      url: url.to_string(),
      status_code,
      content_length: body.len(),
      links_extracted,
      filtered,
      filter_reason,
      depth,
      duration,
    }
  }

  /// Process an error result
  pub fn process_error(&mut self, url: &str, _error: &str) {
    self.stats.requests_made += 1;
    self.stats.errors += 1;
  }

  /// Add extracted links to the queue
  fn add_extracted_links(
    &mut self,
    parent_url: &str,
    parent_depth: usize,
    links: &[ExtractedLink],
  ) {
    let mut children = Vec::new();

    for link in links {
      let source = match link.source {
        LinkSource::Href => DiscoverySource::Href,
        LinkSource::Form => DiscoverySource::Form,
        LinkSource::JavaScript => DiscoverySource::JavaScript,
        _ => DiscoverySource::Href,
      };

      if self
        .queue
        .add_discovered(&link.url, parent_url, parent_depth, source)
      {
        children.push(link.url.clone());
      }
    }

    // Update graph
    if !children.is_empty() {
      self
        .graph
        .entry(parent_url.to_string())
        .or_insert_with(Vec::new)
        .extend(children);
    }
  }

  /// Discover directories from a URL path
  fn discover_directories_from_url(&mut self, url: &str, depth: usize) {
    // Extract path segments and add parent directories
    if let Some(path_start) = url.find("://") {
      let after_proto = &url[path_start + 3..];
      if let Some(slash_pos) = after_proto.find('/') {
        let origin = &url[..path_start + 3 + slash_pos];
        let path = &after_proto[slash_pos..];

        // Add each parent directory
        let mut current = path.to_string();
        while let Some(last_slash) = current[..current.len().saturating_sub(1)].rfind('/') {
          let dir_path = &current[..last_slash + 1];
          if dir_path == "/" {
            break;
          }

          let dir_url = format!("{}{}", origin, dir_path);
          self
            .queue
            .add_discovered(&dir_url, url, depth, DiscoverySource::InferredDir);

          current = dir_path.to_string();
        }
      }
    }
  }

  /// Get statistics
  pub fn stats(&self) -> &RecursiveScanStats {
    &self.stats
  }

  /// Get discovered resources
  pub fn discovered(&self) -> &[DiscoveredResource] {
    &self.discovered
  }

  /// Get the URL graph
  pub fn graph(&self) -> &HashMap<String, Vec<String>> {
    &self.graph
  }

  /// Get queue statistics
  pub fn queue_stats(&self) -> &super::queue::QueueStats {
    self.queue.stats()
  }

  /// Check if there are pending URLs
  pub fn has_pending(&self) -> bool {
    self.queue.has_pending()
  }

  /// Get pending URL count
  pub fn pending_count(&self) -> usize {
    self.queue.pending_count()
  }

  /// Mark a URL as visited without scanning
  pub fn skip_url(&mut self, url: &str) {
    self.queue.mark_visited(url);
  }

  /// Check if a URL has been visited
  pub fn is_visited(&self, url: &str) -> bool {
    self.queue.is_visited(url)
  }

  /// Get all pending URLs (for serialization/resume)
  pub fn pending_urls(&self) -> Vec<QueuedUrl> {
    self.queue.pending_urls()
  }

  /// Get all visited URLs (for serialization/resume)
  pub fn visited_urls(&self) -> Vec<String> {
    self.queue.visited_urls()
  }

  /// Restore scanner state
  pub fn restore(&mut self, pending: Vec<QueuedUrl>, visited: Vec<String>) {
    self.queue.restore(pending, visited);
  }

  /// Update duration in stats
  fn update_stats_duration(&mut self) {
    if let Some(start) = self.start_time {
      let duration = start.elapsed();
      self.stats.duration = duration;
      let secs = duration.as_secs_f64();
      if secs > 0.0 {
        self.stats.requests_per_second = self.stats.requests_made as f64 / secs;
      }
    }
  }

  /// Get configuration
  pub fn config(&self) -> &RecursiveScanConfig {
    &self.config
  }

  /// Update configuration (resets state)
  pub fn set_config(&mut self, config: RecursiveScanConfig) {
    self.config = config.clone();
    self.queue = RecursionQueue::new(config.queue.clone());
    self.extractor = LinkExtractor::new(config.extractor);
  }
}

/// Builder for RecursiveScanner
pub struct RecursiveScannerBuilder {
  config: RecursiveScanConfig,
  seeds: Vec<String>,
}

impl RecursiveScannerBuilder {
  /// Create a new builder
  pub fn new() -> Self {
    Self {
      config: RecursiveScanConfig::default(),
      seeds: Vec::new(),
    }
  }

  /// Set maximum recursion depth
  pub fn max_depth(mut self, depth: usize) -> Self {
    self.config.queue.max_depth = depth;
    self
  }

  /// Enable/disable link extraction
  pub fn extract_links(mut self, enable: bool) -> Self {
    self.config.extract_links = enable;
    self
  }

  /// Enable/disable link following
  pub fn follow_links(mut self, enable: bool) -> Self {
    self.config.follow_links = enable;
    self
  }

  /// Enable/disable same-origin policy
  pub fn same_origin(mut self, enable: bool) -> Self {
    self.config.queue.same_origin = enable;
    self
  }

  /// Enable/disable stay-in-scope
  pub fn stay_in_scope(mut self, enable: bool) -> Self {
    self.config.queue.stay_in_scope = enable;
    self
  }

  /// Set status codes that trigger recursion
  pub fn recurse_on(mut self, codes: Vec<u16>) -> Self {
    self.config.recurse_status_codes = codes;
    self
  }

  /// Set success status codes
  pub fn success_codes(mut self, codes: Vec<u16>) -> Self {
    self.config.success_status_codes = codes;
    self
  }

  /// Set request timeout
  pub fn timeout(mut self, timeout: Duration) -> Self {
    self.config.timeout = timeout;
    self
  }

  /// Add a seed URL
  pub fn add_seed(mut self, url: impl Into<String>) -> Self {
    self.seeds.push(url.into());
    self
  }

  /// Build the scanner
  pub fn build(self) -> RecursiveScanner {
    let mut scanner = RecursiveScanner::new(self.config);
    for seed in self.seeds {
      scanner.add_seed(&seed);
    }
    scanner
  }
}

impl Default for RecursiveScannerBuilder {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_basic_scanning() {
    let mut scanner = RecursiveScanner::with_defaults();
    scanner.add_seed("https://example.com/");
    scanner.start();

    // Get first URL
    let url = scanner.next_url().unwrap();
    assert_eq!(url.url, "https://example.com/");
    assert_eq!(url.depth, 0);

    // Process result with links
    let body = r#"<a href="/admin">Admin</a><a href="/api">API</a>"#;
    let result = scanner.process_result(
      &url.url,
      url.depth,
      200,
      body,
      Some("text/html"),
      Duration::from_millis(100),
      false,
      None,
    );

    assert_eq!(result.links_extracted, 2);
    assert_eq!(scanner.pending_count(), 2);
  }

  #[test]
  fn test_depth_tracking() {
    let mut scanner = RecursiveScannerBuilder::new()
      .max_depth(2)
      .add_seed("https://example.com/")
      .build();
    scanner.start();

    // Process seed
    let url = scanner.next_url().unwrap();
    let body = r#"<a href="/level1">Level 1</a>"#;
    scanner.process_result(
      &url.url,
      url.depth,
      200,
      body,
      None,
      Duration::ZERO,
      false,
      None,
    );

    // Process level 1
    let url = scanner.next_url().unwrap();
    assert_eq!(url.depth, 1);
    let body = r#"<a href="/level2">Level 2</a>"#;
    scanner.process_result(
      &url.url,
      url.depth,
      200,
      body,
      None,
      Duration::ZERO,
      false,
      None,
    );

    // Process level 2
    let url = scanner.next_url().unwrap();
    assert_eq!(url.depth, 2);
    // Level 2 links won't be added (depth limit)
    let body = r#"<a href="/level3">Level 3</a>"#;
    scanner.process_result(
      &url.url,
      url.depth,
      200,
      body,
      None,
      Duration::ZERO,
      false,
      None,
    );

    // No more URLs (level 3 wasn't added)
    assert!(!scanner.has_pending() || scanner.pending_count() == 0);
  }

  #[test]
  fn test_statistics() {
    let mut scanner = RecursiveScanner::with_defaults();
    scanner.add_seed("https://example.com/");
    scanner.start();

    let url = scanner.next_url().unwrap();
    scanner.process_result(
      &url.url,
      url.depth,
      200,
      "<a href='/page'>Link</a>",
      None,
      Duration::from_millis(50),
      false,
      None,
    );

    let stats = scanner.stats();
    assert_eq!(stats.requests_made, 1);
    assert_eq!(stats.successful, 1);
    assert_eq!(stats.links_extracted, 1);
  }

  #[test]
  fn test_builder() {
    let scanner = RecursiveScannerBuilder::new()
      .max_depth(5)
      .extract_links(true)
      .follow_links(true)
      .same_origin(true)
      .add_seed("https://example.com/")
      .build();

    assert_eq!(scanner.config().queue.max_depth, 5);
    assert!(scanner.has_pending());
  }

  #[test]
  fn test_state_transitions() {
    let mut scanner = RecursiveScanner::with_defaults();
    scanner.add_seed("https://example.com/");

    assert_eq!(scanner.state(), ScannerState::Idle);

    scanner.start();
    assert_eq!(scanner.state(), ScannerState::Running);

    scanner.pause();
    assert_eq!(scanner.state(), ScannerState::Paused);

    scanner.resume();
    assert_eq!(scanner.state(), ScannerState::Running);

    scanner.stop();
    assert_eq!(scanner.state(), ScannerState::Complete);
  }
}
