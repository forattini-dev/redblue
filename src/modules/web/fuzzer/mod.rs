/// Web Fuzzing Engine
///
/// Replaces: ffuf, gobuster, dirbuster, feroxbuster
///
/// Implements Phase 2.1 Web Fuzzing Engine:
/// - FUZZ keyword parsing and placement
/// - Multiple attack modes (sniper, clusterbomb, pitchfork)
/// - Response filtering (size, code, words, lines, regex)
/// - Auto-calibration baseline
/// - Recursive directory discovery
/// - Rate limiting and delay controls
///
/// NO external dependencies - pure Rust implementation
use crate::protocols::http::HttpClient;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub mod filters;
pub mod modes;
pub mod ratelimit;
pub mod resume;
pub mod simhash;
pub mod similarity;
pub mod wordlist;

pub use filters::{FilterAction, ResponseFilter};
pub use modes::{AttackMode, FuzzPosition};
pub use ratelimit::{
  AdaptiveRateLimiter, RateLimitConfig, RateLimitResult, RateLimitStats, RateLimiterBuilder,
  TargetRateLimiter,
};
pub use resume::{
  Checkpoint, CheckpointInfo, CheckpointStats, ResumeConfig, ResumeManager, ResumeManagerBuilder,
  ScanId,
};
pub use simhash::{Simhash, SimhashCalculator, SimhashConfig, SimhashIndex};
pub use similarity::{SimilarityConfig, SimilarityFilter, SimilarityResult, Soft404Detector};
pub use wordlist::WordlistManager;

/// The FUZZ keyword used as placeholder in URLs, headers, body, etc.
pub const FUZZ_KEYWORD: &str = "FUZZ";

// Re-export types defined in this module
// WebFuzzer is defined below in this file

/// Fuzzing target configuration
#[derive(Debug, Clone)]
pub struct FuzzTarget {
  /// Base URL with FUZZ placeholders
  pub url: String,
  /// HTTP method
  pub method: HttpMethod,
  /// Request headers with optional FUZZ placeholders
  pub headers: Vec<(String, String)>,
  /// Request body with optional FUZZ placeholder
  pub body: Option<String>,
  /// Cookie header with optional FUZZ placeholder
  pub cookies: Option<String>,
}

/// HTTP methods
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HttpMethod {
  GET,
  POST,
  PUT,
  DELETE,
  PATCH,
  HEAD,
  OPTIONS,
}

impl HttpMethod {
  pub fn as_str(&self) -> &str {
    match self {
      HttpMethod::GET => "GET",
      HttpMethod::POST => "POST",
      HttpMethod::PUT => "PUT",
      HttpMethod::DELETE => "DELETE",
      HttpMethod::PATCH => "PATCH",
      HttpMethod::HEAD => "HEAD",
      HttpMethod::OPTIONS => "OPTIONS",
    }
  }
}

impl std::str::FromStr for HttpMethod {
  type Err = String;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s.to_uppercase().as_str() {
      "GET" => Ok(HttpMethod::GET),
      "POST" => Ok(HttpMethod::POST),
      "PUT" => Ok(HttpMethod::PUT),
      "DELETE" => Ok(HttpMethod::DELETE),
      "PATCH" => Ok(HttpMethod::PATCH),
      "HEAD" => Ok(HttpMethod::HEAD),
      "OPTIONS" => Ok(HttpMethod::OPTIONS),
      _ => Err(format!("Unknown HTTP method: {}", s)),
    }
  }
}

/// Fuzzer configuration
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
  /// Number of concurrent threads
  pub threads: usize,
  /// Request timeout
  pub timeout: Duration,
  /// Delay between requests (per thread)
  pub delay: Duration,
  /// Maximum requests per second (0 = unlimited)
  pub rate_limit: u32,
  /// Follow redirects
  pub follow_redirects: bool,
  /// Maximum redirect depth
  pub max_redirects: u8,
  /// Auto-calibrate filters
  pub auto_calibrate: bool,
  /// Recursive directory discovery
  pub recursive: bool,
  /// Maximum recursion depth
  pub max_depth: u8,
  /// Extensions to append (e.g., [".php", ".html"])
  pub extensions: Vec<String>,
  /// Attack mode
  pub mode: AttackMode,
  /// Response filters
  pub filters: Vec<ResponseFilter>,
  /// User-Agent header
  pub user_agent: String,
  /// Verbose output
  pub verbose: bool,
}

impl Default for FuzzerConfig {
  fn default() -> Self {
    Self {
      threads: 40,
      timeout: Duration::from_secs(10),
      delay: Duration::ZERO,
      rate_limit: 0,
      follow_redirects: false,
      max_redirects: 5,
      auto_calibrate: true,
      recursive: false,
      max_depth: 3,
      extensions: Vec::new(),
      mode: AttackMode::Sniper,
      filters: Vec::new(),
      user_agent: "redblue/1.0".to_string(),
      verbose: false,
    }
  }
}

/// Single fuzz result
#[derive(Debug, Clone)]
pub struct FuzzResult {
  /// The payload used
  pub payload: String,
  /// Full URL requested
  pub url: String,
  /// HTTP status code
  pub status_code: u16,
  /// Response size in bytes
  pub size: usize,
  /// Number of words in response
  pub words: usize,
  /// Number of lines in response
  pub lines: usize,
  /// Response time
  pub duration: Duration,
  /// Whether this result was filtered
  pub filtered: bool,
  /// Redirect location if any
  pub redirect: Option<String>,
  /// Content type
  pub content_type: Option<String>,
}

/// Fuzzing statistics
#[derive(Debug, Clone, Default)]
pub struct FuzzStats {
  /// Total requests sent
  pub total_requests: usize,
  /// Successful (non-filtered) results
  pub hits: usize,
  /// Filtered results
  pub filtered: usize,
  /// Error count
  pub errors: usize,
  /// Start time
  pub start_time: Option<Instant>,
  /// Requests per second
  pub rps: f64,
}

/// Main web fuzzer
pub struct WebFuzzer {
  config: FuzzerConfig,
  http: HttpClient,
  results: Arc<Mutex<Vec<FuzzResult>>>,
  stats: Arc<Mutex<FuzzStats>>,
  baseline: Option<FuzzResult>,
}

impl WebFuzzer {
  pub fn new(config: FuzzerConfig) -> Self {
    Self {
      config,
      http: HttpClient::new(),
      results: Arc::new(Mutex::new(Vec::new())),
      stats: Arc::new(Mutex::new(FuzzStats::default())),
      baseline: None,
    }
  }

  /// Parse FUZZ positions from target
  pub fn parse_fuzz_positions(target: &FuzzTarget) -> Vec<FuzzPosition> {
    let mut positions = Vec::new();
    const FUZZ_KEYWORD: &str = "FUZZ";

    // Check URL
    if target.url.contains(FUZZ_KEYWORD) {
      if target.url.contains('?')
        && target
          .url
          .split('?')
          .nth(1)
          .map(|q| q.contains(FUZZ_KEYWORD))
          .unwrap_or(false)
      {
        positions.push(FuzzPosition::QueryParam);
      } else {
        positions.push(FuzzPosition::UrlPath);
      }
    }

    // Check headers
    for (name, value) in &target.headers {
      if name.contains(FUZZ_KEYWORD) || value.contains(FUZZ_KEYWORD) {
        positions.push(FuzzPosition::Header(name.clone()));
      }
    }

    // Check body
    if let Some(ref body) = target.body {
      if body.contains(FUZZ_KEYWORD) {
        positions.push(FuzzPosition::Body);
      }
    }

    // Check cookies
    if let Some(ref cookies) = target.cookies {
      if cookies.contains(FUZZ_KEYWORD) {
        positions.push(FuzzPosition::Cookie);
      }
    }

    positions
  }

  /// Auto-calibrate baseline response
  pub fn calibrate(&mut self, target: &FuzzTarget) -> Result<(), String> {
    // Send request with random non-existent payload
    let random_payload = format!("rb_calibrate_{}", std::process::id());
    let calibration_url = target.url.replace("FUZZ", &random_payload);

    let response = self
      .http
      .get(&calibration_url)
      .map_err(|e| format!("Calibration request failed: {}", e))?;

    let body = String::from_utf8_lossy(&response.body);

    self.baseline = Some(FuzzResult {
      payload: random_payload,
      url: calibration_url,
      status_code: response.status_code,
      size: response.body.len(),
      words: body.split_whitespace().count(),
      lines: body.lines().count(),
      duration: Duration::ZERO,
      filtered: false,
      redirect: response
        .headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "location")
        .map(|(_, v)| v.clone()),
      content_type: response
        .headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "content-type")
        .map(|(_, v)| v.clone()),
    });

    Ok(())
  }

  /// Run fuzzing with given wordlist
  pub fn fuzz(
    &mut self,
    target: &FuzzTarget,
    wordlist: &[String],
  ) -> Result<Vec<FuzzResult>, String> {
    // Auto-calibrate if enabled
    if self.config.auto_calibrate && self.baseline.is_none() {
      self.calibrate(target)?;
    }

    // Initialize stats
    {
      let mut stats = self.stats.lock().unwrap();
      stats.start_time = Some(Instant::now());
      stats.total_requests = wordlist.len();
    }

    // Build request queue with extensions
    let mut queue: Vec<String> = Vec::new();
    for word in wordlist {
      queue.push(word.clone());

      // Add variations with extensions
      for ext in &self.config.extensions {
        queue.push(format!("{}{}", word, ext));
      }
    }

    // Split into chunks for threading
    let chunk_size = queue.len().div_ceil(self.config.threads);
    let chunks: Vec<Vec<String>> = queue.chunks(chunk_size).map(|c| c.to_vec()).collect();

    let mut handles = vec![];

    for chunk in chunks {
      let target = target.clone();
      let config = self.config.clone();
      let results = Arc::clone(&self.results);
      let stats = Arc::clone(&self.stats);
      let baseline = self.baseline.clone();
      let filters = self.config.filters.clone();

      let handle = thread::spawn(move || {
        let http = HttpClient::new();

        for payload in chunk {
          // Apply delay if configured
          if !config.delay.is_zero() {
            thread::sleep(config.delay);
          }

          // Build request URL
          let url = target.url.replace("FUZZ", &payload);

          // Send request
          let start = Instant::now();
          let response = match target.method {
            HttpMethod::GET | HttpMethod::HEAD => http.get(&url),
            HttpMethod::POST => {
              let body = target
                .body
                .as_ref()
                .map(|b| b.replace("FUZZ", &payload))
                .unwrap_or_default();
              http.post(&url, body.into_bytes())
            }
            _ => http.get(&url), // Fallback
          };
          let duration = start.elapsed();

          match response {
            Ok(resp) => {
              let body_str = String::from_utf8_lossy(&resp.body);

              let result = FuzzResult {
                payload: payload.clone(),
                url: url.clone(),
                status_code: resp.status_code,
                size: resp.body.len(),
                words: body_str.split_whitespace().count(),
                lines: body_str.lines().count(),
                duration,
                filtered: false,
                redirect: resp
                  .headers
                  .iter()
                  .find(|(k, _)| k.to_lowercase() == "location")
                  .map(|(_, v)| v.clone()),
                content_type: resp
                  .headers
                  .iter()
                  .find(|(k, _)| k.to_lowercase() == "content-type")
                  .map(|(_, v)| v.clone()),
              };

              // Check if result should be filtered
              let should_filter = Self::should_filter(&result, &filters, &baseline);

              if !should_filter {
                if let Ok(mut results) = results.lock() {
                  results.push(result);
                }
                if let Ok(mut stats) = stats.lock() {
                  stats.hits += 1;
                }
              } else {
                if let Ok(mut stats) = stats.lock() {
                  stats.filtered += 1;
                }
              }
            }
            Err(_) => {
              if let Ok(mut stats) = stats.lock() {
                stats.errors += 1;
              }
            }
          }
        }
      });

      handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
      let _ = handle.join();
    }

    // Calculate RPS
    {
      let mut stats = self.stats.lock().unwrap();
      if let Some(start) = stats.start_time {
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
          stats.rps = stats.total_requests as f64 / elapsed;
        }
      }
    }

    let results = self.results.lock().unwrap().clone();
    Ok(results)
  }

  /// Check if result should be filtered out
  fn should_filter(
    result: &FuzzResult,
    filters: &[ResponseFilter],
    baseline: &Option<FuzzResult>,
  ) -> bool {
    // Check explicit filters
    for filter in filters {
      match filter.matches(result) {
        FilterAction::Include => return false,
        FilterAction::Exclude => return true,
        FilterAction::None => continue,
      }
    }

    // Check against baseline if available
    if let Some(ref base) = baseline {
      // Filter if matches baseline response
      if result.status_code == base.status_code
        && result.size == base.size
        && result.lines == base.lines
      {
        return true;
      }
    }

    false
  }

  /// Get current stats
  pub fn stats(&self) -> FuzzStats {
    self.stats.lock().unwrap().clone()
  }

  /// Get all results
  pub fn results(&self) -> Vec<FuzzResult> {
    self.results.lock().unwrap().clone()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_fuzz_positions() {
    let target = FuzzTarget {
      url: "http://example.com/FUZZ".to_string(),
      method: HttpMethod::GET,
      headers: vec![],
      body: None,
      cookies: None,
    };

    let positions = WebFuzzer::parse_fuzz_positions(&target);
    assert!(positions.contains(&FuzzPosition::UrlPath));
  }

  #[test]
  fn test_fuzz_positions_query() {
    let target = FuzzTarget {
      url: "http://example.com/page?id=FUZZ".to_string(),
      method: HttpMethod::GET,
      headers: vec![],
      body: None,
      cookies: None,
    };

    let positions = WebFuzzer::parse_fuzz_positions(&target);
    assert!(positions.contains(&FuzzPosition::QueryParam));
  }
}
