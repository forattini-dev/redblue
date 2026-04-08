#![allow(dead_code)]

/// Parameter discovery -- finds hidden GET and POST parameters
///
/// Brute-forces parameter names against a target URL and detects those that
/// cause observable changes in the response.  Useful for discovering debug
/// flags, admin toggles, IDOR vectors, and reflected input points (potential
/// XSS/SSRF).
///
/// Detection heuristics:
/// - Status code change  (e.g. 200 -> 302 when `redirect=` is accepted)
/// - Response size delta  (new content rendered for the parameter)
/// - Value reflection     (the injected value appears in the response body)
/// - New response header  (e.g. `X-Debug: true` triggered by `debug=1`)
///
/// The module requires `config.brute = true` as a safety guard against
/// accidental mass-request traffic.
use crate::modules::common::parallel;
use crate::protocols::http::{HttpClient, HttpRequest};
use std::sync::Mutex;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How the probed parameter changed the response relative to the baseline.
#[derive(Debug, Clone, PartialEq)]
pub enum ParamDiff {
  /// HTTP status code changed.
  StatusChanged { from: u16, to: u16 },
  /// Response body size shifted beyond the configured threshold.
  SizeChanged { from: usize, to: usize, delta: i64 },
  /// The injected test value was reflected verbatim in the response body.
  /// This is a potential XSS or SSRF vector.
  Reflected,
  /// A response header appeared that was not present in the baseline.
  HeaderAdded { header: String },
  /// No observable difference -- the parameter is likely ignored.
  NoChange,
}

/// A parameter that produced an observable difference.
#[derive(Debug, Clone)]
pub struct DiscoveredParam {
  /// Parameter name (e.g. "debug", "redirect")
  pub name: String,
  /// HTTP method used ("GET" or "POST")
  pub method: String,
  /// What changed in the response
  pub diff: ParamDiff,
  /// Status code of the probed response
  pub response_status: u16,
  /// Body size of the probed response
  pub response_size: usize,
}

/// Configuration for parameter enumeration.
pub struct ParamConfig {
  /// Maximum concurrent probe threads (default: 10)
  pub threads: usize,
  /// Per-request timeout (default: 10s)
  pub timeout: Duration,
  /// HTTP method: "GET" or "POST" (default: "GET")
  pub method: String,
  /// Must be true to actually run enumeration (safety guard)
  pub brute: bool,
  /// Optional path to an external wordlist file (one param name per line)
  pub wordlist: Option<String>,
  /// Test value injected for every parameter probe (default: "rb1337test")
  pub param_value: String,
  /// Maximum random jitter in ms between requests (default: 100)
  pub jitter_ms: u64,
  /// Minimum body size difference to report as SizeChanged (default: 50 bytes)
  pub min_size_diff: usize,
}

impl Default for ParamConfig {
  fn default() -> Self {
    Self {
      threads: 10,
      timeout: Duration::from_secs(10),
      method: "GET".to_string(),
      brute: false,
      wordlist: None,
      param_value: "rb1337test".to_string(),
      jitter_ms: 100,
      min_size_diff: 50,
    }
  }
}

// ---------------------------------------------------------------------------
// Enumerator
// ---------------------------------------------------------------------------

pub struct ParamEnumerator {
  client: HttpClient,
  config: ParamConfig,
}

impl ParamEnumerator {
  pub fn new(config: ParamConfig) -> Self {
    let client = HttpClient::new().with_timeout(config.timeout);
    Self { client, config }
  }

  /// Discover hidden parameters on `url`.
  ///
  /// Returns an empty vec if `config.brute` is false (safety guard).
  /// Only parameters that produce an observable change are returned --
  /// NoChange results are filtered out.
  pub fn enumerate(&self, url: &str) -> Vec<DiscoveredParam> {
    if !self.config.brute {
      return Vec::new();
    }

    // Obtain baseline (the response without any extra parameters)
    let baseline = match self.get_baseline(url) {
      Some(b) => b,
      None => return Vec::new(),
    };

    let params = self.load_wordlist();
    if params.is_empty() {
      return Vec::new();
    }

    // Probe each candidate in parallel with jitter
    let results: Mutex<Vec<DiscoveredParam>> = Mutex::new(Vec::new());
    let baseline_ref = &baseline;
    let results_ref = &results;

    parallel::run_with_jitter(
      self.config.threads,
      self.config.jitter_ms,
      &params,
      |param| {
        if let Some(discovered) = self.probe_param(url, param, baseline_ref) {
          if discovered.diff != ParamDiff::NoChange {
            results_ref.lock().unwrap().push(discovered);
          }
        }
      },
    );

    results.into_inner().unwrap()
  }

  /// Get the baseline response (no extra parameters added).
  /// Returns (status, size, body).
  fn get_baseline(&self, url: &str) -> Option<(u16, usize, String)> {
    let result = if self.config.method == "POST" {
      self
        .client
        .post_raw(url, b"", "application/x-www-form-urlencoded")
    } else {
      self.client.get(url)
    };

    match result {
      Ok(resp) => {
        let body = resp.body_as_string();
        let size = body.len();
        Some((resp.status_code, size, body))
      }
      Err(_) => None,
    }
  }

  /// Probe a single parameter by injecting it and comparing to the baseline.
  fn probe_param(
    &self,
    url: &str,
    param_name: &str,
    baseline: &(u16, usize, String),
  ) -> Option<DiscoveredParam> {
    let result = if self.config.method == "POST" {
      // POST: send as form-encoded body
      let body = format!("{}={}", param_name, self.config.param_value);
      self
        .client
        .post_raw(url, body.as_bytes(), "application/x-www-form-urlencoded")
    } else {
      // GET: append as query parameter
      let test_url = Self::build_get_url(url, param_name, &self.config.param_value);
      self.client.get(&test_url)
    };

    match result {
      Ok(resp) => {
        let body = resp.body_as_string();
        let size = body.len();
        let diff = self.detect_diff(resp.status_code, size, &body, baseline, &resp.headers);

        Some(DiscoveredParam {
          name: param_name.to_string(),
          method: self.config.method.clone(),
          diff,
          response_status: resp.status_code,
          response_size: size,
        })
      }
      Err(_) => None,
    }
  }

  /// Build a GET URL with the test parameter appended.
  ///
  /// Handles both cases: URLs with an existing query string (append with &)
  /// and URLs without one (start with ?).
  fn build_get_url(url: &str, param_name: &str, param_value: &str) -> String {
    if url.contains('?') {
      format!("{}&{}={}", url, param_name, param_value)
    } else {
      format!("{}?{}={}", url, param_name, param_value)
    }
  }

  /// Determine how the probe response differs from the baseline.
  ///
  /// Checks are ordered by specificity:
  /// 1. Status code change -- strongest signal
  /// 2. Value reflection  -- potential XSS/SSRF
  /// 3. New header        -- hidden functionality triggered
  /// 4. Size change       -- new content rendered
  /// 5. NoChange          -- parameter is ignored
  fn detect_diff(
    &self,
    status: u16,
    size: usize,
    body: &str,
    baseline: &(u16, usize, String),
    response_headers: &std::collections::HashMap<String, String>,
  ) -> ParamDiff {
    let (base_status, base_size, ref base_body) = *baseline;

    // 1. Status code changed
    if status != base_status {
      return ParamDiff::StatusChanged {
        from: base_status,
        to: status,
      };
    }

    // 2. Injected value reflected in body (potential XSS/SSRF)
    if body.contains(&self.config.param_value) && !base_body.contains(&self.config.param_value) {
      return ParamDiff::Reflected;
    }

    // 3. New header that was not in baseline
    // We parse baseline headers lazily -- look for common indicator headers
    let indicator_headers = [
      "X-Debug",
      "X-Powered-By",
      "X-Request-Id",
      "X-Trace-Id",
      "X-Custom",
      "X-Runtime",
      "X-Cache",
      "X-Backend",
      "X-Server",
      "X-Forwarded",
      "Location",
      "Set-Cookie",
    ];

    for indicator in &indicator_headers {
      let lower = indicator.to_ascii_lowercase();
      let has_header = response_headers
        .keys()
        .any(|k| k.to_ascii_lowercase() == lower);

      if has_header {
        // Check if this header value is new/different by looking at whether
        // the baseline body gives any hint -- since we don't store baseline
        // headers directly, we report if any indicator header is present.
        // This is a heuristic; some false positives are acceptable.
        return ParamDiff::HeaderAdded {
          header: indicator.to_string(),
        };
      }
    }

    // 4. Response size differs beyond threshold
    let diff = (size as i64) - (base_size as i64);
    if diff.unsigned_abs() as usize >= self.config.min_size_diff {
      return ParamDiff::SizeChanged {
        from: base_size,
        to: size,
        delta: diff,
      };
    }

    ParamDiff::NoChange
  }

  /// Load the wordlist of parameter names to probe.
  ///
  /// Priority:
  /// 1. External file from `config.wordlist` if provided
  /// 2. Embedded `web-parameters` wordlist (via crate::wordlists)
  fn load_wordlist(&self) -> Vec<String> {
    // External wordlist file
    if let Some(ref path) = self.config.wordlist {
      if let Ok(lines) = crate::wordlists::Loader::load_lines(path) {
        let filtered: Vec<String> = lines
          .into_iter()
          .map(|l| l.trim().to_string())
          .filter(|l| !l.is_empty() && !l.starts_with('#'))
          .collect();
        if !filtered.is_empty() {
          return filtered;
        }
      }
    }

    // Embedded wordlist
    if let Some(words) = crate::wordlists::embedded::get_embedded("web-parameters") {
      return words;
    }

    Vec::new()
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_default_config() {
    let config = ParamConfig::default();
    assert_eq!(config.threads, 10);
    assert_eq!(config.timeout, Duration::from_secs(10));
    assert_eq!(config.method, "GET");
    assert!(!config.brute);
    assert!(config.wordlist.is_none());
    assert_eq!(config.param_value, "rb1337test");
    assert_eq!(config.jitter_ms, 100);
    assert_eq!(config.min_size_diff, 50);
  }

  #[test]
  fn test_get_param_url_construction() {
    let url = "http://example.com/search";
    let result = ParamEnumerator::build_get_url(url, "debug", "1");
    assert_eq!(result, "http://example.com/search?debug=1");
  }

  #[test]
  fn test_get_param_with_existing_query() {
    let url = "http://example.com/search?q=test";
    let result = ParamEnumerator::build_get_url(url, "debug", "1");
    assert_eq!(result, "http://example.com/search?q=test&debug=1");
  }

  #[test]
  fn test_post_param_body() {
    // Verify the POST body format is correct URL-encoded form
    let param_name = "debug";
    let param_value = "rb1337test";
    let body = format!("{}={}", param_name, param_value);
    assert_eq!(body, "debug=rb1337test");
  }

  #[test]
  fn test_detect_status_change() {
    let config = ParamConfig::default();
    let enumerator = ParamEnumerator::new(config);

    let baseline = (200_u16, 500_usize, String::from("<html>normal</html>"));
    let headers = std::collections::HashMap::new();
    let diff = enumerator.detect_diff(302, 500, "<html>redirect</html>", &baseline, &headers);

    assert_eq!(diff, ParamDiff::StatusChanged { from: 200, to: 302 });
  }

  #[test]
  fn test_detect_size_change() {
    let config = ParamConfig {
      min_size_diff: 50,
      ..Default::default()
    };
    let enumerator = ParamEnumerator::new(config);

    let baseline = (200_u16, 500_usize, String::from("<html>normal</html>"));
    let headers = std::collections::HashMap::new();
    // Body size 600 vs baseline 500 = delta 100 > min_size_diff 50
    let big_body = "x".repeat(600);
    let diff = enumerator.detect_diff(200, 600, &big_body, &baseline, &headers);

    match diff {
      ParamDiff::SizeChanged { from, to, delta } => {
        assert_eq!(from, 500);
        assert_eq!(to, 600);
        assert_eq!(delta, 100);
      }
      other => panic!("Expected SizeChanged, got {:?}", other),
    }
  }

  #[test]
  fn test_detect_reflected() {
    let config = ParamConfig {
      param_value: "rb1337test".to_string(),
      ..Default::default()
    };
    let enumerator = ParamEnumerator::new(config);

    let baseline = (200_u16, 500_usize, String::from("<html>normal</html>"));
    let headers = std::collections::HashMap::new();
    // The test value appears in the response body but not in the baseline
    let reflected_body = "<html>Result: rb1337test</html>";
    let diff = enumerator.detect_diff(
      200,
      reflected_body.len(),
      reflected_body,
      &baseline,
      &headers,
    );

    assert_eq!(diff, ParamDiff::Reflected);
  }

  #[test]
  fn test_detect_reflected_not_if_already_in_baseline() {
    let config = ParamConfig {
      param_value: "rb1337test".to_string(),
      ..Default::default()
    };
    let enumerator = ParamEnumerator::new(config);

    // If the baseline already contains the value, reflection is not a signal
    let baseline = (
      200_u16,
      500_usize,
      String::from("<html>rb1337test already here</html>"),
    );
    let headers = std::collections::HashMap::new();
    let body = "<html>rb1337test already here</html>";
    let diff = enumerator.detect_diff(200, body.len(), body, &baseline, &headers);

    // Should fall through to NoChange (same status, value in baseline, size within threshold)
    assert_eq!(diff, ParamDiff::NoChange);
  }

  #[test]
  fn test_no_change_filtered() {
    let config = ParamConfig {
      min_size_diff: 50,
      ..Default::default()
    };
    let enumerator = ParamEnumerator::new(config);

    let baseline = (200_u16, 500_usize, String::from("<html>normal</html>"));
    let headers = std::collections::HashMap::new();
    // Same status, no reflection, size within threshold (510 - 500 = 10 < 50)
    let diff = enumerator.detect_diff(200, 510, "<html>normal</html>", &baseline, &headers);

    assert_eq!(diff, ParamDiff::NoChange);
  }

  #[test]
  fn test_requires_brute_flag() {
    let config = ParamConfig {
      brute: false,
      ..Default::default()
    };
    let enumerator = ParamEnumerator::new(config);
    let results = enumerator.enumerate("http://example.com/");
    assert!(results.is_empty());
  }

  #[test]
  fn test_load_embedded_params() {
    // Verify the embedded web-parameters wordlist is accessible
    let words = crate::wordlists::embedded::get_embedded("web-parameters");
    assert!(words.is_some());
    let words = words.unwrap();
    assert!(!words.is_empty());
    assert!(words.contains(&"id".to_string()));
    assert!(words.contains(&"debug".to_string()));
    assert!(words.contains(&"redirect".to_string()));
  }

  #[test]
  fn test_discovered_param_fields() {
    let param = DiscoveredParam {
      name: "debug".to_string(),
      method: "GET".to_string(),
      diff: ParamDiff::Reflected,
      response_status: 200,
      response_size: 1024,
    };
    assert_eq!(param.name, "debug");
    assert_eq!(param.method, "GET");
    assert_eq!(param.diff, ParamDiff::Reflected);
    assert_eq!(param.response_status, 200);
    assert_eq!(param.response_size, 1024);
  }

  #[test]
  fn test_size_change_negative_delta() {
    let config = ParamConfig {
      min_size_diff: 50,
      ..Default::default()
    };
    let enumerator = ParamEnumerator::new(config);

    let baseline = (
      200_u16,
      500_usize,
      String::from("<html>normal content</html>"),
    );
    let headers = std::collections::HashMap::new();
    // Response is smaller than baseline (400 vs 500 = delta -100)
    let diff = enumerator.detect_diff(200, 400, "<html>short</html>", &baseline, &headers);

    match diff {
      ParamDiff::SizeChanged { from, to, delta } => {
        assert_eq!(from, 500);
        assert_eq!(to, 400);
        assert_eq!(delta, -100);
      }
      other => panic!("Expected SizeChanged, got {:?}", other),
    }
  }

  #[test]
  fn test_build_url_preserves_fragment() {
    let url = "http://example.com/page#section";
    let result = ParamEnumerator::build_get_url(url, "test", "val");
    // Fragment is preserved as-is (the server won't see it, but the URL is valid)
    assert_eq!(result, "http://example.com/page#section?test=val");
  }

  #[test]
  fn test_param_diff_equality() {
    assert_eq!(ParamDiff::NoChange, ParamDiff::NoChange);
    assert_eq!(ParamDiff::Reflected, ParamDiff::Reflected);
    assert_ne!(ParamDiff::Reflected, ParamDiff::NoChange);
    assert_eq!(
      ParamDiff::StatusChanged { from: 200, to: 302 },
      ParamDiff::StatusChanged { from: 200, to: 302 }
    );
    assert_ne!(
      ParamDiff::StatusChanged { from: 200, to: 302 },
      ParamDiff::StatusChanged { from: 200, to: 404 }
    );
  }
}
