//! Unified HTTP Client for Modules
//!
//! This module provides a standardized HTTP client wrapper for all modules,
//! eliminating duplicated code for caching, retries, and rate limiting.
//!
//! # Features
//!
//! - Automatic response caching with configurable TTL
//! - Retry logic with exponential backoff
//! - Rate limiting to avoid API bans
//! - Consistent error handling
//!
//! # Usage
//!
//! ```ignore
//! use crate::modules::common::http::{ModuleHttpClient, CacheConfig};
//!
//! let client = ModuleHttpClient::new("recon::crtsh")
//!     .with_cache(CacheConfig::new().with_ttl(Duration::from_secs(3600)))
//!     .with_retries(3)
//!     .with_rate_limit(10, Duration::from_secs(1));
//!
//! // Cached GET request
//! let response = client.get_cached("https://api.example.com/data")?;
//! ```

use crate::protocols::http::{HttpClient, HttpRequest, HttpResponse};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cache configuration for HTTP responses
#[derive(Debug, Clone)]
pub struct CacheConfig {
  /// Time-to-live for cached responses
  pub ttl: Duration,
  /// Maximum cache size (number of entries)
  pub max_entries: usize,
  /// Whether to cache error responses
  pub cache_errors: bool,
}

impl Default for CacheConfig {
  fn default() -> Self {
    Self {
      ttl: Duration::from_secs(300), // 5 minutes default
      max_entries: 100,
      cache_errors: false,
    }
  }
}

impl CacheConfig {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn with_ttl(mut self, ttl: Duration) -> Self {
    self.ttl = ttl;
    self
  }

  pub fn with_max_entries(mut self, max_entries: usize) -> Self {
    self.max_entries = max_entries;
    self
  }

  pub fn with_cache_errors(mut self, cache_errors: bool) -> Self {
    self.cache_errors = cache_errors;
    self
  }
}

/// Cached HTTP response
struct CachedResponse {
  response: HttpResponse,
  cached_at: Instant,
}

/// Rate limiter state
struct RateLimiter {
  window_start: Instant,
  request_count: usize,
  max_requests: usize,
  window_duration: Duration,
}

impl RateLimiter {
  fn new(max_requests: usize, window: Duration) -> Self {
    Self {
      window_start: Instant::now(),
      request_count: 0,
      max_requests,
      window_duration: window,
    }
  }

  /// Check if we can make a request, or sleep if needed
  fn acquire(&mut self) {
    let elapsed = self.window_start.elapsed();

    // Reset window if expired
    if elapsed >= self.window_duration {
      self.window_start = Instant::now();
      self.request_count = 0;
    }

    // Check if we're at the limit
    if self.request_count >= self.max_requests {
      // Sleep for remaining window time
      let sleep_time = self.window_duration - elapsed;
      std::thread::sleep(sleep_time);

      // Reset window
      self.window_start = Instant::now();
      self.request_count = 0;
    }

    self.request_count += 1;
  }
}

/// Unified HTTP client for modules
///
/// Provides caching, retries, and rate limiting out of the box.
pub struct ModuleHttpClient {
  inner: HttpClient,
  module_name: String,
  cache: Arc<Mutex<HashMap<String, CachedResponse>>>,
  cache_config: Option<CacheConfig>,
  max_retries: u8,
  rate_limiter: Option<Arc<Mutex<RateLimiter>>>,
}

impl ModuleHttpClient {
  /// Create a new module HTTP client
  pub fn new(module_name: impl Into<String>) -> Self {
    Self {
      inner: HttpClient::new(),
      module_name: module_name.into(),
      cache: Arc::new(Mutex::new(HashMap::new())),
      cache_config: None,
      max_retries: 0,
      rate_limiter: None,
    }
  }

  /// Enable response caching
  pub fn with_cache(mut self, config: CacheConfig) -> Self {
    self.cache_config = Some(config);
    self
  }

  /// Set maximum retry attempts
  pub fn with_retries(mut self, retries: u8) -> Self {
    self.max_retries = retries;
    self
  }

  /// Enable rate limiting
  pub fn with_rate_limit(mut self, max_requests: usize, window: Duration) -> Self {
    self.rate_limiter = Some(Arc::new(Mutex::new(RateLimiter::new(max_requests, window))));
    self
  }

  /// Set timeout
  pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.inner = self.inner.with_timeout(timeout);
    self
  }

  /// Set max response bytes
  pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
    self.inner = self.inner.with_max_response_bytes(limit);
    self
  }

  /// GET request with automatic caching
  pub fn get_cached(&self, url: &str) -> Result<HttpResponse, String> {
    // Check cache first
    if let Some(ref config) = self.cache_config {
      if let Some(cached) = self.get_from_cache(url, config) {
        return Ok(cached);
      }
    }

    // Make the request
    let response = self.get_with_retry(url)?;

    // Cache the response
    if let Some(ref config) = self.cache_config {
      if response.status_code < 400 || config.cache_errors {
        self.add_to_cache(url, response.clone(), config);
      }
    }

    Ok(response)
  }

  /// GET request with retry logic
  pub fn get_with_retry(&self, url: &str) -> Result<HttpResponse, String> {
    // Apply rate limiting
    if let Some(ref limiter) = self.rate_limiter {
      limiter.lock().unwrap().acquire();
    }

    let mut last_error = String::new();

    for attempt in 0..=self.max_retries {
      if attempt > 0 {
        // Exponential backoff: 100ms, 200ms, 400ms, 800ms...
        let backoff = Duration::from_millis(100 * (1 << (attempt - 1)));
        std::thread::sleep(backoff);
      }

      match self.inner.get(url) {
        Ok(response) => return Ok(response),
        Err(e) => {
          last_error = e.clone();
          // Only retry on transient errors
          if !is_retryable_error(&e) {
            return Err(e);
          }
        }
      }
    }

    Err(format!(
      "[{}] Request failed after {} retries: {}",
      self.module_name,
      self.max_retries + 1,
      last_error
    ))
  }

  /// POST request with retry logic
  pub fn post_with_retry(&self, url: &str, body: &[u8]) -> Result<HttpResponse, String> {
    // Apply rate limiting
    if let Some(ref limiter) = self.rate_limiter {
      limiter.lock().unwrap().acquire();
    }

    let mut last_error = String::new();

    for attempt in 0..=self.max_retries {
      if attempt > 0 {
        let backoff = Duration::from_millis(100 * (1 << (attempt - 1)));
        std::thread::sleep(backoff);
      }

      let request = HttpRequest::post(url).with_body(body.to_vec());

      match self.inner.send(&request) {
        Ok(response) => return Ok(response),
        Err(e) => {
          last_error = e.clone();
          if !is_retryable_error(&e) {
            return Err(e);
          }
        }
      }
    }

    Err(format!(
      "[{}] POST failed after {} retries: {}",
      self.module_name,
      self.max_retries + 1,
      last_error
    ))
  }

  /// Direct access to inner client for custom requests
  pub fn inner(&self) -> &HttpClient {
    &self.inner
  }

  /// Clear the response cache
  pub fn clear_cache(&self) {
    self.cache.lock().unwrap().clear();
  }

  /// Get cache statistics
  pub fn cache_stats(&self) -> (usize, usize) {
    let cache = self.cache.lock().unwrap();
    let total = cache.len();
    let valid = if let Some(ref config) = self.cache_config {
      cache
        .values()
        .filter(|c| c.cached_at.elapsed() < config.ttl)
        .count()
    } else {
      0
    };
    (total, valid)
  }

  // ========================================================================
  // Private helpers
  // ========================================================================

  fn get_from_cache(&self, url: &str, config: &CacheConfig) -> Option<HttpResponse> {
    let cache = self.cache.lock().unwrap();
    if let Some(cached) = cache.get(url) {
      if cached.cached_at.elapsed() < config.ttl {
        return Some(cached.response.clone());
      }
    }
    None
  }

  fn add_to_cache(&self, url: &str, response: HttpResponse, config: &CacheConfig) {
    let mut cache = self.cache.lock().unwrap();

    // Evict old entries if cache is full
    if cache.len() >= config.max_entries {
      // Remove expired entries first
      cache.retain(|_, v| v.cached_at.elapsed() < config.ttl);

      // If still full, remove oldest entry
      if cache.len() >= config.max_entries {
        if let Some(oldest_key) = cache
          .iter()
          .min_by_key(|(_, v)| v.cached_at)
          .map(|(k, _)| k.clone())
        {
          cache.remove(&oldest_key);
        }
      }
    }

    cache.insert(
      url.to_string(),
      CachedResponse {
        response,
        cached_at: Instant::now(),
      },
    );
  }
}

/// Check if an error is retryable (transient network issues)
fn is_retryable_error(error: &str) -> bool {
  let error_lower = error.to_lowercase();
  error_lower.contains("timeout")
    || error_lower.contains("connection refused")
    || error_lower.contains("connection reset")
    || error_lower.contains("temporary failure")
    || error_lower.contains("try again")
    || error_lower.contains("503")
    || error_lower.contains("502")
    || error_lower.contains("504")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_cache_config_default() {
    let config = CacheConfig::default();
    assert_eq!(config.ttl, Duration::from_secs(300));
    assert_eq!(config.max_entries, 100);
    assert!(!config.cache_errors);
  }

  #[test]
  fn test_cache_config_builder() {
    let config = CacheConfig::new()
      .with_ttl(Duration::from_secs(3600))
      .with_max_entries(500)
      .with_cache_errors(true);

    assert_eq!(config.ttl, Duration::from_secs(3600));
    assert_eq!(config.max_entries, 500);
    assert!(config.cache_errors);
  }

  #[test]
  fn test_rate_limiter() {
    let mut limiter = RateLimiter::new(2, Duration::from_millis(100));

    // First two requests should be immediate
    limiter.acquire();
    limiter.acquire();

    // Third request should wait
    let start = Instant::now();
    limiter.acquire();
    let elapsed = start.elapsed();

    // Should have waited at least some time
    assert!(elapsed >= Duration::from_millis(50));
  }

  #[test]
  fn test_is_retryable_error() {
    assert!(is_retryable_error("Connection timeout"));
    assert!(is_retryable_error("503 Service Unavailable"));
    assert!(is_retryable_error("connection refused"));
    assert!(!is_retryable_error("404 Not Found"));
    assert!(!is_retryable_error("Invalid JSON"));
  }

  #[test]
  fn test_module_client_creation() {
    let client = ModuleHttpClient::new("test::module")
      .with_cache(CacheConfig::new().with_ttl(Duration::from_secs(60)))
      .with_retries(3)
      .with_rate_limit(10, Duration::from_secs(1));

    assert!(client.cache_config.is_some());
    assert_eq!(client.max_retries, 3);
    assert!(client.rate_limiter.is_some());
  }
}
