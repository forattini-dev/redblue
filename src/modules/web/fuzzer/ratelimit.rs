//! Adaptive Rate Limiter for Web Fuzzing
//!
//! Implements intelligent rate limiting that adapts based on target behavior:
//! - Token bucket algorithm for smooth rate control
//! - Automatic backoff on rate limiting (429) or errors
//! - Gradual recovery when errors decrease
//! - Per-target rate memory

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Result of requesting permission to make a request
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RateLimitResult {
  /// Request is allowed, proceed immediately
  Allowed,
  /// Request is allowed after waiting the specified duration
  AllowedAfterWait(Duration),
  /// Request is temporarily blocked, try again later
  Blocked(Duration),
}

impl RateLimitResult {
  /// Check if the request is allowed (possibly after waiting)
  pub fn is_allowed(&self) -> bool {
    matches!(
      self,
      RateLimitResult::Allowed | RateLimitResult::AllowedAfterWait(_)
    )
  }

  /// Get the wait duration (if any)
  pub fn wait_duration(&self) -> Option<Duration> {
    match self {
      RateLimitResult::Allowed => None,
      RateLimitResult::AllowedAfterWait(d) => Some(*d),
      RateLimitResult::Blocked(d) => Some(*d),
    }
  }
}

/// Configuration for adaptive rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
  /// Initial requests per second
  pub initial_rate: f64,
  /// Minimum requests per second (floor)
  pub min_rate: f64,
  /// Maximum requests per second (ceiling)
  pub max_rate: f64,
  /// Backoff factor when rate limited (multiply rate by this)
  pub backoff_factor: f64,
  /// Recovery factor when successful (multiply rate by this)
  pub recovery_factor: f64,
  /// Error threshold ratio to trigger backoff (0.0 - 1.0)
  pub error_threshold: f64,
  /// Window size for error ratio calculation
  pub error_window_size: usize,
  /// Status codes that indicate rate limiting
  pub rate_limit_codes: Vec<u16>,
  /// Status codes that indicate server errors
  pub server_error_codes: Vec<u16>,
  /// Cooldown period after backoff before recovery starts
  pub recovery_cooldown: Duration,
  /// Enable aggressive backoff on 429
  pub aggressive_429_backoff: bool,
}

impl Default for RateLimitConfig {
  fn default() -> Self {
    Self {
      initial_rate: 50.0,   // 50 requests per second
      min_rate: 1.0,        // Never go below 1 req/sec
      max_rate: 200.0,      // Never exceed 200 req/sec
      backoff_factor: 0.5,  // Halve rate on backoff
      recovery_factor: 1.1, // Increase by 10% on recovery
      error_threshold: 0.1, // Backoff if >10% errors
      error_window_size: 100,
      rate_limit_codes: vec![429],
      server_error_codes: vec![500, 502, 503, 504],
      recovery_cooldown: Duration::from_secs(5),
      aggressive_429_backoff: true,
    }
  }
}

impl RateLimitConfig {
  /// Aggressive configuration (fast but careful)
  pub fn aggressive() -> Self {
    Self {
      initial_rate: 100.0,
      max_rate: 500.0,
      recovery_factor: 1.2,
      ..Default::default()
    }
  }

  /// Conservative configuration (slow but safe)
  pub fn conservative() -> Self {
    Self {
      initial_rate: 10.0,
      max_rate: 50.0,
      backoff_factor: 0.3,
      recovery_factor: 1.05,
      error_threshold: 0.05,
      ..Default::default()
    }
  }

  /// Stealth configuration (very slow, avoids detection)
  pub fn stealth() -> Self {
    Self {
      initial_rate: 2.0,
      min_rate: 0.5,
      max_rate: 10.0,
      backoff_factor: 0.5,
      recovery_factor: 1.02,
      error_threshold: 0.02,
      recovery_cooldown: Duration::from_secs(30),
      ..Default::default()
    }
  }
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
  /// Current number of tokens
  tokens: f64,
  /// Maximum tokens (bucket capacity)
  capacity: f64,
  /// Token refill rate (tokens per second)
  refill_rate: f64,
  /// Last refill time
  last_refill: Instant,
}

impl TokenBucket {
  /// Create a new token bucket
  fn new(rate: f64) -> Self {
    Self {
      tokens: rate,   // Start with full bucket
      capacity: rate, // Bucket size = 1 second of tokens
      refill_rate: rate,
      last_refill: Instant::now(),
    }
  }

  /// Update the rate (and capacity)
  fn set_rate(&mut self, rate: f64) {
    // Refill first with old rate
    self.refill();

    // Scale tokens proportionally
    let ratio = rate / self.refill_rate;
    self.tokens = (self.tokens * ratio).min(rate);

    self.refill_rate = rate;
    self.capacity = rate;
  }

  /// Refill tokens based on elapsed time
  fn refill(&mut self) {
    let now = Instant::now();
    let elapsed = now.duration_since(self.last_refill);
    let new_tokens = elapsed.as_secs_f64() * self.refill_rate;

    self.tokens = (self.tokens + new_tokens).min(self.capacity);
    self.last_refill = now;
  }

  /// Try to consume a token
  fn try_consume(&mut self) -> RateLimitResult {
    self.refill();

    if self.tokens >= 1.0 {
      self.tokens -= 1.0;
      RateLimitResult::Allowed
    } else {
      // Calculate wait time for next token
      let deficit = 1.0 - self.tokens;
      let wait_secs = deficit / self.refill_rate;
      let wait = Duration::from_secs_f64(wait_secs);

      if wait < Duration::from_secs(10) {
        RateLimitResult::AllowedAfterWait(wait)
      } else {
        RateLimitResult::Blocked(wait)
      }
    }
  }

  /// Get current rate
  fn rate(&self) -> f64 {
    self.refill_rate
  }
}

/// Error history entry
#[derive(Debug, Clone)]
struct ResponseRecord {
  status_code: u16,
  timestamp: Instant,
  is_error: bool,
}

/// Statistics for the rate limiter
#[derive(Debug, Clone, Default)]
pub struct RateLimitStats {
  /// Total requests tracked
  pub total_requests: usize,
  /// Requests that were rate limited (429)
  pub rate_limited_count: usize,
  /// Server errors (5xx)
  pub server_error_count: usize,
  /// Number of backoff events
  pub backoff_count: usize,
  /// Number of recovery events
  pub recovery_count: usize,
  /// Current rate (requests per second)
  pub current_rate: f64,
  /// Minimum rate reached
  pub min_rate_reached: f64,
  /// Maximum rate reached
  pub max_rate_reached: f64,
  /// Current error ratio
  pub current_error_ratio: f64,
}

/// Adaptive rate limiter for web scanning
///
/// Automatically adjusts request rate based on target responses,
/// backing off on errors and recovering when successful.
pub struct AdaptiveRateLimiter {
  config: RateLimitConfig,
  /// Token bucket for rate control
  bucket: TokenBucket,
  /// Recent response history for error ratio calculation
  history: Vec<ResponseRecord>,
  /// Last backoff time (for cooldown calculation)
  last_backoff: Option<Instant>,
  /// Whether we're in recovery mode
  in_recovery: bool,
  /// Statistics
  stats: RateLimitStats,
}

impl AdaptiveRateLimiter {
  /// Create a new adaptive rate limiter
  pub fn new(config: RateLimitConfig) -> Self {
    let bucket = TokenBucket::new(config.initial_rate);
    let stats = RateLimitStats {
      current_rate: config.initial_rate,
      min_rate_reached: config.initial_rate,
      max_rate_reached: config.initial_rate,
      ..Default::default()
    };

    Self {
      config,
      bucket,
      history: Vec::new(),
      last_backoff: None,
      in_recovery: false,
      stats,
    }
  }

  /// Create with default configuration
  pub fn with_defaults() -> Self {
    Self::new(RateLimitConfig::default())
  }

  /// Request permission to make a request
  pub fn acquire(&mut self) -> RateLimitResult {
    self.bucket.try_consume()
  }

  /// Record a response status code
  ///
  /// This should be called after each request to adapt the rate.
  pub fn record_response(&mut self, status_code: u16) {
    let is_rate_limited = self.config.rate_limit_codes.contains(&status_code);
    let is_server_error = self.config.server_error_codes.contains(&status_code);
    let is_error = is_rate_limited || is_server_error;

    // Record in history
    self.history.push(ResponseRecord {
      status_code,
      timestamp: Instant::now(),
      is_error,
    });

    // Trim history to window size
    while self.history.len() > self.config.error_window_size {
      self.history.remove(0);
    }

    // Update stats
    self.stats.total_requests += 1;
    if is_rate_limited {
      self.stats.rate_limited_count += 1;
    }
    if is_server_error {
      self.stats.server_error_count += 1;
    }

    // Calculate error ratio
    let error_ratio = self.calculate_error_ratio();
    self.stats.current_error_ratio = error_ratio;

    // Adjust rate based on response
    if is_rate_limited && self.config.aggressive_429_backoff {
      // Immediate aggressive backoff on 429
      self.backoff_aggressive();
    } else if is_error && error_ratio > self.config.error_threshold {
      // Gradual backoff on high error ratio
      self.backoff();
    } else if !is_error && self.should_recover() {
      // Recovery on success
      self.recover();
    }

    // Update rate stats
    self.stats.current_rate = self.bucket.rate();
    self.stats.min_rate_reached = self.stats.min_rate_reached.min(self.bucket.rate());
    self.stats.max_rate_reached = self.stats.max_rate_reached.max(self.bucket.rate());
  }

  /// Calculate current error ratio
  fn calculate_error_ratio(&self) -> f64 {
    if self.history.is_empty() {
      return 0.0;
    }

    let error_count = self.history.iter().filter(|r| r.is_error).count();
    error_count as f64 / self.history.len() as f64
  }

  /// Check if recovery should start
  fn should_recover(&self) -> bool {
    // Must not be in immediate backoff
    if let Some(last_backoff) = self.last_backoff {
      if last_backoff.elapsed() < self.config.recovery_cooldown {
        return false;
      }
    }

    // Must have low error ratio
    self.calculate_error_ratio() < self.config.error_threshold * 0.5
  }

  /// Apply backoff
  fn backoff(&mut self) {
    let current_rate = self.bucket.rate();
    let new_rate = (current_rate * self.config.backoff_factor).max(self.config.min_rate);

    if new_rate < current_rate {
      self.bucket.set_rate(new_rate);
      self.last_backoff = Some(Instant::now());
      self.in_recovery = false;
      self.stats.backoff_count += 1;
    }
  }

  /// Apply aggressive backoff (for 429)
  fn backoff_aggressive(&mut self) {
    let current_rate = self.bucket.rate();
    // More aggressive: reduce to 1/3 of current rate
    let new_rate = (current_rate * 0.33).max(self.config.min_rate);

    self.bucket.set_rate(new_rate);
    self.last_backoff = Some(Instant::now());
    self.in_recovery = false;
    self.stats.backoff_count += 1;
  }

  /// Apply recovery
  fn recover(&mut self) {
    let current_rate = self.bucket.rate();
    let new_rate = (current_rate * self.config.recovery_factor).min(self.config.max_rate);

    if new_rate > current_rate {
      self.bucket.set_rate(new_rate);
      self.in_recovery = true;
      self.stats.recovery_count += 1;
    }
  }

  /// Get current rate (requests per second)
  pub fn current_rate(&self) -> f64 {
    self.bucket.rate()
  }

  /// Get statistics
  pub fn stats(&self) -> &RateLimitStats {
    &self.stats
  }

  /// Reset the rate limiter
  pub fn reset(&mut self) {
    self.bucket = TokenBucket::new(self.config.initial_rate);
    self.history.clear();
    self.last_backoff = None;
    self.in_recovery = false;
    self.stats = RateLimitStats {
      current_rate: self.config.initial_rate,
      min_rate_reached: self.config.initial_rate,
      max_rate_reached: self.config.initial_rate,
      ..Default::default()
    };
  }

  /// Manually set the rate (bypasses adaptation)
  pub fn set_rate(&mut self, rate: f64) {
    let rate = rate.clamp(self.config.min_rate, self.config.max_rate);
    self.bucket.set_rate(rate);
    self.stats.current_rate = rate;
  }

  /// Get the configuration
  pub fn config(&self) -> &RateLimitConfig {
    &self.config
  }

  /// Check if currently in recovery mode
  pub fn is_recovering(&self) -> bool {
    self.in_recovery
  }

  /// Check if currently in backoff mode
  pub fn is_backing_off(&self) -> bool {
    if let Some(last_backoff) = self.last_backoff {
      last_backoff.elapsed() < self.config.recovery_cooldown
    } else {
      false
    }
  }

  /// Get time until recovery is allowed
  pub fn time_until_recovery(&self) -> Option<Duration> {
    self.last_backoff.and_then(|lb| {
      let elapsed = lb.elapsed();
      if elapsed < self.config.recovery_cooldown {
        Some(self.config.recovery_cooldown - elapsed)
      } else {
        None
      }
    })
  }
}

/// Builder for AdaptiveRateLimiter
pub struct RateLimiterBuilder {
  config: RateLimitConfig,
}

impl RateLimiterBuilder {
  /// Create a new builder
  pub fn new() -> Self {
    Self {
      config: RateLimitConfig::default(),
    }
  }

  /// Set initial rate
  pub fn initial_rate(mut self, rate: f64) -> Self {
    self.config.initial_rate = rate.max(0.1);
    self
  }

  /// Set minimum rate
  pub fn min_rate(mut self, rate: f64) -> Self {
    self.config.min_rate = rate.max(0.1);
    self
  }

  /// Set maximum rate
  pub fn max_rate(mut self, rate: f64) -> Self {
    self.config.max_rate = rate;
    self
  }

  /// Set backoff factor
  pub fn backoff_factor(mut self, factor: f64) -> Self {
    self.config.backoff_factor = factor.clamp(0.1, 0.9);
    self
  }

  /// Set recovery factor
  pub fn recovery_factor(mut self, factor: f64) -> Self {
    self.config.recovery_factor = factor.max(1.0);
    self
  }

  /// Set error threshold
  pub fn error_threshold(mut self, threshold: f64) -> Self {
    self.config.error_threshold = threshold.clamp(0.01, 1.0);
    self
  }

  /// Set error window size
  pub fn error_window_size(mut self, size: usize) -> Self {
    self.config.error_window_size = size.max(10);
    self
  }

  /// Set recovery cooldown
  pub fn recovery_cooldown(mut self, duration: Duration) -> Self {
    self.config.recovery_cooldown = duration;
    self
  }

  /// Enable/disable aggressive 429 backoff
  pub fn aggressive_429_backoff(mut self, enable: bool) -> Self {
    self.config.aggressive_429_backoff = enable;
    self
  }

  /// Build the rate limiter
  pub fn build(self) -> AdaptiveRateLimiter {
    AdaptiveRateLimiter::new(self.config)
  }
}

impl Default for RateLimiterBuilder {
  fn default() -> Self {
    Self::new()
  }
}

/// Per-target rate limiter manager
///
/// Maintains separate rate limiters for different targets,
/// allowing independent adaptation for each.
pub struct TargetRateLimiter {
  default_config: RateLimitConfig,
  limiters: HashMap<String, AdaptiveRateLimiter>,
}

impl TargetRateLimiter {
  /// Create a new target rate limiter
  pub fn new(config: RateLimitConfig) -> Self {
    Self {
      default_config: config,
      limiters: HashMap::new(),
    }
  }

  /// Create with default configuration
  pub fn with_defaults() -> Self {
    Self::new(RateLimitConfig::default())
  }

  /// Get or create a rate limiter for a target
  pub fn for_target(&mut self, target: &str) -> &mut AdaptiveRateLimiter {
    self
      .limiters
      .entry(target.to_string())
      .or_insert_with(|| AdaptiveRateLimiter::new(self.default_config.clone()))
  }

  /// Remove a target's rate limiter
  pub fn remove_target(&mut self, target: &str) {
    self.limiters.remove(target);
  }

  /// Get all target statistics
  pub fn all_stats(&self) -> HashMap<String, RateLimitStats> {
    self
      .limiters
      .iter()
      .map(|(k, v)| (k.clone(), v.stats().clone()))
      .collect()
  }

  /// Reset all limiters
  pub fn reset_all(&mut self) {
    for limiter in self.limiters.values_mut() {
      limiter.reset();
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_basic_rate_limiting() {
    let mut limiter = AdaptiveRateLimiter::new(RateLimitConfig {
      initial_rate: 10.0,
      ..Default::default()
    });

    // First few requests should be allowed
    for _ in 0..10 {
      assert!(limiter.acquire().is_allowed());
    }

    // Eventually we should need to wait
    let result = limiter.acquire();
    match result {
      RateLimitResult::Allowed => {}             // Got lucky with timing
      RateLimitResult::AllowedAfterWait(_) => {} // Expected
      RateLimitResult::Blocked(_) => {}          // Also possible
    }
  }

  #[test]
  fn test_backoff_on_429() {
    let mut limiter = AdaptiveRateLimiter::with_defaults();
    let initial_rate = limiter.current_rate();

    // Record a 429
    limiter.record_response(429);

    // Rate should have decreased
    assert!(
      limiter.current_rate() < initial_rate,
      "Rate should decrease after 429"
    );
  }

  #[test]
  fn test_backoff_on_errors() {
    let mut limiter = AdaptiveRateLimiter::new(RateLimitConfig {
      error_threshold: 0.1,
      error_window_size: 10,
      ..Default::default()
    });

    let initial_rate = limiter.current_rate();

    // Record mostly successful responses with some errors
    for i in 0..10 {
      if i < 8 {
        limiter.record_response(200);
      } else {
        limiter.record_response(500);
      }
    }

    // Error ratio is 20%, above threshold, should have backed off
    assert!(
      limiter.current_rate() < initial_rate,
      "Rate should decrease after high error ratio"
    );
  }

  #[test]
  fn test_recovery() {
    let mut limiter = AdaptiveRateLimiter::new(RateLimitConfig {
      initial_rate: 50.0,
      recovery_cooldown: Duration::from_millis(1), // Very short for testing
      ..Default::default()
    });

    // Force backoff
    limiter.record_response(429);
    let backed_off_rate = limiter.current_rate();

    // Wait for cooldown
    std::thread::sleep(Duration::from_millis(5));

    // Record successful responses
    for _ in 0..50 {
      limiter.record_response(200);
    }

    // Should have recovered somewhat
    assert!(
      limiter.current_rate() > backed_off_rate,
      "Rate should increase after recovery"
    );
  }

  #[test]
  fn test_min_max_bounds() {
    let mut limiter = AdaptiveRateLimiter::new(RateLimitConfig {
      initial_rate: 10.0,
      min_rate: 5.0,
      max_rate: 20.0,
      ..Default::default()
    });

    // Try to set below min
    limiter.set_rate(1.0);
    assert_eq!(limiter.current_rate(), 5.0);

    // Try to set above max
    limiter.set_rate(100.0);
    assert_eq!(limiter.current_rate(), 20.0);
  }

  #[test]
  fn test_target_rate_limiter() {
    let mut manager = TargetRateLimiter::with_defaults();

    // Get limiters for different targets
    manager.for_target("target1.com").record_response(429);
    manager.for_target("target2.com").record_response(200);

    let stats = manager.all_stats();
    assert_eq!(stats.len(), 2);

    // target1 should have rate limited count
    assert_eq!(stats["target1.com"].rate_limited_count, 1);
    assert_eq!(stats["target2.com"].rate_limited_count, 0);
  }

  #[test]
  fn test_builder() {
    let limiter = RateLimiterBuilder::new()
      .initial_rate(100.0)
      .min_rate(10.0)
      .max_rate(200.0)
      .backoff_factor(0.5)
      .recovery_factor(1.2)
      .build();

    assert_eq!(limiter.current_rate(), 100.0);
    assert_eq!(limiter.config().min_rate, 10.0);
    assert_eq!(limiter.config().max_rate, 200.0);
  }

  #[test]
  fn test_stats() {
    let mut limiter = AdaptiveRateLimiter::with_defaults();

    limiter.record_response(200);
    limiter.record_response(200);
    limiter.record_response(429);
    limiter.record_response(500);

    let stats = limiter.stats();
    assert_eq!(stats.total_requests, 4);
    assert_eq!(stats.rate_limited_count, 1);
    assert_eq!(stats.server_error_count, 1);
  }
}
