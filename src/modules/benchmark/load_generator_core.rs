use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::protocols::http::pool::{ConnectionPool, PooledHttpClient};
use crate::protocols::http::{HttpClient, HttpRequest};
use crate::protocols::http2::{Header, Http2Client};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolPreference {
  Auto,
  Http1,
  Http2,
}

impl FromStr for ProtocolPreference {
  type Err = String;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value.trim().to_ascii_lowercase().as_str() {
      "" | "auto" => Ok(Self::Auto),
      "http1" | "http/1" | "http/1.1" | "1" => Ok(Self::Http1),
      "http2" | "http/2" | "2" | "h2" => Ok(Self::Http2),
      other => Err(format!(
        "Invalid protocol '{}' (use auto, http1, or http2)",
        other
      )),
    }
  }
}

impl ProtocolPreference {
  pub fn label(self) -> &'static str {
    match self {
      Self::Auto => "auto",
      Self::Http1 => "http1",
      Self::Http2 => "http2",
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedProtocol {
  Unknown,
  Http1,
  Http2,
}

impl NegotiatedProtocol {
  pub fn label(self) -> &'static str {
    match self {
      Self::Unknown => "unknown",
      Self::Http1 => "http1",
      Self::Http2 => "http2",
    }
  }
}

/// Load testing mode - determines connection reuse behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadMode {
  /// Maximum RPS with full connection reuse (tests backend capacity)
  Throughput,
  /// New TCP+TLS connection per request (tests load balancer/TLS termination)
  Connections,
  /// Mixed behavior: configurable ratio of new vs returning users
  #[default]
  Realistic,
  /// Maximum concurrent connections pressure (find breaking point)
  Stress,
  /// Slow HTTP attack — holds connections with partial requests
  Slowloris,
}

impl FromStr for LoadMode {
  type Err = String;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s.trim().to_lowercase().as_str() {
      "throughput" | "tput" | "rps" => Ok(Self::Throughput),
      "connections" | "conn" | "tls" => Ok(Self::Connections),
      "realistic" | "real" | "mixed" => Ok(Self::Realistic),
      "stress" | "max" | "break" => Ok(Self::Stress),
      "slowloris" | "slow" | "loris" => Ok(Self::Slowloris),
      other => Err(format!(
        "Invalid mode '{}'. Valid modes: throughput, connections, realistic, stress, slowloris",
        other
      )),
    }
  }
}

impl LoadMode {
  pub fn label(self) -> &'static str {
    match self {
      Self::Throughput => "throughput",
      Self::Connections => "connections",
      Self::Realistic => "realistic",
      Self::Stress => "stress",
      Self::Slowloris => "slowloris",
    }
  }

  pub fn description(self) -> &'static str {
    match self {
      Self::Throughput => "Max RPS with connection reuse",
      Self::Connections => "New TCP+TLS per request",
      Self::Realistic => "Mixed user behavior simulation",
      Self::Stress => "Maximum connection pressure",
      Self::Slowloris => "Slow HTTP attack — holds connections with partial requests",
    }
  }
}

#[derive(Debug, Clone)]
pub struct ProtocolOutcome {
  pub requested: ProtocolPreference,
  pub negotiated: NegotiatedProtocol,
  pub fallback: bool,
  pub fallback_reason: Option<String>,
}

impl ProtocolOutcome {
  pub fn display_label(&self) -> String {
    match (self.negotiated, self.fallback) {
      (NegotiatedProtocol::Http1, true) => {
        if let Some(reason) = &self.fallback_reason {
          format!("http1 (fallback: {})", reason)
        } else {
          "http1 (fallback)".to_string()
        }
      }
      (negotiated, _) => negotiated.label().to_string(),
    }
  }
}

#[derive(Debug)]
pub(crate) struct ProtocolTracker {
  requested: ProtocolPreference,
  negotiated: AtomicUsize,
  fallback: AtomicBool,
  reason: Mutex<Option<String>>,
}

impl ProtocolTracker {
  pub(crate) fn new(requested: ProtocolPreference) -> Self {
    Self {
      requested,
      negotiated: AtomicUsize::new(NegotiatedProtocol::Unknown as usize),
      fallback: AtomicBool::new(false),
      reason: Mutex::new(None),
    }
  }

  pub(crate) fn record_http2(&self) {
    self
      .negotiated
      .store(NegotiatedProtocol::Http2 as usize, Ordering::Relaxed);
    self.fallback.store(false, Ordering::Relaxed);
    let mut reason = self.reason.lock().unwrap();
    *reason = None;
  }

  pub(crate) fn record_http1(&self, fallback: bool, reason_text: Option<String>) {
    self
      .negotiated
      .store(NegotiatedProtocol::Http1 as usize, Ordering::Relaxed);
    self.fallback.store(fallback, Ordering::Relaxed);
    if fallback {
      let mut reason = self.reason.lock().unwrap();
      if reason.is_none() {
        *reason = reason_text;
      }
    }
  }

  pub(crate) fn outcome(&self) -> ProtocolOutcome {
    let negotiated = match self.negotiated.load(Ordering::Relaxed) {
      x if x == NegotiatedProtocol::Http2 as usize => NegotiatedProtocol::Http2,
      x if x == NegotiatedProtocol::Http1 as usize => NegotiatedProtocol::Http1,
      _ => NegotiatedProtocol::Unknown,
    };

    ProtocolOutcome {
      requested: self.requested,
      negotiated,
      fallback: self.fallback.load(Ordering::Relaxed),
      fallback_reason: self.reason.lock().unwrap().clone(),
    }
  }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedTarget {
  pub url: String,
  pub host: String,
  pub authority: String,
  pub port: u16,
  pub path: String,
  pub is_https: bool,
}

impl ParsedTarget {
  fn fallback_authority(host: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
      host.to_string()
    } else {
      format!("{}:{}", host, port)
    }
  }
}

pub(crate) fn parse_target(url: &str) -> Result<ParsedTarget, String> {
  let trimmed = url.trim();
  let (rest, is_https, default_port) = if let Some(stripped) = trimmed.strip_prefix("https://") {
    (stripped, true, 443)
  } else if let Some(stripped) = trimmed.strip_prefix("http://") {
    (stripped, false, 80)
  } else {
    (trimmed, false, 80)
  };

  let split_index = rest.find('/').unwrap_or(rest.len());
  let host_port = &rest[..split_index];
  let path = if split_index < rest.len() {
    format!("/{}", &rest[split_index + 1..])
  } else {
    "/".to_string()
  };

  if host_port.is_empty() {
    return Err("Missing host in URL".to_string());
  }

  let (host, port) = if let Some(colon) = host_port.rfind(':') {
    let host_part = &host_port[..colon];
    let port_part = &host_port[colon + 1..];
    if host_part.contains(']') && host_part.contains('[') {
      // IPv6 literal with port, e.g. [::1]:443
      let host = host_part.trim_matches(&['[', ']'][..]).to_string();
      let port = port_part
        .parse::<u16>()
        .map_err(|_| format!("Invalid port '{}'", port_part))?;
      (host, port)
    } else if host_part.contains(':') && !host_part.contains(']') {
      // IPv6 literal without brackets (invalid per RFC) -> unsupported
      Err("IPv6 literals must be wrapped in []".to_string())?
    } else {
      let host = host_part.to_string();
      let port = port_part
        .parse::<u16>()
        .map_err(|_| format!("Invalid port '{}'", port_part))?;
      (host, port)
    }
  } else {
    (
      host_port.trim_matches(&['[', ']'][..]).to_string(),
      default_port,
    )
  };

  let authority = ParsedTarget::fallback_authority(&host, port, default_port);

  Ok(ParsedTarget {
    url: trimmed.to_string(),
    host,
    authority,
    port,
    path,
    is_https,
  })
}

pub(crate) fn summarize_reason(reason: &str) -> String {
  const MAX_LEN: usize = 64;
  let trimmed = reason.trim();
  if trimmed.len() <= MAX_LEN {
    trimmed.to_string()
  } else {
    format!("{}…", &trimmed[..MAX_LEN.saturating_sub(1)])
  }
}

#[derive(Debug)]
pub(crate) struct ResponseMetrics {
  pub status: u16,
  pub bytes: usize,
  pub ttfb: Duration,
}

#[derive(Debug)]
pub(crate) struct RequestFailure {
  pub message: String,
  pub ttfb: Option<Duration>,
}

pub(crate) fn execute_http1_request(
  method: &str,
  url: &str,
  timeout: Duration,
  pool: Option<Arc<ConnectionPool>>,
  keep_alive: bool,
  body: Option<&Arc<Vec<u8>>>,
  start: Instant,
) -> Result<ResponseMetrics, RequestFailure> {
  if let Some(pool) = pool {
    let client = PooledHttpClient::new(pool)
      .with_timeout(timeout)
      .with_keep_alive(keep_alive);
    match client.request(method, url, start, body) {
      Ok(response) => Ok(ResponseMetrics {
        status: response.status,
        bytes: response.body.len(),
        ttfb: response.ttfb,
      }),
      Err(error) => Err(RequestFailure {
        message: error.message,
        ttfb: error.ttfb,
      }),
    }
  } else {
    execute_http1_request_direct(method, url, timeout, keep_alive, body)
  }
}

pub(crate) fn execute_http2_request(
  client: &mut Http2Client,
  parsed: &ParsedTarget,
  method: &str,
  body: Option<&Arc<Vec<u8>>>,
  start: Instant,
) -> Result<ResponseMetrics, RequestFailure> {
  let mut extra_headers = Vec::new();
  let body_vec = body.map(|b| b.as_ref().clone());
  if let Some(ref payload) = body_vec {
    extra_headers.push(Header::new("content-length", payload.len().to_string()));
  }
  match client.send_request_with_timing(
    method,
    &parsed.path,
    &parsed.authority,
    extra_headers,
    body_vec,
    start,
  ) {
    Ok((response, ttfb)) => Ok(ResponseMetrics {
      status: response.status,
      bytes: response.body.len(),
      ttfb,
    }),
    Err(err) => Err(RequestFailure {
      message: err,
      ttfb: Some(start.elapsed()),
    }),
  }
}

pub(crate) fn execute_http1_request_direct(
  method: &str,
  url: &str,
  timeout: Duration,
  keep_alive: bool,
  body: Option<&Arc<Vec<u8>>>,
) -> Result<ResponseMetrics, RequestFailure> {
  let mut request = HttpRequest::new(method, url);
  if keep_alive {
    request = request.with_header("Connection", "keep-alive");
  } else {
    request = request.with_header("Connection", "close");
  }
  if let Some(payload) = body {
    request = request.with_body(payload.as_ref().clone());
  }

  let client = HttpClient::new().with_timeout(timeout);
  client
    .send_with_metrics(&request)
    .map(|(response, ttfb)| ResponseMetrics {
      status: response.status_code,
      bytes: response.body.len(),
      ttfb,
    })
    .map_err(|err| RequestFailure {
      message: err.message,
      ttfb: err.ttfb,
    })
}

#[derive(Debug, Clone)]
pub struct LoadConfig {
  pub url: String,
  pub concurrent_users: usize,
  pub requests_per_user: Option<usize>,
  pub duration: Option<Duration>,
  pub think_time: Duration,
  pub timeout: Duration,
  pub use_connection_pool: bool,
  pub max_idle_per_host: usize,
  pub use_thread_pool: bool,
  pub protocol: ProtocolPreference,
  pub method: String,
  pub body: Option<Arc<Vec<u8>>>,
  // Mode-related fields
  pub mode: LoadMode,
  /// Ratio of new users in realistic mode (0.0-1.0)
  pub new_user_ratio: f64,
  /// Requests per session before reconnect (realistic mode)
  pub session_length: Option<usize>,
  /// Think time variance multiplier (realistic mode)
  pub think_time_variance: f64,
  /// Gradual ramp-up duration
  pub ramp_up_duration: Option<Duration>,
  /// Warmup requests to skip from statistics
  pub warmup_requests: usize,
  /// Target RPS limit (0 = unlimited)
  pub rate_limit: usize,
  /// Use shared HTTP/2 connection pool (workers share connections)
  pub use_shared_http2_pool: bool,
  /// Maximum HTTP/2 connections per origin
  pub http2_max_connections_per_origin: usize,
  /// Interval between sending keep-alive header lines (Slowloris mode)
  pub slowloris_interval: Duration,
  /// Initial headers to send before starting the slow drip
  pub slowloris_initial_headers: usize,
}

impl LoadConfig {
  pub fn new(url: String) -> Self {
    Self {
      url,
      concurrent_users: 100,
      requests_per_user: None,
      duration: Some(Duration::from_secs(60)),
      think_time: Duration::from_millis(100),
      timeout: Duration::from_secs(30),
      use_connection_pool: true,
      max_idle_per_host: 50,
      use_thread_pool: true,
      protocol: ProtocolPreference::Auto,
      method: "GET".to_string(),
      body: None,
      // Mode defaults
      mode: LoadMode::Realistic,
      new_user_ratio: 0.3,
      session_length: None,
      think_time_variance: 0.0,
      ramp_up_duration: None,
      warmup_requests: 0,
      rate_limit: 0,
      // HTTP/2 shared pool defaults
      use_shared_http2_pool: true,
      http2_max_connections_per_origin: 6,
      // Slowloris defaults
      slowloris_interval: Duration::from_secs(10),
      slowloris_initial_headers: 3,
    }
  }

  /// Apply a testing mode with its default configuration
  pub fn with_mode(mut self, mode: LoadMode) -> Self {
    self.mode = mode;
    match mode {
      LoadMode::Throughput => {
        self.use_connection_pool = true;
        self.use_shared_http2_pool = true;
        self.think_time = Duration::ZERO;
        self.max_idle_per_host = self.concurrent_users.saturating_mul(2).max(100);
        self.http2_max_connections_per_origin = 6;
        self.think_time_variance = 0.0;
      }
      LoadMode::Connections => {
        self.use_connection_pool = false;
        self.use_shared_http2_pool = false;
        self.think_time = Duration::ZERO;
        self.think_time_variance = 0.0;
      }
      LoadMode::Realistic => {
        self.use_connection_pool = true;
        self.use_shared_http2_pool = true;
        self.think_time = Duration::from_millis(200);
        self.think_time_variance = 0.5;
        self.new_user_ratio = 0.3;
        self.session_length = Some(10);
        self.http2_max_connections_per_origin = 4;
      }
      LoadMode::Stress => {
        self.use_connection_pool = false;
        self.use_shared_http2_pool = false;
        self.think_time = Duration::ZERO;
        self.think_time_variance = 0.0;
      }
      LoadMode::Slowloris => {
        self.use_connection_pool = false;
        self.use_shared_http2_pool = false;
        self.think_time = Duration::ZERO;
        self.think_time_variance = 0.0;
      }
    }
    self
  }

  pub fn with_users(mut self, users: usize) -> Self {
    self.concurrent_users = users;
    self
  }

  pub fn with_duration(mut self, duration: Duration) -> Self {
    self.duration = Some(duration);
    self.requests_per_user = None;
    self
  }

  pub fn with_requests(mut self, requests: usize) -> Self {
    self.requests_per_user = Some(requests);
    self.duration = None;
    self
  }

  pub fn with_think_time(mut self, think_time: Duration) -> Self {
    self.think_time = think_time;
    self
  }

  pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  pub fn with_connection_pool(mut self, enabled: bool) -> Self {
    self.use_connection_pool = enabled;
    self
  }

  pub fn with_max_idle_per_host(mut self, max: usize) -> Self {
    self.max_idle_per_host = max;
    self
  }

  pub fn with_thread_pool(mut self, enabled: bool) -> Self {
    self.use_thread_pool = enabled;
    self
  }

  pub fn with_protocol(mut self, protocol: ProtocolPreference) -> Self {
    self.protocol = protocol;
    self
  }

  pub fn with_method<S: Into<String>>(mut self, method: S) -> Self {
    let mut value = method.into();
    if value.is_empty() {
      value = "GET".to_string();
    } else {
      value = value.to_ascii_uppercase();
    }
    self.method = value;
    self
  }

  pub fn with_body(mut self, body: Option<Vec<u8>>) -> Self {
    self.body = body.map(Arc::new);
    self
  }

  pub fn with_new_user_ratio(mut self, ratio: f64) -> Self {
    self.new_user_ratio = ratio.clamp(0.0, 1.0);
    self
  }

  pub fn with_session_length(mut self, length: Option<usize>) -> Self {
    self.session_length = length;
    self
  }

  pub fn with_think_time_variance(mut self, variance: f64) -> Self {
    self.think_time_variance = variance.max(0.0);
    self
  }

  pub fn with_ramp_up(mut self, duration: Option<Duration>) -> Self {
    self.ramp_up_duration = duration;
    self
  }

  pub fn with_warmup(mut self, requests: usize) -> Self {
    self.warmup_requests = requests;
    self
  }

  pub fn with_rate_limit(mut self, rps: usize) -> Self {
    self.rate_limit = rps;
    self
  }

  pub fn with_shared_http2_pool(mut self, enabled: bool) -> Self {
    self.use_shared_http2_pool = enabled;
    self
  }

  pub fn with_http2_max_connections(mut self, max: usize) -> Self {
    self.http2_max_connections_per_origin = max.max(1);
    self
  }

  pub fn with_slowloris_interval(mut self, interval: Duration) -> Self {
    self.slowloris_interval = interval;
    self
  }

  pub fn with_slowloris_initial_headers(mut self, count: usize) -> Self {
    self.slowloris_initial_headers = count.max(1);
    self
  }
}

/// Simple PRNG using xorshift64 - thread-local state for think time variance
pub(crate) fn rand_f64() -> f64 {
  use std::cell::Cell;
  thread_local! {
      static STATE: Cell<u64> = Cell::new(0);
  }
  STATE.with(|s| {
    let mut state = s.get();
    if state == 0 {
      // Seed from system time + pointer address for thread uniqueness
      state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
      // Use stack address as additional entropy (varies per thread)
      let stack_var: u64 = 0;
      state = state.wrapping_add(&stack_var as *const u64 as u64);
    }
    // xorshift64
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    s.set(state);
    (state as f64) / (u64::MAX as f64)
  })
}

/// Calculate variable think time using gaussian-like distribution
pub(crate) fn calculate_think_time(base: Duration, variance: f64) -> Duration {
  if variance <= 0.0 || base.is_zero() {
    return base;
  }

  let u1 = rand_f64().max(f64::EPSILON);
  let u2 = rand_f64();
  let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();

  let multiplier = 1.0 + (z * variance);
  let result_ms = base.as_millis() as f64 * multiplier.max(0.1);
  Duration::from_millis(result_ms.min(10000.0) as u64)
}

/// Determine if this worker should reuse connections based on mode and worker_id
pub(crate) fn should_reuse_connection(config: &LoadConfig, worker_id: usize) -> bool {
  match config.mode {
    LoadMode::Throughput => true,
    LoadMode::Connections | LoadMode::Stress | LoadMode::Slowloris => false,
    LoadMode::Realistic => {
      // Deterministic split based on worker_id
      let ratio = worker_id as f64 / config.concurrent_users.max(1) as f64;
      ratio >= config.new_user_ratio
    }
  }
}

/// Simple xorshift64 PRNG for slowloris header generation
pub(crate) fn simple_random(seed: &mut u64) -> u64 {
  *seed ^= *seed << 13;
  *seed ^= *seed >> 7;
  *seed ^= *seed << 17;
  *seed
}
