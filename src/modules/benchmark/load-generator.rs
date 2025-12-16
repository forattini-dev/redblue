use super::stats::{AtomicStatsCollector, Percentile, RequestStats, StatsAggregator};
use super::thread_pool::ThreadPool;
/// Multi-threaded load generator using std::thread
use crate::protocols::http::pool::{ConnectionPool, PooledHttpClient};
use crate::protocols::http::{HttpClient, HttpRequest};
use crate::protocols::http2::{Header, Http2Client, SharedHttp2Pool, SharedHttp2PoolConfig};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
}

impl FromStr for LoadMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "throughput" | "tput" | "rps" => Ok(Self::Throughput),
            "connections" | "conn" | "tls" => Ok(Self::Connections),
            "realistic" | "real" | "mixed" => Ok(Self::Realistic),
            "stress" | "max" | "break" => Ok(Self::Stress),
            other => Err(format!(
                "Invalid mode '{}'. Valid modes: throughput, connections, realistic, stress",
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
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Throughput => "Max RPS with connection reuse",
            Self::Connections => "New TCP+TLS per request",
            Self::Realistic => "Mixed user behavior simulation",
            Self::Stress => "Maximum connection pressure",
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
struct ProtocolTracker {
    requested: ProtocolPreference,
    negotiated: AtomicUsize,
    fallback: AtomicBool,
    reason: Mutex<Option<String>>,
}

impl ProtocolTracker {
    fn new(requested: ProtocolPreference) -> Self {
        Self {
            requested,
            negotiated: AtomicUsize::new(NegotiatedProtocol::Unknown as usize),
            fallback: AtomicBool::new(false),
            reason: Mutex::new(None),
        }
    }

    fn record_http2(&self) {
        self.negotiated
            .store(NegotiatedProtocol::Http2 as usize, Ordering::Relaxed);
        self.fallback.store(false, Ordering::Relaxed);
        let mut reason = self.reason.lock().unwrap();
        *reason = None;
    }

    fn record_http1(&self, fallback: bool, reason_text: Option<String>) {
        self.negotiated
            .store(NegotiatedProtocol::Http1 as usize, Ordering::Relaxed);
        self.fallback.store(fallback, Ordering::Relaxed);
        if fallback {
            let mut reason = self.reason.lock().unwrap();
            if reason.is_none() {
                *reason = reason_text;
            }
        }
    }

    fn outcome(&self) -> ProtocolOutcome {
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
struct ParsedTarget {
    url: String,
    host: String,
    authority: String,
    port: u16,
    path: String,
    is_https: bool,
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

fn parse_target(url: &str) -> Result<ParsedTarget, String> {
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
            return Err("IPv6 literals must be wrapped in []".to_string());
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

fn summarize_reason(reason: &str) -> String {
    const MAX_LEN: usize = 64;
    let trimmed = reason.trim();
    if trimmed.len() <= MAX_LEN {
        trimmed.to_string()
    } else {
        format!("{}…", &trimmed[..MAX_LEN.saturating_sub(1)])
    }
}

#[derive(Debug)]
struct ResponseMetrics {
    status: u16,
    bytes: usize,
    ttfb: Duration,
}

#[derive(Debug)]
struct RequestFailure {
    message: String,
    ttfb: Option<Duration>,
}

fn execute_http1_request(
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

fn execute_http2_request(
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

fn execute_http1_request_direct(
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
}

/// Simple PRNG using xorshift64 - thread-local state for think time variance
fn rand_f64() -> f64 {
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
fn calculate_think_time(base: Duration, variance: f64) -> Duration {
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
fn should_reuse_connection(config: &LoadConfig, worker_id: usize) -> bool {
    match config.mode {
        LoadMode::Throughput => true,
        LoadMode::Connections | LoadMode::Stress => false,
        LoadMode::Realistic => {
            // Deterministic split based on worker_id
            let ratio = worker_id as f64 / config.concurrent_users.max(1) as f64;
            ratio >= config.new_user_ratio
        }
    }
}

fn run_worker_session(
    config: LoadConfig,
    stats: Arc<AtomicStatsCollector>,
    should_stop: Arc<Mutex<bool>>,
    pool: Option<Arc<ConnectionPool>>,
    http2_pool: Option<Arc<SharedHttp2Pool>>,
    tracker: Arc<ProtocolTracker>,
    worker_id: usize,
) {
    let parsed = match parse_target(&config.url) {
        Ok(target) => target,
        Err(err) => {
            stats.add(RequestStats::error(Duration::ZERO, Duration::ZERO, err));
            return;
        }
    };

    let method = config.method.clone();
    let body = config.body.clone();

    let max_requests = config.requests_per_user.unwrap_or(usize::MAX);
    let max_duration = config
        .duration
        .unwrap_or_else(|| Duration::from_secs(86400));
    let mut request_count = 0usize;
    let user_start = Instant::now();

    // Mode-specific: determine if this worker reuses connections
    let reuse_connections = should_reuse_connection(&config, worker_id);
    let effective_pool = if reuse_connections { pool } else { None };

    // Session tracking for realistic mode (reconnect after N requests)
    let mut session_requests = 0usize;
    let session_limit = config.session_length.unwrap_or(usize::MAX);

    // Warmup tracking
    let warmup_count = config.warmup_requests;

    let mut http2_client: Option<Http2Client> = None;
    let mut http2_enabled = matches!(config.protocol, ProtocolPreference::Http2)
        || (matches!(config.protocol, ProtocolPreference::Auto) && parsed.is_https);
    let mut http2_reason: Option<String> = None;

    match config.protocol {
        ProtocolPreference::Http1 => tracker.record_http1(false, None),
        ProtocolPreference::Auto if !parsed.is_https => {
            let reason = "target is not HTTPS (HTTP/2 requires TLS)".to_string();
            http2_enabled = false;
            http2_reason = Some(reason.clone());
            tracker.record_http1(true, Some(reason));
        }
        _ => {}
    }

    loop {
        {
            if *should_stop.lock().unwrap() {
                break;
            }
        }

        if request_count >= max_requests {
            break;
        }

        if user_start.elapsed() >= max_duration {
            let mut stop = should_stop.lock().unwrap();
            *stop = true;
            break;
        }

        let req_start = Instant::now();
        let mut stat: Option<RequestStats> = None;

        if http2_enabled {
            // Try shared HTTP/2 pool first (if available and reusing connections)
            if let Some(ref h2_pool) = http2_pool {
                if reuse_connections {
                    let mut extra_headers = Vec::new();
                    let body_vec = body.as_ref().map(|b| b.as_ref().clone());
                    if let Some(ref payload) = body_vec {
                        extra_headers
                            .push(Header::new("content-length", payload.len().to_string()));
                    }

                    match h2_pool.execute_request(
                        &parsed.host,
                        parsed.port,
                        &method,
                        &parsed.path,
                        &parsed.authority,
                        extra_headers,
                        body_vec,
                        req_start,
                    ) {
                        Ok((response, ttfb)) => {
                            tracker.record_http2();
                            stat = Some(RequestStats::success(
                                req_start.elapsed(),
                                ttfb,
                                response.status,
                                response.body.len(),
                            ));
                        }
                        Err(err) => {
                            let summary = summarize_reason(&err);
                            match config.protocol {
                                ProtocolPreference::Auto => {
                                    http2_enabled = false;
                                    http2_reason = Some(summary.clone());
                                    tracker.record_http1(true, Some(summary));
                                }
                                ProtocolPreference::Http2 => {
                                    let ttfb = req_start.elapsed();
                                    stat =
                                        Some(RequestStats::error(req_start.elapsed(), ttfb, err));
                                }
                                ProtocolPreference::Http1 => {}
                            }
                        }
                    }
                }
            }

            // Fall back to individual client if shared pool not used
            if stat.is_none() && http2_pool.is_none() || !reuse_connections {
                if http2_client.is_none() {
                    match Http2Client::connect(&parsed.host, parsed.port) {
                        Ok(client) => {
                            http2_client = Some(client);
                        }
                        Err(err) => {
                            let summary = summarize_reason(&err);
                            match config.protocol {
                                ProtocolPreference::Auto => {
                                    http2_enabled = false;
                                    http2_reason = Some(summary.clone());
                                    tracker.record_http1(true, Some(summary));
                                }
                                ProtocolPreference::Http2 => {
                                    let ttfb = req_start.elapsed();
                                    stat =
                                        Some(RequestStats::error(req_start.elapsed(), ttfb, err));
                                }
                                ProtocolPreference::Http1 => {}
                            }
                        }
                    }
                }

                if stat.is_none() {
                    if let Some(client) = http2_client.as_mut() {
                        match execute_http2_request(
                            client,
                            &parsed,
                            &method,
                            body.as_ref(),
                            req_start,
                        ) {
                            Ok(metrics) => {
                                tracker.record_http2();
                                stat = Some(RequestStats::success(
                                    req_start.elapsed(),
                                    metrics.ttfb,
                                    metrics.status,
                                    metrics.bytes,
                                ));
                            }
                            Err(err) => {
                                let summary = summarize_reason(&err.message);
                                match config.protocol {
                                    ProtocolPreference::Auto => {
                                        http2_enabled = false;
                                        http2_client = None;
                                        http2_reason = Some(summary.clone());
                                        tracker.record_http1(true, Some(summary));
                                    }
                                    ProtocolPreference::Http2 => {
                                        let ttfb = err.ttfb.unwrap_or_else(|| req_start.elapsed());
                                        stat = Some(RequestStats::error(
                                            req_start.elapsed(),
                                            ttfb,
                                            err.message,
                                        ));
                                    }
                                    ProtocolPreference::Http1 => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        if stat.is_none() {
            let http1_pool = effective_pool.as_ref().map(Arc::clone);
            match execute_http1_request(
                &method,
                &parsed.url,
                config.timeout,
                http1_pool,
                reuse_connections && config.use_connection_pool,
                body.as_ref(),
                req_start,
            ) {
                Ok(metrics) => {
                    let fallback = matches!(config.protocol, ProtocolPreference::Auto)
                        && http2_reason.is_some();
                    tracker.record_http1(fallback, http2_reason.clone());
                    stat = Some(RequestStats::success(
                        req_start.elapsed(),
                        metrics.ttfb,
                        metrics.status,
                        metrics.bytes,
                    ));
                }
                Err(err) => {
                    stat = Some(RequestStats::error(
                        req_start.elapsed(),
                        err.ttfb.unwrap_or_else(|| req_start.elapsed()),
                        err.message,
                    ));
                }
            }
        }

        // Only count stats after warmup period
        if request_count >= warmup_count {
            stats.add(stat.expect("request stat must be set"));
        }
        request_count += 1;
        session_requests += 1;

        // Session-based reconnection for realistic mode
        if config.mode == LoadMode::Realistic && session_requests >= session_limit {
            http2_client = None; // Force reconnection on next request
            session_requests = 0;
        }

        // Think time with optional variance
        if config.think_time > Duration::ZERO {
            let delay = calculate_think_time(config.think_time, config.think_time_variance);
            thread::sleep(delay);
        }
    }
}

#[derive(Debug)]
pub struct LoadTestResults {
    pub config: LoadConfig,
    pub test_duration: Duration,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub requests_per_second: f64,
    pub latency: Percentile,
    pub ttfb: Percentile,
    pub status_2xx: usize,
    pub status_3xx: usize,
    pub status_4xx: usize,
    pub status_5xx: usize,
    pub total_bytes: usize,
    pub throughput_mbps: f64,
    pub success_rate: f64,
    pub errors: Vec<String>,
    pub protocol: ProtocolOutcome,
}

pub struct LoadGenerator {
    config: LoadConfig,
}

#[derive(Clone)]
struct LiveObserver {
    callback: Arc<dyn Fn(LiveSnapshot) + Send + Sync>,
    interval: Duration,
}

#[derive(Debug, Clone)]
pub struct LiveSnapshot {
    pub elapsed: Duration,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub status_2xx: usize,
    pub status_3xx: usize,
    pub status_4xx: usize,
    pub status_5xx: usize,
    pub requests_per_second: f64,
    pub throughput_mbps: f64,
    pub success_rate: f64,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub ttfb_p50: Duration,
    pub ttfb_p95: Duration,
    pub ttfb_p99: Duration,
}

impl LoadGenerator {
    pub fn new(config: LoadConfig) -> Self {
        Self { config }
    }

    /// Run load test with multi-threading
    pub fn run(&self) -> Result<LoadTestResults, String> {
        self.run_internal(None)
    }

    /// Run load test with periodic observer callbacks.
    pub fn run_with_observer(
        &self,
        interval: Duration,
        observer: Arc<dyn Fn(LiveSnapshot) + Send + Sync>,
    ) -> Result<LoadTestResults, String> {
        let live = LiveObserver {
            callback: observer,
            interval,
        };
        self.run_internal(Some(live))
    }

    fn run_internal(&self, live: Option<LiveObserver>) -> Result<LoadTestResults, String> {
        if self.config.use_thread_pool {
            self.run_with_thread_pool(live)
        } else {
            self.run_with_spawn(live)
        }
    }

    /// Run using thread pool (FASTEST - reuses threads)
    fn run_with_thread_pool(&self, live: Option<LiveObserver>) -> Result<LoadTestResults, String> {
        let start_time = Instant::now();
        let stats = Arc::new(AtomicStatsCollector::new());
        let should_stop = Arc::new(Mutex::new(false));
        let protocol_tracker = Arc::new(ProtocolTracker::new(self.config.protocol));

        // Create HTTP/1.1 connection pool if enabled
        let pool = if self.config.use_connection_pool {
            Some(Arc::new(
                ConnectionPool::new().with_max_idle(self.config.max_idle_per_host),
            ))
        } else {
            None
        };

        // Create shared HTTP/2 pool if enabled
        let http2_pool = if self.config.use_shared_http2_pool {
            let config = SharedHttp2PoolConfig {
                max_connections_per_origin: self.config.http2_max_connections_per_origin,
                ..Default::default()
            };
            Some(Arc::new(SharedHttp2Pool::with_config(config)))
        } else {
            None
        };

        // Create thread pool (reuses threads!)
        let thread_pool = ThreadPool::new(self.config.concurrent_users);
        let active_workers = Arc::new(AtomicUsize::new(self.config.concurrent_users));

        let live_handle = live.as_ref().map(|observer| {
            spawn_live_reporter(
                Arc::clone(&stats),
                Arc::clone(&should_stop),
                observer.clone(),
                start_time,
            )
        });

        for user_id in 0..self.config.concurrent_users {
            let worker_config = self.config.clone();
            let stats = Arc::clone(&stats);
            let should_stop = Arc::clone(&should_stop);
            let pool = pool.clone();
            let http2_pool = http2_pool.clone();
            let active_workers = Arc::clone(&active_workers);
            let tracker = Arc::clone(&protocol_tracker);

            thread_pool.execute(move || {
                run_worker_session(
                    worker_config,
                    stats,
                    should_stop,
                    pool,
                    http2_pool,
                    tracker,
                    user_id,
                );

                // Decrement active workers counter
                active_workers.fetch_sub(1, Ordering::Relaxed);
            });
        }

        // Wait for all workers to complete
        while active_workers.load(Ordering::Relaxed) > 0 {
            thread::sleep(Duration::from_millis(10));
        }

        {
            let mut stop = should_stop.lock().unwrap();
            *stop = true;
        }

        if let Some(handle) = live_handle {
            let _ = handle.join();
        }

        let test_duration = start_time.elapsed();

        // Take snapshot of atomic stats
        let stats = match Arc::try_unwrap(stats) {
            Ok(atomic_stats) => atomic_stats.snapshot(),
            Err(arc) => arc.snapshot(),
        };

        let protocol_outcome = protocol_tracker.outcome();

        build_results(&self.config, stats, test_duration, protocol_outcome)
    }

    /// Run using thread::spawn (legacy method)
    fn run_with_spawn(&self, live: Option<LiveObserver>) -> Result<LoadTestResults, String> {
        let start_time = Instant::now();
        let stats = Arc::new(AtomicStatsCollector::new());
        let should_stop = Arc::new(Mutex::new(false));
        let protocol_tracker = Arc::new(ProtocolTracker::new(self.config.protocol));

        // Create HTTP/1.1 connection pool if enabled
        let pool = if self.config.use_connection_pool {
            Some(Arc::new(
                ConnectionPool::new().with_max_idle(self.config.max_idle_per_host),
            ))
        } else {
            None
        };

        // Create shared HTTP/2 pool if enabled
        let http2_pool = if self.config.use_shared_http2_pool {
            let config = SharedHttp2PoolConfig {
                max_connections_per_origin: self.config.http2_max_connections_per_origin,
                ..Default::default()
            };
            Some(Arc::new(SharedHttp2Pool::with_config(config)))
        } else {
            None
        };

        // Spawn worker threads with smaller stack size
        let mut handles = Vec::new();

        let live_handle = live.as_ref().map(|observer| {
            spawn_live_reporter(
                Arc::clone(&stats),
                Arc::clone(&should_stop),
                observer.clone(),
                start_time,
            )
        });

        for user_id in 0..self.config.concurrent_users {
            let worker_config = self.config.clone();
            let stats = Arc::clone(&stats);
            let should_stop = Arc::clone(&should_stop);
            let pool = pool.clone();
            let http2_pool = http2_pool.clone();
            let tracker = Arc::clone(&protocol_tracker);

            // Use Builder to set smaller stack (256KB instead of default 2MB)
            // This allows 8x more concurrent users with same memory!
            let handle = thread::Builder::new()
                .stack_size(256 * 1024) // 256KB stack
                .spawn(move || {
                    run_worker_session(
                        worker_config,
                        stats,
                        should_stop,
                        pool,
                        http2_pool,
                        tracker,
                        user_id,
                    );
                })
                .expect("Failed to spawn thread");

            handles.push(handle);
        }

        // Wait for all workers
        for handle in handles {
            let _ = handle.join();
        }

        {
            let mut stop = should_stop.lock().unwrap();
            *stop = true;
        }

        if let Some(handle) = live_handle {
            let _ = handle.join();
        }

        let test_duration = start_time.elapsed();

        // Take snapshot of atomic stats
        let stats = match Arc::try_unwrap(stats) {
            Ok(atomic_stats) => atomic_stats.snapshot(),
            Err(arc) => arc.snapshot(),
        };

        let protocol_outcome = protocol_tracker.outcome();

        build_results(&self.config, stats, test_duration, protocol_outcome)
    }
}

fn build_results(
    config: &LoadConfig,
    stats: StatsAggregator,
    test_duration: Duration,
    protocol: ProtocolOutcome,
) -> Result<LoadTestResults, String> {
    let latency = stats.percentiles();
    let ttfb = stats.ttfb_percentiles();
    let success_rate = stats.success_rate();
    let rps = stats.requests_per_second(test_duration);
    let throughput = stats.throughput_mbps(test_duration);

    // Take only first 100 errors to avoid huge output
    let mut errors = stats.errors.clone();
    errors.truncate(100);

    Ok(LoadTestResults {
        config: config.clone(),
        test_duration,
        total_requests: stats.total_requests,
        successful_requests: stats.successful_requests,
        failed_requests: stats.failed_requests,
        requests_per_second: rps,
        latency,
        ttfb,
        status_2xx: stats.status_2xx,
        status_3xx: stats.status_3xx,
        status_4xx: stats.status_4xx,
        status_5xx: stats.status_5xx,
        total_bytes: stats.total_bytes,
        throughput_mbps: throughput,
        success_rate,
        errors,
        protocol,
    })
}

// Clone impl no longer needed - using AtomicStatsCollector.snapshot() instead

fn spawn_live_reporter(
    stats: Arc<AtomicStatsCollector>,
    should_stop: Arc<Mutex<bool>>,
    observer: LiveObserver,
    start_time: Instant,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        {
            if *should_stop.lock().unwrap() {
                break;
            }
        }

        let snapshot = stats.snapshot();
        let elapsed = start_time.elapsed();
        let percentiles = snapshot.percentiles();
        let ttfb_percentiles = snapshot.ttfb_percentiles();
        let live_snapshot = LiveSnapshot {
            elapsed,
            total_requests: snapshot.total_requests,
            successful_requests: snapshot.successful_requests,
            failed_requests: snapshot.failed_requests,
            status_2xx: snapshot.status_2xx,
            status_3xx: snapshot.status_3xx,
            status_4xx: snapshot.status_4xx,
            status_5xx: snapshot.status_5xx,
            requests_per_second: snapshot.requests_per_second(elapsed),
            throughput_mbps: snapshot.throughput_mbps(elapsed),
            success_rate: snapshot.success_rate(),
            p50: percentiles.p50,
            p95: percentiles.p95,
            p99: percentiles.p99,
            ttfb_p50: ttfb_percentiles.p50,
            ttfb_p95: ttfb_percentiles.p95,
            ttfb_p99: ttfb_percentiles.p99,
        };

        (observer.callback)(live_snapshot);

        thread::sleep(observer.interval);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_preference_from_str() {
        // Auto variants
        assert_eq!(
            ProtocolPreference::from_str("").unwrap(),
            ProtocolPreference::Auto
        );
        assert_eq!(
            ProtocolPreference::from_str("auto").unwrap(),
            ProtocolPreference::Auto
        );
        assert_eq!(
            ProtocolPreference::from_str("AUTO").unwrap(),
            ProtocolPreference::Auto
        );

        // HTTP/1 variants
        assert_eq!(
            ProtocolPreference::from_str("http1").unwrap(),
            ProtocolPreference::Http1
        );
        assert_eq!(
            ProtocolPreference::from_str("http/1").unwrap(),
            ProtocolPreference::Http1
        );
        assert_eq!(
            ProtocolPreference::from_str("http/1.1").unwrap(),
            ProtocolPreference::Http1
        );
        assert_eq!(
            ProtocolPreference::from_str("1").unwrap(),
            ProtocolPreference::Http1
        );

        // HTTP/2 variants
        assert_eq!(
            ProtocolPreference::from_str("http2").unwrap(),
            ProtocolPreference::Http2
        );
        assert_eq!(
            ProtocolPreference::from_str("http/2").unwrap(),
            ProtocolPreference::Http2
        );
        assert_eq!(
            ProtocolPreference::from_str("2").unwrap(),
            ProtocolPreference::Http2
        );
        assert_eq!(
            ProtocolPreference::from_str("h2").unwrap(),
            ProtocolPreference::Http2
        );

        // Invalid
        assert!(ProtocolPreference::from_str("invalid").is_err());
        assert!(ProtocolPreference::from_str("http3").is_err());
    }

    #[test]
    fn test_protocol_preference_labels() {
        assert_eq!(ProtocolPreference::Auto.label(), "auto");
        assert_eq!(ProtocolPreference::Http1.label(), "http1");
        assert_eq!(ProtocolPreference::Http2.label(), "http2");
    }

    #[test]
    fn test_negotiated_protocol_labels() {
        assert_eq!(NegotiatedProtocol::Unknown.label(), "unknown");
        assert_eq!(NegotiatedProtocol::Http1.label(), "http1");
        assert_eq!(NegotiatedProtocol::Http2.label(), "http2");
    }

    #[test]
    fn test_load_mode_from_str() {
        // Throughput variants
        assert_eq!(
            LoadMode::from_str("throughput").unwrap(),
            LoadMode::Throughput
        );
        assert_eq!(LoadMode::from_str("tput").unwrap(), LoadMode::Throughput);
        assert_eq!(LoadMode::from_str("rps").unwrap(), LoadMode::Throughput);

        // Connections variants
        assert_eq!(
            LoadMode::from_str("connections").unwrap(),
            LoadMode::Connections
        );
        assert_eq!(LoadMode::from_str("conn").unwrap(), LoadMode::Connections);
        assert_eq!(LoadMode::from_str("tls").unwrap(), LoadMode::Connections);

        // Realistic variants
        assert_eq!(
            LoadMode::from_str("realistic").unwrap(),
            LoadMode::Realistic
        );
        assert_eq!(LoadMode::from_str("real").unwrap(), LoadMode::Realistic);
        assert_eq!(LoadMode::from_str("mixed").unwrap(), LoadMode::Realistic);

        // Stress variants
        assert_eq!(LoadMode::from_str("stress").unwrap(), LoadMode::Stress);
        assert_eq!(LoadMode::from_str("max").unwrap(), LoadMode::Stress);
        assert_eq!(LoadMode::from_str("break").unwrap(), LoadMode::Stress);

        // Invalid
        assert!(LoadMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_protocol_outcome_display() {
        let outcome_http2 = ProtocolOutcome {
            requested: ProtocolPreference::Auto,
            negotiated: NegotiatedProtocol::Http2,
            fallback: false,
            fallback_reason: None,
        };
        assert_eq!(outcome_http2.display_label(), "http2");

        let outcome_http1_fallback = ProtocolOutcome {
            requested: ProtocolPreference::Auto,
            negotiated: NegotiatedProtocol::Http1,
            fallback: true,
            fallback_reason: Some("not HTTPS".to_string()),
        };
        assert_eq!(
            outcome_http1_fallback.display_label(),
            "http1 (fallback: not HTTPS)"
        );

        let outcome_http1_no_reason = ProtocolOutcome {
            requested: ProtocolPreference::Auto,
            negotiated: NegotiatedProtocol::Http1,
            fallback: true,
            fallback_reason: None,
        };
        assert_eq!(outcome_http1_no_reason.display_label(), "http1 (fallback)");
    }

    #[test]
    fn test_parse_target() {
        // HTTPS URL
        let result = parse_target("https://example.com/path").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.port, 443);
        assert_eq!(result.path, "/path");
        assert!(result.is_https);

        // HTTP URL
        let result = parse_target("http://example.com/").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.port, 80);
        assert_eq!(result.path, "/");
        assert!(!result.is_https);

        // Custom port
        let result = parse_target("https://example.com:8443/api").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.port, 8443);
        assert_eq!(result.path, "/api");

        // No path
        let result = parse_target("https://example.com").unwrap();
        assert_eq!(result.path, "/");

        // Authority formatting
        let result = parse_target("https://example.com:443/").unwrap();
        assert_eq!(result.authority, "example.com"); // Default port omitted

        let result = parse_target("https://example.com:8443/").unwrap();
        assert_eq!(result.authority, "example.com:8443"); // Non-default port included
    }

    #[test]
    fn test_load_config_builders() {
        let config = LoadConfig::new("https://test.com".to_string())
            .with_users(50)
            .with_duration(Duration::from_secs(30))
            .with_protocol(ProtocolPreference::Http2)
            .with_method("POST")
            .with_timeout(Duration::from_secs(10));

        assert_eq!(config.concurrent_users, 50);
        assert_eq!(config.duration, Some(Duration::from_secs(30)));
        assert_eq!(config.protocol, ProtocolPreference::Http2);
        assert_eq!(config.method, "POST");
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_load_config_mode_defaults() {
        // Throughput mode
        let config =
            LoadConfig::new("https://test.com".to_string()).with_mode(LoadMode::Throughput);
        assert!(config.use_connection_pool);
        assert!(config.use_shared_http2_pool);
        assert_eq!(config.think_time, Duration::ZERO);

        // Connections mode
        let config =
            LoadConfig::new("https://test.com".to_string()).with_mode(LoadMode::Connections);
        assert!(!config.use_connection_pool);
        assert!(!config.use_shared_http2_pool);

        // Realistic mode
        let config = LoadConfig::new("https://test.com".to_string()).with_mode(LoadMode::Realistic);
        assert!(config.use_connection_pool);
        assert_eq!(config.think_time, Duration::from_millis(200));
        assert_eq!(config.new_user_ratio, 0.3);
        assert_eq!(config.session_length, Some(10));
    }

    #[test]
    fn test_should_reuse_connection() {
        let mut config = LoadConfig::new("https://test.com".to_string());

        // Throughput always reuses
        config.mode = LoadMode::Throughput;
        assert!(should_reuse_connection(&config, 0));
        assert!(should_reuse_connection(&config, 99));

        // Connections never reuses
        config.mode = LoadMode::Connections;
        assert!(!should_reuse_connection(&config, 0));
        assert!(!should_reuse_connection(&config, 99));

        // Stress never reuses
        config.mode = LoadMode::Stress;
        assert!(!should_reuse_connection(&config, 0));

        // Realistic depends on worker_id and ratio
        config.mode = LoadMode::Realistic;
        config.concurrent_users = 10;
        config.new_user_ratio = 0.3;
        // Workers 0-2 (30%) are "new users" - no connection reuse
        assert!(!should_reuse_connection(&config, 0));
        assert!(!should_reuse_connection(&config, 2));
        // Workers 3-9 (70%) are "returning users" - reuse connections
        assert!(should_reuse_connection(&config, 3));
        assert!(should_reuse_connection(&config, 9));
    }
}
