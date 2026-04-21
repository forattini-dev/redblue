use super::stats::{AtomicStatsCollector, Percentile, RequestStats, StatsAggregator};
use super::thread_pool::ThreadPool;
use crate::protocols::http::pool::ConnectionPool;
use crate::protocols::http2::hpack::Header;
use crate::protocols::http2::{Http2Client, SharedHttp2Pool, SharedHttp2PoolConfig};
mod load_generator_core;
use load_generator_core::{
  calculate_think_time, execute_http1_request, execute_http1_request_direct, execute_http2_request,
  parse_target, rand_f64, should_reuse_connection, simple_random, summarize_reason, ParsedTarget,
  ProtocolTracker, RequestFailure, ResponseMetrics,
};
pub use load_generator_core::{
  LoadConfig, LoadMode, NegotiatedProtocol, ProtocolOutcome, ProtocolPreference,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Slowloris worker: opens a TCP (or TLS) connection, sends partial HTTP
/// headers, then drip-feeds extra headers at `slowloris_interval` to keep
/// the connection alive without ever completing the request.
fn run_slowloris_worker(
  config: &LoadConfig,
  stats: &Arc<AtomicStatsCollector>,
  should_stop: &Arc<Mutex<bool>>,
  worker_id: usize,
) {
  let parsed = match parse_target(&config.url) {
    Ok(target) => target,
    Err(err) => {
      stats.add(RequestStats::error(Duration::ZERO, Duration::ZERO, err));
      return;
    }
  };

  let addr = format!("{}:{}", parsed.host, parsed.port);

  // Seed PRNG from worker_id and current time for uniqueness
  let mut rng_state = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos() as u64;
  rng_state = rng_state
    .wrapping_add(worker_id as u64)
    .wrapping_mul(6364136223846793005);
  // Ensure non-zero seed
  if rng_state == 0 {
    rng_state = 0xdeadbeef_cafebabe;
  }

  let max_duration = config
    .duration
    .unwrap_or_else(|| Duration::from_secs(86400));
  let worker_start = Instant::now();

  loop {
    // Check stop conditions
    if *should_stop.lock().unwrap() {
      break;
    }
    if worker_start.elapsed() >= max_duration {
      let mut stop = should_stop.lock().unwrap();
      *stop = true;
      break;
    }

    let conn_start = Instant::now();

    // Open a connection (plain TCP or TLS via boring)
    let mut stream: Box<dyn std::io::Write + Send> = if parsed.is_https {
      #[cfg(not(target_os = "windows"))]
      {
        match establish_tls_stream(&addr, &parsed.host) {
          Ok(s) => Box::new(s),
          Err(err) => {
            stats.add(RequestStats::error(
              conn_start.elapsed(),
              conn_start.elapsed(),
              format!("TLS connect failed: {}", err),
            ));
            // Brief backoff before retry
            thread::sleep(Duration::from_millis(500));
            continue;
          }
        }
      }
      #[cfg(target_os = "windows")]
      {
        stats.add(RequestStats::error(
          conn_start.elapsed(),
          conn_start.elapsed(),
          "Slowloris TLS not supported on Windows".to_string(),
        ));
        return;
      }
    } else {
      match std::net::TcpStream::connect(&addr) {
        Ok(tcp) => {
          let _ = tcp.set_write_timeout(Some(Duration::from_secs(30)));
          let _ = tcp.set_read_timeout(Some(Duration::from_secs(1)));
          Box::new(tcp)
        }
        Err(err) => {
          stats.add(RequestStats::error(
            conn_start.elapsed(),
            conn_start.elapsed(),
            format!("TCP connect failed: {}", err),
          ));
          thread::sleep(Duration::from_millis(500));
          continue;
        }
      }
    };

    // Send the initial incomplete HTTP request
    let initial_request = format!(
      "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,*/*\r\n",
      parsed.path, parsed.host,
    );

    if let Err(err) = stream.write_all(initial_request.as_bytes()) {
      stats.add(RequestStats::error(
        conn_start.elapsed(),
        conn_start.elapsed(),
        format!("Initial write failed: {}", err),
      ));
      continue;
    }
    let _ = stream.flush();

    // Count the initial headers as successful "requests" (one stat per header sent)
    // Initial line + Host + User-Agent + Accept = config.slowloris_initial_headers
    for _ in 0..config.slowloris_initial_headers {
      stats.add(RequestStats::success(
        conn_start.elapsed(),
        conn_start.elapsed(),
        0, // no HTTP status yet
        0,
      ));
    }

    // Drip-feed extra headers at the configured interval
    loop {
      // Check stop before sleeping
      if *should_stop.lock().unwrap() {
        return;
      }
      if worker_start.elapsed() >= max_duration {
        let mut stop = should_stop.lock().unwrap();
        *stop = true;
        return;
      }

      // Sleep for the slowloris interval, checking stop periodically
      let sleep_end = Instant::now() + config.slowloris_interval;
      while Instant::now() < sleep_end {
        if *should_stop.lock().unwrap() {
          return;
        }
        let remaining = sleep_end.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(500)));
      }

      // Generate a random keep-alive header
      let key_val = simple_random(&mut rng_state);
      let val_val = simple_random(&mut rng_state);
      let header_line = format!("X-rb-{}: {}\r\n", key_val, val_val);

      match stream.write_all(header_line.as_bytes()) {
        Ok(()) => {
          let _ = stream.flush();
          // Each header sent counts as a successful "request" in stats
          stats.add(RequestStats::success(
            conn_start.elapsed(),
            conn_start.elapsed(),
            0,
            header_line.len(),
          ));
        }
        Err(_) => {
          // Connection dropped — count as error and reconnect
          stats.add(RequestStats::error(
            conn_start.elapsed(),
            conn_start.elapsed(),
            "Connection dropped — reconnecting".to_string(),
          ));
          break; // Break inner loop to reconnect in outer loop
        }
      }
    }
  }
}

/// Establish a TLS connection using boring for Slowloris mode
#[cfg(not(target_os = "windows"))]
fn establish_tls_stream(
  addr: &str,
  host: &str,
) -> Result<boring::ssl::SslStream<std::net::TcpStream>, String> {
  use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};

  let tcp =
    std::net::TcpStream::connect(addr).map_err(|e| format!("TCP connect to {}: {}", addr, e))?;
  let _ = tcp.set_write_timeout(Some(Duration::from_secs(30)));
  let _ = tcp.set_read_timeout(Some(Duration::from_secs(1)));

  let mut builder =
    SslConnector::builder(SslMethod::tls()).map_err(|e| format!("SSL connector builder: {}", e))?;
  builder.set_verify(SslVerifyMode::NONE);
  let connector = builder.build();

  connector
    .connect(host, tcp)
    .map_err(|e| format!("TLS handshake with {}: {}", host, e))
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
  // Slowloris mode uses its own dedicated worker
  if config.mode == LoadMode::Slowloris {
    run_slowloris_worker(&config, &stats, &should_stop, worker_id);
    return;
  }

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
            extra_headers.push(Header::new("content-length", payload.len().to_string()));
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
                  stat = Some(RequestStats::error(req_start.elapsed(), ttfb, err));
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
                  stat = Some(RequestStats::error(req_start.elapsed(), ttfb, err));
                }
                ProtocolPreference::Http1 => {}
              }
            }
          }
        }

        if stat.is_none() {
          if let Some(client) = http2_client.as_mut() {
            match execute_http2_request(client, &parsed, &method, body.as_ref(), req_start) {
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
                    stat = Some(RequestStats::error(req_start.elapsed(), ttfb, err.message));
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
          let fallback =
            matches!(config.protocol, ProtocolPreference::Auto) && http2_reason.is_some();
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
  use std::str::FromStr;

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

    // Slowloris variants
    assert_eq!(
      LoadMode::from_str("slowloris").unwrap(),
      LoadMode::Slowloris
    );
    assert_eq!(LoadMode::from_str("slow").unwrap(), LoadMode::Slowloris);
    assert_eq!(LoadMode::from_str("loris").unwrap(), LoadMode::Slowloris);

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
    let config = LoadConfig::new("https://test.com".to_string()).with_mode(LoadMode::Throughput);
    assert!(config.use_connection_pool);
    assert!(config.use_shared_http2_pool);
    assert_eq!(config.think_time, Duration::ZERO);

    // Connections mode
    let config = LoadConfig::new("https://test.com".to_string()).with_mode(LoadMode::Connections);
    assert!(!config.use_connection_pool);
    assert!(!config.use_shared_http2_pool);

    // Realistic mode
    let config = LoadConfig::new("https://test.com".to_string()).with_mode(LoadMode::Realistic);
    assert!(config.use_connection_pool);
    assert_eq!(config.think_time, Duration::from_millis(200));
    assert_eq!(config.new_user_ratio, 0.3);
    assert_eq!(config.session_length, Some(10));

    // Slowloris mode
    let config = LoadConfig::new("https://test.com".to_string()).with_mode(LoadMode::Slowloris);
    assert!(!config.use_connection_pool);
    assert!(!config.use_shared_http2_pool);
    assert_eq!(config.think_time, Duration::ZERO);
    assert_eq!(config.slowloris_interval, Duration::from_secs(10));
    assert_eq!(config.slowloris_initial_headers, 3);
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

    // Slowloris never reuses
    config.mode = LoadMode::Slowloris;
    assert!(!should_reuse_connection(&config, 0));
    assert!(!should_reuse_connection(&config, 99));

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

  #[test]
  fn test_simple_random() {
    let mut seed: u64 = 12345;
    let a = simple_random(&mut seed);
    let b = simple_random(&mut seed);
    // Values should differ
    assert_ne!(a, b);
    // Seed should have changed
    assert_ne!(seed, 12345);
    // Deterministic: same seed produces same sequence
    let mut seed2: u64 = 12345;
    let a2 = simple_random(&mut seed2);
    assert_eq!(a, a2);
  }

  #[test]
  fn test_slowloris_config_builders() {
    let config = LoadConfig::new("https://test.com".to_string())
      .with_slowloris_interval(Duration::from_secs(5))
      .with_slowloris_initial_headers(6);
    assert_eq!(config.slowloris_interval, Duration::from_secs(5));
    assert_eq!(config.slowloris_initial_headers, 6);

    // Minimum initial headers is 1
    let config = LoadConfig::new("https://test.com".to_string()).with_slowloris_initial_headers(0);
    assert_eq!(config.slowloris_initial_headers, 1);
  }

  #[test]
  fn test_slowloris_mode_labels() {
    assert_eq!(LoadMode::Slowloris.label(), "slowloris");
    assert_eq!(
      LoadMode::Slowloris.description(),
      "Slow HTTP attack \u{2014} holds connections with partial requests"
    );
  }
}
