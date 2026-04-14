//! Resource stress testing — CPU, memory, I/O load generation.
//!
//! Pure std, zero deps. Designed for resilience auditing of authorized systems.
//! Hard safety ceilings: timeout max 10min, memory capped by `/proc/meminfo`.

pub mod cpu;
pub mod io;
pub mod limits;
pub mod mem;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Clone)]
pub struct StressConfig {
  pub workers: usize,
  pub timeout: Duration,
  pub bytes: Option<u64>,
  pub mem_pct: Option<u8>,
  pub path: Option<String>,
  pub fsync: bool,
  pub method: CpuMethod,
  pub max_mem_pct: u8,
}

impl Default for StressConfig {
  fn default() -> Self {
    Self {
      workers: num_cpus_fallback(),
      timeout: Duration::from_secs(30),
      bytes: None,
      mem_pct: None,
      path: None,
      fsync: true,
      method: CpuMethod::Sha256,
      max_mem_pct: 80,
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuMethod {
  Sha256,
  Matrix,
  Prime,
}

impl CpuMethod {
  pub fn parse(s: &str) -> Option<Self> {
    match s.to_ascii_lowercase().as_str() {
      "sha256" | "hash" => Some(Self::Sha256),
      "matrix" | "mat" => Some(Self::Matrix),
      "prime" | "primes" => Some(Self::Prime),
      _ => None,
    }
  }

  pub fn name(&self) -> &'static str {
    match self {
      Self::Sha256 => "sha256",
      Self::Matrix => "matrix",
      Self::Prime => "prime",
    }
  }
}

#[derive(Debug, Default)]
pub struct StressStats {
  pub kind: &'static str,
  pub workers: usize,
  pub elapsed_ms: u64,
  pub total_ops: u64,
  pub ops_per_sec: f64,
  pub bytes_touched: u64,
  pub bytes_per_sec: f64,
  pub per_worker_ops: Vec<u64>,
  pub peak_rss_kb: u64,
  pub load_avg: Option<(f64, f64, f64)>,
  pub note: Option<String>,
}

/// Shared runtime state for worker pool.
#[derive(Clone)]
pub struct Deadline {
  stop: Arc<AtomicBool>,
  end: Instant,
}

impl Deadline {
  pub fn new(timeout: Duration) -> Self {
    Self {
      stop: Arc::new(AtomicBool::new(false)),
      end: Instant::now() + timeout,
    }
  }

  pub fn expired(&self) -> bool {
    self.stop.load(Ordering::Relaxed) || Instant::now() >= self.end
  }

  pub fn signal_stop(&self) {
    self.stop.store(true, Ordering::Relaxed);
  }

  pub fn remaining(&self) -> Duration {
    self.end.saturating_duration_since(Instant::now())
  }
}

/// Atomic accumulator for per-worker counters.
pub struct Counter(Arc<AtomicU64>);

impl Counter {
  pub fn new() -> Self {
    Self(Arc::new(AtomicU64::new(0)))
  }
  pub fn clone_handle(&self) -> Self {
    Self(Arc::clone(&self.0))
  }
  pub fn add(&self, n: u64) {
    self.0.fetch_add(n, Ordering::Relaxed);
  }
  pub fn get(&self) -> u64 {
    self.0.load(Ordering::Relaxed)
  }
}

impl Default for Counter {
  fn default() -> Self {
    Self::new()
  }
}

pub fn num_cpus_fallback() -> usize {
  std::thread::available_parallelism()
    .map(|n| n.get())
    .unwrap_or(4)
}

pub fn clamp_timeout(d: Duration) -> Duration {
  let secs = d.as_secs().min(MAX_TIMEOUT_SECS).max(1);
  Duration::from_secs(secs)
}

pub fn read_loadavg() -> Option<(f64, f64, f64)> {
  let raw = std::fs::read_to_string("/proc/loadavg").ok()?;
  let mut it = raw.split_ascii_whitespace();
  let one = it.next()?.parse().ok()?;
  let five = it.next()?.parse().ok()?;
  let fifteen = it.next()?.parse().ok()?;
  Some((one, five, fifteen))
}

pub fn read_self_rss_kb() -> u64 {
  let Ok(raw) = std::fs::read_to_string("/proc/self/status") else {
    return 0;
  };
  for line in raw.lines() {
    if let Some(rest) = line.strip_prefix("VmRSS:") {
      let kb = rest
        .trim()
        .split_ascii_whitespace()
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
      return kb;
    }
  }
  0
}
