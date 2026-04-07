//! Shared parallelism infrastructure
//!
//! Provides scoped thread pools with concurrency limits and OPSEC-aware
//! scheduling (jitter, per-host throttling) for use across all modules.
//!
//! # Why not tokio/async?
//!
//! redblue uses zero external runtime crates.  All parallelism is built on
//! `std::thread::scope` (stable since Rust 1.63) which lets us borrow data
//! from the parent stack without `Arc`, and guarantees all threads join
//! before the scope exits.

use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Scoped parallel execution with concurrency limit
// ---------------------------------------------------------------------------

/// Execute `tasks` in parallel with at most `max_concurrent` threads running
/// at the same time.  Each task receives its index (0-based).
///
/// This is the workhorse for parallelising independent network operations
/// (source queries, host scans, vuln checks) without spawning unbounded
/// threads.
///
/// ```ignore
/// parallel::run(8, &items, |item| {
///     let result = fetch(item);
///     results.lock().unwrap().push(result);
/// });
/// ```
pub fn run<T: Sync, F: Fn(&T) + Send + Sync>(max_concurrent: usize, items: &[T], task: F) {
  let limit = max_concurrent.max(1);
  let semaphore = Semaphore::new(limit);

  thread::scope(|s| {
    for item in items {
      semaphore.acquire();
      let sem = &semaphore;
      let task = &task;
      s.spawn(move || {
        task(item);
        sem.release();
      });
    }
  });
}

/// Like [`run`] but collects results from each task into a `Vec`.
/// Results are in arbitrary order (not necessarily input order).
pub fn map<T: Sync, R: Send, F: Fn(&T) -> R + Send + Sync>(
  max_concurrent: usize,
  items: &[T],
  task: F,
) -> Vec<R> {
  let limit = max_concurrent.max(1);
  let semaphore = Semaphore::new(limit);
  let results: Mutex<Vec<R>> = Mutex::new(Vec::with_capacity(items.len()));

  thread::scope(|s| {
    for item in items {
      semaphore.acquire();
      let sem = &semaphore;
      let task = &task;
      let results = &results;
      s.spawn(move || {
        let result = task(item);
        results.lock().unwrap().push(result);
        sem.release();
      });
    }
  });

  results.into_inner().unwrap()
}

/// Like [`map`] but provides the item index to the task closure.
pub fn map_indexed<T: Sync, R: Send, F: Fn(usize, &T) -> R + Send + Sync>(
  max_concurrent: usize,
  items: &[T],
  task: F,
) -> Vec<R> {
  let limit = max_concurrent.max(1);
  let semaphore = Semaphore::new(limit);
  let results: Mutex<Vec<R>> = Mutex::new(Vec::with_capacity(items.len()));

  thread::scope(|s| {
    for (idx, item) in items.iter().enumerate() {
      semaphore.acquire();
      let sem = &semaphore;
      let task = &task;
      let results = &results;
      s.spawn(move || {
        let result = task(idx, item);
        results.lock().unwrap().push(result);
        sem.release();
      });
    }
  });

  results.into_inner().unwrap()
}

// ---------------------------------------------------------------------------
// OPSEC-aware scheduling
// ---------------------------------------------------------------------------

/// Generate a random-ish jitter duration between 0 and `max_ms` milliseconds.
/// Uses a cheap xorshift seeded from the thread ID and a counter — not
/// cryptographically secure, but good enough for timing jitter.
pub fn jitter(max_ms: u64) -> Duration {
  if max_ms == 0 {
    return Duration::ZERO;
  }
  // Cheap entropy: thread ID bits + a monotonic counter
  static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
  let seed = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
  let thread_bits = format!("{:?}", thread::current().id()).len() as u64;
  let mut x = seed
    .wrapping_mul(6364136223846793005)
    .wrapping_add(thread_bits);
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  let ms = x % (max_ms + 1);
  Duration::from_millis(ms)
}

/// Sleep for a random duration between `min_ms` and `max_ms`.
/// Useful before each network request to avoid burst patterns.
pub fn jitter_sleep(min_ms: u64, max_ms: u64) {
  let range = max_ms.saturating_sub(min_ms);
  let delay = Duration::from_millis(min_ms) + jitter(range);
  thread::sleep(delay);
}

/// Execute tasks with OPSEC-aware jitter: each task gets a random delay
/// before starting, spreading requests over time to avoid burst detection.
pub fn run_with_jitter<T: Sync, F: Fn(&T) + Send + Sync>(
  max_concurrent: usize,
  jitter_max_ms: u64,
  items: &[T],
  task: F,
) {
  let limit = max_concurrent.max(1);
  let semaphore = Semaphore::new(limit);

  thread::scope(|s| {
    for item in items {
      semaphore.acquire();
      let sem = &semaphore;
      let task = &task;
      s.spawn(move || {
        thread::sleep(jitter(jitter_max_ms));
        task(item);
        sem.release();
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Rate limiter — for APIs with request-per-second limits (NVD, etc.)
// ---------------------------------------------------------------------------

/// A thread-safe rate limiter that enforces a maximum number of operations
/// within a sliding time window.  All threads share the same limiter to
/// prevent exceeding global API rate limits.
pub struct RateLimiter {
  state: Mutex<RateLimiterState>,
  cond: Condvar,
}

struct RateLimiterState {
  /// Timestamps of recent operations (ring buffer)
  timestamps: Vec<std::time::Instant>,
  /// Write position in the ring buffer
  pos: usize,
  /// Maximum operations allowed within `window`
  max_ops: usize,
  /// Time window
  window: Duration,
}

impl RateLimiter {
  /// Create a limiter that allows `max_ops` operations per `window` duration.
  ///
  /// Example: `RateLimiter::new(5, Duration::from_secs(30))` for NVD's
  /// 5 requests per 30 seconds limit.
  pub fn new(max_ops: usize, window: Duration) -> Self {
    let max_ops = max_ops.max(1);
    Self {
      state: Mutex::new(RateLimiterState {
        timestamps: vec![std::time::Instant::now() - window; max_ops],
        pos: 0,
        max_ops,
        window,
      }),
      cond: Condvar::new(),
    }
  }

  /// Block until a slot is available, then record the operation.
  pub fn acquire(&self) {
    let mut state = self.state.lock().unwrap();
    loop {
      let oldest = state.timestamps[state.pos];
      let elapsed = oldest.elapsed();
      if elapsed >= state.window {
        // Slot available — record this operation
        let pos = state.pos;
        state.timestamps[pos] = std::time::Instant::now();
        state.pos = (pos + 1) % state.max_ops;
        return;
      }
      // Wait until the oldest slot expires
      let wait = state.window - elapsed + Duration::from_millis(10);
      state = self.cond.wait_timeout(state, wait).unwrap().0;
    }
  }
}

// ---------------------------------------------------------------------------
// Counting semaphore (std-only, no external crates)
// ---------------------------------------------------------------------------

/// A counting semaphore built on `Mutex` + `Condvar`.
/// Limits the number of threads that can run concurrently.
struct Semaphore {
  state: Mutex<usize>,
  cond: Condvar,
  max: usize,
}

impl Semaphore {
  fn new(max: usize) -> Self {
    Self {
      state: Mutex::new(0),
      cond: Condvar::new(),
      max,
    }
  }

  fn acquire(&self) {
    let mut count = self.state.lock().unwrap();
    while *count >= self.max {
      count = self.cond.wait(count).unwrap();
    }
    *count += 1;
  }

  fn release(&self) {
    let mut count = self.state.lock().unwrap();
    *count -= 1;
    self.cond.notify_one();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicUsize, Ordering};

  #[test]
  fn test_parallel_run() {
    let counter = AtomicUsize::new(0);
    let items: Vec<i32> = (0..20).collect();

    run(4, &items, |_| {
      counter.fetch_add(1, Ordering::Relaxed);
    });

    assert_eq!(counter.load(Ordering::Relaxed), 20);
  }

  #[test]
  fn test_parallel_map() {
    let items: Vec<i32> = (0..10).collect();
    let mut results = map(4, &items, |x| x * 2);
    results.sort();
    assert_eq!(results, vec![0, 2, 4, 6, 8, 10, 12, 14, 16, 18]);
  }

  #[test]
  fn test_concurrency_limit() {
    let peak = AtomicUsize::new(0);
    let active = AtomicUsize::new(0);
    let items: Vec<i32> = (0..20).collect();

    run(3, &items, |_| {
      let current = active.fetch_add(1, Ordering::SeqCst) + 1;
      // Update peak
      loop {
        let p = peak.load(Ordering::Relaxed);
        if current <= p
          || peak
            .compare_exchange(p, current, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
          break;
        }
      }
      thread::sleep(Duration::from_millis(10));
      active.fetch_sub(1, Ordering::SeqCst);
    });

    assert!(
      peak.load(Ordering::Relaxed) <= 3,
      "Peak concurrency exceeded limit"
    );
  }

  #[test]
  fn test_jitter_within_range() {
    for _ in 0..100 {
      let d = jitter(50);
      assert!(d <= Duration::from_millis(50));
    }
  }

  #[test]
  fn test_rate_limiter() {
    let limiter = RateLimiter::new(3, Duration::from_millis(100));

    let start = std::time::Instant::now();

    // First 3 should be instant
    limiter.acquire();
    limiter.acquire();
    limiter.acquire();
    assert!(start.elapsed() < Duration::from_millis(50));

    // 4th should wait ~100ms
    limiter.acquire();
    assert!(start.elapsed() >= Duration::from_millis(90));
  }

  #[test]
  fn test_map_indexed() {
    let items = vec!["a", "b", "c"];
    let results = map_indexed(2, &items, |idx, item| format!("{}:{}", idx, item));
    assert_eq!(results.len(), 3);
    // Results may be in any order, but all should be present
    let mut sorted = results.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["0:a", "1:b", "2:c"]);
  }
}
