//! CPU stressor — N worker threads running compute-bound loops until deadline.

use std::hint::black_box;
use std::thread;
use std::time::Instant;

use super::{read_loadavg, Counter, CpuMethod, Deadline, StressConfig, StressStats};

/// Run CPU stress with the configured workers/method/timeout.
pub fn run(cfg: &StressConfig) -> StressStats {
  let deadline = Deadline::new(cfg.timeout);
  let started = Instant::now();

  let mut handles = Vec::with_capacity(cfg.workers);
  let mut counters: Vec<Counter> = Vec::with_capacity(cfg.workers);

  for worker_id in 0..cfg.workers {
    let d = deadline.clone();
    let c = Counter::new();
    counters.push(c.clone_handle());
    let method = cfg.method;
    let h = thread::Builder::new()
      .name(format!("rb-stress-cpu-{}", worker_id))
      .spawn(move || worker_loop(worker_id as u64, method, d, c))
      .expect("failed to spawn cpu worker");
    handles.push(h);
  }

  for h in handles {
    let _ = h.join();
  }

  let elapsed = started.elapsed();
  let per_worker: Vec<u64> = counters.iter().map(|c| c.get()).collect();
  let total_ops: u64 = per_worker.iter().sum();
  let ops_per_sec = if elapsed.as_secs_f64() > 0.0 {
    total_ops as f64 / elapsed.as_secs_f64()
  } else {
    0.0
  };

  StressStats {
    kind: "cpu",
    workers: cfg.workers,
    elapsed_ms: elapsed.as_millis() as u64,
    total_ops,
    ops_per_sec,
    bytes_touched: 0,
    bytes_per_sec: 0.0,
    per_worker_ops: per_worker,
    peak_rss_kb: super::read_self_rss_kb(),
    load_avg: read_loadavg(),
    note: Some(format!("method={}", cfg.method.name())),
  }
}

fn worker_loop(seed: u64, method: CpuMethod, deadline: Deadline, counter: Counter) {
  let mut local_ops: u64 = 0;
  let mut state: u64 = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
  loop {
    // Batch work to reduce atomic store contention and deadline checks.
    for _ in 0..1024 {
      match method {
        CpuMethod::Sha256 => state = sha256_round(state),
        CpuMethod::Matrix => state = matrix_round(state),
        CpuMethod::Prime => state = prime_round(state),
      }
      black_box(state);
      local_ops += 1;
    }
    counter.add(1024);
    if deadline.expired() {
      break;
    }
  }
  // Flush remainder (no-op given batch boundary, kept for clarity).
  let _ = local_ops;
}

/// Single SHA-256 compression round — tight integer work, branch-poor.
/// Uses the first 16 round constants and a mini message schedule — not a
/// real SHA-256, just enough integer mixing to keep an ALU saturated.
#[inline(always)]
fn sha256_round(seed: u64) -> u64 {
  const K: [u32; 16] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  ];
  let mut a: u32 = seed as u32;
  let mut b: u32 = (seed >> 32) as u32;
  let mut c: u32 = a.wrapping_add(0x6a09e667);
  let mut d: u32 = b.wrapping_add(0xbb67ae85);
  for k in K.iter() {
    let s1 = d.rotate_right(6) ^ d.rotate_right(11) ^ d.rotate_right(25);
    let ch = (d & c) ^ (!d & b);
    let t1 = a.wrapping_add(s1).wrapping_add(ch).wrapping_add(*k);
    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let t2 = s0.wrapping_add(maj);
    d = c;
    c = b;
    b = a.wrapping_add(t1);
    a = t1.wrapping_add(t2);
  }
  ((a as u64) << 32) | (b as u64)
}

/// 4x4 u32 matrix multiply step — memory-light but FPU-independent.
#[inline(always)]
fn matrix_round(seed: u64) -> u64 {
  let mut acc: u32 = seed as u32;
  let mut mix: u32 = (seed >> 32) as u32 | 1;
  for i in 0..16u32 {
    acc = acc.wrapping_mul(mix).wrapping_add(i.wrapping_mul(0x9E37));
    mix = mix.rotate_left(5) ^ acc;
  }
  ((acc as u64) << 32) | (mix as u64)
}

/// Trial-division primality check on a small wandering window.
#[inline(always)]
fn prime_round(seed: u64) -> u64 {
  let base = ((seed & 0xFFFF) | 3) as u64;
  let mut hits: u64 = 0;
  for off in 0..64u64 {
    let n = base + off * 2;
    let mut prime = true;
    let mut d = 3u64;
    while d * d <= n {
      if n % d == 0 {
        prime = false;
        break;
      }
      d += 2;
    }
    if prime {
      hits += 1;
    }
  }
  seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(hits)
}
