//! Memory stressor — allocate and touch pages to exert real RSS pressure.
//!
//! Without touching every page Linux never commits the allocation (overcommit),
//! so a naive `vec![0u8; N]` on a 2G request may not pressure memory at all.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::limits::resolve_mem_budget;
use super::{read_loadavg, Counter, Deadline, StressConfig, StressStats};

const PAGE_SIZE: usize = 4096;
const CHUNK_SIZE: usize = 64 * 1024 * 1024; // 64 MiB per alloc chunk

pub fn run(cfg: &StressConfig) -> StressStats {
  let budget_bytes = match resolve_mem_budget(cfg.bytes, cfg.mem_pct, cfg.max_mem_pct) {
    Ok(b) => b,
    Err(e) => {
      return StressStats {
        kind: "mem",
        workers: cfg.workers,
        note: Some(format!("mem budget error: {}", e)),
        ..Default::default()
      }
    }
  };

  let workers = cfg.workers.max(1);
  let per_worker = (budget_bytes / workers as u64) as usize;
  let deadline = Deadline::new(cfg.timeout);
  let started = Instant::now();

  // Shared buffer store keeps allocations alive for the whole run.
  let buffers: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

  let mut handles = Vec::with_capacity(workers);
  let mut counters = Vec::with_capacity(workers);
  for worker_id in 0..workers {
    let d = deadline.clone();
    let c = Counter::new();
    counters.push(c.clone_handle());
    let bufs = Arc::clone(&buffers);
    let h = thread::Builder::new()
      .name(format!("rb-stress-mem-{}", worker_id))
      .spawn(move || worker_loop(worker_id, per_worker, bufs, d, c))
      .expect("failed to spawn mem worker");
    handles.push(h);
  }

  for h in handles {
    let _ = h.join();
  }

  let elapsed = started.elapsed();
  let per_worker_ops: Vec<u64> = counters.iter().map(|c| c.get()).collect();
  let total_ops: u64 = per_worker_ops.iter().sum();
  let bytes_touched = total_ops.saturating_mul(PAGE_SIZE as u64);
  let bytes_per_sec = if elapsed.as_secs_f64() > 0.0 {
    bytes_touched as f64 / elapsed.as_secs_f64()
  } else {
    0.0
  };

  // Drop buffers explicitly so peak RSS measurement still reflects the run.
  let peak_rss = super::read_self_rss_kb();
  drop(buffers);

  StressStats {
    kind: "mem",
    workers,
    elapsed_ms: elapsed.as_millis() as u64,
    total_ops,
    ops_per_sec: if elapsed.as_secs_f64() > 0.0 {
      total_ops as f64 / elapsed.as_secs_f64()
    } else {
      0.0
    },
    bytes_touched,
    bytes_per_sec,
    per_worker_ops,
    peak_rss_kb: peak_rss,
    load_avg: read_loadavg(),
    note: Some(format!("budget={} bytes", budget_bytes)),
  }
}

fn worker_loop(
  worker_id: usize,
  target_bytes: usize,
  buffers: Arc<Mutex<Vec<Vec<u8>>>>,
  deadline: Deadline,
  counter: Counter,
) {
  // Phase 1: grow to target_bytes in CHUNK_SIZE slabs, touching every page.
  let mut allocated: usize = 0;
  while allocated < target_bytes && !deadline.expired() {
    let want = (target_bytes - allocated).min(CHUNK_SIZE);
    let mut buf = vec![0u8; want];
    touch_pages(&mut buf, worker_id, &counter, &deadline);
    {
      let mut guard = buffers.lock().unwrap();
      guard.push(buf);
    }
    allocated += want;
  }

  // Phase 2: keep rewriting pages to exert continuous pressure until deadline.
  while !deadline.expired() {
    let mut guard = buffers.lock().unwrap();
    for buf in guard.iter_mut() {
      touch_pages(buf, worker_id, &counter, &deadline);
      if deadline.expired() {
        break;
      }
    }
    drop(guard);
    thread::sleep(Duration::from_millis(10));
  }
}

#[inline]
fn touch_pages(buf: &mut [u8], worker_id: usize, counter: &Counter, deadline: &Deadline) {
  let mut i = 0;
  let mark = (worker_id as u8).wrapping_add(1);
  while i < buf.len() {
    buf[i] = mark;
    counter.add(1);
    i += PAGE_SIZE;
    if (i & 0xFF_FFFF) == 0 && deadline.expired() {
      return;
    }
  }
}
