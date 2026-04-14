//! I/O stressor — write/fsync/read/unlink loops against a scratch directory.
//!
//! Each worker owns a unique tempfile under the target path. Writes random-ish
//! bytes, optionally fsyncs, seeks, reads back, truncates. Measures bytes/sec.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use super::{read_loadavg, Counter, Deadline, StressConfig, StressStats};

const DEFAULT_BUF_BYTES: usize = 1024 * 1024; // 1 MiB write batches

pub fn run(cfg: &StressConfig) -> StressStats {
  let workers = cfg.workers.max(1);
  let per_worker_target = cfg.bytes.unwrap_or(100 * 1024 * 1024);
  let root: PathBuf = cfg
    .path
    .as_deref()
    .map(PathBuf::from)
    .unwrap_or_else(std::env::temp_dir);

  if let Err(e) = fs::create_dir_all(&root) {
    return StressStats {
      kind: "io",
      workers,
      note: Some(format!("io path error: {}", e)),
      ..Default::default()
    };
  }

  let deadline = super::Deadline::new(cfg.timeout);
  let started = Instant::now();
  let fsync_enabled = cfg.fsync;

  let mut handles = Vec::with_capacity(workers);
  let mut counters = Vec::with_capacity(workers);
  for worker_id in 0..workers {
    let d = deadline.clone();
    let c = Counter::new();
    counters.push(c.clone_handle());
    let path = root.join(format!(
      "rb-stress-io-{}-{}.bin",
      std::process::id(),
      worker_id
    ));
    let h = thread::Builder::new()
      .name(format!("rb-stress-io-{}", worker_id))
      .spawn(move || worker_loop(worker_id, path, per_worker_target, fsync_enabled, d, c))
      .expect("failed to spawn io worker");
    handles.push(h);
  }

  for h in handles {
    let _ = h.join();
  }

  let elapsed = started.elapsed();
  let per_worker_ops: Vec<u64> = counters.iter().map(|c| c.get()).collect();
  let total_bytes: u64 = per_worker_ops.iter().sum();
  let bytes_per_sec = if elapsed.as_secs_f64() > 0.0 {
    total_bytes as f64 / elapsed.as_secs_f64()
  } else {
    0.0
  };

  StressStats {
    kind: "io",
    workers,
    elapsed_ms: elapsed.as_millis() as u64,
    total_ops: total_bytes / DEFAULT_BUF_BYTES as u64,
    ops_per_sec: if elapsed.as_secs_f64() > 0.0 {
      (total_bytes / DEFAULT_BUF_BYTES as u64) as f64 / elapsed.as_secs_f64()
    } else {
      0.0
    },
    bytes_touched: total_bytes,
    bytes_per_sec,
    per_worker_ops,
    peak_rss_kb: super::read_self_rss_kb(),
    load_avg: read_loadavg(),
    note: Some(format!(
      "path={} fsync={}",
      root.display(),
      if fsync_enabled { "on" } else { "off" }
    )),
  }
}

fn worker_loop(
  worker_id: usize,
  path: PathBuf,
  target_bytes: u64,
  fsync_enabled: bool,
  deadline: Deadline,
  counter: Counter,
) {
  let buf = build_buffer(worker_id);

  while !deadline.expired() {
    let mut file = match OpenOptions::new()
      .create(true)
      .read(true)
      .write(true)
      .truncate(true)
      .open(&path)
    {
      Ok(f) => f,
      Err(_) => return,
    };

    // Write phase.
    let mut written: u64 = 0;
    while written < target_bytes && !deadline.expired() {
      if file.write_all(&buf).is_err() {
        break;
      }
      counter.add(buf.len() as u64);
      written += buf.len() as u64;
    }

    if fsync_enabled {
      let _ = file.sync_all();
    }

    // Read phase — touch everything we just wrote, forces page cache churn.
    let mut scratch = vec![0u8; DEFAULT_BUF_BYTES];
    if file.seek(SeekFrom::Start(0)).is_ok() {
      while !deadline.expired() {
        match file.read(&mut scratch) {
          Ok(0) => break,
          Ok(_) => {}
          Err(_) => break,
        }
      }
    }

    drop(file);
    cleanup(&path);
  }

  cleanup(&path);
}

fn build_buffer(seed: usize) -> Vec<u8> {
  let mut buf = vec![0u8; DEFAULT_BUF_BYTES];
  let mut state: u64 = (seed as u64).wrapping_mul(0x9E3779B97F4A7C15) | 1;
  for chunk in buf.chunks_mut(8) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    let bytes = state.to_le_bytes();
    for (i, b) in chunk.iter_mut().enumerate() {
      *b = bytes[i];
    }
  }
  buf
}

fn cleanup(path: &Path) {
  let _ = fs::remove_file(path);
}
