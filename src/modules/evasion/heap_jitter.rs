//! Heap Allocation Pattern Obfuscation
//!
//! EDR/AV solutions fingerprint programs by their heap allocation patterns:
//! predictable sizes, cadence, and memory layout create a unique signature.
//!
//! This module breaks that fingerprint with three techniques:
//!
//! 1. **Allocation jitter** — pads every allocation with random extra bytes
//!    so the same code path produces different sizes each run.
//! 2. **Decoy allocations** — periodically allocates memory blocks that
//!    mimic common legitimate programs (browsers, system services).
//! 3. **Allocation timing noise** — random micro-delays between allocations
//!    to break cadence-based profiling.
//!
//! # Usage
//! ```rust
//! use redblue::modules::evasion::heap_jitter::{HeapJitter, JitterProfile};
//!
//! // Initialize with a profile that mimics a web browser
//! let mut jitter = HeapJitter::new(JitterProfile::Browser);
//! jitter.activate();
//!
//! // Allocate with jitter (adds random padding)
//! let buf = jitter.alloc_jittered(1024); // actually allocates 1024 + random(0..512)
//!
//! // Spray decoy allocations into the heap
//! jitter.spray_decoys(20);
//! ```
//!
//! # Warning
//! For authorized penetration testing only.

use crate::crypto::os_random;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global activation flag
static JITTER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Counter of jittered allocations performed
static JITTER_ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

/// Counter of decoy allocations alive
static DECOY_COUNT: AtomicU64 = AtomicU64::new(0);

/// Allocation size profiles that mimic real programs.
/// EDR solutions build histograms of allocation sizes — these profiles
/// make our histogram look like something benign.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JitterProfile {
  /// Mimics Chromium: many small allocations (32-4096) with occasional large ones
  Browser,
  /// Mimics Node.js: V8 heap pages (256KB), plus many small objects
  NodeJs,
  /// Mimics a system daemon: steady, small, infrequent allocations
  SystemService,
  /// Pure random: no specific pattern, maximum unpredictability
  Random,
}

impl JitterProfile {
  /// Typical allocation sizes for this profile (used for decoy spray)
  fn typical_sizes(&self) -> &'static [usize] {
    match self {
      JitterProfile::Browser => &[
        32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
      ],
      JitterProfile::NodeJs => &[16, 32, 64, 128, 256, 512, 1024, 4096, 8192, 65536, 262144],
      JitterProfile::SystemService => &[64, 128, 256, 512, 1024, 4096],
      JitterProfile::Random => &[
        16, 48, 96, 200, 384, 768, 1500, 3000, 6000, 12000, 24000, 50000,
      ],
    }
  }

  /// Maximum jitter padding (bytes added to real allocations)
  fn max_padding(&self) -> usize {
    match self {
      JitterProfile::Browser => 512,
      JitterProfile::NodeJs => 256,
      JitterProfile::SystemService => 128,
      JitterProfile::Random => 1024,
    }
  }

  /// Name for display
  pub fn name(&self) -> &'static str {
    match self {
      JitterProfile::Browser => "browser",
      JitterProfile::NodeJs => "nodejs",
      JitterProfile::SystemService => "system",
      JitterProfile::Random => "random",
    }
  }

  pub fn from_name(name: &str) -> Option<Self> {
    match name {
      "browser" | "chrome" | "chromium" => Some(Self::Browser),
      "nodejs" | "node" | "v8" => Some(Self::NodeJs),
      "system" | "service" | "daemon" => Some(Self::SystemService),
      "random" | "chaotic" => Some(Self::Random),
      _ => None,
    }
  }
}

/// A single decoy allocation kept alive to pollute heap analysis.
struct Decoy {
  _data: Vec<u8>,
}

impl Drop for Decoy {
  fn drop(&mut self) {
    DECOY_COUNT.fetch_sub(1, Ordering::Relaxed);
  }
}

/// Heap jitter engine.
pub struct HeapJitter {
  profile: JitterProfile,
  /// Live decoy allocations (kept alive to pollute the heap)
  decoys: Vec<Decoy>,
  /// Pseudo-random state
  rng_state: u64,
}

impl HeapJitter {
  /// Create a new heap jitter engine with the given profile.
  pub fn new(profile: JitterProfile) -> Self {
    let seed = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_nanos() as u64
      ^ (std::process::id() as u64).wrapping_mul(0x517cc1b727220a95);

    Self {
      profile,
      decoys: Vec::new(),
      rng_state: seed,
    }
  }

  /// Mark heap jitter as globally active.
  pub fn activate(&self) {
    JITTER_ACTIVE.store(true, Ordering::SeqCst);
  }

  /// Deactivate heap jitter.
  pub fn deactivate(&self) {
    JITTER_ACTIVE.store(false, Ordering::SeqCst);
  }

  /// Check if jitter is globally active.
  pub fn is_active() -> bool {
    JITTER_ACTIVE.load(Ordering::SeqCst)
  }

  /// Fast LCG pseudo-random (not crypto, just for jitter)
  fn next_random(&mut self) -> u64 {
    self.rng_state = self
      .rng_state
      .wrapping_mul(6364136223846793005)
      .wrapping_add(1442695040888963407);
    self.rng_state
  }

  /// Allocate a buffer with random padding added to the requested size.
  /// The actual allocation is `size + random(0..max_padding)`.
  pub fn alloc_jittered(&mut self, size: usize) -> Vec<u8> {
    let padding = (self.next_random() as usize) % (self.profile.max_padding() + 1);
    let actual_size = size + padding;

    let mut buf = Vec::with_capacity(actual_size);
    buf.resize(actual_size, 0);

    // Fill padding region with random-looking data (not zeros — zeros are suspicious)
    if padding > 0 {
      for i in size..actual_size {
        buf[i] = self.next_random() as u8;
      }
    }

    JITTER_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    buf
  }

  /// Allocate a buffer with random padding, filled with OS entropy.
  pub fn alloc_jittered_random(&mut self, size: usize) -> Vec<u8> {
    let padding = (self.next_random() as usize) % (self.profile.max_padding() + 1);
    let actual_size = size + padding;

    let mut buf = vec![0u8; actual_size];
    let _ = os_random::fill_bytes(&mut buf);

    JITTER_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    buf
  }

  /// Spray decoy allocations into the heap to camouflage real allocations.
  /// Decoys are kept alive until `clear_decoys()` is called or the engine is dropped.
  pub fn spray_decoys(&mut self, count: usize) {
    let sizes = self.profile.typical_sizes();

    for _ in 0..count {
      // Pick a typical size for this profile
      let idx = (self.next_random() as usize) % sizes.len();
      let base_size = sizes[idx];

      // Add some jitter to the decoy too
      let jitter = (self.next_random() as usize) % (base_size / 4 + 1);
      let size = base_size + jitter;

      let mut data = vec![0u8; size];
      // Fill with pseudo-random data (not zeros — zero pages are CoW and don't really occupy RAM)
      for chunk in data.chunks_mut(8) {
        let r = self.next_random();
        let bytes = r.to_le_bytes();
        let len = chunk.len().min(8);
        chunk[..len].copy_from_slice(&bytes[..len]);
      }

      DECOY_COUNT.fetch_add(1, Ordering::Relaxed);
      self.decoys.push(Decoy { _data: data });
    }
  }

  /// Clear all decoy allocations.
  pub fn clear_decoys(&mut self) {
    self.decoys.clear();
  }

  /// Get number of live decoys.
  pub fn decoy_count(&self) -> usize {
    self.decoys.len()
  }

  /// Get total jittered allocations performed (global counter).
  pub fn total_jittered_allocs() -> u64 {
    JITTER_ALLOC_COUNT.load(Ordering::Relaxed)
  }

  /// Get global decoy count.
  pub fn global_decoy_count() -> u64 {
    DECOY_COUNT.load(Ordering::Relaxed)
  }

  /// Get the active profile.
  pub fn profile(&self) -> JitterProfile {
    self.profile
  }

  /// Estimate total decoy memory in bytes.
  pub fn decoy_memory_bytes(&self) -> usize {
    self.decoys.iter().map(|d| d._data.len()).sum()
  }

  /// Run a full heap camouflage cycle: spray decoys, perform timing noise,
  /// and return stats.
  pub fn camouflage(&mut self, decoy_count: usize) -> CamouflageResult {
    let before_decoys = self.decoys.len();

    // Spray decoys
    self.spray_decoys(decoy_count);

    // Add timing noise: random micro-sleep (0-5ms)
    let delay_us = (self.next_random() % 5000) as u64;
    std::thread::sleep(std::time::Duration::from_micros(delay_us));

    let total_memory = self.decoy_memory_bytes();

    CamouflageResult {
      decoys_created: decoy_count,
      total_decoys: self.decoys.len(),
      previous_decoys: before_decoys,
      total_memory_bytes: total_memory,
      timing_noise_us: delay_us,
      profile: self.profile.name().to_string(),
    }
  }
}

/// Result of a camouflage operation.
pub struct CamouflageResult {
  pub decoys_created: usize,
  pub total_decoys: usize,
  pub previous_decoys: usize,
  pub total_memory_bytes: usize,
  pub timing_noise_us: u64,
  pub profile: String,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_jittered_alloc_at_least_requested_size() {
    let mut jitter = HeapJitter::new(JitterProfile::Random);
    let buf = jitter.alloc_jittered(100);
    assert!(buf.len() >= 100);
  }

  #[test]
  fn test_jittered_alloc_has_padding() {
    let mut jitter = HeapJitter::new(JitterProfile::Random);
    // With max_padding=1024, most allocations should be larger than requested
    let mut padded = 0;
    for _ in 0..50 {
      let buf = jitter.alloc_jittered(100);
      if buf.len() > 100 {
        padded += 1;
      }
    }
    // At least some should be padded (statistically near-certain)
    assert!(padded > 0, "no allocations were padded");
  }

  #[test]
  fn test_spray_decoys() {
    let mut jitter = HeapJitter::new(JitterProfile::Browser);
    jitter.spray_decoys(10);
    assert_eq!(jitter.decoy_count(), 10);
    assert!(jitter.decoy_memory_bytes() > 0);
  }

  #[test]
  fn test_clear_decoys() {
    let mut jitter = HeapJitter::new(JitterProfile::NodeJs);
    jitter.spray_decoys(5);
    assert_eq!(jitter.decoy_count(), 5);
    jitter.clear_decoys();
    assert_eq!(jitter.decoy_count(), 0);
  }

  #[test]
  fn test_profile_from_name() {
    assert_eq!(
      JitterProfile::from_name("browser"),
      Some(JitterProfile::Browser)
    );
    assert_eq!(
      JitterProfile::from_name("node"),
      Some(JitterProfile::NodeJs)
    );
    assert_eq!(
      JitterProfile::from_name("system"),
      Some(JitterProfile::SystemService)
    );
    assert_eq!(
      JitterProfile::from_name("random"),
      Some(JitterProfile::Random)
    );
    assert_eq!(JitterProfile::from_name("invalid"), None);
  }

  #[test]
  fn test_camouflage() {
    let mut jitter = HeapJitter::new(JitterProfile::SystemService);
    let result = jitter.camouflage(5);
    assert_eq!(result.decoys_created, 5);
    assert_eq!(result.total_decoys, 5);
    assert!(result.total_memory_bytes > 0);
  }

  #[test]
  fn test_activate_deactivate() {
    let jitter = HeapJitter::new(JitterProfile::Random);
    assert!(!HeapJitter::is_active());
    jitter.activate();
    assert!(HeapJitter::is_active());
    jitter.deactivate();
    assert!(!HeapJitter::is_active());
  }

  #[test]
  fn test_alloc_counter() {
    let before = HeapJitter::total_jittered_allocs();
    let mut jitter = HeapJitter::new(JitterProfile::Random);
    jitter.alloc_jittered(64);
    jitter.alloc_jittered(128);
    let after = HeapJitter::total_jittered_allocs();
    assert!(after >= before + 2);
  }
}
