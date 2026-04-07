//! Sleep Encryption (Ekko/Nighthawk-style)
//!
//! When a C2 agent or any long-running process sleeps between operations,
//! its heap contains decrypted strings, keys, and config in plaintext.
//! Memory scanners (EDR, forensics tools) trivially find these during idle.
//!
//! Sleep encryption solves this:
//! 1. Before sleeping, encrypt all registered memory regions with a one-time key
//! 2. Sleep for the requested duration
//! 3. On wake, decrypt everything and resume
//!
//! During sleep, memory contains only ciphertext — scanners find nothing useful.
//!
//! # Usage
//! ```rust
//! use redblue::modules::evasion::sleep_encrypt::SleepEncryptor;
//!
//! let mut encryptor = SleepEncryptor::new();
//!
//! // Register memory regions to protect
//! let mut secret = b"my_api_key_12345".to_vec();
//! let mut config = b"beacon_url=https://c2.example.com".to_vec();
//! unsafe {
//!   encryptor.register(&mut secret);
//!   encryptor.register(&mut config);
//! }
//!
//! // Encrypted sleep: regions are ciphertext during the entire sleep
//! encryptor.encrypted_sleep(std::time::Duration::from_secs(60));
//!
//! // After wake, secret and config are restored to plaintext
//! assert_eq!(&secret, b"my_api_key_12345");
//! ```
//!
//! # Warning
//! For authorized penetration testing only.

use crate::crypto::os_random;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Global flag: are we currently in encrypted sleep?
static IN_ENCRYPTED_SLEEP: AtomicBool = AtomicBool::new(false);

/// Total number of encrypted sleeps performed
static SLEEP_COUNT: AtomicU64 = AtomicU64::new(0);

/// Total time spent in encrypted sleep (milliseconds)
static TOTAL_SLEEP_MS: AtomicU64 = AtomicU64::new(0);

/// A registered memory region that will be encrypted during sleep.
struct ProtectedRegion {
  /// Raw pointer to the start of the region
  ptr: *mut u8,
  /// Length in bytes
  len: usize,
}

// Safety: we manage the lifetime ourselves and only access during encrypt/decrypt
unsafe impl Send for ProtectedRegion {}

/// Sleep encryption engine.
///
/// Registers mutable memory regions and encrypts them before sleep,
/// decrypts on wake. Uses a fresh one-time key for each sleep cycle.
pub struct SleepEncryptor {
  /// Registered regions to encrypt during sleep
  regions: Vec<ProtectedRegion>,
  /// Current encryption key (regenerated each sleep cycle)
  key: Vec<u8>,
  /// Whether regions are currently encrypted
  encrypted: bool,
  /// Stats
  total_sleeps: u64,
  total_bytes_protected: usize,
}

impl SleepEncryptor {
  /// Create a new sleep encryptor.
  pub fn new() -> Self {
    Self {
      regions: Vec::new(),
      key: Vec::new(),
      encrypted: false,
      total_sleeps: 0,
      total_bytes_protected: 0,
    }
  }

  /// Register a mutable byte slice to be encrypted during sleep.
  ///
  /// # Safety
  /// The caller must ensure the slice remains at the same memory address
  /// and is not deallocated for the lifetime of this encryptor
  /// (or until `unregister_all()`).
  pub unsafe fn register(&mut self, data: &mut [u8]) {
    self.regions.push(ProtectedRegion {
      ptr: data.as_mut_ptr(),
      len: data.len(),
    });
    self.total_bytes_protected += data.len();
  }

  /// Register a Vec's backing buffer. The Vec must not be reallocated
  /// (no push/resize) while registered.
  ///
  /// # Safety
  /// The caller must ensure the Vec is not resized, pushed to, or dropped
  /// for the lifetime of this encryptor (or until `unregister_all()`).
  pub unsafe fn register_vec(&mut self, data: &mut Vec<u8>) {
    if !data.is_empty() {
      self.regions.push(ProtectedRegion {
        ptr: data.as_mut_ptr(),
        len: data.len(),
      });
      self.total_bytes_protected += data.len();
    }
  }

  /// Unregister all regions.
  pub fn unregister_all(&mut self) {
    self.regions.clear();
    self.total_bytes_protected = 0;
  }

  /// Number of registered regions.
  pub fn region_count(&self) -> usize {
    self.regions.len()
  }

  /// Total bytes across all registered regions.
  pub fn protected_bytes(&self) -> usize {
    self.total_bytes_protected
  }

  /// Are regions currently encrypted?
  pub fn is_encrypted(&self) -> bool {
    self.encrypted
  }

  /// Is any encryptor currently in encrypted sleep? (global check)
  pub fn in_encrypted_sleep() -> bool {
    IN_ENCRYPTED_SLEEP.load(Ordering::SeqCst)
  }

  /// Global sleep count.
  pub fn global_sleep_count() -> u64 {
    SLEEP_COUNT.load(Ordering::Relaxed)
  }

  /// Global time spent in encrypted sleep (ms).
  pub fn global_sleep_time_ms() -> u64 {
    TOTAL_SLEEP_MS.load(Ordering::Relaxed)
  }

  /// Generate a fresh one-time key from OS CSPRNG.
  fn generate_key(&mut self, size: usize) {
    self.key = vec![0u8; size];
    if os_random::fill_bytes(&mut self.key).is_err() {
      // Fallback: time-based entropy (better than nothing)
      let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
      let mut state = seed;
      for byte in &mut self.key {
        state = state
          .wrapping_mul(6364136223846793005)
          .wrapping_add(1442695040888963407);
        *byte = (state >> 32) as u8;
      }
    }
  }

  /// XOR all registered regions with the current key (encrypt or decrypt).
  fn xor_regions(&self) {
    if self.key.is_empty() {
      return;
    }

    let key = &self.key;
    let key_len = key.len();

    for region in &self.regions {
      let slice = unsafe { std::slice::from_raw_parts_mut(region.ptr, region.len) };
      for (i, byte) in slice.iter_mut().enumerate() {
        *byte ^= key[i % key_len];
      }
    }
  }

  /// Encrypt all registered regions.
  pub fn encrypt(&mut self) {
    if self.encrypted || self.regions.is_empty() {
      return;
    }

    // Find the max region size to determine key length
    let max_len = self.regions.iter().map(|r| r.len).max().unwrap_or(256);
    let key_size = max_len.min(4096); // Cap key at 4KB for efficiency
    self.generate_key(key_size);

    self.xor_regions();
    self.encrypted = true;
  }

  /// Decrypt all registered regions (restores plaintext).
  pub fn decrypt(&mut self) {
    if !self.encrypted {
      return;
    }

    // XOR is symmetric: applying the same key decrypts
    self.xor_regions();
    self.encrypted = false;

    // Zero the key after use
    for byte in &mut self.key {
      unsafe {
        std::ptr::write_volatile(byte, 0);
      }
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
    self.key.clear();
  }

  /// The core operation: encrypt → sleep → decrypt.
  ///
  /// During the entire sleep duration, all registered memory regions contain
  /// only ciphertext. Memory scanners running during this window find nothing.
  pub fn encrypted_sleep(&mut self, duration: Duration) {
    IN_ENCRYPTED_SLEEP.store(true, Ordering::SeqCst);

    // Encrypt all regions
    self.encrypt();

    // Sleep
    let start = Instant::now();
    std::thread::sleep(duration);
    let actual_ms = start.elapsed().as_millis() as u64;

    // Decrypt all regions
    self.decrypt();

    IN_ENCRYPTED_SLEEP.store(false, Ordering::SeqCst);

    // Update stats
    self.total_sleeps += 1;
    SLEEP_COUNT.fetch_add(1, Ordering::Relaxed);
    TOTAL_SLEEP_MS.fetch_add(actual_ms, Ordering::Relaxed);
  }

  /// Encrypted sleep with jitter (randomized duration).
  /// Actual sleep = duration ± jitter_percent%.
  pub fn encrypted_sleep_jittered(&mut self, base_duration: Duration, jitter_percent: u8) {
    let base_ms = base_duration.as_millis() as u64;
    let jitter_range = base_ms * jitter_percent as u64 / 100;

    let actual_ms = if jitter_range > 0 {
      let mut rng_buf = [0u8; 8];
      let _ = os_random::fill_bytes(&mut rng_buf);
      let random_val = u64::from_le_bytes(rng_buf);
      let offset = random_val % (jitter_range * 2 + 1);
      base_ms.saturating_sub(jitter_range) + offset
    } else {
      base_ms
    };

    self.encrypted_sleep(Duration::from_millis(actual_ms));
  }

  /// Get stats for this encryptor instance.
  pub fn stats(&self) -> SleepEncryptStats {
    SleepEncryptStats {
      regions: self.regions.len(),
      total_bytes: self.total_bytes_protected,
      is_encrypted: self.encrypted,
      total_sleeps: self.total_sleeps,
      global_sleep_count: Self::global_sleep_count(),
      global_sleep_time_ms: Self::global_sleep_time_ms(),
    }
  }
}

impl Default for SleepEncryptor {
  fn default() -> Self {
    Self::new()
  }
}

impl Drop for SleepEncryptor {
  fn drop(&mut self) {
    // If we're dropped while encrypted, decrypt first to avoid data loss
    if self.encrypted {
      self.decrypt();
    }
    // Zero the key
    for byte in &mut self.key {
      unsafe {
        std::ptr::write_volatile(byte, 0);
      }
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
  }
}

/// Stats snapshot for display/JSON output.
pub struct SleepEncryptStats {
  pub regions: usize,
  pub total_bytes: usize,
  pub is_encrypted: bool,
  pub total_sleeps: u64,
  pub global_sleep_count: u64,
  pub global_sleep_time_ms: u64,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_encrypt_decrypt_roundtrip() {
    let mut data = b"secret_api_key_12345".to_vec();
    let original = data.clone();

    let mut enc = SleepEncryptor::new();
    unsafe { enc.register_vec(&mut data) };

    enc.encrypt();
    assert!(enc.is_encrypted());
    // Data should be different from original (with overwhelming probability)
    assert_ne!(&data, &original);

    enc.decrypt();
    assert!(!enc.is_encrypted());
    assert_eq!(&data, &original);
  }

  #[test]
  fn test_multiple_regions() {
    let mut secret1 = b"password123".to_vec();
    let mut secret2 = b"api_key_xyz".to_vec();
    let orig1 = secret1.clone();
    let orig2 = secret2.clone();

    let mut enc = SleepEncryptor::new();
    unsafe { enc.register_vec(&mut secret1) };
    unsafe { enc.register_vec(&mut secret2) };
    assert_eq!(enc.region_count(), 2);

    enc.encrypt();
    assert_ne!(&secret1, &orig1);
    assert_ne!(&secret2, &orig2);

    enc.decrypt();
    assert_eq!(&secret1, &orig1);
    assert_eq!(&secret2, &orig2);
  }

  #[test]
  fn test_encrypted_sleep_restores() {
    let mut data = b"beacon_config_data".to_vec();
    let original = data.clone();

    let mut enc = SleepEncryptor::new();
    unsafe { enc.register_vec(&mut data) };

    enc.encrypted_sleep(Duration::from_millis(10));

    // After wake, data should be restored
    assert_eq!(&data, &original);
    assert!(!enc.is_encrypted());
    assert_eq!(enc.stats().total_sleeps, 1);
  }

  #[test]
  fn test_empty_encryptor() {
    let mut enc = SleepEncryptor::new();
    // Should not panic with no regions
    enc.encrypt();
    enc.decrypt();
    enc.encrypted_sleep(Duration::from_millis(1));
  }

  #[test]
  fn test_stats() {
    let mut data = vec![0u8; 100];
    let mut enc = SleepEncryptor::new();
    unsafe { enc.register_vec(&mut data) };

    let stats = enc.stats();
    assert_eq!(stats.regions, 1);
    assert_eq!(stats.total_bytes, 100);
    assert!(!stats.is_encrypted);
  }

  #[test]
  fn test_drop_while_encrypted() {
    let mut data = b"sensitive".to_vec();
    let original = data.clone();

    {
      let mut enc = SleepEncryptor::new();
      unsafe { enc.register_vec(&mut data) };
      enc.encrypt();
      assert_ne!(&data, &original);
      // enc dropped here — should auto-decrypt
    }

    assert_eq!(&data, &original);
  }

  #[test]
  fn test_double_encrypt_is_noop() {
    let mut data = b"test".to_vec();
    let mut enc = SleepEncryptor::new();
    unsafe { enc.register_vec(&mut data) };

    enc.encrypt();
    let after_first = data.clone();

    enc.encrypt(); // should be noop
    assert_eq!(&data, &after_first);

    enc.decrypt();
    assert_eq!(&data, b"test");
  }

  #[test]
  fn test_double_decrypt_is_noop() {
    let mut data = b"test".to_vec();
    let mut enc = SleepEncryptor::new();
    unsafe { enc.register_vec(&mut data) };

    enc.encrypt();
    enc.decrypt();
    let plaintext = data.clone();

    enc.decrypt(); // should be noop
    assert_eq!(&data, &plaintext);
  }

  #[test]
  fn test_register_slice() {
    let mut buf = [0u8; 32];
    buf[..5].copy_from_slice(b"hello");
    let original = buf;

    let mut enc = SleepEncryptor::new();
    unsafe { enc.register(&mut buf) };

    enc.encrypt();
    assert_ne!(buf, original);

    enc.decrypt();
    assert_eq!(buf, original);
  }
}
