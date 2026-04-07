//! Runtime binary self-mutation (rehash)
//!
//! Reads the running binary from disk, locates the mutable marker regions
//! (REHASH_JUNK_BLOCK and REHASH_FP_BLOCK embedded at build time), overwrites
//! them with fresh random data, and atomically writes the modified binary back.
//! The result is a different SHA256 hash on disk after every invocation.
//!
//! Also rotates in-memory encryption keys so the runtime fingerprint changes.
//!
//! # Warning
//! For authorized penetration testing only.

use crate::crypto::os_random;
use crate::crypto::sha256::sha256;

use std::env;
use std::fs;
use std::path::PathBuf;

/// Magic sentinels — hard-coded here so they only appear in the binary as
/// immediate operands (in the .text section), not as separate data constants.
/// The only data-section copy lives inside REHASH_JUNK_BLOCK / REHASH_FP_BLOCK
/// (emitted by build.rs), which is exactly what the scanner should find.
const JUNK_MARKER: [u8; 16] = [
  0x52, 0x42, 0x4A, 0x55, 0x4E, 0x4B, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x52, 0x42, 0x4A, 0x4B,
];
const FP_MARKER: [u8; 16] = [
  0x52, 0x42, 0x46, 0x50, 0x52, 0x49, 0x4E, 0x54, 0xDE, 0xAD, 0xBE, 0xEF, 0x46, 0x50, 0x52, 0x42,
];

/// Result of a successful rehash operation.
pub struct RehashResult {
  /// SHA256 hex digest before mutation
  pub old_hash: String,
  /// SHA256 hex digest after mutation
  pub new_hash: String,
  /// Number of junk bytes overwritten
  pub junk_bytes_mutated: usize,
  /// Number of fingerprint bytes overwritten
  pub fp_bytes_mutated: usize,
  /// Canonical path of the mutated binary
  pub binary_path: String,
  /// Whether the in-memory key was rotated
  pub memory_key_rotated: bool,
}

/// Perform a full self-rehash: mutate binary on disk + rotate memory keys.
pub fn rehash() -> Result<RehashResult, String> {
  // 1. Resolve the real binary path (follow symlinks)
  let exe_path = env::current_exe().map_err(|e| format!("Failed to get current binary: {}", e))?;
  let exe_path = fs::canonicalize(&exe_path)
    .map_err(|e| format!("Failed to canonicalize path {}: {}", exe_path.display(), e))?;

  // Ensure the rehash blocks survive linker dead-code elimination.
  // Without this call, LTO could strip REHASH_JUNK_BLOCK / REHASH_FP_BLOCK.
  super::mutations::polymorphic_nop();

  // 2. Read the binary into memory
  let mut binary = fs::read(&exe_path)
    .map_err(|e| format!("Failed to read binary at {}: {}", exe_path.display(), e))?;

  // 3. Compute old hash
  let old_hash = hex_sha256(&binary);

  // 4. Locate and mutate JUNK region
  let junk_mutable_size = super::mutations::REHASH_JUNK_SIZE;
  let junk_bytes_mutated = mutate_region(&mut binary, &JUNK_MARKER, junk_mutable_size)?;

  // 5. Locate and mutate FINGERPRINT region (16 bytes after marker)
  let fp_bytes_mutated = mutate_region(&mut binary, &FP_MARKER, 16)?;

  // 6. Compute new hash
  let new_hash = hex_sha256(&binary);

  // 7. Atomic write: temp file in same dir, then rename
  atomic_write(&exe_path, &binary)?;

  // 8. Rotate in-memory keys
  super::memory::rotate_key();

  Ok(RehashResult {
    old_hash,
    new_hash,
    junk_bytes_mutated,
    fp_bytes_mutated,
    binary_path: exe_path.display().to_string(),
    memory_key_rotated: true,
  })
}

/// Find the 16-byte marker in `data` and overwrite the next `mutable_size`
/// bytes with OS-provided random data. Returns the number of bytes mutated.
fn mutate_region(data: &mut [u8], marker: &[u8; 16], mutable_size: usize) -> Result<usize, String> {
  let offset = find_marker(data, marker).ok_or_else(|| {
    "Rehash marker not found in binary. Rebuild with latest build.rs.".to_string()
  })?;

  let start = offset + 16; // skip past the marker itself
  let end = start + mutable_size;

  if end > data.len() {
    return Err(format!(
      "Mutable region overflows binary (offset {} + {} > {})",
      start,
      mutable_size,
      data.len()
    ));
  }

  // Generate fresh random bytes from OS CSPRNG
  let mut random_bytes = vec![0u8; mutable_size];
  os_random::fill_bytes(&mut random_bytes)
    .map_err(|e| format!("Failed to generate random bytes: {}", e))?;

  data[start..end].copy_from_slice(&random_bytes);
  Ok(mutable_size)
}

/// Scan for a 16-byte marker in the binary data. Returns the offset of the
/// first occurrence, or None.
fn find_marker(data: &[u8], marker: &[u8; 16]) -> Option<usize> {
  data.windows(16).position(|w| w == marker)
}

/// Write `data` to a temp file next to `target`, copy permissions, then
/// atomically rename over the original.
fn atomic_write(target: &PathBuf, data: &[u8]) -> Result<(), String> {
  // Random suffix prevents symlink attacks and concurrent-run races.
  let mut rand_bytes = [0u8; 8];
  os_random::fill_bytes(&mut rand_bytes).map_err(|e| format!("RNG: {}", e))?;
  let suffix: String = rand_bytes.iter().map(|b| format!("{:02x}", b)).collect();
  let temp_path = target.with_extension(format!("rbrehash.{}.tmp", suffix));

  // Write new content
  fs::write(&temp_path, data)
    .map_err(|e| format!("Failed to write temp file {}: {}", temp_path.display(), e))?;

  // Preserve permissions
  if let Ok(metadata) = fs::metadata(target) {
    let _ = fs::set_permissions(&temp_path, metadata.permissions());
  }

  // Atomic rename (same filesystem on POSIX)
  fs::rename(&temp_path, target).map_err(|e| {
    // Cleanup on failure
    let _ = fs::remove_file(&temp_path);
    format!(
      "Failed to rename {} -> {}: {}",
      temp_path.display(),
      target.display(),
      e
    )
  })
}

fn hex_sha256(data: &[u8]) -> String {
  sha256(data).iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_find_marker_present() {
    let marker: [u8; 16] = [
      0x52, 0x42, 0x4A, 0x55, 0x4E, 0x4B, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x52, 0x42, 0x4A,
      0x4B,
    ];
    let mut data = vec![0u8; 100];
    data[30..46].copy_from_slice(&marker);
    assert_eq!(find_marker(&data, &marker), Some(30));
  }

  #[test]
  fn test_find_marker_absent() {
    let marker: [u8; 16] = [0xFF; 16];
    let data = vec![0u8; 100];
    assert_eq!(find_marker(&data, &marker), None);
  }

  #[test]
  fn test_mutate_region() {
    let marker: [u8; 16] = [
      0x52, 0x42, 0x4A, 0x55, 0x4E, 0x4B, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x52, 0x42, 0x4A,
      0x4B,
    ];
    let mutable_size = 32;
    let mut data = vec![0u8; 100];
    data[10..26].copy_from_slice(&marker);
    // Fill mutable region with known pattern
    for i in 0..mutable_size {
      data[26 + i] = 0xAA;
    }

    let result = mutate_region(&mut data, &marker, mutable_size);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), mutable_size);

    // Marker should be unchanged
    assert_eq!(&data[10..26], &marker);
    // Mutable region should (almost certainly) have changed
    let all_aa = data[26..26 + mutable_size].iter().all(|&b| b == 0xAA);
    // Probability of CSPRNG producing all 0xAA is negligible
    assert!(!all_aa, "mutable region should have been overwritten");
  }

  #[test]
  fn test_hex_sha256() {
    let hash = hex_sha256(b"test");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
  }
}
