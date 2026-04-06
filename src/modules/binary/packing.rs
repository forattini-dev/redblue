//! Binary Packing Utilities
//!
//! Provides pwntools-style packing and unpacking functions for exploit development.
//! Supports 8/16/32/64-bit values in little-endian and big-endian formats.

use super::{BinaryError, BinaryResult, Endianness};

/// Pack a u8 value to bytes
pub fn p8(value: u8) -> Vec<u8> {
  vec![value]
}

/// Pack a u16 value to bytes (little-endian by default)
pub fn p16(value: u16) -> Vec<u8> {
  p16_le(value)
}

/// Pack a u16 value to bytes (little-endian)
pub fn p16_le(value: u16) -> Vec<u8> {
  value.to_le_bytes().to_vec()
}

/// Pack a u16 value to bytes (big-endian)
pub fn p16_be(value: u16) -> Vec<u8> {
  value.to_be_bytes().to_vec()
}

/// Pack a u32 value to bytes (little-endian by default)
pub fn p32(value: u32) -> Vec<u8> {
  p32_le(value)
}

/// Pack a u32 value to bytes (little-endian)
pub fn p32_le(value: u32) -> Vec<u8> {
  value.to_le_bytes().to_vec()
}

/// Pack a u32 value to bytes (big-endian)
pub fn p32_be(value: u32) -> Vec<u8> {
  value.to_be_bytes().to_vec()
}

/// Pack a u64 value to bytes (little-endian by default)
pub fn p64(value: u64) -> Vec<u8> {
  p64_le(value)
}

/// Pack a u64 value to bytes (little-endian)
pub fn p64_le(value: u64) -> Vec<u8> {
  value.to_le_bytes().to_vec()
}

/// Pack a u64 value to bytes (big-endian)
pub fn p64_be(value: u64) -> Vec<u8> {
  value.to_be_bytes().to_vec()
}

/// Unpack bytes to u8
pub fn u8_(data: &[u8]) -> BinaryResult<u8> {
  if data.is_empty() {
    return Err(BinaryError::TooSmall);
  }
  Ok(data[0])
}

/// Unpack bytes to u16 (little-endian by default)
pub fn u16_(data: &[u8]) -> BinaryResult<u16> {
  u16_le(data)
}

/// Unpack bytes to u16 (little-endian)
pub fn u16_le(data: &[u8]) -> BinaryResult<u16> {
  if data.len() < 2 {
    return Err(BinaryError::TooSmall);
  }
  Ok(u16::from_le_bytes([data[0], data[1]]))
}

/// Unpack bytes to u16 (big-endian)
pub fn u16_be(data: &[u8]) -> BinaryResult<u16> {
  if data.len() < 2 {
    return Err(BinaryError::TooSmall);
  }
  Ok(u16::from_be_bytes([data[0], data[1]]))
}

/// Unpack bytes to u32 (little-endian by default)
pub fn u32_(data: &[u8]) -> BinaryResult<u32> {
  u32_le(data)
}

/// Unpack bytes to u32 (little-endian)
pub fn u32_le(data: &[u8]) -> BinaryResult<u32> {
  if data.len() < 4 {
    return Err(BinaryError::TooSmall);
  }
  Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

/// Unpack bytes to u32 (big-endian)
pub fn u32_be(data: &[u8]) -> BinaryResult<u32> {
  if data.len() < 4 {
    return Err(BinaryError::TooSmall);
  }
  Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

/// Unpack bytes to u64 (little-endian by default)
pub fn u64_(data: &[u8]) -> BinaryResult<u64> {
  u64_le(data)
}

/// Unpack bytes to u64 (little-endian)
pub fn u64_le(data: &[u8]) -> BinaryResult<u64> {
  if data.len() < 8 {
    return Err(BinaryError::TooSmall);
  }
  Ok(u64::from_le_bytes([
    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
  ]))
}

/// Unpack bytes to u64 (big-endian)
pub fn u64_be(data: &[u8]) -> BinaryResult<u64> {
  if data.len() < 8 {
    return Err(BinaryError::TooSmall);
  }
  Ok(u64::from_be_bytes([
    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
  ]))
}

/// Pack value with specified endianness
pub fn pack(value: u64, bits: u8, endian: Endianness) -> Vec<u8> {
  match (bits, endian) {
    (8, _) => p8(value as u8),
    (16, Endianness::Little) => p16_le(value as u16),
    (16, Endianness::Big) => p16_be(value as u16),
    (32, Endianness::Little) => p32_le(value as u32),
    (32, Endianness::Big) => p32_be(value as u32),
    (64, Endianness::Little) => p64_le(value),
    (64, Endianness::Big) => p64_be(value),
    _ => p64_le(value), // Default to 64-bit LE
  }
}

/// Unpack bytes with specified endianness
pub fn unpack(data: &[u8], bits: u8, endian: Endianness) -> BinaryResult<u64> {
  match (bits, endian) {
    (8, _) => u8_(data).map(|v| v as u64),
    (16, Endianness::Little) => u16_le(data).map(|v| v as u64),
    (16, Endianness::Big) => u16_be(data).map(|v| v as u64),
    (32, Endianness::Little) => u32_le(data).map(|v| v as u64),
    (32, Endianness::Big) => u32_be(data).map(|v| v as u64),
    (64, Endianness::Little) => u64_le(data),
    (64, Endianness::Big) => u64_be(data),
    _ => u64_le(data), // Default to 64-bit LE
  }
}

/// Flat packer - concatenate multiple values
pub struct Flat {
  data: Vec<u8>,
  bits: u8,
  endian: Endianness,
}

impl Flat {
  pub fn new() -> Self {
    Self {
      data: Vec::new(),
      bits: 64,
      endian: Endianness::Little,
    }
  }

  pub fn new_32() -> Self {
    Self {
      data: Vec::new(),
      bits: 32,
      endian: Endianness::Little,
    }
  }

  pub fn new_64() -> Self {
    Self::new()
  }

  /// Add raw bytes
  pub fn raw(mut self, data: &[u8]) -> Self {
    self.data.extend_from_slice(data);
    self
  }

  /// Add a string (with optional null terminator)
  pub fn string(mut self, s: &str, null_terminate: bool) -> Self {
    self.data.extend_from_slice(s.as_bytes());
    if null_terminate {
      self.data.push(0);
    }
    self
  }

  /// Add an address/value with current context settings
  pub fn addr(mut self, value: u64) -> Self {
    self.data.extend(pack(value, self.bits, self.endian));
    self
  }

  /// Add multiple addresses
  pub fn addrs(mut self, values: &[u64]) -> Self {
    for &v in values {
      self.data.extend(pack(v, self.bits, self.endian));
    }
    self
  }

  /// Add padding bytes
  pub fn pad(mut self, count: usize, byte: u8) -> Self {
    self.data.extend(std::iter::repeat(byte).take(count));
    self
  }

  /// Add alignment padding
  pub fn align(mut self, alignment: usize) -> Self {
    let padding = (alignment - (self.data.len() % alignment)) % alignment;
    self.data.extend(std::iter::repeat(0u8).take(padding));
    self
  }

  /// Get total length
  pub fn len(&self) -> usize {
    self.data.len()
  }

  /// Check if empty
  pub fn is_empty(&self) -> bool {
    self.data.is_empty()
  }

  /// Build final payload
  pub fn build(self) -> Vec<u8> {
    self.data
  }
}

impl Default for Flat {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_p8() {
    assert_eq!(p8(0x41), vec![0x41]);
  }

  #[test]
  fn test_p16() {
    assert_eq!(p16(0x4142), vec![0x42, 0x41]);
    assert_eq!(p16_be(0x4142), vec![0x41, 0x42]);
  }

  #[test]
  fn test_p32() {
    assert_eq!(p32(0x41424344), vec![0x44, 0x43, 0x42, 0x41]);
    assert_eq!(p32_be(0x41424344), vec![0x41, 0x42, 0x43, 0x44]);
  }

  #[test]
  fn test_p64() {
    assert_eq!(
      p64(0x4142434445464748),
      vec![0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41]
    );
    assert_eq!(
      p64_be(0x4142434445464748),
      vec![0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]
    );
  }

  #[test]
  fn test_u16() {
    assert_eq!(u16_(&[0x42, 0x41]).unwrap(), 0x4142);
    assert_eq!(u16_be(&[0x41, 0x42]).unwrap(), 0x4142);
  }

  #[test]
  fn test_u32() {
    assert_eq!(u32_(&[0x44, 0x43, 0x42, 0x41]).unwrap(), 0x41424344);
    assert_eq!(u32_be(&[0x41, 0x42, 0x43, 0x44]).unwrap(), 0x41424344);
  }

  #[test]
  fn test_u64() {
    assert_eq!(
      u64_(&[0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41]).unwrap(),
      0x4142434445464748
    );
  }

  #[test]
  fn test_roundtrip() {
    let original: u64 = 0xDEADBEEFCAFEBABE;
    let packed = p64(original);
    let unpacked = u64_(&packed).unwrap();
    assert_eq!(original, unpacked);
  }

  #[test]
  fn test_flat_builder() {
    let payload = Flat::new_64()
      .raw(b"AAAA")
      .addr(0xdeadbeef)
      .pad(8, 0x41)
      .build();

    assert_eq!(payload.len(), 4 + 8 + 8); // 4 bytes raw + 8 bytes addr + 8 bytes pad
    assert_eq!(&payload[0..4], b"AAAA");
    assert_eq!(u64_(&payload[4..12]).unwrap(), 0xdeadbeef);
  }

  #[test]
  fn test_flat_alignment() {
    let payload = Flat::new()
      .raw(b"ABC") // 3 bytes
      .align(8) // Should add 5 padding bytes
      .build();

    assert_eq!(payload.len(), 8);
  }
}
