//! ASN.1 DER Encoding Helpers for Kerberos
//!
//! Low-level encoding functions for Kerberos ASN.1 structures.

/// Encode ASN.1 length field
pub fn encode_length(len: usize) -> Vec<u8> {
  if len < 128 {
    vec![len as u8]
  } else if len < 256 {
    vec![0x81, len as u8]
  } else if len < 65536 {
    vec![0x82, (len >> 8) as u8, len as u8]
  } else if len < 16777216 {
    vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
  } else {
    vec![
      0x84,
      (len >> 24) as u8,
      (len >> 16) as u8,
      (len >> 8) as u8,
      len as u8,
    ]
  }
}

/// Encode ASN.1 SEQUENCE
pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
  let mut result = vec![0x30]; // SEQUENCE tag
  result.extend_from_slice(&encode_length(content.len()));
  result.extend_from_slice(content);
  result
}

/// Encode ASN.1 APPLICATION tag
pub fn encode_application(tag: u8, content: &[u8]) -> Vec<u8> {
  let mut result = vec![0x60 | tag]; // APPLICATION CONSTRUCTED
  result.extend_from_slice(&encode_length(content.len()));
  result.extend_from_slice(content);
  result
}

/// Encode ASN.1 context-specific tag
pub fn encode_tagged(tag: u8, content: &[u8]) -> Vec<u8> {
  let mut result = vec![0xA0 | tag]; // CONTEXT-SPECIFIC CONSTRUCTED
  result.extend_from_slice(&encode_length(content.len()));
  result.extend_from_slice(content);
  result
}

/// Encode ASN.1 INTEGER
pub fn encode_integer(value: i32) -> Vec<u8> {
  let bytes = value.to_be_bytes();

  // Find first non-zero byte (or keep last byte if zero)
  let mut start = 0;
  while start < 3 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
    start += 1;
  }

  // Handle negative numbers - need to preserve sign
  if value >= 0 && (bytes[start] & 0x80) != 0 {
    // Positive number with high bit set - prepend 0x00
    let len = 4 - start + 1;
    let mut result = vec![0x02, len as u8, 0x00];
    result.extend_from_slice(&bytes[start..]);
    return result;
  }

  let len = 4 - start;
  let mut result = vec![0x02, len as u8];
  result.extend_from_slice(&bytes[start..]);
  result
}

/// Encode ASN.1 BOOLEAN
#[allow(dead_code)]
pub fn encode_boolean(value: bool) -> Vec<u8> {
  vec![0x01, 0x01, if value { 0xFF } else { 0x00 }]
}

/// Encode ASN.1 OCTET STRING
pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
  let mut result = vec![0x04];
  result.extend_from_slice(&encode_length(data.len()));
  result.extend_from_slice(data);
  result
}

/// Encode 32-bit BIT STRING
pub fn encode_bit_string_32(value: u32) -> Vec<u8> {
  // BitString with 4 bytes (32 bits), 0 unused bits
  let bytes = value.to_be_bytes();
  vec![0x03, 0x05, 0x00, bytes[0], bytes[1], bytes[2], bytes[3]]
}

/// Encode ASN.1 GeneralString
pub fn encode_general_string(s: &str) -> Vec<u8> {
  let bytes = s.as_bytes();
  let mut result = vec![0x1B]; // GeneralString tag
  result.extend_from_slice(&encode_length(bytes.len()));
  result.extend_from_slice(bytes);
  result
}

/// Decode DER INTEGER to i32
pub fn der_integer_to_i32(bytes: &[u8]) -> i32 {
  if bytes.is_empty() {
    return 0;
  }

  let is_negative = (bytes[0] & 0x80) != 0;
  let mut result = 0i32;

  for &byte in bytes {
    result = (result << 8) | (byte as i32);
  }

  // Sign extend if necessary
  if is_negative && bytes.len() < 4 {
    let shift = (4 - bytes.len()) * 8;
    result = (result << shift) >> shift;
  }

  result
}
