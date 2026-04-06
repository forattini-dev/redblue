//! Encoding helpers for MCP server (hex, base64, URL encoding)

/// Hex encoding/decoding
pub mod hex {
  /// Encode bytes to hexadecimal string
  pub fn encode(data: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
      result.push(HEX_CHARS[(byte >> 4) as usize] as char);
      result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
  }

  /// Decode hexadecimal string to bytes
  pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let s = s.trim();
    if s.len() % 2 != 0 {
      return Err("odd length");
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
      let hi = nibble(chunk[0])?;
      let lo = nibble(chunk[1])?;
      result.push((hi << 4) | lo);
    }
    Ok(result)
  }

  fn nibble(c: u8) -> Result<u8, &'static str> {
    match c {
      b'0'..=b'9' => Ok(c - b'0'),
      b'a'..=b'f' => Ok(c - b'a' + 10),
      b'A'..=b'F' => Ok(c - b'A' + 10),
      _ => Err("invalid hex character"),
    }
  }
}

/// Encode bytes to base64
pub fn base64_encode(data: &[u8]) -> String {
  const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
  let chunks = data.chunks(3);

  for chunk in chunks {
    let b0 = chunk[0] as usize;
    let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
    let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

    result.push(ALPHABET[b0 >> 2] as char);
    result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

    if chunk.len() > 1 {
      result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
    } else {
      result.push('=');
    }
    if chunk.len() > 2 {
      result.push(ALPHABET[b2 & 0x3f] as char);
    } else {
      result.push('=');
    }
  }
  result
}

/// Decode base64 string to bytes
pub fn base64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
  fn decode_char(c: u8) -> Result<u8, &'static str> {
    match c {
      b'A'..=b'Z' => Ok(c - b'A'),
      b'a'..=b'z' => Ok(c - b'a' + 26),
      b'0'..=b'9' => Ok(c - b'0' + 52),
      b'+' => Ok(62),
      b'/' => Ok(63),
      b'=' => Ok(0),
      _ => Err("invalid base64 character"),
    }
  }

  let s = s.trim().replace('\n', "").replace('\r', "");
  if s.len() % 4 != 0 {
    return Err("invalid base64 length");
  }

  let mut result = Vec::with_capacity(s.len() * 3 / 4);
  for chunk in s.as_bytes().chunks(4) {
    let c0 = decode_char(chunk[0])?;
    let c1 = decode_char(chunk[1])?;
    let c2 = decode_char(chunk[2])?;
    let c3 = decode_char(chunk[3])?;

    result.push((c0 << 2) | (c1 >> 4));
    if chunk[2] != b'=' {
      result.push((c1 << 4) | (c2 >> 2));
    }
    if chunk[3] != b'=' {
      result.push((c2 << 6) | c3);
    }
  }
  Ok(result)
}

/// URL-encode a string
pub fn url_encode(s: &str) -> String {
  let mut result = String::with_capacity(s.len() * 3);
  for byte in s.bytes() {
    match byte {
      b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
        result.push(byte as char);
      }
      _ => {
        result.push('%');
        result.push_str(&format!("{:02X}", byte));
      }
    }
  }
  result
}

/// URL-decode a string
pub fn url_decode(s: &str) -> String {
  let mut result = Vec::with_capacity(s.len());
  let mut chars = s.bytes().peekable();

  while let Some(c) = chars.next() {
    if c == b'%' {
      let hi = chars.next().and_then(|c| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
      });
      let lo = chars.next().and_then(|c| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
      });
      if let (Some(h), Some(l)) = (hi, lo) {
        result.push((h << 4) | l);
      } else {
        result.push(b'%');
      }
    } else if c == b'+' {
      result.push(b' ');
    } else {
      result.push(c);
    }
  }
  String::from_utf8_lossy(&result).to_string()
}
