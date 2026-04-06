/// Hash Format Detection and Verification
///
/// Supports 20+ common hash formats with automatic detection.
/// Uses signature patterns and length heuristics for identification.
use crate::crypto::{md5, sha1, sha256};

/// Supported hash formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFormat {
  // Fast hashes (no salt/iterations)
  MD5,
  SHA1,
  SHA256,
  SHA384,
  SHA512,

  // Windows hashes
  NTLM,
  LM,
  NetNTLMv1,
  NetNTLMv2,

  // Unix crypt variants
  MD5Crypt,    // $1$
  SHA256Crypt, // $5$
  SHA512Crypt, // $6$
  BCrypt,      // $2a$, $2b$, $2y$

  // Database hashes
  MySQLOld,    // MySQL < 4.1
  MySQL41,     // MySQL >= 4.1 (double SHA1)
  PostgresMD5, // md5 + user

  // Web application hashes
  PHPass,    // $P$, $H$
  Drupal7,   // $S$
  WordPress, // $P$ (phpass variant)

  // Key derivation
  PBKDF2SHA1,
  PBKDF2SHA256,

  // Raw (unknown format)
  Raw,
}

impl HashFormat {
  /// Get the hashcat mode number (for compatibility)
  pub fn hashcat_mode(&self) -> u32 {
    match self {
      HashFormat::MD5 => 0,
      HashFormat::SHA1 => 100,
      HashFormat::SHA256 => 1400,
      HashFormat::SHA384 => 10800,
      HashFormat::SHA512 => 1700,
      HashFormat::NTLM => 1000,
      HashFormat::LM => 3000,
      HashFormat::NetNTLMv1 => 5500,
      HashFormat::NetNTLMv2 => 5600,
      HashFormat::MD5Crypt => 500,
      HashFormat::SHA256Crypt => 7400,
      HashFormat::SHA512Crypt => 1800,
      HashFormat::BCrypt => 3200,
      HashFormat::MySQLOld => 200,
      HashFormat::MySQL41 => 300,
      HashFormat::PostgresMD5 => 50,
      HashFormat::PHPass => 400,
      HashFormat::Drupal7 => 7900,
      HashFormat::WordPress => 400,
      HashFormat::PBKDF2SHA1 => 12000,
      HashFormat::PBKDF2SHA256 => 10900,
      HashFormat::Raw => 99999,
    }
  }

  /// Get human-readable format name
  pub fn name(&self) -> &'static str {
    match self {
      HashFormat::MD5 => "MD5",
      HashFormat::SHA1 => "SHA-1",
      HashFormat::SHA256 => "SHA-256",
      HashFormat::SHA384 => "SHA-384",
      HashFormat::SHA512 => "SHA-512",
      HashFormat::NTLM => "NTLM",
      HashFormat::LM => "LM",
      HashFormat::NetNTLMv1 => "NetNTLMv1",
      HashFormat::NetNTLMv2 => "NetNTLMv2",
      HashFormat::MD5Crypt => "md5crypt",
      HashFormat::SHA256Crypt => "sha256crypt",
      HashFormat::SHA512Crypt => "sha512crypt",
      HashFormat::BCrypt => "bcrypt",
      HashFormat::MySQLOld => "MySQL (old)",
      HashFormat::MySQL41 => "MySQL 4.1+",
      HashFormat::PostgresMD5 => "PostgreSQL MD5",
      HashFormat::PHPass => "phpass",
      HashFormat::Drupal7 => "Drupal 7",
      HashFormat::WordPress => "WordPress",
      HashFormat::PBKDF2SHA1 => "PBKDF2-SHA1",
      HashFormat::PBKDF2SHA256 => "PBKDF2-SHA256",
      HashFormat::Raw => "Raw/Unknown",
    }
  }

  /// Get the expected hash length in characters (hex)
  pub fn hash_length(&self) -> Option<usize> {
    match self {
      HashFormat::MD5 => Some(32),
      HashFormat::SHA1 => Some(40),
      HashFormat::SHA256 => Some(64),
      HashFormat::SHA384 => Some(96),
      HashFormat::SHA512 => Some(128),
      HashFormat::NTLM => Some(32),
      HashFormat::LM => Some(32),
      HashFormat::MySQLOld => Some(16),
      HashFormat::MySQL41 => Some(40),
      _ => None, // Variable length (salted/encoded)
    }
  }

  /// Check if format uses salt
  pub fn is_salted(&self) -> bool {
    matches!(
      self,
      HashFormat::MD5Crypt
        | HashFormat::SHA256Crypt
        | HashFormat::SHA512Crypt
        | HashFormat::BCrypt
        | HashFormat::PostgresMD5
        | HashFormat::PHPass
        | HashFormat::Drupal7
        | HashFormat::WordPress
        | HashFormat::PBKDF2SHA1
        | HashFormat::PBKDF2SHA256
        | HashFormat::NetNTLMv1
        | HashFormat::NetNTLMv2
    )
  }

  /// Check if format is slow (iterated)
  pub fn is_slow(&self) -> bool {
    matches!(
      self,
      HashFormat::BCrypt
        | HashFormat::SHA256Crypt
        | HashFormat::SHA512Crypt
        | HashFormat::PBKDF2SHA1
        | HashFormat::PBKDF2SHA256
    )
  }
}

/// Parsed hash information
#[derive(Debug, Clone)]
pub struct HashInfo {
  pub format: HashFormat,
  pub hash: String,
  pub salt: Option<String>,
  pub rounds: Option<u32>,
  pub username: Option<String>,
}

impl HashInfo {
  pub fn new(format: HashFormat, hash: &str) -> Self {
    Self {
      format,
      hash: hash.to_string(),
      salt: None,
      rounds: None,
      username: None,
    }
  }

  pub fn with_salt(mut self, salt: &str) -> Self {
    self.salt = Some(salt.to_string());
    self
  }

  pub fn with_rounds(mut self, rounds: u32) -> Self {
    self.rounds = Some(rounds);
    self
  }

  pub fn with_username(mut self, username: &str) -> Self {
    self.username = Some(username.to_string());
    self
  }
}

/// Detect hash format from hash string
pub fn detect_format(hash: &str) -> Option<HashFormat> {
  let hash = hash.trim();

  // Check signatures first (most reliable)
  if hash.starts_with("$1$") {
    return Some(HashFormat::MD5Crypt);
  }
  if hash.starts_with("$5$") {
    return Some(HashFormat::SHA256Crypt);
  }
  if hash.starts_with("$6$") {
    return Some(HashFormat::SHA512Crypt);
  }
  if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
    return Some(HashFormat::BCrypt);
  }
  if hash.starts_with("$P$") || hash.starts_with("$H$") {
    return Some(HashFormat::PHPass);
  }
  if hash.starts_with("$S$") {
    return Some(HashFormat::Drupal7);
  }
  if hash.starts_with("*") && hash.len() == 41 {
    return Some(HashFormat::MySQL41);
  }
  if hash.starts_with("md5") && hash.len() == 35 {
    return Some(HashFormat::PostgresMD5);
  }

  // NetNTLM detection (contains :: separators)
  if hash.contains("::") {
    let parts: Vec<&str> = hash.split("::").collect();
    if parts.len() >= 5 {
      // Check response length for v1 vs v2
      if let Some(resp) = parts.get(4) {
        if resp.len() == 48 {
          return Some(HashFormat::NetNTLMv1);
        } else if resp.len() > 48 {
          return Some(HashFormat::NetNTLMv2);
        }
      }
    }
  }

  // Fall back to length-based detection
  if is_valid_hex(hash) {
    match hash.len() {
      16 => return Some(HashFormat::MySQLOld),
      32 => {
        // Could be MD5, NTLM, or LM
        // NTLM/LM are uppercase, MD5 is lowercase by convention
        if hash.chars().all(|c| c.is_uppercase() || c.is_ascii_digit()) {
          return Some(HashFormat::NTLM);
        }
        return Some(HashFormat::MD5);
      }
      40 => return Some(HashFormat::SHA1),
      64 => return Some(HashFormat::SHA256),
      96 => return Some(HashFormat::SHA384),
      128 => return Some(HashFormat::SHA512),
      _ => {}
    }
  }

  Some(HashFormat::Raw)
}

/// Parse hash string into HashInfo
pub fn parse_hash(hash: &str) -> Option<HashInfo> {
  let hash = hash.trim();
  let format = detect_format(hash)?;

  match format {
    HashFormat::MD5Crypt => parse_unix_crypt(hash, format),
    HashFormat::SHA256Crypt => parse_unix_crypt(hash, format),
    HashFormat::SHA512Crypt => parse_unix_crypt(hash, format),
    HashFormat::BCrypt => parse_bcrypt(hash),
    HashFormat::PHPass | HashFormat::WordPress => parse_phpass(hash),
    HashFormat::PostgresMD5 => parse_postgres_md5(hash),
    HashFormat::NetNTLMv1 | HashFormat::NetNTLMv2 => parse_netntlm(hash, format),
    _ => Some(HashInfo::new(format, hash)),
  }
}

/// Parse Unix crypt format: $id$salt$hash
fn parse_unix_crypt(hash: &str, format: HashFormat) -> Option<HashInfo> {
  let parts: Vec<&str> = hash.split('$').collect();
  if parts.len() < 4 {
    return None;
  }

  // parts[0] is empty (before first $)
  // parts[1] is id (1, 5, 6)
  // parts[2] is salt (may include rounds=N)
  // parts[3] is hash

  let mut salt = parts[2].to_string();
  let mut rounds = None;

  // Check for rounds=N in salt
  if salt.starts_with("rounds=") {
    let round_parts: Vec<&str> = salt.splitn(2, '$').collect();
    if round_parts.len() == 2 {
      if let Some(r) = round_parts[0].strip_prefix("rounds=") {
        rounds = r.parse().ok();
      }
      salt = round_parts[1].to_string();
    }
  }

  let hash_part = parts.get(3).unwrap_or(&"");

  Some(
    HashInfo::new(format, hash_part)
      .with_salt(&salt)
      .with_rounds(rounds.unwrap_or(match format {
        HashFormat::SHA256Crypt | HashFormat::SHA512Crypt => 5000,
        HashFormat::MD5Crypt => 1000,
        _ => 1,
      })),
  )
}

/// Parse bcrypt format: $2a$cost$salt+hash (22 char salt, 31 char hash)
fn parse_bcrypt(hash: &str) -> Option<HashInfo> {
  let parts: Vec<&str> = hash.split('$').collect();
  if parts.len() < 4 {
    return None;
  }

  let cost: u32 = parts[2].parse().ok()?;
  let salt_and_hash = parts[3];

  if salt_and_hash.len() < 53 {
    return None;
  }

  let (salt, hash_part) = salt_and_hash.split_at(22);

  Some(
    HashInfo::new(HashFormat::BCrypt, hash_part)
      .with_salt(salt)
      .with_rounds(1 << cost),
  )
}

/// Parse phpass format: $P$rounds+salt+hash
fn parse_phpass(hash: &str) -> Option<HashInfo> {
  if hash.len() < 34 {
    return None;
  }

  // Format: $P$B (where B is iteration count char) + 8 char salt + 22 char hash
  let iter_char = hash.chars().nth(3)?;
  let rounds = phpass_decode_count(iter_char);
  let salt = &hash[4..12];
  let hash_part = &hash[12..];

  Some(
    HashInfo::new(HashFormat::PHPass, hash_part)
      .with_salt(salt)
      .with_rounds(rounds),
  )
}

/// Parse PostgreSQL MD5: md5 + 32 hex
fn parse_postgres_md5(hash: &str) -> Option<HashInfo> {
  let hash_part = hash.strip_prefix("md5")?;
  Some(HashInfo::new(HashFormat::PostgresMD5, hash_part))
}

/// Parse NetNTLM format: user::domain:challenge:response:hash
fn parse_netntlm(hash: &str, format: HashFormat) -> Option<HashInfo> {
  let parts: Vec<&str> = hash.split("::").collect();
  if parts.len() < 2 {
    return None;
  }

  let username = parts[0].to_string();
  let rest: Vec<&str> = parts[1].split(':').collect();

  Some(HashInfo::new(format, hash).with_username(&username))
}

/// Decode phpass iteration count
fn phpass_decode_count(c: char) -> u32 {
  const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let idx = ITOA64.iter().position(|&x| x == c as u8).unwrap_or(0);
  1 << idx
}

/// Check if string is valid hexadecimal
fn is_valid_hex(s: &str) -> bool {
  !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Format a password using the specified hash format
pub fn format_hash(password: &str, format: HashFormat, salt: Option<&str>) -> String {
  match format {
    HashFormat::MD5 => {
      let digest = md5(password.as_bytes());
      hex_encode(&digest)
    }
    HashFormat::SHA1 => {
      let digest = sha1(password.as_bytes());
      hex_encode(&digest)
    }
    HashFormat::SHA256 => {
      let digest = sha256(password.as_bytes());
      hex_encode(&digest)
    }
    HashFormat::NTLM => ntlm_hash(password),
    HashFormat::MySQL41 => {
      // SHA1(SHA1(password))
      let first = sha1(password.as_bytes());
      let second = sha1(&first);
      format!("*{}", hex_encode(&second).to_uppercase())
    }
    HashFormat::PostgresMD5 => {
      // md5(password + username)
      let username = salt.unwrap_or("postgres");
      let combined = format!("{}{}", password, username);
      let digest = md5(combined.as_bytes());
      format!("md5{}", hex_encode(&digest))
    }
    HashFormat::BCrypt => {
      // Default cost of 10 for generation
      super::bcrypt::bcrypt_hash_password(password, 10)
    }
    _ => {
      // For unsupported formats, return MD5 as fallback
      let digest = md5(password.as_bytes());
      hex_encode(&digest)
    }
  }
}

/// Verify a password against a hash
pub fn verify_hash(password: &str, info: &HashInfo) -> bool {
  match info.format {
    HashFormat::MD5 => {
      let computed = format_hash(password, HashFormat::MD5, None);
      constant_time_compare(&computed, &info.hash)
    }
    HashFormat::SHA1 => {
      let computed = format_hash(password, HashFormat::SHA1, None);
      constant_time_compare(&computed, &info.hash)
    }
    HashFormat::SHA256 => {
      let computed = format_hash(password, HashFormat::SHA256, None);
      constant_time_compare(&computed, &info.hash)
    }
    HashFormat::NTLM => {
      let computed = format_hash(password, HashFormat::NTLM, None);
      constant_time_compare(&computed.to_lowercase(), &info.hash.to_lowercase())
    }
    HashFormat::MySQL41 => {
      let computed = format_hash(password, HashFormat::MySQL41, None);
      constant_time_compare(&computed.to_uppercase(), &info.hash.to_uppercase())
    }
    HashFormat::PostgresMD5 => {
      let computed = format_hash(password, HashFormat::PostgresMD5, info.username.as_deref());
      constant_time_compare(&computed, &format!("md5{}", info.hash))
    }
    HashFormat::MD5Crypt => verify_md5crypt(password, info),
    HashFormat::BCrypt => verify_bcrypt(password, info),
    _ => false, // Unsupported format
  }
}

/// NTLM hash (MD4 of UTF-16LE password)
fn ntlm_hash(password: &str) -> String {
  // Convert to UTF-16LE
  let utf16: Vec<u8> = password
    .encode_utf16()
    .flat_map(|c| c.to_le_bytes())
    .collect();

  // MD4 hash
  let digest = md4(&utf16);
  hex_encode(&digest).to_uppercase()
}

/// Simple MD4 implementation for NTLM
fn md4(data: &[u8]) -> [u8; 16] {
  // MD4 implementation
  let mut a: u32 = 0x67452301;
  let mut b: u32 = 0xefcdab89;
  let mut c: u32 = 0x98badcfe;
  let mut d: u32 = 0x10325476;

  // Pad message
  let bit_len = (data.len() as u64) * 8;
  let mut msg = data.to_vec();
  msg.push(0x80);
  while (msg.len() % 64) != 56 {
    msg.push(0);
  }
  msg.extend_from_slice(&bit_len.to_le_bytes());

  // Process blocks
  for chunk in msg.chunks(64) {
    let mut x = [0u32; 16];
    for (i, block) in chunk.chunks(4).enumerate() {
      x[i] = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    }

    let (aa, bb, cc, dd) = (a, b, c, d);

    // Round 1
    macro_rules! ff {
      ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
        $a = $a
          .wrapping_add(($b & $c) | (!$b & $d))
          .wrapping_add(x[$k])
          .rotate_left($s);
      };
    }

    ff!(a, b, c, d, 0, 3);
    ff!(d, a, b, c, 1, 7);
    ff!(c, d, a, b, 2, 11);
    ff!(b, c, d, a, 3, 19);
    ff!(a, b, c, d, 4, 3);
    ff!(d, a, b, c, 5, 7);
    ff!(c, d, a, b, 6, 11);
    ff!(b, c, d, a, 7, 19);
    ff!(a, b, c, d, 8, 3);
    ff!(d, a, b, c, 9, 7);
    ff!(c, d, a, b, 10, 11);
    ff!(b, c, d, a, 11, 19);
    ff!(a, b, c, d, 12, 3);
    ff!(d, a, b, c, 13, 7);
    ff!(c, d, a, b, 14, 11);
    ff!(b, c, d, a, 15, 19);

    // Round 2
    macro_rules! gg {
      ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
        $a = $a
          .wrapping_add(($b & $c) | ($b & $d) | ($c & $d))
          .wrapping_add(x[$k])
          .wrapping_add(0x5a827999)
          .rotate_left($s);
      };
    }

    gg!(a, b, c, d, 0, 3);
    gg!(d, a, b, c, 4, 5);
    gg!(c, d, a, b, 8, 9);
    gg!(b, c, d, a, 12, 13);
    gg!(a, b, c, d, 1, 3);
    gg!(d, a, b, c, 5, 5);
    gg!(c, d, a, b, 9, 9);
    gg!(b, c, d, a, 13, 13);
    gg!(a, b, c, d, 2, 3);
    gg!(d, a, b, c, 6, 5);
    gg!(c, d, a, b, 10, 9);
    gg!(b, c, d, a, 14, 13);
    gg!(a, b, c, d, 3, 3);
    gg!(d, a, b, c, 7, 5);
    gg!(c, d, a, b, 11, 9);
    gg!(b, c, d, a, 15, 13);

    // Round 3
    macro_rules! hh {
      ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
        $a = $a
          .wrapping_add($b ^ $c ^ $d)
          .wrapping_add(x[$k])
          .wrapping_add(0x6ed9eba1)
          .rotate_left($s);
      };
    }

    hh!(a, b, c, d, 0, 3);
    hh!(d, a, b, c, 8, 9);
    hh!(c, d, a, b, 4, 11);
    hh!(b, c, d, a, 12, 15);
    hh!(a, b, c, d, 2, 3);
    hh!(d, a, b, c, 10, 9);
    hh!(c, d, a, b, 6, 11);
    hh!(b, c, d, a, 14, 15);
    hh!(a, b, c, d, 1, 3);
    hh!(d, a, b, c, 9, 9);
    hh!(c, d, a, b, 5, 11);
    hh!(b, c, d, a, 13, 15);
    hh!(a, b, c, d, 3, 3);
    hh!(d, a, b, c, 11, 9);
    hh!(c, d, a, b, 7, 11);
    hh!(b, c, d, a, 15, 15);

    a = a.wrapping_add(aa);
    b = b.wrapping_add(bb);
    c = c.wrapping_add(cc);
    d = d.wrapping_add(dd);
  }

  let mut result = [0u8; 16];
  result[0..4].copy_from_slice(&a.to_le_bytes());
  result[4..8].copy_from_slice(&b.to_le_bytes());
  result[8..12].copy_from_slice(&c.to_le_bytes());
  result[12..16].copy_from_slice(&d.to_le_bytes());
  result
}

/// Verify md5crypt hash
fn verify_md5crypt(password: &str, info: &HashInfo) -> bool {
  if let Some(salt) = &info.salt {
    let computed = md5crypt(password.as_bytes(), salt.as_bytes());
    constant_time_compare(&computed, &info.hash)
  } else {
    false
  }
}

/// MD5-crypt implementation
fn md5crypt(password: &[u8], salt: &[u8]) -> String {
  // Limit salt to 8 characters
  let salt = if salt.len() > 8 { &salt[..8] } else { salt };

  // Initial hash: password + magic + salt
  let mut ctx = Md5Context::new();
  ctx.update(password);
  ctx.update(b"$1$");
  ctx.update(salt);

  // Alternate hash: password + salt + password
  let mut alt_ctx = Md5Context::new();
  alt_ctx.update(password);
  alt_ctx.update(salt);
  alt_ctx.update(password);
  let alt_hash = alt_ctx.finalize();

  // Add alternate hash bytes
  let pw_len = password.len();
  let mut i = pw_len;
  while i > 16 {
    ctx.update(&alt_hash);
    i -= 16;
  }
  ctx.update(&alt_hash[..i]);

  // Add bits based on password length
  let mut i = pw_len;
  while i > 0 {
    if i & 1 != 0 {
      ctx.update(&[0]);
    } else {
      ctx.update(&password[..1]);
    }
    i >>= 1;
  }

  let mut hash = ctx.finalize();

  // 1000 iterations
  for i in 0..1000 {
    let mut ctx = Md5Context::new();
    if i & 1 != 0 {
      ctx.update(password);
    } else {
      ctx.update(&hash);
    }
    if i % 3 != 0 {
      ctx.update(salt);
    }
    if i % 7 != 0 {
      ctx.update(password);
    }
    if i & 1 != 0 {
      ctx.update(&hash);
    } else {
      ctx.update(password);
    }
    hash = ctx.finalize();
  }

  // Encode result
  md5crypt_b64_encode(&hash)
}

/// MD5 context for md5crypt
struct Md5Context {
  data: Vec<u8>,
}

impl Md5Context {
  fn new() -> Self {
    Self { data: Vec::new() }
  }

  fn update(&mut self, data: &[u8]) {
    self.data.extend_from_slice(data);
  }

  fn finalize(self) -> [u8; 16] {
    md5(&self.data)
  }
}

/// Base64 encoding for md5crypt
fn md5crypt_b64_encode(hash: &[u8; 16]) -> String {
  const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  let mut result = String::with_capacity(22);

  let encode_triple = |a: u8, b: u8, c: u8| -> String {
    let mut out = String::with_capacity(4);
    let v = (a as u32) | ((b as u32) << 8) | ((c as u32) << 16);
    for i in 0..4 {
      out.push(ITOA64[((v >> (i * 6)) & 0x3f) as usize] as char);
    }
    out
  };

  result.push_str(&encode_triple(hash[0], hash[6], hash[12]));
  result.push_str(&encode_triple(hash[1], hash[7], hash[13]));
  result.push_str(&encode_triple(hash[2], hash[8], hash[14]));
  result.push_str(&encode_triple(hash[3], hash[9], hash[15]));
  result.push_str(&encode_triple(hash[4], hash[10], hash[5]));

  // Last byte
  let v = hash[11] as u32;
  result.push(ITOA64[(v & 0x3f) as usize] as char);
  result.push(ITOA64[((v >> 6) & 0x3f) as usize] as char);

  result
}

/// Verify bcrypt hash
fn verify_bcrypt(password: &str, info: &HashInfo) -> bool {
  // Reconstruct the full bcrypt hash string
  if let (Some(salt), Some(rounds)) = (&info.salt, info.rounds) {
    // Calculate cost from rounds (rounds = 2^cost)
    let cost = (rounds as f64).log2() as u32;
    let hash_str = format!("$2a${:02}${}{}", cost, salt, info.hash);
    super::bcrypt::bcrypt_verify(password, &hash_str)
  } else {
    false
  }
}

/// Hex encode bytes
fn hex_encode(data: &[u8]) -> String {
  const HEX: &[u8] = b"0123456789abcdef";
  let mut result = String::with_capacity(data.len() * 2);
  for &byte in data {
    result.push(HEX[(byte >> 4) as usize] as char);
    result.push(HEX[(byte & 0xf) as usize] as char);
  }
  result
}

/// Constant-time string comparison
fn constant_time_compare(a: &str, b: &str) -> bool {
  if a.len() != b.len() {
    return false;
  }

  let mut result = 0u8;
  for (x, y) in a.bytes().zip(b.bytes()) {
    result |= x ^ y;
  }
  result == 0
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_detect_md5() {
    assert_eq!(
      detect_format("5d41402abc4b2a76b9719d911017c592"),
      Some(HashFormat::MD5)
    );
  }

  #[test]
  fn test_detect_sha1() {
    assert_eq!(
      detect_format("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
      Some(HashFormat::SHA1)
    );
  }

  #[test]
  fn test_detect_bcrypt() {
    assert_eq!(
      detect_format("$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"),
      Some(HashFormat::BCrypt)
    );
  }

  #[test]
  fn test_verify_md5() {
    let info = HashInfo::new(HashFormat::MD5, "5d41402abc4b2a76b9719d911017c592");
    assert!(verify_hash("hello", &info));
    assert!(!verify_hash("world", &info));
  }

  #[test]
  fn test_ntlm_hash() {
    // Known NTLM hash for "password"
    let hash = ntlm_hash("password");
    assert_eq!(hash, "8846F7EAEE8FB117AD06BDD830B7586C");
  }

  #[test]
  fn test_mysql41() {
    let info = HashInfo::new(
      HashFormat::MySQL41,
      "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
    );
    assert!(verify_hash("password", &info));
  }
}
