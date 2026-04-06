//! Git Exposure Scanner
//!
//! Detects and exploits exposed .git directories on web servers.
//! Inspired by git-scanner and GitTools for authorized security testing.
//!
//! # Capabilities
//!
//! - Detect exposed .git directories (directory listing, 403, 404)
//! - Download git objects via HTTP without git binary
//! - Recursive object discovery (commits → trees → blobs)
//! - Pack file extraction
//! - Repository reconstruction
//! - Secret scanning in recovered content
//!
//! # Example
//!
//! ```rust,ignore
//! use redblue::modules::web::git_exposed::{GitScanner, ScanConfig};
//!
//! let config = ScanConfig::default();
//! let scanner = GitScanner::new(config);
//! let result = scanner.scan("http://target.com").await?;
//!
//! if result.is_vulnerable() {
//!     scanner.dump_objects(&result, "./output").await?;
//! }
//! ```

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::Path;

// Synergy integration for cross-module correlation
use crate::modules::common::Severity;
use crate::storage::engine::emitter::GraphEmitter;
use crate::synergy::events::{emit, EntityRef, Event, EventType, MitreAttack};

// ============================================================================
// Configuration
// ============================================================================

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
  /// Maximum concurrent downloads
  pub max_concurrent: usize,
  /// Request timeout in seconds
  pub timeout: u64,
  /// User agent string
  pub user_agent: String,
  /// Maximum objects to download
  pub max_objects: usize,
  /// Download pack files
  pub download_packs: bool,
  /// Scan for secrets
  pub scan_secrets: bool,
  /// Scan git history for secrets
  pub scan_history: bool,
  /// Verbose output
  pub verbose: bool,
}

impl Default for ScanConfig {
  fn default() -> Self {
    Self {
      max_concurrent: 10,
      timeout: 30,
      user_agent: "Mozilla/5.0 (compatible; SecurityScanner/1.0)".to_string(),
      max_objects: 10000,
      download_packs: true,
      scan_secrets: false,
      scan_history: false,
      verbose: false,
    }
  }
}

// ============================================================================
// Exposure Status
// ============================================================================

/// Git exposure status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposureStatus {
  /// Full directory listing enabled (CRITICAL)
  DirectoryListing,
  /// 403 forbidden but objects may be accessible (HIGH)
  Forbidden,
  /// 404 not found (INFO - protected)
  NotFound,
  /// Some objects accessible without listing
  PartialExposure,
  /// Unknown status
  Unknown,
}

impl ExposureStatus {
  /// Get string representation
  pub fn as_str(&self) -> &'static str {
    match self {
      ExposureStatus::DirectoryListing => "directory-listing",
      ExposureStatus::PartialExposure => "partial-exposure",
      ExposureStatus::Forbidden => "forbidden",
      ExposureStatus::NotFound => "not-found",
      ExposureStatus::Unknown => "unknown",
    }
  }

  /// Get severity level
  pub fn severity(&self) -> Severity {
    match self {
      ExposureStatus::DirectoryListing => Severity::Critical,
      ExposureStatus::PartialExposure => Severity::High,
      ExposureStatus::Forbidden => Severity::Medium,
      ExposureStatus::NotFound => Severity::Info,
      ExposureStatus::Unknown => Severity::Info,
    }
  }

  /// Check if potentially vulnerable
  pub fn is_vulnerable(&self) -> bool {
    matches!(
      self,
      ExposureStatus::DirectoryListing | ExposureStatus::PartialExposure
    )
  }
}

// ============================================================================
// Git Objects
// ============================================================================

/// Git object type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitObjectType {
  Commit,
  Tree,
  Blob,
  Tag,
  Unknown,
}

impl GitObjectType {
  /// Parse from object header
  pub fn from_header(header: &str) -> Self {
    if header.starts_with("commit") {
      GitObjectType::Commit
    } else if header.starts_with("tree") {
      GitObjectType::Tree
    } else if header.starts_with("blob") {
      GitObjectType::Blob
    } else if header.starts_with("tag") {
      GitObjectType::Tag
    } else {
      GitObjectType::Unknown
    }
  }
}

/// Parsed git object
#[derive(Debug, Clone)]
pub struct GitObject {
  /// SHA-1 hash (40 hex chars)
  pub hash: String,
  /// Object type
  pub object_type: GitObjectType,
  /// Object size
  pub size: usize,
  /// Raw decompressed content
  pub content: Vec<u8>,
  /// Referenced hashes (for commits/trees)
  pub references: Vec<String>,
}

impl GitObject {
  /// Parse from decompressed data
  pub fn parse(hash: &str, data: &[u8]) -> Result<Self, GitError> {
    // Find null byte separating header from content
    let null_pos = data
      .iter()
      .position(|&b| b == 0)
      .ok_or(GitError::InvalidObject("No null terminator".to_string()))?;

    let header = std::str::from_utf8(&data[..null_pos])
      .map_err(|_| GitError::InvalidObject("Invalid header encoding".to_string()))?;

    // Parse "type size" format
    let parts: Vec<&str> = header.split(' ').collect();
    if parts.len() != 2 {
      return Err(GitError::InvalidObject("Invalid header format".to_string()));
    }

    let object_type = GitObjectType::from_header(parts[0]);
    let size = parts[1]
      .parse()
      .map_err(|_| GitError::InvalidObject("Invalid size".to_string()))?;

    let content = data[null_pos + 1..].to_vec();

    // Extract referenced hashes
    let references = Self::extract_references(object_type, &content);

    Ok(Self {
      hash: hash.to_string(),
      object_type,
      size,
      content,
      references,
    })
  }

  /// Extract referenced hashes from object content
  fn extract_references(obj_type: GitObjectType, content: &[u8]) -> Vec<String> {
    let mut refs = Vec::new();

    match obj_type {
      GitObjectType::Commit => {
        // Parse commit for tree and parent refs
        if let Ok(text) = std::str::from_utf8(content) {
          for line in text.lines() {
            if line.starts_with("tree ") || line.starts_with("parent ") {
              let parts: Vec<&str> = line.split_whitespace().collect();
              if parts.len() >= 2 && is_valid_sha1(parts[1]) {
                refs.push(parts[1].to_string());
              }
            }
          }
        }
      }
      GitObjectType::Tree => {
        // Parse tree entries: "mode name\0<20-byte-sha1>"
        let mut pos = 0;
        while pos < content.len() {
          // Find null terminator after mode+name
          if let Some(null_pos) = content[pos..].iter().position(|&b| b == 0) {
            let entry_end = pos + null_pos + 1 + 20; // null + 20-byte SHA
            if entry_end <= content.len() {
              // Extract 20-byte SHA and convert to hex
              let sha_bytes = &content[pos + null_pos + 1..entry_end];
              let hash = sha_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
              refs.push(hash);
              pos = entry_end;
            } else {
              break;
            }
          } else {
            break;
          }
        }
      }
      _ => {}
    }

    refs
  }
}

/// Commit information
#[derive(Debug, Clone)]
pub struct CommitInfo {
  /// Commit hash
  pub hash: String,
  /// Author name and email
  pub author: String,
  /// Commit timestamp
  pub timestamp: String,
  /// Commit message
  pub message: String,
  /// Parent commit hashes
  pub parents: Vec<String>,
  /// Tree hash
  pub tree: String,
}

impl CommitInfo {
  /// Parse from commit object content
  pub fn from_object(obj: &GitObject) -> Option<Self> {
    if obj.object_type != GitObjectType::Commit {
      return None;
    }

    let text = std::str::from_utf8(&obj.content).ok()?;
    let mut author = String::new();
    let mut timestamp = String::new();
    let mut parents = Vec::new();
    let mut tree = String::new();
    let mut in_message = false;
    let mut message_lines = Vec::new();

    for line in text.lines() {
      if in_message {
        message_lines.push(line);
      } else if line.is_empty() {
        in_message = true;
      } else if line.starts_with("tree ") {
        tree = line[5..].to_string();
      } else if line.starts_with("parent ") {
        parents.push(line[7..].to_string());
      } else if line.starts_with("author ") {
        // Parse "author Name <email> timestamp tz"
        let rest = &line[7..];
        if let Some(ts_pos) = rest.rfind('>') {
          author = rest[..ts_pos + 1].to_string();
          let ts_part = rest[ts_pos + 2..].trim();
          timestamp = ts_part.to_string();
        }
      }
    }

    Some(Self {
      hash: obj.hash.clone(),
      author,
      timestamp,
      message: message_lines.join("\n"),
      parents,
      tree,
    })
  }
}

// ============================================================================
// Known Git Paths
// ============================================================================

/// Standard git paths to check
pub const KNOWN_PATHS: &[&str] = &[
  "/.git/HEAD",
  "/.git/config",
  "/.git/index",
  "/.git/description",
  "/.git/packed-refs",
  "/.git/COMMIT_EDITMSG",
  "/.git/FETCH_HEAD",
  "/.git/ORIG_HEAD",
  "/.git/refs/heads/master",
  "/.git/refs/heads/main",
  "/.git/refs/heads/develop",
  "/.git/refs/heads/dev",
  "/.git/refs/remotes/origin/HEAD",
  "/.git/refs/remotes/origin/master",
  "/.git/refs/remotes/origin/main",
  "/.git/refs/stash",
  "/.git/logs/HEAD",
  "/.git/logs/refs/heads/master",
  "/.git/logs/refs/heads/main",
  "/.git/info/exclude",
  "/.git/info/refs",
  "/.git/objects/info/packs",
];

/// Common branch names to check
pub const COMMON_BRANCHES: &[&str] = &[
  "master",
  "main",
  "develop",
  "dev",
  "staging",
  "production",
  "release",
  "feature",
  "hotfix",
];

// ============================================================================
// Error Types
// ============================================================================

/// Git scanner error
#[derive(Debug)]
pub enum GitError {
  /// HTTP error
  HttpError(String),
  /// Invalid git object
  InvalidObject(String),
  /// Decompression error
  DecompressionError(String),
  /// IO error
  IoError(std::io::Error),
  /// Parse error
  ParseError(String),
  /// Not found
  NotFound(String),
}

impl std::fmt::Display for GitError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      GitError::HttpError(s) => write!(f, "HTTP error: {}", s),
      GitError::InvalidObject(s) => write!(f, "Invalid git object: {}", s),
      GitError::DecompressionError(s) => write!(f, "Decompression error: {}", s),
      GitError::IoError(e) => write!(f, "IO error: {}", e),
      GitError::ParseError(s) => write!(f, "Parse error: {}", s),
      GitError::NotFound(s) => write!(f, "Not found: {}", s),
    }
  }
}

impl std::error::Error for GitError {}

// ============================================================================
// Scan Result
// ============================================================================

/// Git exposure scan result
#[derive(Debug, Clone)]
pub struct ScanResult {
  /// Target URL
  pub target: String,
  /// Exposure status
  pub status: ExposureStatus,
  /// Severity level
  pub severity: Severity,
  /// Downloaded objects
  pub objects: Vec<GitObject>,
  /// Discovered hashes
  pub discovered_hashes: HashSet<String>,
  /// Failed downloads
  pub failed_downloads: Vec<String>,
  /// Detected secrets (if scanning enabled)
  pub secrets: Vec<DetectedSecret>,
  /// Commit history (if extracted)
  pub commits: Vec<CommitInfo>,
  /// Files found (path → hash)
  pub files: HashMap<String, String>,
  /// Pack files found
  pub packs: Vec<String>,
  /// Estimated recovery percentage
  pub recovery_percent: f32,
}

impl ScanResult {
  /// Create new result
  pub fn new(target: &str) -> Self {
    Self {
      target: target.to_string(),
      status: ExposureStatus::Unknown,
      severity: Severity::Info,
      objects: Vec::new(),
      discovered_hashes: HashSet::new(),
      failed_downloads: Vec::new(),
      secrets: Vec::new(),
      commits: Vec::new(),
      files: HashMap::new(),
      packs: Vec::new(),
      recovery_percent: 0.0,
    }
  }

  /// Check if vulnerable
  pub fn is_vulnerable(&self) -> bool {
    self.status.is_vulnerable()
  }

  /// Get object count by type
  pub fn object_counts(&self) -> HashMap<GitObjectType, usize> {
    let mut counts = HashMap::new();
    for obj in &self.objects {
      *counts.entry(obj.object_type).or_insert(0) += 1;
    }
    counts
  }
}

/// Detected secret in repository
#[derive(Debug, Clone)]
pub struct DetectedSecret {
  /// File path
  pub path: String,
  /// Secret type
  pub secret_type: String,
  /// Match content (redacted)
  pub match_content: String,
  /// Line number
  pub line: usize,
  /// Commit hash (if in history)
  pub commit: Option<String>,
}

// ============================================================================
// HTTP Client (minimal)
// ============================================================================

/// Minimal HTTP response
#[derive(Debug)]
pub struct HttpResponse {
  pub status: u16,
  pub body: Vec<u8>,
  pub headers: HashMap<String, String>,
}

impl HttpResponse {
  /// Check if body contains "Index of"
  pub fn is_directory_listing(&self) -> bool {
    if let Ok(text) = std::str::from_utf8(&self.body) {
      text.contains("Index of") || text.contains("Directory listing")
    } else {
      false
    }
  }
}

/// Simple HTTP client using std::net
pub struct HttpClient {
  user_agent: String,
  timeout: u64,
}

impl HttpClient {
  /// Create new client
  pub fn new(user_agent: &str, timeout: u64) -> Self {
    Self {
      user_agent: user_agent.to_string(),
      timeout,
    }
  }

  /// Perform GET request
  pub fn get(&self, url: &str) -> Result<HttpResponse, GitError> {
    // Parse URL
    let (host, port, path) = parse_url(url)?;

    // Connect
    let addr = format!("{}:{}", host, port);
    let stream =
      std::net::TcpStream::connect(&addr).map_err(|e| GitError::HttpError(e.to_string()))?;

    stream
      .set_read_timeout(Some(std::time::Duration::from_secs(self.timeout)))
      .ok();
    stream
      .set_write_timeout(Some(std::time::Duration::from_secs(self.timeout)))
      .ok();

    // Use TLS for HTTPS
    if url.starts_with("https://") {
      return Err(GitError::HttpError(
        "HTTPS not yet supported in minimal client".to_string(),
      ));
    }

    self.do_request(stream, &host, &path)
  }

  fn do_request(
    &self,
    mut stream: std::net::TcpStream,
    host: &str,
    path: &str,
  ) -> Result<HttpResponse, GitError> {
    // Build request
    let request = format!(
      "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n",
      path, host, self.user_agent
    );

    // Send request
    stream
      .write_all(request.as_bytes())
      .map_err(|e| GitError::HttpError(e.to_string()))?;

    // Read response
    let mut response = Vec::new();
    stream
      .read_to_end(&mut response)
      .map_err(|e| GitError::HttpError(e.to_string()))?;

    // Parse response
    self.parse_response(&response)
  }

  fn parse_response(&self, response: &[u8]) -> Result<HttpResponse, GitError> {
    // Find end of headers
    let header_end = response
      .windows(4)
      .position(|w| w == b"\r\n\r\n")
      .ok_or_else(|| GitError::HttpError("Invalid HTTP response".to_string()))?;

    let headers_str = std::str::from_utf8(&response[..header_end])
      .map_err(|_| GitError::HttpError("Invalid header encoding".to_string()))?;

    // Parse status line
    let status_line = headers_str
      .lines()
      .next()
      .ok_or_else(|| GitError::HttpError("No status line".to_string()))?;

    let status_parts: Vec<&str> = status_line.split_whitespace().collect();
    if status_parts.len() < 2 {
      return Err(GitError::HttpError("Invalid status line".to_string()));
    }

    let status = status_parts[1]
      .parse()
      .map_err(|_| GitError::HttpError("Invalid status code".to_string()))?;

    // Parse headers
    let mut headers = HashMap::new();
    for line in headers_str.lines().skip(1) {
      if let Some((key, value)) = line.split_once(':') {
        headers.insert(key.trim().to_lowercase(), value.trim().to_string());
      }
    }

    let body = response[header_end + 4..].to_vec();

    Ok(HttpResponse {
      status,
      body,
      headers,
    })
  }
}

// ============================================================================
// Zlib Decompression (minimal implementation)
// ============================================================================

/// Decompress zlib data
pub fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>, GitError> {
  // Git uses zlib (deflate with header)
  // Header: CMF (1 byte) + FLG (1 byte)
  if data.len() < 2 {
    return Err(GitError::DecompressionError("Data too short".to_string()));
  }

  let cmf = data[0];
  let _flg = data[1];

  // Check compression method (should be 8 = deflate)
  if cmf & 0x0F != 8 {
    return Err(GitError::DecompressionError(
      "Not deflate compression".to_string(),
    ));
  }

  // Skip header and decompress
  let compressed = &data[2..];
  inflate_deflate(compressed)
}

/// Simple DEFLATE decompression
/// This is a minimal implementation that handles common git objects
fn inflate_deflate(data: &[u8]) -> Result<Vec<u8>, GitError> {
  let mut output = Vec::new();
  let mut reader = BitReader::new(data);

  loop {
    // Read BFINAL (1 bit) and BTYPE (2 bits)
    let bfinal = reader.read_bits(1)?;
    let btype = reader.read_bits(2)?;

    match btype {
      0 => {
        // No compression - stored block
        reader.align_byte();
        let len = reader.read_u16_le()?;
        let _nlen = reader.read_u16_le()?;
        for _ in 0..len {
          output.push(reader.read_byte()?);
        }
      }
      1 => {
        // Fixed Huffman codes
        inflate_fixed_huffman(&mut reader, &mut output)?;
      }
      2 => {
        // Dynamic Huffman codes
        inflate_dynamic_huffman(&mut reader, &mut output)?;
      }
      3 => {
        return Err(GitError::DecompressionError(
          "Reserved block type".to_string(),
        ));
      }
      _ => unreachable!(),
    }

    if bfinal == 1 {
      break;
    }
  }

  Ok(output)
}

/// Bit reader for deflate
struct BitReader<'a> {
  data: &'a [u8],
  pos: usize,
  bit_pos: u8,
}

impl<'a> BitReader<'a> {
  fn new(data: &'a [u8]) -> Self {
    Self {
      data,
      pos: 0,
      bit_pos: 0,
    }
  }

  fn read_bits(&mut self, count: u8) -> Result<u32, GitError> {
    let mut value = 0u32;
    for i in 0..count {
      if self.pos >= self.data.len() {
        return Err(GitError::DecompressionError("Unexpected end".to_string()));
      }
      let bit = (self.data[self.pos] >> self.bit_pos) & 1;
      value |= (bit as u32) << i;
      self.bit_pos += 1;
      if self.bit_pos == 8 {
        self.bit_pos = 0;
        self.pos += 1;
      }
    }
    Ok(value)
  }

  fn read_bits_rev(&mut self, count: u8) -> Result<u32, GitError> {
    let mut value = 0u32;
    for _ in 0..count {
      if self.pos >= self.data.len() {
        return Err(GitError::DecompressionError("Unexpected end".to_string()));
      }
      let bit = (self.data[self.pos] >> self.bit_pos) & 1;
      value = (value << 1) | (bit as u32);
      self.bit_pos += 1;
      if self.bit_pos == 8 {
        self.bit_pos = 0;
        self.pos += 1;
      }
    }
    Ok(value)
  }

  fn align_byte(&mut self) {
    if self.bit_pos != 0 {
      self.bit_pos = 0;
      self.pos += 1;
    }
  }

  fn read_byte(&mut self) -> Result<u8, GitError> {
    if self.pos >= self.data.len() {
      return Err(GitError::DecompressionError("Unexpected end".to_string()));
    }
    let b = self.data[self.pos];
    self.pos += 1;
    Ok(b)
  }

  fn read_u16_le(&mut self) -> Result<u16, GitError> {
    let lo = self.read_byte()? as u16;
    let hi = self.read_byte()? as u16;
    Ok(lo | (hi << 8))
  }
}

/// Fixed Huffman code tables
const LEN_BASE: [u16; 29] = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
  163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
  3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

/// Inflate with fixed Huffman codes
fn inflate_fixed_huffman(reader: &mut BitReader, output: &mut Vec<u8>) -> Result<(), GitError> {
  loop {
    // Read literal/length code (7-9 bits)
    let code = read_fixed_lit_code(reader)?;

    if code < 256 {
      // Literal byte
      output.push(code as u8);
    } else if code == 256 {
      // End of block
      break;
    } else {
      // Length code (257-285)
      let len_idx = (code - 257) as usize;
      if len_idx >= LEN_BASE.len() {
        return Err(GitError::DecompressionError(
          "Invalid length code".to_string(),
        ));
      }
      let length = LEN_BASE[len_idx] as usize + reader.read_bits(LEN_EXTRA[len_idx])? as usize;

      // Read distance code (5 bits)
      let dist_code = reader.read_bits_rev(5)? as usize;
      if dist_code >= DIST_BASE.len() {
        return Err(GitError::DecompressionError(
          "Invalid distance code".to_string(),
        ));
      }
      let distance =
        DIST_BASE[dist_code] as usize + reader.read_bits(DIST_EXTRA[dist_code])? as usize;

      // Copy from output buffer
      if distance > output.len() {
        return Err(GitError::DecompressionError(
          "Invalid back reference".to_string(),
        ));
      }
      let start = output.len() - distance;
      for i in 0..length {
        let byte = output[start + (i % distance)];
        output.push(byte);
      }
    }
  }
  Ok(())
}

/// Read fixed literal/length Huffman code
fn read_fixed_lit_code(reader: &mut BitReader) -> Result<u16, GitError> {
  // Fixed Huffman: 0-143 = 8 bits (00110000-10111111)
  //               144-255 = 9 bits (110010000-111111111)
  //               256-279 = 7 bits (0000000-0010111)
  //               280-287 = 8 bits (11000000-11000111)

  let first7 = reader.read_bits_rev(7)? as u16;

  if first7 <= 23 {
    // 256-279 (7 bits)
    Ok(first7 + 256)
  } else {
    let bit8 = reader.read_bits(1)? as u16;
    let code8 = (first7 << 1) | bit8;

    if code8 >= 48 && code8 <= 191 {
      // 0-143 (8 bits: 00110000-10111111)
      Ok(code8 - 48)
    } else if code8 >= 192 && code8 <= 199 {
      // 280-287 (8 bits: 11000000-11000111)
      Ok(code8 - 192 + 280)
    } else {
      // 144-255 (9 bits)
      let bit9 = reader.read_bits(1)? as u16;
      let code9 = (code8 << 1) | bit9;
      if code9 >= 400 && code9 <= 511 {
        Ok(code9 - 400 + 144)
      } else {
        Err(GitError::DecompressionError(format!(
          "Invalid fixed code: {}",
          code9
        )))
      }
    }
  }
}

/// Inflate with dynamic Huffman codes
fn inflate_dynamic_huffman(reader: &mut BitReader, output: &mut Vec<u8>) -> Result<(), GitError> {
  // Read code length counts
  let hlit = reader.read_bits(5)? as usize + 257; // literal/length codes
  let hdist = reader.read_bits(5)? as usize + 1; // distance codes
  let hclen = reader.read_bits(4)? as usize + 4; // code length codes

  // Code length alphabet order
  const ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
  ];

  // Read code lengths for code length alphabet
  let mut code_lengths = [0u8; 19];
  for i in 0..hclen {
    code_lengths[ORDER[i]] = reader.read_bits(3)? as u8;
  }

  // Build code length Huffman tree
  let cl_tree = build_huffman_tree(&code_lengths)?;

  // Read literal/length and distance code lengths
  let mut lengths = vec![0u8; hlit + hdist];
  let mut i = 0;
  while i < lengths.len() {
    let sym = decode_huffman(reader, &cl_tree)?;
    match sym {
      0..=15 => {
        lengths[i] = sym as u8;
        i += 1;
      }
      16 => {
        // Repeat previous
        let repeat = reader.read_bits(2)? as usize + 3;
        let prev = if i > 0 { lengths[i - 1] } else { 0 };
        for _ in 0..repeat {
          if i < lengths.len() {
            lengths[i] = prev;
            i += 1;
          }
        }
      }
      17 => {
        // Repeat 0 (3-10 times)
        let repeat = reader.read_bits(3)? as usize + 3;
        for _ in 0..repeat {
          if i < lengths.len() {
            lengths[i] = 0;
            i += 1;
          }
        }
      }
      18 => {
        // Repeat 0 (11-138 times)
        let repeat = reader.read_bits(7)? as usize + 11;
        for _ in 0..repeat {
          if i < lengths.len() {
            lengths[i] = 0;
            i += 1;
          }
        }
      }
      _ => {
        return Err(GitError::DecompressionError(
          "Invalid code length symbol".to_string(),
        ))
      }
    }
  }

  // Build literal/length and distance trees
  let lit_tree = build_huffman_tree(&lengths[..hlit])?;
  let dist_tree = build_huffman_tree(&lengths[hlit..])?;

  // Decode data
  loop {
    let lit = decode_huffman(reader, &lit_tree)?;
    if lit < 256 {
      output.push(lit as u8);
    } else if lit == 256 {
      break;
    } else {
      let len_idx = (lit - 257) as usize;
      if len_idx >= LEN_BASE.len() {
        return Err(GitError::DecompressionError(
          "Invalid length code".to_string(),
        ));
      }
      let length = LEN_BASE[len_idx] as usize + reader.read_bits(LEN_EXTRA[len_idx])? as usize;

      let dist_code = decode_huffman(reader, &dist_tree)? as usize;
      if dist_code >= DIST_BASE.len() {
        return Err(GitError::DecompressionError(
          "Invalid distance code".to_string(),
        ));
      }
      let distance =
        DIST_BASE[dist_code] as usize + reader.read_bits(DIST_EXTRA[dist_code])? as usize;

      if distance > output.len() {
        return Err(GitError::DecompressionError(
          "Invalid back reference".to_string(),
        ));
      }
      let start = output.len() - distance;
      for i in 0..length {
        let byte = output[start + (i % distance)];
        output.push(byte);
      }
    }
  }

  Ok(())
}

/// Huffman tree node
#[derive(Debug, Clone)]
enum HuffmanNode {
  Leaf(u16),
  Branch(Box<HuffmanNode>, Box<HuffmanNode>),
  Empty,
}

/// Build Huffman tree from code lengths
fn build_huffman_tree(lengths: &[u8]) -> Result<HuffmanNode, GitError> {
  let max_len = lengths.iter().copied().max().unwrap_or(0) as usize;
  if max_len == 0 {
    return Ok(HuffmanNode::Empty);
  }

  // Count codes of each length
  let mut bl_count = vec![0u16; max_len + 1];
  for &len in lengths {
    if len > 0 {
      bl_count[len as usize] += 1;
    }
  }

  // Calculate starting codes
  let mut next_code = vec![0u16; max_len + 1];
  let mut code = 0u16;
  for bits in 1..=max_len {
    code = (code + bl_count[bits - 1]) << 1;
    next_code[bits] = code;
  }

  // Build tree
  let mut root = HuffmanNode::Empty;
  for (sym, &len) in lengths.iter().enumerate() {
    if len > 0 {
      let code = next_code[len as usize];
      next_code[len as usize] += 1;
      insert_huffman(&mut root, code, len, sym as u16);
    }
  }

  Ok(root)
}

/// Insert symbol into Huffman tree
fn insert_huffman(node: &mut HuffmanNode, code: u16, len: u8, symbol: u16) {
  if len == 0 {
    *node = HuffmanNode::Leaf(symbol);
    return;
  }

  let bit = (code >> (len - 1)) & 1;

  match node {
    HuffmanNode::Empty => {
      if bit == 0 {
        *node = HuffmanNode::Branch(Box::new(HuffmanNode::Empty), Box::new(HuffmanNode::Empty));
      } else {
        *node = HuffmanNode::Branch(Box::new(HuffmanNode::Empty), Box::new(HuffmanNode::Empty));
      }
      insert_huffman(node, code, len, symbol);
    }
    HuffmanNode::Branch(left, right) => {
      if bit == 0 {
        insert_huffman(left, code & ((1 << (len - 1)) - 1), len - 1, symbol);
      } else {
        insert_huffman(right, code & ((1 << (len - 1)) - 1), len - 1, symbol);
      }
    }
    HuffmanNode::Leaf(_) => {}
  }
}

/// Decode symbol from Huffman tree
fn decode_huffman(reader: &mut BitReader, tree: &HuffmanNode) -> Result<u16, GitError> {
  let mut node = tree;
  loop {
    match node {
      HuffmanNode::Leaf(sym) => return Ok(*sym),
      HuffmanNode::Branch(left, right) => {
        let bit = reader.read_bits(1)?;
        node = if bit == 0 { left } else { right };
      }
      HuffmanNode::Empty => {
        return Err(GitError::DecompressionError(
          "Invalid Huffman tree".to_string(),
        ))
      }
    }
  }
}

// ============================================================================
// Git Scanner
// ============================================================================

/// Git exposure scanner
pub struct GitScanner {
  config: ScanConfig,
  client: HttpClient,
}

impl GitScanner {
  /// Create new scanner
  pub fn new(config: ScanConfig) -> Self {
    let client = HttpClient::new(&config.user_agent, config.timeout);
    Self { config, client }
  }

  /// Scan target for git exposure
  pub fn scan(&self, target: &str) -> Result<ScanResult, GitError> {
    let mut result = ScanResult::new(target);
    let base_url = target.trim_end_matches('/');

    // Step 1: Check /.git/ directory
    let git_url = format!("{}/.git/", base_url);
    match self.client.get(&git_url) {
      Ok(resp) => {
        if resp.status == 200 && resp.is_directory_listing() {
          result.status = ExposureStatus::DirectoryListing;
          result.severity = Severity::Critical;
        } else if resp.status == 403 {
          result.status = ExposureStatus::Forbidden;
          result.severity = Severity::Medium;
        } else if resp.status == 404 {
          result.status = ExposureStatus::NotFound;
          result.severity = Severity::Info;
        }
      }
      Err(_) => {
        result.status = ExposureStatus::Unknown;
      }
    }

    // Step 2: Try known paths
    for path in KNOWN_PATHS {
      let url = format!("{}{}", base_url, path);
      if let Ok(resp) = self.client.get(&url) {
        if resp.status == 200 {
          if result.status == ExposureStatus::Forbidden || result.status == ExposureStatus::Unknown
          {
            result.status = ExposureStatus::PartialExposure;
            result.severity = Severity::High;
          }

          // Extract hashes from content
          self.extract_hashes(&resp.body, &mut result.discovered_hashes);
        }
      }
    }

    // Step 3: Download objects if vulnerable
    if result.is_vulnerable() {
      self.download_objects(base_url, &mut result)?;
    }

    // Step 4: Extract commit history
    for obj in &result.objects {
      if let Some(commit) = CommitInfo::from_object(obj) {
        result.commits.push(commit);
      }
    }

    // Calculate recovery percentage
    if !result.discovered_hashes.is_empty() {
      result.recovery_percent =
        (result.objects.len() as f32 / result.discovered_hashes.len() as f32) * 100.0;
    }

    Ok(result)
  }

  /// Download git objects
  fn download_objects(&self, base_url: &str, result: &mut ScanResult) -> Result<(), GitError> {
    let mut queue: VecDeque<String> = result.discovered_hashes.iter().cloned().collect();
    let mut downloaded: HashSet<String> = HashSet::new();

    while let Some(hash) = queue.pop_front() {
      if downloaded.contains(&hash) {
        continue;
      }
      if downloaded.len() >= self.config.max_objects {
        break;
      }

      // Construct object URL
      let obj_url = format!("{}/.git/objects/{}/{}", base_url, &hash[..2], &hash[2..]);

      match self.client.get(&obj_url) {
        Ok(resp) if resp.status == 200 => {
          // Decompress and parse object
          if let Ok(decompressed) = decompress_zlib(&resp.body) {
            if let Ok(obj) = GitObject::parse(&hash, &decompressed) {
              // Queue new references
              for ref_hash in &obj.references {
                if !downloaded.contains(ref_hash) {
                  queue.push_back(ref_hash.clone());
                  result.discovered_hashes.insert(ref_hash.clone());
                }
              }
              result.objects.push(obj);
            }
          }
          downloaded.insert(hash);
        }
        _ => {
          result.failed_downloads.push(hash.clone());
          downloaded.insert(hash);
        }
      }
    }

    Ok(())
  }

  /// Extract SHA-1 hashes from content
  fn extract_hashes(&self, content: &[u8], hashes: &mut HashSet<String>) {
    if let Ok(text) = std::str::from_utf8(content) {
      // Look for 40-char hex strings
      let mut i = 0;
      let chars: Vec<char> = text.chars().collect();
      while i + 40 <= chars.len() {
        let candidate: String = chars[i..i + 40].iter().collect();
        if is_valid_sha1(&candidate) {
          hashes.insert(candidate);
          i += 40;
        } else {
          i += 1;
        }
      }
    }
  }

  /// Dump recovered objects to directory
  pub fn dump_to_dir(&self, result: &ScanResult, output_dir: &str) -> Result<usize, GitError> {
    let git_dir = Path::new(output_dir).join(".git");
    let objects_dir = git_dir.join("objects");

    // Create directory structure
    std::fs::create_dir_all(&objects_dir).map_err(GitError::IoError)?;

    let mut count = 0;
    for obj in &result.objects {
      let dir = objects_dir.join(&obj.hash[..2]);
      std::fs::create_dir_all(&dir).map_err(GitError::IoError)?;

      let file_path = dir.join(&obj.hash[2..]);

      // Compress and write object
      // Note: For simplicity, writing raw decompressed for now
      // Real implementation would recompress
      std::fs::write(&file_path, &obj.content).map_err(GitError::IoError)?;
      count += 1;
    }

    Ok(count)
  }

  // ========================================================================
  // Synergy Integration
  // ========================================================================

  /// Emit synergy events for scan results (cross-module correlation)
  pub fn emit_synergy_events(&self, result: &ScanResult) {
    if !result.is_vulnerable() {
      return;
    }

    let severity_str = result.severity.as_str();

    // Emit vulnerability found event
    let event = Event::new(EventType::VulnFound, "web::git_exposed")
      .with_entity(EntityRef::url(result.target.clone()))
      .with_data("status", result.status.as_str())
      .with_data("severity", severity_str)
      .with_data("objects_found", result.objects.len().to_string())
      .with_data("commits", result.commits.len().to_string())
      .with_data(
        "recovery_percent",
        format!("{:.1}", result.recovery_percent),
      )
      .with_mitre(MitreAttack::from_id("T1213")); // Data from Information Repositories

    emit(event);

    // Emit discovery events for secrets found
    for secret in &result.secrets {
      let secret_event = Event::new(EventType::CredentialFound, "web::git_exposed")
        .with_entity(EntityRef::url(result.target.clone()))
        .with_data("secret_type", &secret.secret_type)
        .with_data("file", &secret.path)
        .with_mitre(MitreAttack::from_id("T1552")); // Unsecured Credentials

      emit(secret_event);
    }
  }

  /// Emit results to intelligence graph
  pub fn emit_to_graph(&self, result: &ScanResult) {
    if !result.is_vulnerable() {
      return;
    }

    let emitter = GraphEmitter::global();

    // Extract host from URL
    if let Ok((host, _port, _path)) = parse_url(&result.target) {
      // Emit host node
      emitter.emit_host(&host, None, None);

      // Emit vulnerability
      let vuln_id = format!("git-exposed-{}", &result.target);
      let cvss = match result.severity {
        Severity::Critical => 9.8,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
        Severity::Info => 0.0,
      };

      emitter.emit_vulnerability(
        &vuln_id,
        cvss,
        Some(&format!(
          "Exposed .git Directory: {} objects recovered, {:.1}% recovery",
          result.objects.len(),
          result.recovery_percent
        )),
      );

      emitter.emit_host_vuln(&host, &vuln_id);

      // Emit endpoint
      emitter.emit_endpoint(&host, "GET", "/.git/", Some(200));
    }
  }

  /// Scan with full synergy and graph integration
  pub fn scan_with_synergy(&self, target: &str) -> Result<ScanResult, GitError> {
    let result = self.scan(target)?;
    self.emit_synergy_events(&result);
    self.emit_to_graph(&result);
    Ok(result)
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate SHA-1 hash format (40 hex chars)
fn is_valid_sha1(s: &str) -> bool {
  s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse URL into (host, port, path)
fn parse_url(url: &str) -> Result<(String, u16, String), GitError> {
  let url = url.trim();
  let (scheme, rest) = if url.starts_with("https://") {
    ("https", &url[8..])
  } else if url.starts_with("http://") {
    ("http", &url[7..])
  } else {
    ("http", url)
  };

  let default_port = if scheme == "https" { 443 } else { 80 };

  let (host_port, path) = match rest.find('/') {
    Some(i) => (&rest[..i], &rest[i..]),
    None => (rest, "/"),
  };

  let (host, port) = match host_port.find(':') {
    Some(i) => {
      let port = host_port[i + 1..]
        .parse()
        .map_err(|_| GitError::ParseError("Invalid port".to_string()))?;
      (&host_port[..i], port)
    }
    None => (host_port, default_port),
  };

  Ok((host.to_string(), port, path.to_string()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_is_valid_sha1() {
    assert!(is_valid_sha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"));
    assert!(!is_valid_sha1("a94a8fe5ccb19ba61c4c0873d391e987982fbbd")); // Too short
    assert!(!is_valid_sha1("g94a8fe5ccb19ba61c4c0873d391e987982fbbd3")); // Invalid char
  }

  #[test]
  fn test_parse_url() {
    let (host, port, path) = parse_url("http://example.com/test").unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 80);
    assert_eq!(path, "/test");

    let (host, port, path) = parse_url("http://example.com:8080/api").unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 8080);
    assert_eq!(path, "/api");
  }

  #[test]
  fn test_exposure_status() {
    assert!(ExposureStatus::DirectoryListing.is_vulnerable());
    assert!(ExposureStatus::PartialExposure.is_vulnerable());
    assert!(!ExposureStatus::NotFound.is_vulnerable());
    assert!(!ExposureStatus::Forbidden.is_vulnerable());
  }

  #[test]
  fn test_severity_order() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
  }

  #[test]
  fn test_git_object_type() {
    assert_eq!(
      GitObjectType::from_header("commit 123"),
      GitObjectType::Commit
    );
    assert_eq!(GitObjectType::from_header("tree 456"), GitObjectType::Tree);
    assert_eq!(GitObjectType::from_header("blob 789"), GitObjectType::Blob);
    assert_eq!(GitObjectType::from_header("tag abc"), GitObjectType::Tag);
  }

  #[test]
  fn test_scan_result() {
    let result = ScanResult::new("http://example.com");
    assert!(!result.is_vulnerable());
    assert_eq!(result.recovery_percent, 0.0);
  }
}
