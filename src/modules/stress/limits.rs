//! Memory availability parsing and safety caps.

use std::fs;

#[derive(Debug, Clone, Copy, Default)]
pub struct MemInfo {
  pub total_kb: u64,
  pub available_kb: u64,
}

impl MemInfo {
  pub fn total_bytes(&self) -> u64 {
    self.total_kb.saturating_mul(1024)
  }
  pub fn available_bytes(&self) -> u64 {
    self.available_kb.saturating_mul(1024)
  }
}

pub fn read_meminfo() -> MemInfo {
  let Ok(raw) = fs::read_to_string("/proc/meminfo") else {
    return MemInfo::default();
  };
  let mut out = MemInfo::default();
  for line in raw.lines() {
    let (key, rest) = match line.split_once(':') {
      Some(v) => v,
      None => continue,
    };
    let value = rest
      .trim()
      .split_ascii_whitespace()
      .next()
      .and_then(|v| v.parse::<u64>().ok())
      .unwrap_or(0);
    match key {
      "MemTotal" => out.total_kb = value,
      "MemAvailable" => out.available_kb = value,
      _ => {}
    }
  }
  out
}

/// Resolve a requested stress allocation size against memory safety caps.
///
/// Returns the clamped byte budget (<= max_pct of MemAvailable).
pub fn resolve_mem_budget(
  requested_bytes: Option<u64>,
  pct: Option<u8>,
  max_pct: u8,
) -> Result<u64, String> {
  let info = read_meminfo();
  let available = info.available_bytes();
  if available == 0 {
    return Err("cannot read /proc/meminfo — memory cap unavailable".into());
  }
  let max_allowed = (available as u128 * max_pct.min(100) as u128 / 100) as u64;

  let requested = match (requested_bytes, pct) {
    (Some(b), _) => b,
    (None, Some(p)) => (available as u128 * p.min(100) as u128 / 100) as u64,
    (None, None) => (available as u128 * 25u128 / 100) as u64,
  };

  if requested == 0 {
    return Err("resolved memory budget is zero".into());
  }
  Ok(requested.min(max_allowed))
}

/// Parse human size strings: "3G", "512M", "100K", "1024".
/// Supports B/K/M/G/T (case-insensitive) and `KB/MB/GB` suffixes.
pub fn parse_bytes(s: &str) -> Result<u64, String> {
  let s = s.trim();
  if s.is_empty() {
    return Err("empty size".into());
  }
  let (num_part, mult) = split_unit(s);
  let value: f64 = num_part
    .parse()
    .map_err(|_| format!("invalid size: {}", s))?;
  if value < 0.0 {
    return Err("size must be non-negative".into());
  }
  Ok((value * mult as f64) as u64)
}

fn split_unit(s: &str) -> (&str, u64) {
  let lower = s.trim_end_matches(|c: char| c == 'b' || c == 'B');
  let (num, unit_char) = match lower.chars().last() {
    Some(c) if c.is_ascii_alphabetic() => (&lower[..lower.len() - 1], c),
    _ => (lower, '\0'),
  };
  let mult: u64 = match unit_char.to_ascii_lowercase() {
    'k' => 1024,
    'm' => 1024 * 1024,
    'g' => 1024 * 1024 * 1024,
    't' => 1024u64 * 1024 * 1024 * 1024,
    _ => 1,
  };
  (num, mult)
}

/// Parse duration strings: "30s", "5m", "1h", "500ms", or bare seconds "30".
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
  let s = s.trim();
  if s.is_empty() {
    return Err("empty duration".into());
  }
  if let Some(rest) = s.strip_suffix("ms") {
    let v: u64 = rest
      .parse()
      .map_err(|_| format!("invalid duration: {}", s))?;
    return Ok(((v + 999) / 1000).max(1));
  }
  let (num, mult) = match s.chars().last() {
    Some('s') | Some('S') => (&s[..s.len() - 1], 1u64),
    Some('m') | Some('M') => (&s[..s.len() - 1], 60),
    Some('h') | Some('H') => (&s[..s.len() - 1], 3600),
    Some(c) if c.is_ascii_digit() => (s, 1),
    _ => return Err(format!("invalid duration: {}", s)),
  };
  let value: u64 = num
    .parse()
    .map_err(|_| format!("invalid duration: {}", s))?;
  Ok(value.saturating_mul(mult))
}

pub fn format_bytes(bytes: u64) -> String {
  const KB: u64 = 1024;
  const MB: u64 = KB * 1024;
  const GB: u64 = MB * 1024;
  const TB: u64 = GB * 1024;
  if bytes >= TB {
    format!("{:.2} TB", bytes as f64 / TB as f64)
  } else if bytes >= GB {
    format!("{:.2} GB", bytes as f64 / GB as f64)
  } else if bytes >= MB {
    format!("{:.2} MB", bytes as f64 / MB as f64)
  } else if bytes >= KB {
    format!("{:.2} KB", bytes as f64 / KB as f64)
  } else {
    format!("{} B", bytes)
  }
}

pub fn format_ops(ops: u64) -> String {
  if ops >= 1_000_000_000 {
    format!("{:.2}G", ops as f64 / 1_000_000_000.0)
  } else if ops >= 1_000_000 {
    format!("{:.2}M", ops as f64 / 1_000_000.0)
  } else if ops >= 1_000 {
    format!("{:.2}K", ops as f64 / 1_000.0)
  } else {
    ops.to_string()
  }
}
