//! Shared types and helpers for web commands

use crate::cli::CliContext;
#[cfg(not(target_os = "windows"))]
use crate::protocols::http2::Http2ResponseHandler;
use std::time::{SystemTime, UNIX_EPOCH};

/// HTTP/2 response handler that buffers the body
#[derive(Default)]
pub struct BufferingHttp2Handler {
  pub body: Vec<u8>,
}

#[cfg(not(target_os = "windows"))]
impl Http2ResponseHandler for BufferingHttp2Handler {
  fn on_data(&mut self, chunk: &[u8]) -> Result<(), String> {
    self.body.extend_from_slice(chunk);
    Ok(())
  }
}

/// Escape a string for JSON output
pub fn escape_json(input: &str) -> String {
  let mut escaped = String::with_capacity(input.len());
  for ch in input.chars() {
    match ch {
      '\\' => escaped.push_str("\\\\"),
      '"' => escaped.push_str("\\\""),
      '\n' => escaped.push_str("\\n"),
      '\r' => escaped.push_str("\\r"),
      '\t' => escaped.push_str("\\t"),
      c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
      c => escaped.push(c),
    }
  }
  escaped
}

/// Extract host from URL for database naming
pub fn extract_host(url: &str) -> String {
  if let Some(host_start) = url.find("://") {
    let after_protocol = &url[host_start + 3..];
    if let Some(path_start) = after_protocol.find('/') {
      after_protocol[..path_start].to_string()
    } else {
      after_protocol.to_string()
    }
  } else {
    url.to_string()
  }
}

/// Get current Unix timestamp
pub fn current_timestamp() -> u32 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_else(|_| std::time::Duration::from_secs(0))
    .as_secs() as u32
}

/// Guard against plain HTTP (placeholder - HTTPS is supported)
pub fn guard_plain_http(_url: &str, _command: &str) -> Result<(), String> {
  // HTTPS supported via native TLS 1.2 client
  Ok(())
}

/// Parse HTTPS URL into components (host, port, authority, path)
pub fn parse_https_url(url: &str) -> Result<(String, u16, String, String), String> {
  let lower = url.to_ascii_lowercase();
  if !lower.starts_with("https://") {
    return Err("HTTP/2 client requires an https:// URL".to_string());
  }

  let without_scheme = &url[8..];
  let (authority_raw, path_part) = match without_scheme.find('/') {
    Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
    None => (without_scheme, "/"),
  };

  if authority_raw.is_empty() {
    return Err("Missing host in URL".to_string());
  }

  let (host, port, authority) = if authority_raw.starts_with('[') {
    let end = authority_raw
      .find(']')
      .ok_or_else(|| "Invalid IPv6 host notation".to_string())?;
    let host_part = authority_raw[1..end].to_string();
    let authority = if end + 1 < authority_raw.len() {
      authority_raw.to_string()
    } else {
      format!("[{}]", host_part)
    };

    if end + 1 < authority_raw.len() && authority_raw.as_bytes()[end + 1] == b':' {
      let port_str = &authority_raw[end + 2..];
      let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("Invalid port: {}", port_str))?;
      (host_part, port, authority)
    } else {
      (host_part, 443, authority)
    }
  } else if let Some(idx) = authority_raw.rfind(':') {
    if authority_raw[idx + 1..].contains(':') {
      (authority_raw.to_string(), 443, authority_raw.to_string())
    } else {
      let host_part = authority_raw[..idx].to_string();
      let port_str = &authority_raw[idx + 1..];
      let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("Invalid port: {}", port_str))?;
      (host_part.clone(), port, format!("{}:{}", host_part, port))
    }
  } else {
    (authority_raw.to_string(), 443, authority_raw.to_string())
  };

  Ok((host, port, authority, path_part.to_string()))
}

/// Collect request headers from CLI context
pub fn collect_request_headers(ctx: &CliContext) -> Result<Vec<(String, String)>, String> {
  let mut headers: Vec<(String, String)> = Vec::new();

  if let Some(header_value) = ctx.get_flag("header") {
    if let Some((name, value)) = header_value.split_once(':') {
      headers.push((name.trim().to_lowercase(), value.trim().to_string()));
    } else {
      return Err("Header format must be 'Name: Value'".to_string());
    }
  }

  if let Some(headers_list) = ctx.get_flag("headers") {
    for entry in headers_list
      .split(';')
      .map(str::trim)
      .filter(|s| !s.is_empty())
    {
      if let Some((name, value)) = entry.split_once(':') {
        headers.push((name.trim().to_lowercase(), value.trim().to_string()));
      } else {
        return Err(format!("Invalid header entry: {}", entry));
      }
    }
  }

  Ok(headers)
}
