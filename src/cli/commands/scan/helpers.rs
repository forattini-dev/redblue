//! Shared payload builders, parsers, and helpers for scan commands.

/// Network/ports command - Port scanning and network discovery
use crate::cli::commands::{build_partition_attributes, print_help, Command, Flag, Route};
use crate::cli::{
  format::OutputFormat,
  output::{Output, ProgressBar},
  render,
  validator::Validator,
  CliContext,
};
use crate::config;
use crate::intelligence::{
  banner_analysis, os_probes, os_signatures, service_detection, timing_analysis,
};
use crate::json;
use crate::modules::network::highspeed::{
  DeduplicationCache, RandomScanIterator, ScanRange, SynCookie, TokenBucket,
};
use crate::modules::network::scanner::{
  AdvancedScanner, PortScanResult, PortScanner, ScanType, TimingTemplate,
};
use crate::serde_json::Value;
use crate::storage::service::StorageService;
use std::collections::HashMap;
use std::sync::Arc;

pub(super) fn port_result_to_json(
  result: &crate::modules::network::scanner::PortScanResult,
) -> crate::serde_json::Value {
  json!({
      "port": result.port,
      "service": result.service.clone().unwrap_or_else(|| "unknown".to_string()),
      "banner": result.banner.clone()
  })
}

pub(super) fn range_result_to_json(
  result: &crate::modules::network::scanner::PortScanResult,
) -> crate::serde_json::Value {
  json!({
      "port": result.port,
      "state": "open",
      "service": result.service.clone().unwrap_or_else(|| "unknown".to_string()),
      "banner": result.banner.clone().unwrap_or_default().replace('\n', " ")
  })
}

pub(super) fn advanced_result_to_json(
  result: &crate::modules::network::scanner::AdvancedScanResult,
) -> crate::serde_json::Value {
  json!({
      "port": result.port,
      "state": format!("{}", result.state),
      "service": result.service.clone().unwrap_or_default(),
      "rtt_ms": result.rtt_ms,
      "ttl": result.ttl
  })
}

pub(super) fn scan_ports_payload(
  target: std::net::IpAddr,
  preset: &str,
  open_ports: &[&crate::modules::network::scanner::PortScanResult],
) -> Value {
  let ports_json: Vec<Value> = open_ports
    .iter()
    .map(|result| port_result_to_json(result))
    .collect();
  json!({
    "target": target.to_string(),
    "preset": preset,
    "open_count": open_ports.len(),
    "ports": ports_json
  })
}

pub(super) fn scan_range_payload(
  target: std::net::IpAddr,
  start: u16,
  end: u16,
  threads: usize,
  timeout: u64,
  open_ports: &[&crate::modules::network::scanner::PortScanResult],
) -> Value {
  let ports_json: Vec<Value> = open_ports
    .iter()
    .map(|result| range_result_to_json(result))
    .collect();
  json!({
    "target": target.to_string(),
    "range_start": start,
    "range_end": end,
    "threads": threads,
    "timeout_ms": timeout,
    "total_scanned": end - start + 1,
    "open_count": open_ports.len(),
    "ports": ports_json
  })
}

pub(super) fn advanced_scan_payload(
  scan_type: ScanType,
  target: std::net::IpAddr,
  preset: &str,
  threads: usize,
  timeout: u64,
  total_scanned: usize,
  interesting: &[&crate::modules::network::scanner::AdvancedScanResult],
) -> Value {
  let scan_type_str = match scan_type {
    ScanType::Syn => "syn",
    ScanType::Udp => "udp",
    _ => "advanced",
  };
  let ports_json: Vec<Value> = interesting
    .iter()
    .map(|result| advanced_result_to_json(result))
    .collect();
  json!({
    "scan_type": scan_type_str,
    "target": target.to_string(),
    "preset": preset,
    "threads": threads,
    "timeout_ms": timeout,
    "total_scanned": total_scanned,
    "interesting_count": interesting.len(),
    "ports": ports_json
  })
}

pub(super) fn stealth_scan_payload(
  scan_type: ScanType,
  target: std::net::IpAddr,
  preset: &str,
  threads: usize,
  timeout: u64,
  total_scanned: usize,
  open_filtered: &[&crate::modules::network::scanner::AdvancedScanResult],
  closed_count: usize,
) -> Value {
  let scan_type_str = match scan_type {
    ScanType::Fin => "fin",
    ScanType::Null => "null",
    ScanType::Xmas => "xmas",
    _ => "stealth",
  };
  let open_filtered_json: Vec<Value> = open_filtered
    .iter()
    .map(|result| advanced_result_to_json(result))
    .collect();
  json!({
    "scan_type": scan_type_str,
    "target": target.to_string(),
    "preset": preset,
    "threads": threads,
    "timeout_ms": timeout,
    "total_scanned": total_scanned,
    "open_filtered_count": open_filtered.len(),
    "closed_count": closed_count,
    "open_filtered_ports": open_filtered_json
  })
}

/// Parse port specification like "1-1000,8080,8443"
pub(super) fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
  let mut ports = Vec::new();
  for part in spec.split(',') {
    let part = part.trim();
    if part.contains('-') {
      let range: Vec<&str> = part.split('-').collect();
      if range.len() == 2 {
        let start: u16 = range[0]
          .parse()
          .map_err(|_| format!("Invalid port: {}", range[0]))?;
        let end: u16 = range[1]
          .parse()
          .map_err(|_| format!("Invalid port: {}", range[1]))?;
        for p in start..=end {
          ports.push(p);
        }
      }
    } else {
      let p: u16 = part
        .parse()
        .map_err(|_| format!("Invalid port: {}", part))?;
      ports.push(p);
    }
  }
  Ok(ports)
}

pub(super) fn truncate_banner(input: &str, max_len: usize) -> String {
  if max_len == 0 {
    return String::new();
  }

  let sanitized = input.replace('\n', " ").replace('\r', " ");
  if sanitized.len() <= max_len {
    return sanitized;
  }

  let mut truncated: String = sanitized.chars().take(max_len.saturating_sub(1)).collect();
  truncated.push('…');
  truncated
}

/// Gather intelligence for a specific port/service
pub(super) fn gather_port_intelligence(
  host: &str,
  port: u16,
  service: Option<&str>,
  banner: Option<&str>,
) -> Option<PortIntelligence> {
  let service_name = service.unwrap_or("unknown");

  // Try to gather timing analysis
  let timing_result = match service_name {
    "ssh" => timing_analysis::fingerprint_ssh_timing(host, port).ok(),
    "ftp" => timing_analysis::fingerprint_ftp_timing(host, port)
      .ok()
      .map(|(_, time)| timing_analysis::TimingSignature {
        connection_time: time,
        first_response_time: Some(time),
        timeout_behavior: timing_analysis::TimeoutBehavior::Silent,
        keep_alive_interval: None,
      }),
    "http" | "https" => timing_analysis::fingerprint_http_timing(host, port).ok(),
    "mysql" | "postgres" | "mssql" | "mongodb" => {
      timing_analysis::fingerprint_database_timing(host, port).ok()
    }
    "telnet" => timing_analysis::fingerprint_telnet_timeout(host, port)
      .ok()
      .map(|(_, duration)| timing_analysis::TimingSignature {
        connection_time: duration,
        first_response_time: None,
        timeout_behavior: timing_analysis::TimeoutBehavior::Timeout(duration),
        keep_alive_interval: None,
      }),
    _ => None,
  };

  // Analyze banner if available
  let banner_info = banner.and_then(|b| {
    match service_name {
      "ssh" => Some(banner_analysis::analyze_ssh_banner(b)),
      "ftp" => Some(banner_analysis::analyze_ftp_banner(b)),
      "http" | "https" => {
        // Extract server header from HTTP response
        let server = b
          .lines()
          .find(|line| line.to_lowercase().starts_with("server:"))
          .and_then(|line| line.split(':').nth(1))
          .unwrap_or("")
          .trim();
        if !server.is_empty() {
          Some(banner_analysis::analyze_http_server(server))
        } else {
          None
        }
      }
      _ => None,
    }
  });

  // Combine into service detection
  let probe_responses = HashMap::new();
  let service_info = service_detection::detect_service(
    port,
    banner.map(|s| s.to_string()),
    timing_result.clone(),
    &probe_responses,
  );

  // Only return intelligence if we found something useful
  if timing_result.is_some() || banner_info.is_some() || service_info.confidence > 0.3 {
    Some(PortIntelligence {
      vendor: service_info.vendor,
      version: service_info.version,
      os_hint: service_info.os_hint,
      timing: timing_result,
      confidence: service_info.confidence,
    })
  } else {
    None
  }
}

/// Intelligence gathered for a single port
#[derive(Debug, Clone)]
pub(super) struct PortIntelligence {
  pub(super) vendor: Option<String>,
  pub(super) version: Option<String>,
  pub(super) os_hint: Option<String>,
  pub(super) timing: Option<timing_analysis::TimingSignature>,
  pub(super) confidence: f32,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn scan_ports_payload_reports_open_count() {
    let result = crate::modules::network::scanner::PortScanResult {
      port: 443,
      is_open: true,
      service: Some("https".to_string()),
      banner: Some("nginx".to_string()),
    };
    let payload = scan_ports_payload(
      std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
      "common",
      &[&result],
    );
    assert_eq!(payload["open_count"], json!(1));
    assert_eq!(
      payload["ports"].as_array().unwrap()[0]["service"],
      json!("https")
    );
  }

  #[test]
  fn advanced_scan_payload_reports_scan_type() {
    let result = crate::modules::network::scanner::AdvancedScanResult {
      port: 22,
      state: crate::protocols::raw::PortState::Open,
      service: Some("ssh".to_string()),
      rtt_ms: Some(12.5),
      ttl: Some(64),
      banner: None,
      scan_type: ScanType::Syn,
    };
    let payload = advanced_scan_payload(
      ScanType::Syn,
      std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
      "common",
      100,
      500,
      1000,
      &[&result],
    );
    assert_eq!(payload["scan_type"], json!("syn"));
    assert_eq!(payload["interesting_count"], json!(1));
    assert_eq!(payload["ports"].as_array().unwrap()[0]["port"], json!(22));
  }
}
