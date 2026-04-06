//! SQL Injection testing module
//!
//! Provides comprehensive SQL injection testing capabilities:
//! - 130+ payloads across 6 techniques
//! - 30+ WAF bypass tamper scripts
//! - Detection for MySQL, PostgreSQL, MSSQL, Oracle, SQLite
//! - Auto parameter discovery in GET, POST, JSON, cookies
//!
//! # Example
//! ```ignore
//! use redblue::modules::web::sqli::{SqliScanner, ScanConfig};
//!
//! let scanner = SqliScanner::new(ScanConfig::default());
//! let results = scanner.scan("http://target.com/page?id=1");
//! ```

#![allow(unused_imports, dead_code)]

pub mod payloads;
pub mod tamper;
pub mod techniques;

use payloads::{Dbms, SqliTechnique};
use tamper::{get_tamper, TamperFn};
use techniques::{DetectionConfig, DetectionResult, HttpResponse, InjectionPoint, SqliDetector};

use std::collections::HashMap;
use std::time::Duration;

// Re-exports
pub use payloads::{
  payloads_by_dbms, payloads_by_risk, payloads_by_technique, total_payload_count,
};
pub use tamper::{list_tampers, parse_tamper_list, tampers_for_dbms};
pub use techniques::DetectionConfig as TechniqueConfig;

/// Configuration for SQL injection scanning
#[derive(Debug, Clone)]
pub struct ScanConfig {
  /// Detection configuration
  pub detection: DetectionConfig,
  /// List of tamper script names to apply
  pub tamper_scripts: Vec<String>,
  /// Target specific DBMS (None = test all)
  pub target_dbms: Option<Dbms>,
  /// Scan timeout per parameter (seconds)
  pub timeout_secs: u32,
  /// Enable verbose output
  pub verbose: bool,
  /// Test authentication bypass payloads
  pub test_auth_bypass: bool,
  /// Skip parameters matching these patterns
  pub skip_params: Vec<String>,
  /// Only test parameters matching these patterns
  pub only_params: Vec<String>,
  /// HTTP headers to include
  pub headers: HashMap<String, String>,
  /// HTTP cookies to include
  pub cookies: HashMap<String, String>,
}

impl Default for ScanConfig {
  fn default() -> Self {
    Self {
      detection: DetectionConfig::default(),
      tamper_scripts: Vec::new(),
      target_dbms: None,
      timeout_secs: 30,
      verbose: false,
      test_auth_bypass: false,
      skip_params: vec![
        "submit".to_string(),
        "button".to_string(),
        "action".to_string(),
      ],
      only_params: Vec::new(),
      headers: HashMap::new(),
      cookies: HashMap::new(),
    }
  }
}

impl ScanConfig {
  /// Quick scan - error-based and boolean-blind only
  pub fn quick() -> Self {
    Self {
      detection: DetectionConfig::quick(),
      ..Default::default()
    }
  }

  /// Thorough scan - all techniques, higher risk
  pub fn thorough() -> Self {
    Self {
      detection: DetectionConfig::thorough(),
      test_auth_bypass: true,
      ..Default::default()
    }
  }

  /// Enable specific tamper scripts
  pub fn with_tampers(mut self, tampers: Vec<String>) -> Self {
    self.tamper_scripts = tampers;
    self
  }

  /// Target a specific DBMS
  pub fn for_dbms(mut self, dbms: Dbms) -> Self {
    self.target_dbms = Some(dbms);
    self.detection.target_dbms = Some(dbms);
    self
  }

  /// Add HTTP header
  pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
    self.headers.insert(name.into(), value.into());
    self
  }

  /// Add cookie
  pub fn with_cookie(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
    self.cookies.insert(name.into(), value.into());
    self
  }
}

/// Result of scanning a single parameter
#[derive(Debug, Clone)]
pub struct ParameterResult {
  /// Parameter name
  pub name: String,
  /// Original value
  pub original_value: String,
  /// Injection point type
  pub injection_point: InjectionPoint,
  /// Detection result
  pub detection: DetectionResult,
  /// Payloads that were successful
  pub successful_payloads: Vec<String>,
}

/// Result of scanning a URL
#[derive(Debug, Clone)]
pub struct ScanResult {
  /// Target URL
  pub url: String,
  /// Parameters tested
  pub parameters_tested: usize,
  /// Vulnerable parameters
  pub vulnerable_parameters: Vec<ParameterResult>,
  /// Non-vulnerable parameters
  pub safe_parameters: Vec<String>,
  /// Scan duration
  pub duration: Duration,
  /// Errors encountered
  pub errors: Vec<String>,
}

impl ScanResult {
  /// Check if any vulnerabilities were found
  pub fn is_vulnerable(&self) -> bool {
    !self.vulnerable_parameters.is_empty()
  }

  /// Get count of vulnerable parameters
  pub fn vulnerability_count(&self) -> usize {
    self.vulnerable_parameters.len()
  }

  /// Get detected DBMS types
  pub fn detected_dbms(&self) -> Vec<Dbms> {
    self
      .vulnerable_parameters
      .iter()
      .filter_map(|p| p.detection.dbms)
      .collect()
  }
}

/// SQL Injection scanner
pub struct SqliScanner {
  config: ScanConfig,
  detector: SqliDetector,
  tampers: Vec<TamperFn>,
}

impl SqliScanner {
  /// Create a new scanner with the given configuration
  pub fn new(config: ScanConfig) -> Self {
    // Parse tamper scripts
    let tampers: Vec<TamperFn> = config
      .tamper_scripts
      .iter()
      .filter_map(|name| get_tamper(name).map(|t| t.tamper))
      .collect();

    let mut detection_config = config.detection.clone();
    detection_config.tampers = tampers.clone();

    Self {
      detector: SqliDetector::new(detection_config),
      tampers,
      config,
    }
  }

  /// Create scanner with default configuration
  pub fn default_scanner() -> Self {
    Self::new(ScanConfig::default())
  }

  /// Parse URL and extract parameters
  pub fn parse_url_params(url: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();

    if let Some(query_start) = url.find('?') {
      let query = &url[query_start + 1..];

      for pair in query.split('&') {
        if let Some(eq_pos) = pair.find('=') {
          let name = &pair[..eq_pos];
          let value = &pair[eq_pos + 1..];
          params.insert(Self::url_decode(name), Self::url_decode(value));
        }
      }
    }

    params
  }

  /// Simple URL decode
  fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
      if c == '%' {
        let hex: String = chars.by_ref().take(2).collect();
        if hex.len() == 2 {
          if let Ok(byte) = u8::from_str_radix(&hex, 16) {
            result.push(byte as char);
            continue;
          }
        }
        result.push('%');
        result.push_str(&hex);
      } else if c == '+' {
        result.push(' ');
      } else {
        result.push(c);
      }
    }

    result
  }

  /// Parse JSON body and extract fields
  pub fn parse_json_params(body: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();

    // Simple JSON parsing (not a full parser)
    // Extracts top-level string fields
    for line in body.lines() {
      let line = line.trim();
      if let Some(colon_pos) = line.find(':') {
        let key = line[..colon_pos].trim().trim_matches('"');
        let value = line[colon_pos + 1..].trim().trim_matches([',', '"']);
        if !key.is_empty() && !value.is_empty() {
          params.insert(key.to_string(), value.to_string());
        }
      }
    }

    params
  }

  /// Parse form data body
  pub fn parse_form_params(body: &str) -> HashMap<String, String> {
    Self::parse_url_params(&format!("?{}", body))
  }

  /// Check if parameter should be skipped
  fn should_skip_param(&self, name: &str) -> bool {
    // Check skip list
    if self
      .config
      .skip_params
      .iter()
      .any(|p| name.to_lowercase().contains(&p.to_lowercase()))
    {
      return true;
    }

    // Check only list (if set)
    if !self.config.only_params.is_empty()
      && !self
        .config
        .only_params
        .iter()
        .any(|p| name.to_lowercase().contains(&p.to_lowercase()))
    {
      return true;
    }

    false
  }

  /// Scan a single parameter
  pub fn scan_parameter<F>(
    &self,
    param_name: &str,
    original_value: &str,
    injection_point: InjectionPoint,
    send_request: F,
  ) -> ParameterResult
  where
    F: Fn(&str) -> HttpResponse,
  {
    let detection =
      self
        .detector
        .detect(param_name, original_value, injection_point, &send_request);

    let successful_payloads = if detection.vulnerable {
      detection.payload.clone().into_iter().collect()
    } else {
      Vec::new()
    };

    ParameterResult {
      name: param_name.to_string(),
      original_value: original_value.to_string(),
      injection_point,
      detection,
      successful_payloads,
    }
  }

  /// Build a modified URL with a parameter value changed
  pub fn build_url_with_param(base_url: &str, param: &str, value: &str) -> String {
    let (base, query) = if let Some(pos) = base_url.find('?') {
      (&base_url[..pos], &base_url[pos + 1..])
    } else {
      (base_url, "")
    };

    let mut new_params = Vec::new();
    let mut found = false;

    for pair in query.split('&') {
      if pair.is_empty() {
        continue;
      }

      if let Some(eq_pos) = pair.find('=') {
        let name = &pair[..eq_pos];
        if name == param {
          new_params.push(format!("{}={}", name, Self::url_encode(value)));
          found = true;
        } else {
          new_params.push(pair.to_string());
        }
      }
    }

    if !found {
      new_params.push(format!("{}={}", param, Self::url_encode(value)));
    }

    if new_params.is_empty() {
      base.to_string()
    } else {
      format!("{}?{}", base, new_params.join("&"))
    }
  }

  /// Simple URL encode
  fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);

    for c in s.chars() {
      match c {
        'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
          result.push(c);
        }
        ' ' => result.push('+'),
        _ => {
          for b in c.to_string().as_bytes() {
            result.push_str(&format!("%{:02X}", b));
          }
        }
      }
    }

    result
  }
}

/// Summary statistics for a scan
#[derive(Debug, Clone)]
pub struct ScanStats {
  pub total_requests: u32,
  pub parameters_tested: u32,
  pub vulnerabilities_found: u32,
  pub techniques_successful: HashMap<SqliTechnique, u32>,
  pub dbms_detected: HashMap<Dbms, u32>,
  pub duration: Duration,
}

impl ScanStats {
  pub fn new() -> Self {
    Self {
      total_requests: 0,
      parameters_tested: 0,
      vulnerabilities_found: 0,
      techniques_successful: HashMap::new(),
      dbms_detected: HashMap::new(),
      duration: Duration::ZERO,
    }
  }

  pub fn record_vulnerability(&mut self, technique: SqliTechnique, dbms: Option<Dbms>) {
    self.vulnerabilities_found += 1;
    *self.techniques_successful.entry(technique).or_insert(0) += 1;
    if let Some(db) = dbms {
      *self.dbms_detected.entry(db).or_insert(0) += 1;
    }
  }
}

impl Default for ScanStats {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_url_params() {
    let params = SqliScanner::parse_url_params("http://test.com/page?id=1&name=test");
    assert_eq!(params.get("id"), Some(&"1".to_string()));
    assert_eq!(params.get("name"), Some(&"test".to_string()));
  }

  #[test]
  fn test_parse_url_params_encoded() {
    let params = SqliScanner::parse_url_params("http://test.com/?q=hello%20world");
    assert_eq!(params.get("q"), Some(&"hello world".to_string()));
  }

  #[test]
  fn test_build_url_with_param() {
    let url = SqliScanner::build_url_with_param("http://test.com/page?id=1&x=y", "id", "2");
    assert!(url.contains("id=2"));
    assert!(url.contains("x=y"));
  }

  #[test]
  fn test_scan_config() {
    let config = ScanConfig::quick();
    assert!(!config.detection.time_blind);

    let config = ScanConfig::thorough();
    assert!(config.test_auth_bypass);
  }

  #[test]
  fn test_url_encode() {
    assert_eq!(SqliScanner::url_encode("test"), "test");
    assert_eq!(SqliScanner::url_encode("hello world"), "hello+world");
    assert_eq!(SqliScanner::url_encode("a=b"), "a%3Db");
  }

  #[test]
  fn test_total_payloads() {
    assert!(total_payload_count() >= 80);
  }

  #[test]
  fn test_tamper_scripts() {
    assert!(list_tampers().len() >= 25);
  }
}
