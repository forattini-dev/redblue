//! NoSQL Injection detection techniques
//!
//! Implements detection for:
//! - MongoDB operator injection
//! - MongoDB JavaScript injection ($where)
//! - Redis command injection
//! - Elasticsearch query injection
//! - Authentication bypass patterns

#![allow(dead_code, unused_imports)]

use super::payloads::{NoSqlDb, NoSqlPayload, NoSqlTechnique, RiskLevel};
use std::collections::HashMap;
use std::time::Duration;

/// Result of a NoSQL injection detection attempt
#[derive(Debug, Clone)]
pub struct DetectionResult {
  /// Whether injection was detected
  pub vulnerable: bool,
  /// Detected database type (if identified)
  pub database: Option<NoSqlDb>,
  /// Technique that succeeded
  pub technique: Option<NoSqlTechnique>,
  /// Payload that succeeded
  pub payload: Option<String>,
  /// Confidence level (0.0 to 1.0)
  pub confidence: f64,
  /// Evidence/reason for detection
  pub evidence: String,
}

impl DetectionResult {
  /// Create a non-vulnerable result
  pub fn not_vulnerable() -> Self {
    Self {
      vulnerable: false,
      database: None,
      technique: None,
      payload: None,
      confidence: 0.0,
      evidence: String::new(),
    }
  }

  /// Create a vulnerable result
  pub fn vulnerable(
    database: NoSqlDb,
    technique: NoSqlTechnique,
    payload: String,
    confidence: f64,
    evidence: String,
  ) -> Self {
    Self {
      vulnerable: true,
      database: Some(database),
      technique: Some(technique),
      payload: Some(payload),
      confidence,
      evidence,
    }
  }
}

/// HTTP response for injection testing
#[derive(Debug, Clone)]
pub struct HttpResponse {
  /// HTTP status code
  pub status: u16,
  /// Response body
  pub body: String,
  /// Response headers
  pub headers: HashMap<String, String>,
  /// Response time in milliseconds
  pub response_time_ms: u64,
  /// Content length
  pub content_length: usize,
}

impl HttpResponse {
  /// Create a new HTTP response
  pub fn new(status: u16, body: String) -> Self {
    let content_length = body.len();
    Self {
      status,
      body,
      headers: HashMap::new(),
      response_time_ms: 0,
      content_length,
    }
  }

  /// Check if response contains a pattern (case-insensitive)
  pub fn contains(&self, pattern: &str) -> bool {
    self.body.to_lowercase().contains(&pattern.to_lowercase())
  }
}

/// Injection point type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionPoint {
  /// GET parameter
  GetParam,
  /// POST body parameter
  PostParam,
  /// JSON body field
  JsonBody,
  /// HTTP cookie
  Cookie,
  /// HTTP header
  Header,
  /// URL path segment
  PathSegment,
}

// ============================================================================
// MongoDB Error Patterns
// ============================================================================

/// MongoDB error message patterns for detection
pub static MONGODB_ERROR_PATTERNS: &[(&str, &str)] = &[
  ("MongoError", "MongoDB driver error"),
  ("MongoParseError", "MongoDB parse error"),
  ("BSONTypeError", "BSON type error"),
  ("Unrecognized pipeline stage", "Aggregation pipeline error"),
  ("unknown operator", "Unknown operator error"),
  ("$where not allowed", "$where disabled error"),
  ("not authorized", "Authorization error"),
  ("bad query", "Bad query syntax"),
  ("cannot apply", "Operator application error"),
  ("Failed to parse", "JSON/BSON parse error"),
  ("Unexpected token", "JSON parse error"),
  ("SyntaxError", "JavaScript syntax error"),
  ("ReferenceError", "JavaScript reference error"),
];

/// Redis error patterns
pub static REDIS_ERROR_PATTERNS: &[(&str, &str)] = &[
  ("ERR unknown command", "Unknown Redis command"),
  ("WRONGTYPE", "Wrong type error"),
  ("ERR invalid DB", "Invalid database"),
  ("NOAUTH", "Authentication required"),
  ("NOSCRIPT", "Script not found"),
  ("ERR syntax error", "Redis syntax error"),
];

/// Elasticsearch error patterns
pub static ELASTICSEARCH_ERROR_PATTERNS: &[(&str, &str)] = &[
  ("parsing_exception", "Elasticsearch parse error"),
  ("query_shard_exception", "Query shard exception"),
  ("illegal_argument_exception", "Illegal argument"),
  ("search_phase_execution_exception", "Search execution error"),
  ("script_exception", "Script execution error"),
  ("index_not_found_exception", "Index not found"),
];

// ============================================================================
// Detection Configuration
// ============================================================================

/// Configuration for NoSQL injection detection
#[derive(Debug, Clone)]
pub struct DetectionConfig {
  /// Enable MongoDB detection
  pub mongodb: bool,
  /// Enable Redis detection
  pub redis: bool,
  /// Enable Elasticsearch detection
  pub elasticsearch: bool,
  /// Enable CouchDB detection
  pub couchdb: bool,
  /// Enable Cassandra detection
  pub cassandra: bool,
  /// Enable time-based blind detection
  pub time_blind: bool,
  /// Time threshold for blind detection (seconds)
  pub time_threshold: f64,
  /// Maximum risk level to test
  pub max_risk: RiskLevel,
  /// Enable verbose output
  pub verbose: bool,
}

impl Default for DetectionConfig {
  fn default() -> Self {
    Self {
      mongodb: true,
      redis: true,
      elasticsearch: true,
      couchdb: true,
      cassandra: true,
      time_blind: true,
      time_threshold: 5.0,
      max_risk: RiskLevel::Medium,
      verbose: false,
    }
  }
}

impl DetectionConfig {
  /// Quick scan - operators only, no time-based
  pub fn quick() -> Self {
    Self {
      time_blind: false,
      max_risk: RiskLevel::Low,
      ..Default::default()
    }
  }

  /// Thorough scan - all techniques
  pub fn thorough() -> Self {
    Self {
      max_risk: RiskLevel::High,
      ..Default::default()
    }
  }

  /// MongoDB only
  pub fn mongodb_only() -> Self {
    Self {
      mongodb: true,
      redis: false,
      elasticsearch: false,
      couchdb: false,
      cassandra: false,
      ..Default::default()
    }
  }
}

// ============================================================================
// MongoDB Detector
// ============================================================================

/// MongoDB injection detector
pub struct MongoDbDetector;

impl MongoDbDetector {
  /// Detect MongoDB operator injection
  pub fn detect_operator<F>(
    original_value: &str,
    send_request: &F,
    config: &DetectionConfig,
  ) -> DetectionResult
  where
    F: Fn(&str) -> HttpResponse,
  {
    // Get baseline response
    let baseline = send_request(original_value);

    // Test basic operator injection
    let test_payloads = [
      (r#"{"$gt": ""}"#, "Greater than operator"),
      (r#"{"$ne": null}"#, "Not equal operator"),
      (r#"{"$regex": ".*"}"#, "Regex operator"),
    ];

    for (payload, desc) in test_payloads {
      let response = send_request(payload);

      // Check for error patterns indicating MongoDB
      for (pattern, _) in MONGODB_ERROR_PATTERNS {
        if response.contains(pattern) {
          return DetectionResult::vulnerable(
            NoSqlDb::MongoDB,
            NoSqlTechnique::OperatorInjection,
            payload.to_string(),
            0.9,
            format!("MongoDB error pattern detected: {}", pattern),
          );
        }
      }

      // Check for response difference indicating injection worked
      if Self::response_indicates_injection(&baseline, &response) {
        return DetectionResult::vulnerable(
          NoSqlDb::MongoDB,
          NoSqlTechnique::OperatorInjection,
          payload.to_string(),
          0.7,
          format!("{} - response differs significantly", desc),
        );
      }
    }

    DetectionResult::not_vulnerable()
  }

  /// Detect MongoDB JavaScript injection ($where)
  pub fn detect_javascript<F>(
    original_value: &str,
    send_request: &F,
    config: &DetectionConfig,
  ) -> DetectionResult
  where
    F: Fn(&str) -> HttpResponse,
  {
    let baseline = send_request(original_value);

    // Test $where injection
    let true_payload = r#"{"$where": "1==1"}"#;
    let false_payload = r#"{"$where": "1==0"}"#;

    let true_response = send_request(true_payload);
    let false_response = send_request(false_payload);

    // Check for error patterns
    for (pattern, _) in MONGODB_ERROR_PATTERNS {
      if true_response.contains(pattern) {
        // $where might be disabled
        if pattern.contains("$where") {
          return DetectionResult::vulnerable(
            NoSqlDb::MongoDB,
            NoSqlTechnique::JavaScriptInjection,
            true_payload.to_string(),
            0.8,
            "MongoDB detected - $where is disabled".to_string(),
          );
        }
      }
    }

    // Check for boolean-based detection
    if Self::responses_differ_significantly(&true_response, &false_response) {
      return DetectionResult::vulnerable(
        NoSqlDb::MongoDB,
        NoSqlTechnique::JavaScriptInjection,
        true_payload.to_string(),
        0.8,
        "Boolean-based JavaScript injection detected".to_string(),
      );
    }

    // Time-based detection
    if config.time_blind {
      let sleep_payload = format!(
        r#"{{"$where": "sleep({})"}}"#,
        (config.time_threshold * 1000.0) as u32
      );
      let sleep_response = send_request(&sleep_payload);

      let threshold_ms = (config.time_threshold * 1000.0) as u64;
      if sleep_response.response_time_ms >= threshold_ms - 500 {
        return DetectionResult::vulnerable(
          NoSqlDb::MongoDB,
          NoSqlTechnique::JavaScriptInjection,
          sleep_payload,
          0.85,
          format!(
            "Time-based JavaScript injection: {}ms delay",
            sleep_response.response_time_ms
          ),
        );
      }
    }

    DetectionResult::not_vulnerable()
  }

  /// Check if response indicates successful injection
  fn response_indicates_injection(baseline: &HttpResponse, test: &HttpResponse) -> bool {
    // Significant content length difference
    let len_diff = (baseline.content_length as i64 - test.content_length as i64).abs();
    if len_diff > 100 {
      return true;
    }

    // Status code change (but not to error)
    if baseline.status != test.status && test.status < 400 {
      return true;
    }

    // More data returned (potential data exposure)
    if test.content_length > baseline.content_length * 2 {
      return true;
    }

    false
  }

  /// Check if two responses differ significantly
  fn responses_differ_significantly(r1: &HttpResponse, r2: &HttpResponse) -> bool {
    let len_diff = (r1.content_length as i64 - r2.content_length as i64).abs();
    len_diff > 50 || r1.status != r2.status
  }
}

// ============================================================================
// Redis Detector
// ============================================================================

/// Redis command injection detector
pub struct RedisDetector;

impl RedisDetector {
  /// Detect Redis command injection
  pub fn detect<F>(
    original_value: &str,
    send_request: &F,
    config: &DetectionConfig,
  ) -> DetectionResult
  where
    F: Fn(&str) -> HttpResponse,
  {
    let baseline = send_request(original_value);

    // Test for Redis error patterns
    let test_payloads = ["INFO", "KEYS *", "DBSIZE"];

    for payload in test_payloads {
      let response = send_request(payload);

      // Check for Redis error patterns
      for (pattern, desc) in REDIS_ERROR_PATTERNS {
        if response.contains(pattern) {
          return DetectionResult::vulnerable(
            NoSqlDb::Redis,
            NoSqlTechnique::CommandInjection,
            payload.to_string(),
            0.9,
            format!("Redis error detected: {}", desc),
          );
        }
      }

      // Check for Redis INFO response
      if response.contains("redis_version:")
        || response.contains("used_memory:")
        || response.contains("connected_clients:")
      {
        return DetectionResult::vulnerable(
          NoSqlDb::Redis,
          NoSqlTechnique::CommandInjection,
          payload.to_string(),
          0.95,
          "Redis INFO response detected".to_string(),
        );
      }
    }

    // Time-based detection with DEBUG SLEEP
    if config.time_blind {
      let sleep_payload = format!("DEBUG SLEEP {}", config.time_threshold as u32);
      let sleep_response = send_request(&sleep_payload);

      let threshold_ms = (config.time_threshold * 1000.0) as u64;
      if sleep_response.response_time_ms >= threshold_ms - 500 {
        return DetectionResult::vulnerable(
          NoSqlDb::Redis,
          NoSqlTechnique::CommandInjection,
          sleep_payload,
          0.85,
          format!(
            "Time-based Redis injection: {}ms delay",
            sleep_response.response_time_ms
          ),
        );
      }
    }

    DetectionResult::not_vulnerable()
  }
}

// ============================================================================
// Elasticsearch Detector
// ============================================================================

/// Elasticsearch query injection detector
pub struct ElasticsearchDetector;

impl ElasticsearchDetector {
  /// Detect Elasticsearch query injection
  pub fn detect<F>(
    original_value: &str,
    send_request: &F,
    _config: &DetectionConfig,
  ) -> DetectionResult
  where
    F: Fn(&str) -> HttpResponse,
  {
    let baseline = send_request(original_value);

    // Test for Elasticsearch patterns
    let test_payloads = [
      (r#"{"query": {"match_all": {}}}"#, "Match all query"),
      ("/_cat/indices", "Cat indices API"),
      ("/_cluster/health", "Cluster health API"),
    ];

    for (payload, desc) in test_payloads {
      let response = send_request(payload);

      // Check for Elasticsearch error patterns
      for (pattern, _) in ELASTICSEARCH_ERROR_PATTERNS {
        if response.contains(pattern) {
          return DetectionResult::vulnerable(
            NoSqlDb::Elasticsearch,
            NoSqlTechnique::QueryDslInjection,
            payload.to_string(),
            0.9,
            format!("Elasticsearch error detected: {}", pattern),
          );
        }
      }

      // Check for Elasticsearch-specific responses
      if response.contains("\"hits\":")
        || response.contains("\"_shards\":")
        || response.contains("cluster_name")
      {
        return DetectionResult::vulnerable(
          NoSqlDb::Elasticsearch,
          NoSqlTechnique::QueryDslInjection,
          payload.to_string(),
          0.95,
          format!("{} - Elasticsearch response detected", desc),
        );
      }
    }

    DetectionResult::not_vulnerable()
  }
}

// ============================================================================
// Main NoSQL Detector
// ============================================================================

/// Combined NoSQL injection detector
pub struct NoSqlDetector {
  config: DetectionConfig,
}

impl NoSqlDetector {
  /// Create a new detector with configuration
  pub fn new(config: DetectionConfig) -> Self {
    Self { config }
  }

  /// Detect NoSQL injection vulnerabilities
  pub fn detect<F>(
    &self,
    param_name: &str,
    original_value: &str,
    injection_point: InjectionPoint,
    send_request: &F,
  ) -> DetectionResult
  where
    F: Fn(&str) -> HttpResponse,
  {
    // Try MongoDB detection
    if self.config.mongodb {
      let result = MongoDbDetector::detect_operator(original_value, send_request, &self.config);
      if result.vulnerable {
        return result;
      }

      let result = MongoDbDetector::detect_javascript(original_value, send_request, &self.config);
      if result.vulnerable {
        return result;
      }
    }

    // Try Redis detection
    if self.config.redis {
      let result = RedisDetector::detect(original_value, send_request, &self.config);
      if result.vulnerable {
        return result;
      }
    }

    // Try Elasticsearch detection
    if self.config.elasticsearch {
      let result = ElasticsearchDetector::detect(original_value, send_request, &self.config);
      if result.vulnerable {
        return result;
      }
    }

    DetectionResult::not_vulnerable()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_detection_result() {
    let result = DetectionResult::not_vulnerable();
    assert!(!result.vulnerable);

    let result = DetectionResult::vulnerable(
      NoSqlDb::MongoDB,
      NoSqlTechnique::OperatorInjection,
      "test".to_string(),
      0.9,
      "test".to_string(),
    );
    assert!(result.vulnerable);
    assert_eq!(result.database, Some(NoSqlDb::MongoDB));
  }

  #[test]
  fn test_detection_config() {
    let quick = DetectionConfig::quick();
    assert!(!quick.time_blind);
    assert_eq!(quick.max_risk, RiskLevel::Low);

    let thorough = DetectionConfig::thorough();
    assert!(thorough.time_blind);
    assert_eq!(thorough.max_risk, RiskLevel::High);
  }

  #[test]
  fn test_http_response() {
    let response = HttpResponse::new(200, "test body".to_string());
    assert!(response.contains("test"));
    assert!(!response.contains("notfound"));
  }
}
