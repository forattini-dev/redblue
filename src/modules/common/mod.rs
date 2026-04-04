//! Common Types for redblue Modules
//!
//! This module provides unified types that all security modules should use
//! to ensure consistent data formats and enable cross-module synergy.
//!
//! # Types
//!
//! - [`Severity`]: Unified severity levels (Info, Low, Medium, High, Critical)
//! - [`SecurityFinding`]: Generic security finding with evidence and metadata
//! - [`ScanResult`]: Wrapper for scan results with timing and source info
//! - [`Evidence`]: Evidence supporting a security finding
//!
//! # Canonical Vocabulary
//!
//! For consistency across modules, prefer these canonical terms:
//!
//! | Concept            | Canonical Term     | Avoid              |
//! |--------------------|--------------------|--------------------|
//! | Scan target        | `target`           | asset              |
//! | Individual machine | `host`             | target (too generic)|
//! | Security issue     | `finding`          | vuln, vulnerability|
//! | Data grouping      | `segment`          | table, collection  |
//! | Criticality level  | `severity`         | risk, criticality  |
//! | Supporting proof   | `evidence`         | proof, data        |
//!
//! # Usage
//!
//! ```ignore
//! use crate::modules::common::{Severity, SecurityFinding, Evidence};
//!
//! let finding = SecurityFinding::new("xss-001", "Reflected XSS in search parameter")
//!     .severity(Severity::High)
//!     .cwe("CWE-79")
//!     .cvss(7.5)
//!     .evidence(Evidence::new("Input: <script>alert(1)</script>"))
//!     .remediation("Encode output properly");
//! ```

pub mod http;

use std::fmt;
use std::time::Duration;

// ============================================================================
// Severity Levels
// ============================================================================

/// Unified severity levels for security findings.
///
/// Based on CVSS v3.0 severity rating scale:
/// - Info: Informational, no security impact
/// - Low: CVSS 0.1-3.9
/// - Medium: CVSS 4.0-6.9
/// - High: CVSS 7.0-8.9
/// - Critical: CVSS 9.0-10.0
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// Informational finding, no direct security impact
    Info,
    /// Low severity - limited impact, difficult to exploit
    Low,
    /// Medium severity - moderate impact or exploitability
    Medium,
    /// High severity - significant impact, relatively easy to exploit
    High,
    /// Critical severity - maximum impact, easily exploitable
    Critical,
}

impl Severity {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Get the uppercase string representation
    pub fn as_upper(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// Parse from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" | "informational" | "none" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "moderate" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Get CVSS score range for this severity
    pub fn cvss_range(&self) -> (f32, f32) {
        match self {
            Self::Info => (0.0, 0.0),
            Self::Low => (0.1, 3.9),
            Self::Medium => (4.0, 6.9),
            Self::High => (7.0, 8.9),
            Self::Critical => (9.0, 10.0),
        }
    }

    /// Create severity from CVSS score
    pub fn from_cvss(score: f32) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::Info
        }
    }

    /// Get a numeric weight for sorting (higher = more severe)
    pub fn weight(&self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    /// Get HTML color code for this severity level (for reports)
    pub fn color(&self) -> &'static str {
        match self {
            Self::Info => "#17a2b8",     // Bootstrap info blue
            Self::Low => "#28a745",      // Bootstrap success green
            Self::Medium => "#ffc107",   // Bootstrap warning yellow
            Self::High => "#fd7e14",     // Bootstrap orange
            Self::Critical => "#dc3545", // Bootstrap danger red
        }
    }

    /// Get ANSI color escape code for terminal output
    pub fn color_code(&self) -> &'static str {
        match self {
            Self::Info => "\x1b[37m",     // White
            Self::Low => "\x1b[36m",      // Cyan
            Self::Medium => "\x1b[33m",   // Yellow
            Self::High => "\x1b[31m",     // Red
            Self::Critical => "\x1b[91m", // Bright red
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Self::Info
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_upper())
    }
}

// ============================================================================
// Finding Category
// ============================================================================

/// Category of security finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingCategory {
    /// Web application vulnerability (XSS, SQLi, CSRF, etc.)
    WebVuln,
    /// TLS/SSL configuration issue
    TlsConfig,
    /// Cryptographic weakness
    CryptoWeakness,
    /// Information disclosure
    InfoDisclosure,
    /// Authentication/authorization issue
    AuthIssue,
    /// Configuration misconfiguration
    Misconfiguration,
    /// Exposed sensitive data (secrets, credentials)
    ExposedSecrets,
    /// Network service vulnerability
    NetworkVuln,
    /// Code quality/security issue
    CodeIssue,
    /// Privilege escalation opportunity
    PrivilegeEscalation,
    /// Other/unclassified
    Other,
}

impl FindingCategory {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WebVuln => "web-vuln",
            Self::TlsConfig => "tls-config",
            Self::CryptoWeakness => "crypto",
            Self::InfoDisclosure => "info-disclosure",
            Self::AuthIssue => "auth",
            Self::Misconfiguration => "misconfig",
            Self::ExposedSecrets => "secrets",
            Self::NetworkVuln => "network-vuln",
            Self::CodeIssue => "code",
            Self::PrivilegeEscalation => "privesc",
            Self::Other => "other",
        }
    }
}

impl Default for FindingCategory {
    fn default() -> Self {
        Self::Other
    }
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Evidence
// ============================================================================

/// Evidence supporting a security finding
#[derive(Debug, Clone)]
pub struct Evidence {
    /// Evidence type/label
    pub label: String,
    /// Evidence content
    pub content: String,
    /// Optional file path where evidence was found
    pub file_path: Option<String>,
    /// Optional line number
    pub line: Option<usize>,
}

impl Evidence {
    /// Create new evidence with content
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            label: "evidence".into(),
            content: content.into(),
            file_path: None,
            line: None,
        }
    }

    /// Create labeled evidence
    pub fn labeled(label: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            content: content.into(),
            file_path: None,
            line: None,
        }
    }

    /// Set file location
    pub fn at_file(mut self, path: impl Into<String>, line: Option<usize>) -> Self {
        self.file_path = Some(path.into());
        self.line = line;
        self
    }
}

// ============================================================================
// Security Finding
// ============================================================================

/// A unified security finding that can be used across all modules.
///
/// This type consolidates the various Finding types scattered across
/// web, tls, recon, and other modules into a single, consistent format.
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    /// Unique identifier for this finding type (e.g., "xss-reflected")
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: Option<String>,
    /// Severity level
    pub severity: Severity,
    /// Finding category
    pub category: FindingCategory,
    /// Evidence supporting the finding
    pub evidence: Vec<Evidence>,
    /// Suggested remediation
    pub remediation: Option<String>,
    /// Reference URLs (documentation, CVEs, etc.)
    pub references: Vec<String>,
    /// CWE identifier (e.g., "CWE-79")
    pub cwe: Option<String>,
    /// CVSS score (0.0 - 10.0)
    pub cvss: Option<f32>,
    /// Target affected (URL, host, file, etc.)
    pub target: Option<String>,
    /// MITRE ATT&CK technique IDs
    pub mitre_techniques: Vec<String>,
}

impl SecurityFinding {
    /// Create a new finding with ID and title
    pub fn new(id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: None,
            severity: Severity::Info,
            category: FindingCategory::Other,
            evidence: Vec::new(),
            remediation: None,
            references: Vec::new(),
            cwe: None,
            cvss: None,
            target: None,
            mitre_techniques: Vec::new(),
        }
    }

    /// Set description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set severity
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set category
    pub fn category(mut self, category: FindingCategory) -> Self {
        self.category = category;
        self
    }

    /// Add evidence
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Set remediation
    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Add reference URL
    pub fn reference(mut self, url: impl Into<String>) -> Self {
        self.references.push(url.into());
        self
    }

    /// Set CWE identifier
    pub fn cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe = Some(cwe.into());
        self
    }

    /// Set CVSS score (also updates severity based on score)
    pub fn cvss(mut self, score: f32) -> Self {
        self.cvss = Some(score);
        self.severity = Severity::from_cvss(score);
        self
    }

    /// Set target
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Add MITRE ATT&CK technique
    pub fn mitre(mut self, technique_id: impl Into<String>) -> Self {
        self.mitre_techniques.push(technique_id.into());
        self
    }
}

// ============================================================================
// Scan Result
// ============================================================================

/// Generic wrapper for scan results with metadata.
///
/// Provides consistent metadata (timing, source) for all scan operations.
#[derive(Debug, Clone)]
pub struct ScanResult<T> {
    /// The scan target (URL, IP, domain, etc.)
    pub target: String,
    /// The actual scan data
    pub data: T,
    /// How long the scan took
    pub duration: Duration,
    /// Module that produced this result (e.g., "web::scanner")
    pub source: &'static str,
    /// Whether the scan completed successfully
    pub success: bool,
    /// Optional error message if scan failed
    pub error: Option<String>,
}

impl<T> ScanResult<T> {
    /// Create a successful scan result
    pub fn success(
        target: impl Into<String>,
        data: T,
        duration: Duration,
        source: &'static str,
    ) -> Self {
        Self {
            target: target.into(),
            data,
            duration,
            source,
            success: true,
            error: None,
        }
    }

    /// Create a failed scan result with default data
    pub fn failure(
        target: impl Into<String>,
        error: impl Into<String>,
        duration: Duration,
        source: &'static str,
        default: T,
    ) -> Self {
        Self {
            target: target.into(),
            data: default,
            duration,
            source,
            success: false,
            error: Some(error.into()),
        }
    }

    /// Map the data to a different type
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> ScanResult<U> {
        ScanResult {
            target: self.target,
            data: f(self.data),
            duration: self.duration,
            source: self.source,
            success: self.success,
            error: self.error,
        }
    }
}

// ============================================================================
// Progress Tracking
// ============================================================================

/// Unified progress tracking trait for all scanning operations.
///
/// This trait consolidates the various progress tracking implementations
/// scattered across modules into a single, consistent interface.
///
/// # Usage
///
/// ```ignore
/// use crate::modules::common::Progress;
///
/// struct MyProgress {
///     total: u64,
///     completed: std::sync::atomic::AtomicU64,
/// }
///
/// impl Progress for MyProgress {
///     fn inc(&self, delta: u64) {
///         self.completed.fetch_add(delta, std::sync::atomic::Ordering::Relaxed);
///     }
///     fn set_total(&self, total: u64) { /* ... */ }
///     fn finish(&self) { /* ... */ }
/// }
/// ```
pub trait Progress: Send + Sync {
    /// Increment progress by delta units
    fn inc(&self, delta: u64);

    /// Set the total expected work units (optional)
    fn set_total(&self, _total: u64) {}

    /// Mark progress as complete
    fn finish(&self) {}

    /// Set a message/status (optional)
    fn set_message(&self, _msg: &str) {}

    /// Get current progress percentage (0.0 - 1.0)
    fn percentage(&self) -> f64 {
        0.0
    }
}

/// No-op progress tracker for when progress reporting isn't needed
pub struct NoProgress;

impl Progress for NoProgress {
    fn inc(&self, _delta: u64) {}
}

/// Simple atomic counter progress tracker
pub struct AtomicProgress {
    current: std::sync::atomic::AtomicU64,
    total: std::sync::atomic::AtomicU64,
}

impl AtomicProgress {
    pub fn new(total: u64) -> Self {
        Self {
            current: std::sync::atomic::AtomicU64::new(0),
            total: std::sync::atomic::AtomicU64::new(total),
        }
    }

    pub fn current(&self) -> u64 {
        self.current.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.total.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Progress for AtomicProgress {
    fn inc(&self, delta: u64) {
        self.current
            .fetch_add(delta, std::sync::atomic::Ordering::Relaxed);
    }

    fn set_total(&self, total: u64) {
        self.total
            .store(total, std::sync::atomic::Ordering::Relaxed);
    }

    fn finish(&self) {
        let total = self.total.load(std::sync::atomic::Ordering::Relaxed);
        self.current
            .store(total, std::sync::atomic::Ordering::Relaxed);
    }

    fn percentage(&self) -> f64 {
        let current = self.current.load(std::sync::atomic::Ordering::Relaxed) as f64;
        let total = self.total.load(std::sync::atomic::Ordering::Relaxed) as f64;
        if total > 0.0 {
            current / total
        } else {
            0.0
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(5.5), Severity::Medium);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(9.5), Severity::Critical);
    }

    #[test]
    fn test_severity_parsing() {
        assert_eq!(Severity::from_str("critical"), Some(Severity::Critical));
        assert_eq!(Severity::from_str("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_str("none"), Some(Severity::Info));
        assert_eq!(Severity::from_str("invalid"), None);
    }

    #[test]
    fn test_finding_builder() {
        let finding = SecurityFinding::new("test-001", "Test Finding")
            .severity(Severity::High)
            .category(FindingCategory::WebVuln)
            .cwe("CWE-79")
            .cvss(7.5)
            .evidence(Evidence::new("Test evidence"))
            .remediation("Fix the issue");

        assert_eq!(finding.id, "test-001");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.cwe, Some("CWE-79".into()));
        assert_eq!(finding.evidence.len(), 1);
    }

    #[test]
    fn test_scan_result() {
        let result = ScanResult::success(
            "https://example.com",
            vec!["data"],
            Duration::from_secs(1),
            "test::scanner",
        );

        assert!(result.success);
        assert_eq!(result.target, "https://example.com");
        assert_eq!(result.data.len(), 1);
    }
}
