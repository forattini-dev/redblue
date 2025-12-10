/// TLS/SSL Vulnerability Checks Module
///
/// Replaces: testssl.sh, sslyze, sslscan
///
/// Implements Phase 2.2 TLS/SSL Vulnerability Checks:
/// - Heartbleed (CVE-2014-0160)
/// - ROBOT attack
/// - CCS Injection (CVE-2014-0224)
/// - DROWN (CVE-2016-0800)
/// - POODLE (CVE-2014-3566)
/// - BEAST (CVE-2011-3389)
/// - LOGJAM (weak DH)
/// - Ticketbleed (CVE-2016-9244)
/// - Renegotiation vulnerabilities
///
/// NO external dependencies - pure Rust implementation

use std::net::{TcpStream, ToSocketAddrs};
use std::io::{Read, Write};
use std::time::Duration;

pub mod heartbleed;
pub mod poodle;
pub mod beast;
pub mod logjam;
pub mod robot;
pub mod ccs_injection;
pub mod drown;
pub mod ticketbleed;
pub mod renegotiation;

pub use heartbleed::HeartbleedChecker;
pub use poodle::PoodleChecker;
pub use beast::BeastChecker;
pub use logjam::LogjamChecker;
pub use robot::RobotChecker;
pub use ccs_injection::CcsInjectionChecker;
pub use drown::DrownChecker;
pub use ticketbleed::TicketbleedChecker;
pub use renegotiation::RenegotiationChecker;

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Result of a vulnerability check
#[derive(Debug, Clone)]
pub struct VulnCheckResult {
    /// Name of the vulnerability
    pub name: String,
    /// CVE identifier if applicable
    pub cve: Option<String>,
    /// Whether the target is vulnerable
    pub vulnerable: bool,
    /// Severity if vulnerable
    pub severity: Severity,
    /// Detailed description
    pub description: String,
    /// Remediation advice
    pub remediation: String,
    /// Additional evidence/details
    pub evidence: Vec<String>,
}

impl VulnCheckResult {
    pub fn not_vulnerable(name: &str, cve: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            cve: cve.map(|s| s.to_string()),
            vulnerable: false,
            severity: Severity::Info,
            description: format!("Target is not vulnerable to {}", name),
            remediation: String::new(),
            evidence: Vec::new(),
        }
    }

    pub fn vulnerable(name: &str, cve: Option<&str>, severity: Severity, description: &str, remediation: &str) -> Self {
        Self {
            name: name.to_string(),
            cve: cve.map(|s| s.to_string()),
            vulnerable: true,
            severity,
            description: description.to_string(),
            remediation: remediation.to_string(),
            evidence: Vec::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn error(name: &str, error: &str) -> Self {
        Self {
            name: name.to_string(),
            cve: None,
            vulnerable: false,
            severity: Severity::Info,
            description: format!("Check failed: {}", error),
            remediation: String::new(),
            evidence: Vec::new(),
        }
    }
}

/// Trait for vulnerability checkers
pub trait VulnChecker: Send + Sync {
    /// Name of the vulnerability
    fn name(&self) -> &str;

    /// CVE identifier
    fn cve(&self) -> Option<&str>;

    /// Brief description
    fn description(&self) -> &str;

    /// Check if target is vulnerable
    fn check(&self, host: &str, port: u16) -> VulnCheckResult;
}

/// TLS scanner configuration
#[derive(Debug, Clone)]
pub struct TlsScanConfig {
    /// Connection timeout
    pub timeout: Duration,
    /// Number of retries on connection failure
    pub retries: u8,
    /// Verbose output
    pub verbose: bool,
    /// Skip specific checks
    pub skip_checks: Vec<String>,
}

impl Default for TlsScanConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            retries: 2,
            verbose: false,
            skip_checks: Vec::new(),
        }
    }
}

/// Main TLS vulnerability scanner
pub struct TlsVulnScanner {
    config: TlsScanConfig,
    checkers: Vec<Box<dyn VulnChecker>>,
}

impl TlsVulnScanner {
    pub fn new(config: TlsScanConfig) -> Self {
        let mut checkers: Vec<Box<dyn VulnChecker>> = Vec::new();

        // Add all checkers unless skipped
        if !config.skip_checks.contains(&"heartbleed".to_string()) {
            checkers.push(Box::new(HeartbleedChecker::new()));
        }
        if !config.skip_checks.contains(&"poodle".to_string()) {
            checkers.push(Box::new(PoodleChecker::new()));
        }
        if !config.skip_checks.contains(&"beast".to_string()) {
            checkers.push(Box::new(BeastChecker::new()));
        }
        if !config.skip_checks.contains(&"logjam".to_string()) {
            checkers.push(Box::new(LogjamChecker::new()));
        }
        if !config.skip_checks.contains(&"robot".to_string()) {
            checkers.push(Box::new(RobotChecker::new()));
        }
        if !config.skip_checks.contains(&"ccs_injection".to_string()) {
            checkers.push(Box::new(CcsInjectionChecker::new()));
        }
        if !config.skip_checks.contains(&"drown".to_string()) {
            checkers.push(Box::new(DrownChecker::new()));
        }
        if !config.skip_checks.contains(&"ticketbleed".to_string()) {
            checkers.push(Box::new(TicketbleedChecker::new()));
        }
        if !config.skip_checks.contains(&"renegotiation".to_string()) {
            checkers.push(Box::new(RenegotiationChecker::new()));
        }

        Self { config, checkers }
    }

    /// Run all vulnerability checks
    pub fn scan(&self, host: &str, port: u16) -> Vec<VulnCheckResult> {
        let mut results = Vec::new();

        for checker in &self.checkers {
            if self.config.verbose {
                println!("  Checking {}...", checker.name());
            }

            let result = checker.check(host, port);
            results.push(result);
        }

        results
    }

    /// Run only critical vulnerability checks (faster)
    pub fn quick_scan(&self, host: &str, port: u16) -> Vec<VulnCheckResult> {
        let critical_checks = ["Heartbleed", "POODLE", "DROWN"];
        let mut results = Vec::new();

        for checker in &self.checkers {
            if critical_checks.contains(&checker.name()) {
                let result = checker.check(host, port);
                results.push(result);
            }
        }

        results
    }

    /// Get summary of scan results
    pub fn summarize(results: &[VulnCheckResult]) -> ScanSummary {
        let mut summary = ScanSummary::default();

        for result in results {
            summary.total_checks += 1;

            if result.vulnerable {
                summary.vulnerabilities_found += 1;

                match result.severity {
                    Severity::Critical => summary.critical += 1,
                    Severity::High => summary.high += 1,
                    Severity::Medium => summary.medium += 1,
                    Severity::Low => summary.low += 1,
                    Severity::Info => summary.info += 1,
                }
            }
        }

        summary
    }
}

/// Summary of scan results
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    pub total_checks: usize,
    pub vulnerabilities_found: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanSummary {
    pub fn risk_rating(&self) -> &str {
        if self.critical > 0 {
            "CRITICAL"
        } else if self.high > 0 {
            "HIGH"
        } else if self.medium > 0 {
            "MEDIUM"
        } else if self.low > 0 {
            "LOW"
        } else {
            "SECURE"
        }
    }
}

/// Helper function to establish TCP connection with timeout
pub fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let addr = format!("{}:{}", host, port);
    let socket_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .next()
        .ok_or_else(|| "No addresses found".to_string())?;

    let stream = TcpStream::connect_timeout(&socket_addr, timeout)
        .map_err(|e| format!("Connection failed: {}", e))?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;

    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    Ok(stream)
}

/// TLS record types
pub mod tls_types {
    pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
    pub const CONTENT_TYPE_ALERT: u8 = 21;
    pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
    pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
    pub const CONTENT_TYPE_HEARTBEAT: u8 = 24;

    pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
    pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
    pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
    pub const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE: u8 = 12;
    pub const HANDSHAKE_TYPE_SERVER_HELLO_DONE: u8 = 14;

    pub const VERSION_SSL30: [u8; 2] = [0x03, 0x00];
    pub const VERSION_TLS10: [u8; 2] = [0x03, 0x01];
    pub const VERSION_TLS11: [u8; 2] = [0x03, 0x02];
    pub const VERSION_TLS12: [u8; 2] = [0x03, 0x03];

    pub const ALERT_LEVEL_WARNING: u8 = 1;
    pub const ALERT_LEVEL_FATAL: u8 = 2;

    pub const ALERT_DESCRIPTION_CLOSE_NOTIFY: u8 = 0;
    pub const ALERT_DESCRIPTION_UNEXPECTED_MESSAGE: u8 = 10;
    pub const ALERT_DESCRIPTION_BAD_RECORD_MAC: u8 = 20;
    pub const ALERT_DESCRIPTION_HANDSHAKE_FAILURE: u8 = 40;
    pub const ALERT_DESCRIPTION_PROTOCOL_VERSION: u8 = 70;
}

/// Build a minimal ClientHello for testing
pub fn build_client_hello(version: [u8; 2], cipher_suites: &[u16], extensions: &[u8]) -> Vec<u8> {
    let mut hello = Vec::new();

    // Client version
    hello.extend_from_slice(&version);

    // Random (32 bytes)
    hello.extend_from_slice(&[0u8; 32]);

    // Session ID length (0)
    hello.push(0);

    // Cipher suites
    let cs_len = (cipher_suites.len() * 2) as u16;
    hello.push((cs_len >> 8) as u8);
    hello.push(cs_len as u8);
    for cs in cipher_suites {
        hello.push((*cs >> 8) as u8);
        hello.push(*cs as u8);
    }

    // Compression methods (null only)
    hello.push(1); // Length
    hello.push(0); // NULL compression

    // Extensions
    if !extensions.is_empty() {
        hello.push((extensions.len() >> 8) as u8);
        hello.push(extensions.len() as u8);
        hello.extend_from_slice(extensions);
    }

    // Build handshake record
    let mut record = Vec::new();
    record.push(tls_types::HANDSHAKE_TYPE_CLIENT_HELLO);
    record.push(0); // Length high byte
    record.push((hello.len() >> 8) as u8);
    record.push(hello.len() as u8);
    record.extend_from_slice(&hello);

    // Build TLS record
    let mut tls_record = Vec::new();
    tls_record.push(tls_types::CONTENT_TYPE_HANDSHAKE);
    tls_record.extend_from_slice(&version);
    tls_record.push((record.len() >> 8) as u8);
    tls_record.push(record.len() as u8);
    tls_record.extend_from_slice(&record);

    tls_record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_build_client_hello() {
        let ciphers = vec![0x002f, 0x0035]; // AES128-SHA, AES256-SHA
        let hello = build_client_hello(tls_types::VERSION_TLS12, &ciphers, &[]);

        // Check record type
        assert_eq!(hello[0], tls_types::CONTENT_TYPE_HANDSHAKE);
        // Check version
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x03);
    }
}
