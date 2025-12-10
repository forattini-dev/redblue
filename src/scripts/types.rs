/// Script Types and Definitions
///
/// Core types for redblue's scripting engine.
/// Scripts are declarative security checks that can be:
/// - Compiled Rust modules (fast, type-safe)
/// - TOML-defined scripts (flexible, no recompilation)
///
/// ## Script Categories
/// - `vuln`: Vulnerability detection scripts
/// - `discovery`: Service/host discovery scripts
/// - `default`: Safe scripts run by default
/// - `safe`: Non-intrusive, read-only scripts
/// - `intrusive`: May cause service disruption
/// - `exploit`: Active exploitation (requires explicit consent)

use std::collections::HashMap;
use std::time::Duration;

/// Script category for filtering and safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptCategory {
    /// Vulnerability detection (CVE checks, misconfigurations)
    Vuln,
    /// Service and host discovery
    Discovery,
    /// Safe scripts that don't modify anything
    Safe,
    /// Scripts run by default (subset of safe)
    Default,
    /// May cause service disruption
    Intrusive,
    /// Active exploitation (requires --exploit flag)
    Exploit,
    /// Brute force attacks (requires explicit consent)
    Brute,
    /// Authentication testing
    Auth,
    /// Denial of service (never run without explicit flag)
    Dos,
    /// Information gathering
    Info,
    /// Fuzzing scripts
    Fuzz,
    /// Malware/backdoor detection
    Malware,
    /// Version detection
    Version,
    /// Banner grabbing
    Banner,
}

impl ScriptCategory {
    /// Check if category is considered safe
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            ScriptCategory::Safe
                | ScriptCategory::Default
                | ScriptCategory::Discovery
                | ScriptCategory::Info
                | ScriptCategory::Version
                | ScriptCategory::Banner
        )
    }

    /// Check if category requires explicit consent
    pub fn requires_consent(&self) -> bool {
        matches!(
            self,
            ScriptCategory::Intrusive
                | ScriptCategory::Exploit
                | ScriptCategory::Brute
                | ScriptCategory::Dos
        )
    }

    /// Parse category from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "vuln" | "vulnerability" => Some(ScriptCategory::Vuln),
            "discovery" | "discover" => Some(ScriptCategory::Discovery),
            "safe" => Some(ScriptCategory::Safe),
            "default" => Some(ScriptCategory::Default),
            "intrusive" => Some(ScriptCategory::Intrusive),
            "exploit" => Some(ScriptCategory::Exploit),
            "brute" | "bruteforce" => Some(ScriptCategory::Brute),
            "auth" | "authentication" => Some(ScriptCategory::Auth),
            "dos" | "denial" => Some(ScriptCategory::Dos),
            "info" | "information" => Some(ScriptCategory::Info),
            "fuzz" | "fuzzing" => Some(ScriptCategory::Fuzz),
            "malware" => Some(ScriptCategory::Malware),
            "version" => Some(ScriptCategory::Version),
            "banner" => Some(ScriptCategory::Banner),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScriptCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptCategory::Vuln => write!(f, "vuln"),
            ScriptCategory::Discovery => write!(f, "discovery"),
            ScriptCategory::Safe => write!(f, "safe"),
            ScriptCategory::Default => write!(f, "default"),
            ScriptCategory::Intrusive => write!(f, "intrusive"),
            ScriptCategory::Exploit => write!(f, "exploit"),
            ScriptCategory::Brute => write!(f, "brute"),
            ScriptCategory::Auth => write!(f, "auth"),
            ScriptCategory::Dos => write!(f, "dos"),
            ScriptCategory::Info => write!(f, "info"),
            ScriptCategory::Fuzz => write!(f, "fuzz"),
            ScriptCategory::Malware => write!(f, "malware"),
            ScriptCategory::Version => write!(f, "version"),
            ScriptCategory::Banner => write!(f, "banner"),
        }
    }
}

/// Script metadata
#[derive(Debug, Clone)]
pub struct ScriptMetadata {
    /// Unique script identifier (e.g., "http-vuln-cve2021-44228")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Author
    pub author: String,
    /// Version string
    pub version: String,
    /// Description
    pub description: String,
    /// Categories this script belongs to
    pub categories: Vec<ScriptCategory>,
    /// Target protocols/services (e.g., ["http", "https"])
    pub protocols: Vec<String>,
    /// Target port numbers (empty = any)
    pub ports: Vec<u16>,
    /// License
    pub license: String,
    /// CVE identifiers if applicable
    pub cves: Vec<String>,
    /// References/URLs
    pub references: Vec<String>,
}

impl Default for ScriptMetadata {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            author: "redblue".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            categories: vec![ScriptCategory::Safe],
            protocols: Vec::new(),
            ports: Vec::new(),
            license: "MIT".to_string(),
            cves: Vec::new(),
            references: Vec::new(),
        }
    }
}

/// Script execution context
#[derive(Debug, Clone)]
pub struct ScriptContext {
    /// Target host
    pub host: String,
    /// Target port
    pub port: u16,
    /// Protocol detected/assumed
    pub protocol: String,
    /// Timeout for operations
    pub timeout: Duration,
    /// Previously gathered data (banner, headers, etc.)
    pub data: HashMap<String, String>,
    /// Arguments passed to script
    pub args: HashMap<String, String>,
    /// Verbosity level (0-3)
    pub verbosity: u8,
    /// Whether intrusive actions are allowed
    pub allow_intrusive: bool,
}

impl ScriptContext {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            protocol: String::new(),
            timeout: Duration::from_secs(10),
            data: HashMap::new(),
            args: HashMap::new(),
            verbosity: 1,
            allow_intrusive: false,
        }
    }

    /// Set a data value
    pub fn set_data(&mut self, key: &str, value: &str) {
        self.data.insert(key.to_string(), value.to_string());
    }

    /// Get a data value
    pub fn get_data(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(|s| s.as_str())
    }

    /// Set an argument
    pub fn set_arg(&mut self, key: &str, value: &str) {
        self.args.insert(key.to_string(), value.to_string());
    }

    /// Get an argument
    pub fn get_arg(&self, key: &str) -> Option<&str> {
        self.args.get(key).map(|s| s.as_str())
    }
}

/// Script execution result
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// Script ID
    pub script_id: String,
    /// Whether the script found something
    pub success: bool,
    /// Result status
    pub status: ScriptStatus,
    /// Output lines
    pub output: Vec<String>,
    /// Structured findings
    pub findings: Vec<Finding>,
    /// Extracted data (for use by other scripts)
    pub extracted: HashMap<String, String>,
    /// Execution time
    pub duration: Duration,
}

impl ScriptResult {
    pub fn new(script_id: &str) -> Self {
        Self {
            script_id: script_id.to_string(),
            success: false,
            status: ScriptStatus::NotRun,
            output: Vec::new(),
            findings: Vec::new(),
            extracted: HashMap::new(),
            duration: Duration::ZERO,
        }
    }

    /// Create a success result
    pub fn success(script_id: &str) -> Self {
        Self {
            script_id: script_id.to_string(),
            success: true,
            status: ScriptStatus::Completed,
            output: Vec::new(),
            findings: Vec::new(),
            extracted: HashMap::new(),
            duration: Duration::ZERO,
        }
    }

    /// Create a failure result
    pub fn failure(script_id: &str, reason: &str) -> Self {
        Self {
            script_id: script_id.to_string(),
            success: false,
            status: ScriptStatus::Failed,
            output: vec![reason.to_string()],
            findings: Vec::new(),
            extracted: HashMap::new(),
            duration: Duration::ZERO,
        }
    }

    /// Add an output line
    pub fn add_output(&mut self, line: &str) {
        self.output.push(line.to_string());
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Extract data for subsequent scripts
    pub fn extract(&mut self, key: &str, value: &str) {
        self.extracted.insert(key.to_string(), value.to_string());
    }
}

/// Script execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptStatus {
    /// Script hasn't run yet
    NotRun,
    /// Script is running
    Running,
    /// Script completed successfully
    Completed,
    /// Script failed with error
    Failed,
    /// Script was skipped (precondition not met)
    Skipped,
    /// Script timed out
    Timeout,
    /// Script was aborted by user
    Aborted,
}

impl std::fmt::Display for ScriptStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptStatus::NotRun => write!(f, "NOT_RUN"),
            ScriptStatus::Running => write!(f, "RUNNING"),
            ScriptStatus::Completed => write!(f, "COMPLETED"),
            ScriptStatus::Failed => write!(f, "FAILED"),
            ScriptStatus::Skipped => write!(f, "SKIPPED"),
            ScriptStatus::Timeout => write!(f, "TIMEOUT"),
            ScriptStatus::Aborted => write!(f, "ABORTED"),
        }
    }
}

/// A finding from a script
#[derive(Debug, Clone)]
pub struct Finding {
    /// Finding type
    pub finding_type: FindingType,
    /// Severity
    pub severity: FindingSeverity,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Evidence
    pub evidence: Vec<String>,
    /// Remediation advice
    pub remediation: Option<String>,
    /// CVE if applicable
    pub cve: Option<String>,
    /// CVSS score if known
    pub cvss: Option<f32>,
    /// Confidence (0.0 - 1.0)
    pub confidence: f32,
}

impl Finding {
    pub fn new(finding_type: FindingType, title: &str) -> Self {
        Self {
            finding_type,
            severity: FindingSeverity::Info,
            title: title.to_string(),
            description: String::new(),
            evidence: Vec::new(),
            remediation: None,
            cve: None,
            cvss: None,
            confidence: 1.0,
        }
    }

    pub fn with_severity(mut self, severity: FindingSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_evidence(mut self, evidence: &str) -> Self {
        self.evidence.push(evidence.to_string());
        self
    }

    pub fn with_cve(mut self, cve: &str) -> Self {
        self.cve = Some(cve.to_string());
        self
    }

    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

/// Finding type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingType {
    /// Vulnerability found
    Vulnerability,
    /// Service/version discovered
    Discovery,
    /// Configuration issue
    Misconfiguration,
    /// Information disclosure
    InfoLeak,
    /// Credentials found
    Credential,
    /// Software version
    Version,
    /// General information
    Info,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::Vulnerability => write!(f, "VULN"),
            FindingType::Discovery => write!(f, "DISCOVERY"),
            FindingType::Misconfiguration => write!(f, "MISCONFIG"),
            FindingType::InfoLeak => write!(f, "INFO_LEAK"),
            FindingType::Credential => write!(f, "CREDENTIAL"),
            FindingType::Version => write!(f, "VERSION"),
            FindingType::Info => write!(f, "INFO"),
        }
    }
}

/// Finding severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => FindingSeverity::Critical,
            s if s >= 7.0 => FindingSeverity::High,
            s if s >= 4.0 => FindingSeverity::Medium,
            s if s >= 0.1 => FindingSeverity::Low,
            _ => FindingSeverity::Info,
        }
    }
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Info => write!(f, "INFO"),
            FindingSeverity::Low => write!(f, "LOW"),
            FindingSeverity::Medium => write!(f, "MEDIUM"),
            FindingSeverity::High => write!(f, "HIGH"),
            FindingSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Script argument definition
#[derive(Debug, Clone)]
pub struct ScriptArg {
    /// Argument name
    pub name: String,
    /// Description
    pub description: String,
    /// Default value
    pub default: Option<String>,
    /// Whether required
    pub required: bool,
}

impl ScriptArg {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            default: None,
            required: false,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn with_default(mut self, default: &str) -> Self {
        self.default = Some(default.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_safety() {
        assert!(ScriptCategory::Safe.is_safe());
        assert!(ScriptCategory::Default.is_safe());
        assert!(ScriptCategory::Discovery.is_safe());
        assert!(!ScriptCategory::Intrusive.is_safe());
        assert!(!ScriptCategory::Exploit.is_safe());
    }

    #[test]
    fn test_category_consent() {
        assert!(!ScriptCategory::Safe.requires_consent());
        assert!(ScriptCategory::Intrusive.requires_consent());
        assert!(ScriptCategory::Exploit.requires_consent());
        assert!(ScriptCategory::Dos.requires_consent());
    }

    #[test]
    fn test_category_parsing() {
        assert_eq!(ScriptCategory::from_str("vuln"), Some(ScriptCategory::Vuln));
        assert_eq!(ScriptCategory::from_str("VULN"), Some(ScriptCategory::Vuln));
        assert_eq!(ScriptCategory::from_str("exploit"), Some(ScriptCategory::Exploit));
        assert_eq!(ScriptCategory::from_str("unknown"), None);
    }

    #[test]
    fn test_script_result() {
        let mut result = ScriptResult::new("test-script");
        result.add_output("Found something");
        result.add_finding(Finding::new(FindingType::Info, "Test finding"));
        result.extract("version", "1.0.0");

        assert_eq!(result.output.len(), 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.extracted.get("version"), Some(&"1.0.0".to_string()));
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(FindingSeverity::from_cvss(9.5), FindingSeverity::Critical);
        assert_eq!(FindingSeverity::from_cvss(7.5), FindingSeverity::High);
        assert_eq!(FindingSeverity::from_cvss(5.0), FindingSeverity::Medium);
        assert_eq!(FindingSeverity::from_cvss(2.0), FindingSeverity::Low);
        assert_eq!(FindingSeverity::from_cvss(0.0), FindingSeverity::Info);
    }
}
