/// Secrets Detection Module
///
/// Replaces: gitleaks, trufflehog, detect-secrets, git-secrets
///
/// Features:
/// - Pattern-based secret detection
/// - Entropy analysis
/// - Git history scanning
/// - Multiple output formats
/// - Custom rule support

pub mod patterns;
pub mod scanner;
pub mod entropy;
pub mod git;

pub use scanner::SecretsScanner;
pub use patterns::{SecretPattern, PatternCategory};
pub use entropy::EntropyAnalyzer;

use std::path::PathBuf;

/// A detected secret
#[derive(Debug, Clone)]
pub struct SecretFinding {
    /// Type of secret detected
    pub secret_type: String,
    /// Category of the secret
    pub category: PatternCategory,
    /// The matched content (potentially redacted)
    pub match_text: String,
    /// File where secret was found
    pub file_path: PathBuf,
    /// Line number
    pub line_number: usize,
    /// Column start position
    pub column: usize,
    /// Full line content
    pub line_content: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Severity level
    pub severity: SecretSeverity,
    /// Git commit hash if found in history
    pub commit: Option<String>,
    /// Author if found in git history
    pub author: Option<String>,
    /// Date if found in git history
    pub date: Option<String>,
    /// Additional context
    pub context: Vec<String>,
    /// Is this a false positive?
    pub is_false_positive: bool,
}

impl SecretFinding {
    /// Redact the actual secret value
    pub fn redacted(&self) -> Self {
        let mut finding = self.clone();
        if finding.match_text.len() > 8 {
            let prefix = &finding.match_text[..4];
            let suffix = &finding.match_text[finding.match_text.len() - 4..];
            finding.match_text = format!("{}****{}", prefix, suffix);
        } else {
            finding.match_text = "****".to_string();
        }
        finding
    }
}

/// Severity levels for secrets
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Include files matching these patterns
    pub include_patterns: Vec<String>,
    /// Exclude files matching these patterns
    pub exclude_patterns: Vec<String>,
    /// Maximum file size to scan (bytes)
    pub max_file_size: usize,
    /// Number of threads for scanning
    pub threads: usize,
    /// Scan git history
    pub scan_git_history: bool,
    /// Maximum git commits to scan
    pub max_commits: Option<usize>,
    /// Minimum entropy threshold
    pub entropy_threshold: f64,
    /// Redact secrets in output
    pub redact_secrets: bool,
    /// Categories to scan for
    pub categories: Vec<PatternCategory>,
    /// Custom patterns to include
    pub custom_patterns: Vec<SecretPattern>,
    /// Allow list of patterns to ignore
    pub allow_list: Vec<String>,
    /// Verbose output
    pub verbose: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            include_patterns: vec!["*".to_string()],
            exclude_patterns: vec![
                "*.png".to_string(),
                "*.jpg".to_string(),
                "*.jpeg".to_string(),
                "*.gif".to_string(),
                "*.ico".to_string(),
                "*.svg".to_string(),
                "*.woff".to_string(),
                "*.woff2".to_string(),
                "*.ttf".to_string(),
                "*.eot".to_string(),
                "*.pdf".to_string(),
                "*.zip".to_string(),
                "*.tar".to_string(),
                "*.gz".to_string(),
                "*.rar".to_string(),
                "*.7z".to_string(),
                "*.exe".to_string(),
                "*.dll".to_string(),
                "*.so".to_string(),
                "*.dylib".to_string(),
                "*.pyc".to_string(),
                "*.pyo".to_string(),
                "*.class".to_string(),
                "*.lock".to_string(),
                "package-lock.json".to_string(),
                "yarn.lock".to_string(),
                "Cargo.lock".to_string(),
                "node_modules/*".to_string(),
                ".git/*".to_string(),
                "vendor/*".to_string(),
                "target/*".to_string(),
                "dist/*".to_string(),
                "build/*".to_string(),
            ],
            max_file_size: 1024 * 1024, // 1MB
            threads: 4,
            scan_git_history: false,
            max_commits: Some(100),
            entropy_threshold: 4.0,
            redact_secrets: true,
            categories: vec![
                PatternCategory::ApiKey,
                PatternCategory::PrivateKey,
                PatternCategory::Password,
                PatternCategory::Token,
                PatternCategory::CloudCredential,
                PatternCategory::DatabaseCredential,
            ],
            custom_patterns: Vec::new(),
            allow_list: Vec::new(),
            verbose: false,
        }
    }
}

/// Scan result summary
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    /// Total files scanned
    pub files_scanned: usize,
    /// Total lines scanned
    pub lines_scanned: usize,
    /// Total secrets found
    pub secrets_found: usize,
    /// Findings by severity
    pub by_severity: std::collections::HashMap<SecretSeverity, usize>,
    /// Findings by category
    pub by_category: std::collections::HashMap<PatternCategory, usize>,
    /// Files with secrets
    pub files_with_secrets: Vec<PathBuf>,
    /// Scan duration
    pub duration: std::time::Duration,
    /// Git commits scanned (if applicable)
    pub commits_scanned: usize,
}

impl ScanSummary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_finding(&mut self, finding: &SecretFinding) {
        self.secrets_found += 1;

        *self.by_severity.entry(finding.severity).or_insert(0) += 1;
        *self.by_category.entry(finding.category).or_insert(0) += 1;

        if !self.files_with_secrets.contains(&finding.file_path) {
            self.files_with_secrets.push(finding.file_path.clone());
        }
    }

    /// Risk rating based on findings
    pub fn risk_rating(&self) -> &str {
        let critical = *self.by_severity.get(&SecretSeverity::Critical).unwrap_or(&0);
        let high = *self.by_severity.get(&SecretSeverity::High).unwrap_or(&0);
        let medium = *self.by_severity.get(&SecretSeverity::Medium).unwrap_or(&0);

        if critical > 0 {
            "CRITICAL"
        } else if high > 0 {
            "HIGH"
        } else if medium > 0 {
            "MEDIUM"
        } else if self.secrets_found > 0 {
            "LOW"
        } else {
            "CLEAN"
        }
    }
}

/// Output format for scan results
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// SARIF format for CI/CD integration
    Sarif,
    /// CSV format
    Csv,
    /// JUnit XML format
    JUnit,
}
