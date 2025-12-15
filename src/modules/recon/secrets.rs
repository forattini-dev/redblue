//! Secrets detection in recon context
//!
//! Wraps collection::secrets module with additional types for recon CLI.
//! Adds URL scanning capability for web reconnaissance.

pub use crate::modules::collection::secrets::{SecretFinding, SecretRule, SecretScanner};
use crate::protocols::http::HttpClient;

/// Secret severity levels for classification
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretSeverity::Critical => write!(f, "CRITICAL"),
            SecretSeverity::High => write!(f, "HIGH"),
            SecretSeverity::Medium => write!(f, "MEDIUM"),
            SecretSeverity::Low => write!(f, "LOW"),
        }
    }
}

/// Web-focused secret finding with severity
#[derive(Debug, Clone)]
pub struct WebSecretFinding {
    /// Type of secret found
    pub secret_type: String,
    /// Severity level
    pub severity: SecretSeverity,
    /// The matched content (truncated)
    pub matched: String,
    /// Source URL
    pub location: String,
    /// Line number
    pub line: Option<usize>,
    /// Context around the match
    pub context: Option<String>,
    /// Pattern name
    pub pattern_name: String,
}

/// Secrets scanner for URL content
pub struct SecretsScanner {
    http_client: HttpClient,
    file_scanner: SecretScanner,
}

impl SecretsScanner {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new(),
            file_scanner: SecretScanner::new(),
        }
    }

    /// Scan a URL for secrets in the response body
    pub fn scan_url(&self, url: &str) -> Result<Vec<WebSecretFinding>, String> {
        let response = self
            .http_client
            .get(url)
            .map_err(|e| format!("Failed to fetch URL: {}", e))?;

        let content = String::from_utf8_lossy(&response.body);
        self.scan_content(&content, url)
    }

    /// Scan text content for secrets
    pub fn scan_content(
        &self,
        content: &str,
        location: &str,
    ) -> Result<Vec<WebSecretFinding>, String> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_findings = self
                .file_scanner
                .scan_line_internal(location, line_num + 1, line);
            for finding in line_findings {
                let severity = Self::classify_severity(&finding.rule_id);
                findings.push(WebSecretFinding {
                    secret_type: finding.description.clone(),
                    severity,
                    matched: Self::truncate_secret(&finding.secret),
                    location: location.to_string(),
                    line: finding.line,
                    context: Some(Self::truncate_line(&finding.line_content, 100)),
                    pattern_name: finding.rule_id,
                });
            }
        }

        // Deduplicate by matched content
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| seen.insert(f.matched.clone()));

        // Sort by severity (critical first)
        findings.sort_by(|a, b| a.severity.cmp(&b.severity));

        Ok(findings)
    }

    fn classify_severity(rule_id: &str) -> SecretSeverity {
        match rule_id {
            "private-key" | "aws-secret-access-key" | "database-connection" => {
                SecretSeverity::Critical
            }
            "aws-access-key-id" | "github-token" | "slack-token" | "jwt-token" => {
                SecretSeverity::High
            }
            "generic-api-key" | "generic-secret" | "bearer-token" | "oauth-token" => {
                SecretSeverity::Medium
            }
            "password" | _ => SecretSeverity::Low,
        }
    }

    fn truncate_secret(secret: &str) -> String {
        if secret.len() <= 20 {
            secret.to_string()
        } else {
            let prefix = &secret[..8];
            let suffix = &secret[secret.len() - 4..];
            format!("{}...{}", prefix, suffix)
        }
    }

    fn truncate_line(line: &str, max_len: usize) -> String {
        if line.len() <= max_len {
            line.to_string()
        } else {
            format!("{}...", &line[..max_len])
        }
    }
}

impl Default for SecretsScanner {
    fn default() -> Self {
        Self::new()
    }
}
