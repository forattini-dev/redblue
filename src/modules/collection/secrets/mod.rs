#![allow(dead_code)]

pub mod archive;
pub mod config;
pub mod decoding;
pub mod git_scanner;
pub mod verifiers;

use config::SecretsConfig;
/// Secret detection module (Gitleaks replacement)
///
/// Detects secrets, API keys, tokens, and credentials in code using:
/// - Pattern-based detection (regex)
/// - Shannon entropy analysis
/// - Recursive file scanning
/// - False positive filtering
///
/// NO external dependencies - pure Rust std implementation
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

struct HighRiskFile {
    rule_id: &'static str,
    description: String,
    secret_label: String,
    skip_text_scan: bool,
}

#[derive(Debug, Clone)]
pub struct SecretRule {
    pub id: String,
    pub description: String,
    pub pattern: String,
    pub min_entropy: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub file: String,
    pub line: Option<usize>,
    pub column: usize,
    pub rule_id: String,
    pub description: String,
    pub secret: String,
    pub severity: SecretSeverity,
    pub entropy: Option<f64>,
    pub pattern_name: String,
    pub matched: String,
    pub line_content: String,
    pub secret_type: String, // For compatibility with existing code
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecretSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct SecretScanner {
    rules: Vec<SecretRule>,
    min_entropy: f64,
    max_file_size: usize,
    exclude_patterns: Vec<String>,
    exclude_dirs: Vec<String>,
    allowlist: HashSet<String>, // Added allowlist field
}

impl SecretScanner {
    pub fn new() -> Self {
        Self::from_config(SecretsConfig::default()) // Use default config
    }

    pub fn from_config(cfg: SecretsConfig) -> Self {
        let rules = if let Some(path) = cfg.rules_path {
            // Placeholder for loading custom rules from file
            println!(
                "Warning: Custom rules loading from {} not yet implemented. Using default rules.",
                path
            );
            Self::default_rules()
        } else {
            Self::default_rules()
        };

        Self {
            rules,
            min_entropy: cfg.min_entropy.unwrap_or(3.5),
            max_file_size: cfg.max_file_size_mb.unwrap_or(10) * 1024 * 1024,
            exclude_patterns: cfg.exclude_patterns.clone(),
            exclude_dirs: cfg.exclude_dirs.clone(),
            allowlist: cfg.allowlist.into_iter().collect(),
        }
    }

    /// Set an allowlist of secrets to ignore
    pub fn with_allowlist(mut self, allowlist: HashSet<String>) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Default secret detection rules (Gitleaks-inspired)
    fn default_rules() -> Vec<SecretRule> {
        vec![
            // --- Cloud Provider Credentials ---
            SecretRule {
                id: "aws-access-key-id".to_string(),
                description: "AWS Access Key ID".to_string(),
                pattern: r"AKIA[0-9A-Z]{16}".to_string(),
                min_entropy: Some(3.0),
            },
            SecretRule {
                id: "aws-secret-access-key".to_string(),
                description: "AWS Secret Access Key".to_string(),
                pattern: r#"aws[_\-]?secret[_\-]?access[_\-]?key["'\s:=]+([a-zA-Z0-9/+]{40})"#.to_string(),
                min_entropy: Some(4.5),
            },
            SecretRule {
                id: "aws-session-token".to_string(),
                description: "AWS Session Token".to_string(),
                pattern: r#"aws[_\-]?session[_\-]?token["'\s:=]+(T?KID[a-zA-Z0-9]{20,})"#.to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "azure-client-secret".to_string(),
                description: "Azure Client Secret".to_string(),
                pattern: r#"(Azure|AZURE)[\s_.-]?(Client|CLIENT)[\s_.-]?(Secret|SECRET)[\s:=]+([a-zA-Z0-9\-_~.]{43})"#.to_string(),
                min_entropy: Some(4.0),
            },
            // --- Source Code & Version Control ---
            SecretRule {
                id: "github-token".to_string(),
                description: "GitHub Personal Access Token".to_string(),
                pattern: r"gh[pousr]_[A-Za-z0-9_]{36}".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "github-oauth-access-token".to_string(),
                description: "GitHub OAuth Access Token".to_string(),
                pattern: r"gho_[A-Za-z0-9_]{36}".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "gitlab-personal-access-token".to_string(),
                description: "GitLab Personal Access Token".to_string(),
                pattern: r"glpat-[a-zA-Z0-9\-]{20}".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "gitlab-private-token".to_string(),
                description: "GitLab Private Token".to_string(),
                pattern: r"[a-f0-9]{20}".to_string(), // General 20-char hex for now
                min_entropy: Some(4.0),
            },
            // --- Communication & Collaboration ---
            SecretRule {
                id: "slack-token".to_string(),
                description: "Slack Bot/User Token".to_string(),
                pattern: r"(xoxb|xoxp|xapp|xoxa|xoxr)-[0-9]{10,12}-[0-9]{10,12}(-[a-zA-Z0-9]{10,})?".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "slack-webhook".to_string(),
                description: "Slack Webhook URL".to_string(),
                pattern: r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}".to_string(),
                min_entropy: None,
            },
            // --- API Keys & Generic Tokens ---
            SecretRule {
                id: "generic-api-key".to_string(),
                description: "Generic API Key".to_string(),
                pattern: r"(api|API)[-_]?(key|KEY)[\s:=]+([a-zA-Z0-9\-_]{20,})".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "jwt-token".to_string(),
                description: "JSON Web Token (JWT)".to_string(),
                pattern: r"ey[A-Za-z0-9-_]+\.ey[A-Za-z0-9-_]+\.ey[A-Za-z0-9-_]+".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "bearer-token".to_string(),
                description: "Bearer Token".to_string(),
                pattern: r"Bearer\s+([a-zA-Z0-9-._~+/]{20,})".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "oauth-token".to_string(),
                description: "OAuth Token".to_string(),
                pattern: r"(oauth|OAuth)[-_]?(token|TOKEN)[\s:=]+([a-zA-Z0-9_.-]{30,})".to_string(),
                min_entropy: Some(4.0),
            },
            // --- Database & Connection Strings ---
            SecretRule {
                id: "database-connection-string".to_string(),
                description: "Database Connection String".to_string(),
                pattern: r#"(postgres|mysql|mongodb|redis|amqp|jdbc)://[^\s"']+"#.to_string(),
                min_entropy: None,
            },
            SecretRule {
                id: "ssh-private-key".to_string(),
                description: "SSH Private Key".to_string(),
                pattern: r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----".to_string(),
                min_entropy: None,
            },
            SecretRule {
                id: "pgp-private-key".to_string(),
                description: "PGP Private Key Block".to_string(),
                pattern: r"-----BEGIN PGP PRIVATE KEY BLOCK-----".to_string(),
                min_entropy: None,
            },
            // --- Generic Passwords ---
            SecretRule {
                id: "password-in-url".to_string(),
                description: "Password found in URL".to_string(),
                pattern: r"(username|user|pass|password|pwd)=([a-zA-Z0-9!@#$%^&*()_+=\-]{6,})".to_string(),
                min_entropy: None,
            },
            // --- Other Specifics ---
            SecretRule {
                id: "stripe-api-key".to_string(),
                description: "Stripe API Key".to_string(),
                pattern: r"sk_live_[0-9a-zA-Z]{24}".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "twilio-api-key".to_string(),
                description: "Twilio API Key".to_string(),
                pattern: r"SK[0-9a-fA-F]{32}".to_string(),
                min_entropy: Some(4.0),
            },
            SecretRule {
                id: "sentry-dsn".to_string(),
                description: "Sentry DSN (Data Source Name)".to_string(),
                pattern: r"https:\/\/[0-9a-fA-F]{32}@sentry\.io\/[0-9]+".to_string(),
                min_entropy: None,
            },
            // Placeholder for many more rules for "trufflehog parity"
            // True parity would involve loading a large list of patterns from a file
            // and a more sophisticated regex engine.
        ]
    }

    /// File patterns to exclude from scanning
    fn default_excludes() -> Vec<String> {
        vec![
            r"\.min\.js$".to_string(),
            r"\.map$".to_string(),
            r"\.lock$".to_string(),
            r"package-lock\.json$".to_string(),
            r"yarn\.lock$".to_string(),
            r"Cargo\.lock$".to_string(),
            r"\.png$".to_string(),
            r"\.jpg$".to_string(),
            r"\.jpeg$".to_string(),
            r"\.gif$".to_string(),
            r"\.svg$".to_string(),
            r"\.pdf$".to_string(),
            r"\.zip$".to_string(),
            r"\.tar$".to_string(),
            r"\.gz$".to_string(),
        ]
    }

    /// Scan a directory recursively for secrets
    pub fn scan_directory(&self, path: &str) -> Result<Vec<SecretFinding>, String> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(format!("Path does not exist: {}", path.display()));
        }

        let mut findings = Vec::new();
        self.scan_dir_recursive(path, &mut findings)?;

        Ok(findings)
    }

    /// Recursive directory scanning
    fn scan_dir_recursive(
        &self,
        dir: &Path,
        findings: &mut Vec<SecretFinding>,
    ) -> Result<(), String> {
        let entries = fs::read_dir(dir)
            .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let path = entry.path();

            // Skip excluded directories
            if path.is_dir() {
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                if self.exclude_dirs.contains(&dir_name.to_string()) {
                    continue;
                }

                self.scan_dir_recursive(&path, findings)?;
            } else if path.is_file() {
                // Skip excluded file patterns
                let file_name = path.to_str().unwrap_or("");
                if self.should_exclude_file(file_name) {
                    continue;
                }

                // Skip large files
                if let Ok(metadata) = fs::metadata(&path) {
                    if metadata.len() > self.max_file_size as u64 {
                        continue;
                    }
                }

                // Scan the file
                if let Ok(file_findings) = self.scan_file(&path) {
                    findings.extend(file_findings);
                }
            }
        }

        Ok(())
    }

    /// Check if file should be excluded based on patterns
    fn should_exclude_file(&self, filename: &str) -> bool {
        for pattern in &self.exclude_patterns {
            if self.simple_regex_match(pattern, filename) {
                return true;
            }
        }
        false
    }

    /// Simple regex matching (basic implementation)
    fn simple_regex_match(&self, pattern: &str, text: &str) -> bool {
        let mut clean_pattern = pattern.to_string();
        let mut check_end = false;

        if clean_pattern.ends_with('$') {
            check_end = true;
            clean_pattern.pop();
        }

        // Replace all escaped dots with literal dots
        let clean_pattern = clean_pattern.replace(r"\.", ".");

        if check_end {
            text.ends_with(&clean_pattern)
        } else {
            text.contains(&clean_pattern)
        }
    }

    /// Scan a single file for secrets
    pub fn scan_file(&self, path: &Path) -> Result<Vec<SecretFinding>, String> {
        let file = fs::File::open(path)
            .map_err(|e| format!("Failed to open file {}: {}", path.display(), e))?;

        let reader = BufReader::new(file);
        let mut findings = Vec::new();
        let file_path = path.to_str().unwrap_or("unknown");

        if let Some(risk) = Self::classify_high_risk_file(path) {
            findings.push(SecretFinding {
                file: file_path.to_string(),
                line: None, // No specific line for binary match
                column: 0,
                rule_id: risk.rule_id.to_string(),
                description: risk.description,
                secret: risk.secret_label,
                severity: SecretSeverity::High,
                entropy: None,
                pattern_name: risk.rule_id.to_string(),
                matched: "BINARY FILE".to_string(),
                line_content: "<binary>".to_string(),
                secret_type: "High Risk File".to_string(),
            });

            if risk.skip_text_scan {
                return Ok(findings);
            }
        }

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => continue, // Skip binary lines
            };

            let line_findings = self.scan_line(file_path, line_num + 1, &line);
            findings.extend(line_findings);
        }

        Ok(findings)
    }

    /// Scan a single line for secrets (public wrapper for URL scanning)
    pub fn scan_line_internal(
        &self,
        file_path: &str,
        line_num: usize,
        line: &str,
    ) -> Vec<SecretFinding> {
        self.scan_line(file_path, line_num, line)
    }

    /// Scan a single line for secrets
    fn scan_line(&self, file_path: &str, line_num: usize, line: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        // Check for ignore comments like 'gitleaks:allow' or 'redblue:ignore'
        if line.contains("gitleaks:allow") || line.contains("redblue:ignore") {
            return findings; // Skip scanning this line if ignore comment is present
        }

        for rule in &self.rules {
            if let Some(matches) = self.pattern_match(&rule.pattern, line) {
                for (col, secret) in matches {
                    // Check against allowlist
                    if self.allowlist.contains(&secret) {
                        continue;
                    }

                    // Calculate entropy if required
                    let entropy = if rule.min_entropy.is_some() {
                        Some(Self::calculate_entropy(&secret))
                    } else {
                        None
                    };

                    // Check minimum entropy threshold
                    if let Some(min_entropy) = rule.min_entropy {
                        if let Some(ent) = entropy {
                            if ent < min_entropy {
                                continue; // Skip low-entropy matches
                            }
                        }
                    }

                    // Filter false positives
                    if self.is_false_positive(&secret) {
                        continue;
                    }

                    findings.push(SecretFinding {
                        file: file_path.to_string(),
                        line: Some(line_num),
                        column: col,
                        rule_id: rule.id.clone(),
                        description: rule.description.clone(),
                        secret: secret.clone(),
                        severity: SecretSeverity::High,
                        entropy,
                        pattern_name: rule.id.clone(),
                        matched: secret.clone(),
                        line_content: line.to_string(),
                        secret_type: rule.description.clone(),
                    });
                }
            }
        }

        findings
    }

    fn classify_high_risk_file(path: &Path) -> Option<HighRiskFile> {
        let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
        let path_lower = path.to_str().unwrap_or("").to_ascii_lowercase();

        if path_lower.ends_with(".tar.gz") || path_lower.ends_with(".tgz") {
            return Some(HighRiskFile {
                rule_id: "archive-backup",
                description:
                    "Compressed archive detected (tar.gz/tgz). Inspect for database or credential backups."
                        .to_string(),
                secret_label: file_name,
                skip_text_scan: true,
            });
        }

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase());

        match extension.as_deref() {
            Some("zip") | Some("rar") | Some("7z") | Some("gz") => Some(HighRiskFile {
                rule_id: "archive-backup",
                description:
                    "Compressed archive detected. Ensure sensitive exports are stored securely."
                        .to_string(),
                secret_label: file_name,
                skip_text_scan: true,
            }),
            Some("sqlite") | Some("db") | Some("rdb") | Some("realm") | Some("mdb") => {
                Some(HighRiskFile {
                    rule_id: "database-dump",
                    description:
                        "Database file detected. These often contain credentials or PII."
                            .to_string(),
                    secret_label: file_name,
                    skip_text_scan: true,
                })
            }
            Some("bak") | Some("backup") => Some(HighRiskFile {
                rule_id: "config-backup",
                description:
                    "Backup file detected (.bak). Review contents for embedded secrets."
                        .to_string(),
                secret_label: file_name,
                skip_text_scan: false,
            }),
            Some("sql") | Some("dump") => Some(HighRiskFile {
                rule_id: "database-dump",
                description:
                    "Database dump detected (.sql/.dump). Check for credential or user data exposure."
                        .to_string(),
                secret_label: file_name,
                skip_text_scan: false,
            }),
            Some("env") if file_name.contains("backup") || file_name.contains("bak") => {
                Some(HighRiskFile {
                    rule_id: "config-backup",
                    description:
                        "Environment file backup detected. Ensure secret copies are removed."
                            .to_string(),
                    secret_label: file_name,
                    skip_text_scan: false,
                })
            }
            _ => {
                if file_name.contains(".env.") && (file_name.contains("bak") || file_name.contains("backup")) {
                    return Some(HighRiskFile {
                        rule_id: "config-backup",
                        description:
                            "Environment file backup detected. Remove stale copies of secrets."
                                .to_string(),
                        secret_label: file_name,
                        skip_text_scan: false,
                    });
                }

                if file_name.ends_with(".env.enc") {
                    return Some(HighRiskFile {
                        rule_id: "encrypted-env",
                        description:
                            "Encrypted environment file detected (.env.enc). Protect decryption keys."
                                .to_string(),
                        secret_label: file_name,
                        skip_text_scan: false,
                    });
                }

                None
            }
        }
    }

    /// Basic pattern matching (simplified regex)
    fn pattern_match(&self, pattern: &str, text: &str) -> Option<Vec<(usize, String)>> {
        let mut matches = Vec::new();

        // Handle AWS Access Key ID pattern
        if pattern.contains("AKIA") {
            for (i, _) in text.match_indices("AKIA") {
                if let Some(candidate) = text.get(i..i + 20) {
                    if candidate
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    {
                        matches.push((i, candidate.to_string()));
                    }
                }
            }
        }

        // Handle JWT pattern
        if pattern.contains("eyJ") {
            for (i, _) in text.match_indices("eyJ") {
                // Find the full JWT token
                let rest = &text[i..];
                if let Some(end) = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
                    let candidate = &rest[..end];
                    let parts: Vec<&str> = candidate.split('.').collect();
                    if parts.len() == 3 && parts.iter().all(|p| p.len() > 10) {
                        matches.push((i, candidate.to_string()));
                    }
                } else if rest.len() > 50 {
                    // Token might extend to end of line
                    let parts: Vec<&str> = rest.split('.').collect();
                    if parts.len() == 3 {
                        matches.push((i, rest.to_string()));
                    }
                }
            }
        }

        // Handle GitHub token pattern
        if pattern.contains("gh[pousr]") {
            for prefix in &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
                for (i, _) in text.match_indices(prefix) {
                    if let Some(candidate) = text.get(i..i + 40) {
                        if candidate.chars().skip(4).all(|c| c.is_ascii_alphanumeric()) {
                            matches.push((i, candidate.to_string()));
                        }
                    }
                }
            }
        }

        // Handle Slack webhook pattern
        if pattern.contains("hooks.slack.com") {
            if let Some(idx) = text.find("https://hooks.slack.com/services/") {
                let rest = &text[idx..];
                if let Some(end) = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
                    matches.push((idx, rest[..end].to_string()));
                }
            }
        }

        // Handle private key pattern
        if pattern.contains("BEGIN") && pattern.contains("PRIVATE KEY") {
            if let Some(idx) = text.find("-----BEGIN") {
                if text[idx..].contains("PRIVATE KEY-----") {
                    matches.push((idx, "-----BEGIN PRIVATE KEY-----".to_string()));
                }
            }
        }

        // Handle generic key=value patterns (api_key, secret, password, etc.)
        if pattern.contains("[\"'\\s:=]+") {
            let keywords = vec![
                ("api_key", "api[_\\-]?key"),
                ("api-key", "api[_\\-]?key"),
                ("apikey", "api[_\\-]?key"),
                ("secret", "secret"),
                ("password", "password"),
                ("bearer", "bearer\\s+"),
                ("oauth_token", "oauth[_\\-]?token"),
                ("oauth-token", "oauth[_\\-]?token"),
            ];

            for (keyword, _) in keywords {
                if pattern.to_lowercase().contains(keyword) {
                    if let Some(matches_for_keyword) = self.extract_key_value(text, keyword) {
                        matches.extend(matches_for_keyword);
                    }
                }
            }
        }

        // Handle database connection strings
        if pattern.contains("postgres") || pattern.contains("mysql") || pattern.contains("mongodb")
        {
            for proto in &["postgres://", "mysql://", "mongodb://"] {
                if let Some(idx) = text.find(proto) {
                    let rest = &text[idx..];
                    if let Some(end) =
                        rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    {
                        let conn_str = &rest[..end];
                        if conn_str.contains('@') {
                            matches.push((idx, conn_str.to_string()));
                        }
                    }
                }
            }
        }

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    /// Extract key=value or key: value patterns
    fn extract_key_value(&self, text: &str, keyword: &str) -> Option<Vec<(usize, String)>> {
        let mut matches = Vec::new();
        let keyword_len = keyword.len();

        // Use char_indices to safely iterate through valid character boundaries
        for (i, _) in text.char_indices() {
            // Check if the substring starting at i matches the keyword case-insensitively
            // text.get(i..i+len) returns None if the end index is not a char boundary
            if let Some(candidate) = text.get(i..i + keyword_len) {
                if candidate.eq_ignore_ascii_case(keyword) {
                    let rest = &text[i..];

                    // Look for assignment operators
                    let after_keyword = &rest[keyword.len()..];
                    let trimmed = after_keyword.trim_start();

                    if trimmed.is_empty() {
                        continue;
                    }

                    // Check for assignment operators: =, :, or quotes
                    let first_char = trimmed.chars().next().unwrap();
                    if first_char == '='
                        || first_char == ':'
                        || first_char == '"'
                        || first_char == '\''
                    {
                        let value_start = if first_char == '=' || first_char == ':' {
                            trimmed[1..].trim_start()
                        } else {
                            trimmed
                        };

                        // Extract the value
                        let value = self.extract_quoted_or_unquoted_value(value_start);
                        if !value.is_empty() && value.len() >= 8 {
                            matches.push((i, value));
                        }
                    }
                }
            }
        }

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    /// Extract quoted or unquoted value from assignment
    fn extract_quoted_or_unquoted_value(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }

        let first_char = text.chars().next().unwrap();

        // Quoted value
        if first_char == '"' || first_char == '\'' {
            let quote = first_char;
            let rest = &text[1..];
            if let Some(end) = rest.find(quote) {
                return rest[..end].to_string();
            }
        }

        // Unquoted value - take until whitespace or special char
        let value: String = text
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ',' && *c != ';' && *c != ')')
            .collect();

        value
    }

    /// Calculate Shannon entropy of a string
    fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq_map = std::collections::HashMap::new();
        for c in s.chars() {
            *freq_map.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for &count in freq_map.values() {
            let prob = count as f64 / len;
            entropy -= prob * prob.log2();
        }

        entropy
    }

    /// Filter out common false positives
    fn is_false_positive(&self, secret: &str) -> bool {
        let false_positives = vec![
            "example.com",
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "YOUR_API_KEY",
            "your_api_key",
            "INSERT_KEY_HERE",
            "REPLACE_ME",
            "CHANGEME",
            "changeme",
            "dummy",
            "test123",
            "password123",
            "12345678",
            "abcd1234",
            "xxxxxxxx",
            "XXXXXXXX",
        ];

        let secret_lower = secret.to_lowercase();

        // Check exact matches
        for fp in &false_positives {
            if secret_lower.contains(&fp.to_lowercase()) {
                return true;
            }
        }

        // Check for placeholder patterns
        if secret.contains("XXXX") || secret.contains("****") || secret.contains("....") {
            return true;
        }

        // Check for repeated characters (low entropy)
        if secret.len() > 8 {
            let unique_chars: HashSet<char> = secret.chars().collect();
            if unique_chars.len() < 4 {
                return true; // Too few unique characters
            }
        }

        false
    }

    /// Scan git diff for secrets (basic implementation)
    pub fn scan_git_diff(&self, repo_path: &str) -> Result<Vec<SecretFinding>, String> {
        // This would require implementing git diff parsing
        // For now, return an error indicating it's not implemented
        Err(format!(
            "Git diff scanning not yet implemented for {}. Use directory scanning instead.",
            repo_path
        ))
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_calculate_entropy() {
        // Low entropy (repeated characters)
        assert!(SecretScanner::calculate_entropy("aaaaaaa") < 1.0);

        // High entropy (random-looking)
        assert!(SecretScanner::calculate_entropy("aB3xK9mP2qL7") > 3.0);

        // Base64-like high entropy
        assert!(SecretScanner::calculate_entropy("dGVzdDEyMzQ1Njc4OTA=") > 3.5);
    }

    #[test]
    fn test_false_positive_detection() {
        let scanner = SecretScanner::new();

        assert!(scanner.is_false_positive("YOUR_API_KEY"));
        assert!(scanner.is_false_positive("example.com"));
        assert!(scanner.is_false_positive("password123"));
        assert!(scanner.is_false_positive("XXXXXXXXXXXXXXXX"));

        assert!(!scanner.is_false_positive("AKIAIOSFODNN7EXAMPLE"));
        assert!(!scanner.is_false_positive("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }

    #[test]
    fn test_pattern_matching() {
        let scanner = SecretScanner::new();

        // AWS Access Key ID
        let line = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let matches = scanner.pattern_match(r"AKIA[0-9A-Z]{16}", line);
        assert!(matches.is_some());

        // JWT token
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let matches =
            scanner.pattern_match(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", jwt);
        assert!(matches.is_some());
    }

    #[test]
    fn test_should_exclude_file() {
        let scanner = SecretScanner::new();

        assert!(scanner.should_exclude_file("bundle.min.js"));
        assert!(scanner.should_exclude_file("image.png"));
        assert!(scanner.should_exclude_file("package-lock.json"));

        assert!(!scanner.should_exclude_file("config.rs"));
        assert!(!scanner.should_exclude_file("secrets.txt"));
    }

    #[test]
    fn test_classify_archive_file() {
        let path = Path::new("/tmp/backup/export.tar.gz");
        let risk = SecretScanner::classify_high_risk_file(path).expect("risk");
        assert_eq!(risk.rule_id, "archive-backup");
        assert!(risk.skip_text_scan);
    }

    #[test]
    fn test_classify_env_backup() {
        let path = Path::new("/tmp/config/.env.backup");
        let risk = SecretScanner::classify_high_risk_file(path).expect("risk");
        assert_eq!(risk.rule_id, "config-backup");
        assert!(!risk.skip_text_scan);
    }
}
