/// Secrets Scanner Module
///
/// Main scanner that coordinates pattern matching, entropy analysis,
/// and git history scanning.

use super::{
    SecretFinding, SecretSeverity, ScannerConfig, ScanSummary,
    patterns::{SecretPattern, PatternCategory, get_all_patterns},
    entropy::EntropyAnalyzer,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use std::collections::VecDeque;

/// Main secrets scanner
pub struct SecretsScanner {
    config: ScannerConfig,
    patterns: Vec<SecretPattern>,
    entropy_analyzer: EntropyAnalyzer,
}

impl SecretsScanner {
    pub fn new(config: ScannerConfig) -> Self {
        // Get patterns filtered by category
        let patterns: Vec<SecretPattern> = get_all_patterns()
            .into_iter()
            .filter(|p| config.categories.contains(&p.category))
            .collect();

        let entropy_analyzer = EntropyAnalyzer::new(config.entropy_threshold);

        Self {
            config,
            patterns,
            entropy_analyzer,
        }
    }

    /// Scan a directory for secrets
    pub fn scan_directory(&self, path: &Path) -> (Vec<SecretFinding>, ScanSummary) {
        let start = Instant::now();
        let findings = Arc::new(Mutex::new(Vec::new()));
        let summary = Arc::new(Mutex::new(ScanSummary::new()));

        // Collect files to scan
        let files: Vec<PathBuf> = self.collect_files(path);

        // Update summary
        {
            let mut s = summary.lock().unwrap();
            s.files_scanned = files.len();
        }

        // Create work queue
        let work_queue = Arc::new(Mutex::new(VecDeque::from(files)));

        // Spawn worker threads
        let mut handles = Vec::new();
        let num_threads = self.config.threads.min(work_queue.lock().unwrap().len().max(1));

        for _ in 0..num_threads {
            let queue = Arc::clone(&work_queue);
            let findings = Arc::clone(&findings);
            let summary = Arc::clone(&summary);
            let patterns = self.patterns.clone();
            let config = self.config.clone();
            let entropy_analyzer = EntropyAnalyzer::new(config.entropy_threshold);

            let handle = thread::spawn(move || {
                loop {
                    let file = {
                        let mut q = queue.lock().unwrap();
                        q.pop_front()
                    };

                    match file {
                        Some(file_path) => {
                            let file_findings = Self::scan_file_inner(
                                &file_path,
                                &patterns,
                                &entropy_analyzer,
                                &config,
                            );

                            if !file_findings.is_empty() {
                                let mut f = findings.lock().unwrap();
                                let mut s = summary.lock().unwrap();

                                for finding in file_findings {
                                    s.add_finding(&finding);
                                    f.push(finding);
                                }
                            }
                        }
                        None => break,
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        // Finalize summary
        {
            let mut s = summary.lock().unwrap();
            s.duration = start.elapsed();
        }

        let findings = Arc::try_unwrap(findings)
            .unwrap_or_else(|_| panic!("Failed to unwrap findings"))
            .into_inner()
            .unwrap();

        let summary = Arc::try_unwrap(summary)
            .unwrap_or_else(|_| panic!("Failed to unwrap summary"))
            .into_inner()
            .unwrap();

        (findings, summary)
    }

    /// Scan a single file
    pub fn scan_file(&self, path: &Path) -> Vec<SecretFinding> {
        Self::scan_file_inner(path, &self.patterns, &self.entropy_analyzer, &self.config)
    }

    /// Internal file scanning
    fn scan_file_inner(
        path: &Path,
        patterns: &[SecretPattern],
        entropy_analyzer: &EntropyAnalyzer,
        config: &ScannerConfig,
    ) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        // Read file
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                // Try reading as binary
                match fs::read(path) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(_) => return findings,
                }
            }
        };

        // Check file size
        if content.len() > config.max_file_size {
            return findings;
        }

        // Scan each line
        for (line_num, line) in content.lines().enumerate() {
            // Skip if line is in allow list
            if config.allow_list.iter().any(|p| line.contains(p)) {
                continue;
            }

            // Check against patterns
            for pattern in patterns {
                if let Some(finding) = Self::check_line_against_pattern(
                    path,
                    line_num + 1,
                    line,
                    pattern,
                    entropy_analyzer,
                    config,
                ) {
                    findings.push(finding);
                }
            }

            // Also check for high entropy strings
            let high_entropy_strings = entropy_analyzer.find_high_entropy_strings(line);
            for entropy_result in high_entropy_strings {
                // Only report if not already found by a pattern
                if !findings.iter().any(|f| f.match_text.contains(&entropy_result.value)) {
                    let finding = SecretFinding {
                        secret_type: "High Entropy String".to_string(),
                        category: PatternCategory::GenericSecret,
                        match_text: if config.redact_secrets {
                            redact_secret(&entropy_result.value)
                        } else {
                            entropy_result.value.clone()
                        },
                        file_path: path.to_path_buf(),
                        line_number: line_num + 1,
                        column: line.find(&entropy_result.value).unwrap_or(0),
                        line_content: line.to_string(),
                        confidence: entropy_result.normalized_entropy,
                        severity: SecretSeverity::Low,
                        commit: None,
                        author: None,
                        date: None,
                        context: vec![entropy_result.description()],
                        is_false_positive: false,
                    };
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Check a single line against a pattern
    fn check_line_against_pattern(
        path: &Path,
        line_number: usize,
        line: &str,
        pattern: &SecretPattern,
        entropy_analyzer: &EntropyAnalyzer,
        config: &ScannerConfig,
    ) -> Option<SecretFinding> {
        // First check if any keywords are present
        let has_keyword = pattern.keywords.is_empty()
            || pattern.keywords.iter().any(|kw| {
                line.to_lowercase().contains(&kw.to_lowercase())
            });

        if !has_keyword {
            return None;
        }

        // Extract potential secrets from the line
        let potential_secrets = extract_potential_secrets(line);

        for secret in potential_secrets {
            // Check length constraints
            if secret.len() < pattern.min_length || secret.len() > pattern.max_length {
                continue;
            }

            // Check pattern match
            if !pattern.pattern.matches(&secret) {
                continue;
            }

            // Check entropy if required
            if pattern.requires_entropy {
                if !entropy_analyzer.is_high_entropy(&secret) {
                    continue;
                }
            }

            // Found a match!
            let column = line.find(&secret).unwrap_or(0);
            let match_text = if config.redact_secrets {
                redact_secret(&secret)
            } else {
                secret.clone()
            };

            return Some(SecretFinding {
                secret_type: pattern.name.to_string(),
                category: pattern.category,
                match_text,
                file_path: path.to_path_buf(),
                line_number,
                column,
                line_content: line.to_string(),
                confidence: 0.9,
                severity: pattern.severity,
                commit: None,
                author: None,
                date: None,
                context: vec![pattern.description.to_string()],
                is_false_positive: false,
            });
        }

        None
    }

    /// Collect files to scan
    fn collect_files(&self, path: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();

        if path.is_file() {
            if self.should_scan_file(path) {
                files.push(path.to_path_buf());
            }
        } else if path.is_dir() {
            self.collect_files_recursive(path, &mut files);
        }

        files
    }

    /// Recursively collect files
    fn collect_files_recursive(&self, dir: &Path, files: &mut Vec<PathBuf>) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                // Check if directory should be excluded
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.should_exclude_path(&path) {
                        continue;
                    }
                }
                self.collect_files_recursive(&path, files);
            } else if path.is_file() {
                if self.should_scan_file(&path) {
                    files.push(path);
                }
            }
        }
    }

    /// Check if a file should be scanned
    fn should_scan_file(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check exclude patterns
        if self.should_exclude_path(path) {
            return false;
        }

        // Check file size
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.len() as usize > self.config.max_file_size {
                return false;
            }
        }

        true
    }

    /// Check if path matches exclude patterns
    fn should_exclude_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &self.config.exclude_patterns {
            if pattern.ends_with("/*") {
                let dir = &pattern[..pattern.len() - 2];
                if path_str.contains(dir) {
                    return true;
                }
            } else if pattern.starts_with("*.") {
                let ext = &pattern[1..];
                if path_str.ends_with(ext) {
                    return true;
                }
            } else if path_str.contains(pattern) {
                return true;
            }
        }

        false
    }

    /// Scan a string directly
    pub fn scan_string(&self, content: &str, source: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();
        let path = PathBuf::from(source);

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.patterns {
                if let Some(finding) = Self::check_line_against_pattern(
                    &path,
                    line_num + 1,
                    line,
                    pattern,
                    &self.entropy_analyzer,
                    &self.config,
                ) {
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Get pattern count
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for SecretsScanner {
    fn default() -> Self {
        Self::new(ScannerConfig::default())
    }
}

/// Extract potential secrets from a line
fn extract_potential_secrets(line: &str) -> Vec<String> {
    let mut secrets = Vec::new();

    // Split on common delimiters
    let delimiters = [' ', '\t', '"', '\'', '`', '=', ':', ';', ',', '(', ')', '[', ']', '{', '}', '<', '>'];

    for word in line.split(|c| delimiters.contains(&c)) {
        let trimmed = word.trim();
        if trimmed.len() >= 8 {
            secrets.push(trimmed.to_string());
        }
    }

    // Also look for quoted strings
    let mut in_quote = false;
    let mut quote_char = '"';
    let mut current = String::new();

    for c in line.chars() {
        if !in_quote && (c == '"' || c == '\'') {
            in_quote = true;
            quote_char = c;
            current.clear();
        } else if in_quote && c == quote_char {
            in_quote = false;
            if current.len() >= 8 {
                secrets.push(current.clone());
            }
        } else if in_quote {
            current.push(c);
        }
    }

    secrets
}

/// Redact a secret for safe display
fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        return "****".to_string();
    }

    let prefix_len = (secret.len() / 4).min(8);
    let suffix_len = (secret.len() / 4).min(4);

    format!(
        "{}...{}",
        &secret[..prefix_len],
        &secret[secret.len() - suffix_len..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_potential_secrets() {
        let line = r#"API_KEY="ghp_xK4mL9bN3pR7wE2yJ8nQ5tH0zS6vU1cA""#;
        let secrets = extract_potential_secrets(line);

        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.starts_with("ghp_")));
    }

    #[test]
    fn test_redact_secret() {
        let secret = "ghp_xK4mL9bN3pR7wE2yJ8nQ5tH0zS6vU1cA";
        let redacted = redact_secret(secret);

        assert!(redacted.contains("..."));
        assert!(redacted.starts_with("ghp_"));
        assert!(!redacted.contains("xK4mL9bN3pR7wE2y"));
    }

    #[test]
    fn test_scanner_string() {
        let scanner = SecretsScanner::default();
        let content = r#"
            AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
            github_token: ghp_xK4mL9bN3pR7wE2yJ8nQ5tH0zS6vU1cA
        "#;

        let findings = scanner.scan_string(content, "test.env");

        assert!(!findings.is_empty());
    }
}
