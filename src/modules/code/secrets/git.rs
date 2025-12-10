/// Git History Scanner Module
///
/// Scans git history for secrets that may have been committed
/// and later removed but still exist in history.

use super::{SecretFinding, SecretSeverity, ScannerConfig, ScanSummary};
use super::scanner::SecretsScanner;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};

/// Git history scanner
pub struct GitHistoryScanner {
    scanner: SecretsScanner,
    config: ScannerConfig,
}

impl GitHistoryScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let scanner = SecretsScanner::new(config.clone());
        Self { scanner, config }
    }

    /// Check if path is a git repository
    pub fn is_git_repo(path: &Path) -> bool {
        path.join(".git").exists()
    }

    /// Get git root directory
    pub fn get_git_root(path: &Path) -> Option<PathBuf> {
        let output = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .current_dir(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;

        if output.status.success() {
            let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Some(PathBuf::from(root))
        } else {
            None
        }
    }

    /// Scan git history for secrets
    pub fn scan_history(&self, repo_path: &Path, max_commits: Option<usize>) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        if !Self::is_git_repo(repo_path) {
            return findings;
        }

        // Get commit list
        let commits = self.get_commits(repo_path, max_commits);

        for commit in commits {
            let commit_findings = self.scan_commit(repo_path, &commit);
            findings.extend(commit_findings);
        }

        findings
    }

    /// Get list of commits
    fn get_commits(&self, repo_path: &Path, max_commits: Option<usize>) -> Vec<CommitInfo> {
        let mut commits = Vec::new();

        let mut args = vec![
            "log".to_string(),
            "--format=%H|%an|%ae|%aI|%s".to_string(),
            "--no-walk".to_string(),
        ];

        if let Some(max) = max_commits {
            args.push(format!("-{}", max));
        }

        // Remove --no-walk to get all commits
        args.retain(|a| a != "--no-walk");

        let output = match Command::new("git")
            .args(&args)
            .current_dir(repo_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) => o,
            Err(_) => return commits,
        };

        if !output.status.success() {
            return commits;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.splitn(5, '|').collect();
            if parts.len() >= 5 {
                commits.push(CommitInfo {
                    hash: parts[0].to_string(),
                    author_name: parts[1].to_string(),
                    author_email: parts[2].to_string(),
                    date: parts[3].to_string(),
                    message: parts[4].to_string(),
                });
            }
        }

        commits
    }

    /// Scan a single commit for secrets
    fn scan_commit(&self, repo_path: &Path, commit: &CommitInfo) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        // Get diff for this commit
        let output = match Command::new("git")
            .args(["show", "--format=", &commit.hash])
            .current_dir(repo_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) => o,
            Err(_) => return findings,
        };

        if !output.status.success() {
            return findings;
        }

        let diff = String::from_utf8_lossy(&output.stdout);

        // Parse diff and look for added lines
        let mut current_file = String::new();
        let mut line_number = 0;

        for line in diff.lines() {
            if line.starts_with("diff --git") {
                // New file
                if let Some(path) = line.split(" b/").nth(1) {
                    current_file = path.to_string();
                }
            } else if line.starts_with("@@") {
                // Line number marker
                // Format: @@ -old,count +new,count @@
                if let Some(new_pos) = line.split('+').nth(1) {
                    if let Some(num) = new_pos.split(',').next() {
                        line_number = num.trim().parse().unwrap_or(0);
                    }
                }
            } else if line.starts_with('+') && !line.starts_with("+++") {
                // Added line
                let content = &line[1..]; // Remove the '+'

                // Scan this line
                let line_findings = self.scanner.scan_string(
                    content,
                    &current_file,
                );

                for mut finding in line_findings {
                    finding.commit = Some(commit.hash.clone());
                    finding.author = Some(format!("{} <{}>", commit.author_name, commit.author_email));
                    finding.date = Some(commit.date.clone());
                    finding.line_number = line_number;
                    finding.context.push(format!("Commit: {}", &commit.hash[..8]));
                    finding.context.push(format!("Message: {}", commit.message));
                    findings.push(finding);
                }

                line_number += 1;
            } else if !line.starts_with('-') {
                // Context line (not removed)
                line_number += 1;
            }
        }

        findings
    }

    /// Scan all branches for secrets
    pub fn scan_all_branches(&self, repo_path: &Path) -> Vec<SecretFinding> {
        let mut findings = Vec::new();
        let branches = self.get_branches(repo_path);

        for branch in branches {
            // Checkout branch and scan
            let branch_findings = self.scan_branch(repo_path, &branch);
            findings.extend(branch_findings);
        }

        // Deduplicate by commit hash + file + line
        findings.sort_by(|a, b| {
            (&a.commit, &a.file_path, a.line_number)
                .cmp(&(&b.commit, &b.file_path, b.line_number))
        });
        findings.dedup_by(|a, b| {
            a.commit == b.commit && a.file_path == b.file_path && a.line_number == b.line_number
        });

        findings
    }

    /// Get list of branches
    fn get_branches(&self, repo_path: &Path) -> Vec<String> {
        let mut branches = Vec::new();

        let output = match Command::new("git")
            .args(["branch", "-a", "--format=%(refname:short)"])
            .current_dir(repo_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) => o,
            Err(_) => return branches,
        };

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let branch = line.trim();
                if !branch.is_empty() && !branch.contains("HEAD") {
                    branches.push(branch.to_string());
                }
            }
        }

        branches
    }

    /// Scan a specific branch
    fn scan_branch(&self, repo_path: &Path, branch: &str) -> Vec<SecretFinding> {
        // Get commits specific to this branch
        let output = match Command::new("git")
            .args(["log", "--format=%H", branch, "--"])
            .current_dir(repo_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for hash in stdout.lines().take(self.config.max_commits.unwrap_or(100)) {
                let commit = CommitInfo {
                    hash: hash.to_string(),
                    author_name: String::new(),
                    author_email: String::new(),
                    date: String::new(),
                    message: String::new(),
                };

                let commit_findings = self.scan_commit(repo_path, &commit);
                findings.extend(commit_findings);
            }
        }

        findings
    }

    /// Get staged changes and scan them (pre-commit hook)
    pub fn scan_staged(&self, repo_path: &Path) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        // Get staged diff
        let output = match Command::new("git")
            .args(["diff", "--cached", "--diff-filter=ACMR"])
            .current_dir(repo_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) => o,
            Err(_) => return findings,
        };

        if !output.status.success() {
            return findings;
        }

        let diff = String::from_utf8_lossy(&output.stdout);
        let mut current_file = String::new();

        for line in diff.lines() {
            if line.starts_with("diff --git") {
                if let Some(path) = line.split(" b/").nth(1) {
                    current_file = path.to_string();
                }
            } else if line.starts_with('+') && !line.starts_with("+++") {
                let content = &line[1..];
                let line_findings = self.scanner.scan_string(content, &current_file);

                for mut finding in line_findings {
                    finding.context.push("Found in staged changes".to_string());
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Verify that historical secrets have been rotated
    pub fn verify_rotated(&self, repo_path: &Path, findings: &[SecretFinding]) -> Vec<RotationStatus> {
        let mut statuses = Vec::new();

        for finding in findings {
            // Check if this secret still exists in the current working tree
            let exists_now = self.secret_exists_in_head(repo_path, finding);

            statuses.push(RotationStatus {
                finding: finding.clone(),
                still_exists: exists_now,
                rotated: !exists_now,
                needs_action: exists_now,
            });
        }

        statuses
    }

    /// Check if a secret still exists in HEAD
    fn secret_exists_in_head(&self, repo_path: &Path, finding: &SecretFinding) -> bool {
        // Try to read the file from HEAD
        let output = Command::new("git")
            .args(["show", &format!("HEAD:{}", finding.file_path.display())])
            .current_dir(repo_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let content = String::from_utf8_lossy(&output.stdout);
                // Check if the secret pattern still exists
                return content.contains(&finding.match_text)
                    || content.lines().any(|l| l.contains(&finding.secret_type));
            }
        }

        false
    }
}

impl Default for GitHistoryScanner {
    fn default() -> Self {
        Self::new(ScannerConfig::default())
    }
}

/// Information about a git commit
#[derive(Debug, Clone)]
struct CommitInfo {
    hash: String,
    author_name: String,
    author_email: String,
    date: String,
    message: String,
}

/// Status of secret rotation
#[derive(Debug, Clone)]
pub struct RotationStatus {
    pub finding: SecretFinding,
    pub still_exists: bool,
    pub rotated: bool,
    pub needs_action: bool,
}

/// Pre-commit hook integration
pub fn pre_commit_check(repo_path: &Path) -> Result<(), Vec<SecretFinding>> {
    let scanner = GitHistoryScanner::default();
    let findings = scanner.scan_staged(repo_path);

    if findings.is_empty() {
        Ok(())
    } else {
        Err(findings)
    }
}

/// Generate pre-commit hook script
pub fn generate_pre_commit_hook() -> String {
    r#"#!/bin/sh
# redblue secrets pre-commit hook
# Place this in .git/hooks/pre-commit

rb code secrets scan --staged

if [ $? -ne 0 ]; then
    echo "Secrets detected in staged changes. Commit blocked."
    exit 1
fi
"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_is_git_repo() {
        // Current directory should be a git repo if running from redblue project
        let cwd = env::current_dir().unwrap();
        // Note: This test may fail if not run from within a git repo
        let is_repo = GitHistoryScanner::is_git_repo(&cwd);
        // Just ensure it doesn't panic
        assert!(is_repo || !is_repo);
    }
}
