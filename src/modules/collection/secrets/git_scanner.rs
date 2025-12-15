use crate::modules::collection::secrets::SecretFinding;
use crate::modules::collection::secrets::SecretScanner;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::process::Command; // To reuse scan_line

pub struct GitScanner {
    scanner: SecretScanner,
}

impl GitScanner {
    pub fn new() -> Self {
        Self {
            scanner: SecretScanner::new(),
        }
    }

    /// Scans all branches in a git repository for secrets.
    pub fn scan_branches(&self, repo_path: &str) -> Result<Vec<SecretFinding>, String> {
        let mut all_findings = Vec::new();
        let current_dir =
            std::env::current_dir().map_err(|e| format!("Failed to get current dir: {}", e))?;
        let repo_path_abs = current_dir.join(repo_path);

        if !repo_path_abs.is_dir() {
            return Err(format!("Repository path is not a directory: {}", repo_path));
        }

        // Ensure it's a git repository
        if !repo_path_abs.join(".git").exists() {
            return Err(format!("Not a git repository: {}", repo_path));
        }

        // Get list of local branches
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo_path_abs)
            .arg("branch")
            .output()
            .map_err(|e| format!("Failed to execute git branch: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "git branch failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let branches: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                // Remove asterisk for current branch and trim
                let branch_name = line.trim_start_matches('*').trim().to_string();
                if branch_name.is_empty() {
                    None
                } else {
                    Some(branch_name)
                }
            })
            .collect();

        // Save current branch to restore later
        let current_branch_output = Command::new("git")
            .arg("-C")
            .arg(&repo_path_abs)
            .arg("rev-parse")
            .arg("--abbrev-ref")
            .arg("HEAD")
            .output()
            .map_err(|e| format!("Failed to get current branch: {}", e))?;

        let current_branch = String::from_utf8_lossy(&current_branch_output.stdout)
            .trim()
            .to_string();

        for branch in branches {
            println!("Scanning branch: {}", branch);

            // Checkout branch (temporarily)
            let checkout_output = Command::new("git")
                .arg("-C")
                .arg(&repo_path_abs)
                .arg("checkout")
                .arg(&branch)
                .output()
                .map_err(|e| format!("Failed to checkout branch {}: {}", branch, e))?;
            if !checkout_output.status.success() {
                eprintln!(
                    "Warning: Failed to checkout branch {}: {}",
                    branch,
                    String::from_utf8_lossy(&checkout_output.stderr)
                );
                continue;
            }

            // Scan the current working directory of the branch
            match self
                .scanner
                .scan_directory(&repo_path_abs.to_string_lossy())
            {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => eprintln!(
                    "Warning: Failed to scan directory for branch {}: {}",
                    branch, e
                ),
            }
        }

        // Restore original branch
        let _ = Command::new("git")
            .arg("-C")
            .arg(&repo_path_abs)
            .arg("checkout")
            .arg(&current_branch)
            .output();

        Ok(all_findings)
    }

    /// Scans the full git history (log and diffs) for secrets.
    pub fn scan_history(&self, repo_path: &str) -> Result<Vec<SecretFinding>, String> {
        let mut all_findings = Vec::new();
        let repo_path_abs = Path::new(repo_path);

        if !repo_path_abs.is_dir() {
            return Err(format!("Repository path is not a directory: {}", repo_path));
        }

        // Use git log --raw --full-history to get file names, then git show for content
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo_path_abs)
            .arg("log")
            .arg("--format=%H") // Commit hash
            .arg("--name-only") // Only show file names
            .arg("--no-merges") // Exclude merge commits
            .output()
            .map_err(|e| format!("Failed to execute git log: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "git log failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_commit = String::new();

        for line in stdout.lines() {
            if line.is_empty() {
                continue;
            }

            if line.len() == 40 && line.chars().all(|c| c.is_ascii_hexdigit()) {
                // This is a commit hash
                current_commit = line.to_string();
            } else {
                // This is a file path changed in the commit
                let file_path = line;

                // Get content of the file at this commit
                let file_content_output = Command::new("git")
                    .arg("-C")
                    .arg(&repo_path_abs)
                    .arg("show")
                    .arg(format!("{}:{}", current_commit, file_path))
                    .output();

                match file_content_output {
                    Ok(output) if output.status.success() => {
                        let content = String::from_utf8_lossy(&output.stdout);
                        for (line_num, line_content) in content.lines().enumerate() {
                            let findings = self.scanner.scan_line_internal(
                                &format!("{}:{}@{}", repo_path, file_path, current_commit),
                                line_num + 1,
                                line_content,
                            );
                            all_findings.extend(findings);
                        }
                    }
                    _ => {
                        // File might not exist in that commit (deleted/renamed), or binary. Ignore.
                    }
                }
            }
        }

        Ok(all_findings)
    }

    /// Scans git diffs for secrets (reusing existing SecretScanner logic for line scanning).
    pub fn scan_diff(
        &self,
        repo_path: &str,
        diff_target: &str,
    ) -> Result<Vec<SecretFinding>, String> {
        let mut all_findings = Vec::new();
        let repo_path_abs = Path::new(repo_path);

        if !repo_path_abs.is_dir() {
            return Err(format!("Repository path is not a directory: {}", repo_path));
        }

        let output = Command::new("git")
            .arg("-C")
            .arg(&repo_path_abs)
            .arg("diff")
            .arg(diff_target) // e.g., HEAD, branch_name, commit_hash
            .output()
            .map_err(|e| format!("Failed to execute git diff: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "git diff failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_file = String::new();
        let mut current_line_num = 0;

        for line in stdout.lines() {
            if line.starts_with("--- a/") {
                current_file = line["--- a/".len()..].to_string();
                current_line_num = 0; // Reset line number for new file
            } else if line.starts_with("+++ b/") {
                current_file = line["+++ b/".len()..].to_string();
                current_line_num = 0; // Reset line number for new file
            } else if line.starts_with("@@") {
                // Parse line number changes: @@ -old_start,old_count +new_start,new_count @@
                if let Some(plus_idx) = line.find('+') {
                    if let Some(comma_idx) = line[plus_idx + 1..].find(',') {
                        if let Ok(num) =
                            line[plus_idx + 1..plus_idx + 1 + comma_idx].parse::<usize>()
                        {
                            current_line_num = num - 1; // -1 because we increment before scanning
                        }
                    }
                }
            } else if line.starts_with('+') && !line.starts_with("+++") {
                // Added line in the diff
                current_line_num += 1;
                let line_content = &line[1..]; // Remove '+'
                let findings = self.scanner.scan_line_internal(
                    &format!("{}:{} (diff)", repo_path, current_file),
                    current_line_num,
                    line_content,
                );
                all_findings.extend(findings);
            } else if !line.starts_with('-') {
                // Unchanged line
                current_line_num += 1;
            }
        }

        Ok(all_findings)
    }
}
