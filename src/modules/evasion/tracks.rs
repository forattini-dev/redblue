//! Track Covering Module
//!
//! Techniques to clear forensic artifacts:
//! - Shell history (bash, zsh, fish, etc.)
//! - Application logs
//! - Recent files
//! - redblue session files
//!
//! # Warning
//! These techniques are for authorized penetration testing only.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// History file locations for various shells
pub struct HistoryFiles {
    pub bash: Vec<PathBuf>,
    pub zsh: Vec<PathBuf>,
    pub fish: Vec<PathBuf>,
    pub sh: Vec<PathBuf>,
    pub other: Vec<PathBuf>,
}

impl HistoryFiles {
    /// Detect all history files on the system
    pub fn detect() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let home = PathBuf::from(home);

        let mut files = Self {
            bash: Vec::new(),
            zsh: Vec::new(),
            fish: Vec::new(),
            sh: Vec::new(),
            other: Vec::new(),
        };

        // Bash history locations
        let bash_locations = [
            home.join(".bash_history"),
            home.join(".history"),
            PathBuf::from("/root/.bash_history"),
        ];
        for path in bash_locations {
            if path.exists() {
                files.bash.push(path);
            }
        }

        // Zsh history locations
        let zsh_locations = [
            home.join(".zsh_history"),
            home.join(".zhistory"),
            home.join(".local/share/zsh/history"),
            PathBuf::from("/root/.zsh_history"),
        ];
        for path in zsh_locations {
            if path.exists() {
                files.zsh.push(path);
            }
        }

        // Fish history
        let fish_locations = [
            home.join(".local/share/fish/fish_history"),
            home.join(".config/fish/fish_history"),
        ];
        for path in fish_locations {
            if path.exists() {
                files.fish.push(path);
            }
        }

        // Other shells
        let other_locations = [
            home.join(".sh_history"),
            home.join(".ksh_history"),
            home.join(".tcsh_history"),
            home.join(".csh_history"),
        ];
        for path in other_locations {
            if path.exists() {
                files.other.push(path);
            }
        }

        files
    }

    /// Get all detected history files
    pub fn all(&self) -> Vec<&PathBuf> {
        let mut all = Vec::new();
        all.extend(self.bash.iter());
        all.extend(self.zsh.iter());
        all.extend(self.fish.iter());
        all.extend(self.sh.iter());
        all.extend(self.other.iter());
        all
    }

    /// Count total files
    pub fn count(&self) -> usize {
        self.all().len()
    }
}

/// Result of clearing operation
#[derive(Debug)]
pub struct ClearResult {
    pub file: PathBuf,
    pub success: bool,
    pub error: Option<String>,
    pub bytes_cleared: u64,
}

/// Clear a single history file
pub fn clear_file(path: &PathBuf) -> ClearResult {
    // Get file size before clearing
    let bytes_cleared = fs::metadata(path)
        .map(|m| m.len())
        .unwrap_or(0);

    // Try to truncate the file (preserve it but empty contents)
    match fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
    {
        Ok(_) => ClearResult {
            file: path.clone(),
            success: true,
            error: None,
            bytes_cleared,
        },
        Err(e) => ClearResult {
            file: path.clone(),
            success: false,
            error: Some(e.to_string()),
            bytes_cleared: 0,
        },
    }
}

/// Securely overwrite and clear a file
pub fn secure_clear_file(path: &PathBuf) -> ClearResult {
    // Get file size
    let size = match fs::metadata(path) {
        Ok(m) => m.len() as usize,
        Err(e) => {
            return ClearResult {
                file: path.clone(),
                success: false,
                error: Some(e.to_string()),
                bytes_cleared: 0,
            };
        }
    };

    // Overwrite with zeros
    let zeros = vec![0u8; size];
    if let Err(e) = fs::write(path, &zeros) {
        return ClearResult {
            file: path.clone(),
            success: false,
            error: Some(format!("Failed to overwrite: {}", e)),
            bytes_cleared: 0,
        };
    }

    // Overwrite with random data
    let random: Vec<u8> = (0..size)
        .map(|i| ((i * 0x5A + 0x3B) & 0xFF) as u8)
        .collect();
    if let Err(e) = fs::write(path, &random) {
        return ClearResult {
            file: path.clone(),
            success: false,
            error: Some(format!("Failed to overwrite with random: {}", e)),
            bytes_cleared: 0,
        };
    }

    // Finally truncate
    match fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
    {
        Ok(_) => ClearResult {
            file: path.clone(),
            success: true,
            error: None,
            bytes_cleared: size as u64,
        },
        Err(e) => ClearResult {
            file: path.clone(),
            success: false,
            error: Some(e.to_string()),
            bytes_cleared: 0,
        },
    }
}

/// Clear all shell history files
pub fn clear_all_history(secure: bool) -> Vec<ClearResult> {
    let files = HistoryFiles::detect();
    let mut results = Vec::new();

    for path in files.all() {
        let result = if secure {
            secure_clear_file(path)
        } else {
            clear_file(path)
        };
        results.push(result);
    }

    results
}

/// Clear specific shell's history
pub fn clear_shell_history(shell: &str, secure: bool) -> Vec<ClearResult> {
    let files = HistoryFiles::detect();
    let paths = match shell {
        "bash" => &files.bash,
        "zsh" => &files.zsh,
        "fish" => &files.fish,
        "sh" => &files.sh,
        _ => return Vec::new(),
    };

    let mut results = Vec::new();
    for path in paths {
        let result = if secure {
            secure_clear_file(path)
        } else {
            clear_file(path)
        };
        results.push(result);
    }

    results
}

/// Clear redblue session files
pub fn clear_redblue_sessions() -> Vec<ClearResult> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut results = Vec::new();

    // Find .rb-session files
    if let Ok(entries) = fs::read_dir(&cwd) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Some(name) = path.file_name() {
                if name.to_string_lossy().ends_with(".rb-session") {
                    results.push(secure_clear_file(&path));
                }
            }
        }
    }

    // Also check home directory
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        let rb_dir = home.join(".redblue");
        if rb_dir.exists() {
            if let Ok(entries) = fs::read_dir(&rb_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.extension().map(|e| e == "session").unwrap_or(false) {
                        results.push(secure_clear_file(&path));
                    }
                }
            }
        }
    }

    results
}

/// Generate shell command to clear current session history
pub fn get_clear_session_command(shell: &str) -> String {
    match shell {
        "bash" => "history -c && history -w".to_string(),
        "zsh" => "fc -p && history -p".to_string(),
        "fish" => "history clear".to_string(),
        "sh" | "dash" => "unset HISTFILE".to_string(),
        _ => "history -c".to_string(),
    }
}

/// Detect current shell
pub fn detect_shell() -> String {
    // Check SHELL environment variable
    if let Ok(shell) = std::env::var("SHELL") {
        if shell.contains("zsh") {
            return "zsh".to_string();
        } else if shell.contains("bash") {
            return "bash".to_string();
        } else if shell.contains("fish") {
            return "fish".to_string();
        }
    }

    // Fallback to bash
    "bash".to_string()
}

/// Clear system logs (requires root)
pub fn clear_system_logs() -> Vec<ClearResult> {
    let log_locations = [
        PathBuf::from("/var/log/auth.log"),
        PathBuf::from("/var/log/secure"),
        PathBuf::from("/var/log/wtmp"),
        PathBuf::from("/var/log/btmp"),
        PathBuf::from("/var/log/lastlog"),
        PathBuf::from("/var/log/messages"),
        PathBuf::from("/var/log/syslog"),
    ];

    let mut results = Vec::new();
    for path in &log_locations {
        if path.exists() {
            results.push(clear_file(path));
        }
    }

    results
}

/// Clear recently used files (Linux)
pub fn clear_recent_files() -> Vec<ClearResult> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let home = PathBuf::from(home);

    let recent_locations = [
        home.join(".local/share/recently-used.xbel"),
        home.join(".recently-used"),
        home.join(".local/share/Trash"),
    ];

    let mut results = Vec::new();
    for path in &recent_locations {
        if path.exists() {
            if path.is_file() {
                results.push(clear_file(path));
            }
        }
    }

    results
}

/// Statistics about what can be cleared
#[derive(Debug)]
pub struct ClearStats {
    pub history_files: usize,
    pub history_bytes: u64,
    pub session_files: usize,
    pub log_files: usize,
    pub recent_files: usize,
}

impl ClearStats {
    /// Gather statistics without clearing
    pub fn gather() -> Self {
        let history = HistoryFiles::detect();
        let mut history_bytes = 0u64;

        for path in history.all() {
            if let Ok(meta) = fs::metadata(path) {
                history_bytes += meta.len();
            }
        }

        // Count session files
        let mut session_files = 0;
        let cwd = std::env::current_dir().unwrap_or_default();
        if let Ok(entries) = fs::read_dir(&cwd) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().to_string_lossy().ends_with(".rb-session") {
                    session_files += 1;
                }
            }
        }

        Self {
            history_files: history.count(),
            history_bytes,
            session_files,
            log_files: 0,  // Would need root to check
            recent_files: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_history_files() {
        let files = HistoryFiles::detect();
        // Just ensure it doesn't crash
        let _ = files.count();
    }

    #[test]
    fn test_detect_shell() {
        let shell = detect_shell();
        assert!(!shell.is_empty());
    }

    #[test]
    fn test_clear_session_command() {
        let cmd = get_clear_session_command("bash");
        assert!(cmd.contains("history"));
    }

    #[test]
    fn test_gather_stats() {
        let stats = ClearStats::gather();
        // Just verify it doesn't crash
        let _ = stats.history_files;
    }
}
