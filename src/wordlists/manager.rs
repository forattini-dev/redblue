/// Wordlist Manager - handles resolution, caching, and access to wordlists
use super::embedded;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

pub struct WordlistManager {
    cache_dir: PathBuf,
    auto_download: bool,
    fallback_embedded: bool,
}

impl WordlistManager {
    /// Create a new WordlistManager
    pub fn new() -> Result<Self, String> {
        let cwd =
            env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?;
        let cache_dir = cwd.join(".redblue").join("wordlists");

        Ok(Self {
            cache_dir,
            auto_download: true,
            fallback_embedded: true,
        })
    }

    /// Initialize the .redblue directory structure
    pub fn init(&self) -> Result<(), String> {
        // Create cache directory if it doesn't exist
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir)
                .map_err(|e| format!("Failed to create cache directory: {}", e))?;
        }

        // Create subdirectories
        let subdirs = vec!["seclists", "assetnote", "custom"];
        for subdir in subdirs {
            let path = self.cache_dir.join(subdir);
            if !path.exists() {
                fs::create_dir_all(&path)
                    .map_err(|e| format!("Failed to create {} directory: {}", subdir, e))?;
            }
        }

        Ok(())
    }

    /// Get wordlist by name or path
    /// Resolution priority:
    /// 1. Absolute path
    /// 2. Relative path from CWD
    /// 3. Embedded wordlist
    /// 4. Project wordlists/ directory
    /// 5. Cached wordlist in .redblue/wordlists/
    /// 6. Fallback to embedded default
    pub fn get(&self, name: &str) -> Result<Vec<String>, String> {
        // 1. Check if it's an absolute path
        if Path::new(name).is_absolute() {
            if Path::new(name).exists() {
                return self.load_from_file(Path::new(name));
            } else {
                return Err(format!("Wordlist file not found: {}", name));
            }
        }

        // 2. Check if it's a relative path from CWD
        if Path::new(name).exists() {
            return self.load_from_file(Path::new(name));
        }

        // 3. Check embedded wordlists
        if let Some(wordlist) = embedded::get_embedded(name) {
            return Ok(wordlist);
        }

        // 4. Check project wordlists/ directory (shipped with redblue)
        if let Ok(project_wordlist) = self.find_in_project_wordlists(name) {
            return self.load_from_file(&project_wordlist);
        }

        // 5. Check cached wordlists
        let cached_path = self.cache_dir.join(name);
        if cached_path.exists() {
            return self.load_from_file(&cached_path);
        }

        // 5. Check for source notation (e.g., "seclists:Discovery/DNS/subdomains-top1million.txt")
        if name.contains(':') {
            let parts: Vec<&str> = name.split(':').collect();
            if parts.len() == 2 {
                let source = parts[0];
                let path = parts[1];
                let cached_path = self.cache_dir.join(source).join(path);

                if cached_path.exists() {
                    return self.load_from_file(&cached_path);
                }

                // If auto_download is enabled, suggest installation
                if self.auto_download {
                    return Err(format!(
                        "Wordlist '{}' not found in cache.\nRun: rb wordlist install {}",
                        name, source
                    ));
                }
            }
        }

        // 6. Fallback to embedded default
        if self.fallback_embedded {
            if let Some(wordlist) = embedded::get_embedded("directories-common") {
                return Ok(wordlist);
            }
        }

        Err(format!("Wordlist not found: {}", name))
    }

    /// Load wordlist from file
    fn load_from_file(&self, path: &Path) -> Result<Vec<String>, String> {
        let file =
            fs::File::open(path).map_err(|e| format!("Failed to open wordlist file: {}", e))?;

        let reader = BufReader::new(file);
        let mut wordlist = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                wordlist.push(trimmed.to_string());
            }
        }

        if wordlist.is_empty() {
            return Err("Wordlist file is empty".to_string());
        }

        Ok(wordlist)
    }

    /// Find wordlist in project wordlists/ directory
    /// This searches for wordlists shipped with redblue binary
    fn find_in_project_wordlists(&self, name: &str) -> Result<PathBuf, String> {
        // Get the executable's directory
        let exe_path =
            env::current_exe().map_err(|e| format!("Failed to get executable path: {}", e))?;

        let exe_dir = exe_path
            .parent()
            .ok_or("Failed to get executable directory")?;

        // Try multiple locations relative to the executable
        let search_paths = vec![
            // 1. Alongside the binary: /usr/local/bin/wordlists/
            exe_dir.join("wordlists"),
            // 2. In standard locations: /usr/share/redblue/wordlists/
            PathBuf::from("/usr/share/redblue/wordlists"),
            PathBuf::from("/usr/local/share/redblue/wordlists"),
            // 3. Development mode: ./wordlists/ from CWD
            env::current_dir()
                .ok()
                .map(|cwd| cwd.join("wordlists"))
                .unwrap_or_default(),
        ];

        for base_path in search_paths {
            if !base_path.exists() {
                continue;
            }

            // Try exact name match
            let wordlist_path = base_path.join(name);
            if wordlist_path.exists() && wordlist_path.is_file() {
                return Ok(wordlist_path);
            }

            // Try with .txt extension
            let wordlist_txt = base_path.join(format!("{}.txt", name));
            if wordlist_txt.exists() && wordlist_txt.is_file() {
                return Ok(wordlist_txt);
            }
        }

        Err(format!(
            "Wordlist '{}' not found in project directories",
            name
        ))
    }

    /// List all available wordlists (embedded + cached + project)
    pub fn list(&self) -> Vec<WordlistInfo> {
        let mut wordlists = Vec::new();

        // Add embedded wordlists
        for (name, count) in embedded::list_embedded() {
            wordlists.push(WordlistInfo {
                name: name.to_string(),
                source: "embedded".to_string(),
                line_count: count,
                size_kb: 0, // Size is negligible
                installed: true,
            });
        }

        // Add project wordlists (shipped with redblue)
        if let Ok(project_wordlists) = self.scan_project_wordlists() {
            for wordlist in project_wordlists {
                wordlists.push(wordlist);
            }
        }

        // Add cached wordlists (scan .redblue/wordlists/)
        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_file() {
                        if let Some(name) = entry.file_name().to_str() {
                            if name.ends_with(".txt") {
                                let path = entry.path();
                                let line_count = self.count_lines(&path).unwrap_or(0);
                                let size_kb =
                                    fs::metadata(&path).map(|m| m.len() / 1024).unwrap_or(0);

                                wordlists.push(WordlistInfo {
                                    name: name.to_string(),
                                    source: "cached".to_string(),
                                    line_count,
                                    size_kb: size_kb as usize,
                                    installed: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        wordlists
    }

    /// Scan project wordlists/ directory
    fn scan_project_wordlists(&self) -> Result<Vec<WordlistInfo>, String> {
        let mut wordlists = Vec::new();

        // Get search paths for project wordlists
        let exe_path = env::current_exe().ok();
        let exe_dir = exe_path.as_ref().and_then(|p| p.parent());

        let search_paths = vec![
            exe_dir.map(|d| d.join("wordlists")),
            Some(PathBuf::from("/usr/share/redblue/wordlists")),
            Some(PathBuf::from("/usr/local/share/redblue/wordlists")),
            env::current_dir().ok().map(|cwd| cwd.join("wordlists")),
        ];

        for base_path in search_paths.into_iter().flatten() {
            if !base_path.exists() || !base_path.is_dir() {
                continue;
            }

            if let Ok(entries) = fs::read_dir(&base_path) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_file() {
                            if let Some(name) = entry.file_name().to_str() {
                                if name.ends_with(".txt") {
                                    let path = entry.path();
                                    let line_count = self.count_lines(&path).unwrap_or(0);
                                    let size_kb =
                                        fs::metadata(&path).map(|m| m.len() / 1024).unwrap_or(0);

                                    wordlists.push(WordlistInfo {
                                        name: name.to_string(),
                                        source: "project".to_string(),
                                        line_count,
                                        size_kb: size_kb as usize,
                                        installed: true,
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Only scan the first existing directory
            if !wordlists.is_empty() {
                break;
            }
        }

        Ok(wordlists)
    }

    /// Count lines in a file
    fn count_lines(&self, path: &Path) -> Result<usize, String> {
        let file = fs::File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        let reader = BufReader::new(file);
        Ok(reader.lines().count())
    }

    /// Get cache directory path
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Set auto-download behavior
    pub fn set_auto_download(&mut self, enabled: bool) {
        self.auto_download = enabled;
    }

    /// Set fallback behavior
    pub fn set_fallback_embedded(&mut self, enabled: bool) {
        self.fallback_embedded = enabled;
    }
}

#[derive(Debug, Clone)]
pub struct WordlistInfo {
    pub name: String,
    pub source: String,
    pub line_count: usize,
    pub size_kb: usize,
    pub installed: bool,
}

impl Default for WordlistManager {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_creation() {
        let manager = WordlistManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_get_embedded_wordlist() {
        let manager = WordlistManager::new().unwrap();
        let wordlist = manager.get("subdomains-top100");
        assert!(wordlist.is_ok());
        assert!(!wordlist.unwrap().is_empty());
    }

    #[test]
    fn test_list_wordlists() {
        let manager = WordlistManager::new().unwrap();
        let wordlists = manager.list();
        assert!(!wordlists.is_empty());
        // At least the embedded wordlists should be available
        assert!(wordlists.iter().any(|w| w.name == "subdomains-top100"));
    }
}
