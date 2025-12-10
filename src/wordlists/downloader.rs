/// Wordlist downloader - handles downloading from remote sources
use crate::cli::output::Output;
use crate::compression::gzip_decompress;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Known wordlist sources with metadata
pub struct WordlistSource {
    pub name: &'static str,
    pub description: &'static str,
    pub url: &'static str,
    pub size_hint: &'static str,
    pub category: WordlistCategory,
    pub compressed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WordlistCategory {
    Passwords,
    Subdomains,
    Directories,
    Usernames,
    Mixed,
}

/// Registry of known wordlist sources
pub fn get_wordlist_sources() -> Vec<WordlistSource> {
    vec![
        // Password wordlists
        WordlistSource {
            name: "rockyou",
            description: "Famous RockYou breach passwords (14M entries)",
            url: "https://weakpass.com/wordlists/rockyou.txt",
            size_hint: "~140MB",
            category: WordlistCategory::Passwords,
            compressed: false,
        },
        WordlistSource {
            name: "rockyou-75",
            description: "RockYou top 75k most common passwords",
            url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt",
            size_hint: "~600KB",
            category: WordlistCategory::Passwords,
            compressed: false,
        },
        WordlistSource {
            name: "common-passwords",
            description: "10k most common passwords",
            url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
            size_hint: "~80KB",
            category: WordlistCategory::Passwords,
            compressed: false,
        },
        WordlistSource {
            name: "darkweb-top1000",
            description: "Top 1000 darkweb passwords",
            url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top1000.txt",
            size_hint: "~10KB",
            category: WordlistCategory::Passwords,
            compressed: false,
        },
        // Subdomain wordlists
        WordlistSource {
            name: "subdomains-top1m",
            description: "Top 1 million subdomains",
            url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
            size_hint: "~50KB",
            category: WordlistCategory::Subdomains,
            compressed: false,
        },
        WordlistSource {
            name: "assetnote-dns",
            description: "Assetnote best DNS wordlist",
            url: "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
            size_hint: "~15MB",
            category: WordlistCategory::Subdomains,
            compressed: false,
        },
        // Directory/web fuzzing
        WordlistSource {
            name: "raft-large-dirs",
            description: "RAFT large directories list",
            url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
            size_hint: "~500KB",
            category: WordlistCategory::Directories,
            compressed: false,
        },
        WordlistSource {
            name: "common-dirs",
            description: "Common web directories",
            url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
            size_hint: "~20KB",
            category: WordlistCategory::Directories,
            compressed: false,
        },
        WordlistSource {
            name: "dirsearch",
            description: "Dirsearch default wordlist",
            url: "https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt",
            size_hint: "~200KB",
            category: WordlistCategory::Directories,
            compressed: false,
        },
        // Username wordlists
        WordlistSource {
            name: "usernames-top",
            description: "Top usernames from breaches",
            url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
            size_hint: "~2KB",
            category: WordlistCategory::Usernames,
            compressed: false,
        },
        WordlistSource {
            name: "names",
            description: "Common first names",
            url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt",
            size_hint: "~100KB",
            category: WordlistCategory::Usernames,
            compressed: false,
        },
        // Compressed wordlists (using native gzip decompression)
        WordlistSource {
            name: "rockyou-gzip",
            description: "RockYou passwords (compressed, 14M entries)",
            url: "https://weakpass.com/wordlists/rockyou.txt.gz",
            size_hint: "~60MB compressed -> ~140MB",
            category: WordlistCategory::Passwords,
            compressed: true,
        },
    ]
}

/// Get a wordlist source by name
pub fn get_source(name: &str) -> Option<&'static WordlistSource> {
    // Use lazy_static or just search each time (it's a small list)
    let sources = get_wordlist_sources();
    for source in sources.iter() {
        if source.name == name {
            // This is a workaround since we can't return a reference to local data
            // In practice, we'll match and return the static data
            return None; // We'll handle this differently
        }
    }
    None
}

pub struct Downloader {
    cache_dir: PathBuf,
}

impl Downloader {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    /// Download SecLists collection via git clone
    pub fn download_seclists(&self) -> Result<(), String> {
        Output::header("Installing SecLists");
        Output::info("This will download ~1.2GB of security wordlists");

        let target = self.cache_dir.join("seclists");

        // Check if already exists AND is a valid git repo
        // An empty or corrupted directory should not block re-installation
        if target.exists() {
            let git_dir = target.join(".git");
            if git_dir.exists() {
                return Err(format!(
                    "SecLists already installed at: {}\nRun `rb wordlist update seclists` to update",
                    target.display()
                ));
            }
            // Directory exists but is not a valid git clone - remove it
            Output::warning("Found incomplete installation, removing...");
            fs::remove_dir_all(&target)
                .map_err(|e| format!("Failed to remove incomplete directory: {}", e))?;
        }

        // Check if git is available
        if !self.check_git_available() {
            return Err(
                "Git is not installed.\nPlease install git: sudo apt-get install git".to_string(),
            );
        }

        Output::spinner_start("Cloning repository (this may take 2-3 minutes)");

        let result = Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("https://github.com/danielmiessler/SecLists.git")
            .arg(&target)
            .output();

        Output::spinner_done();

        match result {
            Ok(output) if output.status.success() => {
                Output::success("✓ SecLists installed successfully");
                Output::dim(&format!("  Location: {}", target.display()));

                // Show some stats
                if let Ok(size) = self.calculate_dir_size(&target) {
                    let size_mb = size / 1024 / 1024;
                    Output::dim(&format!("  Size: {}MB", size_mb));
                }

                Ok(())
            }
            Ok(output) => {
                let error = String::from_utf8_lossy(&output.stderr);
                Err(format!("Failed to download SecLists: {}", error))
            }
            Err(e) => Err(format!("Failed to execute git: {}", e)),
        }
    }

    /// Download Assetnote best-dns-wordlist
    pub fn download_assetnote_dns(&self) -> Result<(), String> {
        Output::header("Installing Assetnote DNS Wordlist");

        let target = self.cache_dir.join("assetnote");
        fs::create_dir_all(&target).map_err(|e| format!("Failed to create directory: {}", e))?;

        let file_path = target.join("best-dns-wordlist.txt");

        if file_path.exists() {
            return Err(format!(
                "Assetnote DNS wordlist already installed at: {}",
                file_path.display()
            ));
        }

        let url = "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt";

        Output::spinner_start("Downloading wordlist");

        // Use curl or wget depending on what's available
        let result = if self.check_curl_available() {
            Command::new("curl")
                .arg("-L")
                .arg("-o")
                .arg(&file_path)
                .arg(url)
                .output()
        } else if self.check_wget_available() {
            Command::new("wget")
                .arg("-O")
                .arg(&file_path)
                .arg(url)
                .output()
        } else {
            Output::spinner_done();
            return Err(
                "Neither curl nor wget found.\nPlease install: sudo apt-get install curl"
                    .to_string(),
            );
        };

        Output::spinner_done();

        match result {
            Ok(output) if output.status.success() => {
                Output::success("✓ Assetnote DNS wordlist installed");
                Output::dim(&format!("  Location: {}", file_path.display()));

                if let Ok(metadata) = fs::metadata(&file_path) {
                    let size_kb = metadata.len() / 1024;
                    Output::dim(&format!("  Size: {}KB", size_kb));
                }

                Ok(())
            }
            Ok(output) => {
                let error = String::from_utf8_lossy(&output.stderr);
                Err(format!("Failed to download: {}", error))
            }
            Err(e) => Err(format!("Failed to execute download command: {}", e)),
        }
    }

    /// Update SecLists collection
    pub fn update_seclists(&self) -> Result<(), String> {
        Output::header("Updating SecLists");

        let target = self.cache_dir.join("seclists");

        if !target.exists() {
            return Err("SecLists not installed.\nRun: rb wordlist install seclists".to_string());
        }

        Output::spinner_start("Pulling latest changes");

        let result = Command::new("git")
            .arg("-C")
            .arg(&target)
            .arg("pull")
            .arg("origin")
            .arg("master")
            .output();

        Output::spinner_done();

        match result {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);

                if stdout.contains("Already up to date") {
                    Output::info("SecLists is already up to date");
                } else {
                    Output::success("✓ SecLists updated successfully");
                }

                Ok(())
            }
            Ok(output) => {
                let error = String::from_utf8_lossy(&output.stderr);
                Err(format!("Failed to update SecLists: {}", error))
            }
            Err(e) => Err(format!("Failed to execute git: {}", e)),
        }
    }

    /// Remove downloaded wordlist collection
    pub fn remove(&self, name: &str) -> Result<(), String> {
        let target = match name {
            "seclists" => self.cache_dir.join("seclists"),
            "assetnote" | "assetnote-dns" => self.cache_dir.join("assetnote"),
            _ => {
                // Check if it's a single wordlist file
                let file_path = self.cache_dir.join(format!("{}.txt", name));
                if file_path.exists() {
                    fs::remove_file(&file_path)
                        .map_err(|e| format!("Failed to remove file: {}", e))?;
                    Output::success(&format!("✓ Removed {}.txt", name));
                    return Ok(());
                }
                return Err(format!(
                    "Unknown wordlist: {}\nRun `rb wordlist collection sources` to see available",
                    name
                ));
            }
        };

        if !target.exists() {
            return Err(format!("Collection '{}' is not installed", name));
        }

        Output::warning(&format!("Removing: {}", target.display()));

        fs::remove_dir_all(&target).map_err(|e| format!("Failed to remove directory: {}", e))?;

        Output::success(&format!("✓ Removed {}", name));
        Ok(())
    }

    /// Download a wordlist from the registry by name
    pub fn download_wordlist(&self, name: &str) -> Result<(), String> {
        let sources = get_wordlist_sources();

        // Find the source
        let source = sources
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| {
                format!(
                    "Unknown wordlist: '{}'\nRun `rb wordlist collection sources` to see available",
                    name
                )
            })?;

        Output::header(&format!("Installing {}", source.name));
        Output::info(source.description);
        Output::dim(&format!("Size: {}", source.size_hint));
        if source.compressed {
            Output::dim("Format: gzip compressed (will be decompressed natively)");
        }

        // Determine download path
        let download_name = if source.compressed {
            format!("{}.txt.gz", source.name)
        } else {
            format!("{}.txt", source.name)
        };
        let download_path = self.cache_dir.join(&download_name);

        // Final output path (always .txt)
        let final_name = format!("{}.txt", source.name);
        let final_path = self.cache_dir.join(&final_name);

        // Check if already exists
        if final_path.exists() {
            return Err(format!(
                "'{}' already installed at: {}\nUse --force to re-download",
                name,
                final_path.display()
            ));
        }

        Output::spinner_start("Downloading");

        // Use curl or wget
        let result = if self.check_curl_available() {
            Command::new("curl")
                .arg("-L") // Follow redirects
                .arg("-#") // Progress bar
                .arg("-o")
                .arg(&download_path)
                .arg(source.url)
                .output()
        } else if self.check_wget_available() {
            Command::new("wget")
                .arg("-q")
                .arg("--show-progress")
                .arg("-O")
                .arg(&download_path)
                .arg(source.url)
                .output()
        } else {
            Output::spinner_done();
            return Err(
                "Neither curl nor wget found.\nInstall: sudo apt-get install curl".to_string(),
            );
        };

        Output::spinner_done();

        match result {
            Ok(output) if output.status.success() => {
                // Handle compressed files with native decompression
                let output_path = if source.compressed {
                    let decompressed_path = self.decompress_gzip(&download_path)?;
                    // Remove the compressed file
                    let _ = fs::remove_file(&download_path);
                    decompressed_path
                } else {
                    download_path.clone()
                };

                Output::success(&format!("✓ {} installed", source.name));
                Output::dim(&format!("  Location: {}", output_path.display()));

                // Show actual size
                if let Ok(metadata) = fs::metadata(&output_path) {
                    let size = metadata.len();
                    let size_str = if size > 1024 * 1024 {
                        format!("{:.1}MB", size as f64 / 1024.0 / 1024.0)
                    } else {
                        format!("{}KB", size / 1024)
                    };
                    Output::dim(&format!("  Size: {}", size_str));

                    // Count lines (skip for very large files)
                    if size < 50 * 1024 * 1024 {
                        // Only count lines for files < 50MB
                        if let Ok(content) = fs::read_to_string(&output_path) {
                            let lines = content.lines().count();
                            Output::dim(&format!("  Lines: {}", lines));
                        }
                    }
                }

                Ok(())
            }
            Ok(output) => {
                // Clean up failed download
                let _ = fs::remove_file(&download_path);
                let error = String::from_utf8_lossy(&output.stderr);
                Err(format!("Download failed: {}", error))
            }
            Err(e) => {
                let _ = fs::remove_file(&download_path);
                Err(format!("Failed to execute download: {}", e))
            }
        }
    }

    /// List all available wordlist sources
    pub fn list_sources(&self) -> Vec<WordlistSource> {
        get_wordlist_sources()
    }

    /// Get sources by category
    pub fn get_sources_by_category(&self, category: WordlistCategory) -> Vec<WordlistSource> {
        get_wordlist_sources()
            .into_iter()
            .filter(|s| s.category == category)
            .collect()
    }

    /// Search sources by name or description
    pub fn search_sources(&self, query: &str) -> Vec<WordlistSource> {
        let query_lower = query.to_lowercase();
        get_wordlist_sources()
            .into_iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&query_lower)
                    || s.description.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Check if git is available
    fn check_git_available(&self) -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if curl is available
    fn check_curl_available(&self) -> bool {
        Command::new("curl")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if wget is available
    fn check_wget_available(&self) -> bool {
        Command::new("wget")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Decompress a gzip file using native implementation (RFC 1952/1951)
    ///
    /// Zero external dependencies - all decompression done in pure Rust.
    fn decompress_gzip(&self, gz_path: &Path) -> Result<PathBuf, String> {
        Output::spinner_start("Decompressing (native)");

        // Read compressed data
        let compressed =
            fs::read(gz_path).map_err(|e| format!("Failed to read gzip file: {}", e))?;

        // Decompress using our native implementation
        let decompressed = gzip_decompress(&compressed)
            .map_err(|e| format!("Decompression failed: {}", e))?;

        Output::spinner_done();

        // Determine output path (remove .gz extension)
        let output_path = if gz_path.extension().map_or(false, |ext| ext == "gz") {
            gz_path.with_extension("")
        } else {
            // If no .gz extension, append .txt
            let stem = gz_path.file_stem().unwrap_or_default();
            let parent = gz_path.parent().unwrap_or(Path::new("."));
            parent.join(format!("{}.txt", stem.to_string_lossy()))
        };

        // Write decompressed data
        fs::write(&output_path, &decompressed)
            .map_err(|e| format!("Failed to write decompressed file: {}", e))?;

        Output::dim(&format!(
            "  Decompressed: {} -> {} bytes",
            compressed.len(),
            decompressed.len()
        ));

        Ok(output_path)
    }

    /// Calculate directory size recursively
    fn calculate_dir_size(&self, path: &Path) -> Result<u64, String> {
        let mut total = 0u64;

        if path.is_dir() {
            for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let metadata = entry.metadata().map_err(|e| e.to_string())?;

                if metadata.is_file() {
                    total += metadata.len();
                } else if metadata.is_dir() {
                    total += self.calculate_dir_size(&entry.path())?;
                }
            }
        }

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_downloader_creation() {
        let downloader = Downloader::new(PathBuf::from("/tmp/test"));
        assert_eq!(downloader.cache_dir, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_git_check() {
        let downloader = Downloader::new(PathBuf::from("/tmp/test"));
        // Git should be available in CI/development environments
        // If this fails, git is not installed
        let _ = downloader.check_git_available();
    }
}
