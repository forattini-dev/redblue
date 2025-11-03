/// Directory and file fuzzing module
///
/// Replaces: ffuf, feroxbuster, gobuster
///
/// Features:
/// - High-performance concurrent fuzzing
/// - Wordlist-based discovery
/// - Status code filtering
/// - Response size analysis
/// - Auto-detection of interesting files
///
/// NO external dependencies - pure Rust implementation
use crate::modules::network::scanner::ScanProgress;
use crate::protocols::http::HttpClient;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub path: String,
    pub status_code: u16,
    pub size: usize,
    pub interesting: bool,
}

#[derive(Debug, Clone)]
pub struct FuzzStats {
    pub total_requests: usize,
    pub found: usize,
    pub errors: usize,
    pub duration_ms: u128,
}

pub struct DirectoryFuzzer {
    base_url: String,
    wordlist_path: String,
    threads: usize,
    filter_status: Vec<u16>,
    match_status: Vec<u16>,
    recursive: bool,
    max_depth: usize,
    progress: Option<Arc<dyn ScanProgress>>,
}

impl DirectoryFuzzer {
    pub fn new(base_url: &str, wordlist_path: &str) -> Self {
        let base_url = if base_url.ends_with('/') {
            base_url.trim_end_matches('/').to_string()
        } else {
            base_url.to_string()
        };

        Self {
            base_url,
            wordlist_path: wordlist_path.to_string(),
            threads: 50,
            filter_status: vec![404], // Default: filter out 404s
            match_status: Vec::new(), // Empty = match all
            recursive: false,
            max_depth: 3, // Default: 3 levels deep
            progress: None,
        }
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1).min(500);
        self
    }

    pub fn with_filter_status(mut self, codes: Vec<u16>) -> Self {
        self.filter_status = codes;
        self
    }

    pub fn with_match_status(mut self, codes: Vec<u16>) -> Self {
        self.match_status = codes;
        self
    }

    pub fn with_recursive(mut self, max_depth: usize) -> Self {
        self.recursive = true;
        self.max_depth = max_depth.max(1).min(10); // Limit: 1-10 levels
        self
    }

    pub fn with_progress(mut self, progress: Arc<dyn ScanProgress>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Run directory fuzzing
    pub fn fuzz(&self) -> Result<(Vec<FuzzResult>, FuzzStats), String> {
        // HTTPS supported via native TLS client

        if self.recursive {
            self.fuzz_recursive()
        } else {
            self.fuzz_single_level(&self.base_url, 0)
        }
    }

    /// Run recursive fuzzing (feroxbuster-style)
    fn fuzz_recursive(&self) -> Result<(Vec<FuzzResult>, FuzzStats), String> {
        let start = std::time::Instant::now();

        // Shared state
        let all_results = Arc::new(Mutex::new(Vec::new()));
        let visited_paths = Arc::new(Mutex::new(HashSet::new()));
        let directory_queue = Arc::new(Mutex::new(vec![(self.base_url.clone(), 0)]));
        let total_errors = Arc::new(Mutex::new(0usize));
        let total_requests = Arc::new(Mutex::new(0usize));

        loop {
            // Get next directory to fuzz
            let current = {
                let mut queue = directory_queue.lock().unwrap();
                queue.pop()
            };

            let (current_url, depth) = match current {
                Some(item) => item,
                None => break, // Queue is empty, we're done
            };

            // Check if already visited
            {
                let mut visited = visited_paths.lock().unwrap();
                if visited.contains(&current_url) {
                    continue;
                }
                visited.insert(current_url.clone());
            }

            // Fuzz this directory level
            let (results, stats) = self.fuzz_single_level(&current_url, depth)?;

            // Update total stats
            {
                let mut errors = total_errors.lock().unwrap();
                *errors += stats.errors;
            }
            {
                let mut requests = total_requests.lock().unwrap();
                *requests += stats.total_requests;
            }

            // Process results
            for result in &results {
                // Add to global results
                {
                    let mut all = all_results.lock().unwrap();
                    all.push(result.clone());
                }

                // If it's a directory (status 200-299, no extension), add to queue
                if depth < self.max_depth && Self::is_directory(result) {
                    let new_url = format!("{}/{}", current_url, result.path);
                    let mut queue = directory_queue.lock().unwrap();
                    queue.push((new_url, depth + 1));
                }
            }
        }

        // Collect final results
        let final_results = match Arc::try_unwrap(all_results) {
            Ok(mutex) => mutex.into_inner().unwrap_or_default(),
            Err(arc) => arc.lock().unwrap().clone(),
        };

        let error_count = match Arc::try_unwrap(total_errors) {
            Ok(mutex) => mutex.into_inner().unwrap_or(0),
            Err(arc) => *arc.lock().unwrap(),
        };

        let request_count = match Arc::try_unwrap(total_requests) {
            Ok(mutex) => mutex.into_inner().unwrap_or(0),
            Err(arc) => *arc.lock().unwrap(),
        };

        let stats = FuzzStats {
            total_requests: request_count,
            found: final_results.len(),
            errors: error_count,
            duration_ms: start.elapsed().as_millis(),
        };

        Ok((final_results, stats))
    }

    /// Fuzz a single directory level (non-recursive)
    fn fuzz_single_level(
        &self,
        base_url: &str,
        _depth: usize,
    ) -> Result<(Vec<FuzzResult>, FuzzStats), String> {
        let start = std::time::Instant::now();

        // Load wordlist
        let words = self.load_wordlist()?;
        if words.is_empty() {
            return Err("Wordlist is empty".to_string());
        }

        let total_words = words.len();

        // Shared state
        let word_queue = Arc::new(Mutex::new(words));
        let results = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(0usize));

        // Spawn worker threads
        let progress = self.progress.clone();

        let mut handles = Vec::new();
        for _ in 0..self.threads {
            let queue = Arc::clone(&word_queue);
            let results = Arc::clone(&results);
            let errors = Arc::clone(&errors);
            let base_url = base_url.to_string();
            let filter_status = self.filter_status.clone();
            let match_status = self.match_status.clone();
            let progress = progress.as_ref().map(Arc::clone);

            let handle = thread::spawn(move || {
                let client = HttpClient::new();
                loop {
                    // Get next word
                    let word = {
                        let mut guard = queue.lock().unwrap();
                        guard.pop()
                    };

                    let word = match word {
                        Some(w) => w,
                        None => break,
                    };

                    // Construct URL
                    let url = format!("{}/{}", base_url, word);

                    // Make request
                    match client.get(&url) {
                        Ok(response) => {
                            let status = response.status_code;

                            if let Some(p) = progress.as_ref() {
                                p.inc(1);
                            }

                            // Apply filters
                            if !filter_status.is_empty() && filter_status.contains(&status) {
                                continue;
                            }

                            // Apply matches (if specified)
                            if !match_status.is_empty() && !match_status.contains(&status) {
                                continue;
                            }

                            // Determine if interesting
                            let interesting = Self::is_interesting(status, &response.body);

                            let result = FuzzResult {
                                path: word,
                                status_code: status,
                                size: response.body.len(),
                                interesting,
                            };

                            let mut guard = results.lock().unwrap();
                            guard.push(result);
                        }
                        Err(_) => {
                            let mut guard = errors.lock().unwrap();
                            *guard += 1;
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for completion
        for handle in handles {
            let _ = handle.join();
        }

        // Collect results
        let mut final_results = match Arc::try_unwrap(results) {
            Ok(mutex) => mutex.into_inner().unwrap_or_default(),
            Err(arc) => arc.lock().unwrap().clone(),
        };

        let error_count = match Arc::try_unwrap(errors) {
            Ok(mutex) => mutex.into_inner().unwrap_or(0),
            Err(arc) => *arc.lock().unwrap(),
        };

        // Sort by status code, then path
        final_results.sort_by(|a, b| a.status_code.cmp(&b.status_code).then(a.path.cmp(&b.path)));

        let stats = FuzzStats {
            total_requests: total_words,
            found: final_results.len(),
            errors: error_count,
            duration_ms: start.elapsed().as_millis(),
        };

        Ok((final_results, stats))
    }

    pub fn preview_wordlist_count(&self) -> Result<usize, String> {
        let path = Path::new(&self.wordlist_path);

        if !path.exists() {
            return Ok(0);
        }

        let file = File::open(path).map_err(|e| format!("Failed to open wordlist: {}", e))?;
        let reader = BufReader::new(file);
        let mut count = 0usize;
        for line in reader.lines() {
            if let Ok(word) = line {
                let word = word.trim();
                if !word.is_empty() && !word.starts_with('#') {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    fn load_wordlist(&self) -> Result<Vec<String>, String> {
        let path = Path::new(&self.wordlist_path);

        // Try SecLists wordlists if path doesn't exist
        if !path.exists() {
            // Try to find SecLists wordlists
            let seclists_paths = vec![
                "wordlists/paths-common.txt",
                "wordlists/directories-large.txt",
                "/home/cyber/Work/FF/security/wordlists/paths-common.txt",
                "./wordlists/paths-common.txt",
            ];

            for seclists_path in seclists_paths {
                if Path::new(seclists_path).exists() {
                    if let Ok(content) = std::fs::read_to_string(seclists_path) {
                        let words: Vec<String> = content
                            .lines()
                            .map(|line| line.trim().to_string())
                            .filter(|line| !line.is_empty() && !line.starts_with('#'))
                            .collect();

                        if !words.is_empty() {
                            println!(
                                "  ✅ Loaded {} entries from SecLists: {}",
                                words.len(),
                                seclists_path
                            );
                            return Ok(words);
                        }
                    }
                }
            }

            return Err(format!(
                "Wordlist not found: {}\\nTip: Download SecLists wordlists to wordlists/ directory",
                self.wordlist_path
            ));
        }

        let file = File::open(path).map_err(|e| format!("Failed to open wordlist: {}", e))?;

        let reader = BufReader::new(file);
        let mut words = Vec::new();

        for line in reader.lines() {
            if let Ok(word) = line {
                let word = word.trim();
                if !word.is_empty() && !word.starts_with('#') {
                    words.push(word.to_string());
                }
            }
        }

        Ok(words)
    }

    /// Determine if a response is interesting
    fn is_interesting(status: u16, body: &[u8]) -> bool {
        // Success codes are always interesting
        if (200..300).contains(&status) {
            return true;
        }

        // Redirects might be interesting
        if (300..400).contains(&status) {
            return true;
        }

        // Forbidden/Unauthorized suggests something exists
        if status == 401 || status == 403 {
            return true;
        }

        // Large responses might be interesting
        if body.len() > 10_000 {
            return true;
        }

        false
    }

    /// Determine if a result is likely a directory
    fn is_directory(result: &FuzzResult) -> bool {
        // Must be successful response
        if !(200..300).contains(&result.status_code) {
            return false;
        }

        // If path has no extension, likely a directory
        // Check for common file extensions
        let common_extensions = [
            ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".js", ".css", ".xml", ".json",
            ".txt", ".pdf", ".zip", ".tar", ".gz", ".sql", ".bak", ".log", ".conf", ".config",
            ".ini", ".md", ".rst",
        ];

        let path_lower = result.path.to_lowercase();
        for ext in &common_extensions {
            if path_lower.ends_with(ext) {
                return false; // Has file extension, not a directory
            }
        }

        // No extension detected, likely a directory
        true
    }
}

/// Built-in common wordlists
pub struct Wordlists;

impl Wordlists {
    /// Get common web directories
    pub fn common_dirs() -> Vec<&'static str> {
        vec![
            "admin",
            "api",
            "assets",
            "backup",
            "backups",
            "bin",
            "blog",
            "cache",
            "cgi-bin",
            "config",
            "content",
            "css",
            "data",
            "db",
            "dev",
            "dist",
            "doc",
            "docs",
            "download",
            "downloads",
            "etc",
            "files",
            "images",
            "img",
            "include",
            "includes",
            "js",
            "lib",
            "libs",
            "log",
            "logs",
            "media",
            "old",
            "private",
            "public",
            "scripts",
            "secret",
            "src",
            "static",
            "temp",
            "tmp",
            "upload",
            "uploads",
            "vendor",
            "www",
        ]
    }

    /// Get common web files
    pub fn common_files() -> Vec<&'static str> {
        vec![
            ".env",
            ".git",
            ".htaccess",
            ".htpasswd",
            "admin.php",
            "backup.sql",
            "backup.zip",
            "composer.json",
            "config.json",
            "config.php",
            "database.sql",
            "db.sql",
            "env",
            "index.php",
            "package.json",
            "README.md",
            "robots.txt",
            "sitemap.xml",
            "web.config",
            "wp-config.php",
        ]
    }

    /// Create a temporary wordlist file
    pub fn create_temp_wordlist(words: &[&str]) -> Result<String, String> {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("redblue_wordlist.txt");

        let mut file = File::create(&temp_path)
            .map_err(|e| format!("Failed to create temp wordlist: {}", e))?;

        for word in words {
            writeln!(file, "{}", word).map_err(|e| format!("Failed to write wordlist: {}", e))?;
        }

        Ok(temp_path.to_string_lossy().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzer_creation() {
        let fuzzer = DirectoryFuzzer::new("http://example.com", "/tmp/wordlist.txt");
        assert_eq!(fuzzer.base_url, "http://example.com");
        assert_eq!(fuzzer.threads, 50);
    }

    #[test]
    fn test_url_normalization() {
        let fuzzer = DirectoryFuzzer::new("http://example.com/", "/tmp/wordlist.txt");
        assert_eq!(fuzzer.base_url, "http://example.com");
    }

    #[test]
    fn test_is_interesting() {
        assert!(DirectoryFuzzer::is_interesting(200, &[]));
        assert!(DirectoryFuzzer::is_interesting(301, &[]));
        assert!(DirectoryFuzzer::is_interesting(403, &[]));
        assert!(!DirectoryFuzzer::is_interesting(404, &[]));
    }

    #[test]
    fn test_common_wordlists() {
        let dirs = Wordlists::common_dirs();
        assert!(!dirs.is_empty());
        assert!(dirs.contains(&"admin"));

        let files = Wordlists::common_files();
        assert!(!files.is_empty());
        assert!(files.contains(&".env"));
    }
}
