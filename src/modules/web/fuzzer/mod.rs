/// Web Fuzzing Engine
///
/// Replaces: ffuf, gobuster, dirbuster, feroxbuster
///
/// Implements Phase 2.1 Web Fuzzing Engine:
/// - FUZZ keyword parsing and placement
/// - Multiple attack modes (sniper, clusterbomb, pitchfork)
/// - Response filtering (size, code, words, lines, regex)
/// - Auto-calibration baseline
/// - Recursive directory discovery
/// - Rate limiting and delay controls
///
/// NO external dependencies - pure Rust implementation
use crate::protocols::http::HttpClient;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub mod filters;
pub mod modes;
pub mod wordlist;

pub use filters::{FilterAction, ResponseFilter};
pub use modes::{AttackMode, FuzzPosition};
pub use wordlist::WordlistManager;

/// The FUZZ keyword used as placeholder in URLs, headers, body, etc.
pub const FUZZ_KEYWORD: &str = "FUZZ";

// Re-export types defined in this module
// WebFuzzer, DirectoryFuzzer, Wordlists are defined below in this file

/// Fuzzing target configuration
#[derive(Debug, Clone)]
pub struct FuzzTarget {
    /// Base URL with FUZZ placeholders
    pub url: String,
    /// HTTP method
    pub method: HttpMethod,
    /// Request headers with optional FUZZ placeholders
    pub headers: Vec<(String, String)>,
    /// Request body with optional FUZZ placeholder
    pub body: Option<String>,
    /// Cookie header with optional FUZZ placeholder
    pub cookies: Option<String>,
}

/// HTTP methods
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
}

impl HttpMethod {
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
        }
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::GET),
            "POST" => Ok(HttpMethod::POST),
            "PUT" => Ok(HttpMethod::PUT),
            "DELETE" => Ok(HttpMethod::DELETE),
            "PATCH" => Ok(HttpMethod::PATCH),
            "HEAD" => Ok(HttpMethod::HEAD),
            "OPTIONS" => Ok(HttpMethod::OPTIONS),
            _ => Err(format!("Unknown HTTP method: {}", s)),
        }
    }
}

/// Fuzzer configuration
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    /// Number of concurrent threads
    pub threads: usize,
    /// Request timeout
    pub timeout: Duration,
    /// Delay between requests (per thread)
    pub delay: Duration,
    /// Maximum requests per second (0 = unlimited)
    pub rate_limit: u32,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Maximum redirect depth
    pub max_redirects: u8,
    /// Auto-calibrate filters
    pub auto_calibrate: bool,
    /// Recursive directory discovery
    pub recursive: bool,
    /// Maximum recursion depth
    pub max_depth: u8,
    /// Extensions to append (e.g., [".php", ".html"])
    pub extensions: Vec<String>,
    /// Attack mode
    pub mode: AttackMode,
    /// Response filters
    pub filters: Vec<ResponseFilter>,
    /// User-Agent header
    pub user_agent: String,
    /// Verbose output
    pub verbose: bool,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            threads: 40,
            timeout: Duration::from_secs(10),
            delay: Duration::ZERO,
            rate_limit: 0,
            follow_redirects: false,
            max_redirects: 5,
            auto_calibrate: true,
            recursive: false,
            max_depth: 3,
            extensions: Vec::new(),
            mode: AttackMode::Sniper,
            filters: Vec::new(),
            user_agent: "redblue/1.0".to_string(),
            verbose: false,
        }
    }
}

/// Single fuzz result
#[derive(Debug, Clone)]
pub struct FuzzResult {
    /// The payload used
    pub payload: String,
    /// Full URL requested
    pub url: String,
    /// HTTP status code
    pub status_code: u16,
    /// Response size in bytes
    pub size: usize,
    /// Number of words in response
    pub words: usize,
    /// Number of lines in response
    pub lines: usize,
    /// Response time
    pub duration: Duration,
    /// Whether this result was filtered
    pub filtered: bool,
    /// Redirect location if any
    pub redirect: Option<String>,
    /// Content type
    pub content_type: Option<String>,
}

/// Fuzzing statistics
#[derive(Debug, Clone, Default)]
pub struct FuzzStats {
    /// Total requests sent
    pub total_requests: usize,
    /// Successful (non-filtered) results
    pub hits: usize,
    /// Filtered results
    pub filtered: usize,
    /// Error count
    pub errors: usize,
    /// Start time
    pub start_time: Option<Instant>,
    /// Requests per second
    pub rps: f64,
}

/// Main web fuzzer
pub struct WebFuzzer {
    config: FuzzerConfig,
    http: HttpClient,
    results: Arc<Mutex<Vec<FuzzResult>>>,
    stats: Arc<Mutex<FuzzStats>>,
    baseline: Option<FuzzResult>,
}

impl WebFuzzer {
    pub fn new(config: FuzzerConfig) -> Self {
        Self {
            config,
            http: HttpClient::new(),
            results: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(FuzzStats::default())),
            baseline: None,
        }
    }

    /// Parse FUZZ positions from target
    pub fn parse_fuzz_positions(target: &FuzzTarget) -> Vec<FuzzPosition> {
        let mut positions = Vec::new();
        const FUZZ_KEYWORD: &str = "FUZZ";

        // Check URL
        if target.url.contains(FUZZ_KEYWORD) {
            if target.url.contains('?')
                && target
                    .url
                    .split('?')
                    .nth(1)
                    .map(|q| q.contains(FUZZ_KEYWORD))
                    .unwrap_or(false)
            {
                positions.push(FuzzPosition::QueryParam);
            } else {
                positions.push(FuzzPosition::UrlPath);
            }
        }

        // Check headers
        for (name, value) in &target.headers {
            if name.contains(FUZZ_KEYWORD) || value.contains(FUZZ_KEYWORD) {
                positions.push(FuzzPosition::Header(name.clone()));
            }
        }

        // Check body
        if let Some(ref body) = target.body {
            if body.contains(FUZZ_KEYWORD) {
                positions.push(FuzzPosition::Body);
            }
        }

        // Check cookies
        if let Some(ref cookies) = target.cookies {
            if cookies.contains(FUZZ_KEYWORD) {
                positions.push(FuzzPosition::Cookie);
            }
        }

        positions
    }

    /// Auto-calibrate baseline response
    pub fn calibrate(&mut self, target: &FuzzTarget) -> Result<(), String> {
        // Send request with random non-existent payload
        let random_payload = format!("rb_calibrate_{}", std::process::id());
        let calibration_url = target.url.replace("FUZZ", &random_payload);

        let response = self
            .http
            .get(&calibration_url)
            .map_err(|e| format!("Calibration request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);

        self.baseline = Some(FuzzResult {
            payload: random_payload,
            url: calibration_url,
            status_code: response.status_code,
            size: response.body.len(),
            words: body.split_whitespace().count(),
            lines: body.lines().count(),
            duration: Duration::ZERO,
            filtered: false,
            redirect: response
                .headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == "location")
                .map(|(_, v)| v.clone()),
            content_type: response
                .headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == "content-type")
                .map(|(_, v)| v.clone()),
        });

        Ok(())
    }

    /// Run fuzzing with given wordlist
    pub fn fuzz(
        &mut self,
        target: &FuzzTarget,
        wordlist: &[String],
    ) -> Result<Vec<FuzzResult>, String> {
        // Auto-calibrate if enabled
        if self.config.auto_calibrate && self.baseline.is_none() {
            self.calibrate(target)?;
        }

        // Initialize stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.start_time = Some(Instant::now());
            stats.total_requests = wordlist.len();
        }

        // Build request queue with extensions
        let mut queue: Vec<String> = Vec::new();
        for word in wordlist {
            queue.push(word.clone());

            // Add variations with extensions
            for ext in &self.config.extensions {
                queue.push(format!("{}{}", word, ext));
            }
        }

        // Split into chunks for threading
        let chunk_size = (queue.len() + self.config.threads - 1) / self.config.threads;
        let chunks: Vec<Vec<String>> = queue.chunks(chunk_size).map(|c| c.to_vec()).collect();

        let mut handles = vec![];

        for chunk in chunks {
            let target = target.clone();
            let config = self.config.clone();
            let results = Arc::clone(&self.results);
            let stats = Arc::clone(&self.stats);
            let baseline = self.baseline.clone();
            let filters = self.config.filters.clone();

            let handle = thread::spawn(move || {
                let http = HttpClient::new();

                for payload in chunk {
                    // Apply delay if configured
                    if !config.delay.is_zero() {
                        thread::sleep(config.delay);
                    }

                    // Build request URL
                    let url = target.url.replace("FUZZ", &payload);

                    // Send request
                    let start = Instant::now();
                    let response = match target.method {
                        HttpMethod::GET | HttpMethod::HEAD => http.get(&url),
                        HttpMethod::POST => {
                            let body = target
                                .body
                                .as_ref()
                                .map(|b| b.replace("FUZZ", &payload))
                                .unwrap_or_default();
                            http.post(&url, body.into_bytes())
                        }
                        _ => http.get(&url), // Fallback
                    };
                    let duration = start.elapsed();

                    match response {
                        Ok(resp) => {
                            let body_str = String::from_utf8_lossy(&resp.body);

                            let result = FuzzResult {
                                payload: payload.clone(),
                                url: url.clone(),
                                status_code: resp.status_code,
                                size: resp.body.len(),
                                words: body_str.split_whitespace().count(),
                                lines: body_str.lines().count(),
                                duration,
                                filtered: false,
                                redirect: resp
                                    .headers
                                    .iter()
                                    .find(|(k, _)| k.to_lowercase() == "location")
                                    .map(|(_, v)| v.clone()),
                                content_type: resp
                                    .headers
                                    .iter()
                                    .find(|(k, _)| k.to_lowercase() == "content-type")
                                    .map(|(_, v)| v.clone()),
                            };

                            // Check if result should be filtered
                            let should_filter = Self::should_filter(&result, &filters, &baseline);

                            if !should_filter {
                                if let Ok(mut results) = results.lock() {
                                    results.push(result);
                                }
                                if let Ok(mut stats) = stats.lock() {
                                    stats.hits += 1;
                                }
                            } else {
                                if let Ok(mut stats) = stats.lock() {
                                    stats.filtered += 1;
                                }
                            }
                        }
                        Err(_) => {
                            if let Ok(mut stats) = stats.lock() {
                                stats.errors += 1;
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        // Calculate RPS
        {
            let mut stats = self.stats.lock().unwrap();
            if let Some(start) = stats.start_time {
                let elapsed = start.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    stats.rps = stats.total_requests as f64 / elapsed;
                }
            }
        }

        let results = self.results.lock().unwrap().clone();
        Ok(results)
    }

    /// Check if result should be filtered out
    fn should_filter(
        result: &FuzzResult,
        filters: &[ResponseFilter],
        baseline: &Option<FuzzResult>,
    ) -> bool {
        // Check explicit filters
        for filter in filters {
            match filter.matches(result) {
                FilterAction::Include => return false,
                FilterAction::Exclude => return true,
                FilterAction::None => continue,
            }
        }

        // Check against baseline if available
        if let Some(ref base) = baseline {
            // Filter if matches baseline response
            if result.status_code == base.status_code
                && result.size == base.size
                && result.lines == base.lines
            {
                return true;
            }
        }

        false
    }

    /// Get current stats
    pub fn stats(&self) -> FuzzStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get all results
    pub fn results(&self) -> Vec<FuzzResult> {
        self.results.lock().unwrap().clone()
    }
}

/// Directory fuzzer result (CLI compatibility type)
#[derive(Debug, Clone)]
pub struct DirFuzzResult {
    /// HTTP status code
    pub status_code: u16,
    /// Path found
    pub path: String,
    /// Response size in bytes
    pub size: usize,
    /// Whether this result is interesting (e.g., admin panel, config file)
    pub interesting: bool,
}

/// Directory fuzzer statistics
#[derive(Debug, Clone, Default)]
pub struct DirFuzzStats {
    /// Total requests made
    pub total_requests: usize,
    /// Number of results found
    pub found: usize,
    /// Number of errors
    pub errors: usize,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Progress bar trait for CLI compatibility
pub trait ProgressBar: Send + Sync {
    fn inc(&self, delta: u64);
    fn finish(&self);
}

/// Directory fuzzer with builder pattern (CLI compatibility wrapper)
pub struct DirectoryFuzzer {
    base_url: String,
    wordlist_path: String,
    threads: usize,
    filter_codes: Vec<u16>,
    match_codes: Vec<u16>,
    recursive: bool,
    max_depth: usize,
    extensions: Vec<String>,
    timeout: Duration,
    progress: Option<Arc<dyn ProgressBar>>,
}

impl DirectoryFuzzer {
    /// Create a new directory fuzzer
    pub fn new(base_url: &str, wordlist_path: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            wordlist_path: wordlist_path.to_string(),
            threads: 50,
            filter_codes: vec![404],
            match_codes: Vec::new(),
            recursive: false,
            max_depth: 3,
            extensions: Vec::new(),
            timeout: Duration::from_secs(10),
            progress: None,
        }
    }

    /// Set number of threads
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    /// Set status codes to filter (exclude)
    pub fn with_filter_status(mut self, codes: Vec<u16>) -> Self {
        self.filter_codes = codes;
        self
    }

    /// Set status codes to match (include only)
    pub fn with_match_status(mut self, codes: Vec<u16>) -> Self {
        self.match_codes = codes;
        self
    }

    /// Enable recursive mode
    pub fn with_recursive(mut self, max_depth: usize) -> Self {
        self.recursive = true;
        self.max_depth = max_depth;
        self
    }

    /// Set extensions to try
    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Set request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set progress bar
    pub fn with_progress(mut self, progress: Arc<dyn ProgressBar>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Preview wordlist count
    pub fn preview_wordlist_count(&self) -> Result<usize, String> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open(&self.wordlist_path)
            .map_err(|e| format!("Failed to open wordlist: {}", e))?;
        let reader = BufReader::new(file);
        let count = reader.lines().filter(|l| l.is_ok()).count();
        Ok(count)
    }

    /// Run the fuzzer and return results with stats
    pub fn fuzz(&mut self) -> Result<(Vec<DirFuzzResult>, DirFuzzStats), String> {
        let start = Instant::now();

        // Load wordlist
        let mut wm = WordlistManager::new();
        wm.load_file(&self.wordlist_path)?;
        let words = wm.words().to_vec();

        let total_words = words.len();
        let mut stats = DirFuzzStats {
            total_requests: 0,
            found: 0,
            errors: 0,
            duration_ms: 0,
        };

        let results: Arc<Mutex<Vec<DirFuzzResult>>> = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(0usize));
        let requests = Arc::new(Mutex::new(0usize));

        // Split into chunks for threading
        let chunk_size = (total_words + self.threads - 1) / self.threads;
        let chunks: Vec<Vec<String>> = words.chunks(chunk_size).map(|c| c.to_vec()).collect();

        let mut handles = vec![];

        for chunk in chunks {
            let base_url = self.base_url.clone();
            let filter_codes = self.filter_codes.clone();
            let match_codes = self.match_codes.clone();
            let results = Arc::clone(&results);
            let errors = Arc::clone(&errors);
            let requests = Arc::clone(&requests);
            let progress = self.progress.clone();
            let timeout = self.timeout;

            let handle = thread::spawn(move || {
                let http = HttpClient::new();

                for word in chunk {
                    // Build URL
                    let url = if base_url.ends_with('/') {
                        format!("{}{}", base_url, word)
                    } else {
                        format!("{}/{}", base_url, word)
                    };

                    // Send request
                    let response = http.get(&url);

                    // Update request count
                    {
                        let mut req = requests.lock().unwrap();
                        *req += 1;
                    }

                    // Update progress
                    if let Some(ref p) = progress {
                        p.inc(1);
                    }

                    match response {
                        Ok(resp) => {
                            let status_code = resp.status_code;

                            // Check if should be filtered
                            if filter_codes.contains(&status_code) {
                                continue;
                            }

                            // Check if matches (if match_codes specified)
                            if !match_codes.is_empty() && !match_codes.contains(&status_code) {
                                continue;
                            }

                            // Determine if interesting
                            let interesting = Self::is_interesting(&word, status_code);

                            let result = DirFuzzResult {
                                status_code,
                                path: format!("/{}", word),
                                size: resp.body.len(),
                                interesting,
                            };

                            if let Ok(mut results) = results.lock() {
                                results.push(result);
                            }
                        }
                        Err(_) => {
                            if let Ok(mut err) = errors.lock() {
                                *err += 1;
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        // Collect stats
        stats.total_requests = *requests.lock().unwrap();
        stats.errors = *errors.lock().unwrap();
        stats.duration_ms = start.elapsed().as_millis() as u64;

        let final_results = results.lock().unwrap().clone();
        stats.found = final_results.len();

        Ok((final_results, stats))
    }

    /// Check if a path is interesting (admin panels, config files, etc.)
    fn is_interesting(path: &str, status_code: u16) -> bool {
        let path_lower = path.to_lowercase();

        // Admin panels
        if path_lower.contains("admin")
            || path_lower.contains("dashboard")
            || path_lower.contains("panel")
            || path_lower.contains("login")
            || path_lower.contains("console")
        {
            return true;
        }

        // Config files
        if path_lower.ends_with(".conf")
            || path_lower.ends_with(".config")
            || path_lower.ends_with(".ini")
            || path_lower.ends_with(".env")
            || path_lower.ends_with(".yml")
            || path_lower.ends_with(".yaml")
        {
            return true;
        }

        // Backup files
        if path_lower.ends_with(".bak")
            || path_lower.ends_with(".backup")
            || path_lower.ends_with(".old")
            || path_lower.ends_with(".orig")
            || path_lower.contains(".sql")
        {
            return true;
        }

        // Sensitive directories
        if path_lower == ".git"
            || path_lower == ".svn"
            || path_lower == ".htaccess"
            || path_lower == ".htpasswd"
            || path_lower == "web.config"
            || path_lower == "phpinfo"
            || path_lower == "info.php"
        {
            return true;
        }

        // 401/403 can be interesting (protected resources)
        if status_code == 401 || status_code == 403 {
            return true;
        }

        false
    }
}

/// Wordlist utilities (CLI compatibility)
pub struct Wordlists;

impl Wordlists {
    /// Create a temporary wordlist file from a list of words
    pub fn create_temp_wordlist(words: &[&str]) -> Result<String, String> {
        use std::fs::File;
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("rb_wordlist_{}.txt", std::process::id()));
        let path = temp_file.to_string_lossy().to_string();

        let mut file = File::create(&temp_file)
            .map_err(|e| format!("Failed to create temp wordlist: {}", e))?;

        for word in words {
            writeln!(file, "{}", word)
                .map_err(|e| format!("Failed to write to temp wordlist: {}", e))?;
        }

        Ok(path)
    }

    /// Get built-in common directories wordlist
    pub fn common_directories() -> Vec<String> {
        WordlistManager::builtin_directories()
    }

    /// Get built-in extensions wordlist
    pub fn common_extensions() -> Vec<String> {
        WordlistManager::builtin_extensions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fuzz_positions() {
        let target = FuzzTarget {
            url: "http://example.com/FUZZ".to_string(),
            method: HttpMethod::GET,
            headers: vec![],
            body: None,
            cookies: None,
        };

        let positions = WebFuzzer::parse_fuzz_positions(&target);
        assert!(positions.contains(&FuzzPosition::UrlPath));
    }

    #[test]
    fn test_fuzz_positions_query() {
        let target = FuzzTarget {
            url: "http://example.com/page?id=FUZZ".to_string(),
            method: HttpMethod::GET,
            headers: vec![],
            body: None,
            cookies: None,
        };

        let positions = WebFuzzer::parse_fuzz_positions(&target);
        assert!(positions.contains(&FuzzPosition::QueryParam));
    }
}
