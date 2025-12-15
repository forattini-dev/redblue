pub mod capture;
/// Screenshot Capture Module
///
/// Replaces: gowitness, eyewitness, aquatone
///
/// Features:
/// - Chrome DevTools Protocol integration
/// - Multi-threaded capture
/// - HTML report generation
/// - Thumbnail gallery
/// - Response metadata collection
pub mod cdp;
pub mod report;

pub use capture::ScreenshotCapture;
pub use report::ReportGenerator;

use std::path::PathBuf;
use std::time::Duration;

/// Screenshot capture configuration
#[derive(Debug, Clone)]
pub struct ScreenshotConfig {
    /// Chrome/Chromium binary path
    pub chrome_path: Option<String>,
    /// Chrome remote debugging port
    pub debug_port: u16,
    /// Viewport width
    pub viewport_width: u32,
    /// Viewport height
    pub viewport_height: u32,
    /// Page load timeout
    pub timeout: Duration,
    /// Wait for JavaScript rendering
    pub js_render_wait: Duration,
    /// Screenshot quality (JPEG, 0-100)
    pub quality: u8,
    /// Full page screenshot
    pub full_page: bool,
    /// Output directory
    pub output_dir: PathBuf,
    /// Number of threads
    pub threads: usize,
    /// User agent
    pub user_agent: String,
    /// Custom headers
    pub headers: Vec<(String, String)>,
    /// Ignore TLS errors
    pub ignore_tls_errors: bool,
    /// Generate HTML report
    pub generate_report: bool,
    /// Generate thumbnails
    pub generate_thumbnails: bool,
    /// Thumbnail width
    pub thumbnail_width: u32,
}

impl Default for ScreenshotConfig {
    fn default() -> Self {
        Self {
            chrome_path: None,
            debug_port: 9222,
            viewport_width: 1440,
            viewport_height: 900,
            timeout: Duration::from_secs(30),
            js_render_wait: Duration::from_secs(2),
            quality: 80,
            full_page: false,
            output_dir: PathBuf::from("screenshots"),
            threads: 4,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            headers: Vec::new(),
            ignore_tls_errors: true,
            generate_report: true,
            generate_thumbnails: true,
            thumbnail_width: 300,
        }
    }
}

/// Screenshot result for a single URL
#[derive(Debug, Clone)]
pub struct ScreenshotResult {
    /// Target URL
    pub url: String,
    /// Final URL after redirects
    pub final_url: Option<String>,
    /// Screenshot file path
    pub screenshot_path: Option<PathBuf>,
    /// Thumbnail file path
    pub thumbnail_path: Option<PathBuf>,
    /// Page title
    pub title: Option<String>,
    /// HTTP status code
    pub status_code: Option<u16>,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Server header
    pub server: Option<String>,
    /// Technologies detected
    pub technologies: Vec<String>,
    /// Page load time (ms)
    pub load_time_ms: u64,
    /// Error message if failed
    pub error: Option<String>,
    /// Screenshot width
    pub width: u32,
    /// Screenshot height
    pub height: u32,
    /// File size in bytes
    pub file_size: u64,
}

impl ScreenshotResult {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            final_url: None,
            screenshot_path: None,
            thumbnail_path: None,
            title: None,
            status_code: None,
            headers: Vec::new(),
            server: None,
            technologies: Vec::new(),
            load_time_ms: 0,
            error: None,
            width: 0,
            height: 0,
            file_size: 0,
        }
    }

    pub fn success(&self) -> bool {
        self.screenshot_path.is_some() && self.error.is_none()
    }
}

/// Batch screenshot results
#[derive(Debug)]
pub struct BatchResult {
    /// All results
    pub results: Vec<ScreenshotResult>,
    /// Successful captures
    pub successful: usize,
    /// Failed captures
    pub failed: usize,
    /// Total time
    pub total_time_ms: u64,
    /// Report path (if generated)
    pub report_path: Option<PathBuf>,
}

impl BatchResult {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            successful: 0,
            failed: 0,
            total_time_ms: 0,
            report_path: None,
        }
    }

    pub fn add_result(&mut self, result: ScreenshotResult) {
        if result.success() {
            self.successful += 1;
        } else {
            self.failed += 1;
        }
        self.results.push(result);
    }
}

impl Default for BatchResult {
    fn default() -> Self {
        Self::new()
    }
}
