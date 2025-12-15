/// Collection/screenshot command - Web screenshot capture
///
/// Replaces: aquatone, eyewitness, gowitness
///
/// Features:
/// - Chrome DevTools Protocol integration
/// - Multi-threaded capture
/// - HTML gallery report
/// - Technology detection
/// - HTTP fallback mode
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::collection::screenshot::{
    ReportGenerator, ScreenshotCapture, ScreenshotConfig,
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub struct ScreenshotCommand;

impl Command for ScreenshotCommand {
    fn domain(&self) -> &str {
        "collection"
    }

    fn resource(&self) -> &str {
        "screenshot"
    }

    fn description(&self) -> &str {
        "Web screenshot capture and visual reconnaissance (aquatone/eyewitness replacement)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "capture",
                summary: "Capture screenshot of a web page",
                usage: "rb collection screenshot capture <url> [--output DIR]",
            },
            Route {
                verb: "batch",
                summary: "Capture screenshots from a list of URLs",
                usage: "rb collection screenshot batch <file> [--output DIR] [--threads 5]",
            },
            Route {
                verb: "http",
                summary: "Capture using HTTP fallback (no Chrome required)",
                usage: "rb collection screenshot http <url> [--output DIR]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("output", "Output directory for screenshots")
                .with_short('o')
                .with_default("./screenshots"),
            Flag::new("width", "Browser viewport width")
                .with_short('w')
                .with_default("1440"),
            Flag::new("height", "Browser viewport height")
                .with_short('h')
                .with_default("900"),
            Flag::new("timeout", "Page load timeout in seconds")
                .with_short('t')
                .with_default("30"),
            Flag::new("threads", "Number of concurrent captures (batch mode)").with_default("4"),
            Flag::new(
                "full-page",
                "Capture full page screenshot (not just viewport)",
            ),
            Flag::new("quality", "JPEG quality (0-100)").with_default("80"),
            Flag::new("report", "Generate HTML report after batch capture"),
            Flag::new("json", "Generate JSON report"),
            Flag::new("csv", "Generate CSV report"),
            Flag::new("chrome", "Path to Chrome/Chromium binary"),
            Flag::new("port", "Chrome debugging port").with_default("9222"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Capture single screenshot",
                "rb collection screenshot capture https://example.com",
            ),
            (
                "Custom viewport size",
                "rb collection screenshot capture https://example.com --width 1920 --height 1080",
            ),
            (
                "Full page screenshot",
                "rb collection screenshot capture https://example.com --full-page",
            ),
            (
                "Batch capture from file",
                "rb collection screenshot batch urls.txt --threads 10",
            ),
            (
                "Batch with HTML report",
                "rb collection screenshot batch urls.txt --report",
            ),
            (
                "HTTP fallback (no Chrome)",
                "rb collection screenshot http http://example.com",
            ),
            (
                "Custom output directory",
                "rb collection screenshot batch urls.txt --output ./reports/screenshots",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "capture" => self.capture(ctx),
            "batch" => self.batch(ctx),
            "http" => self.http_fallback(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(verb, &["capture", "batch", "http"])
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl ScreenshotCommand {
    /// Build configuration from CLI context
    fn build_config(&self, ctx: &CliContext) -> ScreenshotConfig {
        let output_dir = ctx
            .flags
            .get("output")
            .map(|s| PathBuf::from(s.as_str()))
            .unwrap_or_else(|| PathBuf::from("./screenshots"));

        let width = ctx
            .flags
            .get("width")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1440);

        let height = ctx
            .flags
            .get("height")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(900);

        let timeout = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        let threads = ctx
            .flags
            .get("threads")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4);

        let quality = ctx
            .flags
            .get("quality")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(80);

        let port = ctx
            .flags
            .get("port")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(9222);

        let full_page = ctx.flags.contains_key("full-page");
        let chrome_path = ctx.flags.get("chrome").map(|s| s.clone());

        ScreenshotConfig {
            chrome_path,
            debug_port: port,
            viewport_width: width,
            viewport_height: height,
            timeout: Duration::from_secs(timeout),
            js_render_wait: Duration::from_secs(2),
            quality,
            full_page,
            output_dir,
            threads,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            headers: Vec::new(),
            ignore_tls_errors: true,
            generate_report: ctx.flags.contains_key("report"),
            generate_thumbnails: true,
            thumbnail_width: 300,
        }
    }

    fn capture(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb collection screenshot capture <URL> [--output DIR]\nExample: rb collection screenshot capture https://example.com",
        )?;

        Validator::validate_url(url)?;

        let config = self.build_config(ctx);

        Output::header(&format!("Screenshot Capture: {}", url));
        Output::info(&format!(
            "Viewport: {}x{} ({})",
            config.viewport_width,
            config.viewport_height,
            if config.full_page {
                "full page"
            } else {
                "viewport only"
            }
        ));
        Output::info(&format!("Output: {}", config.output_dir.display()));
        Output::info(&format!("Quality: {}%", config.quality));
        println!();

        // Create output directory
        if let Err(e) = fs::create_dir_all(&config.output_dir) {
            return Err(format!("Failed to create output directory: {}", e));
        }

        Output::spinner_start("Launching Chrome...");

        let capture = ScreenshotCapture::new(config.clone());
        let result = capture.capture(url);

        Output::spinner_done();

        if result.success() {
            Output::success("Screenshot captured successfully!");
            println!();

            Output::section("Result");
            if let Some(ref path) = result.screenshot_path {
                Output::item("Screenshot", &path.display().to_string());
            }
            if let Some(ref title) = result.title {
                Output::item("Page Title", title);
            }
            if let Some(status) = result.status_code {
                Output::item("HTTP Status", &status.to_string());
            }
            Output::item("Load Time", &format!("{}ms", result.load_time_ms));
            Output::item("File Size", &format_size(result.file_size));

            if !result.technologies.is_empty() {
                println!();
                Output::section("Technologies Detected");
                for tech in &result.technologies {
                    println!("  • {}", Output::colorize(tech, "cyan"));
                }
            }
        } else {
            Output::error("Screenshot capture failed");
            if let Some(ref error) = result.error {
                Output::dim(&format!("Error: {}", error));
            }

            println!();
            Output::info("Try HTTP fallback mode:");
            Output::dim(&format!("  rb collection screenshot http {}", url));
        }

        Ok(())
    }

    fn batch(&self, ctx: &CliContext) -> Result<(), String> {
        let file = ctx.target.as_ref().ok_or(
            "Missing file.\nUsage: rb collection screenshot batch <FILE> [--threads 5]\nExample: rb collection screenshot batch urls.txt",
        )?;

        if !std::path::Path::new(file).exists() {
            return Err(format!("File not found: {}", file));
        }

        // Read URLs from file
        let content =
            fs::read_to_string(file).map_err(|e| format!("Failed to read file: {}", e))?;

        let urls: Vec<String> = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        if urls.is_empty() {
            return Err("No valid URLs found in file".to_string());
        }

        let config = self.build_config(ctx);

        Output::header(&format!("Batch Screenshot Capture: {}", file));
        Output::info(&format!("URLs: {}", urls.len()));
        Output::info(&format!("Threads: {}", config.threads));
        Output::info(&format!("Output: {}", config.output_dir.display()));
        println!();

        // Create output directory
        if let Err(e) = fs::create_dir_all(&config.output_dir) {
            return Err(format!("Failed to create output directory: {}", e));
        }

        // Show preview
        Output::section("URLs to Capture");
        for (i, url) in urls.iter().take(5).enumerate() {
            println!("  {}. {}", i + 1, Output::colorize(url, "cyan"));
        }
        if urls.len() > 5 {
            Output::dim(&format!("  ... and {} more", urls.len() - 5));
        }
        println!();

        Output::spinner_start("Capturing screenshots...");

        let capture = ScreenshotCapture::new(config.clone());
        let results = capture.capture_batch(&urls);

        Output::spinner_done();

        // Show results
        Output::section("Results");
        Output::item("Total", &results.results.len().to_string());
        Output::item(
            "Successful",
            &format!("{} \x1b[32m✓\x1b[0m", results.successful),
        );
        Output::item("Failed", &format!("{} \x1b[31m✗\x1b[0m", results.failed));
        Output::item(
            "Total Time",
            &format!("{:.1}s", results.total_time_ms as f64 / 1000.0),
        );
        println!();

        // Generate reports if requested
        if config.generate_report || ctx.flags.contains_key("report") {
            Output::spinner_start("Generating HTML report...");
            let report_gen = ReportGenerator::new(config.clone());
            match report_gen.generate(&results) {
                Ok(path) => {
                    Output::spinner_done();
                    Output::success(&format!("HTML report: {}", path.display()));
                }
                Err(e) => {
                    Output::spinner_done();
                    Output::warning(&format!("Failed to generate HTML report: {}", e));
                }
            }
        }

        if ctx.flags.contains_key("json") {
            let report_gen = ReportGenerator::new(config.clone());
            match report_gen.generate_json(&results) {
                Ok(path) => Output::success(&format!("JSON report: {}", path.display())),
                Err(e) => Output::warning(&format!("Failed to generate JSON report: {}", e)),
            }
        }

        if ctx.flags.contains_key("csv") {
            let report_gen = ReportGenerator::new(config.clone());
            match report_gen.generate_csv(&results) {
                Ok(path) => Output::success(&format!("CSV report: {}", path.display())),
                Err(e) => Output::warning(&format!("Failed to generate CSV report: {}", e)),
            }
        }

        // Show failed URLs
        let failed: Vec<_> = results.results.iter().filter(|r| !r.success()).collect();

        if !failed.is_empty() && failed.len() <= 10 {
            println!();
            Output::section("Failed URLs");
            for result in &failed {
                let error = result.error.as_deref().unwrap_or("Unknown error");
                println!("  \x1b[31m✗\x1b[0m {} - {}", result.url, error);
            }
        }

        Ok(())
    }

    fn http_fallback(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb collection screenshot http <URL>\nExample: rb collection screenshot http http://example.com",
        )?;

        // HTTP fallback only works with http:// URLs
        if url.starts_with("https://") {
            return Err("HTTP fallback mode only supports http:// URLs (no TLS).\nUse 'capture' verb for HTTPS URLs with Chrome.".to_string());
        }

        let config = self.build_config(ctx);

        Output::header(&format!("HTTP Fallback Capture: {}", url));
        Output::warning("Note: HTTP fallback captures metadata only (no JavaScript rendering)");
        println!();

        // Create output directory
        if let Err(e) = fs::create_dir_all(&config.output_dir) {
            return Err(format!("Failed to create output directory: {}", e));
        }

        Output::spinner_start("Fetching page...");

        let capture = ScreenshotCapture::new(config);
        let result = capture.capture_http_fallback(url);

        Output::spinner_done();

        Output::section("Result");

        if let Some(ref title) = result.title {
            Output::item("Page Title", title);
        }
        if let Some(status) = result.status_code {
            let status_color = match status {
                200..=299 => "green",
                300..=399 => "yellow",
                _ => "red",
            };
            Output::item(
                "HTTP Status",
                &Output::colorize(&status.to_string(), status_color),
            );
        }
        if let Some(ref server) = result.server {
            Output::item("Server", server);
        }
        if let Some(ref final_url) = result.final_url {
            Output::item("Redirect To", final_url);
        }
        Output::item("Load Time", &format!("{}ms", result.load_time_ms));

        if !result.technologies.is_empty() {
            println!();
            Output::section("Technologies Detected");
            for tech in &result.technologies {
                println!("  • {}", Output::colorize(tech, "cyan"));
            }
        }

        if !result.headers.is_empty() {
            println!();
            Output::section("Response Headers");
            for (name, value) in result.headers.iter().take(10) {
                println!("  {}: {}", Output::colorize(name, "blue"), value);
            }
            if result.headers.len() > 10 {
                Output::dim(&format!("  ... and {} more", result.headers.len() - 10));
            }
        }

        if let Some(ref error) = result.error {
            println!();
            Output::warning(error);
        }

        Ok(())
    }
}

/// Format file size in human-readable format
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
