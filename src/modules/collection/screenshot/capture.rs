use super::cdp::CdpClient;
/// Screenshot Capture Engine
///
/// Multi-threaded screenshot capture with Chrome DevTools Protocol
use super::{BatchResult, ScreenshotConfig, ScreenshotResult};
use std::collections::VecDeque;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

/// Screenshot capture engine
pub struct ScreenshotCapture {
    config: ScreenshotConfig,
}

impl ScreenshotCapture {
    pub fn new(config: ScreenshotConfig) -> Self {
        Self { config }
    }

    /// Capture screenshot of a single URL
    pub fn capture(&self, url: &str) -> ScreenshotResult {
        let start = Instant::now();
        let mut result = ScreenshotResult::new(url);

        // Create output directory
        if let Err(e) = fs::create_dir_all(&self.config.output_dir) {
            result.error = Some(format!("Failed to create output directory: {}", e));
            return result;
        }

        // Launch Chrome and capture
        let mut client = CdpClient::new(self.config.debug_port);

        if let Err(e) = client.launch_chrome(self.config.chrome_path.as_deref()) {
            result.error = Some(e);
            return result;
        }

        if let Err(e) = client.connect() {
            result.error = Some(e);
            return result;
        }

        // Set viewport and user agent
        if let Err(e) = client.set_viewport(self.config.viewport_width, self.config.viewport_height)
        {
            result.error = Some(e);
            return result;
        }

        if let Err(e) = client.set_user_agent(&self.config.user_agent) {
            result.error = Some(e);
            return result;
        }

        // Navigate to URL
        if let Err(e) = client.navigate(url) {
            result.error = Some(e);
            return result;
        }

        // Wait for JavaScript rendering
        thread::sleep(self.config.js_render_wait);

        // Get page title
        if let Ok(title) = client.get_title() {
            result.title = Some(title);
        }

        // Capture screenshot
        match client.capture_screenshot(self.config.full_page, self.config.quality) {
            Ok(screenshot_data) => {
                let filename = self.generate_filename(url, "jpg");
                let screenshot_path = self.config.output_dir.join(&filename);

                if let Err(e) = fs::write(&screenshot_path, &screenshot_data) {
                    result.error = Some(format!("Failed to save screenshot: {}", e));
                } else {
                    result.screenshot_path = Some(screenshot_path.clone());
                    result.file_size = screenshot_data.len() as u64;
                    result.width = self.config.viewport_width;
                    result.height = self.config.viewport_height;

                    // Generate thumbnail if enabled
                    if self.config.generate_thumbnails {
                        let thumb_filename = self.generate_filename(url, "thumb.jpg");
                        let thumb_path = self.config.output_dir.join(&thumb_filename);

                        if let Ok(thumb_data) = self.create_thumbnail(&screenshot_data) {
                            if fs::write(&thumb_path, &thumb_data).is_ok() {
                                result.thumbnail_path = Some(thumb_path);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                result.error = Some(e);
            }
        }

        result.load_time_ms = start.elapsed().as_millis() as u64;

        // Close browser
        client.close();

        result
    }

    /// Capture screenshots of multiple URLs
    pub fn capture_batch(&self, urls: &[String]) -> BatchResult {
        let start = Instant::now();
        let mut batch_result = BatchResult::new();

        // Create output directory
        if let Err(_e) = fs::create_dir_all(&self.config.output_dir) {
            return batch_result;
        }

        // Use thread pool for parallel capture
        let results = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(urls.to_vec())));
        let config = Arc::new(self.config.clone());

        let mut handles = Vec::new();
        let num_threads = self.config.threads.min(urls.len().max(1));

        for thread_id in 0..num_threads {
            let queue = Arc::clone(&queue);
            let results = Arc::clone(&results);
            let config = Arc::clone(&config);
            // Use different port for each thread
            let debug_port = config.debug_port + thread_id as u16;

            let handle = thread::spawn(move || {
                // Create capture instance for this thread
                let mut thread_config = (*config).clone();
                thread_config.debug_port = debug_port;
                let capture = ScreenshotCapture::new(thread_config);

                loop {
                    let url = {
                        let mut q = queue.lock().unwrap();
                        q.pop_front()
                    };

                    match url {
                        Some(url) => {
                            let result = capture.capture(&url);
                            results.lock().unwrap().push(result);
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

        // Collect results
        let results = Arc::try_unwrap(results)
            .unwrap_or_else(|_| panic!("Failed to unwrap results"))
            .into_inner()
            .unwrap();

        for result in results {
            batch_result.add_result(result);
        }

        batch_result.total_time_ms = start.elapsed().as_millis() as u64;

        batch_result
    }

    /// Generate filename from URL
    fn generate_filename(&self, url: &str, extension: &str) -> String {
        // Sanitize URL for filename
        let sanitized: String = url
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .take(100)
            .collect();

        // Add timestamp for uniqueness
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        format!("{}_{}.{}", sanitized, timestamp, extension)
    }

    /// Create thumbnail from screenshot data
    fn create_thumbnail(&self, _data: &[u8]) -> Result<Vec<u8>, String> {
        // Note: True image resizing would require an image processing library
        // Since we can't use external crates, we return the original data
        // In a real implementation, this would resize the JPEG
        //
        // For a proper implementation without external crates, we'd need to:
        // 1. Parse JPEG format
        // 2. Decode image data
        // 3. Resize using bilinear/bicubic interpolation
        // 4. Re-encode as JPEG
        //
        // This is a significant undertaking (~1000+ lines of code)
        // For now, we'll note this as a limitation

        Err("Thumbnail generation requires image processing (not implemented without external crates)".to_string())
    }

    /// Capture with fallback to HTTP-only method
    pub fn capture_http_fallback(&self, url: &str) -> ScreenshotResult {
        let start = Instant::now();
        let mut result = ScreenshotResult::new(url);

        // If Chrome isn't available, try HTTP-only capture
        // This captures HTML/CSS metadata but can't render JavaScript

        // Create output directory
        if let Err(e) = fs::create_dir_all(&self.config.output_dir) {
            result.error = Some(format!("Failed to create output directory: {}", e));
            return result;
        }

        // Fetch page via HTTP
        match self.fetch_page(url) {
            Ok((status, headers, body, final_url)) => {
                result.status_code = Some(status);
                result.headers = headers.clone();
                result.final_url = final_url;

                // Extract server header
                for (name, value) in &headers {
                    if name.to_lowercase() == "server" {
                        result.server = Some(value.clone());
                        break;
                    }
                }

                // Extract title from HTML
                if let Some(title) = extract_html_title(&body) {
                    result.title = Some(title);
                }

                // Detect technologies
                result.technologies = detect_technologies(&headers, &body);

                // Save HTML for reference
                let html_filename = self.generate_filename(url, "html");
                let html_path = self.config.output_dir.join(&html_filename);
                let _ = fs::write(&html_path, &body);

                // Note: No actual screenshot in HTTP-only mode
                result.error = Some("HTTP-only mode: No browser screenshot available".to_string());
            }
            Err(e) => {
                result.error = Some(e);
            }
        }

        result.load_time_ms = start.elapsed().as_millis() as u64;

        result
    }

    /// Fetch page via HTTP
    fn fetch_page(
        &self,
        url: &str,
    ) -> Result<(u16, Vec<(String, String)>, String, Option<String>), String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let (host, port, path, use_tls) = parse_url(url)?;

        if use_tls {
            return Err("HTTPS not supported in HTTP-only fallback mode".to_string());
        }

        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
             Connection: close\r\n\
             \r\n",
            path, host, self.config.user_agent
        );

        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| format!("Invalid address: {}", e))?,
            self.config.timeout,
        )
        .map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(self.config.timeout)).ok();
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("Request failed: {}", e))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).ok();

        let text = String::from_utf8_lossy(&response);
        let mut lines = text.lines();

        // Parse status
        let status_line = lines.next().ok_or("Empty response")?;
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        // Parse headers
        let mut headers = Vec::new();
        let mut final_url = None;

        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some(pos) = line.find(':') {
                let name = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();

                if name.to_lowercase() == "location" {
                    final_url = Some(value.clone());
                }

                headers.push((name, value));
            }
        }

        // Body
        let body_start = text
            .find("\r\n\r\n")
            .map(|p| p + 4)
            .or_else(|| text.find("\n\n").map(|p| p + 2))
            .unwrap_or(text.len());
        let body = text[body_start..].to_string();

        Ok((status, headers, body, final_url))
    }
}

/// Parse URL into components
fn parse_url(url: &str) -> Result<(String, u16, String, bool), String> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        ("http", url)
    };

    let use_tls = scheme == "https";
    let default_port = if use_tls { 443 } else { 80 };

    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(pos) => (
            &host_port[..pos],
            host_port[pos + 1..].parse().unwrap_or(default_port),
        ),
        None => (host_port, default_port),
    };

    Ok((host.to_string(), port, path.to_string(), use_tls))
}

/// Extract title from HTML
fn extract_html_title(html: &str) -> Option<String> {
    let html_lower = html.to_lowercase();

    if let Some(start) = html_lower.find("<title>") {
        let content_start = start + 7;
        if let Some(end) = html_lower[content_start..].find("</title>") {
            let title = &html[content_start..content_start + end];
            return Some(title.trim().to_string());
        }
    }

    None
}

/// Detect technologies from headers and HTML
fn detect_technologies(headers: &[(String, String)], body: &str) -> Vec<String> {
    let mut technologies = Vec::new();
    let body_lower = body.to_lowercase();

    // Check headers
    for (name, value) in headers {
        let name_lower = name.to_lowercase();
        let value_lower = value.to_lowercase();

        if name_lower == "server" {
            if value_lower.contains("nginx") {
                technologies.push("nginx".to_string());
            } else if value_lower.contains("apache") {
                technologies.push("Apache".to_string());
            } else if value_lower.contains("iis") {
                technologies.push("IIS".to_string());
            } else if value_lower.contains("cloudflare") {
                technologies.push("Cloudflare".to_string());
            }
        }

        if name_lower == "x-powered-by" {
            if value_lower.contains("php") {
                technologies.push("PHP".to_string());
            } else if value_lower.contains("asp") {
                technologies.push("ASP.NET".to_string());
            } else if value_lower.contains("express") {
                technologies.push("Express.js".to_string());
            }
        }
    }

    // Check HTML
    if body_lower.contains("/wp-content/") || body_lower.contains("/wp-includes/") {
        technologies.push("WordPress".to_string());
    }
    if body_lower.contains("drupal") {
        technologies.push("Drupal".to_string());
    }
    if body_lower.contains("joomla") {
        technologies.push("Joomla".to_string());
    }
    if body_lower.contains("react") || body_lower.contains("__next") {
        technologies.push("React".to_string());
    }
    if body_lower.contains("angular") || body_lower.contains("ng-version") {
        technologies.push("Angular".to_string());
    }
    if body_lower.contains("vue.js") || body_lower.contains("v-cloak") {
        technologies.push("Vue.js".to_string());
    }
    if body_lower.contains("jquery") {
        technologies.push("jQuery".to_string());
    }
    if body_lower.contains("bootstrap") {
        technologies.push("Bootstrap".to_string());
    }

    // Deduplicate
    technologies.sort();
    technologies.dedup();

    technologies
}
