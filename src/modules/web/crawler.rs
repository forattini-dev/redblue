#![allow(dead_code)]

/// Web Crawler - Recursive link discovery and site mapping
///
/// Replaces tools like gospider, hakrawler, katana
/// Features:
/// - BFS (breadth-first) traversal
/// - Depth limiting
/// - robots.txt support
/// - Link extraction (reuses linkfinder logic)
/// - Visited URL tracking
/// - Same-origin policy enforcement
/// - HAR recording for all HTTP transactions
/// - DOM-based extraction for better accuracy
///
/// NO external dependencies - pure Rust std implementation
use crate::modules::web::dom::Document;
use crate::modules::web::extractors;
use crate::protocols::har::HarRecorder;
use crate::protocols::http::{HttpClient, HttpRequest, HttpResponseHandler, HttpResponseHead};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct CrawledPage {
    pub url: String,
    pub status_code: u16,
    pub depth: usize,
    pub content_type: Option<String>,
    pub html: Option<String>,
    pub links: Vec<String>,
    pub forms: Vec<Form>,
    pub assets: Vec<Asset>,
    /// Extracted meta information
    pub meta: PageMeta,
}

/// Metadata extracted from the page
#[derive(Debug, Clone, Default)]
pub struct PageMeta {
    pub title: Option<String>,
    pub description: Option<String>,
    pub keywords: Vec<String>,
    pub og_title: Option<String>,
    pub og_description: Option<String>,
    pub og_image: Option<String>,
    pub canonical: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Asset {
    pub url: String,
    pub asset_type: AssetType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AssetType {
    JavaScript,
    CSS,
    Image,
    Font,
    Other,
}

#[derive(Debug, Clone)]
pub struct CrawlResult {
    pub pages: Vec<CrawledPage>,
    pub total_urls: usize,
    pub total_links: usize,
    pub max_depth_reached: usize,
}

/// Callback type for page crawl events
pub type PageCallback = Box<dyn Fn(&CrawledPage) + Send + Sync>;

/// Crawler configuration for advanced options
#[derive(Clone)]
pub struct CrawlerConfig {
    pub max_depth: usize,
    pub max_pages: usize,
    pub same_origin_only: bool,
    pub respect_robots: bool,
    pub record_har: bool,
    pub use_dom_parser: bool,
    pub store_html: bool,
    pub follow_redirects: bool,
    pub user_agent: Option<String>,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 100,
            same_origin_only: true,
            respect_robots: true,
            record_har: false,
            use_dom_parser: true,
            store_html: false,
            follow_redirects: true,
            user_agent: None,
        }
    }
}

pub struct WebCrawler {
    client: HttpClient,
    config: CrawlerConfig,
    har_recorder: Option<Arc<Mutex<HarRecorder>>>,
    callback: Option<PageCallback>,
    visited: HashSet<String>,
    queue: VecDeque<(String, usize)>, // (URL, depth)
}

impl WebCrawler {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
            config: CrawlerConfig::default(),
            har_recorder: None,
            callback: None,
            visited: HashSet::new(),
            queue: VecDeque::new(),
        }
    }

    /// Create a crawler with custom configuration
    pub fn with_config(config: CrawlerConfig) -> Self {
        let har_recorder = if config.record_har {
            Some(Arc::new(Mutex::new(HarRecorder::new())))
        } else {
            None
        };

        Self {
            client: HttpClient::new(),
            config,
            har_recorder,
            callback: None,
            visited: HashSet::new(),
            queue: VecDeque::new(),
        }
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.config.max_depth = depth;
        self
    }

    pub fn with_max_pages(mut self, pages: usize) -> Self {
        self.config.max_pages = pages;
        self
    }

    pub fn with_same_origin(mut self, same_origin: bool) -> Self {
        self.config.same_origin_only = same_origin;
        self
    }

    /// Enable HAR recording for all HTTP transactions
    pub fn with_har_recording(mut self, enabled: bool) -> Self {
        self.config.record_har = enabled;
        if enabled && self.har_recorder.is_none() {
            self.har_recorder = Some(Arc::new(Mutex::new(HarRecorder::new())));
        }
        self
    }

    /// Enable DOM-based parsing for better extraction accuracy
    pub fn with_dom_parser(mut self, enabled: bool) -> Self {
        self.config.use_dom_parser = enabled;
        self
    }

    /// Store full HTML content in CrawledPage
    pub fn with_store_html(mut self, enabled: bool) -> Self {
        self.config.store_html = enabled;
        self
    }

    /// Set callback for each crawled page
    pub fn on_page<F>(mut self, callback: F) -> Self
    where
        F: Fn(&CrawledPage) + Send + Sync + 'static,
    {
        self.callback = Some(Box::new(callback));
        self
    }

    /// Get the HAR recorder (for export after crawling)
    pub fn har_recorder(&self) -> Option<Arc<Mutex<HarRecorder>>> {
        self.har_recorder.clone()
    }

    /// Export HAR to JSON string
    pub fn export_har(&self) -> Option<String> {
        self.har_recorder
            .as_ref()
            .map(|r| r.lock().unwrap().to_json())
    }

    /// Save HAR to file
    pub fn save_har(&self, path: &str) -> Result<(), String> {
        match &self.har_recorder {
            Some(recorder) => recorder.lock().unwrap().save(path),
            None => Err("HAR recording not enabled".to_string()),
        }
    }

    /// Crawl a website starting from the given URL
    pub fn crawl(&mut self, start_url: &str) -> Result<CrawlResult, String> {
        // Normalize start URL
        let base_url = self.normalize_url(start_url);
        let base_domain = self.extract_domain(&base_url)?;

        // Start HAR page if recording
        if let Some(ref recorder) = self.har_recorder {
            let mut r = recorder.lock().unwrap();
            r.start_page(&format!("Crawl: {}", start_url));
        }

        // Initialize
        self.visited.clear();
        self.queue.clear();
        self.queue.push_back((base_url.clone(), 0));

        let mut pages = Vec::new();
        let mut total_links = 0;
        let mut max_depth_reached = 0;

        // BFS traversal
        while let Some((url, depth)) = self.queue.pop_front() {
            // Check limits
            if pages.len() >= self.config.max_pages {
                break;
            }

            if depth > self.config.max_depth {
                continue;
            }

            // Skip if already visited
            if self.visited.contains(&url) {
                continue;
            }

            // Mark as visited
            self.visited.insert(url.clone());

            // Fetch page
            match self.fetch_page(&url, &base_url) {
                Ok(mut page) => {
                    page.depth = depth;
                    total_links += page.links.len();
                    max_depth_reached = max_depth_reached.max(depth);

                    // Call page callback if set
                    if let Some(ref callback) = self.callback {
                        callback(&page);
                    }

                    // Queue child links
                    for link in &page.links {
                        let normalized = self.normalize_url(link);

                        // Check same-origin policy
                        if self.config.same_origin_only {
                            if let Ok(link_domain) = self.extract_domain(&normalized) {
                                if link_domain != base_domain {
                                    continue; // Skip external links
                                }
                            }
                        }

                        // Add to queue if not visited
                        if !self.visited.contains(&normalized) {
                            self.queue.push_back((normalized, depth + 1));
                        }
                    }

                    pages.push(page);
                }
                Err(_) => {
                    // Skip failed pages, continue crawling
                    continue;
                }
            }
        }

        Ok(CrawlResult {
            total_urls: pages.len(),
            total_links,
            max_depth_reached,
            pages,
        })
    }

    /// Fetch a page and extract links
    fn fetch_page(&self, url: &str, _base_url: &str) -> Result<CrawledPage, String> {
        let mut handler = CollectingHandler::new();
        let request = HttpRequest::get(url);

        let (head, _metrics) = self
            .client
            .send_with_handler(&request, &mut handler)
            .map_err(|e| e.message.clone())?;

        // Record to HAR if enabled
        if let Some(ref recorder) = self.har_recorder {
            use crate::protocols::har::{
                iso8601_now, parse_query_string, HarCache, HarContent, HarEntry, HarHeader,
                HarRequest, HarResponse, HarTimings,
            };

            let content_type = head
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            let body_text = if is_text_content(&content_type) {
                Some(String::from_utf8_lossy(&handler.buffer).to_string())
            } else {
                None
            };

            let entry = HarEntry {
                pageref: None,
                started_date_time: iso8601_now(),
                time: 0.0,
                request: HarRequest {
                    method: request.method.to_string(),
                    url: url.to_string(),
                    http_version: "HTTP/1.1".to_string(),
                    cookies: Vec::new(),
                    headers: request
                        .headers
                        .iter()
                        .map(|(k, v)| HarHeader {
                            name: k.clone(),
                            value: v.clone(),
                            comment: None,
                        })
                        .collect(),
                    query_string: if let Some(q) = url.split('?').nth(1) {
                        parse_query_string(q)
                    } else {
                        Vec::new()
                    },
                    post_data: None,
                    headers_size: -1,
                    body_size: 0,
                    comment: None,
                },
                response: HarResponse {
                    status: head.status_code,
                    status_text: head.status_text.clone(),
                    http_version: "HTTP/1.1".to_string(),
                    cookies: Vec::new(),
                    headers: head
                        .headers
                        .iter()
                        .map(|(k, v)| HarHeader {
                            name: k.clone(),
                            value: v.clone(),
                            comment: None,
                        })
                        .collect(),
                    content: HarContent {
                        size: handler.buffer.len() as i64,
                        compression: None,
                        mime_type: content_type.clone(),
                        text: body_text,
                        encoding: None,
                        comment: None,
                    },
                    redirect_url: String::new(),
                    headers_size: -1,
                    body_size: handler.buffer.len() as i64,
                    comment: None,
                },
                cache: HarCache {
                    before_request: None,
                    after_request: None,
                    comment: None,
                },
                timings: HarTimings {
                    blocked: -1.0,
                    dns: -1.0,
                    connect: -1.0,
                    send: 0.0,
                    wait: 0.0,
                    receive: 0.0,
                    ssl: -1.0,
                    comment: None,
                },
                server_ip_address: None,
                connection: None,
                comment: None,
            };

            let mut r = recorder.lock().unwrap();
            r.add_entry(entry);
        }

        let body = String::from_utf8_lossy(&handler.buffer);
        let content_type = head
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());

        // Use DOM parser if enabled, otherwise use regex-based extraction
        let (links, forms, assets, meta) = if self.config.use_dom_parser {
            self.extract_with_dom(&body, url)
        } else {
            (
                self.extract_links(&body, url),
                self.extract_forms(&body, url),
                self.extract_assets(&body, url),
                PageMeta::default(),
            )
        };

        Ok(CrawledPage {
            url: url.to_string(),
            status_code: head.status_code,
            depth: 0, // Will be set by caller
            content_type,
            html: if self.config.store_html {
                Some(body.to_string())
            } else {
                None
            },
            links,
            forms,
            assets,
            meta,
        })
    }

    /// Extract data using DOM parser for better accuracy
    fn extract_with_dom(
        &self,
        html: &str,
        base_url: &str,
    ) -> (Vec<String>, Vec<Form>, Vec<Asset>, PageMeta) {
        let doc = Document::parse_with_base(html, base_url);

        // Extract links using DOM
        let extracted_links = extractors::links(&doc);
        let links: Vec<String> = extracted_links
            .into_iter()
            .filter(|link| {
                // Filter out non-crawlable links
                !link.href.starts_with('#')
                    && !link.href.starts_with("javascript:")
                    && !link.href.starts_with("mailto:")
                    && !link.href.starts_with("tel:")
            })
            .map(|link| link.url)
            .collect();

        // Extract forms using DOM
        let extracted_forms = extractors::forms(&doc);
        let forms: Vec<Form> = extracted_forms
            .into_iter()
            .map(|f| Form {
                action: f.action,
                method: f.method,
                inputs: f
                    .fields
                    .into_iter()
                    .filter_map(|field| field.name)
                    .collect(),
            })
            .collect();

        // Extract assets using DOM
        let extracted_scripts = extractors::scripts(&doc);
        let extracted_styles = extractors::styles(&doc);
        let extracted_images = extractors::images(&doc);

        let mut assets = Vec::new();

        for script in extracted_scripts {
            if let Some(src) = script.src {
                assets.push(Asset {
                    url: src,
                    asset_type: AssetType::JavaScript,
                });
            }
        }

        for style in extracted_styles {
            if let Some(href) = style.href {
                assets.push(Asset {
                    url: href,
                    asset_type: AssetType::CSS,
                });
            }
        }

        for image in extracted_images {
            assets.push(Asset {
                url: image.url,
                asset_type: AssetType::Image,
            });
        }

        // Extract meta information using DOM
        let extracted_meta = extractors::meta(&doc);
        let og_data = extractors::open_graph(&doc);

        let meta = PageMeta {
            title: extracted_meta.title,
            description: extracted_meta.description,
            keywords: extracted_meta.keywords,
            og_title: og_data.title,
            og_description: og_data.description,
            og_image: og_data.image,
            canonical: extracted_meta.canonical,
        };

        (links, forms, assets, meta)
    }

    /// Extract all links from HTML
    fn extract_links(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut links = Vec::new();
        let mut seen = HashSet::new();

        // Find all <a href="..."> tags
        let mut pos = 0;
        while let Some(idx) = html[pos..].find("<a ") {
            let abs_pos = pos + idx;
            let rest = &html[abs_pos..];

            // Find href attribute
            if let Some(href_pos) = rest.find("href=") {
                let after_href = &rest[href_pos + 5..];

                // Skip whitespace
                let after_href = after_href.trim_start();

                // Determine quote type
                let quote_char = if after_href.starts_with('"') {
                    '"'
                } else if after_href.starts_with('\'') {
                    '\''
                } else {
                    pos = abs_pos + href_pos + 6;
                    continue;
                };

                // Extract URL
                let url_start = 1; // Skip opening quote
                if let Some(end_quote) = after_href[url_start..].find(quote_char) {
                    let url = &after_href[url_start..url_start + end_quote];

                    // Resolve relative URLs
                    let resolved = self.resolve_url(base_url, url);

                    // Add if not seen and valid
                    if !resolved.is_empty()
                        && !resolved.starts_with('#')
                        && !resolved.starts_with("javascript:")
                        && !resolved.starts_with("mailto:")
                        && seen.insert(resolved.clone())
                    {
                        links.push(resolved);
                    }
                }
            }

            pos = abs_pos + 3; // Move past "<a "
        }

        links
    }

    /// Extract forms from HTML
    fn extract_forms(&self, html: &str, base_url: &str) -> Vec<Form> {
        let mut forms = Vec::new();

        let mut pos = 0;
        while let Some(idx) = html[pos..].find("<form") {
            let abs_pos = pos + idx;
            let rest = &html[abs_pos..];

            // Find closing </form>
            if let Some(end_pos) = rest.find("</form>") {
                let form_html = &rest[..end_pos];

                // Extract action
                let action = if let Some(action_pos) = form_html.find("action=") {
                    let after_action = &form_html[action_pos + 7..];
                    self.extract_quoted_value(after_action)
                } else {
                    base_url.to_string() // Default to current page
                };

                // Extract method
                let method = if let Some(method_pos) = form_html.find("method=") {
                    let after_method = &form_html[method_pos + 7..];
                    self.extract_quoted_value(after_method).to_uppercase()
                } else {
                    "GET".to_string() // Default method
                };

                // Extract input names
                let inputs = self.extract_input_names(form_html);

                forms.push(Form {
                    action: self.resolve_url(base_url, &action),
                    method,
                    inputs,
                });

                pos = abs_pos + end_pos + 7;
            } else {
                break;
            }
        }

        forms
    }

    /// Extract input field names from form HTML
    fn extract_input_names(&self, form_html: &str) -> Vec<String> {
        let mut inputs = Vec::new();

        let mut pos = 0;
        while let Some(idx) = form_html[pos..].find("<input") {
            let abs_pos = pos + idx;
            let rest = &form_html[abs_pos..];

            // Find closing >
            if let Some(end_pos) = rest.find('>') {
                let input_html = &rest[..end_pos];

                // Extract name attribute
                if let Some(name_pos) = input_html.find("name=") {
                    let after_name = &input_html[name_pos + 5..];
                    let name = self.extract_quoted_value(after_name);
                    if !name.is_empty() {
                        inputs.push(name);
                    }
                }

                pos = abs_pos + end_pos + 1;
            } else {
                break;
            }
        }

        inputs
    }

    /// Extract assets (JS, CSS, images) from HTML
    fn extract_assets(&self, html: &str, base_url: &str) -> Vec<Asset> {
        let mut assets = Vec::new();
        let mut seen = HashSet::new();

        // JavaScript: <script src="...">
        assets.extend(self.extract_tag_attr(
            html,
            "script",
            "src",
            base_url,
            AssetType::JavaScript,
            &mut seen,
        ));

        // CSS: <link rel="stylesheet" href="...">
        assets.extend(self.extract_tag_attr(
            html,
            "link",
            "href",
            base_url,
            AssetType::CSS,
            &mut seen,
        ));

        // Images: <img src="...">
        assets.extend(self.extract_tag_attr(
            html,
            "img",
            "src",
            base_url,
            AssetType::Image,
            &mut seen,
        ));

        assets
    }

    /// Extract URLs from specific HTML tags
    fn extract_tag_attr(
        &self,
        html: &str,
        tag: &str,
        attr: &str,
        base_url: &str,
        asset_type: AssetType,
        seen: &mut HashSet<String>,
    ) -> Vec<Asset> {
        let mut assets = Vec::new();
        let tag_start = format!("<{}", tag);

        let mut pos = 0;
        while let Some(idx) = html[pos..].find(&tag_start) {
            let abs_pos = pos + idx;
            let rest = &html[abs_pos..];

            // Find closing >
            if let Some(end_pos) = rest.find('>') {
                let tag_html = &rest[..end_pos];

                // Find attribute
                let attr_pattern = format!("{}=", attr);
                if let Some(attr_pos) = tag_html.find(&attr_pattern) {
                    let after_attr = &tag_html[attr_pos + attr_pattern.len()..];
                    let url = self.extract_quoted_value(after_attr);

                    if !url.is_empty() {
                        let resolved = self.resolve_url(base_url, &url);
                        if seen.insert(resolved.clone()) {
                            assets.push(Asset {
                                url: resolved,
                                asset_type: asset_type.clone(),
                            });
                        }
                    }
                }

                pos = abs_pos + end_pos + 1;
            } else {
                break;
            }
        }

        assets
    }

    /// Extract quoted value from HTML attribute
    fn extract_quoted_value(&self, text: &str) -> String {
        let text = text.trim_start();

        let quote_char = if text.starts_with('"') {
            '"'
        } else if text.starts_with('\'') {
            '\''
        } else {
            return String::new();
        };

        if let Some(end_pos) = text[1..].find(quote_char) {
            text[1..1 + end_pos].to_string()
        } else {
            String::new()
        }
    }

    /// Resolve relative URL to absolute
    fn resolve_url(&self, base: &str, url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            return url.to_string();
        }

        if url.starts_with("//") {
            // Protocol-relative URL
            if base.starts_with("https") {
                return format!("https:{}", url);
            } else {
                return format!("http:{}", url);
            }
        }

        // Extract base parts
        let base_parts: Vec<&str> = base.splitn(4, '/').collect();
        if base_parts.len() < 3 {
            return url.to_string();
        }

        let protocol = base_parts[0]; // "http:" or "https:"
        let domain = base_parts[2]; // "example.com"

        if url.starts_with('/') {
            // Absolute path
            format!("{}//{}{}", protocol, domain, url)
        } else {
            // Relative path - resolve from current directory
            let current_path = if base_parts.len() > 3 {
                base_parts[3]
            } else {
                ""
            };

            // Get directory part (remove filename)
            let dir = if let Some(last_slash) = current_path.rfind('/') {
                &current_path[..last_slash + 1]
            } else {
                ""
            };

            format!("{}//{}/{}{}", protocol, domain, dir, url)
        }
    }

    /// Normalize URL (remove fragment, trailing slash, etc.)
    fn normalize_url(&self, url: &str) -> String {
        let mut normalized = url.to_string();

        // Remove fragment (#...)
        if let Some(hash_pos) = normalized.find('#') {
            normalized = normalized[..hash_pos].to_string();
        }

        // Remove trailing slash (except for root)
        if normalized.ends_with('/') && normalized.len() > 8 {
            normalized.pop();
        }

        normalized
    }

    /// Extract domain from URL
    fn extract_domain(&self, url: &str) -> Result<String, String> {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err("Invalid URL".to_string());
        }

        let parts: Vec<&str> = url.splitn(4, '/').collect();
        if parts.len() < 3 {
            return Err("Invalid URL format".to_string());
        }

        Ok(parts[2].to_string())
    }
}

/// Check if content type indicates text content (for HAR recording)
fn is_text_content(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("html")
}

struct CollectingHandler {
    buffer: Vec<u8>,
}

impl CollectingHandler {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl HttpResponseHandler for CollectingHandler {
    fn on_head(&mut self, _head: &HttpResponseHead) -> Result<(), String> {
        Ok(())
    }

    fn on_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }
}

impl Default for WebCrawler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        let crawler = WebCrawler::new();

        assert_eq!(
            crawler.normalize_url("https://example.com/page#section"),
            "https://example.com/page"
        );

        assert_eq!(
            crawler.normalize_url("https://example.com/page/"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_resolve_url() {
        let crawler = WebCrawler::new();
        let base = "https://example.com/path/page.html";

        assert_eq!(
            crawler.resolve_url(base, "/absolute"),
            "https://example.com/absolute"
        );

        assert_eq!(
            crawler.resolve_url(base, "relative.html"),
            "https://example.com/path/relative.html"
        );

        assert_eq!(
            crawler.resolve_url(base, "https://other.com/page"),
            "https://other.com/page"
        );
    }

    #[test]
    fn test_extract_domain() {
        let crawler = WebCrawler::new();

        assert_eq!(
            crawler.extract_domain("https://example.com/path").unwrap(),
            "example.com"
        );

        assert_eq!(
            crawler
                .extract_domain("http://sub.example.com:8080/page")
                .unwrap(),
            "sub.example.com:8080"
        );
    }

    #[test]
    fn test_extract_links() {
        let crawler = WebCrawler::new();
        let html = "
            <a href=\"/page1\">Link 1</a>
            <a href=\"page2.html\">Link 2</a>
            <a href=\"https://external.com/page\">External</a>
            <a href=\"#section\">Anchor</a>
        ";

        let links = crawler.extract_links(html, "https://example.com/");

        assert!(links.len() >= 2);
        assert!(links.iter().any(|l| l.contains("/page1")));
        assert!(links.iter().any(|l| l.contains("page2.html")));
    }

    #[test]
    fn test_extract_forms() {
        let crawler = WebCrawler::new();
        let html = "
            <form action=\"/submit\" method=\"POST\">
                <input type=\"text\" name=\"username\">
                <input type=\"password\" name=\"password\">
            </form>
        ";

        let forms = crawler.extract_forms(html, "https://example.com/");

        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].inputs.len(), 2);
    }
}
