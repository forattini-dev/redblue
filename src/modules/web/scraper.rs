#![allow(dead_code)]

/// Web Scraper Module - Rule-based web scraping with config support
///
/// Provides a configurable scraping engine:
/// - Rule-based extraction using CSS selectors
/// - Nested extraction support
/// - Pagination handling
/// - Rate limiting
/// - Transform pipelines
///
/// NO external dependencies - pure Rust std implementation

use crate::modules::web::dom::Document;
use crate::modules::web::extractors;
use crate::protocols::http::{HttpClient, HttpRequest};
use crate::protocols::selector::parse as parse_selector;
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Configuration Types
// ============================================================================

/// Main scrape configuration
#[derive(Debug, Clone)]
pub struct ScrapeConfig {
    /// Name of this scrape configuration
    pub name: String,
    /// Base URL for relative link resolution
    pub base_url: Option<String>,
    /// Extraction rules
    pub rules: Vec<ScrapeRule>,
    /// Pagination configuration
    pub pagination: Option<PaginationConfig>,
    /// Rate limiting configuration
    pub rate_limit: Option<RateLimitConfig>,
    /// Request configuration
    pub request: RequestConfig,
}

/// A single extraction rule
#[derive(Debug, Clone)]
pub struct ScrapeRule {
    /// Name of the field to extract
    pub name: String,
    /// CSS selector to find elements
    pub selector: String,
    /// What to extract from matched elements
    pub extract: ExtractType,
    /// Optional transform to apply
    pub transform: Option<Transform>,
    /// Nested rules for extracting from child elements
    pub nested: Vec<ScrapeRule>,
    /// Whether to extract all matches or just first
    pub multiple: bool,
}

/// What to extract from an element
#[derive(Debug, Clone)]
pub enum ExtractType {
    /// Extract text content
    Text,
    /// Extract inner HTML
    Html,
    /// Extract outer HTML
    OuterHtml,
    /// Extract an attribute value
    Attr(String),
    /// Extract multiple attributes
    Attrs(Vec<String>),
}

/// Transform to apply to extracted value
#[derive(Debug, Clone)]
pub enum Transform {
    /// Trim whitespace
    Trim,
    /// Parse as integer
    ParseInt,
    /// Parse as float
    ParseFloat,
    /// Apply regex extraction (pattern, group)
    Regex(String, usize),
    /// Replace pattern with string
    Replace(String, String),
    /// Split by delimiter
    Split(String),
    /// Take first N characters
    TakeFirst(usize),
    /// Take last N characters
    TakeLast(usize),
    /// Convert to lowercase
    Lowercase,
    /// Convert to uppercase
    Uppercase,
    /// Chain multiple transforms
    Chain(Vec<Transform>),
}

/// Pagination configuration
#[derive(Debug, Clone)]
pub struct PaginationConfig {
    /// Selector for next page link
    pub next_selector: String,
    /// Maximum pages to scrape
    pub max_pages: usize,
    /// Delay between pages in milliseconds
    pub delay_ms: u64,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Minimum delay between requests in milliseconds
    pub min_delay_ms: u64,
    /// Maximum delay between requests in milliseconds (for random jitter)
    pub max_delay_ms: Option<u64>,
}

/// Request configuration
#[derive(Debug, Clone, Default)]
pub struct RequestConfig {
    /// Custom headers
    pub headers: HashMap<String, String>,
    /// Custom User-Agent
    pub user_agent: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: Option<u64>,
}

// ============================================================================
// Extracted Data Types
// ============================================================================

/// Result of scraping
#[derive(Debug, Clone)]
pub struct ScrapeResult {
    /// URL that was scraped
    pub url: String,
    /// Extracted data
    pub data: HashMap<String, ExtractedValue>,
    /// Pages scraped (for pagination)
    pub page_count: usize,
    /// Any errors encountered
    pub errors: Vec<String>,
}

/// Extracted value types
#[derive(Debug, Clone)]
pub enum ExtractedValue {
    /// Single string value
    String(String),
    /// Single numeric value
    Number(f64),
    /// Array of values
    Array(Vec<ExtractedValue>),
    /// Object with nested values
    Object(HashMap<String, ExtractedValue>),
    /// No value (null/missing)
    None,
}

impl ExtractedValue {
    /// Get as string if possible
    pub fn as_string(&self) -> Option<&str> {
        match self {
            ExtractedValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as number if possible
    pub fn as_number(&self) -> Option<f64> {
        match self {
            ExtractedValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as array if possible
    pub fn as_array(&self) -> Option<&Vec<ExtractedValue>> {
        match self {
            ExtractedValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Get as object if possible
    pub fn as_object(&self) -> Option<&HashMap<String, ExtractedValue>> {
        match self {
            ExtractedValue::Object(obj) => Some(obj),
            _ => None,
        }
    }

    /// Check if value is none
    pub fn is_none(&self) -> bool {
        matches!(self, ExtractedValue::None)
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> String {
        match self {
            ExtractedValue::String(s) => format!("\"{}\"", escape_json(s)),
            ExtractedValue::Number(n) => {
                if n.is_nan() || n.is_infinite() {
                    "null".to_string()
                } else {
                    format!("{}", n)
                }
            }
            ExtractedValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| v.to_json()).collect();
                format!("[{}]", items.join(", "))
            }
            ExtractedValue::Object(obj) => {
                let pairs: Vec<String> = obj
                    .iter()
                    .map(|(k, v)| format!("\"{}\": {}", escape_json(k), v.to_json()))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
            ExtractedValue::None => "null".to_string(),
        }
    }
}

// ============================================================================
// Scraper Implementation
// ============================================================================

/// Web scraper engine
pub struct Scraper {
    client: HttpClient,
    config: ScrapeConfig,
    last_request: Option<Instant>,
}

impl Scraper {
    /// Create a new scraper with default configuration
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
            config: ScrapeConfig {
                name: "default".to_string(),
                base_url: None,
                rules: Vec::new(),
                pagination: None,
                rate_limit: None,
                request: RequestConfig::default(),
            },
            last_request: None,
        }
    }

    /// Create a new scraper with configuration
    pub fn with_config(config: ScrapeConfig) -> Self {
        let mut client = HttpClient::new();

        if let Some(timeout) = config.request.timeout_secs {
            client = client.with_timeout(Duration::from_secs(timeout));
        }

        Self {
            client,
            config,
            last_request: None,
        }
    }

    /// Add a simple extraction rule
    pub fn add_rule(&mut self, name: &str, selector: &str, extract: ExtractType) {
        self.config.rules.push(ScrapeRule {
            name: name.to_string(),
            selector: selector.to_string(),
            extract,
            transform: None,
            nested: Vec::new(),
            multiple: false,
        });
    }

    /// Add a rule with transform
    pub fn add_rule_with_transform(
        &mut self,
        name: &str,
        selector: &str,
        extract: ExtractType,
        transform: Transform,
    ) {
        self.config.rules.push(ScrapeRule {
            name: name.to_string(),
            selector: selector.to_string(),
            extract,
            transform: Some(transform),
            nested: Vec::new(),
            multiple: false,
        });
    }

    /// Add a rule that extracts all matches
    pub fn add_rule_multiple(&mut self, name: &str, selector: &str, extract: ExtractType) {
        self.config.rules.push(ScrapeRule {
            name: name.to_string(),
            selector: selector.to_string(),
            extract,
            transform: None,
            nested: Vec::new(),
            multiple: true,
        });
    }

    /// Configure pagination
    pub fn with_pagination(&mut self, next_selector: &str, max_pages: usize, delay_ms: u64) {
        self.config.pagination = Some(PaginationConfig {
            next_selector: next_selector.to_string(),
            max_pages,
            delay_ms,
        });
    }

    /// Configure rate limiting
    pub fn with_rate_limit(&mut self, min_delay_ms: u64, max_delay_ms: Option<u64>) {
        self.config.rate_limit = Some(RateLimitConfig {
            min_delay_ms,
            max_delay_ms,
        });
    }

    /// Set base URL for relative link resolution
    pub fn with_base_url(&mut self, url: &str) {
        self.config.base_url = Some(url.to_string());
    }

    /// Scrape a URL using configured rules
    pub fn scrape(&mut self, url: &str) -> Result<ScrapeResult, String> {
        // Apply rate limiting
        self.apply_rate_limit();

        // Fetch the page
        let html = self.fetch_page(url)?;

        // Parse the document
        let base = self.config.base_url.as_deref().unwrap_or(url);
        let doc = Document::parse_with_base(&html, base);

        // Extract data using rules
        let data = self.extract_with_rules(&doc, &self.config.rules.clone())?;

        let mut result = ScrapeResult {
            url: url.to_string(),
            data,
            page_count: 1,
            errors: Vec::new(),
        };

        // Handle pagination
        if let Some(ref pagination) = self.config.pagination.clone() {
            self.handle_pagination(&doc, url, pagination, &mut result)?;
        }

        Ok(result)
    }

    /// Scrape raw HTML (no HTTP request)
    pub fn scrape_html(&self, html: &str, base_url: Option<&str>) -> Result<ScrapeResult, String> {
        let base = base_url
            .or(self.config.base_url.as_deref())
            .unwrap_or("");
        let doc = Document::parse_with_base(html, base);

        let data = self.extract_with_rules(&doc, &self.config.rules.clone())?;

        Ok(ScrapeResult {
            url: base.to_string(),
            data,
            page_count: 1,
            errors: Vec::new(),
        })
    }

    /// Extract data from document using rules
    fn extract_with_rules(
        &self,
        doc: &Document,
        rules: &[ScrapeRule],
    ) -> Result<HashMap<String, ExtractedValue>, String> {
        let mut data = HashMap::new();

        for rule in rules {
            let value = self.apply_rule(doc, rule)?;
            data.insert(rule.name.clone(), value);
        }

        Ok(data)
    }

    /// Apply a single extraction rule
    fn apply_rule(&self, doc: &Document, rule: &ScrapeRule) -> Result<ExtractedValue, String> {
        let selector =
            parse_selector(&rule.selector).map_err(|e| format!("Invalid selector: {}", e))?;

        let selection = selector.match_in(doc);

        if rule.multiple {
            // Extract from all matches
            let values: Vec<ExtractedValue> = selection
                .iter()
                .filter_map(|elem| self.extract_from_element(doc, elem, &rule.extract, &rule.transform, &rule.nested))
                .collect();

            Ok(ExtractedValue::Array(values))
        } else {
            // Extract from first match only
            if let Some(elem) = selection.first() {
                self.extract_from_element(doc, elem, &rule.extract, &rule.transform, &rule.nested)
                    .map(|v| v)
                    .ok_or_else(|| "Failed to extract value".to_string())
            } else {
                Ok(ExtractedValue::None)
            }
        }
    }

    /// Extract value from a single element
    fn extract_from_element(
        &self,
        doc: &Document,
        elem: &crate::modules::web::dom::Element,
        extract: &ExtractType,
        transform: &Option<Transform>,
        nested: &[ScrapeRule],
    ) -> Option<ExtractedValue> {
        let raw_value = match extract {
            ExtractType::Text => doc.element_text(elem.self_index),
            ExtractType::Html => doc.element_html(elem.self_index),
            ExtractType::OuterHtml => doc.element_outer_html(elem.self_index),
            ExtractType::Attr(name) => elem.attr(name).cloned().unwrap_or_default(),
            ExtractType::Attrs(names) => {
                // Return object with multiple attributes
                let mut obj = HashMap::new();
                for name in names {
                    let val = elem.attr(name).cloned().unwrap_or_default();
                    obj.insert(name.clone(), ExtractedValue::String(val));
                }
                return Some(ExtractedValue::Object(obj));
            }
        };

        // Apply transform
        let transformed = if let Some(t) = transform {
            self.apply_transform(&raw_value, t)
        } else {
            ExtractedValue::String(raw_value)
        };

        // Handle nested extraction
        if !nested.is_empty() {
            // For nested rules, we need to extract from descendants of this element
            // Create a sub-document from this element's HTML
            let element_html = doc.element_outer_html(elem.self_index);
            let sub_doc = Document::parse(&element_html);

            let mut obj = HashMap::new();

            for nested_rule in nested {
                if let Ok(val) = self.apply_rule(&sub_doc, nested_rule) {
                    obj.insert(nested_rule.name.clone(), val);
                }
            }

            if !matches!(transformed, ExtractedValue::None) {
                obj.insert("_value".to_string(), transformed);
            }

            return Some(ExtractedValue::Object(obj));
        }

        Some(transformed)
    }

    /// Apply transform to value
    fn apply_transform(&self, value: &str, transform: &Transform) -> ExtractedValue {
        match transform {
            Transform::Trim => ExtractedValue::String(value.trim().to_string()),
            Transform::ParseInt => {
                let trimmed = value.trim();
                // Remove non-numeric prefix/suffix
                let numeric: String = trimmed.chars().filter(|c| c.is_ascii_digit() || *c == '-').collect();
                numeric
                    .parse::<i64>()
                    .map(|n| ExtractedValue::Number(n as f64))
                    .unwrap_or(ExtractedValue::None)
            }
            Transform::ParseFloat => {
                let trimmed = value.trim();
                let numeric: String = trimmed.chars().filter(|c| c.is_ascii_digit() || *c == '-' || *c == '.').collect();
                numeric
                    .parse::<f64>()
                    .map(ExtractedValue::Number)
                    .unwrap_or(ExtractedValue::None)
            }
            Transform::Regex(pattern, group) => {
                // Simple regex support without regex crate
                // For now, just return the original value
                // Full regex would need implementation
                ExtractedValue::String(value.to_string())
            }
            Transform::Replace(from, to) => {
                ExtractedValue::String(value.replace(from, to))
            }
            Transform::Split(delimiter) => {
                let parts: Vec<ExtractedValue> = value
                    .split(delimiter)
                    .map(|s| ExtractedValue::String(s.to_string()))
                    .collect();
                ExtractedValue::Array(parts)
            }
            Transform::TakeFirst(n) => {
                let chars: String = value.chars().take(*n).collect();
                ExtractedValue::String(chars)
            }
            Transform::TakeLast(n) => {
                let chars: Vec<char> = value.chars().collect();
                let start = if chars.len() > *n { chars.len() - n } else { 0 };
                let result: String = chars[start..].iter().collect();
                ExtractedValue::String(result)
            }
            Transform::Lowercase => ExtractedValue::String(value.to_lowercase()),
            Transform::Uppercase => ExtractedValue::String(value.to_uppercase()),
            Transform::Chain(transforms) => {
                let mut current = ExtractedValue::String(value.to_string());
                for t in transforms {
                    if let ExtractedValue::String(s) = current {
                        current = self.apply_transform(&s, t);
                    } else {
                        break;
                    }
                }
                current
            }
        }
    }

    /// Fetch a page with HTTP client
    fn fetch_page(&mut self, url: &str) -> Result<String, String> {
        let request = HttpRequest::get(url);
        let response = self.client.send(&request)?;

        self.last_request = Some(Instant::now());

        String::from_utf8(response.body).map_err(|_| "Invalid UTF-8 in response".to_string())
    }

    /// Apply rate limiting delay
    fn apply_rate_limit(&self) {
        if let Some(ref rate_limit) = self.config.rate_limit {
            if let Some(last) = self.last_request {
                let elapsed = last.elapsed().as_millis() as u64;
                if elapsed < rate_limit.min_delay_ms {
                    let sleep_time = rate_limit.min_delay_ms - elapsed;
                    thread::sleep(Duration::from_millis(sleep_time));
                }
            }
        }
    }

    /// Handle pagination
    fn handle_pagination(
        &mut self,
        initial_doc: &Document,
        initial_url: &str,
        pagination: &PaginationConfig,
        result: &mut ScrapeResult,
    ) -> Result<(), String> {
        // Find the first next page link from initial document
        let mut next_url_opt = self.find_next_page(initial_doc, &pagination.next_selector)?;

        for _ in 1..pagination.max_pages {
            // Check if we have a next page
            if next_url_opt.is_none() {
                break;
            }

            let next_url = next_url_opt.unwrap();

            // Delay between pages
            thread::sleep(Duration::from_millis(pagination.delay_ms));

            // Apply rate limiting
            self.apply_rate_limit();

            // Fetch next page
            let html = match self.fetch_page(&next_url) {
                Ok(h) => h,
                Err(e) => {
                    result.errors.push(format!("Failed to fetch page: {}", e));
                    break;
                }
            };

            let base = self.config.base_url.as_deref().unwrap_or(&next_url);
            let current_doc = Document::parse_with_base(&html, base);

            // Extract data from this page
            match self.extract_with_rules(&current_doc, &self.config.rules.clone()) {
                Ok(page_data) => {
                    // Merge page data into result
                    for (key, value) in page_data {
                        match result.data.get_mut(&key) {
                            Some(ExtractedValue::Array(arr)) => {
                                if let ExtractedValue::Array(new_arr) = value {
                                    arr.extend(new_arr);
                                } else {
                                    arr.push(value);
                                }
                            }
                            Some(_) => {
                                // Convert to array
                                let existing = result.data.remove(&key).unwrap();
                                let mut arr = vec![existing];
                                if let ExtractedValue::Array(new_arr) = value {
                                    arr.extend(new_arr);
                                } else {
                                    arr.push(value);
                                }
                                result.data.insert(key, ExtractedValue::Array(arr));
                            }
                            None => {
                                result.data.insert(key, value);
                            }
                        }
                    }
                    result.page_count += 1;

                    // Find next page link from current document
                    next_url_opt = self.find_next_page(&current_doc, &pagination.next_selector)?;
                }
                Err(e) => {
                    result.errors.push(format!("Extraction error on page {}: {}", result.page_count + 1, e));
                    break;
                }
            }
        }

        Ok(())
    }

    /// Find next page URL from document
    fn find_next_page(&self, doc: &Document, selector: &str) -> Result<Option<String>, String> {
        let sel = parse_selector(selector).map_err(|e| format!("Invalid pagination selector: {}", e))?;
        let selection = sel.match_in(doc);

        if let Some(elem) = selection.first() {
            if let Some(href) = elem.attr("href") {
                let resolved = doc.resolve_url(href);
                return Ok(Some(resolved));
            }
        }

        Ok(None)
    }
}

impl Default for Scraper {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Config Parsing (Simple YAML-like format)
// ============================================================================

impl ScrapeConfig {
    /// Parse configuration from simple YAML-like string
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut config = ScrapeConfig {
            name: "default".to_string(),
            base_url: None,
            rules: Vec::new(),
            pagination: None,
            rate_limit: None,
            request: RequestConfig::default(),
        };

        let lines: Vec<&str> = input.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();

            if line.is_empty() || line.starts_with('#') {
                i += 1;
                continue;
            }

            if let Some(value) = line.strip_prefix("name:") {
                config.name = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("base_url:") {
                config.base_url = Some(value.trim().to_string());
            } else if line.starts_with("rules:") {
                // Parse rules block
                i += 1;
                while i < lines.len() {
                    let rule_line = lines[i];
                    if !rule_line.starts_with("  ") && !rule_line.trim().is_empty() {
                        i -= 1; // Back up to re-process this line
                        break;
                    }
                    if let Some(rule) = Self::parse_rule_line(rule_line) {
                        config.rules.push(rule);
                    }
                    i += 1;
                }
            } else if line.starts_with("pagination:") {
                // Parse pagination block
                i += 1;
                let mut next_sel = String::new();
                let mut max_pages = 10usize;
                let mut delay = 1000u64;

                while i < lines.len() {
                    let p_line = lines[i].trim();
                    if !p_line.starts_with("next:") && !p_line.starts_with("max_pages:") && !p_line.starts_with("delay:") {
                        if !p_line.is_empty() && !p_line.starts_with('#') {
                            i -= 1;
                            break;
                        }
                    }
                    if let Some(v) = p_line.strip_prefix("next:") {
                        next_sel = v.trim().to_string();
                    } else if let Some(v) = p_line.strip_prefix("max_pages:") {
                        max_pages = v.trim().parse().unwrap_or(10);
                    } else if let Some(v) = p_line.strip_prefix("delay:") {
                        delay = v.trim().parse().unwrap_or(1000);
                    }
                    i += 1;
                }

                if !next_sel.is_empty() {
                    config.pagination = Some(PaginationConfig {
                        next_selector: next_sel,
                        max_pages,
                        delay_ms: delay,
                    });
                }
            } else if line.starts_with("rate_limit:") {
                // Parse rate limit
                i += 1;
                let mut min_delay = 1000u64;
                let mut max_delay: Option<u64> = None;

                while i < lines.len() {
                    let r_line = lines[i].trim();
                    if let Some(v) = r_line.strip_prefix("min_delay:") {
                        min_delay = v.trim().parse().unwrap_or(1000);
                    } else if let Some(v) = r_line.strip_prefix("max_delay:") {
                        max_delay = v.trim().parse().ok();
                    } else if !r_line.is_empty() && !r_line.starts_with('#') {
                        i -= 1;
                        break;
                    }
                    i += 1;
                }

                config.rate_limit = Some(RateLimitConfig {
                    min_delay_ms: min_delay,
                    max_delay_ms: max_delay,
                });
            }

            i += 1;
        }

        Ok(config)
    }

    /// Parse a single rule line
    fn parse_rule_line(line: &str) -> Option<ScrapeRule> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        // Format: - name: selector [-> extract] [| transform]
        let trimmed = trimmed.strip_prefix("- ")?.trim();

        let (name_sel, transform_part) = if let Some(idx) = trimmed.find(" | ") {
            (trimmed[..idx].trim(), Some(trimmed[idx + 3..].trim()))
        } else {
            (trimmed, None)
        };

        let parts: Vec<&str> = name_sel.splitn(2, ':').collect();
        if parts.len() < 2 {
            return None;
        }

        let name = parts[0].trim();
        let rest = parts[1].trim();

        // Check for extraction type
        let (selector, extract) = if let Some(idx) = rest.find(" -> ") {
            let sel = rest[..idx].trim();
            let ext = rest[idx + 4..].trim();
            let extract_type = match ext {
                "text" => ExtractType::Text,
                "html" => ExtractType::Html,
                "outer_html" => ExtractType::OuterHtml,
                attr if attr.starts_with("@") => ExtractType::Attr(attr[1..].to_string()),
                _ => ExtractType::Text,
            };
            (sel, extract_type)
        } else {
            (rest, ExtractType::Text)
        };

        let transform = transform_part.map(|t| match t {
            "trim" => Transform::Trim,
            "lowercase" => Transform::Lowercase,
            "uppercase" => Transform::Uppercase,
            "int" | "parse_int" => Transform::ParseInt,
            "float" | "parse_float" => Transform::ParseFloat,
            _ => Transform::Trim,
        });

        Some(ScrapeRule {
            name: name.to_string(),
            selector: selector.to_string(),
            extract,
            transform,
            nested: Vec::new(),
            multiple: selector.ends_with("[]"),
        })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Escape string for JSON
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_value_to_json() {
        let s = ExtractedValue::String("hello".to_string());
        assert_eq!(s.to_json(), "\"hello\"");

        let n = ExtractedValue::Number(42.0);
        assert_eq!(n.to_json(), "42");

        let arr = ExtractedValue::Array(vec![
            ExtractedValue::String("a".to_string()),
            ExtractedValue::Number(1.0),
        ]);
        assert_eq!(arr.to_json(), "[\"a\", 1]");

        let none = ExtractedValue::None;
        assert_eq!(none.to_json(), "null");
    }

    #[test]
    fn test_transform_trim() {
        let scraper = Scraper::new();
        let result = scraper.apply_transform("  hello  ", &Transform::Trim);
        assert_eq!(result.as_string(), Some("hello"));
    }

    #[test]
    fn test_transform_parse_int() {
        let scraper = Scraper::new();
        let result = scraper.apply_transform("$42", &Transform::ParseInt);
        assert_eq!(result.as_number(), Some(42.0));
    }

    #[test]
    fn test_transform_split() {
        let scraper = Scraper::new();
        let result = scraper.apply_transform("a,b,c", &Transform::Split(",".to_string()));
        if let ExtractedValue::Array(arr) = result {
            assert_eq!(arr.len(), 3);
        } else {
            panic!("Expected array");
        }
    }

    #[test]
    fn test_scrape_html() {
        let html = r#"
            <html>
                <head><title>Test Page</title></head>
                <body>
                    <h1>Welcome</h1>
                    <p class="intro">This is a test</p>
                    <a href="/page1">Link 1</a>
                    <a href="/page2">Link 2</a>
                </body>
            </html>
        "#;

        let mut scraper = Scraper::new();
        scraper.add_rule("title", "title", ExtractType::Text);
        scraper.add_rule("heading", "h1", ExtractType::Text);
        scraper.add_rule("intro", "p.intro", ExtractType::Text);
        scraper.add_rule_multiple("links", "a", ExtractType::Attr("href".to_string()));

        let result = scraper.scrape_html(html, Some("http://example.com")).unwrap();

        assert_eq!(result.data.get("title").and_then(|v| v.as_string()), Some("Test Page"));
        assert_eq!(result.data.get("heading").and_then(|v| v.as_string()), Some("Welcome"));

        if let Some(ExtractedValue::Array(links)) = result.data.get("links") {
            assert_eq!(links.len(), 2);
        }
    }

    #[test]
    fn test_config_parse() {
        let config_str = r#"
name: example
base_url: http://example.com

rules:
  - title: h1 -> text | trim
  - description: meta[name="description"] -> @content
  - links: a[] -> @href

pagination:
  next: a.next-page
  max_pages: 5
  delay: 2000
"#;

        let config = ScrapeConfig::parse(config_str).unwrap();
        assert_eq!(config.name, "example");
        assert_eq!(config.base_url, Some("http://example.com".to_string()));
        assert_eq!(config.rules.len(), 3);
        assert!(config.pagination.is_some());

        let pagination = config.pagination.unwrap();
        assert_eq!(pagination.next_selector, "a.next-page");
        assert_eq!(pagination.max_pages, 5);
        assert_eq!(pagination.delay_ms, 2000);
    }
}
