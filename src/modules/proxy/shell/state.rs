//! Shell state management - request history, filters, and selection

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// A captured HTTP exchange (request + response pair)
#[derive(Debug, Clone)]
pub struct HttpExchange {
    /// Unique identifier
    pub id: u64,
    /// When the request was received
    pub timestamp: SystemTime,
    /// Source IP address (client making the request)
    pub source_ip: String,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Target host
    pub host: String,
    /// Request path
    pub path: String,
    /// HTTP version
    pub version: String,
    /// Request headers
    pub request_headers: HashMap<String, String>,
    /// Request body (if any)
    pub request_body: Vec<u8>,
    /// Response status code (None if pending)
    pub status_code: Option<u16>,
    /// Response status text
    pub status_text: Option<String>,
    /// Response headers
    pub response_headers: HashMap<String, String>,
    /// Response body
    pub response_body: Vec<u8>,
    /// Round-trip time in milliseconds
    pub duration_ms: Option<u64>,
    /// Whether this request was intercepted/modified
    pub was_modified: bool,
    /// Whether this request was dropped
    pub was_dropped: bool,
    /// Tags for organization
    pub tags: Vec<String>,
}

impl HttpExchange {
    /// Create a new exchange from a request
    pub fn from_request(
        id: u64,
        source_ip: &str,
        method: &str,
        host: &str,
        path: &str,
        version: &str,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            id,
            timestamp: SystemTime::now(),
            source_ip: source_ip.to_string(),
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            version: version.to_string(),
            request_headers: headers,
            request_body: body,
            status_code: None,
            status_text: None,
            response_headers: HashMap::new(),
            response_body: Vec::new(),
            duration_ms: None,
            was_modified: false,
            was_dropped: false,
            tags: Vec::new(),
        }
    }

    /// Add response data to this exchange
    pub fn add_response(
        &mut self,
        status_code: u16,
        status_text: &str,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        duration_ms: u64,
    ) {
        self.status_code = Some(status_code);
        self.status_text = Some(status_text.to_string());
        self.response_headers = headers;
        self.response_body = body;
        self.duration_ms = Some(duration_ms);
    }

    /// Get formatted timestamp
    pub fn timestamp_str(&self) -> String {
        let secs = self
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hours = (secs / 3600) % 24;
        let mins = (secs / 60) % 60;
        let secs = secs % 60;
        format!("{:02}:{:02}:{:02}", hours, mins, secs)
    }

    /// Get status display (colored in UI)
    pub fn status_display(&self) -> String {
        match self.status_code {
            Some(code) => format!("{}", code),
            None if self.was_dropped => "DROP".to_string(),
            None => "...".to_string(),
        }
    }

    /// Get duration display
    pub fn duration_display(&self) -> String {
        match self.duration_ms {
            Some(ms) if ms < 1000 => format!("{}ms", ms),
            Some(ms) => format!("{:.1}s", ms as f64 / 1000.0),
            None => "-".to_string(),
        }
    }

    /// Check if this matches a filter
    pub fn matches_filter(&self, filter: &RequestFilter) -> bool {
        // Host filter
        if let Some(ref pattern) = filter.host_pattern {
            if !glob_match(pattern, &self.host) {
                return false;
            }
        }

        // Method filter
        if let Some(ref method) = filter.method {
            if !self.method.eq_ignore_ascii_case(method) {
                return false;
            }
        }

        // Path filter
        if let Some(ref pattern) = filter.path_pattern {
            if !glob_match(pattern, &self.path) {
                return false;
            }
        }

        // Status code filter
        if let Some(status) = filter.status_code {
            match self.status_code {
                Some(code) => {
                    // Allow ranges like 4xx, 5xx
                    if status < 100 {
                        // It's a range (4 means 4xx)
                        if code / 100 != status {
                            return false;
                        }
                    } else if code != status {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Content-type filter
        if let Some(ref content_type) = filter.content_type {
            let resp_ct = self
                .response_headers
                .get("content-type")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            if !resp_ct.contains(&content_type.to_lowercase()) {
                return false;
            }
        }

        true
    }

    /// Get content type from response
    pub fn content_type(&self) -> Option<&str> {
        self.response_headers
            .get("content-type")
            .map(|s| s.as_str())
    }

    /// Check if response is JSON
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("json"))
            .unwrap_or(false)
    }

    /// Get request as raw HTTP
    pub fn request_raw(&self) -> String {
        let mut raw = format!("{} {} {}\r\n", self.method, self.path, self.version);
        for (key, value) in &self.request_headers {
            raw.push_str(&format!("{}: {}\r\n", key, value));
        }
        raw.push_str("\r\n");
        if !self.request_body.is_empty() {
            raw.push_str(&String::from_utf8_lossy(&self.request_body));
        }
        raw
    }

    /// Get response as raw HTTP
    pub fn response_raw(&self) -> String {
        let status = self.status_code.unwrap_or(0);
        let text = self.status_text.as_deref().unwrap_or("Unknown");
        let mut raw = format!("HTTP/1.1 {} {}\r\n", status, text);
        for (key, value) in &self.response_headers {
            raw.push_str(&format!("{}: {}\r\n", key, value));
        }
        raw.push_str("\r\n");
        if !self.response_body.is_empty() {
            raw.push_str(&String::from_utf8_lossy(&self.response_body));
        }
        raw
    }
}

/// Filter for requests
#[derive(Debug, Clone, Default)]
pub struct RequestFilter {
    /// Host pattern (glob, e.g., "*.game.com")
    pub host_pattern: Option<String>,
    /// HTTP method (e.g., "POST")
    pub method: Option<String>,
    /// Path pattern (glob, e.g., "/api/*")
    pub path_pattern: Option<String>,
    /// Status code or range (e.g., 200 or 4 for 4xx)
    pub status_code: Option<u16>,
    /// Content-type contains
    pub content_type: Option<String>,
    /// Search text in request/response
    pub search_text: Option<String>,
}

impl RequestFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.host_pattern.is_none()
            && self.method.is_none()
            && self.path_pattern.is_none()
            && self.status_code.is_none()
            && self.content_type.is_none()
            && self.search_text.is_none()
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Parse a filter string like "host:*.game.com" or "method:POST"
    pub fn parse(input: &str) -> Self {
        let mut filter = Self::new();
        for part in input.split_whitespace() {
            if let Some((key, value)) = part.split_once(':') {
                match key.to_lowercase().as_str() {
                    "host" | "h" => filter.host_pattern = Some(value.to_string()),
                    "method" | "m" => filter.method = Some(value.to_uppercase()),
                    "path" | "p" => filter.path_pattern = Some(value.to_string()),
                    "status" | "s" => {
                        if let Ok(code) = value.parse::<u16>() {
                            filter.status_code = Some(code);
                        } else if value.ends_with("xx") {
                            // Parse "4xx" -> 4
                            if let Ok(range) = value[..1].parse::<u16>() {
                                filter.status_code = Some(range);
                            }
                        }
                    }
                    "type" | "t" | "content-type" => filter.content_type = Some(value.to_string()),
                    _ => {}
                }
            }
        }
        filter
    }

    /// Get display string for status bar
    pub fn display(&self) -> String {
        if self.is_empty() {
            return "*".to_string();
        }

        let mut parts = Vec::new();
        if let Some(ref h) = self.host_pattern {
            parts.push(format!("host:{}", h));
        }
        if let Some(ref m) = self.method {
            parts.push(format!("method:{}", m));
        }
        if let Some(ref p) = self.path_pattern {
            parts.push(format!("path:{}", p));
        }
        if let Some(s) = self.status_code {
            if s < 100 {
                parts.push(format!("status:{}xx", s));
            } else {
                parts.push(format!("status:{}", s));
            }
        }
        if let Some(ref t) = self.content_type {
            parts.push(format!("type:{}", t));
        }
        parts.join(" ")
    }
}

/// View modes within the shell
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellViewMode {
    /// Request list (default view)
    List,
    /// Full request/response details
    Details,
    /// Editing a request for replay
    Edit,
    /// Intercepting live request
    Intercept,
    /// Command input mode
    Command,
    /// Search mode
    Search,
    /// Help overlay
    Help,
}

/// Tab for detail view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Headers,
    Body,
    Raw,
}

/// Main shell state
#[derive(Debug)]
pub struct ShellState {
    /// All captured exchanges
    pub exchanges: Vec<HttpExchange>,
    /// Currently selected index
    pub selected_idx: usize,
    /// Scroll offset for the list
    pub scroll_offset: usize,
    /// Active filter
    pub filter: RequestFilter,
    /// Whether intercept mode is enabled
    pub intercept_enabled: bool,
    /// Current view mode
    pub view_mode: ShellViewMode,
    /// Detail view tab
    pub detail_tab: DetailTab,
    /// Command buffer (for : commands)
    pub command_buffer: String,
    /// Search buffer
    pub search_buffer: String,
    /// Auto-scroll to new requests
    pub auto_scroll: bool,
    /// Next exchange ID
    next_id: u64,
    /// Filtered indices (cache)
    filtered_indices: Vec<usize>,
    /// Filter cache dirty flag
    filter_dirty: bool,
}

impl ShellState {
    pub fn new() -> Self {
        Self {
            exchanges: Vec::new(),
            selected_idx: 0,
            scroll_offset: 0,
            filter: RequestFilter::new(),
            intercept_enabled: false,
            view_mode: ShellViewMode::List,
            detail_tab: DetailTab::Headers,
            command_buffer: String::new(),
            search_buffer: String::new(),
            auto_scroll: true,
            next_id: 1,
            filtered_indices: Vec::new(),
            filter_dirty: true,
        }
    }

    /// Add a new exchange (from request)
    pub fn add_exchange(&mut self, exchange: HttpExchange) -> u64 {
        let id = exchange.id;
        self.exchanges.push(exchange);
        self.filter_dirty = true;

        // Auto-scroll to new request if enabled
        if self.auto_scroll {
            self.update_filtered_indices();
            if !self.filtered_indices.is_empty() {
                self.selected_idx = self.filtered_indices.len() - 1;
                // Adjust scroll to show selected
                let visible_rows = 10; // Will be updated by UI
                if self.selected_idx >= self.scroll_offset + visible_rows {
                    self.scroll_offset = self.selected_idx.saturating_sub(visible_rows - 1);
                }
            }
        }

        id
    }

    /// Generate next exchange ID
    pub fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Update response for an exchange
    pub fn update_response(
        &mut self,
        id: u64,
        status_code: u16,
        status_text: &str,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        duration_ms: u64,
    ) {
        if let Some(exchange) = self.exchanges.iter_mut().find(|e| e.id == id) {
            exchange.add_response(status_code, status_text, headers, body, duration_ms);
        }
    }

    /// Get filtered exchanges
    pub fn filtered_exchanges(&mut self) -> Vec<&HttpExchange> {
        self.update_filtered_indices();
        self.filtered_indices
            .iter()
            .filter_map(|&idx| self.exchanges.get(idx))
            .collect()
    }

    /// Update the filtered indices cache
    fn update_filtered_indices(&mut self) {
        if !self.filter_dirty {
            return;
        }

        self.filtered_indices = self
            .exchanges
            .iter()
            .enumerate()
            .filter(|(_, e)| e.matches_filter(&self.filter))
            .map(|(i, _)| i)
            .collect();

        self.filter_dirty = false;

        // Adjust selection if out of bounds
        if !self.filtered_indices.is_empty() && self.selected_idx >= self.filtered_indices.len() {
            self.selected_idx = self.filtered_indices.len() - 1;
        }
    }

    /// Get currently selected exchange
    pub fn selected_exchange(&mut self) -> Option<&HttpExchange> {
        self.update_filtered_indices();
        self.filtered_indices
            .get(self.selected_idx)
            .and_then(|&idx| self.exchanges.get(idx))
    }

    /// Move selection up
    pub fn select_prev(&mut self) {
        if self.selected_idx > 0 {
            self.selected_idx -= 1;
            // Adjust scroll if needed
            if self.selected_idx < self.scroll_offset {
                self.scroll_offset = self.selected_idx;
            }
        }
    }

    /// Move selection down
    pub fn select_next(&mut self, visible_rows: usize) {
        self.update_filtered_indices();
        if self.selected_idx + 1 < self.filtered_indices.len() {
            self.selected_idx += 1;
            // Adjust scroll if needed
            if self.selected_idx >= self.scroll_offset + visible_rows {
                self.scroll_offset = self.selected_idx - visible_rows + 1;
            }
        }
    }

    /// Get count of filtered exchanges
    pub fn filtered_count(&mut self) -> usize {
        self.update_filtered_indices();
        self.filtered_indices.len()
    }

    /// Get total exchange count
    pub fn total_count(&self) -> usize {
        self.exchanges.len()
    }

    /// Set filter and mark dirty
    pub fn set_filter(&mut self, filter: RequestFilter) {
        self.filter = filter;
        self.filter_dirty = true;
        self.selected_idx = 0;
        self.scroll_offset = 0;
    }

    /// Clear all exchanges
    pub fn clear(&mut self) {
        self.exchanges.clear();
        self.filtered_indices.clear();
        self.selected_idx = 0;
        self.scroll_offset = 0;
        self.filter_dirty = true;
    }
}

impl Default for ShellState {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple glob matching (* and ?)
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let text = text.to_lowercase();

    let mut p_chars = pattern.chars().peekable();
    let mut t_chars = text.chars().peekable();

    fn match_inner(
        p: &mut std::iter::Peekable<std::str::Chars>,
        t: &mut std::iter::Peekable<std::str::Chars>,
    ) -> bool {
        loop {
            match (p.peek(), t.peek()) {
                (None, None) => return true,
                (Some('*'), _) => {
                    p.next();
                    // Try matching * with 0, 1, 2, ... characters
                    let mut t_clone = t.clone();
                    loop {
                        let mut p_clone = p.clone();
                        if match_inner(&mut p_clone, &mut t_clone.clone()) {
                            return true;
                        }
                        if t_clone.next().is_none() {
                            break;
                        }
                    }
                    return false;
                }
                (Some('?'), Some(_)) => {
                    p.next();
                    t.next();
                }
                (Some(pc), Some(tc)) if *pc == *tc => {
                    p.next();
                    t.next();
                }
                _ => return false,
            }
        }
    }

    match_inner(&mut p_chars, &mut t_chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("*.example.com", "www.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("api.*", "api.example.com"));
        assert!(glob_match("/api/*", "/api/v1/users"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("test?", "test1"));
        assert!(!glob_match("test?", "test12"));
    }

    #[test]
    fn test_filter_parse() {
        let filter = RequestFilter::parse("host:*.game.com method:POST status:4xx");
        assert_eq!(filter.host_pattern, Some("*.game.com".to_string()));
        assert_eq!(filter.method, Some("POST".to_string()));
        assert_eq!(filter.status_code, Some(4));
    }
}
