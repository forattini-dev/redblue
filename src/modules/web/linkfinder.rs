#![allow(dead_code)]

/// LinkFinder - Extract endpoints and URLs from JavaScript files
///
/// Replaces linkfinder tool for finding hidden API endpoints in JS
/// Useful for discovering:
/// - API endpoints
/// - Internal URLs
/// - S3 buckets
/// - Cloud storage URLs
/// - Parameter names
///
/// NO external dependencies - pure Rust std implementation
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub url: String,
    pub endpoint_type: EndpointType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointType {
    RelativePath, // /api/users
    AbsoluteUrl,  // https://api.example.com/v1/users
    ApiEndpoint,  // Specifically identified as API
    S3Bucket,     // AWS S3 bucket
    CloudStorage, // Other cloud storage
    WebSocket,    // WebSocket endpoints
    GraphQL,      // GraphQL endpoints
}

pub struct LinkFinder {
    client: HttpClient,
    min_length: usize,
    max_length: usize,
}

impl LinkFinder {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
            min_length: 3,
            max_length: 200,
        }
    }

    /// Extract endpoints from a JavaScript file URL
    pub fn extract_from_url(&self, url: &str) -> Result<Vec<Endpoint>, String> {
        let response = self.client.get(url)?;

        if response.status_code != 200 {
            return Err(format!(
                "Failed to fetch {}: HTTP {}",
                url, response.status_code
            ));
        }

        let body = String::from_utf8_lossy(&response.body);
        Ok(self.extract_from_content(&body))
    }

    /// Extract endpoints from JavaScript content
    pub fn extract_from_content(&self, content: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        // Extract different types of endpoints
        endpoints.extend(self.extract_relative_paths(content));
        endpoints.extend(self.extract_absolute_urls(content));
        endpoints.extend(self.extract_api_endpoints(content));
        endpoints.extend(self.extract_s3_buckets(content));
        endpoints.extend(self.extract_cloud_storage(content));
        endpoints.extend(self.extract_websockets(content));
        endpoints.extend(self.extract_graphql(content));

        // Deduplicate
        let mut seen = HashSet::new();
        endpoints
            .into_iter()
            .filter(|e| seen.insert(e.clone()))
            .collect()
    }

    /// Extract relative paths like /api/users, /admin/dashboard
    fn extract_relative_paths(&self, content: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let patterns = vec![
            r#"["'](/[a-zA-Z0-9_\-/\.{}]+)["']"#,
            r#"url\s*:\s*["']([^"']+)["']"#,
            r#"path\s*:\s*["']([^"']+)["']"#,
            r#"route\s*:\s*["']([^"']+)["']"#,
        ];

        for line in content.lines() {
            for pattern in &patterns {
                if let Some(paths) = self.simple_pattern_match(pattern, line) {
                    for path in paths {
                        if self.is_valid_path(&path) && path.starts_with('/') {
                            endpoints.push(Endpoint {
                                url: path,
                                endpoint_type: EndpointType::RelativePath,
                            });
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Extract absolute URLs
    fn extract_absolute_urls(&self, content: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        // Pattern: https://example.com/path or http://example.com/path
        for line in content.lines() {
            // Find all http:// or https:// occurrences
            let mut pos = 0;
            while let Some(idx) = line[pos..].find("http") {
                let abs_pos = pos + idx;
                let rest = &line[abs_pos..];

                // Check if it's http:// or https://
                if rest.starts_with("http://") || rest.starts_with("https://") {
                    if let Some(url) = self.extract_url_from_position(rest) {
                        if self.is_valid_url(&url) {
                            endpoints.push(Endpoint {
                                url,
                                endpoint_type: EndpointType::AbsoluteUrl,
                            });
                        }
                    }
                }

                pos = abs_pos + 4; // Move past "http"
            }
        }

        endpoints
    }

    /// Extract URL from a position (assuming it starts with http)
    fn extract_url_from_position(&self, text: &str) -> Option<String> {
        let mut url = String::new();
        let mut in_quotes = false;
        let mut quote_char = ' ';

        for ch in text.chars() {
            if !in_quotes && (ch == '"' || ch == '\'' || ch == '`') {
                in_quotes = true;
                quote_char = ch;
                continue;
            }

            if in_quotes && ch == quote_char {
                break;
            }

            if !in_quotes
                && (ch.is_whitespace() || ch == ',' || ch == ')' || ch == ']' || ch == '}')
            {
                break;
            }

            url.push(ch);

            if url.len() > self.max_length {
                return None;
            }
        }

        if url.len() < self.min_length {
            None
        } else {
            Some(url)
        }
    }

    /// Extract API endpoints (specific patterns)
    fn extract_api_endpoints(&self, content: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let api_patterns = vec![
            "/api/",
            "/v1/",
            "/v2/",
            "/v3/",
            "/rest/",
            "/graphql",
            "/query",
            "/mutation",
        ];

        for line in content.lines() {
            for pattern in &api_patterns {
                if line.contains(pattern) {
                    // Extract the full path around this pattern
                    if let Some(paths) = self.extract_quoted_strings(line) {
                        for path in paths {
                            if path.contains(pattern) && self.is_valid_path(&path) {
                                endpoints.push(Endpoint {
                                    url: path,
                                    endpoint_type: EndpointType::ApiEndpoint,
                                });
                            }
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Extract S3 bucket URLs
    fn extract_s3_buckets(&self, content: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        // S3 patterns:
        // https://bucket-name.s3.amazonaws.com
        // https://s3.amazonaws.com/bucket-name
        // https://bucket-name.s3.region.amazonaws.com

        for line in content.lines() {
            if line.contains(".s3.") || line.contains("s3.amazonaws.com") {
                if let Some(urls) = self.extract_quoted_strings(line) {
                    for url in urls {
                        if url.contains("s3") && url.contains("amazonaws.com") {
                            endpoints.push(Endpoint {
                                url,
                                endpoint_type: EndpointType::S3Bucket,
                            });
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Extract cloud storage URLs (GCS, Azure, etc.)
    fn extract_cloud_storage(&self, content: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let patterns = vec![
            "storage.googleapis.com",
            "blob.core.windows.net",
            "digitaloceanspaces.com",
            "storage.cloud.google.com",
        ];

        for line in content.lines() {
            for pattern in &patterns {
                if line.contains(pattern) {
                    if let Some(urls) = self.extract_quoted_strings(line) {
                        for url in urls {
                            if url.contains(pattern) {
                                endpoints.push(Endpoint {
                                    url,
                                    endpoint_type: EndpointType::CloudStorage,
                                });
                            }
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Extract WebSocket endpoints
    fn extract_websockets(&self, content: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        for line in content.lines() {
            if line.contains("ws://") || line.contains("wss://") {
                if let Some(urls) = self.extract_quoted_strings(line) {
                    for url in urls {
                        if url.starts_with("ws://") || url.starts_with("wss://") {
                            endpoints.push(Endpoint {
                                url,
                                endpoint_type: EndpointType::WebSocket,
                            });
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Extract GraphQL endpoints
    fn extract_graphql(&self, content: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        for line in content.lines() {
            if line.contains("graphql") || line.contains("GraphQL") {
                if let Some(paths) = self.extract_quoted_strings(line) {
                    for path in paths {
                        if path.to_lowercase().contains("graphql") && self.is_valid_path(&path) {
                            endpoints.push(Endpoint {
                                url: path,
                                endpoint_type: EndpointType::GraphQL,
                            });
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Simple pattern matching (basic regex alternative)
    fn simple_pattern_match(&self, _pattern: &str, text: &str) -> Option<Vec<String>> {
        // For now, just extract quoted strings
        self.extract_quoted_strings(text)
    }

    /// Extract all quoted strings from text
    fn extract_quoted_strings(&self, text: &str) -> Option<Vec<String>> {
        let mut strings = Vec::new();
        let mut i = 0;
        let chars: Vec<char> = text.chars().collect();

        while i < chars.len() {
            if chars[i] == '"' || chars[i] == '\'' || chars[i] == '`' {
                let quote = chars[i];
                i += 1;
                let mut s = String::new();
                let mut escaped = false;

                while i < chars.len() {
                    if escaped {
                        s.push(chars[i]);
                        escaped = false;
                    } else if chars[i] == '\\' {
                        escaped = true;
                    } else if chars[i] == quote {
                        if !s.is_empty() {
                            strings.push(s.clone());
                        }
                        break;
                    } else {
                        s.push(chars[i]);
                    }
                    i += 1;
                }
            }
            i += 1;
        }

        if strings.is_empty() {
            None
        } else {
            Some(strings)
        }
    }

    /// Check if a path is valid
    fn is_valid_path(&self, path: &str) -> bool {
        if path.len() < self.min_length || path.len() > self.max_length {
            return false;
        }

        // Must contain at least one alphabetic character
        if !path.chars().any(|c| c.is_alphabetic()) {
            return false;
        }

        // Exclude common false positives
        let false_positives = vec![
            "/favicon.ico",
            "/robots.txt",
            "/__webpack",
            "/static/",
            "/assets/",
            "/img/",
            "/images/",
            "/css/",
            "/js/",
            "/fonts/",
        ];

        for fp in &false_positives {
            if path.starts_with(fp) {
                return false;
            }
        }

        true
    }

    /// Check if a URL is valid
    fn is_valid_url(&self, url: &str) -> bool {
        if url.len() < self.min_length || url.len() > self.max_length {
            return false;
        }

        // Must start with http:// or https://
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return false;
        }

        // Must contain at least one dot
        if !url.contains('.') {
            return false;
        }

        // Exclude localhost and internal IPs
        if url.contains("localhost") || url.contains("127.0.0.1") || url.contains("0.0.0.0") {
            return false;
        }

        true
    }

    /// Filter endpoints by type
    pub fn filter_by_type(endpoints: Vec<Endpoint>, endpoint_type: EndpointType) -> Vec<Endpoint> {
        endpoints
            .into_iter()
            .filter(|e| e.endpoint_type == endpoint_type)
            .collect()
    }

    /// Get unique endpoints only
    pub fn unique(endpoints: Vec<Endpoint>) -> Vec<Endpoint> {
        let mut seen = HashSet::new();
        endpoints
            .into_iter()
            .filter(|e| seen.insert(e.clone()))
            .collect()
    }
}

impl Default for LinkFinder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_relative_paths() {
        let finder = LinkFinder::new();
        let js_content = r#"
            fetch("/api/users");
            url: "/admin/dashboard";
            path: "/v1/products";
        "#;

        let endpoints = finder.extract_relative_paths(js_content);
        assert!(endpoints.len() >= 2);
        assert!(endpoints.iter().any(|e| e.url.contains("/api/")));
    }

    #[test]
    fn test_extract_absolute_urls() {
        let finder = LinkFinder::new();
        let js_content = r#"
            const api = "https://api.example.com/v1/users";
            fetch('http://backend.example.com/data');
        "#;

        let endpoints = finder.extract_absolute_urls(js_content);
        assert!(endpoints.len() >= 2);
        assert!(endpoints.iter().any(|e| e.url.contains("api.example.com")));
    }

    #[test]
    fn test_extract_s3_buckets() {
        let finder = LinkFinder::new();
        let js_content = r#"
            const bucket = "https://my-bucket.s3.amazonaws.com/file.jpg";
            const another = "https://s3.amazonaws.com/another-bucket/data.json";
        "#;

        let endpoints = finder.extract_s3_buckets(js_content);
        assert!(endpoints.len() >= 1);
        assert!(endpoints
            .iter()
            .all(|e| e.endpoint_type == EndpointType::S3Bucket));
    }

    #[test]
    fn test_extract_websockets() {
        let finder = LinkFinder::new();
        let js_content = r#"
            const socket = new WebSocket("wss://example.com/live");
            connect("ws://localhost:8080/stream");
        "#;

        let endpoints = finder.extract_websockets(js_content);
        assert!(endpoints.len() >= 1);
        assert!(endpoints
            .iter()
            .all(|e| e.endpoint_type == EndpointType::WebSocket));
    }

    #[test]
    fn test_is_valid_path() {
        let finder = LinkFinder::new();

        assert!(finder.is_valid_path("/api/users"));
        assert!(finder.is_valid_path("/v1/products"));
        assert!(!finder.is_valid_path("/favicon.ico"));
        assert!(!finder.is_valid_path("/static/image.png"));
    }

    #[test]
    fn test_is_valid_url() {
        let finder = LinkFinder::new();

        assert!(finder.is_valid_url("https://api.example.com/v1/users"));
        assert!(finder.is_valid_url("http://backend.test.com/data"));
        assert!(!finder.is_valid_url("https://localhost/test"));
        assert!(!finder.is_valid_url("not-a-url"));
    }
}
