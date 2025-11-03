#![allow(dead_code)]

/// URL harvester - Fetches historical URLs from multiple sources
///
/// Replaces waybackurls and gau (GetAllUrls) tools
/// Sources:
/// - Wayback Machine (archive.org)
/// - URLScan.io
/// - Common Crawl (via index API)
/// - AlienVault OTX
///
/// NO external dependencies - pure Rust std implementation
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct HarvestedUrl {
    pub url: String,
    pub source: String,
    pub timestamp: Option<String>,
}

pub struct UrlHarvester {
    client: HttpClient,
    timeout_sec: u64,
}

impl UrlHarvester {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
            timeout_sec: 30,
        }
    }

    /// Harvest URLs from all available sources
    pub fn harvest(&self, domain: &str) -> Result<Vec<HarvestedUrl>, String> {
        let mut all_urls = Vec::new();

        // Wayback Machine
        if let Ok(wayback_urls) = self.fetch_wayback_urls(domain) {
            all_urls.extend(wayback_urls);
        }

        // URLScan.io
        if let Ok(urlscan_urls) = self.fetch_urlscan_urls(domain) {
            all_urls.extend(urlscan_urls);
        }

        // Common Crawl
        if let Ok(commoncrawl_urls) = self.fetch_commoncrawl_urls(domain) {
            all_urls.extend(commoncrawl_urls);
        }

        // AlienVault OTX
        if let Ok(otx_urls) = self.fetch_otx_urls(domain) {
            all_urls.extend(otx_urls);
        }

        // Deduplicate by URL
        let mut seen = HashSet::new();
        let unique_urls: Vec<HarvestedUrl> = all_urls
            .into_iter()
            .filter(|u| seen.insert(u.url.clone()))
            .collect();

        Ok(unique_urls)
    }

    /// Fetch URLs from Wayback Machine
    fn fetch_wayback_urls(&self, domain: &str) -> Result<Vec<HarvestedUrl>, String> {
        let url = format!(
            "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original,timestamp&collapse=urlkey",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("Wayback Machine request failed: {}", e))?;

        if response.status_code != 200 {
            return Err(format!(
                "Wayback Machine returned status {}",
                response.status_code
            ));
        }

        let body = String::from_utf8_lossy(&response.body);
        let mut urls = Vec::new();

        // Parse JSON array manually (zero dependencies!)
        // Format: [["original", "timestamp"], ["url1", "20210101"], ["url2", "20210102"], ...]
        let lines: Vec<&str> = body.lines().collect();

        for line in lines.iter().skip(1) {
            // Skip header
            if let Some(parsed) = self.parse_wayback_line(line) {
                urls.push(HarvestedUrl {
                    url: parsed.0,
                    source: "Wayback Machine".to_string(),
                    timestamp: Some(parsed.1),
                });
            }
        }

        Ok(urls)
    }

    /// Parse Wayback Machine JSON line
    fn parse_wayback_line(&self, line: &str) -> Option<(String, String)> {
        // Format: ["url", "timestamp"]
        let trimmed = line.trim();
        if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
            return None;
        }

        let content = &trimmed[1..trimmed.len() - 1]; // Remove [ ]
        let parts: Vec<&str> = content.split(',').collect();

        if parts.len() != 2 {
            return None;
        }

        let url = parts[0].trim().trim_matches('"').to_string();
        let timestamp = parts[1].trim().trim_matches('"').to_string();

        if url.is_empty() || timestamp.is_empty() {
            return None;
        }

        Some((url, timestamp))
    }

    /// Fetch URLs from URLScan.io
    fn fetch_urlscan_urls(&self, domain: &str) -> Result<Vec<HarvestedUrl>, String> {
        let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}", domain);

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("URLScan.io request failed: {}", e))?;

        if response.status_code != 200 {
            return Err(format!(
                "URLScan.io returned status {}",
                response.status_code
            ));
        }

        let body = String::from_utf8_lossy(&response.body);
        let mut urls = Vec::new();

        // Parse JSON manually - look for "page": {"url": "..."}
        for line in body.lines() {
            if let Some(extracted_url) = self.extract_url_from_json(line, "page") {
                urls.push(HarvestedUrl {
                    url: extracted_url,
                    source: "URLScan.io".to_string(),
                    timestamp: None,
                });
            }
        }

        Ok(urls)
    }

    /// Fetch URLs from Common Crawl
    fn fetch_commoncrawl_urls(&self, domain: &str) -> Result<Vec<HarvestedUrl>, String> {
        // Common Crawl index API
        let url = format!(
            "http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{}/*&output=json",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("Common Crawl request failed: {}", e))?;

        if response.status_code != 200 {
            return Err(format!(
                "Common Crawl returned status {}",
                response.status_code
            ));
        }

        let body = String::from_utf8_lossy(&response.body);
        let mut urls = Vec::new();

        // Each line is a JSON object with "url" field
        for line in body.lines() {
            if let Some(extracted_url) = self.extract_url_from_json(line, "url") {
                urls.push(HarvestedUrl {
                    url: extracted_url,
                    source: "Common Crawl".to_string(),
                    timestamp: None,
                });
            }
        }

        Ok(urls)
    }

    /// Fetch URLs from AlienVault OTX
    fn fetch_otx_urls(&self, domain: &str) -> Result<Vec<HarvestedUrl>, String> {
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("AlienVault OTX request failed: {}", e))?;

        if response.status_code != 200 {
            return Err(format!(
                "AlienVault OTX returned status {}",
                response.status_code
            ));
        }

        let body = String::from_utf8_lossy(&response.body);
        let mut urls = Vec::new();

        // Look for "url": "..." in JSON
        for line in body.lines() {
            if let Some(extracted_url) = self.extract_url_from_json(line, "url") {
                urls.push(HarvestedUrl {
                    url: extracted_url,
                    source: "AlienVault OTX".to_string(),
                    timestamp: None,
                });
            }
        }

        Ok(urls)
    }

    /// Extract URL from JSON line (simple parser, zero dependencies)
    fn extract_url_from_json(&self, json: &str, field: &str) -> Option<String> {
        // Look for "field": "value" or "field":{"url":"value"}
        let field_pattern = format!("\"{}\"", field);

        if let Some(field_pos) = json.find(&field_pattern) {
            let after_field = &json[field_pos + field_pattern.len()..];

            // Skip whitespace and colon
            let trimmed = after_field.trim_start();
            if !trimmed.starts_with(':') {
                return None;
            }

            let after_colon = trimmed[1..].trim_start();

            // Check if it's an object or a string
            if after_colon.starts_with('{') {
                // Nested object - look for "url" field inside
                if let Some(url_pos) = after_colon.find("\"url\"") {
                    return self.extract_string_value(&after_colon[url_pos..]);
                }
            } else if after_colon.starts_with('"') {
                // Direct string value
                return self.extract_string_value(after_colon);
            }
        }

        None
    }

    /// Extract string value from JSON (starts with ")
    fn extract_string_value(&self, json: &str) -> Option<String> {
        if !json.starts_with('"') {
            // Try to find the opening quote
            if let Some(quote_pos) = json.find('"') {
                return self.extract_string_value(&json[quote_pos..]);
            }
            return None;
        }

        let content = &json[1..]; // Skip opening "

        // Find closing " (handling escaped quotes)
        let mut escaped = false;
        for (i, ch) in content.chars().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }

            if ch == '\\' {
                escaped = true;
                continue;
            }

            if ch == '"' {
                return Some(content[..i].to_string());
            }
        }

        None
    }

    /// Filter URLs by pattern
    pub fn filter_urls(
        &self,
        urls: Vec<HarvestedUrl>,
        include_pattern: Option<&str>,
        exclude_pattern: Option<&str>,
    ) -> Vec<HarvestedUrl> {
        urls.into_iter()
            .filter(|u| {
                // Include pattern (if specified)
                if let Some(pattern) = include_pattern {
                    if !u.url.contains(pattern) {
                        return false;
                    }
                }

                // Exclude pattern (if specified)
                if let Some(pattern) = exclude_pattern {
                    if u.url.contains(pattern) {
                        return false;
                    }
                }

                true
            })
            .collect()
    }

    /// Filter by file extension
    pub fn filter_by_extension(
        &self,
        urls: Vec<HarvestedUrl>,
        extensions: &[&str],
    ) -> Vec<HarvestedUrl> {
        urls.into_iter()
            .filter(|u| {
                for ext in extensions {
                    if u.url.ends_with(ext) || u.url.contains(&format!(".{}?", ext)) {
                        return true;
                    }
                }
                false
            })
            .collect()
    }

    /// Remove duplicate URLs
    pub fn deduplicate(urls: Vec<HarvestedUrl>) -> Vec<HarvestedUrl> {
        let mut seen = HashSet::new();
        urls.into_iter()
            .filter(|u| seen.insert(u.url.clone()))
            .collect()
    }
}

impl Default for UrlHarvester {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wayback_line() {
        let harvester = UrlHarvester::new();

        let line = r#"["https://example.com/page", "20210101000000"]"#;
        let parsed = harvester.parse_wayback_line(line);

        assert!(parsed.is_some());
        let (url, timestamp) = parsed.unwrap();
        assert_eq!(url, "https://example.com/page");
        assert_eq!(timestamp, "20210101000000");
    }

    #[test]
    fn test_extract_string_value() {
        let harvester = UrlHarvester::new();

        assert_eq!(
            harvester.extract_string_value(r#""https://example.com""#),
            Some("https://example.com".to_string())
        );

        assert_eq!(
            harvester.extract_string_value(r#""escaped \"quote\" test""#),
            Some(r#"escaped \"quote\" test"#.to_string())
        );
    }

    #[test]
    fn test_extract_url_from_json() {
        let harvester = UrlHarvester::new();

        let json = r#"{"url": "https://example.com/path"}"#;
        assert_eq!(
            harvester.extract_url_from_json(json, "url"),
            Some("https://example.com/path".to_string())
        );

        let json2 = r#"{"page": {"url": "https://test.com"}}"#;
        assert_eq!(
            harvester.extract_url_from_json(json2, "page"),
            Some("https://test.com".to_string())
        );
    }

    #[test]
    fn test_filter_urls() {
        let harvester = UrlHarvester::new();

        let urls = vec![
            HarvestedUrl {
                url: "https://example.com/api/v1/users".to_string(),
                source: "test".to_string(),
                timestamp: None,
            },
            HarvestedUrl {
                url: "https://example.com/admin/login".to_string(),
                source: "test".to_string(),
                timestamp: None,
            },
            HarvestedUrl {
                url: "https://example.com/static/image.png".to_string(),
                source: "test".to_string(),
                timestamp: None,
            },
        ];

        // Include only API URLs
        let filtered = harvester.filter_urls(urls.clone(), Some("/api/"), None);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].url.contains("/api/"));

        // Exclude static files
        let filtered2 = harvester.filter_urls(urls.clone(), None, Some("/static/"));
        assert_eq!(filtered2.len(), 2);
    }

    #[test]
    fn test_deduplicate() {
        let urls = vec![
            HarvestedUrl {
                url: "https://example.com/page".to_string(),
                source: "source1".to_string(),
                timestamp: None,
            },
            HarvestedUrl {
                url: "https://example.com/page".to_string(),
                source: "source2".to_string(),
                timestamp: None,
            },
            HarvestedUrl {
                url: "https://example.com/other".to_string(),
                source: "source1".to_string(),
                timestamp: None,
            },
        ];

        let deduped = UrlHarvester::deduplicate(urls);
        assert_eq!(deduped.len(), 2);
    }
}
