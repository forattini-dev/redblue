/// Wayback Machine (web.archive.org) Source
///
/// Extracts subdomains from archived URLs in the Wayback Machine.
/// Free, no API key required, rate limited.
///
/// Implements task 1.2.4: Web archive data extractor
///
/// API: https://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=json&fl=original&collapse=urlkey
use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct WaybackSource {
    config: SourceConfig,
    http: HttpClient,
}

impl WaybackSource {
    pub fn new() -> Self {
        Self {
            config: SourceConfig {
                timeout: std::time::Duration::from_secs(120), // Wayback can be slow
                ..Default::default()
            },
            http: HttpClient::new(),
        }
    }

    fn parse_response(
        &self,
        body: &str,
        domain: &str,
    ) -> Result<Vec<SubdomainRecord>, SourceError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let domain_lower = domain.to_lowercase();

        // Handle empty response
        if body.trim().is_empty() || body.trim() == "[]" {
            return Ok(records);
        }

        // Response is JSON array of arrays: [["original"],["http://sub.example.com/page"]]
        // Or could be plain text URLs, one per line
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line == "[" || line == "]" || line.starts_with("[\"original\"") {
                continue;
            }

            // Try to extract URL
            let url = if line.starts_with("[\"") {
                // JSON format: ["http://..."]
                let start = line.find("\"").map(|p| p + 1);
                let end = line.rfind("\"");
                if let (Some(s), Some(e)) = (start, end) {
                    if s < e {
                        &line[s..e]
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            } else if line.starts_with("http") {
                // Plain text format
                line
            } else {
                continue;
            };

            // Extract subdomain from URL
            if let Some(subdomain) = self.extract_subdomain_from_url(url, &domain_lower) {
                if seen.insert(subdomain.clone()) {
                    records.push(SubdomainRecord {
                        subdomain,
                        ips: Vec::new(),
                        source: SourceType::WebArchive("wayback".into()),
                        discovered_at: None,
                        metadata: RecordMetadata::default(),
                    });
                }
            }
        }

        Ok(records)
    }

    fn extract_subdomain_from_url(&self, url: &str, domain: &str) -> Option<String> {
        // Remove protocol
        let without_proto = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        // Extract hostname (before first / or :)
        let hostname = without_proto
            .split('/')
            .next()?
            .split(':')
            .next()?
            .to_lowercase();

        // Validate it's a subdomain of target
        if hostname.ends_with(&format!(".{}", domain)) || hostname == *domain {
            Some(hostname)
        } else {
            None
        }
    }
}

impl Default for WaybackSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for WaybackSource {
    fn name(&self) -> &str {
        "wayback"
    }

    fn description(&self) -> &str {
        "Wayback Machine archived URLs (free, can be slow)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    fn source_type(&self) -> SourceType {
        SourceType::WebArchive("wayback".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        // Use the CDX API for efficiency
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=text&fl=original&collapse=urlkey&limit=10000",
            domain
        );

        let response = self.http.get(&url).map_err(SourceError::NetworkError)?;

        if response.status_code == 429 {
            return Err(SourceError::RateLimited(std::time::Duration::from_secs(60)));
        }

        if response.status_code != 200 {
            return Err(SourceError::NetworkError(format!(
                "HTTP {}",
                response.status_code
            )));
        }

        let body = String::from_utf8_lossy(&response.body);
        self.parse_response(&body, domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subdomain() {
        let source = WaybackSource::new();

        assert_eq!(
            source.extract_subdomain_from_url("https://www.example.com/page", "example.com"),
            Some("www.example.com".into())
        );

        assert_eq!(
            source.extract_subdomain_from_url("http://api.example.com:8080/v1", "example.com"),
            Some("api.example.com".into())
        );

        assert_eq!(
            source.extract_subdomain_from_url("https://other.com/page", "example.com"),
            None
        );
    }
}
