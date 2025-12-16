/// Common Crawl Source
///
/// Extracts subdomains from Common Crawl web archive data.
/// Free, no API key required, massive dataset.
///
/// API: https://index.commoncrawl.org/CC-MAIN-2024-*-index?url=*.example.com&output=json
use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct CommonCrawlSource {
    config: SourceConfig,
    http: HttpClient,
}

impl CommonCrawlSource {
    pub fn new() -> Self {
        Self {
            config: SourceConfig {
                timeout: std::time::Duration::from_secs(120), // Can be slow
                ..Default::default()
            },
            http: HttpClient::new(),
        }
    }

    /// Get the latest Common Crawl index name
    fn get_latest_index(&self) -> Result<String, SourceError> {
        let url = "https://index.commoncrawl.org/collinfo.json";

        let response = self.http.get(url).map_err(SourceError::NetworkError)?;

        if response.status_code != 200 {
            // Fall back to a known recent index
            return Ok("CC-MAIN-2024-10".to_string());
        }

        let body = String::from_utf8_lossy(&response.body);

        // Extract the first (most recent) index ID
        // Format: [{"id": "CC-MAIN-2024-10", ...}, ...]
        if let Some(id_pos) = body.find("\"id\"") {
            let rest = &body[id_pos..];
            if let Some(value) = self.extract_string_value(rest) {
                return Ok(value);
            }
        }

        Ok("CC-MAIN-2024-10".to_string())
    }

    fn parse_response(
        &self,
        body: &str,
        domain: &str,
    ) -> Result<Vec<SubdomainRecord>, SourceError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let domain_lower = domain.to_lowercase();

        // Each line is a JSON object with URL info
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with('{') {
                continue;
            }

            // Extract URL from the JSON
            if let Some(url) = self.extract_json_field(line, "url") {
                if let Some(subdomain) = self.extract_subdomain_from_url(&url, &domain_lower) {
                    if seen.insert(subdomain.clone()) {
                        // Extract timestamp if available
                        let timestamp = self.extract_json_field(line, "timestamp");

                        records.push(SubdomainRecord {
                            subdomain,
                            ips: Vec::new(),
                            source: SourceType::WebArchive("commoncrawl".into()),
                            discovered_at: timestamp,
                            metadata: RecordMetadata::default(),
                        });
                    }
                }
            }
        }

        Ok(records)
    }

    fn extract_subdomain_from_url(&self, url: &str, domain: &str) -> Option<String> {
        let without_proto = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        let hostname = without_proto
            .split('/')
            .next()?
            .split(':')
            .next()?
            .to_lowercase();

        if hostname.ends_with(&format!(".{}", domain)) || hostname == *domain {
            Some(hostname)
        } else {
            None
        }
    }

    fn extract_string_value(&self, json: &str) -> Option<String> {
        let colon_pos = json.find(':')?;
        let rest = &json[colon_pos + 1..];
        let quote_pos = rest.find('"')?;
        let content = &rest[quote_pos + 1..];
        let end_quote = content.find('"')?;
        Some(content[..end_quote].to_string())
    }

    fn extract_json_field(&self, json: &str, key: &str) -> Option<String> {
        let search = format!("\"{}\"", key);
        if let Some(pos) = json.find(&search) {
            self.extract_string_value(&json[pos..])
        } else {
            None
        }
    }
}

impl Default for CommonCrawlSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for CommonCrawlSource {
    fn name(&self) -> &str {
        "commoncrawl"
    }

    fn description(&self) -> &str {
        "Common Crawl web archive (free, massive dataset, can be slow)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    fn source_type(&self) -> SourceType {
        SourceType::WebArchive("commoncrawl".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let index = self.get_latest_index()?;

        let url = format!(
            "https://index.commoncrawl.org/{}-index?url=*.{}&output=json&limit=1000",
            index, domain
        );

        let response = self.http.get(&url).map_err(SourceError::NetworkError)?;

        if response.status_code == 404 {
            // Index might not have data for this domain
            return Ok(Vec::new());
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
