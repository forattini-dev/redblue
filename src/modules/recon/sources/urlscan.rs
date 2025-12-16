/// URLScan.io Source
///
/// Queries URLScan.io for subdomain data from scanned websites.
/// Free: 100 searches/day, Pro: unlimited.
///
/// API: https://urlscan.io/api/v1/search/?q=domain:example.com
use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct UrlScanSource {
    config: SourceConfig,
    http: HttpClient,
}

impl UrlScanSource {
    pub fn new() -> Self {
        Self {
            config: SourceConfig::default(),
            http: HttpClient::new(),
        }
    }

    pub fn with_api_key(api_key: &str) -> Self {
        Self {
            config: SourceConfig {
                api_key: Some(api_key.to_string()),
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
        if body.trim().is_empty() {
            return Ok(records);
        }

        // Parse JSON response - looking for page.domain entries
        // Format: {"results": [{"page": {"domain": "sub.example.com"}}, ...]}
        let mut pos = 0;
        while let Some(domain_pos) = body[pos..].find("\"domain\"") {
            let abs_pos = pos + domain_pos;

            if let Some(found_domain) = self.extract_string_value(&body[abs_pos..]) {
                let found_domain = found_domain.to_lowercase();

                // Validate domain
                if (found_domain.ends_with(&format!(".{}", domain_lower))
                    || found_domain == domain_lower)
                    && seen.insert(found_domain.clone())
                {
                    // Try to find associated IP
                    let ip = self.find_nearby_field(&body[abs_pos..], "ip");

                    records.push(SubdomainRecord {
                        subdomain: found_domain,
                        ips: ip.into_iter().collect(),
                        source: SourceType::PassiveDns("urlscan".into()),
                        discovered_at: None,
                        metadata: RecordMetadata::default(),
                    });
                }
            }

            pos = abs_pos + 1;
        }

        Ok(records)
    }

    fn extract_string_value(&self, json: &str) -> Option<String> {
        let colon_pos = json.find(':')?;
        let rest = &json[colon_pos + 1..];
        let quote_pos = rest.find('"')?;
        let content = &rest[quote_pos + 1..];

        let end_quote = content.find('"')?;
        Some(content[..end_quote].to_string())
    }

    fn find_nearby_field(&self, json: &str, key: &str) -> Option<String> {
        let search = format!("\"{}\"", key);
        let window = if json.len() > 500 { &json[..500] } else { json };

        if let Some(pos) = window.find(&search) {
            self.extract_string_value(&window[pos..])
        } else {
            None
        }
    }
}

impl Default for UrlScanSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for UrlScanSource {
    fn name(&self) -> &str {
        "urlscan"
    }

    fn description(&self) -> &str {
        "URLScan.io website scan results (free: 100 searches/day)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false // Works without key but limited
    }

    fn source_type(&self) -> SourceType {
        SourceType::PassiveDns("urlscan".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}", domain);

        let response = self.http.get(&url).map_err(SourceError::NetworkError)?;

        if response.status_code == 429 {
            return Err(SourceError::RateLimited(std::time::Duration::from_secs(
                86400,
            )));
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
