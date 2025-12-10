/// Shodan Source
///
/// Queries Shodan for subdomain data from internet-wide scanning.
/// Requires API key (free tier: 100 queries/month).
///
/// API: https://api.shodan.io/dns/domain/{domain}?key=API_KEY

use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct ShodanSource {
    config: SourceConfig,
    http: HttpClient,
}

impl ShodanSource {
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

    fn parse_response(&self, body: &str, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let domain_lower = domain.to_lowercase();

        // Handle empty response
        if body.trim().is_empty() {
            return Ok(records);
        }

        // Parse JSON response
        // Format: {"domain": "example.com", "subdomains": ["www", "api", "mail"], "data": [...]}

        // Extract subdomains array
        if let Some(subdomains_pos) = body.find("\"subdomains\"") {
            let rest = &body[subdomains_pos..];

            if let Some(array_start) = rest.find('[') {
                if let Some(array_end) = rest[array_start..].find(']') {
                    let array_content = &rest[array_start + 1..array_start + array_end];

                    // Parse array entries
                    let mut in_string = false;
                    let mut current = String::new();

                    for c in array_content.chars() {
                        if c == '"' {
                            if in_string {
                                // Shodan returns just the subdomain prefix (e.g., "www" not "www.example.com")
                                let subdomain = if current.contains('.') {
                                    current.to_lowercase()
                                } else {
                                    format!("{}.{}", current.to_lowercase(), domain_lower)
                                };

                                if seen.insert(subdomain.clone()) {
                                    records.push(SubdomainRecord {
                                        subdomain,
                                        ips: Vec::new(),
                                        source: SourceType::PassiveDns("shodan".into()),
                                        discovered_at: None,
                                        metadata: RecordMetadata::default(),
                                    });
                                }
                                current.clear();
                            }
                            in_string = !in_string;
                        } else if in_string {
                            current.push(c);
                        }
                    }
                }
            }
        }

        // Also extract data entries for IP information
        // Format: {"data": [{"subdomain": "www", "value": "1.2.3.4", "type": "A"}, ...]}
        if let Some(data_pos) = body.find("\"data\"") {
            let rest = &body[data_pos..];
            let mut pos = 0;

            while let Some(subdomain_pos) = rest[pos..].find("\"subdomain\"") {
                let abs_pos = pos + subdomain_pos;

                if let Some(subdomain) = self.extract_string_value(&rest[abs_pos..]) {
                    let full_subdomain = if subdomain.contains('.') {
                        subdomain.to_lowercase()
                    } else {
                        format!("{}.{}", subdomain.to_lowercase(), domain_lower)
                    };

                    // Find associated value (IP)
                    let ip = self.find_nearby_field(&rest[abs_pos..], "value");

                    if seen.insert(full_subdomain.clone()) {
                        records.push(SubdomainRecord {
                            subdomain: full_subdomain,
                            ips: ip.into_iter().collect(),
                            source: SourceType::PassiveDns("shodan".into()),
                            discovered_at: None,
                            metadata: RecordMetadata::default(),
                        });
                    }
                }

                pos = abs_pos + 1;
            }
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
        let window = if json.len() > 300 { &json[..300] } else { json };

        if let Some(pos) = window.find(&search) {
            self.extract_string_value(&window[pos..])
        } else {
            None
        }
    }
}

impl Default for ShodanSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for ShodanSource {
    fn name(&self) -> &str {
        "shodan"
    }

    fn description(&self) -> &str {
        "Shodan internet scanner (requires API key, free: 100/month)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        true
    }

    fn source_type(&self) -> SourceType {
        SourceType::PassiveDns("shodan".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled && self.config.api_key.is_some()
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let api_key = self
            .config
            .api_key
            .as_ref()
            .ok_or(SourceError::ApiKeyRequired)?;

        let url = format!(
            "https://api.shodan.io/dns/domain/{}?key={}",
            domain, api_key
        );

        let response = self
            .http
            .get(&url)
            .map_err(|e| SourceError::NetworkError(e))?;

        if response.status_code == 401 {
            return Err(SourceError::AuthenticationError("Invalid API key".into()));
        }

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
