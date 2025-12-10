/// ThreatCrowd Source
///
/// Queries ThreatCrowd API for subdomain data from threat intelligence.
/// Free, no API key required.
///
/// API: https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=example.com

use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct ThreatCrowdSource {
    config: SourceConfig,
    http: HttpClient,
}

impl ThreatCrowdSource {
    pub fn new() -> Self {
        Self {
            config: SourceConfig {
                timeout: std::time::Duration::from_secs(30),
                ..Default::default()
            },
            http: HttpClient::new(),
        }
    }

    fn parse_response(&self, body: &str, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let domain_lower = domain.to_lowercase();

        // Handle empty or error response
        if body.trim().is_empty() {
            return Ok(records);
        }

        // Check for rate limiting
        if body.contains("\"response_code\": \"-1\"") || body.contains("\"response_code\":\"-1\"") {
            return Err(SourceError::RateLimited(std::time::Duration::from_secs(60)));
        }

        // Parse JSON response - looking for subdomains array
        // Format: {"subdomains": ["sub1.example.com", "sub2.example.com"], ...}
        if let Some(subdomains_pos) = body.find("\"subdomains\"") {
            let rest = &body[subdomains_pos..];

            // Find the array
            if let Some(array_start) = rest.find('[') {
                if let Some(array_end) = rest[array_start..].find(']') {
                    let array_content = &rest[array_start + 1..array_start + array_end];

                    // Extract each subdomain from the array
                    let mut in_string = false;
                    let mut current = String::new();

                    for c in array_content.chars() {
                        if c == '"' {
                            if in_string {
                                let subdomain = current.trim().to_lowercase();

                                if (subdomain.ends_with(&format!(".{}", domain_lower)) || subdomain == domain_lower)
                                    && seen.insert(subdomain.clone())
                                {
                                    records.push(SubdomainRecord {
                                        subdomain,
                                        ips: Vec::new(),
                                        source: SourceType::ThreatIntel("threatcrowd".into()),
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

        // Also try to extract IPs for resolution data
        // Format: {"resolutions": [{"ip_address": "1.2.3.4", "last_resolved": "..."}, ...]}
        if let Some(resolutions_pos) = body.find("\"resolutions\"") {
            let rest = &body[resolutions_pos..];

            // Extract IP addresses from resolutions
            let mut pos = 0;
            while let Some(ip_pos) = rest[pos..].find("\"ip_address\"") {
                let abs_pos = pos + ip_pos;

                if let Some(ip) = self.extract_string_value(&rest[abs_pos..]) {
                    // We could associate these with the domain, but for now just note them
                    // This data could be used to enrich subdomain records
                    let _ = ip; // Currently unused but could enhance metadata
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
}

impl Default for ThreatCrowdSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for ThreatCrowdSource {
    fn name(&self) -> &str {
        "threatcrowd"
    }

    fn description(&self) -> &str {
        "ThreatCrowd threat intelligence (free, rate limited)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    fn source_type(&self) -> SourceType {
        SourceType::ThreatIntel("threatcrowd".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let url = format!(
            "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}",
            domain
        );

        let response = self
            .http
            .get(&url)
            .map_err(|e| SourceError::NetworkError(e))?;

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
