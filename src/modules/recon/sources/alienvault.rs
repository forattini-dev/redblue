/// AlienVault OTX (Open Threat Exchange) Source
///
/// Queries AlienVault's threat intelligence platform for subdomain data.
/// Free API key required for unlimited access.
///
/// API: https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns
use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct AlienVaultSource {
    config: SourceConfig,
    http: HttpClient,
}

impl AlienVaultSource {
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
        if body.trim().is_empty() || body.trim() == "{}" {
            return Ok(records);
        }

        // Parse JSON response - looking for passive_dns entries
        // Format: {"passive_dns": [{"hostname": "sub.example.com", "address": "1.2.3.4"}, ...]}
        let mut pos = 0;
        while let Some(hostname_pos) = body[pos..].find("\"hostname\"") {
            let abs_pos = pos + hostname_pos;

            if let Some(hostname) = self.extract_string_value(&body[abs_pos..]) {
                let hostname = hostname.to_lowercase();

                // Find associated IP address
                let ip = self.find_nearby_field(&body[abs_pos..], "address");

                // Validate domain
                if (hostname.ends_with(&format!(".{}", domain_lower)) || hostname == domain_lower)
                    && seen.insert(hostname.clone())
                {
                    records.push(SubdomainRecord {
                        subdomain: hostname,
                        ips: ip.into_iter().collect(),
                        source: SourceType::ThreatIntel("alienvault".into()),
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
        let window = if json.len() > 300 { &json[..300] } else { json };

        if let Some(pos) = window.find(&search) {
            self.extract_string_value(&window[pos..])
        } else {
            None
        }
    }
}

impl Default for AlienVaultSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for AlienVaultSource {
    fn name(&self) -> &str {
        "alienvault"
    }

    fn description(&self) -> &str {
        "AlienVault OTX threat intelligence (free API key for unlimited)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false // Works without key but limited
    }

    fn source_type(&self) -> SourceType {
        SourceType::ThreatIntel("alienvault".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
            domain
        );

        let response = self
            .http
            .get(&url)
            .map_err(|e| SourceError::NetworkError(e))?;

        if response.status_code == 429 {
            return Err(SourceError::RateLimited(std::time::Duration::from_secs(60)));
        }

        if response.status_code == 403 {
            return Err(SourceError::AuthenticationError("API key required".into()));
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
