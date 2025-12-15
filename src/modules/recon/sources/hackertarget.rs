/// HackerTarget Subdomain Source
///
/// Queries HackerTarget API for subdomain enumeration.
/// Free: 10 queries/day, Pro: unlimited with API key.
///
/// API: https://api.hackertarget.com/hostsearch/?q=example.com
use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct HackerTargetSource {
    config: SourceConfig,
    http: HttpClient,
}

impl HackerTargetSource {
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

        // Check for error messages
        if body.contains("error check") || body.contains("API count exceeded") {
            return Err(SourceError::RateLimited(std::time::Duration::from_secs(
                86400,
            )));
        }

        // Format: subdomain.domain.com,IP
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.is_empty() {
                continue;
            }

            let subdomain = parts[0].to_lowercase();
            let ip = if parts.len() > 1 {
                Some(parts[1].trim().to_string())
            } else {
                None
            };

            // Validate domain
            if (subdomain.ends_with(&format!(".{}", domain_lower)) || subdomain == domain_lower)
                && seen.insert(subdomain.clone())
            {
                records.push(SubdomainRecord {
                    subdomain,
                    ips: ip.into_iter().collect(),
                    source: SourceType::PassiveDns("hackertarget".into()),
                    discovered_at: None,
                    metadata: RecordMetadata::default(),
                });
            }
        }

        Ok(records)
    }
}

impl Default for HackerTargetSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for HackerTargetSource {
    fn name(&self) -> &str {
        "hackertarget"
    }

    fn description(&self) -> &str {
        "HackerTarget subdomain search (free: 10/day, pro: unlimited)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false // Free tier available
    }

    fn source_type(&self) -> SourceType {
        SourceType::PassiveDns("hackertarget".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let url = if let Some(ref key) = self.config.api_key {
            format!(
                "https://api.hackertarget.com/hostsearch/?q={}&apikey={}",
                domain, key
            )
        } else {
            format!("https://api.hackertarget.com/hostsearch/?q={}", domain)
        };

        let response = self
            .http
            .get(&url)
            .map_err(|e| SourceError::NetworkError(e))?;

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
