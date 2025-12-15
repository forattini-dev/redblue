/// BufferOver.run Source
///
/// Queries BufferOver DNS database for subdomain enumeration.
/// Free, no API key required.
///
/// API: https://dns.bufferover.run/dns?q=.example.com
use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct BufferOverSource {
    config: SourceConfig,
    http: HttpClient,
}

impl BufferOverSource {
    pub fn new() -> Self {
        Self {
            config: SourceConfig::default(),
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

        // Parse JSON response
        // Format: {"FDNS_A": ["1.2.3.4,subdomain.example.com"], "RDNS": [...]}

        // Extract FDNS_A (Forward DNS A records)
        if let Some(fdns_pos) = body.find("\"FDNS_A\"") {
            self.extract_dns_records(&body[fdns_pos..], &domain_lower, &mut records, &mut seen);
        }

        // Extract RDNS (Reverse DNS)
        if let Some(rdns_pos) = body.find("\"RDNS\"") {
            self.extract_dns_records(&body[rdns_pos..], &domain_lower, &mut records, &mut seen);
        }

        Ok(records)
    }

    fn extract_dns_records(
        &self,
        json: &str,
        domain: &str,
        records: &mut Vec<SubdomainRecord>,
        seen: &mut HashSet<String>,
    ) {
        // Find the array
        if let Some(array_start) = json.find('[') {
            if let Some(array_end) = json[array_start..].find(']') {
                let array_content = &json[array_start + 1..array_start + array_end];

                // Parse array entries - format: "IP,subdomain"
                let mut in_string = false;
                let mut current = String::new();

                for c in array_content.chars() {
                    if c == '"' {
                        if in_string {
                            // Parse the entry: "1.2.3.4,subdomain.example.com"
                            let parts: Vec<&str> = current.split(',').collect();

                            if parts.len() >= 2 {
                                let ip = parts[0].trim().to_string();
                                let subdomain = parts[1].trim().to_lowercase();

                                if (subdomain.ends_with(&format!(".{}", domain))
                                    || subdomain == *domain)
                                    && seen.insert(subdomain.clone())
                                {
                                    records.push(SubdomainRecord {
                                        subdomain,
                                        ips: vec![ip],
                                        source: SourceType::PassiveDns("bufferover".into()),
                                        discovered_at: None,
                                        metadata: RecordMetadata::default(),
                                    });
                                }
                            } else if parts.len() == 1 {
                                // Just a subdomain without IP
                                let subdomain = parts[0].trim().to_lowercase();

                                if (subdomain.ends_with(&format!(".{}", domain))
                                    || subdomain == *domain)
                                    && seen.insert(subdomain.clone())
                                {
                                    records.push(SubdomainRecord {
                                        subdomain,
                                        ips: Vec::new(),
                                        source: SourceType::PassiveDns("bufferover".into()),
                                        discovered_at: None,
                                        metadata: RecordMetadata::default(),
                                    });
                                }
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
}

impl Default for BufferOverSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for BufferOverSource {
    fn name(&self) -> &str {
        "bufferover"
    }

    fn description(&self) -> &str {
        "BufferOver.run DNS database (free, no API key)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    fn source_type(&self) -> SourceType {
        SourceType::PassiveDns("bufferover".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let url = format!("https://dns.bufferover.run/dns?q=.{}", domain);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fdns_response() {
        let source = BufferOverSource::new();
        let json = r#"{"FDNS_A": ["1.2.3.4,www.example.com", "5.6.7.8,api.example.com"]}"#;

        let records = source.parse_response(json, "example.com").unwrap();
        assert_eq!(records.len(), 2);

        let subs: Vec<&str> = records.iter().map(|r| r.subdomain.as_str()).collect();
        assert!(subs.contains(&"www.example.com"));
        assert!(subs.contains(&"api.example.com"));

        // Check IPs are extracted
        let www_record = records
            .iter()
            .find(|r| r.subdomain == "www.example.com")
            .unwrap();
        assert_eq!(www_record.ips, vec!["1.2.3.4"]);
    }
}
