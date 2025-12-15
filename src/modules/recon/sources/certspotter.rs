/// CertSpotter Certificate Transparency Source
///
/// Queries the CertSpotter API for certificate transparency data.
/// Free tier: 100 queries/hour without API key, unlimited with key.
///
/// API: https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true
use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct CertSpotterSource {
    config: SourceConfig,
    http: HttpClient,
}

impl CertSpotterSource {
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
        if body.trim().is_empty() || body.trim() == "[]" {
            return Ok(records);
        }

        // Parse JSON response
        // Each entry has: dns_names, issuer, not_before, not_after
        let mut pos = 0;
        while let Some(dns_pos) = body[pos..].find("\"dns_names\"") {
            let abs_pos = pos + dns_pos;

            // Extract dns_names array
            if let Some(names) = self.extract_array_values(&body[abs_pos..]) {
                // Extract certificate metadata
                let issuer = self.find_field(&body[abs_pos..], "issuer");
                let not_before = self.find_field(&body[abs_pos..], "not_before");
                let not_after = self.find_field(&body[abs_pos..], "not_after");

                for name in names {
                    let name = name.to_lowercase();
                    if name.is_empty() {
                        continue;
                    }

                    // Handle wildcards
                    let clean_name = if name.starts_with("*.") {
                        &name[2..]
                    } else {
                        &name
                    };

                    // Validate domain
                    if (clean_name.ends_with(&format!(".{}", domain_lower))
                        || clean_name == domain_lower)
                        && seen.insert(clean_name.to_string())
                    {
                        records.push(SubdomainRecord {
                            subdomain: clean_name.to_string(),
                            ips: Vec::new(),
                            source: SourceType::CertificateTransparency("certspotter".into()),
                            discovered_at: None,
                            metadata: RecordMetadata {
                                cert_issuer: issuer.clone(),
                                cert_not_before: not_before.clone(),
                                cert_not_after: not_after.clone(),
                                ..Default::default()
                            },
                        });
                    }
                }
            }

            pos = abs_pos + 1;
        }

        Ok(records)
    }

    fn extract_array_values(&self, json: &str) -> Option<Vec<String>> {
        // Find opening bracket
        let start = json.find('[')?;
        let end = json[start..].find(']')? + start;
        let array_content = &json[start + 1..end];

        // Extract string values
        let mut values = Vec::new();
        let mut in_string = false;
        let mut current = String::new();
        let mut escaped = false;

        for c in array_content.chars() {
            if escaped {
                current.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                if in_string {
                    values.push(current.clone());
                    current.clear();
                }
                in_string = !in_string;
            } else if in_string {
                current.push(c);
            }
        }

        if values.is_empty() {
            None
        } else {
            Some(values)
        }
    }

    fn find_field(&self, json: &str, key: &str) -> Option<String> {
        let search = format!("\"{}\"", key);
        let window = if json.len() > 1000 {
            &json[..1000]
        } else {
            json
        };

        if let Some(pos) = window.find(&search) {
            self.extract_string_at(&window[pos..])
        } else {
            None
        }
    }

    fn extract_string_at(&self, json: &str) -> Option<String> {
        let colon_pos = json.find(':')?;
        let rest = &json[colon_pos + 1..];
        let quote_pos = rest.find('"')?;
        let content = &rest[quote_pos + 1..];

        let mut result = String::new();
        for c in content.chars() {
            if c == '"' {
                break;
            }
            result.push(c);
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}

impl Default for CertSpotterSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for CertSpotterSource {
    fn name(&self) -> &str {
        "certspotter"
    }

    fn description(&self) -> &str {
        "Certificate Transparency via CertSpotter API (free tier: 100 queries/hour)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false // Free tier available
    }

    fn source_type(&self) -> SourceType {
        SourceType::CertificateTransparency("certspotter".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let url = format!(
            "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
            domain
        );

        let response = self
            .http
            .get(&url)
            .map_err(|e| SourceError::NetworkError(e))?;

        if response.status_code == 429 {
            return Err(SourceError::RateLimited(std::time::Duration::from_secs(
                3600,
            )));
        }

        if response.status_code == 401 {
            return Err(SourceError::AuthenticationError("Invalid API key".into()));
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
