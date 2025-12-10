/// crt.sh Certificate Transparency Source
///
/// Queries the crt.sh database for certificates issued to a domain.
/// Free, no API key required, rate limited.
///
/// API: https://crt.sh/?q=%.domain.com&output=json

use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct CrtShSource {
    config: SourceConfig,
    http: HttpClient,
}

impl CrtShSource {
    pub fn new() -> Self {
        Self {
            config: SourceConfig {
                timeout: std::time::Duration::from_secs(60), // crt.sh can be slow
                ..Default::default()
            },
            http: HttpClient::new(),
        }
    }

    pub fn with_config(config: SourceConfig) -> Self {
        Self {
            config,
            http: HttpClient::new(),
        }
    }

    fn parse_response(&self, body: &str, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let domain_lower = domain.to_lowercase();

        // Handle empty response
        if body.trim().is_empty() || body.trim() == "[]" {
            return Ok(records);
        }

        // Parse JSON array of certificate entries
        // Each entry has: name_value, issuer_name, not_before, not_after
        let mut pos = 0;
        while let Some(nv_pos) = body[pos..].find("\"name_value\"") {
            let abs_pos = pos + nv_pos;

            // Extract name_value
            if let Some(value) = self.extract_string_value(&body[abs_pos..]) {
                // Extract certificate metadata
                let issuer = self.find_nearby_field(&body[abs_pos..], "issuer_name");
                let not_before = self.find_nearby_field(&body[abs_pos..], "not_before");
                let not_after = self.find_nearby_field(&body[abs_pos..], "not_after");

                // name_value contains newline-separated domain names
                for name in value.split('\n') {
                    let name = name.trim().to_lowercase();
                    if name.is_empty() {
                        continue;
                    }

                    // Handle wildcards
                    let clean_name = if name.starts_with("*.") {
                        &name[2..]
                    } else {
                        &name
                    };

                    // Validate it belongs to target domain
                    if (clean_name.ends_with(&format!(".{}", domain_lower)) || clean_name == domain_lower)
                        && seen.insert(clean_name.to_string())
                    {
                        records.push(SubdomainRecord {
                            subdomain: clean_name.to_string(),
                            ips: Vec::new(),
                            source: SourceType::CertificateTransparency("crt.sh".into()),
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

    fn extract_string_value(&self, json: &str) -> Option<String> {
        // Find the colon after the key
        let colon_pos = json.find(':')?;
        let rest = &json[colon_pos + 1..];

        // Skip whitespace to opening quote
        let quote_pos = rest.find('"')?;
        let content = &rest[quote_pos + 1..];

        // Find closing quote (handle escapes)
        let mut result = String::new();
        let mut escaped = false;

        for c in content.chars() {
            if escaped {
                match c {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    _ => {
                        result.push('\\');
                        result.push(c);
                    }
                }
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                break;
            } else {
                result.push(c);
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn find_nearby_field(&self, json: &str, key: &str) -> Option<String> {
        let search = format!("\"{}\"", key);
        // Only look within the next 500 chars (within same JSON object)
        let window = if json.len() > 500 { &json[..500] } else { json };

        if let Some(pos) = window.find(&search) {
            self.extract_string_value(&window[pos..])
        } else {
            None
        }
    }
}

impl Default for CrtShSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for CrtShSource {
    fn name(&self) -> &str {
        "crt.sh"
    }

    fn description(&self) -> &str {
        "Certificate Transparency log search via crt.sh (free, no API key)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    fn source_type(&self) -> SourceType {
        SourceType::CertificateTransparency("crt.sh".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

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
    fn test_parse_response() {
        let source = CrtShSource::new();
        let json = r#"[{"name_value": "www.example.com\napi.example.com", "issuer_name": "Let's Encrypt"}]"#;

        let records = source.parse_response(json, "example.com").unwrap();
        assert_eq!(records.len(), 2);

        let subs: Vec<&str> = records.iter().map(|r| r.subdomain.as_str()).collect();
        assert!(subs.contains(&"www.example.com"));
        assert!(subs.contains(&"api.example.com"));
    }

    #[test]
    fn test_wildcard_handling() {
        let source = CrtShSource::new();
        let json = r#"[{"name_value": "*.example.com"}]"#;

        let records = source.parse_response(json, "example.com").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].subdomain, "example.com");
    }
}
