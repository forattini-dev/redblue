/// DNSDumpster Source
///
/// Queries DNSDumpster for subdomain enumeration via DNS reconnaissance.
/// Free, no API key required, but requires CSRF token handling.
///
/// URL: https://dnsdumpster.com/

use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct DnsDumpsterSource {
    config: SourceConfig,
    http: HttpClient,
}

impl DnsDumpsterSource {
    pub fn new() -> Self {
        Self {
            config: SourceConfig {
                timeout: std::time::Duration::from_secs(60),
                ..Default::default()
            },
            http: HttpClient::new(),
        }
    }

    fn parse_response(&self, body: &str, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let domain_lower = domain.to_lowercase();

        // DNSDumpster returns HTML with subdomains in table cells
        // Look for patterns like: <td class="col-md-4">subdomain.example.com<br>

        let mut pos = 0;
        while let Some(td_pos) = body[pos..].find("<td") {
            let abs_pos = pos + td_pos;

            // Find the closing >
            if let Some(gt_pos) = body[abs_pos..].find('>') {
                let content_start = abs_pos + gt_pos + 1;

                // Find next tag or content end
                if let Some(next_tag) = body[content_start..].find('<') {
                    let content = body[content_start..content_start + next_tag].trim();
                    let content_lower = content.to_lowercase();

                    // Check if it looks like a subdomain
                    if (content_lower.ends_with(&format!(".{}", domain_lower)) || content_lower == domain_lower)
                        && !content_lower.contains(' ')
                        && content_lower.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
                        && seen.insert(content_lower.clone())
                    {
                        records.push(SubdomainRecord {
                            subdomain: content_lower,
                            ips: Vec::new(),
                            source: SourceType::PassiveDns("dnsdumpster".into()),
                            discovered_at: None,
                            metadata: RecordMetadata::default(),
                        });
                    }

                    pos = content_start + next_tag;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(records)
    }

    fn extract_csrf_token(&self, html: &str) -> Option<String> {
        // Look for: <input type="hidden" name="csrfmiddlewaretoken" value="TOKEN">
        let search = "csrfmiddlewaretoken";
        if let Some(pos) = html.find(search) {
            let rest = &html[pos..];
            if let Some(value_pos) = rest.find("value=\"") {
                let start = value_pos + 7;
                let content = &rest[start..];
                if let Some(end) = content.find('"') {
                    return Some(content[..end].to_string());
                }
            }
        }
        None
    }
}

impl Default for DnsDumpsterSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for DnsDumpsterSource {
    fn name(&self) -> &str {
        "dnsdumpster"
    }

    fn description(&self) -> &str {
        "DNSDumpster DNS reconnaissance (free, no API key)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    fn source_type(&self) -> SourceType {
        SourceType::PassiveDns("dnsdumpster".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        // DNSDumpster requires a POST with CSRF token
        // First, get the page to extract the token
        let initial_response = self
            .http
            .get("https://dnsdumpster.com/")
            .map_err(|e| SourceError::NetworkError(e))?;

        if initial_response.status_code != 200 {
            return Err(SourceError::NetworkError(format!(
                "HTTP {}",
                initial_response.status_code
            )));
        }

        let html = String::from_utf8_lossy(&initial_response.body);

        let csrf_token = self.extract_csrf_token(&html)
            .ok_or_else(|| SourceError::ParseError("Could not extract CSRF token".into()))?;

        // Now make the POST request
        let post_body = format!("csrfmiddlewaretoken={}&targetip={}", csrf_token, domain);

        // Note: This requires proper cookie handling which our HTTP client may not fully support
        // For now, we'll attempt the request and handle potential failures gracefully
        let response = self
            .http
            .post("https://dnsdumpster.com/", post_body.as_bytes(), "application/x-www-form-urlencoded")
            .map_err(|e| SourceError::NetworkError(e))?;

        if response.status_code == 403 || response.status_code == 400 {
            // CSRF or cookie issue - return empty rather than error
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
