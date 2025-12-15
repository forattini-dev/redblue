/// RapidDNS Source
///
/// Queries RapidDNS for subdomain enumeration.
/// Free, no API key required.
///
/// URL: https://rapiddns.io/subdomain/{domain}
use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct RapidDnsSource {
    config: SourceConfig,
    http: HttpClient,
}

impl RapidDnsSource {
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

        // RapidDNS returns HTML with subdomains in table rows
        // Format: <td>subdomain.example.com</td>

        // Find all table cells that might contain subdomains
        let mut pos = 0;
        while let Some(td_pos) = body[pos..].find("<td>") {
            let abs_pos = pos + td_pos + 4; // Skip "<td>"

            // Find closing tag
            if let Some(end_pos) = body[abs_pos..].find("</td>") {
                let content = &body[abs_pos..abs_pos + end_pos];
                let content = content.trim().to_lowercase();

                // Check if it looks like a subdomain of our target
                if content.ends_with(&format!(".{}", domain_lower)) || content == domain_lower {
                    // Validate it's actually a hostname (no spaces, HTML tags, etc.)
                    if !content.contains(' ')
                        && !content.contains('<')
                        && !content.contains('>')
                        && content
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
                        && seen.insert(content.clone())
                    {
                        records.push(SubdomainRecord {
                            subdomain: content,
                            ips: Vec::new(),
                            source: SourceType::PassiveDns("rapiddns".into()),
                            discovered_at: None,
                            metadata: RecordMetadata::default(),
                        });
                    }
                }

                pos = abs_pos + end_pos;
            } else {
                break;
            }
        }

        Ok(records)
    }
}

impl Default for RapidDnsSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for RapidDnsSource {
    fn name(&self) -> &str {
        "rapiddns"
    }

    fn description(&self) -> &str {
        "RapidDNS subdomain database (free, no API key)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false
    }

    fn source_type(&self) -> SourceType {
        SourceType::PassiveDns("rapiddns".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        let url = format!("https://rapiddns.io/subdomain/{}?full=1", domain);

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
