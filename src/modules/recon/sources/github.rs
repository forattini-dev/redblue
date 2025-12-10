/// GitHub Code Search Source
///
/// Searches GitHub code for subdomain references.
/// Implements task 1.2.6: Code repository search
///
/// Free: 10 searches/min unauthenticated, 30/min with token
///
/// API: https://api.github.com/search/code?q=example.com

use super::{
    RecordMetadata, SourceCategory, SourceConfig, SourceError, SourceType, SubdomainRecord,
    SubdomainSource,
};
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

pub struct GitHubSource {
    config: SourceConfig,
    http: HttpClient,
}

impl GitHubSource {
    pub fn new() -> Self {
        Self {
            config: SourceConfig::default(),
            http: HttpClient::new(),
        }
    }

    pub fn with_token(token: &str) -> Self {
        Self {
            config: SourceConfig {
                api_key: Some(token.to_string()),
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

        // GitHub returns JSON with items containing text_matches
        // We'll extract subdomains from the matched content

        // Look for potential subdomains in the response
        // Pattern: something.domain.com
        let subdomain_pattern = format!(".{}", domain_lower);

        let mut pos = 0;
        while pos < body.len() {
            // Find potential subdomain references
            if let Some(domain_pos) = body[pos..].find(&subdomain_pattern) {
                let abs_pos = pos + domain_pos;

                // Walk backward to find the start of the subdomain
                let start = self.find_subdomain_start(&body[..abs_pos]);
                let end = abs_pos + subdomain_pattern.len();

                if start < abs_pos {
                    let potential_subdomain = &body[start..end];
                    let subdomain = potential_subdomain.to_lowercase();

                    // Validate it's a proper subdomain
                    if self.is_valid_subdomain(&subdomain, &domain_lower)
                        && seen.insert(subdomain.clone())
                    {
                        records.push(SubdomainRecord {
                            subdomain,
                            ips: Vec::new(),
                            source: SourceType::CodeRepository("github".into()),
                            discovered_at: None,
                            metadata: RecordMetadata {
                                tags: vec!["code-search".into()],
                                ..Default::default()
                            },
                        });
                    }
                }

                pos = end;
            } else {
                break;
            }
        }

        Ok(records)
    }

    fn find_subdomain_start(&self, text: &str) -> usize {
        // Walk backward to find where the subdomain starts
        let bytes = text.as_bytes();
        let mut start = text.len();

        for i in (0..text.len()).rev() {
            let c = bytes[i] as char;
            if c.is_alphanumeric() || c == '-' || c == '.' {
                start = i;
            } else {
                break;
            }
        }

        start
    }

    fn is_valid_subdomain(&self, subdomain: &str, domain: &str) -> bool {
        // Must end with the domain
        if !subdomain.ends_with(&format!(".{}", domain)) && subdomain != domain {
            return false;
        }

        // Must not be too long
        if subdomain.len() > 253 {
            return false;
        }

        // Must contain only valid characters
        subdomain.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.')
            && !subdomain.starts_with('.')
            && !subdomain.starts_with('-')
            && !subdomain.contains("..")
    }
}

impl Default for GitHubSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainSource for GitHubSource {
    fn name(&self) -> &str {
        "github"
    }

    fn description(&self) -> &str {
        "GitHub code search for subdomain references (free: 10 searches/min)"
    }

    fn category(&self) -> SourceCategory {
        SourceCategory::Passive
    }

    fn requires_api_key(&self) -> bool {
        false // Works without but very limited
    }

    fn source_type(&self) -> SourceType {
        SourceType::CodeRepository("github".into())
    }

    fn is_available(&self) -> bool {
        self.config.enabled
    }

    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError> {
        // Search for the domain in code
        let url = format!(
            "https://api.github.com/search/code?q={}&per_page=100",
            domain
        );

        let response = self
            .http
            .get(&url)
            .map_err(|e| SourceError::NetworkError(e))?;

        if response.status_code == 403 {
            return Err(SourceError::RateLimited(std::time::Duration::from_secs(60)));
        }

        if response.status_code == 401 {
            return Err(SourceError::AuthenticationError("Token required".into()));
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
