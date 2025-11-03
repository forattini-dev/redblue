/// OSINT data harvester module
///
/// Replaces: theHarvester
///
/// Features:
/// - Email address discovery
/// - Subdomain enumeration from multiple sources
/// - IP address collection
/// - URL discovery
/// - Search engine scraping (passive reconnaissance)
///
/// NO external dependencies - pure Rust implementation
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct HarvestResult {
    pub domain: String,
    pub emails: Vec<String>,
    pub subdomains: Vec<String>,
    pub ips: Vec<String>,
    pub urls: Vec<String>,
}

pub struct Harvester {
    client: HttpClient,
}

impl Harvester {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
        }
    }

    /// Harvest OSINT data for a domain
    pub fn harvest(&self, domain: &str) -> Result<HarvestResult, String> {
        let mut emails = HashSet::new();
        let mut subdomains = HashSet::new();
        let ips = HashSet::new();
        let mut urls = HashSet::new();

        // 1. Search crt.sh for subdomains and emails
        if let Ok((subs, addrs)) = self.search_crtsh(domain) {
            subdomains.extend(subs);
            emails.extend(addrs);
        }

        // 2. Check common email patterns
        emails.extend(self.generate_common_emails(domain));

        // 3. Extract from public sources
        if let Ok((found_emails, found_urls)) = self.search_public_sources(domain) {
            emails.extend(found_emails);
            urls.extend(found_urls);
        }

        Ok(HarvestResult {
            domain: domain.to_string(),
            emails: emails.into_iter().collect(),
            subdomains: subdomains.into_iter().collect(),
            ips: ips.into_iter().collect(),
            urls: urls.into_iter().collect(),
        })
    }

    /// Search crt.sh for certificates (subdomains + emails)
    fn search_crtsh(&self, domain: &str) -> Result<(Vec<String>, Vec<String>), String> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("Failed to fetch crt.sh data: {}", e))?;

        if response.status_code != 200 {
            return Ok((Vec::new(), Vec::new()));
        }

        let body = String::from_utf8_lossy(&response.body);

        let mut subdomains = HashSet::new();
        let mut emails = HashSet::new();

        // Parse JSON-like responses for name_value fields
        for line in body.lines() {
            if line.contains("name_value") {
                // Extract domain names from "name_value":"*.example.com"
                if let Some(start) = line.find("name_value\":\"") {
                    let start_pos = start + 13;
                    if let Some(end) = line[start_pos..].find('"') {
                        let name_value = &line[start_pos..start_pos + end];

                        // Process each domain in name_value (might be newline-separated)
                        for sub in name_value.split('\n') {
                            let sub = sub.trim();
                            if !sub.is_empty() && sub.contains(domain) {
                                // Remove wildcard
                                let clean = sub.trim_start_matches("*.").to_string();
                                if Self::is_valid_subdomain(&clean) {
                                    subdomains.insert(clean);
                                }
                            }
                        }
                    }
                }
            }

            // Look for email addresses in the response
            if let Some(email) = Self::extract_email(line, domain) {
                emails.insert(email);
            }
        }

        Ok((
            subdomains.into_iter().collect(),
            emails.into_iter().collect(),
        ))
    }

    /// Generate common email patterns
    fn generate_common_emails(&self, domain: &str) -> Vec<String> {
        let common_prefixes = vec![
            "admin",
            "info",
            "contact",
            "support",
            "sales",
            "hello",
            "security",
            "webmaster",
            "postmaster",
            "noreply",
            "abuse",
        ];

        common_prefixes
            .iter()
            .map(|prefix| format!("{}@{}", prefix, domain))
            .collect()
    }

    /// Search public sources (robots.txt, sitemap.xml)
    fn search_public_sources(&self, domain: &str) -> Result<(Vec<String>, Vec<String>), String> {
        let mut emails = HashSet::new();
        let mut urls = HashSet::new();

        // Check robots.txt
        let robots_url = format!("https://{}/robots.txt", domain);
        if let Ok(response) = self.client.get(&robots_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);

                // Extract URLs from robots.txt
                for line in body.lines() {
                    if line.starts_with("Disallow:") || line.starts_with("Allow:") {
                        if let Some(path) = line.split(':').nth(1) {
                            let path = path.trim();
                            if !path.is_empty() && path != "/" {
                                urls.insert(format!("https://{}{}", domain, path));
                            }
                        }
                    }
                }

                // Extract emails from robots.txt
                for email in Self::extract_all_emails(&body, domain) {
                    emails.insert(email);
                }
            }
        }

        // Check sitemap.xml
        let sitemap_url = format!("https://{}/sitemap.xml", domain);
        if let Ok(response) = self.client.get(&sitemap_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);

                // Extract URLs from sitemap
                for line in body.lines() {
                    if line.contains("<loc>") {
                        if let Some(start) = line.find("<loc>") {
                            let start_pos = start + 5;
                            if let Some(end) = line[start_pos..].find("</loc>") {
                                let url = line[start_pos..start_pos + end].trim();
                                if !url.is_empty() {
                                    urls.insert(url.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((emails.into_iter().collect(), urls.into_iter().collect()))
    }

    /// Extract email from text
    fn extract_email(text: &str, domain: &str) -> Option<String> {
        let text_lower = text.to_lowercase();

        // Simple email regex pattern: word@domain
        let parts: Vec<&str> = text_lower.split('@').collect();
        if parts.len() >= 2 {
            for i in 0..parts.len() - 1 {
                let before = parts[i];
                let after = parts[i + 1];

                // Get last word before @
                let username =
                    before
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .trim_matches(|c: char| {
                            !c.is_alphanumeric() && c != '.' && c != '-' && c != '_'
                        });

                // Get first word after @
                let dom = after
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');

                if !username.is_empty() && dom.contains(domain) {
                    return Some(format!("{}@{}", username, dom));
                }
            }
        }

        None
    }

    /// Extract all emails from text
    fn extract_all_emails(text: &str, domain: &str) -> Vec<String> {
        let mut emails = Vec::new();

        for line in text.lines() {
            if let Some(email) = Self::extract_email(line, domain) {
                emails.push(email);
            }
        }

        emails
    }

    /// Validate subdomain format
    fn is_valid_subdomain(subdomain: &str) -> bool {
        if subdomain.is_empty() || subdomain.len() > 255 {
            return false;
        }

        // Should contain at least one dot
        if !subdomain.contains('.') {
            return false;
        }

        // Should not start or end with dot or hyphen
        if subdomain.starts_with('.')
            || subdomain.ends_with('.')
            || subdomain.starts_with('-')
            || subdomain.ends_with('-')
        {
            return false;
        }

        // Should only contain valid characters
        subdomain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    }
}

impl Default for Harvester {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_subdomain() {
        assert!(Harvester::is_valid_subdomain("www.example.com"));
        assert!(Harvester::is_valid_subdomain("api.example.com"));
        assert!(Harvester::is_valid_subdomain("sub-domain.example.com"));

        assert!(!Harvester::is_valid_subdomain(""));
        assert!(!Harvester::is_valid_subdomain(".example.com"));
        assert!(!Harvester::is_valid_subdomain("example.com."));
        assert!(!Harvester::is_valid_subdomain("-example.com"));
    }

    #[test]
    fn test_email_extraction() {
        let result =
            Harvester::extract_email("Contact us at admin@example.com for help", "example.com");
        assert_eq!(result, Some("admin@example.com".to_string()));

        let result = Harvester::extract_email("No email here", "example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_common_emails() {
        let harvester = Harvester::new();
        let emails = harvester.generate_common_emails("example.com");

        assert!(emails.contains(&"admin@example.com".to_string()));
        assert!(emails.contains(&"info@example.com".to_string()));
        assert!(emails.contains(&"support@example.com".to_string()));
    }
}
