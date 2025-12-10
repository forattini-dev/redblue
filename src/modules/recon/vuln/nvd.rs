//! NVD (National Vulnerability Database) API Client
//!
//! Query vulnerabilities from NIST NVD REST API.
//!
//! API Docs: https://nvd.nist.gov/developers/vulnerabilities
//!
//! Rate limits:
//! - Without API key: 5 requests per 30 seconds
//! - With API key: 50 requests per 30 seconds

use crate::protocols::http::HttpClient;
use crate::utils::json::{JsonValue, parse_json};
use super::types::{Vulnerability, Severity, VulnSource, VersionRange};

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// NVD API client
pub struct NvdClient {
    http: HttpClient,
    api_key: Option<String>,
    last_request: std::time::Instant,
    requests_in_window: u32,
}

impl NvdClient {
    /// Create new NVD client
    pub fn new() -> Self {
        Self {
            http: HttpClient::new(),
            api_key: None,
            last_request: std::time::Instant::now(),
            requests_in_window: 0,
        }
    }

    /// Set API key for higher rate limits
    pub fn with_api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
        self
    }

    /// Respect rate limits
    fn wait_for_rate_limit(&mut self) {
        let max_requests = if self.api_key.is_some() { 50 } else { 5 };
        let window = std::time::Duration::from_secs(30);

        if self.last_request.elapsed() > window {
            self.requests_in_window = 0;
            self.last_request = std::time::Instant::now();
        }

        if self.requests_in_window >= max_requests {
            let sleep_time = window - self.last_request.elapsed();
            if sleep_time > std::time::Duration::ZERO {
                std::thread::sleep(sleep_time);
            }
            self.requests_in_window = 0;
            self.last_request = std::time::Instant::now();
        }

        self.requests_in_window += 1;
    }

    /// Query vulnerabilities by CPE name
    pub fn query_by_cpe(&mut self, cpe: &str) -> Result<Vec<Vulnerability>, String> {
        self.wait_for_rate_limit();

        let url = format!(
            "{}?cpeName={}&resultsPerPage=100",
            NVD_API_BASE,
            urlencoding::encode(cpe)
        );

        let response = self.http.get(&url)?;

        if response.status_code != 200 {
            return Err(format!("NVD API error: HTTP {}", response.status_code));
        }

        let body = String::from_utf8_lossy(&response.body).to_string();
        let json = parse_json(&body)?;

        self.parse_response(&json)
    }

    /// Query vulnerability by CVE ID
    pub fn query_by_cve(&mut self, cve_id: &str) -> Result<Option<Vulnerability>, String> {
        self.wait_for_rate_limit();

        let url = format!("{}?cveId={}", NVD_API_BASE, cve_id);

        let response = self.http.get(&url)?;

        if response.status_code == 404 {
            return Ok(None);
        }

        if response.status_code != 200 {
            return Err(format!("NVD API error: HTTP {}", response.status_code));
        }

        let body = String::from_utf8_lossy(&response.body).to_string();
        let json = parse_json(&body)?;

        let vulns = self.parse_response(&json)?;
        Ok(vulns.into_iter().next())
    }

    /// Query vulnerabilities by keyword search
    pub fn query_by_keyword(&mut self, keyword: &str) -> Result<Vec<Vulnerability>, String> {
        self.wait_for_rate_limit();

        let url = format!(
            "{}?keywordSearch={}&resultsPerPage=50",
            NVD_API_BASE,
            urlencoding::encode(keyword)
        );

        let response = self.http.get(&url)?;

        if response.status_code != 200 {
            return Err(format!("NVD API error: HTTP {}", response.status_code));
        }

        let body = String::from_utf8_lossy(&response.body).to_string();
        let json = parse_json(&body)?;

        self.parse_response(&json)
    }

    /// Parse NVD API response
    fn parse_response(&self, json: &JsonValue) -> Result<Vec<Vulnerability>, String> {
        let vulns_array = json.get("vulnerabilities")
            .and_then(|v| v.as_array())
            .ok_or("Invalid NVD response: missing vulnerabilities array")?;

        let mut result = Vec::new();

        for item in vulns_array {
            if let Some(cve) = item.get("cve") {
                if let Some(vuln) = self.parse_cve(cve) {
                    result.push(vuln);
                }
            }
        }

        Ok(result)
    }

    /// Parse a single CVE entry
    fn parse_cve(&self, cve: &JsonValue) -> Option<Vulnerability> {
        let id = cve.get("id")?.as_str()?;

        let mut vuln = Vulnerability::new(id);
        vuln.sources.push(VulnSource::Nvd);

        // Description
        if let Some(descriptions) = cve.get("descriptions").and_then(|d| d.as_array()) {
            for desc in descriptions {
                if desc.get("lang").and_then(|l| l.as_str()) == Some("en") {
                    vuln.description = desc.get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    break;
                }
            }
        }

        // Title from first line of description
        vuln.title = vuln.description
            .lines()
            .next()
            .unwrap_or(&vuln.id)
            .chars()
            .take(100)
            .collect();

        // CVSS v3.1 score
        if let Some(metrics) = cve.get("metrics") {
            if let Some(cvss31) = metrics.get("cvssMetricV31").and_then(|m| m.as_array()).and_then(|a| a.first()) {
                if let Some(cvss_data) = cvss31.get("cvssData") {
                    vuln.cvss_v3 = cvss_data.get("baseScore").and_then(|s| s.as_f64()).map(|s| s as f32);
                }
            } else if let Some(cvss30) = metrics.get("cvssMetricV30").and_then(|m| m.as_array()).and_then(|a| a.first()) {
                if let Some(cvss_data) = cvss30.get("cvssData") {
                    vuln.cvss_v3 = cvss_data.get("baseScore").and_then(|s| s.as_f64()).map(|s| s as f32);
                }
            }

            // CVSS v2 as fallback
            if let Some(cvss2) = metrics.get("cvssMetricV2").and_then(|m| m.as_array()).and_then(|a| a.first()) {
                if let Some(cvss_data) = cvss2.get("cvssData") {
                    vuln.cvss_v2 = cvss_data.get("baseScore").and_then(|s| s.as_f64()).map(|s| s as f32);
                }
            }
        }

        // Set severity
        if let Some(cvss) = vuln.best_cvss() {
            vuln.severity = Severity::from_cvss(cvss);
        }

        // Published date
        vuln.published = cve.get("published").and_then(|p| p.as_str()).map(|s| s.to_string());
        vuln.modified = cve.get("lastModified").and_then(|m| m.as_str()).map(|s| s.to_string());

        // References
        if let Some(refs) = cve.get("references").and_then(|r| r.as_array()) {
            for reference in refs {
                if let Some(url) = reference.get("url").and_then(|u| u.as_str()) {
                    vuln.references.push(url.to_string());
                }
            }
        }

        // CWEs
        if let Some(weaknesses) = cve.get("weaknesses").and_then(|w| w.as_array()) {
            for weakness in weaknesses {
                if let Some(descriptions) = weakness.get("description").and_then(|d| d.as_array()) {
                    for desc in descriptions {
                        if let Some(value) = desc.get("value").and_then(|v| v.as_str()) {
                            if value.starts_with("CWE-") {
                                vuln.cwes.push(value.to_string());
                            }
                        }
                    }
                }
            }
        }

        // CPE configurations (affected versions)
        if let Some(configs) = cve.get("configurations").and_then(|c| c.as_array()) {
            for config in configs {
                if let Some(nodes) = config.get("nodes").and_then(|n| n.as_array()) {
                    for node in nodes {
                        if let Some(cpe_matches) = node.get("cpeMatch").and_then(|c| c.as_array()) {
                            for cpe_match in cpe_matches {
                                if cpe_match.get("vulnerable").and_then(|v| v.as_bool()) == Some(true) {
                                    if let Some(criteria) = cpe_match.get("criteria").and_then(|c| c.as_str()) {
                                        vuln.affected_cpes.push(criteria.to_string());
                                    }

                                    // Version range
                                    let range = VersionRange {
                                        start_including: cpe_match.get("versionStartIncluding")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string()),
                                        start_excluding: cpe_match.get("versionStartExcluding")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string()),
                                        end_including: cpe_match.get("versionEndIncluding")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string()),
                                        end_excluding: cpe_match.get("versionEndExcluding")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string()),
                                    };

                                    if range.start_including.is_some()
                                        || range.start_excluding.is_some()
                                        || range.end_including.is_some()
                                        || range.end_excluding.is_some()
                                    {
                                        vuln.affected_versions.push(range);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(vuln)
    }
}

impl Default for NvdClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple URL encoding (we don't have a crate for this)
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 3);
        for c in s.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                    result.push(c);
                }
                ':' => result.push_str("%3A"),
                '/' => result.push_str("%2F"),
                '*' => result.push_str("%2A"),
                ' ' => result.push_str("%20"),
                _ => {
                    for byte in c.to_string().as_bytes() {
                        result.push_str(&format!("%{:02X}", byte));
                    }
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlencoding() {
        assert_eq!(
            urlencoding::encode("cpe:2.3:a:nginx:nginx:*"),
            "cpe%3A2.3%3Aa%3Anginx%3Anginx%3A%2A"
        );
    }
}
