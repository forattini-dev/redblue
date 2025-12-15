//! OSV (Open Source Vulnerabilities) API Client
//!
//! Query vulnerabilities from OSV.dev for open-source packages.
//!
//! API Docs: https://osv.dev/docs/

use super::types::{Severity, VersionRange, VulnSource, Vulnerability};
use crate::protocols::http::HttpClient;
use crate::utils::json::{parse_json, JsonValue};

const OSV_API_BASE: &str = "https://api.osv.dev/v1";

/// Supported package ecosystems
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Cargo,
    Go,
    Maven,
    NuGet,
    Packagist,
    RubyGems,
    Pub,
    Hex,
    ConanCenter,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Maven => "Maven",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Pub => "Pub",
            Ecosystem::Hex => "Hex",
            Ecosystem::ConanCenter => "ConanCenter",
        }
    }

    /// Detect ecosystem from package name or file
    pub fn detect(package: &str) -> Option<Self> {
        if package.starts_with('@') || package.contains('/') && !package.contains('.') {
            Some(Ecosystem::Npm)
        } else if package.ends_with(".py") {
            Some(Ecosystem::PyPI)
        } else if package.contains("::") {
            Some(Ecosystem::Cargo)
        } else {
            None
        }
    }
}

/// OSV API client
pub struct OsvClient {
    http: HttpClient,
}

impl OsvClient {
    /// Create new OSV client
    pub fn new() -> Self {
        Self {
            http: HttpClient::new(),
        }
    }

    /// Query vulnerabilities for a package
    pub fn query_package(
        &self,
        package: &str,
        version: Option<&str>,
        ecosystem: Ecosystem,
    ) -> Result<Vec<Vulnerability>, String> {
        let url = format!("{}/query", OSV_API_BASE);

        // Build request body
        let mut body = format!(
            r#"{{"package":{{"name":"{}","ecosystem":"{}"}}"#,
            escape_json(package),
            ecosystem.as_str()
        );

        if let Some(ver) = version {
            body.push_str(&format!(r#","version":"{}""#, escape_json(ver)));
        }

        body.push_str("}");

        let response = self.http.post(&url, body.into_bytes())?;

        if response.status_code != 200 {
            return Err(format!("OSV API error: HTTP {}", response.status_code));
        }

        let body_str = String::from_utf8_lossy(&response.body).to_string();
        let json = parse_json(&body_str)?;

        self.parse_response(&json)
    }

    /// Get vulnerability by ID
    pub fn get_by_id(&self, vuln_id: &str) -> Result<Option<Vulnerability>, String> {
        let url = format!("{}/vulns/{}", OSV_API_BASE, vuln_id);

        let response = self.http.get(&url)?;

        if response.status_code == 404 {
            return Ok(None);
        }

        if response.status_code != 200 {
            return Err(format!("OSV API error: HTTP {}", response.status_code));
        }

        let body = String::from_utf8_lossy(&response.body).to_string();
        let json = parse_json(&body)?;

        Ok(self.parse_vuln(&json))
    }

    /// Parse OSV API response
    fn parse_response(&self, json: &JsonValue) -> Result<Vec<Vulnerability>, String> {
        let vulns_array = match json.get("vulns") {
            Some(v) => v.as_array().ok_or("Invalid OSV response")?,
            None => return Ok(Vec::new()), // No vulnerabilities found
        };

        let mut result = Vec::new();

        for item in vulns_array {
            if let Some(vuln) = self.parse_vuln(item) {
                result.push(vuln);
            }
        }

        Ok(result)
    }

    /// Parse a single OSV vulnerability entry
    fn parse_vuln(&self, json: &JsonValue) -> Option<Vulnerability> {
        let id = json.get("id")?.as_str()?;

        let mut vuln = Vulnerability::new(id);
        vuln.sources.push(VulnSource::Osv);

        // Summary as title
        vuln.title = json
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or(id)
            .to_string();

        // Details as description
        vuln.description = json
            .get("details")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();

        // Published and modified dates
        vuln.published = json
            .get("published")
            .and_then(|p| p.as_str())
            .map(|s| s.to_string());
        vuln.modified = json
            .get("modified")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string());

        // Severity from CVSS
        if let Some(severity) = json.get("severity").and_then(|s| s.as_array()) {
            for sev in severity {
                if sev.get("type").and_then(|t| t.as_str()) == Some("CVSS_V3") {
                    if let Some(score_str) = sev.get("score").and_then(|s| s.as_str()) {
                        // Parse CVSS vector to extract base score
                        if let Some(score) = extract_cvss_score(score_str) {
                            vuln.cvss_v3 = Some(score);
                            vuln.severity = Severity::from_cvss(score);
                        }
                    }
                }
            }
        }

        // Database-specific severity
        if let Some(db_specific) = json.get("database_specific") {
            if let Some(severity) = db_specific.get("severity").and_then(|s| s.as_str()) {
                if vuln.cvss_v3.is_none() {
                    vuln.severity = match severity.to_uppercase().as_str() {
                        "CRITICAL" => Severity::Critical,
                        "HIGH" => Severity::High,
                        "MODERATE" | "MEDIUM" => Severity::Medium,
                        "LOW" => Severity::Low,
                        _ => Severity::None,
                    };
                }
            }
        }

        // Aliases (CVE IDs)
        if let Some(aliases) = json.get("aliases").and_then(|a| a.as_array()) {
            for alias in aliases {
                if let Some(alias_str) = alias.as_str() {
                    // If we find a CVE, use it as the canonical ID
                    if alias_str.starts_with("CVE-") {
                        vuln.id = alias_str.to_string();
                    }
                }
            }
        }

        // References
        if let Some(refs) = json.get("references").and_then(|r| r.as_array()) {
            for reference in refs {
                if let Some(url) = reference.get("url").and_then(|u| u.as_str()) {
                    vuln.references.push(url.to_string());
                }
            }
        }

        // Affected versions
        if let Some(affected) = json.get("affected").and_then(|a| a.as_array()) {
            for affected_pkg in affected {
                if let Some(ranges) = affected_pkg.get("ranges").and_then(|r| r.as_array()) {
                    for range in ranges {
                        if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                            let mut version_range = VersionRange {
                                start_including: None,
                                start_excluding: None,
                                end_including: None,
                                end_excluding: None,
                            };

                            for event in events {
                                if let Some(introduced) =
                                    event.get("introduced").and_then(|i| i.as_str())
                                {
                                    if introduced != "0" {
                                        version_range.start_including =
                                            Some(introduced.to_string());
                                    }
                                }
                                if let Some(fixed) = event.get("fixed").and_then(|f| f.as_str()) {
                                    version_range.end_excluding = Some(fixed.to_string());
                                }
                            }

                            if version_range.start_including.is_some()
                                || version_range.end_excluding.is_some()
                            {
                                vuln.affected_versions.push(version_range);
                            }
                        }
                    }
                }
            }
        }

        Some(vuln)
    }
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract base score from CVSS vector string
fn extract_cvss_score(vector: &str) -> Option<f32> {
    // Try to parse as a direct score first
    if let Ok(score) = vector.parse::<f32>() {
        return Some(score);
    }

    // Try to extract from CVSS:3.x/... format
    // This is a simplified extraction - real CVSS calculation is complex
    None
}

/// Escape string for JSON
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_detect() {
        assert_eq!(Ecosystem::detect("@angular/core"), Some(Ecosystem::Npm));
        assert_eq!(Ecosystem::detect("lodash"), None);
    }

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json("test"), "test");
        assert_eq!(escape_json("te\"st"), "te\\\"st");
        assert_eq!(escape_json("te\\st"), "te\\\\st");
    }
}
