//! CISA KEV (Known Exploited Vulnerabilities) Client
//!
//! Query CISA's Known Exploited Vulnerabilities catalog.
//!
//! Catalog URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

use super::types::{ExploitRef, VulnSource, Vulnerability};
use crate::protocols::http::HttpClient;
use crate::utils::json::{parse_json, JsonValue};
use std::collections::HashMap;

const KEV_JSON_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// CISA KEV entry
#[derive(Debug, Clone)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    pub known_ransomware_use: bool,
    pub notes: Option<String>,
}

/// CISA KEV client
pub struct KevClient {
    http: HttpClient,
    /// Cached KEV entries (CVE ID -> entry)
    cache: Option<HashMap<String, KevEntry>>,
    /// Cache timestamp
    cache_time: Option<std::time::Instant>,
}

impl KevClient {
    /// Create new KEV client
    pub fn new() -> Self {
        Self {
            http: HttpClient::new(),
            cache: None,
            cache_time: None,
        }
    }

    /// Fetch and cache the KEV catalog
    pub fn fetch_catalog(&mut self) -> Result<(), String> {
        // Check if cache is still valid (1 hour)
        if let (Some(_cache), Some(time)) = (&self.cache, &self.cache_time) {
            if time.elapsed() < std::time::Duration::from_secs(3600) {
                return Ok(());
            }
        }

        let response = self.http.get(KEV_JSON_URL)?;

        if response.status_code != 200 {
            return Err(format!("CISA KEV error: HTTP {}", response.status_code));
        }

        let body = String::from_utf8_lossy(&response.body).to_string();
        let json = parse_json(&body)?;

        let vulns = json
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .ok_or("Invalid KEV response")?;

        let mut cache = HashMap::new();

        for vuln in vulns {
            if let Some(entry) = self.parse_entry(vuln) {
                cache.insert(entry.cve_id.clone(), entry);
            }
        }

        self.cache = Some(cache);
        self.cache_time = Some(std::time::Instant::now());

        Ok(())
    }

    /// Check if a CVE is in the KEV catalog
    pub fn is_in_kev(&mut self, cve_id: &str) -> Result<bool, String> {
        self.fetch_catalog()?;

        Ok(self
            .cache
            .as_ref()
            .map(|c| c.contains_key(cve_id))
            .unwrap_or(false))
    }

    /// Get KEV entry for a CVE
    pub fn get_entry(&mut self, cve_id: &str) -> Result<Option<KevEntry>, String> {
        self.fetch_catalog()?;

        Ok(self.cache.as_ref().and_then(|c| c.get(cve_id).cloned()))
    }

    /// Enrich vulnerability with KEV data
    pub fn enrich_vulnerability(&mut self, vuln: &mut Vulnerability) -> Result<(), String> {
        if let Some(entry) = self.get_entry(&vuln.id)? {
            vuln.cisa_kev = true;
            vuln.kev_due_date = Some(entry.due_date.clone());
            vuln.sources.push(VulnSource::CisaKev);

            // Add exploit reference since it's known exploited
            vuln.exploits.push(ExploitRef {
                source: "CISA-KEV".to_string(),
                url: format!("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={}", vuln.id),
                title: Some(entry.vulnerability_name.clone()),
                exploit_type: Some("Known Exploited".to_string()),
            });

            // Add note about ransomware use
            if entry.known_ransomware_use {
                vuln.references
                    .push("CISA Warning: Known to be used in ransomware campaigns".to_string());
            }
        }

        Ok(())
    }

    /// Get all KEV entries
    pub fn get_all(&mut self) -> Result<Vec<KevEntry>, String> {
        self.fetch_catalog()?;

        Ok(self
            .cache
            .as_ref()
            .map(|c| c.values().cloned().collect())
            .unwrap_or_default())
    }

    /// Get KEV entries by vendor
    pub fn get_by_vendor(&mut self, vendor: &str) -> Result<Vec<KevEntry>, String> {
        self.fetch_catalog()?;

        let vendor_lower = vendor.to_lowercase();

        Ok(self
            .cache
            .as_ref()
            .map(|c| {
                c.values()
                    .filter(|e| e.vendor_project.to_lowercase().contains(&vendor_lower))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Get KEV entries by product
    pub fn get_by_product(&mut self, product: &str) -> Result<Vec<KevEntry>, String> {
        self.fetch_catalog()?;

        let product_lower = product.to_lowercase();

        Ok(self
            .cache
            .as_ref()
            .map(|c| {
                c.values()
                    .filter(|e| e.product.to_lowercase().contains(&product_lower))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Parse KEV entry from JSON
    fn parse_entry(&self, json: &JsonValue) -> Option<KevEntry> {
        Some(KevEntry {
            cve_id: json.get("cveID")?.as_str()?.to_string(),
            vendor_project: json.get("vendorProject")?.as_str()?.to_string(),
            product: json.get("product")?.as_str()?.to_string(),
            vulnerability_name: json.get("vulnerabilityName")?.as_str()?.to_string(),
            date_added: json.get("dateAdded")?.as_str()?.to_string(),
            short_description: json.get("shortDescription")?.as_str()?.to_string(),
            required_action: json.get("requiredAction")?.as_str()?.to_string(),
            due_date: json.get("dueDate")?.as_str()?.to_string(),
            known_ransomware_use: json
                .get("knownRansomwareCampaignUse")
                .and_then(|k| k.as_str())
                .map(|s| s.to_lowercase() == "known")
                .unwrap_or(false),
            notes: json
                .get("notes")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string()),
        })
    }

    /// Get catalog statistics
    pub fn stats(&mut self) -> Result<KevStats, String> {
        self.fetch_catalog()?;

        let cache = self.cache.as_ref().ok_or("No cache available")?;

        let total = cache.len();
        let ransomware_count = cache.values().filter(|e| e.known_ransomware_use).count();

        // Count by vendor
        let mut by_vendor: HashMap<String, usize> = HashMap::new();
        for entry in cache.values() {
            *by_vendor.entry(entry.vendor_project.clone()).or_insert(0) += 1;
        }

        // Get top vendors
        let mut vendors: Vec<_> = by_vendor.into_iter().collect();
        vendors.sort_by(|a, b| b.1.cmp(&a.1));
        let top_vendors: Vec<_> = vendors.into_iter().take(10).collect();

        Ok(KevStats {
            total,
            ransomware_count,
            top_vendors,
        })
    }
}

impl Default for KevClient {
    fn default() -> Self {
        Self::new()
    }
}

/// KEV catalog statistics
#[derive(Debug)]
pub struct KevStats {
    pub total: usize,
    pub ransomware_count: usize,
    pub top_vendors: Vec<(String, usize)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kev_client_new() {
        let client = KevClient::new();
        assert!(client.cache.is_none());
    }
}
