//! Vulnerability Correlation Engine
//!
//! Correlates detected technologies with known vulnerabilities from multiple sources.
//!
//! ## Pipeline
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
//! │ DetectedTech[]  │────▶│ CPE Mapping  │────▶│ Source Queries  │
//! │                 │     │              │     │                 │
//! │ nginx 1.18.0    │     │ cpe:2.3:a:   │     │ NVD │ OSV │ KEV │
//! │ PHP 8.1.2       │     │ f5:nginx:... │     │ Exploit-DB      │
//! └─────────────────┘     └──────────────┘     └────────┬────────┘
//!                                                       │
//!                                                       ▼
//! ┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
//! │ CorrelationReport│◀────│ Risk Scoring │◀────│ Deduplication   │
//! │                 │     │              │     │                 │
//! │ Per-tech vulns  │     │ CVSS + KEV + │     │ Merge by CVE ID │
//! │ Risk matrix     │     │ Exploit bonus│     │                 │
//! └─────────────────┘     └──────────────┘     └─────────────────┘
//! ```

use super::exploitdb::ExploitDbEntry;
use super::kev::KevEntry;
use super::osv::Ecosystem;
use super::{
    calculate_risk_score, find_cpe, generate_cpe, CpeMapping, DetectedTech, ExploitDbClient,
    KevClient, NvdClient, OsvClient, Severity, TechCategory, VulnCollection, VulnSource,
    Vulnerability,
};
use std::time::{Duration, Instant};

/// Configuration for the correlation engine
#[derive(Debug, Clone)]
pub struct CorrelatorConfig {
    /// Query NVD for CVEs
    pub use_nvd: bool,
    /// Query OSV for package vulns
    pub use_osv: bool,
    /// Check CISA KEV catalog
    pub use_kev: bool,
    /// Search Exploit-DB
    pub use_exploitdb: bool,
    /// Maximum vulnerabilities per technology
    pub max_vulns_per_tech: usize,
    /// Request timeout
    pub timeout: Duration,
    /// NVD API key for higher rate limits
    pub nvd_api_key: Option<String>,
    /// OSV ecosystem filter (npm, pypi, cargo, etc.)
    pub osv_ecosystem: Option<String>,
    /// Minimum severity to include
    pub min_severity: Severity,
    /// Only include vulns with exploits
    pub exploits_only: bool,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        Self {
            use_nvd: true,
            use_osv: true,
            use_kev: true,
            use_exploitdb: true,
            max_vulns_per_tech: 50,
            timeout: Duration::from_secs(30),
            nvd_api_key: None,
            osv_ecosystem: None,
            min_severity: Severity::None,
            exploits_only: false,
        }
    }
}

/// Results for a single technology
#[derive(Debug)]
pub struct TechCorrelation {
    /// The detected technology
    pub tech: DetectedTech,
    /// Resolved CPE identifier
    pub cpe: Option<String>,
    /// Found vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,
    /// Total CVE count
    pub cve_count: usize,
    /// Critical severity count
    pub critical_count: usize,
    /// High severity count
    pub high_count: usize,
    /// Vulnerabilities with known exploits
    pub exploitable_count: usize,
    /// KEV entries
    pub kev_count: usize,
    /// Query duration
    pub query_time_ms: u64,
}

impl TechCorrelation {
    fn new(tech: DetectedTech) -> Self {
        Self {
            tech,
            cpe: None,
            vulnerabilities: Vec::new(),
            cve_count: 0,
            critical_count: 0,
            high_count: 0,
            exploitable_count: 0,
            kev_count: 0,
            query_time_ms: 0,
        }
    }

    /// Calculate statistics from vulnerabilities
    fn calculate_stats(&mut self) {
        self.cve_count = self.vulnerabilities.iter().filter(|v| v.is_cve()).count();
        self.critical_count = self
            .vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();
        self.high_count = self
            .vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::High)
            .count();
        self.exploitable_count = self
            .vulnerabilities
            .iter()
            .filter(|v| v.has_exploit())
            .count();
        self.kev_count = self.vulnerabilities.iter().filter(|v| v.cisa_kev).count();
    }

    /// Get highest risk score among vulnerabilities
    pub fn max_risk_score(&self) -> u8 {
        self.vulnerabilities
            .iter()
            .filter_map(|v| v.risk_score)
            .max()
            .unwrap_or(0)
    }

    /// Get highest severity
    pub fn max_severity(&self) -> Severity {
        self.vulnerabilities
            .iter()
            .map(|v| v.severity)
            .max()
            .unwrap_or(Severity::None)
    }
}

/// Source query statistics
#[derive(Debug, Clone)]
pub struct SourceStats {
    /// Source name
    pub source: String,
    /// Number of vulnerabilities found
    pub found: usize,
    /// Query duration in milliseconds
    pub duration_ms: u64,
    /// Error message if failed
    pub error: Option<String>,
}

/// Complete correlation report
#[derive(Debug)]
pub struct CorrelationReport {
    /// Results per technology
    pub tech_correlations: Vec<TechCorrelation>,
    /// All unique vulnerabilities (deduplicated)
    pub all_vulnerabilities: VulnCollection,
    /// Source query statistics
    pub source_stats: Vec<SourceStats>,
    /// Total query time
    pub total_time_ms: u64,
    /// Technologies without vulnerabilities
    pub clean_techs: Vec<String>,
    /// Summary statistics
    pub summary: CorrelationSummary,
}

/// Summary statistics
#[derive(Debug, Default)]
pub struct CorrelationSummary {
    /// Total technologies scanned
    pub techs_scanned: usize,
    /// Technologies with vulnerabilities
    pub techs_vulnerable: usize,
    /// Total unique vulnerabilities
    pub total_vulns: usize,
    /// Critical severity count
    pub critical_count: usize,
    /// High severity count
    pub high_count: usize,
    /// Medium severity count
    pub medium_count: usize,
    /// Low severity count
    pub low_count: usize,
    /// Vulnerabilities with known exploits
    pub exploitable_count: usize,
    /// CISA KEV entries
    pub kev_count: usize,
    /// Average risk score
    pub avg_risk_score: f32,
    /// Highest risk score
    pub max_risk_score: u8,
}

impl CorrelationReport {
    fn new() -> Self {
        Self {
            tech_correlations: Vec::new(),
            all_vulnerabilities: VulnCollection::new(),
            source_stats: Vec::new(),
            total_time_ms: 0,
            clean_techs: Vec::new(),
            summary: CorrelationSummary::default(),
        }
    }

    /// Calculate summary statistics
    fn calculate_summary(&mut self) {
        self.summary.techs_scanned = self.tech_correlations.len() + self.clean_techs.len();
        self.summary.techs_vulnerable = self
            .tech_correlations
            .iter()
            .filter(|t| !t.vulnerabilities.is_empty())
            .count();
        self.summary.total_vulns = self.all_vulnerabilities.len();

        let mut total_risk: u32 = 0;
        let mut risk_count = 0;

        for vuln in self.all_vulnerabilities.iter() {
            match vuln.severity {
                Severity::Critical => self.summary.critical_count += 1,
                Severity::High => self.summary.high_count += 1,
                Severity::Medium => self.summary.medium_count += 1,
                Severity::Low => self.summary.low_count += 1,
                Severity::None => {}
            }

            if vuln.has_exploit() {
                self.summary.exploitable_count += 1;
            }

            if vuln.cisa_kev {
                self.summary.kev_count += 1;
            }

            if let Some(score) = vuln.risk_score {
                total_risk += score as u32;
                risk_count += 1;
                if score > self.summary.max_risk_score {
                    self.summary.max_risk_score = score;
                }
            }
        }

        if risk_count > 0 {
            self.summary.avg_risk_score = total_risk as f32 / risk_count as f32;
        }
    }

    /// Get top N vulnerabilities by risk score
    pub fn top_risks(&self, n: usize) -> Vec<&Vulnerability> {
        let mut vulns: Vec<_> = self.all_vulnerabilities.iter().collect();
        vulns.sort_by(|a, b| b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0)));
        vulns.into_iter().take(n).collect()
    }

    /// Get vulnerabilities with exploits
    pub fn exploitable(&self) -> Vec<&Vulnerability> {
        self.all_vulnerabilities.with_exploits()
    }

    /// Get KEV entries
    pub fn kev_entries(&self) -> Vec<&Vulnerability> {
        self.all_vulnerabilities.kev_only()
    }
}

/// Vulnerability Correlation Engine
///
/// Takes detected technologies and correlates them with known vulnerabilities.
pub struct VulnCorrelator {
    config: CorrelatorConfig,
    nvd_client: NvdClient,
    osv_client: OsvClient,
    kev_client: KevClient,
    exploitdb_client: ExploitDbClient,
}

impl VulnCorrelator {
    /// Create a new correlator with default configuration
    pub fn new() -> Self {
        Self {
            config: CorrelatorConfig::default(),
            nvd_client: NvdClient::new(),
            osv_client: OsvClient::new(),
            kev_client: KevClient::new(),
            exploitdb_client: ExploitDbClient::new(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: CorrelatorConfig) -> Self {
        let mut correlator = Self::new();
        correlator.config = config;
        correlator
    }

    /// Set NVD API key
    pub fn with_nvd_api_key(mut self, key: &str) -> Self {
        self.config.nvd_api_key = Some(key.to_string());
        self
    }

    /// Set OSV ecosystem filter
    pub fn with_osv_ecosystem(mut self, ecosystem: &str) -> Self {
        self.config.osv_ecosystem = Some(ecosystem.to_string());
        self
    }

    /// Set minimum severity filter
    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.config.min_severity = severity;
        self
    }

    /// Only include vulnerabilities with known exploits
    pub fn exploits_only(mut self) -> Self {
        self.config.exploits_only = true;
        self
    }

    /// Correlate a list of detected technologies with vulnerabilities
    pub fn correlate(&mut self, techs: &[DetectedTech]) -> CorrelationReport {
        let total_start = Instant::now();
        let mut report = CorrelationReport::new();

        for tech in techs {
            let correlation = self.correlate_single(tech, &mut report.source_stats);

            if correlation.vulnerabilities.is_empty() {
                report.clean_techs.push(tech.name.clone());
            } else {
                // Add vulnerabilities to global collection
                for vuln in &correlation.vulnerabilities {
                    report.all_vulnerabilities.add(vuln.clone());
                }
                report.tech_correlations.push(correlation);
            }
        }

        report.total_time_ms = total_start.elapsed().as_millis() as u64;
        report.calculate_summary();
        report
    }

    /// Correlate a single technology
    fn correlate_single(
        &mut self,
        tech: &DetectedTech,
        source_stats: &mut Vec<SourceStats>,
    ) -> TechCorrelation {
        let start = Instant::now();
        let mut correlation = TechCorrelation::new(tech.clone());

        // Resolve CPE
        let cpe = self.resolve_cpe(tech);
        correlation.cpe = cpe.clone();

        let mut collection = VulnCollection::new();

        // Query NVD
        if self.config.use_nvd {
            let nvd_start = Instant::now();
            match self.query_nvd(&tech.name, tech.version.as_deref(), cpe.as_deref()) {
                Ok(vulns) => {
                    let count = vulns.len();
                    for vuln in vulns {
                        collection.add(vuln);
                    }
                    source_stats.push(SourceStats {
                        source: "NVD".to_string(),
                        found: count,
                        duration_ms: nvd_start.elapsed().as_millis() as u64,
                        error: None,
                    });
                }
                Err(e) => {
                    source_stats.push(SourceStats {
                        source: "NVD".to_string(),
                        found: 0,
                        duration_ms: nvd_start.elapsed().as_millis() as u64,
                        error: Some(e),
                    });
                }
            }
        }

        // Query OSV
        if self.config.use_osv {
            let osv_start = Instant::now();
            match self.query_osv(&tech.name, tech.version.as_deref(), &tech.category) {
                Ok(vulns) => {
                    let count = vulns.len();
                    for vuln in vulns {
                        collection.add(vuln);
                    }
                    source_stats.push(SourceStats {
                        source: "OSV".to_string(),
                        found: count,
                        duration_ms: osv_start.elapsed().as_millis() as u64,
                        error: None,
                    });
                }
                Err(e) => {
                    source_stats.push(SourceStats {
                        source: "OSV".to_string(),
                        found: 0,
                        duration_ms: osv_start.elapsed().as_millis() as u64,
                        error: Some(e),
                    });
                }
            }
        }

        // Query KEV
        if self.config.use_kev {
            let kev_start = Instant::now();
            match self.query_kev(&tech.name) {
                Ok(vulns) => {
                    let count = vulns.len();
                    for vuln in vulns {
                        collection.add(vuln);
                    }
                    source_stats.push(SourceStats {
                        source: "CISA-KEV".to_string(),
                        found: count,
                        duration_ms: kev_start.elapsed().as_millis() as u64,
                        error: None,
                    });
                }
                Err(e) => {
                    source_stats.push(SourceStats {
                        source: "CISA-KEV".to_string(),
                        found: 0,
                        duration_ms: kev_start.elapsed().as_millis() as u64,
                        error: Some(e),
                    });
                }
            }
        }

        // Query Exploit-DB
        if self.config.use_exploitdb {
            let edb_start = Instant::now();
            match self.query_exploitdb(&tech.name, tech.version.as_deref()) {
                Ok(vulns) => {
                    let count = vulns.len();
                    for vuln in vulns {
                        collection.add(vuln);
                    }
                    source_stats.push(SourceStats {
                        source: "Exploit-DB".to_string(),
                        found: count,
                        duration_ms: edb_start.elapsed().as_millis() as u64,
                        error: None,
                    });
                }
                Err(e) => {
                    source_stats.push(SourceStats {
                        source: "Exploit-DB".to_string(),
                        found: 0,
                        duration_ms: edb_start.elapsed().as_millis() as u64,
                        error: Some(e),
                    });
                }
            }
        }

        // Calculate risk scores
        for vuln in collection.iter_mut() {
            vuln.risk_score = Some(calculate_risk_score(vuln));
        }

        // Filter by severity
        let mut vulns: Vec<Vulnerability> = collection
            .into_iter()
            .filter(|v| v.severity >= self.config.min_severity)
            .collect();

        // Filter by exploits if requested
        if self.config.exploits_only {
            vulns.retain(|v| v.has_exploit());
        }

        // Sort by risk score
        vulns.sort_by(|a, b| b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0)));

        // Limit results
        vulns.truncate(self.config.max_vulns_per_tech);

        correlation.vulnerabilities = vulns;
        correlation.query_time_ms = start.elapsed().as_millis() as u64;
        correlation.calculate_stats();

        correlation
    }

    /// Resolve CPE identifier for a technology
    fn resolve_cpe(&self, tech: &DetectedTech) -> Option<String> {
        // First check if tech already has a CPE
        if let Some(ref cpe) = tech.cpe {
            return Some(cpe.clone());
        }

        // Try to find in CPE dictionary and generate versioned CPE
        if let Some(mapping) = find_cpe(&tech.name) {
            return Some(mapping.to_cpe(tech.version.as_deref()));
        }

        // Fallback: use generate_cpe which looks up from dictionary
        generate_cpe(&tech.name, tech.version.as_deref())
    }

    /// Query NVD for vulnerabilities
    fn query_nvd(
        &mut self,
        _name: &str,
        _version: Option<&str>,
        cpe: Option<&str>,
    ) -> Result<Vec<Vulnerability>, String> {
        // Prefer CPE query if available
        if let Some(cpe) = cpe {
            return self.nvd_client.query_by_cpe(cpe);
        }

        // NVD requires CPE for accurate queries
        Ok(Vec::new())
    }

    /// Query OSV for vulnerabilities
    fn query_osv(
        &self,
        name: &str,
        version: Option<&str>,
        category: &TechCategory,
    ) -> Result<Vec<Vulnerability>, String> {
        // Determine ecosystem from category or config
        let ecosystem = match category {
            TechCategory::JsLibrary => Some(Ecosystem::Npm),
            TechCategory::Runtime => {
                // Could be Node.js (npm) or Python, etc.
                if name.to_lowercase().contains("node") {
                    Some(Ecosystem::Npm)
                } else if name.to_lowercase().contains("python") {
                    Some(Ecosystem::PyPI)
                } else {
                    None
                }
            }
            TechCategory::Framework => {
                // Try to detect from name
                if name.to_lowercase().contains("django") || name.to_lowercase().contains("flask") {
                    Some(Ecosystem::PyPI)
                } else if name.to_lowercase().contains("express")
                    || name.to_lowercase().contains("react")
                {
                    Some(Ecosystem::Npm)
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(eco) = ecosystem {
            self.osv_client.query_package(name, version, eco)
        } else {
            // OSV requires ecosystem for package queries
            Ok(Vec::new())
        }
    }

    /// Query CISA KEV catalog
    fn query_kev(&mut self, name: &str) -> Result<Vec<Vulnerability>, String> {
        // Get KEV entries by product name
        let entries = self.kev_client.get_by_product(name)?;

        // Convert KEV entries to Vulnerability records
        let vulns: Vec<Vulnerability> = entries
            .into_iter()
            .map(|entry| kev_entry_to_vuln(entry))
            .collect();

        Ok(vulns)
    }

    /// Query Exploit-DB
    fn query_exploitdb(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<Vec<Vulnerability>, String> {
        // Search by product and version
        let entries = self.exploitdb_client.search_by_product(name, version)?;

        // Convert to vulnerabilities
        let vulns: Vec<Vulnerability> = entries
            .into_iter()
            .filter_map(|entry| {
                // Only include if there's a CVE associated or create a placeholder
                if !entry.cve_ids.is_empty() {
                    let mut vuln = Vulnerability::new(&entry.cve_ids[0]);
                    vuln.title = entry.title.clone();
                    vuln.exploits.push(entry.to_exploit_ref());
                    vuln.sources.push(VulnSource::ExploitDb);
                    Some(vuln)
                } else {
                    // Create an EDB-based entry
                    let mut vuln = Vulnerability::new(&format!("EDB-{}", entry.id));
                    vuln.title = entry.title.clone();
                    vuln.exploits.push(entry.to_exploit_ref());
                    vuln.sources.push(VulnSource::ExploitDb);
                    Some(vuln)
                }
            })
            .collect();

        Ok(vulns)
    }
}

/// Convert KEV entry to Vulnerability
fn kev_entry_to_vuln(entry: KevEntry) -> Vulnerability {
    let mut vuln = Vulnerability::new(&entry.cve_id);
    vuln.title = entry.vulnerability_name;
    vuln.description = entry.short_description;
    vuln.cisa_kev = true;
    vuln.kev_due_date = Some(entry.due_date);
    vuln.sources.push(VulnSource::CisaKev);

    // Add reference about ransomware use
    if entry.known_ransomware_use {
        vuln.references
            .push("Known to be used in ransomware campaigns".to_string());
    }

    vuln
}

impl Default for VulnCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick correlation without full configuration
pub fn correlate_techs(techs: &[DetectedTech]) -> CorrelationReport {
    let mut correlator = VulnCorrelator::new();
    correlator.correlate(techs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlator_config_default() {
        let config = CorrelatorConfig::default();
        assert!(config.use_nvd);
        assert!(config.use_osv);
        assert!(config.use_kev);
        assert!(config.use_exploitdb);
        assert_eq!(config.max_vulns_per_tech, 50);
        assert_eq!(config.min_severity, Severity::None);
        assert!(!config.exploits_only);
    }

    #[test]
    fn test_tech_correlation_stats() {
        let tech = DetectedTech::new("nginx", Some("1.18.0"));
        let mut correlation = TechCorrelation::new(tech);

        // Add some test vulnerabilities
        let mut v1 = Vulnerability::new("CVE-2024-1234");
        v1.severity = Severity::Critical;
        v1.cisa_kev = true;
        correlation.vulnerabilities.push(v1);

        let mut v2 = Vulnerability::new("CVE-2024-5678");
        v2.severity = Severity::High;
        correlation.vulnerabilities.push(v2);

        correlation.calculate_stats();

        assert_eq!(correlation.cve_count, 2);
        assert_eq!(correlation.critical_count, 1);
        assert_eq!(correlation.high_count, 1);
        assert_eq!(correlation.kev_count, 1);
    }

    #[test]
    fn test_resolve_cpe() {
        let correlator = VulnCorrelator::new();

        // Tech with existing CPE
        let mut tech = DetectedTech::new("nginx", Some("1.18.0"));
        tech.cpe = Some("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*".to_string());
        let cpe = correlator.resolve_cpe(&tech);
        assert!(cpe.is_some());
        assert!(cpe.unwrap().contains("nginx"));

        // Tech without CPE but in dictionary (should find CPE)
        let tech2 = DetectedTech::new("apache", Some("2.4.50"));
        let cpe2 = correlator.resolve_cpe(&tech2);
        assert!(cpe2.is_some());
        assert!(cpe2.unwrap().contains("apache"));

        // Tech not in dictionary - returns None (we don't invent CPEs)
        let tech3 = DetectedTech::new("unknown-tech", Some("1.0.0"));
        let cpe3 = correlator.resolve_cpe(&tech3);
        assert!(cpe3.is_none());
    }

    #[test]
    fn test_correlation_report_summary() {
        let mut report = CorrelationReport::new();

        let mut v1 = Vulnerability::new("CVE-2024-1234");
        v1.severity = Severity::Critical;
        v1.risk_score = Some(95);
        v1.cisa_kev = true;
        report.all_vulnerabilities.add(v1);

        let mut v2 = Vulnerability::new("CVE-2024-5678");
        v2.severity = Severity::High;
        v2.risk_score = Some(75);
        report.all_vulnerabilities.add(v2);

        let mut v3 = Vulnerability::new("CVE-2024-9999");
        v3.severity = Severity::Medium;
        v3.risk_score = Some(50);
        report.all_vulnerabilities.add(v3);

        report.calculate_summary();

        assert_eq!(report.summary.total_vulns, 3);
        assert_eq!(report.summary.critical_count, 1);
        assert_eq!(report.summary.high_count, 1);
        assert_eq!(report.summary.medium_count, 1);
        assert_eq!(report.summary.kev_count, 1);
        assert_eq!(report.summary.max_risk_score, 95);
    }

    #[test]
    fn test_top_risks() {
        let mut report = CorrelationReport::new();

        for i in 0..10 {
            let mut v = Vulnerability::new(&format!("CVE-2024-{:04}", i));
            v.risk_score = Some((i * 10) as u8);
            report.all_vulnerabilities.add(v);
        }

        let top = report.top_risks(3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].risk_score, Some(90));
        assert_eq!(top[1].risk_score, Some(80));
        assert_eq!(top[2].risk_score, Some(70));
    }
}
