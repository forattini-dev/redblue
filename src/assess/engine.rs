//! Assessment Engine
//!
//! Orchestrates the complete assessment workflow:
//! 1. Technology discovery (fingerprinting)
//! 2. Vulnerability correlation
//! 3. Playbook recommendation
//!
//! Integrates with cache for intelligent data reuse.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::assess::cache::{CacheManager, CacheStatus, CachedTechnologies, CachedVulnerabilities};
use crate::modules::recon::vuln::{
    CorrelationReport, CorrelatorConfig, DetectedTech, TechCategory as VulnTechCategory,
    VulnCorrelator,
};
use crate::modules::web::fingerprinter::{
    FingerprintResult, TechCategory, Technology, WebFingerprinter,
};
use crate::playbooks::recommender::{
    DetectedOS, PlaybookRecommender, RecommendationResult, ReconFindings,
};
use crate::playbooks::types::RiskLevel;
use crate::storage::records::{Severity as RecordSeverity, VulnerabilityRecord};
use crate::storage::RedDb;

/// Assessment options
#[derive(Debug, Clone)]
pub struct AssessOptions {
    /// Skip fingerprinting phase (use cache only)
    pub skip_fingerprint: bool,
    /// Skip vulnerability lookup (use cache only)
    pub skip_vuln: bool,
    /// Force refresh all data regardless of cache status
    pub refresh: bool,
    /// Dry run - don't execute playbooks
    pub dry_run: bool,
    /// Maximum risk level for playbook recommendations
    pub max_risk: RiskLevel,
    /// NVD API key for higher rate limits
    pub nvd_api_key: Option<String>,
}

impl Default for AssessOptions {
    fn default() -> Self {
        Self {
            skip_fingerprint: false,
            skip_vuln: false,
            refresh: false,
            dry_run: false,
            max_risk: RiskLevel::High,
            nvd_api_key: None,
        }
    }
}

/// Assessment result containing all phases' output
#[derive(Debug)]
pub struct AssessmentResult {
    /// Target that was assessed
    pub target: String,
    /// Detected technologies
    pub technologies: Vec<Technology>,
    /// Vulnerability correlation report
    pub vulnerabilities: Option<CorrelationReport>,
    /// Vulnerability records (from cache or fresh)
    pub vuln_records: Vec<VulnerabilityRecord>,
    /// Playbook recommendations
    pub recommendations: RecommendationResult,
    /// Overall risk score (0-100)
    pub risk_score: u8,
    /// Cache status for fingerprints
    pub fingerprint_cache_status: CacheStatus,
    /// Cache status for vulnerabilities
    pub vuln_cache_status: CacheStatus,
    /// Total assessment time
    pub elapsed: Duration,
}

/// Assessment Engine
///
/// Orchestrates the continuous assessment workflow integrating
/// fingerprinting, vulnerability correlation, and playbook recommendation.
pub struct AssessmentEngine {
    target: String,
    cache: CacheManager,
    fingerprinter: WebFingerprinter,
    db_path: String,
}

impl AssessmentEngine {
    /// Create a new assessment engine for a target
    pub fn new(target: &str, db_path: &str) -> Self {
        Self {
            target: target.to_string(),
            cache: CacheManager::new(),
            fingerprinter: WebFingerprinter::new(),
            db_path: db_path.to_string(),
        }
    }

    /// Create with custom cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache = CacheManager::with_ttl(ttl);
        self
    }

    /// Run the full assessment workflow
    pub fn run(&self, opts: AssessOptions) -> Result<AssessmentResult, String> {
        let start = Instant::now();

        // Open database
        let mut db =
            RedDb::open(&self.db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        // Phase 1: Technology Discovery
        let (technologies, fingerprint_cache_status) = self.phase_fingerprint(&opts, &mut db)?;

        // Phase 2: Vulnerability Correlation
        let (vuln_report, vuln_records, vuln_cache_status) =
            self.phase_vulnerabilities(&opts, &technologies, &mut db)?;

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&vuln_records, vuln_report.as_ref());

        // Phase 3: Playbook Recommendations
        let recommendations = self.phase_recommendations(&technologies, &vuln_records, &opts);

        // Persist any new data
        db.flush()
            .map_err(|e| format!("Failed to flush database: {}", e))?;

        Ok(AssessmentResult {
            target: self.target.clone(),
            technologies,
            vulnerabilities: vuln_report,
            vuln_records,
            recommendations,
            risk_score,
            fingerprint_cache_status,
            vuln_cache_status,
            elapsed: start.elapsed(),
        })
    }

    /// Phase 1: Technology Discovery
    fn phase_fingerprint(
        &self,
        opts: &AssessOptions,
        db: &mut RedDb,
    ) -> Result<(Vec<Technology>, CacheStatus), String> {
        // Check cache first
        let cached = self.cache.get_technologies(&self.target, db);

        match cached {
            Some(CachedTechnologies {
                technologies,
                status,
                ..
            }) if status.is_fresh() && !opts.refresh && !opts.skip_fingerprint => {
                // Use fresh cache
                Ok((technologies, status))
            }
            Some(CachedTechnologies {
                technologies,
                status,
                ..
            }) if opts.skip_fingerprint => {
                // User wants to skip fingerprinting, use whatever cache we have
                Ok((technologies, status))
            }
            _ if opts.skip_fingerprint => {
                // Skip fingerprinting but no cache - return empty
                Ok((Vec::new(), CacheStatus::Miss))
            }
            _ => {
                // Need fresh fingerprint
                let url = self.normalize_url(&self.target);
                let result = self.fingerprinter.fingerprint(&url)?;

                // Store results in database
                self.store_fingerprint_results(&result, db)?;

                Ok((result.technologies, CacheStatus::Miss))
            }
        }
    }

    /// Phase 2: Vulnerability Correlation
    fn phase_vulnerabilities(
        &self,
        opts: &AssessOptions,
        technologies: &[Technology],
        db: &mut RedDb,
    ) -> Result<
        (
            Option<CorrelationReport>,
            Vec<VulnerabilityRecord>,
            CacheStatus,
        ),
        String,
    > {
        // Check cache first
        let cached = self.cache.get_vulnerabilities(&self.target, db);

        match cached {
            Some(CachedVulnerabilities {
                vulnerabilities,
                status,
                ..
            }) if status.is_fresh() && !opts.refresh && !opts.skip_vuln => {
                // Use fresh cache
                Ok((None, vulnerabilities, status))
            }
            Some(CachedVulnerabilities {
                vulnerabilities,
                status,
                ..
            }) if opts.skip_vuln => {
                // User wants to skip vuln lookup, use whatever cache we have
                Ok((None, vulnerabilities, status))
            }
            _ if opts.skip_vuln => {
                // Skip vuln lookup but no cache - return empty
                Ok((None, Vec::new(), CacheStatus::Miss))
            }
            _ => {
                // Need fresh correlation
                let detected_techs = self.convert_to_detected_techs(technologies);

                let config = CorrelatorConfig {
                    nvd_api_key: opts.nvd_api_key.clone(),
                    ..Default::default()
                };

                let mut correlator = VulnCorrelator::with_config(config);
                let report = correlator.correlate(&detected_techs);

                // Convert to records and store
                let records = self.convert_to_vuln_records(&report);
                self.store_vuln_records(&records, db)?;

                Ok((Some(report), records, CacheStatus::Miss))
            }
        }
    }

    /// Phase 3: Playbook Recommendations
    fn phase_recommendations(
        &self,
        technologies: &[Technology],
        vulns: &[VulnerabilityRecord],
        opts: &AssessOptions,
    ) -> RecommendationResult {
        let findings = ReconFindings {
            target: self.target.clone(),
            ports: Vec::new(), // Could be enhanced with port scan data
            vulns: vulns.to_vec(),
            fingerprints: technologies.iter().map(|t| t.name.clone()).collect(),
            detected_os: self.detect_os_from_tech(technologies),
            target_type: None,
            is_internal: self.is_internal_target(),
        };

        // Create a new recommender with the configured max risk
        let recommender = PlaybookRecommender::new().with_max_risk(opts.max_risk);
        recommender.recommend(&findings)
    }

    /// Normalize target to URL format
    fn normalize_url(&self, target: &str) -> String {
        if target.starts_with("http://") || target.starts_with("https://") {
            target.to_string()
        } else {
            format!("http://{}", target)
        }
    }

    /// Convert fingerprinter Technology to vuln DetectedTech
    fn convert_to_detected_techs(&self, technologies: &[Technology]) -> Vec<DetectedTech> {
        technologies
            .iter()
            .map(|t| {
                let category = match t.category {
                    TechCategory::CMS => VulnTechCategory::Cms,
                    TechCategory::Framework => VulnTechCategory::Framework,
                    TechCategory::WebServer => VulnTechCategory::WebServer,
                    TechCategory::Language => VulnTechCategory::Runtime,
                    TechCategory::Library => VulnTechCategory::JsLibrary,
                    TechCategory::CDN => VulnTechCategory::Cdn,
                    TechCategory::Database => VulnTechCategory::Database,
                    _ => VulnTechCategory::Other,
                };

                let confidence = match t.confidence {
                    crate::modules::web::fingerprinter::Confidence::High => 0.9,
                    crate::modules::web::fingerprinter::Confidence::Medium => 0.7,
                    crate::modules::web::fingerprinter::Confidence::Low => 0.4,
                };

                DetectedTech::new(&t.name, t.version.as_deref())
                    .with_category(category)
                    .with_confidence(confidence)
                    .with_source("fingerprinter")
            })
            .collect()
    }

    /// Convert CorrelationReport to VulnerabilityRecords
    fn convert_to_vuln_records(&self, report: &CorrelationReport) -> Vec<VulnerabilityRecord> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        report
            .all_vulnerabilities
            .iter()
            .map(|v| {
                let severity = match v.severity {
                    crate::modules::recon::vuln::Severity::Critical => RecordSeverity::Critical,
                    crate::modules::recon::vuln::Severity::High => RecordSeverity::High,
                    crate::modules::recon::vuln::Severity::Medium => RecordSeverity::Medium,
                    crate::modules::recon::vuln::Severity::Low => RecordSeverity::Low,
                    crate::modules::recon::vuln::Severity::None => RecordSeverity::Info,
                };

                // Extract technology name from CPE or use title
                let technology = v
                    .affected_cpes
                    .first()
                    .map(|cpe| {
                        // CPE format: cpe:2.3:a:vendor:product:version:...
                        let parts: Vec<_> = cpe.split(':').collect();
                        if parts.len() >= 5 {
                            parts[4].to_string()
                        } else {
                            v.title.clone()
                        }
                    })
                    .unwrap_or_else(|| v.title.clone());

                // Extract version from affected_versions
                let version = v.affected_versions.first().and_then(|vr| {
                    vr.end_including
                        .clone()
                        .or_else(|| vr.start_including.clone())
                });

                // Format sources
                let source = v
                    .sources
                    .iter()
                    .map(|s| format!("{:?}", s))
                    .collect::<Vec<_>>()
                    .join(", ");

                VulnerabilityRecord {
                    cve_id: v.id.clone(),
                    technology,
                    version,
                    cvss: v.cvss_v3.unwrap_or(0.0),
                    risk_score: v.risk_score.unwrap_or(0),
                    severity,
                    description: v.description.clone(),
                    references: v.references.clone(),
                    exploit_available: v.has_exploit(),
                    in_kev: v.cisa_kev,
                    discovered_at: now,
                    source,
                }
            })
            .collect()
    }

    /// Store fingerprint results in database
    fn store_fingerprint_results(
        &self,
        _result: &FingerprintResult,
        _db: &mut RedDb,
    ) -> Result<(), String> {
        // HTTP records are automatically stored by the fingerprinter
        // when it makes requests, so we don't need to store them again
        Ok(())
    }

    /// Store vulnerability records in database
    fn store_vuln_records(
        &self,
        records: &[VulnerabilityRecord],
        db: &mut RedDb,
    ) -> Result<(), String> {
        for record in records {
            db.vulns()
                .insert(record.clone())
                .map_err(|e| format!("Failed to store vulnerability: {}", e))?;
        }
        Ok(())
    }

    /// Calculate overall risk score
    fn calculate_risk_score(
        &self,
        records: &[VulnerabilityRecord],
        report: Option<&CorrelationReport>,
    ) -> u8 {
        if let Some(report) = report {
            // Use correlation report's calculated score
            report.summary.max_risk_score
        } else if !records.is_empty() {
            // Calculate from records
            records.iter().map(|r| r.risk_score).max().unwrap_or(0)
        } else {
            0
        }
    }

    /// Detect OS from technology fingerprints
    fn detect_os_from_tech(&self, technologies: &[Technology]) -> Option<DetectedOS> {
        for tech in technologies {
            let name_lower = tech.name.to_lowercase();
            if name_lower.contains("windows")
                || name_lower.contains("iis")
                || name_lower.contains("asp.net")
            {
                return Some(DetectedOS::Windows);
            }
            if name_lower.contains("linux")
                || name_lower.contains("ubuntu")
                || name_lower.contains("debian")
            {
                return Some(DetectedOS::Linux);
            }
            if name_lower.contains("macos") || name_lower.contains("darwin") {
                return Some(DetectedOS::MacOS);
            }
        }
        None
    }

    /// Check if target appears to be internal
    fn is_internal_target(&self) -> bool {
        let target = self.target.to_lowercase();
        target.contains("internal")
            || target.contains("intranet")
            || target.contains("localhost")
            || target.starts_with("10.")
            || target.starts_with("192.168.")
            || target.starts_with("172.16.")
            || target.starts_with("172.17.")
            || target.starts_with("172.18.")
            || target.starts_with("172.19.")
            || target.starts_with("172.2")
            || target.starts_with("172.30.")
            || target.starts_with("172.31.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        let engine = AssessmentEngine::new("example.com", "/tmp/test.db");
        assert_eq!(engine.normalize_url("example.com"), "http://example.com");
        assert_eq!(
            engine.normalize_url("https://example.com"),
            "https://example.com"
        );
        assert_eq!(
            engine.normalize_url("http://example.com"),
            "http://example.com"
        );
    }

    #[test]
    fn test_is_internal_target() {
        let engine = AssessmentEngine::new("192.168.1.1", "/tmp/test.db");
        assert!(engine.is_internal_target());

        let engine = AssessmentEngine::new("10.0.0.1", "/tmp/test.db");
        assert!(engine.is_internal_target());

        let engine = AssessmentEngine::new("example.com", "/tmp/test.db");
        assert!(!engine.is_internal_target());

        let engine = AssessmentEngine::new("internal.company.com", "/tmp/test.db");
        assert!(engine.is_internal_target());
    }

    #[test]
    fn test_assess_options_default() {
        let opts = AssessOptions::default();
        assert!(!opts.skip_fingerprint);
        assert!(!opts.skip_vuln);
        assert!(!opts.refresh);
        assert!(!opts.dry_run);
        assert_eq!(opts.max_risk, RiskLevel::High);
    }
}
