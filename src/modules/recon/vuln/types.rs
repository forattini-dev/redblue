//! Core types for vulnerability intelligence
//!
//! Data structures for representing vulnerabilities, exploits, and detected technologies.

use super::cpe::TechCategory;

/// Detected technology with version information
#[derive(Debug, Clone)]
pub struct DetectedTech {
    /// Technology name (e.g., "nginx", "wordpress")
    pub name: String,
    /// Detected version (e.g., "1.18.0")
    pub version: Option<String>,
    /// Vendor name if known
    pub vendor: Option<String>,
    /// Technology category
    pub category: TechCategory,
    /// CPE identifier if resolved
    pub cpe: Option<String>,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f32,
    /// How was this detected
    pub detection_source: String,
}

impl DetectedTech {
    /// Create a new detected technology
    pub fn new(name: &str, version: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            vendor: None,
            category: TechCategory::Other,
            cpe: None,
            confidence: 0.5,
            detection_source: "unknown".to_string(),
        }
    }

    /// Set the CPE from the dictionary
    pub fn with_cpe(mut self, cpe: Option<String>) -> Self {
        self.cpe = cpe;
        self
    }

    /// Set detection confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set detection source
    pub fn with_source(mut self, source: &str) -> Self {
        self.detection_source = source.to_string();
        self
    }

    /// Set category
    pub fn with_category(mut self, category: TechCategory) -> Self {
        self.category = category;
        self
    }
}

/// Vulnerability severity levels based on CVSS
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// CVSS 0.0 or unknown
    None,
    /// CVSS 0.1 - 3.9
    Low,
    /// CVSS 4.0 - 6.9
    Medium,
    /// CVSS 7.0 - 8.9
    High,
    /// CVSS 9.0 - 10.0
    Critical,
}

impl Severity {
    /// Convert CVSS score to severity
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s >= 0.1 => Severity::Low,
            _ => Severity::None,
        }
    }

    /// Get display string
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::None => "NONE",
        }
    }

    /// Get color code for terminal output
    pub fn color_code(&self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[91m", // Bright red
            Severity::High => "\x1b[31m",     // Red
            Severity::Medium => "\x1b[33m",   // Yellow
            Severity::Low => "\x1b[36m",      // Cyan
            Severity::None => "\x1b[37m",     // White
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Source of vulnerability information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulnSource {
    /// NIST National Vulnerability Database
    Nvd,
    /// Open Source Vulnerabilities database
    Osv,
    /// CISA Known Exploited Vulnerabilities
    CisaKev,
    /// Vulners aggregator
    Vulners,
    /// Exploit Database
    ExploitDb,
    /// GitHub Security Advisories
    Ghsa,
    /// Vendor advisory
    Vendor(String),
}

impl VulnSource {
    pub fn as_str(&self) -> &str {
        match self {
            VulnSource::Nvd => "NVD",
            VulnSource::Osv => "OSV",
            VulnSource::CisaKev => "CISA-KEV",
            VulnSource::Vulners => "Vulners",
            VulnSource::ExploitDb => "Exploit-DB",
            VulnSource::Ghsa => "GHSA",
            VulnSource::Vendor(name) => name,
        }
    }
}

/// Reference to a known exploit
#[derive(Debug, Clone)]
pub struct ExploitRef {
    /// Source of the exploit (exploit-db, github, etc.)
    pub source: String,
    /// URL to the exploit
    pub url: String,
    /// Exploit title if available
    pub title: Option<String>,
    /// Exploit type (PoC, Metasploit module, etc.)
    pub exploit_type: Option<String>,
}

/// Version range for affected software
#[derive(Debug, Clone)]
pub struct VersionRange {
    /// Start version (inclusive)
    pub start_including: Option<String>,
    /// Start version (exclusive)
    pub start_excluding: Option<String>,
    /// End version (inclusive)
    pub end_including: Option<String>,
    /// End version (exclusive)
    pub end_excluding: Option<String>,
}

impl VersionRange {
    /// Check if a version falls within this range
    pub fn contains(&self, version: &str) -> bool {
        // Simplified semver comparison
        // TODO: Implement proper semver comparison
        let ver = parse_version(version);

        if let Some(ref start) = self.start_including {
            let start_ver = parse_version(start);
            if ver < start_ver {
                return false;
            }
        }

        if let Some(ref start) = self.start_excluding {
            let start_ver = parse_version(start);
            if ver <= start_ver {
                return false;
            }
        }

        if let Some(ref end) = self.end_including {
            let end_ver = parse_version(end);
            if ver > end_ver {
                return false;
            }
        }

        if let Some(ref end) = self.end_excluding {
            let end_ver = parse_version(end);
            if ver >= end_ver {
                return false;
            }
        }

        true
    }
}

/// Parse version string into comparable tuple
fn parse_version(version: &str) -> Vec<u32> {
    version
        .split(|c: char| c == '.' || c == '-' || c == '_')
        .filter_map(|part| {
            // Extract leading digits from each part
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
        .collect()
}

/// Vulnerability record from any source
#[derive(Debug, Clone)]
pub struct Vulnerability {
    /// Canonical identifier (CVE-YYYY-NNNNN or GHSA-xxxx-xxxx-xxxx)
    pub id: String,
    /// Short title/summary
    pub title: String,
    /// Full description
    pub description: String,
    /// CVSS v3 base score (0.0 - 10.0)
    pub cvss_v3: Option<f32>,
    /// CVSS v2 base score (legacy)
    pub cvss_v2: Option<f32>,
    /// Calculated severity
    pub severity: Severity,
    /// Publication date (ISO 8601)
    pub published: Option<String>,
    /// Last modified date
    pub modified: Option<String>,
    /// Reference URLs
    pub references: Vec<String>,
    /// Known exploits
    pub exploits: Vec<ExploitRef>,
    /// Is in CISA KEV catalog
    pub cisa_kev: bool,
    /// CISA KEV due date
    pub kev_due_date: Option<String>,
    /// Affected version ranges
    pub affected_versions: Vec<VersionRange>,
    /// CPE matches
    pub affected_cpes: Vec<String>,
    /// Data sources
    pub sources: Vec<VulnSource>,
    /// CWE IDs
    pub cwes: Vec<String>,
    /// Calculated risk score (0-100)
    pub risk_score: Option<u8>,
}

impl Vulnerability {
    /// Create a new vulnerability with minimal info
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            title: String::new(),
            description: String::new(),
            cvss_v3: None,
            cvss_v2: None,
            severity: Severity::None,
            published: None,
            modified: None,
            references: Vec::new(),
            exploits: Vec::new(),
            cisa_kev: false,
            kev_due_date: None,
            affected_versions: Vec::new(),
            affected_cpes: Vec::new(),
            sources: Vec::new(),
            cwes: Vec::new(),
            risk_score: None,
        }
    }

    /// Check if exploit is available
    pub fn has_exploit(&self) -> bool {
        !self.exploits.is_empty()
    }

    /// Check if this is a CVE
    pub fn is_cve(&self) -> bool {
        self.id.starts_with("CVE-")
    }

    /// Get the best CVSS score available
    pub fn best_cvss(&self) -> Option<f32> {
        self.cvss_v3.or(self.cvss_v2)
    }

    /// Merge data from another vulnerability (same ID)
    pub fn merge(&mut self, other: &Vulnerability) {
        // Take higher CVSS
        if let Some(other_cvss) = other.cvss_v3 {
            if self.cvss_v3.map_or(true, |s| other_cvss > s) {
                self.cvss_v3 = Some(other_cvss);
            }
        }

        // Merge references (dedupe)
        for reference in &other.references {
            if !self.references.contains(reference) {
                self.references.push(reference.clone());
            }
        }

        // Merge exploits
        for exploit in &other.exploits {
            if !self.exploits.iter().any(|e| e.url == exploit.url) {
                self.exploits.push(exploit.clone());
            }
        }

        // Take KEV status
        if other.cisa_kev {
            self.cisa_kev = true;
            if self.kev_due_date.is_none() {
                self.kev_due_date = other.kev_due_date.clone();
            }
        }

        // Merge sources
        for source in &other.sources {
            if !self.sources.contains(source) {
                self.sources.push(source.clone());
            }
        }

        // Merge CWEs
        for cwe in &other.cwes {
            if !self.cwes.contains(cwe) {
                self.cwes.push(cwe.clone());
            }
        }

        // Update severity based on new CVSS
        if let Some(cvss) = self.best_cvss() {
            self.severity = Severity::from_cvss(cvss);
        }
    }
}

/// Collection of vulnerabilities with deduplication
#[derive(Debug, Default)]
pub struct VulnCollection {
    vulns: std::collections::HashMap<String, Vulnerability>,
}

impl VulnCollection {
    pub fn new() -> Self {
        Self {
            vulns: std::collections::HashMap::new(),
        }
    }

    /// Add or merge a vulnerability
    pub fn add(&mut self, vuln: Vulnerability) {
        if let Some(existing) = self.vulns.get_mut(&vuln.id) {
            existing.merge(&vuln);
        } else {
            self.vulns.insert(vuln.id.clone(), vuln);
        }
    }

    /// Get all vulnerabilities sorted by risk score
    pub fn sorted_by_risk(&self) -> Vec<&Vulnerability> {
        let mut vulns: Vec<_> = self.vulns.values().collect();
        vulns.sort_by(|a, b| b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0)));
        vulns
    }

    /// Get all vulnerabilities sorted by severity
    pub fn sorted_by_severity(&self) -> Vec<&Vulnerability> {
        let mut vulns: Vec<_> = self.vulns.values().collect();
        vulns.sort_by(|a, b| b.severity.cmp(&a.severity));
        vulns
    }

    /// Get only CVEs
    pub fn cves_only(&self) -> Vec<&Vulnerability> {
        self.vulns.values().filter(|v| v.is_cve()).collect()
    }

    /// Get only with exploits
    pub fn with_exploits(&self) -> Vec<&Vulnerability> {
        self.vulns.values().filter(|v| v.has_exploit()).collect()
    }

    /// Get only KEV entries
    pub fn kev_only(&self) -> Vec<&Vulnerability> {
        self.vulns.values().filter(|v| v.cisa_kev).collect()
    }

    /// Total count
    pub fn len(&self) -> usize {
        self.vulns.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.vulns.is_empty()
    }

    /// Get by ID
    pub fn get(&self, id: &str) -> Option<&Vulnerability> {
        self.vulns.get(id)
    }

    /// Iterate over all vulnerabilities
    pub fn iter(&self) -> impl Iterator<Item = &Vulnerability> {
        self.vulns.values()
    }

    /// Iterate mutably over all vulnerabilities
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Vulnerability> {
        self.vulns.values_mut()
    }

    /// Consume the collection and return sorted vulnerabilities by risk score
    pub fn into_sorted(self) -> Vec<Vulnerability> {
        let mut vulns: Vec<Vulnerability> = self.vulns.into_values().collect();
        vulns.sort_by(|a, b| b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0)));
        vulns
    }
}

impl IntoIterator for VulnCollection {
    type Item = Vulnerability;
    type IntoIter = std::collections::hash_map::IntoValues<String, Vulnerability>;

    fn into_iter(self) -> Self::IntoIter {
        self.vulns.into_values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::None);
    }

    #[test]
    fn test_version_range_contains() {
        let range = VersionRange {
            start_including: Some("1.0.0".to_string()),
            start_excluding: None,
            end_including: None,
            end_excluding: Some("2.0.0".to_string()),
        };

        assert!(range.contains("1.0.0"));
        assert!(range.contains("1.5.0"));
        assert!(range.contains("1.9.9"));
        assert!(!range.contains("0.9.0"));
        assert!(!range.contains("2.0.0"));
        assert!(!range.contains("2.1.0"));
    }

    #[test]
    fn test_vuln_merge() {
        let mut v1 = Vulnerability::new("CVE-2024-1234");
        v1.cvss_v3 = Some(7.5);
        v1.references.push("https://example.com/1".to_string());
        v1.sources.push(VulnSource::Nvd);

        let mut v2 = Vulnerability::new("CVE-2024-1234");
        v2.cvss_v3 = Some(8.0);
        v2.references.push("https://example.com/2".to_string());
        v2.cisa_kev = true;
        v2.sources.push(VulnSource::CisaKev);

        v1.merge(&v2);

        assert_eq!(v1.cvss_v3, Some(8.0)); // Takes higher
        assert_eq!(v1.references.len(), 2);
        assert!(v1.cisa_kev);
        assert_eq!(v1.sources.len(), 2);
    }

    #[test]
    fn test_vuln_collection() {
        let mut collection = VulnCollection::new();

        let mut v1 = Vulnerability::new("CVE-2024-1234");
        v1.cvss_v3 = Some(9.8);
        v1.severity = Severity::Critical;
        collection.add(v1);

        let mut v2 = Vulnerability::new("CVE-2024-5678");
        v2.cvss_v3 = Some(5.0);
        v2.severity = Severity::Medium;
        collection.add(v2);

        assert_eq!(collection.len(), 2);

        let sorted = collection.sorted_by_severity();
        assert_eq!(sorted[0].id, "CVE-2024-1234");
    }
}
