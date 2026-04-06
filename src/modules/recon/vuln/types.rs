//! Core types for vulnerability intelligence
//!
//! Data structures for representing vulnerabilities, exploits, and detected technologies.

use super::cpe::TechCategory;

use crate::modules::common::Severity;
use std::cmp::Ordering;

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

// Severity is imported from crate::modules::common
// Previous local Severity::None maps to common::Severity::Info

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
fn parse_version(version: &str) -> ParsedVersion {
  let core_and_suffix = version.split('+').next().unwrap_or("");
  let mut parts = core_and_suffix.splitn(2, '-');
  let core = parts.next().unwrap_or("");
  let prerelease = parts.next().unwrap_or("");

  let core_parts = core
    .split('.')
    .filter_map(|segment| {
      let normalized = segment.trim_start_matches(&['v', 'V'][..]);
      let digits: String = normalized
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
      if digits.is_empty() {
        None
      } else {
        digits.parse::<u32>().ok()
      }
    })
    .collect::<Vec<_>>();

  let prerelease_parts = prerelease
    .split('.')
    .filter(|segment| !segment.is_empty())
    .map(|segment| {
      if segment.chars().all(|c| c.is_ascii_digit()) {
        Identifier::Numeric(segment.parse().unwrap_or(0))
      } else {
        Identifier::Alpha(segment.to_string())
      }
    })
    .collect::<Vec<_>>();

  ParsedVersion {
    core: core_parts,
    prerelease: prerelease_parts,
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedVersion {
  core: Vec<u32>,
  prerelease: Vec<Identifier>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Identifier {
  Numeric(u32),
  Alpha(String),
}

impl Ord for Identifier {
  fn cmp(&self, other: &Self) -> Ordering {
    match (self, other) {
      (Identifier::Numeric(a), Identifier::Numeric(b)) => a.cmp(b),
      (Identifier::Alpha(a), Identifier::Alpha(b)) => a.cmp(b),
      (Identifier::Numeric(_), Identifier::Alpha(_)) => Ordering::Less,
      (Identifier::Alpha(_), Identifier::Numeric(_)) => Ordering::Greater,
    }
  }
}

impl PartialOrd for Identifier {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for ParsedVersion {
  fn cmp(&self, other: &Self) -> Ordering {
    let core_len = std::cmp::max(self.core.len(), other.core.len());
    for i in 0..core_len {
      let left = self.core.get(i).copied().unwrap_or(0);
      let right = other.core.get(i).copied().unwrap_or(0);
      match left.cmp(&right) {
        Ordering::Equal => {}
        diff => return diff,
      }
    }

    match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
      (true, true) => {}
      (true, false) => return Ordering::Greater,
      (false, true) => return Ordering::Less,
      (false, false) => {}
    }

    let prerelease_len = std::cmp::max(self.prerelease.len(), other.prerelease.len());
    for i in 0..prerelease_len {
      let left = self.prerelease.get(i);
      let right = other.prerelease.get(i);

      match (left, right) {
        (None, None) => break,
        (Some(_), None) => return Ordering::Greater,
        (None, Some(_)) => return Ordering::Less,
        (Some(left_id), Some(right_id)) => match left_id.cmp(right_id) {
          Ordering::Equal => {}
          diff => return diff,
        },
      }
    }

    Ordering::Equal
  }
}

impl PartialOrd for ParsedVersion {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
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
      severity: Severity::Info,
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
      if self.cvss_v3.is_none_or(|s| other_cvss > s) {
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
    assert_eq!(Severity::from_cvss(0.0), Severity::Info);
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
