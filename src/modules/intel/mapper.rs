//! MITRE ATT&CK Technique Mapping Engine
//!
//! Maps security findings (open ports, CVEs, fingerprints) to MITRE ATT&CK techniques.
//!
//! ## Port Mapping
//!
//! Open ports indicate potential attack vectors:
//! - SSH (22) → T1021.004 Remote Services: SSH
//! - RDP (3389) → T1021.001 Remote Services: RDP
//! - SMB (445) → T1021.002 Remote Services: SMB
//!
//! ## CVE Mapping
//!
//! Vulnerability types map to techniques:
//! - RCE vulnerabilities → T1203 Exploitation for Client Execution
//! - SQLi vulnerabilities → T1190 Exploit Public-Facing Application
//!
//! ## Fingerprint Mapping
//!
//! Technology fingerprints indicate attacker interest:
//! - WordPress → T1583.008 Compromise Websites
//! - Apache → T1190 Exploit Public-Facing Application

use std::collections::HashMap;

mod data;
#[cfg(test)]
mod tests;

use data::{build_cve_patterns, build_fingerprint_mappings, build_port_mappings};

/// A mapped technique result
#[derive(Debug, Clone)]
pub struct MappedTechnique {
  /// MITRE technique ID (e.g., "T1021.004")
  pub technique_id: String,
  /// Technique name
  pub name: String,
  /// Why this was mapped
  pub reason: String,
  /// Associated tactic
  pub tactic: String,
  /// Confidence: high, medium, low
  pub confidence: Confidence,
  /// Source of the mapping (port, cve, fingerprint)
  pub source: MappingSource,
  /// Original value that triggered the mapping
  pub original_value: String,
}

/// Confidence level for technique mappings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
  High,
  Medium,
  Low,
}

impl Confidence {
  pub fn as_str(&self) -> &'static str {
    match self {
      Confidence::High => "high",
      Confidence::Medium => "medium",
      Confidence::Low => "low",
    }
  }

  pub fn score(&self) -> u8 {
    match self {
      Confidence::High => 100,
      Confidence::Medium => 70,
      Confidence::Low => 40,
    }
  }
}

/// Source of the mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingSource {
  Port,
  Cve,
  Fingerprint,
  Banner,
}

impl MappingSource {
  pub fn as_str(&self) -> &'static str {
    match self {
      MappingSource::Port => "port",
      MappingSource::Cve => "cve",
      MappingSource::Fingerprint => "fingerprint",
      MappingSource::Banner => "banner",
    }
  }
}

/// Port to technique mapping entry
struct PortMapping {
  technique_id: &'static str,
  name: &'static str,
  tactic: &'static str,
  confidence: Confidence,
  reason: &'static str,
}

/// CVE pattern mapping entry
struct CvePattern {
  /// Keywords to match in CVE description
  keywords: Vec<&'static str>,
  /// Technique ID
  technique_id: &'static str,
  name: &'static str,
  tactic: &'static str,
  confidence: Confidence,
  reason: &'static str,
}

/// Fingerprint mapping entry
struct FingerprintMapping {
  technique_id: &'static str,
  name: &'static str,
  tactic: &'static str,
  confidence: Confidence,
  reason: &'static str,
}

/// Technique mapper engine
pub struct TechniqueMapper {
  /// Port number to technique mappings
  port_mappings: HashMap<u16, Vec<PortMapping>>,
  /// CVE pattern to technique mappings
  cve_patterns: Vec<CvePattern>,
  /// Technology fingerprint to technique mappings
  fingerprint_mappings: HashMap<String, Vec<FingerprintMapping>>,
}

impl Default for TechniqueMapper {
  fn default() -> Self {
    Self::new()
  }
}

impl TechniqueMapper {
  /// Create a new technique mapper with built-in mappings
  pub fn new() -> Self {
    Self {
      port_mappings: build_port_mappings(),
      cve_patterns: build_cve_patterns(),
      fingerprint_mappings: build_fingerprint_mappings(),
    }
  }

  /// Map an open port to techniques
  pub fn map_port(&self, port: u16) -> Vec<MappedTechnique> {
    self
      .port_mappings
      .get(&port)
      .map(|mappings| {
        mappings
          .iter()
          .map(|m| MappedTechnique {
            technique_id: m.technique_id.to_string(),
            name: m.name.to_string(),
            reason: m.reason.to_string(),
            tactic: m.tactic.to_string(),
            confidence: m.confidence,
            source: MappingSource::Port,
            original_value: format!("port/{}", port),
          })
          .collect()
      })
      .unwrap_or_default()
  }

  /// Map a CVE description to techniques
  pub fn map_cve(&self, cve_id: &str, description: &str) -> Vec<MappedTechnique> {
    let lower = description.to_lowercase();
    let mut results = Vec::new();

    for pattern in &self.cve_patterns {
      let matches = pattern.keywords.iter().any(|kw| lower.contains(kw));
      if matches {
        results.push(MappedTechnique {
          technique_id: pattern.technique_id.to_string(),
          name: pattern.name.to_string(),
          reason: pattern.reason.to_string(),
          tactic: pattern.tactic.to_string(),
          confidence: pattern.confidence,
          source: MappingSource::Cve,
          original_value: cve_id.to_string(),
        });
      }
    }

    results
  }

  /// Map a technology fingerprint to techniques
  pub fn map_fingerprint(&self, technology: &str) -> Vec<MappedTechnique> {
    let lower = technology.to_lowercase();

    // Try exact match first
    if let Some(mappings) = self.fingerprint_mappings.get(&lower) {
      return mappings
        .iter()
        .map(|m| MappedTechnique {
          technique_id: m.technique_id.to_string(),
          name: m.name.to_string(),
          reason: m.reason.to_string(),
          tactic: m.tactic.to_string(),
          confidence: m.confidence,
          source: MappingSource::Fingerprint,
          original_value: technology.to_string(),
        })
        .collect();
    }

    // Try partial match
    for (key, mappings) in &self.fingerprint_mappings {
      if lower.contains(key) || key.contains(&lower) {
        return mappings
          .iter()
          .map(|m| MappedTechnique {
            technique_id: m.technique_id.to_string(),
            name: m.name.to_string(),
            reason: m.reason.to_string(),
            tactic: m.tactic.to_string(),
            confidence: Confidence::Low, // Lower confidence for partial match
            source: MappingSource::Fingerprint,
            original_value: technology.to_string(),
          })
          .collect();
      }
    }

    Vec::new()
  }

  /// Map a banner string to techniques
  pub fn map_banner(&self, banner: &str) -> Vec<MappedTechnique> {
    let lower = banner.to_lowercase();
    let mut results = Vec::new();

    // Extract technology from banner and map
    for (tech, mappings) in &self.fingerprint_mappings {
      if lower.contains(tech) {
        for m in mappings {
          results.push(MappedTechnique {
            technique_id: m.technique_id.to_string(),
            name: m.name.to_string(),
            reason: format!("{} (detected in banner)", m.reason),
            tactic: m.tactic.to_string(),
            confidence: Confidence::Medium,
            source: MappingSource::Banner,
            original_value: banner.to_string(),
          });
        }
      }
    }

    results
  }

  /// Map all findings for a target
  pub fn map_findings(&self, findings: &Findings) -> MappingResult {
    let mut result = MappingResult {
      techniques: Vec::new(),
      by_tactic: HashMap::new(),
      coverage: Vec::new(),
    };

    // Map ports
    for port in &findings.ports {
      let mapped = self.map_port(*port);
      for tech in mapped {
        result.add_technique(tech);
      }
    }

    // Map CVEs
    for (cve_id, description) in &findings.cves {
      let mapped = self.map_cve(cve_id, description);
      for tech in mapped {
        result.add_technique(tech);
      }
    }

    // Map fingerprints
    for fingerprint in &findings.fingerprints {
      let mapped = self.map_fingerprint(fingerprint);
      for tech in mapped {
        result.add_technique(tech);
      }
    }

    // Map banners
    for banner in &findings.banners {
      let mapped = self.map_banner(banner);
      for tech in mapped {
        result.add_technique(tech);
      }
    }

    // Calculate tactic coverage
    result.calculate_coverage();

    result
  }

  /// Get all mapped port numbers
  pub fn mapped_ports(&self) -> Vec<u16> {
    let mut ports: Vec<_> = self.port_mappings.keys().cloned().collect();
    ports.sort();
    ports
  }

  /// Get all mapped technologies
  pub fn mapped_technologies(&self) -> Vec<&str> {
    let mut techs: Vec<_> = self
      .fingerprint_mappings
      .keys()
      .map(|s| s.as_str())
      .collect();
    techs.sort();
    techs
  }
}

/// Findings to map
#[derive(Debug, Default)]
pub struct Findings {
  /// Open ports
  pub ports: Vec<u16>,
  /// CVEs (id, description)
  pub cves: Vec<(String, String)>,
  /// Technology fingerprints
  pub fingerprints: Vec<String>,
  /// Service banners
  pub banners: Vec<String>,
}

/// Mapping result
#[derive(Debug)]
pub struct MappingResult {
  /// All mapped techniques (deduplicated)
  pub techniques: Vec<MappedTechnique>,
  /// Techniques grouped by tactic
  pub by_tactic: HashMap<String, Vec<MappedTechnique>>,
  /// Tactic coverage (tactic, count, percentage)
  pub coverage: Vec<(String, usize, f32)>,
}

impl MappingResult {
  /// Add a technique (deduplicates by ID)
  fn add_technique(&mut self, tech: MappedTechnique) {
    // Check for duplicate
    if self
      .techniques
      .iter()
      .any(|t| t.technique_id == tech.technique_id && t.original_value == tech.original_value)
    {
      return;
    }

    let tactic = tech.tactic.clone();
    self.by_tactic.entry(tactic).or_default().push(tech.clone());
    self.techniques.push(tech);
  }

  /// Calculate tactic coverage
  fn calculate_coverage(&mut self) {
    // Standard MITRE ATT&CK tactics in kill chain order
    let tactics = [
      "Reconnaissance",
      "Resource Development",
      "Initial Access",
      "Execution",
      "Persistence",
      "Privilege Escalation",
      "Defense Evasion",
      "Credential Access",
      "Discovery",
      "Lateral Movement",
      "Collection",
      "Command and Control",
      "Exfiltration",
      "Impact",
    ];

    let total = self.techniques.len();

    for tactic in tactics {
      let count = self.by_tactic.get(tactic).map(|v| v.len()).unwrap_or(0);
      let percentage = if total > 0 {
        (count as f32 / total as f32) * 100.0
      } else {
        0.0
      };
      self.coverage.push((tactic.to_string(), count, percentage));
    }
  }

  /// Get unique technique IDs
  pub fn unique_technique_ids(&self) -> Vec<&str> {
    let mut ids: Vec<_> = self
      .techniques
      .iter()
      .map(|t| t.technique_id.as_str())
      .collect();
    ids.sort();
    ids.dedup();
    ids
  }

  /// Get techniques sorted by confidence
  pub fn by_confidence(&self) -> Vec<&MappedTechnique> {
    let mut sorted: Vec<_> = self.techniques.iter().collect();
    sorted.sort_by(|a, b| b.confidence.score().cmp(&a.confidence.score()));
    sorted
  }
}
