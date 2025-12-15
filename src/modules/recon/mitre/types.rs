//! MITRE ATT&CK types and data structures
//!
//! Represents techniques, tactics, groups, and software from ATT&CK framework.

use std::collections::HashMap;

/// ATT&CK Matrix type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMatrix {
    /// Enterprise ATT&CK (Windows, macOS, Linux, Cloud, Network, Containers)
    Enterprise,
    /// Mobile ATT&CK (Android, iOS)
    Mobile,
    /// ICS ATT&CK (Industrial Control Systems)
    Ics,
}

impl AttackMatrix {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackMatrix::Enterprise => "enterprise",
            AttackMatrix::Mobile => "mobile",
            AttackMatrix::Ics => "ics",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            AttackMatrix::Enterprise => "Enterprise",
            AttackMatrix::Mobile => "Mobile",
            AttackMatrix::Ics => "ICS",
        }
    }
}

/// ATT&CK Tactic (column in the matrix)
#[derive(Debug, Clone)]
pub struct Tactic {
    /// Tactic ID (e.g., "TA0001")
    pub id: String,
    /// Tactic name (e.g., "Initial Access")
    pub name: String,
    /// Short name for URLs (e.g., "initial-access")
    pub short_name: String,
    /// Description of the tactic
    pub description: String,
    /// External references (MITRE URL, etc.)
    pub references: Vec<ExternalRef>,
    /// Matrix this belongs to
    pub matrix: AttackMatrix,
}

/// ATT&CK Technique or Sub-technique
#[derive(Debug, Clone)]
pub struct Technique {
    /// Technique ID (e.g., "T1059" or "T1059.001")
    pub id: String,
    /// Technique name (e.g., "Command and Scripting Interpreter")
    pub name: String,
    /// Full description
    pub description: String,
    /// Associated tactics (kill chain phases)
    pub tactics: Vec<String>,
    /// Detection strategies
    pub detection: Option<String>,
    /// Platforms this applies to (Windows, Linux, macOS, etc.)
    pub platforms: Vec<String>,
    /// Data sources for detection
    pub data_sources: Vec<String>,
    /// Is this a sub-technique?
    pub is_subtechnique: bool,
    /// Parent technique ID if sub-technique
    pub parent_id: Option<String>,
    /// MITRE ATT&CK URL
    pub url: String,
    /// External references
    pub references: Vec<ExternalRef>,
    /// Mitigation IDs
    pub mitigations: Vec<String>,
    /// Deprecated flag
    pub deprecated: bool,
    /// Revoked flag
    pub revoked: bool,
    /// Associated CVEs (extracted from references)
    pub cves: Vec<String>,
}

impl Technique {
    /// Get the base technique ID (without sub-technique suffix)
    pub fn base_id(&self) -> &str {
        if let Some(pos) = self.id.find('.') {
            &self.id[..pos]
        } else {
            &self.id
        }
    }

    /// Check if this is a sub-technique
    pub fn is_sub(&self) -> bool {
        self.id.contains('.')
    }

    /// Get display string with tactics
    pub fn display_with_tactics(&self) -> String {
        if self.tactics.is_empty() {
            self.name.clone()
        } else {
            format!("{} [{}]", self.name, self.tactics.join(", "))
        }
    }
}

/// ATT&CK Threat Group (APT group)
#[derive(Debug, Clone)]
pub struct ThreatGroup {
    /// Group ID (e.g., "G0016")
    pub id: String,
    /// Group name (e.g., "APT29", "Cozy Bear")
    pub name: String,
    /// Aliases/other names
    pub aliases: Vec<String>,
    /// Description
    pub description: String,
    /// Techniques used by this group
    pub techniques: Vec<String>,
    /// Software used by this group
    pub software: Vec<String>,
    /// External references
    pub references: Vec<ExternalRef>,
    /// Deprecated flag
    pub deprecated: bool,
}

/// ATT&CK Software (Malware or Tool)
#[derive(Debug, Clone)]
pub struct Software {
    /// Software ID (e.g., "S0154")
    pub id: String,
    /// Software name (e.g., "Cobalt Strike")
    pub name: String,
    /// Type: "malware" or "tool"
    pub software_type: SoftwareType,
    /// Description
    pub description: String,
    /// Platforms
    pub platforms: Vec<String>,
    /// Techniques this software implements
    pub techniques: Vec<String>,
    /// Aliases
    pub aliases: Vec<String>,
    /// External references
    pub references: Vec<ExternalRef>,
    /// Deprecated flag
    pub deprecated: bool,
}

/// Software type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareType {
    Malware,
    Tool,
}

impl SoftwareType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SoftwareType::Malware => "malware",
            SoftwareType::Tool => "tool",
        }
    }
}

/// ATT&CK Mitigation
#[derive(Debug, Clone)]
pub struct Mitigation {
    /// Mitigation ID (e.g., "M1036")
    pub id: String,
    /// Mitigation name
    pub name: String,
    /// Description
    pub description: String,
    /// Techniques this mitigates
    pub techniques: Vec<String>,
    /// External references
    pub references: Vec<ExternalRef>,
    /// Deprecated flag
    pub deprecated: bool,
}

/// External reference (URLs, etc.)
#[derive(Debug, Clone)]
pub struct ExternalRef {
    /// Source name (e.g., "mitre-attack")
    pub source: String,
    /// External ID (e.g., "T1059")
    pub external_id: Option<String>,
    /// URL
    pub url: Option<String>,
    /// Description
    pub description: Option<String>,
}

/// Search result from ATT&CK
#[derive(Debug, Clone)]
pub enum AttackObject {
    Technique(Technique),
    Tactic(Tactic),
    Group(ThreatGroup),
    Software(Software),
    Mitigation(Mitigation),
}

impl AttackObject {
    pub fn id(&self) -> &str {
        match self {
            AttackObject::Technique(t) => &t.id,
            AttackObject::Tactic(t) => &t.id,
            AttackObject::Group(g) => &g.id,
            AttackObject::Software(s) => &s.id,
            AttackObject::Mitigation(m) => &m.id,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            AttackObject::Technique(t) => &t.name,
            AttackObject::Tactic(t) => &t.name,
            AttackObject::Group(g) => &g.name,
            AttackObject::Software(s) => &s.name,
            AttackObject::Mitigation(m) => &m.name,
        }
    }

    pub fn object_type(&self) -> &'static str {
        match self {
            AttackObject::Technique(_) => "technique",
            AttackObject::Tactic(_) => "tactic",
            AttackObject::Group(_) => "group",
            AttackObject::Software(_) => "software",
            AttackObject::Mitigation(_) => "mitigation",
        }
    }
}

/// ATT&CK data store with indexes for fast lookup
#[derive(Debug, Default)]
pub struct AttackData {
    /// All techniques by ID
    pub techniques: HashMap<String, Technique>,
    /// All tactics by ID
    pub tactics: HashMap<String, Tactic>,
    /// All groups by ID
    pub groups: HashMap<String, ThreatGroup>,
    /// All software by ID
    pub software: HashMap<String, Software>,
    /// All mitigations by ID
    pub mitigations: HashMap<String, Mitigation>,
    /// Technique ID to tactic mapping
    pub technique_tactics: HashMap<String, Vec<String>>,
    /// Tactic to techniques mapping
    pub tactic_techniques: HashMap<String, Vec<String>>,
    /// Group to techniques mapping
    pub group_techniques: HashMap<String, Vec<String>>,
    /// Software to techniques mapping
    pub software_techniques: HashMap<String, Vec<String>>,
    /// Technique to groups mapping
    pub technique_groups: HashMap<String, Vec<String>>,
    /// Technique to software mapping
    pub technique_software: HashMap<String, Vec<String>>,
    /// Technique to mitigations mapping
    pub technique_mitigations: HashMap<String, Vec<String>>,
}

impl AttackData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get technique by ID (supports both T1059 and T1059.001 formats)
    pub fn get_technique(&self, id: &str) -> Option<&Technique> {
        let normalized = normalize_technique_id(id);
        self.techniques.get(&normalized)
    }

    /// Get tactic by ID or short name
    pub fn get_tactic(&self, id_or_name: &str) -> Option<&Tactic> {
        // Try direct ID lookup first
        if let Some(tactic) = self.tactics.get(id_or_name) {
            return Some(tactic);
        }

        // Try by short name
        let lower = id_or_name.to_lowercase().replace(' ', "-");
        self.tactics
            .values()
            .find(|t| t.short_name == lower || t.name.to_lowercase() == id_or_name.to_lowercase())
    }

    /// Get group by ID or name/alias
    pub fn get_group(&self, id_or_name: &str) -> Option<&ThreatGroup> {
        // Try direct ID lookup
        if let Some(group) = self.groups.get(id_or_name) {
            return Some(group);
        }

        // Try by name or alias
        let lower = id_or_name.to_lowercase();
        self.groups.values().find(|g| {
            g.name.to_lowercase() == lower || g.aliases.iter().any(|a| a.to_lowercase() == lower)
        })
    }

    /// Get software by ID or name
    pub fn get_software(&self, id_or_name: &str) -> Option<&Software> {
        // Try direct ID lookup
        if let Some(sw) = self.software.get(id_or_name) {
            return Some(sw);
        }

        // Try by name or alias
        let lower = id_or_name.to_lowercase();
        self.software.values().find(|s| {
            s.name.to_lowercase() == lower || s.aliases.iter().any(|a| a.to_lowercase() == lower)
        })
    }

    /// Get mitigation by ID
    pub fn get_mitigation(&self, id: &str) -> Option<&Mitigation> {
        self.mitigations.get(id)
    }

    /// Search all objects by keyword
    pub fn search(&self, query: &str) -> Vec<AttackObject> {
        let lower = query.to_lowercase();
        let mut results = Vec::new();

        // Search techniques
        for tech in self.techniques.values() {
            if tech.deprecated || tech.revoked {
                continue;
            }
            if tech.id.to_lowercase().contains(&lower)
                || tech.name.to_lowercase().contains(&lower)
                || tech.description.to_lowercase().contains(&lower)
            {
                results.push(AttackObject::Technique(tech.clone()));
            }
        }

        // Search tactics
        for tactic in self.tactics.values() {
            if tactic.id.to_lowercase().contains(&lower)
                || tactic.name.to_lowercase().contains(&lower)
            {
                results.push(AttackObject::Tactic(tactic.clone()));
            }
        }

        // Search groups
        for group in self.groups.values() {
            if group.deprecated {
                continue;
            }
            if group.id.to_lowercase().contains(&lower)
                || group.name.to_lowercase().contains(&lower)
                || group
                    .aliases
                    .iter()
                    .any(|a| a.to_lowercase().contains(&lower))
            {
                results.push(AttackObject::Group(group.clone()));
            }
        }

        // Search software
        for sw in self.software.values() {
            if sw.deprecated {
                continue;
            }
            if sw.id.to_lowercase().contains(&lower)
                || sw.name.to_lowercase().contains(&lower)
                || sw.aliases.iter().any(|a| a.to_lowercase().contains(&lower))
            {
                results.push(AttackObject::Software(sw.clone()));
            }
        }

        results
    }

    /// Get techniques for a tactic
    pub fn techniques_for_tactic(&self, tactic_id: &str) -> Vec<&Technique> {
        let normalized = tactic_id.to_uppercase();
        self.tactic_techniques
            .get(&normalized)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.techniques.get(id))
                    .filter(|t| !t.deprecated && !t.revoked)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get techniques used by a group
    pub fn techniques_for_group(&self, group_id: &str) -> Vec<&Technique> {
        self.group_techniques
            .get(group_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.techniques.get(id))
                    .filter(|t| !t.deprecated && !t.revoked)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get groups using a technique
    pub fn groups_for_technique(&self, technique_id: &str) -> Vec<&ThreatGroup> {
        let normalized = normalize_technique_id(technique_id);
        self.technique_groups
            .get(&normalized)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.groups.get(id))
                    .filter(|g| !g.deprecated)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get mitigations for a technique
    pub fn mitigations_for_technique(&self, technique_id: &str) -> Vec<&Mitigation> {
        let normalized = normalize_technique_id(technique_id);
        self.technique_mitigations
            .get(&normalized)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.mitigations.get(id))
                    .filter(|m| !m.deprecated)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get software using a technique
    pub fn software_for_technique(&self, technique_id: &str) -> Vec<&Software> {
        let normalized = normalize_technique_id(technique_id);
        self.technique_software
            .get(&normalized)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.software.get(id))
                    .filter(|s| !s.deprecated)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all tactics in matrix order
    pub fn all_tactics(&self) -> Vec<&Tactic> {
        // Return tactics in typical kill chain order
        let order = [
            "TA0043", // Reconnaissance
            "TA0042", // Resource Development
            "TA0001", // Initial Access
            "TA0002", // Execution
            "TA0003", // Persistence
            "TA0004", // Privilege Escalation
            "TA0005", // Defense Evasion
            "TA0006", // Credential Access
            "TA0007", // Discovery
            "TA0008", // Lateral Movement
            "TA0009", // Collection
            "TA0011", // Command and Control
            "TA0010", // Exfiltration
            "TA0040", // Impact
        ];

        let mut result = Vec::new();
        for id in order {
            if let Some(tactic) = self.tactics.get(id) {
                result.push(tactic);
            }
        }

        // Add any tactics not in the predefined order
        for tactic in self.tactics.values() {
            if !order.contains(&tactic.id.as_str()) {
                result.push(tactic);
            }
        }

        result
    }

    /// Get statistics
    pub fn stats(&self) -> AttackStats {
        AttackStats {
            techniques: self.techniques.len(),
            subtechniques: self
                .techniques
                .values()
                .filter(|t| t.is_subtechnique)
                .count(),
            tactics: self.tactics.len(),
            groups: self.groups.len(),
            software: self.software.len(),
            mitigations: self.mitigations.len(),
        }
    }
}

/// Statistics about loaded ATT&CK data
#[derive(Debug)]
pub struct AttackStats {
    pub techniques: usize,
    pub subtechniques: usize,
    pub tactics: usize,
    pub groups: usize,
    pub software: usize,
    pub mitigations: usize,
}

/// Normalize technique ID to uppercase with proper format
fn normalize_technique_id(id: &str) -> String {
    let upper = id.to_uppercase();
    // Ensure T prefix
    if upper.starts_with('T') {
        upper
    } else {
        format!("T{}", upper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_technique_id() {
        assert_eq!(normalize_technique_id("T1059"), "T1059");
        assert_eq!(normalize_technique_id("t1059"), "T1059");
        assert_eq!(normalize_technique_id("T1059.001"), "T1059.001");
        assert_eq!(normalize_technique_id("1059"), "T1059");
    }

    #[test]
    fn test_technique_base_id() {
        let tech = Technique {
            id: "T1059.001".to_string(),
            name: "PowerShell".to_string(),
            description: String::new(),
            tactics: vec![],
            detection: None,
            platforms: vec![],
            data_sources: vec![],
            is_subtechnique: true,
            parent_id: Some("T1059".to_string()),
            url: String::new(),
            references: vec![],
            mitigations: vec![],
            deprecated: false,
            revoked: false,
            cves: vec![],
        };

        assert_eq!(tech.base_id(), "T1059");
        assert!(tech.is_sub());
    }
}
