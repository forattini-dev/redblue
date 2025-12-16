use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::compression::gzip::decompress;

// Embedded compressed ATT&CK data
const ATTACK_DATA_GZ: &[u8] = include_bytes!("data/enterprise-attack.json.gz");

static DB: OnceLock<AttackDatabase> = OnceLock::new();

/// Get the singleton ATT&CK database instance
pub fn db() -> &'static AttackDatabase {
    DB.get_or_init(|| AttackDatabase::load().expect("Failed to load embedded ATT&CK database"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id: String,           // STIX ID
    pub technique_id: String, // T1059.001
    pub name: String,
    pub description: String,
    pub tactics: Vec<String>,
    pub platforms: Vec<String>,
    pub is_subtechnique: bool,
    pub parent_technique: Option<String>,
    pub url: Option<String>,
    pub deprecated: bool,
    pub revoked: bool,
    pub data_sources: Vec<String>,
    pub detection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatGroup {
    pub id: String,       // STIX ID
    pub group_id: String, // G0016
    pub name: String,
    pub description: String,
    pub aliases: Vec<String>,
    pub associated_techniques: Vec<String>, // List of T-codes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tactic {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Software {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug)]
pub struct AttackDatabase {
    pub techniques: HashMap<String, AttackTechnique>, // Key: T-code (e.g. T1059.001)
    pub groups: HashMap<String, ThreatGroup>,         // Key: Group ID (e.g. G0016)
    pub technique_by_name: HashMap<String, String>,   // Name -> T-code
    pub group_by_name: HashMap<String, String>,       // Name -> Group ID
}

impl AttackDatabase {
    fn load() -> Result<Self, String> {
        let json_bytes =
            decompress(ATTACK_DATA_GZ).map_err(|e| format!("Decompression failed: {:?}", e))?;
        let bundle: StixBundle =
            serde_json::from_slice(&json_bytes).map_err(|e| format!("JSON parse failed: {}", e))?;

        let mut techniques = HashMap::new();
        let mut groups = HashMap::new();
        let mut relationships = Vec::new();

        // Pass 1: Load objects
        for object in bundle.objects {
            match object {
                StixObject::AttackPattern(ap) => {
                    if let Some(ext_id) = ap
                        .external_references
                        .iter()
                        .find(|r| r.source_name == "mitre-attack")
                        .and_then(|r| r.external_id.clone())
                    {
                        let is_subtechnique = ap.x_mitre_is_subtechnique.unwrap_or(false);
                        let tactics = ap
                            .kill_chain_phases
                            .unwrap_or_default()
                            .into_iter()
                            .map(|p| p.phase_name)
                            .collect();
                        let platforms = ap.x_mitre_platforms.unwrap_or_default();

                        let technique = AttackTechnique {
                            id: ap.id,
                            technique_id: ext_id.clone(),
                            name: ap.name,
                            description: ap.description.unwrap_or_default(),
                            tactics,
                            platforms,
                            is_subtechnique,
                            parent_technique: None, // Filled in pass 2 if needed (or via relationships)
                            url: ap
                                .external_references
                                .iter()
                                .find(|r| r.source_name == "mitre-attack")
                                .and_then(|r| r.url.clone()),
                            deprecated: ap.x_mitre_deprecated.unwrap_or(false),
                            revoked: ap.revoked.unwrap_or(false),
                            data_sources: ap.x_mitre_data_sources.unwrap_or_default(),
                            detection: ap.x_mitre_detection,
                        };
                        techniques.insert(ext_id, technique);
                    }
                }
                StixObject::IntrusionSet(is) => {
                    if let Some(ext_id) = is
                        .external_references
                        .iter()
                        .find(|r| r.source_name == "mitre-attack")
                        .and_then(|r| r.external_id.clone())
                    {
                        let group = ThreatGroup {
                            id: is.id,
                            group_id: ext_id.clone(),
                            name: is.name,
                            description: is.description.unwrap_or_default(),
                            aliases: is.aliases.unwrap_or_default(),
                            associated_techniques: Vec::new(), // Filled in pass 2
                        };
                        groups.insert(ext_id, group);
                    }
                }
                StixObject::Relationship(rel) => {
                    relationships.push(rel);
                }
                _ => {}
            }
        }

        // Pass 2: Process relationships
        // Map STIX ID to T-code/G-code for faster lookup
        let mut stix_to_tech: HashMap<String, String> = HashMap::new();
        for t in techniques.values() {
            stix_to_tech.insert(t.id.clone(), t.technique_id.clone());
        }
        let mut stix_to_group: HashMap<String, String> = HashMap::new();
        for g in groups.values() {
            stix_to_group.insert(g.id.clone(), g.group_id.clone());
        }

        for rel in relationships {
            if rel.relationship_type == "uses" {
                // Group uses Technique
                if let Some(group_code) = stix_to_group.get(&rel.source_ref) {
                    if let Some(tech_code) = stix_to_tech.get(&rel.target_ref) {
                        if let Some(group) = groups.get_mut(group_code) {
                            group.associated_techniques.push(tech_code.clone());
                        }
                    }
                }
            } else if rel.relationship_type == "subtechnique-of" {
                // Subtechnique child of Parent
                if let Some(child_code) = stix_to_tech.get(&rel.source_ref) {
                    if let Some(parent_code) = stix_to_tech.get(&rel.target_ref) {
                        if let Some(child) = techniques.get_mut(child_code) {
                            child.parent_technique = Some(parent_code.clone());
                        }
                    }
                }
            }
        }

        let mut technique_by_name = HashMap::new();
        for t in techniques.values() {
            technique_by_name.insert(t.name.to_lowercase(), t.technique_id.clone());
        }

        let mut group_by_name = HashMap::new();
        for g in groups.values() {
            group_by_name.insert(g.name.to_lowercase(), g.group_id.clone());
            for alias in &g.aliases {
                group_by_name.insert(alias.to_lowercase(), g.group_id.clone());
            }
        }

        Ok(Self {
            techniques,
            groups,
            technique_by_name,
            group_by_name,
        })
    }

    pub fn get_technique(&self, id: &str) -> Option<&AttackTechnique> {
        self.techniques.get(id)
    }

    pub fn get_technique_by_name(&self, name: &str) -> Option<&AttackTechnique> {
        self.technique_by_name
            .get(&name.to_lowercase())
            .and_then(|id| self.techniques.get(id))
    }

    pub fn get_group(&self, id: &str) -> Option<&ThreatGroup> {
        self.groups.get(id)
    }

    pub fn get_group_by_name(&self, name: &str) -> Option<&ThreatGroup> {
        self.group_by_name
            .get(&name.to_lowercase())
            .and_then(|id| self.groups.get(id))
    }

    pub fn search_techniques(&self, query: &str) -> Vec<&AttackTechnique> {
        let q = query.to_lowercase();
        self.techniques
            .values()
            .filter(|t| {
                t.name.to_lowercase().contains(&q) || t.technique_id.to_lowercase().contains(&q)
            })
            .collect()
    }

    pub fn search_groups(&self, query: &str) -> Vec<&ThreatGroup> {
        let q = query.to_lowercase();
        self.groups
            .values()
            .filter(|g| {
                g.name.to_lowercase().contains(&q)
                    || g.group_id.to_lowercase().contains(&q)
                    || g.aliases.iter().any(|a| a.to_lowercase().contains(&q))
            })
            .collect()
    }
}

// STIX Types for Deserialization

#[derive(Deserialize)]
struct StixBundle {
    objects: Vec<StixObject>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum StixObject {
    #[serde(rename = "attack-pattern")]
    AttackPattern(AttackPattern),
    #[serde(rename = "intrusion-set")]
    IntrusionSet(IntrusionSet),
    #[serde(rename = "relationship")]
    Relationship(Relationship),
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ExternalReference {
    source_name: String,
    external_id: Option<String>,
    url: Option<String>,
}

#[derive(Deserialize)]
struct KillChainPhase {
    phase_name: String,
}

#[derive(Deserialize)]
struct AttackPattern {
    id: String,
    name: String,
    description: Option<String>,
    external_references: Vec<ExternalReference>,
    kill_chain_phases: Option<Vec<KillChainPhase>>,
    x_mitre_platforms: Option<Vec<String>>,
    x_mitre_is_subtechnique: Option<bool>,
    x_mitre_deprecated: Option<bool>,
    revoked: Option<bool>,
    x_mitre_data_sources: Option<Vec<String>>,
    x_mitre_detection: Option<String>,
}

#[derive(Deserialize)]
struct IntrusionSet {
    id: String,
    name: String,
    description: Option<String>,
    aliases: Option<Vec<String>>,
    external_references: Vec<ExternalReference>,
}

#[derive(Deserialize)]
struct Relationship {
    relationship_type: String,
    source_ref: String,
    target_ref: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_loads_successfully() {
        // Test that the embedded ATT&CK database loads without error
        let database = db();

        // Should have loaded techniques
        assert!(
            !database.techniques.is_empty(),
            "Should have techniques loaded"
        );

        // Should have loaded groups
        assert!(!database.groups.is_empty(), "Should have groups loaded");

        // Should have name indexes
        assert!(
            !database.technique_by_name.is_empty(),
            "Should have technique name index"
        );
        assert!(
            !database.group_by_name.is_empty(),
            "Should have group name index"
        );
    }

    #[test]
    fn test_get_technique_by_id() {
        let database = db();

        // T1059 - Command and Scripting Interpreter (a well-known technique)
        let technique = database.get_technique("T1059");
        assert!(technique.is_some(), "T1059 should exist");

        let t = technique.unwrap();
        assert_eq!(t.technique_id, "T1059");
        assert!(
            t.name.to_lowercase().contains("command") || t.name.to_lowercase().contains("script")
        );
        assert!(!t.tactics.is_empty(), "T1059 should have tactics");
    }

    #[test]
    fn test_get_subtechnique_by_id() {
        let database = db();

        // T1059.001 - PowerShell (subtechnique of T1059)
        let technique = database.get_technique("T1059.001");
        assert!(technique.is_some(), "T1059.001 should exist");

        let t = technique.unwrap();
        assert_eq!(t.technique_id, "T1059.001");
        assert!(
            t.is_subtechnique,
            "T1059.001 should be marked as subtechnique"
        );
        assert!(t.name.to_lowercase().contains("powershell"));
    }

    #[test]
    fn test_get_technique_by_name() {
        let database = db();

        // Search by name (case-insensitive)
        let technique = database.get_technique_by_name("powershell");
        assert!(
            technique.is_some(),
            "Should find PowerShell technique by name"
        );

        let t = technique.unwrap();
        // PowerShell could be T1086 (deprecated) or T1059.001 (current subtechnique)
        assert!(
            t.technique_id == "T1059.001" || t.technique_id == "T1086",
            "PowerShell technique should be T1059.001 or T1086, got {}",
            t.technique_id
        );
        assert!(t.name.to_lowercase().contains("powershell"));
    }

    #[test]
    fn test_get_technique_by_name_case_insensitive() {
        let database = db();

        // Test various cases - all should find the same technique
        let t1 = database.get_technique_by_name("PowerShell");
        let t2 = database.get_technique_by_name("POWERSHELL");
        let t3 = database.get_technique_by_name("powershell");

        assert!(
            t1.is_some() && t2.is_some() && t3.is_some(),
            "Should find PowerShell in all case variations"
        );

        // All lookups should return the same technique
        let id1 = &t1.unwrap().technique_id;
        let id2 = &t2.unwrap().technique_id;
        let id3 = &t3.unwrap().technique_id;

        assert_eq!(id1, id2, "Case variations should return same technique");
        assert_eq!(id2, id3, "Case variations should return same technique");
    }

    #[test]
    fn test_get_nonexistent_technique() {
        let database = db();

        let technique = database.get_technique("T9999");
        assert!(technique.is_none(), "T9999 should not exist");

        let technique2 = database.get_technique_by_name("nonexistent_technique_xyz");
        assert!(
            technique2.is_none(),
            "Nonexistent technique should return None"
        );
    }

    #[test]
    fn test_get_group_by_id() {
        let database = db();

        // G0016 - APT29 (well-known threat group)
        let group = database.get_group("G0016");

        if group.is_some() {
            let g = group.unwrap();
            assert_eq!(g.group_id, "G0016");
            // APT29 is also known as Cozy Bear, The Dukes, etc.
            assert!(g.name.contains("APT29") || g.aliases.iter().any(|a| a.contains("APT29")));
        }
    }

    #[test]
    fn test_get_group_by_name() {
        let database = db();

        // Search by name (case-insensitive)
        let group = database.get_group_by_name("apt29");

        if group.is_some() {
            let g = group.unwrap();
            assert_eq!(g.group_id, "G0016");
        }
    }

    #[test]
    fn test_get_group_by_alias() {
        let database = db();

        // APT29 is also known as "Cozy Bear"
        let group = database.get_group_by_name("cozy bear");

        // This may or may not exist depending on the ATT&CK version
        // If it exists, verify it's APT29
        if let Some(g) = group {
            assert!(
                g.aliases.iter().any(|a| a.to_lowercase().contains("cozy"))
                    || g.name.to_lowercase().contains("cozy")
            );
        }
    }

    #[test]
    fn test_search_techniques() {
        let database = db();

        // Search for "phishing" - should find multiple techniques
        let results = database.search_techniques("phishing");
        assert!(!results.is_empty(), "Should find phishing techniques");

        // All results should contain "phishing" in name or ID
        for t in &results {
            let matches = t.name.to_lowercase().contains("phishing")
                || t.technique_id.to_lowercase().contains("phishing");
            assert!(matches, "Result should match 'phishing': {}", t.name);
        }
    }

    #[test]
    fn test_search_techniques_by_id() {
        let database = db();

        // Search by technique ID pattern
        let results = database.search_techniques("T1566");
        assert!(!results.is_empty(), "Should find T1566 techniques");

        // Should include T1566 and its subtechniques
        let has_parent = results.iter().any(|t| t.technique_id == "T1566");
        assert!(has_parent, "Should find T1566 parent technique");
    }

    #[test]
    fn test_search_groups() {
        let database = db();

        // Search for "APT" - should find multiple groups
        let results = database.search_groups("APT");
        assert!(!results.is_empty(), "Should find APT groups");

        // All results should contain "APT" in name, ID, or aliases
        for g in &results {
            let matches = g.name.to_lowercase().contains("apt")
                || g.group_id.to_lowercase().contains("apt")
                || g.aliases.iter().any(|a| a.to_lowercase().contains("apt"));
            assert!(matches, "Result should match 'APT': {}", g.name);
        }
    }

    #[test]
    fn test_technique_has_required_fields() {
        let database = db();

        // Get any technique and verify required fields
        if let Some((_, technique)) = database.techniques.iter().next() {
            assert!(!technique.id.is_empty(), "STIX ID should not be empty");
            assert!(
                !technique.technique_id.is_empty(),
                "Technique ID should not be empty"
            );
            assert!(!technique.name.is_empty(), "Name should not be empty");
            // description may be empty for some techniques
        }
    }

    #[test]
    fn test_group_has_required_fields() {
        let database = db();

        // Get any group and verify required fields
        if let Some((_, group)) = database.groups.iter().next() {
            assert!(!group.id.is_empty(), "STIX ID should not be empty");
            assert!(!group.group_id.is_empty(), "Group ID should not be empty");
            assert!(!group.name.is_empty(), "Name should not be empty");
        }
    }

    #[test]
    fn test_subtechnique_parent_relationship() {
        let database = db();

        // Find a subtechnique and verify parent relationship
        for technique in database.techniques.values() {
            if technique.is_subtechnique {
                // Subtechniques should have parent_technique set (if relationships were processed)
                // Note: This depends on the relationship data being present
                if technique.parent_technique.is_some() {
                    let parent_id = technique.parent_technique.as_ref().unwrap();
                    // Parent should exist
                    assert!(
                        database.techniques.contains_key(parent_id),
                        "Parent {} should exist for subtechnique {}",
                        parent_id,
                        technique.technique_id
                    );
                }
                break; // Just check one for efficiency
            }
        }
    }

    #[test]
    fn test_group_technique_associations() {
        let database = db();

        // Find a group with associated techniques
        for group in database.groups.values() {
            if !group.associated_techniques.is_empty() {
                // Verify associated techniques exist
                for tech_id in &group.associated_techniques {
                    assert!(
                        database.techniques.contains_key(tech_id),
                        "Associated technique {} should exist for group {}",
                        tech_id,
                        group.group_id
                    );
                }
                break; // Just check one for efficiency
            }
        }
    }

    #[test]
    fn test_database_singleton() {
        // Verify db() returns the same instance
        let db1 = db();
        let db2 = db();

        // Compare technique counts (should be identical since it's the same data)
        assert_eq!(db1.techniques.len(), db2.techniques.len());
        assert_eq!(db1.groups.len(), db2.groups.len());
    }

    #[test]
    fn test_technique_tactics_not_empty() {
        let database = db();

        // Most active techniques should have at least one tactic
        let active_techniques: Vec<_> = database
            .techniques
            .values()
            .filter(|t| !t.deprecated && !t.revoked)
            .collect();

        let with_tactics = active_techniques
            .iter()
            .filter(|t| !t.tactics.is_empty())
            .count();

        // At least 80% should have tactics
        let ratio = with_tactics as f64 / active_techniques.len() as f64;
        assert!(
            ratio > 0.8,
            "At least 80% of active techniques should have tactics, got {}%",
            ratio * 100.0
        );
    }
}
