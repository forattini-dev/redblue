//! MITRE ATT&CK client for fetching and parsing STIX data
//!
//! Fetches ATT&CK data from MITRE's GitHub repository (STIX 2.1 format).
//! Uses simple JSON parsing instead of full STIX library.

use super::types::*;
use crate::protocols::http::HttpClient;
use std::collections::HashMap;
use std::time::Duration;

/// Base URL for MITRE ATT&CK STIX data on GitHub
const ATTACK_ENTERPRISE_URL: &str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
const ATTACK_MOBILE_URL: &str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json";
const ATTACK_ICS_URL: &str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json";

/// MITRE ATT&CK client
pub struct MitreClient {
    http: HttpClient,
    cache: Option<AttackData>,
    matrix: AttackMatrix,
}

impl MitreClient {
    /// Create a new MITRE client for Enterprise ATT&CK
    pub fn new() -> Self {
        Self {
            // ATT&CK STIX data is ~40MB, so we need a higher response limit
            http: HttpClient::new()
                .with_timeout(Duration::from_secs(120))
                .with_max_response_bytes(50_000_000), // 50MB limit for STIX data
            cache: None,
            matrix: AttackMatrix::Enterprise,
        }
    }

    /// Set the matrix to fetch (Enterprise, Mobile, ICS)
    pub fn with_matrix(mut self, matrix: AttackMatrix) -> Self {
        self.matrix = matrix;
        self.cache = None; // Clear cache when changing matrix
        self
    }

    /// Get the URL for the current matrix
    fn get_url(&self) -> &'static str {
        match self.matrix {
            AttackMatrix::Enterprise => ATTACK_ENTERPRISE_URL,
            AttackMatrix::Mobile => ATTACK_MOBILE_URL,
            AttackMatrix::Ics => ATTACK_ICS_URL,
        }
    }

    /// Fetch and parse ATT&CK data
    pub fn fetch(&mut self) -> Result<&AttackData, String> {
        if self.cache.is_some() {
            return Ok(self.cache.as_ref().unwrap());
        }

        let url = self.get_url();
        let response = self.http.get(url)?;

        if response.status_code != 200 {
            return Err(format!(
                "Failed to fetch ATT&CK data: HTTP {}",
                response.status_code
            ));
        }

        let body = String::from_utf8_lossy(&response.body);
        let data = self.parse_stix_bundle(&body)?;
        self.cache = Some(data);

        Ok(self.cache.as_ref().unwrap())
    }

    /// Parse STIX 2.1 bundle JSON into AttackData
    fn parse_stix_bundle(&self, json: &str) -> Result<AttackData, String> {
        let mut data = AttackData::new();

        // Simple JSON parsing - find "objects" array
        let objects_start = json
            .find("\"objects\"")
            .and_then(|pos| json[pos..].find('[').map(|p| pos + p))
            .ok_or("Invalid STIX bundle: no objects array")?;

        // Parse each object in the array
        let objects_json = &json[objects_start..];
        let mut depth = 0;
        let mut obj_start = 0;
        let mut in_string = false;
        let mut escape_next = false;

        for (i, c) in objects_json.char_indices() {
            if escape_next {
                escape_next = false;
                continue;
            }

            match c {
                '\\' if in_string => escape_next = true,
                '"' => in_string = !in_string,
                '[' | '{' if !in_string => {
                    if depth == 1 && c == '{' {
                        obj_start = i;
                    }
                    depth += 1;
                }
                ']' | '}' if !in_string => {
                    depth -= 1;
                    if depth == 1 && c == '}' {
                        // Found complete object
                        let obj_json = &objects_json[obj_start..=i];
                        self.parse_stix_object(obj_json, &mut data);
                    }
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }

        // Build indexes
        self.build_indexes(&mut data);

        Ok(data)
    }

    /// Parse a single STIX object
    fn parse_stix_object(&self, json: &str, data: &mut AttackData) {
        let obj_type = extract_string(json, "type");

        match obj_type.as_deref() {
            Some("attack-pattern") => {
                if let Some(tech) = self.parse_technique(json) {
                    data.techniques.insert(tech.id.clone(), tech);
                }
            }
            Some("x-mitre-tactic") => {
                if let Some(tactic) = self.parse_tactic(json) {
                    data.tactics.insert(tactic.id.clone(), tactic);
                }
            }
            Some("intrusion-set") => {
                if let Some(group) = self.parse_group(json) {
                    data.groups.insert(group.id.clone(), group);
                }
            }
            Some("malware") | Some("tool") => {
                if let Some(sw) = self.parse_software(json, obj_type.as_ref().unwrap()) {
                    data.software.insert(sw.id.clone(), sw);
                }
            }
            Some("course-of-action") => {
                if let Some(mit) = self.parse_mitigation(json) {
                    data.mitigations.insert(mit.id.clone(), mit);
                }
            }
            Some("relationship") => {
                self.parse_relationship(json, data);
            }
            _ => {}
        }
    }

    /// Parse a technique from STIX attack-pattern
    fn parse_technique(&self, json: &str) -> Option<Technique> {
        let external_refs = extract_external_references(json);
        let mitre_ref = external_refs.iter().find(|r| r.source == "mitre-attack")?;

        let id = mitre_ref.external_id.clone()?;

        // Skip if deprecated or revoked
        let deprecated = extract_bool(json, "x_mitre_deprecated").unwrap_or(false);
        let revoked = extract_bool(json, "revoked").unwrap_or(false);

        let name = extract_string(json, "name")?;
        let description = extract_string(json, "description").unwrap_or_default();
        let detection = extract_string(json, "x_mitre_detection");

        let platforms = extract_string_array(json, "x_mitre_platforms");
        let data_sources = extract_string_array(json, "x_mitre_data_sources");

        let is_subtechnique = extract_bool(json, "x_mitre_is_subtechnique").unwrap_or(false);

        // Extract kill chain phases (tactics)
        let tactics = extract_kill_chain_phases(json);

        // Get URL from external references
        let url = mitre_ref.url.clone().unwrap_or_else(|| {
            format!(
                "https://attack.mitre.org/techniques/{}/",
                id.replace('.', "/")
            )
        });

        // Extract CVEs from references
        let cves = external_refs
            .iter()
            .filter_map(|r| r.external_id.as_ref())
            .filter(|id| id.starts_with("CVE-"))
            .cloned()
            .collect();

        Some(Technique {
            id: id.clone(),
            name,
            description,
            tactics,
            detection,
            platforms,
            data_sources,
            is_subtechnique,
            parent_id: if is_subtechnique {
                Some(id.split('.').next().unwrap_or(&id).to_string())
            } else {
                None
            },
            url,
            references: external_refs,
            mitigations: Vec::new(), // Populated from relationships
            deprecated,
            revoked,
            cves,
        })
    }

    /// Parse a tactic from STIX x-mitre-tactic
    fn parse_tactic(&self, json: &str) -> Option<Tactic> {
        let external_refs = extract_external_references(json);
        let mitre_ref = external_refs.iter().find(|r| r.source == "mitre-attack")?;

        let id = mitre_ref.external_id.clone()?;
        let name = extract_string(json, "name")?;
        let description = extract_string(json, "description").unwrap_or_default();
        let short_name = extract_string(json, "x_mitre_shortname")
            .unwrap_or_else(|| name.to_lowercase().replace(' ', "-"));

        Some(Tactic {
            id,
            name,
            short_name,
            description,
            references: external_refs,
            matrix: self.matrix,
        })
    }

    /// Parse a threat group from STIX intrusion-set
    fn parse_group(&self, json: &str) -> Option<ThreatGroup> {
        let external_refs = extract_external_references(json);
        let mitre_ref = external_refs.iter().find(|r| r.source == "mitre-attack")?;

        let id = mitre_ref.external_id.clone()?;
        let name = extract_string(json, "name")?;
        let description = extract_string(json, "description").unwrap_or_default();
        let aliases = extract_string_array(json, "aliases");
        let deprecated = extract_bool(json, "x_mitre_deprecated").unwrap_or(false);

        Some(ThreatGroup {
            id,
            name,
            aliases,
            description,
            techniques: Vec::new(), // Populated from relationships
            software: Vec::new(),   // Populated from relationships
            references: external_refs,
            deprecated,
        })
    }

    /// Parse software (malware or tool) from STIX
    fn parse_software(&self, json: &str, obj_type: &str) -> Option<Software> {
        let external_refs = extract_external_references(json);
        let mitre_ref = external_refs.iter().find(|r| r.source == "mitre-attack")?;

        let id = mitre_ref.external_id.clone()?;
        let name = extract_string(json, "name")?;
        let description = extract_string(json, "description").unwrap_or_default();
        let platforms = extract_string_array(json, "x_mitre_platforms");
        let aliases = extract_string_array(json, "x_mitre_aliases");
        let deprecated = extract_bool(json, "x_mitre_deprecated").unwrap_or(false);

        let software_type = if obj_type == "malware" {
            SoftwareType::Malware
        } else {
            SoftwareType::Tool
        };

        Some(Software {
            id,
            name,
            software_type,
            description,
            platforms,
            techniques: Vec::new(), // Populated from relationships
            aliases,
            references: external_refs,
            deprecated,
        })
    }

    /// Parse a mitigation from STIX course-of-action
    fn parse_mitigation(&self, json: &str) -> Option<Mitigation> {
        let external_refs = extract_external_references(json);
        let mitre_ref = external_refs.iter().find(|r| r.source == "mitre-attack")?;

        let id = mitre_ref.external_id.clone()?;

        // Skip non-mitigation course-of-actions
        if !id.starts_with('M') {
            return None;
        }

        let name = extract_string(json, "name")?;
        let description = extract_string(json, "description").unwrap_or_default();
        let deprecated = extract_bool(json, "x_mitre_deprecated").unwrap_or(false);

        Some(Mitigation {
            id,
            name,
            description,
            techniques: Vec::new(), // Populated from relationships
            references: external_refs,
            deprecated,
        })
    }

    /// Parse a relationship and update data indexes
    fn parse_relationship(&self, json: &str, data: &mut AttackData) {
        let rel_type = match extract_string(json, "relationship_type") {
            Some(t) => t,
            None => return,
        };

        let source_ref = match extract_string(json, "source_ref") {
            Some(r) => r,
            None => return,
        };

        let target_ref = match extract_string(json, "target_ref") {
            Some(r) => r,
            None => return,
        };

        // Extract IDs from STIX refs (e.g., "attack-pattern--xxx" -> technique ID)
        let source_id = self.stix_ref_to_id(&source_ref, data);
        let target_id = self.stix_ref_to_id(&target_ref, data);

        if source_id.is_none() || target_id.is_none() {
            return;
        }

        let source_id = source_id.unwrap();
        let target_id = target_id.unwrap();

        match rel_type.as_str() {
            "uses" => {
                // Group uses technique, or software uses technique
                if source_id.starts_with('G') && target_id.starts_with('T') {
                    data.group_techniques
                        .entry(source_id.clone())
                        .or_default()
                        .push(target_id.clone());
                    data.technique_groups
                        .entry(target_id)
                        .or_default()
                        .push(source_id);
                } else if source_id.starts_with('S') && target_id.starts_with('T') {
                    data.software_techniques
                        .entry(source_id.clone())
                        .or_default()
                        .push(target_id.clone());
                    data.technique_software
                        .entry(target_id)
                        .or_default()
                        .push(source_id);
                }
            }
            "mitigates" => {
                // Mitigation mitigates technique
                if source_id.starts_with('M') && target_id.starts_with('T') {
                    data.technique_mitigations
                        .entry(target_id)
                        .or_default()
                        .push(source_id);
                }
            }
            _ => {}
        }
    }

    /// Convert STIX ref to ATT&CK ID
    fn stix_ref_to_id(&self, stix_ref: &str, data: &AttackData) -> Option<String> {
        // STIX refs are like "attack-pattern--uuid" or "intrusion-set--uuid"
        // We need to look up the actual ATT&CK ID

        // For now, we'll store a mapping during parsing
        // This is a simplified approach - in production we'd build a proper index

        // Try to find by matching the UUID portion
        let uuid = stix_ref.split("--").last()?;

        // Check techniques
        for (id, tech) in &data.techniques {
            if stix_ref.contains("attack-pattern") {
                // Match by comparing with stored STIX ID if available
                // For simplicity, we use pattern matching on the ref
                if id.starts_with('T') {
                    // This is a simplified lookup - in reality we'd index by STIX ID
                    return Some(id.clone());
                }
            }
        }

        // Check groups
        for (id, _) in &data.groups {
            if stix_ref.contains("intrusion-set") && id.starts_with('G') {
                return Some(id.clone());
            }
        }

        // Check software
        for (id, _) in &data.software {
            if (stix_ref.contains("malware") || stix_ref.contains("tool")) && id.starts_with('S') {
                return Some(id.clone());
            }
        }

        // Check mitigations
        for (id, _) in &data.mitigations {
            if stix_ref.contains("course-of-action") && id.starts_with('M') {
                return Some(id.clone());
            }
        }

        None
    }

    /// Build indexes after parsing all objects
    fn build_indexes(&self, data: &mut AttackData) {
        // Build technique -> tactic mapping
        for (id, tech) in &data.techniques {
            for tactic_name in &tech.tactics {
                // Find tactic ID by short name
                if let Some(tactic) = data.tactics.values().find(|t| {
                    t.short_name == *tactic_name
                        || t.name.to_lowercase().replace(' ', "-") == *tactic_name
                }) {
                    data.technique_tactics
                        .entry(id.clone())
                        .or_default()
                        .push(tactic.id.clone());
                    data.tactic_techniques
                        .entry(tactic.id.clone())
                        .or_default()
                        .push(id.clone());
                }
            }
        }
    }

    /// Get technique by ID
    pub fn get_technique(&mut self, id: &str) -> Result<Option<&Technique>, String> {
        self.fetch()?;
        Ok(self.cache.as_ref().unwrap().get_technique(id))
    }

    /// Get tactic by ID
    pub fn get_tactic(&mut self, id: &str) -> Result<Option<&Tactic>, String> {
        self.fetch()?;
        Ok(self.cache.as_ref().unwrap().get_tactic(id))
    }

    /// Get group by ID or name
    pub fn get_group(&mut self, id_or_name: &str) -> Result<Option<&ThreatGroup>, String> {
        self.fetch()?;
        Ok(self.cache.as_ref().unwrap().get_group(id_or_name))
    }

    /// Get software by ID or name
    pub fn get_software(&mut self, id_or_name: &str) -> Result<Option<&Software>, String> {
        self.fetch()?;
        Ok(self.cache.as_ref().unwrap().get_software(id_or_name))
    }

    /// Search across all ATT&CK objects
    pub fn search(&mut self, query: &str) -> Result<Vec<AttackObject>, String> {
        self.fetch()?;
        Ok(self.cache.as_ref().unwrap().search(query))
    }

    /// Get techniques for a tactic
    pub fn techniques_for_tactic(&mut self, tactic_id: &str) -> Result<Vec<Technique>, String> {
        self.fetch()?;
        Ok(self
            .cache
            .as_ref()
            .unwrap()
            .techniques_for_tactic(tactic_id)
            .into_iter()
            .cloned()
            .collect())
    }

    /// Get groups using a technique
    pub fn groups_for_technique(&mut self, technique_id: &str) -> Result<Vec<ThreatGroup>, String> {
        self.fetch()?;
        Ok(self
            .cache
            .as_ref()
            .unwrap()
            .groups_for_technique(technique_id)
            .into_iter()
            .cloned()
            .collect())
    }

    /// Get mitigations for a technique
    pub fn mitigations_for_technique(
        &mut self,
        technique_id: &str,
    ) -> Result<Vec<Mitigation>, String> {
        self.fetch()?;
        Ok(self
            .cache
            .as_ref()
            .unwrap()
            .mitigations_for_technique(technique_id)
            .into_iter()
            .cloned()
            .collect())
    }

    /// Get all tactics in kill chain order
    pub fn all_tactics(&mut self) -> Result<Vec<Tactic>, String> {
        self.fetch()?;
        Ok(self
            .cache
            .as_ref()
            .unwrap()
            .all_tactics()
            .into_iter()
            .cloned()
            .collect())
    }

    /// Get statistics about loaded data
    pub fn stats(&mut self) -> Result<AttackStats, String> {
        self.fetch()?;
        Ok(self.cache.as_ref().unwrap().stats())
    }
}

impl Default for MitreClient {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions for JSON parsing without external dependencies

/// Extract a string value from JSON
fn extract_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let key_pos = json.find(&pattern)?;
    let after_key = &json[key_pos + pattern.len()..];

    // Skip whitespace and colon
    let colon_pos = after_key.find(':')?;
    let after_colon = &after_key[colon_pos + 1..];
    let trimmed = after_colon.trim_start();

    if !trimmed.starts_with('"') {
        return None;
    }

    // Find end of string value
    let value_start = 1;
    let mut value_end = value_start;
    let chars: Vec<char> = trimmed.chars().collect();
    let mut escape_next = false;

    for i in value_start..chars.len() {
        if escape_next {
            escape_next = false;
            value_end = i + 1;
            continue;
        }
        match chars[i] {
            '\\' => {
                escape_next = true;
                value_end = i + 1;
            }
            '"' => {
                return Some(
                    trimmed[value_start..i]
                        .replace("\\n", "\n")
                        .replace("\\\"", "\""),
                );
            }
            _ => value_end = i + 1,
        }
    }

    None
}

/// Extract a boolean value from JSON
fn extract_bool(json: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\"", key);
    let key_pos = json.find(&pattern)?;
    let after_key = &json[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Extract an array of strings from JSON
fn extract_string_array(json: &str, key: &str) -> Vec<String> {
    let pattern = format!("\"{}\"", key);
    let key_pos = match json.find(&pattern) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let after_key = &json[key_pos + pattern.len()..];
    let colon_pos = match after_key.find(':') {
        Some(p) => p,
        None => return Vec::new(),
    };

    let after_colon = after_key[colon_pos + 1..].trim_start();
    if !after_colon.starts_with('[') {
        return Vec::new();
    }

    // Find matching bracket
    let mut depth = 0;
    let mut array_end = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, c) in after_colon.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match c {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '[' if !in_string => depth += 1,
            ']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    array_end = i;
                    break;
                }
            }
            _ => {}
        }
    }

    if array_end == 0 {
        return Vec::new();
    }

    let array_content = &after_colon[1..array_end];
    let mut result = Vec::new();

    // Parse array items
    let mut current = String::new();
    let mut in_string = false;
    let mut escape_next = false;

    for c in array_content.chars() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }
        match c {
            '\\' if in_string => {
                escape_next = true;
            }
            '"' => {
                if in_string {
                    result.push(current.clone());
                    current.clear();
                }
                in_string = !in_string;
            }
            _ if in_string => current.push(c),
            _ => {}
        }
    }

    result
}

/// Extract kill chain phases (tactics) from STIX object
fn extract_kill_chain_phases(json: &str) -> Vec<String> {
    let mut phases = Vec::new();

    // Find kill_chain_phases array
    let pattern = "\"kill_chain_phases\"";
    let key_pos = match json.find(pattern) {
        Some(p) => p,
        None => return phases,
    };

    let after_key = &json[key_pos + pattern.len()..];
    let array_start = match after_key.find('[') {
        Some(p) => p,
        None => return phases,
    };

    // Find all phase_name values
    let array_json = &after_key[array_start..];
    let mut pos = 0;
    while let Some(phase_pos) = array_json[pos..].find("\"phase_name\"") {
        let abs_pos = pos + phase_pos;
        if let Some(phase_name) = extract_string(&array_json[abs_pos..], "phase_name") {
            phases.push(phase_name);
        }
        pos = abs_pos + 12; // Move past "phase_name"
    }

    phases
}

/// Extract external references from STIX object
fn extract_external_references(json: &str) -> Vec<ExternalRef> {
    let mut refs = Vec::new();

    // Find external_references array
    let pattern = "\"external_references\"";
    let key_pos = match json.find(pattern) {
        Some(p) => p,
        None => return refs,
    };

    let after_key = &json[key_pos + pattern.len()..];
    let array_start = match after_key.find('[') {
        Some(p) => p,
        None => return refs,
    };

    // Parse each reference object
    let array_json = &after_key[array_start..];
    let mut depth = 0;
    let mut obj_start = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, c) in array_json.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match c {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '[' | '{' if !in_string => {
                if depth == 1 && c == '{' {
                    obj_start = i;
                }
                depth += 1;
            }
            ']' | '}' if !in_string => {
                depth -= 1;
                if depth == 1 && c == '}' {
                    let obj_json = &array_json[obj_start..=i];
                    if let Some(ext_ref) = parse_external_ref(obj_json) {
                        refs.push(ext_ref);
                    }
                }
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }

    refs
}

/// Parse a single external reference object
fn parse_external_ref(json: &str) -> Option<ExternalRef> {
    let source = extract_string(json, "source_name")?;
    let external_id = extract_string(json, "external_id");
    let url = extract_string(json, "url");
    let description = extract_string(json, "description");

    Some(ExternalRef {
        source,
        external_id,
        url,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_string() {
        let json = r#"{"name": "Test Name", "other": 123}"#;
        assert_eq!(extract_string(json, "name"), Some("Test Name".to_string()));
        assert_eq!(extract_string(json, "missing"), None);
    }

    #[test]
    fn test_extract_bool() {
        let json = r#"{"active": true, "deprecated": false}"#;
        assert_eq!(extract_bool(json, "active"), Some(true));
        assert_eq!(extract_bool(json, "deprecated"), Some(false));
        assert_eq!(extract_bool(json, "missing"), None);
    }

    #[test]
    fn test_extract_string_array() {
        let json = r#"{"platforms": ["Windows", "Linux", "macOS"]}"#;
        let result = extract_string_array(json, "platforms");
        assert_eq!(result, vec!["Windows", "Linux", "macOS"]);
    }
}
