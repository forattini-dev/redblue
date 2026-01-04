//! MITRE ATT&CK Finding Correlation Engine
//!
//! Maps security findings (tool outputs, observations, IOCs) to MITRE ATT&CK techniques.
//!
//! ## Correlation Methods
//!
//! 1. **Tool Matching**: Maps known tool names (mimikatz, cobalt strike) to techniques
//! 2. **Keyword Matching**: Matches finding text against technique keywords
//! 3. **IOC Matching**: Correlates indicators (file paths, registry keys) to techniques
//! 4. **CVE Mapping**: Links CVE IDs to techniques that exploit them
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use redblue::modules::recon::mitre::{CorrelationEngine, MitreClient};
//!
//! let mut client = MitreClient::new();
//! let data = client.fetch()?;
//! let engine = CorrelationEngine::new(data);
//!
//! // Correlate a finding
//! let results = engine.correlate("Detected mimikatz.exe execution");
//! for result in results {
//!     println!("{}: {} (confidence: {}%)",
//!         result.technique_id, result.technique_name, result.confidence);
//! }
//! ```

use super::types::{AttackData, Technique};
use std::collections::HashMap;

/// Correlation engine for mapping findings to MITRE techniques
pub struct CorrelationEngine<'a> {
    /// Reference to ATT&CK data
    attack_data: &'a AttackData,
    /// Tool name to technique mappings
    tool_mappings: HashMap<String, Vec<ToolMapping>>,
    /// Keyword to technique mappings
    keyword_mappings: HashMap<String, Vec<KeywordMapping>>,
    /// Custom user-defined mappings
    custom_mappings: Vec<CustomMapping>,
}

/// Tool name to technique mapping
#[derive(Debug, Clone)]
struct ToolMapping {
    technique_id: String,
    confidence: u8,
    description: String,
}

/// Keyword to technique mapping
#[derive(Debug, Clone)]
struct KeywordMapping {
    technique_id: String,
    confidence: u8,
    context: String,
}

/// Custom user-defined mapping
#[derive(Debug, Clone)]
pub struct CustomMapping {
    /// Pattern to match (case-insensitive)
    pub pattern: String,
    /// Target technique ID
    pub technique_id: String,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Description of why this maps
    pub reason: String,
}

/// Result of correlating a finding
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    /// Original finding text
    pub finding: String,
    /// Matched techniques
    pub matches: Vec<FindingMatch>,
}

/// A matched technique for a finding
#[derive(Debug, Clone)]
pub struct FindingMatch {
    /// Technique ID
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// How the match was made
    pub match_type: MatchType,
    /// Reason for the match
    pub reason: String,
    /// Associated tactics
    pub tactics: Vec<String>,
}

/// Type of match that was made
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    /// Matched by tool name
    ToolName,
    /// Matched by keyword
    Keyword,
    /// Matched by CVE
    Cve,
    /// Matched by IOC pattern
    Ioc,
    /// Matched by custom rule
    Custom,
    /// Matched by technique name/description search
    TextSearch,
}

impl MatchType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchType::ToolName => "tool",
            MatchType::Keyword => "keyword",
            MatchType::Cve => "cve",
            MatchType::Ioc => "ioc",
            MatchType::Custom => "custom",
            MatchType::TextSearch => "search",
        }
    }
}

impl<'a> CorrelationEngine<'a> {
    /// Create a new correlation engine
    pub fn new(attack_data: &'a AttackData) -> Self {
        let mut engine = Self {
            attack_data,
            tool_mappings: HashMap::new(),
            keyword_mappings: HashMap::new(),
            custom_mappings: Vec::new(),
        };
        engine.init_builtin_mappings();
        engine
    }

    /// Initialize built-in tool and keyword mappings
    fn init_builtin_mappings(&mut self) {
        // Common offensive tools mapped to MITRE techniques
        self.add_tool_mapping("mimikatz", "T1003", 95, "Credential dumping tool");
        self.add_tool_mapping(
            "mimikatz",
            "T1003.001",
            95,
            "LSASS memory credential extraction",
        );
        self.add_tool_mapping("mimikatz", "T1558.003", 90, "Kerberoasting capability");
        self.add_tool_mapping("mimikatz", "T1550.002", 85, "Pass-the-hash capability");

        self.add_tool_mapping("cobalt strike", "T1071.001", 90, "HTTP-based C2");
        self.add_tool_mapping("cobalt strike", "T1055", 90, "Process injection");
        self.add_tool_mapping("cobalt strike", "T1059.001", 85, "PowerShell execution");
        self.add_tool_mapping("cobaltstrike", "T1071.001", 90, "HTTP-based C2");
        self.add_tool_mapping("beacon", "T1071.001", 80, "Cobalt Strike beacon");

        self.add_tool_mapping("psexec", "T1569.002", 90, "Remote service execution");
        self.add_tool_mapping("psexec", "T1021.002", 85, "SMB-based lateral movement");

        self.add_tool_mapping("rubeus", "T1558.003", 95, "Kerberoasting");
        self.add_tool_mapping("rubeus", "T1558.004", 95, "AS-REP Roasting");
        self.add_tool_mapping("rubeus", "T1550.003", 90, "Pass-the-ticket");

        self.add_tool_mapping("bloodhound", "T1087.002", 85, "AD user enumeration");
        self.add_tool_mapping("bloodhound", "T1069.002", 85, "Domain group discovery");
        self.add_tool_mapping("sharphound", "T1087.002", 85, "BloodHound collector");

        self.add_tool_mapping("lazagne", "T1555", 90, "Credential extraction");
        self.add_tool_mapping("lazagne", "T1555.003", 90, "Browser credential theft");

        self.add_tool_mapping("impacket", "T1021.002", 85, "SMB tools");
        self.add_tool_mapping("wmiexec", "T1047", 90, "WMI execution");
        self.add_tool_mapping("smbexec", "T1021.002", 90, "SMB execution");
        self.add_tool_mapping("atexec", "T1053.002", 90, "Scheduled task execution");
        self.add_tool_mapping("secretsdump", "T1003.003", 95, "NTDS.dit extraction");

        self.add_tool_mapping("nmap", "T1046", 70, "Network scanning");
        self.add_tool_mapping("masscan", "T1046", 70, "Port scanning");

        self.add_tool_mapping("metasploit", "T1059", 80, "Exploit framework");
        self.add_tool_mapping("meterpreter", "T1055", 85, "Process injection shell");

        self.add_tool_mapping("hashcat", "T1110.002", 85, "Password cracking");
        self.add_tool_mapping("john", "T1110.002", 85, "Password cracking");

        // Keyword mappings for common attack patterns
        self.add_keyword_mapping("powershell", "T1059.001", 70, "PowerShell execution");
        self.add_keyword_mapping("powershell -enc", "T1059.001", 85, "Encoded PowerShell");
        self.add_keyword_mapping(
            "powershell -encodedcommand",
            "T1059.001",
            85,
            "Encoded PowerShell",
        );
        self.add_keyword_mapping("invoke-expression", "T1059.001", 80, "PowerShell IEX");
        self.add_keyword_mapping("invoke-mimikatz", "T1003", 95, "PowerShell Mimikatz");

        self.add_keyword_mapping("cmd.exe", "T1059.003", 60, "Windows command shell");
        self.add_keyword_mapping("wscript", "T1059.005", 70, "VBScript execution");
        self.add_keyword_mapping("cscript", "T1059.005", 70, "VBScript execution");

        self.add_keyword_mapping("scheduled task", "T1053.005", 75, "Task scheduling");
        self.add_keyword_mapping("schtasks", "T1053.005", 80, "Task scheduler CLI");
        self.add_keyword_mapping("at.exe", "T1053.002", 80, "AT command scheduling");

        self.add_keyword_mapping("registry run key", "T1547.001", 85, "Registry persistence");
        self.add_keyword_mapping(
            "hklm\\software\\microsoft\\windows\\currentversion\\run",
            "T1547.001",
            90,
            "Registry run key",
        );
        self.add_keyword_mapping(
            "hkcu\\software\\microsoft\\windows\\currentversion\\run",
            "T1547.001",
            90,
            "User registry run key",
        );

        self.add_keyword_mapping("lsass", "T1003.001", 85, "LSASS access");
        self.add_keyword_mapping("lsass.exe", "T1003.001", 85, "LSASS process");
        self.add_keyword_mapping("procdump", "T1003.001", 90, "Process dump for creds");

        self.add_keyword_mapping("ntds.dit", "T1003.003", 95, "AD database extraction");
        self.add_keyword_mapping("sam database", "T1003.002", 90, "SAM extraction");
        self.add_keyword_mapping("security account manager", "T1003.002", 85, "SAM access");

        self.add_keyword_mapping("pass-the-hash", "T1550.002", 95, "PtH attack");
        self.add_keyword_mapping("pth", "T1550.002", 75, "PtH abbreviation");
        self.add_keyword_mapping("pass-the-ticket", "T1550.003", 95, "PtT attack");
        self.add_keyword_mapping("golden ticket", "T1558.001", 95, "Kerberos golden ticket");
        self.add_keyword_mapping("silver ticket", "T1558.002", 95, "Kerberos silver ticket");
        self.add_keyword_mapping("kerberoast", "T1558.003", 95, "Kerberoasting");

        self.add_keyword_mapping("rdp", "T1021.001", 70, "Remote Desktop");
        self.add_keyword_mapping("remote desktop", "T1021.001", 75, "RDP access");
        self.add_keyword_mapping("ssh", "T1021.004", 65, "SSH access");
        self.add_keyword_mapping("winrm", "T1021.006", 80, "Windows Remote Management");
        self.add_keyword_mapping("wmi", "T1047", 70, "WMI execution");

        self.add_keyword_mapping("dll injection", "T1055.001", 90, "DLL injection");
        self.add_keyword_mapping("process injection", "T1055", 85, "Process injection");
        self.add_keyword_mapping("process hollowing", "T1055.012", 90, "Process hollowing");

        self.add_keyword_mapping("data exfiltration", "T1041", 80, "Exfiltration over C2");
        self.add_keyword_mapping("exfil", "T1041", 70, "Data exfiltration");

        self.add_keyword_mapping("reverse shell", "T1059", 80, "Reverse shell");
        self.add_keyword_mapping("bind shell", "T1059", 75, "Bind shell");
        self.add_keyword_mapping("webshell", "T1505.003", 90, "Web shell");

        self.add_keyword_mapping("phishing", "T1566", 80, "Phishing");
        self.add_keyword_mapping("spearphishing", "T1566.001", 85, "Spearphishing attachment");

        self.add_keyword_mapping("privilege escalation", "T1068", 70, "Privilege escalation");
        self.add_keyword_mapping("uac bypass", "T1548.002", 90, "UAC bypass");
        self.add_keyword_mapping("sudo", "T1548.003", 65, "Sudo abuse");
    }

    /// Add a tool name mapping
    fn add_tool_mapping(&mut self, tool: &str, technique_id: &str, confidence: u8, desc: &str) {
        self.tool_mappings
            .entry(tool.to_lowercase())
            .or_default()
            .push(ToolMapping {
                technique_id: technique_id.to_string(),
                confidence,
                description: desc.to_string(),
            });
    }

    /// Add a keyword mapping
    fn add_keyword_mapping(
        &mut self,
        keyword: &str,
        technique_id: &str,
        confidence: u8,
        context: &str,
    ) {
        self.keyword_mappings
            .entry(keyword.to_lowercase())
            .or_default()
            .push(KeywordMapping {
                technique_id: technique_id.to_string(),
                confidence,
                context: context.to_string(),
            });
    }

    /// Add a custom user-defined mapping
    pub fn add_custom_mapping(&mut self, mapping: CustomMapping) {
        self.custom_mappings.push(mapping);
    }

    /// Correlate a finding text to MITRE techniques
    pub fn correlate(&self, finding: &str) -> CorrelationResult {
        let mut matches = Vec::new();
        let finding_lower = finding.to_lowercase();

        // Check tool mappings
        for (tool_name, mappings) in &self.tool_mappings {
            if finding_lower.contains(tool_name) {
                for mapping in mappings {
                    if let Some(tech) = self.attack_data.get_technique(&mapping.technique_id) {
                        matches.push(FindingMatch {
                            technique_id: tech.id.clone(),
                            technique_name: tech.name.clone(),
                            confidence: mapping.confidence,
                            match_type: MatchType::ToolName,
                            reason: format!("Tool '{}': {}", tool_name, mapping.description),
                            tactics: tech.tactics.clone(),
                        });
                    }
                }
            }
        }

        // Check keyword mappings
        for (keyword, mappings) in &self.keyword_mappings {
            if finding_lower.contains(keyword) {
                for mapping in mappings {
                    // Avoid duplicates from tool mappings
                    if matches
                        .iter()
                        .any(|m| m.technique_id == mapping.technique_id)
                    {
                        continue;
                    }
                    if let Some(tech) = self.attack_data.get_technique(&mapping.technique_id) {
                        matches.push(FindingMatch {
                            technique_id: tech.id.clone(),
                            technique_name: tech.name.clone(),
                            confidence: mapping.confidence,
                            match_type: MatchType::Keyword,
                            reason: format!("Keyword '{}': {}", keyword, mapping.context),
                            tactics: tech.tactics.clone(),
                        });
                    }
                }
            }
        }

        // Check custom mappings
        for mapping in &self.custom_mappings {
            if finding_lower.contains(&mapping.pattern.to_lowercase()) {
                if matches
                    .iter()
                    .any(|m| m.technique_id == mapping.technique_id)
                {
                    continue;
                }
                if let Some(tech) = self.attack_data.get_technique(&mapping.technique_id) {
                    matches.push(FindingMatch {
                        technique_id: tech.id.clone(),
                        technique_name: tech.name.clone(),
                        confidence: mapping.confidence,
                        match_type: MatchType::Custom,
                        reason: mapping.reason.clone(),
                        tactics: tech.tactics.clone(),
                    });
                }
            }
        }

        // Check for CVE patterns
        let cve_matches = extract_cves(&finding_lower);
        for cve in cve_matches {
            for tech in self.attack_data.techniques.values() {
                if tech.cves.iter().any(|c| c.to_lowercase() == cve) {
                    if !matches.iter().any(|m| m.technique_id == tech.id) {
                        matches.push(FindingMatch {
                            technique_id: tech.id.clone(),
                            technique_name: tech.name.clone(),
                            confidence: 85,
                            match_type: MatchType::Cve,
                            reason: format!("CVE {} linked to technique", cve.to_uppercase()),
                            tactics: tech.tactics.clone(),
                        });
                    }
                }
            }
        }

        // Sort by confidence descending
        matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));

        // Deduplicate by technique ID, keeping highest confidence
        let mut seen = std::collections::HashSet::new();
        matches.retain(|m| seen.insert(m.technique_id.clone()));

        CorrelationResult {
            finding: finding.to_string(),
            matches,
        }
    }

    /// Correlate multiple findings
    pub fn correlate_all(&self, findings: &[&str]) -> Vec<CorrelationResult> {
        findings.iter().map(|f| self.correlate(f)).collect()
    }

    /// Get all techniques that match a specific tool
    pub fn techniques_for_tool(&self, tool_name: &str) -> Vec<FindingMatch> {
        let tool_lower = tool_name.to_lowercase();
        let mut matches = Vec::new();

        if let Some(mappings) = self.tool_mappings.get(&tool_lower) {
            for mapping in mappings {
                if let Some(tech) = self.attack_data.get_technique(&mapping.technique_id) {
                    matches.push(FindingMatch {
                        technique_id: tech.id.clone(),
                        technique_name: tech.name.clone(),
                        confidence: mapping.confidence,
                        match_type: MatchType::ToolName,
                        reason: mapping.description.clone(),
                        tactics: tech.tactics.clone(),
                    });
                }
            }
        }

        matches
    }

    /// Search ATT&CK data and return matches
    pub fn search(&self, query: &str) -> Vec<FindingMatch> {
        let results = self.attack_data.search(query);
        let mut matches = Vec::new();

        for obj in results {
            if let super::types::AttackObject::Technique(tech) = obj {
                // Calculate confidence based on match quality
                let confidence = calculate_search_confidence(query, &tech);

                matches.push(FindingMatch {
                    technique_id: tech.id.clone(),
                    technique_name: tech.name.clone(),
                    confidence,
                    match_type: MatchType::TextSearch,
                    reason: format!("Matches technique description/name"),
                    tactics: tech.tactics.clone(),
                });
            }
        }

        matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        matches
    }

    /// List all known tool mappings
    pub fn list_tool_mappings(&self) -> Vec<(&str, Vec<String>)> {
        self.tool_mappings
            .iter()
            .map(|(tool, mappings)| {
                (
                    tool.as_str(),
                    mappings.iter().map(|m| m.technique_id.clone()).collect(),
                )
            })
            .collect()
    }
}

/// Extract CVE IDs from text
fn extract_cves(text: &str) -> Vec<String> {
    let mut cves = Vec::new();
    let text_upper = text.to_uppercase();

    // Simple pattern: CVE-YYYY-NNNNN
    let mut i = 0;
    while i < text_upper.len() {
        if text_upper[i..].starts_with("CVE-") {
            let start = i;
            i += 4;

            // Skip year (4 digits)
            let mut year_digits = 0;
            while i < text_upper.len() && text_upper.as_bytes()[i].is_ascii_digit() {
                year_digits += 1;
                i += 1;
            }

            if year_digits != 4 {
                continue;
            }

            // Skip separator
            if i >= text_upper.len() || text_upper.as_bytes()[i] != b'-' {
                continue;
            }
            i += 1;

            // Read number
            let num_start = i;
            while i < text_upper.len() && text_upper.as_bytes()[i].is_ascii_digit() {
                i += 1;
            }

            if i > num_start {
                cves.push(text_upper[start..i].to_string());
            }
        } else {
            i += 1;
        }
    }

    cves
}

/// Calculate search confidence based on match quality
fn calculate_search_confidence(query: &str, tech: &Technique) -> u8 {
    let query_lower = query.to_lowercase();
    let name_lower = tech.name.to_lowercase();
    let id_lower = tech.id.to_lowercase();

    // Exact ID match
    if id_lower == query_lower {
        return 100;
    }

    // Exact name match
    if name_lower == query_lower {
        return 95;
    }

    // Name starts with query
    if name_lower.starts_with(&query_lower) {
        return 85;
    }

    // Name contains query
    if name_lower.contains(&query_lower) {
        return 75;
    }

    // ID contains query
    if id_lower.contains(&query_lower) {
        return 70;
    }

    // Description contains query
    if tech.description.to_lowercase().contains(&query_lower) {
        return 50;
    }

    40
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_data() -> AttackData {
        let mut data = AttackData::new();

        // Add a test technique
        data.techniques.insert(
            "T1059.001".to_string(),
            Technique {
                id: "T1059.001".to_string(),
                name: "PowerShell".to_string(),
                description: "PowerShell execution for command and control".to_string(),
                tactics: vec!["execution".to_string()],
                detection: None,
                platforms: vec!["Windows".to_string()],
                data_sources: vec![],
                is_subtechnique: true,
                parent_id: Some("T1059".to_string()),
                url: "https://attack.mitre.org/techniques/T1059/001/".to_string(),
                references: vec![],
                mitigations: vec![],
                deprecated: false,
                revoked: false,
                cves: vec![],
            },
        );

        data.techniques.insert(
            "T1003".to_string(),
            Technique {
                id: "T1003".to_string(),
                name: "OS Credential Dumping".to_string(),
                description: "Dumping credentials from the operating system".to_string(),
                tactics: vec!["credential-access".to_string()],
                detection: None,
                platforms: vec!["Windows".to_string(), "Linux".to_string()],
                data_sources: vec![],
                is_subtechnique: false,
                parent_id: None,
                url: "https://attack.mitre.org/techniques/T1003/".to_string(),
                references: vec![],
                mitigations: vec![],
                deprecated: false,
                revoked: false,
                cves: vec![],
            },
        );

        data
    }

    #[test]
    fn test_tool_correlation() {
        let data = create_test_data();
        let engine = CorrelationEngine::new(&data);

        let result = engine.correlate("Detected mimikatz.exe execution on host");

        assert!(!result.matches.is_empty());
        assert!(result
            .matches
            .iter()
            .any(|m| m.technique_id == "T1003" && m.match_type == MatchType::ToolName));
    }

    #[test]
    fn test_keyword_correlation() {
        let data = create_test_data();
        let engine = CorrelationEngine::new(&data);

        let result = engine.correlate("PowerShell -encodedcommand detected");

        assert!(!result.matches.is_empty());
        assert!(result
            .matches
            .iter()
            .any(|m| m.technique_id == "T1059.001" && m.match_type == MatchType::Keyword));
    }

    #[test]
    fn test_custom_mapping() {
        let data = create_test_data();
        let mut engine = CorrelationEngine::new(&data);

        engine.add_custom_mapping(CustomMapping {
            pattern: "custom-malware".to_string(),
            technique_id: "T1059.001".to_string(),
            confidence: 90,
            reason: "Custom malware detection".to_string(),
        });

        let result = engine.correlate("Found custom-malware process");

        assert!(!result.matches.is_empty());
        assert!(result
            .matches
            .iter()
            .any(|m| m.technique_id == "T1059.001" && m.match_type == MatchType::Custom));
    }

    #[test]
    fn test_cve_extraction() {
        let cves = extract_cves("Exploited CVE-2021-44228 and CVE-2022-12345");
        assert_eq!(cves.len(), 2);
        assert!(cves.contains(&"CVE-2021-44228".to_string()));
        assert!(cves.contains(&"CVE-2022-12345".to_string()));
    }

    #[test]
    fn test_techniques_for_tool() {
        let data = create_test_data();
        let engine = CorrelationEngine::new(&data);

        let matches = engine.techniques_for_tool("mimikatz");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_confidence_ordering() {
        let data = create_test_data();
        let engine = CorrelationEngine::new(&data);

        let result = engine.correlate("Mimikatz detected with PowerShell execution");

        // Results should be sorted by confidence
        let confidences: Vec<u8> = result.matches.iter().map(|m| m.confidence).collect();
        let mut sorted = confidences.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(confidences, sorted);
    }
}
