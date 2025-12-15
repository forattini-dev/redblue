//! Playbook Recommender
//!
//! Automatically recommends playbooks based on scan findings.
//!
//! ## Pipeline
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
//! │ ReconFindings   │────▶│ PlaybookMatcher  │────▶│ Recommendations │
//! │                 │     │                  │     │                 │
//! │ ports, vulns,   │     │ score each       │     │ ranked list of  │
//! │ fingerprints,OS │     │ playbook         │     │ playbooks       │
//! └─────────────────┘     └──────────────────┘     └─────────────────┘
//! ```
//!
//! ## Matching Rules
//!
//! - SSH port open → ssh-credential-test
//! - Web ports open → web-app-assessment, webshell-upload
//! - Critical CVE → reverse-shell-*, webshell-upload
//! - Windows detected → windows-privesc, reverse-shell-windows
//! - Linux detected → linux-privesc, reverse-shell-linux
//! - Domain recon → external-footprint
//! - Internal network → internal-recon, lateral-movement

use crate::storage::records::{VulnerabilityRecord, PortScanRecord, Severity};
use crate::modules::exploit::planner::{AttackPlan, AttackOption, PlannerInput};
use super::catalog::{all_playbooks, get_playbook};
use super::apt_catalog::all_apt_playbooks;
use super::types::{Playbook, TargetType, TargetOS, RiskLevel};

/// Input for playbook recommendation
#[derive(Debug, Clone, Default)]
pub struct ReconFindings {
    /// Target being assessed
    pub target: String,
    /// Open ports found
    pub ports: Vec<PortScanRecord>,
    /// Vulnerabilities found
    pub vulns: Vec<VulnerabilityRecord>,
    /// Detected technologies/fingerprints
    pub fingerprints: Vec<String>,
    /// Detected operating system
    pub detected_os: Option<DetectedOS>,
    /// Target type (domain, IP, URL, etc.)
    pub target_type: Option<TargetType>,
    /// Is this internal network?
    pub is_internal: bool,
}

/// Detected operating system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedOS {
    Linux,
    Windows,
    MacOS,
    Unknown,
}

impl DetectedOS {
    pub fn to_target_os(&self) -> TargetOS {
        match self {
            DetectedOS::Linux => TargetOS::Linux,
            DetectedOS::Windows => TargetOS::Windows,
            DetectedOS::MacOS => TargetOS::MacOS,
            DetectedOS::Unknown => TargetOS::Any,
        }
    }
}

/// A playbook recommendation with score
#[derive(Debug, Clone)]
pub struct PlaybookRecommendation {
    /// Playbook ID
    pub playbook_id: String,
    /// Playbook name
    pub playbook_name: String,
    /// Match score (0-100)
    pub score: u8,
    /// Reasons for recommendation
    pub reasons: Vec<String>,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Related attack options from planner
    pub related_attacks: Vec<String>,
    /// Is this an APT adversary emulation playbook?
    pub is_apt_playbook: bool,
}

/// Recommendation results
#[derive(Debug, Clone)]
pub struct RecommendationResult {
    /// Target
    pub target: String,
    /// Recommended playbooks (sorted by score)
    pub recommendations: Vec<PlaybookRecommendation>,
    /// Summary statistics
    pub summary: RecommendationSummary,
}

/// Summary of recommendations
#[derive(Debug, Clone, Default)]
pub struct RecommendationSummary {
    /// Total playbooks matched
    pub total_matched: usize,
    /// High-risk playbooks
    pub high_risk_count: usize,
    /// Medium-risk playbooks
    pub medium_risk_count: usize,
    /// Low-risk playbooks
    pub low_risk_count: usize,
    /// Has critical vulns that need immediate attention
    pub has_critical_findings: bool,
    /// Recommended first playbook
    pub top_recommendation: Option<String>,
    /// APT playbooks matched
    pub apt_playbooks_matched: usize,
}

/// Playbook Recommender
///
/// Analyzes scan findings and recommends appropriate playbooks.
pub struct PlaybookRecommender {
    /// Maximum risk level to include
    max_risk: RiskLevel,
    /// Minimum score to include
    min_score: u8,
    /// Maximum recommendations to return
    max_recommendations: usize,
}

impl Default for PlaybookRecommender {
    fn default() -> Self {
        Self {
            max_risk: RiskLevel::High,
            min_score: 20,
            max_recommendations: 10,
        }
    }
}

impl PlaybookRecommender {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum risk level
    pub fn with_max_risk(mut self, risk: RiskLevel) -> Self {
        self.max_risk = risk;
        self
    }

    /// Set minimum score threshold
    pub fn with_min_score(mut self, score: u8) -> Self {
        self.min_score = score;
        self
    }

    /// Set max recommendations
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_recommendations = max;
        self
    }

    /// Recommend playbooks from findings
    pub fn recommend(&self, findings: &ReconFindings) -> RecommendationResult {
        let mut recommendations = Vec::new();

        // Score each standard playbook
        for playbook in all_playbooks() {
            // Skip if above max risk
            if playbook.metadata.risk_level > self.max_risk {
                continue;
            }

            let (score, reasons) = self.score_playbook(&playbook, findings);

            if score >= self.min_score {
                recommendations.push(PlaybookRecommendation {
                    playbook_id: playbook.metadata.id.clone(),
                    playbook_name: playbook.metadata.name.clone(),
                    score,
                    reasons,
                    risk_level: playbook.metadata.risk_level,
                    related_attacks: Vec::new(),
                    is_apt_playbook: false,
                });
            }
        }

        // Score APT adversary emulation playbooks
        for playbook in all_apt_playbooks() {
            if playbook.metadata.risk_level > self.max_risk {
                continue;
            }

            let (score, reasons) = self.score_apt_playbook(&playbook, findings);

            if score >= self.min_score {
                recommendations.push(PlaybookRecommendation {
                    playbook_id: playbook.metadata.id.clone(),
                    playbook_name: playbook.metadata.name.clone(),
                    score,
                    reasons,
                    risk_level: playbook.metadata.risk_level,
                    related_attacks: Vec::new(),
                    is_apt_playbook: true,
                });
            }
        }

        // Sort by score descending
        recommendations.sort_by(|a, b| b.score.cmp(&a.score));

        // Truncate to max
        recommendations.truncate(self.max_recommendations);

        // Build summary
        let summary = self.build_summary(&recommendations, findings);

        RecommendationResult {
            target: findings.target.clone(),
            recommendations,
            summary,
        }
    }

    /// Recommend playbooks from attack plan
    pub fn recommend_from_plan(&self, plan: &AttackPlan, findings: &ReconFindings) -> RecommendationResult {
        let mut result = self.recommend(findings);

        // Enhance recommendations with attack plan data
        for rec in &mut result.recommendations {
            for phase in &plan.phases {
                for option in &phase.options {
                    // Match techniques to playbooks
                    if self.technique_matches_playbook(&option.technique_id, &rec.playbook_id) {
                        rec.related_attacks.push(format!(
                            "{}: {}",
                            option.technique_id,
                            option.technique_name
                        ));
                        // Boost score if there's an attack plan match
                        rec.score = (rec.score + 10).min(100);
                    }
                }
            }
        }

        // Re-sort after score adjustments
        result.recommendations.sort_by(|a, b| b.score.cmp(&a.score));

        result
    }

    /// Score a playbook against findings
    fn score_playbook(&self, playbook: &Playbook, findings: &ReconFindings) -> (u8, Vec<String>) {
        let mut score: u32 = 0;
        let mut reasons = Vec::new();

        // === PORT-BASED SCORING ===
        let port_score = self.score_ports(playbook, findings, &mut reasons);
        score += port_score as u32;

        // === VULNERABILITY-BASED SCORING ===
        let vuln_score = self.score_vulns(playbook, findings, &mut reasons);
        score += vuln_score as u32;

        // === OS-BASED SCORING ===
        let os_score = self.score_os(playbook, findings, &mut reasons);
        score += os_score as u32;

        // === FINGERPRINT-BASED SCORING ===
        let fp_score = self.score_fingerprints(playbook, findings, &mut reasons);
        score += fp_score as u32;

        // === TARGET TYPE SCORING ===
        let target_score = self.score_target_type(playbook, findings, &mut reasons);
        score += target_score as u32;

        // === INTERNAL NETWORK SCORING ===
        if findings.is_internal {
            if playbook.metadata.id == "internal-recon" || playbook.metadata.id == "lateral-movement" {
                score += 30;
                reasons.push("Internal network detected".to_string());
            }
        }

        // Normalize to 0-100
        let final_score = score.min(100) as u8;

        (final_score, reasons)
    }

    /// Score based on open ports
    fn score_ports(&self, playbook: &Playbook, findings: &ReconFindings, reasons: &mut Vec<String>) -> u8 {
        let mut score = 0u8;
        let pb_id = &playbook.metadata.id;

        let has_ssh = findings.ports.iter().any(|p| p.port == 22);
        let has_web = findings.ports.iter().any(|p| matches!(p.port, 80 | 443 | 8080 | 8443));
        let has_smb = findings.ports.iter().any(|p| matches!(p.port, 445 | 139));
        let has_rdp = findings.ports.iter().any(|p| p.port == 3389);
        let has_ftp = findings.ports.iter().any(|p| p.port == 21);

        // SSH playbooks
        if has_ssh {
            if pb_id == "ssh-credential-test" {
                score += 40;
                reasons.push("SSH port (22) is open".to_string());
            }
            if pb_id == "reverse-shell-linux" {
                score += 20;
                reasons.push("SSH suggests Linux host".to_string());
            }
            if pb_id == "linux-privesc" {
                score += 15;
                reasons.push("SSH suggests Linux for privesc".to_string());
            }
        }

        // Web playbooks
        if has_web {
            if pb_id == "web-app-assessment" {
                score += 40;
                let web_ports: Vec<_> = findings.ports.iter()
                    .filter(|p| matches!(p.port, 80 | 443 | 8080 | 8443))
                    .map(|p| p.port.to_string())
                    .collect();
                reasons.push(format!("Web ports open: {}", web_ports.join(", ")));
            }
            if pb_id == "webshell-upload" {
                score += 25;
                reasons.push("Web server detected".to_string());
            }
        }

        // SMB playbooks
        if has_smb {
            if pb_id == "lateral-movement" {
                score += 30;
                reasons.push("SMB port (445) suggests Windows/lateral movement".to_string());
            }
            if pb_id == "reverse-shell-windows" {
                score += 20;
                reasons.push("SMB suggests Windows host".to_string());
            }
            if pb_id == "windows-privesc" {
                score += 15;
                reasons.push("SMB suggests Windows for privesc".to_string());
            }
        }

        // RDP
        if has_rdp {
            if pb_id == "reverse-shell-windows" || pb_id == "windows-privesc" {
                score += 25;
                reasons.push("RDP port (3389) suggests Windows".to_string());
            }
        }

        // FTP
        if has_ftp {
            if pb_id == "credential-harvesting" {
                score += 15;
                reasons.push("FTP port (21) open".to_string());
            }
        }

        score
    }

    /// Score based on vulnerabilities
    fn score_vulns(&self, playbook: &Playbook, findings: &ReconFindings, reasons: &mut Vec<String>) -> u8 {
        let mut score = 0u8;
        let pb_id = &playbook.metadata.id;

        let has_critical = findings.vulns.iter().any(|v| v.severity == Severity::Critical);
        let has_high = findings.vulns.iter().any(|v| v.severity == Severity::High);
        let has_rce = findings.vulns.iter().any(|v|
            v.description.to_lowercase().contains("remote code execution") ||
            v.description.to_lowercase().contains("rce") ||
            v.cve_id.contains("Log4j") ||
            v.cve_id.contains("2021-44228")
        );
        let has_exploit = findings.vulns.iter().any(|v| v.exploit_available);

        // Critical vulns push toward exploitation playbooks
        if has_critical || has_rce {
            if pb_id == "reverse-shell-linux" || pb_id == "reverse-shell-windows" {
                score += 35;
                reasons.push("Critical RCE vulnerability found".to_string());
            }
            if pb_id == "webshell-upload" {
                score += 30;
                reasons.push("Critical vulnerability may allow webshell".to_string());
            }
        }

        // High severity vulns
        if has_high {
            if pb_id == "web-app-assessment" {
                score += 20;
                reasons.push("High severity vulnerabilities found".to_string());
            }
        }

        // Exploitable vulns
        if has_exploit {
            if pb_id == "reverse-shell-linux" || pb_id == "reverse-shell-windows" {
                score += 25;
                let exploit_count = findings.vulns.iter().filter(|v| v.exploit_available).count();
                reasons.push(format!("{} exploits available", exploit_count));
            }
        }

        score
    }

    /// Score based on OS detection
    fn score_os(&self, playbook: &Playbook, findings: &ReconFindings, reasons: &mut Vec<String>) -> u8 {
        let mut score = 0u8;
        let pb_id = &playbook.metadata.id;

        if let Some(os) = &findings.detected_os {
            match os {
                DetectedOS::Linux => {
                    if pb_id == "reverse-shell-linux" {
                        score += 30;
                        reasons.push("Linux OS detected".to_string());
                    }
                    if pb_id == "linux-privesc" {
                        score += 30;
                        reasons.push("Linux detected for privilege escalation".to_string());
                    }
                }
                DetectedOS::Windows => {
                    if pb_id == "reverse-shell-windows" {
                        score += 30;
                        reasons.push("Windows OS detected".to_string());
                    }
                    if pb_id == "windows-privesc" {
                        score += 30;
                        reasons.push("Windows detected for privilege escalation".to_string());
                    }
                    if pb_id == "lateral-movement" {
                        score += 15;
                        reasons.push("Windows enables AD lateral movement".to_string());
                    }
                }
                _ => {}
            }
        }

        score
    }

    /// Score based on fingerprints
    fn score_fingerprints(&self, playbook: &Playbook, findings: &ReconFindings, reasons: &mut Vec<String>) -> u8 {
        let mut score = 0u8;
        let pb_id = &playbook.metadata.id;

        for fp in &findings.fingerprints {
            let fp_lower = fp.to_lowercase();

            // WordPress
            if fp_lower.contains("wordpress") {
                if pb_id == "web-app-assessment" {
                    score += 25;
                    reasons.push("WordPress CMS detected".to_string());
                }
                if pb_id == "webshell-upload" {
                    score += 20;
                    reasons.push("WordPress may have upload vulnerabilities".to_string());
                }
            }

            // Jenkins
            if fp_lower.contains("jenkins") {
                if pb_id == "web-app-assessment" {
                    score += 30;
                    reasons.push("Jenkins CI/CD detected".to_string());
                }
                if pb_id == "credential-harvesting" {
                    score += 25;
                    reasons.push("Jenkins may have credentials".to_string());
                }
            }

            // Apache/Nginx
            if fp_lower.contains("apache") || fp_lower.contains("nginx") {
                if pb_id == "web-app-assessment" {
                    score += 15;
                    reasons.push(format!("{} web server detected", fp));
                }
            }

            // SSH banner (OpenSSH)
            if fp_lower.contains("openssh") {
                if pb_id == "ssh-credential-test" || pb_id == "reverse-shell-linux" {
                    score += 10;
                }
            }

            // Active Directory
            if fp_lower.contains("active directory") || fp_lower.contains("domain controller") {
                if pb_id == "lateral-movement" {
                    score += 35;
                    reasons.push("Active Directory detected".to_string());
                }
                if pb_id == "credential-harvesting" {
                    score += 30;
                    reasons.push("AD is prime credential target".to_string());
                }
            }
        }

        score
    }

    /// Score based on target type
    fn score_target_type(&self, playbook: &Playbook, findings: &ReconFindings, reasons: &mut Vec<String>) -> u8 {
        let mut score = 0u8;
        let pb_id = &playbook.metadata.id;

        if let Some(target_type) = &findings.target_type {
            // Check if playbook targets this type
            if playbook.metadata.target_types.contains(target_type) {
                score += 15;
            }

            match target_type {
                TargetType::Domain => {
                    if pb_id == "external-footprint" {
                        score += 40;
                        reasons.push("Domain target detected".to_string());
                    }
                }
                TargetType::WebApp => {
                    if pb_id == "web-app-assessment" {
                        score += 35;
                        reasons.push("Web application target".to_string());
                    }
                }
                TargetType::Host => {
                    if pb_id.contains("privesc") || pb_id.contains("shell") {
                        score += 10;
                    }
                }
                TargetType::Internal => {
                    if pb_id == "internal-recon" {
                        score += 40;
                        reasons.push("Internal network target".to_string());
                    }
                    if pb_id == "lateral-movement" {
                        score += 35;
                        reasons.push("Internal movement potential".to_string());
                    }
                }
                _ => {}
            }
        }

        score
    }

    /// Check if MITRE technique matches a playbook
    fn technique_matches_playbook(&self, technique_id: &str, playbook_id: &str) -> bool {
        match technique_id {
            "T1190" => matches!(playbook_id, "web-app-assessment" | "webshell-upload"),
            "T1133" => matches!(playbook_id, "ssh-credential-test" | "reverse-shell-linux"),
            "T1110" => playbook_id == "ssh-credential-test",
            "T1059" | "T1059.001" | "T1059.004" => playbook_id.contains("reverse-shell"),
            "T1068" | "T1548" => playbook_id.contains("privesc"),
            "T1021" | "T1021.002" | "T1021.004" => playbook_id == "lateral-movement",
            "T1505.003" => playbook_id == "webshell-upload",
            "T1552" => playbook_id == "credential-harvesting",
            _ => false,
        }
    }

    /// Score an APT adversary emulation playbook against findings
    ///
    /// APT playbooks are scored based on:
    /// 1. Technique correlation: Do discovered vulns/TTPs match APT techniques?
    /// 2. Infrastructure match: Does target infra match typical APT targets?
    /// 3. Fingerprint match: Do discovered technologies align with APT preferences?
    fn score_apt_playbook(&self, playbook: &Playbook, findings: &ReconFindings) -> (u8, Vec<String>) {
        let mut score: u32 = 0;
        let mut reasons = Vec::new();
        let apt_id = &playbook.metadata.id;

        // === TECHNIQUE CORRELATION ===
        // Match MITRE techniques in playbook steps against discovered vulnerabilities
        for step in &playbook.steps {
            if let Some(technique) = &step.mitre_technique {
                // Check if any vulnerability matches this technique
                for vuln in &findings.vulns {
                    if self.vuln_matches_technique(&vuln, technique) {
                        score += 15;
                        reasons.push(format!("Technique {} matches CVE {}", technique, vuln.cve_id));
                    }
                }
            }
        }

        // === OS CORRELATION ===
        if let Some(os) = &findings.detected_os {
            match os {
                DetectedOS::Windows => {
                    // APT groups known for Windows targeting
                    if matches!(apt_id.as_str(),
                        "apt28" | "apt29" | "wizard-spider" | "sandworm-team" |
                        "turla" | "scattered-spider" | "fin7" | "apt41"
                    ) {
                        score += 20;
                        reasons.push("Windows host matches APT targeting profile".to_string());
                    }
                }
                DetectedOS::Linux => {
                    // APT groups with Linux capability
                    if matches!(apt_id.as_str(),
                        "apt28" | "apt29" | "sandworm-team" | "turla" | "lazarus-group"
                    ) {
                        score += 15;
                        reasons.push("Linux host within APT capability".to_string());
                    }
                }
                _ => {}
            }
        }

        // === PORT-BASED INFRASTRUCTURE MATCHING ===
        let has_web = findings.ports.iter().any(|p| matches!(p.port, 80 | 443 | 8080 | 8443));
        let has_mail = findings.ports.iter().any(|p| matches!(p.port, 25 | 587 | 993 | 995));
        let has_vpn = findings.ports.iter().any(|p| matches!(p.port, 443 | 500 | 1194 | 4500));
        let has_ssh = findings.ports.iter().any(|p| p.port == 22);
        let has_rdp = findings.ports.iter().any(|p| p.port == 3389);
        let has_smb = findings.ports.iter().any(|p| matches!(p.port, 445 | 139));

        // Web-focused APTs
        if has_web {
            if matches!(apt_id.as_str(),
                "apt32" | "muddywater" | "oilrig" | "apt41" | "volt-typhoon"
            ) {
                score += 15;
                reasons.push("Web presence matches APT initial access vectors".to_string());
            }
        }

        // Email/phishing-focused APTs
        if has_mail {
            if matches!(apt_id.as_str(),
                "apt28" | "apt29" | "kimsuky" | "muddywater" | "fin7"
            ) {
                score += 20;
                reasons.push("Email infrastructure aligns with APT phishing TTPs".to_string());
            }
        }

        // VPN/Remote access (LOTL APTs)
        if has_vpn || has_ssh || has_rdp {
            if matches!(apt_id.as_str(),
                "volt-typhoon" | "scattered-spider" | "apt29"
            ) {
                score += 20;
                reasons.push("Remote access exposure matches LOTL APT techniques".to_string());
            }
        }

        // Active Directory focused APTs
        if has_smb && has_rdp {
            if matches!(apt_id.as_str(),
                "apt29" | "wizard-spider" | "scattered-spider" | "turla"
            ) {
                score += 25;
                reasons.push("AD infrastructure matches APT lateral movement profile".to_string());
            }
        }

        // === FINGERPRINT-BASED MATCHING ===
        for fp in &findings.fingerprints {
            let fp_lower = fp.to_lowercase();

            // Cloud providers
            if fp_lower.contains("azure") || fp_lower.contains("microsoft 365") || fp_lower.contains("office 365") {
                if matches!(apt_id.as_str(), "apt29" | "scattered-spider" | "volt-typhoon") {
                    score += 20;
                    reasons.push(format!("Cloud tech {} targeted by APT", fp));
                }
            }

            // Virtualization
            if fp_lower.contains("vmware") || fp_lower.contains("esxi") {
                if matches!(apt_id.as_str(), "sandworm-team" | "apt41") {
                    score += 20;
                    reasons.push("VMware infrastructure targeted by APT".to_string());
                }
            }

            // Fortinet/VPN appliances
            if fp_lower.contains("fortinet") || fp_lower.contains("fortigate") ||
               fp_lower.contains("pulse secure") || fp_lower.contains("citrix") {
                if matches!(apt_id.as_str(), "volt-typhoon" | "apt41" | "sandworm-team") {
                    score += 25;
                    reasons.push("Network appliance known APT target".to_string());
                }
            }

            // Financial systems
            if fp_lower.contains("swift") || fp_lower.contains("banking") {
                if matches!(apt_id.as_str(), "lazarus-group" | "fin7") {
                    score += 30;
                    reasons.push("Financial system targeted by financially-motivated APT".to_string());
                }
            }

            // Exchange
            if fp_lower.contains("exchange") || fp_lower.contains("outlook web") {
                if matches!(apt_id.as_str(), "apt28" | "apt29" | "turla" | "volt-typhoon") {
                    score += 25;
                    reasons.push("Exchange server commonly exploited by APT".to_string());
                }
            }
        }

        // === CRITICAL VULNERABILITY BOOST ===
        let has_critical = findings.vulns.iter().any(|v| v.severity == Severity::Critical);
        let has_exploit = findings.vulns.iter().any(|v| v.exploit_available);

        if has_critical && has_exploit {
            // All APTs get a boost for critical exploitable vulns
            score += 20;
            reasons.push("Critical exploitable vulnerability available".to_string());
        }

        // === INTERNAL NETWORK BONUS ===
        if findings.is_internal {
            // Post-compromise APTs
            if matches!(apt_id.as_str(),
                "apt29" | "turla" | "wizard-spider" | "scattered-spider" | "volt-typhoon"
            ) {
                score += 25;
                reasons.push("Internal access enables APT post-compromise TTPs".to_string());
            }
        }

        // Normalize to 0-100
        let final_score = score.min(100) as u8;

        (final_score, reasons)
    }

    /// Check if a vulnerability matches a MITRE technique
    fn vuln_matches_technique(&self, vuln: &VulnerabilityRecord, technique: &str) -> bool {
        let desc_lower = vuln.description.to_lowercase();
        let cve_id = &vuln.cve_id;

        match technique {
            // Initial Access
            "T1190" => desc_lower.contains("remote code execution") ||
                       desc_lower.contains("web exploit") ||
                       desc_lower.contains("injection"),
            "T1566" => desc_lower.contains("phishing") ||
                       desc_lower.contains("spearphishing"),
            "T1133" => desc_lower.contains("vpn") ||
                       desc_lower.contains("remote access") ||
                       desc_lower.contains("rdp"),

            // Execution
            "T1059" | "T1059.001" | "T1059.003" | "T1059.004" =>
                desc_lower.contains("command execution") ||
                desc_lower.contains("code execution") ||
                desc_lower.contains("rce"),

            // Privilege Escalation
            "T1068" => desc_lower.contains("privilege escalation") ||
                       desc_lower.contains("local privilege"),
            "T1548" => desc_lower.contains("elevation") ||
                       desc_lower.contains("bypass uac"),

            // Defense Evasion
            "T1562" => desc_lower.contains("disable") ||
                       desc_lower.contains("bypass security"),

            // Credential Access
            "T1003" => desc_lower.contains("credential") ||
                       desc_lower.contains("password") ||
                       desc_lower.contains("hash"),
            "T1552" => desc_lower.contains("unsecured credentials") ||
                       desc_lower.contains("plaintext"),

            // Lateral Movement
            "T1021" => desc_lower.contains("remote service") ||
                       desc_lower.contains("lateral"),

            // Known CVEs for specific techniques
            _ => {
                // Log4Shell
                if cve_id.contains("2021-44228") || cve_id.contains("Log4j") {
                    return matches!(technique, "T1190" | "T1059");
                }
                // ProxyLogon/ProxyShell
                if cve_id.contains("2021-26855") || cve_id.contains("2021-34473") {
                    return matches!(technique, "T1190" | "T1505.003");
                }
                // Zerologon
                if cve_id.contains("2020-1472") {
                    return matches!(technique, "T1068" | "T1003");
                }
                false
            }
        }
    }

    /// Build recommendation summary
    fn build_summary(&self, recommendations: &[PlaybookRecommendation], findings: &ReconFindings) -> RecommendationSummary {
        let mut summary = RecommendationSummary::default();

        summary.total_matched = recommendations.len();

        for rec in recommendations {
            match rec.risk_level {
                RiskLevel::High | RiskLevel::Critical => summary.high_risk_count += 1,
                RiskLevel::Medium => summary.medium_risk_count += 1,
                _ => summary.low_risk_count += 1,
            }

            if rec.is_apt_playbook {
                summary.apt_playbooks_matched += 1;
            }
        }

        summary.has_critical_findings = findings.vulns.iter()
            .any(|v| v.severity == Severity::Critical);

        summary.top_recommendation = recommendations.first().map(|r| r.playbook_id.clone());

        summary
    }
}

/// Quick recommendation from findings
pub fn recommend_playbooks(findings: &ReconFindings) -> RecommendationResult {
    PlaybookRecommender::new().recommend(findings)
}

/// Recommend from attack plan and findings
pub fn recommend_from_attack_plan(plan: &AttackPlan, findings: &ReconFindings) -> RecommendationResult {
    PlaybookRecommender::new().recommend_from_plan(plan, findings)
}

/// Create ReconFindings from planner input (convenience function)
pub fn findings_from_planner_input(input: &PlannerInput) -> ReconFindings {
    ReconFindings {
        target: input.target.to_string(),
        ports: input.ports.to_vec(),
        vulns: input.vulns.to_vec(),
        fingerprints: input.fingerprints.to_vec(),
        detected_os: detect_os_from_ports(input.ports),
        target_type: None,
        is_internal: false,
    }
}

/// Detect OS from port signatures
fn detect_os_from_ports(ports: &[PortScanRecord]) -> Option<DetectedOS> {
    let has_ssh = ports.iter().any(|p| p.port == 22);
    let has_smb = ports.iter().any(|p| matches!(p.port, 445 | 139));
    let has_rdp = ports.iter().any(|p| p.port == 3389);

    // Windows indicators
    if has_rdp || (has_smb && !has_ssh) {
        return Some(DetectedOS::Windows);
    }

    // Linux indicators
    if has_ssh && !has_smb && !has_rdp {
        return Some(DetectedOS::Linux);
    }

    // Could be either
    if has_ssh && has_smb {
        // SSH + SMB could be Samba on Linux or Windows with OpenSSH
        return Some(DetectedOS::Unknown);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;
    use crate::storage::records::PortStatus;

    fn make_port(port: u16) -> PortScanRecord {
        PortScanRecord {
            ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            port,
            status: PortStatus::Open,
            service_id: 0,
            timestamp: 0,
        }
    }

    fn make_vuln(cve: &str, severity: Severity) -> VulnerabilityRecord {
        VulnerabilityRecord {
            cve_id: cve.to_string(),
            technology: String::new(),
            version: None,
            cvss: match severity {
                Severity::Critical => 9.8,
                Severity::High => 7.5,
                Severity::Medium => 5.0,
                Severity::Low => 2.5,
                Severity::Info => 0.0,
            },
            risk_score: match severity {
                Severity::Critical => 95,
                Severity::High => 75,
                Severity::Medium => 50,
                Severity::Low => 25,
                Severity::Info => 5,
            },
            severity,
            description: String::new(),
            references: Vec::new(),
            exploit_available: false,
            in_kev: false,
            discovered_at: 0,
            source: "test".to_string(),
        }
    }

    #[test]
    fn test_empty_findings_returns_no_recommendations() {
        let findings = ReconFindings::default();
        let result = recommend_playbooks(&findings);
        assert!(result.recommendations.is_empty() || result.recommendations.iter().all(|r| r.score < 20));
    }

    #[test]
    fn test_ssh_port_recommends_ssh_playbook() {
        let findings = ReconFindings {
            target: "192.168.1.1".to_string(),
            ports: vec![make_port(22)],
            ..Default::default()
        };

        let result = recommend_playbooks(&findings);

        let ssh_rec = result.recommendations.iter()
            .find(|r| r.playbook_id == "ssh-credential-test");

        assert!(ssh_rec.is_some(), "Should recommend ssh-credential-test");
        assert!(ssh_rec.unwrap().score >= 30, "SSH playbook should have high score");
    }

    #[test]
    fn test_web_ports_recommend_web_playbooks() {
        let findings = ReconFindings {
            target: "192.168.1.1".to_string(),
            ports: vec![make_port(80), make_port(443)],
            ..Default::default()
        };

        let result = recommend_playbooks(&findings);

        let web_rec = result.recommendations.iter()
            .find(|r| r.playbook_id == "web-app-assessment");

        assert!(web_rec.is_some(), "Should recommend web-app-assessment");
        assert!(web_rec.unwrap().score >= 30);
    }

    #[test]
    fn test_critical_vuln_recommends_shell_playbooks() {
        let mut vuln = make_vuln("CVE-2021-44228", Severity::Critical);
        vuln.description = "Remote Code Execution in Log4j".to_string();
        vuln.exploit_available = true;

        let findings = ReconFindings {
            target: "192.168.1.1".to_string(),
            vulns: vec![vuln],
            ..Default::default()
        };

        let result = recommend_playbooks(&findings);

        let shell_rec = result.recommendations.iter()
            .find(|r| r.playbook_id.contains("reverse-shell"));

        assert!(shell_rec.is_some(), "Critical RCE should recommend reverse shell");
    }

    #[test]
    fn test_os_detection_from_ports() {
        // Windows: RDP
        let windows_ports = vec![make_port(3389), make_port(445)];
        assert_eq!(detect_os_from_ports(&windows_ports), Some(DetectedOS::Windows));

        // Linux: SSH only
        let linux_ports = vec![make_port(22)];
        assert_eq!(detect_os_from_ports(&linux_ports), Some(DetectedOS::Linux));

        // Unknown: SSH + SMB
        let mixed_ports = vec![make_port(22), make_port(445)];
        assert_eq!(detect_os_from_ports(&mixed_ports), Some(DetectedOS::Unknown));
    }

    #[test]
    fn test_detected_os_affects_recommendations() {
        let findings = ReconFindings {
            target: "192.168.1.1".to_string(),
            detected_os: Some(DetectedOS::Windows),
            ports: vec![make_port(445)],
            ..Default::default()
        };

        let result = recommend_playbooks(&findings);

        // Windows privesc should be recommended
        let win_rec = result.recommendations.iter()
            .find(|r| r.playbook_id == "windows-privesc");

        assert!(win_rec.is_some(), "Should recommend windows-privesc for Windows host");
    }

    #[test]
    fn test_fingerprint_matching() {
        let findings = ReconFindings {
            target: "192.168.1.1".to_string(),
            ports: vec![make_port(80)],
            fingerprints: vec!["WordPress 5.8".to_string()],
            ..Default::default()
        };

        let result = recommend_playbooks(&findings);

        let wp_rec = result.recommendations.iter()
            .find(|r| r.playbook_id == "web-app-assessment");

        assert!(wp_rec.is_some());
        assert!(wp_rec.unwrap().reasons.iter().any(|r| r.contains("WordPress")));
    }

    #[test]
    fn test_internal_network_recommendations() {
        let findings = ReconFindings {
            target: "10.0.0.1".to_string(),
            is_internal: true,
            ports: vec![make_port(445), make_port(22)],
            ..Default::default()
        };

        let result = recommend_playbooks(&findings);

        let internal_rec = result.recommendations.iter()
            .find(|r| r.playbook_id == "internal-recon");

        assert!(internal_rec.is_some(), "Should recommend internal-recon for internal network");
    }

    #[test]
    fn test_risk_level_filtering() {
        let findings = ReconFindings {
            target: "192.168.1.1".to_string(),
            ports: vec![make_port(22), make_port(80)],
            ..Default::default()
        };

        // Low risk only
        let result = PlaybookRecommender::new()
            .with_max_risk(RiskLevel::Low)
            .recommend(&findings);

        for rec in &result.recommendations {
            assert!(rec.risk_level <= RiskLevel::Low,
                "Playbook {} has risk {:?} above Low", rec.playbook_id, rec.risk_level);
        }
    }

    #[test]
    fn test_summary_statistics() {
        let findings = ReconFindings {
            target: "192.168.1.1".to_string(),
            ports: vec![make_port(22), make_port(80), make_port(445)],
            vulns: vec![make_vuln("CVE-2024-0001", Severity::Critical)],
            ..Default::default()
        };

        let result = recommend_playbooks(&findings);

        assert!(result.summary.total_matched > 0);
        assert!(result.summary.has_critical_findings);
        assert!(result.summary.top_recommendation.is_some());
    }

    #[test]
    fn test_recommendations_are_sorted_by_score() {
        let findings = ReconFindings {
            target: "192.168.1.1".to_string(),
            ports: vec![make_port(22), make_port(80), make_port(443), make_port(445)],
            fingerprints: vec!["WordPress".to_string()],
            ..Default::default()
        };

        let result = recommend_playbooks(&findings);

        // Verify descending order
        for i in 1..result.recommendations.len() {
            assert!(result.recommendations[i-1].score >= result.recommendations[i].score,
                "Recommendations should be sorted by score descending");
        }
    }
}
