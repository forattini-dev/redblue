/// MITRE ATT&CK APT Group Playbooks
///
/// Pre-built playbooks based on real APT group TTPs extracted from MITRE ATT&CK v18.1.
/// These playbooks simulate adversary behavior for purple team exercises.
///
/// ## Available APT Playbooks
///
/// - `apt28` - Russia GRU (Fancy Bear)
/// - `apt29` - Russia SVR (Cozy Bear)
/// - `apt3` - China MSS (Gothic Panda)
/// - `apt32` - Vietnam (OceanLotus)
/// - `apt41` - China (Wicked Panda)
/// - `fin7` - Financially motivated (Carbanak)
/// - `kimsuky` - North Korea (Velvet Chollima)
/// - `lazarus-group` - North Korea (HIDDEN COBRA)
/// - `muddywater` - Iran MOIS
/// - `oilrig` - Iran (APT34)
/// - `sandworm-team` - Russia GRU (BlackEnergy)
/// - `scattered-spider` - Financially motivated
/// - `turla` - Russia FSB (Waterbug)
/// - `volt-typhoon` - China (BRONZE SILHOUETTE)
/// - `wizard-spider` - Russia (TrickBot/Ryuk)
///
/// **IMPORTANT**: These playbooks are for authorized security testing ONLY.
/// Unauthorized use is illegal and unethical.
use super::types::*;
use crate::scripts::FindingSeverity;

/// Get all APT playbooks
pub fn all_apt_playbooks() -> Vec<Playbook> {
    vec![
        apt28(),
        apt29(),
        apt3(),
        apt32(),
        apt41(),
        fin7(),
        kimsuky(),
        lazarus_group(),
        muddywater(),
        oilrig(),
        sandworm_team(),
        scattered_spider(),
        turla(),
        volt_typhoon(),
        wizard_spider(),
    ]
}

/// Get APT playbook by group name or alias
pub fn get_apt_playbook(name: &str) -> Option<Playbook> {
    let name_lower = name.to_lowercase();
    all_apt_playbooks().into_iter().find(|p| {
        p.metadata.id.to_lowercase() == name_lower
            || p.metadata.name.to_lowercase().contains(&name_lower)
    })
}

/// List all APT group names
pub fn list_apt_groups() -> Vec<(&'static str, &'static str)> {
    vec![
        ("apt28", "APT28"),
        ("apt29", "APT29"),
        ("apt3", "APT3"),
        ("apt32", "APT32"),
        ("apt41", "APT41"),
        ("fin7", "FIN7"),
        ("kimsuky", "Kimsuky"),
        ("lazarus-group", "Lazarus Group"),
        ("muddywater", "MuddyWater"),
        ("oilrig", "OilRig"),
        ("sandworm-team", "Sandworm Team"),
        ("scattered-spider", "Scattered Spider"),
        ("turla", "Turla"),
        ("volt-typhoon", "Volt Typhoon"),
        ("wizard-spider", "Wizard Spider"),
    ]
}

// =============================================================================
// APT28 Playbook
// =============================================================================

/// APT28 - Adversary Emulation Playbook
///
/// Aliases: APT28, IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74
/// Techniques: 91
pub fn apt28() -> Playbook {
    Playbook::new("apt28", "APT28 Adversary Emulation")
        .with_description("APT28 is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special S...")
        .with_objective("Emulate APT28 TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1048.002")
        .with_mitre("T1596")
        .with_mitre("T1203")
        .with_mitre("T1090.002")
        .with_mitre("T1039")
        .with_mitre("T1105")
        .with_mitre("T1550.002")
        .with_mitre("T1583.001")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("APT28: Credentials, Gather Victim Org Informa, Search Open Technica")
                .with_manual("Emulate: Credentials")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1589.001", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("APT28: Virtual Private Server, Domains, Email Accounts")
                .with_manual("Emulate: Virtual Private Server")
                .with_success("Resource Development phase completed")
                .with_mitre("T1583.003", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("APT28: Spearphishing Attachment, Exploit Public-Facing App, Wi-Fi N")
                .with_manual("Emulate: Spearphishing Attachment")
                .with_success("Initial Access phase completed")
                .with_mitre("T1566.001", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("APT28: PowerShell, Exploitation for Client E, Windows Command Shell")
                .with_manual("Emulate: PowerShell")
                .with_success("Execution phase completed")
                .with_mitre("T1059.001", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("APT28: Registry Run Keys / Start, Web Shell, Logon Script (Windows)")
                .with_manual("Emulate: Registry Run Keys / Startup Folder")
                .with_success("Persistence phase completed")
                .with_mitre("T1547.001", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("APT28: Registry Run Keys / Start, Logon Script (Windows), Component")
                .with_manual("Emulate: Registry Run Keys / Startup Folder")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1547.001", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("APT28: Hidden Files and Director, Timestomp, Encrypted/Encoded File")
                .with_manual("Emulate: Hidden Files and Directories")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1564.001", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("APT28: NTDS, Keylogging, Password Guessing")
                .with_manual("Emulate: NTDS")
                .with_success("Credential Access phase completed")
                .with_mitre("T1003.003", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("APT28: File and Directory Discov, Process Discovery, Peripheral Dev")
                .with_manual("Emulate: File and Directory Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1083", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("APT28: Pass the Hash, Exploitation of Remote Se, Application Access")
                .with_manual("Emulate: Pass the Hash")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1550.002", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching APT28 TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "APT28 techniques not triggering alerts"
            ).with_fix("Update detection rules to cover APT28 TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// APT29 Playbook
// =============================================================================

/// APT29 - Adversary Emulation Playbook
///
/// Aliases: APT29, IRON RITUAL, IRON HEMLOCK, NobleBaron, Dark Halo
/// Techniques: 66
pub fn apt29() -> Playbook {
    Playbook::new("apt29", "APT29 Adversary Emulation")
        .with_description("APT29 is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Cost...")
        .with_objective("Emulate APT29 TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1027.006")
        .with_mitre("T1133")
        .with_mitre("T1203")
        .with_mitre("T1528")
        .with_mitre("T1105")
        .with_mitre("T1587.003")
        .with_mitre("T1621")
        .with_mitre("T1053.005")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("APT29: Vulnerability Scanning")
                .with_manual("Emulate: Vulnerability Scanning")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1595.002", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("APT29: Tool, Digital Certificates, Malware")
                .with_manual("Emulate: Tool")
                .with_success("Resource Development phase completed")
                .with_mitre("T1588.002", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("APT29: Spearphishing Attachment, Cloud Accounts, External Remote Se")
                .with_manual("Emulate: Spearphishing Attachment")
                .with_success("Initial Access phase completed")
                .with_mitre("T1566.001", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("APT29: Cloud Administration Comm, Scheduled Task, Exploitation for ")
                .with_manual("Emulate: Cloud Administration Command")
                .with_success("Execution phase completed")
                .with_mitre("T1651", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("APT29: Windows Management Instru, Registry Run Keys / Start, Cloud ")
                .with_manual("Emulate: Windows Management Instrumentation ")
                .with_success("Persistence phase completed")
                .with_mitre("T1546.003", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("APT29: Exploitation for Privileg, Windows Management Instru, Regist")
                .with_manual("Emulate: Exploitation for Privilege Escalati")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1068", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("APT29: Cloud Accounts, HTML Smuggling, File Deletion")
                .with_manual("Emulate: Cloud Accounts")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1078.004", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("APT29: Multi-Factor Authenticati, Security Account Manager, Steal A")
                .with_manual("Emulate: Multi-Factor Authentication Request")
                .with_success("Credential Access phase completed")
                .with_mitre("T1621", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("APT29: Internet Connection Disco, Cloud Account")
                .with_manual("Emulate: Internet Connection Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1016.001", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("APT29: Pass the Ticket, Cloud Services")
                .with_manual("Emulate: Pass the Ticket")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1550.003", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching APT29 TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "APT29 techniques not triggering alerts"
            ).with_fix("Update detection rules to cover APT29 TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// APT3 Playbook
// =============================================================================

/// APT3 - Adversary Emulation Playbook
///
/// Aliases: APT3, Gothic Panda, Pirpi, UPS Team, Buckeye
/// Techniques: 44
pub fn apt3() -> Playbook {
    Playbook::new("apt3", "APT3 Adversary Emulation")
        .with_description("APT3 is a China-based threat group that researchers have attributed to China's Ministry of State Security.(Citation: FireEye Cland...")
        .with_objective("Emulate APT3 TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1566.002")
        .with_mitre("T1041")
        .with_mitre("T1090.002")
        .with_mitre("T1074.001")
        .with_mitre("T1053.005")
        .with_mitre("T1564.003")
        .with_mitre("T1049")
        .with_mitre("T1005")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("APT3: Spearphishing Link, Domain Accounts")
                .with_manual("Emulate: Spearphishing Link")
                .with_success("Initial Access phase completed")
                .with_mitre("T1566.002", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Execution, "Execution")
                .with_description("APT3: Scheduled Task, Windows Command Shell, Malicious Link")
                .with_manual("Emulate: Scheduled Task")
                .with_success("Execution phase completed")
                .with_mitre("T1053.005", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Persistence, "Persistence")
                .with_description("APT3: Scheduled Task, Additional Local or Domai, Domain Accounts")
                .with_manual("Emulate: Scheduled Task")
                .with_success("Persistence phase completed")
                .with_mitre("T1053.005", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("APT3: Scheduled Task, Additional Local or Domai, Domain Accounts")
                .with_manual("Emulate: Scheduled Task")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1053.005", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("APT3: Hidden Window, Rundll32, Obfuscated Files or Infor")
                .with_manual("Emulate: Hidden Window")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1564.003", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("APT3: Password Cracking, Credentials from Web Brow, Credentials In")
                .with_manual("Emulate: Password Cracking")
                .with_success("Credential Access phase completed")
                .with_mitre("T1110.002", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::Discovery, "Discovery")
                .with_description("APT3: System Network Configurat, System Network Connection, Local ")
                .with_manual("Emulate: System Network Configuration Discov")
                .with_success("Discovery phase completed")
                .with_mitre("T1016", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("APT3: SMB/Windows Admin Shares, Remote Desktop Protocol")
                .with_manual("Emulate: SMB/Windows Admin Shares")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.002", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Collection, "Collection")
                .with_description("APT3: Local Data Staging, Data from Local System, Archive via Util")
                .with_manual("Emulate: Local Data Staging")
                .with_success("Collection phase completed")
                .with_mitre("T1074.001", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::C2, "Command And Control")
                .with_description("APT3: Multi-Stage Channels, External Proxy, Non-Application Layer ")
                .with_manual("Emulate: Multi-Stage Channels")
                .with_success("Command And Control phase completed")
                .with_mitre("T1104", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching APT3 TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "APT3 techniques not triggering alerts"
            ).with_fix("Update detection rules to cover APT3 TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// APT32 Playbook
// =============================================================================

/// APT32 - Adversary Emulation Playbook
///
/// Aliases: APT32, SeaLotus, OceanLotus, APT-C-00, Canvas Cyclone
/// Techniques: 78
pub fn apt32() -> Playbook {
    Playbook::new("apt32", "APT32 Adversary Emulation")
        .with_description("APT32 is a suspected Vietnam-based threat group that has been active since at least 2014. The group has targeted multiple private ...")
        .with_objective("Emulate APT32 TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1566.002")
        .with_mitre("T1571")
        .with_mitre("T1041")
        .with_mitre("T1598.003")
        .with_mitre("T1589")
        .with_mitre("T1608.001")
        .with_mitre("T1550.002")
        .with_mitre("T1552.002")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("APT32: Spearphishing Link, Gather Victim Identity In, Email Address")
                .with_manual("Emulate: Spearphishing Link")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1598.003", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("APT32: Domains, Drive-by Target, Upload Malware")
                .with_manual("Emulate: Domains")
                .with_success("Resource Development phase completed")
                .with_mitre("T1583.001", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("APT32: Spearphishing Attachment, Spearphishing Link, Local Accounts")
                .with_manual("Emulate: Spearphishing Attachment")
                .with_success("Initial Access phase completed")
                .with_mitre("T1566.001", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("APT32: JavaScript, Windows Management Instru, Software Deployment T")
                .with_manual("Emulate: JavaScript")
                .with_success("Execution phase completed")
                .with_mitre("T1059.007", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("APT32: DLL, Local Accounts, Modify Registry")
                .with_manual("Emulate: DLL")
                .with_success("Persistence phase completed")
                .with_mitre("T1574.001", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("APT32: Process Injection, DLL, Local Accounts")
                .with_manual("Emulate: Process Injection")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1055", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("APT32: Pass the Hash, Masquerading, NTFS File Attributes")
                .with_manual("Emulate: Pass the Hash")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1550.002", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("APT32: Credentials in Registry, LSASS Memory, OS Credential Dumping")
                .with_manual("Emulate: Credentials in Registry")
                .with_success("Credential Access phase completed")
                .with_mitre("T1552.002", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("APT32: Network Share Discovery, System Owner/User Discove, System I")
                .with_manual("Emulate: Network Share Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1135", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("APT32: Pass the Hash, Software Deployment Tools, Lateral Tool Trans")
                .with_manual("Emulate: Pass the Hash")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1550.002", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching APT32 TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "APT32 techniques not triggering alerts"
            ).with_fix("Update detection rules to cover APT32 TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// APT41 Playbook
// =============================================================================

/// APT41 - Adversary Emulation Playbook
///
/// Aliases: APT41, Wicked Panda, Brass Typhoon, BARIUM
/// Techniques: 82
pub fn apt41() -> Playbook {
    Playbook::new("apt41", "APT41 Adversary Emulation")
        .with_description("APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group that also conducts financially-m...")
        .with_objective("Emulate APT41 TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1069")
        .with_mitre("T1133")
        .with_mitre("T1110")
        .with_mitre("T1562.006")
        .with_mitre("T1550.002")
        .with_mitre("T1053.005")
        .with_mitre("T1014")
        .with_mitre("T1005")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("APT41: Wordlist Scanning, Scan Databases, Vulnerability Scanning")
                .with_manual("Emulate: Wordlist Scanning")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1595.003", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("APT41: Tool")
                .with_manual("Emulate: Tool")
                .with_success("Resource Development phase completed")
                .with_mitre("T1588.002", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("APT41: Valid Accounts, Compromise Software Suppl, External Remote S")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Initial Access phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("APT41: PowerShell, Scheduled Task, Windows Command Shell")
                .with_manual("Emulate: PowerShell")
                .with_success("Execution phase completed")
                .with_mitre("T1059.001", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("APT41: Valid Accounts, Windows Service, Additional Local or Domai")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Persistence phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("APT41: Valid Accounts, Windows Service, Additional Local or Domai")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("APT41: Valid Accounts, Indicator Blocking, Rootkit")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("APT41: Credentials from Web Brow, Brute Force, Security Account Man")
                .with_manual("Emulate: Credentials from Web Browsers")
                .with_success("Credential Access phase completed")
                .with_mitre("T1555.003", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("APT41: System Information Discov, Permission Groups Discove, Domain")
                .with_manual("Emulate: System Information Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1082", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("APT41: SMB/Windows Admin Shares, Pass the Hash, Remote Desktop Prot")
                .with_manual("Emulate: SMB/Windows Admin Shares")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.002", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching APT41 TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "APT41 techniques not triggering alerts"
            ).with_fix("Update detection rules to cover APT41 TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// FIN7 Playbook
// =============================================================================

/// FIN7 - Adversary Emulation Playbook
///
/// Aliases: FIN7, GOLD NIAGARA, ITG14, Carbon Spider, ELBRUS
/// Techniques: 67
pub fn fin7() -> Playbook {
    Playbook::new("fin7", "FIN7 Adversary Emulation")
        .with_description("FIN7 is a financially-motivated threat group that has been active since 2013. FIN7 has targeted the retail, restaurant, hospitalit...")
        .with_objective("Emulate FIN7 TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1558.003")
        .with_mitre("T1583.006")
        .with_mitre("T1566.002")
        .with_mitre("T1571")
        .with_mitre("T1608.005")
        .with_mitre("T1125")
        .with_mitre("T1572")
        .with_mitre("T1059")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("FIN7: Gather Victim Org Informa, Identify Roles")
                .with_manual("Emulate: Gather Victim Org Information")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1591", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("FIN7: Link Target, Tool, Web Services")
                .with_manual("Emulate: Link Target")
                .with_success("Resource Development phase completed")
                .with_mitre("T1608.005", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("FIN7: Valid Accounts, Exploit Public-Facing App, Spearphishing Lin")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Initial Access phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("FIN7: Malicious Link, Command and Scripting Int, Scheduled Task")
                .with_manual("Emulate: Malicious Link")
                .with_success("Execution phase completed")
                .with_mitre("T1204.001", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("FIN7: Valid Accounts, Scheduled Task, Application Shimming")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Persistence phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("FIN7: Valid Accounts, Scheduled Task, Application Shimming")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("FIN7: Code Signing, Valid Accounts, Junk Code Insertion")
                .with_manual("Emulate: Code Signing")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1553.002", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("FIN7: Kerberoasting")
                .with_manual("Emulate: Kerberoasting")
                .with_success("Credential Access phase completed")
                .with_mitre("T1558.003", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("FIN7: System Owner/User Discove, Domain Groups, User Activity Base")
                .with_manual("Emulate: System Owner/User Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1033", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("FIN7: SSH, VNC, Remote Desktop Protocol")
                .with_manual("Emulate: SSH")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.004", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching FIN7 TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "FIN7 techniques not triggering alerts"
            ).with_fix("Update detection rules to cover FIN7 TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// Kimsuky Playbook
// =============================================================================

/// Kimsuky - Adversary Emulation Playbook
///
/// Aliases: Kimsuky, Black Banshee, Velvet Chollima, Emerald Sleet, THALLIUM
/// Techniques: 109
pub fn kimsuky() -> Playbook {
    Playbook::new("kimsuky", "Kimsuky Adversary Emulation")
        .with_description("Kimsuky is a North Korea-based cyber espionage group that has been active since at least 2012. The group initially targeted South ...")
        .with_objective("Emulate Kimsuky TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1040")
        .with_mitre("T1593.001")
        .with_mitre("T1566.002")
        .with_mitre("T1539")
        .with_mitre("T1585.002")
        .with_mitre("T1041")
        .with_mitre("T1546.001")
        .with_mitre("T1111")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("Kimsuky: Phishing for Information, Social Media, Employee Names")
                .with_manual("Emulate: Phishing for Information")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1598", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("Kimsuky: Malware, Acquire Infrastructure, Email Accounts")
                .with_manual("Emulate: Malware")
                .with_success("Resource Development phase completed")
                .with_mitre("T1587.001", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("Kimsuky: Phishing, Spearphishing Link, Local Accounts")
                .with_manual("Emulate: Phishing")
                .with_success("Initial Access phase completed")
                .with_mitre("T1566", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("Kimsuky: Malicious File, Malicious Link, Windows Command Shell")
                .with_manual("Emulate: Malicious File")
                .with_success("Execution phase completed")
                .with_mitre("T1204.002", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("Kimsuky: Local Accounts, Browser Extensions, Local Account")
                .with_manual("Emulate: Local Accounts")
                .with_success("Persistence phase completed")
                .with_mitre("T1078.003", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("Kimsuky: Local Accounts, Change Default File Assoc, Process Injection")
                .with_manual("Emulate: Local Accounts")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1078.003", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("Kimsuky: Local Accounts, Deobfuscate/Decode Files , Command Obfuscati")
                .with_manual("Emulate: Local Accounts")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1078.003", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("Kimsuky: Network Sniffing, Steal Web Session Cookie, Multi-Factor Aut")
                .with_manual("Emulate: Network Sniffing")
                .with_success("Credential Access phase completed")
                .with_mitre("T1040", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("Kimsuky: Network Sniffing, Query Registry, System Service Discovery")
                .with_manual("Emulate: Network Sniffing")
                .with_success("Discovery phase completed")
                .with_mitre("T1040", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("Kimsuky: Remote Desktop Protocol, Internal Spearphishing, Pass the Ha")
                .with_manual("Emulate: Remote Desktop Protocol")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.001", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching Kimsuky TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "Kimsuky techniques not triggering alerts"
            ).with_fix("Update detection rules to cover Kimsuky TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// Lazarus Group Playbook
// =============================================================================

/// Lazarus Group - Adversary Emulation Playbook
///
/// Aliases: Lazarus Group, Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC
/// Techniques: 93
pub fn lazarus_group() -> Playbook {
    Playbook::new("lazarus-group", "Lazarus Group Adversary Emulation")
        .with_description("Lazarus Group is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau (RGB). (Citatio...")
        .with_objective("Emulate Lazarus Group TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1566.002")
        .with_mitre("T1041")
        .with_mitre("T1203")
        .with_mitre("T1557.001")
        .with_mitre("T1010")
        .with_mitre("T1001.003")
        .with_mitre("T1090.002")
        .with_mitre("T1110.003")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("Lazarus Group: Gather Victim Org Informa, Email Addresses")
                .with_manual("Emulate: Gather Victim Org Information")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1591", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("Lazarus Group: Server, Malware, Digital Certificates")
                .with_manual("Emulate: Server")
                .with_success("Resource Development phase completed")
                .with_mitre("T1584.004", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("Lazarus Group: Spearphishing Attachment, Valid Accounts, Spearphishing Link")
                .with_manual("Emulate: Spearphishing Attachment")
                .with_success("Initial Access phase completed")
                .with_mitre("T1566.001", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("Lazarus Group: Windows Command Shell, Native API, Exploitation for Client E")
                .with_manual("Emulate: Windows Command Shell")
                .with_success("Execution phase completed")
                .with_mitre("T1059.003", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("Lazarus Group: Account Manipulation, Valid Accounts, Registry Run Keys / St")
                .with_manual("Emulate: Account Manipulation")
                .with_success("Persistence phase completed")
                .with_mitre("T1098", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("Lazarus Group: Create Process with Token, Account Manipulation, Valid Accou")
                .with_manual("Emulate: Create Process with Token")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1134.002", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("Lazarus Group: Indirect Command Executio, Mshta, Create Process with Token")
                .with_manual("Emulate: Indirect Command Execution")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1202", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("Lazarus Group: LLMNR/NBT-NS Poisoning an, Keylogging, Password Spraying")
                .with_manual("Emulate: LLMNR/NBT-NS Poisoning and SMB Rela")
                .with_success("Credential Access phase completed")
                .with_mitre("T1557.001", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("Lazarus Group: Application Window Discov, Query Registry, Network Service D")
                .with_manual("Emulate: Application Window Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1010", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("Lazarus Group: SSH, Remote Desktop Protocol, SMB/Windows Admin Shares")
                .with_manual("Emulate: SSH")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.004", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching Lazarus Group TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "Lazarus Group techniques not triggering alerts"
            ).with_fix("Update detection rules to cover Lazarus Group TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// MuddyWater Playbook
// =============================================================================

/// MuddyWater - Adversary Emulation Playbook
///
/// Aliases: MuddyWater, Earth Vetala, MERCURY, Static Kitten, Seedworm
/// Techniques: 58
pub fn muddywater() -> Playbook {
    Playbook::new("muddywater", "MuddyWater Adversary Emulation")
        .with_description("MuddyWater is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MO...")
        .with_objective("Emulate MuddyWater TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1548.002")
        .with_mitre("T1583.006")
        .with_mitre("T1137.001")
        .with_mitre("T1566.002")
        .with_mitre("T1041")
        .with_mitre("T1555")
        .with_mitre("T1105")
        .with_mitre("T1074.001")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Resource Development")
                .with_description("MuddyWater: Tool, Web Services")
                .with_manual("Emulate: Tool")
                .with_success("Resource Development phase completed")
                .with_mitre("T1588.002", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("MuddyWater: Spearphishing Link, Spearphishing Attachment, Exploit Public")
                .with_manual("Emulate: Spearphishing Link")
                .with_success("Initial Access phase completed")
                .with_mitre("T1566.002", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Execution, "Execution")
                .with_description("MuddyWater: Windows Management Instru, Component Object Model, Windows C")
                .with_manual("Emulate: Windows Management Instrumentation")
                .with_success("Execution phase completed")
                .with_mitre("T1047", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Persistence, "Persistence")
                .with_description("MuddyWater: Office Template Macros, DLL, Registry Run Keys / Start")
                .with_manual("Emulate: Office Template Macros")
                .with_success("Persistence phase completed")
                .with_mitre("T1137.001", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("MuddyWater: DLL, Registry Run Keys / Start, Bypass User Account Contr")
                .with_manual("Emulate: DLL")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1574.001", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("MuddyWater: DLL, Mshta, CMSTP")
                .with_manual("Emulate: DLL")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1574.001", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("MuddyWater: LSA Secrets, Credentials from Web Brow, Credentials from Pas")
                .with_manual("Emulate: LSA Secrets")
                .with_success("Credential Access phase completed")
                .with_mitre("T1003.004", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::Discovery, "Discovery")
                .with_description("MuddyWater: Domain Account, System Network Configurat, Security Software")
                .with_manual("Emulate: Domain Account")
                .with_success("Discovery phase completed")
                .with_mitre("T1087.002", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("MuddyWater: Exploitation of Remote Se")
                .with_manual("Emulate: Exploitation of Remote Services")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1210", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::Collection, "Collection")
                .with_description("MuddyWater: Local Data Staging, Screen Capture, Archive via Utility")
                .with_manual("Emulate: Local Data Staging")
                .with_success("Collection phase completed")
                .with_mitre("T1074.001", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching MuddyWater TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "MuddyWater techniques not triggering alerts"
            ).with_fix("Update detection rules to cover MuddyWater TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// OilRig Playbook
// =============================================================================

/// OilRig - Adversary Emulation Playbook
///
/// Aliases: OilRig, COBALT GYPSY, IRN2, APT34, Helix Kitten
/// Techniques: 76
pub fn oilrig() -> Playbook {
    Playbook::new("oilrig", "OilRig Adversary Emulation")
        .with_description("OilRig is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The gro...")
        .with_objective("Emulate OilRig TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1566.002")
        .with_mitre("T1025")
        .with_mitre("T1133")
        .with_mitre("T1588.003")
        .with_mitre("T1608.001")
        .with_mitre("T1137.004")
        .with_mitre("T1005")
        .with_mitre("T1071.001")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Resource Development")
                .with_description("OilRig: Code Signing Certificates, Malware, Upload Malware")
                .with_manual("Emulate: Code Signing Certificates")
                .with_success("Resource Development phase completed")
                .with_mitre("T1588.003", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("OilRig: External Remote Services, Domain Accounts, Spearphishing Lin")
                .with_manual("Emulate: External Remote Services")
                .with_success("Initial Access phase completed")
                .with_mitre("T1133", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Execution, "Execution")
                .with_description("OilRig: Windows Command Shell, PowerShell, Malicious File")
                .with_manual("Emulate: Windows Command Shell")
                .with_success("Execution phase completed")
                .with_mitre("T1059.003", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Persistence, "Persistence")
                .with_description("OilRig: Web Shell, Outlook Home Page, Password Filter DLL")
                .with_manual("Emulate: Web Shell")
                .with_success("Persistence phase completed")
                .with_mitre("T1505.003", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("OilRig: Domain Accounts, Windows Service, Valid Accounts")
                .with_manual("Emulate: Domain Accounts")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1078.002", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("OilRig: Masquerading, Compiled HTML File, Password Filter DLL")
                .with_manual("Emulate: Masquerading")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1036", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("OilRig: Windows Credential Manage, LSASS Memory, Password Filter DLL")
                .with_manual("Emulate: Windows Credential Manager")
                .with_success("Credential Access phase completed")
                .with_mitre("T1555.004", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::Discovery, "Discovery")
                .with_description("OilRig: System Information Discov, Network Service Discovery, Local ")
                .with_manual("Emulate: System Information Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1082", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("OilRig: Remote Desktop Protocol, SSH")
                .with_manual("Emulate: Remote Desktop Protocol")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.001", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::Collection, "Collection")
                .with_description("OilRig: Data from Local System, Screen Capture, Data from Removable ")
                .with_manual("Emulate: Data from Local System")
                .with_success("Collection phase completed")
                .with_mitre("T1005", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching OilRig TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "OilRig techniques not triggering alerts"
            ).with_fix("Update detection rules to cover OilRig TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// Sandworm Team Playbook
// =============================================================================

/// Sandworm Team - Adversary Emulation Playbook
///
/// Aliases: Sandworm Team, ELECTRUM, Telebots, IRON VIKING, BlackEnergy (Group)
/// Techniques: 79
pub fn sandworm_team() -> Playbook {
    Playbook::new("sandworm-team", "Sandworm Team Adversary Emulation")
        .with_description("Sandworm Team is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU)...")
        .with_objective("Emulate Sandworm Team TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1040")
        .with_mitre("T1571")
        .with_mitre("T1539")
        .with_mitre("T1041")
        .with_mitre("T1598.003")
        .with_mitre("T1133")
        .with_mitre("T1588.006")
        .with_mitre("T1203")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("Sandworm Team: Vulnerability Scanning, Spearphishing Link, Employee Names")
                .with_manual("Emulate: Vulnerability Scanning")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1595.002", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("Sandworm Team: Upload Malware, Vulnerabilities, Social Media Accounts")
                .with_manual("Emulate: Upload Malware")
                .with_success("Resource Development phase completed")
                .with_mitre("T1608.001", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("Sandworm Team: Exploit Public-Facing App, Domain Accounts, External Remote ")
                .with_manual("Emulate: Exploit Public-Facing Application")
                .with_success("Initial Access phase completed")
                .with_mitre("T1190", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("Sandworm Team: PowerShell, Exploitation for Client E, Scheduled Task")
                .with_manual("Emulate: PowerShell")
                .with_success("Execution phase completed")
                .with_mitre("T1059.001", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("Sandworm Team: Scheduled Task, Domain Accounts, External Remote Services")
                .with_manual("Emulate: Scheduled Task")
                .with_success("Persistence phase completed")
                .with_mitre("T1053.005", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("Sandworm Team: Scheduled Task, Domain Accounts, Valid Accounts")
                .with_manual("Emulate: Scheduled Task")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1053.005", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("Sandworm Team: Command Obfuscation, Domain Accounts, Masquerading")
                .with_manual("Emulate: Command Obfuscation")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1027.010", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("Sandworm Team: Network Sniffing, Steal Web Session Cookie, NTDS")
                .with_manual("Emulate: Network Sniffing")
                .with_success("Credential Access phase completed")
                .with_mitre("T1040", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("Sandworm Team: Network Sniffing, Remote System Discovery, File and Director")
                .with_manual("Emulate: Network Sniffing")
                .with_success("Discovery phase completed")
                .with_mitre("T1040", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("Sandworm Team: Software Deployment Tools, SMB/Windows Admin Shares, Lateral")
                .with_manual("Emulate: Software Deployment Tools")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1072", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching Sandworm Team TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "Sandworm Team techniques not triggering alerts"
            ).with_fix("Update detection rules to cover Sandworm Team TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// Scattered Spider Playbook
// =============================================================================

/// Scattered Spider - Adversary Emulation Playbook
///
/// Aliases: Scattered Spider, Roasted 0ktapus, Octo Tempest, Storm-0875, UNC3944
/// Techniques: 64
pub fn scattered_spider() -> Playbook {
    Playbook::new("scattered-spider", "Scattered Spider Adversary Emulation")
        .with_description("Scattered Spider is a native English-speaking cybercriminal group active since at least 2022. (Citation: CrowdStrike Scattered Spi...")
        .with_objective("Emulate Scattered Spider TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1539")
        .with_mitre("T1556.009")
        .with_mitre("T1580")
        .with_mitre("T1041")
        .with_mitre("T1598.003")
        .with_mitre("T1133")
        .with_mitre("T1585.001")
        .with_mitre("T1589")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("Scattered Spider: Phishing for Information, Spearphishing Link, Gather Victim ")
                .with_manual("Emulate: Phishing for Information")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1598", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("Scattered Spider: Social Media Accounts, Tool, Domains")
                .with_manual("Emulate: Social Media Accounts")
                .with_success("Resource Development phase completed")
                .with_mitre("T1585.001", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("Scattered Spider: Valid Accounts, External Remote Services, Cloud Accounts")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Initial Access phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("Scattered Spider: Unix Shell, User Execution, PowerShell")
                .with_manual("Emulate: Unix Shell")
                .with_success("Execution phase completed")
                .with_mitre("T1059.004", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("Scattered Spider: Conditional Access Polici, Valid Accounts, External Remote S")
                .with_manual("Emulate: Conditional Access Policies")
                .with_success("Persistence phase completed")
                .with_mitre("T1556.009", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("Scattered Spider: Valid Accounts, Trust Modification, Systemd Service")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("Scattered Spider: Code Signing, Conditional Access Polici, Valid Accounts")
                .with_manual("Emulate: Code Signing")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1553.002", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("Scattered Spider: Conditional Access Polici, NTDS, Steal Web Session Cookie")
                .with_manual("Emulate: Conditional Access Policies")
                .with_success("Credential Access phase completed")
                .with_mitre("T1556.009", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("Scattered Spider: Cloud Infrastructure Disc, Domain Account, Account Discovery")
                .with_manual("Emulate: Cloud Infrastructure Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1580", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("Scattered Spider: SSH, Remote Desktop Protocol, Cloud Services")
                .with_manual("Emulate: SSH")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.004", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching Scattered Spider TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "Scattered Spider techniques not triggering alerts"
            ).with_fix("Update detection rules to cover Scattered Spider TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// Turla Playbook
// =============================================================================

/// Turla - Adversary Emulation Playbook
///
/// Aliases: Turla, IRON HUNTER, Group 88, Waterbug, WhiteBear
/// Techniques: 68
pub fn turla() -> Playbook {
    Playbook::new("turla", "Turla Adversary Emulation")
        .with_description("Turla is a cyber espionage threat group that has been attributed to Russia's Federal Security Service (FSB).  They have compromise...")
        .with_objective("Emulate Turla TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1583.006")
        .with_mitre("T1566.002")
        .with_mitre("T1189")
        .with_mitre("T1025")
        .with_mitre("T1546.013")
        .with_mitre("T1110")
        .with_mitre("T1105")
        .with_mitre("T1570")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Resource Development")
                .with_description("Turla: Web Services, Tool, Web Services")
                .with_manual("Emulate: Web Services")
                .with_success("Resource Development phase completed")
                .with_mitre("T1584.006", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("Turla: Drive-by Compromise, Spearphishing Link, Local Accounts")
                .with_manual("Emulate: Drive-by Compromise")
                .with_success("Initial Access phase completed")
                .with_mitre("T1189", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Execution, "Execution")
                .with_description("Turla: JavaScript, Visual Basic, Native API")
                .with_manual("Emulate: JavaScript")
                .with_success("Execution phase completed")
                .with_mitre("T1059.007", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Persistence, "Persistence")
                .with_description("Turla: Modify Registry, PowerShell Profile, Registry Run Keys / Sta")
                .with_manual("Emulate: Modify Registry")
                .with_success("Persistence phase completed")
                .with_mitre("T1112", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("Turla: Create Process with Token, PowerShell Profile, Dynamic-link ")
                .with_manual("Emulate: Create Process with Token")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1134.002", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("Turla: Modify Registry, Deobfuscate/Decode Files , Create Process w")
                .with_manual("Emulate: Modify Registry")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1112", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("Turla: Windows Credential Manage, Brute Force")
                .with_manual("Emulate: Windows Credential Manager")
                .with_success("Credential Access phase completed")
                .with_mitre("T1555.004", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::Discovery, "Discovery")
                .with_description("Turla: Local Groups, Group Policy Discovery, System Network Connect")
                .with_manual("Emulate: Local Groups")
                .with_success("Discovery phase completed")
                .with_mitre("T1069.001", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("Turla: SMB/Windows Admin Shares, Lateral Tool Transfer")
                .with_manual("Emulate: SMB/Windows Admin Shares")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.002", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::Collection, "Collection")
                .with_description("Turla: Data from Local System, Archive via Utility, Data from Remov")
                .with_manual("Emulate: Data from Local System")
                .with_success("Collection phase completed")
                .with_mitre("T1005", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching Turla TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "Turla techniques not triggering alerts"
            ).with_fix("Update detection rules to cover Turla TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// Volt Typhoon Playbook
// =============================================================================

/// Volt Typhoon - Adversary Emulation Playbook
///
/// Aliases: Volt Typhoon, BRONZE SILHOUETTE, Vanguard Panda, DEV-0391, UNC3236
/// Techniques: 81
pub fn volt_typhoon() -> Playbook {
    Playbook::new("volt-typhoon", "Volt Typhoon Adversary Emulation")
        .with_description("Volt Typhoon is a People's Republic of China (PRC) state-sponsored actor that has been active since at least 2021 primarily target...")
        .with_objective("Emulate Volt Typhoon TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1133")
        .with_mitre("T1555")
        .with_mitre("T1584.005")
        .with_mitre("T1047")
        .with_mitre("T1570")
        .with_mitre("T1593")
        .with_mitre("T1074")
        .with_mitre("T1560.001")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Reconnaissance")
                .with_description("Volt Typhoon: Identify Roles, Gather Victim Network Inf, Search Open Websi")
                .with_manual("Emulate: Identify Roles")
                .with_success("Reconnaissance phase completed")
                .with_mitre("T1591.004", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Resource Development")
                .with_description("Volt Typhoon: Server, Network Devices, Botnet")
                .with_manual("Emulate: Server")
                .with_success("Resource Development phase completed")
                .with_mitre("T1584.004", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("Volt Typhoon: Valid Accounts, Exploit Public-Facing App, External Remote S")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Initial Access phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execution")
                .with_description("Volt Typhoon: Windows Command Shell, Windows Management Instru, PowerShell")
                .with_manual("Emulate: Windows Command Shell")
                .with_success("Execution phase completed")
                .with_mitre("T1059.003", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Persistence, "Persistence")
                .with_description("Volt Typhoon: Valid Accounts, External Remote Services, Modify Registry")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Persistence phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("Volt Typhoon: Valid Accounts, Exploitation for Privileg, Domain Accounts")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("Volt Typhoon: Valid Accounts, Match Legitimate Resource, Masquerade File T")
                .with_manual("Emulate: Valid Accounts")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1078", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("Volt Typhoon: Keylogging, Credentials from Password, NTDS")
                .with_manual("Emulate: Keylogging")
                .with_success("Credential Access phase completed")
                .with_mitre("T1056.001", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::Discovery, "Discovery")
                .with_description("Volt Typhoon: Network Service Discovery, File and Directory Discov, Proces")
                .with_manual("Emulate: Network Service Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1046", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("Volt Typhoon: Remote Desktop Protocol, Lateral Tool Transfer")
                .with_manual("Emulate: Remote Desktop Protocol")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1021.001", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching Volt Typhoon TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "Volt Typhoon techniques not triggering alerts"
            ).with_fix("Update detection rules to cover Volt Typhoon TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

// =============================================================================
// Wizard Spider Playbook
// =============================================================================

/// Wizard Spider - Adversary Emulation Playbook
///
/// Aliases: Wizard Spider, UNC1878, TEMP.MixMaster, Grim Spider, FIN12
/// Techniques: 64
pub fn wizard_spider() -> Playbook {
    Playbook::new("wizard-spider", "Wizard Spider Adversary Emulation")
        .with_description("Wizard Spider is a Russia-based financially motivated threat group originally known for the creation and deployment of TrickBot si...")
        .with_objective("Emulate Wizard Spider TTPs to test detection and response capabilities")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("2-4 hours")
        .with_tag("apt")
        .with_tag("adversary-emulation")
        .with_tag("mitre-attack")
        .with_mitre("T1558.003")
        .with_mitre("T1585.002")
        .with_mitre("T1041")
        .with_mitre("T1133")
        .with_mitre("T1557.001")
        .with_mitre("T1588.003")
        .with_mitre("T1105")
        .with_mitre("T1074.001")
        .add_precondition(PreCondition::new("Authorization for adversary emulation confirmed"))
        .add_precondition(PreCondition::new("Scope and rules of engagement defined"))
        .add_precondition(PreCondition::new("Detection tools are being monitored"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Resource Development")
                .with_description("Wizard Spider: Code Signing Certificates, Tool, Email Accounts")
                .with_manual("Emulate: Code Signing Certificates")
                .with_success("Resource Development phase completed")
                .with_mitre("T1588.003", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Initial Access")
                .with_description("Wizard Spider: Domain Accounts, External Remote Services, Valid Accounts")
                .with_manual("Emulate: Domain Accounts")
                .with_success("Initial Access phase completed")
                .with_mitre("T1078.002", None)
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Execution, "Execution")
                .with_description("Wizard Spider: Windows Command Shell, Windows Management Instru, Malicious ")
                .with_manual("Emulate: Windows Command Shell")
                .with_success("Execution phase completed")
                .with_mitre("T1059.003", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Persistence, "Persistence")
                .with_description("Wizard Spider: Local Account, Windows Service, Domain Accounts")
                .with_manual("Emulate: Local Account")
                .with_success("Persistence phase completed")
                .with_mitre("T1136.001", None)
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::PrivilegeEscalation, "Privilege Escalation")
                .with_description("Wizard Spider: Windows Service, Domain Accounts, Process Injection")
                .with_manual("Emulate: Windows Service")
                .with_success("Privilege Escalation phase completed")
                .with_mitre("T1543.003", None)
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::DefenseEvasion, "Defense Evasion")
                .with_description("Wizard Spider: Domain Accounts, Process Injection, Pass the Hash")
                .with_manual("Emulate: Domain Accounts")
                .with_success("Defense Evasion phase completed")
                .with_mitre("T1078.002", None)
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::CredentialAccess, "Credential Access")
                .with_description("Wizard Spider: Group Policy Preferences, Kerberoasting, LLMNR/NBT-NS Poison")
                .with_manual("Emulate: Group Policy Preferences")
                .with_success("Credential Access phase completed")
                .with_mitre("T1552.006", None)
        )
        .add_step(
            PlaybookStep::new(8, PlaybookPhase::Discovery, "Discovery")
                .with_description("Wizard Spider: Security Software Discove, Domain Account, Backup Software D")
                .with_manual("Emulate: Security Software Discovery")
                .with_success("Discovery phase completed")
                .with_mitre("T1518.001", None)
        )
        .add_step(
            PlaybookStep::new(9, PlaybookPhase::LateralMovement, "Lateral Movement")
                .with_description("Wizard Spider: Exploitation of Remote Se, SMB/Windows Admin Shares, Remote ")
                .with_manual("Emulate: Exploitation of Remote Services")
                .with_success("Lateral Movement phase completed")
                .with_mitre("T1210", None)
        )
        .add_step(
            PlaybookStep::new(10, PlaybookPhase::Collection, "Collection")
                .with_description("Wizard Spider: Archive via Utility, Data Staged, Local Data Staging")
                .with_manual("Emulate: Archive via Utility")
                .with_success("Collection phase completed")
                .with_mitre("T1560.001", None)
        )
        .add_evidence(
            ExpectedEvidence::new("Adversary activity detected")
                .at("SIEM/EDR alerts")
                .with_indicator("Behavioral alerts matching Wizard Spider TTPs")
                .severity(FindingSeverity::High)
        )
        .add_evidence(
            ExpectedEvidence::new("Technique execution logged")
                .at("Endpoint logs")
                .with_indicator("Command execution and process creation events")
                .severity(FindingSeverity::Medium)
        )
        .add_failed_control(
            FailedControl::new(
                "Detection Coverage",
                "Wizard Spider techniques not triggering alerts"
            ).with_fix("Update detection rules to cover Wizard Spider TTPs")
        )
        .add_failed_control(
            FailedControl::new(
                "Response Time",
                "Insufficient response to adversary activity"
            ).with_fix("Improve SOC playbooks and response procedures")
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_apt_playbooks_valid() {
        for playbook in all_apt_playbooks() {
            assert!(!playbook.metadata.id.is_empty());
            assert!(!playbook.metadata.name.is_empty());
            assert!(!playbook.steps.is_empty());
            assert!(playbook.metadata.tags.contains(&"apt".to_string()));
        }
    }

    #[test]
    fn test_get_apt_playbook_by_name() {
        assert!(get_apt_playbook("apt29").is_some());
        assert!(get_apt_playbook("lazarus").is_some());
        assert!(get_apt_playbook("fin7").is_some());
        assert!(get_apt_playbook("APT28").is_some());
    }

    #[test]
    fn test_list_apt_groups() {
        let groups = list_apt_groups();
        assert!(groups.len() >= 15);
        assert!(groups.iter().any(|(id, _)| *id == "apt29"));
    }
}
