//! Russian APT Groups
//!
//! - APT28 (GRU)
//! - APT29 (SVR)
//! - Sandworm Team (GRU)
//! - Turla (FSB)
//! - Wizard Spider

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

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
