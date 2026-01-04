//! Chinese APT Groups
//!
//! - APT3 (MSS - Gothic Panda)
//! - APT41 (Wicked Panda)
//! - Volt Typhoon (BRONZE SILHOUETTE)

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

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
