//! Financially-Motivated Threat Group Playbooks
//!
//! Pre-built playbooks for financially-motivated threat actors.
//!
//! ## Groups
//! - `fin7` - Carbanak / GOLD NIAGARA
//! - `scattered_spider` - Roasted 0ktapus / Octo Tempest

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

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
