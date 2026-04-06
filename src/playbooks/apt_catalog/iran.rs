//! Iranian APT Group Playbooks
//!
//! Pre-built playbooks for Iranian state-sponsored threat actors.
//!
//! ## Groups
//! - `muddywater` - MOIS (Ministry of Intelligence and Security)
//! - `oilrig` - APT34 / Helix Kitten

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

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
