//! East Asian APT Groups (Vietnam, North Korea)
//!
//! - APT32 (Vietnam - OceanLotus)
//! - Kimsuky (North Korea)
//! - Lazarus Group (North Korea - HIDDEN COBRA)

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

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
