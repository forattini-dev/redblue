//! Credential Collection Playbooks
//!
//! Playbooks for credential harvesting: config files, memory dumps, browser creds.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

/// Credential Harvesting Assessment
pub fn credential_harvesting() -> Playbook {
    Playbook::new("credential-harvesting", "Credential Harvesting Assessment")
        .with_description("Assess credential exposure and harvesting vectors")
        .with_objective("Identify credentials stored insecurely or exposed in various locations")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("30-90 minutes")
        .with_mitre("T1552")
        .add_precondition(PreCondition::new("Shell access on target system"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Collection, "Config File Search")
                .with_description("Search for credentials in configuration files")
                .with_command("rb code secrets scan /")
                .with_success("Config files with credentials found")
                .with_mitre("T1552.001", None), // Credentials In Files
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Collection, "Environment Variables")
                .with_description("Check for credentials in environment")
                .with_manual("Check: env, printenv, .bashrc, .profile")
                .with_success("Environment credentials documented")
                .with_mitre("T1552.001", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Collection, "Browser Credential Check")
                .with_description("Check for stored browser credentials")
                .with_manual("Check browser credential stores")
                .with_success("Browser credentials identified")
                .with_mitre("T1555.003", None), // Credentials from Web Browsers
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Collection, "SSH Key Discovery")
                .with_description("Search for SSH private keys")
                .with_manual("Search: ~/.ssh/, /home/*/.ssh/, /root/.ssh/")
                .with_success("SSH keys located")
                .with_mitre("T1552.004", None), // Private Keys
        )
        .add_evidence(
            ExpectedEvidence::new("Plaintext credentials")
                .at("Configuration files")
                .with_indicator("API keys, passwords, tokens in plaintext")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new("Secret Management", "Credentials stored in plaintext files")
                .with_fix("Use secrets manager (Vault, AWS Secrets Manager)"),
        )
}

/// Post-Exploitation Credential Harvesting
pub fn credential_harvesting_post() -> Playbook {
    Playbook::new(
        "credential-harvesting-post",
        "Post-Exploitation Credential Harvesting",
    )
    .with_description("Extract credentials from compromised systems")
    .with_objective("Gather credentials for lateral movement and persistence")
    .for_target(TargetType::Host)
    .for_os(TargetOS::Any)
    .with_risk(RiskLevel::High)
    .with_duration("30-60 minutes")
    .with_tag("credentials")
    .with_tag("post-exploitation")
    .with_tag("lateral")
    .with_mitre("T1003")
    .add_precondition(PreCondition::new("Administrative/root access on target"))
    .add_step(
        PlaybookStep::new(1, PlaybookPhase::CredentialAccess, "Memory Dump")
            .with_description("Dump credentials from memory")
            .with_manual("mimikatz sekurlsa::logonpasswords (Windows), proc dump LSASS")
            .with_success("Memory credentials extracted")
            .collects(EvidenceType::Credentials)
            .with_mitre("T1003.001", None),
    )
    .add_step(
        PlaybookStep::new(2, PlaybookPhase::CredentialAccess, "Hash Extraction")
            .with_description("Extract password hashes")
            .with_manual("mimikatz lsadump::sam, /etc/shadow dump")
            .with_success("Password hashes obtained")
            .parallel(1)
            .collects(EvidenceType::Credentials)
            .with_mitre("T1003.002", None),
    )
    .add_step(
        PlaybookStep::new(3, PlaybookPhase::Collection, "Browser Credentials")
            .with_description("Extract saved browser passwords")
            .with_manual("SharpChrome, LaZagne, firefox_decrypt")
            .with_success("Browser credentials extracted")
            .parallel(1)
            .collects(EvidenceType::Credentials)
            .with_mitre("T1555.003", None),
    )
    .add_step(
        PlaybookStep::new(4, PlaybookPhase::Collection, "SSH/API Keys")
            .with_description("Find SSH keys and API tokens")
            .with_command("rb code secrets scan ~")
            .with_success("Keys and tokens collected")
            .collects(EvidenceType::Credentials)
            .with_mitre("T1552.004", None),
    )
    .add_evidence(
        ExpectedEvidence::new("Harvested credentials")
            .at("Credential dump")
            .with_indicator("Plaintext passwords, hashes, keys")
            .severity(FindingSeverity::Critical),
    )
    .add_failed_control(
        FailedControl::new("Credential Protection", "Credentials accessible in memory")
            .with_fix("Enable Credential Guard, use LSA protection, rotate credentials"),
    )
}
