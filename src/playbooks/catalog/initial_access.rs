//! Initial Access Playbooks
//!
//! Playbooks for gaining initial access: web app assessment, external footprint, SSH testing.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

/// Web Application Security Assessment
///
/// Comprehensive web application security testing.
pub fn web_app_assessment() -> Playbook {
  Playbook::new("web-app-assessment", "Web Application Security Assessment")
        .with_description("Comprehensive security assessment of web applications")
        .with_objective("Identify vulnerabilities in web applications including injection, auth issues, and misconfigurations")
        .for_target(TargetType::WebApp)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Medium)
        .with_duration("2-4 hours")
        .with_mitre("T1190") // Exploit Public-Facing Application
        .add_precondition(PreCondition::new("Target URL accessible"))
        .add_precondition(PreCondition::new("Authorization for testing confirmed"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Technology Fingerprinting")
                .with_description("Identify web technologies and frameworks")
                .with_command("rb web asset headers {{ target }}")
                .with_success("Technologies identified")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1592.002", None), // Software Discovery
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Directory Discovery")
                .with_description("Find hidden paths and files")
                .with_command("rb web fuzz {{ target }} --wordlist common")
                .with_success("Directories enumerated")
                .parallel(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1595.002", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Recon, "Parameter Discovery")
                .with_description("Crawl application and identify parameters")
                .with_command("rb web crawl {{ target }} --depth 3")
                .with_success("Parameters and forms discovered")
                .parallel(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1595.002", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::InitialAccess, "Injection Testing")
                .with_description("Test for SQL injection and other injections")
                .with_command("rb web fuzz {{ target }} --wordlist sqli")
                .with_success("Injection points identified")
                .depends(3)
                .collects(EvidenceType::Vulnerability)
                .with_mitre("T1190", None),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::InitialAccess, "Authentication Testing")
                .with_description("Test authentication mechanisms")
                .with_manual("Test default creds, weak passwords, session handling")
                .with_success("Auth weaknesses documented")
                .collects(EvidenceType::Vulnerability)
                .with_mitre("T1078", None), // Valid Accounts
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::InitialAccess, "Security Headers Check")
                .with_description("Analyze security headers")
                .with_command("rb web asset security {{ target }}")
                .with_success("Security posture assessed")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1592.002", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Web vulnerabilities")
                .at("Application responses")
                .with_indicator("Error messages, injection responses, misconfigurations")
                .severity(FindingSeverity::High),
        )
        .add_failed_control(
            FailedControl::new("Input Validation", "Application vulnerable to injection attacks")
                .with_fix("Implement parameterized queries and input validation"),
        )
        .with_kill_chain(KillChainPhase::Reconnaissance())
        .with_kill_chain(KillChainPhase::Exploitation())
}

/// External Footprint Mapping
///
/// Maps the external attack surface of an organization.
pub fn external_footprint() -> Playbook {
  Playbook::new("external-footprint", "External Footprint Mapping")
    .with_description(
      "Map the external attack surface including domains, IPs, and exposed services",
    )
    .with_objective("Create comprehensive inventory of externally accessible assets")
    .for_target(TargetType::Domain)
    .for_os(TargetOS::Any)
    .with_risk(RiskLevel::Low)
    .with_duration("1-3 hours")
    .with_mitre("T1595") // Active Scanning
    .with_mitre("T1592") // Gather Victim Host Info
    .add_precondition(PreCondition::new("Target domain identified"))
    .add_step(
      PlaybookStep::new(1, PlaybookPhase::Recon, "WHOIS Lookup")
        .with_description("Gather domain registration information")
        .with_command("rb recon domain whois {{ target }}")
        .with_success("Registration details obtained")
        .parallel(1)
        .collects(EvidenceType::SystemInfo)
        .with_mitre("T1596.002", None), // WHOIS/DNS Info
    )
    .add_step(
      PlaybookStep::new(2, PlaybookPhase::Recon, "DNS Enumeration")
        .with_description("Enumerate DNS records")
        .with_command("rb dns record lookup {{ target }} --type ALL")
        .with_success("DNS records mapped")
        .parallel(1)
        .collects(EvidenceType::NetworkMap)
        .with_mitre("T1596.001", None), // DNS/Passive DNS
    )
    .add_step(
      PlaybookStep::new(3, PlaybookPhase::Recon, "Subdomain Discovery")
        .with_description("Find subdomains using passive and active methods")
        .with_command("rb recon domain subdomains {{ target }}")
        .with_success("Subdomains enumerated")
        .parallel(1)
        .collects(EvidenceType::NetworkMap)
        .with_mitre("T1595.002", None),
    )
    .add_step(
      PlaybookStep::new(4, PlaybookPhase::Recon, "Port Scanning")
        .with_description("Scan for open ports on discovered hosts")
        .with_command("rb network ports scan {{ hosts }} --preset common")
        .with_success("Open ports identified")
        .depends(3)
        .collects(EvidenceType::NetworkMap)
        .with_mitre("T1046", None), // Network Service Scanning
    )
    .add_step(
      PlaybookStep::new(5, PlaybookPhase::Recon, "Service Identification")
        .with_description("Identify services and versions")
        .with_command("rb network ports scan {{ hosts }} --banner")
        .with_success("Services identified")
        .depends(4)
        .collects(EvidenceType::SystemInfo)
        .with_mitre("T1046", None),
    )
    .add_evidence(
      ExpectedEvidence::new("Attack surface inventory")
        .at("Scan results")
        .with_indicator("Complete list of domains, IPs, ports, services")
        .severity(FindingSeverity::Info),
    )
    .add_failed_control(
      FailedControl::new("Asset Inventory", "Unknown external assets discovered")
        .with_fix("Implement continuous asset discovery and inventory management"),
    )
    .with_kill_chain(KillChainPhase::Reconnaissance())
}

/// SSH Credential Testing
///
/// Tests SSH authentication for weak or default credentials.
pub fn ssh_credential_test() -> Playbook {
  Playbook::new("ssh-credential-test", "SSH Credential Testing")
        .with_description("Test SSH services for weak, default, or reused credentials")
        .with_objective("Identify SSH services with weak authentication that could be exploited")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Linux)
        .with_risk(RiskLevel::Medium)
        .with_duration("15-60 minutes")
        .with_mitre("T1110") // Brute Force
        .with_mitre("T1021.004") // SSH
        .add_precondition(PreCondition::new("SSH service running on target (port 22)"))
        .add_precondition(PreCondition::new("Authorization for credential testing"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "SSH Banner Grab")
                .with_description("Identify SSH version and configuration")
                .with_command("rb network ports scan {{ target }} 22 --banner")
                .with_success("SSH version identified")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1046", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Enumerate Users")
                .with_description("Enumerate valid usernames if possible")
                .with_command("rb exploit run ssh-enum {{ target }}")
                .with_success("Usernames enumerated")
                .optional()
                .depends(1)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1087.001", None), // Account Discovery: Local
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::CredentialAccess, "Default Credential Test")
                .with_description("Test common default credentials")
                .with_command("rb password spray {{ target }} --service ssh --wordlist default-creds")
                .with_success("Valid default credentials found")
                .depends(1)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1078.001", None), // Default Accounts
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::CredentialAccess, "Password Spray")
                .with_description("Test common passwords against identified users")
                .with_command("rb password spray {{ target }} --service ssh --users {{ users }} --wordlist common-passwords")
                .with_success("Weak credentials identified")
                .depends(2)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1110.003", None), // Password Spraying
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::InitialAccess, "Validate Access")
                .with_description("Verify SSH access with discovered credentials")
                .with_manual("ssh {{ user }}@{{ target }} with discovered password")
                .with_success("SSH access confirmed")
                .when(StepCondition::OnSuccess(3))
                .collects(EvidenceType::SessionData)
                .with_mitre("T1021.004", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Valid SSH credentials")
                .at("Credential spray results")
                .with_indicator("Username:password combinations that work")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new("Password Policy", "Weak or default SSH passwords in use")
                .with_fix("Enforce strong password policy, use key-based authentication"),
        )
        .add_failed_control(
            FailedControl::new("Account Lockout", "No lockout after failed attempts")
                .with_fix("Implement fail2ban or similar brute-force protection"),
        )
        .with_kill_chain(KillChainPhase::Exploitation())
}
