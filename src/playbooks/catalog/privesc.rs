//! Privilege Escalation Playbooks
//!
//! Playbooks for escalating privileges on Linux and Windows systems.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

/// Linux Privilege Escalation Assessment
pub fn linux_privesc_assessment() -> Playbook {
  Playbook::new(
    "linux-privesc-assessment",
    "Linux Privilege Escalation Assessment",
  )
  .with_description("Assess Linux systems for privilege escalation vulnerabilities")
  .with_objective(
    "Identify misconfigurations and vulnerabilities that allow escalation from user to root",
  )
  .for_target(TargetType::Host)
  .for_os(TargetOS::Linux)
  .with_risk(RiskLevel::Medium)
  .with_duration("30-60 minutes")
  .with_mitre("T1548") // Abuse Elevation Control Mechanism
  .add_precondition(PreCondition::new("Shell access as unprivileged user"))
  .add_step(
    PlaybookStep::new(1, PlaybookPhase::Discovery, "System Enumeration")
      .with_description("Gather system information for privilege escalation")
      .with_command("rb exploit assess linux {{ target }}")
      .with_success("System enumerated for privesc vectors")
      .collects(EvidenceType::SystemInfo)
      .with_mitre("T1082", None), // System Information Discovery
  )
  .add_step(
    PlaybookStep::new(2, PlaybookPhase::PrivilegeEscalation, "SUID Binary Check")
      .with_description("Find SUID/SGID binaries")
      .with_manual("find / -perm -4000 -type f 2>/dev/null")
      .with_success("SUID binaries enumerated")
      .parallel(1)
      .collects(EvidenceType::Vulnerability)
      .with_mitre("T1548.001", None), // Setuid and Setgid
  )
  .add_step(
    PlaybookStep::new(3, PlaybookPhase::PrivilegeEscalation, "Sudo Configuration")
      .with_description("Check sudo privileges")
      .with_manual("sudo -l")
      .with_success("Sudo configuration assessed")
      .parallel(1)
      .collects(EvidenceType::Vulnerability)
      .with_mitre("T1548.003", None), // Sudo and Sudo Caching
  )
  .add_step(
    PlaybookStep::new(4, PlaybookPhase::PrivilegeEscalation, "Cron Job Analysis")
      .with_description("Check for writable cron jobs")
      .with_manual("cat /etc/crontab; ls -la /etc/cron.*")
      .with_success("Cron jobs analyzed")
      .collects(EvidenceType::Vulnerability)
      .with_mitre("T1053.003", None), // Cron
  )
  .add_step(
    PlaybookStep::new(
      5,
      PlaybookPhase::PrivilegeEscalation,
      "Kernel Vulnerability Check",
    )
    .with_description("Check for applicable kernel exploits")
    .with_manual("uname -a; check kernel exploit databases")
    .with_success("Kernel vulnerabilities assessed")
    .optional()
    .collects(EvidenceType::Vulnerability)
    .with_mitre("T1068", None), // Exploitation for Privilege Escalation
  )
  .add_evidence(
    ExpectedEvidence::new("Privilege escalation vector")
      .at("Enumeration output")
      .with_indicator("Exploitable SUID, sudo rule, or misconfiguration")
      .severity(FindingSeverity::High),
  )
  .add_failed_control(
    FailedControl::new("Least Privilege", "Users have excessive privileges")
      .with_fix("Review and restrict sudo access, audit SUID binaries"),
  )
  .with_kill_chain(KillChainPhase::Exploitation())
}

/// Windows Privilege Escalation Assessment
pub fn windows_privesc_assessment() -> Playbook {
  Playbook::new(
    "windows-privesc-assessment",
    "Windows Privilege Escalation Assessment",
  )
  .with_description("Assess Windows systems for privilege escalation vulnerabilities")
  .with_objective("Identify misconfigurations allowing escalation from user to SYSTEM/Admin")
  .for_target(TargetType::Host)
  .for_os(TargetOS::Windows)
  .with_risk(RiskLevel::Medium)
  .with_duration("30-60 minutes")
  .with_mitre("T1548") // Abuse Elevation Control Mechanism
  .add_precondition(PreCondition::new("Shell access as unprivileged user"))
  .add_step(
    PlaybookStep::new(1, PlaybookPhase::Discovery, "System Enumeration")
      .with_description("Gather Windows system information")
      .with_manual("systeminfo; whoami /all; net user")
      .with_success("System information gathered")
      .collects(EvidenceType::SystemInfo)
      .with_mitre("T1082", None),
  )
  .add_step(
    PlaybookStep::new(2, PlaybookPhase::PrivilegeEscalation, "Service Enumeration")
      .with_description("Check for vulnerable services")
      .with_manual("wmic service get name,displayname,pathname,startmode")
      .with_success("Services enumerated")
      .parallel(1)
      .collects(EvidenceType::Vulnerability)
      .with_mitre("T1574.011", None), // Services Registry Permissions Weakness
  )
  .add_step(
    PlaybookStep::new(
      3,
      PlaybookPhase::PrivilegeEscalation,
      "Unquoted Service Paths",
    )
    .with_description("Find unquoted service paths")
    .with_manual("Look for services with spaces in unquoted paths")
    .with_success("Unquoted paths identified")
    .parallel(1)
    .collects(EvidenceType::Vulnerability)
    .with_mitre("T1574.009", None), // Unquoted Path
  )
  .add_step(
    PlaybookStep::new(4, PlaybookPhase::PrivilegeEscalation, "Token Privileges")
      .with_description("Check for dangerous token privileges")
      .with_manual("whoami /priv - look for SeImpersonate, SeAssignPrimaryToken")
      .with_success("Token privileges assessed")
      .collects(EvidenceType::Vulnerability)
      .with_mitre("T1134", None), // Access Token Manipulation
  )
  .add_step(
    PlaybookStep::new(
      5,
      PlaybookPhase::PrivilegeEscalation,
      "AlwaysInstallElevated",
    )
    .with_description("Check AlwaysInstallElevated registry setting")
    .with_manual("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer")
    .with_success("AlwaysInstallElevated status checked")
    .optional()
    .collects(EvidenceType::Vulnerability)
    .with_mitre("T1548.002", None), // Bypass UAC
  )
  .add_evidence(
    ExpectedEvidence::new("Windows privesc vector")
      .at("Enumeration output")
      .with_indicator("Exploitable service, token, or misconfiguration")
      .severity(FindingSeverity::High),
  )
  .add_failed_control(
    FailedControl::new("Service Security", "Vulnerable service configurations")
      .with_fix("Audit services for weak permissions and unquoted paths"),
  )
  .with_kill_chain(KillChainPhase::Exploitation())
}

/// Linux Privilege Escalation (Post-Exploitation)
pub fn linux_privesc() -> Playbook {
  Playbook::new("privilege-escalation-linux", "Linux Privilege Escalation")
    .with_description("Comprehensive Linux privilege escalation assessment")
    .with_objective("Escalate from standard user to root through various techniques")
    .for_target(TargetType::Host)
    .for_os(TargetOS::Linux)
    .with_risk(RiskLevel::Medium)
    .with_duration("30-90 minutes")
    .with_tag("linux")
    .with_tag("privesc")
    .with_tag("post-exploitation")
    .with_mitre("T1068")
    .add_precondition(PreCondition::new("Shell access as unprivileged user"))
    .add_step(
      PlaybookStep::new(1, PlaybookPhase::Discovery, "System Enumeration")
        .with_description("Enumerate system for privesc vectors")
        .with_command("rb exploit assess linux {{ target }}")
        .with_manual("Run linpeas.sh or linux-exploit-suggester")
        .with_success("Privilege escalation vectors identified")
        .collects(EvidenceType::SystemInfo)
        .with_mitre("T1082", None),
    )
    .add_step(
      PlaybookStep::new(2, PlaybookPhase::PrivilegeEscalation, "SUID/SGID Check")
        .with_description("Find exploitable SUID/SGID binaries")
        .with_manual("find / -perm -4000 2>/dev/null")
        .with_success("Exploitable SUID binaries found")
        .parallel(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1548.001", None),
    )
    .add_step(
      PlaybookStep::new(3, PlaybookPhase::PrivilegeEscalation, "Sudo Misconfig")
        .with_description("Check for sudo misconfigurations")
        .with_manual("sudo -l, check GTFOBins for entries")
        .with_success("Exploitable sudo rules found")
        .parallel(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1548.003", None),
    )
    .add_step(
      PlaybookStep::new(4, PlaybookPhase::PrivilegeEscalation, "Kernel Exploit")
        .with_description("Check for kernel exploits")
        .with_manual("uname -a, searchsploit linux kernel [version]")
        .with_success("Applicable kernel exploit identified")
        .optional()
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1068", None),
    )
    .add_evidence(
      ExpectedEvidence::new("Root shell")
        .at("Terminal output")
        .with_indicator("uid=0(root) in id output")
        .severity(FindingSeverity::Critical),
    )
    .add_failed_control(
      FailedControl::new("Privilege Management", "Overly permissive SUID/sudo config")
        .with_fix("Audit SUID binaries, restrict sudo rules, patch kernel"),
    )
}

/// Windows Privilege Escalation (Post-Exploitation)
pub fn windows_privesc() -> Playbook {
  Playbook::new(
    "privilege-escalation-windows",
    "Windows Privilege Escalation",
  )
  .with_description("Comprehensive Windows privilege escalation assessment")
  .with_objective("Escalate from standard user to SYSTEM/Administrator")
  .for_target(TargetType::Host)
  .for_os(TargetOS::Windows)
  .with_risk(RiskLevel::Medium)
  .with_duration("30-90 minutes")
  .with_tag("windows")
  .with_tag("privesc")
  .with_tag("post-exploitation")
  .with_mitre("T1068")
  .add_precondition(PreCondition::new("Shell access as unprivileged user"))
  .add_step(
    PlaybookStep::new(1, PlaybookPhase::Discovery, "System Enumeration")
      .with_description("Enumerate system for privesc vectors")
      .with_manual("Run winPEAS, PowerUp, or Seatbelt")
      .with_success("Privilege escalation vectors identified")
      .collects(EvidenceType::SystemInfo)
      .with_mitre("T1082", None),
  )
  .add_step(
    PlaybookStep::new(
      2,
      PlaybookPhase::PrivilegeEscalation,
      "Unquoted Service Path",
    )
    .with_description("Check for unquoted service paths")
    .with_manual("wmic service get name,displayname,pathname,startmode")
    .with_success("Unquoted paths with write access found")
    .parallel(1)
    .collects(EvidenceType::Vulnerability)
    .with_mitre("T1574.009", None),
  )
  .add_step(
    PlaybookStep::new(3, PlaybookPhase::PrivilegeEscalation, "Service Permissions")
      .with_description("Check for weak service permissions")
      .with_manual("accesschk.exe -uwcqv * /accepteula")
      .with_success("Modifiable services found")
      .parallel(1)
      .collects(EvidenceType::Vulnerability)
      .with_mitre("T1574.011", None),
  )
  .add_step(
    PlaybookStep::new(4, PlaybookPhase::PrivilegeEscalation, "Token Impersonation")
      .with_description("Check for impersonation privileges")
      .with_manual("whoami /priv, look for SeImpersonate")
      .with_success("Token impersonation possible")
      .collects(EvidenceType::Vulnerability)
      .with_mitre("T1134.001", None),
  )
  .add_evidence(
    ExpectedEvidence::new("SYSTEM shell")
      .at("Terminal output")
      .with_indicator("NT AUTHORITY\\SYSTEM in whoami")
      .severity(FindingSeverity::Critical),
  )
  .add_failed_control(
    FailedControl::new("Service Hardening", "Weak service configurations")
      .with_fix("Quote service paths, restrict service permissions, remove SeImpersonate"),
  )
}
