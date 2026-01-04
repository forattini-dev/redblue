//! Network Attack Playbooks
//!
//! Playbooks for network reconnaissance, lateral movement, pivoting, and attacks.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

/// Internal Network Reconnaissance
pub fn internal_recon() -> Playbook {
    Playbook::new("internal-network-recon", "Internal Network Reconnaissance")
        .with_description("Reconnaissance within an internal network after initial compromise")
        .with_objective("Map internal network topology and identify high-value targets")
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

/// Network Pivoting and Lateral Movement
pub fn network_pivot() -> Playbook {
    Playbook::new("network-pivot", "Network Pivoting and Lateral Movement")
        .with_description("Techniques for moving laterally through compromised networks")
        .with_objective("Establish access to additional network segments through pivot points")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("1-2 hours")
        .with_tag("network")
        .with_tag("pivot")
        .with_tag("lateral")
        .with_mitre("T1021")
        .add_precondition(PreCondition::new("Initial foothold established"))
        .add_precondition(PreCondition::new("Multiple network segments accessible"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Discovery, "Network Discovery")
                .with_description("Map internal network from compromised host")
                .with_command("rb network ports scan {{ internal_range }} --preset common")
                .with_success("Internal network topology mapped")
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1046", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::LateralMovement, "SSH Pivoting")
                .with_description("Set up SSH tunnel for network pivoting")
                .with_manual("ssh -D 1080 user@pivot -N (SOCKS proxy)")
                .with_success("SSH tunnel established")
                .parallel(1)
                .collects(EvidenceType::SessionData)
                .with_mitre("T1021.004", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::LateralMovement, "Port Forwarding")
                .with_description("Set up local/remote port forwards")
                .with_manual("ssh -L local:remote:port, chisel, socat")
                .with_success("Port forwards active")
                .parallel(1)
                .collects(EvidenceType::SessionData)
                .with_mitre("T1572", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::LateralMovement, "Proxy Chains")
                .with_description("Configure proxy chains for multi-hop access")
                .with_manual("proxychains configuration, nested tunnels")
                .with_success("Multi-hop access established")
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1090.001", None),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Discovery, "Target Enumeration")
                .with_description("Enumerate targets in new network segment")
                .with_command("rb network ports scan {{ pivot_range }} --preset discovery")
                .with_success("New targets identified")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1018", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Pivot access")
                .at("Network access")
                .with_indicator("Access to previously unreachable network segments")
                .severity(FindingSeverity::High),
        )
        .add_failed_control(
            FailedControl::new("Network Segmentation", "Insufficient network isolation")
                .with_fix("Implement micro-segmentation, restrict inter-VLAN traffic, monitor lateral movement"),
        )
}

/// Man-in-the-Middle Attack Scenarios
pub fn mitm_attacks() -> Playbook {
    Playbook::new("mitm-attacks", "Man-in-the-Middle Attack Scenarios")
        .with_description("Network-based credential interception and traffic manipulation")
        .with_objective(
            "Intercept and manipulate network traffic to capture credentials or inject payloads",
        )
        .for_target(TargetType::Network)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("1-2 hours")
        .with_tag("network")
        .with_tag("mitm")
        .with_tag("credentials")
        .with_mitre("T1557")
        .add_precondition(PreCondition::new("Access to target network segment"))
        .add_precondition(PreCondition::new("Network allows layer 2 attacks"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Network Assessment")
                .with_description("Assess network for MITM opportunities")
                .with_manual("ARP table analysis, switch port security check")
                .with_success("MITM opportunity identified")
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1040", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Collection, "ARP Spoofing")
                .with_description("Position between target and gateway")
                .with_manual("arpspoof, ettercap, bettercap")
                .with_success("ARP cache poisoned")
                .parallel(1)
                .collects(EvidenceType::NetworkCapture)
                .with_mitre("T1557.002", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Collection, "Traffic Capture")
                .with_description("Capture and analyze network traffic")
                .with_command("rb network capture {{ interface }} --filter 'port 80 or port 443'")
                .with_success("Traffic captured")
                .parallel(1)
                .collects(EvidenceType::NetworkCapture)
                .with_mitre("T1040", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::CredentialAccess, "Credential Extraction")
                .with_description("Extract credentials from captured traffic")
                .with_manual("pcredz, net-creds, manual pcap analysis")
                .with_success("Credentials captured")
                .collects(EvidenceType::Credentials)
                .with_mitre("T1557", None),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Execution, "SSL Stripping")
                .with_description("Downgrade HTTPS to HTTP where possible")
                .with_manual("sslstrip, hsts bypass techniques")
                .with_success("SSL stripped successfully")
                .when(StepCondition::OnEvidence(EvidenceType::NetworkCapture))
                .collects(EvidenceType::NetworkCapture)
                .with_mitre("T1557.002", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Intercepted credentials")
                .at("Traffic capture")
                .with_indicator("Cleartext or captured authentication data")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new("Network Security", "MITM attacks possible")
                .with_fix("Enable port security, use DHCP snooping, deploy 802.1X, use HSTS"),
        )
}

/// Common Service Exploitation
pub fn service_exploitation() -> Playbook {
    Playbook::new("service-exploitation", "Common Service Exploitation")
        .with_description("Exploit common network services for initial or expanded access")
        .with_objective("Gain access through vulnerable network services")
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::High)
        .with_duration("1-3 hours")
        .with_tag("network")
        .with_tag("services")
        .with_tag("exploitation")
        .with_mitre("T1210")
        .add_precondition(PreCondition::new("Target services identified"))
        .add_precondition(PreCondition::new("Network connectivity to services"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Service Enumeration")
                .with_description("Identify service versions and configurations")
                .with_command("rb network ports scan {{ target }} --banner")
                .with_success("Service versions identified")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1046", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::InitialAccess, "SSH Attack")
                .with_description("Test SSH for weak credentials or vulnerabilities")
                .with_command("rb exploit run ssh-enum {{ target }}")
                .with_success("SSH access obtained")
                .parallel(1)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1021.004", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::InitialAccess, "SMB Attack")
                .with_description("Exploit SMB vulnerabilities or weak configs")
                .with_manual("EternalBlue check, null session, share enum")
                .with_success("SMB access obtained")
                .parallel(1)
                .collects(EvidenceType::Vulnerability)
                .with_mitre("T1021.002", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::InitialAccess, "FTP Attack")
                .with_description("Test FTP for anonymous access or weak creds")
                .with_command("rb exploit run ftp-anon {{ target }}")
                .with_success("FTP access obtained")
                .parallel(1)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1078", None),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::InitialAccess, "RDP Attack")
                .with_description("Test RDP for BlueKeep or weak credentials")
                .with_manual("CVE-2019-0708 check, credential testing")
                .with_success("RDP access obtained")
                .parallel(1)
                .collects(EvidenceType::Vulnerability)
                .with_mitre("T1021.001", None),
        )
        .add_step(
            PlaybookStep::new(6, PlaybookPhase::InitialAccess, "Database Attack")
                .with_description("Test database services for weak auth")
                .with_command("rb database scan {{ target }}")
                .with_success("Database access obtained")
                .collects(EvidenceType::Credentials)
                .with_mitre("T1210", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Service access")
                .at("Service connection")
                .with_indicator("Authenticated access to target service")
                .severity(FindingSeverity::High),
        )
        .add_failed_control(
            FailedControl::new("Service Hardening", "Vulnerable service configurations").with_fix(
                "Patch services, disable legacy protocols, enforce strong auth, use firewalls",
            ),
        )
}

/// Internal Network Mapping
pub fn network_mapping() -> Playbook {
    Playbook::new("network-mapping", "Internal Network Mapping")
        .with_description("Map internal network topology and discover assets")
        .with_objective("Create comprehensive internal network diagram with all discoverable hosts and services")
        .for_target(TargetType::Network)
        .for_target(TargetType::Internal)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Medium)
        .with_duration("1-4 hours")
        .with_tag("reconnaissance")
        .with_tag("internal")
        .with_tag("network")
        .with_mitre("T1046")
        .with_mitre("T1018")
        .add_precondition(PreCondition::new("Internal network access obtained"))
        .add_precondition(PreCondition::new("Authorization for internal scanning"))
        // Host Discovery
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Discovery, "ARP Scan")
                .with_description("Discover hosts via ARP on local subnet")
                .with_command("rb network host discover {{ network }} --arp")
                .with_success("Local hosts discovered")
                .parallel(1)
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1018", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Discovery, "ICMP Sweep")
                .with_description("Ping sweep for host discovery")
                .with_command("rb network host discover {{ network }} --ping")
                .with_success("Responsive hosts identified")
                .parallel(1)
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1018", None),
        )
        // Port Scanning
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Discovery, "Port Scan")
                .with_description("Full port scan on discovered hosts")
                .with_command("rb network ports scan {{ host }} --preset full")
                .with_success("Open ports enumerated")
                .depends(1)
                .parallel(2)
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1046", None),
        )
        // Service Identification
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Discovery, "Service Enumeration")
                .with_description("Identify services on open ports")
                .with_command("rb network ports scan {{ host }} --banner")
                .with_success("Services identified and versioned")
                .depends(3)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1046", None),
        )
        // Network Shares
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Discovery, "SMB Share Enumeration")
                .with_description("Discover accessible SMB shares")
                .with_manual("Use smbclient -L or rb smb enum shares")
                .with_success("Network shares documented")
                .optional()
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1135", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Network topology map")
                .at("Network diagram")
                .with_indicator("Hosts, services, network segments")
                .severity(FindingSeverity::Info),
        )
        .add_failed_control(
            FailedControl::new("Network Segmentation", "Flat network allows broad discovery")
                .with_fix("Implement VLANs and network segmentation"),
        )
}
