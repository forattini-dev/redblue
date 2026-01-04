//! Reconnaissance Playbooks
//!
//! Playbooks for external reconnaissance: subdomain discovery, fingerprinting, OSINT.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

/// Comprehensive External Reconnaissance
pub fn comprehensive_recon() -> Playbook {
    Playbook::new(
        "comprehensive-recon",
        "Comprehensive External Reconnaissance",
    )
    .with_description("Full external footprint discovery combining passive and active techniques")
    .with_objective(
        "Map the complete external attack surface including subdomains, services, and technologies",
    )
    .for_target(TargetType::Domain)
    .for_os(TargetOS::Any)
    .with_risk(RiskLevel::Low)
    .with_duration("1-4 hours")
    .with_tag("reconnaissance")
    .with_tag("external")
    .with_mitre("T1595")
    .with_mitre("T1592")
    // Preconditions
    .add_precondition(PreCondition::new("Target domain identified"))
    .add_precondition(PreCondition::new(
        "Authorization for reconnaissance confirmed",
    ))
    // Passive OSINT Phase
    .add_step(
        PlaybookStep::new(1, PlaybookPhase::Recon, "WHOIS Lookup")
            .with_description("Gather registration and ownership information")
            .with_command("rb recon domain whois {{ target }}")
            .with_success("Registrant information obtained")
            .with_success("Name servers identified")
            .parallel(1) // Parallel group 1
            .collects(EvidenceType::SystemInfo)
            .with_mitre("T1596.002", None),
    )
    .add_step(
        PlaybookStep::new(2, PlaybookPhase::Recon, "DNS Enumeration")
            .with_description("Enumerate all DNS record types")
            .with_command("rb dns record lookup {{ target }} --type ALL")
            .with_success("DNS records mapped")
            .parallel(1) // Same group - runs in parallel with step 1
            .collects(EvidenceType::NetworkMap)
            .with_mitre("T1596.001", None),
    )
    .add_step(
        PlaybookStep::new(3, PlaybookPhase::Recon, "Subdomain Discovery")
            .with_description("Discover subdomains using multiple sources")
            .with_command("rb recon domain subdomains {{ target }}")
            .with_success("Subdomains enumerated")
            .parallel(1)
            .collects(EvidenceType::NetworkMap)
            .with_mitre("T1595.002", None),
    )
    // Active Scanning Phase
    .add_step(
        PlaybookStep::new(4, PlaybookPhase::Recon, "Port Scanning")
            .with_description("Identify open ports on discovered hosts")
            .with_command("rb network ports scan {{ target }} --preset common")
            .with_success("Open ports identified")
            .depends(3)
            .parallel(2)
            .collects(EvidenceType::NetworkMap)
            .with_mitre("T1046", None),
    )
    .add_step(
        PlaybookStep::new(5, PlaybookPhase::Recon, "Technology Fingerprinting")
            .with_description("Identify technologies and frameworks")
            .with_command("rb web asset headers https://{{ target }}")
            .with_success("Technologies identified")
            .depends(4)
            .parallel(2)
            .collects(EvidenceType::SystemInfo)
            .with_mitre("T1592.002", None),
    )
    .add_step(
        PlaybookStep::new(6, PlaybookPhase::Recon, "SSL/TLS Analysis")
            .with_description("Analyze certificate and TLS configuration")
            .with_command("rb tls audit {{ target }}")
            .with_success("TLS configuration assessed")
            .depends(4)
            .parallel(2)
            .collects(EvidenceType::Vulnerability)
            .with_mitre("T1596.003", None),
    )
    // Evidence
    .add_evidence(
        ExpectedEvidence::new("Complete asset inventory")
            .at("Reconnaissance report")
            .with_indicator("Subdomains, IPs, open ports, technologies")
            .severity(FindingSeverity::Info),
    )
    .add_evidence(
        ExpectedEvidence::new("Attack surface map")
            .at("Network diagram")
            .with_indicator("Visual representation of infrastructure")
            .severity(FindingSeverity::Info),
    )
    // Failed controls
    .add_failed_control(
        FailedControl::new(
            "Information Exposure",
            "Public DNS reveals internal structure",
        )
        .with_fix("Minimize public DNS records, use internal DNS for private services"),
    )
}

/// Subdomain Discovery
pub fn subdomain_discovery() -> Playbook {
    Playbook::new("subdomain-discovery", "Subdomain Discovery")
        .with_description("Comprehensive subdomain enumeration using passive and active techniques")
        .with_objective("Discover all subdomains of target domain using multiple data sources")
        .for_target(TargetType::Domain)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Passive)
        .with_duration("15-60 minutes")
        .with_tag("reconnaissance")
        .with_tag("subdomains")
        .with_mitre("T1595.002")
        .add_precondition(PreCondition::new("Target domain identified"))
        // Passive enumeration
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Certificate Transparency")
                .with_description("Search CT logs for issued certificates")
                .with_command("rb recon domain subdomains {{ target }} --source ct")
                .with_success("CT log subdomains extracted")
                .parallel(1)
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1596.003", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "DNS Zone Transfer")
                .with_description("Attempt zone transfer from DNS servers")
                .with_command("rb dns record axfr {{ target }}")
                .with_success("Zone transfer successful or properly blocked")
                .optional()
                .parallel(1)
                .with_mitre("T1596.001", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Recon, "Subdomain Bruteforce")
                .with_description("Active subdomain brute-forcing")
                .with_command("rb recon domain subdomains {{ target }} --brute")
                .with_success("Additional subdomains discovered")
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1595.002", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Recon, "Validate Live Hosts")
                .with_description("Verify which discovered subdomains are live")
                .with_command("rb network host ping {{ subdomain }}")
                .with_success("Live hosts identified")
                .depends(3)
                .collects(EvidenceType::NetworkMap)
                .with_mitre("T1046", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Subdomain list")
                .at("Enumeration output")
                .with_indicator("Complete list of subdomains with resolution status")
                .severity(FindingSeverity::Info),
        )
        .add_failed_control(
            FailedControl::new(
                "Subdomain Exposure",
                "Hidden services on predictable subdomains",
            )
            .with_fix("Use random subdomain names for internal services"),
        )
}

/// Technology Fingerprinting
pub fn technology_fingerprint() -> Playbook {
    Playbook::new("technology-fingerprint", "Technology Fingerprinting")
        .with_description("Identify technologies, frameworks, and software versions on target")
        .with_objective("Create detailed technology stack inventory for vulnerability research")
        .for_target(TargetType::WebApp)
        .for_target(TargetType::Host)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Low)
        .with_duration("15-30 minutes")
        .with_tag("reconnaissance")
        .with_tag("fingerprinting")
        .with_mitre("T1592.002")
        .add_precondition(PreCondition::new("Target URL or IP accessible"))
        // HTTP Header Analysis
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "HTTP Header Analysis")
                .with_description("Extract technology info from HTTP headers")
                .with_command("rb web asset headers {{ target }}")
                .with_success("Server headers captured")
                .parallel(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1592.002", None),
        )
        // Service Banner Grabbing
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Service Banner Grabbing")
                .with_description("Grab banners from open services")
                .with_command("rb network ports scan {{ target }} --banner")
                .with_success("Service versions identified")
                .parallel(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1046", None),
        )
        // Web Technology Detection
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Recon, "Web Framework Detection")
                .with_description("Identify web frameworks and CMS")
                .with_command("rb web asset security {{ target }}")
                .with_success("Web technologies identified")
                .depends(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1592.002", None),
        )
        // JavaScript Library Analysis
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Recon, "JavaScript Analysis")
                .with_description("Identify client-side JavaScript libraries")
                .with_manual("Inspect page source and network requests for JS libraries")
                .with_success("Client-side libraries documented")
                .optional()
                .with_mitre("T1592.002", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Technology inventory")
                .at("Fingerprint report")
                .with_indicator("Software names, versions, frameworks")
                .severity(FindingSeverity::Info),
        )
        .add_failed_control(
            FailedControl::new(
                "Version Disclosure",
                "Server headers reveal software versions",
            )
            .with_fix("Configure servers to minimize version disclosure"),
        )
}

/// OSINT Intelligence Gathering
pub fn osint_collection() -> Playbook {
    Playbook::new("osint-collection", "OSINT Intelligence Gathering")
        .with_description("Collect open source intelligence about target organization")
        .with_objective(
            "Gather publicly available information for social engineering and attack planning",
        )
        .for_target(TargetType::Domain)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Passive)
        .with_duration("1-3 hours")
        .with_tag("reconnaissance")
        .with_tag("osint")
        .with_mitre("T1589")
        .with_mitre("T1591")
        .add_precondition(PreCondition::new("Target organization identified"))
        // Domain OSINT
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Domain History")
                .with_description("Research domain registration history")
                .with_command("rb recon domain whois {{ target }}")
                .with_success("Registration history documented")
                .parallel(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1596.002", None),
        )
        // Email Pattern Discovery
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Email Pattern Discovery")
                .with_description("Identify email naming conventions")
                .with_manual("Search for emails in format: first.last@domain, flast@domain")
                .with_success("Email pattern identified")
                .parallel(1)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1589.002", None),
        )
        // Breach Data Check
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Recon, "Credential Breach Check")
                .with_description("Check for leaked credentials in public breaches")
                .with_manual("Check haveibeenpwned.com, dehashed.com for domain")
                .with_success("Breach status documented")
                .collects(EvidenceType::Credentials)
                .with_mitre("T1589.001", None),
        )
        // Social Media Recon
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Recon, "Social Media Intelligence")
                .with_description("Gather intel from social media profiles")
                .with_manual("Search LinkedIn, Twitter, GitHub for employees")
                .with_success("Key personnel identified")
                .optional()
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1591.004", None),
        )
        // Code Repository Search
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Recon, "Code Repository Search")
                .with_description("Search for leaked code and secrets in public repos")
                .with_manual("Search GitHub, GitLab for domain references")
                .with_success("Public code exposure documented")
                .collects(EvidenceType::Credentials)
                .with_mitre("T1593.003", None),
        )
        .add_evidence(
            ExpectedEvidence::new("OSINT dossier")
                .at("Intelligence report")
                .with_indicator("Emails, personnel, leaked data, social profiles")
                .severity(FindingSeverity::Info),
        )
        .add_failed_control(
            FailedControl::new("Information Leakage", "Sensitive data in public sources")
                .with_fix("Regular monitoring of public exposure, employee training"),
        )
}
