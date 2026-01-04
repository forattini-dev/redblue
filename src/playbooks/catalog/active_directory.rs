//! Active Directory Playbooks
//!
//! Playbooks for AD attacks: enumeration, Kerberos, PKINIT, persistence.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

/// Active Directory Enumeration
pub fn ad_enumeration() -> Playbook {
    Playbook::new("ad-enumeration", "Active Directory Enumeration")
        .with_description(
            "Enumerate Active Directory domain structure, users, groups, and policies",
        )
        .with_objective("Map the AD environment for privilege escalation and lateral movement")
        .for_target(TargetType::Internal)
        .for_os(TargetOS::Windows)
        .with_risk(RiskLevel::Low)
        .with_duration("30-90 minutes")
        .with_tag("ad")
        .with_tag("windows")
        .with_tag("enumeration")
        .with_mitre("T1087")
        .add_precondition(PreCondition::new(
            "Domain-joined system or valid domain credentials",
        ))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Discovery, "Domain Info")
                .with_description("Gather basic domain information")
                .with_manual("Get-ADDomain, nltest /dclist, net user /domain")
                .with_success("Domain name, DCs, and forest info obtained")
                .parallel(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1082", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Discovery, "User Enumeration")
                .with_description("Enumerate domain users and attributes")
                .with_manual("Get-ADUser -Filter *, net user /domain")
                .with_success("User list with attributes extracted")
                .parallel(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1087.002", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Discovery, "Group Enumeration")
                .with_description("Enumerate groups and memberships")
                .with_manual("Get-ADGroup -Filter *, Get-ADGroupMember")
                .with_success("Groups and members documented")
                .parallel(1)
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1087.002", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Discovery, "GPO Analysis")
                .with_description("Enumerate Group Policy Objects")
                .with_manual("Get-GPO -All, gpresult /r")
                .with_success("GPOs and linked OUs mapped")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1615", None),
        )
        .add_evidence(
            ExpectedEvidence::new("AD structure documentation")
                .at("Enumeration output")
                .with_indicator("Users, groups, OUs, GPOs, trusts")
                .severity(FindingSeverity::Info),
        )
        .add_failed_control(
            FailedControl::new("AD Query Logging", "Domain enumeration not detected")
                .with_fix("Enable Advanced Audit Policy for Directory Service Access"),
        )
}

/// Kerberos Attack Assessment
pub fn kerberos_attacks() -> Playbook {
    Playbook::new("kerberos-attacks", "Kerberos Attack Assessment")
        .with_description("Test for Kerberoasting, AS-REP roasting, and other Kerberos weaknesses")
        .with_objective("Extract service account credentials through Kerberos ticket abuse")
        .for_target(TargetType::Internal)
        .for_os(TargetOS::Windows)
        .with_risk(RiskLevel::Medium)
        .with_duration("30-60 minutes")
        .with_tag("ad")
        .with_tag("kerberos")
        .with_tag("credential")
        .with_mitre("T1558")
        .add_precondition(PreCondition::new("Domain user credentials available"))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Discovery, "SPN Discovery")
                .with_description("Find accounts with Service Principal Names")
                .with_manual("Get-ADUser -Filter {ServicePrincipalName -ne '$null'}")
                .with_success("SPNs enumerated")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1558.003", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::CredentialAccess, "Kerberoasting")
                .with_description("Request and crack service tickets")
                .with_manual("Invoke-Kerberoast, GetUserSPNs.py, hashcat -m 13100")
                .with_success("Service ticket hashes obtained")
                .depends(1)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1558.003", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Discovery, "AS-REP Roast Targets")
                .with_description("Find accounts without pre-auth")
                .with_manual("Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}")
                .with_success("Pre-auth disabled accounts found")
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1558.004", None),
        )
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::CredentialAccess, "AS-REP Roasting")
                .with_description("Request and crack AS-REP hashes")
                .with_manual("GetNPUsers.py, hashcat -m 18200")
                .with_success("AS-REP hashes cracked")
                .depends(3)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1558.004", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Cracked Kerberos credentials")
                .at("Hashcat output")
                .with_indicator("Plaintext service account passwords")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new("Service Account Security", "Weak service account passwords")
                .with_fix("Use MSAs/gMSAs, enforce strong passwords, disable RC4"),
        )
}

/// PKINIT/Certificate Attack Assessment
pub fn pkinit_exploitation() -> Playbook {
    Playbook::new(
        "pkinit-exploitation",
        "PKINIT/Certificate Attack Assessment",
    )
    .with_description("Test for ADCS misconfigurations and PKINIT-based attacks")
    .with_objective("Exploit certificate services for domain privilege escalation")
    .for_target(TargetType::Internal)
    .for_os(TargetOS::Windows)
    .with_risk(RiskLevel::High)
    .with_duration("1-3 hours")
    .with_tag("ad")
    .with_tag("pkinit")
    .with_tag("certificate")
    .with_tag("adcs")
    .with_mitre("T1649")
    .add_precondition(PreCondition::new("Domain user credentials available"))
    .add_precondition(PreCondition::new(
        "ADCS (Certificate Services) deployed in domain",
    ))
    .add_step(
        PlaybookStep::new(1, PlaybookPhase::Discovery, "CA Enumeration")
            .with_description("Identify Certificate Authorities in the domain")
            .with_manual("certutil -config - -ping, Certify.exe cas")
            .with_success("Certificate Authorities identified")
            .collects(EvidenceType::SystemInfo)
            .with_mitre("T1649", None),
    )
    .add_step(
        PlaybookStep::new(2, PlaybookPhase::Discovery, "Template Analysis")
            .with_description("Find vulnerable certificate templates")
            .with_manual("Certify.exe find /vulnerable, certipy find")
            .with_success("Vulnerable templates identified (ESC1-ESC8)")
            .depends(1)
            .collects(EvidenceType::Vulnerability)
            .with_mitre("T1649", None),
    )
    .add_step(
        PlaybookStep::new(3, PlaybookPhase::PrivilegeEscalation, "Certificate Request")
            .with_description("Request certificate using vulnerable template")
            .with_manual("Certify.exe request, certipy req")
            .with_success("Certificate obtained for privilege escalation")
            .when(StepCondition::OnSuccess(2))
            .collects(EvidenceType::Credentials)
            .with_mitre("T1649", None),
    )
    .add_step(
        PlaybookStep::new(4, PlaybookPhase::CredentialAccess, "PKINIT Authentication")
            .with_description("Use certificate for Kerberos authentication")
            .with_manual("Rubeus.exe asktgt /certificate:, certipy auth")
            .with_success("TGT obtained via PKINIT")
            .depends(3)
            .collects(EvidenceType::SessionData)
            .with_mitre("T1558.004", None),
    )
    .add_evidence(
        ExpectedEvidence::new("Domain admin access via certificate")
            .at("TGT/certificate")
            .with_indicator("High-privilege Kerberos ticket")
            .severity(FindingSeverity::Critical),
    )
    .add_failed_control(
        FailedControl::new("ADCS Security", "Vulnerable certificate templates")
            .with_fix("Audit templates, remove dangerous permissions, enable Manager Approval"),
    )
}

/// AD Persistence Assessment
pub fn ad_persistence() -> Playbook {
    Playbook::new("ad-persistence", "AD Persistence Assessment")
        .with_description("Test for common AD persistence mechanisms and their detection")
        .with_objective("Validate detection of domain-level persistence techniques")
        .for_target(TargetType::Internal)
        .for_os(TargetOS::Windows)
        .with_risk(RiskLevel::Critical)
        .with_duration("1-2 hours")
        .with_tag("ad")
        .with_tag("persistence")
        .with_tag("golden-ticket")
        .with_mitre("T1098")
        .add_precondition(PreCondition::new("Domain Admin or equivalent access"))
        .add_precondition(PreCondition::new(
            "Explicit authorization for persistence testing",
        ))
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Persistence, "Golden Ticket Test")
                .with_description("Test golden ticket creation and use")
                .with_manual("mimikatz kerberos::golden /krbtgt:[hash]")
                .with_success("Golden ticket created and used")
                .collects(EvidenceType::SessionData)
                .with_mitre("T1558.001", None),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Persistence, "DCSync Detection")
                .with_description("Test DCSync replication monitoring")
                .with_manual("mimikatz lsadump::dcsync /user:krbtgt")
                .with_success("DCSync activity monitored")
                .collects(EvidenceType::Credentials)
                .with_mitre("T1003.006", None),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Persistence, "AdminSDHolder Abuse")
                .with_description("Test AdminSDHolder modification detection")
                .with_manual("Add user to AdminSDHolder ACL, wait for SDProp")
                .with_success("AdminSDHolder modification detected")
                .optional()
                .collects(EvidenceType::SystemInfo)
                .with_mitre("T1098", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Persistence mechanism artifacts")
                .at("Domain controller logs")
                .with_indicator("Event IDs 4662, 4768, 4769 anomalies")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new(
                "Privileged Access Monitoring",
                "No alerting on persistence techniques",
            )
            .with_fix("Enable advanced audit logging, deploy EDR on DCs"),
        )
}
