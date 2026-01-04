//! Playbook Chains
//!
//! Composite playbook chains for multi-stage assessments.

use crate::playbooks::types::*;

/// Get all available playbook chains
pub fn all_chains() -> Vec<PlaybookChain> {
    vec![
        ad_compromise_chain(),
        web_exploitation_chain(),
        full_assessment_chain(),
    ]
}

/// Get a chain by ID
pub fn get_chain(id: &str) -> Option<PlaybookChain> {
    all_chains().into_iter().find(|c| c.id == id)
}

/// Active Directory Compromise Chain
/// Combines AD enumeration, Kerberos attacks, and persistence
pub fn ad_compromise_chain() -> PlaybookChain {
    PlaybookChain::new("ad-compromise", "Active Directory Compromise")
        .with_description("Full AD compromise flow from enumeration to domain dominance")
        .with_tag("active-directory")
        .with_tag("chain")
        .with_risk(RiskLevel::High)
        .then("ad-enumeration")
        .on_success("kerberos-attacks")
        .on_evidence("pkinit-exploitation", EvidenceType::Credentials)
        .on_success("ad-persistence")
}

/// Web Application Exploitation Chain
/// Combines recon, fingerprinting, and various web attacks
pub fn web_exploitation_chain() -> PlaybookChain {
    PlaybookChain::new("web-exploitation", "Web Application Exploitation")
        .with_description("Complete web application assessment from recon to exploitation")
        .with_tag("web")
        .with_tag("chain")
        .with_risk(RiskLevel::Medium)
        .then("comprehensive-recon")
        .on_success("technology-fingerprint")
        .on_success("sql-injection-discovery")
        .add_playbook(
            ChainedPlaybook::new("xss-detection")
                .when(ChainCondition::OnSuccess)
                .continue_on_fail(),
        )
        .add_playbook(
            ChainedPlaybook::new("file-upload-exploitation")
                .when(ChainCondition::OnEvidence(EvidenceType::Vulnerability)),
        )
}

/// Full Security Assessment Chain
/// Comprehensive multi-phase assessment
pub fn full_assessment_chain() -> PlaybookChain {
    PlaybookChain::new("full-assessment", "Full Security Assessment")
        .with_description("Complete security assessment covering recon through post-exploitation")
        .with_tag("comprehensive")
        .with_tag("chain")
        .with_risk(RiskLevel::High)
        // Phase 1: Reconnaissance
        .then("comprehensive-recon")
        .on_success("subdomain-discovery")
        .on_success("technology-fingerprint")
        // Phase 2: Vulnerability Discovery
        .on_success("sql-injection-discovery")
        .add_playbook(
            ChainedPlaybook::new("xss-detection")
                .when(ChainCondition::OnSuccess)
                .continue_on_fail(),
        )
        .add_playbook(
            ChainedPlaybook::new("authentication-bypass")
                .when(ChainCondition::OnSuccess)
                .continue_on_fail(),
        )
        // Phase 3: Exploitation
        .on_evidence("service-exploitation", EvidenceType::Vulnerability)
        // Phase 4: Post-Exploitation
        .on_evidence("credential-harvesting-post", EvidenceType::Credentials)
}
