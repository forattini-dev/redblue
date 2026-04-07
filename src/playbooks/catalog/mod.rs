//! Playbook Catalog
//!
//! Pre-built playbooks for common Red Team scenarios.
//! All playbooks use human-friendly names - MITRE mappings are internal only.
//!
//! ## Available Playbooks
//!
//! ### Remote Access
//! - `reverse-shell-linux` - Establish reverse shell on Linux
//! - `reverse-shell-windows` - Establish reverse shell on Windows
//! - `webshell-upload` - Upload and execute webshell
//!
//! ### Initial Access
//! - `web-app-assessment` - Full web application security assessment
//! - `external-footprint` - External attack surface mapping
//! - `ssh-bruteforce` - SSH credential testing
//!
//! ### Privilege Escalation
//! - `linux-privesc` - Linux privilege escalation assessment
//! - `windows-privesc` - Windows privilege escalation assessment
//!
//! ### Network
//! - `internal-network-recon` - Internal network reconnaissance
//! - `lateral-movement` - Lateral movement techniques
//!
//! ### Data Collection
//! - `credential-harvesting` - Credential collection techniques
//! - `data-exfiltration` - Data extraction methods

mod active_directory;
mod binary_exploitation;
mod chains;
mod collection;
mod ctf;
mod initial_access;
mod network;
mod privesc;
mod recon;
mod remote_access;
mod web;

use super::types::*;

// Re-export submodule functions
pub use active_directory::{ad_enumeration, ad_persistence, kerberos_attacks, pkinit_exploitation};
pub use binary_exploitation::{got_hijacking, ret2dlresolve};
pub use chains::{
  ad_compromise_chain, all_chains, full_assessment_chain, get_chain, web_exploitation_chain,
};
pub use collection::{credential_harvesting, credential_harvesting_post};
pub use ctf::{ctf_crypto_challenge, ctf_web_challenge};
pub use initial_access::{external_footprint, ssh_credential_test, web_app_assessment};
pub use network::{
  internal_recon, lateral_movement_assessment, mitm_attacks, network_mapping, network_pivot,
  service_exploitation,
};
pub use privesc::{
  linux_privesc, linux_privesc_assessment, windows_privesc, windows_privesc_assessment,
};
pub use recon::{
  comprehensive_recon, osint_collection, subdomain_discovery, technology_fingerprint,
};
pub use remote_access::{reverse_shell_linux, reverse_shell_windows, webshell_upload};
pub use web::{
  api_security_assessment, authentication_bypass, file_upload_exploitation,
  sql_injection_discovery, xss_detection,
};

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
    // Reconnaissance (NEW)
    comprehensive_recon(),
    subdomain_discovery(),
    technology_fingerprint(),
    osint_collection(),
    network_mapping(),
    // Web Application (NEW)
    sql_injection_discovery(),
    xss_detection(),
    authentication_bypass(),
    api_security_assessment(),
    file_upload_exploitation(),
    // Active Directory (NEW)
    ad_enumeration(),
    kerberos_attacks(),
    pkinit_exploitation(),
    ad_persistence(),
    // Network (NEW)
    network_pivot(),
    mitm_attacks(),
    service_exploitation(),
    // Post-Exploitation (NEW)
    linux_privesc(),
    windows_privesc(),
    credential_harvesting_post(),
    // CTF (NEW)
    ctf_web_challenge(),
    ctf_crypto_challenge(),
    // Binary Exploitation
    got_hijacking(),
    ret2dlresolve(),
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

  #[test]
  fn test_all_chains() {
    let chains = all_chains();
    assert!(chains.len() >= 3);
  }

  #[test]
  fn test_get_chain_by_id() {
    let chain = get_chain("ad-compromise");
    assert!(chain.is_some());
    assert_eq!(chain.unwrap().name, "Active Directory Compromise");
  }
}
