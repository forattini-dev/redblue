//! MITRE ATT&CK APT Group Playbooks
//!
//! Pre-built playbooks based on real APT group TTPs extracted from MITRE ATT&CK v18.1.
//! These playbooks simulate adversary behavior for purple team exercises.
//!
//! ## Available APT Playbooks
//!
//! ### Russia
//! - `apt28` - GRU (Fancy Bear)
//! - `apt29` - SVR (Cozy Bear)
//! - `sandworm-team` - GRU (BlackEnergy)
//! - `turla` - FSB (Waterbug)
//! - `wizard-spider` - TrickBot/Ryuk
//!
//! ### China
//! - `apt3` - MSS (Gothic Panda)
//! - `apt41` - Wicked Panda
//! - `volt-typhoon` - BRONZE SILHOUETTE
//!
//! ### East Asia
//! - `apt32` - Vietnam (OceanLotus)
//! - `kimsuky` - North Korea (Velvet Chollima)
//! - `lazarus-group` - North Korea (HIDDEN COBRA)
//!
//! ### Iran
//! - `muddywater` - MOIS
//! - `oilrig` - APT34
//!
//! ### Financial
//! - `fin7` - Carbanak
//! - `scattered-spider` - Roasted 0ktapus
//!
//! **IMPORTANT**: These playbooks are for authorized security testing ONLY.
//! Unauthorized use is illegal and unethical.

mod china;
mod east_asia;
mod financial;
mod iran;
mod russia;

pub use china::*;
pub use east_asia::*;
pub use financial::*;
pub use iran::*;
pub use russia::*;

use super::types::Playbook;

/// Get all APT playbooks
pub fn all_apt_playbooks() -> Vec<Playbook> {
    vec![
        apt28(),
        apt29(),
        apt3(),
        apt32(),
        apt41(),
        fin7(),
        kimsuky(),
        lazarus_group(),
        muddywater(),
        oilrig(),
        sandworm_team(),
        scattered_spider(),
        turla(),
        volt_typhoon(),
        wizard_spider(),
    ]
}

/// Get APT playbook by group name or alias
pub fn get_apt_playbook(name: &str) -> Option<Playbook> {
    let name_lower = name.to_lowercase();
    all_apt_playbooks().into_iter().find(|p| {
        p.metadata.id.to_lowercase() == name_lower
            || p.metadata.name.to_lowercase().contains(&name_lower)
    })
}

/// List all APT group names
pub fn list_apt_groups() -> Vec<(&'static str, &'static str)> {
    vec![
        ("apt28", "APT28"),
        ("apt29", "APT29"),
        ("apt3", "APT3"),
        ("apt32", "APT32"),
        ("apt41", "APT41"),
        ("fin7", "FIN7"),
        ("kimsuky", "Kimsuky"),
        ("lazarus-group", "Lazarus Group"),
        ("muddywater", "MuddyWater"),
        ("oilrig", "OilRig"),
        ("sandworm-team", "Sandworm Team"),
        ("scattered-spider", "Scattered Spider"),
        ("turla", "Turla"),
        ("volt-typhoon", "Volt Typhoon"),
        ("wizard-spider", "Wizard Spider"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_apt_playbooks_valid() {
        for playbook in all_apt_playbooks() {
            assert!(!playbook.metadata.id.is_empty());
            assert!(!playbook.metadata.name.is_empty());
            assert!(!playbook.steps.is_empty());
            assert!(playbook.metadata.tags.contains(&"apt".to_string()));
        }
    }

    #[test]
    fn test_get_apt_playbook_by_name() {
        assert!(get_apt_playbook("apt29").is_some());
        assert!(get_apt_playbook("lazarus").is_some());
        assert!(get_apt_playbook("fin7").is_some());
        assert!(get_apt_playbook("APT28").is_some());
    }

    #[test]
    fn test_list_apt_groups() {
        let groups = list_apt_groups();
        assert!(groups.len() >= 15);
        assert!(groups.iter().any(|(id, _)| *id == "apt29"));
    }
}
