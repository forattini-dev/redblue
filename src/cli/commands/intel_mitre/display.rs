//! Display helpers for MITRE ATT&CK objects
//!
//! Functions to display techniques, tactics, groups, and software.

use crate::cli::output::Output;
use crate::modules::intel::attack_database::{AttackTechnique, Software, Tactic, ThreatGroup};

use super::helpers::wrap_text;

/// Display technique details
pub fn display_technique(tech: &AttackTechnique, full: bool) {
  Output::section("Overview");
  Output::item("ID", &tech.technique_id);
  Output::item("Name", &tech.name);
  if let Some(url) = &tech.url {
    Output::item("URL", url);
  }

  if tech.is_subtechnique {
    if let Some(ref parent) = tech.parent_technique {
      Output::item("Parent", parent);
    }
  }

  if !tech.tactics.is_empty() {
    Output::item("Tactics", &tech.tactics.join(", "));
  }

  if !tech.platforms.is_empty() {
    Output::item("Platforms", &tech.platforms.join(", "));
  }

  if tech.deprecated {
    println!();
    Output::warning("This technique is DEPRECATED");
  }

  if tech.revoked {
    println!();
    Output::warning("This technique is REVOKED");
  }

  if full && !tech.description.is_empty() {
    println!();
    Output::section("Description");
    println!("{}", wrap_text(&tech.description, 80));
  }

  if !tech.data_sources.is_empty() {
    println!();
    Output::section("Data Sources");
    for ds in &tech.data_sources {
      println!("  • {}", ds);
    }
  }

  if full {
    if let Some(ref detection) = tech.detection {
      println!();
      Output::section("Detection");
      println!("{}", wrap_text(detection, 80));
    }
  }
}

/// Display tactic details
pub fn display_tactic(tactic: &Tactic, full: bool) {
  Output::section("Overview");
  Output::item("ID", &tactic.id);
  Output::item("Name", &tactic.name);

  let url = format!("https://attack.mitre.org/tactics/{}/", tactic.id);
  Output::item("URL", &url);

  if full && !tactic.description.is_empty() {
    println!();
    Output::section("Description");
    println!("{}", wrap_text(&tactic.description, 80));
  }
}

/// Display group details
pub fn display_group(group: &ThreatGroup, full: bool) {
  Output::section("Overview");
  Output::item("ID", &group.group_id);
  Output::item("Name", &group.name);

  if !group.aliases.is_empty() {
    Output::item("Aliases", &group.aliases.join(", "));
  }

  let url = format!("https://attack.mitre.org/groups/{}/", group.group_id);
  Output::item("URL", &url);

  if full && !group.description.is_empty() {
    println!();
    Output::section("Description");
    println!("{}", wrap_text(&group.description, 80));
  }

  if !group.associated_techniques.is_empty() {
    println!();
    Output::section(&format!(
      "Techniques ({})",
      group.associated_techniques.len()
    ));
    for tech in group.associated_techniques.iter().take(15) {
      println!("  • {}", tech);
    }
    if group.associated_techniques.len() > 15 {
      Output::info(&format!(
        "  ... and {} more",
        group.associated_techniques.len() - 15
      ));
    }
  }
}

/// Display software details
pub fn display_software(software: &Software, full: bool) {
  Output::section("Overview");
  Output::item("ID", &software.id);
  Output::item("Name", &software.name);

  let url = format!("https://attack.mitre.org/software/{}/", software.id);
  Output::item("URL", &url);

  if full && !software.description.is_empty() {
    println!();
    Output::section("Description");
    println!("{}", wrap_text(&software.description, 80));
  }
}
