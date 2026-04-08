//! Lookup commands for MITRE ATT&CK objects
//!
//! Query techniques, tactics, groups, and software.

use crate::cli::CliContext;
use crate::cli::{output::Output, render};
use crate::json;
use crate::modules::intel::attack_database;
use crate::modules::intel::attack_database::{AttackTechnique, ThreatGroup};

use super::display;

/// Get technique details
pub fn get_technique(ctx: &CliContext) -> Result<(), String> {
  let tech_id = ctx
    .target
    .as_ref()
    .ok_or("Missing technique ID (e.g., T1059)")?;

  if !ctx.wants_machine_output() {
    Output::header(&format!("MITRE ATT&CK Technique: {}", tech_id));
    println!();
    Output::spinner_start("Fetching ATT&CK data...");
  }

  let db = attack_database::db();
  let tech = db
    .get_technique(tech_id)
    .or_else(|| db.get_technique_by_name(tech_id));

  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = technique_payload(tech_id, tech);
  if render::render_machine_output(ctx, "rb intel mitre technique", &payload)? {
    return Ok(());
  }

  match tech {
    Some(t) => display::display_technique(t, ctx.has_flag("full")),
    None => {
      Output::warning(&format!("Technique {} not found", tech_id));
      Output::info("Try searching: rb intel mitre search <query>");
    }
  }

  Ok(())
}

/// Get tactic details
pub fn get_tactic(ctx: &CliContext) -> Result<(), String> {
  if render::render_machine_output(
    ctx,
    "rb intel mitre tactic",
    &not_implemented_payload(ctx.target.as_deref(), "tactic"),
  )? {
    return Ok(());
  }
  Output::info("Tactic lookup is not yet implemented with the embedded database.");
  Ok(())
}

/// Get threat group details
pub fn get_group(ctx: &CliContext) -> Result<(), String> {
  let group_id = ctx
    .target
    .as_ref()
    .ok_or("Missing group ID or name (e.g., G0016 or APT29)")?;

  if !ctx.wants_machine_output() {
    Output::header(&format!("MITRE ATT&CK Threat Group: {}", group_id));
    println!();
    Output::spinner_start("Fetching ATT&CK data...");
  }

  let db = attack_database::db();
  let group = db
    .get_group(group_id)
    .or_else(|| db.get_group_by_name(group_id));

  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = group_payload(group_id, group);
  if render::render_machine_output(ctx, "rb intel mitre group", &payload)? {
    return Ok(());
  }

  match group {
    Some(g) => display::display_group(g, ctx.has_flag("full")),
    None => {
      Output::warning(&format!("Group {} not found", group_id));
      Output::info("Try searching: rb intel mitre search <query>");
    }
  }

  Ok(())
}

/// Get software details
pub fn get_software(ctx: &CliContext) -> Result<(), String> {
  if render::render_machine_output(
    ctx,
    "rb intel mitre software",
    &not_implemented_payload(ctx.target.as_deref(), "software"),
  )? {
    return Ok(());
  }
  Output::info("Software lookup is not yet implemented with the embedded database.");
  Ok(())
}

/// Search ATT&CK
pub fn search(ctx: &CliContext) -> Result<(), String> {
  let query = ctx.target.as_ref().ok_or("Missing search query")?;
  let limit: usize = ctx
    .get_flag_with_config("limit")
    .and_then(|s| s.parse().ok())
    .unwrap_or(20);

  if !ctx.wants_machine_output() {
    Output::header(&format!("MITRE ATT&CK Search: {}", query));
    println!();
    Output::spinner_start("Searching ATT&CK data...");
  }

  let db = attack_database::db();
  let techniques = db.search_techniques(query);
  let groups = db.search_groups(query);

  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = search_payload(query, limit, &techniques, &groups);
  if render::render_machine_output(ctx, "rb intel mitre search", &payload)? {
    return Ok(());
  }

  if techniques.is_empty() && groups.is_empty() {
    Output::info("No results found.");
    return Ok(());
  }

  Output::success(&format!(
    "Found {} results",
    techniques.len() + groups.len()
  ));
  println!();

  if !techniques.is_empty() {
    Output::section(&format!("Techniques ({})", techniques.len()));
    for t in techniques.iter().take(limit) {
      let tactics_str = if t.tactics.is_empty() {
        String::new()
      } else {
        format!(" [{}]", t.tactics.join(", "))
      };
      println!("  {} - {}{}", t.technique_id, t.name, tactics_str);
    }
    if techniques.len() > limit {
      Output::info(&format!("  ... and {} more", techniques.len() - limit));
    }
    println!();
  }

  if !groups.is_empty() {
    Output::section(&format!("Groups ({})", groups.len()));
    for g in groups.iter().take(limit) {
      let aliases = if g.aliases.is_empty() {
        String::new()
      } else {
        format!(" ({})", g.aliases.join(", "))
      };
      println!("  {} - {}{}", g.group_id, g.name, aliases);
    }
    if groups.len() > limit {
      Output::info(&format!("  ... and {} more", groups.len() - limit));
    }
    println!();
  }

  Ok(())
}

fn technique_payload(query: &str, technique: Option<&AttackTechnique>) -> crate::serde_json::Value {
  match technique {
    Some(t) => json!({
      "found": true,
      "technique_id": t.technique_id.clone(),
      "name": t.name.clone(),
      "is_subtechnique": t.is_subtechnique,
      "parent_technique": t.parent_technique.clone(),
      "tactics": t.tactics.clone(),
      "platforms": t.platforms.clone(),
      "data_sources": t.data_sources.clone(),
      "url": t.url.clone(),
      "deprecated": t.deprecated,
      "revoked": t.revoked,
      "description": t.description.clone(),
    }),
    None => json!({
      "found": false,
      "query": query,
    }),
  }
}

fn group_payload(query: &str, group: Option<&ThreatGroup>) -> crate::serde_json::Value {
  match group {
    Some(g) => json!({
      "found": true,
      "group_id": g.group_id.clone(),
      "name": g.name.clone(),
      "aliases": g.aliases.clone(),
      "associated_techniques": g.associated_techniques.clone(),
      "url": format!("https://attack.mitre.org/groups/{}/", g.group_id),
      "description": g.description.clone(),
    }),
    None => json!({
      "found": false,
      "query": query,
    }),
  }
}

fn search_payload(
  query: &str,
  limit: usize,
  techniques: &[&AttackTechnique],
  groups: &[&ThreatGroup],
) -> crate::serde_json::Value {
  let techniques_json: Vec<_> = techniques
    .iter()
    .take(limit)
    .map(|t| {
      json!({
        "technique_id": t.technique_id.clone(),
        "name": t.name.clone(),
        "tactics": t.tactics.clone(),
      })
    })
    .collect();
  let groups_json: Vec<_> = groups
    .iter()
    .take(limit)
    .map(|g| {
      json!({
        "group_id": g.group_id.clone(),
        "name": g.name.clone(),
        "aliases": g.aliases.clone(),
      })
    })
    .collect();
  json!({
    "query": query,
    "limit": limit,
    "total_results": techniques.len() + groups.len(),
    "techniques": techniques_json,
    "groups": groups_json,
  })
}

fn not_implemented_payload(target: Option<&str>, route: &str) -> crate::serde_json::Value {
  json!({
    "target": target,
    "route": route,
    "status": "not_implemented",
    "message": format!(
      "{} lookup is not yet implemented with the embedded database.",
      route
    ),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn technique_payload_reports_lookup_miss() {
    let payload = technique_payload("T9999", None);
    assert_eq!(payload["found"].as_bool(), Some(false));
    assert_eq!(payload["query"].as_str(), Some("T9999"));
  }

  #[test]
  fn group_payload_serializes_group_fields() {
    let group = ThreatGroup {
      id: "intrusion-set--1".to_string(),
      group_id: "G0001".to_string(),
      name: "Example Group".to_string(),
      description: "Example description".to_string(),
      aliases: vec!["Alias".to_string()],
      associated_techniques: vec!["T1059".to_string()],
    };

    let payload = group_payload("G0001", Some(&group));

    assert_eq!(payload["found"].as_bool(), Some(true));
    assert_eq!(payload["group_id"].as_str(), Some("G0001"));
    assert_eq!(payload["name"].as_str(), Some("Example Group"));
    assert_eq!(
      payload["associated_techniques"].as_array().unwrap()[0].as_str(),
      Some("T1059")
    );
  }

  #[test]
  fn search_payload_respects_limit_and_counts() {
    let technique = AttackTechnique {
      id: "attack-pattern--1".to_string(),
      technique_id: "T1059".to_string(),
      name: "Command and Scripting Interpreter".to_string(),
      description: String::new(),
      tactics: vec!["execution".to_string()],
      platforms: vec!["Linux".to_string()],
      is_subtechnique: false,
      parent_technique: None,
      url: None,
      deprecated: false,
      revoked: false,
      data_sources: Vec::new(),
      detection: None,
    };
    let group = ThreatGroup {
      id: "intrusion-set--1".to_string(),
      group_id: "G0001".to_string(),
      name: "Example Group".to_string(),
      description: String::new(),
      aliases: vec!["Alias".to_string()],
      associated_techniques: vec!["T1059".to_string()],
    };

    let payload = search_payload("exec", 1, &[&technique], &[&group]);

    assert_eq!(payload["query"].as_str(), Some("exec"));
    assert_eq!(payload["limit"].as_i64(), Some(1));
    assert_eq!(payload["total_results"].as_i64(), Some(2));
    assert_eq!(
      payload["techniques"].as_array().unwrap()[0]["technique_id"].as_str(),
      Some("T1059")
    );
    assert_eq!(
      payload["groups"].as_array().unwrap()[0]["group_id"].as_str(),
      Some("G0001")
    );
  }

  #[test]
  fn not_implemented_payload_is_machine_friendly() {
    let payload = not_implemented_payload(Some("APT29"), "software");
    assert_eq!(payload["status"].as_str(), Some("not_implemented"));
    assert_eq!(payload["route"].as_str(), Some("software"));
    assert_eq!(payload["target"].as_str(), Some("APT29"));
  }
}
