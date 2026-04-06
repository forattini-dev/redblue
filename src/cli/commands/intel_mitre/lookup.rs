//! Lookup commands for MITRE ATT&CK objects
//!
//! Query techniques, tactics, groups, and software.

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::intel::attack_database;

use super::display;

/// Get technique details
pub fn get_technique(ctx: &CliContext) -> Result<(), String> {
  let tech_id = ctx
    .target
    .as_ref()
    .ok_or("Missing technique ID (e.g., T1059)")?;

  let format = ctx.get_output_format();
  let is_json = format == crate::cli::format::OutputFormat::Json;

  if !is_json {
    Output::header(&format!("MITRE ATT&CK Technique: {}", tech_id));
    println!();
    Output::spinner_start("Fetching ATT&CK data...");
  }

  let db = attack_database::db();
  let tech = db
    .get_technique(tech_id)
    .or_else(|| db.get_technique_by_name(tech_id));

  if !is_json {
    Output::spinner_done();
  }

  if is_json {
    match tech {
      Some(t) => {
        Output::json_value(&json!({
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
        }));
      }
      None => {
        Output::json_value(&json!({
            "found": false,
            "query": tech_id,
        }));
      }
    }
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
pub fn get_tactic(_ctx: &CliContext) -> Result<(), String> {
  Output::info("Tactic lookup is not yet implemented with the embedded database.");
  Ok(())
}

/// Get threat group details
pub fn get_group(ctx: &CliContext) -> Result<(), String> {
  let group_id = ctx
    .target
    .as_ref()
    .ok_or("Missing group ID or name (e.g., G0016 or APT29)")?;

  let format = ctx.get_output_format();
  let is_json = format == crate::cli::format::OutputFormat::Json;

  if !is_json {
    Output::header(&format!("MITRE ATT&CK Threat Group: {}", group_id));
    println!();
    Output::spinner_start("Fetching ATT&CK data...");
  }

  let db = attack_database::db();
  let group = db
    .get_group(group_id)
    .or_else(|| db.get_group_by_name(group_id));

  if !is_json {
    Output::spinner_done();
  }

  if is_json {
    match group {
      Some(g) => {
        Output::json_value(&json!({
            "found": true,
            "group_id": g.group_id.clone(),
            "name": g.name.clone(),
            "aliases": g.aliases.clone(),
            "associated_techniques": g.associated_techniques.clone(),
            "url": format!("https://attack.mitre.org/groups/{}/", g.group_id),
            "description": g.description.clone(),
        }));
      }
      None => {
        Output::json_value(&json!({
            "found": false,
            "query": group_id,
        }));
      }
    }
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
pub fn get_software(_ctx: &CliContext) -> Result<(), String> {
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

  let format = ctx.get_output_format();
  let is_json = format == crate::cli::format::OutputFormat::Json;

  if !is_json {
    Output::header(&format!("MITRE ATT&CK Search: {}", query));
    println!();
    Output::spinner_start("Searching ATT&CK data...");
  }

  let db = attack_database::db();
  let techniques = db.search_techniques(query);
  let groups = db.search_groups(query);

  if !is_json {
    Output::spinner_done();
  }

  if is_json {
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
    Output::json_value(&json!({
        "query": query,
        "total_results": techniques.len() + groups.len(),
        "techniques": techniques_json,
        "groups": groups_json,
    }));
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
