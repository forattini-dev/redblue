//! Matrix and coverage commands for MITRE ATT&CK
//!
//! Display matrix overview, tactic coverage, statistics, and detection info.

use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::intel::attack_database::{self, AttackTechnique};
use crate::modules::intel::{Confidence, Findings, MappingResult, TechniqueMapper};

use super::helpers::wrap_text;

/// Show ATT&CK matrix overview (ASCII representation)
pub fn show_matrix(ctx: &CliContext) -> Result<(), String> {
  if !ctx.wants_machine_output() {
    Output::header("MITRE ATT&CK Enterprise Matrix");
    println!();
    Output::spinner_start("Loading ATT&CK data...");
  }

  let db = attack_database::db();

  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  // Enterprise ATT&CK tactics in kill chain order
  let tactics_order = [
    ("reconnaissance", "TA0043", "Recon"),
    ("resource-development", "TA0042", "Resource Dev"),
    ("initial-access", "TA0001", "Initial Access"),
    ("execution", "TA0002", "Execution"),
    ("persistence", "TA0003", "Persistence"),
    ("privilege-escalation", "TA0004", "Priv Esc"),
    ("defense-evasion", "TA0005", "Defense Evasion"),
    ("credential-access", "TA0006", "Cred Access"),
    ("discovery", "TA0007", "Discovery"),
    ("lateral-movement", "TA0008", "Lateral Move"),
    ("collection", "TA0009", "Collection"),
    ("command-and-control", "TA0011", "C2"),
    ("exfiltration", "TA0010", "Exfiltration"),
    ("impact", "TA0040", "Impact"),
  ];

  // Count techniques per tactic
  let mut tactic_counts: std::collections::HashMap<&str, Vec<&AttackTechnique>> =
    std::collections::HashMap::new();

  for tech in db.techniques.values() {
    if tech.deprecated || tech.revoked {
      continue;
    }
    for tactic in &tech.tactics {
      tactic_counts.entry(tactic.as_str()).or_default().push(tech);
    }
  }

  let show_full = ctx.has_flag("full");
  let limit: usize = ctx
    .get_flag_with_config("limit")
    .and_then(|s| s.parse().ok())
    .unwrap_or(5);

  // Show statistics summary
  let total_techniques = db
    .techniques
    .values()
    .filter(|t| !t.deprecated && !t.revoked)
    .count();
  let parent_techniques = db
    .techniques
    .values()
    .filter(|t| !t.deprecated && !t.revoked && !t.is_subtechnique)
    .count();
  let subtechniques = total_techniques - parent_techniques;

  let payload = matrix_payload(
    &tactics_order,
    &tactic_counts,
    total_techniques,
    parent_techniques,
    subtechniques,
    db.groups.len(),
  );
  if render::render_machine_output(ctx, "rb intel mitre matrix", &payload)? {
    return Ok(());
  }

  Output::section("Summary");
  Output::item("Total Techniques", &total_techniques.to_string());
  Output::item("Parent Techniques", &parent_techniques.to_string());
  Output::item("Sub-techniques", &subtechniques.to_string());
  Output::item("Threat Groups", &db.groups.len().to_string());
  println!();

  // Display matrix overview (horizontal bar chart)
  Output::section("Tactics Coverage (techniques per tactic)");
  println!();

  let max_count = tactic_counts.values().map(|v| v.len()).max().unwrap_or(1);
  let bar_width = 40;

  for (tactic_key, tactic_id, display_name) in &tactics_order {
    let techs = tactic_counts
      .get(*tactic_key)
      .map(|v| v.as_slice())
      .unwrap_or(&[]);
    let count = techs.len();
    let parent_count = techs.iter().filter(|t| !t.is_subtechnique).count();

    let bar_len = (count * bar_width).checked_div(max_count).unwrap_or(0);

    let bar: String = "█".repeat(bar_len.min(bar_width));

    let color = if count > 50 {
      "\x1b[31m"
    } else if count > 20 {
      "\x1b[33m"
    } else {
      "\x1b[32m"
    };

    println!(
      "  {:<14} {:<7} {}{}\x1b[0m  {:>3} ({} parent)",
      display_name, tactic_id, color, bar, count, parent_count
    );
  }

  println!();

  // If --full flag, show techniques for each tactic
  if show_full {
    Output::section("Techniques by Tactic");
    println!();

    for (tactic_key, tactic_id, display_name) in &tactics_order {
      let techs = match tactic_counts.get(*tactic_key) {
        Some(t) => t,
        None => continue,
      };

      if techs.is_empty() {
        continue;
      }

      let mut sorted_techs: Vec<_> = techs.iter().collect();
      sorted_techs.sort_by(|a, b| match (a.is_subtechnique, b.is_subtechnique) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        _ => a.technique_id.cmp(&b.technique_id),
      });

      println!(
        "  \x1b[1m{} ({})\x1b[0m - {} techniques",
        display_name,
        tactic_id,
        techs.len()
      );

      for tech in sorted_techs.iter().take(limit) {
        let prefix = if tech.is_subtechnique {
          "  └"
        } else {
          "  ├"
        };
        println!("    {} {} - {}", prefix, tech.technique_id, tech.name);
      }

      if sorted_techs.len() > limit {
        println!("    ... and {} more", sorted_techs.len() - limit);
      }
      println!();
    }
  } else {
    Output::info("Use --full to show techniques for each tactic");
    Output::info("Use --limit <n> to control how many techniques to show per tactic");
  }

  Ok(())
}

/// Show tactic coverage based on mapped findings
pub fn show_coverage(ctx: &CliContext) -> Result<(), String> {
  if !ctx.wants_machine_output() {
    Output::header("MITRE ATT&CK Tactic Coverage Report");
    println!();
  }

  let mapper = TechniqueMapper::new();
  let mut findings = Findings::default();

  // Helper to parse a key=value pair
  let parse_kv = |arg: &str, findings: &mut Findings| {
    if let Some(eq_pos) = arg.find('=') {
      let (key, value) = arg.split_at(eq_pos);
      let value = &value[1..];

      match key {
        "ports" | "p" => {
          for part in value.split(',') {
            if let Ok(port) = part.trim().parse::<u16>() {
              findings.ports.push(port);
            }
          }
        }
        "cves" | "cve" => {
          for cve in value.split(',') {
            let cve = cve.trim().to_string();
            let desc = format!("{} vulnerability", cve);
            findings.cves.push((cve, desc));
          }
        }
        "tech" | "t" | "fingerprint" | "fp" => {
          for tech in value.split(',') {
            findings.fingerprints.push(tech.trim().to_string());
          }
        }
        "banner" | "b" => {
          findings.banners.push(value.to_string());
        }
        _ => {}
      }
    }
  };

  if let Some(ref target) = ctx.target {
    parse_kv(target, &mut findings);
  }
  for arg in &ctx.args {
    parse_kv(arg, &mut findings);
  }

  if findings.ports.is_empty()
    && findings.cves.is_empty()
    && findings.fingerprints.is_empty()
    && findings.banners.is_empty()
  {
    if render::render_machine_output(ctx, "rb intel mitre coverage", &coverage_missing_payload())? {
      return Ok(());
    }
    Output::warning("No findings provided. Use flags to specify what to analyze:");
    println!();
    Output::info("  ports=22,80,443        Map open ports");
    Output::info("  cves=CVE-2021-44228    Map CVE IDs");
    Output::info("  tech=wordpress         Map technologies");
    Output::info("  banner=\"Apache/2\"      Map service banner");
    println!();
    Output::info("Example: rb intel mitre coverage ports=22,80,443 tech=wordpress");
    return Ok(());
  }

  // Show what we're analyzing
  if !ctx.wants_machine_output() {
    Output::section("Input Findings");
    if !findings.ports.is_empty() {
      Output::item(
        "Ports",
        &findings
          .ports
          .iter()
          .map(|p| p.to_string())
          .collect::<Vec<_>>()
          .join(", "),
      );
    }
    if !findings.cves.is_empty() {
      Output::item(
        "CVEs",
        &findings
          .cves
          .iter()
          .map(|(id, _)| id.as_str())
          .collect::<Vec<_>>()
          .join(", "),
      );
    }
    if !findings.fingerprints.is_empty() {
      Output::item("Technologies", &findings.fingerprints.join(", "));
    }
    if !findings.banners.is_empty() {
      Output::item("Banners", &findings.banners.join(", "));
    }
    println!();
  }

  if !ctx.wants_machine_output() {
    Output::spinner_start("Mapping to ATT&CK techniques...");
  }
  let result = mapper.map_findings(&findings);
  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  if result.techniques.is_empty() {
    if render::render_machine_output(
      ctx,
      "rb intel mitre coverage",
      &coverage_empty_payload(&findings),
    )? {
      return Ok(());
    }
    Output::info("No techniques mapped for these findings.");
    return Ok(());
  }

  // Enterprise ATT&CK tactics in kill chain order
  let tactics_order = [
    ("Reconnaissance", "TA0043"),
    ("Resource Development", "TA0042"),
    ("Initial Access", "TA0001"),
    ("Execution", "TA0002"),
    ("Persistence", "TA0003"),
    ("Privilege Escalation", "TA0004"),
    ("Defense Evasion", "TA0005"),
    ("Credential Access", "TA0006"),
    ("Discovery", "TA0007"),
    ("Lateral Movement", "TA0008"),
    ("Collection", "TA0009"),
    ("Command and Control", "TA0011"),
    ("Exfiltration", "TA0010"),
    ("Impact", "TA0040"),
  ];

  let total_tactics = tactics_order.len();
  let covered_tactics = result.by_tactic.len();
  let coverage_pct = (covered_tactics as f64 / total_tactics as f64) * 100.0;

  let payload = coverage_payload(
    &findings,
    &result,
    total_tactics,
    covered_tactics,
    coverage_pct,
  );
  if render::render_machine_output(ctx, "rb intel mitre coverage", &payload)? {
    return Ok(());
  }

  Output::section("Coverage Summary");
  Output::item(
    "Techniques Mapped",
    &result.unique_technique_ids().len().to_string(),
  );
  Output::item(
    "Tactics Covered",
    &format!(
      "{}/{} ({:.0}%)",
      covered_tactics, total_tactics, coverage_pct
    ),
  );
  println!();

  // Display tactic coverage bar chart
  Output::section("Tactic Coverage");
  println!();

  let bar_width = 30;

  for (tactic_name, tactic_id) in &tactics_order {
    let tech_count = result
      .by_tactic
      .get(*tactic_name)
      .map(|v| v.len())
      .unwrap_or(0);

    let (bar, color) = if tech_count > 0 {
      let bar_len = (tech_count * bar_width / 10).min(bar_width);
      let bar = "█".repeat(bar_len) + &"░".repeat(bar_width - bar_len);

      let color = if tech_count >= 5 {
        "\x1b[31m"
      } else if tech_count >= 2 {
        "\x1b[33m"
      } else {
        "\x1b[32m"
      };
      (bar, color)
    } else {
      ("░".repeat(bar_width), "\x1b[90m")
    };

    let status = if tech_count > 0 {
      format!("{:>2} techniques", tech_count)
    } else {
      "Not covered".to_string()
    };

    println!(
      "  {:<22} {:<7} {}{}  {}\x1b[0m",
      tactic_name, tactic_id, color, bar, status
    );
  }

  println!();

  // Show technique details per covered tactic
  Output::section("Technique Details");
  println!();

  for (tactic_name, tactic_id) in &tactics_order {
    if let Some(techs) = result.by_tactic.get(*tactic_name) {
      println!("  \x1b[1m{} ({})\x1b[0m", tactic_name, tactic_id);
      for tech in techs {
        let conf_badge = match tech.confidence {
          Confidence::High => "\x1b[32m●\x1b[0m",
          Confidence::Medium => "\x1b[33m●\x1b[0m",
          Confidence::Low => "\x1b[90m●\x1b[0m",
        };
        println!(
          "    {} {} - {} (from {})",
          conf_badge, tech.technique_id, tech.name, tech.original_value
        );
      }
      println!();
    }
  }

  // Summary recommendations
  Output::section("Assessment");
  if coverage_pct >= 70.0 {
    Output::success("High tactic coverage detected. Multiple attack vectors are possible.");
  } else if coverage_pct >= 40.0 {
    Output::warning("Moderate tactic coverage. Some attack vectors identified.");
  } else {
    Output::info("Low tactic coverage. Limited attack surface mapped.");
  }

  let uncovered: Vec<_> = tactics_order
    .iter()
    .filter(|(name, _)| !result.by_tactic.contains_key(*name))
    .map(|(name, _)| *name)
    .collect();

  if !uncovered.is_empty() && uncovered.len() <= 5 {
    println!();
    Output::info(&format!("Uncovered tactics: {}", uncovered.join(", ")));
  }

  Ok(())
}

/// Get mitigations for a technique
pub fn get_mitigations(ctx: &CliContext) -> Result<(), String> {
  if render::render_machine_output(
    ctx,
    "rb intel mitre mitigations",
    &matrix_not_implemented_payload(ctx.target.as_deref(), "mitigations"),
  )? {
    return Ok(());
  }
  Output::info("Mitigations lookup is not yet implemented with the embedded database.");
  Ok(())
}

/// Get detection strategies for a technique
pub fn get_detection(ctx: &CliContext) -> Result<(), String> {
  let tech_id = ctx.target.as_ref().ok_or("Missing technique ID")?;

  if !ctx.wants_machine_output() {
    Output::header(&format!("Detection Strategies for {}", tech_id));
    println!();
  }

  if !ctx.wants_machine_output() {
    Output::spinner_start("Fetching technique data...");
  }
  let db = attack_database::db();
  let tech = db
    .get_technique(tech_id)
    .or_else(|| db.get_technique_by_name(tech_id));
  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = detection_payload(tech_id, tech);
  if render::render_machine_output(ctx, "rb intel mitre detection", &payload)? {
    return Ok(());
  }

  match tech {
    Some(t) => {
      Output::section("Technique");
      Output::item("ID", &t.technique_id);
      Output::item("Name", &t.name);
      println!();

      if !t.data_sources.is_empty() {
        Output::section("Data Sources");
        for ds in &t.data_sources {
          println!("  • {}", ds);
        }
        println!();
      }

      if let Some(ref detection) = t.detection {
        Output::section("Detection Strategy");
        println!("{}", wrap_text(detection, 80));
        println!();
      } else {
        Output::info("No specific detection guidance available.");
      }
    }
    None => {
      Output::warning(&format!("Technique {} not found", tech_id));
    }
  }

  Ok(())
}

/// Show ATT&CK statistics
pub fn show_stats(ctx: &CliContext) -> Result<(), String> {
  if !ctx.wants_machine_output() {
    Output::header("MITRE ATT&CK Statistics");
    println!();
    Output::spinner_start("Loading ATT&CK data...");
  }

  let db = attack_database::db();

  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = stats_payload(db.techniques.len(), db.groups.len());
  if render::render_machine_output(ctx, "rb intel mitre stats", &payload)? {
    return Ok(());
  }

  Output::section("Object Counts");
  Output::item("Techniques", &db.techniques.len().to_string());
  Output::item("Groups", &db.groups.len().to_string());
  println!();

  Output::item("Data Source", "Embedded Enterprise ATT&CK Data");

  Ok(())
}

fn matrix_payload(
  tactics_order: &[(&str, &str, &str)],
  tactic_counts: &std::collections::HashMap<&str, Vec<&AttackTechnique>>,
  total_techniques: usize,
  parent_techniques: usize,
  subtechniques: usize,
  threat_groups: usize,
) -> crate::serde_json::Value {
  let tactics_json: Vec<_> = tactics_order
    .iter()
    .map(|(tactic_key, tactic_id, display_name)| {
      let techs = tactic_counts
        .get(*tactic_key)
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
      let count = techs.len();
      let parent_count = techs.iter().filter(|t| !t.is_subtechnique).count();
      json!({
        "id": tactic_id,
        "name": display_name,
        "technique_count": count,
        "parent_count": parent_count,
      })
    })
    .collect();
  let summary_json = json!({
    "total_techniques": total_techniques,
    "parent_techniques": parent_techniques,
    "subtechniques": subtechniques,
    "threat_groups": threat_groups,
  });
  json!({
    "summary": summary_json,
    "tactics": tactics_json,
  })
}

fn stats_payload(techniques: usize, groups: usize) -> crate::serde_json::Value {
  json!({
    "techniques": techniques,
    "groups": groups,
    "data_source": "Embedded Enterprise ATT&CK Data",
  })
}

fn coverage_input_payload(findings: &Findings) -> crate::serde_json::Value {
  json!({
    "ports": findings.ports.clone(),
    "cves": findings
      .cves
      .iter()
      .map(|(id, _)| id.clone())
      .collect::<Vec<_>>(),
    "technologies": findings.fingerprints.clone(),
    "banners": findings.banners.clone(),
  })
}

fn coverage_missing_payload() -> crate::serde_json::Value {
  json!({
    "error": "No findings provided",
    "coverage": crate::serde_json::Value::Null,
  })
}

fn coverage_empty_payload(findings: &Findings) -> crate::serde_json::Value {
  json!({
    "input": coverage_input_payload(findings),
    "techniques_mapped": 0,
    "tactics_covered": 0,
    "coverage_pct": 0.0,
    "techniques": [],
    "tactics": [],
  })
}

fn coverage_payload(
  findings: &Findings,
  result: &MappingResult,
  total_tactics: usize,
  covered_tactics: usize,
  coverage_pct: f64,
) -> crate::serde_json::Value {
  let tactics: Vec<_> = result
    .coverage
    .iter()
    .filter(|(_, count, _)| *count > 0)
    .map(|(tactic, count, percentage)| {
      json!({
        "tactic": tactic,
        "technique_count": count,
        "percentage": percentage,
      })
    })
    .collect();
  let techniques: Vec<_> = result
    .techniques
    .iter()
    .map(|tech| {
      json!({
        "technique_id": tech.technique_id.clone(),
        "name": tech.name.clone(),
        "tactic": tech.tactic.clone(),
        "confidence": tech.confidence.as_str(),
        "reason": tech.reason.clone(),
        "source": tech.original_value.clone(),
      })
    })
    .collect();
  json!({
    "input": coverage_input_payload(findings),
    "techniques_mapped": result.unique_technique_ids().len(),
    "tactics_covered": covered_tactics,
    "total_tactics": total_tactics,
    "coverage_pct": coverage_pct,
    "tactics": tactics,
    "techniques": techniques,
  })
}

fn matrix_not_implemented_payload(target: Option<&str>, route: &str) -> crate::serde_json::Value {
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

fn detection_payload(query: &str, technique: Option<&AttackTechnique>) -> crate::serde_json::Value {
  match technique {
    Some(t) => json!({
      "found": true,
      "technique_id": t.technique_id.clone(),
      "name": t.name.clone(),
      "data_sources": t.data_sources.clone(),
      "detection": t.detection.clone(),
    }),
    None => json!({
      "found": false,
      "query": query,
    }),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn stats_payload_serializes_counts() {
    let payload = stats_payload(123, 9);
    assert_eq!(payload["techniques"].as_i64(), Some(123));
    assert_eq!(payload["groups"].as_i64(), Some(9));
    assert_eq!(
      payload["data_source"].as_str(),
      Some("Embedded Enterprise ATT&CK Data")
    );
  }

  #[test]
  fn matrix_payload_serializes_summary_and_tactics() {
    let technique = AttackTechnique {
      id: "attack-pattern--1".to_string(),
      technique_id: "T1059".to_string(),
      name: "Command and Scripting Interpreter".to_string(),
      description: String::new(),
      tactics: vec!["execution".to_string()],
      platforms: vec![],
      is_subtechnique: false,
      parent_technique: None,
      url: None,
      deprecated: false,
      revoked: false,
      data_sources: vec![],
      detection: None,
    };
    let mut tactic_counts: std::collections::HashMap<&str, Vec<&AttackTechnique>> =
      std::collections::HashMap::new();
    tactic_counts.insert("execution", vec![&technique]);

    let payload = matrix_payload(
      &[("execution", "TA0002", "Execution")],
      &tactic_counts,
      10,
      7,
      3,
      2,
    );

    assert_eq!(payload["summary"]["total_techniques"].as_i64(), Some(10));
    assert_eq!(payload["summary"]["threat_groups"].as_i64(), Some(2));
    assert_eq!(
      payload["tactics"].as_array().unwrap()[0]["id"].as_str(),
      Some("TA0002")
    );
    assert_eq!(
      payload["tactics"].as_array().unwrap()[0]["technique_count"].as_i64(),
      Some(1)
    );
    assert_eq!(
      payload["tactics"].as_array().unwrap()[0]["parent_count"].as_i64(),
      Some(1)
    );
  }

  #[test]
  fn coverage_payload_serializes_inputs_and_summary() {
    let findings = Findings {
      ports: vec![22],
      cves: vec![("CVE-2021-44228".to_string(), "desc".to_string())],
      fingerprints: vec!["wordpress".to_string()],
      banners: vec!["Apache/2".to_string()],
    };
    let technique = crate::modules::intel::MappedTechnique {
      technique_id: "T1021.004".to_string(),
      name: "Remote Services: SSH".to_string(),
      reason: "SSH enables remote command execution".to_string(),
      tactic: "Lateral Movement".to_string(),
      confidence: Confidence::High,
      source: crate::modules::intel::MappingSource::Port,
      original_value: "22".to_string(),
    };
    let mut by_tactic = std::collections::HashMap::new();
    by_tactic.insert("Lateral Movement".to_string(), vec![technique.clone()]);
    let result = MappingResult {
      techniques: vec![technique],
      by_tactic,
      coverage: vec![("Lateral Movement".to_string(), 1, 100.0)],
    };

    let payload = coverage_payload(&findings, &result, 14, 1, 7.14);

    assert_eq!(
      payload["input"]["ports"].as_array().unwrap()[0].as_i64(),
      Some(22)
    );
    assert_eq!(payload["techniques_mapped"].as_i64(), Some(1));
    assert_eq!(payload["tactics_covered"].as_i64(), Some(1));
    assert_eq!(
      payload["techniques"].as_array().unwrap()[0]["technique_id"].as_str(),
      Some("T1021.004")
    );
  }

  #[test]
  fn detection_payload_handles_lookup_miss() {
    let payload = detection_payload("T9999", None);
    assert_eq!(payload["found"].as_bool(), Some(false));
    assert_eq!(payload["query"].as_str(), Some("T9999"));
  }

  #[test]
  fn matrix_not_implemented_payload_is_structured() {
    let payload = matrix_not_implemented_payload(Some("T1059"), "mitigations");
    assert_eq!(payload["status"].as_str(), Some("not_implemented"));
    assert_eq!(payload["route"].as_str(), Some("mitigations"));
    assert_eq!(payload["target"].as_str(), Some("T1059"));
  }
}
