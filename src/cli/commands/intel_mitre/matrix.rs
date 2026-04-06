//! Matrix and coverage commands for MITRE ATT&CK
//!
//! Display matrix overview, tactic coverage, statistics, and detection info.

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::intel::attack_database::{self, AttackTechnique};
use crate::modules::intel::{Confidence, Findings, TechniqueMapper};

use super::helpers::wrap_text;

/// Show ATT&CK matrix overview (ASCII representation)
pub fn show_matrix(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_output_format();
  let is_json = format == crate::cli::format::OutputFormat::Json;

  if !is_json {
    Output::header("MITRE ATT&CK Enterprise Matrix");
    println!();
    Output::spinner_start("Loading ATT&CK data...");
  }

  let db = attack_database::db();

  if !is_json {
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

  if is_json {
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
        "threat_groups": db.groups.len(),
    });
    Output::json_value(&json!({
        "summary": summary_json,
        "tactics": tactics_json,
    }));
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

    let bar_len = if max_count > 0 {
      (count * bar_width) / max_count
    } else {
      0
    };

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
  Output::header("MITRE ATT&CK Tactic Coverage Report");
  println!();

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

  Output::spinner_start("Mapping to ATT&CK techniques...");
  let result = mapper.map_findings(&findings);
  Output::spinner_done();

  if result.techniques.is_empty() {
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
pub fn get_mitigations(_ctx: &CliContext) -> Result<(), String> {
  Output::info("Mitigations lookup is not yet implemented with the embedded database.");
  Ok(())
}

/// Get detection strategies for a technique
pub fn get_detection(ctx: &CliContext) -> Result<(), String> {
  let tech_id = ctx.target.as_ref().ok_or("Missing technique ID")?;

  Output::header(&format!("Detection Strategies for {}", tech_id));
  println!();

  Output::spinner_start("Fetching technique data...");
  let db = attack_database::db();
  let tech = db
    .get_technique(tech_id)
    .or_else(|| db.get_technique_by_name(tech_id));
  Output::spinner_done();

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
  let format = ctx.get_output_format();
  let is_json = format == crate::cli::format::OutputFormat::Json;

  if !is_json {
    Output::header("MITRE ATT&CK Statistics");
    println!();
    Output::spinner_start("Loading ATT&CK data...");
  }

  let db = attack_database::db();

  if !is_json {
    Output::spinner_done();
  }

  if is_json {
    Output::json_value(&json!({
        "techniques": db.techniques.len(),
        "groups": db.groups.len(),
        "data_source": "Embedded Enterprise ATT&CK Data",
    }));
    return Ok(());
  }

  Output::section("Object Counts");
  Output::item("Techniques", &db.techniques.len().to_string());
  Output::item("Groups", &db.groups.len().to_string());
  println!();

  Output::item("Data Source", "Embedded Enterprise ATT&CK Data");

  Ok(())
}
