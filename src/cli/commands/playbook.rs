//! Playbook Command - Manage and execute pentest methodologies
//!
//! rb playbook list                    # List available playbooks
//! rb playbook catalog                 # List catalog playbooks (new system)
//! rb playbook show <id>               # Show playbook phases and techniques
//! rb playbook run <id> --target <t>   # Execute a playbook against target
//! rb playbook chain <id> --target <t> # Execute a playbook chain
//! rb playbook chains                  # List available chains
//! rb playbook history                 # Show execution history

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::playbooks::{
  all_chains, all_playbooks, get_chain, get_playbook, ChainCondition, RiskLevel,
};
use crate::storage::records::{PlaybookRunRecord, PlaybookStatus, StepResult};
use crate::storage::segments::playbook_defs::{
  Playbook, PlaybookCategory, PlaybookDefinitionSegment,
};
use crate::storage::segments::playbooks::PlaybookSegment;

use super::{Command, Flag, Route};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// PlaybookCommand - rb playbook *
// ============================================================================

pub struct PlaybookCommand;

impl Command for PlaybookCommand {
  fn domain(&self) -> &str {
    "playbook"
  }

  fn resource(&self) -> &str {
    "methodology"
  }

  fn description(&self) -> &str {
    "Manage and execute pentest methodologies"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "list",
        summary: "List available playbooks",
        usage: "rb playbook methodology list",
      },
      Route {
        verb: "catalog",
        summary: "List catalog playbooks (new system)",
        usage: "rb playbook methodology catalog --category recon",
      },
      Route {
        verb: "show",
        summary: "Show playbook details",
        usage: "rb playbook methodology show thp3-web",
      },
      Route {
        verb: "phases",
        summary: "List phases for a playbook",
        usage: "rb playbook methodology phases thp3-network",
      },
      Route {
        verb: "run",
        summary: "Execute a playbook",
        usage: "rb playbook methodology run thp3-web --target example.com",
      },
      Route {
        verb: "chains",
        summary: "List available playbook chains",
        usage: "rb playbook methodology chains",
      },
      Route {
        verb: "chain",
        summary: "Execute a playbook chain",
        usage: "rb playbook methodology chain ad-compromise --target dc01.corp.local",
      },
      Route {
        verb: "history",
        summary: "Show execution history",
        usage: "rb playbook methodology history",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("target", "Target for playbook execution").with_short('t'),
      Flag::new(
        "category",
        "Filter by category: web, network, recon, cloud, etc.",
      )
      .with_short('c'),
      Flag::new("dry-run", "Show what would be executed without running"),
      Flag::new("format", "Output format: text, json")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("List all playbooks", "rb playbook methodology list"),
      (
        "Show web testing playbook",
        "rb playbook methodology show thp3-web",
      ),
      (
        "Run network playbook",
        "rb playbook methodology run thp3-network --target 192.168.1.0/24",
      ),
      (
        "Dry run a playbook",
        "rb playbook methodology run thp3-recon --target example.com --dry-run",
      ),
      ("Show execution history", "rb playbook methodology history"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("list");

    match verb {
      "list" => execute_list(ctx),
      "catalog" => execute_catalog(ctx),
      "show" => execute_show(ctx),
      "phases" => execute_phases(ctx),
      "run" => execute_run(ctx),
      "chains" => execute_chains(ctx),
      "chain" => execute_chain(ctx),
      "history" => execute_history(ctx),
      _ => Err(format!(
        "Unknown verb '{}'. Use: list, catalog, show, phases, run, chains, chain, history",
        verb
      )),
    }
  }
}

// ============================================================================
// Persistence Helpers
// ============================================================================

fn get_defs_path() -> std::path::PathBuf {
  let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
  std::path::PathBuf::from(home)
    .join(".redblue")
    .join("playbook_defs.segment")
}

fn get_history_path() -> std::path::PathBuf {
  let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
  std::path::PathBuf::from(home)
    .join(".redblue")
    .join("playbook_history.segment")
}

fn load_definitions() -> PlaybookDefinitionSegment {
  let path = get_defs_path();
  if path.exists() {
    match std::fs::read(&path) {
      Ok(bytes) => PlaybookDefinitionSegment::deserialize(&bytes)
        .unwrap_or_else(|_| PlaybookDefinitionSegment::with_builtins()),
      Err(_) => PlaybookDefinitionSegment::with_builtins(),
    }
  } else {
    // First run - create with builtins and save
    let segment = PlaybookDefinitionSegment::with_builtins();
    let _ = save_definitions(&segment);
    segment
  }
}

fn save_definitions(segment: &PlaybookDefinitionSegment) -> Result<(), String> {
  let path = get_defs_path();
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
  }
  let bytes = segment.serialize();
  std::fs::write(&path, bytes).map_err(|e| format!("Failed to save playbook definitions: {}", e))
}

fn load_history() -> PlaybookSegment {
  let path = get_history_path();
  if path.exists() {
    match std::fs::read(&path) {
      Ok(bytes) => PlaybookSegment::deserialize(&bytes).unwrap_or_default(),
      Err(_) => PlaybookSegment::new(),
    }
  } else {
    PlaybookSegment::new()
  }
}

fn save_history(segment: &PlaybookSegment) -> Result<(), String> {
  let path = get_history_path();
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
  }
  let bytes = segment.serialize();
  std::fs::write(&path, bytes).map_err(|e| format!("Failed to save playbook history: {}", e))
}

// ============================================================================
// Verb Implementations
// ============================================================================

fn execute_list(ctx: &CliContext) -> Result<(), String> {
  let segment = load_definitions();

  let category_filter = ctx
    .flags
    .get("category")
    .map(|s| parse_category(s))
    .transpose()?;

  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");

  let playbooks: Vec<&Playbook> = if let Some(cat) = category_filter {
    segment.get_by_category(cat)
  } else {
    segment.all().iter().collect()
  };

  if playbooks.is_empty() {
    Output::info("No playbooks found");
    return Ok(());
  }

  match format {
    "json" => {
      println!("[");
      for (i, pb) in playbooks.iter().enumerate() {
        let comma = if i < playbooks.len() - 1 { "," } else { "" };
        println!(
          r#"  {{"id":"{}","name":"{}","category":"{}","phases":{}}}{}"#,
          pb.id,
          pb.name,
          pb.category.as_str(),
          pb.phases.len(),
          comma
        );
      }
      println!("]");
    }
    _ => {
      Output::header(&format!("Playbooks ({} available)", playbooks.len()));
      println!();

      for pb in &playbooks {
        let cat_color = match pb.category {
          PlaybookCategory::Web => "\x1b[35m",     // magenta
          PlaybookCategory::Network => "\x1b[34m", // blue
          PlaybookCategory::Recon => "\x1b[36m",   // cyan
          PlaybookCategory::Cloud => "\x1b[33m",   // yellow
          _ => "\x1b[37m",                         // white
        };
        let reset = "\x1b[0m";

        println!(
          "  \x1b[1m{:<15}\x1b[0m {}{:>12}{} │ {} phases",
          pb.id,
          cat_color,
          pb.category.as_str(),
          reset,
          pb.phases.len()
        );
        println!("                  {}", truncate(&pb.description, 60));
        println!();
      }
    }
  }

  Ok(())
}

// ============================================================================
// Catalog Playbook Functions (New System)
// ============================================================================

fn execute_catalog(ctx: &CliContext) -> Result<(), String> {
  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");
  let category_filter = ctx.flags.get("category");

  let mut playbooks = all_playbooks();

  // Filter by category/tag if specified
  if let Some(cat) = category_filter {
    let cat_lower = cat.to_lowercase();
    playbooks.retain(|p| {
      p.metadata
        .tags
        .iter()
        .any(|t| t.to_lowercase().contains(&cat_lower))
    });
  }

  if playbooks.is_empty() {
    Output::info("No catalog playbooks found");
    return Ok(());
  }

  match format {
    "json" => {
      println!("[");
      for (i, pb) in playbooks.iter().enumerate() {
        let comma = if i < playbooks.len() - 1 { "," } else { "" };
        println!(
          r#"  {{"id":"{}","name":"{}","risk":"{}","steps":{}}}{}"#,
          pb.metadata.id,
          pb.metadata.name,
          risk_level_str(&pb.metadata.risk_level),
          pb.total_steps(),
          comma
        );
      }
      println!("]");
    }
    _ => {
      Output::header(&format!(
        "Catalog Playbooks ({} available)",
        playbooks.len()
      ));
      println!();

      for pb in &playbooks {
        let risk_color = match pb.metadata.risk_level {
          RiskLevel::Critical => "\x1b[31m", // red
          RiskLevel::High => "\x1b[33m",     // yellow
          RiskLevel::Medium => "\x1b[36m",   // cyan
          RiskLevel::Low => "\x1b[32m",      // green
          RiskLevel::Passive => "\x1b[37m",  // white
        };
        let reset = "\x1b[0m";

        println!(
          "  \x1b[1m{:<30}\x1b[0m {}{:>8}{} │ {} steps",
          pb.metadata.id,
          risk_color,
          risk_level_str(&pb.metadata.risk_level),
          reset,
          pb.total_steps()
        );
        println!(
          "                                 {}",
          truncate(&pb.metadata.description, 50)
        );
        println!();
      }

      println!("  Use 'rb playbook methodology show <id>' for details");
    }
  }

  Ok(())
}

fn execute_chains(ctx: &CliContext) -> Result<(), String> {
  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");
  let chains = all_chains();

  if chains.is_empty() {
    Output::info("No playbook chains defined");
    return Ok(());
  }

  match format {
    "json" => {
      println!("[");
      for (i, chain) in chains.iter().enumerate() {
        let comma = if i < chains.len() - 1 { "," } else { "" };
        println!(
          r#"  {{"id":"{}","name":"{}","playbooks":{}}}{}"#,
          chain.id,
          chain.name,
          chain.total_playbooks(),
          comma
        );
      }
      println!("]");
    }
    _ => {
      Output::header(&format!("Playbook Chains ({} available)", chains.len()));
      println!();

      for chain in &chains {
        let risk_color = match chain.risk_level {
          RiskLevel::Critical => "\x1b[31m",
          RiskLevel::High => "\x1b[33m",
          RiskLevel::Medium => "\x1b[36m",
          RiskLevel::Low => "\x1b[32m",
          RiskLevel::Passive => "\x1b[37m",
        };
        let reset = "\x1b[0m";

        println!(
          "  \x1b[1m{:<20}\x1b[0m {}{:>8}{} │ {} playbooks",
          chain.id,
          risk_color,
          risk_level_str(&chain.risk_level),
          reset,
          chain.total_playbooks()
        );
        println!(
          "                       {}",
          truncate(&chain.description, 55)
        );
        println!();

        // Show chain flow
        print!("    Flow: ");
        for (i, pb) in chain.playbooks.iter().enumerate() {
          if i > 0 {
            print!(" → ");
          }
          let cond = match &pb.condition {
            ChainCondition::Always => "",
            ChainCondition::OnSuccess => "(on success)",
            ChainCondition::OnFailure => "(on failure)",
            ChainCondition::OnEvidence(_) => "(on evidence)",
            ChainCondition::OnSeverity(_) => "(on severity)",
          };
          print!("{}{}", pb.playbook_id, cond);
        }
        println!();
        println!();
      }
    }
  }

  Ok(())
}

fn execute_chain(ctx: &CliContext) -> Result<(), String> {
  let id = ctx
    .target
    .as_deref()
    .ok_or("Missing chain ID. Usage: rb playbook methodology chain <id> --target <target>")?;
  let target = ctx.flags.get("target").ok_or("Missing --target flag")?;
  let dry_run = ctx.flags.contains_key("dry-run");

  let chain = get_chain(id).ok_or_else(|| format!("Chain '{}' not found", id))?;

  if dry_run {
    Output::header(&format!("Dry Run Chain: {} against {}", chain.name, target));
    println!();
    println!("  Chain: {}", chain.description);
    println!();
    println!("  The following playbooks would be executed:");
    println!();

    for (i, chained) in chain.playbooks.iter().enumerate() {
      let condition = match &chained.condition {
        ChainCondition::Always => "always".to_string(),
        ChainCondition::OnSuccess => "on success".to_string(),
        ChainCondition::OnFailure => "on failure".to_string(),
        ChainCondition::OnEvidence(e) => format!("on evidence: {:?}", e),
        ChainCondition::OnSeverity(s) => format!("on severity: {:?}", s),
      };

      if let Some(pb) = get_playbook(&chained.playbook_id) {
        println!(
          "  {}. \x1b[1m{}\x1b[0m ({})",
          i + 1,
          pb.metadata.name,
          condition
        );
        println!("     {} steps", pb.total_steps());
      } else {
        println!(
          "  {}. \x1b[31m{} (NOT FOUND)\x1b[0m",
          i + 1,
          chained.playbook_id
        );
      }
    }

    println!();
    println!("  Total: {} playbooks in chain", chain.total_playbooks());
    return Ok(());
  }

  // Start actual chain execution
  Output::header(&format!("Running Chain: {} against {}", chain.name, target));
  println!();

  for (i, chained) in chain.playbooks.iter().enumerate() {
    if let Some(pb) = get_playbook(&chained.playbook_id) {
      println!(
        "  [{}/{}] \x1b[1m{}\x1b[0m",
        i + 1,
        chain.total_playbooks(),
        pb.metadata.name
      );
      println!("  ────────────────────────────────────────────");

      for step in &pb.steps {
        println!("    Step {}: {}", step.number, step.name);
        if !step.commands.is_empty() {
          for cmd in &step.commands {
            let resolved = cmd.replace("{{ target }}", target);
            println!("      \x1b[36m$ {}\x1b[0m", resolved);
          }
        }
        if let Some(manual) = &step.manual_instructions {
          println!("      \x1b[33m→ Manual: {}\x1b[0m", manual);
        }
      }
      println!();
    } else {
      println!(
        "  [{}/{}] \x1b[31mSkipping {} (not found)\x1b[0m",
        i + 1,
        chain.total_playbooks(),
        chained.playbook_id
      );
    }
  }

  Output::success(&format!("Chain '{}' completed for target '{}'", id, target));
  println!();
  println!("  Note: Commands are shown but not automatically executed.");
  println!("  Copy and run the commands manually or use a scripting integration.");

  Ok(())
}

fn risk_level_str(risk: &RiskLevel) -> &'static str {
  match risk {
    RiskLevel::Passive => "passive",
    RiskLevel::Low => "low",
    RiskLevel::Medium => "medium",
    RiskLevel::High => "high",
    RiskLevel::Critical => "critical",
  }
}

// ============================================================================
// Playbook Functions
// ============================================================================

fn execute_show(ctx: &CliContext) -> Result<(), String> {
  let id = ctx
    .target
    .as_deref()
    .ok_or("Missing playbook ID. Usage: rb playbook methodology show <id>")?;

  // Try catalog playbooks first
  if let Some(pb) = get_playbook(id) {
    Output::header(&format!("Playbook: {}", pb.metadata.name));
    println!();
    println!("  ID:          {}", pb.metadata.id);
    println!("  Risk:        {}", risk_level_str(&pb.metadata.risk_level));
    println!("  Tags:        {}", pb.metadata.tags.join(", "));
    println!("  Duration:    {}", pb.metadata.estimated_duration);
    println!();
    println!("  Objective:");
    println!("  {}", pb.metadata.objective);
    println!();
    println!("  Description:");
    println!("  {}", pb.metadata.description);
    println!();

    if !pb.preconditions.is_empty() {
      println!("  Preconditions:");
      for pre in &pb.preconditions {
        println!("    • {}", pre.description);
      }
      println!();
    }

    println!("  Steps ({}):", pb.steps.len());
    println!("  ─────────────────────────────────────────────");

    for step in &pb.steps {
      println!();
      println!(
        "  {}. \x1b[1m{}\x1b[0m [{}]",
        step.number, step.name, step.phase
      );
      println!("     {}", step.description);

      if !step.commands.is_empty() {
        println!("     Commands:");
        for cmd in &step.commands {
          println!("       \x1b[36m$ {}\x1b[0m", cmd);
        }
      }

      if let Some(manual) = &step.manual_instructions {
        println!("     Manual: {}", manual);
      }

      if let Some(evidence) = &step.evidence_type {
        println!("     Evidence: {:?}", evidence);
      }
    }

    if !pb.evidence.is_empty() {
      println!();
      println!("  Expected Evidence:");
      for ev in &pb.evidence {
        println!("    • {} at {}", ev.description, ev.location);
      }
    }

    return Ok(());
  }

  // Fall back to definition segment
  let segment = load_definitions();

  let playbook = segment
    .get(id)
    .ok_or_else(|| format!("Playbook '{}' not found", id))?;

  Output::header(&format!("Playbook: {}", playbook.name));
  println!();
  println!("  ID:          {}", playbook.id);
  println!("  Category:    {}", playbook.category.as_str());
  println!("  Author:      {}", playbook.author);
  println!("  Version:     {}", playbook.version);
  println!("  Tags:        {}", playbook.tags.join(", "));
  println!();
  println!("  Description:");
  println!("  {}", playbook.description);
  println!();

  println!("  Phases ({}):", playbook.phases.len());
  println!("  ─────────────────────────────────────────────");

  for phase in &playbook.phases {
    println!();
    println!("  {}. \x1b[1m{}\x1b[0m", phase.order, phase.name);
    println!("     Objective: {}", phase.objective);
    println!("     Techniques ({}):", phase.techniques.len());

    for tech in &phase.techniques {
      let required = if tech.required { "*" } else { " " };
      let mitre = tech.mitre_id.as_deref().unwrap_or("-");
      println!(
        "       {}[{:<10}] {} - {}",
        required, mitre, tech.id, tech.name
      );
    }
  }

  println!();
  println!("  * = required technique");

  Ok(())
}

fn execute_phases(ctx: &CliContext) -> Result<(), String> {
  let id = ctx
    .target
    .as_deref()
    .ok_or("Missing playbook ID. Usage: rb playbook methodology phases <id>")?;
  let segment = load_definitions();

  let playbook = segment
    .get(id)
    .ok_or_else(|| format!("Playbook '{}' not found", id))?;

  Output::header(&format!("Phases: {}", playbook.name));
  println!();

  for phase in &playbook.phases {
    println!("  Phase {}: {}", phase.order, phase.name);
    println!("  ────────────────────────────────────");
    println!("  Objective: {}", phase.objective);
    println!();

    println!("  Techniques:");
    for tech in &phase.techniques {
      let required = if tech.required {
        "[REQUIRED]"
      } else {
        "[optional]"
      };
      println!("    • {} {} - {}", tech.name, required, tech.description);
      println!("      Command: \x1b[36m{}\x1b[0m", tech.command_hint);
      if let Some(mitre) = &tech.mitre_id {
        println!("      MITRE: {}", mitre);
      }
      println!();
    }
  }

  Ok(())
}

fn execute_run(ctx: &CliContext) -> Result<(), String> {
  let id = ctx
    .target
    .as_deref()
    .ok_or("Missing playbook ID. Usage: rb playbook methodology run <id> --target <target>")?;
  let target = ctx.flags.get("target").ok_or("Missing --target flag")?;
  let dry_run = ctx.flags.contains_key("dry-run");

  let segment = load_definitions();
  let playbook = segment
    .get(id)
    .ok_or_else(|| format!("Playbook '{}' not found", id))?;

  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs() as u32;

  if dry_run {
    Output::header(&format!("Dry Run: {} against {}", playbook.name, target));
    println!();
    println!("  The following commands would be executed:");
    println!();

    for phase in &playbook.phases {
      println!("  Phase {}: {}", phase.order, phase.name);
      for tech in &phase.techniques {
        let cmd = tech.command_hint.replace("{target}", target);
        println!("    \x1b[36m{}\x1b[0m", cmd);
      }
      println!();
    }

    return Ok(());
  }

  // Start actual execution
  Output::header(&format!("Running: {} against {}", playbook.name, target));
  println!();

  let mut run_record = PlaybookRunRecord {
    playbook_name: playbook.id.clone(),
    target: target.clone(),
    status: PlaybookStatus::Running,
    current_phase: 0,
    started_at: now,
    completed_at: None,
    results: Vec::new(),
  };

  // Execute each phase
  for phase in &playbook.phases {
    run_record.current_phase = phase.order as u8;
    println!("  Phase {}: {}", phase.order, phase.name);
    println!("  ────────────────────────────────────");

    for tech in &phase.techniques {
      let cmd = tech.command_hint.replace("{target}", target);
      println!("    Running: {}", tech.name);
      println!("    \x1b[36m$ {}\x1b[0m", cmd);

      // For now, we just record the intent - actual execution would shell out
      // This is a safe approach since we don't auto-execute potentially dangerous commands
      run_record.results.push(StepResult {
        name: tech.id.clone(),
        status: "pending".to_string(),
        output: Some(format!("Command: {}", cmd)),
      });

      println!("    \x1b[33m→ Queued for execution\x1b[0m");
      println!();
    }

    println!();
  }

  run_record.status = PlaybookStatus::Completed;
  run_record.completed_at = Some(
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs() as u32,
  );

  // Save history
  let mut history = load_history();
  history.push(run_record);
  save_history(&history)?;

  Output::success(&format!("Playbook '{}' queued for target '{}'", id, target));
  println!();
  println!("  Note: Commands are queued but not automatically executed.");
  println!("  Copy and run the commands manually or use a scripting integration.");

  Ok(())
}

fn execute_history(ctx: &CliContext) -> Result<(), String> {
  let history = load_history();
  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");

  let records = history.all_records();

  if records.is_empty() {
    Output::info("No playbook execution history");
    return Ok(());
  }

  match format {
    "json" => {
      println!("[");
      for (i, rec) in records.iter().enumerate() {
        let comma = if i < records.len() - 1 { "," } else { "" };
        println!(
          r#"  {{"playbook":"{}","target":"{}","status":"{}","started_at":{}}}{}"#,
          rec.playbook_name,
          rec.target,
          status_str(&rec.status),
          rec.started_at,
          comma
        );
      }
      println!("]");
    }
    _ => {
      Output::header(&format!("Playbook History ({} runs)", records.len()));
      println!();

      for rec in &records {
        let status_color = match rec.status {
          PlaybookStatus::Completed => "\x1b[32m", // green
          PlaybookStatus::Running => "\x1b[33m",   // yellow
          PlaybookStatus::Failed => "\x1b[31m",    // red
        };
        let reset = "\x1b[0m";

        println!(
          "  {}{:>10}{} │ {:<20} │ {} │ {}",
          status_color,
          status_str(&rec.status),
          reset,
          rec.playbook_name,
          rec.target,
          format_timestamp(rec.started_at)
        );
      }
    }
  }

  Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_category(s: &str) -> Result<PlaybookCategory, String> {
  match s.to_lowercase().as_str() {
        "web" => Ok(PlaybookCategory::Web),
        "network" => Ok(PlaybookCategory::Network),
        "recon" => Ok(PlaybookCategory::Recon),
        "cloud" => Ok(PlaybookCategory::Cloud),
        "mobile" => Ok(PlaybookCategory::Mobile),
        "api" => Ok(PlaybookCategory::Api),
        "infrastructure" => Ok(PlaybookCategory::Infrastructure),
        "wireless" => Ok(PlaybookCategory::Wireless),
        "social" => Ok(PlaybookCategory::Social),
        "physical" => Ok(PlaybookCategory::Physical),
        _ => Err(format!("Unknown category '{}'. Use: web, network, recon, cloud, mobile, api, infrastructure, wireless, social, physical", s)),
    }
}

fn status_str(status: &PlaybookStatus) -> &'static str {
  match status {
    PlaybookStatus::Running => "running",
    PlaybookStatus::Completed => "completed",
    PlaybookStatus::Failed => "failed",
  }
}

fn truncate(s: &str, max_len: usize) -> String {
  if s.len() <= max_len {
    s.to_string()
  } else {
    format!("{}...", &s[..max_len - 3])
  }
}

fn format_timestamp(ts: u32) -> String {
  let secs = ts as u64;
  let days = secs / 86400;
  let hours = (secs % 86400) / 3600;
  let mins = (secs % 3600) / 60;

  let years = 1970 + (days / 365);
  let month_day = days % 365;

  format!(
    "{}-{:02}-{:02} {:02}:{:02}",
    years,
    month_day / 30 + 1,
    month_day % 30 + 1,
    hours,
    mins
  )
}
