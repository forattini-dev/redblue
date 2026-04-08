/// Attack Workflow Commands
///
/// Unified workflow for reconnaissance, planning, and playbook execution.
///
/// ## Flow
/// ```
/// rb recon full <target>     → Complete reconnaissance
/// rb recon show <target>     → View consolidated findings
/// rb attack plan <target>    → Get playbook recommendations
/// rb attack run <playbook> <target> → Execute playbook
/// ```
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::{render, CliContext};
use crate::json;
use crate::modules::common::Severity as StorageSeverity;
use crate::playbooks::{
  all_playbooks, get_apt_playbook, get_playbook, list_apt_groups, DetectedOS, PlaybookContext,
  PlaybookExecutor, PlaybookRecommendation, PlaybookRecommender, ReconFindings, RiskLevel,
};
use crate::serde_json::Value;
use crate::storage::records::{PortScanRecord, PortStatus, VulnerabilityRecord};
use crate::storage::service::StorageService;
use crate::storage::{
  ActionOutcome, ActionRecord, ActionSource, RecordPayload, RedDB, UnifiedEntity,
};
use std::net::IpAddr;

pub struct AttackCommand;

impl Command for AttackCommand {
  fn domain(&self) -> &str {
    "attack"
  }

  fn resource(&self) -> &str {
    "target"
  }

  fn description(&self) -> &str {
    "Attack planning and playbook execution workflow"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let json_support = match verb {
      "plan" | "run" | "playbooks" | "apt" => crate::cli::schema::JsonSupport::Guaranteed,
      _ => crate::cli::schema::JsonSupport::BestEffort,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(json_support)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "plan",
        summary: "Analyze findings and recommend playbooks (standard + APT)",
        usage: "rb attack target plan <target>",
      },
      Route {
        verb: "run",
        summary: "Execute a playbook against target",
        usage: "rb attack target run <playbook-id> <target>",
      },
      Route {
        verb: "playbooks",
        summary: "List all available playbooks",
        usage: "rb attack target playbooks [--apt]",
      },
      Route {
        verb: "apt",
        summary: "List APT adversary emulation playbooks",
        usage: "rb attack target apt [group-id]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new(
        "risk",
        "Maximum risk level (passive|low|medium|high|critical)",
      )
      .with_short('r')
      .with_default("high"),
      Flag::new("min-score", "Minimum recommendation score (0-100)").with_default("20"),
      Flag::new("limit", "Maximum recommendations to show").with_default("10"),
      Flag::new("apt", "Show only APT playbooks"),
      Flag::new("dry-run", "Show what would be executed without running"),
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Get playbook recommendations",
        "rb attack target plan example.com",
      ),
      (
        "Show only high-confidence matches",
        "rb attack target plan example.com --min-score 60",
      ),
      ("Run a playbook", "rb attack target run apt29 example.com"),
      ("List all playbooks", "rb attack target playbooks"),
      ("Show APT playbooks", "rb attack target apt"),
      ("View APT29 details", "rb attack target apt apt29"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "Missing verb. Use: rb attack target <plan|run|playbooks|apt>".to_string()
    })?;

    match verb.as_str() {
      "plan" => self.plan(ctx),
      "run" => self.run_playbook(ctx),
      "playbooks" => self.list_playbooks(ctx),
      "apt" => self.list_apt(ctx),
      "help" => {
        print_help(self);
        Ok(())
      }
      _ => Err(format!(
        "Unknown verb '{}'. Use: rb attack target help",
        verb
      )),
    }
  }
}

impl AttackCommand {
  /// Analyze findings and recommend playbooks
  fn plan(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb attack target plan <target>\nExample: rb attack target plan example.com"
        )?;

    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    if !is_json {
      Output::header(&format!("Attack Planning: {}", target));
    }

    // Load findings from storage (Modern RedDB)
    let db_path = StorageService::db_path(target);

    // Try to open the database
    let db_result = RedDB::open(&db_path);

    let findings = match db_result {
      Ok(db) => {
        if !is_json {
          Output::spinner_start("Loading reconnaissance data...");
        }

        // Get target IP for port lookup
        let target_ip: Option<std::net::IpAddr> = if target.parse::<std::net::IpAddr>().is_ok() {
          target.parse().ok()
        } else {
          // Try to resolve domain
          let dns = crate::protocols::dns::DnsClient::new("8.8.8.8");
          dns
            .query(target, crate::protocols::dns::DnsRecordType::A)
            .ok()
            .and_then(|answers| {
              answers.into_iter().find_map(|ans| {
                if let crate::protocols::dns::DnsRdata::A(ip_str) = ans.data {
                  ip_str.parse::<std::net::IpAddr>().ok()
                } else {
                  None
                }
              })
            })
        };

        // Query ports
        let mut ports = Vec::new();
        if let Some(ip) = target_ip {
          // Query the RedDB store
          let results = db
            .query()
            .collection("ports")
            .where_prop("ip", ip.to_string())
            .execute();

          if let Ok(query_res) = results {
            for item in query_res.items {
              if let Some(record) = self.entity_to_port_record(&item.entity) {
                ports.push(record);
              }
            }
          }
        }

        // Query vulnerabilities
        // Note: Vulnerability scanning results integration is pending in PersistenceManager
        // Assuming "vulns" collection
        let vulns_res = db.query().collection("vulns").execute();
        let vulns = if let Ok(res) = vulns_res {
          res
            .items
            .into_iter()
            .filter_map(|item| self.entity_to_vuln_record(&item.entity))
            .collect()
        } else {
          Vec::new()
        };

        if !is_json {
          Output::spinner_done();
        }

        // Convert to ReconFindings
        let detected_os = self.detect_os_from_ports(&ports);

        // Get unique technologies from vulnerability data
        let fp_strings: Vec<String> = vulns
          .iter()
          .map(|v| {
            let ver = v.version.as_deref().unwrap_or("");
            format!("{} {}", v.technology, ver)
          })
          .collect::<std::collections::HashSet<_>>()
          .into_iter()
          .collect();

        ReconFindings {
          target: target.to_string(),
          ports,
          vulns,
          fingerprints: fp_strings,
          detected_os,
          target_type: Some(self.detect_target_type(target)),
          is_internal: self.is_internal_target(target),
        }
      }
      Err(_) => {
        // Handle case where no DB exists yet
        if is_json {
          let payload = missing_recon_payload(target);
          render::render_machine_output(ctx, "rb attack target plan", &payload)?;
          return Ok(());
        }
        println!();
        Output::warning(&format!("No reconnaissance data found for '{}'", target));
        println!();
        Output::info("Run reconnaissance first:");
        println!("  \x1b[1;36mrb recon full {}\x1b[0m", target);
        return Ok(());
      }
    };

    // Get recommendations
    let max_risk = ctx
      .get_flag("risk")
      .map(|r| self.parse_risk_level(&r))
      .unwrap_or(RiskLevel::High);

    let min_score: u8 = ctx
      .get_flag("min-score")
      .and_then(|s| s.parse().ok())
      .unwrap_or(20);

    let max_results: usize = ctx
      .get_flag("limit")
      .and_then(|s| s.parse().ok())
      .unwrap_or(10);

    if !is_json {
      Output::spinner_start("Analyzing attack surface...");
    }

    let recommender = PlaybookRecommender::new()
      .with_max_risk(max_risk)
      .with_min_score(min_score)
      .with_max_results(max_results);

    let result = recommender.recommend(&findings);

    if !is_json {
      Output::spinner_done();
    }

    // JSON output
    if is_json {
      let payload = attack_plan_payload(target, &findings, &result);
      render::render_machine_output(ctx, "rb attack target plan", &payload)?;
      return Ok(());
    }

    // Display findings summary
    self.display_findings_summary(&findings);

    // Display recommendations
    self.display_recommendations(&result, target);

    Ok(())
  }

  /// Convert UnifiedEntity to PortScanRecord
  fn entity_to_port_record(&self, entity: &UnifiedEntity) -> Option<PortScanRecord> {
    if let Some(node) = entity.data.as_node() {
      let ip_str = node.get("ip")?.as_text()?;
      let port = node.get("port")?.as_integer()? as u16;
      let state_str = node.get("state")?.as_text()?;

      let status = match state_str {
        "open" => PortStatus::Open,
        "closed" => PortStatus::Closed,
        "filtered" => PortStatus::Filtered,
        "open|filtered" => PortStatus::OpenFiltered,
        _ => PortStatus::Open,
      };

      Some(PortScanRecord {
        ip: ip_str.parse().ok()?,
        port,
        status,
        service_id: 0,
        timestamp: 0,
      })
    } else {
      None
    }
  }

  /// Convert UnifiedEntity to VulnerabilityRecord (Placeholder)
  fn entity_to_vuln_record(&self, entity: &UnifiedEntity) -> Option<VulnerabilityRecord> {
    let node = entity.data.as_node()?;
    let cve_id = node.get("cve_id").and_then(|v| v.as_text())?.to_string();
    let technology = node
      .get("technology")
      .and_then(|v| v.as_text())?
      .to_string();
    let description = node
      .get("description")
      .and_then(|v| v.as_text())
      .unwrap_or("")
      .to_string();
    let source = node
      .get("source")
      .and_then(|v| v.as_text())
      .unwrap_or("unknown")
      .to_string();
    let version = node
      .get("version")
      .and_then(|v| v.as_text())
      .map(|s| s.to_string());
    let cvss = node.get("cvss").and_then(|v| v.as_float()).unwrap_or(0.0) as f32;
    let risk_score = node
      .get("risk_score")
      .and_then(|v| v.as_integer())
      .unwrap_or(0) as u8;
    let severity = node
      .get("severity")
      .and_then(|v| v.as_text())
      .and_then(StorageSeverity::from_str)
      .or_else(|| self.severity_from_cvss(cvss))
      .unwrap_or(StorageSeverity::Info);
    let exploit_available = node
      .get("exploit_available")
      .and_then(|v| v.as_boolean())
      .unwrap_or(false);
    let in_kev = node
      .get("in_kev")
      .and_then(|v| v.as_boolean())
      .unwrap_or(false);
    let discovered_at = node
      .get("discovered_at")
      .and_then(|v| v.as_integer())
      .map(|value| value as u32)
      .unwrap_or(entity.updated_at as u32);
    let references = node
      .get("references")
      .and_then(|v| v.as_text())
      .map(parse_references)
      .unwrap_or_default();

    Some(VulnerabilityRecord {
      cve_id,
      technology,
      version,
      cvss,
      risk_score,
      severity,
      description,
      references,
      exploit_available,
      in_kev,
      discovered_at,
      source,
    })
  }

  fn severity_from_cvss(&self, cvss: f32) -> Option<StorageSeverity> {
    match cvss {
      score if score >= 9.0 => Some(StorageSeverity::Critical),
      score if score >= 7.0 => Some(StorageSeverity::High),
      score if score >= 4.0 => Some(StorageSeverity::Medium),
      score if score > 0.0 => Some(StorageSeverity::Low),
      _ => None,
    }
  }

  /// Execute a playbook
  fn run_playbook(&self, ctx: &CliContext) -> Result<(), String> {
    let playbook_id = ctx
      .target
      .as_ref()
      .ok_or("Missing playbook ID.\nUsage: rb attack target run <playbook-id> <target>")?;

    let target = ctx
      .args
      .get(0)
      .ok_or("Missing target.\nUsage: rb attack target run <playbook-id> <target>")?;

    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    // Find playbook (standard or APT)
    let playbook = get_playbook(playbook_id)
            .or_else(|| get_apt_playbook(playbook_id))
            .ok_or_else(|| {
                format!(
                    "Playbook '{}' not found.\n\nAvailable playbooks:\n  rb attack target playbooks\n  rb attack target apt",
                    playbook_id
                )
            })?;

    let is_apt = get_apt_playbook(playbook_id).is_some();

    if !is_json {
      let apt_badge = if is_apt {
        " \x1b[1;35m[APT]\x1b[0m"
      } else {
        ""
      };

      Output::header(&format!(
        "Executing: {}{}",
        playbook.metadata.name, apt_badge
      ));
      println!();

      Output::item("Target", target);
      Output::item("Playbook", &playbook.metadata.id);
      Output::item("Objective", &playbook.metadata.objective);
      Output::item("Risk Level", playbook.metadata.risk_level.as_str());
      Output::item("Steps", &playbook.steps.len().to_string());

      // Risk warning
      if playbook.metadata.risk_level.requires_consent() {
        println!();
        Output::warning("⚠️  HIGH RISK playbook - ensure you have authorization!");
      }
    }

    // Dry run check
    if ctx.has_flag("dry-run") {
      let execution_preview = playbook_execution_preview(&playbook);
      if is_json {
        let payload = playbook_dry_run_payload(&playbook, target, is_apt, &execution_preview);
        render::render_machine_output(ctx, "rb attack target run", &payload)?;
        return Ok(());
      }
      println!();
      Output::info("DRY RUN - showing steps without execution:");
      println!();
      Output::item("Estimated Duration", &playbook.metadata.estimated_duration);
      Output::item(
        "Command Hints",
        &execution_preview.total_commands.to_string(),
      );
      Output::item("Manual Steps", &execution_preview.manual_steps.to_string());
      Output::item(
        "Optional Steps",
        &execution_preview.optional_steps.to_string(),
      );

      if !execution_preview.phases.is_empty() {
        println!();
        Output::section("Execution Summary");
        for phase in &execution_preview.phases {
          println!(
            "  \x1b[36m•\x1b[0m {}: {} step(s), {} command hint(s)",
            phase.phase, phase.total_steps, phase.command_count
          );
        }
      }

      if !execution_preview.narrative.is_empty() {
        println!();
        Output::section("Execution Narrative");
        for item in &execution_preview.narrative {
          println!("  \x1b[36m•\x1b[0m {}", item);
        }
      }

      if !playbook.preconditions.is_empty() {
        println!();
        Output::section("Preconditions");
        for condition in &playbook.preconditions {
          let required = if condition.required {
            "required"
          } else {
            "optional"
          };
          println!(
            "  \x1b[36m•\x1b[0m {} ({})",
            condition.description, required
          );
        }
      }

      if !playbook.assertions.is_empty() {
        println!();
        Output::section("Assertions");
        for assertion in &playbook.assertions {
          let critical = if assertion.critical {
            "critical"
          } else {
            "non-critical"
          };
          println!(
            "  \x1b[36m•\x1b[0m {} ({})",
            assertion.description, critical
          );
        }
      }
      println!();

      for step in &playbook.steps {
        println!(
          "  {}. \x1b[1m{}[0m [{}]",
          step.number,
          step.name,
          step.phase.as_str()
        );
        println!("     {}", step.description);
        if !step.commands.is_empty() {
          println!("     Commands: {}", step.commands.join(", "));
        }
      }
      return Ok(());
    }

    // Execute
    if !is_json {
      println!();
      Output::spinner_start("Executing playbook...");
    }

    let mut context = PlaybookContext::new(target);
    for (k, v) in &ctx.flags {
      context.set_arg(k, v);
    }

    let mut executor = PlaybookExecutor::new();
    let result = executor.execute(&playbook, &mut context);
    let actions = executor.actions();
    let action_summary = execution_action_summary(actions);
    let execution_narrative = execution_narrative_from_action_summary(&action_summary);
    let persisted_actions = match executor.persist_actions() {
      Ok(count) => PersistenceSummary {
        attempted: actions.len(),
        persisted: count,
        error: None,
      },
      Err(error) => PersistenceSummary {
        attempted: actions.len(),
        persisted: 0,
        error: Some(error),
      },
    };

    if !is_json {
      Output::spinner_done();
    }

    // JSON output
    if is_json {
      let payload = playbook_result_payload(
        &result,
        is_apt,
        &action_summary,
        &execution_narrative,
        &persisted_actions,
      );
      render::render_machine_output(ctx, "rb attack target run", &payload)?;
      return Ok(());
    }

    // Display results
    println!();
    if result.success {
      Output::success(&format!("Playbook completed: {}", result.summary));
    } else {
      Output::error(&format!("Playbook failed: {}", result.summary));
    }

    println!();
    Output::section("Step Results");

    for step in &result.step_results {
      let status_icon = match step.status.as_str() {
        "completed" => "\x1b[32m✓\x1b[0m",
        "failed" => "\x1b[31m✗\x1b[0m",
        "skipped" => "\x1b[33m⊘\x1b[0m",
        _ => "•",
      };

      println!(
        "  {} Step {}: {} - {}",
        status_icon, step.step_number, step.step_name, step.status
      );

      for line in &step.output {
        if !line.is_empty() {
          println!("    {}", line);
        }
      }

      if let Some(err) = &step.error {
        println!("    \x1b[31mError: {}\x1b[0m", err);
      }
    }

    // Summary stats
    println!();
    Output::item("Steps completed", &result.steps_completed.to_string());
    Output::item("Steps skipped", &result.steps_skipped.to_string());
    Output::item("Steps failed", &result.steps_failed.to_string());
    Output::item(
      "Duration",
      &format!("{:.2}s", result.duration.as_secs_f64()),
    );
    Output::item(
      "Actions recorded",
      &action_summary.total_actions.to_string(),
    );
    Output::item(
      "Actions persisted",
      &persisted_actions.persisted.to_string(),
    );

    if !action_summary.phases.is_empty() {
      println!();
      Output::section("Execution Summary");
      for phase in &action_summary.phases {
        println!(
          "  \x1b[36m•\x1b[0m {}: {} total, {} success, {} failed, {} skipped",
          phase.phase,
          phase.total_steps,
          phase.successful_steps,
          phase.failed_steps,
          phase.skipped_steps
        );
      }
    }

    if !execution_narrative.is_empty() {
      println!();
      Output::section("Execution Narrative");
      for item in &execution_narrative {
        println!("  \x1b[36m•\x1b[0m {}", item);
      }
    }

    if let Some(error) = &persisted_actions.error {
      println!();
      Output::warning(&format!("Could not persist execution actions: {}", error));
    }

    Ok(())
  }

  /// List all playbooks
  fn list_playbooks(&self, ctx: &CliContext) -> Result<(), String> {
    if ctx.has_flag("apt") {
      return self.list_apt(ctx);
    }

    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    // JSON output
    if is_json {
      let playbooks = all_playbooks();
      let apt_groups = list_apt_groups();

      let payload = playbooks_listing_payload(&playbooks, &apt_groups);
      render::render_machine_output(ctx, "rb attack target playbooks", &payload)?;
      return Ok(());
    }

    Output::header("Available Playbooks");

    // Standard playbooks
    println!();
    println!("\x1b[1;36m📋 Standard Playbooks\x1b[0m");
    println!();

    for pb in all_playbooks() {
      let risk_color = self.risk_color(&pb.metadata.risk_level);
      println!(
        "  \x1b[1m{:<25}\x1b[0m {}{:?}\x1b[0m  {} steps",
        pb.metadata.id,
        risk_color,
        pb.metadata.risk_level,
        pb.steps.len()
      );
      println!("    {}", pb.metadata.name);
    }

    // APT playbooks summary
    println!();
    println!(
      "\x1b[1;35m🎭 APT Adversary Emulation ({} groups)\x1b[0m",
      list_apt_groups().len()
    );
    println!();

    for (id, name) in list_apt_groups() {
      println!("  \x1b[1m{:<20}\x1b[0m {}", id, name);
    }

    println!();
    Output::info("View APT details: rb attack target apt <group-id>");
    Output::info("Run playbook: rb attack target run <playbook-id> <target>");

    Ok(())
  }

  /// List APT playbooks
  fn list_apt(&self, ctx: &CliContext) -> Result<(), String> {
    let group_id = ctx.target.as_ref();
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    if let Some(id) = group_id {
      // Show specific APT playbook
      let playbook = get_apt_playbook(id).ok_or_else(|| {
        format!(
          "APT group '{}' not found. Use 'rb attack target apt' to list groups.",
          id
        )
      })?;

      // JSON output for specific playbook
      if is_json {
        let payload = apt_playbook_payload(&playbook);
        render::render_machine_output(ctx, "rb attack target apt", &payload)?;
        return Ok(());
      }

      Output::header(&format!("APT Playbook: {}", playbook.metadata.name));
      println!();

      Output::item("ID", &playbook.metadata.id);
      Output::item("Objective", &playbook.metadata.objective);
      Output::item("Risk", playbook.metadata.risk_level.as_str());
      Output::item("Steps", &playbook.steps.len().to_string());

      // Pre-conditions
      if !playbook.preconditions.is_empty() {
        println!();
        println!("\x1b[1;33m⚡ Pre-conditions:\x1b[0m");
        for cond in &playbook.preconditions {
          println!("  • {}", cond.description);
        }
      }

      // Attack flow
      println!();
      println!("\x1b[1;36m🎯 Attack Flow:\x1b[0m");

      for step in &playbook.steps {
        let phase_color = self.phase_color(&step.phase);
        println!();
        println!(
          "  \x1b[1m{}. {}\x1b[0m {}[{}]\x1b[0m",
          step.number,
          step.name,
          phase_color,
          step.phase.as_str()
        );
        println!("     {}", step.description);

        if let Some(technique) = &step.mitre_technique {
          println!("     \x1b[2mMITRE: {}\x1b[0m", technique);
        }
      }

      // Evidence
      if !playbook.evidence.is_empty() {
        println!();
        println!("\x1b[1;32m✓ Evidence of Success:\x1b[0m");
        for ev in &playbook.evidence {
          println!("  • {}", ev.description);
        }
      }

      // Failed controls
      if !playbook.failed_controls.is_empty() {
        println!();
        println!("\x1b[1;31m✗ Common Defensive Gaps:\x1b[0m");
        for ctrl in &playbook.failed_controls {
          println!("  • {} - {}", ctrl.name, ctrl.reason);
        }
      }

      println!();
      Output::info(&format!("Run: rb attack target run {} <target>", id));
    } else {
      // JSON output for listing all APT groups
      if is_json {
        let apt_groups = list_apt_groups();
        let payload = apt_groups_payload(&apt_groups);
        render::render_machine_output(ctx, "rb attack target apt", &payload)?;
        return Ok(());
      }

      // List all APT groups
      Output::header("APT Adversary Emulation Playbooks");
      println!();
      println!("Real-world threat actor TTPs from MITRE ATT&CK v18.1");
      println!();

      println!("\x1b[1;31m🇷🇺 Russia\x1b[0m");
      println!("  apt28          Fancy Bear (GRU Unit 26165)");
      println!("  apt29          Cozy Bear (SVR)");
      println!("  sandworm-team  BlackEnergy (GRU Unit 74455)");
      println!("  turla          Waterbug (FSB)");
      println!("  wizard-spider  TrickBot/Ryuk");
      println!();

      println!("\x1b[1;33m🇨🇳 China\x1b[0m");
      println!("  apt3           Gothic Panda (MSS)");
      println!("  apt41          Wicked Panda (MSS contractor)");
      println!("  volt-typhoon   BRONZE SILHOUETTE (PLA)");
      println!();

      println!("\x1b[1;34m🇰🇵 North Korea\x1b[0m");
      println!("  kimsuky        Velvet Chollima (RGB)");
      println!("  lazarus-group  HIDDEN COBRA (RGB)");
      println!();

      println!("\x1b[1;32m🇮🇷 Iran\x1b[0m");
      println!("  muddywater     MOIS");
      println!("  oilrig         APT34 (MOIS)");
      println!();

      println!("\x1b[1;35m🇻🇳 Vietnam\x1b[0m");
      println!("  apt32          OceanLotus");
      println!();

      println!("\x1b[1;36m💰 Financially Motivated\x1b[0m");
      println!("  fin7           Carbanak");
      println!("  scattered-spider  Social Engineering");
      println!();

      Output::info("View details: rb attack target apt <group-id>");
      Output::info("Example: rb attack target apt apt29");
    }

    Ok(())
  }

  // === Helper Methods ===

  fn display_findings_summary(&self, findings: &ReconFindings) {
    println!();
    Output::section("Reconnaissance Summary");

    // Ports
    let open_ports: Vec<_> = findings
      .ports
      .iter()
      .filter(|p| p.status == PortStatus::Open)
      .collect();

    if !open_ports.is_empty() {
      let port_list: Vec<String> = open_ports
        .iter()
        .take(10)
        .map(|p| p.port.to_string())
        .collect();
      let suffix = if open_ports.len() > 10 {
        format!(" (+{} more)", open_ports.len() - 10)
      } else {
        String::new()
      };
      Output::item("Open Ports", &format!("{}{}", port_list.join(", "), suffix));
    } else {
      Output::item("Open Ports", "None found");
    }

    // OS Detection
    if let Some(os) = &findings.detected_os {
      Output::item("Detected OS", &format!("{:?}", os));
    }

    // Fingerprints
    if !findings.fingerprints.is_empty() {
      let fp_list: String = findings
        .fingerprints
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
      let suffix = if findings.fingerprints.len() > 5 {
        format!(" (+{} more)", findings.fingerprints.len() - 5)
      } else {
        String::new()
      };
      Output::item("Technologies", &format!("{}{}", fp_list, suffix));
    }

    // Vulnerabilities
    if !findings.vulns.is_empty() {
      let critical = findings
        .vulns
        .iter()
        .filter(|v| v.severity == StorageSeverity::Critical)
        .count();
      let high = findings
        .vulns
        .iter()
        .filter(|v| v.severity == StorageSeverity::High)
        .count();
      let medium = findings
        .vulns
        .iter()
        .filter(|v| v.severity == StorageSeverity::Medium)
        .count();

      Output::item(
        "Vulnerabilities",
        &format!(
          "{} total (\x1b[31m{} critical\x1b[0m, \x1b[33m{} high\x1b[0m, {} medium)",
          findings.vulns.len(),
          critical,
          high,
          medium
        ),
      );

      // Show top CVEs
      let mut sorted_vulns = findings.vulns.clone();
      sorted_vulns.sort_by(|a, b| {
        b.cvss
          .partial_cmp(&a.cvss)
          .unwrap_or(std::cmp::Ordering::Equal)
      });

      for vuln in sorted_vulns.iter().take(3) {
        let sev_color = match vuln.severity {
          StorageSeverity::Critical => "\x1b[1;31m",
          StorageSeverity::High => "\x1b[31m",
          StorageSeverity::Medium => "\x1b[33m",
          _ => "\x1b[0m",
        };
        println!(
          "    {}• {} (CVSS {:.1})\x1b[0m",
          sev_color, vuln.cve_id, vuln.cvss
        );
      }
    } else {
      Output::item("Vulnerabilities", "None found");
    }

    // Target type
    if let Some(tt) = &findings.target_type {
      Output::item("Target Type", &format!("{:?}", tt));
    }

    if findings.is_internal {
      Output::item("Network", "Internal");
    }
  }

  fn display_recommendations(&self, result: &crate::playbooks::RecommendationResult, target: &str) {
    println!();
    Output::section("Playbook Recommendations");

    // Summary
    Output::item("Total matches", &result.summary.total_matched.to_string());
    if result.summary.apt_playbooks_matched > 0 {
      Output::item(
        "APT playbooks",
        &result.summary.apt_playbooks_matched.to_string(),
      );
    }

    if result.summary.has_critical_findings {
      println!();
      Output::warning("⚠️  Critical vulnerabilities detected - prioritize high-risk playbooks");
    }

    if result.recommendations.is_empty() {
      println!();
      Output::info("No playbooks matched. Run more reconnaissance:");
      println!("  \x1b[36mrb recon full {}\x1b[0m", target);
      return;
    }

    // Group by score
    let strong: Vec<_> = result
      .recommendations
      .iter()
      .filter(|r| r.score >= 70)
      .collect();
    let moderate: Vec<_> = result
      .recommendations
      .iter()
      .filter(|r| r.score >= 40 && r.score < 70)
      .collect();
    let weak: Vec<_> = result
      .recommendations
      .iter()
      .filter(|r| r.score < 40)
      .collect();

    if !strong.is_empty() {
      println!();
      println!("\x1b[1;32m🎯 STRONG MATCHES (≥70)\x1b[0m");
      for rec in &strong {
        self.display_recommendation(rec);
      }
    }

    if !moderate.is_empty() {
      println!();
      println!("\x1b[1;33m📋 MODERATE MATCHES (40-69)\x1b[0m");
      for rec in &moderate {
        self.display_recommendation(rec);
      }
    }

    if !weak.is_empty() {
      println!();
      println!("\x1b[1;34m💡 WEAK MATCHES (<40)\x1b[0m");
      for rec in weak.iter().take(3) {
        self.display_recommendation(rec);
      }
      if weak.len() > 3 {
        println!("  \x1b[2m... and {} more\x1b[0m", weak.len() - 3);
      }
    }

    // Next steps
    if let Some(top) = result.recommendations.first() {
      println!();
      Output::section("Recommended Next Step");
      println!("  Run the top playbook:");
      println!(
        "  \x1b[1;36mrb attack target run {} {}\x1b[0m",
        top.playbook_id, target
      );
    }
  }

  fn display_recommendation(&self, rec: &PlaybookRecommendation) {
    let risk_color = self.risk_color(&rec.risk_level);
    let apt_badge = if rec.is_apt_playbook {
      " \x1b[35m[APT]\x1b[0m"
    } else {
      ""
    };

    println!();
    println!(
      "  \x1b[1m{}\x1b[0m{} (Score: {}/100)",
      rec.playbook_name, apt_badge, rec.score
    );
    println!(
      "    ID: {}  Risk: {}{:?}\x1b[0m",
      rec.playbook_id, risk_color, rec.risk_level
    );

    if !rec.reasons.is_empty() {
      for reason in rec.reasons.iter().take(3) {
        println!("    \x1b[32m•\x1b[0m {}", reason);
      }
    }

    let non_zero_components: Vec<_> = rec
      .score_breakdown
      .components
      .iter()
      .filter(|component| component.points > 0)
      .collect();
    if !non_zero_components.is_empty() {
      println!("    Score Breakdown:");
      for component in non_zero_components.iter().take(4) {
        println!(
          "      \x1b[36m•\x1b[0m {}: +{}",
          component.category, component.points
        );
      }
    }
  }

  fn detect_os_from_ports(&self, ports: &[PortScanRecord]) -> Option<DetectedOS> {
    let has_ssh = ports
      .iter()
      .any(|p| p.port == 22 && p.status == PortStatus::Open);
    let has_smb = ports
      .iter()
      .any(|p| (p.port == 445 || p.port == 139) && p.status == PortStatus::Open);
    let has_rdp = ports
      .iter()
      .any(|p| p.port == 3389 && p.status == PortStatus::Open);

    if has_rdp || (has_smb && !has_ssh) {
      Some(DetectedOS::Windows)
    } else if has_ssh && !has_smb && !has_rdp {
      Some(DetectedOS::Linux)
    } else if has_ssh && has_smb {
      Some(DetectedOS::Unknown)
    } else {
      None
    }
  }

  fn detect_target_type(&self, target: &str) -> crate::playbooks::TargetType {
    if target.starts_with("http://") || target.starts_with("https://") {
      crate::playbooks::TargetType::WebApp
    } else if target.parse::<IpAddr>().is_ok() {
      crate::playbooks::TargetType::Host
    } else if target.contains('.') {
      crate::playbooks::TargetType::Domain
    } else {
      crate::playbooks::TargetType::Host
    }
  }

  fn is_internal_target(&self, target: &str) -> bool {
    if let Ok(ip) = target.parse::<IpAddr>() {
      match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
      }
    } else {
      // Check for common internal domain patterns
      target.ends_with(".local")
        || target.ends_with(".internal")
        || target.ends_with(".corp")
        || target.ends_with(".lan")
    }
  }

  fn parse_risk_level(&self, s: &str) -> RiskLevel {
    match s.to_lowercase().as_str() {
      "passive" => RiskLevel::Passive,
      "low" => RiskLevel::Low,
      "medium" => RiskLevel::Medium,
      "high" => RiskLevel::High,
      "critical" => RiskLevel::Critical,
      _ => RiskLevel::High,
    }
  }

  fn risk_color(&self, risk: &RiskLevel) -> &'static str {
    match risk {
      RiskLevel::Critical => "\x1b[1;31m",
      RiskLevel::High => "\x1b[31m",
      RiskLevel::Medium => "\x1b[33m",
      RiskLevel::Low => "\x1b[32m",
      RiskLevel::Passive => "\x1b[36m",
    }
  }

  fn phase_color(&self, phase: &crate::playbooks::PlaybookPhase) -> &'static str {
    use crate::playbooks::PlaybookPhase::*;
    match phase {
      InitialAccess => "\x1b[31m",
      Execution => "\x1b[33m",
      Persistence => "\x1b[35m",
      PrivilegeEscalation => "\x1b[1;31m",
      DefenseEvasion => "\x1b[36m",
      CredentialAccess => "\x1b[1;33m",
      Discovery => "\x1b[34m",
      LateralMovement => "\x1b[1;35m",
      Collection => "\x1b[32m",
      C2 => "\x1b[1;36m",
      Exfiltration => "\x1b[1;32m",
      Impact => "\x1b[1;31m",
      _ => "\x1b[0m",
    }
  }
}

fn playbook_recommendation_to_json(rec: &PlaybookRecommendation) -> crate::serde_json::Value {
  json!({
      "playbook_id": rec.playbook_id.clone(),
      "playbook_name": rec.playbook_name.clone(),
      "score": rec.score,
      "risk_level": format!("{:?}", rec.risk_level),
      "reasons": rec.reasons.clone(),
      "score_breakdown": score_breakdown_to_json(&rec.score_breakdown),
      "related_attacks": rec.related_attacks.clone(),
      "is_apt_playbook": rec.is_apt_playbook
  })
}

fn score_breakdown_to_json(
  breakdown: &crate::playbooks::ScoreBreakdown,
) -> crate::serde_json::Value {
  let components: Vec<Value> = breakdown
    .components
    .iter()
    .map(|component| {
      json!({
        "category": component.category,
        "points": component.points,
        "reasons": component.reasons
      })
    })
    .collect();

  json!({
    "raw_score": breakdown.raw_score,
    "final_score": breakdown.final_score,
    "components": components
  })
}

fn missing_recon_payload(target: &str) -> Value {
  json!({
    "target": target,
    "error": "no_recon_data",
    "message": "No reconnaissance data found for target"
  })
}

fn findings_summary_payload(findings: &ReconFindings) -> Value {
  json!({
    "open_ports": findings
      .ports
      .iter()
      .filter(|p| p.status == PortStatus::Open)
      .count(),
    "vulnerabilities": findings.vulns.len(),
    "fingerprints": findings.fingerprints.len(),
    "detected_os": findings.detected_os.as_ref().map(|os| format!("{:?}", os)),
    "target_type": findings.target_type.as_ref().map(|tt| format!("{:?}", tt)),
    "is_internal": findings.is_internal
  })
}

fn recommendation_summary_payload(result: &crate::playbooks::RecommendationResult) -> Value {
  json!({
    "total_matched": result.summary.total_matched,
    "high_risk_count": result.summary.high_risk_count,
    "medium_risk_count": result.summary.medium_risk_count,
    "low_risk_count": result.summary.low_risk_count,
    "has_critical_findings": result.summary.has_critical_findings,
    "top_recommendation": result.summary.top_recommendation,
    "apt_playbooks_matched": result.summary.apt_playbooks_matched
  })
}

fn attack_plan_payload(
  target: &str,
  findings: &ReconFindings,
  result: &crate::playbooks::RecommendationResult,
) -> Value {
  let recommendations: Vec<Value> = result
    .recommendations
    .iter()
    .map(playbook_recommendation_to_json)
    .collect();
  json!({
    "target": target,
    "findings": findings_summary_payload(findings),
    "summary": recommendation_summary_payload(result),
    "recommendations": recommendations
  })
}

fn playbook_step_payload(step: &crate::playbooks::PlaybookStep) -> Value {
  json!({
    "number": step.number,
    "name": step.name,
    "phase": step.phase.as_str(),
    "description": step.description.replace('\n', " "),
    "commands": step.commands,
    "mitre_technique": step.mitre_technique
  })
}

fn playbook_dry_run_payload(
  playbook: &crate::playbooks::Playbook,
  target: &str,
  is_apt: bool,
  preview: &ExecutionPreview,
) -> Value {
  let steps: Vec<Value> = playbook.steps.iter().map(playbook_step_payload).collect();
  let summary = json!({
    "total_steps": playbook.steps.len(),
    "total_commands": preview.total_commands,
    "optional_steps": preview.optional_steps,
    "manual_steps": preview.manual_steps,
    "preconditions": playbook.preconditions.len(),
    "assertions": playbook.assertions.len()
  });
  let preconditions: Vec<Value> = playbook
    .preconditions
    .iter()
    .map(|condition| {
      json!({
        "description": condition.description,
        "required": condition.required,
        "check": condition.check,
        "notes": condition.notes
      })
    })
    .collect();
  let assertions: Vec<Value> = playbook
    .assertions
    .iter()
    .map(|assertion| {
      json!({
        "description": assertion.description,
        "critical": assertion.critical
      })
    })
    .collect();
  json!({
    "playbook_id": playbook.metadata.id,
    "playbook_name": playbook.metadata.name,
    "target": target,
    "dry_run": true,
    "is_apt": is_apt,
    "risk_level": playbook.metadata.risk_level.as_str(),
    "estimated_duration": playbook.metadata.estimated_duration,
    "summary": summary,
    "phase_summary": execution_preview_phases_payload(&preview.phases),
    "execution_narrative": preview.narrative,
    "preconditions": preconditions,
    "assertions": assertions,
    "steps": steps
  })
}

fn playbook_result_payload(
  result: &crate::playbooks::PlaybookExecutionResult,
  is_apt: bool,
  action_summary: &ExecutionActionSummary,
  execution_narrative: &[String],
  persisted_actions: &PersistenceSummary,
) -> Value {
  let mut result_json = json!(result.clone());
  if let Some(obj) = result_json.as_object().cloned() {
    let mut map = obj;
    map.insert("is_apt".to_string(), json!(is_apt));
    map.insert(
      "duration_secs".to_string(),
      json!(result.duration.as_secs_f64()),
    );
    map.insert(
      "action_summary".to_string(),
      execution_action_summary_payload(action_summary),
    );
    map.insert(
      "execution_narrative".to_string(),
      json!(execution_narrative),
    );
    map.insert(
      "persistence".to_string(),
      persistence_summary_payload(persisted_actions),
    );
    result_json = Value::Object(map);
  }
  result_json
}

#[derive(Debug, Clone, Default)]
struct ExecutionActionSummary {
  total_actions: usize,
  successful_actions: usize,
  failed_actions: usize,
  skipped_actions: usize,
  exploit_actions: usize,
  scan_actions: usize,
  enumerate_actions: usize,
  report_actions: usize,
  phases: Vec<ExecutionPhaseSummary>,
  steps: Vec<Value>,
}

#[derive(Debug, Clone, Default)]
struct ExecutionPhaseSummary {
  phase: String,
  total_steps: usize,
  successful_steps: usize,
  failed_steps: usize,
  skipped_steps: usize,
  total_duration_ms: u64,
  command_count: usize,
  steps: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct ExecutionPreview {
  total_commands: usize,
  optional_steps: usize,
  manual_steps: usize,
  phases: Vec<ExecutionPhaseSummary>,
  narrative: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct PersistenceSummary {
  attempted: usize,
  persisted: usize,
  error: Option<String>,
}

fn execution_action_summary(actions: &[ActionRecord]) -> ExecutionActionSummary {
  let mut summary = ExecutionActionSummary {
    total_actions: actions.len(),
    ..ExecutionActionSummary::default()
  };

  for action in actions {
    match &action.outcome {
      ActionOutcome::Success => summary.successful_actions += 1,
      ActionOutcome::Failed { .. } | ActionOutcome::Timeout { .. } => summary.failed_actions += 1,
      ActionOutcome::Skipped { .. } => summary.skipped_actions += 1,
      ActionOutcome::Partial { .. } => summary.successful_actions += 1,
    }

    match action.action_type {
      crate::storage::ActionType::Exploit => summary.exploit_actions += 1,
      crate::storage::ActionType::Scan => summary.scan_actions += 1,
      crate::storage::ActionType::Enumerate => summary.enumerate_actions += 1,
      crate::storage::ActionType::Report => summary.report_actions += 1,
      _ => {}
    }

    if let Some(custom) = custom_action_payload(action) {
      if let Some(phase_name) = custom
        .get("phase")
        .and_then(|value| value.as_str())
        .map(str::to_string)
      {
        let step_name = custom
          .get("step_name")
          .and_then(|value| value.as_str())
          .unwrap_or("Unnamed Step")
          .to_string();
        let duration_ms = custom
          .get("duration_ms")
          .and_then(|value| value.as_i64())
          .unwrap_or(0)
          .max(0) as u64;
        upsert_execution_phase(
          &mut summary.phases,
          &phase_name,
          &step_name,
          action,
          duration_ms,
          custom
            .get("command_count")
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            .max(0) as usize,
        );
      }
    }

    summary.steps.push(action_record_summary_payload(action));
  }

  summary
}

fn action_record_summary_payload(action: &ActionRecord) -> Value {
  let mut payload = json!({
    "timestamp": action.timestamp,
    "action_type": action.action_type.as_str(),
    "target": action.target.host_str(),
    "source": action_source_payload(&action.source),
    "outcome": action_outcome_payload(&action.outcome),
  });

  if let Some(custom) = custom_action_payload(action) {
    if let Some(obj) = payload.as_object().cloned() {
      let mut map = obj;
      map.insert("context".to_string(), custom);
      payload = Value::Object(map);
    }
  }

  payload
}

fn execution_action_summary_payload(summary: &ExecutionActionSummary) -> Value {
  json!({
    "total_actions": summary.total_actions,
    "successful_actions": summary.successful_actions,
    "failed_actions": summary.failed_actions,
    "skipped_actions": summary.skipped_actions,
    "exploit_actions": summary.exploit_actions,
    "scan_actions": summary.scan_actions,
    "enumerate_actions": summary.enumerate_actions,
    "report_actions": summary.report_actions,
    "phases": execution_preview_phases_payload(&summary.phases),
    "steps": summary.steps,
  })
}

fn persistence_summary_payload(summary: &PersistenceSummary) -> Value {
  json!({
    "attempted": summary.attempted,
    "persisted": summary.persisted,
    "error": summary.error,
  })
}

fn action_source_payload(source: &ActionSource) -> Value {
  match source {
    ActionSource::Tool { name } => json!({ "kind": "tool", "name": name }),
    ActionSource::Playbook { id, step } => json!({
      "kind": "playbook",
      "step": step,
      "run_id_prefix": format!("{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3]),
    }),
    ActionSource::Manual => json!({ "kind": "manual" }),
  }
}

fn action_outcome_payload(outcome: &ActionOutcome) -> Value {
  match outcome {
    ActionOutcome::Success => json!({ "status": "success" }),
    ActionOutcome::Failed { error } => json!({ "status": "failed", "error": error }),
    ActionOutcome::Timeout { after_ms } => json!({ "status": "timeout", "after_ms": after_ms }),
    ActionOutcome::Partial { completed, total } => json!({
      "status": "partial",
      "completed": completed,
      "total": total
    }),
    ActionOutcome::Skipped { reason } => json!({ "status": "skipped", "reason": reason }),
  }
}

fn custom_action_payload(action: &ActionRecord) -> Option<Value> {
  match &action.payload {
    RecordPayload::Custom(data) if !data.is_empty() => crate::serde_json::from_slice(data).ok(),
    _ => None,
  }
}

fn playbook_catalog_entry_payload(playbook: &crate::playbooks::Playbook) -> Value {
  json!({
    "id": playbook.metadata.id,
    "name": playbook.metadata.name,
    "objective": playbook.metadata.objective,
    "risk_level": format!("{:?}", playbook.metadata.risk_level),
    "steps": playbook.steps.len()
  })
}

fn playbooks_listing_payload(
  playbooks: &[crate::playbooks::Playbook],
  apt_groups: &[(&str, &str)],
) -> Value {
  let playbooks_json: Vec<Value> = playbooks
    .iter()
    .map(playbook_catalog_entry_payload)
    .collect();
  let apt_groups_json: Vec<Value> = apt_groups
    .iter()
    .map(|(id, name)| json!({ "id": id, "name": name }))
    .collect();
  json!({
    "playbooks": playbooks_json,
    "apt_groups": apt_groups_json
  })
}

fn apt_groups_payload(apt_groups: &[(&str, &str)]) -> Value {
  let apt_groups_json: Vec<Value> = apt_groups
    .iter()
    .map(|(id, name)| json!({ "id": id, "name": name }))
    .collect();
  json!({ "apt_groups": apt_groups_json })
}

fn apt_playbook_payload(playbook: &crate::playbooks::Playbook) -> Value {
  json!(playbook.clone())
}

fn playbook_execution_preview(playbook: &crate::playbooks::Playbook) -> ExecutionPreview {
  let mut preview = ExecutionPreview::default();

  for step in &playbook.steps {
    preview.total_commands += step.commands.len();
    if step.optional {
      preview.optional_steps += 1;
    }
    if step.manual_instructions.is_some() {
      preview.manual_steps += 1;
    }

    let phase_name = step.phase.as_str().to_string();
    if let Some(existing) = preview
      .phases
      .iter_mut()
      .find(|item| item.phase == phase_name)
    {
      existing.total_steps += 1;
      existing.command_count += step.commands.len();
      if !existing.steps.iter().any(|name| name == &step.name) {
        existing.steps.push(step.name.clone());
      }
    } else {
      preview.phases.push(ExecutionPhaseSummary {
        phase: phase_name,
        total_steps: 1,
        command_count: step.commands.len(),
        steps: vec![step.name.clone()],
        ..ExecutionPhaseSummary::default()
      });
    }
  }

  preview.narrative = execution_preview_narrative(&preview.phases);
  preview
}

fn execution_preview_narrative(phases: &[ExecutionPhaseSummary]) -> Vec<String> {
  phases
    .iter()
    .map(|phase| {
      format!(
        "{} is planned with {} step(s) and {} command hint(s).",
        phase.phase, phase.total_steps, phase.command_count
      )
    })
    .collect()
}

fn execution_narrative_from_action_summary(summary: &ExecutionActionSummary) -> Vec<String> {
  summary
    .phases
    .iter()
    .map(|phase| {
      format!(
        "{} executed {} step(s): {} succeeded, {} failed, {} skipped.",
        phase.phase,
        phase.total_steps,
        phase.successful_steps,
        phase.failed_steps,
        phase.skipped_steps
      )
    })
    .collect()
}

fn execution_preview_phases_payload(phases: &[ExecutionPhaseSummary]) -> Value {
  let items: Vec<Value> = phases
    .iter()
    .map(|phase| {
      json!({
        "phase": phase.phase,
        "total_steps": phase.total_steps,
        "successful_steps": phase.successful_steps,
        "failed_steps": phase.failed_steps,
        "skipped_steps": phase.skipped_steps,
        "total_duration_ms": phase.total_duration_ms,
        "command_count": phase.command_count,
        "steps": phase.steps
      })
    })
    .collect();

  Value::Array(items)
}

fn upsert_execution_phase(
  phases: &mut Vec<ExecutionPhaseSummary>,
  phase_name: &str,
  step_name: &str,
  action: &ActionRecord,
  duration_ms: u64,
  command_count: usize,
) {
  let phase = if let Some(existing) = phases.iter_mut().find(|item| item.phase == phase_name) {
    existing
  } else {
    phases.push(ExecutionPhaseSummary {
      phase: phase_name.to_string(),
      ..ExecutionPhaseSummary::default()
    });
    phases.last_mut().expect("phase inserted")
  };

  phase.total_steps += 1;
  phase.total_duration_ms += duration_ms;
  phase.command_count += command_count;

  match &action.outcome {
    ActionOutcome::Success | ActionOutcome::Partial { .. } => phase.successful_steps += 1,
    ActionOutcome::Failed { .. } | ActionOutcome::Timeout { .. } => phase.failed_steps += 1,
    ActionOutcome::Skipped { .. } => phase.skipped_steps += 1,
  }

  if !phase.steps.iter().any(|name| name == step_name) {
    phase.steps.push(step_name.to_string());
  }
}

fn parse_references(value: &str) -> Vec<String> {
  value
    .split('\n')
    .map(str::trim)
    .filter(|item| !item.is_empty())
    .map(|item| item.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::storage::schema::Value as StorageValue;
  use crate::storage::{EntityId, UnifiedEntity};
  use std::collections::HashMap;

  #[test]
  fn missing_recon_payload_marks_error() {
    let payload = missing_recon_payload("example.com");
    assert_eq!(payload["target"], json!("example.com"));
    assert_eq!(payload["error"], json!("no_recon_data"));
  }

  #[test]
  fn apt_groups_payload_lists_groups() {
    let payload = apt_groups_payload(&[("apt29", "Cozy Bear"), ("apt28", "Fancy Bear")]);
    // Verify the payload serializes as a JSON string containing expected values
    let json_str = format!("{:?}", payload);
    assert!(json_str.contains("apt29"));
    assert!(json_str.contains("Fancy Bear"));
  }

  #[test]
  fn entity_to_vuln_record_maps_graph_node() {
    let mut props = HashMap::new();
    props.insert(
      "cve_id".to_string(),
      StorageValue::Text("CVE-2024-1234".to_string()),
    );
    props.insert(
      "technology".to_string(),
      StorageValue::Text("nginx".to_string()),
    );
    props.insert(
      "version".to_string(),
      StorageValue::Text("1.25.3".to_string()),
    );
    props.insert("cvss".to_string(), StorageValue::Float(9.8));
    props.insert("risk_score".to_string(), StorageValue::Integer(92));
    props.insert(
      "severity".to_string(),
      StorageValue::Text("critical".to_string()),
    );
    props.insert(
      "description".to_string(),
      StorageValue::Text("Remote code execution in crafted request path".to_string()),
    );
    props.insert(
      "references".to_string(),
      StorageValue::Text(
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234\nhttps://example.com/advisory".to_string(),
      ),
    );
    props.insert("exploit_available".to_string(), StorageValue::Boolean(true));
    props.insert("in_kev".to_string(), StorageValue::Boolean(true));
    props.insert(
      "discovered_at".to_string(),
      StorageValue::Integer(1_712_345_678),
    );
    props.insert("source".to_string(), StorageValue::Text("nvd".to_string()));

    let entity = UnifiedEntity::graph_node(EntityId::new(1), "vuln", "finding", props);
    let record = AttackCommand
      .entity_to_vuln_record(&entity)
      .expect("expected vuln record");

    assert_eq!(record.cve_id, "CVE-2024-1234");
    assert_eq!(record.technology, "nginx");
    assert_eq!(record.version.as_deref(), Some("1.25.3"));
    assert_eq!(record.severity, StorageSeverity::Critical);
    assert_eq!(record.references.len(), 2);
    assert!(record.exploit_available);
    assert!(record.in_kev);
  }

  #[test]
  fn entity_to_vuln_record_falls_back_to_cvss_for_severity() {
    let mut props = HashMap::new();
    props.insert(
      "cve_id".to_string(),
      StorageValue::Text("CVE-2023-9999".to_string()),
    );
    props.insert(
      "technology".to_string(),
      StorageValue::Text("apache".to_string()),
    );
    props.insert("cvss".to_string(), StorageValue::Float(7.5));

    let entity = UnifiedEntity::graph_node(EntityId::new(2), "vuln", "finding", props);
    let record = AttackCommand
      .entity_to_vuln_record(&entity)
      .expect("expected vuln record");

    assert_eq!(record.severity, StorageSeverity::High);
    assert_eq!(record.source, "unknown");
    assert_eq!(record.references, Vec::<String>::new());
  }

  #[test]
  fn execution_action_summary_counts_and_keeps_context() {
    let action = ActionRecord::new(
      ActionSource::playbook([1u8; 16], 2),
      crate::storage::Target::Domain("example.com".to_string()),
      crate::storage::ActionType::Exploit,
      RecordPayload::Custom(
        crate::serde_json::to_vec(&json!({
          "step_name": "Privilege Escalation",
          "phase": "Privilege Escalation",
          "duration_ms": 4200
        }))
        .unwrap(),
      ),
      ActionOutcome::Success,
    );

    let summary = execution_action_summary(&[action]);

    assert_eq!(summary.total_actions, 1);
    assert_eq!(summary.successful_actions, 1);
    assert_eq!(summary.exploit_actions, 1);
    assert_eq!(
      summary.steps[0]["context"]["step_name"],
      json!("Privilege Escalation")
    );
    assert_eq!(summary.phases[0].phase, "Privilege Escalation");
    assert_eq!(summary.phases[0].successful_steps, 1);
  }

  #[test]
  fn playbook_dry_run_payload_includes_phase_summary_and_narrative() {
    let playbook = crate::playbooks::Playbook::new("pb-1", "Privilege Escalation")
      .with_risk(RiskLevel::High)
      .with_duration("15 minutes")
      .add_precondition(crate::playbooks::PreCondition::new(
        "Operator authorization",
      ))
      .add_step(
        crate::playbooks::PlaybookStep::new(
          1,
          crate::playbooks::PlaybookPhase::Discovery,
          "Enumerate sudo rights",
        )
        .with_command("rb access system process list")
        .with_manual("Confirm local shell access"),
      )
      .add_step(
        crate::playbooks::PlaybookStep::new(
          2,
          crate::playbooks::PlaybookPhase::PrivilegeEscalation,
          "Escalate privileges",
        )
        .with_command("rb exploit payload privesc")
        .with_success("Root shell obtained"),
      )
      .add_assertion(
        crate::playbooks::Assertion::new("Root privileges confirmed", "steps_completed").critical(),
      );

    let preview = playbook_execution_preview(&playbook);
    let payload = playbook_dry_run_payload(&playbook, "example.com", false, &preview);

    assert_eq!(payload["summary"]["total_steps"], json!(2));
    assert_eq!(payload["summary"]["manual_steps"], json!(1));
    assert_eq!(
      payload["phase_summary"].as_array().unwrap()[0]["phase"],
      json!("Discovery")
    );
    assert_eq!(
      payload["execution_narrative"].as_array().unwrap()[1],
      json!("Privilege Escalation is planned with 1 step(s) and 1 command hint(s).")
    );
    assert_eq!(
      payload["assertions"].as_array().unwrap()[0]["critical"],
      json!(true)
    );
  }
}
