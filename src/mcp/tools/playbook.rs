//! Playbook MCP Tools
//!
//! List, inspect, and execute security playbooks and APT emulation plans.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register playbook tools with the server
pub fn register_playbook_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
        ToolDefinition {
            name: "rb.playbook.list",
            description: "List all available security playbooks with descriptions, risk levels, and target types.",
            fields: &[
                ToolField {
                    name: "risk",
                    field_type: "string",
                    description: "Filter by maximum risk level: 'passive', 'low', 'medium', 'high', 'critical'.",
                    required: false,
                },
                ToolField {
                    name: "tag",
                    field_type: "string",
                    description: "Filter by tag (e.g., 'web', 'network', 'privesc', 'lateral-movement').",
                    required: false,
                },
            ],
            handler: tool_playbook_list,
        },
        ToolDefinition {
            name: "rb.playbook.show",
            description: "Show detailed information about a specific playbook including steps, phases, and kill chain mapping.",
            fields: &[ToolField {
                name: "id",
                field_type: "string",
                description: "Playbook ID (e.g., 'reverse-shell-linux', 'web-app-assessment', 'linux-privesc').",
                required: true,
            }],
            handler: tool_playbook_show,
        },
        ToolDefinition {
            name: "rb.playbook.apt.list",
            description: "List all APT adversary emulation playbooks with group names and technique counts.",
            fields: &[],
            handler: tool_playbook_apt_list,
        },
        ToolDefinition {
            name: "rb.playbook.apt.show",
            description: "Show details of an APT adversary emulation playbook including phases, steps, and technique coverage.",
            fields: &[ToolField {
                name: "group",
                field_type: "string",
                description: "APT group ID (e.g., 'apt28', 'apt29', 'lazarus-group', 'volt-typhoon').",
                required: true,
            }],
            handler: tool_playbook_apt_show,
        },
        ToolDefinition {
            name: "rb.playbook.run",
            description: "Execute a playbook against a target. Runs in dry-run mode by default for safety.",
            fields: &[
                ToolField {
                    name: "id",
                    field_type: "string",
                    description: "Playbook ID to execute (e.g., 'web-app-assessment', 'external-footprint').",
                    required: true,
                },
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target to run the playbook against (IP, hostname, URL, or CIDR).",
                    required: true,
                },
                ToolField {
                    name: "dry_run",
                    field_type: "boolean",
                    description: "If true, show what would happen without executing. Default: true.",
                    required: false,
                },
                ToolField {
                    name: "allow_intrusive",
                    field_type: "boolean",
                    description: "Allow high-risk/intrusive steps. Default: false.",
                    required: false,
                },
                ToolField {
                    name: "verbosity",
                    field_type: "number",
                    description: "Verbosity level 0-3. Default: 1.",
                    required: false,
                },
            ],
            handler: tool_playbook_run,
        },
    ]
}

fn tool_playbook_list(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::playbooks::{all_playbooks, playbooks_by_risk, playbooks_by_tag, RiskLevel};

  let playbooks = if let Some(tag) = args.get("tag").and_then(|v| v.as_str()) {
    playbooks_by_tag(tag)
  } else if let Some(risk) = args.get("risk").and_then(|v| v.as_str()) {
    let max_risk = match risk.to_lowercase().as_str() {
      "passive" => RiskLevel::Passive,
      "low" => RiskLevel::Low,
      "medium" => RiskLevel::Medium,
      "high" => RiskLevel::High,
      "critical" => RiskLevel::Critical,
      _ => {
        return Err(format!(
          "Invalid risk level: {}. Use: passive, low, medium, high, critical",
          risk
        ))
      }
    };
    playbooks_by_risk(max_risk)
  } else {
    all_playbooks()
  };

  let playbooks_json: Vec<JsonValue> = playbooks
    .iter()
    .map(|p| {
      let target_types: Vec<JsonValue> = p
        .metadata
        .target_types
        .iter()
        .map(|t| JsonValue::String(t.as_str().to_string()))
        .collect();

      let tags: Vec<JsonValue> = p
        .metadata
        .tags
        .iter()
        .map(|t| JsonValue::String(t.clone()))
        .collect();

      JsonValue::object(vec![
        ("id".to_string(), JsonValue::String(p.metadata.id.clone())),
        (
          "name".to_string(),
          JsonValue::String(p.metadata.name.clone()),
        ),
        (
          "description".to_string(),
          JsonValue::String(p.metadata.description.clone()),
        ),
        (
          "risk_level".to_string(),
          JsonValue::String(p.metadata.risk_level.as_str().to_string()),
        ),
        ("target_types".to_string(), JsonValue::array(target_types)),
        ("tags".to_string(), JsonValue::array(tags)),
        (
          "steps".to_string(),
          JsonValue::Number(p.total_steps() as f64),
        ),
        (
          "estimated_duration".to_string(),
          JsonValue::String(p.metadata.estimated_duration.clone()),
        ),
      ])
    })
    .collect();

  let text = format!("Found {} playbooks", playbooks_json.len());

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "count".to_string(),
        JsonValue::Number(playbooks_json.len() as f64),
      ),
      ("playbooks".to_string(), JsonValue::array(playbooks_json)),
    ]),
  })
}

fn tool_playbook_show(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::playbooks::get_playbook;

  let id = args
    .get("id")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: id")?;

  let playbook = get_playbook(id).ok_or_else(|| format!("Playbook not found: {}", id))?;

  let steps_json: Vec<JsonValue> = playbook
    .steps
    .iter()
    .map(|s| {
      let commands: Vec<JsonValue> = s
        .commands
        .iter()
        .map(|c| JsonValue::String(c.clone()))
        .collect();

      let success_criteria: Vec<JsonValue> = s
        .success_criteria
        .iter()
        .map(|c| JsonValue::String(c.clone()))
        .collect();

      JsonValue::object(vec![
        ("number".to_string(), JsonValue::Number(s.number as f64)),
        (
          "phase".to_string(),
          JsonValue::String(s.phase.as_str().to_string()),
        ),
        ("name".to_string(), JsonValue::String(s.name.clone())),
        (
          "description".to_string(),
          JsonValue::String(s.description.clone()),
        ),
        ("commands".to_string(), JsonValue::array(commands)),
        (
          "success_criteria".to_string(),
          JsonValue::array(success_criteria),
        ),
        ("optional".to_string(), JsonValue::Bool(s.optional)),
        (
          "timeout_secs".to_string(),
          JsonValue::Number(s.timeout.as_secs() as f64),
        ),
      ])
    })
    .collect();

  let preconditions_json: Vec<JsonValue> = playbook
    .preconditions
    .iter()
    .map(|pc| {
      JsonValue::object(vec![
        (
          "description".to_string(),
          JsonValue::String(pc.description.clone()),
        ),
        ("required".to_string(), JsonValue::Bool(pc.required)),
        (
          "notes".to_string(),
          pc.notes
            .as_ref()
            .map(|n| JsonValue::String(n.clone()))
            .unwrap_or(JsonValue::Null),
        ),
      ])
    })
    .collect();

  let kill_chain_json: Vec<JsonValue> = playbook
    .kill_chain
    .iter()
    .map(|kc| {
      let step_nums: Vec<JsonValue> = kc
        .step_numbers
        .iter()
        .map(|n| JsonValue::Number(*n as f64))
        .collect();

      JsonValue::object(vec![
        ("name".to_string(), JsonValue::String(kc.name.clone())),
        (
          "description".to_string(),
          JsonValue::String(kc.description.clone()),
        ),
        ("step_numbers".to_string(), JsonValue::array(step_nums)),
      ])
    })
    .collect();

  let target_types: Vec<JsonValue> = playbook
    .metadata
    .target_types
    .iter()
    .map(|t| JsonValue::String(t.as_str().to_string()))
    .collect();

  let target_os: Vec<JsonValue> = playbook
    .metadata
    .target_os
    .iter()
    .map(|os| JsonValue::String(os.as_str().to_string()))
    .collect();

  let tags: Vec<JsonValue> = playbook
    .metadata
    .tags
    .iter()
    .map(|t| JsonValue::String(t.clone()))
    .collect();

  let evidence_json: Vec<JsonValue> = playbook
    .evidence
    .iter()
    .map(|e| {
      let indicators: Vec<JsonValue> = e
        .indicators
        .iter()
        .map(|i| JsonValue::String(i.clone()))
        .collect();

      JsonValue::object(vec![
        (
          "description".to_string(),
          JsonValue::String(e.description.clone()),
        ),
        (
          "location".to_string(),
          JsonValue::String(e.location.clone()),
        ),
        ("indicators".to_string(), JsonValue::array(indicators)),
        (
          "severity".to_string(),
          JsonValue::String(format!("{:?}", e.severity)),
        ),
      ])
    })
    .collect();

  let failed_controls_json: Vec<JsonValue> = playbook
    .failed_controls
    .iter()
    .map(|fc| {
      JsonValue::object(vec![
        ("name".to_string(), JsonValue::String(fc.name.clone())),
        ("reason".to_string(), JsonValue::String(fc.reason.clone())),
        (
          "remediation".to_string(),
          JsonValue::String(fc.remediation.clone()),
        ),
      ])
    })
    .collect();

  let text = format!(
    "Playbook: {} ({}) - {} steps, risk: {}",
    playbook.metadata.name,
    playbook.metadata.id,
    playbook.total_steps(),
    playbook.metadata.risk_level.as_str()
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "id".to_string(),
        JsonValue::String(playbook.metadata.id.clone()),
      ),
      (
        "name".to_string(),
        JsonValue::String(playbook.metadata.name.clone()),
      ),
      (
        "description".to_string(),
        JsonValue::String(playbook.metadata.description.clone()),
      ),
      (
        "objective".to_string(),
        JsonValue::String(playbook.metadata.objective.clone()),
      ),
      (
        "author".to_string(),
        JsonValue::String(playbook.metadata.author.clone()),
      ),
      (
        "version".to_string(),
        JsonValue::String(playbook.metadata.version.clone()),
      ),
      (
        "risk_level".to_string(),
        JsonValue::String(playbook.metadata.risk_level.as_str().to_string()),
      ),
      (
        "estimated_duration".to_string(),
        JsonValue::String(playbook.metadata.estimated_duration.clone()),
      ),
      ("target_types".to_string(), JsonValue::array(target_types)),
      ("target_os".to_string(), JsonValue::array(target_os)),
      ("tags".to_string(), JsonValue::array(tags)),
      (
        "total_steps".to_string(),
        JsonValue::Number(playbook.total_steps() as f64),
      ),
      (
        "preconditions".to_string(),
        JsonValue::array(preconditions_json),
      ),
      ("steps".to_string(), JsonValue::array(steps_json)),
      ("kill_chain".to_string(), JsonValue::array(kill_chain_json)),
      ("evidence".to_string(), JsonValue::array(evidence_json)),
      (
        "failed_controls".to_string(),
        JsonValue::array(failed_controls_json),
      ),
    ]),
  })
}

fn tool_playbook_apt_list(
  _server: &mut McpServer,
  _args: &JsonValue,
) -> Result<ToolResult, String> {
  use crate::playbooks::{all_apt_playbooks, list_apt_groups};

  let groups = list_apt_groups();
  let apt_playbooks = all_apt_playbooks();

  let groups_json: Vec<JsonValue> = groups
    .iter()
    .map(|(id, name)| {
      let step_count = apt_playbooks
        .iter()
        .find(|p| p.metadata.id == *id)
        .map(|p| p.total_steps())
        .unwrap_or(0);

      let description = apt_playbooks
        .iter()
        .find(|p| p.metadata.id == *id)
        .map(|p| p.metadata.description.clone())
        .unwrap_or_default();

      let technique_count = apt_playbooks
        .iter()
        .find(|p| p.metadata.id == *id)
        .map(|p| p.metadata.mitre_techniques.len())
        .unwrap_or(0);

      JsonValue::object(vec![
        ("id".to_string(), JsonValue::String(id.to_string())),
        ("name".to_string(), JsonValue::String(name.to_string())),
        ("description".to_string(), JsonValue::String(description)),
        ("steps".to_string(), JsonValue::Number(step_count as f64)),
        (
          "techniques".to_string(),
          JsonValue::Number(technique_count as f64),
        ),
      ])
    })
    .collect();

  let text = format!(
    "Found {} APT adversary emulation playbooks",
    groups_json.len()
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "count".to_string(),
        JsonValue::Number(groups_json.len() as f64),
      ),
      ("groups".to_string(), JsonValue::array(groups_json)),
    ]),
  })
}

fn tool_playbook_apt_show(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::playbooks::get_apt_playbook;

  let group = args
    .get("group")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: group")?;

  let playbook =
    get_apt_playbook(group).ok_or_else(|| format!("APT playbook not found: {}", group))?;

  let steps_json: Vec<JsonValue> = playbook
    .steps
    .iter()
    .map(|s| {
      let commands: Vec<JsonValue> = s
        .commands
        .iter()
        .map(|c| JsonValue::String(c.clone()))
        .collect();

      JsonValue::object(vec![
        ("number".to_string(), JsonValue::Number(s.number as f64)),
        (
          "phase".to_string(),
          JsonValue::String(s.phase.as_str().to_string()),
        ),
        ("name".to_string(), JsonValue::String(s.name.clone())),
        (
          "description".to_string(),
          JsonValue::String(s.description.clone()),
        ),
        ("commands".to_string(), JsonValue::array(commands)),
        ("optional".to_string(), JsonValue::Bool(s.optional)),
      ])
    })
    .collect();

  // Collect unique phases
  let mut phases: Vec<String> = playbook
    .steps
    .iter()
    .map(|s| s.phase.as_str().to_string())
    .collect();
  phases.dedup();
  let phases_json: Vec<JsonValue> = phases
    .iter()
    .map(|p| JsonValue::String(p.clone()))
    .collect();

  let kill_chain_json: Vec<JsonValue> = playbook
    .kill_chain
    .iter()
    .map(|kc| {
      let step_nums: Vec<JsonValue> = kc
        .step_numbers
        .iter()
        .map(|n| JsonValue::Number(*n as f64))
        .collect();

      JsonValue::object(vec![
        ("name".to_string(), JsonValue::String(kc.name.clone())),
        (
          "description".to_string(),
          JsonValue::String(kc.description.clone()),
        ),
        ("step_numbers".to_string(), JsonValue::array(step_nums)),
      ])
    })
    .collect();

  let target_types: Vec<JsonValue> = playbook
    .metadata
    .target_types
    .iter()
    .map(|t| JsonValue::String(t.as_str().to_string()))
    .collect();

  let tags: Vec<JsonValue> = playbook
    .metadata
    .tags
    .iter()
    .map(|t| JsonValue::String(t.clone()))
    .collect();

  let text = format!(
    "APT Playbook: {} ({}) - {} steps, {} techniques",
    playbook.metadata.name,
    playbook.metadata.id,
    playbook.total_steps(),
    playbook.metadata.mitre_techniques.len()
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "id".to_string(),
        JsonValue::String(playbook.metadata.id.clone()),
      ),
      (
        "name".to_string(),
        JsonValue::String(playbook.metadata.name.clone()),
      ),
      (
        "description".to_string(),
        JsonValue::String(playbook.metadata.description.clone()),
      ),
      (
        "objective".to_string(),
        JsonValue::String(playbook.metadata.objective.clone()),
      ),
      (
        "risk_level".to_string(),
        JsonValue::String(playbook.metadata.risk_level.as_str().to_string()),
      ),
      ("target_types".to_string(), JsonValue::array(target_types)),
      ("tags".to_string(), JsonValue::array(tags)),
      (
        "total_steps".to_string(),
        JsonValue::Number(playbook.total_steps() as f64),
      ),
      (
        "technique_count".to_string(),
        JsonValue::Number(playbook.metadata.mitre_techniques.len() as f64),
      ),
      ("phases".to_string(), JsonValue::array(phases_json)),
      ("steps".to_string(), JsonValue::array(steps_json)),
      ("kill_chain".to_string(), JsonValue::array(kill_chain_json)),
    ]),
  })
}

fn tool_playbook_run(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::playbooks::{get_playbook, PlaybookContext, PlaybookExecutor};

  let id = args
    .get("id")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: id")?;

  let target = args
    .get("target")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: target")?;

  let dry_run = args
    .get("dry_run")
    .and_then(|v| v.as_bool())
    .unwrap_or(true);

  let allow_intrusive = args
    .get("allow_intrusive")
    .and_then(|v| v.as_bool())
    .unwrap_or(false);

  let verbosity = args
    .get("verbosity")
    .and_then(|v| v.as_f64())
    .map(|v| v as u8)
    .unwrap_or(1);

  let playbook = get_playbook(id).ok_or_else(|| format!("Playbook not found: {}", id))?;

  // Safety check: require explicit consent for high-risk playbooks
  if playbook.metadata.risk_level.requires_consent() && !allow_intrusive && !dry_run {
    return Err(format!(
            "Playbook '{}' has {} risk level. Set allow_intrusive=true to execute, or use dry_run=true to preview.",
            id,
            playbook.metadata.risk_level.as_str()
        ));
  }

  let mut context = PlaybookContext::new(target);
  context.dry_run = dry_run;
  context.allow_intrusive = allow_intrusive;
  context.verbosity = verbosity;

  let mut executor = PlaybookExecutor::new();
  let result = executor.execute(&playbook, &mut context);

  let step_results_json: Vec<JsonValue> = result
    .step_results
    .iter()
    .map(|sr| {
      let output: Vec<JsonValue> = sr
        .output
        .iter()
        .map(|o| JsonValue::String(o.clone()))
        .collect();

      JsonValue::object(vec![
        (
          "step_number".to_string(),
          JsonValue::Number(sr.step_number as f64),
        ),
        (
          "step_name".to_string(),
          JsonValue::String(sr.step_name.clone()),
        ),
        ("success".to_string(), JsonValue::Bool(sr.success)),
        ("skipped".to_string(), JsonValue::Bool(sr.skipped)),
        ("status".to_string(), JsonValue::String(sr.status.clone())),
        ("output".to_string(), JsonValue::array(output)),
        (
          "duration_secs".to_string(),
          JsonValue::Number(sr.duration.as_secs_f64()),
        ),
        (
          "error".to_string(),
          sr.error
            .as_ref()
            .map(|e| JsonValue::String(e.clone()))
            .unwrap_or(JsonValue::Null),
        ),
      ])
    })
    .collect();

  let findings_json: Vec<JsonValue> = result
    .all_findings
    .iter()
    .map(|f| {
      JsonValue::object(vec![
        ("title".to_string(), JsonValue::String(f.title.clone())),
        (
          "severity".to_string(),
          JsonValue::String(format!("{:?}", f.severity)),
        ),
        (
          "description".to_string(),
          JsonValue::String(f.description.clone()),
        ),
      ])
    })
    .collect();

  let mode = if dry_run { "dry-run" } else { "live" };
  let text = format!(
    "Playbook '{}' {} execution against {}: {} - {}/{} steps completed, {} skipped, {} failed",
    playbook.metadata.name,
    mode,
    target,
    if result.success { "SUCCESS" } else { "FAILED" },
    result.steps_completed,
    playbook.total_steps(),
    result.steps_skipped,
    result.steps_failed
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "playbook_id".to_string(),
        JsonValue::String(result.playbook_id.clone()),
      ),
      (
        "playbook_name".to_string(),
        JsonValue::String(result.playbook_name.clone()),
      ),
      (
        "target".to_string(),
        JsonValue::String(result.target.clone()),
      ),
      ("mode".to_string(), JsonValue::String(mode.to_string())),
      ("success".to_string(), JsonValue::Bool(result.success)),
      (
        "summary".to_string(),
        JsonValue::String(result.summary.clone()),
      ),
      (
        "steps_completed".to_string(),
        JsonValue::Number(result.steps_completed as f64),
      ),
      (
        "steps_skipped".to_string(),
        JsonValue::Number(result.steps_skipped as f64),
      ),
      (
        "steps_failed".to_string(),
        JsonValue::Number(result.steps_failed as f64),
      ),
      (
        "total_steps".to_string(),
        JsonValue::Number(playbook.total_steps() as f64),
      ),
      (
        "duration_secs".to_string(),
        JsonValue::Number(result.duration.as_secs_f64()),
      ),
      (
        "step_results".to_string(),
        JsonValue::array(step_results_json),
      ),
      ("findings".to_string(), JsonValue::array(findings_json)),
      (
        "findings_count".to_string(),
        JsonValue::Number(result.all_findings.len() as f64),
      ),
      (
        "next_playbook".to_string(),
        result
          .next_playbook
          .as_ref()
          .map(|n| JsonValue::String(n.clone()))
          .unwrap_or(JsonValue::Null),
      ),
    ]),
  })
}
