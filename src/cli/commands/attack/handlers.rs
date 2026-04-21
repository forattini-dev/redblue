impl AttackCommand {
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
