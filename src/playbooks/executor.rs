use crate::crypto::uuid::Uuid;
use crate::json;
use crate::playbooks::template::TemplateEngine;
use crate::playbooks::{
  Assertion, AssertionOperator, AssertionResult, EvidenceType, Playbook, PlaybookContext,
  PlaybookExecutionResult, PlaybookStep, StepCondition, StepExecutionResult, StepFailureAction,
};
use crate::scripts::{builtin, ScriptContext, ScriptRunner};
use crate::serde_json;
use crate::storage::segments::actions::{
  ActionOutcome, ActionRecord, ActionSource, ActionType, RecordPayload, Target,
};
use crate::storage::ActionConfig;
use std::io::Read;
use std::net::IpAddr;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

enum CommandExecError {
  Spawn(String),
  Io(String),
  Timeout {
    after: Duration,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
  },
}

/// Executor for playbooks with unified intelligence layer integration
pub struct PlaybookExecutor {
  template_engine: TemplateEngine,
  /// Playbook run ID for action tracking
  run_id: [u8; 16],
  /// Action configuration (tracing, storage)
  action_config: ActionConfig,
  /// Recorded actions for this execution
  actions: Vec<ActionRecord>,
  /// Evidence types collected during this execution
  collected_evidence: std::collections::HashSet<EvidenceType>,
  /// Historical actions loaded from database for the current target
  historical_actions: Vec<ActionRecord>,
}

impl Default for PlaybookExecutor {
  fn default() -> Self {
    Self::new()
  }
}

impl PlaybookExecutor {
  /// Create a new executor with default configuration
  pub fn new() -> Self {
    Self::with_config(ActionConfig::default())
  }

  /// Create a new executor with specific action configuration
  pub fn with_config(action_config: ActionConfig) -> Self {
    // Generate a unique run ID for this playbook execution
    let run_id = Uuid::new_v4().as_bytes().clone();
    Self {
      template_engine: TemplateEngine::new(),
      run_id,
      action_config,
      actions: Vec::new(),
      collected_evidence: std::collections::HashSet::new(),
      historical_actions: Vec::new(),
    }
  }

  /// Get the run ID for this execution
  pub fn run_id(&self) -> [u8; 16] {
    self.run_id
  }

  /// Get all recorded actions from this execution
  pub fn actions(&self) -> &[ActionRecord] {
    &self.actions
  }

  /// Query actions by target from this execution
  pub fn actions_for_target(&self, target: &Target) -> Vec<&ActionRecord> {
    self
      .actions
      .iter()
      .filter(|a| &a.target == target)
      .collect()
  }

  /// Query successful actions from this execution
  pub fn successful_actions(&self) -> Vec<&ActionRecord> {
    self
      .actions
      .iter()
      .filter(|a| matches!(a.outcome, ActionOutcome::Success))
      .collect()
  }

  /// Get collected evidence types
  pub fn collected_evidence(&self) -> &std::collections::HashSet<EvidenceType> {
    &self.collected_evidence
  }

  /// Get historical actions for the current target
  pub fn historical_actions(&self) -> &[ActionRecord] {
    &self.historical_actions
  }

  /// Load historical actions for a target from the database
  /// This populates historical_actions for use in step conditions
  pub fn load_historical_actions(&mut self, target: &str) -> Result<usize, String> {
    use crate::storage::service::StorageService;

    let path = StorageService::db_path("_actions");
    let mut db = match StorageService::global().open_query_manager(path) {
      Ok(db) => db,
      Err(_) => return Ok(0), // No database yet, no historical actions
    };

    match db.list_actions_by_target(target) {
      Ok(actions) => {
        let count = actions.len();
        self.historical_actions = actions;
        Ok(count)
      }
      Err(e) => Err(format!("Failed to load historical actions: {}", e)),
    }
  }

  /// Check if target was previously scanned successfully
  pub fn was_previously_scanned(&self) -> bool {
    self.historical_actions.iter().any(|a| {
      matches!(a.action_type, ActionType::Scan) && matches!(a.outcome, ActionOutcome::Success)
    })
  }

  /// Check if target has previous vulnerability findings
  pub fn has_previous_vulnerabilities(&self) -> bool {
    self.historical_actions.iter().any(|a| {
      matches!(a.action_type, ActionType::Audit)
        && matches!(a.outcome, ActionOutcome::Success)
        && matches!(a.payload, RecordPayload::Tls(_) | RecordPayload::Vuln(_))
    })
  }

  /// Evaluate an assertion against the execution result and context
  fn evaluate_assertion(
    &self,
    assertion: &Assertion,
    result: &PlaybookExecutionResult,
    context: &PlaybookContext,
  ) -> AssertionResult {
    // Resolve the subject value from result/context
    let actual = self.resolve_assertion_subject(&assertion.subject, result, context);

    let passed = match &assertion.operator {
      AssertionOperator::Equals => actual.as_ref() == assertion.expected.as_ref(),
      AssertionOperator::NotEquals => actual.as_ref() != assertion.expected.as_ref(),
      AssertionOperator::GreaterThan => {
        match (
          actual.as_ref().and_then(|v| v.parse::<i64>().ok()),
          assertion
            .expected
            .as_ref()
            .and_then(|v| v.parse::<i64>().ok()),
        ) {
          (Some(a), Some(e)) => a > e,
          _ => false,
        }
      }
      AssertionOperator::LessThan => {
        match (
          actual.as_ref().and_then(|v| v.parse::<i64>().ok()),
          assertion
            .expected
            .as_ref()
            .and_then(|v| v.parse::<i64>().ok()),
        ) {
          (Some(a), Some(e)) => a < e,
          _ => false,
        }
      }
      AssertionOperator::GreaterOrEqual => {
        match (
          actual.as_ref().and_then(|v| v.parse::<i64>().ok()),
          assertion
            .expected
            .as_ref()
            .and_then(|v| v.parse::<i64>().ok()),
        ) {
          (Some(a), Some(e)) => a >= e,
          _ => false,
        }
      }
      AssertionOperator::LessOrEqual => {
        match (
          actual.as_ref().and_then(|v| v.parse::<i64>().ok()),
          assertion
            .expected
            .as_ref()
            .and_then(|v| v.parse::<i64>().ok()),
        ) {
          (Some(a), Some(e)) => a <= e,
          _ => false,
        }
      }
      AssertionOperator::Contains => match (actual.as_ref(), assertion.expected.as_ref()) {
        (Some(a), Some(e)) => a.contains(e.as_str()),
        _ => false,
      },
      AssertionOperator::NotContains => match (actual.as_ref(), assertion.expected.as_ref()) {
        (Some(a), Some(e)) => !a.contains(e.as_str()),
        _ => true,
      },
      AssertionOperator::Matches => {
        // Simple pattern matching (could use regex crate if available)
        match (actual.as_ref(), assertion.expected.as_ref()) {
          (Some(a), Some(pattern)) => {
            // Basic wildcard support: * matches anything
            let pattern = pattern.replace("*", ".*");
            a.contains(&pattern.replace(".*", ""))
          }
          _ => false,
        }
      }
      AssertionOperator::IsTrue => actual
        .as_ref()
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false),
      AssertionOperator::IsFalse => actual
        .as_ref()
        .map(|v| v == "false" || v == "0")
        .unwrap_or(true),
      AssertionOperator::Exists => actual.is_some() && !actual.as_ref().unwrap().is_empty(),
      AssertionOperator::NotExists => actual.is_none() || actual.as_ref().unwrap().is_empty(),
    };

    if passed {
      AssertionResult::passed(&assertion.description)
    } else {
      let message = assertion.failure_message.clone().unwrap_or_else(|| {
        format!(
          "Assertion failed: {} {} {}",
          assertion.subject,
          assertion.operator.as_str(),
          assertion.expected.as_ref().unwrap_or(&"".to_string())
        )
      });
      let mut result = AssertionResult::failed(&assertion.description, &message);
      if let Some(actual_val) = actual {
        result = result.with_values(
          &actual_val,
          assertion.expected.as_ref().unwrap_or(&"".to_string()),
        );
      }
      result
    }
  }

  /// Resolve a subject path to its value
  fn resolve_assertion_subject(
    &self,
    subject: &str,
    result: &PlaybookExecutionResult,
    context: &PlaybookContext,
  ) -> Option<String> {
    match subject {
      // Built-in result metrics
      "steps_completed" => Some(result.steps_completed.to_string()),
      "steps_skipped" => Some(result.steps_skipped.to_string()),
      "steps_failed" => Some(result.steps_failed.to_string()),
      "success" => Some(result.success.to_string()),
      "findings.count" => Some(result.all_findings.len().to_string()),
      "duration_secs" => Some(result.duration.as_secs().to_string()),

      // Evidence types
      "evidence.credentials" => Some(
        self
          .collected_evidence
          .contains(&EvidenceType::Credentials)
          .to_string(),
      ),
      "evidence.vulnerability" => Some(
        self
          .collected_evidence
          .contains(&EvidenceType::Vulnerability)
          .to_string(),
      ),
      "evidence.screenshot" => Some(
        self
          .collected_evidence
          .contains(&EvidenceType::Screenshot)
          .to_string(),
      ),
      "evidence.file_artifact" => Some(
        self
          .collected_evidence
          .contains(&EvidenceType::FileArtifact)
          .to_string(),
      ),
      "evidence.system_info" => Some(
        self
          .collected_evidence
          .contains(&EvidenceType::SystemInfo)
          .to_string(),
      ),

      // Context data
      s if s.starts_with("data.") => {
        let key = &s[5..];
        context.gathered_data.get(key).cloned()
      }
      s if s.starts_with("arg.") => {
        let key = &s[4..];
        context.args.get(key).cloned()
      }

      // Fallback - try gathered data
      _ => context.gathered_data.get(subject).cloned(),
    }
  }

  /// Execute steps in a parallel group concurrently
  fn execute_parallel_group(
    &self,
    steps: Vec<&PlaybookStep>,
    context: &PlaybookContext,
  ) -> Vec<StepExecutionResult> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for step in steps {
      let step_clone = step.clone();
      let context_clone = context.clone();
      let template_engine = TemplateEngine::new();
      let results_clone = Arc::clone(&results);

      let handle = thread::spawn(move || {
        let start = Instant::now();
        let mut result = StepExecutionResult::new(&step_clone);
        let mut any_failure = false;
        let mut timed_out = false;
        let step_deadline = start + context_clone.step_timeout;

        // Execute commands
        for cmd_tmpl in &step_clone.commands {
          let cmd_str = template_engine.render(cmd_tmpl, &context_clone);
          let parts = match Self::split_command_line(&cmd_str) {
            Ok(parts) => parts,
            Err(e) => {
              result
                .output
                .push(format!("Command parse error: {} ({})", cmd_str, e));
              any_failure = true;
              continue;
            }
          };

          if parts.is_empty() {
            continue;
          }

          let cmd = parts[0].clone();
          let args = parts[1..].to_vec();
          let remaining = step_deadline.saturating_duration_since(Instant::now());
          if remaining.is_zero() {
            result
              .output
              .push(format!("Step timed out before: {}", cmd_str));
            timed_out = true;
            any_failure = true;
            break;
          }

          match Self::run_command_with_timeout(&cmd, &args, remaining) {
            Ok(output) => {
              let stdout = String::from_utf8_lossy(&output.stdout).to_string();
              if !stdout.is_empty() {
                result.output.push(stdout);
              }
              if !output.status.success() {
                any_failure = true;
              }
            }
            Err(CommandExecError::Timeout {
              after,
              stdout,
              stderr,
            }) => {
              let stdout = String::from_utf8_lossy(&stdout).to_string();
              if !stdout.is_empty() {
                result.output.push(stdout);
              }
              let stderr = String::from_utf8_lossy(&stderr).to_string();
              if !stderr.is_empty() {
                result.output.push(stderr);
              }
              result.output.push(format!(
                "Command timed out after {}s: {}",
                after.as_secs(),
                cmd_str
              ));
              timed_out = true;
              any_failure = true;
              break;
            }
            Err(CommandExecError::Spawn(e) | CommandExecError::Io(e)) => {
              result.output.push(format!("Failed to execute: {}", e));
              any_failure = true;
            }
          }
        }

        if timed_out {
          result.status = "Timeout".to_string();
          result.error = Some("Step timeout".to_string());
        } else if !any_failure {
          result = result.success();
        } else {
          result = result.failed("Step execution failed");
        }
        result.duration = start.elapsed();

        let mut results = results_clone.lock().unwrap();
        results.push(result);
      });

      handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
      let _ = handle.join();
    }

    Arc::try_unwrap(results).unwrap().into_inner().unwrap()
  }

  /// Check if a previous action matches the specified criteria
  /// Format: "action_type:outcome" e.g., "scan:success" or "exploit:failed"
  fn matches_previous_action(&self, criteria: &str) -> bool {
    let parts: Vec<&str> = criteria.split(':').collect();
    if parts.len() != 2 {
      return false;
    }

    let action_type = match parts[0].to_lowercase().as_str() {
      "scan" => ActionType::Scan,
      "enumerate" => ActionType::Enumerate,
      "fingerprint" => ActionType::Fingerprint,
      "audit" => ActionType::Audit,
      "exploit" => ActionType::Exploit,
      "report" => ActionType::Report,
      "resolve" => ActionType::Resolve,
      "request" => ActionType::Request,
      "inspect" => ActionType::Inspect,
      "lookup" => ActionType::Lookup,
      _ => return false,
    };

    let outcome_matches = |a: &ActionRecord| -> bool {
      match parts[1].to_lowercase().as_str() {
        "success" => matches!(a.outcome, ActionOutcome::Success),
        "failed" | "failure" => matches!(a.outcome, ActionOutcome::Failed { .. }),
        "timeout" => matches!(a.outcome, ActionOutcome::Timeout { .. }),
        "partial" => matches!(a.outcome, ActionOutcome::Partial { .. }),
        "skipped" => matches!(a.outcome, ActionOutcome::Skipped { .. }),
        "any" => true,
        _ => false,
      }
    };

    self
      .historical_actions
      .iter()
      .any(|a| a.action_type == action_type && outcome_matches(a))
  }

  /// Evaluate if a step condition is met
  fn evaluate_condition(
    &self,
    condition: &StepCondition,
    step_results: &[StepExecutionResult],
  ) -> bool {
    match condition {
      StepCondition::Always => true,
      StepCondition::OnSuccess(step_num) => step_results
        .iter()
        .any(|r| r.step_number == *step_num && r.success),
      StepCondition::OnFailure(step_num) => step_results
        .iter()
        .any(|r| r.step_number == *step_num && !r.success && !r.skipped),
      StepCondition::OnEvidence(evidence_type) => self.collected_evidence.contains(evidence_type),
      StepCondition::Custom(expr) => {
        // Custom expressions - for now, check if it matches a gathered variable
        // Format: "var_name == value" or just "var_name" (truthy check)
        // This is a simple implementation; could be extended with a proper expression parser
        expr.is_empty() || expr == "true"
      }
      // Historical action-based conditions
      StepCondition::OnPreviousAction(criteria) => self.matches_previous_action(criteria),
      StepCondition::IfNotScanned => !self.was_previously_scanned(),
      StepCondition::IfHasVulnerabilities => self.has_previous_vulnerabilities(),
    }
  }

  /// Record an action for a step
  fn record_step_action(
    &mut self,
    step: &PlaybookStep,
    context: &PlaybookContext,
    outcome: ActionOutcome,
    duration_ms: u64,
  ) {
    let source = ActionSource::playbook(self.run_id, step.number as u32);

    // Parse target - try IP first, then domain
    let target = if let Ok(ip) = context.target.parse::<IpAddr>() {
      Target::Host(ip)
    } else {
      Target::Domain(context.target.clone())
    };

    // Determine action type from step phase (MITRE ATT&CK phases)
    let action_type = match step.phase {
      crate::playbooks::PlaybookPhase::Recon => ActionType::Enumerate,
      crate::playbooks::PlaybookPhase::Discovery => ActionType::Scan,
      crate::playbooks::PlaybookPhase::InitialAccess => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::Execution => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::Persistence => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::PrivilegeEscalation => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::DefenseEvasion => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::CredentialAccess => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::LateralMovement => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::Collection => ActionType::Enumerate,
      crate::playbooks::PlaybookPhase::C2 => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::Exfiltration => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::Impact => ActionType::Exploit,
      crate::playbooks::PlaybookPhase::Cleanup => ActionType::Report,
    };

    let record = ActionRecord::new(
      source,
      target,
      action_type,
      RecordPayload::Custom(step_action_payload(step, context, duration_ms)),
      outcome,
    );

    self.actions.push(record);
  }

  /// Execute a playbook with action recording
  pub fn execute(
    &mut self,
    playbook: &Playbook,
    context: &mut PlaybookContext,
  ) -> PlaybookExecutionResult {
    let start_time = Instant::now();
    let mut result = PlaybookExecutionResult::new(playbook, &context.target);

    // 0. Load historical actions for this target (for conditional step execution)
    if let Err(e) = self.load_historical_actions(&context.target) {
      // Non-fatal: log warning but continue
      eprintln!("Warning: could not load historical actions: {}", e);
    }

    // 1. Check Preconditions
    for condition in &playbook.preconditions {
      if condition.required {
        if let Some(check_id) = &condition.check {
          // Try to run script check
          if let Some(script) = builtin::get_script(check_id) {
            let script_ctx = ScriptContext::new(&context.target, 0); // Port 0 as placeholder
            let script_res = ScriptRunner::run(script.as_ref(), &script_ctx);
            if !script_res.success {
              result.success = false;
              result.summary = format!("Precondition failed: {}", condition.description);
              result.finalize(start_time.elapsed());
              return result;
            }
          }
        }
      }
    }

    // 2. Execute Steps
    for step in &playbook.steps {
      if context.dry_run {
        // In dry run, we just record that we would have run it
        let mut res = StepExecutionResult::new(step);
        res.status = "Dry Run".to_string();
        res.success = true;

        // Record skipped action
        self.record_step_action(
          step,
          context,
          ActionOutcome::Skipped {
            reason: "dry_run".to_string(),
          },
          0,
        );

        result.add_step_result(res);
        continue;
      }

      // Check dependencies
      if !step.depends_on.is_empty() {
        let all_deps_met = step.depends_on.iter().all(|dep_num| {
          result
            .step_results
            .iter()
            .any(|r| r.step_number == *dep_num && r.success)
        });

        if !all_deps_met {
          let mut res = StepExecutionResult::new(step);
          res = res.skipped("Dependencies not met");

          // Record skipped action
          self.record_step_action(
            step,
            context,
            ActionOutcome::Skipped {
              reason: "dependencies_not_met".to_string(),
            },
            0,
          );

          result.add_step_result(res);
          continue;
        }
      }

      // Check step condition
      if !self.evaluate_condition(&step.condition, &result.step_results) {
        let mut res = StepExecutionResult::new(step);
        res = res.skipped("Condition not met");

        // Record skipped action
        self.record_step_action(
          step,
          context,
          ActionOutcome::Skipped {
            reason: "condition_not_met".to_string(),
          },
          0,
        );

        result.add_step_result(res);
        continue;
      }

      let step_start = Instant::now();
      let step_res = self.execute_step(step, context);
      let step_duration_ms = step_start.elapsed().as_millis() as u64;
      let success = step_res.success;

      // Record action with outcome
      let outcome = if step_res.status == "Timeout" {
        ActionOutcome::Timeout {
          after_ms: step_duration_ms,
        }
      } else if success {
        ActionOutcome::Success
      } else {
        ActionOutcome::Failed {
          error: step_res.status.clone(),
        }
      };
      self.record_step_action(step, context, outcome, step_duration_ms);

      // Collect evidence type if step succeeded and has evidence_type
      if success {
        if let Some(evidence_type) = step.evidence_type {
          self.collected_evidence.insert(evidence_type);
        }
      }

      result.add_step_result(step_res);

      if !success {
        match step.on_failure {
          StepFailureAction::Abort => break,
          StepFailureAction::AskUser => {
            // In non-interactive mode, this is equivalent to abort
            break;
          }
          // Continue and SkipDependents handled by loop and dependency check
          _ => {}
        }
      }
    }

    result.finalize(start_time.elapsed());

    // 3. Evaluate Assertions
    if !playbook.assertions.is_empty() {
      let mut critical_failed = false;

      for assertion in &playbook.assertions {
        let assertion_result = self.evaluate_assertion(assertion, &result, context);

        if !assertion_result.passed && assertion.critical {
          critical_failed = true;
        }

        result.assertion_results.push(assertion_result);
      }

      // Critical assertion failure overrides success
      if critical_failed {
        result.success = false;
        result.summary = format!("{} (CRITICAL ASSERTION FAILED)", result.summary);
      }
    }

    // Determine next playbook
    if result.success {
      if let Some(next) = &playbook.on_success {
        result.next_playbook = Some(next.clone());
      }
    } else {
      if let Some(next) = &playbook.on_failure {
        result.next_playbook = Some(next.clone());
      }
    }

    result
  }

  fn execute_step(
    &self,
    step: &PlaybookStep,
    context: &mut PlaybookContext,
  ) -> StepExecutionResult {
    let start = Instant::now();
    let mut result = StepExecutionResult::new(step);
    let mut any_failure = false;
    let mut timed_out = false;
    let step_deadline = start + context.step_timeout;

    // 1. Execute Scripts
    for script_id in &step.scripts {
      if let Some(script) = builtin::get_script(script_id) {
        // Determine port from context or args
        let port = context
          .get_arg("port")
          .and_then(|p| p.parse().ok())
          .unwrap_or(0); // Default/placeholder

        let mut script_ctx = ScriptContext::new(&context.target, port);
        // Pass args
        for (k, v) in &context.args {
          script_ctx.set_arg(k, v);
        }

        let script_res = ScriptRunner::run(script.as_ref(), &script_ctx);

        result.findings.extend(script_res.findings);

        // Merge extracts into global context and result
        for (k, v) in script_res.extracted {
          context.store_data(&k, &v);
          result.extracted_data.insert(k, v);
        }

        if !script_res.success {
          result
            .output
            .push(format!("Script {} failed or found nothing", script_id));
        } else {
          result
            .output
            .push(format!("Script {} completed successfully", script_id));
        }
      } else {
        result
          .output
          .push(format!("Script {} not found", script_id));
        // Script not found is not necessarily a failure of execution if optional,
        // but for now let's log it.
      }
    }

    // 2. Execute Commands
    for cmd_tmpl in &step.commands {
      let cmd_str = self.template_engine.render(cmd_tmpl, context);

      let parts = match Self::split_command_line(&cmd_str) {
        Ok(parts) => parts,
        Err(e) => {
          result
            .output
            .push(format!("Command parse error: {} ({})", cmd_str, e));
          any_failure = true;
          continue;
        }
      };

      if parts.is_empty() {
        continue;
      }

      let cmd = parts[0].clone();
      let args = parts[1..].to_vec();
      let remaining = step_deadline.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        result
          .output
          .push(format!("Step timed out before: {}", cmd_str));
        timed_out = true;
        any_failure = true;
        break;
      }

      match Self::run_command_with_timeout(&cmd, &args, remaining) {
        Ok(output) => {
          let stdout = String::from_utf8_lossy(&output.stdout).to_string();
          let stderr = String::from_utf8_lossy(&output.stderr).to_string();

          if !stdout.is_empty() {
            result.output.push(stdout);
          }

          if output.status.success() {
            // Success already reflected by lack of failure.
          } else {
            result
              .output
              .push(format!("Command failed: {}\nStderr: {}", cmd_str, stderr));
            any_failure = true;
          }
        }
        Err(CommandExecError::Timeout {
          after,
          stdout,
          stderr,
        }) => {
          let stdout = String::from_utf8_lossy(&stdout).to_string();
          if !stdout.is_empty() {
            result.output.push(stdout);
          }
          let stderr = String::from_utf8_lossy(&stderr).to_string();
          if !stderr.is_empty() {
            result.output.push(stderr);
          }
          result.output.push(format!(
            "Command timed out after {}s: {}",
            after.as_secs(),
            cmd_str
          ));
          timed_out = true;
          any_failure = true;
          break;
        }
        Err(CommandExecError::Spawn(e) | CommandExecError::Io(e)) => {
          result
            .output
            .push(format!("Failed to execute command '{}': {}", cmd_str, e));
          any_failure = true;
        }
      }
    }

    if timed_out {
      result.success = false;
      result.status = "Timeout".to_string();
      result.error = Some("Step timeout".to_string());
      result.duration = start.elapsed();
      return result;
    }

    // 3. Determine Step Success
    // If success criteria are defined, they override implicit success
    if !step.success_criteria.is_empty() {
      let rendered: Vec<String> = step
        .success_criteria
        .iter()
        .map(|criteria| self.template_engine.render(criteria, context))
        .collect();
      let (criteria_met, missing) = Self::evaluate_success_criteria(&rendered, &result);

      if any_failure {
        result = result.failed("Step execution failed");
      } else if criteria_met {
        result = result.success();
      } else {
        let message = if missing.is_empty() {
          "Success criteria not met".to_string()
        } else {
          format!("Success criteria not met: {}", missing.join(", "))
        };
        result = result.failed(&message);
      }
    } else {
      // Implicit success: no hard failure, even if nothing ran.
      if !any_failure {
        result = result.success();
      } else {
        result = result.failed("Step execution failed");
      }
    }

    result.duration = start.elapsed();
    result
  }

  fn evaluate_success_criteria(
    criteria: &[String],
    result: &StepExecutionResult,
  ) -> (bool, Vec<String>) {
    let mut corpus = String::new();

    for output in &result.output {
      corpus.push_str(output);
      corpus.push('\n');
    }

    for finding in &result.findings {
      corpus.push_str(&finding.title);
      corpus.push('\n');
      corpus.push_str(&finding.description);
      corpus.push('\n');
      for evidence in &finding.evidence {
        corpus.push_str(evidence);
        corpus.push('\n');
      }
    }

    for (key, value) in &result.extracted_data {
      corpus.push_str(key);
      corpus.push('=');
      corpus.push_str(value);
      corpus.push('\n');
    }

    let corpus = corpus.to_lowercase();
    let mut missing = Vec::new();

    for criteria in criteria {
      let needle = criteria.to_lowercase();
      if !needle.is_empty() && !corpus.contains(&needle) {
        missing.push(criteria.clone());
      }
    }

    (missing.is_empty(), missing)
  }

  fn split_command_line(input: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = input.chars();

    while let Some(ch) = chars.next() {
      match ch {
        '\'' if !in_double => {
          in_single = !in_single;
        }
        '"' if !in_single => {
          in_double = !in_double;
        }
        '\\' if !in_single => {
          if let Some(next) = chars.next() {
            current.push(next);
          } else {
            current.push('\\');
          }
        }
        c if c.is_whitespace() && !in_single && !in_double => {
          if !current.is_empty() {
            args.push(current.clone());
            current.clear();
          }
        }
        _ => current.push(ch),
      }
    }

    if in_single || in_double {
      return Err("Unterminated quote".to_string());
    }

    if !current.is_empty() {
      args.push(current);
    }

    Ok(args)
  }

  fn spawn_reader<R: Read + Send + 'static>(mut reader: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
      let mut buf = Vec::new();
      let _ = reader.read_to_end(&mut buf);
      buf
    })
  }

  fn run_command_with_timeout(
    cmd: &str,
    args: &[String],
    timeout: Duration,
  ) -> Result<Output, CommandExecError> {
    let mut child = Command::new(cmd)
      .args(args)
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .map_err(|e| CommandExecError::Spawn(format!("{}: {}", cmd, e)))?;

    let stdout = child
      .stdout
      .take()
      .ok_or_else(|| CommandExecError::Io("Failed to capture stdout".to_string()))?;
    let stderr = child
      .stderr
      .take()
      .ok_or_else(|| CommandExecError::Io("Failed to capture stderr".to_string()))?;
    let stdout_handle = Self::spawn_reader(stdout);
    let stderr_handle = Self::spawn_reader(stderr);

    let start = Instant::now();
    loop {
      match child.try_wait() {
        Ok(Some(status)) => {
          let stdout = stdout_handle.join().unwrap_or_default();
          let stderr = stderr_handle.join().unwrap_or_default();
          return Ok(Output {
            status,
            stdout,
            stderr,
          });
        }
        Ok(None) => {}
        Err(e) => {
          return Err(CommandExecError::Io(format!("Command wait failed: {}", e)));
        }
      }

      if start.elapsed() >= timeout {
        let _ = child.kill();
        let _ = child.wait();
        let stdout = stdout_handle.join().unwrap_or_default();
        let stderr = stderr_handle.join().unwrap_or_default();
        return Err(CommandExecError::Timeout {
          after: timeout,
          stdout,
          stderr,
        });
      }

      thread::sleep(Duration::from_millis(20));
    }
  }

  /// Persist recorded actions to storage
  /// Returns the number of actions persisted
  pub fn persist_actions(&self) -> Result<usize, String> {
    if !self.action_config.should_store() || self.actions.is_empty() {
      return Ok(0);
    }

    use crate::storage::client::ActionRecorder;
    use crate::storage::service::StorageService;

    let path = StorageService::db_path("_actions");
    let mut recorder =
      ActionRecorder::with_db_path("playbook-executor", self.action_config.clone(), path)?;

    for action in &self.actions {
      recorder.record_raw(action.clone())?;
    }

    recorder.commit()
  }
}

fn step_action_payload(
  step: &PlaybookStep,
  context: &PlaybookContext,
  duration_ms: u64,
) -> Vec<u8> {
  let payload = json!({
    "step_number": step.number,
    "step_name": step.name,
    "phase": step.phase.as_str(),
    "description": step.description,
    "commands": step.commands,
    "command_count": step.commands.len(),
    "mitre_technique": step.mitre_technique,
    "parallel_group": step.parallel_group,
    "target": context.target,
    "additional_targets": context.additional_targets,
    "dry_run": context.dry_run,
    "allow_intrusive": context.allow_intrusive,
    "duration_ms": duration_ms,
    "session_id": context.session_id,
  });

  serde_json::to_vec(&payload).unwrap_or_default()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::playbooks::{Playbook, PlaybookPhase, PlaybookStep};

  #[test]
  fn test_split_command_line_quotes() {
    let args = PlaybookExecutor::split_command_line(
      "rb web asset get \"https://example.com/path with space\" --flag",
    )
    .expect("parse failed");
    assert_eq!(
      args,
      vec![
        "rb",
        "web",
        "asset",
        "get",
        "https://example.com/path with space",
        "--flag",
      ]
    );
  }

  #[test]
  fn test_split_command_line_single_quotes() {
    let args = PlaybookExecutor::split_command_line("echo 'hello world'").expect("parse failed");
    assert_eq!(args, vec!["echo", "hello world"]);
  }

  #[test]
  fn test_split_command_line_unterminated() {
    assert!(PlaybookExecutor::split_command_line("echo \"unterminated").is_err());
  }

  #[test]
  fn test_executor_variable_substitution() {
    let mut context = PlaybookContext::new("127.0.0.1");
    context.set_arg("port", "8080");

    let engine = TemplateEngine::new();
    let cmd = "nc {{ target }} {{ port }}";
    let rendered = engine.render(cmd, &context);

    assert_eq!(rendered, "nc 127.0.0.1 8080");
  }

  #[test]
  fn test_executor_dry_run() {
    let mut playbook = Playbook::new("test", "Test");
    playbook
      .steps
      .push(PlaybookStep::new(1, PlaybookPhase::Recon, "Test Step").with_command("echo hello"));

    let mut context = PlaybookContext::new("localhost");
    context.dry_run = true;

    let mut executor = PlaybookExecutor::new();
    let result = executor.execute(&playbook, &mut context);

    assert!(result.success);
    assert_eq!(result.step_results.len(), 1);
    assert_eq!(result.step_results[0].status, "Dry Run");

    // Verify action was recorded
    assert_eq!(executor.actions().len(), 1);
    assert!(matches!(
      executor.actions()[0].outcome,
      ActionOutcome::Skipped { .. }
    ));
  }

  #[test]
  fn test_executor_records_actions() {
    let mut playbook = Playbook::new("test", "Test");
    playbook
      .steps
      .push(PlaybookStep::new(1, PlaybookPhase::Discovery, "Scan Step").with_command("echo scan"));
    playbook
      .steps
      .push(PlaybookStep::new(2, PlaybookPhase::Collection, "Enum Step").with_command("echo enum"));

    let mut context = PlaybookContext::new("192.168.1.1");
    context.dry_run = true;

    let mut executor = PlaybookExecutor::new();
    let _result = executor.execute(&playbook, &mut context);

    // Both steps should have actions recorded
    assert_eq!(executor.actions().len(), 2);

    // Verify run ID is consistent
    let run_id = executor.run_id();
    for action in executor.actions() {
      if let ActionSource::Playbook { id, .. } = &action.source {
        assert_eq!(*id, run_id);
      }
    }

    match &executor.actions()[0].payload {
      RecordPayload::Custom(data) => {
        let payload: crate::serde_json::Value =
          crate::serde_json::from_slice(data).expect("step action payload should be valid json");
        assert_eq!(payload["step_name"], json!("Scan Step"));
        assert_eq!(payload["phase"], json!("discovery"));
        assert_eq!(payload["dry_run"], json!(true));
      }
      other => panic!("expected custom payload, got {:?}", other),
    }
  }

  #[test]
  fn test_executor_with_config() {
    let config = ActionConfig::with_tracing();
    let executor = PlaybookExecutor::with_config(config);

    assert!(executor.action_config.should_trace());
    assert!(executor.action_config.should_store());
  }

  #[test]
  fn test_assertion_evaluation_equals() {
    use crate::playbooks::Assertion;

    let mut playbook = Playbook::new("test", "Test");
    playbook = playbook
      .add_assertion(Assertion::new("Check steps completed", "steps_completed").equals("0"));

    let mut context = PlaybookContext::new("localhost");
    context.dry_run = true;

    let mut executor = PlaybookExecutor::new();
    let result = executor.execute(&playbook, &mut context);

    // With no steps, steps_completed should be 0
    assert_eq!(result.assertion_results.len(), 1);
    assert!(result.assertion_results[0].passed);
  }

  #[test]
  fn test_assertion_evaluation_greater_than() {
    use crate::playbooks::Assertion;

    let mut playbook = Playbook::new("test", "Test");
    playbook
      .steps
      .push(PlaybookStep::new(1, PlaybookPhase::Recon, "Step 1").with_command("echo test"));
    playbook = playbook
      .add_assertion(Assertion::new("At least one step", "steps_completed").greater_than("0"));

    let mut context = PlaybookContext::new("localhost");
    context.dry_run = true;

    let mut executor = PlaybookExecutor::new();
    let result = executor.execute(&playbook, &mut context);

    // In dry run, steps are marked as completed
    assert_eq!(result.assertion_results.len(), 1);
    assert!(result.assertion_results[0].passed);
  }

  #[test]
  fn test_critical_assertion_failure() {
    use crate::playbooks::Assertion;

    let mut playbook = Playbook::new("test", "Test");
    playbook = playbook.add_assertion(
      Assertion::new("Must have findings", "findings.count")
        .greater_than("100")
        .critical(),
    );

    let mut context = PlaybookContext::new("localhost");
    context.dry_run = true;

    let mut executor = PlaybookExecutor::new();
    let result = executor.execute(&playbook, &mut context);

    // Critical assertion should fail and mark playbook as failed
    assert!(!result.success);
    assert!(result.summary.contains("CRITICAL ASSERTION FAILED"));
  }

  #[test]
  fn test_assertion_with_context_data() {
    use crate::playbooks::Assertion;

    let mut playbook = Playbook::new("test", "Test");
    playbook =
      playbook.add_assertion(Assertion::new("Check target arg", "arg.port").equals("8080"));

    let mut context = PlaybookContext::new("localhost");
    context.set_arg("port", "8080");
    context.dry_run = true;

    let mut executor = PlaybookExecutor::new();
    let result = executor.execute(&playbook, &mut context);

    assert_eq!(result.assertion_results.len(), 1);
    assert!(result.assertion_results[0].passed);
  }

  #[test]
  fn test_parallel_group_field() {
    // Test that parallel_group is set correctly on steps
    let step = PlaybookStep::new(1, PlaybookPhase::Recon, "Step 1").parallel(1);

    assert_eq!(step.parallel_group, Some(1));
  }
}
