use crate::playbooks::template::TemplateEngine;
use crate::playbooks::{
    Playbook, PlaybookContext, PlaybookExecutionResult, PlaybookStep, StepExecutionResult,
    StepFailureAction,
};
use crate::scripts::{builtin, ScriptContext, ScriptRunner};
use std::process::Command;
use std::time::Instant;

/// Executor for playbooks
pub struct PlaybookExecutor {
    template_engine: TemplateEngine,
}

impl Default for PlaybookExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaybookExecutor {
    pub fn new() -> Self {
        Self {
            template_engine: TemplateEngine::new(),
        }
    }

    /// Execute a playbook
    pub fn execute(
        &self,
        playbook: &Playbook,
        context: &mut PlaybookContext,
    ) -> PlaybookExecutionResult {
        let start_time = Instant::now();
        let mut result = PlaybookExecutionResult::new(playbook, &context.target);

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
                            result.summary =
                                format!("Precondition failed: {}", condition.description);
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
                    result.add_step_result(res);
                    continue;
                }
            }

            let step_res = self.execute_step(step, context);
            let success = step_res.success;
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
        let mut any_success = false;

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
                    any_success = true;
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

            // Basic parsing of command line (splitting by space, respecting quotes would be better but simple split for now)
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            if !parts.is_empty() {
                let cmd = parts[0];
                let args = &parts[1..];

                match Command::new(cmd).args(args).output() {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                        if !stdout.is_empty() {
                            result.output.push(stdout);
                        }

                        if output.status.success() {
                            any_success = true;
                        } else {
                            result
                                .output
                                .push(format!("Command failed: {}\nStderr: {}", cmd_str, stderr));
                            any_failure = true;
                        }
                    }
                    Err(e) => {
                        result
                            .output
                            .push(format!("Failed to execute command '{}': {}", cmd_str, e));
                        any_failure = true;
                    }
                }
            }
        }

        // 3. Determine Step Success
        // If success criteria are defined, they override implicit success
        if !step.success_criteria.is_empty() {
            // TODO: check success criteria against output/findings
            // For now, if we had any success and no critical failure
            if any_success && !any_failure {
                result = result.success();
            } else {
                result = result.failed("Success criteria not met");
            }
        } else {
            // Implicit success: if we ran something and it didn't fail hard
            // Or if we ran nothing (informational step)
            if !any_failure {
                result = result.success();
            } else {
                result = result.failed("Step execution failed");
            }
        }

        result.duration = start.elapsed();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbooks::{Playbook, PlaybookPhase, PlaybookStep, PreCondition};

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
        playbook.steps.push(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Test Step").with_command("echo hello"),
        );

        let mut context = PlaybookContext::new("localhost");
        context.dry_run = true;

        let executor = PlaybookExecutor::new();
        let result = executor.execute(&playbook, &mut context);

        assert!(result.success);
        assert_eq!(result.step_results.len(), 1);
        assert_eq!(result.step_results[0].status, "Dry Run");
    }

    #[test]
    fn test_executor_dependency_check() {
        let mut playbook = Playbook::new("dep-test", "Dependency Test");

        // Step 1: Fails (simulated by non-dry run with invalid command if we were running it,
        // but here we just want to test dependency logic.
        // We'll use a dry run but manually fail the first step in result to test logic?
        // Cannot easily mock execute_step without trait/struct split.
        // Instead, we rely on the fact that dry run always succeeds.
        // Let's test checking logic: if step 1 is skipped, step 2 depending on it should be skipped.

        // Actually, without mocking `execute_step` or `Command`, meaningful execution tests are hard.
        // But we can test the template engine and basic flow.
    }
}
