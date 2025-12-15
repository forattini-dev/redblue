use redblue::playbooks::{
    Playbook, PlaybookContext, PlaybookExecutor, PlaybookPhase, PlaybookStep, RiskLevel,
    StepFailureAction,
};

#[test]
fn test_playbook_execution_simple() {
    // Create a simple playbook
    let mut playbook = Playbook::new("test-simple", "Simple Test");
    playbook.metadata.objective = "Test basic execution".to_string();
    playbook.metadata.risk_level = RiskLevel::Low;

    // Add a step that echoes something
    playbook.steps.push(
        PlaybookStep::new(1, PlaybookPhase::Recon, "Echo Test")
            .with_description("Echo a string")
            .with_command("echo 'Hello RedBlue'"),
    );

    // Create context
    let mut context = PlaybookContext::new("127.0.0.1");
    // Enable dry run to avoid actual execution if we want, but echo is safe.
    // However, RedBlue's executor runs commands. Let's run it for real since it's just echo.

    let executor = PlaybookExecutor::new();
    let result = executor.execute(&playbook, &mut context);

    assert!(result.success);
    assert_eq!(result.steps_completed, 1);
    assert_eq!(result.step_results.len(), 1);

    let step_res = &result.step_results[0];
    assert_eq!(step_res.step_name, "Echo Test");
    // Output capture depends on Command execution.
    // If output capturing works:
    assert!(step_res.output.iter().any(|s| s.contains("Hello RedBlue")));
}

#[test]
fn test_playbook_variables() {
    let mut playbook = Playbook::new("test-vars", "Variable Test");
    playbook.steps.push(
        PlaybookStep::new(1, PlaybookPhase::Recon, "Var Echo")
            .with_command("echo 'Target: {{ target }}, Custom: {{ custom }}'"),
    );

    let mut context = PlaybookContext::new("127.0.0.1");
    context.set_arg("custom", "MyValue");

    let executor = PlaybookExecutor::new();
    let result = executor.execute(&playbook, &mut context);

    assert!(result.success);
    let output = result.step_results[0].output.join("\n");
    assert!(output.contains("Target: 127.0.0.1"));
    assert!(output.contains("Custom: MyValue"));
}

#[test]
fn test_playbook_chaining() {
    // Playbook 1
    let mut pb1 = Playbook::new("pb1", "Playbook 1");
    pb1.steps
        .push(PlaybookStep::new(1, PlaybookPhase::Recon, "Step 1").with_command("echo 1"));
    pb1 = pb1.with_next_playbook("pb2");

    // Context
    let mut context = PlaybookContext::new("localhost");
    let executor = PlaybookExecutor::new();

    let result = executor.execute(&pb1, &mut context);

    assert!(result.success);
    assert_eq!(result.next_playbook, Some("pb2".to_string()));
}

#[test]
fn test_playbook_failure_handling() {
    // Playbook with failing step
    let mut pb = Playbook::new("fail-test", "Failure Test");
    pb.steps.push(
        PlaybookStep::new(1, PlaybookPhase::Recon, "Fail Step")
            .with_command("false") // Returns exit code 1
            .on_fail(StepFailureAction::Abort),
    );
    pb.steps.push(
        PlaybookStep::new(2, PlaybookPhase::Recon, "Should Not Run").with_command("echo 'skipped'"),
    );

    let mut context = PlaybookContext::new("localhost");
    let executor = PlaybookExecutor::new();

    let result = executor.execute(&pb, &mut context);

    assert!(!result.success);
    assert_eq!(result.steps_failed, 1);
    // Step 2 should not be in results or marked skipped?
    // Executor loop breaks on Abort.
    assert_eq!(result.step_results.len(), 1);
}
