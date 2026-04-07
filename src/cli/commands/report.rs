//! Report generation CLI commands
//!
//! Generates pentest reports from loot data and graph insights.
//!
//! Commands:
//! - rb report generate <target> [--format md|json|html] [--output file]
//! - rb report preview <target>
//! - rb report stats

use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::report::pentest::{
  PentestReport, PentestReportBuild, PentestReportStatsBuild, ReportDataSource,
};
use crate::serde_json::Value;

use super::{Command, Flag, Route};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// ReportCommand - rb report *
// ============================================================================

pub struct ReportCommand;

impl Command for ReportCommand {
  fn domain(&self) -> &str {
    "report"
  }

  fn resource(&self) -> &str {
    "pentest"
  }

  fn description(&self) -> &str {
    "Generate pentest reports from loot and graph data"
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
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "generate",
        summary: "Generate a full report",
        usage: "rb report pentest generate 192.168.1.0/24",
      },
      Route {
        verb: "preview",
        summary: "Preview report summary",
        usage: "rb report pentest preview example.com",
      },
      Route {
        verb: "stats",
        summary: "Show report data statistics",
        usage: "rb report pentest stats",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("format", "Output format: md, json, html")
        .with_short('f')
        .with_default("md"),
      Flag::new("output", "Output file path").with_short('o'),
      Flag::new("methodology", "Methodology used (e.g., PTES, OWASP)").with_short('m'),
      Flag::new("scope", "Comma-separated scope items"),
      Flag::new(
        "project",
        "Project/target identifier (compat alias for positional target)",
      ),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Generate markdown report",
        "rb report pentest generate 192.168.1.0/24",
      ),
      (
        "Generate JSON report",
        "rb report pentest generate example.com --format json",
      ),
      (
        "Generate with output file",
        "rb report pentest generate 10.0.0.0/8 -o pentest.md",
      ),
      ("Preview report", "rb report pentest preview 192.168.1.1"),
      ("Show statistics", "rb report pentest stats"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("preview");

    match verb {
      "generate" => execute_generate(ctx),
      "preview" => execute_preview(ctx),
      "stats" => execute_stats(ctx),
      _ => Err(format!(
        "Unknown verb '{}'. Use: generate, preview, stats",
        verb
      )),
    }
  }
}

fn execute_generate(ctx: &CliContext) -> Result<(), String> {
  let target = resolve_report_target(ctx, "Usage: rb report pentest generate <target>")?;

  let format = ctx.flags.get("format").map(|s| s.as_str()).unwrap_or("md");
  let methodology = ctx.flags.get("methodology").map(|s| s.as_str());
  let scope_str = ctx.flags.get("scope").map(|s| s.as_str());
  let build = build_report_for_target(&target, methodology, scope_str);
  let report = &build.report;
  let surface = report.report_surface();
  let is_empty_source = matches!(build.data_source, ReportDataSource::Empty);

  // Generate output
  let content = match format {
    "json" => build.report.to_json(),
    "html" => build.report.to_html(),
    "md" | "markdown" => build.report.to_markdown(),
    _ => return Err(format!("Unknown format '{}'. Use: md, json, html", format)),
  };

  // Determine output path
  let output_path = if let Some(path) = ctx.flags.get("output") {
    PathBuf::from(path)
  } else {
    let ext = match format {
      "json" => "json",
      "html" => "html",
      _ => "md",
    };
    let timestamp = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs();
    PathBuf::from(format!(
      "report-{}-{}.{}",
      sanitize_filename(&target),
      timestamp,
      ext
    ))
  };

  // Write report
  fs::write(&output_path, &content).map_err(|e| format!("Failed to write report: {}", e))?;

  let payload = generate_payload(&build, &target, format, &output_path);
  if render::render_machine_output(ctx, "rb report pentest generate", &payload)? {
    return Ok(());
  }

  if should_emit_empty_source_warning(ctx, is_empty_source) {
    Output::warning(&format!(
      "No report data found for target '{}'. Generating an empty report shell.",
      target
    ));
  }

  Output::success(&format!("Report generated: {}", output_path.display()));
  println!();
  println!("  Format:    {}", format.to_uppercase());
  println!("  Source:    {}", build.data_source.as_str());
  println!("  Findings:  {}", surface.findings);
  println!("  Recs:      {}", surface.recommendations);
  println!("  Hosts:     {}", surface.hosts);
  println!("  Insights:  {}", surface.insights);
  println!("  Paths:     {}", surface.paths);
  println!("  Phases:    {}", surface.phases);
  println!("  Sections:  {}", surface.section_count);
  println!("  Loot:      {}", build.loot_count);
  println!("  Actions:   {}", build.action_count);

  Ok(())
}

fn execute_preview(ctx: &CliContext) -> Result<(), String> {
  let target = resolve_report_target(ctx, "Usage: rb report pentest preview <target>")?;

  let build = build_report_for_target(&target, None, None);
  let report = &build.report;
  let surface = report.report_surface();
  let preview = report.preview_surface();
  let payload = preview_payload(&build, &target);

  if render::render_machine_output(ctx, "rb report pentest preview", &payload)? {
    return Ok(());
  }

  if matches!(build.data_source, ReportDataSource::Empty) {
    Output::info("No report data found. Add findings or execute playbooks first.");
    return Ok(());
  }

  Output::header(&format!("Report Preview: {}", target));
  println!();
  Output::item("Source", build.data_source.as_str());
  Output::item("Loot records", &build.loot_count.to_string());
  Output::item("Action records", &build.action_count.to_string());
  Output::item("Attack paths", &surface.paths.to_string());
  Output::item("Execution phases", &surface.phases.to_string());
  Output::item("Hosts", &surface.hosts.to_string());
  Output::item("Sections", &surface.section_count.to_string());
  println!();

  // Severity summary
  println!("  \x1b[1mSeverity Summary\x1b[0m");
  println!("  ────────────────────────────────────────");

  let critical = preview
    .severity_summary
    .get(&crate::modules::common::Severity::Critical)
    .unwrap_or(&0);
  let high = preview
    .severity_summary
    .get(&crate::modules::common::Severity::High)
    .unwrap_or(&0);
  let medium = preview
    .severity_summary
    .get(&crate::modules::common::Severity::Medium)
    .unwrap_or(&0);
  let low = preview
    .severity_summary
    .get(&crate::modules::common::Severity::Low)
    .unwrap_or(&0);
  let info = preview
    .severity_summary
    .get(&crate::modules::common::Severity::Info)
    .unwrap_or(&0);

  if *critical > 0 {
    println!("  \x1b[31m●\x1b[0m Critical:  {}", critical);
  }
  if *high > 0 {
    println!("  \x1b[33m●\x1b[0m High:      {}", high);
  }
  if *medium > 0 {
    println!("  \x1b[93m●\x1b[0m Medium:    {}", medium);
  }
  if *low > 0 {
    println!("  \x1b[32m●\x1b[0m Low:       {}", low);
  }
  if *info > 0 {
    println!("  \x1b[36m●\x1b[0m Info:      {}", info);
  }
  println!();

  // Top findings
  println!("  \x1b[1mTop Findings\x1b[0m");
  println!("  ────────────────────────────────────────");

  for finding in preview.top_findings.iter().take(5) {
    let severity_color = match finding.severity {
      crate::modules::common::Severity::Critical => "\x1b[31m",
      crate::modules::common::Severity::High => "\x1b[33m",
      crate::modules::common::Severity::Medium => "\x1b[93m",
      crate::modules::common::Severity::Low => "\x1b[32m",
      crate::modules::common::Severity::Info => "\x1b[36m",
    };

    println!(
      "  {}{:>8}\x1b[0m │ {}",
      severity_color,
      finding.severity.as_str(),
      truncate(&finding.title, 50)
    );
  }

  if report.base.findings.len() > preview.top_findings.len() {
    println!(
      "  ... and {} more findings",
      report.base.findings.len() - preview.top_findings.len()
    );
  }
  println!();

  // Insights
  if !report.graph_insights.is_empty() {
    println!("  \x1b[1mStrategic Insights\x1b[0m");
    println!("  ────────────────────────────────────────");

    for insight in &preview.top_insights {
      println!("  → {}", truncate(&insight, 60));
    }

    if surface.insights > 3 {
      println!("  ... and {} more insights", surface.insights - 3);
    }
    println!();
  }

  // Recommendations
  if !report.recommendations.is_empty() {
    println!("  \x1b[1mRecommendations\x1b[0m");
    println!("  ────────────────────────────────────────");

    for rec in &preview.top_recommendations {
      println!("  • {} ({})", rec.title, rec.priority.as_str());
      if !rec.affected_phases.is_empty() {
        println!("    phases: {}", rec.affected_phases.join(", "));
      }
      if !rec.affected_paths.is_empty() {
        println!("    paths: {}", rec.affected_paths.join(", "));
      }
    }
    println!();
  }

  let execution_narrative = surface.execution_narrative.clone();
  if !execution_narrative.is_empty() {
    println!("  \x1b[1mExecution Narrative\x1b[0m");
    println!("  ────────────────────────────────────────");

    for item in execution_narrative.iter().take(3) {
      println!("  → {}", truncate(item, 90));
    }
    println!();
  }

  println!(
    "  Use 'rb report pentest generate {}' to create the full report",
    target
  );

  Ok(())
}

fn execute_stats(ctx: &CliContext) -> Result<(), String> {
  let stats = PentestReport::build_stats_from_storage();

  let payload = stats_payload(&stats);
  if render::render_machine_output(ctx, "rb report pentest stats", &payload)? {
    return Ok(());
  }

  Output::header("Report Statistics");
  println!();

  println!("  \x1b[1mLoot Data\x1b[0m");
  println!("  ────────────────────────────────────────");
  println!("  Total entries:    {}", stats.loot.total);
  println!("  Vulnerabilities:  {}", stats.loot.vulnerabilities);
  println!("  Credentials:      {}", stats.loot.credentials);
  println!("  Services:         {}", stats.loot.services);
  println!("  Confirmed:        {}", stats.loot.confirmed);
  println!("  Potential:        {}", stats.loot.potential);
  println!();

  println!("  \x1b[1mAction Data\x1b[0m");
  println!("  ────────────────────────────────────────");
  println!("  Total actions:    {}", stats.actions.total);
  println!("  Exploit actions:  {}", stats.actions.exploit);
  println!("  Successful:       {}", stats.actions.successful);
  println!("  Unique targets:   {}", stats.actions.unique_targets);
  println!("  Observed phases:  {}", stats.actions.observed_phases);
  println!("  Attack paths:     {}", stats.actions.observed_paths);
  println!();

  println!("  \x1b[1mReport Surface\x1b[0m");
  println!("  ────────────────────────────────────────");
  println!("  Findings:         {}", stats.report.findings);
  println!("  Recommendations:  {}", stats.report.recommendations);
  println!("  Hosts:            {}", stats.report.hosts);
  println!("  Insights:         {}", stats.report.insights);
  println!("  Paths:            {}", stats.report.paths);
  println!("  Phases:           {}", stats.report.phases);
  println!("  Section count:    {}", stats.report.section_count);
  println!("  Phase names:      {}", stats.report.phase_names.len());
  println!("  Host targets:     {}", stats.report.host_targets.len());
  println!(
    "  Recommendation titles: {}",
    stats.report.recommendation_titles.len()
  );
  println!("  Sections:         {}", stats.report.sections.len());
  println!();

  if let Some(graph) = stats.graph_stats {
    println!("  \x1b[1mGraph Data\x1b[0m");
    println!("  ────────────────────────────────────────");
    println!("  Nodes:            {}", graph.total_nodes);
    println!("  Edges:            {}", graph.total_edges);
    println!("  Components:       {}", graph.connected_components);
    println!("  Max depth:        {}", graph.max_depth);
    println!();
  } else {
    println!("  \x1b[90mNo graph data available. Use 'rb loot graph rebuild' first.\x1b[0m");
    println!();
  }

  Ok(())
}

// Helper functions

fn build_report_for_target(
  target: &str,
  methodology: Option<&str>,
  scope_str: Option<&str>,
) -> PentestReportBuild {
  let mut build =
    PentestReport::build_from_storage(target).unwrap_or_else(|_| PentestReportBuild {
      report: PentestReport::new(format!("Penetration Test Report - {}", target), target),
      data_source: ReportDataSource::Empty,
      loot_count: 0,
      action_count: 0,
      graph_loaded: false,
    });

  if let Some(methodology) = methodology {
    build.report = build.report.with_methodology(methodology);
  }

  if let Some(scope) = scope_str {
    for item in scope.split(',') {
      let trimmed = item.trim();
      if !trimmed.is_empty() {
        build.report = build.report.add_scope(trimmed);
      }
    }
  }

  build
}

fn sanitize_filename(s: &str) -> String {
  s.chars()
    .map(|c| {
      if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
        c
      } else {
        '_'
      }
    })
    .collect()
}

fn should_emit_empty_source_warning(ctx: &CliContext, is_empty_source: bool) -> bool {
  is_empty_source && !ctx.wants_machine_output()
}

fn resolve_report_target(ctx: &CliContext, usage: &str) -> Result<String, String> {
  if let Some(parsed_target) = ctx.target.as_deref() {
    let trimmed = parsed_target.trim();
    if !trimmed.is_empty() {
      return Ok(trimmed.to_string());
    }
  }

  if let Some(arg_target) = ctx.args.first() {
    let trimmed = arg_target.trim();
    if !trimmed.is_empty() {
      return Ok(trimmed.to_string());
    }
  }

  if let Some(flag_target) = ctx.flags.get("project") {
    let trimmed = flag_target.trim();
    if !trimmed.is_empty() {
      return Ok(trimmed.to_string());
    }
  }

  Err(usage.to_string())
}

fn truncate(s: &str, max_len: usize) -> String {
  if s.len() <= max_len {
    s.to_string()
  } else {
    format!("{}...", &s[..max_len - 3])
  }
}

fn generate_payload(
  build: &PentestReportBuild,
  target: &str,
  format: &str,
  output_path: &PathBuf,
) -> Value {
  let surface = build.report.report_surface();
  let scope: Vec<_> = surface
    .scope
    .iter()
    .map(|item| Value::String(item.clone()))
    .collect();
  let out_of_scope: Vec<_> = surface
    .out_of_scope
    .iter()
    .map(|item| Value::String(item.clone()))
    .collect();
  let sections: Vec<_> = surface
    .sections
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let path_titles: Vec<_> = surface
    .path_titles
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let phase_names: Vec<_> = surface
    .phase_names
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let host_targets: Vec<_> = surface
    .host_targets
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let execution_narrative: Vec<_> = surface
    .execution_narrative
    .iter()
    .cloned()
    .map(Value::String)
    .collect();

  json!({
    "target": target,
    "format": format,
    "output_path": output_path.display().to_string(),
    "source": build.data_source.as_str(),
    "loot_records": build.loot_count,
    "action_records": build.action_count,
    "graph_loaded": build.graph_loaded,
    "methodology": surface.methodology,
    "scope": scope,
    "out_of_scope": out_of_scope,
    "findings": surface.findings,
    "recommendations": surface.recommendations,
    "hosts": surface.hosts,
    "insights": surface.insights,
    "paths": surface.paths,
    "phases": surface.phases,
    "path_titles": path_titles,
    "phase_names": phase_names,
    "host_targets": host_targets,
    "execution_narrative": execution_narrative,
    "section_count": surface.section_count,
    "sections": sections
  })
}

fn preview_payload(build: &PentestReportBuild, target: &str) -> Value {
  let report = &build.report;
  let surface = report.report_surface();
  let preview = report.preview_surface();

  let top_findings: Vec<_> = preview
    .top_findings
    .iter()
    .take(5)
    .map(|finding| {
      json!({
        "title": finding.title.clone(),
        "severity": finding.severity.as_str()
      })
    })
    .collect();
  let insights: Vec<_> = preview
    .top_insights
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let recommendations: Vec<_> = preview
    .top_recommendations
    .iter()
    .cloned()
    .map(|rec| {
      json!({
        "title": rec.title.clone(),
        "priority": rec.priority.as_str(),
        "affected_findings": rec.affected_findings.clone(),
        "affected_phases": rec.affected_phases.clone(),
        "affected_paths": rec.affected_paths.clone()
      })
    })
    .collect();
  let recommendation_titles: Vec<_> = surface
    .recommendation_titles
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let path_titles: Vec<_> = surface
    .path_titles
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let phase_names: Vec<_> = surface
    .phase_names
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let host_targets: Vec<_> = surface
    .host_targets
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let scope: Vec<_> = surface
    .scope
    .iter()
    .map(|item| Value::String(item.clone()))
    .collect();
  let out_of_scope: Vec<_> = surface
    .out_of_scope
    .iter()
    .map(|item| Value::String(item.clone()))
    .collect();
  let sections: Vec<_> = surface
    .sections
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let execution_narrative: Vec<_> = surface
    .execution_narrative
    .iter()
    .cloned()
    .map(Value::String)
    .collect();
  let severity_summary = json!({
    "critical": preview.severity_summary.get(&crate::modules::common::Severity::Critical).copied().unwrap_or(0),
    "high": preview.severity_summary.get(&crate::modules::common::Severity::High).copied().unwrap_or(0),
    "medium": preview.severity_summary.get(&crate::modules::common::Severity::Medium).copied().unwrap_or(0),
    "low": preview.severity_summary.get(&crate::modules::common::Severity::Low).copied().unwrap_or(0),
    "info": preview.severity_summary.get(&crate::modules::common::Severity::Info).copied().unwrap_or(0)
  });

  json!({
    "target": target,
    "source": build.data_source.as_str(),
    "empty": matches!(build.data_source, ReportDataSource::Empty),
    "loot_records": build.loot_count,
    "action_records": build.action_count,
    "graph_loaded": build.graph_loaded,
    "methodology": surface.methodology,
    "scope": scope,
    "out_of_scope": out_of_scope,
    "executive_summary": report.base.executive_summary,
    "severity_summary": severity_summary,
    "top_findings": top_findings,
    "insights": insights,
    "recommendations": recommendations,
    "recommendation_titles": recommendation_titles,
    "path_titles": path_titles,
    "phase_names": phase_names,
    "host_targets": host_targets,
    "execution_narrative": execution_narrative,
    "section_count": surface.section_count,
    "sections": sections,
    "paths": surface.paths,
    "phases": surface.phases,
    "hosts": surface.hosts
  })
}

fn stats_payload(stats: &PentestReportStatsBuild) -> Value {
  let graph = stats.graph_stats.as_ref().map(|value| {
    json!({
      "nodes": value.total_nodes,
      "edges": value.total_edges,
      "components": value.connected_components,
      "max_depth": value.max_depth
    })
  });
  let loot = json!({
    "total": stats.loot.total,
    "vulnerabilities": stats.loot.vulnerabilities,
    "credentials": stats.loot.credentials,
    "services": stats.loot.services,
    "confirmed": stats.loot.confirmed,
    "potential": stats.loot.potential
  });
  let actions = json!({
    "total": stats.actions.total,
    "exploit": stats.actions.exploit,
    "successful": stats.actions.successful,
    "unique_targets": stats.actions.unique_targets,
    "observed_phases": stats.actions.observed_phases,
    "observed_paths": stats.actions.observed_paths
  });
  let report = json!({
    "methodology": stats.report.methodology,
    "scope": stats.report.scope,
    "out_of_scope": stats.report.out_of_scope,
    "findings": stats.report.findings,
    "recommendations": stats.report.recommendations,
    "hosts": stats.report.hosts,
    "insights": stats.report.insights,
    "paths": stats.report.paths,
    "phases": stats.report.phases,
    "section_count": stats.report.section_count,
    "sections": stats.report.sections,
    "phase_names": stats.report.phase_names,
    "path_titles": stats.report.path_titles,
    "host_targets": stats.report.host_targets,
    "recommendation_titles": stats.report.recommendation_titles,
    "execution_narrative": stats.report.execution_narrative
  });

  json!({
    "loot": loot,
    "actions": actions,
    "report": report,
    "graph": graph
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn array_item(value: &Value, idx: usize) -> Option<&Value> {
    value.as_array().and_then(|values| values.get(idx))
  }

  #[test]
  fn test_sanitize_filename() {
    assert_eq!(sanitize_filename("192.168.1.0/24"), "192.168.1.0_24");
    assert_eq!(sanitize_filename("example.com"), "example.com");
    assert_eq!(sanitize_filename("test:target"), "test_target");
  }

  #[test]
  fn test_should_emit_empty_source_warning_respects_machine_mode() {
    let human_ctx = CliContext::default();
    assert!(should_emit_empty_source_warning(&human_ctx, true));

    let machine_ctx = CliContext {
      flags: std::collections::HashMap::from([("json".to_string(), "true".to_string())]),
      ..CliContext::default()
    };
    assert!(!should_emit_empty_source_warning(&machine_ctx, true));
    assert!(!should_emit_empty_source_warning(&machine_ctx, false));
  }

  #[test]
  fn test_resolve_report_target_prefers_parser_target() {
    let ctx = CliContext {
      target: Some("parsed.example".to_string()),
      args: vec!["positional.example".to_string()],
      flags: std::collections::HashMap::from([("project".to_string(), "flag.example".to_string())]),
      ..CliContext::default()
    };

    assert_eq!(
      resolve_report_target(&ctx, "usage").ok().as_deref(),
      Some("parsed.example")
    );
  }

  #[test]
  fn test_resolve_report_target_uses_positional_when_parser_target_missing() {
    let ctx = CliContext {
      args: vec!["positional.example".to_string()],
      flags: std::collections::HashMap::from([("project".to_string(), "flag.example".to_string())]),
      ..CliContext::default()
    };

    assert_eq!(
      resolve_report_target(&ctx, "usage").ok().as_deref(),
      Some("positional.example")
    );
  }

  #[test]
  fn test_resolve_report_target_uses_project_flag_when_arg_missing() {
    let ctx = CliContext {
      args: vec![],
      flags: std::collections::HashMap::from([("project".to_string(), "flag.example".to_string())]),
      ..CliContext::default()
    };

    assert_eq!(
      resolve_report_target(&ctx, "usage").ok().as_deref(),
      Some("flag.example")
    );
  }

  #[test]
  fn test_stats_payload_includes_loot_counts() {
    let payload = stats_payload(&PentestReportStatsBuild {
      loot: crate::modules::report::pentest::LootStatsSurface {
        total: 10,
        vulnerabilities: 4,
        credentials: 2,
        services: 1,
        confirmed: 7,
        potential: 3,
      },
      actions: crate::modules::report::pentest::ActionStatsSurface {
        total: 8,
        exploit: 5,
        successful: 6,
        unique_targets: 3,
        observed_phases: 2,
        observed_paths: 1,
      },
      report: crate::modules::report::pentest::ReportSurface {
        methodology: Some("PTES".to_string()),
        scope: vec!["example.com".to_string()],
        out_of_scope: vec!["third-party".to_string()],
        findings: 12,
        recommendations: 4,
        hosts: 2,
        insights: 3,
        paths: 1,
        phases: 1,
        section_count: 2,
        sections: vec![
          "Report Information".to_string(),
          "Detailed Findings".to_string(),
        ],
        phase_names: vec!["privilege-escalation".to_string()],
        path_titles: vec!["Observed Execution Path".to_string()],
        host_targets: vec!["example.com".to_string()],
        recommendation_titles: vec!["Privilege Boundary Hardening".to_string()],
        execution_narrative: vec!["Phase 'privilege-escalation' executed 1 action(s).".to_string()],
      },
      graph_stats: None,
    });
    assert_eq!(payload["loot"]["total"].as_i64(), Some(10));
    assert_eq!(payload["loot"]["vulnerabilities"].as_i64(), Some(4));
    assert_eq!(payload["actions"]["exploit"].as_i64(), Some(5));
    assert_eq!(payload["actions"]["observed_paths"].as_i64(), Some(1));
    assert_eq!(payload["report"]["findings"].as_i64(), Some(12));
    assert_eq!(payload["report"]["methodology"].as_str(), Some("PTES"));
    assert_eq!(payload["report"]["insights"].as_i64(), Some(3));
    assert_eq!(payload["report"]["phases"].as_i64(), Some(1));
    assert_eq!(
      array_item(&payload["report"]["scope"], 0).and_then(Value::as_str),
      Some("example.com")
    );
    assert_eq!(
      array_item(&payload["report"]["out_of_scope"], 0).and_then(Value::as_str),
      Some("third-party")
    );
    assert_eq!(payload["report"]["section_count"].as_i64(), Some(2));
    assert_eq!(
      array_item(&payload["report"]["sections"], 1).and_then(Value::as_str),
      Some("Detailed Findings")
    );
    assert_eq!(
      array_item(&payload["report"]["phase_names"], 0).and_then(Value::as_str),
      Some("privilege-escalation")
    );
    assert_eq!(
      array_item(&payload["report"]["path_titles"], 0).and_then(Value::as_str),
      Some("Observed Execution Path")
    );
    assert_eq!(
      array_item(&payload["report"]["host_targets"], 0).and_then(Value::as_str),
      Some("example.com")
    );
    assert_eq!(
      array_item(&payload["report"]["recommendation_titles"], 0).and_then(Value::as_str),
      Some("Privilege Boundary Hardening")
    );
    assert!(array_item(&payload["report"]["execution_narrative"], 0)
      .and_then(Value::as_str)
      .unwrap_or_default()
      .contains("privilege-escalation"));
    assert!(matches!(payload.get("graph"), Some(Value::Null)));
  }

  #[test]
  fn test_generate_payload_includes_output_path() {
    let report = PentestReport::from_loot(&[], "example.com")
      .with_methodology("PTES")
      .add_scope("example.com")
      .add_out_of_scope("third-party");
    let build = PentestReportBuild {
      report,
      data_source: ReportDataSource::Loot,
      loot_count: 3,
      action_count: 0,
      graph_loaded: false,
    };
    let payload = generate_payload(
      &build,
      "example.com",
      "md",
      &PathBuf::from("report-example.md"),
    );
    assert_eq!(payload["target"].as_str(), Some("example.com"));
    assert_eq!(payload["format"].as_str(), Some("md"));
    assert_eq!(payload["output_path"].as_str(), Some("report-example.md"));
    assert_eq!(payload["source"].as_str(), Some("loot"));
    assert_eq!(payload["loot_records"].as_i64(), Some(3));
    assert_eq!(payload["methodology"].as_str(), Some("PTES"));
    assert_eq!(
      array_item(&payload["scope"], 0).and_then(Value::as_str),
      Some("example.com")
    );
    assert_eq!(
      array_item(&payload["out_of_scope"], 0).and_then(Value::as_str),
      Some("third-party")
    );
    assert!(payload["execution_narrative"]
      .as_array()
      .map(|values| values.to_vec())
      .unwrap_or_default()
      .is_empty());
    assert_eq!(
      payload["section_count"].as_i64(),
      payload["sections"]
        .as_array()
        .map(|values| values.len() as i64)
    );
    let sections = payload["sections"]
      .as_array()
      .map(|values| values.to_vec())
      .unwrap_or_default();
    assert!(sections
      .iter()
      .filter_map(|value| value.as_str())
      .any(|value| value == "Detailed Findings"));
  }

  #[test]
  fn test_preview_payload_exposes_report_shape() {
    let mut report = PentestReport::new("Preview", "example.com");
    report.base.executive_summary = "Observed execution with one critical finding.".to_string();
    report = report.with_methodology("PTES").add_scope("example.com");
    report
      .attack_paths
      .push(crate::modules::report::pentest::AttackPath {
        title: "Observed Execution Path".to_string(),
        steps: vec![],
        impact: "Privilege escalation achieved".to_string(),
        likelihood: crate::modules::common::Severity::Critical,
      });
    report
      .execution_phases
      .push(crate::modules::report::pentest::ExecutionPhaseSummary {
        phase: "privilege-escalation".to_string(),
        total_actions: 1,
        successful_actions: 1,
        failed_actions: 0,
        skipped_actions: 0,
        total_duration_ms: 1200,
        steps: vec!["Privilege Escalation".to_string()],
      });

    let build = PentestReportBuild {
      report,
      data_source: ReportDataSource::Actions,
      loot_count: 0,
      action_count: 2,
      graph_loaded: true,
    };

    let payload = preview_payload(&build, "example.com");
    assert_eq!(payload["source"].as_str(), Some("actions"));
    assert_eq!(payload["graph_loaded"].as_bool(), Some(true));
    assert_eq!(payload["paths"].as_i64(), Some(1));
    assert_eq!(payload["phases"].as_i64(), Some(1));
    assert_eq!(payload["hosts"].as_i64(), Some(0));
    assert_eq!(payload["methodology"].as_str(), Some("PTES"));
    assert_eq!(
      array_item(&payload["scope"], 0).and_then(Value::as_str),
      Some("example.com")
    );
    assert!(payload["host_targets"]
      .as_array()
      .map(|values| values.to_vec())
      .unwrap_or_default()
      .is_empty());
    assert_eq!(
      array_item(&payload["path_titles"], 0).and_then(Value::as_str),
      Some("Observed Execution Path")
    );
    assert_eq!(
      array_item(&payload["phase_names"], 0).and_then(Value::as_str),
      Some("privilege-escalation")
    );
    assert_eq!(
      array_item(&payload["recommendation_titles"], 0).and_then(Value::as_str),
      Some("Privilege Boundary Hardening")
    );
    assert_eq!(
      payload["recommendations"]
        .as_array()
        .and_then(|values| values.first())
        .and_then(|rec| rec["affected_phases"].as_array())
        .and_then(|values| values.first())
        .and_then(Value::as_str),
      Some("privilege-escalation")
    );
    assert_eq!(
      payload["recommendations"]
        .as_array()
        .and_then(|values| values.first())
        .and_then(|rec| rec["affected_paths"].as_array())
        .and_then(|values| values.first())
        .and_then(Value::as_str),
      Some("Observed Execution Path")
    );
    assert!(array_item(&payload["execution_narrative"], 0)
      .and_then(Value::as_str)
      .unwrap_or_default()
      .contains("privilege-escalation"));
    assert_eq!(
      payload["section_count"].as_i64(),
      payload["sections"]
        .as_array()
        .map(|values| values.len() as i64)
    );
    let sections = payload["sections"]
      .as_array()
      .map(|values| values.to_vec())
      .unwrap_or_default();
    assert!(sections
      .iter()
      .filter_map(|value| value.as_str())
      .any(|value| value == "Attack Paths"));
    assert!(payload["executive_summary"]
      .as_str()
      .unwrap_or_default()
      .contains("critical finding"));
  }

  #[test]
  fn test_preview_payload_marks_empty_builds() {
    let build = PentestReportBuild {
      report: PentestReport::new("Preview", "empty.local"),
      data_source: ReportDataSource::Empty,
      loot_count: 0,
      action_count: 0,
      graph_loaded: false,
    };

    let payload = preview_payload(&build, "empty.local");
    assert_eq!(payload["source"].as_str(), Some("empty"));
    assert_eq!(payload["empty"].as_bool(), Some(true));
    assert!(payload["top_findings"]
      .as_array()
      .map(|values| values.to_vec())
      .unwrap_or_default()
      .is_empty());
    assert!(payload["recommendations"]
      .as_array()
      .map(|values| values.to_vec())
      .unwrap_or_default()
      .is_empty());
  }
}
