//! Report generation CLI commands
//!
//! Generates pentest reports from loot data and graph insights.
//!
//! Commands:
//! - rb report generate <target> [--format md|json|html] [--output file]
//! - rb report preview <target>
//! - rb report stats

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::graph::ShadowGraph;
use crate::modules::report::pentest::PentestReport;
use crate::storage::segments::loot::LootSegment;

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
  let target = ctx
    .args
    .first()
    .ok_or("Usage: rb report pentest generate <target>")?;

  let format = ctx.flags.get("format").map(|s| s.as_str()).unwrap_or("md");
  let methodology = ctx.flags.get("methodology").map(|s| s.as_str());
  let scope_str = ctx.flags.get("scope").map(|s| s.as_str());

  // Load loot data
  let mut loot = load_loot();
  let entries = loot.all();

  // Filter entries for target (if target is an IP or network)
  let filtered_entries: Vec<_> = if let Ok(ip) = target.parse::<std::net::IpAddr>() {
    entries
      .iter()
      .filter(|e| e.target == Some(ip))
      .cloned()
      .collect()
  } else {
    // Use all entries for domain/string targets
    entries.clone()
  };

  if filtered_entries.is_empty() {
    Output::warning(&format!(
      "No loot entries found for target '{}'. Using all entries.",
      target
    ));
  }

  let entries_to_use = if filtered_entries.is_empty() {
    &entries
  } else {
    &filtered_entries
  };

  // Build report
  let mut report = PentestReport::from_loot(entries_to_use, target);

  // Add methodology if specified
  if let Some(m) = methodology {
    report = report.with_methodology(m);
  }

  // Add scope items
  if let Some(scope) = scope_str {
    for item in scope.split(',') {
      report = report.add_scope(item.trim());
    }
  }

  // Try to load graph for insights
  if let Some(graph) = load_graph() {
    report = report.with_graph_insights(&graph);
  }

  // Generate output
  let content = match format {
    "json" => report.to_json(),
    "html" => report.base.to_html(),
    "md" | "markdown" => report.to_markdown(),
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
      sanitize_filename(target),
      timestamp,
      ext
    ))
  };

  // Write report
  fs::write(&output_path, &content).map_err(|e| format!("Failed to write report: {}", e))?;

  Output::success(&format!("Report generated: {}", output_path.display()));
  println!();
  println!("  Format:    {}", format.to_uppercase());
  println!("  Findings:  {}", report.base.findings.len());
  println!("  Insights:  {}", report.graph_insights.len());
  println!("  Paths:     {}", report.attack_paths.len());

  Ok(())
}

fn execute_preview(ctx: &CliContext) -> Result<(), String> {
  let target = ctx
    .args
    .first()
    .ok_or("Usage: rb report pentest preview <target>")?;

  // Load loot data
  let mut loot = load_loot();
  let entries = loot.all();

  if entries.is_empty() {
    Output::info("No loot entries found. Add findings first with 'rb loot entry add'");
    return Ok(());
  }

  // Build report
  let mut report = PentestReport::from_loot(&entries, target);

  // Try to load graph for insights
  if let Some(graph) = load_graph() {
    report = report.with_graph_insights(&graph);
  }

  let counts = report.base.severity_counts();

  Output::header(&format!("Report Preview: {}", target));
  println!();

  // Severity summary
  println!("  \x1b[1mSeverity Summary\x1b[0m");
  println!("  ────────────────────────────────────────");

  let critical = counts
    .get(&crate::modules::common::Severity::Critical)
    .unwrap_or(&0);
  let high = counts
    .get(&crate::modules::common::Severity::High)
    .unwrap_or(&0);
  let medium = counts
    .get(&crate::modules::common::Severity::Medium)
    .unwrap_or(&0);
  let low = counts
    .get(&crate::modules::common::Severity::Low)
    .unwrap_or(&0);
  let info = counts
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

  let mut sorted_findings = report.base.findings.clone();
  sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

  for finding in sorted_findings.iter().take(5) {
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

  if sorted_findings.len() > 5 {
    println!("  ... and {} more findings", sorted_findings.len() - 5);
  }
  println!();

  // Insights
  if !report.graph_insights.is_empty() {
    println!("  \x1b[1mStrategic Insights\x1b[0m");
    println!("  ────────────────────────────────────────");

    for insight in report.graph_insights.iter().take(3) {
      println!("  → {}", truncate(insight, 60));
    }

    if report.graph_insights.len() > 3 {
      println!(
        "  ... and {} more insights",
        report.graph_insights.len() - 3
      );
    }
    println!();
  }

  // Recommendations
  if !report.recommendations.is_empty() {
    println!("  \x1b[1mRecommendations\x1b[0m");
    println!("  ────────────────────────────────────────");

    for rec in report.recommendations.iter().take(3) {
      println!("  • {} ({})", rec.title, rec.priority.as_str());
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
  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");

  // Load loot data
  let mut loot = load_loot();
  let entries = loot.all();

  // Calculate stats
  let total_entries = entries.len();
  let vulns = entries
    .iter()
    .filter(|e| e.category == crate::storage::segments::loot::LootCategory::Vulnerability)
    .count();
  let creds = entries
    .iter()
    .filter(|e| e.category == crate::storage::segments::loot::LootCategory::Credential)
    .count();
  let services = entries
    .iter()
    .filter(|e| e.category == crate::storage::segments::loot::LootCategory::Service)
    .count();

  let confirmed = entries
    .iter()
    .filter(|e| e.status == crate::storage::segments::loot::LootStatus::Confirmed)
    .count();
  let potential = entries
    .iter()
    .filter(|e| e.status == crate::storage::segments::loot::LootStatus::Potential)
    .count();

  // Graph stats
  let graph_stats = load_graph().map(|g| g.stats());

  match format {
    "json" => {
      let graph = graph_stats.map(|stats| {
        json!({
            "nodes": stats.total_nodes,
            "edges": stats.total_edges,
            "components": stats.connected_components,
            "max_depth": stats.max_depth
        })
      });
      Output::json_value(&json!({
          "loot": json!({
              "total": total_entries,
              "vulnerabilities": vulns,
              "credentials": creds,
              "services": services,
              "confirmed": confirmed,
              "potential": potential
          }),
          "graph": graph
      }));
    }
    _ => {
      Output::header("Report Statistics");
      println!();

      println!("  \x1b[1mLoot Data\x1b[0m");
      println!("  ────────────────────────────────────────");
      println!("  Total entries:    {}", total_entries);
      println!("  Vulnerabilities:  {}", vulns);
      println!("  Credentials:      {}", creds);
      println!("  Services:         {}", services);
      println!("  Confirmed:        {}", confirmed);
      println!("  Potential:        {}", potential);
      println!();

      if let Some(stats) = graph_stats {
        println!("  \x1b[1mGraph Data\x1b[0m");
        println!("  ────────────────────────────────────────");
        println!("  Nodes:            {}", stats.total_nodes);
        println!("  Edges:            {}", stats.total_edges);
        println!("  Components:       {}", stats.connected_components);
        println!("  Max depth:        {}", stats.max_depth);
        println!();
      } else {
        println!("  \x1b[90mNo graph data available. Use 'rb loot graph rebuild' first.\x1b[0m");
        println!();
      }
    }
  }

  Ok(())
}

// Helper functions

fn load_loot() -> LootSegment {
  let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
  let path = format!("{}/.redblue/loot.db", home);

  if let Ok(data) = fs::read(&path) {
    LootSegment::deserialize(&data).unwrap_or_default()
  } else {
    LootSegment::default()
  }
}

fn load_graph() -> Option<ShadowGraph> {
  let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
  let path = format!("{}/.redblue/graph.db", home);

  if let Ok(data) = fs::read(&path) {
    ShadowGraph::from_bytes(&data).ok()
  } else {
    None
  }
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

fn truncate(s: &str, max_len: usize) -> String {
  if s.len() <= max_len {
    s.to_string()
  } else {
    format!("{}...", &s[..max_len - 3])
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_sanitize_filename() {
    assert_eq!(sanitize_filename("192.168.1.0/24"), "192.168.1.0_24");
    assert_eq!(sanitize_filename("example.com"), "example.com");
    assert_eq!(sanitize_filename("test:target"), "test_target");
  }
}
