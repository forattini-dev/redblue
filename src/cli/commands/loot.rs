//! Loot Command - Manage pentest findings and artifacts
//!
//! rb loot entry add <key> [--category cred|vuln|finding|...] [--content "..."]
//! rb loot entry list [--category <cat>] [--status <status>]
//! rb loot entry show <key>
//! rb loot entry delete <key>
//! rb loot entry export [--format json|csv]
//!
//! rb loot graph show [--format mermaid|dot]
//! rb loot graph paths <from> <to> [--max-depth N]
//! rb loot graph insights
//! rb loot graph rebuild

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::graph::ShadowGraph;
use crate::storage::segments::loot::{
  Confidence, LootCategory, LootEntry, LootSegment, LootStatus,
};

use super::{Command, Flag, Route};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// LootEntryCommand - rb loot entry *
// ============================================================================

pub struct LootEntryCommand;

impl Command for LootEntryCommand {
  fn domain(&self) -> &str {
    "loot"
  }

  fn resource(&self) -> &str {
    "entry"
  }

  fn description(&self) -> &str {
    "Manage loot entries (credentials, vulnerabilities, findings)"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "add",
        summary: "Add a new loot entry",
        usage: "rb loot entry add ssh_admin --category cred --content 'admin:password123'",
      },
      Route {
        verb: "list",
        summary: "List all loot entries",
        usage: "rb loot entry list --category cred",
      },
      Route {
        verb: "show",
        summary: "Show details of a loot entry",
        usage: "rb loot entry show ssh_admin",
      },
      Route {
        verb: "delete",
        summary: "Delete a loot entry",
        usage: "rb loot entry delete ssh_admin",
      },
      Route {
        verb: "export",
        summary: "Export loot to file",
        usage: "rb loot entry export --format json > loot.json",
      },
      Route {
        verb: "stats",
        summary: "Show loot statistics",
        usage: "rb loot entry stats",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new(
        "category",
        "Loot category: cred, vuln, finding, artifact, service, endpoint, tech, task, info",
      )
      .with_short('c')
      .with_default("finding"),
      Flag::new("content", "Content/description of the finding").with_short('C'),
      Flag::new("confidence", "Confidence level: high, medium, low").with_default("medium"),
      Flag::new(
        "status",
        "Status: open, closed, confirmed, potential, filtered",
      )
      .with_default("open"),
      Flag::new("target", "Target IP or hostname").with_short('t'),
      Flag::new("format", "Output format: text, json, csv")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
            ("Add SSH credentials found on a host", "rb loot entry add ssh_creds_10.0.0.1 --category cred --content 'root:toor' --target 10.0.0.1"),
            ("Add a vulnerability finding", "rb loot entry add sqli_login --category vuln --content 'SQL injection in login form' --confidence high"),
            ("List all credentials", "rb loot entry list --category cred"),
            ("Export to JSON", "rb loot entry export --format json"),
            ("Show statistics", "rb loot entry stats"),
        ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("list");

    match verb {
      "add" => execute_add(ctx),
      "list" => execute_list(ctx),
      "show" => execute_show(ctx),
      "delete" => execute_delete(ctx),
      "export" => execute_export(ctx),
      "stats" => execute_stats(ctx),
      _ => Err(format!(
        "Unknown verb '{}'. Use: add, list, show, delete, export, stats",
        verb
      )),
    }
  }
}

fn get_loot_path() -> std::path::PathBuf {
  let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
  std::path::PathBuf::from(home)
    .join(".redblue")
    .join("loot.segment")
}

fn load_loot() -> LootSegment {
  let path = get_loot_path();
  if path.exists() {
    match std::fs::read(&path) {
      Ok(bytes) => LootSegment::deserialize(&bytes).unwrap_or_default(),
      Err(_) => LootSegment::new(),
    }
  } else {
    LootSegment::new()
  }
}

fn save_loot(segment: &mut LootSegment) -> Result<(), String> {
  let path = get_loot_path();
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)
      .map_err(|e| format!("Failed to create loot directory: {}", e))?;
  }
  let bytes = segment.serialize();
  std::fs::write(&path, bytes).map_err(|e| format!("Failed to save loot: {}", e))
}

fn parse_category(s: &str) -> Result<LootCategory, String> {
  match s.to_lowercase().as_str() {
        "cred" | "credential" | "credentials" => Ok(LootCategory::Credential),
        "vuln" | "vulnerability" => Ok(LootCategory::Vulnerability),
        "finding" => Ok(LootCategory::Finding),
        "artifact" => Ok(LootCategory::Artifact),
        "service" => Ok(LootCategory::Service),
        "endpoint" => Ok(LootCategory::Endpoint),
        "tech" | "technology" => Ok(LootCategory::Technology),
        "task" => Ok(LootCategory::Task),
        "info" => Ok(LootCategory::Info),
        _ => Err(format!("Unknown category '{}'. Use: cred, vuln, finding, artifact, service, endpoint, tech, task, info", s)),
    }
}

fn parse_confidence(s: &str) -> Result<Confidence, String> {
  match s.to_lowercase().as_str() {
    "high" => Ok(Confidence::High),
    "medium" | "med" => Ok(Confidence::Medium),
    "low" => Ok(Confidence::Low),
    _ => Err(format!(
      "Unknown confidence '{}'. Use: high, medium, low",
      s
    )),
  }
}

fn parse_status(s: &str) -> Result<LootStatus, String> {
  match s.to_lowercase().as_str() {
    "open" => Ok(LootStatus::Open),
    "closed" => Ok(LootStatus::Closed),
    "confirmed" => Ok(LootStatus::Confirmed),
    "potential" => Ok(LootStatus::Potential),
    "filtered" => Ok(LootStatus::Filtered),
    _ => Err(format!(
      "Unknown status '{}'. Use: open, closed, confirmed, potential, filtered",
      s
    )),
  }
}

fn execute_add(ctx: &CliContext) -> Result<(), String> {
  let key = ctx
    .target
    .as_deref()
    .ok_or("Missing loot key. Usage: rb loot entry add <key>")?;

  let category = ctx
    .flags
    .get("category")
    .map(|s| parse_category(s))
    .transpose()?
    .unwrap_or(LootCategory::Finding);

  let content = ctx
    .flags
    .get("content")
    .cloned()
    .unwrap_or_else(|| format!("Loot entry: {}", key));

  let confidence = ctx
    .flags
    .get("confidence")
    .map(|s| parse_confidence(s))
    .transpose()?
    .unwrap_or(Confidence::Medium);

  let status = ctx
    .flags
    .get("status")
    .map(|s| parse_status(s))
    .transpose()?
    .unwrap_or(LootStatus::Open);

  let target = ctx.flags.get("target").and_then(|s| s.parse().ok());

  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs() as i64;

  let entry = LootEntry {
    key: key.to_string(),
    category,
    content,
    confidence,
    status,
    target,
    source: None,
    created_at: now,
    updated_at: now,
    metadata: Default::default(),
  };

  let mut segment = load_loot();
  segment.push(entry);
  save_loot(&mut segment)?;

  Output::success(&format!("Added loot entry: {}", key));
  println!("  Category:   {}", category.as_str());
  println!("  Confidence: {}", confidence.as_str());
  println!("  Status:     {}", status.as_str());

  Ok(())
}

fn execute_list(ctx: &CliContext) -> Result<(), String> {
  let mut segment = load_loot();

  let category_filter = ctx
    .flags
    .get("category")
    .map(|s| parse_category(s))
    .transpose()?;

  let status_filter = ctx
    .flags
    .get("status")
    .map(|s| parse_status(s))
    .transpose()?;

  let all_entries = segment.all();
  let entries: Vec<_> = all_entries
    .iter()
    .filter(|e| category_filter.map_or(true, |c| e.category == c))
    .filter(|e| status_filter.map_or(true, |s| e.status == s))
    .collect();

  if entries.is_empty() {
    Output::info("No loot entries found");
    return Ok(());
  }

  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");

  match format {
    "json" => {
      println!("[");
      for (i, entry) in entries.iter().enumerate() {
        let comma = if i < entries.len() - 1 { "," } else { "" };
        println!(
          r#"  {{"key":"{}","category":"{}","content":"{}","confidence":"{}","status":"{}","created_at":{}}}{}"#,
          entry.key,
          entry.category.as_str(),
          entry.content.replace('"', "\\\""),
          entry.confidence.as_str(),
          entry.status.as_str(),
          entry.created_at,
          comma
        );
      }
      println!("]");
    }
    "csv" => {
      println!("key,category,content,confidence,status,created_at");
      for entry in &entries {
        println!(
          "{},{},{},{},{},{}",
          entry.key,
          entry.category.as_str(),
          entry.content.replace(',', ";"),
          entry.confidence.as_str(),
          entry.status.as_str(),
          entry.created_at
        );
      }
    }
    _ => {
      Output::header(&format!("Loot Entries ({} total)", entries.len()));
      println!();

      for entry in &entries {
        let status_color = match entry.status {
          LootStatus::Open => "\x1b[33m",      // yellow
          LootStatus::Confirmed => "\x1b[31m", // red
          LootStatus::Closed => "\x1b[32m",    // green
          LootStatus::Potential => "\x1b[36m", // cyan
          LootStatus::Filtered => "\x1b[90m",  // gray
        };
        let reset = "\x1b[0m";

        println!(
          "  {} [{:>12}] {}{:>10}{} - {}",
          entry.key,
          entry.category.as_str(),
          status_color,
          entry.status.as_str(),
          reset,
          truncate(&entry.content, 50)
        );
      }
    }
  }

  Ok(())
}

fn execute_show(ctx: &CliContext) -> Result<(), String> {
  let key = ctx
    .target
    .as_deref()
    .ok_or("Missing loot key. Usage: rb loot entry show <key>")?;
  let mut segment = load_loot();

  let entry = segment
    .get(key)
    .ok_or_else(|| format!("Loot entry '{}' not found", key))?;

  Output::header(&format!("Loot: {}", entry.key));
  println!();
  println!("  Category:   {}", entry.category.as_str());
  println!("  Confidence: {}", entry.confidence.as_str());
  println!("  Status:     {}", entry.status.as_str());
  if let Some(target) = entry.target {
    println!("  Target:     {}", target);
  }
  if let Some(source) = entry.source {
    println!("  Source:     {}", source);
  }
  println!("  Created:    {}", format_timestamp(entry.created_at));
  println!("  Updated:    {}", format_timestamp(entry.updated_at));
  println!();
  println!("  Content:");
  println!("  ─────────────────────────────────────");
  for line in entry.content.lines() {
    println!("  {}", line);
  }

  Ok(())
}

fn execute_delete(ctx: &CliContext) -> Result<(), String> {
  let key = ctx
    .target
    .as_deref()
    .ok_or("Missing loot key. Usage: rb loot entry delete <key>")?;
  let mut segment = load_loot();

  if segment.get(key).is_none() {
    return Err(format!("Loot entry '{}' not found", key));
  }

  segment.remove(key);
  save_loot(&mut segment)?;

  Output::success(&format!("Deleted loot entry: {}", key));
  Ok(())
}

fn execute_export(ctx: &CliContext) -> Result<(), String> {
  let mut segment = load_loot();
  let entries = segment.all();

  if entries.is_empty() {
    Output::info("No loot entries to export");
    return Ok(());
  }

  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("json");

  match format {
    "json" => {
      println!("[");
      for (i, entry) in entries.iter().enumerate() {
        let comma = if i < entries.len() - 1 { "," } else { "" };
        println!(
          r#"  {{
    "key": "{}",
    "category": "{}",
    "content": "{}",
    "confidence": "{}",
    "status": "{}",
    "target": {},
    "source": {},
    "created_at": {},
    "updated_at": {}
  }}{}"#,
          entry.key,
          entry.category.as_str(),
          entry.content.replace('"', "\\\"").replace('\n', "\\n"),
          entry.confidence.as_str(),
          entry.status.as_str(),
          entry
            .target
            .map(|t| format!("\"{}\"", t))
            .unwrap_or_else(|| "null".to_string()),
          entry
            .source
            .map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| "null".to_string()),
          entry.created_at,
          entry.updated_at,
          comma
        );
      }
      println!("]");
    }
    "csv" => {
      println!("key,category,content,confidence,status,target,source,created_at,updated_at");
      for entry in entries {
        println!(
          "{},{},{},{},{},{},{},{},{}",
          entry.key,
          entry.category.as_str(),
          entry.content.replace(',', ";").replace('\n', " "),
          entry.confidence.as_str(),
          entry.status.as_str(),
          entry.target.map(|t| t.to_string()).unwrap_or_default(),
          entry.source.map(|s| s.to_string()).unwrap_or_default(),
          entry.created_at,
          entry.updated_at
        );
      }
    }
    _ => return Err(format!("Unknown format '{}'. Use: json, csv", format)),
  }

  Ok(())
}

fn execute_stats(ctx: &CliContext) -> Result<(), String> {
  let mut segment = load_loot();
  let entries = segment.all();

  if entries.is_empty() {
    Output::info("No loot entries");
    return Ok(());
  }

  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");

  // Count by category
  let mut by_category = std::collections::HashMap::new();
  let mut by_status = std::collections::HashMap::new();
  let mut by_confidence = std::collections::HashMap::new();

  for entry in entries {
    *by_category.entry(entry.category.as_str()).or_insert(0) += 1;
    *by_status.entry(entry.status.as_str()).or_insert(0) += 1;
    *by_confidence.entry(entry.confidence.as_str()).or_insert(0) += 1;
  }

  match format {
    "json" => {
      println!(r#"{{"total":{},"by_category":{{"#, segment.len());
      let cats: Vec<_> = by_category.iter().collect();
      for (i, (k, v)) in cats.iter().enumerate() {
        let comma = if i < cats.len() - 1 { "," } else { "" };
        print!(r#""{}":{}{}""#, k, v, comma);
      }
      println!(r#"}},"by_status":{{"#);
      let stats: Vec<_> = by_status.iter().collect();
      for (i, (k, v)) in stats.iter().enumerate() {
        let comma = if i < stats.len() - 1 { "," } else { "" };
        print!(r#""{}":{}{}""#, k, v, comma);
      }
      println!(r#"}}}}"#);
    }
    _ => {
      Output::header(&format!("Loot Statistics ({} entries)", segment.len()));
      println!();

      println!("  By Category:");
      for (cat, count) in &by_category {
        println!("    {:>12}: {}", cat, count);
      }

      println!();
      println!("  By Status:");
      for (status, count) in &by_status {
        println!("    {:>12}: {}", status, count);
      }

      println!();
      println!("  By Confidence:");
      for (conf, count) in &by_confidence {
        println!("    {:>12}: {}", conf, count);
      }
    }
  }

  Ok(())
}

// ============================================================================
// LootGraphCommand - rb loot graph *
// ============================================================================

pub struct LootGraphCommand;

impl Command for LootGraphCommand {
  fn domain(&self) -> &str {
    "loot"
  }

  fn resource(&self) -> &str {
    "graph"
  }

  fn description(&self) -> &str {
    "Attack path analysis with Shadow Graph"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "show",
        summary: "Show graph structure",
        usage: "rb loot graph show --format mermaid",
      },
      Route {
        verb: "rebuild",
        summary: "Rebuild graph from loot data",
        usage: "rb loot graph rebuild",
      },
      Route {
        verb: "paths",
        summary: "Find attack paths between nodes",
        usage: "rb loot graph paths host:10.0.0.1 host:10.0.0.5 --max-depth 5",
      },
      Route {
        verb: "insights",
        summary: "Generate strategic insights",
        usage: "rb loot graph insights",
      },
      Route {
        verb: "stats",
        summary: "Show graph statistics",
        usage: "rb loot graph stats",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("format", "Output format: text, mermaid, dot, json")
        .with_short('f')
        .with_default("text"),
      Flag::new("max-depth", "Maximum path depth").with_default("5"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Rebuild graph from loot", "rb loot graph rebuild"),
      (
        "Show graph as Mermaid diagram",
        "rb loot graph show --format mermaid",
      ),
      (
        "Find paths between hosts",
        "rb loot graph paths host:10.0.0.1 host:10.0.0.50",
      ),
      ("Generate attack insights", "rb loot graph insights"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("stats");

    match verb {
      "show" => execute_graph_show(ctx),
      "rebuild" => execute_graph_rebuild(ctx),
      "paths" => execute_graph_paths(ctx),
      "insights" => execute_graph_insights(ctx),
      "stats" => execute_graph_stats(ctx),
      _ => Err(format!(
        "Unknown verb '{}'. Use: show, rebuild, paths, insights, stats",
        verb
      )),
    }
  }
}

fn get_graph_path() -> std::path::PathBuf {
  let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
  std::path::PathBuf::from(home)
    .join(".redblue")
    .join("graph.segment")
}

fn load_graph() -> ShadowGraph {
  let path = get_graph_path();
  if path.exists() {
    match std::fs::read(&path) {
      Ok(bytes) => ShadowGraph::from_bytes(&bytes).unwrap_or_default(),
      Err(_) => ShadowGraph::new(),
    }
  } else {
    ShadowGraph::new()
  }
}

fn save_graph(graph: &mut ShadowGraph) -> Result<(), String> {
  let path = get_graph_path();
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)
      .map_err(|e| format!("Failed to create graph directory: {}", e))?;
  }
  let bytes = graph.to_bytes();
  std::fs::write(&path, bytes).map_err(|e| format!("Failed to save graph: {}", e))
}

fn execute_graph_show(ctx: &CliContext) -> Result<(), String> {
  let graph = load_graph();
  let stats = graph.stats();

  if stats.total_nodes == 0 {
    Output::info("Graph is empty. Use 'rb loot graph rebuild' to build from loot data.");
    return Ok(());
  }

  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");

  match format {
    "mermaid" => {
      println!("{}", graph.to_mermaid());
    }
    "json" => {
      println!(
        r#"{{"nodes":{},"edges":{},"max_depth":{}}}"#,
        stats.total_nodes, stats.total_edges, stats.max_depth
      );
    }
    _ => {
      Output::header("Shadow Graph");
      println!();
      println!("  Nodes: {}", stats.total_nodes);
      println!("  Edges: {}", stats.total_edges);
      println!("  Max Depth: {}", stats.max_depth);
      println!();

      // Show by node type
      println!("  Nodes by Type:");
      for (node_type, count) in &stats.nodes_by_type {
        println!("    {:>12}: {}", node_type.as_str(), count);
      }

      println!();
      println!("  Edges by Type:");
      for (edge_type, count) in &stats.edges_by_type {
        println!("    {:>12}: {}", edge_type.as_str(), count);
      }
    }
  }

  Ok(())
}

fn execute_graph_rebuild(_ctx: &CliContext) -> Result<(), String> {
  let mut loot = load_loot();
  let mut graph = ShadowGraph::new();

  graph.rebuild_from_loot(&mut loot);

  // Validate DAG and fix cycles
  let validation = graph.validate_dag();
  if !validation.is_dag {
    let fixed = graph.fix_cycles();
    Output::warning(&format!("Fixed {} cycles in graph", fixed));
  }

  save_graph(&mut graph)?;

  let stats = graph.stats();
  Output::success("Graph rebuilt from loot data");
  println!("  Nodes: {}", stats.total_nodes);
  println!("  Edges: {}", stats.total_edges);

  Ok(())
}

fn execute_graph_paths(ctx: &CliContext) -> Result<(), String> {
  let graph = load_graph();

  // Parse from/to from target and remaining args
  let from = ctx
    .target
    .as_deref()
    .ok_or("Missing source node. Usage: rb loot graph paths <from> <to>")?;

  // Get 'to' from additional args
  let to = ctx
    .args
    .first()
    .map(|s| s.as_str())
    .ok_or("Missing destination node. Usage: rb loot graph paths <from> <to>")?;

  let max_depth: usize = ctx
    .flags
    .get("max-depth")
    .and_then(|s| s.parse().ok())
    .unwrap_or(5);

  let paths = graph.find_all_paths(from, to, max_depth);

  if paths.is_empty() {
    Output::info(&format!("No paths found from '{}' to '{}'", from, to));

    // Try shortest path as fallback
    if let Some(path) = graph.shortest_path(from, to) {
      Output::info("Shortest path (via Dijkstra):");
      println!("  {}", path.join(" → "));
    }

    return Ok(());
  }

  Output::header(&format!("Attack Paths: {} → {}", from, to));
  println!();

  for (i, path) in paths.iter().enumerate() {
    println!("  Path {}: ({} hops)", i + 1, path.len() - 1);
    println!("    {}", path.join(" → "));
    println!();
  }

  Ok(())
}

fn execute_graph_insights(_ctx: &CliContext) -> Result<(), String> {
  let graph = load_graph();
  let insights = graph.get_insights();

  if insights.is_empty() {
    Output::info("No insights available. Build more loot data first.");
    return Ok(());
  }

  Output::header(&format!("Strategic Insights ({} total)", insights.len()));
  println!();

  for insight in &insights {
    let priority_color = match insight.priority {
      crate::modules::graph::Priority::Critical => "\x1b[31m", // red
      crate::modules::graph::Priority::High => "\x1b[33m",     // yellow
      crate::modules::graph::Priority::Medium => "\x1b[36m",   // cyan
      crate::modules::graph::Priority::Low => "\x1b[37m",      // white
      crate::modules::graph::Priority::Info => "\x1b[90m",     // gray
    };
    let reset = "\x1b[0m";

    println!(
      "  {}[{:>8}]{} {}",
      priority_color,
      insight.priority.as_str(),
      reset,
      insight.message
    );
  }

  Ok(())
}

fn execute_graph_stats(ctx: &CliContext) -> Result<(), String> {
  let graph = load_graph();
  let stats = graph.stats();

  let format = ctx
    .flags
    .get("format")
    .map(|s| s.as_str())
    .unwrap_or("text");

  match format {
    "json" => {
      println!(
        r#"{{"total_nodes":{},"total_edges":{},"max_depth":{},"connected_components":{}}}"#,
        stats.total_nodes, stats.total_edges, stats.max_depth, stats.connected_components
      );
    }
    _ => {
      Output::header("Graph Statistics");
      println!();
      println!("  Total Nodes:          {}", stats.total_nodes);
      println!("  Total Edges:          {}", stats.total_edges);
      println!("  Max Depth:            {}", stats.max_depth);
      println!("  Connected Components: {}", stats.connected_components);
    }
  }

  Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

fn truncate(s: &str, max_len: usize) -> String {
  if s.len() <= max_len {
    s.to_string()
  } else {
    format!("{}...", &s[..max_len - 3])
  }
}

fn format_timestamp(ts: i64) -> String {
  // Simple timestamp formatting (ISO-ish)
  let secs = ts as u64;
  let days = secs / 86400;
  let hours = (secs % 86400) / 3600;
  let mins = (secs % 3600) / 60;

  // Approximate date from Unix epoch
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
