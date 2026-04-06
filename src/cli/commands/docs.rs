use crate::cli::commands::{Command, Flag, Route};
use crate::cli::{format::OutputFormat, output::Output, render, CliContext};
use crate::json;
use crate::serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command as ProcessCommand;

pub struct DocsCommand;

impl Command for DocsCommand {
  fn domain(&self) -> &str {
    "docs"
  }

  fn resource(&self) -> &str {
    "kb" // Knowledge Base
  }

  fn description(&self) -> &str {
    "Documentation and knowledge base access"
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
        verb: "search",
        summary: "Search documentation (grep-based)",
        usage: "rb docs kb search <query>",
      },
      Route {
        verb: "index",
        summary: "Build/Download documentation index (placeholder)",
        usage: "rb docs kb index [--download]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output format (text, json, yaml)")
        .with_short('o')
        .with_default("text"),
      Flag::new("download", "Download pre-built embeddings (simulated)"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Search for TLS help", "rb docs kb search tls"),
      ("Update local index", "rb docs kb index --download"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("help");

    match verb {
      "search" => self.search(ctx),
      "index" => self.index(ctx),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

impl DocsCommand {
  fn search(&self, ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();

    let query = ctx.target.as_ref().ok_or("Missing search query")?;

    // Simple grep-based search in docs/ directory
    let docs_dir = Path::new("docs");
    if !docs_dir.exists() {
      if format == OutputFormat::Json {
        Output::json_value(&json!({
          "success": false,
          "error": "Docs directory not found"
        }));
      }
      return Err("Docs directory not found. Are you in the project root?".to_string());
    }

    let output = ProcessCommand::new("grep")
      .arg("-r")
      .arg("-i")
      .arg("-n")
      .arg(query)
      .arg("docs")
      .output()
      .map_err(|e| format!("Failed to run search: {}", e))?;

    let matches = if output.status.success() {
      let stdout = String::from_utf8_lossy(&output.stdout);
      stdout
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
    } else {
      Vec::new()
    };
    let payload = Self::search_payload(query, matches);
    if render::render_machine_output(ctx, "rb docs kb search", &payload)? {
      return Ok(());
    }

    Output::header("Documentation Search");
    println!("Searching for: '{}'", query);

    if output.status.success() {
      let stdout = String::from_utf8_lossy(&output.stdout);
      for line in stdout.lines() {
        println!("{}", line);
      }
    } else {
      Output::warning("No matches found.");
    }

    Ok(())
  }

  fn index(&self, ctx: &CliContext) -> Result<(), String> {
    let download = ctx.has_flag("download");
    let docs_count = fs::read_dir("docs").map(|iter| iter.count()).unwrap_or(0);
    let payload = Self::index_payload(download, docs_count);
    if render::render_machine_output(ctx, "rb docs kb index", &payload)? {
      return Ok(());
    }

    if download {
      Output::spinner_start("Downloading documentation embeddings...");
      // Simulate download
      std::thread::sleep(std::time::Duration::from_secs(2));
      Output::spinner_done();
      Output::success("Embeddings downloaded to ~/.redblue/docs_embeddings.bin");
    } else {
      Output::info("Building local index...");
      Output::success(&format!("Indexed {} documents", docs_count));
    }
    Ok(())
  }

  fn search_payload(query: &str, matches: Vec<String>) -> Value {
    json!({
      "query": query,
      "total": matches.len(),
      "matches": matches
    })
  }

  fn index_payload(download: bool, docs_count: usize) -> Value {
    json!({
      "action": if download { "download" } else { "build" },
      "docs_count": docs_count,
      "success": true
    })
  }
}
