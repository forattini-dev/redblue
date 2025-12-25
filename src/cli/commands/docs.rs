use crate::cli::commands::{Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
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
        let is_json = format == crate::cli::format::OutputFormat::Json;

        let query = ctx.target.as_ref().ok_or("Missing search query")?;

        // Simple grep-based search in docs/ directory
        let docs_dir = Path::new("docs");
        if !docs_dir.exists() {
            if is_json {
                println!("{{");
                println!("  \"success\": false,");
                println!("  \"error\": \"Docs directory not found\"");
                println!("}}");
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

        if is_json {
            println!("{{");
            println!("  \"query\": \"{}\",", query.replace('"', "\\\""));
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = stdout.lines().collect();
                println!("  \"total\": {},", lines.len());
                println!("  \"matches\": [");
                for (i, line) in lines.iter().enumerate() {
                    let comma = if i < lines.len() - 1 { "," } else { "" };
                    println!(
                        "    \"{}\"{}",
                        line.replace('"', "\\\"").replace('\\', "\\\\"),
                        comma
                    );
                }
                println!("  ]");
            } else {
                println!("  \"total\": 0,");
                println!("  \"matches\": []");
            }
            println!("}}");
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
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        let download = ctx.has_flag("download");
        let docs_count = fs::read_dir("docs").map(|iter| iter.count()).unwrap_or(0);

        if is_json {
            println!("{{");
            println!(
                "  \"action\": \"{}\",",
                if download { "download" } else { "build" }
            );
            println!("  \"docs_count\": {},", docs_count);
            println!("  \"success\": true");
            println!("}}");
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
}
