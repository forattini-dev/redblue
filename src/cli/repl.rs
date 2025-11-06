// REPL - Interactive mode for redblue (k9s-style)
// Usage: rb repl <target>
//        rb repl www.tetis.io.rb-session

use crate::cli::output::Output;
use crate::storage::session::{SessionFile, SessionMetadata};
use std::io::{self, Write};

pub struct Repl {
    target: String,
    session_path: String,
    metadata: Option<SessionMetadata>,
    running: bool,
    context: ReplContext,
}

#[derive(Debug, Clone, PartialEq)]
enum ReplContext {
    Main,       // Top-level: show overview
    Passive,    // Viewing passive recon results
    Stealth,    // Viewing stealth scan results
    Aggressive, // Viewing aggressive scan results
    #[allow(dead_code)]
    Execute, // Execute arbitrary commands
}

impl Repl {
    /// Create new REPL session
    pub fn new(target: String) -> Result<Self, String> {
        // Check if target is a session file or a domain
        let session_path = if target.ends_with(SessionFile::EXTENSION) {
            target.clone()
        } else if target.ends_with(".rdb") {
            target.clone()
        } else {
            format!("{}{}", target, SessionFile::EXTENSION)
        };

        // Try to load existing session
        let metadata = if SessionFile::exists_from_path(&session_path) {
            Some(SessionFile::load_metadata_from_path(&session_path)?)
        } else {
            None
        };

        Ok(Self {
            target: target.clone(),
            session_path,
            metadata,
            running: false,
            context: ReplContext::Main,
        })
    }

    /// Start the REPL
    pub fn start(&mut self) -> Result<(), String> {
        self.running = true;
        self.print_welcome();

        while self.running {
            self.print_prompt();

            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .map_err(|e| format!("Failed to read input: {}", e))?;

            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            if let Err(e) = self.handle_command(input) {
                Output::error(&e);
            }
        }

        Ok(())
    }

    /// Print welcome message
    fn print_welcome(&self) {
        // ANSI codes: black background (40) + bright orange text (38;5;208) + bold (1)
        const BG_BLACK: &str = "\x1b[40m";
        const ORANGE_FLUORESCENT: &str = "\x1b[38;5;208;1m"; // Bright orange + bold
        const RESET: &str = "\x1b[0m";

        // Create a full-width line (80 chars) with black background
        let text = "redblue v1";
        let padding_total = 80 - text.len();
        let padding_left = padding_total / 2;
        let padding_right = padding_total - padding_left;

        let full_line = format!(
            "{}{}{}{}{}{}",
            BG_BLACK,
            ORANGE_FLUORESCENT,
            " ".repeat(padding_left),
            text,
            " ".repeat(padding_right),
            RESET
        );

        println!("\n{}\n", full_line);

        if let Some(ref meta) = self.metadata {
            Output::success(&format!("✓ Loaded session: {}", meta.target));
            Output::info(&format!("  Created: {} seconds ago", meta.age_secs()));
            if meta.is_complete() {
                Output::success(&format!(
                    "  Status: Completed ({:.2}s)",
                    meta.duration_secs.unwrap_or(0.0)
                ));
            } else {
                Output::warning("  Status: Incomplete");
            }
        } else {
            Output::warning(&format!("⚠ No existing session found for {}", self.target));
            Output::info("  Start a new scan with: run <preset>");
        }

        println!("\nType 'help' for available commands, 'quit' to exit\n");
    }

    /// Print context-aware prompt
    fn print_prompt(&self) {
        let context_str = match self.context {
            ReplContext::Main => "main",
            ReplContext::Passive => "passive",
            ReplContext::Stealth => "stealth",
            ReplContext::Aggressive => "aggressive",
            ReplContext::Execute => "exec",
        };

        print!(
            "\x1b[36m{}\x1b[0m:\x1b[33m{}\x1b[0m> ",
            self.target, context_str
        );
        io::stdout().flush().unwrap();
    }

    /// Handle user command
    fn handle_command(&mut self, input: &str) -> Result<(), String> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        match parts[0] {
            "help" | "h" | "?" => self.show_help(),
            "quit" | "exit" | "q" => {
                self.running = false;
                Output::success("Goodbye!");
                Ok(())
            }

            // Navigation
            "main" | "home" => {
                self.context = ReplContext::Main;
                Output::info("Context: Main");
                Ok(())
            }
            "passive" | "p" => {
                self.context = ReplContext::Passive;
                self.show_passive_results()
            }
            "stealth" | "s" => {
                self.context = ReplContext::Stealth;
                self.show_stealth_results()
            }
            "aggressive" | "a" => {
                self.context = ReplContext::Aggressive;
                self.show_aggressive_results()
            }

            // Data viewing
            "show" | "ls" | "view" => self.show_current_context(),
            "all" => self.show_all_results(),
            "summary" | "stats" => self.show_summary(),
            "raw" => self.show_raw_file(),

            // Execution
            "run" => {
                if parts.len() < 2 {
                    return Err("Usage: run <preset>  (passive|stealth|aggressive)".to_string());
                }
                self.run_scan(parts[1])
            }
            "exec" => {
                if parts.len() < 2 {
                    return Err("Usage: exec <command>".to_string());
                }
                self.exec_command(&parts[1..].join(" "))
            }

            // Refresh
            "reload" | "refresh" => self.reload_session(),

            // Clear screen
            "clear" | "cls" => {
                print!("\x1b[2J\x1b[H");
                Ok(())
            }

            _ => Err(format!(
                "Unknown command: '{}'. Type 'help' for available commands.",
                parts[0]
            )),
        }
    }

    /// Show help
    fn show_help(&self) -> Result<(), String> {
        println!("\n{}", "═".repeat(80));
        Output::header("RedBlue REPL - Available Commands");
        println!("{}\n", "═".repeat(80));

        println!("\x1b[1mNAVIGATION:\x1b[0m");
        println!("  main, home          Switch to main context");
        println!("  passive, p          View passive reconnaissance results");
        println!("  stealth, s          View stealth scan results");
        println!("  aggressive, a       View aggressive scan results");

        println!("\n\x1b[1mVIEWING DATA:\x1b[0m");
        println!("  show, ls, view      Show results for current context");
        println!("  all                 Show all results from all phases");
        println!("  summary, stats      Show scan statistics");
        println!(
            "  raw                 Show raw {} file contents",
            SessionFile::EXTENSION
        );

        println!("\n\x1b[1mEXECUTION:\x1b[0m");
        println!("  run <preset>        Run new scan (passive|stealth|aggressive)");
        println!("  exec <command>      Execute arbitrary rb command");
        println!("  reload, refresh     Reload session from disk");

        println!("\n\x1b[1mUTILITY:\x1b[0m");
        println!("  help, h, ?          Show this help");
        println!("  clear, cls          Clear screen");
        println!("  quit, exit, q       Exit REPL");

        println!("\n\x1b[1mEXAMPLES:\x1b[0m");
        println!("  \x1b[2m# View passive recon results\x1b[0m");
        println!("  \x1b[36mpassive\x1b[0m");
        println!();
        println!("  \x1b[2m# Run aggressive scan\x1b[0m");
        println!("  \x1b[36mrun aggressive\x1b[0m");
        println!();
        println!("  \x1b[2m# Execute custom command\x1b[0m");
        println!("  \x1b[36mexec dns record lookup example.com\x1b[0m");
        println!();

        Ok(())
    }

    /// Show results for current context
    fn show_current_context(&self) -> Result<(), String> {
        match self.context {
            ReplContext::Main => self.show_summary(),
            ReplContext::Passive => self.show_passive_results(),
            ReplContext::Stealth => self.show_stealth_results(),
            ReplContext::Aggressive => self.show_aggressive_results(),
            ReplContext::Execute => {
                Output::info("Execute context - use 'run <preset>' or 'exec <command>'");
                Ok(())
            }
        }
    }

    /// Show passive reconnaissance results
    fn show_passive_results(&self) -> Result<(), String> {
        println!();
        Output::phase("Phase 1: Passive Reconnaissance Results");
        println!();

        let results = self.get_phase_results("passive")?;
        if results.is_empty() {
            Output::warning("No passive reconnaissance results found");
            Output::info("Run: run passive");
            return Ok(());
        }

        for (module, status, data, timestamp) in results {
            self.print_result(&module, &status, &data, timestamp);
        }

        println!();
        Ok(())
    }

    /// Show stealth scan results
    fn show_stealth_results(&self) -> Result<(), String> {
        println!();
        Output::phase("Phase 2: Stealth Scanning Results");
        println!();

        let results = self.get_phase_results("stealth")?;
        if results.is_empty() {
            Output::warning("No stealth scan results found");
            Output::info("Run: run stealth");
            return Ok(());
        }

        for (module, status, data, timestamp) in results {
            self.print_result(&module, &status, &data, timestamp);
        }

        println!();
        Ok(())
    }

    /// Show aggressive scan results
    fn show_aggressive_results(&self) -> Result<(), String> {
        println!();
        Output::phase("Phase 3: Aggressive Scanning Results");
        println!();

        let results = self.get_phase_results("aggressive")?;
        if results.is_empty() {
            Output::warning("No aggressive scan results found");
            Output::info("Run: run aggressive");
            return Ok(());
        }

        for (module, status, data, timestamp) in results {
            self.print_result(&module, &status, &data, timestamp);
        }

        println!();
        Ok(())
    }

    /// Show all results
    fn show_all_results(&self) -> Result<(), String> {
        self.show_passive_results()?;
        self.show_stealth_results()?;
        self.show_aggressive_results()?;
        Ok(())
    }

    /// Show summary statistics
    fn show_summary(&self) -> Result<(), String> {
        println!();
        Output::header("Scan Summary");
        println!();

        if let Some(ref meta) = self.metadata {
            Output::item("Target", &meta.target);
            Output::item("Identifier", &meta.identifier);
            Output::item("Command", &meta.command);
            Output::item("Created", &format!("{} seconds ago", meta.age_secs()));

            if meta.is_complete() {
                Output::item("Status", "✓ Completed");
                if let Some(duration) = meta.duration_secs {
                    Output::item("Duration", &format!("{:.2}s", duration));
                }
            } else {
                Output::item("Status", "⚠ Incomplete");
            }
        } else {
            Output::warning("No session metadata available");
        }

        // Count results per phase
        let passive_count = self.get_phase_results("passive").unwrap_or_default().len();
        let stealth_count = self.get_phase_results("stealth").unwrap_or_default().len();
        let aggressive_count = self
            .get_phase_results("aggressive")
            .unwrap_or_default()
            .len();

        println!();
        Output::header("Results Count");
        println!();
        Output::item("Passive", &format!("{} results", passive_count));
        Output::item("Stealth", &format!("{} results", stealth_count));
        Output::item("Aggressive", &format!("{} results", aggressive_count));
        Output::item(
            "Total",
            &format!(
                "{} results",
                passive_count + stealth_count + aggressive_count
            ),
        );

        println!();
        Ok(())
    }

    /// Show raw file contents
    fn show_raw_file(&self) -> Result<(), String> {
        let content = std::fs::read_to_string(&self.session_path)
            .map_err(|e| format!("Failed to read session file: {}", e))?;

        println!("\n{}", "─".repeat(80));
        Output::info(&format!("Raw contents of: {}", self.session_path));
        println!("{}\n", "─".repeat(80));
        println!("{}", content);
        println!("{}\n", "─".repeat(80));

        Ok(())
    }

    /// Get results for a specific phase
    fn get_phase_results(&self, phase: &str) -> Result<Vec<(String, String, String, u64)>, String> {
        let content = std::fs::read_to_string(&self.session_path)
            .map_err(|e| format!("Failed to read session file: {}", e))?;

        let mut results = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            // Parse result line: timestamp | phase | module | status | data
            let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
            if parts.len() == 5 {
                let timestamp: u64 = parts[0].parse().unwrap_or(0);
                let result_phase = parts[1];
                let module = parts[2].to_string();
                let status = parts[3].to_string();
                let data = parts[4].to_string();

                if result_phase == phase {
                    results.push((module, status, data, timestamp));
                }
            }
        }

        Ok(results)
    }

    /// Print a single result
    fn print_result(&self, module: &str, status: &str, data: &str, _timestamp: u64) {
        let status_icon = if status == "success" {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        };

        println!("  {} \x1b[1m{:<20}\x1b[0m {}", status_icon, module, data);
    }

    /// Run a new scan
    fn run_scan(&self, preset: &str) -> Result<(), String> {
        Output::info(&format!("Running {} scan...", preset));

        // Build command
        let cmd = format!("{} --preset {}", self.target, preset);

        Output::info(&format!("Command: rb {}", cmd));
        Output::warning(&format!(
            "This will execute a real scan and update the {} file",
            SessionFile::EXTENSION
        ));

        // Execute via magic scan
        use crate::cli::commands::magic;
        use crate::cli::CliContext;

        let mut ctx = CliContext::new();
        ctx.domain = Some(self.target.clone());
        ctx.raw = vec![
            self.target.clone(),
            "--preset".to_string(),
            preset.to_string(),
        ];
        ctx.flags.insert("preset".to_string(), preset.to_string());

        magic::execute(&ctx)?;

        Output::success("Scan complete! Type 'reload' to refresh results");
        Ok(())
    }

    /// Execute arbitrary command
    fn exec_command(&self, command: &str) -> Result<(), String> {
        Output::info(&format!("Executing: rb {}", command));
        Output::warning("Custom command execution not yet implemented");
        Output::info("Coming soon: ability to run any rb command from REPL");
        Ok(())
    }

    /// Reload session from disk
    fn reload_session(&mut self) -> Result<(), String> {
        self.metadata = if SessionFile::exists_from_path(&self.session_path) {
            Some(SessionFile::load_metadata_from_path(&self.session_path)?)
        } else {
            None
        };

        Output::success("Session reloaded from disk");
        self.show_summary()
    }
}

// Helper trait extension for SessionFile
trait SessionFileExt {
    fn exists_from_path(path: &str) -> bool;
    fn load_metadata_from_path(path: &str) -> Result<SessionMetadata, String>;
}

impl SessionFileExt for SessionFile {
    fn exists_from_path(path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn load_metadata_from_path(path: &str) -> Result<SessionMetadata, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read session file: {}", e))?;

        Self::parse_metadata(&content)
    }
}

/// Entry point for REPL mode
pub fn start_repl(target: String) -> Result<(), String> {
    let mut repl = Repl::new(target)?;
    repl.start()
}
