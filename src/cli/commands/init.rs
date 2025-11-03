/// Init command - Generate configuration file with all defaults
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use std::fs;
use std::path::PathBuf;

pub struct InitCommand;

impl Command for InitCommand {
    fn domain(&self) -> &str {
        "config"
    }

    fn resource(&self) -> &str {
        "init"
    }

    fn description(&self) -> &str {
        "Initialize redblue configuration file with all defaults"
    }

    fn routes(&self) -> Vec<Route> {
        vec![Route {
            verb: "create",
            summary: "Create .redblue.yaml config file in current directory",
            usage: "rb config init create",
        }]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("force", "Overwrite existing config file").with_short('f'),
            Flag::new("output", "Output file path")
                .with_short('o')
                .with_default(".redblue.yaml"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Create config in current directory",
                "rb config init create",
            ),
            ("Overwrite existing config", "rb config init create --force"),
            (
                "Create with custom name",
                "rb config init create --output my-config.yaml",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "create" => self.create_config(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                Output::info("Available verb: create");
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl InitCommand {
    fn create_config(&self, ctx: &CliContext) -> Result<(), String> {
        let output_path = ctx
            .get_flag("output")
            .cloned()
            .unwrap_or_else(|| ".redblue.yaml".to_string());

        let path = PathBuf::from(&output_path);
        let force = ctx.has_flag("force");

        // Check if file exists
        if path.exists() && !force {
            return Err(format!(
                "Config file already exists: {}\nUse --force to overwrite",
                path.display()
            ));
        }

        Output::header("RedBlue Configuration Generator");
        Output::info(&format!("Creating config file: {}", path.display()));

        let config_content = generate_full_config();

        fs::write(&path, config_content)
            .map_err(|e| format!("Failed to write config file: {}", e))?;

        Output::success(&format!("✓ Config file created: {}", path.display()));
        println!();
        Output::info("Edit this file to customize your redblue settings");
        Output::info("Key features:");
        Output::info("  • auto_persist: true   → Automatically save all scan results to .rdb files");
        Output::info("  • threads: 50          → Adjust for faster/slower scans");
        Output::info("  • preset: aggressive   → Use scanning presets");
        println!();
        Output::info("All commands will now use these settings by default");

        Ok(())
    }
}

fn generate_full_config() -> String {
    r#"# RedBlue Configuration File
# Place this file as .redblue.yaml in your working directory
# All values shown are the default settings

# Automatic persistence - saves all scan results to .rdb files
# Set to 'true' to enable global auto-save for all commands
auto_persist: true

# Scan preset: stealth, balanced, aggressive
# Controls threads, timeouts, and delay settings
# preset: aggressive

# Output format: human, json, yaml
output: human

# Number of concurrent threads for scanning operations
# Higher values = faster scans but more network load
threads: 50

# Rate limiting: requests per second (0 = no limit)
rate_limit: 0

# Output file for results (optional)
# output_file: results.json

# Custom wordlists for fuzzing and enumeration
wordlists:
  subdomains: /usr/share/wordlists/subdomains-top1000.txt
  directories: /usr/share/wordlists/common.txt
  parameters: /usr/share/wordlists/params.txt

# ============================================================================
# NOTES:
# - Command-line flags always override config file settings
# - With auto_persist enabled, all scans save to .rdb files automatically
# - RESTful commands (list, get, describe) query saved .rdb files
# - Action commands (scan, lookup, whois) perform active operations
# ============================================================================
"#
    .to_string()
}
