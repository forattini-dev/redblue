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
        Output::info(
            "  • auto_persist: true   → Automatically save all scan results to .rdb files",
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_init_command_domain() {
        let cmd = InitCommand;
        assert_eq!(cmd.domain(), "config");
    }

    #[test]
    fn test_init_command_resource() {
        let cmd = InitCommand;
        assert_eq!(cmd.resource(), "init");
    }

    #[test]
    fn test_init_command_description() {
        let cmd = InitCommand;
        assert!(!cmd.description().is_empty());
        assert!(cmd.description().contains("config"));
    }

    #[test]
    fn test_init_command_routes() {
        let cmd = InitCommand;
        let routes = cmd.routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].verb, "create");
        assert!(routes[0].summary.contains("config"));
    }

    #[test]
    fn test_init_command_flags() {
        let cmd = InitCommand;
        let flags = cmd.flags();
        assert_eq!(flags.len(), 2);

        // Check --force flag
        let force_flag = flags.iter().find(|f| f.long == "force");
        assert!(force_flag.is_some());
        assert_eq!(force_flag.unwrap().short, Some('f'));

        // Check --output flag
        let output_flag = flags.iter().find(|f| f.long == "output");
        assert!(output_flag.is_some());
        assert_eq!(output_flag.unwrap().short, Some('o'));
        assert_eq!(
            output_flag.unwrap().default,
            Some(".redblue.yaml".to_string())
        );
    }

    #[test]
    fn test_init_command_examples() {
        let cmd = InitCommand;
        let examples = cmd.examples();
        assert!(!examples.is_empty());
        // Verify examples contain rb config commands
        for (desc, cmd) in &examples {
            assert!(!desc.is_empty());
            assert!(cmd.contains("rb config init"));
        }
    }

    #[test]
    fn test_generate_full_config_content() {
        let config = generate_full_config();

        // Verify key configuration sections exist
        assert!(config.contains("auto_persist: true"));
        assert!(config.contains("output: human"));
        assert!(config.contains("threads: 50"));
        assert!(config.contains("rate_limit: 0"));
        assert!(config.contains("wordlists:"));
        assert!(config.contains("subdomains:"));
        assert!(config.contains("directories:"));
        assert!(config.contains("parameters:"));
    }

    #[test]
    fn test_generate_full_config_is_valid_yaml_structure() {
        let config = generate_full_config();

        // Verify it looks like valid YAML (not parsing, just structure)
        assert!(config.starts_with('#')); // Comments first
        assert!(config.contains(':')); // Has key-value pairs
        assert!(!config.contains('\t')); // No tabs (YAML best practice)
    }

    #[test]
    fn test_generate_full_config_comments() {
        let config = generate_full_config();

        // Verify helpful comments are present
        assert!(config.contains("# RedBlue Configuration File"));
        assert!(config.contains("NOTES:"));
        assert!(config.contains("Command-line flags always override"));
    }

    #[test]
    fn test_execute_no_verb() {
        let cmd = InitCommand;
        let ctx = CliContext {
            raw: vec!["config".to_string(), "init".to_string()],
            domain: Some("config".to_string()),
            resource: Some("init".to_string()),
            verb: None,
            target: None,
            args: vec![],
            flags: HashMap::new(),
        };

        let result = cmd.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No verb provided"));
    }

    #[test]
    fn test_execute_invalid_verb() {
        let cmd = InitCommand;
        let ctx = CliContext {
            raw: vec![
                "config".to_string(),
                "init".to_string(),
                "invalid".to_string(),
            ],
            domain: Some("config".to_string()),
            resource: Some("init".to_string()),
            verb: Some("invalid".to_string()),
            target: None,
            args: vec![],
            flags: HashMap::new(),
        };

        let result = cmd.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid verb"));
    }

    #[test]
    fn test_create_config_in_temp_dir() {
        let cmd = InitCommand;

        // Create a unique temp directory
        let unique_id = uuid::Uuid::new_v4();
        let temp_dir = std::env::temp_dir()
            .join("redblue_init_tests")
            .join(format!("create_{}", unique_id));
        fs::create_dir_all(&temp_dir).unwrap();

        let config_path = temp_dir.join("test-config.yaml");
        let mut flags = HashMap::new();
        flags.insert(
            "output".to_string(),
            config_path.to_string_lossy().to_string(),
        );

        let ctx = CliContext {
            raw: vec![
                "config".to_string(),
                "init".to_string(),
                "create".to_string(),
            ],
            domain: Some("config".to_string()),
            resource: Some("init".to_string()),
            verb: Some("create".to_string()),
            target: None,
            args: vec![],
            flags,
        };

        let result = cmd.execute(&ctx);
        assert!(result.is_ok(), "Failed to create config: {:?}", result);

        // Verify file was created
        assert!(config_path.exists());

        // Verify content
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("auto_persist:"));
        assert!(content.contains("threads:"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_create_config_file_exists_no_force() {
        let cmd = InitCommand;

        // Create a unique temp directory
        let unique_id = uuid::Uuid::new_v4();
        let temp_dir = std::env::temp_dir()
            .join("redblue_init_tests")
            .join(format!("exists_{}", unique_id));
        fs::create_dir_all(&temp_dir).unwrap();

        let config_path = temp_dir.join("existing.yaml");

        // Create existing file
        fs::write(&config_path, "existing content").unwrap();

        let mut flags = HashMap::new();
        flags.insert(
            "output".to_string(),
            config_path.to_string_lossy().to_string(),
        );

        let ctx = CliContext {
            raw: vec![
                "config".to_string(),
                "init".to_string(),
                "create".to_string(),
            ],
            domain: Some("config".to_string()),
            resource: Some("init".to_string()),
            verb: Some("create".to_string()),
            target: None,
            args: vec![],
            flags,
        };

        let result = cmd.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));

        // Verify original file is unchanged
        let content = fs::read_to_string(&config_path).unwrap();
        assert_eq!(content, "existing content");

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_create_config_file_exists_with_force() {
        let cmd = InitCommand;

        // Create a unique temp directory
        let unique_id = uuid::Uuid::new_v4();
        let temp_dir = std::env::temp_dir()
            .join("redblue_init_tests")
            .join(format!("force_{}", unique_id));
        fs::create_dir_all(&temp_dir).unwrap();

        let config_path = temp_dir.join("forced.yaml");

        // Create existing file
        fs::write(&config_path, "old content").unwrap();

        let mut flags = HashMap::new();
        flags.insert(
            "output".to_string(),
            config_path.to_string_lossy().to_string(),
        );
        flags.insert("force".to_string(), "true".to_string());

        let ctx = CliContext {
            raw: vec![
                "config".to_string(),
                "init".to_string(),
                "create".to_string(),
            ],
            domain: Some("config".to_string()),
            resource: Some("init".to_string()),
            verb: Some("create".to_string()),
            target: None,
            args: vec![],
            flags,
        };

        let result = cmd.execute(&ctx);
        assert!(result.is_ok());

        // Verify file was overwritten
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("auto_persist:"));
        assert!(!content.contains("old content"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_create_config_default_output() {
        let cmd = InitCommand;

        // Create a unique temp directory and use it as current dir
        let unique_id = uuid::Uuid::new_v4();
        let temp_dir = std::env::temp_dir()
            .join("redblue_init_tests")
            .join(format!("default_{}", unique_id));
        fs::create_dir_all(&temp_dir).unwrap();

        // Use explicit path for testing (can't reliably change cwd in tests)
        let config_path = temp_dir.join(".redblue.yaml");
        let mut flags = HashMap::new();
        flags.insert(
            "output".to_string(),
            config_path.to_string_lossy().to_string(),
        );

        let ctx = CliContext {
            raw: vec![
                "config".to_string(),
                "init".to_string(),
                "create".to_string(),
            ],
            domain: Some("config".to_string()),
            resource: Some("init".to_string()),
            verb: Some("create".to_string()),
            target: None,
            args: vec![],
            flags,
        };

        let result = cmd.execute(&ctx);
        assert!(result.is_ok());
        assert!(config_path.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
