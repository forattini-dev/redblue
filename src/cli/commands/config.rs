// Config commands for redblue settings
// - rb config database set-password: Set database encryption password
// - rb config database clear-password: Remove stored password from keyring
// - rb config database show: Show current database configuration

use super::{Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::terminal::{confirm, read_password_with_confirm};
use crate::cli::CliContext;
use crate::storage::keyring::{clear_keyring, has_keyring_password, save_to_keyring};

pub struct ConfigDatabaseCommand;

impl Command for ConfigDatabaseCommand {
    fn domain(&self) -> &str {
        "config"
    }

    fn resource(&self) -> &str {
        "database"
    }

    fn description(&self) -> &str {
        "Database encryption and persistence configuration"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "set-password",
                summary: "Set database encryption password (stored in keyring)",
                usage: "rb config database set-password",
            },
            Route {
                verb: "clear-password",
                summary: "Remove stored password from keyring",
                usage: "rb config database clear-password",
            },
            Route {
                verb: "show",
                summary: "Show current database configuration",
                usage: "rb config database show",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![Flag::new("force", "Skip confirmation prompts").with_short('f')]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Set database password (interactive prompt)",
                "rb config database set-password",
            ),
            (
                "Clear stored password from keyring",
                "rb config database clear-password",
            ),
            ("Show database configuration", "rb config database show"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().ok_or_else(|| {
            super::print_help(self);
            "No verb provided. Use: set-password, clear-password, show".to_string()
        })?;

        match verb {
            "set-password" => self.set_password(ctx),
            "clear-password" => self.clear_password(ctx),
            "show" => self.show(ctx),
            _ => {
                super::print_help(self);
                Err(format!(
                    "Unknown verb '{}'. Use: set-password, clear-password, show",
                    verb
                ))
            }
        }
    }
}

impl ConfigDatabaseCommand {
    fn set_password(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("Set Database Encryption Password");
        println!();

        // Check if password already exists
        if has_keyring_password() {
            Output::warning("A database password is already stored in your keyring.");
            println!();

            let force = ctx.has_flag("force") || ctx.has_flag("f");
            if !force {
                let replace = confirm("Do you want to replace it?", false)
                    .map_err(|e| format!("Failed to read confirmation: {}", e))?;

                if !replace {
                    Output::info("Password not changed.");
                    return Ok(());
                }
            }
        }

        // Prompt for new password
        println!("This password will be used to encrypt all redblue databases.");
        println!("Store it safely - data cannot be recovered if lost.");
        println!();

        let password = read_password_with_confirm("Enter new password: ")
            .map_err(|e| format!("Failed to read password: {}", e))?;

        // Validate password strength (basic check)
        if password.len() < 8 {
            return Err("Password must be at least 8 characters long.".to_string());
        }

        // Save to keyring
        save_to_keyring(&password)
            .map_err(|e| format!("Failed to save password to keyring: {}", e))?;

        println!();
        Output::success("Password saved to keyring successfully!");
        Output::info("All databases will now be encrypted with this password.");
        println!("  \x1b[36mTip:\x1b[0m Use --db-password <pwd> to override per-command, or set REDBLUE_DB_KEY environment variable.");

        Ok(())
    }

    fn clear_password(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("Clear Database Password");
        println!();

        if !has_keyring_password() {
            Output::info("No password stored in keyring.");
            return Ok(());
        }

        let force = ctx.has_flag("force") || ctx.has_flag("f");
        if !force {
            Output::warning("This will remove the stored database password from your keyring.");
            Output::warning(
                "Existing encrypted databases will require --db-password flag to open.",
            );
            println!();

            let proceed = confirm("Are you sure you want to clear the password?", false)
                .map_err(|e| format!("Failed to read confirmation: {}", e))?;

            if !proceed {
                Output::info("Password not cleared.");
                return Ok(());
            }
        }

        clear_keyring().map_err(|e| format!("Failed to clear keyring: {}", e))?;

        println!();
        Output::success("Password cleared from keyring.");
        println!("  \x1b[36mTip:\x1b[0m To set a new password: rb config database set-password");

        Ok(())
    }

    fn show(&self, _ctx: &CliContext) -> Result<(), String> {
        Output::header("Database Configuration");
        println!();

        let config = crate::config::get();

        // Auto-persist setting
        let auto_persist = if config.database.auto_persist {
            "\x1b[32menabled\x1b[0m"
        } else {
            "\x1b[33mdisabled\x1b[0m"
        };
        println!("  Auto-persist:       {}", auto_persist);

        // Auto-name setting
        let auto_name = if config.database.auto_name {
            "\x1b[32menabled\x1b[0m (target-based filenames)"
        } else {
            "\x1b[33mdisabled\x1b[0m (single scan.rdb)"
        };
        println!("  Auto-name:          {}", auto_name);

        // Database directory
        let db_dir = config
            .database
            .db_dir
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "./ (current directory)".to_string());
        println!("  Database directory: {}", db_dir);

        println!();

        // Keyring status
        let has_keyring = has_keyring_password();
        let keyring_status = if has_keyring {
            "\x1b[32mstored\x1b[0m (keyring)"
        } else {
            "\x1b[33mnot set\x1b[0m"
        };
        println!("  Password status:    {}", keyring_status);

        // Check environment variable
        if std::env::var("REDBLUE_DB_KEY").is_ok() {
            println!("  Environment:        \x1b[36mREDBLUE_DB_KEY is set\x1b[0m");
        }

        println!();
        println!(
            "  \x1b[36mTip:\x1b[0m Use --save flag on commands to persist results to database."
        );
        println!(
            "  \x1b[36mTip:\x1b[0m Password priority: --db-password > REDBLUE_DB_KEY > keyring"
        );

        if !has_keyring {
            println!();
            Output::warning("No password configured. Databases will not be encrypted!");
            println!("  \x1b[36mTip:\x1b[0m Run: rb config database set-password");
        }

        Ok(())
    }
}
