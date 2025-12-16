pub mod aliases;
pub mod commands;
pub mod format;
pub mod output;
/// Modern CLI inspired by kubectl and Docker
/// Focus on Developer Experience (DevX)
pub mod parser;
pub mod terminal;
pub mod tui;
pub mod validator;

use crate::storage::PersistenceConfig;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct CliContext {
    /// Full argument vector after `rb`
    pub raw: Vec<String>,
    /// Primary domain (e.g. "network", "dns")
    pub domain: Option<String>,
    /// Resource within the domain (e.g. "ports", "record")
    pub resource: Option<String>,
    /// Verb or action to perform (e.g. "scan", "lookup")
    pub verb: Option<String>,
    /// Optional target (host, domain, url, etc.)
    pub target: Option<String>,
    /// Additional positional arguments beyond the target
    pub args: Vec<String>,
    /// Parsed flags (`--flag=value`, `-f value`, etc.)
    pub flags: HashMap<String, String>,
}

impl CliContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get flag value from CLI, then from YAML config if not present.
    pub fn get_flag(&self, key: &str) -> Option<String> {
        // 1. Check CLI flags first
        let config = crate::config::yaml::YamlConfig::load_from_cwd_cached();
        // Check command-specific flags
        if let (Some(domain), Some(resource), Some(verb)) = (
            self.domain.as_deref(),
            self.resource.as_deref(),
            self.verb.as_deref(),
        ) {
            if let Some(value) = config.get_command_flag(domain, resource, verb, key) {
                return Some(value);
            }
        }

        // Check global flags/settings from YAML config (not implemented yet in yaml.rs for arbitrary keys)
        // For now, this is where it would be.

        // Check for credentials
        if key.ends_with("_key") || key == "api-key" || key == "hibp-key" {
            let service_name = key.trim_end_matches("-key").replace("-", "_"); // e.g., "hibp" from "hibp-key"
            if let Some(cred_value) = config.get_credential(&service_name, key) {
                return Some(cred_value);
            }
        }

        None
    }

    /// Check if flag is set, either from CLI or YAML config.
    pub fn has_flag(&self, key: &str) -> bool {
        // Check CLI flags
        if self.flags.contains_key(key) {
            return true;
        }

        // Check YAML config
        let config = crate::config::yaml::YamlConfig::load_from_cwd_cached();
        // Check command-specific flags
        if let (Some(domain), Some(resource), Some(verb)) = (
            self.domain.as_deref(),
            self.resource.as_deref(),
            self.verb.as_deref(),
        ) {
            if config
                .get_command_flag(domain, resource, verb, key)
                .is_some()
            {
                return true;
            }
        }
        // Check for credentials
        if key.ends_with("_key") || key == "api-key" || key == "hibp-key" {
            let service_name = key.trim_end_matches("-key").replace("-", "_");
            if config.get_credential(&service_name, key).is_some() {
                return true;
            }
        }

        false
    }

    /// Get flag value as owned string
    // This method is now effectively replaced by `get_flag`
    pub fn get_flag_with_config(&self, key: &str) -> Option<String> {
        self.get_flag(key)
    }

    pub fn get_flag_or(&self, key: &str, default: &str) -> String {
        self.get_flag(key).unwrap_or_else(|| default.to_string())
    }

    pub fn domain_only(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Get the output format from flags or default to human
    pub fn get_output_format(&self) -> format::OutputFormat {
        // Check both --output/-o and --format
        let format_str = self
            .get_flag("output")
            .or_else(|| self.get_flag("o"))
            .or_else(|| self.get_flag("format"));

        if let Some(format_str) = format_str {
            format::OutputFormat::from_str(&format_str).unwrap_or_default()
        } else {
            format::OutputFormat::default()
        }
    }

    /// Get persistence configuration from CLI flags and global config
    /// Flags: --save, --no-save, --db/--db-path, --db-password
    ///
    /// Priority: --save/--no-save flags override config.database.auto_persist
    pub fn get_persistence_config(&self) -> PersistenceConfig {
        let config = crate::config::get();

        // --no-save explicitly disables, --save explicitly enables
        // Otherwise fall back to config.database.auto_persist
        let force_save = if self.has_flag("no-save") {
            false
        } else if self.has_flag("save") {
            true
        } else {
            config.database.auto_persist
        };

        let db_path = self
            .get_flag("db")
            .or_else(|| self.get_flag("db-path"))
            .map(PathBuf::from);
        let password = self.get_flag("db-password");

        PersistenceConfig {
            db_path,
            password,
            force_save,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_context_default() {
        let ctx = CliContext::default();
        assert!(ctx.raw.is_empty());
        assert!(ctx.domain.is_none());
        assert!(ctx.resource.is_none());
        assert!(ctx.verb.is_none());
        assert!(ctx.target.is_none());
        assert!(ctx.args.is_empty());
        assert!(ctx.flags.is_empty());
    }

    #[test]
    fn test_cli_context_new() {
        let ctx = CliContext::new();
        assert!(ctx.raw.is_empty());
        assert!(ctx.domain.is_none());
    }

    #[test]
    fn test_get_flag_from_cli() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("timeout".to_string(), "5000".to_string());
        ctx.flags.insert("threads".to_string(), "100".to_string());

        assert_eq!(ctx.get_flag("timeout"), Some("5000".to_string()));
        assert_eq!(ctx.get_flag("threads"), Some("100".to_string()));
        assert_eq!(ctx.get_flag("nonexistent"), None);
    }

    #[test]
    fn test_has_flag() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("verbose".to_string(), "true".to_string());
        ctx.flags.insert("quiet".to_string(), "".to_string());

        assert!(ctx.has_flag("verbose"));
        assert!(ctx.has_flag("quiet"));
        assert!(!ctx.has_flag("nonexistent"));
    }

    #[test]
    fn test_get_flag_or() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("timeout".to_string(), "5000".to_string());

        assert_eq!(ctx.get_flag_or("timeout", "1000"), "5000");
        assert_eq!(ctx.get_flag_or("threads", "200"), "200");
    }

    #[test]
    fn test_get_flag_with_config_delegates_to_get_flag() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("key".to_string(), "value".to_string());

        assert_eq!(ctx.get_flag_with_config("key"), ctx.get_flag("key"));
        assert_eq!(
            ctx.get_flag_with_config("nonexistent"),
            ctx.get_flag("nonexistent")
        );
    }

    #[test]
    fn test_domain_only() {
        let mut ctx = CliContext::new();
        assert_eq!(ctx.domain_only(), None);

        ctx.domain = Some("network".to_string());
        assert_eq!(ctx.domain_only(), Some("network"));
    }

    #[test]
    fn test_get_output_format_default() {
        let ctx = CliContext::new();
        let format = ctx.get_output_format();
        assert_eq!(format, format::OutputFormat::default());
    }

    #[test]
    fn test_get_output_format_from_output_flag() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("output".to_string(), "json".to_string());
        let format = ctx.get_output_format();
        assert_eq!(format, format::OutputFormat::Json);
    }

    #[test]
    fn test_get_output_format_from_o_flag() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("o".to_string(), "json".to_string());
        let format = ctx.get_output_format();
        assert_eq!(format, format::OutputFormat::Json);
    }

    #[test]
    fn test_get_output_format_from_format_flag() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("format".to_string(), "json".to_string());
        let format = ctx.get_output_format();
        assert_eq!(format, format::OutputFormat::Json);
    }

    #[test]
    fn test_get_output_format_priority() {
        let mut ctx = CliContext::new();
        // --output has priority over -o and --format
        ctx.flags.insert("output".to_string(), "json".to_string());
        ctx.flags.insert("o".to_string(), "text".to_string());
        ctx.flags.insert("format".to_string(), "csv".to_string());
        let format = ctx.get_output_format();
        assert_eq!(format, format::OutputFormat::Json);
    }

    #[test]
    fn test_get_persistence_config_no_save_flag() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("no-save".to_string(), "true".to_string());

        let config = ctx.get_persistence_config();
        assert!(!config.force_save);
        assert!(config.db_path.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_get_persistence_config_save_flag() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("save".to_string(), "true".to_string());

        let config = ctx.get_persistence_config();
        assert!(config.force_save);
    }

    #[test]
    fn test_get_persistence_config_no_save_overrides_save() {
        let mut ctx = CliContext::new();
        // --no-save should override --save (checked first)
        ctx.flags.insert("no-save".to_string(), "true".to_string());
        ctx.flags.insert("save".to_string(), "true".to_string());

        let config = ctx.get_persistence_config();
        assert!(!config.force_save);
    }

    #[test]
    fn test_get_persistence_config_with_db_path() {
        let mut ctx = CliContext::new();
        ctx.flags
            .insert("db".to_string(), "/custom/path.rbdb".to_string());

        let config = ctx.get_persistence_config();
        assert_eq!(config.db_path, Some(PathBuf::from("/custom/path.rbdb")));
    }

    #[test]
    fn test_get_persistence_config_with_db_path_long() {
        let mut ctx = CliContext::new();
        ctx.flags
            .insert("db-path".to_string(), "/another/path.rbdb".to_string());

        let config = ctx.get_persistence_config();
        assert_eq!(config.db_path, Some(PathBuf::from("/another/path.rbdb")));
    }

    #[test]
    fn test_get_persistence_config_db_over_db_path() {
        let mut ctx = CliContext::new();
        // --db has priority over --db-path
        ctx.flags
            .insert("db".to_string(), "/priority/path.rbdb".to_string());
        ctx.flags
            .insert("db-path".to_string(), "/fallback/path.rbdb".to_string());

        let config = ctx.get_persistence_config();
        assert_eq!(config.db_path, Some(PathBuf::from("/priority/path.rbdb")));
    }

    #[test]
    fn test_get_persistence_config_with_password() {
        let mut ctx = CliContext::new();
        ctx.flags
            .insert("db-password".to_string(), "secret123".to_string());

        let config = ctx.get_persistence_config();
        assert_eq!(config.password, Some("secret123".to_string()));
    }

    #[test]
    fn test_get_persistence_config_full() {
        let mut ctx = CliContext::new();
        ctx.flags.insert("save".to_string(), "true".to_string());
        ctx.flags
            .insert("db".to_string(), "/data/scan.rbdb".to_string());
        ctx.flags
            .insert("db-password".to_string(), "mypassword".to_string());

        let config = ctx.get_persistence_config();
        assert!(config.force_save);
        assert_eq!(config.db_path, Some(PathBuf::from("/data/scan.rbdb")));
        assert_eq!(config.password, Some("mypassword".to_string()));
    }

    #[test]
    fn test_cli_context_with_full_command() {
        let mut ctx = CliContext::new();
        ctx.raw = vec![
            "network".to_string(),
            "ports".to_string(),
            "scan".to_string(),
            "192.168.1.1".to_string(),
        ];
        ctx.domain = Some("network".to_string());
        ctx.resource = Some("ports".to_string());
        ctx.verb = Some("scan".to_string());
        ctx.target = Some("192.168.1.1".to_string());
        ctx.flags.insert("preset".to_string(), "common".to_string());
        ctx.flags.insert("threads".to_string(), "500".to_string());

        assert_eq!(ctx.domain_only(), Some("network"));
        assert_eq!(ctx.resource.as_deref(), Some("ports"));
        assert_eq!(ctx.verb.as_deref(), Some("scan"));
        assert_eq!(ctx.target.as_deref(), Some("192.168.1.1"));
        assert_eq!(ctx.get_flag("preset"), Some("common".to_string()));
        assert_eq!(ctx.get_flag_or("threads", "200"), "500");
        assert!(ctx.has_flag("preset"));
        assert!(!ctx.has_flag("verbose"));
    }

    #[test]
    fn test_cli_context_with_args() {
        let mut ctx = CliContext::new();
        ctx.args = vec!["arg1".to_string(), "arg2".to_string(), "arg3".to_string()];

        assert_eq!(ctx.args.len(), 3);
        assert_eq!(ctx.args[0], "arg1");
        assert_eq!(ctx.args[1], "arg2");
        assert_eq!(ctx.args[2], "arg3");
    }

    #[test]
    fn test_cli_context_clone() {
        let mut ctx = CliContext::new();
        ctx.domain = Some("dns".to_string());
        ctx.flags
            .insert("server".to_string(), "8.8.8.8".to_string());

        let ctx2 = ctx.clone();
        assert_eq!(ctx2.domain, ctx.domain);
        assert_eq!(ctx2.get_flag("server"), ctx.get_flag("server"));
    }

    #[test]
    fn test_cli_context_debug() {
        let ctx = CliContext::new();
        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("CliContext"));
        assert!(debug_str.contains("raw"));
        assert!(debug_str.contains("domain"));
    }
}
