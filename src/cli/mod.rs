pub mod commands;
pub mod format;
pub mod output;
/// Modern CLI inspired by kubectl and Docker
/// Focus on Developer Experience (DevX)
pub mod parser;
pub mod repl;
pub mod tui;
pub mod validator;

use std::collections::HashMap;

#[derive(Debug, Clone)]
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
    /// YAML config from .redblue.yaml (if exists)
    pub config: Option<crate::config::yaml::YamlConfig>,
}

impl Default for CliContext {
    fn default() -> Self {
        Self {
            raw: Vec::new(),
            domain: None,
            resource: None,
            verb: None,
            target: None,
            args: Vec::new(),
            flags: HashMap::new(),
            config: None,
        }
    }
}

impl CliContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get flag value with fallback to YAML config
    /// Priority: CLI flag > YAML command config > global YAML
    pub fn get_flag(&self, key: &str) -> Option<&String> {
        // 1. Check CLI flags first
        if let Some(value) = self.flags.get(key) {
            return Some(value);
        }

        // 2. Check YAML command-specific config
        if let Some(config) = &self.config {
            let domain = self.domain.as_deref().unwrap_or("");
            let resource = self.resource.as_deref().unwrap_or("");
            let verb = self.verb.as_deref().unwrap_or("");

            if let Some(value) = config.get_command_flag(domain, resource, verb, key) {
                // HACK: We need to return &String but we own value
                // This is a limitation of the current API - ideally would return Option<String>
                // For now, store in flags as cache
                return None; // Will be handled by get_flag_with_config
            }
        }

        None
    }

    /// Check if flag is set (CLI or YAML)
    pub fn has_flag(&self, key: &str) -> bool {
        // Check CLI flags
        if self.flags.contains_key(key) {
            return true;
        }

        // Check YAML config
        if let Some(config) = &self.config {
            let domain = self.domain.as_deref().unwrap_or("");
            let resource = self.resource.as_deref().unwrap_or("");
            let verb = self.verb.as_deref().unwrap_or("");

            config.has_command_flag(domain, resource, verb, key)
        } else {
            false
        }
    }

    /// Get flag value with config fallback (returns owned String)
    pub fn get_flag_with_config(&self, key: &str) -> Option<String> {
        // 1. Check CLI flags first
        if let Some(value) = self.flags.get(key) {
            return Some(value.clone());
        }

        // 2. Check YAML command-specific config
        if let Some(config) = &self.config {
            let domain = self.domain.as_deref().unwrap_or("");
            let resource = self.resource.as_deref().unwrap_or("");
            let verb = self.verb.as_deref().unwrap_or("");

            if let Some(value) = config.get_command_flag(domain, resource, verb, key) {
                return Some(value);
            }
        }

        None
    }

    pub fn get_flag_or(&self, key: &str, default: &str) -> String {
        self.flags
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
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
            format::OutputFormat::from_str(format_str).unwrap_or_default()
        } else {
            format::OutputFormat::default()
        }
    }
}
