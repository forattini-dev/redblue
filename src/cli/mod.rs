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

    pub fn get_flag(&self, key: &str) -> Option<&String> {
        self.flags.get(key)
    }

    pub fn has_flag(&self, key: &str) -> bool {
        self.flags.contains_key(key)
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
