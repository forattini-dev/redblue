// YAML config parser - ZERO external dependencies!
// Implements minimal YAML parser for .redblue.yaml

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Once;

/// Parsed configuration from .redblue.yaml
#[derive(Debug, Clone)]
pub struct YamlConfig {
    // Global flags (apply to all commands)
    pub verbose: Option<bool>,
    pub no_color: Option<bool>,
    pub output_format: Option<String>,
    pub output_file: Option<String>,

    // Legacy/common fields
    pub preset: Option<String>,
    pub threads: Option<usize>,
    pub rate_limit: Option<u32>,
    pub auto_persist: Option<bool>,

    // Wordlists
    pub wordlists: HashMap<String, String>,

    // Command-specific configs (domain.resource.verb -> flags)
    pub commands: HashMap<String, HashMap<String, String>>,

    // Custom/unknown fields
    pub custom: HashMap<String, String>,
}

impl YamlConfig {
    /// Load config from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;

        Self::parse(&content)
    }

    /// Try to load from current directory
    pub fn load_from_cwd() -> Option<Self> {
        // Try .redblue.yaml first
        if let Ok(config) = Self::load(".redblue.yaml") {
            return Some(config);
        }

        // Try .redblue.yml
        if let Ok(config) = Self::load(".redblue.yml") {
            return Some(config);
        }

        None
    }

    /// Load from current directory once and cache the result.
    pub fn load_from_cwd_cached() -> Option<&'static YamlConfig> {
        static INIT: Once = Once::new();
        static mut CACHE: Option<YamlConfig> = None;

        unsafe {
            INIT.call_once(|| {
                if let Some(cfg) = Self::load_from_cwd() {
                    CACHE = Some(cfg);
                }
            });
            CACHE.as_ref()
        }
    }

    /// Parse YAML content (minimal parser)
    fn parse(content: &str) -> Result<Self, String> {
        let mut config = YamlConfig {
            verbose: None,
            no_color: None,
            output_format: None,
            output_file: None,
            preset: None,
            threads: None,
            rate_limit: None,
            auto_persist: None,
            wordlists: HashMap::new(),
            commands: HashMap::new(),
            custom: HashMap::new(),
        };

        let mut current_section: Option<String> = None;
        let mut current_command_section: Option<String> = None;

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Detect indentation for nested sections
            let indent_level = line.len() - line.trim_start().len();

            // Check for section header (ends with :)
            if trimmed.ends_with(':') && !trimmed.contains(": ") {
                let section_name = trimmed.trim_end_matches(':').to_string();

                if indent_level == 0 {
                    // Top-level section
                    current_section = Some(section_name.clone());
                    current_command_section = None;
                } else if indent_level == 2 && current_section.is_some() {
                    // Nested section (for commands)
                    current_command_section = Some(section_name);
                }
                continue;
            }

            // Parse key-value pairs
            if let Some((key, value)) = Self::parse_key_value(trimmed) {
                match (current_section.as_deref(), current_command_section.as_ref()) {
                    // Wordlists section
                    (Some("wordlists"), None) => {
                        config.wordlists.insert(key.to_string(), value.to_string());
                    }
                    // Command-specific flags (e.g., network.nc.listen)
                    (Some("commands"), Some(cmd)) => {
                        config
                            .commands
                            .entry(cmd.clone())
                            .or_insert_with(HashMap::new)
                            .insert(key.to_string(), value.to_string());
                    }
                    // Top-level keys
                    (None, None) => match key {
                        "verbose" => {
                            config.verbose =
                                Some(value == "true" || value == "yes" || value == "1");
                        }
                        "no_color" | "no-color" => {
                            config.no_color =
                                Some(value == "true" || value == "yes" || value == "1");
                        }
                        "preset" => config.preset = Some(value.to_string()),
                        "output" | "output_format" => {
                            config.output_format = Some(value.to_string())
                        }
                        "output_file" => config.output_file = Some(value.to_string()),
                        "threads" => {
                            config.threads = value.parse().ok();
                        }
                        "rate_limit" => {
                            config.rate_limit = value.parse().ok();
                        }
                        "auto_persist" | "persist" => {
                            config.auto_persist =
                                Some(value == "true" || value == "yes" || value == "1");
                        }
                        _ => {
                            config.custom.insert(key.to_string(), value.to_string());
                        }
                    },
                    _ => {
                        config.custom.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }

        Ok(config)
    }

    /// Parse "key: value" line
    fn parse_key_value(line: &str) -> Option<(&str, &str)> {
        let mut parts = line.splitn(2, ':');
        let key = parts.next()?.trim();
        let value = parts.next()?.trim();

        // Remove quotes if present
        let value = value.trim_matches(|c| c == '"' || c == '\'');

        Some((key, value))
    }

    /// Get command-specific flag value
    /// Tries: domain.resource.verb -> domain.resource -> domain
    pub fn get_command_flag(
        &self,
        domain: &str,
        resource: &str,
        verb: &str,
        flag: &str,
    ) -> Option<String> {
        // Try full path: network.nc.listen
        let full_path = format!("{}.{}.{}", domain, resource, verb);
        if let Some(flags) = self.commands.get(&full_path) {
            if let Some(value) = flags.get(flag) {
                return Some(value.clone());
            }
        }

        // Try resource level: network.nc
        let resource_path = format!("{}.{}", domain, resource);
        if let Some(flags) = self.commands.get(&resource_path) {
            if let Some(value) = flags.get(flag) {
                return Some(value.clone());
            }
        }

        // Try domain level: network
        if let Some(flags) = self.commands.get(domain) {
            if let Some(value) = flags.get(flag) {
                return Some(value.clone());
            }
        }

        None
    }

    /// Collect all command-level flags (domain/resource/verb) with specificity overrides.
    pub fn command_flags(
        &self,
        domain: &str,
        resource: &str,
        verb: &str,
    ) -> HashMap<String, String> {
        let mut merged = HashMap::new();

        if domain.is_empty() {
            return merged;
        }

        if let Some(flags) = self.commands.get(domain) {
            merged.extend(flags.clone());
        }

        if !resource.is_empty() {
            let resource_path = format!("{}.{}", domain, resource);
            if let Some(flags) = self.commands.get(&resource_path) {
                merged.extend(flags.clone());
            }
        }

        if !resource.is_empty() && !verb.is_empty() {
            let full_path = format!("{}.{}.{}", domain, resource, verb);
            if let Some(flags) = self.commands.get(&full_path) {
                merged.extend(flags.clone());
            }
        }

        merged
    }

    /// Check if command flag is set to true
    pub fn has_command_flag(&self, domain: &str, resource: &str, verb: &str, flag: &str) -> bool {
        if let Some(value) = self.get_command_flag(domain, resource, verb, flag) {
            value == "true" || value == "yes" || value == "1"
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let yaml = r#"
# RedBlue config
preset: stealth
output: json
threads: 20
rate_limit: 10
"#;

        let config = YamlConfig::parse(yaml).unwrap();
        assert_eq!(config.preset, Some("stealth".to_string()));
        assert_eq!(config.output_format, Some("json".to_string()));
        assert_eq!(config.threads, Some(20));
        assert_eq!(config.rate_limit, Some(10));
    }

    #[test]
    fn test_parse_wordlists() {
        let yaml = r#"
preset: aggressive
wordlists:
  subdomains: /usr/share/wordlists/subdomains.txt
  directories: /usr/share/wordlists/dirs.txt
"#;

        let config = YamlConfig::parse(yaml).unwrap();
        assert_eq!(config.wordlists.len(), 2);
        assert!(config.wordlists.contains_key("subdomains"));
    }

    #[test]
    fn test_parse_quoted_values() {
        let yaml = r#"
output_file: "results.json"
preset: 'stealth'
"#;

        let config = YamlConfig::parse(yaml).unwrap();
        assert_eq!(config.output_file, Some("results.json".to_string()));
        assert_eq!(config.preset, Some("stealth".to_string()));
    }
}
