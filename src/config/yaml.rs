// YAML config parser - ZERO external dependencies!
// Implements minimal YAML parser for .redblue.yaml

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Parsed configuration from .redblue.yaml
#[derive(Debug, Clone)]
pub struct YamlConfig {
    pub preset: Option<String>,
    pub output_format: Option<String>,
    pub output_file: Option<String>,
    pub threads: Option<usize>,
    pub rate_limit: Option<u32>,
    pub auto_persist: Option<bool>,
    pub wordlists: HashMap<String, String>,
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

    /// Parse YAML content (minimal parser)
    fn parse(content: &str) -> Result<Self, String> {
        let mut config = YamlConfig {
            preset: None,
            output_format: None,
            output_file: None,
            threads: None,
            rate_limit: None,
            auto_persist: None,
            wordlists: HashMap::new(),
            custom: HashMap::new(),
        };

        let mut current_section: Option<String> = None;

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check for section header (ends with :)
            if trimmed.ends_with(':') && !trimmed.contains(": ") {
                current_section = Some(trimmed.trim_end_matches(':').to_string());
                continue;
            }

            // Parse key-value pairs
            if let Some((key, value)) = Self::parse_key_value(trimmed) {
                match current_section.as_deref() {
                    Some("wordlists") => {
                        config.wordlists.insert(key.to_string(), value.to_string());
                    }
                    None => {
                        // Top-level keys
                        match key {
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
                                config.auto_persist = Some(value == "true" || value == "yes" || value == "1");
                            }
                            _ => {
                                config.custom.insert(key.to_string(), value.to_string());
                            }
                        }
                    }
                    Some(_) => {
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
