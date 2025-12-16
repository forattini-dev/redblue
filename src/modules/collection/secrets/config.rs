use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct SecretsConfig {
    pub rules_path: Option<String>,
    pub min_entropy: Option<f64>,
    pub max_file_size_mb: Option<usize>,
    pub exclude_patterns: Vec<String>,
    pub exclude_dirs: Vec<String>,
    pub allowlist: Vec<String>,
}

impl SecretsConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read secrets config file: {}", e))?;
        Self::parse_toml(&content)
    }

    /// Minimal TOML parser for SecretsConfig.
    /// Handles basic key = "value" and key = [ "value1", "value2" ] (multi-line supported)
    fn parse_toml(content: &str) -> Result<Self, String> {
        let mut config = Self::default();
        let mut current_array_key: Option<String> = None;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Handle multi-line array continuation
            if let Some(key) = &current_array_key {
                if trimmed == "]" || trimmed.starts_with(']') {
                    current_array_key = None;
                    continue;
                }
                // Parse array item "value", or "value"
                let val = trimmed.trim_end_matches(',').trim_matches('"').to_string();
                if !val.is_empty() {
                    match key.as_str() {
                        "exclude_patterns" => config.exclude_patterns.push(val),
                        "exclude_dirs" => config.exclude_dirs.push(val),
                        "allowlist" => config.allowlist.push(val),
                        _ => {}
                    }
                }
                continue;
            }

            // Handle start of array: key = [
            if trimmed.ends_with(" = [") {
                let key = trimmed.trim_end_matches(" = [").trim().to_string();
                current_array_key = Some(key);
                continue;
            }

            // Handle key = value
            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');

                match key {
                    "rules_path" => config.rules_path = Some(value.to_string()),
                    "min_entropy" => config.min_entropy = value.parse().ok(),
                    "max_file_size_mb" => config.max_file_size_mb = value.parse().ok(),
                    _ => {}
                }
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_secrets_toml() {
        let toml_content = r#"
# Secrets Scanner Configuration

rules_path = "/etc/redblue/secrets_rules.toml"
min_entropy = 3.8
max_file_size_mb = 10

exclude_patterns = [
    "*.min.js",
    "*.map",
    "*.lock"
]

exclude_dirs = [
    "node_modules",
    "vendor"
]

allowlist = [
    "my_test_secret",
    "another_safe_key"
]
"#;
        let config = SecretsConfig::parse_toml(toml_content).unwrap();

        assert_eq!(
            config.rules_path,
            Some("/etc/redblue/secrets_rules.toml".to_string())
        );
        assert_eq!(config.min_entropy, Some(3.8));
        assert_eq!(config.max_file_size_mb, Some(10));
        assert!(config.exclude_patterns.contains(&"*.min.js".to_string()));
        assert!(config.exclude_dirs.contains(&"node_modules".to_string()));
        assert!(config.allowlist.contains(&"my_test_secret".to_string()));
    }
}
