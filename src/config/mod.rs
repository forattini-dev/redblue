/// Configuration management for redblue
pub mod presets;
pub mod yaml;

pub use presets::{Module, OutputFormat, Parallelism, RateLimit, ScanPreset};
pub use yaml::YamlConfig;

// Legacy config structures (from old config.rs)
use std::collections::HashMap;
use std::sync::Once;

#[derive(Debug, Clone)]
pub struct RedBlueConfig {
    pub network: NetworkConfig,
    pub web: WebConfig,
    pub recon: ReconConfig,
    pub output: OutputConfig,
    pub database: DatabaseConfig,
}

static INIT: Once = Once::new();
static mut GLOBAL_CONFIG: Option<RedBlueConfig> = None;

/// Initialize and return the global configuration (idempotent).
pub fn init() -> &'static RedBlueConfig {
    unsafe {
        INIT.call_once(|| {
            GLOBAL_CONFIG = Some(RedBlueConfig::load());
        });
        GLOBAL_CONFIG.as_ref().unwrap()
    }
}

/// Access the global configuration, loading defaults if necessary.
pub fn get() -> &'static RedBlueConfig {
    init()
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub threads: usize,
    pub timeout_ms: u64,
    pub max_retries: usize,
    pub request_delay_ms: u64,
    pub dns_resolver: String,
    pub dns_timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct WebConfig {
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
    pub headers: HashMap<String, String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ReconConfig {
    pub subdomain_wordlist: Option<String>,
    pub passive_only: bool,
    pub dns_timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct OutputConfig {
    pub format: String,
    pub color: bool,
    pub verbose: bool,
    pub save_to_file: bool,
    pub output_dir: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub auto_persist: bool,
    pub db_dir: Option<String>,
    pub auto_name: bool,
    pub format_version: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            threads: 10,
            timeout_ms: 5000,
            max_retries: 2,
            request_delay_ms: 0,
            dns_resolver: "8.8.8.8".to_string(),
            dns_timeout_ms: 3000,
        }
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            user_agent: "RedBlue/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 5,
            verify_ssl: true,
            headers: HashMap::new(),
            timeout_secs: 10,
        }
    }
}

impl Default for ReconConfig {
    fn default() -> Self {
        Self {
            subdomain_wordlist: None,
            passive_only: false,
            dns_timeout_ms: 3000,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "human".to_string(),
            color: true,
            verbose: false,
            save_to_file: false,
            output_dir: None,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            auto_persist: false,
            db_dir: None,
            auto_name: true,
            format_version: 1,
        }
    }
}

impl Default for RedBlueConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            web: WebConfig::default(),
            recon: ReconConfig::default(),
            output: OutputConfig::default(),
            database: DatabaseConfig::default(),
        }
    }
}

impl RedBlueConfig {
    pub fn load() -> Self {
        // Try to load from .redblue.toml in current directory
        if let Ok(config) = Self::load_from_file(".redblue.toml") {
            return config;
        }

        // Fallback to defaults
        Self::default()
    }

    /// Load configuration from TOML file
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        use std::fs;

        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        Self::parse_toml(&content)
    }

    /// Parse TOML configuration (simple parser, no external dependencies)
    fn parse_toml(content: &str) -> Result<Self, String> {
        let mut config = Self::default();
        let mut current_section = String::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Section headers: [section]
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len() - 1].to_string();
                continue;
            }

            // Parse key = value
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');

                match current_section.as_str() {
                    "database" => {
                        if key == "auto_persist" {
                            config.database.auto_persist = value == "true";
                        } else if key == "db_dir" {
                            config.database.db_dir = Some(value.to_string());
                        }
                    }
                    "output" => {
                        if key == "format" {
                            config.output.format = value.to_string();
                        } else if key == "color" {
                            config.output.color = value == "true";
                        } else if key == "verbose" {
                            config.output.verbose = value == "true";
                        }
                    }
                    "network" => {
                        if key == "threads" {
                            config.network.threads = value.parse().unwrap_or(10);
                        } else if key == "timeout_ms" {
                            config.network.timeout_ms = value.parse().unwrap_or(5000);
                        }
                    }
                    _ => {
                        // Unknown section, ignore
                    }
                }
            }
        }

        Ok(config)
    }

    /// Create default .redblue.toml file
    pub fn create_default_file() -> Result<(), String> {
        use std::fs;
        use std::path::Path;

        let path = ".redblue.toml";

        if Path::new(path).exists() {
            return Err("Config file already exists. Delete .redblue.toml first or edit it manually.".to_string());
        }

        let content = r#"# RedBlue Configuration File
# Auto-generated by 'rb init'
#
# This file configures redblue behavior for the current directory

[database]
# Enable automatic persistence for all commands (saves to .rdb files)
auto_persist = true

# Directory for database files (optional, defaults to current directory)
# db_dir = "./redblue-data"

[output]
# Output format: human, json, yaml
format = "human"

# Enable colored output
color = true

# Verbose mode
verbose = false

[network]
# Number of concurrent threads for scanning
threads = 10

# Connection timeout in milliseconds
timeout_ms = 5000

[web]
# User agent string
# user_agent = "RedBlue/1.0"

# Follow HTTP redirects
# follow_redirects = true

# Verify SSL certificates
# verify_ssl = true
"#;

        fs::write(path, content)
            .map_err(|e| format!("Failed to write config file: {}", e))?;

        Ok(())
    }
}
