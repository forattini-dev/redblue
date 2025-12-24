//! MCP Tool Categories - Organize and filter tools by functional area
//!
//! Allows users to selectively enable tool categories to reduce context
//! overhead and improve LLM focus on relevant capabilities.

use std::collections::HashSet;

/// Tool category for grouping related functionality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolCategory {
    /// Core discovery tools (list domains, resources, describe commands)
    Discovery,
    /// Documentation tools (search docs, get docs, index)
    Documentation,
    /// Target management (list, save, remove targets)
    Targets,
    /// Network scanning (port scan, ping, health check)
    Network,
    /// DNS operations (lookup, resolve)
    Dns,
    /// Web crawling and scraping
    Web,
    /// HAR recording and analysis
    Har,
    /// TLS certificate and audit
    Tls,
    /// Reconnaissance (WHOIS, subdomains, crt.sh, dnsdumpster, massdns)
    Recon,
    /// Vulnerability intelligence (NVD, OSV, KEV, Exploit-DB)
    Vulnerability,
    /// Threat intelligence (MITRE ATT&CK, IOC extraction)
    Intel,
    /// Evasion techniques (sandbox, antidebug, obfuscate)
    Evasion,
    /// Service fingerprinting
    Fingerprint,
    /// Direct command execution
    Command,
    /// Autonomous operations (LLM-guided scans)
    Auto,
}

impl ToolCategory {
    /// Get category from tool name
    pub fn from_tool_name(name: &str) -> Self {
        match name {
            // Discovery
            "rb.list-domains" | "rb.list-resources" | "rb.describe-command" => {
                ToolCategory::Discovery
            }

            // Documentation
            "rb.search-docs" | "rb.docs.index" | "rb.docs.get" => ToolCategory::Documentation,

            // Targets
            "rb.targets.list" | "rb.targets.save" | "rb.targets.remove" => ToolCategory::Targets,

            // Network
            "rb.network.scan" | "rb.network.ping" | "rb.network.health" => ToolCategory::Network,

            // DNS
            "rb.dns.lookup" | "rb.dns.resolve" => ToolCategory::Dns,

            // Web
            "rb.web.crawl" | "rb.web.scrape" | "rb.html.select" | "rb.web.links"
            | "rb.web.tables" => ToolCategory::Web,

            // HAR
            "rb.har.record" | "rb.har.analyze" => ToolCategory::Har,

            // TLS
            "rb.tls.cert" | "rb.tls.audit" => ToolCategory::Tls,

            // Recon
            "rb.recon.whois"
            | "rb.recon.subdomains"
            | "rb.recon.crtsh"
            | "rb.recon.dnsdumpster"
            | "rb.recon.massdns" => ToolCategory::Recon,

            // Vulnerability
            "rb.vuln.search"
            | "rb.vuln.cve"
            | "rb.vuln.kev"
            | "rb.vuln.exploit"
            | "rb.vuln.fingerprint" => ToolCategory::Vulnerability,

            // Intel
            "rb.intel.mitre.map" | "rb.intel.mitre.layer" | "rb.intel.ioc.extract" => {
                ToolCategory::Intel
            }

            // Evasion
            "rb.evasion.sandbox" | "rb.evasion.obfuscate" | "rb.evasion.antidebug" => {
                ToolCategory::Evasion
            }

            // Fingerprint
            "rb.fingerprint.service" => ToolCategory::Fingerprint,

            // Command
            "rb.command.run" => ToolCategory::Command,

            // Autonomous operations
            "rb.auto.recon" | "rb.auto.vulnscan" | "rb.auto.step" | "rb.auto.guide"
            | "rb.auto.status" | "rb.auto.stop" => ToolCategory::Auto,

            // Default to Discovery for unknown tools
            _ => ToolCategory::Discovery,
        }
    }

    /// Get category short name for display
    pub fn as_str(&self) -> &'static str {
        match self {
            ToolCategory::Discovery => "discovery",
            ToolCategory::Documentation => "docs",
            ToolCategory::Targets => "targets",
            ToolCategory::Network => "network",
            ToolCategory::Dns => "dns",
            ToolCategory::Web => "web",
            ToolCategory::Har => "har",
            ToolCategory::Tls => "tls",
            ToolCategory::Recon => "recon",
            ToolCategory::Vulnerability => "vuln",
            ToolCategory::Intel => "intel",
            ToolCategory::Evasion => "evasion",
            ToolCategory::Fingerprint => "fingerprint",
            ToolCategory::Command => "command",
            ToolCategory::Auto => "auto",
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ToolCategory::Discovery => "Core discovery tools (list domains, resources, commands)",
            ToolCategory::Documentation => "Documentation access (search, get, index)",
            ToolCategory::Targets => "Target management (list, save, remove)",
            ToolCategory::Network => "Network scanning (ports, ping, health)",
            ToolCategory::Dns => "DNS operations (lookup, resolve)",
            ToolCategory::Web => "Web crawling and scraping",
            ToolCategory::Har => "HAR recording and analysis",
            ToolCategory::Tls => "TLS certificate and security audit",
            ToolCategory::Recon => "Reconnaissance (WHOIS, subdomains, CT logs)",
            ToolCategory::Vulnerability => "Vulnerability intelligence (NVD, OSV, KEV)",
            ToolCategory::Intel => "Threat intelligence (MITRE ATT&CK, IOCs)",
            ToolCategory::Evasion => "Evasion techniques (AUTHORIZED USE ONLY)",
            ToolCategory::Fingerprint => "Service fingerprinting",
            ToolCategory::Command => "Direct command execution",
            ToolCategory::Auto => "Autonomous LLM-guided operations",
        }
    }

    /// Parse category from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "discovery" => Some(ToolCategory::Discovery),
            "docs" | "documentation" => Some(ToolCategory::Documentation),
            "targets" => Some(ToolCategory::Targets),
            "network" => Some(ToolCategory::Network),
            "dns" => Some(ToolCategory::Dns),
            "web" => Some(ToolCategory::Web),
            "har" => Some(ToolCategory::Har),
            "tls" => Some(ToolCategory::Tls),
            "recon" => Some(ToolCategory::Recon),
            "vuln" | "vulnerability" => Some(ToolCategory::Vulnerability),
            "intel" | "intelligence" => Some(ToolCategory::Intel),
            "evasion" => Some(ToolCategory::Evasion),
            "fingerprint" => Some(ToolCategory::Fingerprint),
            "command" | "cmd" => Some(ToolCategory::Command),
            "auto" | "autonomous" => Some(ToolCategory::Auto),
            _ => None,
        }
    }

    /// Get all categories
    pub fn all() -> Vec<Self> {
        vec![
            ToolCategory::Discovery,
            ToolCategory::Documentation,
            ToolCategory::Targets,
            ToolCategory::Network,
            ToolCategory::Dns,
            ToolCategory::Web,
            ToolCategory::Har,
            ToolCategory::Tls,
            ToolCategory::Recon,
            ToolCategory::Vulnerability,
            ToolCategory::Intel,
            ToolCategory::Evasion,
            ToolCategory::Fingerprint,
            ToolCategory::Command,
            ToolCategory::Auto,
        ]
    }

    /// Get tool count for this category
    pub fn tool_count(&self) -> usize {
        match self {
            ToolCategory::Discovery => 3,
            ToolCategory::Documentation => 3,
            ToolCategory::Targets => 3,
            ToolCategory::Network => 3,
            ToolCategory::Dns => 2,
            ToolCategory::Web => 5,
            ToolCategory::Har => 2,
            ToolCategory::Tls => 2,
            ToolCategory::Recon => 5,
            ToolCategory::Vulnerability => 5,
            ToolCategory::Intel => 3,
            ToolCategory::Evasion => 3,
            ToolCategory::Fingerprint => 1,
            ToolCategory::Command => 1,
            ToolCategory::Auto => 6,
        }
    }
}

/// Category configuration preset
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategoryPreset {
    /// All categories enabled
    All,
    /// Core tools only (discovery, docs, targets)
    Core,
    /// Blue team focus (network, dns, recon, vuln, intel)
    BlueTeam,
    /// Red team focus (network, recon, evasion, command)
    RedTeam,
    /// Web focus (web, har, tls, recon)
    WebSecurity,
    /// Minimal (discovery only)
    Minimal,
    /// Custom configuration (manual selection)
    Custom,
}

impl CategoryPreset {
    /// Get categories for this preset
    pub fn categories(&self) -> HashSet<ToolCategory> {
        match self {
            CategoryPreset::All => ToolCategory::all().into_iter().collect(),
            CategoryPreset::Core => vec![
                ToolCategory::Discovery,
                ToolCategory::Documentation,
                ToolCategory::Targets,
            ]
            .into_iter()
            .collect(),
            CategoryPreset::BlueTeam => vec![
                ToolCategory::Discovery,
                ToolCategory::Documentation,
                ToolCategory::Targets,
                ToolCategory::Network,
                ToolCategory::Dns,
                ToolCategory::Tls,
                ToolCategory::Recon,
                ToolCategory::Vulnerability,
                ToolCategory::Intel,
                ToolCategory::Fingerprint,
                ToolCategory::Auto,
            ]
            .into_iter()
            .collect(),
            CategoryPreset::RedTeam => vec![
                ToolCategory::Discovery,
                ToolCategory::Targets,
                ToolCategory::Network,
                ToolCategory::Dns,
                ToolCategory::Web,
                ToolCategory::Tls,
                ToolCategory::Recon,
                ToolCategory::Evasion,
                ToolCategory::Command,
                ToolCategory::Auto,
            ]
            .into_iter()
            .collect(),
            CategoryPreset::WebSecurity => vec![
                ToolCategory::Discovery,
                ToolCategory::Documentation,
                ToolCategory::Web,
                ToolCategory::Har,
                ToolCategory::Tls,
                ToolCategory::Recon,
                ToolCategory::Fingerprint,
            ]
            .into_iter()
            .collect(),
            CategoryPreset::Minimal => vec![ToolCategory::Discovery].into_iter().collect(),
            CategoryPreset::Custom => HashSet::new(),
        }
    }

    /// Get preset name
    pub fn as_str(&self) -> &'static str {
        match self {
            CategoryPreset::All => "all",
            CategoryPreset::Core => "core",
            CategoryPreset::BlueTeam => "blue-team",
            CategoryPreset::RedTeam => "red-team",
            CategoryPreset::WebSecurity => "web-security",
            CategoryPreset::Minimal => "minimal",
            CategoryPreset::Custom => "custom",
        }
    }

    /// Get preset description
    pub fn description(&self) -> &'static str {
        match self {
            CategoryPreset::All => "All categories enabled (48 tools)",
            CategoryPreset::Core => "Core tools only: discovery, docs, targets (9 tools)",
            CategoryPreset::BlueTeam => {
                "Blue team focus: network, recon, vuln, intel, auto (36 tools)"
            }
            CategoryPreset::RedTeam => "Red team focus: network, recon, evasion, auto (31 tools)",
            CategoryPreset::WebSecurity => "Web security focus: web, har, tls, recon (18 tools)",
            CategoryPreset::Minimal => "Minimal: discovery only (3 tools)",
            CategoryPreset::Custom => "Custom category selection",
        }
    }

    /// Parse preset from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "all" => Some(CategoryPreset::All),
            "core" => Some(CategoryPreset::Core),
            "blue-team" | "blueteam" | "blue" => Some(CategoryPreset::BlueTeam),
            "red-team" | "redteam" | "red" => Some(CategoryPreset::RedTeam),
            "web-security" | "websecurity" | "web" => Some(CategoryPreset::WebSecurity),
            "minimal" | "min" => Some(CategoryPreset::Minimal),
            "custom" => Some(CategoryPreset::Custom),
            _ => None,
        }
    }

    /// Get all presets
    pub fn all_presets() -> Vec<Self> {
        vec![
            CategoryPreset::All,
            CategoryPreset::Core,
            CategoryPreset::BlueTeam,
            CategoryPreset::RedTeam,
            CategoryPreset::WebSecurity,
            CategoryPreset::Minimal,
        ]
    }
}

/// Tool category configuration manager
pub struct CategoryConfig {
    /// Enabled categories
    enabled: HashSet<ToolCategory>,
    /// Current preset (if any)
    preset: CategoryPreset,
}

impl CategoryConfig {
    /// Create new config with all categories enabled
    pub fn new() -> Self {
        Self {
            enabled: ToolCategory::all().into_iter().collect(),
            preset: CategoryPreset::All,
        }
    }

    /// Create config from preset
    pub fn from_preset(preset: CategoryPreset) -> Self {
        Self {
            enabled: preset.categories(),
            preset,
        }
    }

    /// Check if a category is enabled
    pub fn is_enabled(&self, category: ToolCategory) -> bool {
        self.enabled.contains(&category)
    }

    /// Check if a tool is enabled (by name)
    pub fn is_tool_enabled(&self, tool_name: &str) -> bool {
        let category = ToolCategory::from_tool_name(tool_name);
        self.is_enabled(category)
    }

    /// Enable a category
    pub fn enable(&mut self, category: ToolCategory) {
        self.enabled.insert(category);
        self.preset = CategoryPreset::Custom;
    }

    /// Disable a category
    pub fn disable(&mut self, category: ToolCategory) {
        self.enabled.remove(&category);
        self.preset = CategoryPreset::Custom;
    }

    /// Toggle a category
    pub fn toggle(&mut self, category: ToolCategory) -> bool {
        if self.enabled.contains(&category) {
            self.enabled.remove(&category);
            self.preset = CategoryPreset::Custom;
            false
        } else {
            self.enabled.insert(category);
            self.preset = CategoryPreset::Custom;
            true
        }
    }

    /// Apply preset
    pub fn apply_preset(&mut self, preset: CategoryPreset) {
        self.enabled = preset.categories();
        self.preset = preset;
    }

    /// Get enabled categories
    pub fn enabled_categories(&self) -> &HashSet<ToolCategory> {
        &self.enabled
    }

    /// Get current preset
    pub fn current_preset(&self) -> CategoryPreset {
        self.preset
    }

    /// Count enabled tools
    pub fn enabled_tool_count(&self) -> usize {
        self.enabled.iter().map(|c| c.tool_count()).sum()
    }

    /// Get category status summary
    pub fn status_summary(&self) -> Vec<(ToolCategory, bool, usize)> {
        ToolCategory::all()
            .into_iter()
            .map(|cat| (cat, self.enabled.contains(&cat), cat.tool_count()))
            .collect()
    }

    /// Export as JSON
    pub fn to_json(&self) -> String {
        let categories: Vec<&str> = self.enabled.iter().map(|c| c.as_str()).collect();
        format!(
            r#"{{"preset":"{}","enabled":[{}],"tool_count":{}}}"#,
            self.preset.as_str(),
            categories
                .iter()
                .map(|c| format!(r#""{}""#, c))
                .collect::<Vec<_>>()
                .join(","),
            self.enabled_tool_count()
        )
    }

    /// Parse from JSON (simplified)
    pub fn from_json(json: &str) -> Option<Self> {
        // Simple parsing - look for preset first
        if let Some(start) = json.find(r#""preset":""#) {
            let rest = &json[start + 10..];
            if let Some(end) = rest.find('"') {
                let preset_str = &rest[..end];
                if let Some(preset) = CategoryPreset::from_str(preset_str) {
                    if preset != CategoryPreset::Custom {
                        return Some(Self::from_preset(preset));
                    }
                }
            }
        }

        // Look for enabled categories
        if let Some(start) = json.find(r#""enabled":["#) {
            let rest = &json[start + 11..];
            if let Some(end) = rest.find(']') {
                let cats_str = &rest[..end];
                let mut config = Self {
                    enabled: HashSet::new(),
                    preset: CategoryPreset::Custom,
                };

                for cat_str in cats_str.split(',') {
                    let cat_name = cat_str.trim().trim_matches('"');
                    if let Some(cat) = ToolCategory::from_str(cat_name) {
                        config.enabled.insert(cat);
                    }
                }

                return Some(config);
            }
        }

        None
    }
}

impl Default for CategoryConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_from_tool_name() {
        assert_eq!(
            ToolCategory::from_tool_name("rb.network.scan"),
            ToolCategory::Network
        );
        assert_eq!(
            ToolCategory::from_tool_name("rb.vuln.cve"),
            ToolCategory::Vulnerability
        );
        assert_eq!(
            ToolCategory::from_tool_name("rb.evasion.sandbox"),
            ToolCategory::Evasion
        );
    }

    #[test]
    fn test_preset_categories() {
        let core = CategoryPreset::Core.categories();
        assert!(core.contains(&ToolCategory::Discovery));
        assert!(core.contains(&ToolCategory::Documentation));
        assert!(!core.contains(&ToolCategory::Evasion));
    }

    #[test]
    fn test_config_toggle() {
        let mut config = CategoryConfig::from_preset(CategoryPreset::Minimal);
        assert!(config.is_enabled(ToolCategory::Discovery));
        assert!(!config.is_enabled(ToolCategory::Network));

        config.enable(ToolCategory::Network);
        assert!(config.is_enabled(ToolCategory::Network));
        assert_eq!(config.current_preset(), CategoryPreset::Custom);
    }

    #[test]
    fn test_config_json() {
        let config = CategoryConfig::from_preset(CategoryPreset::Core);
        let json = config.to_json();
        assert!(json.contains(r#""preset":"core""#));
        assert!(json.contains("discovery"));
    }
}
