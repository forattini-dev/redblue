/// CMS Security Testing Module
///
/// Replaces: wpscan, droopescan, joomscan, cmseek
///
/// Features:
/// - Multi-CMS detection (WordPress, Drupal, Joomla, etc.)
/// - Version fingerprinting
/// - Plugin/theme enumeration
/// - User enumeration
/// - Vulnerability database
/// - WAF evasion techniques
/// - Authentication testing

pub mod types;
pub mod detect;
pub mod wordpress;
pub mod drupal;
pub mod joomla;
pub mod vulndb;
pub mod waf;
pub mod auth;

pub use types::*;
pub use detect::CmsDetector;
pub use vulndb::VulnDatabase;
pub use waf::WafEvasion;

use std::time::Duration;

/// CMS Scanner configuration
#[derive(Debug, Clone)]
pub struct CmsScanConfig {
    /// Target URL
    pub target: String,
    /// Request timeout
    pub timeout: Duration,
    /// User agent to use
    pub user_agent: String,
    /// Number of threads
    pub threads: usize,
    /// Enable aggressive scanning
    pub aggressive: bool,
    /// Enable plugin enumeration
    pub enumerate_plugins: bool,
    /// Enable theme enumeration
    pub enumerate_themes: bool,
    /// Enable user enumeration
    pub enumerate_users: bool,
    /// Custom wordlist for enumeration
    pub wordlist: Option<String>,
    /// Maximum enumeration items
    pub max_enum_items: usize,
    /// Enable WAF evasion
    pub waf_evasion: bool,
    /// Rate limit (requests per second)
    pub rate_limit: Option<f64>,
    /// Random delay range (ms)
    pub random_delay: Option<(u64, u64)>,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Custom headers
    pub headers: Vec<(String, String)>,
    /// Proxy URL
    pub proxy: Option<String>,
    /// API token for vulnerability databases
    pub api_token: Option<String>,
}

impl Default for CmsScanConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            timeout: Duration::from_secs(10),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            threads: 10,
            aggressive: false,
            enumerate_plugins: true,
            enumerate_themes: true,
            enumerate_users: true,
            wordlist: None,
            max_enum_items: 1000,
            waf_evasion: false,
            rate_limit: None,
            random_delay: None,
            follow_redirects: true,
            headers: Vec::new(),
            proxy: None,
            api_token: None,
        }
    }
}

/// Main CMS Scanner
pub struct CmsScanner {
    config: CmsScanConfig,
    detector: CmsDetector,
    vuln_db: VulnDatabase,
    waf_evasion: WafEvasion,
}

impl CmsScanner {
    pub fn new(config: CmsScanConfig) -> Self {
        Self {
            detector: CmsDetector::new(),
            vuln_db: VulnDatabase::new(),
            waf_evasion: WafEvasion::new(config.waf_evasion),
            config,
        }
    }

    /// Run full CMS scan
    pub fn scan(&self) -> CmsScanResult {
        let mut result = CmsScanResult::new(&self.config.target);

        // Step 1: Detect CMS type
        let detection = self.detector.detect(&self.config.target, &self.config);
        result.cms_type = detection.cms_type;
        result.version = detection.version.clone();
        result.confidence = detection.confidence;
        result.detection_methods = detection.methods.clone();

        if result.cms_type == CmsType::Unknown {
            return result;
        }

        // Step 2: CMS-specific scanning
        match result.cms_type {
            CmsType::WordPress => {
                let wp_result = wordpress::scan(&self.config, &detection);
                result.plugins = wp_result.plugins;
                result.themes = wp_result.themes;
                result.users = wp_result.users;
                result.interesting_findings = wp_result.findings;
            }
            CmsType::Drupal => {
                let drupal_result = drupal::scan(&self.config, &detection);
                result.plugins = drupal_result.modules;
                result.themes = drupal_result.themes;
                result.users = drupal_result.users;
                result.interesting_findings = drupal_result.findings;
            }
            CmsType::Joomla => {
                let joomla_result = joomla::scan(&self.config, &detection);
                result.plugins = joomla_result.extensions;
                result.themes = joomla_result.templates;
                result.users = joomla_result.users;
                result.interesting_findings = joomla_result.findings;
            }
            _ => {}
        }

        // Step 3: Vulnerability lookup
        if let Some(ref version) = result.version {
            result.vulnerabilities = self.vuln_db.lookup(
                result.cms_type,
                version,
                &result.plugins,
                &result.themes,
            );
        }

        // Step 4: Calculate risk score
        result.risk_score = self.calculate_risk_score(&result);

        result
    }

    /// Calculate overall risk score (0-100)
    fn calculate_risk_score(&self, result: &CmsScanResult) -> u8 {
        let mut score = 0u32;

        // Base score from vulnerabilities
        for vuln in &result.vulnerabilities {
            match vuln.severity {
                VulnSeverity::Critical => score += 25,
                VulnSeverity::High => score += 15,
                VulnSeverity::Medium => score += 8,
                VulnSeverity::Low => score += 3,
                VulnSeverity::Info => score += 1,
            }
        }

        // Outdated version penalty
        if result.version.is_some() {
            // Check if version is outdated (simplified)
            score += 10;
        }

        // Exposed user enumeration
        if !result.users.is_empty() {
            score += 5;
        }

        // Known vulnerable plugins
        for plugin in &result.plugins {
            if plugin.vulnerable {
                score += 10;
            }
        }

        score.min(100) as u8
    }
}

/// Complete CMS scan result
#[derive(Debug, Clone)]
pub struct CmsScanResult {
    /// Target URL
    pub target: String,
    /// Detected CMS type
    pub cms_type: CmsType,
    /// Detected version
    pub version: Option<String>,
    /// Detection confidence (0-100)
    pub confidence: u8,
    /// Methods used for detection
    pub detection_methods: Vec<String>,
    /// Discovered plugins/modules
    pub plugins: Vec<PluginInfo>,
    /// Discovered themes/templates
    pub themes: Vec<ThemeInfo>,
    /// Enumerated users
    pub users: Vec<UserInfo>,
    /// Known vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,
    /// Interesting findings
    pub interesting_findings: Vec<Finding>,
    /// Overall risk score (0-100)
    pub risk_score: u8,
}

impl CmsScanResult {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            cms_type: CmsType::Unknown,
            version: None,
            confidence: 0,
            detection_methods: Vec::new(),
            plugins: Vec::new(),
            themes: Vec::new(),
            users: Vec::new(),
            vulnerabilities: Vec::new(),
            interesting_findings: Vec::new(),
            risk_score: 0,
        }
    }

    /// Get risk rating string
    pub fn risk_rating(&self) -> &str {
        match self.risk_score {
            0..=20 => "Low",
            21..=50 => "Medium",
            51..=75 => "High",
            _ => "Critical",
        }
    }

    /// Count vulnerabilities by severity
    pub fn vuln_counts(&self) -> (usize, usize, usize, usize, usize) {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for vuln in &self.vulnerabilities {
            match vuln.severity {
                VulnSeverity::Critical => critical += 1,
                VulnSeverity::High => high += 1,
                VulnSeverity::Medium => medium += 1,
                VulnSeverity::Low => low += 1,
                VulnSeverity::Info => info += 1,
            }
        }

        (critical, high, medium, low, info)
    }
}
