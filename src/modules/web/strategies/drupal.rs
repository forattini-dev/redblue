/// Drupal security scanner
///
/// Replaces: droopescan (Drupal plugin for CMSmap)
///
/// Features:
/// - Drupal detection (multiple methods)
/// - Version detection
/// - Module enumeration
/// - Theme enumeration
/// - User enumeration
/// - Common vulnerabilities check
/// - Configuration file exposure
///
/// NO external dependencies - pure Rust implementation
use crate::modules::network::scanner::ScanProgress;
use crate::protocols::http::HttpClient;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DrupalScanResult {
    pub is_drupal: bool,
    pub version: Option<String>,
    pub modules: Vec<DrupalModule>,
    pub themes: Vec<DrupalTheme>,
    pub users: Vec<String>,
    pub vulnerabilities: Vec<DrupalVulnerability>,
    pub config_exposure: Vec<ConfigFile>,
}

#[derive(Debug, Clone)]
pub struct DrupalModule {
    pub name: String,
    pub version: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct DrupalTheme {
    pub name: String,
    pub version: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct DrupalVulnerability {
    pub title: String,
    pub severity: VulnSeverity,
    pub description: String,
    pub affected_versions: String,
    pub cve: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnSeverity::Critical => write!(f, "CRITICAL"),
            VulnSeverity::High => write!(f, "HIGH"),
            VulnSeverity::Medium => write!(f, "MEDIUM"),
            VulnSeverity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigFile {
    pub path: String,
    pub status: u16,
    pub risk: String,
}

pub struct DrupalScanner {
    client: HttpClient,
    aggressive: bool,
}

impl DrupalScanner {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
            aggressive: false,
        }
    }

    pub fn with_aggressive(mut self, aggressive: bool) -> Self {
        self.aggressive = aggressive;
        self
    }

    /// Main scan entry point
    pub fn scan(&self, url: &str) -> Result<DrupalScanResult, String> {
        self.scan_with_progress(url, None)
    }

    pub fn scan_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<DrupalScanResult, String> {
        const TOTAL_PHASES: usize = 6;
        fn advance_progress(
            progress: &Option<Arc<dyn ScanProgress>>,
            completed: &mut usize,
            count: usize,
        ) {
            if count == 0 {
                return;
            }
            if let Some(p) = progress.as_ref() {
                p.inc(count);
            }
            *completed += count;
        }

        let mut completed = 0usize;
        let base_url = url.trim_end_matches('/');

        // 1. Detect if it's Drupal
        let (is_drupal, version) = self.detect_drupal(base_url)?;
        advance_progress(&progress, &mut completed, 1);

        if !is_drupal {
            let remaining = TOTAL_PHASES.saturating_sub(completed);
            if remaining > 0 {
                advance_progress(&progress, &mut completed, remaining);
            }
            return Ok(DrupalScanResult {
                is_drupal: false,
                version: None,
                modules: vec![],
                themes: vec![],
                users: vec![],
                vulnerabilities: vec![],
                config_exposure: vec![],
            });
        }

        // 2. Enumerate modules
        let modules = self.enumerate_modules(base_url)?;
        advance_progress(&progress, &mut completed, 1);

        // 3. Enumerate themes
        let themes = self.enumerate_themes(base_url)?;
        advance_progress(&progress, &mut completed, 1);

        // 4. Enumerate users (if aggressive)
        let users = if self.aggressive {
            let users = self.enumerate_users(base_url)?;
            advance_progress(&progress, &mut completed, 1);
            users
        } else {
            advance_progress(&progress, &mut completed, 1);
            vec![]
        };

        // 5. Check for config file exposure
        let config_exposure = self.check_config_files(base_url)?;
        advance_progress(&progress, &mut completed, 1);

        // 6. Check for known vulnerabilities based on version
        let vulnerabilities = if let Some(ref ver) = version {
            self.check_vulnerabilities(ver)
        } else {
            vec![]
        };
        advance_progress(&progress, &mut completed, 1);

        Ok(DrupalScanResult {
            is_drupal: true,
            version,
            modules,
            themes,
            users,
            vulnerabilities,
            config_exposure,
        })
    }

    /// Detect Drupal using multiple methods
    fn detect_drupal(&self, base_url: &str) -> Result<(bool, Option<String>), String> {
        // Method 1: Check main page for Drupal signatures
        if let Ok(response) = self.client.get(base_url) {
            let body = String::from_utf8_lossy(&response.body);
            let body_lower = body.to_lowercase();

            // Look for Drupal-specific patterns
            if body_lower.contains("/sites/default/files")
                || body_lower.contains("drupal.js")
                || body_lower.contains("drupal-")
                || body_lower.contains("x-drupal-cache")
                || body.contains("Drupal.settings")
            {
                // Try to extract version
                let version = self.detect_version(base_url, &body);
                return Ok((true, version));
            }

            // Check meta generator
            if let Some(start) = body_lower.find("<meta name=\"generator\"") {
                if let Some(content_start) = body[start..].find("content=\"") {
                    let content_pos = start + content_start + 9;
                    if let Some(content_end) = body[content_pos..].find('"') {
                        let generator = &body[content_pos..content_pos + content_end];
                        if generator.to_lowercase().contains("drupal") {
                            let version = self.extract_version_from_text(generator);
                            return Ok((true, version));
                        }
                    }
                }
            }
        }

        // Method 2: Try CHANGELOG.txt
        let changelog_url = format!("{}/CHANGELOG.txt", base_url);
        if let Ok(response) = self.client.get(&changelog_url) {
            if response.status_code == 200 {
                let changelog = String::from_utf8_lossy(&response.body);
                if changelog.to_lowercase().contains("drupal") {
                    let version = changelog
                        .lines()
                        .next()
                        .and_then(|line| self.extract_version_from_text(line));
                    return Ok((true, version));
                }
            }
        }

        // Method 3: Try core/CHANGELOG.txt (Drupal 8+)
        let core_changelog = format!("{}/core/CHANGELOG.txt", base_url);
        if let Ok(response) = self.client.get(&core_changelog) {
            if response.status_code == 200 {
                let changelog = String::from_utf8_lossy(&response.body);
                let version = changelog
                    .lines()
                    .next()
                    .and_then(|line| self.extract_version_from_text(line));
                return Ok((true, version));
            }
        }

        Ok((false, None))
    }

    /// Detect Drupal version
    fn detect_version(&self, base_url: &str, body: &str) -> Option<String> {
        // Try CHANGELOG.txt first
        let changelog_url = format!("{}/CHANGELOG.txt", base_url);
        if let Ok(response) = self.client.get(&changelog_url) {
            if response.status_code == 200 {
                let changelog = String::from_utf8_lossy(&response.body);
                if let Some(first_line) = changelog.lines().next() {
                    if let Some(version) = self.extract_version_from_text(first_line) {
                        return Some(version);
                    }
                }
            }
        }

        // Try core/CHANGELOG.txt (Drupal 8+)
        let core_changelog = format!("{}/core/CHANGELOG.txt", base_url);
        if let Ok(response) = self.client.get(&core_changelog) {
            if response.status_code == 200 {
                let changelog = String::from_utf8_lossy(&response.body);
                if let Some(first_line) = changelog.lines().next() {
                    if let Some(version) = self.extract_version_from_text(first_line) {
                        return Some(version);
                    }
                }
            }
        }

        // Try extracting from body
        self.extract_version_from_text(body)
    }

    /// Extract version number from text
    fn extract_version_from_text(&self, text: &str) -> Option<String> {
        let chars: Vec<char> = text.chars().collect();
        for i in 0..chars.len() {
            if chars[i].is_ascii_digit() {
                let start = i;
                let mut end = i;

                while end < chars.len() && (chars[end].is_ascii_digit() || chars[end] == '.') {
                    end += 1;
                }

                let version = &text[start..end];
                if version.contains('.') && version.len() >= 3 {
                    return Some(version.trim_end_matches('.').to_string());
                }
            }
        }
        None
    }

    /// Enumerate installed modules
    fn enumerate_modules(&self, base_url: &str) -> Result<Vec<DrupalModule>, String> {
        let mut modules = Vec::new();
        let mut found_modules = HashSet::new();

        // Common Drupal module paths
        let module_paths = vec![
            "sites/all/modules",     // Drupal 7
            "modules",               // Drupal 8+
            "sites/default/modules", // Custom location
        ];

        // Popular modules to check
        let popular_modules = vec![
            "admin_menu",
            "views",
            "ctools",
            "token",
            "pathauto",
            "imce",
            "webform",
            "backup_migrate",
            "date",
            "entity",
            "libraries",
            "jquery_update",
            "module_filter",
            "google_analytics",
            "metatag",
            "panels",
            "ckeditor",
            "colorbox",
            "devel",
            "features",
            "field_group",
            "link",
            "rules",
            "xmlsitemap",
        ];

        for module_name in popular_modules {
            for path in &module_paths {
                let module_url =
                    format!("{}/{}/{}/{}.info", base_url, path, module_name, module_name);

                if let Ok(response) = self.client.get(&module_url) {
                    if response.status_code == 200 && !found_modules.contains(module_name) {
                        let info = String::from_utf8_lossy(&response.body);
                        let version = self.extract_module_version(&info);

                        modules.push(DrupalModule {
                            name: module_name.to_string(),
                            version,
                            path: format!("{}/{}", path, module_name),
                        });

                        found_modules.insert(module_name);
                        break;
                    }
                }
            }
        }

        Ok(modules)
    }

    /// Extract module version from .info file
    fn extract_module_version(&self, info_content: &str) -> Option<String> {
        for line in info_content.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("version") {
                if let Some(equals_pos) = line.find('=') {
                    let version = line[equals_pos + 1..].trim().trim_matches('"');
                    if !version.is_empty() {
                        return Some(version.to_string());
                    }
                }
            }
        }
        None
    }

    /// Enumerate installed themes
    fn enumerate_themes(&self, base_url: &str) -> Result<Vec<DrupalTheme>, String> {
        let mut themes = Vec::new();
        let mut found_themes = HashSet::new();

        // Common theme paths
        let theme_paths = vec![
            "sites/all/themes",     // Drupal 7
            "themes",               // Drupal 8+
            "sites/default/themes", // Custom
        ];

        // Popular themes
        let popular_themes = vec![
            "bartik",
            "garland",
            "zen",
            "omega",
            "adaptive_theme",
            "bootstrap",
            "corporate",
            "marinelli",
            "nexus",
            "seven",
            "stark",
        ];

        for theme_name in popular_themes {
            for path in &theme_paths {
                let theme_url = format!("{}/{}/{}/{}.info", base_url, path, theme_name, theme_name);

                if let Ok(response) = self.client.get(&theme_url) {
                    if response.status_code == 200 && !found_themes.contains(theme_name) {
                        let info = String::from_utf8_lossy(&response.body);
                        let version = self.extract_module_version(&info);

                        themes.push(DrupalTheme {
                            name: theme_name.to_string(),
                            version,
                            path: format!("{}/{}", path, theme_name),
                        });

                        found_themes.insert(theme_name);
                        break;
                    }
                }
            }
        }

        Ok(themes)
    }

    /// Enumerate users (aggressive mode)
    fn enumerate_users(&self, base_url: &str) -> Result<Vec<String>, String> {
        let mut users = Vec::new();

        // Try common user IDs (1-10)
        for uid in 1..=10 {
            let user_url = format!("{}/user/{}", base_url, uid);

            if let Ok(response) = self.client.get(&user_url) {
                if response.status_code == 200 {
                    let body = String::from_utf8_lossy(&response.body);

                    // Try to extract username from page title or profile
                    if let Some(title_start) = body.find("<title>") {
                        let title_pos = title_start + 7;
                        if let Some(title_end) = body[title_pos..].find("</title>") {
                            let title = &body[title_pos..title_pos + title_end];
                            // Remove site name if present
                            let username = title.split('|').next().unwrap_or(title).trim();
                            if !username.is_empty() && username != "User account" {
                                users.push(username.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(users)
    }

    /// Check for exposed configuration files
    fn check_config_files(&self, base_url: &str) -> Result<Vec<ConfigFile>, String> {
        let mut exposed = Vec::new();

        let sensitive_files = vec![
            (
                "/sites/default/settings.php",
                "Database credentials may be exposed",
                "CRITICAL",
            ),
            (
                "/sites/default/default.settings.php",
                "Default configuration file",
                "MEDIUM",
            ),
            ("/.htaccess", "Apache configuration exposed", "MEDIUM"),
            ("/web.config", "IIS configuration exposed", "MEDIUM"),
            ("/CHANGELOG.txt", "Version information disclosure", "LOW"),
            ("/INSTALL.txt", "Installation instructions exposed", "LOW"),
            ("/README.txt", "Readme file exposed", "LOW"),
            ("/core/CHANGELOG.txt", "Core version disclosure", "LOW"),
        ];

        for (path, risk, _severity) in sensitive_files {
            let url = format!("{}{}", base_url, path);

            if let Ok(response) = self.client.get(&url) {
                if response.status_code == 200 {
                    exposed.push(ConfigFile {
                        path: path.to_string(),
                        status: response.status_code,
                        risk: risk.to_string(),
                    });
                }
            }
        }

        Ok(exposed)
    }

    /// Check for known vulnerabilities based on version
    fn check_vulnerabilities(&self, version: &str) -> Vec<DrupalVulnerability> {
        let mut vulns = Vec::new();

        // Parse version (e.g., "8.9.13" -> (8, 9, 13))
        let parts: Vec<&str> = version.split('.').collect();
        if parts.is_empty() {
            return vulns;
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = if parts.len() > 1 {
            parts[1].parse().unwrap_or(0)
        } else {
            0
        };

        // Drupal 7 EOL (End of Life in 2025)
        if major == 7 {
            vulns.push(DrupalVulnerability {
                title: "Drupal 7 End of Life".to_string(),
                severity: VulnSeverity::High,
                description:
                    "Drupal 7 reaches end of life in 2025. No more security updates after EOL."
                        .to_string(),
                affected_versions: "7.x".to_string(),
                cve: None,
            });
        }

        // Drupalgeddon 2 (SA-CORE-2018-002) - CVE-2018-7600
        if (major == 7 && minor < 58) || (major == 8 && minor < 5) {
            vulns.push(DrupalVulnerability {
                title: "Drupalgeddon 2 - Remote Code Execution".to_string(),
                severity: VulnSeverity::Critical,
                description: "Critical RCE vulnerability allowing attackers to execute arbitrary code without authentication.".to_string(),
                affected_versions: "< 7.58, 8.x < 8.5.1".to_string(),
                cve: Some("CVE-2018-7600".to_string()),
            });
        }

        // Drupalgeddon 3 (SA-CORE-2018-004) - CVE-2018-7602
        if (major == 7 && minor < 59) || (major == 8 && minor < 5) {
            vulns.push(DrupalVulnerability {
                title: "Drupalgeddon 3 - Remote Code Execution".to_string(),
                severity: VulnSeverity::Critical,
                description: "RCE vulnerability related to Drupalgeddon 2, allows authenticated users to execute code.".to_string(),
                affected_versions: "< 7.59, 8.x < 8.5.3".to_string(),
                cve: Some("CVE-2018-7602".to_string()),
            });
        }

        // RESTful Web Services - CVE-2019-6340
        if major == 8 && minor < 6 {
            vulns.push(DrupalVulnerability {
                title: "RESTful Web Services RCE".to_string(),
                severity: VulnSeverity::Critical,
                description: "Remote code execution via RESTful Web Services module.".to_string(),
                affected_versions: "8.x < 8.6.10".to_string(),
                cve: Some("CVE-2019-6340".to_string()),
            });
        }

        vulns
    }
}

impl Default for DrupalScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_extraction() {
        let scanner = DrupalScanner::new();
        assert_eq!(
            scanner.extract_version_from_text("Drupal 8.9.13, 2021-02-03"),
            Some("8.9.13".to_string())
        );
        assert_eq!(
            scanner.extract_version_from_text("Version 7.58"),
            Some("7.58".to_string())
        );
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", VulnSeverity::Critical), "CRITICAL");
        assert_eq!(format!("{}", VulnSeverity::High), "HIGH");
        assert_eq!(format!("{}", VulnSeverity::Medium), "MEDIUM");
        assert_eq!(format!("{}", VulnSeverity::Low), "LOW");
    }
}
