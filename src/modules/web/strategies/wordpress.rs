/// WordPress security scanner module
///
/// Replaces: wpscan
///
/// Features:
/// - WordPress version detection
/// - Plugin enumeration and version detection
/// - Theme enumeration and version detection
/// - User enumeration
/// - Common vulnerability checks
/// - Directory listing detection
/// - XML-RPC detection
/// - Debug mode detection
///
/// NO external dependencies - pure Rust implementation
use crate::modules::network::scanner::ScanProgress;
use crate::protocols::http::HttpClient;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct WPScanResult {
    pub url: String,
    pub is_wordpress: bool,
    pub version: Option<String>,
    pub plugins: Vec<Plugin>,
    pub themes: Vec<Theme>,
    pub users: Vec<String>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone)]
pub struct Plugin {
    pub name: String,
    pub version: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub name: String,
    pub version: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub severity: VulnSeverity,
    pub title: String,
    pub description: String,
    pub path: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VulnSeverity::Critical => write!(f, "CRITICAL"),
            VulnSeverity::High => write!(f, "HIGH"),
            VulnSeverity::Medium => write!(f, "MEDIUM"),
            VulnSeverity::Low => write!(f, "LOW"),
            VulnSeverity::Info => write!(f, "INFO"),
        }
    }
}

pub struct WPScanner {
    client: HttpClient,
}

impl WPScanner {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
        }
    }

    /// Main scan entry point
    pub fn scan(&self, url: &str) -> Result<WPScanResult, String> {
        self.scan_with_progress(url, None)
    }

    pub fn scan_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<WPScanResult, String> {
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

        // 1. Detect if it's WordPress
        let is_wordpress = self.detect_wordpress(base_url)?;
        advance_progress(&progress, &mut completed, 1);
        if !is_wordpress {
            let current = completed;
            let remaining = TOTAL_PHASES.saturating_sub(current);
            if remaining > 0 {
                advance_progress(&progress, &mut completed, remaining);
            }
            return Ok(WPScanResult {
                url: base_url.to_string(),
                is_wordpress: false,
                version: None,
                plugins: Vec::new(),
                themes: Vec::new(),
                users: Vec::new(),
                vulnerabilities: Vec::new(),
            });
        }

        // 2. Detect WordPress version
        let version = self.detect_version(base_url);
        advance_progress(&progress, &mut completed, 1);

        // 3. Enumerate plugins
        let plugins = self.enumerate_plugins(base_url);
        advance_progress(&progress, &mut completed, 1);

        // 4. Enumerate themes
        let themes = self.enumerate_themes(base_url);
        advance_progress(&progress, &mut completed, 1);

        // 5. Enumerate users
        let users = self.enumerate_users(base_url);
        advance_progress(&progress, &mut completed, 1);

        // 6. Check for vulnerabilities
        let vulnerabilities = self.check_vulnerabilities(base_url, &version);
        advance_progress(&progress, &mut completed, 1);

        Ok(WPScanResult {
            url: base_url.to_string(),
            is_wordpress: true,
            version,
            plugins,
            themes,
            users,
            vulnerabilities,
        })
    }

    /// Detect if the site is running WordPress
    fn detect_wordpress(&self, base_url: &str) -> Result<bool, String> {
        // Method 1: Check for wp-content in homepage
        if let Ok(response) = self.client.get(base_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);
                if body.contains("wp-content") || body.contains("wordpress") {
                    return Ok(true);
                }
            }
        }

        // Method 2: Check for wp-login.php
        let login_url = format!("{}/wp-login.php", base_url);
        if let Ok(response) = self.client.get(&login_url) {
            if response.status_code == 200 {
                return Ok(true);
            }
        }

        // Method 3: Check for wp-admin
        let admin_url = format!("{}/wp-admin/", base_url);
        if let Ok(response) = self.client.get(&admin_url) {
            if response.status_code == 200 || response.status_code == 302 {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Detect WordPress version
    fn detect_version(&self, base_url: &str) -> Option<String> {
        // Method 1: Check meta generator tag
        if let Ok(response) = self.client.get(base_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);

                // Look for <meta name="generator" content="WordPress X.Y.Z" />
                if let Some(version) = Self::extract_version_from_meta(&body) {
                    return Some(version);
                }
            }
        }

        // Method 2: Check readme.html
        let readme_url = format!("{}/readme.html", base_url);
        if let Ok(response) = self.client.get(&readme_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);
                if let Some(version) = Self::extract_version_from_readme(&body) {
                    return Some(version);
                }
            }
        }

        // Method 3: Check RSS feed
        let feed_url = format!("{}/feed/", base_url);
        if let Ok(response) = self.client.get(&feed_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);
                if let Some(version) = Self::extract_version_from_feed(&body) {
                    return Some(version);
                }
            }
        }

        None
    }

    /// Extract version from meta generator tag
    fn extract_version_from_meta(html: &str) -> Option<String> {
        for line in html.lines() {
            if line.contains("generator") && line.contains("WordPress") {
                // Look for WordPress X.Y.Z
                if let Some(start) = line.find("WordPress ") {
                    let after_wp = &line[start + 10..];
                    if let Some(end) = after_wp.find(|c: char| !c.is_ascii_digit() && c != '.') {
                        let version = &after_wp[..end];
                        if !version.is_empty() {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract version from readme.html
    fn extract_version_from_readme(html: &str) -> Option<String> {
        for line in html.lines() {
            if line.contains("Version") {
                // Look for Version X.Y.Z
                if let Some(start) = line.find("Version ") {
                    let after = &line[start + 8..];
                    if let Some(end) = after.find(|c: char| !c.is_ascii_digit() && c != '.') {
                        let version = &after[..end];
                        if !version.is_empty() {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract version from RSS feed
    fn extract_version_from_feed(xml: &str) -> Option<String> {
        for line in xml.lines() {
            if line.contains("generator") {
                // Look for WordPress X.Y.Z or wordpress.org/?v=X.Y.Z
                if let Some(start) = line.find("?v=") {
                    let after = &line[start + 3..];
                    if let Some(end) = after.find(|c: char| !c.is_ascii_digit() && c != '.') {
                        let version = &after[..end];
                        if !version.is_empty() {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Enumerate installed plugins
    fn enumerate_plugins(&self, base_url: &str) -> Vec<Plugin> {
        let mut plugins = Vec::new();
        let mut found_names = HashSet::new();

        // Common plugin detection via directory listing
        let plugins_url = format!("{}/wp-content/plugins/", base_url);
        if let Ok(response) = self.client.get(&plugins_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);

                // Extract plugin names from directory listing or links
                for line in body.lines() {
                    if let Some(plugin_name) = Self::extract_plugin_name(line) {
                        if !found_names.contains(&plugin_name) {
                            found_names.insert(plugin_name.clone());

                            // Try to get version
                            let version = self.detect_plugin_version(base_url, &plugin_name);

                            plugins.push(Plugin {
                                name: plugin_name.clone(),
                                version,
                                path: format!("/wp-content/plugins/{}", plugin_name),
                            });
                        }
                    }
                }
            }
        }

        // Try common popular plugins
        let common_plugins = vec![
            "akismet",
            "jetpack",
            "contact-form-7",
            "yoast",
            "wordfence",
            "elementor",
            "woocommerce",
            "wpforms",
            "all-in-one-seo-pack",
            "google-analytics",
            "wp-super-cache",
            "duplicate-post",
        ];

        for plugin in common_plugins {
            if !found_names.contains(plugin) {
                let plugin_path = format!("{}/wp-content/plugins/{}/", base_url, plugin);
                if let Ok(response) = self.client.get(&plugin_path) {
                    if response.status_code == 200 || response.status_code == 403 {
                        found_names.insert(plugin.to_string());
                        let version = self.detect_plugin_version(base_url, plugin);

                        plugins.push(Plugin {
                            name: plugin.to_string(),
                            version,
                            path: format!("/wp-content/plugins/{}", plugin),
                        });
                    }
                }
            }
        }

        plugins
    }

    /// Extract plugin name from HTML line
    fn extract_plugin_name(line: &str) -> Option<String> {
        if line.contains("wp-content/plugins/") {
            if let Some(start) = line.find("wp-content/plugins/") {
                let after = &line[start + 19..];
                if let Some(end) = after.find('/') {
                    let name = &after[..end];
                    if !name.is_empty()
                        && name
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                    {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }

    /// Detect plugin version
    fn detect_plugin_version(&self, base_url: &str, plugin_name: &str) -> Option<String> {
        // Try to read readme.txt
        let readme_url = format!("{}/wp-content/plugins/{}/readme.txt", base_url, plugin_name);
        if let Ok(response) = self.client.get(&readme_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);
                for line in body.lines() {
                    if line.to_lowercase().starts_with("stable tag:") {
                        let version = line.split(':').nth(1)?.trim();
                        if !version.is_empty() {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Enumerate installed themes
    fn enumerate_themes(&self, base_url: &str) -> Vec<Theme> {
        let mut themes = Vec::new();
        let mut found_names = HashSet::new();

        // Try common themes
        let common_themes = vec![
            "twentytwentyfour",
            "twentytwentythree",
            "twentytwentytwo",
            "twentytwentyone",
            "twentytwenty",
            "twentynineteen",
            "astra",
            "oceanwp",
            "generatepress",
            "neve",
            "kadence",
        ];

        for theme in common_themes {
            let theme_path = format!("{}/wp-content/themes/{}/", base_url, theme);
            if let Ok(response) = self.client.get(&theme_path) {
                if response.status_code == 200 || response.status_code == 403 {
                    found_names.insert(theme.to_string());
                    let version = self.detect_theme_version(base_url, theme);

                    themes.push(Theme {
                        name: theme.to_string(),
                        version,
                        path: format!("/wp-content/themes/{}", theme),
                    });
                }
            }
        }

        themes
    }

    /// Detect theme version
    fn detect_theme_version(&self, base_url: &str, theme_name: &str) -> Option<String> {
        // Try to read style.css
        let style_url = format!("{}/wp-content/themes/{}/style.css", base_url, theme_name);
        if let Ok(response) = self.client.get(&style_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);
                for line in body.lines() {
                    if line.to_lowercase().starts_with("version:") {
                        let version = line.split(':').nth(1)?.trim();
                        if !version.is_empty() {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Enumerate WordPress users
    fn enumerate_users(&self, base_url: &str) -> Vec<String> {
        let mut users = Vec::new();

        // Method 1: Try REST API (WordPress 4.7+)
        let api_url = format!("{}/wp-json/wp/v2/users", base_url);
        if let Ok(response) = self.client.get(&api_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);

                // Simple JSON parsing for username fields
                for line in body.lines() {
                    if line.contains("\"slug\":") || line.contains("\"name\":") {
                        if let Some(username) = Self::extract_json_string_value(line) {
                            if !users.contains(&username) {
                                users.push(username);
                            }
                        }
                    }
                }
            }
        }

        // Method 2: Try author archives (/?author=1, /?author=2, etc.)
        for i in 1..=10 {
            let author_url = format!("{}/?author={}", base_url, i);
            if let Ok(response) = self.client.get(&author_url) {
                if response.status_code == 200 {
                    let body = String::from_utf8_lossy(&response.body);

                    // Look for author name in URL redirect or content
                    if let Some(username) = Self::extract_author_from_redirect(&body) {
                        if !users.contains(&username) {
                            users.push(username);
                        }
                    }
                }
            }
        }

        users
    }

    /// Extract JSON string value (simple parser)
    fn extract_json_string_value(line: &str) -> Option<String> {
        if let Some(start) = line.find(":\"") {
            let after = &line[start + 2..];
            if let Some(end) = after.find('"') {
                let value = &after[..end];
                if !value.is_empty()
                    && value
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    /// Extract author from redirect or content
    fn extract_author_from_redirect(html: &str) -> Option<String> {
        if let Some(pos) = html.find("/author/") {
            let after = &html[pos + 8..];
            if let Some(end) = after.find(|c: char| c == '/' || c == '"' || c.is_whitespace()) {
                let username = &after[..end];
                if !username.is_empty() {
                    return Some(username.to_string());
                }
            }
        }
        None
    }

    /// Check for common WordPress vulnerabilities
    fn check_vulnerabilities(
        &self,
        base_url: &str,
        version: &Option<String>,
    ) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // 1. Check for XML-RPC
        let xmlrpc_url = format!("{}/xmlrpc.php", base_url);
        if let Ok(response) = self.client.get(&xmlrpc_url) {
            if response.status_code == 200 || response.status_code == 405 {
                vulns.push(Vulnerability {
                    severity: VulnSeverity::Medium,
                    title: "XML-RPC Enabled".to_string(),
                    description: "XML-RPC is enabled and can be abused for brute force attacks"
                        .to_string(),
                    path: Some("/xmlrpc.php".to_string()),
                });
            }
        }

        // 2. Check for debug mode
        if let Ok(response) = self.client.get(base_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);
                if body.contains("WP_DEBUG") || body.contains("Fatal error") {
                    vulns.push(Vulnerability {
                        severity: VulnSeverity::Low,
                        title: "Debug Mode Enabled".to_string(),
                        description: "WordPress debug mode may expose sensitive information"
                            .to_string(),
                        path: None,
                    });
                }
            }
        }

        // 3. Check for directory listing
        let uploads_url = format!("{}/wp-content/uploads/", base_url);
        if let Ok(response) = self.client.get(&uploads_url) {
            if response.status_code == 200 {
                let body = String::from_utf8_lossy(&response.body);
                if body.contains("Index of") || body.contains("Parent Directory") {
                    vulns.push(Vulnerability {
                        severity: VulnSeverity::Medium,
                        title: "Directory Listing Enabled".to_string(),
                        description: "Uploads directory has directory listing enabled".to_string(),
                        path: Some("/wp-content/uploads/".to_string()),
                    });
                }
            }
        }

        // 4. Check for exposed wp-config.php backup
        let config_backup = format!("{}/wp-config.php.bak", base_url);
        if let Ok(response) = self.client.get(&config_backup) {
            if response.status_code == 200 {
                vulns.push(Vulnerability {
                    severity: VulnSeverity::Critical,
                    title: "wp-config.php Backup Exposed".to_string(),
                    description: "Backup of wp-config.php is publicly accessible".to_string(),
                    path: Some("/wp-config.php.bak".to_string()),
                });
            }
        }

        // 5. Check for old/vulnerable WordPress version
        if let Some(ref ver) = version {
            if Self::is_outdated_version(ver) {
                vulns.push(Vulnerability {
                    severity: VulnSeverity::High,
                    title: "Outdated WordPress Version".to_string(),
                    description: format!(
                        "WordPress {} is outdated and may contain known vulnerabilities",
                        ver
                    ),
                    path: None,
                });
            }
        }

        // 6. Check for user enumeration via REST API
        let users_api = format!("{}/wp-json/wp/v2/users", base_url);
        if let Ok(response) = self.client.get(&users_api) {
            if response.status_code == 200 {
                vulns.push(Vulnerability {
                    severity: VulnSeverity::Low,
                    title: "User Enumeration Possible".to_string(),
                    description: "WordPress REST API exposes user information".to_string(),
                    path: Some("/wp-json/wp/v2/users".to_string()),
                });
            }
        }

        vulns
    }

    /// Check if WordPress version is outdated
    fn is_outdated_version(version: &str) -> bool {
        // Versions older than 6.0 are considered outdated (as of 2024)
        let parts: Vec<&str> = version.split('.').collect();
        if let Some(major) = parts.get(0) {
            if let Ok(major_num) = major.parse::<u32>() {
                return major_num < 6;
            }
        }
        false
    }
}

impl Default for WPScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version_from_meta() {
        let html = r#"<meta name="generator" content="WordPress 6.4.2" />"#;
        let version = WPScanner::extract_version_from_meta(html);
        assert_eq!(version, Some("6.4.2".to_string()));
    }

    #[test]
    fn test_is_outdated_version() {
        assert!(WPScanner::is_outdated_version("5.9.3"));
        assert!(WPScanner::is_outdated_version("4.9.22"));
        assert!(!WPScanner::is_outdated_version("6.4.2"));
        assert!(!WPScanner::is_outdated_version("6.0.0"));
    }

    #[test]
    fn test_extract_plugin_name() {
        let line = r#"<a href="/wp-content/plugins/akismet/">akismet</a>"#;
        let name = WPScanner::extract_plugin_name(line);
        assert_eq!(name, Some("akismet".to_string()));
    }
}
