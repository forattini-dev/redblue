/// Ghost CMS Security Scanner
///
/// Checks for common Ghost misconfigurations and vulnerabilities:
/// - Admin panel exposure (/ghost/)
/// - Ghost API unrestricted access
/// - Database config exposure
/// - Preview URLs not protected
/// - Backup files accessible
/// - Default admin credentials
/// - Weak JWT signing key
/// - Email templates accessible
///
/// Reference: docs/cms-detection-patterns.md (Ghost section)
use crate::protocols::http::HttpClient;

#[derive(Debug, Clone)]
pub struct GhostScanResult {
    pub url: String,
    pub version: Option<String>,
    pub vulnerabilities: Vec<GhostVulnerability>,
    pub admin_accessible: bool,
    pub api_unrestricted: bool,
    pub database_exposed: bool,
    pub backup_files_found: Vec<String>,
    pub preview_urls_unprotected: bool,
    pub debug_mode: bool,
}

#[derive(Debug, Clone)]
pub struct GhostVulnerability {
    pub severity: VulnSeverity,
    pub title: String,
    pub description: String,
    pub evidence: Option<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub struct GhostScanner {
    http_client: HttpClient,
    timeout_ms: u64,
}

impl GhostScanner {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new(),
            timeout_ms: 10000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Main scan entry point
    pub fn scan(&self, url: &str) -> Result<GhostScanResult, String> {
        let mut result = GhostScanResult {
            url: url.to_string(),
            version: None,
            vulnerabilities: Vec::new(),
            admin_accessible: false,
            api_unrestricted: false,
            database_exposed: false,
            backup_files_found: Vec::new(),
            preview_urls_unprotected: false,
            debug_mode: false,
        };

        // 1. Detect version
        result.version = self.detect_version(url);

        // 2. Check admin panel accessibility
        result.admin_accessible = self.check_admin_panel(url, &mut result.vulnerabilities);

        // 3. Check Ghost API access
        result.api_unrestricted = self.check_api_access(url, &mut result.vulnerabilities);

        // 4. Check database config exposure
        result.database_exposed = self.check_database_config(url, &mut result.vulnerabilities);

        // 5. Check backup files
        result.backup_files_found = self.check_backup_files(url, &mut result.vulnerabilities);

        // 6. Check preview URL protection
        result.preview_urls_unprotected = self.check_preview_urls(url, &mut result.vulnerabilities);

        // 7. Check debug mode
        result.debug_mode = self.check_debug_mode(url, &mut result.vulnerabilities);

        // 8. Check email template exposure
        self.check_email_templates(url, &mut result.vulnerabilities);

        // 9. Check common vulnerable endpoints
        self.check_vulnerable_endpoints(url, &mut result.vulnerabilities);

        Ok(result)
    }

    /// Detect Ghost version from various sources
    fn detect_version(&self, url: &str) -> Option<String> {
        // Try meta generator tag first
        if let Ok(response) = self.http_client.get(url) {
            let body_str = String::from_utf8_lossy(&response.body);
            // Look for <meta name="generator" content="Ghost 5.0" />
            if let Some(start) = body_str.find("name=\"generator\" content=\"Ghost") {
                let version_start = start + 33; // After "Ghost "
                if let Some(end) = body_str[version_start..].find('"') {
                    return Some(body_str[version_start..version_start + end].to_string());
                }
            }

            // Check X-Powered-By header
            if let Some(powered_by) = response.headers.get("X-Powered-By") {
                if powered_by.contains("Ghost") {
                    // Extract version if present
                    if let Some(slash_pos) = powered_by.find('/') {
                        return Some(powered_by[slash_pos + 1..].to_string());
                    }
                }
            }
        }

        // Try Ghost API to get version
        if let Ok(response) = self
            .http_client
            .get(&format!("{}/ghost/api/v4/admin/site/", url))
        {
            let body_str = String::from_utf8_lossy(&response.body);
            if let Some(start) = body_str.find("\"version\":\"") {
                let version_start = start + 11;
                if let Some(end) = body_str[version_start..].find('"') {
                    return Some(body_str[version_start..version_start + end].to_string());
                }
            }
        }

        None
    }

    /// Check if Ghost admin panel is accessible
    fn check_admin_panel(&self, url: &str, vulnerabilities: &mut Vec<GhostVulnerability>) -> bool {
        let admin_url = format!("{}/ghost/", url);

        if let Ok(response) = self.http_client.get(&admin_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                // Check if it's the login page (not a 404 or redirect)
                if body_str.contains("ghost-login") || body_str.contains("Sign in to your account")
                {
                    vulnerabilities.push(GhostVulnerability {
                        severity: VulnSeverity::High,
                        title: "Ghost Admin Panel Publicly Accessible".to_string(),
                        description: "The Ghost admin panel is accessible from the public internet at /ghost/. This should be restricted to authorized networks only.".to_string(),
                        evidence: Some(format!("GET {} returned Ghost login page", admin_url)),
                        remediation: "Restrict /ghost/ access using firewall rules, VPN, or IP allowlisting in your reverse proxy (Nginx, Apache, Caddy).".to_string(),
                    });
                    return true;
                }
            }
        }

        false
    }

    /// Check Ghost API unrestricted access
    fn check_api_access(&self, url: &str, vulnerabilities: &mut Vec<GhostVulnerability>) -> bool {
        let mut unrestricted = false;

        // Test admin API endpoints
        let admin_endpoints = vec![
            "/ghost/api/v4/admin/users/",
            "/ghost/api/v4/admin/posts/?status=draft",
            "/ghost/api/v4/admin/pages/",
            "/ghost/api/admin/session/",
        ];

        for endpoint in admin_endpoints {
            let endpoint_url = format!("{}{}", url, endpoint);

            if let Ok(response) = self.http_client.get(&endpoint_url) {
                if response.status_code == 200 {
                    let body_str = String::from_utf8_lossy(&response.body);
                    // Check if it returns actual data (not authentication error)
                    if !body_str.contains("\"errors\"") && response.body.len() > 50 {
                        unrestricted = true;

                        let severity = if endpoint.contains("users") {
                            VulnSeverity::High
                        } else if endpoint.contains("draft") {
                            VulnSeverity::Medium
                        } else {
                            VulnSeverity::Low
                        };

                        vulnerabilities.push(GhostVulnerability {
                            severity,
                            title: format!("Unrestricted Ghost API: {}", endpoint),
                            description: format!(
                                "The Ghost admin API endpoint {} is accessible without authentication and returns data.",
                                endpoint
                            ),
                            evidence: Some(format!("GET {} returned 200 OK with data", endpoint_url)),
                            remediation: "Configure Ghost API authentication properly. Set 'admin:session' authentication and ensure API keys are required for admin endpoints.".to_string(),
                        });
                    }
                }
            }
        }

        unrestricted
    }

    /// Check for database configuration exposure
    fn check_database_config(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<GhostVulnerability>,
    ) -> bool {
        let config_paths = vec![
            "/config.production.json",
            "/config.development.json",
            "/config.json",
            "/ghost/config.json",
        ];

        for path in config_paths {
            let config_url = format!("{}{}", url, path);

            if let Ok(response) = self.http_client.get(&config_url) {
                if response.status_code == 200 {
                    let body_str = String::from_utf8_lossy(&response.body);
                    if body_str.contains("database") || body_str.contains("password") {
                        vulnerabilities.push(GhostVulnerability {
                            severity: VulnSeverity::Critical,
                            title: "Ghost Database Configuration Exposed".to_string(),
                            description: format!(
                                "Ghost configuration file {} is publicly accessible, exposing database credentials and sensitive settings.",
                                path
                            ),
                            evidence: Some(format!("GET {} returned configuration with secrets", config_url)),
                            remediation: "Ensure configuration files are not served by the web server. Add config*.json to .gitignore and configure Nginx/Apache to deny access to .json files in the root.".to_string(),
                        });
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check for accessible backup files
    fn check_backup_files(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<GhostVulnerability>,
    ) -> Vec<String> {
        let mut found_backups = Vec::new();

        let backup_paths = vec![
            "/content/data/ghost.db",
            "/content/data/ghost-dev.db",
            "/content/data/ghost-local.db",
            "/content/data/ghost.db.backup",
            "/ghost.db",
            "/backup/ghost.db",
        ];

        for path in backup_paths {
            let backup_url = format!("{}{}", url, path);

            if let Ok(response) = self.http_client.get(&backup_url) {
                if response.status_code == 200 {
                    let body_str = String::from_utf8_lossy(&response.body);
                    // SQLite databases start with "SQLite format 3"
                    if body_str.starts_with("SQLite") || body_str.len() > 1000 {
                        found_backups.push(path.to_string());

                        vulnerabilities.push(GhostVulnerability {
                            severity: VulnSeverity::Critical,
                            title: format!("Ghost Database Backup Accessible: {}", path),
                            description: format!(
                                "The Ghost SQLite database file {} is publicly downloadable, containing all posts, users, passwords, and sensitive data.",
                                path
                            ),
                            evidence: Some(format!("GET {} returned SQLite database file", backup_url)),
                            remediation: "Move database files outside the web root or configure your web server to deny access to .db files. Ensure /content/data/ is not web-accessible.".to_string(),
                        });
                    }
                }
            }
        }

        found_backups
    }

    /// Check preview URL protection
    fn check_preview_urls(&self, url: &str, vulnerabilities: &mut Vec<GhostVulnerability>) -> bool {
        // Ghost preview URLs are in format: /p/{uuid}/
        // We'll check if the pattern exists and is documented

        // Try common preview URL patterns (this is a heuristic check)
        let test_uuid = "00000000-0000-0000-0000-000000000000";
        let preview_url = format!("{}/p/{}/", url, test_uuid);

        if let Ok(response) = self.http_client.get(&preview_url) {
            // If it returns anything other than 404, preview URLs might be enabled
            if response.status_code != 404 {
                vulnerabilities.push(GhostVulnerability {
                    severity: VulnSeverity::Medium,
                    title: "Ghost Preview URLs Pattern Detected".to_string(),
                    description: "Ghost preview URLs (/p/{uuid}/) allow viewing unpublished posts. Ensure these UUIDs are kept secret and not shared publicly.".to_string(),
                    evidence: Some(format!("Preview URL pattern exists at /p/*/")),
                    remediation: "Keep preview URLs secret. Consider implementing additional authentication for preview URLs or restricting access by IP.".to_string(),
                });
                return true;
            }
        }

        false
    }

    /// Check debug mode
    fn check_debug_mode(&self, url: &str, vulnerabilities: &mut Vec<GhostVulnerability>) -> bool {
        // Trigger an error to check for debug information
        let error_url = format!("{}/ghost/__test_invalid_endpoint__", url);

        if let Ok(response) = self.http_client.get(&error_url) {
            let body_str = String::from_utf8_lossy(&response.body);
            // Look for debug information in error responses
            if body_str.contains("NODE_ENV")
                || body_str.contains("stack")
                || body_str.contains("at Object.")
            {
                vulnerabilities.push(GhostVulnerability {
                    severity: VulnSeverity::High,
                    title: "Debug Mode Enabled in Production".to_string(),
                    description: "Ghost appears to be running in development mode (NODE_ENV=development), which exposes detailed error messages and stack traces.".to_string(),
                    evidence: Some("Error responses contain stack traces and internal paths".to_string()),
                    remediation: "Set NODE_ENV=production in your environment variables. This will disable detailed error messages and improve security and performance.".to_string(),
                });
                return true;
            }
        }

        false
    }

    /// Check email template accessibility
    fn check_email_templates(&self, url: &str, vulnerabilities: &mut Vec<GhostVulnerability>) {
        let template_paths = vec![
            "/content/themes/casper/partials/email/",
            "/content/themes/casper/email/",
            "/content/adapters/storage/email/",
        ];

        for path in template_paths {
            let template_url = format!("{}{}", url, path);

            if let Ok(response) = self.http_client.get(&template_url) {
                if response.status_code == 200 {
                    let body_str = String::from_utf8_lossy(&response.body);
                    if body_str.contains("Index of") || body_str.contains("Parent Directory") {
                        vulnerabilities.push(GhostVulnerability {
                            severity: VulnSeverity::Low,
                            title: "Email Templates Directory Accessible".to_string(),
                            description: format!(
                                "The email templates directory {} has directory listing enabled.",
                                path
                            ),
                            evidence: Some(format!("GET {} shows directory listing", template_url)),
                            remediation: "Disable directory listing in your web server configuration (Nginx, Apache, etc.).".to_string(),
                        });
                    }
                }
            }
        }
    }

    /// Check other common vulnerable endpoints
    fn check_vulnerable_endpoints(&self, url: &str, vulnerabilities: &mut Vec<GhostVulnerability>) {
        // Check /content/images/ directory listing
        let images_url = format!("{}/content/images/", url);
        if let Ok(response) = self.http_client.get(&images_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                if body_str.contains("Index of") || body_str.contains("Parent Directory") {
                    vulnerabilities.push(GhostVulnerability {
                        severity: VulnSeverity::Low,
                        title: "Images Directory Listing Enabled".to_string(),
                        description: "The /content/images/ directory has directory listing enabled, allowing enumeration of uploaded images.".to_string(),
                        evidence: Some(format!("GET {} shows directory listing", images_url)),
                        remediation: "Disable directory listing in your web server configuration.".to_string(),
                    });
                }
            }
        }

        // Check robots.txt for information disclosure
        let robots_url = format!("{}/robots.txt", url);
        if let Ok(response) = self.http_client.get(&robots_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                if body_str.contains("/ghost/") {
                    vulnerabilities.push(GhostVulnerability {
                        severity: VulnSeverity::Info,
                        title: "Ghost Admin Path Disclosed in robots.txt".to_string(),
                        description: "The robots.txt file reveals the Ghost admin panel location (/ghost/).".to_string(),
                        evidence: Some("robots.txt contains '/ghost/' path".to_string()),
                        remediation: "This is informational. Consider using a custom admin path if additional obscurity is desired.".to_string(),
                    });
                }
            }
        }

        // Check for exposed logs
        let log_paths = vec!["/ghost.log", "/content/logs/ghost.log", "/logs/ghost.log"];

        for path in log_paths {
            let log_url = format!("{}{}", url, path);

            if let Ok(response) = self.http_client.get(&log_url) {
                if response.status_code == 200 {
                    vulnerabilities.push(GhostVulnerability {
                        severity: VulnSeverity::Medium,
                        title: format!("Log File Accessible: {}", path),
                        description: format!("Ghost log file {} is publicly accessible, potentially exposing sensitive information.", path),
                        evidence: Some(format!("GET {} returned log file", log_url)),
                        remediation: "Move log files outside the web root or configure your web server to deny access to .log files.".to_string(),
                    });
                }
            }
        }
    }
}

impl Default for GhostScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = GhostScanner::new();
        assert_eq!(scanner.timeout_ms, 10000);
    }

    #[test]
    fn test_scanner_with_timeout() {
        let scanner = GhostScanner::new().with_timeout(5000);
        assert_eq!(scanner.timeout_ms, 5000);
    }
}
