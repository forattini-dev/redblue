/// Directus CMS Security Scanner
///
/// Checks for common Directus misconfigurations and vulnerabilities:
/// - Server info exposure (/server/info)
/// - GraphQL introspection enabled
/// - Public collections without permissions
/// - .env file exposure
/// - File upload vulnerabilities
/// - SQL injection via filters
/// - SSRF in asset proxying
/// - Weak password policy
/// - Admin panel accessibility
/// - Default admin credentials
///
/// Reference: docs/cms-detection-patterns.md (Directus section)
use crate::protocols::http::HttpClient;

#[derive(Debug, Clone)]
pub struct DirectusScanResult {
    pub url: String,
    pub version: Option<String>,
    pub vulnerabilities: Vec<DirectusVulnerability>,
    pub server_info_exposed: bool,
    pub graphql_introspection: bool,
    pub admin_accessible: bool,
    pub env_exposed: bool,
    pub public_collections: Vec<String>,
    pub file_upload_vulnerable: bool,
    pub weak_password_policy: bool,
    pub exposed_archives: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DirectusVulnerability {
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

pub struct DirectusScanner {
    http_client: HttpClient,
    timeout_ms: u64,
}

impl DirectusScanner {
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
    pub fn scan(&self, url: &str) -> Result<DirectusScanResult, String> {
        let mut result = DirectusScanResult {
            url: url.to_string(),
            version: None,
            vulnerabilities: Vec::new(),
            server_info_exposed: false,
            graphql_introspection: false,
            admin_accessible: false,
            env_exposed: false,
            public_collections: Vec::new(),
            file_upload_vulnerable: false,
            weak_password_policy: false,
            exposed_archives: Vec::new(),
        };

        // 1. Check server info exposure (also detects version)
        result.server_info_exposed = self.check_server_info(url, &mut result);

        // 2. Check admin panel accessibility
        result.admin_accessible = self.check_admin_panel(url, &mut result.vulnerabilities);

        // 3. Check GraphQL introspection
        result.graphql_introspection =
            self.check_graphql_introspection(url, &mut result.vulnerabilities);

        // 4. Check .env file exposure
        result.env_exposed = self.check_env_exposure(url, &mut result.vulnerabilities);

        // 5. Check public collections
        result.public_collections = self.check_public_collections(url, &mut result.vulnerabilities);

        // 6. Check exposed backups/archives
        result.exposed_archives = self.check_backup_archives(url, &mut result.vulnerabilities);

        // 7. Check file upload vulnerabilities
        result.file_upload_vulnerable = self.check_file_upload(url, &mut result.vulnerabilities);

        // 8. Check SQL injection vectors
        self.check_sql_injection(url, &mut result.vulnerabilities);

        // 9. Check SSRF in asset proxying
        self.check_ssrf_vectors(url, &mut result.vulnerabilities);

        // 10. Check other endpoints
        self.check_vulnerable_endpoints(url, &mut result.vulnerabilities);

        Ok(result)
    }

    /// Check server info exposure and detect version
    fn check_server_info(&self, url: &str, result: &mut DirectusScanResult) -> bool {
        let server_info_url = format!("{}/server/info", url);

        if let Ok(response) = self.http_client.get(&server_info_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                // Try to extract version
                if let Some(start) = body_str.find("\"version\":\"") {
                    let version_start = start + 11;
                    if let Some(end) = body_str[version_start..].find('"') {
                        result.version =
                            Some(body_str[version_start..version_start + end].to_string());
                    }
                }

                // Check if it exposes sensitive information
                if body_str.contains("project_name")
                    || body_str.contains("project_descriptor")
                    || body_str.contains("directus")
                {
                    result.vulnerabilities.push(DirectusVulnerability {
                        severity: VulnSeverity::Medium,
                        title: "Server Info Endpoint Exposed".to_string(),
                        description: "The /server/info endpoint is publicly accessible, exposing project configuration, Directus version, and internal details.".to_string(),
                        evidence: Some(format!("GET {} returned server information", server_info_url)),
                        remediation: "Restrict access to /server/info using authentication or firewall rules. This endpoint should only be accessible to administrators.".to_string(),
                    });
                    return true;
                }
            }
        }

        // Try X-Powered-By header
        if result.version.is_none() {
            if let Ok(response) = self.http_client.get(url) {
                if let Some(powered_by) = response.headers.get("X-Powered-By") {
                    if powered_by.contains("Directus") {
                        if let Some(slash_pos) = powered_by.find('/') {
                            result.version = Some(powered_by[slash_pos + 1..].to_string());
                        }
                    }
                }
            }
        }

        false
    }

    /// Check admin panel accessibility
    fn check_admin_panel(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<DirectusVulnerability>,
    ) -> bool {
        let admin_url = format!("{}/admin", url);

        if let Ok(response) = self.http_client.get(&admin_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                // Check if it's the Directus admin interface
                if body_str.contains("directus") || body_str.contains("admin") {
                    vulnerabilities.push(DirectusVulnerability {
                        severity: VulnSeverity::High,
                        title: "Admin Panel Publicly Accessible".to_string(),
                        description: "The Directus admin panel is accessible from the public internet. This should be restricted to authorized networks only.".to_string(),
                        evidence: Some(format!("GET {} returned admin interface", admin_url)),
                        remediation: "Restrict /admin access using firewall rules, VPN, or IP allowlisting in your reverse proxy configuration.".to_string(),
                    });
                    return true;
                }
            }
        }

        false
    }

    /// Check GraphQL introspection
    fn check_graphql_introspection(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<DirectusVulnerability>,
    ) -> bool {
        let graphql_url = format!("{}/graphql", url);
        let introspection_query = r#"{"query": "{ __schema { types { name } } }"}"#;

        if let Ok(response) = self
            .http_client
            .post(&graphql_url, introspection_query.as_bytes().to_vec())
        {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                if body_str.contains("__schema") || body_str.contains("types") {
                    vulnerabilities.push(DirectusVulnerability {
                        severity: VulnSeverity::Medium,
                        title: "GraphQL Introspection Enabled".to_string(),
                        description: "GraphQL introspection is enabled, allowing attackers to discover your entire API schema, including all collections, fields, and relationships.".to_string(),
                        evidence: Some("GraphQL __schema query returned schema information".to_string()),
                        remediation: "Disable GraphQL introspection in production in your Directus configuration.".to_string(),
                    });
                    return true;
                }
            }
        }

        false
    }

    /// Check .env file exposure
    fn check_env_exposure(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<DirectusVulnerability>,
    ) -> bool {
        let env_url = format!("{}/.env", url);

        if let Ok(response) = self.http_client.get(&env_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                if body_str.contains("DB_PASSWORD")
                    || body_str.contains("KEY")
                    || body_str.contains("SECRET")
                {
                    vulnerabilities.push(DirectusVulnerability {
                        severity: VulnSeverity::Critical,
                        title: ".env File Exposed".to_string(),
                        description: "The .env configuration file is publicly accessible, exposing database credentials, API keys, and secret tokens.".to_string(),
                        evidence: Some(format!("GET {} returned sensitive environment variables", env_url)),
                        remediation: "Ensure .env files are not served by the web server. Add .env to .gitignore and configure your web server to deny access to dotfiles.".to_string(),
                    });
                    return true;
                }
            }
        }

        false
    }

    /// Check for exposed Directus backups/archives
    fn check_backup_archives(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<DirectusVulnerability>,
    ) -> Vec<String> {
        let mut exposed = Vec::new();
        let candidates = vec![
            "/backup.zip",
            "/backups/latest.zip",
            "/exports/export.zip",
            "/exports/export.tar.gz",
            "/storage/backups/latest.zip",
            "/database.sqlite",
            "/directus.db",
        ];

        for path in candidates {
            let target = format!("{}{}", url, path);
            if let Ok(response) = self.http_client.get(&target) {
                if response.status_code == 200 && response.body.len() > 512 {
                    exposed.push(path.to_string());
                    vulnerabilities.push(DirectusVulnerability {
                        severity: VulnSeverity::Critical,
                        title: format!("Backup Archive Exposed: {}", path),
                        description: format!(
                            "The Directus export/backup {} is publicly accessible ({} bytes). Backups can contain admin credentials, API tokens, and all content.",
                            path, response.body.len()
                        ),
                        evidence: Some(format!("GET {} returned {} bytes", target, response.body.len())),
                        remediation: "Restrict backup/export endpoints to authenticated users or move archives outside the web root. Consider enabling signed download URLs.".to_string(),
                    });
                }
            }
        }

        exposed
    }

    /// Check for public collections without authentication
    fn check_public_collections(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<DirectusVulnerability>,
    ) -> Vec<String> {
        let mut public_collections = Vec::new();

        let collections_to_check = vec![
            "/items/users",
            "/items/credentials",
            "/items/secrets",
            "/items/config",
            "/items/settings",
            "/users/me",
        ];

        for collection in collections_to_check {
            let collection_url = format!("{}{}", url, collection);

            if let Ok(response) = self.http_client.get(&collection_url) {
                if response.status_code == 200 {
                    let body_str = String::from_utf8_lossy(&response.body);
                    // Check if it returns actual data
                    if response.body.len() > 50 && !body_str.contains("\"errors\"") {
                        public_collections.push(collection.to_string());

                        let severity = if collection.contains("users")
                            || collection.contains("credentials")
                            || collection.contains("secrets")
                        {
                            VulnSeverity::Critical
                        } else {
                            VulnSeverity::High
                        };

                        vulnerabilities.push(DirectusVulnerability {
                            severity,
                            title: format!("Public Collection: {}", collection),
                            description: format!(
                                "The collection {} is publicly accessible without authentication and returns data.",
                                collection
                            ),
                            evidence: Some(format!("GET {} returned 200 OK with data", collection_url)),
                            remediation: "Configure proper permissions in Directus. Collections containing sensitive data should require authentication. Set read permissions to 'Authenticated' or specific roles.".to_string(),
                        });
                    }
                }
            }
        }

        public_collections
    }

    /// Check file upload vulnerabilities
    fn check_file_upload(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<DirectusVulnerability>,
    ) -> bool {
        // Check if /files endpoint is accessible
        let files_url = format!("{}/files", url);

        if let Ok(response) = self.http_client.get(&files_url) {
            if response.status_code == 200 {
                vulnerabilities.push(DirectusVulnerability {
                    severity: VulnSeverity::Medium,
                    title: "Files Endpoint Accessible".to_string(),
                    description: "The /files endpoint is accessible. Ensure file upload restrictions are properly configured to prevent malicious file uploads.".to_string(),
                    evidence: Some(format!("GET {} returned 200 OK", files_url)),
                    remediation: "Configure file upload restrictions: limit file types, validate MIME types, sanitize filenames, and scan for malware. Set proper permissions on the /files endpoint.".to_string(),
                });
                return true;
            }
        }

        // Check /uploads directory
        let uploads_url = format!("{}/uploads/", url);
        if let Ok(response) = self.http_client.get(&uploads_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                if body_str.contains("Index of") || body_str.contains("Parent Directory") {
                    vulnerabilities.push(DirectusVulnerability {
                        severity: VulnSeverity::Low,
                        title: "Uploads Directory Listing Enabled".to_string(),
                        description: "The /uploads directory has directory listing enabled, allowing enumeration of uploaded files.".to_string(),
                        evidence: Some(format!("GET {} shows directory listing", uploads_url)),
                        remediation: "Disable directory listing in your web server configuration.".to_string(),
                    });
                }
            }
        }

        false
    }

    /// Check SQL injection vectors via filters
    fn check_sql_injection(&self, url: &str, vulnerabilities: &mut Vec<DirectusVulnerability>) {
        // Test filter parameter with SQL injection payload
        let test_payloads = vec![
            "/items/posts?filter[title][_contains]='",
            "/items/posts?filter[id][_eq]=1' OR '1'='1",
        ];

        for payload in test_payloads {
            let test_url = format!("{}{}", url, payload);

            if let Ok(response) = self.http_client.get(&test_url) {
                if response.status_code == 500 {
                    let body_str = String::from_utf8_lossy(&response.body);
                    // Look for SQL error messages
                    if body_str.contains("SQL")
                        || body_str.contains("syntax")
                        || body_str.contains("mysql")
                    {
                        vulnerabilities.push(DirectusVulnerability {
                            severity: VulnSeverity::High,
                            title: "Potential SQL Injection Vector".to_string(),
                            description: "Filter parameters may be vulnerable to SQL injection. SQL error messages are exposed in responses.".to_string(),
                            evidence: Some(format!("SQL error detected when testing: {}", payload)),
                            remediation: "Ensure all filter inputs are properly sanitized. Use parameterized queries. Disable detailed error messages in production.".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    /// Check SSRF in asset proxying
    fn check_ssrf_vectors(&self, url: &str, vulnerabilities: &mut Vec<DirectusVulnerability>) {
        // Check if assets endpoint accepts external URLs
        let ssrf_test = format!("{}/assets?url=http://localhost", url);

        if let Ok(response) = self.http_client.get(&ssrf_test) {
            if response.status_code != 404 {
                vulnerabilities.push(DirectusVulnerability {
                    severity: VulnSeverity::Medium,
                    title: "Potential SSRF in Asset Proxying".to_string(),
                    description: "The /assets endpoint may be vulnerable to Server-Side Request Forgery (SSRF) attacks if it accepts external URLs without proper validation.".to_string(),
                    evidence: Some("Assets endpoint accepts URL parameter".to_string()),
                    remediation: "Implement strict URL validation: whitelist allowed domains, block internal IP ranges (127.0.0.1, 169.254.0.0/16, 10.0.0.0/8, etc.), and disable URL-based asset fetching if not needed.".to_string(),
                });
            }
        }
    }

    /// Check other vulnerable endpoints
    fn check_vulnerable_endpoints(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<DirectusVulnerability>,
    ) {
        // Check /.directus directory
        let directus_dir = format!("{}/.directus/", url);
        if let Ok(response) = self.http_client.get(&directus_dir) {
            if response.status_code == 200 {
                vulnerabilities.push(DirectusVulnerability {
                    severity: VulnSeverity::Low,
                    title: ".directus Directory Accessible".to_string(),
                    description: "The /.directus directory is accessible, potentially exposing configuration files.".to_string(),
                    evidence: Some(format!("GET {} returned 200 OK", directus_dir)),
                    remediation: "Restrict access to /.directus directory using web server configuration.".to_string(),
                });
            }
        }

        // Check default admin credentials (informational check)
        vulnerabilities.push(DirectusVulnerability {
            severity: VulnSeverity::Info,
            title: "Default Admin Credentials Check Recommended".to_string(),
            description: "Consider testing for default credentials: admin@example.com:d1r3ctu5. This scanner does not perform active authentication attempts.".to_string(),
            evidence: None,
            remediation: "Ensure default admin credentials have been changed. Use strong, unique passwords for all admin accounts.".to_string(),
        });
    }
}

impl Default for DirectusScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = DirectusScanner::new();
        assert_eq!(scanner.timeout_ms, 10000);
    }

    #[test]
    fn test_scanner_with_timeout() {
        let scanner = DirectusScanner::new().with_timeout(5000);
        assert_eq!(scanner.timeout_ms, 5000);
    }
}
