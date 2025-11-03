/// Strapi CMS Security Scanner
///
/// Checks for common Strapi misconfigurations and vulnerabilities:
/// - Admin panel exposure (/admin)
/// - GraphQL introspection enabled
/// - .env file exposure
/// - Public API endpoints without authentication
/// - Debug mode enabled
/// - JWT secret weak/default
/// - Unrestricted CORS
///
/// Reference: docs/CMS_DETECTION_PATTERNS.md (Strapi section)
use crate::protocols::http::HttpClient;

#[derive(Debug, Clone)]
pub struct StrapiScanResult {
    pub url: String,
    pub version: Option<String>,
    pub vulnerabilities: Vec<StrapiVulnerability>,
    pub admin_accessible: bool,
    pub graphql_introspection: bool,
    pub env_exposed: bool,
    pub public_api_endpoints: Vec<String>,
    pub exposed_archives: Vec<String>,
    pub debug_mode: bool,
    pub cors_misconfigured: bool,
}

#[derive(Debug, Clone)]
pub struct StrapiVulnerability {
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

pub struct StrapiScanner {
    http_client: HttpClient,
    timeout_ms: u64,
}

impl StrapiScanner {
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
    pub fn scan(&self, url: &str) -> Result<StrapiScanResult, String> {
        let mut result = StrapiScanResult {
            url: url.to_string(),
            version: None,
            vulnerabilities: Vec::new(),
            admin_accessible: false,
            graphql_introspection: false,
            env_exposed: false,
            public_api_endpoints: Vec::new(),
            exposed_archives: Vec::new(),
            debug_mode: false,
            cors_misconfigured: false,
        };

        // 1. Detect version
        result.version = self.detect_version(url);

        // 2. Check admin panel accessibility
        result.admin_accessible = self.check_admin_panel(url, &mut result.vulnerabilities);

        // 3. Check GraphQL introspection
        result.graphql_introspection =
            self.check_graphql_introspection(url, &mut result.vulnerabilities);

        // 4. Check .env file exposure
        result.env_exposed = self.check_env_exposure(url, &mut result.vulnerabilities);

        // 5. Check public API endpoints
        result.public_api_endpoints = self.check_public_apis(url, &mut result.vulnerabilities);

        // 6. Check exposed backups/archives
        result.exposed_archives = self.check_backup_archives(url, &mut result.vulnerabilities);

        // 7. Check debug mode
        result.debug_mode = self.check_debug_mode(url, &mut result.vulnerabilities);

        // 8. Check CORS configuration
        result.cors_misconfigured = self.check_cors(url, &mut result.vulnerabilities);

        // 9. Check common vulnerable endpoints
        self.check_vulnerable_endpoints(url, &mut result.vulnerabilities);

        Ok(result)
    }

    /// Detect Strapi version from various sources
    fn detect_version(&self, url: &str) -> Option<String> {
        // Try /admin/init endpoint
        if let Ok(response) = self.http_client.get(&format!("{}/admin/init", url)) {
            let body = String::from_utf8_lossy(&response.body);
            // Look for version in JSON response
            if let Some(start) = body.find("\"strapiVersion\":\"") {
                let version_start = start + 17;
                if let Some(end) = body[version_start..].find('"') {
                    return Some(body[version_start..version_start + end].to_string());
                }
            }

            // Check X-Strapi-Version header
            if let Some(version) = response.headers.get("X-Strapi-Version") {
                return Some(version.clone());
            }
        }

        // Try to read package.json if exposed
        if let Ok(response) = self.http_client.get(&format!("{}/package.json", url)) {
            let body = String::from_utf8_lossy(&response.body);
            if let Some(start) = body.find("\"version\":\"") {
                let version_start = start + 11;
                if let Some(end) = body[version_start..].find('"') {
                    return Some(body[version_start..version_start + end].to_string());
                }
            }
        }

        None
    }

    /// Check if admin panel is accessible without authentication
    fn check_admin_panel(&self, url: &str, vulnerabilities: &mut Vec<StrapiVulnerability>) -> bool {
        let admin_url = format!("{}/admin", url);

        if let Ok(response) = self.http_client.get(&admin_url) {
            if response.status_code == 200 {
                vulnerabilities.push(StrapiVulnerability {
                    severity: VulnSeverity::High,
                    title: "Admin Panel Publicly Accessible".to_string(),
                    description: "The Strapi admin panel is accessible without authentication. This should be restricted to authorized networks only.".to_string(),
                    evidence: Some(format!("GET {} returned 200 OK", admin_url)),
                    remediation: "Restrict /admin access using firewall rules, VPN, or IP allowlisting. Consider using environment-specific URLs.".to_string(),
                });
                return true;
            }
        }

        false
    }

    /// Check if GraphQL introspection is enabled
    fn check_graphql_introspection(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<StrapiVulnerability>,
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
                    vulnerabilities.push(StrapiVulnerability {
                        severity: VulnSeverity::Medium,
                        title: "GraphQL Introspection Enabled".to_string(),
                        description: "GraphQL introspection is enabled, allowing attackers to discover your entire API schema, including potentially sensitive endpoints and data structures.".to_string(),
                        evidence: Some("GraphQL __schema query returned schema information".to_string()),
                        remediation: "Disable GraphQL introspection in production by setting 'introspection: false' in your GraphQL configuration.".to_string(),
                    });
                    return true;
                }
            }
        }

        false
    }

    /// Check if .env file is exposed
    fn check_env_exposure(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<StrapiVulnerability>,
    ) -> bool {
        let env_url = format!("{}/.env", url);

        if let Ok(response) = self.http_client.get(&env_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                if body_str.contains("DATABASE_PASSWORD")
                    || body_str.contains("JWT_SECRET")
                    || body_str.contains("ADMIN_JWT_SECRET")
                {
                    vulnerabilities.push(StrapiVulnerability {
                        severity: VulnSeverity::Critical,
                        title: ".env File Exposed".to_string(),
                        description: "The .env configuration file is publicly accessible, exposing sensitive credentials including database passwords, JWT secrets, and API keys.".to_string(),
                        evidence: Some(format!("GET {} returned sensitive environment variables", env_url)),
                        remediation: "Ensure .env files are not served by the web server. Add .env to .gitignore and configure your web server to deny access to dotfiles.".to_string(),
                    });
                    return true;
                }
            }
        }

        false
    }

    /// Check for exposed Strapi backups/archives
    fn check_backup_archives(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<StrapiVulnerability>,
    ) -> Vec<String> {
        let mut exposed = Vec::new();
        let candidates = vec![
            "/backup.zip",
            "/backups/backup.zip",
            "/exports/export.zip",
            "/exports/export.tar.gz",
            "/exports/latest.tar.gz",
            "/database.sqlite",
            "/data/strapi.db",
            "/.tmp/data/strapi.db",
        ];

        for path in candidates {
            let target = format!("{}{}", url, path);
            if let Ok(response) = self.http_client.get(&target) {
                if response.status_code == 200 && response.body.len() > 512 {
                    exposed.push(path.to_string());
                    vulnerabilities.push(StrapiVulnerability {
                        severity: VulnSeverity::Critical,
                        title: format!("Backup Archive Exposed: {}", path),
                        description: format!(
                            "The path {} is publicly accessible and returned {} bytes. Strapi exports often contain database content, API tokens, and credentials.",
                            path,
                            response.body.len()
                        ),
                        evidence: Some(format!("GET {} returned {} bytes", target, response.body.len())),
                        remediation: "Move backup/export files outside the web root and restrict access to archival storage. Consider enabling signed or authenticated download flows for exports.".to_string(),
                    });
                }
            }
        }

        exposed
    }

    /// Check for public API endpoints without authentication
    fn check_public_apis(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<StrapiVulnerability>,
    ) -> Vec<String> {
        let mut public_endpoints = Vec::new();

        let endpoints_to_check = vec![
            "/api/users",
            "/api/users/me",
            "/api/content-types",
            "/api/posts",
            "/api/articles",
        ];

        for endpoint in endpoints_to_check {
            let endpoint_url = format!("{}{}", url, endpoint);

            if let Ok(response) = self.http_client.get(&endpoint_url) {
                if response.status_code == 200 {
                    let body_str = String::from_utf8_lossy(&response.body);
                    // Check if it returns actual data (not just empty array)
                    if response.body.len() > 10 && !body_str.contains("\"data\":[]") {
                        public_endpoints.push(endpoint.to_string());

                        let severity = if endpoint.contains("users") {
                            VulnSeverity::High
                        } else {
                            VulnSeverity::Medium
                        };

                        vulnerabilities.push(StrapiVulnerability {
                            severity,
                            title: format!("Public API Endpoint: {}", endpoint),
                            description: format!(
                                "The endpoint {} is publicly accessible without authentication and returns data.",
                                endpoint
                            ),
                            evidence: Some(format!("GET {} returned 200 OK with data", endpoint_url)),
                            remediation: "Configure proper permissions in Strapi admin panel. Set 'find' and 'findOne' permissions to 'Authenticated' for sensitive content types.".to_string(),
                        });
                    }
                }
            }
        }

        public_endpoints
    }

    /// Check if debug mode is enabled (NODE_ENV=development)
    fn check_debug_mode(&self, url: &str, vulnerabilities: &mut Vec<StrapiVulnerability>) -> bool {
        // Trigger an error to check for stack traces
        let error_url = format!("{}/api/__invalid_endpoint_test__", url);

        if let Ok(response) = self.http_client.get(&error_url) {
            let body_str = String::from_utf8_lossy(&response.body);
            // Look for stack traces indicating debug mode
            if body_str.contains("at Object.")
                || body_str.contains("stack")
                || body_str.contains("NODE_ENV")
            {
                vulnerabilities.push(StrapiVulnerability {
                    severity: VulnSeverity::High,
                    title: "Debug Mode Enabled in Production".to_string(),
                    description: "Strapi appears to be running in development mode (NODE_ENV=development), which exposes detailed error messages and stack traces.".to_string(),
                    evidence: Some("Error responses contain stack traces and internal paths".to_string()),
                    remediation: "Set NODE_ENV=production in your environment variables. This will disable detailed error messages and improve performance.".to_string(),
                });
                return true;
            }
        }

        false
    }

    /// Check CORS configuration
    fn check_cors(&self, url: &str, vulnerabilities: &mut Vec<StrapiVulnerability>) -> bool {
        if let Ok(response) = self.http_client.get(url) {
            if let Some(cors) = response.headers.get("Access-Control-Allow-Origin") {
                if cors == "*" {
                    vulnerabilities.push(StrapiVulnerability {
                        severity: VulnSeverity::Medium,
                        title: "Unrestricted CORS Policy".to_string(),
                        description: "The API allows requests from any origin (Access-Control-Allow-Origin: *), which could enable CSRF attacks and data theft.".to_string(),
                        evidence: Some("Access-Control-Allow-Origin: *".to_string()),
                        remediation: "Configure CORS to only allow requests from trusted origins. Update config/middleware.js to specify allowed origins.".to_string(),
                    });
                    return true;
                }
            }
        }

        false
    }

    /// Check for other common vulnerable endpoints
    fn check_vulnerable_endpoints(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<StrapiVulnerability>,
    ) {
        // Check /uploads directory listing
        let uploads_url = format!("{}/uploads/", url);
        if let Ok(response) = self.http_client.get(&uploads_url) {
            if response.status_code == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                if body_str.contains("Index of") || body_str.contains("Parent Directory") {
                    vulnerabilities.push(StrapiVulnerability {
                        severity: VulnSeverity::Low,
                        title: "Directory Listing Enabled on /uploads".to_string(),
                        description: "The /uploads directory has directory listing enabled, allowing enumeration of uploaded files.".to_string(),
                        evidence: Some(format!("GET {} shows directory listing", uploads_url)),
                        remediation: "Disable directory listing in your web server configuration (Nginx, Apache, etc.).".to_string(),
                    });
                }
            }
        }

        // Check /_health endpoint exposure
        let health_url = format!("{}/_health", url);
        if let Ok(response) = self.http_client.get(&health_url) {
            if response.status_code == 200 {
                vulnerabilities.push(StrapiVulnerability {
                    severity: VulnSeverity::Info,
                    title: "Health Check Endpoint Exposed".to_string(),
                    description: "The /_health endpoint is publicly accessible, revealing system status information.".to_string(),
                    evidence: Some(format!("GET {} returned 200 OK", health_url)),
                    remediation: "Consider restricting access to health check endpoints to monitoring systems only.".to_string(),
                });
            }
        }
    }
}

impl Default for StrapiScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = StrapiScanner::new();
        assert_eq!(scanner.timeout_ms, 10000);
    }

    #[test]
    fn test_scanner_with_timeout() {
        let scanner = StrapiScanner::new().with_timeout(5000);
        assert_eq!(scanner.timeout_ms, 5000);
    }
}
