/// HTTP Vulnerability Detection Script
///
/// Detects common web server vulnerabilities and misconfigurations
/// based on response patterns.
use crate::scripts::types::*;
use crate::scripts::Script;

/// HTTP Vulnerability Detection Script
pub struct HttpVulnsScript {
    meta: ScriptMetadata,
}

impl HttpVulnsScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "http-vulns".to_string(),
                name: "HTTP Vulnerability Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects common web server vulnerabilities and misconfigurations"
                    .to_string(),
                categories: vec![ScriptCategory::Vuln, ScriptCategory::Safe],
                protocols: vec!["http".to_string(), "https".to_string()],
                ports: vec![80, 443, 8080, 8443, 8000, 3000],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec![
                    "https://owasp.org/www-project-web-security-testing-guide/".to_string()
                ],
            },
        }
    }
}

impl Default for HttpVulnsScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for HttpVulnsScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let headers = ctx.get_data("headers").unwrap_or("");
        let body = ctx.get_data("body").unwrap_or("");
        let server = ctx.get_data("server").unwrap_or("");

        if headers.is_empty() && body.is_empty() {
            result.add_output("No HTTP data available in context");
            return Ok(result);
        }

        result.success = true;

        let headers_lower = headers.to_lowercase();
        let body_lower = body.to_lowercase();
        let server_lower = server.to_lowercase();

        // Check for directory listing
        if body_lower.contains("index of /") || body_lower.contains("directory listing") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Directory Listing Enabled")
                    .with_description(
                        "Web server has directory listing enabled, exposing file structure",
                    )
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Disable directory listing in web server configuration"),
            );
        }

        // Check for common error pages with stack traces
        if body_lower.contains("stack trace") || body_lower.contains("stacktrace") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Stack Trace Disclosure")
                    .with_description("Application exposes stack traces in error responses")
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Disable detailed error messages in production"),
            );
        }

        // Check for database errors
        let db_errors = [
            ("mysql", "MySQL Error"),
            ("postgresql", "PostgreSQL Error"),
            ("ora-", "Oracle Error"),
            ("sql syntax", "SQL Syntax Error"),
            ("sqlite", "SQLite Error"),
            ("jdbc", "JDBC Error"),
        ];

        for (pattern, error_name) in db_errors {
            if body_lower.contains(pattern) {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, &format!("{} Disclosed", error_name))
                        .with_description("Database error messages exposed in response")
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation(
                            "Implement custom error handling to hide database errors",
                        ),
                );
                break;
            }
        }

        // Check for path disclosure
        let path_patterns = [
            "/var/www/",
            "/home/",
            "c:\\inetpub",
            "c:\\users",
            "/usr/local/",
            "/opt/",
        ];

        for pattern in path_patterns {
            if body_lower.contains(pattern) {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, "File Path Disclosure")
                        .with_description(&format!("Server path disclosed: {}", pattern))
                        .with_severity(FindingSeverity::Low)
                        .with_remediation("Configure application to not expose file system paths"),
                );
                break;
            }
        }

        // Check for ASP.NET detailed errors
        if body_lower.contains("aspnet")
            && (body_lower.contains("exception") || body_lower.contains("error"))
        {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "ASP.NET Detailed Errors")
                    .with_description("ASP.NET application shows detailed error information")
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation(
                        "Set customErrors mode=\"RemoteOnly\" or \"On\" in web.config",
                    ),
            );
        }

        // Check for PHP errors
        if body_lower.contains("fatal error") && body_lower.contains("php") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "PHP Error Display Enabled")
                    .with_description("PHP is configured to display errors")
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Set display_errors = Off in php.ini for production"),
            );
        }

        // Check for Laravel debug mode
        if body_lower.contains("laravel") && body_lower.contains("whoops") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Laravel Debug Mode Enabled")
                    .with_description("Laravel application has debug mode enabled")
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Set APP_DEBUG=false in .env file"),
            );
        }

        // Check for Django debug mode
        if body_lower.contains("django")
            && body_lower.contains("debug")
            && body_lower.contains("true")
        {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Django Debug Mode Enabled")
                    .with_description("Django application has debug mode enabled")
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Set DEBUG = False in settings.py"),
            );
        }

        // Check for exposed .git directory
        if body_lower.contains("git") && body_lower.contains("ref:") {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "Git Repository Exposed")
                    .with_description(
                        ".git directory is accessible, potentially exposing source code",
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Block access to .git directory in web server configuration"),
            );
        }

        // Check for backup files
        let backup_indicators = ["~", ".bak", ".old", ".backup", ".swp", ".save"];
        for indicator in backup_indicators {
            if headers_lower.contains(&format!(
                "content-disposition: attachment; filename=\"{}",
                indicator
            )) || body_lower.contains(&format!("href=\"{}", indicator))
            {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, "Backup Files Accessible")
                        .with_description("Backup files may be accessible on the server")
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Remove backup files from web-accessible directories"),
                );
                break;
            }
        }

        // Server-specific vulnerabilities
        self.check_server_vulns(&server_lower, &mut result);

        result.add_output(&format!(
            "HTTP vulnerability scan complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

impl HttpVulnsScript {
    fn check_server_vulns(&self, server: &str, result: &mut ScriptResult) {
        // Apache vulnerabilities
        if server.contains("apache") {
            if server.contains("2.4.49") || server.contains("2.4.50") {
                result.add_finding(
                    Finding::new(
                        FindingType::Vulnerability,
                        "Apache Path Traversal (CVE-2021-41773)",
                    )
                    .with_cve("CVE-2021-41773")
                    .with_description("Apache 2.4.49-2.4.50 vulnerable to path traversal/RCE")
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Upgrade to Apache 2.4.51 or later"),
                );
            }
        }

        // Nginx vulnerabilities
        if server.contains("nginx") {
            // Check for very old nginx
            if let Some(version) = self.extract_nginx_version(server) {
                if self.version_lt(&version, "1.20.0") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "Outdated Nginx Version")
                            .with_description(&format!(
                                "Nginx {} may have known vulnerabilities",
                                version
                            ))
                            .with_severity(FindingSeverity::Medium)
                            .with_remediation("Upgrade to latest Nginx stable release"),
                    );
                }
            }
        }

        // IIS vulnerabilities
        if server.contains("iis") {
            if server.contains("6.0") || server.contains("7.0") || server.contains("7.5") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "End-of-Life IIS Version")
                        .with_description("IIS 6.0/7.x is end-of-life and unsupported")
                        .with_severity(FindingSeverity::High)
                        .with_remediation("Upgrade to Windows Server with IIS 10+"),
                );
            }
        }

        // Tomcat vulnerabilities
        if server.contains("tomcat") {
            if server.contains("8.5.") {
                if let Some(minor) = self.extract_tomcat_minor(server, "8.5.") {
                    if minor < 85 {
                        result.add_finding(
                            Finding::new(FindingType::Vulnerability, "Outdated Tomcat Version")
                                .with_description("Tomcat 8.5.x before 8.5.85 has vulnerabilities")
                                .with_severity(FindingSeverity::Medium)
                                .with_remediation(
                                    "Upgrade to Tomcat 8.5.85+ or migrate to 9.x/10.x",
                                ),
                        );
                    }
                }
            }
        }
    }

    fn extract_nginx_version(&self, server: &str) -> Option<String> {
        if let Some(start) = server.find("nginx/") {
            let after = &server[start + 6..];
            let version: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !version.is_empty() {
                return Some(version);
            }
        }
        None
    }

    fn extract_tomcat_minor(&self, server: &str, prefix: &str) -> Option<u32> {
        if let Some(start) = server.find(prefix) {
            let after = &server[start + prefix.len()..];
            let minor: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            return minor.parse().ok();
        }
        None
    }

    fn version_lt(&self, version: &str, target: &str) -> bool {
        let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
        let v1 = parse(version);
        let v2 = parse(target);
        for (a, b) in v1.iter().zip(v2.iter()) {
            if a < b {
                return true;
            }
            if a > b {
                return false;
            }
        }
        v1.len() < v2.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_vulns_script() {
        let script = HttpVulnsScript::new();
        assert_eq!(script.id(), "http-vulns");
        assert!(script.has_category(ScriptCategory::Vuln));
    }

    #[test]
    fn test_directory_listing() {
        let script = HttpVulnsScript::new();
        let mut ctx = ScriptContext::new("example.com", 80);
        ctx.set_data("body", "<html><title>Index of /</title></html>");

        let result = script.run(&ctx).unwrap();
        let has_dir_listing = result
            .findings
            .iter()
            .any(|f| f.title.contains("Directory Listing"));
        assert!(has_dir_listing);
    }

    #[test]
    fn test_apache_cve() {
        let script = HttpVulnsScript::new();
        let mut ctx = ScriptContext::new("example.com", 80);
        ctx.set_data("server", "Apache/2.4.49");
        ctx.set_data("headers", "Server: Apache/2.4.49");

        let result = script.run(&ctx).unwrap();
        let has_cve = result
            .findings
            .iter()
            .any(|f| f.cve == Some("CVE-2021-41773".to_string()));
        assert!(has_cve);
    }
}
