/// HTTP Security Headers Script
///
/// Checks for presence and configuration of security headers.
/// Identifies missing headers that could lead to vulnerabilities.

use crate::scripts::types::*;
use crate::scripts::Script;

/// HTTP Security Headers Script
pub struct HttpSecurityScript {
    meta: ScriptMetadata,
}

impl HttpSecurityScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "http-security-headers".to_string(),
                name: "HTTP Security Headers Check".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Analyzes HTTP response for security headers and identifies missing protections".to_string(),
                categories: vec![ScriptCategory::Vuln, ScriptCategory::Safe, ScriptCategory::Default],
                protocols: vec!["http".to_string(), "https".to_string()],
                ports: vec![80, 443, 8080, 8443],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec![
                    "https://owasp.org/www-project-secure-headers/".to_string(),
                    "https://securityheaders.com/".to_string(),
                ],
            },
        }
    }
}

impl Default for HttpSecurityScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for HttpSecurityScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let headers_data = ctx.get_data("headers").unwrap_or("");

        if headers_data.is_empty() {
            result.add_output("No HTTP headers available in context");
            return Ok(result);
        }

        result.success = true;

        // Parse headers into a map
        let mut headers: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for line in headers_data.lines() {
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Check critical security headers
        let security_checks = [
            (
                "strict-transport-security",
                "Missing HSTS Header",
                "Strict-Transport-Security header is not set. This allows protocol downgrade attacks.",
                FindingSeverity::Medium,
                "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
                true, // HTTPS only
            ),
            (
                "x-frame-options",
                "Missing X-Frame-Options",
                "X-Frame-Options header is not set. Site may be vulnerable to clickjacking.",
                FindingSeverity::Medium,
                "Add X-Frame-Options: DENY or SAMEORIGIN",
                false,
            ),
            (
                "x-content-type-options",
                "Missing X-Content-Type-Options",
                "X-Content-Type-Options header is not set. Browser may MIME-sniff responses.",
                FindingSeverity::Low,
                "Add X-Content-Type-Options: nosniff",
                false,
            ),
            (
                "x-xss-protection",
                "Missing X-XSS-Protection",
                "X-XSS-Protection header is not set (legacy but still useful for older browsers).",
                FindingSeverity::Info,
                "Add X-XSS-Protection: 1; mode=block",
                false,
            ),
            (
                "content-security-policy",
                "Missing Content-Security-Policy",
                "CSP header is not set. Site may be vulnerable to XSS and data injection attacks.",
                FindingSeverity::Medium,
                "Implement a Content-Security-Policy header",
                false,
            ),
            (
                "referrer-policy",
                "Missing Referrer-Policy",
                "Referrer-Policy header is not set. Referrer data may leak to third parties.",
                FindingSeverity::Low,
                "Add Referrer-Policy: strict-origin-when-cross-origin",
                false,
            ),
            (
                "permissions-policy",
                "Missing Permissions-Policy",
                "Permissions-Policy (formerly Feature-Policy) header is not set.",
                FindingSeverity::Low,
                "Add Permissions-Policy header to control browser features",
                false,
            ),
        ];

        let is_https = ctx.protocol == "https" || ctx.port == 443;

        for (header, title, desc, severity, remediation, https_only) in security_checks {
            // Skip HTTPS-only checks for HTTP
            if https_only && !is_https {
                continue;
            }

            if !headers.contains_key(header) {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, title)
                        .with_description(desc)
                        .with_severity(severity)
                        .with_remediation(remediation),
                );
            }
        }

        // Check for insecure CSP directives
        if let Some(csp) = headers.get("content-security-policy") {
            let csp_lower = csp.to_lowercase();

            if csp_lower.contains("'unsafe-inline'") {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "CSP Allows unsafe-inline")
                        .with_description("Content-Security-Policy contains 'unsafe-inline' which weakens XSS protection")
                        .with_evidence(csp)
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Remove 'unsafe-inline' and use nonces or hashes instead"),
                );
            }

            if csp_lower.contains("'unsafe-eval'") {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "CSP Allows unsafe-eval")
                        .with_description("Content-Security-Policy contains 'unsafe-eval' which allows eval()")
                        .with_evidence(csp)
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Remove 'unsafe-eval' to prevent code injection"),
                );
            }

            if csp_lower.contains("*") && !csp_lower.contains("*.") {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "CSP Contains Wildcard")
                        .with_description("Content-Security-Policy contains wildcard (*) which allows any source")
                        .with_evidence(csp)
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Replace wildcards with specific domains"),
                );
            }
        }

        // Check HSTS configuration
        if let Some(hsts) = headers.get("strict-transport-security") {
            // Check max-age
            if let Some(max_age_start) = hsts.find("max-age=") {
                let value_start = max_age_start + 8;
                let value_end = hsts[value_start..]
                    .find(|c: char| !c.is_ascii_digit())
                    .map(|i| value_start + i)
                    .unwrap_or(hsts.len());

                if let Ok(max_age) = hsts[value_start..value_end].parse::<u64>() {
                    if max_age < 31536000 {
                        // Less than 1 year
                        result.add_finding(
                            Finding::new(FindingType::Misconfiguration, "HSTS max-age Too Short")
                                .with_description(&format!(
                                    "HSTS max-age is {} seconds. Recommended: at least 31536000 (1 year)",
                                    max_age
                                ))
                                .with_evidence(hsts)
                                .with_severity(FindingSeverity::Low)
                                .with_remediation("Increase max-age to at least 31536000"),
                        );
                    }
                }
            }

            if !hsts.contains("includeSubDomains") {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "HSTS Missing includeSubDomains")
                        .with_description("HSTS does not include subdomains")
                        .with_evidence(hsts)
                        .with_severity(FindingSeverity::Low)
                        .with_remediation("Add includeSubDomains directive"),
                );
            }
        }

        // Check for CORS misconfiguration
        if let Some(cors) = headers.get("access-control-allow-origin") {
            if cors == "*" {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "CORS Allows Any Origin")
                        .with_description("Access-Control-Allow-Origin is set to * allowing any origin")
                        .with_evidence(cors)
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Restrict CORS to specific trusted origins"),
                );
            }

            if let Some(creds) = headers.get("access-control-allow-credentials") {
                if creds == "true" && cors == "*" {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "CORS Credentials with Wildcard")
                            .with_description("CORS allows credentials with wildcard origin - this is a security vulnerability")
                            .with_severity(FindingSeverity::High)
                            .with_remediation("Never combine Access-Control-Allow-Credentials: true with wildcard origin"),
                    );
                }
            }
        }

        let finding_count = result.findings.len();
        if finding_count == 0 {
            result.add_output("All security headers are properly configured");
        } else {
            result.add_output(&format!("Found {} security header issues", finding_count));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_security_script() {
        let script = HttpSecurityScript::new();
        assert_eq!(script.id(), "http-security-headers");
        assert!(script.has_category(ScriptCategory::Vuln));
    }

    #[test]
    fn test_missing_headers() {
        let script = HttpSecurityScript::new();
        let mut ctx = ScriptContext::new("example.com", 443);
        ctx.protocol = "https".to_string();
        ctx.set_data("headers", "Content-Type: text/html");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        // Should find missing HSTS, X-Frame-Options, etc.
        assert!(result.findings.len() >= 4);
    }

    #[test]
    fn test_all_headers_present() {
        let script = HttpSecurityScript::new();
        let mut ctx = ScriptContext::new("example.com", 443);
        ctx.protocol = "https".to_string();
        ctx.set_data(
            "headers",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n\
             X-Frame-Options: DENY\r\n\
             X-Content-Type-Options: nosniff\r\n\
             Content-Security-Policy: default-src 'self'\r\n\
             Referrer-Policy: strict-origin-when-cross-origin\r\n\
             Permissions-Policy: geolocation=()",
        );

        let result = script.run(&ctx).unwrap();
        // Should find no issues (X-XSS-Protection is optional/info level)
        let high_issues = result
            .findings
            .iter()
            .filter(|f| f.severity >= FindingSeverity::Medium)
            .count();
        assert_eq!(high_issues, 0);
    }

    #[test]
    fn test_unsafe_csp() {
        let script = HttpSecurityScript::new();
        let mut ctx = ScriptContext::new("example.com", 80);
        ctx.set_data(
            "headers",
            "Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'",
        );

        let result = script.run(&ctx).unwrap();
        let csp_issues = result
            .findings
            .iter()
            .filter(|f| f.title.contains("CSP"))
            .count();
        assert!(csp_issues >= 2); // unsafe-inline and unsafe-eval
    }
}
