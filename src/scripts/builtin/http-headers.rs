/// HTTP Headers Script
///
/// Extracts and analyzes HTTP response headers.
/// Identifies server software, technologies, and potential information leaks.

use crate::scripts::types::*;
use crate::scripts::Script;

/// HTTP Headers Discovery Script
pub struct HttpHeadersScript {
    meta: ScriptMetadata,
}

impl HttpHeadersScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "http-headers".to_string(),
                name: "HTTP Headers Analysis".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Extracts and analyzes HTTP response headers for server identification and information disclosure".to_string(),
                categories: vec![ScriptCategory::Discovery, ScriptCategory::Safe, ScriptCategory::Default],
                protocols: vec!["http".to_string(), "https".to_string()],
                ports: vec![80, 443, 8080, 8443],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers".to_string()],
            },
        }
    }
}

impl Default for HttpHeadersScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for HttpHeadersScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn args(&self) -> Vec<ScriptArg> {
        vec![
            ScriptArg::new("path", "URL path to request").with_default("/"),
        ]
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        // Check for headers in context data
        let headers_data = ctx.get_data("headers").unwrap_or("");

        if headers_data.is_empty() {
            result.add_output("No HTTP headers available in context");
            return Ok(result);
        }

        result.success = true;

        // Parse and analyze headers
        for line in headers_data.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                match key.as_str() {
                    "server" => {
                        result.add_finding(
                            Finding::new(FindingType::Version, "Server Header Detected")
                                .with_description(&format!("Server: {}", value))
                                .with_evidence(value)
                                .with_severity(FindingSeverity::Info),
                        );
                        result.extract("server", value);

                        // Check for version disclosure
                        if value.contains('/') {
                            result.add_finding(
                                Finding::new(FindingType::InfoLeak, "Server Version Disclosed")
                                    .with_description("Server header reveals version information")
                                    .with_evidence(value)
                                    .with_severity(FindingSeverity::Low)
                                    .with_remediation("Consider hiding server version in production"),
                            );
                        }
                    }
                    "x-powered-by" => {
                        result.add_finding(
                            Finding::new(FindingType::InfoLeak, "X-Powered-By Header")
                                .with_description(&format!("Technology disclosed: {}", value))
                                .with_evidence(value)
                                .with_severity(FindingSeverity::Low)
                                .with_remediation("Remove X-Powered-By header in production"),
                        );
                        result.extract("powered_by", value);
                    }
                    "x-aspnet-version" | "x-aspnetmvc-version" => {
                        result.add_finding(
                            Finding::new(FindingType::InfoLeak, "ASP.NET Version Disclosed")
                                .with_description(&format!("{}: {}", key, value))
                                .with_evidence(value)
                                .with_severity(FindingSeverity::Low)
                                .with_remediation("Disable version headers in ASP.NET configuration"),
                        );
                        result.extract("aspnet_version", value);
                    }
                    "x-generator" => {
                        result.add_finding(
                            Finding::new(FindingType::Version, "Generator Header")
                                .with_description(&format!("Site generator: {}", value))
                                .with_evidence(value)
                                .with_severity(FindingSeverity::Info),
                        );
                        result.extract("generator", value);
                    }
                    "via" => {
                        result.add_finding(
                            Finding::new(FindingType::Discovery, "Proxy/CDN Detected")
                                .with_description(&format!("Via: {}", value))
                                .with_evidence(value)
                                .with_severity(FindingSeverity::Info),
                        );
                        result.extract("via", value);
                    }
                    "x-cache" | "x-cache-status" => {
                        result.add_finding(
                            Finding::new(FindingType::Discovery, "Cache Header")
                                .with_description(&format!("{}: {}", key, value))
                                .with_evidence(value)
                                .with_severity(FindingSeverity::Info),
                        );
                    }
                    "set-cookie" => {
                        // Check for security flags
                        let has_httponly = value.to_lowercase().contains("httponly");
                        let has_secure = value.to_lowercase().contains("secure");
                        let has_samesite = value.to_lowercase().contains("samesite");

                        if !has_httponly {
                            result.add_finding(
                                Finding::new(FindingType::Misconfiguration, "Cookie Missing HttpOnly")
                                    .with_description("Cookie is accessible to JavaScript")
                                    .with_severity(FindingSeverity::Medium)
                                    .with_remediation("Add HttpOnly flag to cookies"),
                            );
                        }
                        if !has_secure && ctx.protocol == "https" {
                            result.add_finding(
                                Finding::new(FindingType::Misconfiguration, "Cookie Missing Secure Flag")
                                    .with_description("Cookie may be sent over unencrypted connection")
                                    .with_severity(FindingSeverity::Medium)
                                    .with_remediation("Add Secure flag to cookies"),
                            );
                        }
                        if !has_samesite {
                            result.add_finding(
                                Finding::new(FindingType::Misconfiguration, "Cookie Missing SameSite")
                                    .with_description("Cookie vulnerable to CSRF attacks")
                                    .with_severity(FindingSeverity::Low)
                                    .with_remediation("Add SameSite=Strict or SameSite=Lax"),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        result.add_output(&format!("Analyzed HTTP headers for {}", ctx.host));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_headers_script() {
        let script = HttpHeadersScript::new();
        assert_eq!(script.id(), "http-headers");
        assert!(script.has_category(ScriptCategory::Discovery));
    }

    #[test]
    fn test_server_detection() {
        let script = HttpHeadersScript::new();
        let mut ctx = ScriptContext::new("example.com", 80);
        ctx.set_data("headers", "Server: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert!(!result.findings.is_empty());
        assert_eq!(result.extracted.get("server"), Some(&"Apache/2.4.41 (Ubuntu)".to_string()));
    }

    #[test]
    fn test_cookie_security() {
        let script = HttpHeadersScript::new();
        let mut ctx = ScriptContext::new("example.com", 443);
        ctx.protocol = "https".to_string();
        ctx.set_data("headers", "Set-Cookie: session=abc123; Path=/");

        let result = script.run(&ctx).unwrap();
        // Should find missing HttpOnly, Secure, and SameSite
        let misconfig_count = result
            .findings
            .iter()
            .filter(|f| f.finding_type == FindingType::Misconfiguration)
            .count();
        assert!(misconfig_count >= 2);
    }
}
