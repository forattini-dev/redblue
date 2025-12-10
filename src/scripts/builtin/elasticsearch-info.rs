/// Elasticsearch Information Script
///
/// Detects Elasticsearch services and identifies security issues
/// including unauthenticated access and data exposure.

use crate::scripts::types::*;
use crate::scripts::Script;

/// Elasticsearch Information Script
pub struct ElasticsearchInfoScript {
    meta: ScriptMetadata,
}

impl ElasticsearchInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "elasticsearch-info".to_string(),
                name: "Elasticsearch Service Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects Elasticsearch and identifies security misconfigurations".to_string(),
                categories: vec![ScriptCategory::Discovery, ScriptCategory::Vuln, ScriptCategory::Safe],
                protocols: vec!["http".to_string(), "https".to_string()],
                ports: vec![9200, 9300, 9243],
                license: "MIT".to_string(),
                cves: vec![
                    "CVE-2015-1427".to_string(), // Groovy RCE
                    "CVE-2014-3120".to_string(), // MVEL RCE
                ],
                references: vec!["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html".to_string()],
            },
        }
    }
}

impl Default for ElasticsearchInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for ElasticsearchInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let es_data = ctx.get_data("elasticsearch_response").unwrap_or("");
        let auth_enabled = ctx.get_data("elasticsearch_auth").unwrap_or("");
        let cluster_name = ctx.get_data("elasticsearch_cluster").unwrap_or("");

        if es_data.is_empty() && cluster_name.is_empty() {
            result.add_output("No Elasticsearch data available in context");
            return Ok(result);
        }

        result.success = true;
        let data_lower = es_data.to_lowercase();

        // Elasticsearch detected
        result.add_finding(
            Finding::new(FindingType::Discovery, "Elasticsearch Service Detected")
                .with_description(&format!("Elasticsearch service running on port {}", ctx.port))
                .with_severity(FindingSeverity::Info),
        );

        // Extract cluster name
        if !cluster_name.is_empty() {
            result.extract("cluster_name", cluster_name);
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Cluster Name Exposed")
                    .with_description(&format!("Elasticsearch cluster name: {}", cluster_name))
                    .with_severity(FindingSeverity::Low),
            );
        }

        // Check authentication status
        match auth_enabled.to_lowercase().as_str() {
            "false" | "disabled" | "no" | "0" => {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "Elasticsearch No Authentication")
                        .with_description(
                            "Elasticsearch is accessible without authentication. \
                             This allows anyone to read, modify, or delete all data."
                        )
                        .with_severity(FindingSeverity::Critical)
                        .with_remediation(
                            "Enable X-Pack security or configure authentication. \
                             Set xpack.security.enabled: true in elasticsearch.yml"
                        ),
                );
            }
            "true" | "enabled" | "yes" | "1" | "xpack" => {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "Authentication Enabled")
                        .with_description("Elasticsearch authentication is enabled")
                        .with_severity(FindingSeverity::Info),
                );
            }
            _ => {}
        }

        // Extract version
        if let Some(version) = self.extract_version(&data_lower) {
            result.extract("elasticsearch_version", &version);
            result.add_finding(
                Finding::new(FindingType::Version, "Elasticsearch Version")
                    .with_description(&format!("Elasticsearch version: {}", version))
                    .with_severity(FindingSeverity::Info),
            );

            // Check for vulnerable versions
            self.check_version_vulns(&version, &mut result);
        }

        // Check for exposed indices
        if data_lower.contains("indices") || data_lower.contains("_cat") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Index Information Exposed")
                    .with_description("Elasticsearch index information is accessible")
                    .with_severity(FindingSeverity::Medium),
            );
        }

        // Check for sensitive data indicators
        let sensitive_indices = [
            "users", "customers", "passwords", "credentials", "secrets",
            "tokens", "sessions", "payment", "credit", "ssn", "pii",
        ];

        for idx in sensitive_indices {
            if data_lower.contains(idx) {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, "Potentially Sensitive Index Found")
                        .with_description(&format!("Index matching '{}' found - may contain sensitive data", idx))
                        .with_severity(FindingSeverity::High)
                        .with_remediation("Review index contents and restrict access appropriately"),
                );
                break;
            }
        }

        // Check for dynamic scripting (pre-5.0 vulnerability)
        if data_lower.contains("script.disable_dynamic") && data_lower.contains("false") {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "Dynamic Scripting Enabled")
                    .with_description(
                        "Dynamic scripting is enabled, which may allow remote code execution \
                         in older Elasticsearch versions."
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Disable dynamic scripting or upgrade to Elasticsearch 5.0+"),
            );
        }

        // Check for Kibana
        if data_lower.contains("kibana") {
            result.add_finding(
                Finding::new(FindingType::Discovery, "Kibana Integration Detected")
                    .with_description("Elasticsearch appears to have Kibana integration")
                    .with_severity(FindingSeverity::Info),
            );
        }

        // Check for internet exposure
        let is_external = !ctx.host.starts_with("192.168.")
            && !ctx.host.starts_with("10.")
            && !ctx.host.starts_with("172.")
            && ctx.host != "localhost"
            && ctx.host != "127.0.0.1";

        if is_external {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Elasticsearch Exposed to Internet")
                    .with_description(
                        "Elasticsearch is exposed to the internet. \
                         This service should not be directly accessible from the internet."
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation(
                        "Place Elasticsearch behind a firewall. \
                         Use VPN or reverse proxy for external access."
                    ),
            );
        }

        result.add_output(&format!("Elasticsearch analysis complete for {}:{}", ctx.host, ctx.port));
        Ok(result)
    }
}

impl ElasticsearchInfoScript {
    fn extract_version(&self, data: &str) -> Option<String> {
        // Look for version patterns like "7.10.0" or "version": "7.10.0"
        if let Some(pos) = data.find("\"version\"") {
            let after = &data[pos..];
            // Find the version number
            let mut in_version = false;
            let mut version = String::new();
            for ch in after.chars() {
                if ch.is_ascii_digit() || ch == '.' {
                    in_version = true;
                    version.push(ch);
                } else if in_version && !ch.is_ascii_digit() && ch != '.' {
                    break;
                }
            }
            if !version.is_empty() {
                return Some(version);
            }
        }
        None
    }

    fn check_version_vulns(&self, version: &str, result: &mut ScriptResult) {
        let parts: Vec<u32> = version
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();

        if parts.is_empty() {
            return;
        }

        let major = parts[0];
        let minor = parts.get(1).copied().unwrap_or(0);

        // CVE-2015-1427 - Groovy sandbox bypass (affects 1.3.x - 1.4.x)
        if major == 1 && (minor == 3 || minor == 4) {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "Groovy RCE Vulnerability")
                    .with_cve("CVE-2015-1427")
                    .with_description(
                        "Elasticsearch 1.3.x-1.4.x is vulnerable to remote code execution \
                         via Groovy scripting sandbox bypass."
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Upgrade to Elasticsearch 1.4.3+ or disable dynamic scripting"),
            );
        }

        // CVE-2014-3120 - MVEL RCE (affects < 1.2.0)
        if major == 1 && minor < 2 {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "MVEL RCE Vulnerability")
                    .with_cve("CVE-2014-3120")
                    .with_description(
                        "Elasticsearch < 1.2.0 is vulnerable to remote code execution \
                         via MVEL scripting."
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Upgrade to Elasticsearch 1.2.0 or later"),
            );
        }

        // End of life versions
        if major < 7 {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "End-of-Life Elasticsearch Version")
                    .with_description(&format!(
                        "Elasticsearch {} is end-of-life and no longer receives security updates",
                        version
                    ))
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Upgrade to Elasticsearch 7.x or 8.x"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elasticsearch_script() {
        let script = ElasticsearchInfoScript::new();
        assert_eq!(script.id(), "elasticsearch-info");
    }

    #[test]
    fn test_no_auth() {
        let script = ElasticsearchInfoScript::new();
        let mut ctx = ScriptContext::new("192.168.1.1", 9200);
        ctx.set_data("elasticsearch_auth", "disabled");
        ctx.set_data("elasticsearch_cluster", "test-cluster");

        let result = script.run(&ctx).unwrap();
        let has_no_auth = result.findings.iter().any(|f| f.title.contains("No Authentication"));
        assert!(has_no_auth);
    }
}
