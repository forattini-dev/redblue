/// Redis Information Script
///
/// Detects Redis servers and identifies potential security issues
/// including unauthenticated access.
use crate::scripts::types::*;
use crate::scripts::Script;

/// Redis Information Script
pub struct RedisInfoScript {
    meta: ScriptMetadata,
}

impl RedisInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "redis-info".to_string(),
                name: "Redis Server Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description:
                    "Detects Redis servers and identifies version and security configuration"
                        .to_string(),
                categories: vec![
                    ScriptCategory::Banner,
                    ScriptCategory::Version,
                    ScriptCategory::Vuln,
                    ScriptCategory::Safe,
                ],
                protocols: vec!["redis".to_string()],
                ports: vec![6379, 6380, 6381],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://redis.io/docs/management/security/".to_string()],
            },
        }
    }
}

impl Default for RedisInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for RedisInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let banner = ctx.get_data("banner").unwrap_or("");
        let info_response = ctx.get_data("redis_info").unwrap_or("");

        if banner.is_empty() && info_response.is_empty() {
            result.add_output("No Redis data available in context");
            return Ok(result);
        }

        result.success = true;

        // Check for Redis identification
        let combined = format!("{} {}", banner, info_response);
        let combined_lower = combined.to_lowercase();

        if combined_lower.contains("redis")
            || combined_lower.contains("-err")
            || combined_lower.contains("+pong")
        {
            result.add_finding(
                Finding::new(FindingType::Discovery, "Redis Server Detected")
                    .with_evidence(&combined)
                    .with_severity(FindingSeverity::Info),
            );
            result.extract("service", "redis");
        }

        // Parse version from INFO response
        if let Some(version) = self.extract_version(&combined) {
            result.extract("redis_version", &version);
            result.add_finding(
                Finding::new(FindingType::Version, &format!("Redis {}", version))
                    .with_description(&format!("Redis Server Version: {}", version))
                    .with_severity(FindingSeverity::Info),
            );

            // Check for vulnerable versions
            self.check_vulnerabilities(&version, &mut result);
        }

        // Check for unauthenticated access (critical security issue)
        if combined_lower.contains("+pong") || combined_lower.contains("redis_version") {
            if !combined_lower.contains("noauth") && !combined_lower.contains("authentication") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "Redis Unauthenticated Access")
                        .with_description("Redis server appears to allow unauthenticated access")
                        .with_severity(FindingSeverity::Critical)
                        .with_remediation(
                            "Enable Redis authentication with 'requirepass' directive",
                        ),
                );
            }
        }

        // Check for dangerous commands
        if combined_lower.contains("config") || combined_lower.contains("debug") {
            result.add_finding(
                Finding::new(
                    FindingType::Misconfiguration,
                    "Dangerous Commands May Be Enabled",
                )
                .with_description("Redis CONFIG and DEBUG commands may allow RCE")
                .with_severity(FindingSeverity::High)
                .with_remediation("Rename or disable dangerous commands in redis.conf"),
            );
        }

        // Check for protected mode
        if combined_lower.contains("protected-mode:no")
            || combined_lower.contains("protected_mode:0")
        {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Protected Mode Disabled")
                    .with_description(
                        "Redis protected mode is disabled, allowing remote connections",
                    )
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Enable protected mode or configure proper authentication"),
            );
        }

        result.add_output(&format!(
            "Redis analysis complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

impl RedisInfoScript {
    fn extract_version(&self, data: &str) -> Option<String> {
        // Look for redis_version:X.X.X pattern
        for line in data.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.contains("redis_version:") || line_lower.contains("redis version") {
                if let Some(colon) = line.find(':') {
                    let version = line[colon + 1..].trim();
                    if !version.is_empty() {
                        return Some(version.to_string());
                    }
                }
            }
        }

        // Try to find version pattern directly
        let mut version = String::new();
        let mut in_version = false;
        for c in data.chars() {
            if c.is_ascii_digit() && !in_version {
                in_version = true;
                version.push(c);
            } else if in_version && (c.is_ascii_digit() || c == '.') {
                version.push(c);
            } else if in_version && version.contains('.') {
                return Some(version);
            } else if in_version {
                version.clear();
                in_version = false;
            }
        }

        None
    }

    fn check_vulnerabilities(&self, version: &str, result: &mut ScriptResult) {
        // CVE-2022-24735 - Lua sandbox escape
        if self.version_lt(version, "6.2.7") || self.version_in_range(version, "7.0.0", "7.0.0") {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "Redis Lua Sandbox Escape")
                    .with_cve("CVE-2022-24735")
                    .with_description(
                        "Redis before 6.2.7 and 7.0.0 vulnerable to Lua sandbox escape",
                    )
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Upgrade to Redis 6.2.7+ or 7.0.1+"),
            );
        }

        // CVE-2022-24736 - Denial of service
        if self.version_lt(version, "6.2.7") {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "Redis DoS Vulnerability")
                    .with_cve("CVE-2022-24736")
                    .with_description("Redis before 6.2.7 vulnerable to denial of service")
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Upgrade to Redis 6.2.7 or later"),
            );
        }

        // Very old Redis
        if self.version_lt(version, "5.0.0") {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "Outdated Redis Version")
                    .with_description("Redis 4.x and earlier have multiple known vulnerabilities")
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Upgrade to Redis 6.x or 7.x"),
            );
        }
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

    fn version_in_range(&self, version: &str, min: &str, max: &str) -> bool {
        !self.version_lt(version, min) && self.version_lt(version, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_script() {
        let script = RedisInfoScript::new();
        assert_eq!(script.id(), "redis-info");
        assert!(script.has_category(ScriptCategory::Vuln));
    }

    #[test]
    fn test_redis_unauth() {
        let script = RedisInfoScript::new();
        let mut ctx = ScriptContext::new("localhost", 6379);
        ctx.set_data("banner", "+PONG");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        let has_unauth = result
            .findings
            .iter()
            .any(|f| f.title.contains("Unauthenticated"));
        assert!(has_unauth);
    }
}
