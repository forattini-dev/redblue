/// MySQL Information Script
///
/// Detects MySQL/MariaDB servers and identifies version information
/// and potential security issues.
use crate::scripts::types::*;
use crate::scripts::Script;

/// MySQL Information Script
pub struct MysqlInfoScript {
    meta: ScriptMetadata,
}

impl MysqlInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "mysql-info".to_string(),
                name: "MySQL/MariaDB Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description:
                    "Detects MySQL/MariaDB servers and identifies version and configuration"
                        .to_string(),
                categories: vec![
                    ScriptCategory::Banner,
                    ScriptCategory::Version,
                    ScriptCategory::Safe,
                    ScriptCategory::Default,
                ],
                protocols: vec!["mysql".to_string()],
                ports: vec![3306, 3307, 33060],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://dev.mysql.com/doc/".to_string()],
            },
        }
    }
}

impl Default for MysqlInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for MysqlInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let banner = ctx.get_data("banner").unwrap_or("");

        if banner.is_empty() {
            result.add_output("No MySQL banner available in context");
            return Ok(result);
        }

        result.success = true;

        // Parse MySQL greeting packet info
        let (server_type, version) = self.parse_mysql_banner(banner);

        result.extract("mysql_server", &server_type);
        if let Some(ref v) = version {
            result.extract("mysql_version", v);
        }

        result.add_finding(
            Finding::new(FindingType::Version, &format!("{} Detected", server_type))
                .with_description(&format!(
                    "Server: {}\nVersion: {}",
                    server_type,
                    version.as_deref().unwrap_or("unknown")
                ))
                .with_evidence(banner)
                .with_severity(FindingSeverity::Info),
        );

        // Check for known vulnerable versions
        if let Some(ref ver) = version {
            self.check_vulnerabilities(ver, &server_type, &mut result);
        }

        // Check for MariaDB
        let banner_lower = banner.to_lowercase();
        if banner_lower.contains("mariadb") {
            result.add_finding(
                Finding::new(FindingType::Discovery, "MariaDB Server")
                    .with_description("Server is MariaDB (MySQL fork)")
                    .with_severity(FindingSeverity::Info),
            );
        }

        // Check for authentication issues
        if banner_lower.contains("access denied") {
            result.add_finding(
                Finding::new(FindingType::Discovery, "Authentication Required")
                    .with_description("MySQL requires authentication")
                    .with_severity(FindingSeverity::Info),
            );
        }

        result.add_output(&format!("MySQL banner: {}", banner));
        Ok(result)
    }
}

impl MysqlInfoScript {
    fn parse_mysql_banner(&self, banner: &str) -> (String, Option<String>) {
        // MySQL banners often contain version like "5.7.32" or "8.0.23-0ubuntu0.20.04.1"
        let banner_lower = banner.to_lowercase();

        let server_type = if banner_lower.contains("mariadb") {
            "MariaDB".to_string()
        } else if banner_lower.contains("percona") {
            "Percona Server".to_string()
        } else {
            "MySQL".to_string()
        };

        // Extract version number
        let version = self.extract_version(banner);

        (server_type, version)
    }

    fn extract_version(&self, banner: &str) -> Option<String> {
        // Look for version patterns like 5.7.32, 8.0.23, 10.5.9-MariaDB
        let mut version = String::new();
        let mut in_version = false;

        for c in banner.chars() {
            if c.is_ascii_digit() {
                in_version = true;
                version.push(c);
            } else if in_version && (c == '.' || c == '-') {
                version.push(c);
            } else if in_version {
                break;
            }
        }

        // Clean up trailing dots/dashes
        let version = version
            .trim_end_matches(|c| c == '.' || c == '-')
            .to_string();

        if version.contains('.') {
            Some(version)
        } else {
            None
        }
    }

    fn check_vulnerabilities(&self, version: &str, server_type: &str, result: &mut ScriptResult) {
        let is_mariadb = server_type.to_lowercase().contains("mariadb");

        if is_mariadb {
            // MariaDB vulnerabilities
            if self.version_lt(version, "10.5.18") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "Outdated MariaDB Version")
                        .with_description("MariaDB before 10.5.18 has known vulnerabilities")
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Upgrade to MariaDB 10.5.18 or later"),
                );
            }
        } else {
            // MySQL vulnerabilities
            // CVE-2023-21912 - MySQL Server DOS
            if self.version_in_range(version, "8.0.0", "8.0.33") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "MySQL Server Vulnerability")
                        .with_cve("CVE-2023-21912")
                        .with_description(
                            "MySQL 8.0.0-8.0.32 has multiple security vulnerabilities",
                        )
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Upgrade to MySQL 8.0.33 or later"),
                );
            }

            // Very old MySQL 5.x
            if self.version_lt(version, "5.7.0") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "End-of-Life MySQL Version")
                        .with_description("MySQL 5.6 and earlier are end-of-life and unsupported")
                        .with_severity(FindingSeverity::High)
                        .with_remediation("Upgrade to MySQL 5.7 or 8.0"),
                );
            }
        }
    }

    fn version_lt(&self, version: &str, target: &str) -> bool {
        let parse = |s: &str| -> Vec<u32> {
            s.split('.')
                .filter_map(|p| {
                    p.chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect::<String>()
                        .parse()
                        .ok()
                })
                .collect()
        };

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
    fn test_mysql_script() {
        let script = MysqlInfoScript::new();
        assert_eq!(script.id(), "mysql-info");
    }

    #[test]
    fn test_mysql_version_detection() {
        let script = MysqlInfoScript::new();
        let mut ctx = ScriptContext::new("localhost", 3306);
        ctx.set_data("banner", "5.7.32-0ubuntu0.18.04.1");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(
            result.extracted.get("mysql_version"),
            Some(&"5.7.32-0ubuntu0.18.04.1".to_string())
        );
    }
}
