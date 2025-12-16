/// PostgreSQL Information Script
///
/// Detects PostgreSQL services and identifies security issues
/// including weak authentication and known vulnerabilities.
use crate::scripts::types::*;
use crate::scripts::Script;

/// PostgreSQL Information Script
pub struct PostgresInfoScript {
    meta: ScriptMetadata,
}

impl PostgresInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "postgres-info".to_string(),
                name: "PostgreSQL Service Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects PostgreSQL services and identifies security issues"
                    .to_string(),
                categories: vec![
                    ScriptCategory::Discovery,
                    ScriptCategory::Vuln,
                    ScriptCategory::Safe,
                ],
                protocols: vec!["postgresql".to_string()],
                ports: vec![5432, 5433],
                license: "MIT".to_string(),
                cves: vec![
                    "CVE-2019-9193".to_string(), // COPY command RCE
                    "CVE-2023-2454".to_string(), // CREATE SCHEMA privilege escalation
                ],
                references: vec![
                    "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html".to_string(),
                ],
            },
        }
    }
}

impl Default for PostgresInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for PostgresInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let pg_data = ctx.get_data("postgres_response").unwrap_or("");
        let pg_version = ctx.get_data("postgres_version").unwrap_or("");
        let auth_method = ctx.get_data("postgres_auth").unwrap_or("");

        if pg_data.is_empty() && pg_version.is_empty() {
            result.add_output("No PostgreSQL data available in context");
            return Ok(result);
        }

        result.success = true;

        // PostgreSQL detected
        result.add_finding(
            Finding::new(FindingType::Discovery, "PostgreSQL Service Detected")
                .with_description(&format!("PostgreSQL database server on port {}", ctx.port))
                .with_severity(FindingSeverity::Info),
        );

        // Extract and check version
        if !pg_version.is_empty() {
            result.extract("postgres_version", pg_version);
            result.add_finding(
                Finding::new(FindingType::Version, "PostgreSQL Version")
                    .with_description(&format!("PostgreSQL version: {}", pg_version))
                    .with_severity(FindingSeverity::Info),
            );

            self.check_version_vulns(pg_version, &mut result);
        }

        // Check authentication method
        let auth_lower = auth_method.to_lowercase();
        match auth_lower.as_str() {
            "trust" => {
                result.add_finding(
                    Finding::new(
                        FindingType::Vulnerability,
                        "PostgreSQL Trust Authentication",
                    )
                    .with_description(
                        "PostgreSQL is configured with 'trust' authentication. \
                             This allows connections without any password.",
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation(
                        "Change pg_hba.conf to use 'scram-sha-256' or 'md5' authentication",
                    ),
                );
            }
            "md5" => {
                result.add_finding(
                    Finding::new(
                        FindingType::Misconfiguration,
                        "PostgreSQL MD5 Authentication",
                    )
                    .with_description(
                        "PostgreSQL uses MD5 authentication which is deprecated. \
                             SCRAM-SHA-256 is more secure.",
                    )
                    .with_severity(FindingSeverity::Low)
                    .with_remediation("Upgrade to SCRAM-SHA-256 authentication"),
                );
            }
            "scram-sha-256" => {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "Secure Authentication")
                        .with_description("PostgreSQL uses SCRAM-SHA-256 authentication")
                        .with_severity(FindingSeverity::Info),
                );
            }
            "password" => {
                result.add_finding(
                    Finding::new(
                        FindingType::Misconfiguration,
                        "Cleartext Password Authentication",
                    )
                    .with_description(
                        "PostgreSQL uses cleartext password authentication. \
                             Passwords are sent unencrypted.",
                    )
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Use SCRAM-SHA-256 or MD5 authentication"),
                );
            }
            _ => {}
        }

        let data_lower = pg_data.to_lowercase();

        // Check for superuser access
        if (data_lower.contains("superuser") || data_lower.contains("postgres"))
            && (data_lower.contains("yes") || data_lower.contains("true"))
        {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Superuser Access Available")
                    .with_description(
                        "Connection appears to have superuser privileges. \
                         Applications should use least-privilege accounts.",
                    )
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Create application-specific users with limited privileges"),
            );
        }

        // Check for SSL/TLS
        if data_lower.contains("ssl")
            && (data_lower.contains("off") || data_lower.contains("disabled"))
        {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "PostgreSQL SSL Disabled")
                    .with_description(
                        "SSL/TLS is not enabled for PostgreSQL connections. \
                         Data including passwords is transmitted in cleartext.",
                    )
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Enable SSL in postgresql.conf: ssl = on"),
            );
        } else if data_lower.contains("ssl")
            && (data_lower.contains("on") || data_lower.contains("enabled"))
        {
            result.add_finding(
                Finding::new(FindingType::Discovery, "SSL Enabled")
                    .with_description("PostgreSQL SSL is enabled")
                    .with_severity(FindingSeverity::Info),
            );
        }

        // Check for remote connections
        if data_lower.contains("listen_addresses")
            && (data_lower.contains("*") || data_lower.contains("0.0.0.0"))
        {
            result.add_finding(
                Finding::new(
                    FindingType::Misconfiguration,
                    "PostgreSQL Listening on All Interfaces",
                )
                .with_description(
                    "PostgreSQL is configured to listen on all network interfaces. \
                         Combined with weak pg_hba.conf rules, this can expose the database.",
                )
                .with_severity(FindingSeverity::Medium)
                .with_remediation(
                    "Restrict listen_addresses to specific IPs. \
                         Use firewall rules to limit access.",
                ),
            );
        }

        // Check for exposed database names
        let sensitive_dbs = [
            "production",
            "prod",
            "customer",
            "users",
            "payment",
            "finance",
        ];
        for db in sensitive_dbs {
            if data_lower.contains(db) {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, "Sensitive Database Name Exposed")
                        .with_description(&format!("Database name containing '{}' found", db))
                        .with_severity(FindingSeverity::Low),
                );
                break;
            }
        }

        // Check for extensions that could be security risks
        let risky_extensions = [
            (
                "plpythonu",
                "PL/Python Untrusted",
                "Allows arbitrary Python code execution",
            ),
            (
                "plperlu",
                "PL/Perl Untrusted",
                "Allows arbitrary Perl code execution",
            ),
            ("adminpack", "Admin Pack", "Provides file system access"),
            ("file_fdw", "File FDW", "Can read arbitrary files"),
        ];

        for (ext, name, desc) in risky_extensions {
            if data_lower.contains(ext) {
                result.add_finding(
                    Finding::new(
                        FindingType::Misconfiguration,
                        &format!("{} Extension Enabled", name),
                    )
                    .with_description(&format!("{} extension is enabled. {}", name, desc))
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation(&format!("Review necessity of {} extension", name)),
                );
            }
        }

        result.add_output(&format!(
            "PostgreSQL analysis complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

impl PostgresInfoScript {
    fn check_version_vulns(&self, version: &str, result: &mut ScriptResult) {
        // Parse version like "14.5" or "PostgreSQL 14.5"
        let version_str = version
            .to_lowercase()
            .replace("postgresql", "")
            .trim()
            .to_string();

        let parts: Vec<u32> = version_str
            .split('.')
            .filter_map(|p| p.trim().parse().ok())
            .collect();

        if parts.is_empty() {
            return;
        }

        let major = parts[0];
        let minor = parts.get(1).copied().unwrap_or(0);

        // End of life versions (< 12 as of 2024)
        if major < 12 {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "End-of-Life PostgreSQL Version")
                    .with_description(&format!(
                        "PostgreSQL {} is end-of-life and no longer receives security updates",
                        version
                    ))
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Upgrade to PostgreSQL 12 or later"),
            );
        }

        // CVE-2023-2454 - CREATE SCHEMA privilege escalation (fixed in various minors)
        let affected_2454 = match major {
            15 if minor < 3 => true,
            14 if minor < 8 => true,
            13 if minor < 11 => true,
            12 if minor < 15 => true,
            _ => false,
        };

        if affected_2454 {
            result.add_finding(
                Finding::new(
                    FindingType::Vulnerability,
                    "CREATE SCHEMA Privilege Escalation",
                )
                .with_cve("CVE-2023-2454")
                .with_description(
                    "PostgreSQL version may be vulnerable to privilege escalation \
                         via CREATE SCHEMA statement.",
                )
                .with_severity(FindingSeverity::High)
                .with_remediation(&format!(
                    "Upgrade PostgreSQL {} to latest minor version",
                    major
                )),
            );
        }

        // CVE-2019-9193 - COPY command arbitrary code execution
        // Affects all versions when a user has COPY TO/FROM PROGRAM privilege
        result.add_finding(
            Finding::new(FindingType::Discovery, "COPY PROGRAM Capability")
                .with_cve("CVE-2019-9193")
                .with_description(
                    "PostgreSQL COPY TO/FROM PROGRAM allows command execution. \
                     Ensure only trusted users have this capability.",
                )
                .with_severity(FindingSeverity::Info),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgres_script() {
        let script = PostgresInfoScript::new();
        assert_eq!(script.id(), "postgres-info");
    }

    #[test]
    fn test_trust_auth() {
        let script = PostgresInfoScript::new();
        let mut ctx = ScriptContext::new("192.168.1.1", 5432);
        ctx.set_data("postgres_auth", "trust");
        ctx.set_data("postgres_version", "14.5");

        let result = script.run(&ctx).unwrap();
        let has_trust = result
            .findings
            .iter()
            .any(|f| f.title.contains("Trust Authentication"));
        assert!(has_trust);
    }
}
