/// LDAP Information Script
///
/// Detects LDAP services and identifies security issues
/// including anonymous binding and cleartext authentication.
use crate::scripts::types::*;
use crate::scripts::Script;

/// LDAP Information Script
pub struct LdapInfoScript {
    meta: ScriptMetadata,
}

impl LdapInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "ldap-info".to_string(),
                name: "LDAP Service Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects LDAP services and identifies security misconfigurations"
                    .to_string(),
                categories: vec![
                    ScriptCategory::Discovery,
                    ScriptCategory::Vuln,
                    ScriptCategory::Safe,
                ],
                protocols: vec!["ldap".to_string(), "ldaps".to_string()],
                ports: vec![389, 636, 3268, 3269],
                license: "MIT".to_string(),
                cves: vec![
                    "CVE-2021-42278".to_string(), // sAMAccountName spoofing
                    "CVE-2021-42287".to_string(), // noPac
                ],
                references: vec!["https://tools.ietf.org/html/rfc4511".to_string()],
            },
        }
    }
}

impl Default for LdapInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for LdapInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let ldap_data = ctx.get_data("ldap_response").unwrap_or("");
        let anonymous_bind = ctx.get_data("ldap_anonymous").unwrap_or("");
        let tls_enabled = ctx.get_data("ldap_tls").unwrap_or("");

        if ldap_data.is_empty() && anonymous_bind.is_empty() {
            result.add_output("No LDAP data available in context");
            return Ok(result);
        }

        result.success = true;

        // Determine service type
        let service_name = if ctx.port == 636 || ctx.port == 3269 {
            "LDAPS (LDAP over TLS)"
        } else {
            "LDAP"
        };

        result.add_finding(
            Finding::new(
                FindingType::Discovery,
                &format!("{} Service Detected", service_name),
            )
            .with_description(&format!(
                "{} service running on port {}",
                service_name, ctx.port
            ))
            .with_severity(FindingSeverity::Info),
        );

        // Check for anonymous binding
        match anonymous_bind.to_lowercase().as_str() {
            "true" | "enabled" | "yes" | "1" | "allowed" => {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "LDAP Anonymous Bind Allowed")
                        .with_description(
                            "LDAP server allows anonymous binding. This can expose \
                             directory information including usernames, groups, and structure.",
                        )
                        .with_severity(FindingSeverity::High)
                        .with_remediation(
                            "Disable anonymous LDAP binding in directory configuration",
                        ),
                );
            }
            "false" | "disabled" | "no" | "0" => {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "Anonymous Bind Disabled")
                        .with_description("LDAP anonymous binding is disabled")
                        .with_severity(FindingSeverity::Info),
                );
            }
            _ => {}
        }

        // Check TLS status for non-LDAPS ports
        if ctx.port == 389 || ctx.port == 3268 {
            match tls_enabled.to_lowercase().as_str() {
                "false" | "disabled" | "no" | "0" => {
                    result.add_finding(
                        Finding::new(FindingType::Misconfiguration, "LDAP Without TLS")
                            .with_description(
                                "LDAP is running without TLS encryption. Credentials and \
                                 data are transmitted in cleartext.",
                            )
                            .with_severity(FindingSeverity::High)
                            .with_remediation("Enable LDAPS or STARTTLS for LDAP connections"),
                    );
                }
                "true" | "starttls" | "enabled" => {
                    result.add_finding(
                        Finding::new(FindingType::Discovery, "STARTTLS Available")
                            .with_description("LDAP STARTTLS is available for encryption")
                            .with_severity(FindingSeverity::Info),
                    );
                }
                _ => {}
            }
        }

        let data_lower = ldap_data.to_lowercase();

        // Detect directory type
        let directory_types = [
            ("active directory", "Microsoft Active Directory"),
            ("microsoft", "Microsoft Active Directory"),
            ("openldap", "OpenLDAP"),
            ("389 directory", "389 Directory Server"),
            ("fedora directory", "Fedora Directory Server"),
            ("oracle", "Oracle Internet Directory"),
            ("novell", "Novell eDirectory"),
            ("apacheds", "Apache Directory Server"),
        ];

        for (pattern, directory) in directory_types {
            if data_lower.contains(pattern) {
                result.extract("directory_type", directory);
                result.add_finding(
                    Finding::new(FindingType::Version, &format!("{} Detected", directory))
                        .with_description(&format!("Directory server: {}", directory))
                        .with_severity(FindingSeverity::Info),
                );
                break;
            }
        }

        // Check for domain information
        if data_lower.contains("dc=") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Domain Structure Exposed")
                    .with_description("LDAP exposes domain naming context (DC)")
                    .with_severity(FindingSeverity::Low),
            );
        }

        // Check for Active Directory specific issues
        if data_lower.contains("active directory") || data_lower.contains("microsoft") {
            // LDAP channel binding
            if data_lower.contains("channel binding") && data_lower.contains("not required") {
                result.add_finding(
                    Finding::new(
                        FindingType::Misconfiguration,
                        "LDAP Channel Binding Not Required",
                    )
                    .with_description(
                        "LDAP channel binding is not enforced, allowing potential \
                             relay attacks against domain controllers.",
                    )
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Enable LDAP channel binding via Group Policy"),
                );
            }

            // LDAP signing
            if data_lower.contains("signing") && data_lower.contains("not required") {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "LDAP Signing Not Required")
                        .with_description(
                            "LDAP signing is not required, allowing potential \
                             man-in-the-middle attacks.",
                        )
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Require LDAP signing via Group Policy"),
                );
            }
        }

        // Check for sensitive attributes exposed
        let sensitive_attrs = [
            "userpassword",
            "unicodepwd",
            "ntpasswordhash",
            "lmpasswordhash",
        ];
        for attr in sensitive_attrs {
            if data_lower.contains(attr) {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, "Sensitive Attribute Exposed")
                        .with_description(&format!(
                            "Password-related attribute '{}' found in LDAP response",
                            attr
                        ))
                        .with_severity(FindingSeverity::Critical)
                        .with_remediation("Restrict access to sensitive LDAP attributes"),
                );
                break;
            }
        }

        result.add_output(&format!(
            "LDAP analysis complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_script() {
        let script = LdapInfoScript::new();
        assert_eq!(script.id(), "ldap-info");
    }

    #[test]
    fn test_anonymous_bind() {
        let script = LdapInfoScript::new();
        let mut ctx = ScriptContext::new("dc.example.com", 389);
        ctx.set_data("ldap_anonymous", "true");
        ctx.set_data("ldap_response", "Active Directory");

        let result = script.run(&ctx).unwrap();
        let has_anon = result
            .findings
            .iter()
            .any(|f| f.title.contains("Anonymous Bind Allowed"));
        assert!(has_anon);
    }
}
