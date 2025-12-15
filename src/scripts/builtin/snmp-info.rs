/// SNMP Information Script
///
/// Detects SNMP services and identifies security issues
/// including default community strings.
use crate::scripts::types::*;
use crate::scripts::Script;

/// SNMP Information Script
pub struct SnmpInfoScript {
    meta: ScriptMetadata,
}

impl SnmpInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "snmp-info".to_string(),
                name: "SNMP Service Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects SNMP services and identifies configuration issues"
                    .to_string(),
                categories: vec![
                    ScriptCategory::Discovery,
                    ScriptCategory::Vuln,
                    ScriptCategory::Safe,
                ],
                protocols: vec!["snmp".to_string()],
                ports: vec![161, 162],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://tools.ietf.org/html/rfc3411".to_string()],
            },
        }
    }
}

impl Default for SnmpInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for SnmpInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let snmp_data = ctx.get_data("snmp_response").unwrap_or("");
        let community = ctx.get_data("snmp_community").unwrap_or("");
        let version = ctx.get_data("snmp_version").unwrap_or("");

        if snmp_data.is_empty() && community.is_empty() {
            result.add_output("No SNMP data available in context");
            return Ok(result);
        }

        result.success = true;

        // SNMP detected
        result.add_finding(
            Finding::new(FindingType::Discovery, "SNMP Service Detected")
                .with_description(&format!("SNMP service running on port {}", ctx.port))
                .with_severity(FindingSeverity::Info),
        );

        // Check SNMP version
        if !version.is_empty() {
            result.extract("snmp_version", version);

            match version {
                "1" | "v1" => {
                    result.add_finding(
                        Finding::new(FindingType::Misconfiguration, "SNMPv1 in Use")
                            .with_description(
                                "SNMPv1 has no encryption and uses cleartext community strings. \
                                 This is insecure and should be upgraded.",
                            )
                            .with_severity(FindingSeverity::High)
                            .with_remediation(
                                "Upgrade to SNMPv3 with authentication and encryption",
                            ),
                    );
                }
                "2" | "2c" | "v2c" => {
                    result.add_finding(
                        Finding::new(FindingType::Misconfiguration, "SNMPv2c in Use")
                            .with_description(
                                "SNMPv2c uses cleartext community strings. \
                                 Consider upgrading to SNMPv3.",
                            )
                            .with_severity(FindingSeverity::Medium)
                            .with_remediation(
                                "Upgrade to SNMPv3 with authentication and encryption",
                            ),
                    );
                }
                "3" | "v3" => {
                    result.add_finding(
                        Finding::new(FindingType::Discovery, "SNMPv3 in Use")
                            .with_description(
                                "SNMPv3 detected (supports authentication and encryption)",
                            )
                            .with_severity(FindingSeverity::Info),
                    );
                }
                _ => {}
            }
        }

        // Check for default community strings
        let community_lower = community.to_lowercase();
        let default_communities = [
            "public",
            "private",
            "community",
            "snmp",
            "admin",
            "default",
            "test",
        ];

        if default_communities.iter().any(|c| community_lower == *c) {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "Default SNMP Community String")
                    .with_description(&format!(
                        "SNMP is accessible with default community string '{}'. \
                         This allows unauthorized access to device information.",
                        community
                    ))
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Change community strings to unique, complex values"),
            );
        } else if !community.is_empty() {
            result.extract("snmp_community", community);
        }

        // Parse system information from SNMP data
        let data_lower = snmp_data.to_lowercase();

        // System description (OID 1.3.6.1.2.1.1.1)
        if data_lower.contains("sysdescr") || data_lower.contains("system description") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "System Description Available")
                    .with_description("SNMP exposes system description")
                    .with_evidence(snmp_data)
                    .with_severity(FindingSeverity::Low),
            );
        }

        // Contact and location
        if data_lower.contains("syscontact") || data_lower.contains("syslocation") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "System Contact/Location Exposed")
                    .with_description("SNMP exposes contact and location information")
                    .with_severity(FindingSeverity::Low),
            );
        }

        // Network interfaces
        if data_lower.contains("interface") || data_lower.contains("ifindex") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Network Interface Information")
                    .with_description("SNMP exposes network interface details")
                    .with_severity(FindingSeverity::Low),
            );
        }

        // Routing information
        if data_lower.contains("route") || data_lower.contains("iproute") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Routing Table Information")
                    .with_description("SNMP may expose routing table information")
                    .with_severity(FindingSeverity::Medium),
            );
        }

        result.add_output(&format!(
            "SNMP analysis complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snmp_script() {
        let script = SnmpInfoScript::new();
        assert_eq!(script.id(), "snmp-info");
    }

    #[test]
    fn test_default_community() {
        let script = SnmpInfoScript::new();
        let mut ctx = ScriptContext::new("192.168.1.1", 161);
        ctx.set_data("snmp_community", "public");
        ctx.set_data("snmp_version", "2c");

        let result = script.run(&ctx).unwrap();
        let has_default = result
            .findings
            .iter()
            .any(|f| f.title.contains("Default SNMP Community"));
        assert!(has_default);
    }
}
