/// RDP Information Script
///
/// Detects RDP services and identifies security configuration issues.
use crate::scripts::types::*;
use crate::scripts::Script;

/// RDP Information Script
pub struct RdpInfoScript {
    meta: ScriptMetadata,
}

impl RdpInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "rdp-info".to_string(),
                name: "RDP Service Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects RDP services and identifies security configuration".to_string(),
                categories: vec![ScriptCategory::Discovery, ScriptCategory::Vuln, ScriptCategory::Safe],
                protocols: vec!["rdp".to_string()],
                ports: vec![3389, 3390, 3391],
                license: "MIT".to_string(),
                cves: vec!["CVE-2019-0708".to_string()],
                references: vec!["https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/".to_string()],
            },
        }
    }
}

impl Default for RdpInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for RdpInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let rdp_data = ctx.get_data("rdp_response").unwrap_or("");
        let nla_enabled = ctx.get_data("rdp_nla").unwrap_or("");
        let encryption = ctx.get_data("rdp_encryption").unwrap_or("");

        if rdp_data.is_empty() && nla_enabled.is_empty() {
            result.add_output("No RDP data available in context");
            return Ok(result);
        }

        result.success = true;

        // RDP detected
        result.add_finding(
            Finding::new(FindingType::Discovery, "RDP Service Detected")
                .with_description(&format!(
                    "Remote Desktop Protocol service on port {}",
                    ctx.port
                ))
                .with_severity(FindingSeverity::Info),
        );

        // Internet-exposed RDP is a risk
        let is_external = !ctx.host.starts_with("192.168.")
            && !ctx.host.starts_with("10.")
            && !ctx.host.starts_with("172.")
            && ctx.host != "localhost"
            && ctx.host != "127.0.0.1";

        if is_external {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "RDP Exposed to Internet")
                    .with_description(
                        "RDP service appears to be exposed to the internet. \
                         This is a common attack vector for ransomware and brute force attacks.",
                    )
                    .with_severity(FindingSeverity::High)
                    .with_remediation(
                        "Use VPN or RD Gateway for remote access. \
                         Do not expose RDP directly to the internet.",
                    ),
            );
        }

        // Check NLA (Network Level Authentication)
        match nla_enabled.to_lowercase().as_str() {
            "false" | "disabled" | "no" | "0" => {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "NLA Disabled")
                        .with_description(
                            "Network Level Authentication is disabled. \
                             This allows unauthenticated users to reach the Windows login screen.",
                        )
                        .with_severity(FindingSeverity::High)
                        .with_remediation("Enable Network Level Authentication (NLA) for RDP"),
                );
            }
            "true" | "enabled" | "yes" | "1" => {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "NLA Enabled")
                        .with_description("Network Level Authentication is enabled")
                        .with_severity(FindingSeverity::Info),
                );
            }
            _ => {}
        }

        // Check encryption level
        let enc_lower = encryption.to_lowercase();
        if enc_lower.contains("low") || enc_lower.contains("none") || enc_lower.contains("client") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Weak RDP Encryption")
                    .with_description(&format!("RDP encryption level is weak: {}", encryption))
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Set RDP encryption to 'High' level"),
            );
        }

        // Check for BlueKeep vulnerability indicators
        let data_lower = rdp_data.to_lowercase();
        if data_lower.contains("windows 7")
            || data_lower.contains("windows server 2008")
            || data_lower.contains("windows xp")
            || data_lower.contains("windows vista")
        {
            result.add_finding(
                Finding::new(
                    FindingType::Vulnerability,
                    "Potential BlueKeep Vulnerability",
                )
                .with_cve("CVE-2019-0708")
                .with_description(
                    "System may be vulnerable to BlueKeep (CVE-2019-0708), \
                         a critical RCE vulnerability in RDP.",
                )
                .with_severity(FindingSeverity::Critical)
                .with_remediation(
                    "Apply security patches immediately. \
                         Block RDP at perimeter if patching is not possible.",
                ),
            );
        }

        // Windows version detection
        let windows_versions = [
            ("windows 11", "Windows 11"),
            ("windows 10", "Windows 10"),
            ("windows server 2022", "Windows Server 2022"),
            ("windows server 2019", "Windows Server 2019"),
            ("windows server 2016", "Windows Server 2016"),
            ("windows server 2012", "Windows Server 2012"),
            ("windows server 2008", "Windows Server 2008"),
            ("windows 8", "Windows 8"),
            ("windows 7", "Windows 7"),
        ];

        for (pattern, version) in windows_versions {
            if data_lower.contains(pattern) {
                result.extract("windows_version", version);
                result.add_finding(
                    Finding::new(FindingType::Version, &format!("{} Detected", version))
                        .with_description(&format!("Windows version: {}", version))
                        .with_severity(FindingSeverity::Info),
                );
                break;
            }
        }

        result.add_output(&format!(
            "RDP analysis complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdp_script() {
        let script = RdpInfoScript::new();
        assert_eq!(script.id(), "rdp-info");
    }

    #[test]
    fn test_nla_disabled() {
        let script = RdpInfoScript::new();
        let mut ctx = ScriptContext::new("192.168.1.1", 3389);
        ctx.set_data("rdp_response", "Windows Server 2019");
        ctx.set_data("rdp_nla", "disabled");

        let result = script.run(&ctx).unwrap();
        let has_nla_issue = result
            .findings
            .iter()
            .any(|f| f.title.contains("NLA Disabled"));
        assert!(has_nla_issue);
    }
}
