/// Telnet Information Script
///
/// Detects Telnet services and identifies security issues.
/// Telnet is inherently insecure (cleartext) and should be replaced with SSH.

use crate::scripts::types::*;
use crate::scripts::Script;

/// Telnet Information Script
pub struct TelnetInfoScript {
    meta: ScriptMetadata,
}

impl TelnetInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "telnet-info".to_string(),
                name: "Telnet Service Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects Telnet services and identifies security concerns".to_string(),
                categories: vec![ScriptCategory::Banner, ScriptCategory::Vuln, ScriptCategory::Safe],
                protocols: vec!["telnet".to_string()],
                ports: vec![23, 2323, 992],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://tools.ietf.org/html/rfc854".to_string()],
            },
        }
    }
}

impl Default for TelnetInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for TelnetInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let banner = ctx.get_data("banner").unwrap_or("");

        if banner.is_empty() {
            result.add_output("No Telnet banner available in context");
            return Ok(result);
        }

        result.success = true;

        // Telnet is always a security concern
        result.add_finding(
            Finding::new(FindingType::Vulnerability, "Telnet Service Enabled")
                .with_description(
                    "Telnet transmits all data including passwords in cleartext. \
                     This service should be disabled in favor of SSH."
                )
                .with_severity(FindingSeverity::High)
                .with_remediation("Disable Telnet and use SSH for remote administration"),
        );

        let banner_lower = banner.to_lowercase();

        // Identify device type from banner
        let device_patterns = [
            ("cisco", "Cisco Device"),
            ("juniper", "Juniper Device"),
            ("mikrotik", "MikroTik Router"),
            ("ubnt", "Ubiquiti Device"),
            ("linux", "Linux System"),
            ("bsd", "BSD System"),
            ("busybox", "BusyBox (Embedded Linux)"),
            ("router", "Router"),
            ("switch", "Network Switch"),
            ("firewall", "Firewall"),
        ];

        for (pattern, device) in device_patterns {
            if banner_lower.contains(pattern) {
                result.add_finding(
                    Finding::new(FindingType::Discovery, &format!("{} Detected", device))
                        .with_description(&format!("Device type: {}", device))
                        .with_evidence(banner)
                        .with_severity(FindingSeverity::Info),
                );
                result.extract("device_type", device);
                break;
            }
        }

        // Check for default credential prompts
        if banner_lower.contains("login:") || banner_lower.contains("username:") {
            result.add_finding(
                Finding::new(FindingType::Discovery, "Login Prompt Detected")
                    .with_description("Telnet service shows login prompt")
                    .with_severity(FindingSeverity::Info),
            );
        }

        // Check for potential default credentials
        if banner_lower.contains("default password")
            || banner_lower.contains("admin")
            || banner_lower.contains("root")
        {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Potential Default Credentials")
                    .with_description("Banner suggests default credentials may be in use")
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Change default credentials immediately"),
            );
        }

        // Check for version info
        if let Some(version) = self.extract_version(banner) {
            result.extract("telnet_version", &version);
        }

        result.extract("telnet_banner", banner);
        result.add_output(&format!("Telnet banner: {}", banner));
        Ok(result)
    }
}

impl TelnetInfoScript {
    fn extract_version(&self, banner: &str) -> Option<String> {
        let words: Vec<&str> = banner.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            if word.to_lowercase() == "version" || word.to_lowercase() == "ver" {
                if let Some(version) = words.get(i + 1) {
                    return Some(version.to_string());
                }
            }
            if word.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) && word.contains('.') {
                return Some(word.to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telnet_script() {
        let script = TelnetInfoScript::new();
        assert_eq!(script.id(), "telnet-info");
    }

    #[test]
    fn test_telnet_always_vuln() {
        let script = TelnetInfoScript::new();
        let mut ctx = ScriptContext::new("example.com", 23);
        ctx.set_data("banner", "Welcome to Linux\r\nlogin:");

        let result = script.run(&ctx).unwrap();
        let has_vuln = result.findings.iter().any(|f| f.title.contains("Telnet Service Enabled"));
        assert!(has_vuln);
    }
}
