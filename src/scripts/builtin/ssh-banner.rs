/// SSH Banner Script
///
/// Grabs and analyzes SSH banners for version detection
/// and potential vulnerability identification.

use crate::scripts::types::*;
use crate::scripts::Script;

/// SSH Banner Detection Script
pub struct SshBannerScript {
    meta: ScriptMetadata,
}

impl SshBannerScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "ssh-banner".to_string(),
                name: "SSH Banner Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Grabs SSH banner and identifies version information".to_string(),
                categories: vec![ScriptCategory::Banner, ScriptCategory::Version, ScriptCategory::Safe, ScriptCategory::Default],
                protocols: vec!["ssh".to_string()],
                ports: vec![22, 2222, 22222],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://www.openssh.com/".to_string()],
            },
        }
    }

    fn parse_ssh_version(&self, banner: &str) -> Option<SshVersion> {
        // SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1
        // SSH-2.0-dropbear_2020.81
        // SSH-1.99-OpenSSH_3.8.1

        if !banner.starts_with("SSH-") {
            return None;
        }

        let parts: Vec<&str> = banner.splitn(3, '-').collect();
        if parts.len() < 3 {
            return None;
        }

        let protocol = parts[1].to_string();
        let software_part = parts[2];

        // Parse software and version
        let (software, version, os_info) = if software_part.contains('_') {
            let sw_parts: Vec<&str> = software_part.splitn(2, '_').collect();
            let software = sw_parts[0].to_string();
            let rest = sw_parts.get(1).unwrap_or(&"");

            // Check for OS info (e.g., "8.4p1 Ubuntu-5ubuntu1")
            if let Some(space_idx) = rest.find(' ') {
                let version = rest[..space_idx].to_string();
                let os_info = Some(rest[space_idx + 1..].to_string());
                (software, version, os_info)
            } else {
                (software, rest.to_string(), None)
            }
        } else {
            (software_part.to_string(), String::new(), None)
        };

        Some(SshVersion {
            protocol,
            software,
            version,
            os_info,
        })
    }
}

#[derive(Debug)]
struct SshVersion {
    protocol: String,
    software: String,
    version: String,
    os_info: Option<String>,
}

impl Default for SshBannerScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for SshBannerScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let banner = ctx.get_data("banner").unwrap_or("");

        if banner.is_empty() {
            result.add_output("No SSH banner available in context");
            return Ok(result);
        }

        result.success = true;

        // Parse version info
        if let Some(version_info) = self.parse_ssh_version(banner) {
            // Main finding
            result.add_finding(
                Finding::new(FindingType::Version, &format!("{} Detected", version_info.software))
                    .with_description(&format!(
                        "SSH Software: {}\nVersion: {}\nProtocol: SSH-{}",
                        version_info.software, version_info.version, version_info.protocol
                    ))
                    .with_evidence(banner)
                    .with_severity(FindingSeverity::Info),
            );

            // Extract data
            result.extract("ssh_software", &version_info.software);
            result.extract("ssh_version", &version_info.version);
            result.extract("ssh_protocol", &version_info.protocol);

            if let Some(os) = &version_info.os_info {
                result.extract("ssh_os_info", os);
                result.add_finding(
                    Finding::new(FindingType::Discovery, "OS Information Disclosed")
                        .with_description(&format!("Operating system: {}", os))
                        .with_evidence(os)
                        .with_severity(FindingSeverity::Info),
                );
            }

            // Check for old protocols
            if version_info.protocol == "1.99" || version_info.protocol == "1.0" {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "SSH Protocol 1.x Supported")
                        .with_description("SSH-1 protocol is vulnerable to various attacks")
                        .with_severity(FindingSeverity::High)
                        .with_remediation("Disable SSH-1 protocol support"),
                );
            }

            // Check for known vulnerable versions
            self.check_vulnerable_versions(&version_info, &mut result);
        } else {
            result.add_finding(
                Finding::new(FindingType::Discovery, "SSH Banner")
                    .with_description("Raw SSH banner captured")
                    .with_evidence(banner)
                    .with_severity(FindingSeverity::Info),
            );
            result.extract("ssh_banner_raw", banner);
        }

        result.add_output(&format!("SSH banner: {}", banner));
        Ok(result)
    }
}

impl SshBannerScript {
    fn check_vulnerable_versions(&self, version: &SshVersion, result: &mut ScriptResult) {
        let software = version.software.to_lowercase();
        let ver = &version.version;

        // OpenSSH vulnerabilities
        if software.contains("openssh") {
            // CVE-2024-6387 - RegreSSHion (OpenSSH < 9.8)
            if self.version_lt(ver, "9.8") && !self.version_lt(ver, "8.5") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "Potential RegreSSHion Vulnerability")
                        .with_cve("CVE-2024-6387")
                        .with_description("OpenSSH 8.5p1 to 9.7p1 may be vulnerable to race condition in signal handler")
                        .with_severity(FindingSeverity::Critical)
                        .with_remediation("Upgrade to OpenSSH 9.8 or later"),
                );
            }

            // CVE-2023-38408 - PKCS#11 feature
            if self.version_lt(ver, "9.3") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "Potential PKCS#11 Vulnerability")
                        .with_cve("CVE-2023-38408")
                        .with_description("OpenSSH before 9.3p2 has PKCS#11 feature vulnerabilities")
                        .with_severity(FindingSeverity::High)
                        .with_remediation("Upgrade to OpenSSH 9.3p2 or later"),
                );
            }

            // CVE-2016-20012 - Username enumeration
            if self.version_lt(ver, "8.0") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "Username Enumeration Possible")
                        .with_cve("CVE-2016-20012")
                        .with_description("OpenSSH before 8.0 allows username enumeration via timing")
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Upgrade to OpenSSH 8.0 or later"),
                );
            }
        }

        // Dropbear vulnerabilities
        if software.contains("dropbear") {
            if self.version_lt(ver, "2022.83") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "Outdated Dropbear SSH")
                        .with_description("Dropbear versions before 2022.83 have known vulnerabilities")
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Upgrade to Dropbear 2022.83 or later"),
                );
            }
        }
    }

    fn version_lt(&self, version: &str, target: &str) -> bool {
        // Simple version comparison (handles formats like "8.4p1", "9.8")
        let parse_version = |s: &str| -> Vec<u32> {
            s.chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect::<String>()
                .split('.')
                .filter_map(|p| p.parse().ok())
                .collect()
        };

        let v1 = parse_version(version);
        let v2 = parse_version(target);

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_banner_script() {
        let script = SshBannerScript::new();
        assert_eq!(script.id(), "ssh-banner");
        assert!(script.has_category(ScriptCategory::Banner));
    }

    #[test]
    fn test_openssh_parsing() {
        let script = SshBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 22);
        ctx.set_data("banner", "SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(result.extracted.get("ssh_software"), Some(&"OpenSSH".to_string()));
        assert_eq!(result.extracted.get("ssh_version"), Some(&"8.4p1".to_string()));
    }

    #[test]
    fn test_dropbear_parsing() {
        let script = SshBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 22);
        ctx.set_data("banner", "SSH-2.0-dropbear_2020.81");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(result.extracted.get("ssh_software"), Some(&"dropbear".to_string()));
    }

    #[test]
    fn test_version_comparison() {
        let script = SshBannerScript::new();
        assert!(script.version_lt("8.4", "9.0"));
        assert!(script.version_lt("8.4p1", "9.8"));
        assert!(!script.version_lt("9.8", "8.4"));
        assert!(!script.version_lt("9.0", "9.0"));
    }

    #[test]
    fn test_old_protocol_detection() {
        let script = SshBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 22);
        ctx.set_data("banner", "SSH-1.99-OpenSSH_3.8.1");

        let result = script.run(&ctx).unwrap();
        let has_protocol_vuln = result
            .findings
            .iter()
            .any(|f| f.title.contains("SSH Protocol 1.x"));
        assert!(has_protocol_vuln);
    }
}
