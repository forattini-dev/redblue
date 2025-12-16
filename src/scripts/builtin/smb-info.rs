/// SMB/CIFS Information Script
///
/// Detects SMB services and identifies security issues including
/// EternalBlue (MS17-010) and other SMB vulnerabilities.
use crate::scripts::types::*;
use crate::scripts::Script;

/// SMB Information Script
pub struct SmbInfoScript {
    meta: ScriptMetadata,
}

impl SmbInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "smb-info".to_string(),
                name: "SMB Service Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects SMB services and identifies security vulnerabilities".to_string(),
                categories: vec![ScriptCategory::Discovery, ScriptCategory::Vuln, ScriptCategory::Safe],
                protocols: vec!["smb".to_string(), "cifs".to_string()],
                ports: vec![445, 139],
                license: "MIT".to_string(),
                cves: vec![
                    "CVE-2017-0144".to_string(), // EternalBlue
                    "CVE-2020-0796".to_string(), // SMBGhost
                ],
                references: vec![
                    "https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview".to_string(),
                ],
            },
        }
    }
}

impl Default for SmbInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for SmbInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let smb_data = ctx.get_data("smb_response").unwrap_or("");
        let smb_version = ctx.get_data("smb_version").unwrap_or("");
        let signing = ctx.get_data("smb_signing").unwrap_or("");

        if smb_data.is_empty() && smb_version.is_empty() {
            result.add_output("No SMB data available in context");
            return Ok(result);
        }

        result.success = true;

        // SMB detected
        result.add_finding(
            Finding::new(FindingType::Discovery, "SMB Service Detected")
                .with_description(&format!("SMB/CIFS service running on port {}", ctx.port))
                .with_severity(FindingSeverity::Info),
        );

        // Check SMB version
        let version_lower = smb_version.to_lowercase();
        if !smb_version.is_empty() {
            result.extract("smb_version", smb_version);

            if version_lower.contains("1") || version_lower.contains("smb1") {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "SMBv1 Enabled")
                        .with_description(
                            "SMBv1 is enabled. This protocol version has known vulnerabilities \
                             including EternalBlue (MS17-010) and should be disabled.",
                        )
                        .with_severity(FindingSeverity::Critical)
                        .with_remediation("Disable SMBv1 and use SMBv2/v3"),
                );
            }
        }

        // Check message signing
        match signing.to_lowercase().as_str() {
            "disabled" | "not required" | "false" | "0" => {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "SMB Signing Not Required")
                        .with_description(
                            "SMB message signing is not required. This allows \
                             man-in-the-middle attacks and SMB relay attacks.",
                        )
                        .with_severity(FindingSeverity::High)
                        .with_remediation("Enable SMB signing on all systems"),
                );
            }
            "enabled" | "required" | "true" | "1" => {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "SMB Signing Enabled")
                        .with_description("SMB message signing is enabled")
                        .with_severity(FindingSeverity::Info),
                );
            }
            _ => {}
        }

        // Check for known vulnerabilities based on version info
        let data_lower = smb_data.to_lowercase();

        // EternalBlue (CVE-2017-0144) - Windows 7, Server 2008
        if (data_lower.contains("windows 7")
            || data_lower.contains("windows server 2008")
            || data_lower.contains("windows xp")
            || data_lower.contains("windows vista"))
            && (version_lower.contains("1") || version_lower.contains("smb1"))
        {
            result.add_finding(
                Finding::new(
                    FindingType::Vulnerability,
                    "Potential EternalBlue Vulnerability",
                )
                .with_cve("CVE-2017-0144")
                .with_description(
                    "System may be vulnerable to EternalBlue (MS17-010), \
                         a critical RCE vulnerability in SMBv1.",
                )
                .with_severity(FindingSeverity::Critical)
                .with_remediation("Apply MS17-010 patches immediately. Disable SMBv1."),
            );
        }

        // SMBGhost (CVE-2020-0796) - Windows 10 1903/1909
        if data_lower.contains("windows 10")
            && (data_lower.contains("1903") || data_lower.contains("1909"))
        {
            result.add_finding(
                Finding::new(
                    FindingType::Vulnerability,
                    "Potential SMBGhost Vulnerability",
                )
                .with_cve("CVE-2020-0796")
                .with_description(
                    "Windows 10 1903/1909 may be vulnerable to SMBGhost, \
                         a critical RCE in SMBv3.1.1 compression.",
                )
                .with_severity(FindingSeverity::Critical)
                .with_remediation("Apply KB4551762 patch or disable SMBv3 compression"),
            );
        }

        // Check for null session access
        if data_lower.contains("null session") || data_lower.contains("anonymous") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "SMB Null Session Allowed")
                    .with_description(
                        "SMB null sessions are allowed, enabling anonymous access \
                         to share enumeration and potentially sensitive information.",
                    )
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Disable null sessions via registry or Group Policy"),
            );
        }

        // Check for guest access
        if data_lower.contains("guest") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "SMB Guest Access Enabled")
                    .with_description("Guest account access to SMB shares may be enabled")
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Disable guest access to shares"),
            );
        }

        // Detect Windows version from SMB
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
            ("samba", "Samba (Linux)"),
        ];

        for (pattern, os) in windows_versions {
            if data_lower.contains(pattern) {
                result.extract("os_version", os);
                result.add_finding(
                    Finding::new(FindingType::Version, &format!("{} Detected", os))
                        .with_description(&format!("Operating system: {}", os))
                        .with_severity(FindingSeverity::Info),
                );
                break;
            }
        }

        result.add_output(&format!(
            "SMB analysis complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_script() {
        let script = SmbInfoScript::new();
        assert_eq!(script.id(), "smb-info");
    }

    #[test]
    fn test_smbv1_vuln() {
        let script = SmbInfoScript::new();
        let mut ctx = ScriptContext::new("192.168.1.1", 445);
        ctx.set_data("smb_version", "SMB1");
        ctx.set_data("smb_response", "Windows 7 Professional");

        let result = script.run(&ctx).unwrap();
        let has_vuln = result
            .findings
            .iter()
            .any(|f| f.title.contains("SMBv1 Enabled"));
        assert!(has_vuln);
    }
}
