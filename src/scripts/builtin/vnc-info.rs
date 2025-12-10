/// VNC Information Script
///
/// Detects VNC services and identifies security issues
/// including weak authentication and known vulnerabilities.

use crate::scripts::types::*;
use crate::scripts::Script;

/// VNC Information Script
pub struct VncInfoScript {
    meta: ScriptMetadata,
}

impl VncInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "vnc-info".to_string(),
                name: "VNC Service Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects VNC services and identifies security issues".to_string(),
                categories: vec![ScriptCategory::Discovery, ScriptCategory::Vuln, ScriptCategory::Safe],
                protocols: vec!["vnc".to_string(), "rfb".to_string()],
                ports: vec![5900, 5901, 5902, 5903, 5800],
                license: "MIT".to_string(),
                cves: vec![
                    "CVE-2019-15678".to_string(), // TightVNC heap buffer overflow
                    "CVE-2018-7225".to_string(),  // LibVNC auth bypass
                ],
                references: vec!["https://tools.ietf.org/html/rfc6143".to_string()],
            },
        }
    }
}

impl Default for VncInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for VncInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let banner = ctx.get_data("banner").unwrap_or("");
        let auth_types = ctx.get_data("vnc_auth").unwrap_or("");

        if banner.is_empty() && auth_types.is_empty() {
            result.add_output("No VNC data available in context");
            return Ok(result);
        }

        result.success = true;
        let banner_lower = banner.to_lowercase();

        // VNC detected
        result.add_finding(
            Finding::new(FindingType::Discovery, "VNC Service Detected")
                .with_description(&format!("VNC (Remote Framebuffer) service on port {}", ctx.port))
                .with_severity(FindingSeverity::Info),
        );

        // Extract RFB version
        if banner.starts_with("RFB ") {
            let version = banner.trim_start_matches("RFB ").trim();
            result.extract("rfb_version", version);
            result.add_finding(
                Finding::new(FindingType::Version, "RFB Protocol Version")
                    .with_description(&format!("RFB version: {}", version))
                    .with_severity(FindingSeverity::Info),
            );

            // Check for old protocol versions
            if version.starts_with("003.003") || version.starts_with("003.007") {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "Old RFB Protocol Version")
                        .with_description(&format!(
                            "RFB {} is an older protocol version with limited security features",
                            version
                        ))
                        .with_severity(FindingSeverity::Low)
                        .with_remediation("Upgrade VNC server to support RFB 3.8 or later"),
                );
            }
        }

        // Check authentication types
        let auth_lower = auth_types.to_lowercase();
        if auth_lower.contains("none") || auth_lower.contains("no auth") || auth_lower == "1" {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "VNC No Authentication")
                    .with_description(
                        "VNC server allows connections without authentication. \
                         Anyone can view and control this desktop."
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Enable VNC authentication immediately"),
            );
        }

        if auth_lower.contains("vnc auth") || auth_lower == "2" {
            result.add_finding(
                Finding::new(FindingType::Discovery, "VNC Password Authentication")
                    .with_description("VNC uses password-based authentication")
                    .with_severity(FindingSeverity::Info),
            );
        }

        // Identify VNC server type
        let vnc_servers = [
            ("realvnc", "RealVNC"),
            ("tightvnc", "TightVNC"),
            ("tigervnc", "TigerVNC"),
            ("ultravnc", "UltraVNC"),
            ("turbovnc", "TurboVNC"),
            ("libvnc", "LibVNC"),
            ("x11vnc", "x11vnc"),
            ("vino", "Vino (GNOME)"),
            ("krfb", "KRFB (KDE)"),
            ("apple", "Apple Remote Desktop"),
        ];

        for (pattern, server) in vnc_servers {
            if banner_lower.contains(pattern) {
                result.extract("vnc_server", server);
                result.add_finding(
                    Finding::new(FindingType::Version, &format!("{} Detected", server))
                        .with_description(&format!("VNC server: {}", server))
                        .with_severity(FindingSeverity::Info),
                );

                // Server-specific vulnerabilities
                self.check_server_vulns(server, &banner_lower, &mut result);
                break;
            }
        }

        // Check for internet exposure
        let is_external = !ctx.host.starts_with("192.168.")
            && !ctx.host.starts_with("10.")
            && !ctx.host.starts_with("172.")
            && ctx.host != "localhost"
            && ctx.host != "127.0.0.1";

        if is_external {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "VNC Exposed to Internet")
                    .with_description(
                        "VNC service appears to be exposed to the internet. \
                         VNC traffic is often unencrypted and susceptible to brute force."
                    )
                    .with_severity(FindingSeverity::High)
                    .with_remediation(
                        "Use VPN or SSH tunneling for remote VNC access. \
                         Do not expose VNC directly to the internet."
                    ),
            );
        }

        // Check for encryption indicators
        if !banner_lower.contains("tls") && !banner_lower.contains("ssl") && !banner_lower.contains("encrypt") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "VNC Without Encryption")
                    .with_description(
                        "VNC appears to be running without TLS encryption. \
                         Screen contents and keystrokes are transmitted in cleartext."
                    )
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Enable VNC encryption or tunnel through SSH/VPN"),
            );
        }

        result.extract("vnc_banner", banner);
        result.add_output(&format!("VNC analysis complete for {}:{}", ctx.host, ctx.port));
        Ok(result)
    }
}

impl VncInfoScript {
    fn check_server_vulns(&self, server: &str, banner: &str, result: &mut ScriptResult) {
        match server {
            "TightVNC" => {
                // CVE-2019-15678 - heap buffer overflow
                if banner.contains("1.3.") || banner.contains("2.7.") || banner.contains("2.8.") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "TightVNC Potential Vulnerability")
                            .with_cve("CVE-2019-15678")
                            .with_description(
                                "TightVNC versions prior to 2.8.63 may be vulnerable to \
                                 heap buffer overflow (CVE-2019-15678)."
                            )
                            .with_severity(FindingSeverity::High)
                            .with_remediation("Upgrade to TightVNC 2.8.63 or later"),
                    );
                }
            }
            "LibVNC" => {
                // CVE-2018-7225 - auth bypass
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "LibVNC Authentication Bypass Check")
                        .with_cve("CVE-2018-7225")
                        .with_description(
                            "LibVNC-based servers may be vulnerable to auth bypass \
                             if not updated to patched versions."
                        )
                        .with_severity(FindingSeverity::Medium)
                        .with_remediation("Ensure LibVNC is updated to latest version"),
                );
            }
            "UltraVNC" => {
                // Various vulnerabilities in older versions
                if banner.contains("1.0.") || banner.contains("1.1.") || banner.contains("1.2.") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "Outdated UltraVNC Version")
                            .with_description(
                                "Older UltraVNC versions have known vulnerabilities \
                                 including buffer overflows and auth bypasses."
                            )
                            .with_severity(FindingSeverity::High)
                            .with_remediation("Upgrade to latest UltraVNC version"),
                    );
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vnc_script() {
        let script = VncInfoScript::new();
        assert_eq!(script.id(), "vnc-info");
    }

    #[test]
    fn test_vnc_no_auth() {
        let script = VncInfoScript::new();
        let mut ctx = ScriptContext::new("192.168.1.1", 5900);
        ctx.set_data("banner", "RFB 003.008");
        ctx.set_data("vnc_auth", "none");

        let result = script.run(&ctx).unwrap();
        let has_no_auth = result.findings.iter().any(|f| f.title.contains("No Authentication"));
        assert!(has_no_auth);
    }
}
