/// FTP Banner Script
///
/// Grabs and analyzes FTP banners for version detection
/// and configuration issues.

use crate::scripts::types::*;
use crate::scripts::Script;

/// FTP Banner Detection Script
pub struct FtpBannerScript {
    meta: ScriptMetadata,
}

impl FtpBannerScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "ftp-banner".to_string(),
                name: "FTP Banner Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Grabs FTP banner and identifies server software and version".to_string(),
                categories: vec![ScriptCategory::Banner, ScriptCategory::Version, ScriptCategory::Safe, ScriptCategory::Default],
                protocols: vec!["ftp".to_string()],
                ports: vec![21, 2121],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://tools.ietf.org/html/rfc959".to_string()],
            },
        }
    }

    fn identify_ftp_server(&self, banner: &str) -> FtpServerInfo {
        let banner_lower = banner.to_lowercase();

        // Known FTP servers and their patterns
        let servers = [
            ("vsftpd", "vsFTPd", &["vsftpd"][..]),
            ("proftpd", "ProFTPD", &["proftpd"]),
            ("pureftpd", "Pure-FTPd", &["pure-ftpd", "pureftpd"]),
            ("filezilla", "FileZilla Server", &["filezilla"]),
            ("microsoft", "Microsoft FTP", &["microsoft ftp", "iis"]),
            ("wu-ftpd", "WU-FTPD", &["wu-ftpd", "wu-"]),
            ("ncftpd", "NcFTPd", &["ncftpd"]),
            ("glftpd", "glFTPd", &["glftpd"]),
            ("bftpd", "Bftpd", &["bftpd"]),
        ];

        for (id, name, patterns) in servers {
            if patterns.iter().any(|p| banner_lower.contains(p)) {
                return FtpServerInfo {
                    server_id: id.to_string(),
                    server_name: name.to_string(),
                    version: self.extract_version(banner),
                };
            }
        }

        FtpServerInfo {
            server_id: "unknown".to_string(),
            server_name: "Unknown FTP Server".to_string(),
            version: self.extract_version(banner),
        }
    }

    fn extract_version(&self, banner: &str) -> Option<String> {
        // Common version patterns
        // "220 (vsFTPd 3.0.3)"
        // "220 ProFTPD 1.3.5 Server"
        // "220-FileZilla Server 0.9.60 beta"

        // Try parenthesis pattern
        if let Some(start) = banner.find('(') {
            if let Some(end) = banner[start..].find(')') {
                let content = &banner[start + 1..start + end];
                // Extract version from content like "vsFTPd 3.0.3"
                if let Some(space_idx) = content.rfind(' ') {
                    let potential_version = &content[space_idx + 1..];
                    if potential_version.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                        return Some(potential_version.to_string());
                    }
                }
            }
        }

        // Try to find version number pattern
        let mut chars = banner.chars().peekable();
        while let Some(c) = chars.next() {
            if c.is_ascii_digit() {
                let mut version = String::from(c);
                while let Some(&next) = chars.peek() {
                    if next.is_ascii_digit() || next == '.' || next == '-' || next == 'p' {
                        version.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                if version.contains('.') {
                    return Some(version);
                }
            }
        }

        None
    }
}

#[derive(Debug)]
struct FtpServerInfo {
    server_id: String,
    server_name: String,
    version: Option<String>,
}

impl Default for FtpBannerScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for FtpBannerScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let banner = ctx.get_data("banner").unwrap_or("");

        if banner.is_empty() {
            result.add_output("No FTP banner available in context");
            return Ok(result);
        }

        result.success = true;

        // Identify server
        let server_info = self.identify_ftp_server(banner);

        // Main finding
        let mut finding = Finding::new(FindingType::Version, &format!("{} Detected", server_info.server_name))
            .with_evidence(banner)
            .with_severity(FindingSeverity::Info);

        if let Some(ref version) = server_info.version {
            finding = finding.with_description(&format!(
                "FTP Server: {}\nVersion: {}",
                server_info.server_name, version
            ));
        } else {
            finding = finding.with_description(&format!("FTP Server: {}", server_info.server_name));
        }

        result.add_finding(finding);

        // Extract data
        result.extract("ftp_server", &server_info.server_name);
        result.extract("ftp_server_id", &server_info.server_id);
        if let Some(version) = &server_info.version {
            result.extract("ftp_version", version);
        }

        // Check for anonymous FTP
        let banner_lower = banner.to_lowercase();
        if banner_lower.contains("anonymous") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Anonymous FTP May Be Enabled")
                    .with_description("Banner suggests anonymous FTP access may be available")
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Disable anonymous FTP unless required"),
            );
        }

        // Check for version disclosure
        if server_info.version.is_some() {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "FTP Version Disclosed")
                    .with_description("FTP server version is exposed in banner")
                    .with_severity(FindingSeverity::Low)
                    .with_remediation("Configure server to hide version information"),
            );
        }

        // Check for known vulnerable versions
        self.check_vulnerabilities(&server_info, &mut result);

        result.add_output(&format!("FTP banner: {}", banner));
        Ok(result)
    }
}

impl FtpBannerScript {
    fn check_vulnerabilities(&self, info: &FtpServerInfo, result: &mut ScriptResult) {
        let version = match &info.version {
            Some(v) => v,
            None => return,
        };

        match info.server_id.as_str() {
            "vsftpd" => {
                // CVE-2011-2523 - vsftpd 2.3.4 backdoor
                if version.starts_with("2.3.4") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "vsFTPd Backdoor (Smiley Face)")
                            .with_cve("CVE-2011-2523")
                            .with_description("vsFTPd 2.3.4 contained a backdoor that opens a shell on port 6200")
                            .with_severity(FindingSeverity::Critical)
                            .with_remediation("Upgrade immediately to a newer version"),
                    );
                }
            }
            "proftpd" => {
                // CVE-2019-12815 - ProFTPD mod_copy
                if self.version_lt(version, "1.3.6") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "ProFTPD mod_copy Vulnerability")
                            .with_cve("CVE-2019-12815")
                            .with_description("ProFTPD before 1.3.6 allows arbitrary file copy via mod_copy")
                            .with_severity(FindingSeverity::High)
                            .with_remediation("Upgrade to ProFTPD 1.3.6 or later, or disable mod_copy"),
                    );
                }
            }
            "pureftpd" => {
                // Generally secure, but check for very old versions
                if self.version_lt(version, "1.0.47") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "Outdated Pure-FTPd")
                            .with_description("Pure-FTPd before 1.0.47 has known vulnerabilities")
                            .with_severity(FindingSeverity::Medium)
                            .with_remediation("Upgrade to Pure-FTPd 1.0.47 or later"),
                    );
                }
            }
            _ => {}
        }
    }

    fn version_lt(&self, version: &str, target: &str) -> bool {
        let parse_version = |s: &str| -> Vec<u32> {
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
    fn test_ftp_banner_script() {
        let script = FtpBannerScript::new();
        assert_eq!(script.id(), "ftp-banner");
        assert!(script.has_category(ScriptCategory::Banner));
    }

    #[test]
    fn test_vsftpd_detection() {
        let script = FtpBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 21);
        ctx.set_data("banner", "220 (vsFTPd 3.0.3)");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(result.extracted.get("ftp_server_id"), Some(&"vsftpd".to_string()));
        assert_eq!(result.extracted.get("ftp_version"), Some(&"3.0.3".to_string()));
    }

    #[test]
    fn test_proftpd_detection() {
        let script = FtpBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 21);
        ctx.set_data("banner", "220 ProFTPD 1.3.5 Server (ProFTPD Default Installation)");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(result.extracted.get("ftp_server_id"), Some(&"proftpd".to_string()));
    }

    #[test]
    fn test_vsftpd_backdoor() {
        let script = FtpBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 21);
        ctx.set_data("banner", "220 (vsFTPd 2.3.4)");

        let result = script.run(&ctx).unwrap();
        let has_backdoor = result
            .findings
            .iter()
            .any(|f| f.cve == Some("CVE-2011-2523".to_string()));
        assert!(has_backdoor);
    }
}
