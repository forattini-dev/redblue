/// SMTP Banner Script
///
/// Grabs and analyzes SMTP banners for version detection
/// and mail server identification.
use crate::scripts::types::*;
use crate::scripts::Script;

/// SMTP Banner Detection Script
pub struct SmtpBannerScript {
    meta: ScriptMetadata,
}

impl SmtpBannerScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "smtp-banner".to_string(),
                name: "SMTP Banner Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Grabs SMTP banner and identifies mail server software".to_string(),
                categories: vec![
                    ScriptCategory::Banner,
                    ScriptCategory::Version,
                    ScriptCategory::Safe,
                    ScriptCategory::Default,
                ],
                protocols: vec!["smtp".to_string()],
                ports: vec![25, 465, 587, 2525],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://tools.ietf.org/html/rfc5321".to_string()],
            },
        }
    }

    fn identify_smtp_server(&self, banner: &str) -> SmtpServerInfo {
        let banner_lower = banner.to_lowercase();

        // Known SMTP servers and their patterns
        let servers = [
            ("postfix", "Postfix", &["postfix"][..]),
            ("sendmail", "Sendmail", &["sendmail"]),
            ("exim", "Exim", &["exim"]),
            (
                "exchange",
                "Microsoft Exchange",
                &["microsoft", "exchange", "esmtp mail"],
            ),
            ("qmail", "qmail", &["qmail"]),
            ("gmail", "Google SMTP", &["smtp.google", "gmail", "google"]),
            ("dovecot", "Dovecot", &["dovecot"]),
            ("courier", "Courier", &["courier"]),
            ("zimbra", "Zimbra", &["zimbra"]),
            (
                "office365",
                "Office 365",
                &["outlook", "office365", "protection.outlook"],
            ),
            ("protonmail", "ProtonMail", &["protonmail"]),
            ("mailcow", "mailcow", &["mailcow"]),
            ("hMailServer", "hMailServer", &["hmailserver"]),
        ];

        for (id, name, patterns) in servers {
            if patterns.iter().any(|p| banner_lower.contains(p)) {
                return SmtpServerInfo {
                    server_id: id.to_string(),
                    server_name: name.to_string(),
                    version: self.extract_version(banner),
                    hostname: self.extract_hostname(banner),
                };
            }
        }

        SmtpServerInfo {
            server_id: "unknown".to_string(),
            server_name: "Unknown SMTP Server".to_string(),
            version: self.extract_version(banner),
            hostname: self.extract_hostname(banner),
        }
    }

    fn extract_version(&self, banner: &str) -> Option<String> {
        // "220 mail.example.com ESMTP Postfix (Ubuntu)"
        // "220 mx.google.com ESMTP"
        // "220 mail.example.com ESMTP Exim 4.92"

        // Simple version extraction
        let words: Vec<&str> = banner.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            if word
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && word.contains('.')
            {
                // Check if previous word might be a software name
                if i > 0 {
                    let prev = words[i - 1].to_lowercase();
                    if ["postfix", "exim", "sendmail", "dovecot"]
                        .iter()
                        .any(|s| prev.contains(s))
                    {
                        return Some(
                            word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
                                .to_string(),
                        );
                    }
                }
                // Still return if it looks like a version
                let clean: String = word
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if clean.contains('.') {
                    return Some(clean);
                }
            }
        }

        None
    }

    fn extract_hostname(&self, banner: &str) -> Option<String> {
        // "220 mail.example.com ESMTP"
        // Extract hostname after 220 code
        let parts: Vec<&str> = banner.split_whitespace().collect();
        if parts.len() >= 2 && parts[0].starts_with("220") {
            let hostname =
                parts[1].trim_end_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
            if hostname.contains('.') {
                return Some(hostname.to_string());
            }
        }
        None
    }
}

#[derive(Debug)]
struct SmtpServerInfo {
    server_id: String,
    server_name: String,
    version: Option<String>,
    hostname: Option<String>,
}

impl Default for SmtpBannerScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for SmtpBannerScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let banner = ctx.get_data("banner").unwrap_or("");

        if banner.is_empty() {
            result.add_output("No SMTP banner available in context");
            return Ok(result);
        }

        result.success = true;

        // Identify server
        let server_info = self.identify_smtp_server(banner);

        // Main finding
        let mut desc = format!("SMTP Server: {}", server_info.server_name);
        if let Some(ref version) = server_info.version {
            desc.push_str(&format!("\nVersion: {}", version));
        }
        if let Some(ref hostname) = server_info.hostname {
            desc.push_str(&format!("\nHostname: {}", hostname));
        }

        result.add_finding(
            Finding::new(
                FindingType::Version,
                &format!("{} Detected", server_info.server_name),
            )
            .with_description(&desc)
            .with_evidence(banner)
            .with_severity(FindingSeverity::Info),
        );

        // Extract data
        result.extract("smtp_server", &server_info.server_name);
        result.extract("smtp_server_id", &server_info.server_id);
        if let Some(version) = &server_info.version {
            result.extract("smtp_version", version);
        }
        if let Some(hostname) = &server_info.hostname {
            result.extract("smtp_hostname", hostname);
        }

        // Check for hostname disclosure
        if server_info.hostname.is_some() {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Internal Hostname Disclosed")
                    .with_description("SMTP banner reveals internal hostname")
                    .with_severity(FindingSeverity::Low)
                    .with_remediation("Consider using a generic banner"),
            );
        }

        // Check for open relay indicators
        let banner_lower = banner.to_lowercase();
        if banner_lower.contains("open relay") || banner_lower.contains("relay access") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Possible Open Relay")
                    .with_description("Banner suggests mail server may be an open relay")
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Configure SMTP authentication and relay restrictions"),
            );
        }

        // Check for STARTTLS support hint
        if banner_lower.contains("starttls") || banner_lower.contains("tls") {
            result.add_finding(
                Finding::new(FindingType::Discovery, "TLS Support Indicated")
                    .with_description("Banner suggests TLS/STARTTLS support")
                    .with_severity(FindingSeverity::Info),
            );
        }

        // Check vulnerabilities
        self.check_vulnerabilities(&server_info, &mut result);

        result.add_output(&format!("SMTP banner: {}", banner));
        Ok(result)
    }
}

impl SmtpBannerScript {
    fn check_vulnerabilities(&self, info: &SmtpServerInfo, result: &mut ScriptResult) {
        let version = match &info.version {
            Some(v) => v,
            None => return,
        };

        match info.server_id.as_str() {
            "exim" => {
                // CVE-2019-15846 - Exim RCE
                if self.version_lt(version, "4.92.2") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "Exim Remote Code Execution")
                            .with_cve("CVE-2019-15846")
                            .with_description(
                                "Exim before 4.92.2 allows remote code execution via TLS SNI",
                            )
                            .with_severity(FindingSeverity::Critical)
                            .with_remediation("Upgrade to Exim 4.92.2 or later"),
                    );
                }

                // CVE-2019-16928 - Exim heap overflow
                if self.version_lt(version, "4.92.3") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "Exim Heap Overflow")
                            .with_cve("CVE-2019-16928")
                            .with_description("Exim before 4.92.3 has a heap-based buffer overflow in string_vformat")
                            .with_severity(FindingSeverity::Critical)
                            .with_remediation("Upgrade to Exim 4.92.3 or later"),
                    );
                }
            }
            "sendmail" => {
                // Very old versions
                if self.version_lt(version, "8.15") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "Outdated Sendmail")
                            .with_description(
                                "Sendmail before 8.15 has multiple known vulnerabilities",
                            )
                            .with_severity(FindingSeverity::High)
                            .with_remediation("Upgrade to Sendmail 8.15 or later"),
                    );
                }
            }
            "postfix" => {
                // CVE-2023-51764 - SMTP smuggling
                if self.version_lt(version, "3.8.4") {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "Postfix SMTP Smuggling")
                            .with_cve("CVE-2023-51764")
                            .with_description("Postfix before 3.8.4 vulnerable to SMTP smuggling")
                            .with_severity(FindingSeverity::Medium)
                            .with_remediation(
                                "Upgrade to Postfix 3.8.4+ or configure smtpd_data_restrictions",
                            ),
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
    fn test_smtp_banner_script() {
        let script = SmtpBannerScript::new();
        assert_eq!(script.id(), "smtp-banner");
        assert!(script.has_category(ScriptCategory::Banner));
    }

    #[test]
    fn test_postfix_detection() {
        let script = SmtpBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 25);
        ctx.set_data("banner", "220 mail.example.com ESMTP Postfix (Ubuntu)");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(
            result.extracted.get("smtp_server_id"),
            Some(&"postfix".to_string())
        );
        assert_eq!(
            result.extracted.get("smtp_hostname"),
            Some(&"mail.example.com".to_string())
        );
    }

    #[test]
    fn test_exim_detection() {
        let script = SmtpBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 25);
        ctx.set_data("banner", "220 mail.example.com ESMTP Exim 4.92 Ubuntu");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(
            result.extracted.get("smtp_server_id"),
            Some(&"exim".to_string())
        );
        assert_eq!(
            result.extracted.get("smtp_version"),
            Some(&"4.92".to_string())
        );
    }

    #[test]
    fn test_exim_vulnerability() {
        let script = SmtpBannerScript::new();
        let mut ctx = ScriptContext::new("example.com", 25);
        ctx.set_data("banner", "220 mail.example.com ESMTP Exim 4.91");

        let result = script.run(&ctx).unwrap();
        let has_vuln = result.findings.iter().any(|f| f.cve.is_some());
        assert!(has_vuln);
    }
}
