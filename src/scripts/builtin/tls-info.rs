/// TLS Information Script
///
/// Analyzes TLS/SSL configuration and certificates.
/// Identifies security issues and version information.

use crate::scripts::types::*;
use crate::scripts::Script;

/// TLS Information Script
pub struct TlsInfoScript {
    meta: ScriptMetadata,
}

impl TlsInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "tls-info".to_string(),
                name: "TLS/SSL Information".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Analyzes TLS/SSL configuration and certificate information".to_string(),
                categories: vec![ScriptCategory::Discovery, ScriptCategory::Safe, ScriptCategory::Default],
                protocols: vec!["https".to_string(), "tls".to_string(), "ssl".to_string()],
                ports: vec![443, 465, 636, 853, 993, 995, 8443],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec![
                    "https://wiki.mozilla.org/Security/Server_Side_TLS".to_string(),
                    "https://ssl-config.mozilla.org/".to_string(),
                ],
            },
        }
    }
}

impl Default for TlsInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for TlsInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        // Check for TLS data in context
        let tls_version = ctx.get_data("tls_version");
        let cipher_suite = ctx.get_data("cipher_suite");
        let cert_subject = ctx.get_data("cert_subject");
        let cert_issuer = ctx.get_data("cert_issuer");
        let _cert_not_before = ctx.get_data("cert_not_before");
        let cert_not_after = ctx.get_data("cert_not_after");
        let cert_san = ctx.get_data("cert_san");

        if tls_version.is_none() && cert_subject.is_none() {
            result.add_output("No TLS information available in context");
            return Ok(result);
        }

        result.success = true;

        // TLS Version analysis
        if let Some(version) = tls_version {
            result.extract("tls_version", version);

            let (severity, desc) = match version.to_uppercase().as_str() {
                "TLSV1.3" | "TLS 1.3" => (
                    FindingSeverity::Info,
                    "TLS 1.3 - Modern and secure protocol",
                ),
                "TLSV1.2" | "TLS 1.2" => (
                    FindingSeverity::Info,
                    "TLS 1.2 - Secure protocol (ensure strong ciphers)",
                ),
                "TLSV1.1" | "TLS 1.1" => (
                    FindingSeverity::Medium,
                    "TLS 1.1 - Deprecated protocol, should be disabled",
                ),
                "TLSV1.0" | "TLS 1.0" => (
                    FindingSeverity::High,
                    "TLS 1.0 - Deprecated and vulnerable protocol",
                ),
                "SSLV3" | "SSL 3.0" => (
                    FindingSeverity::Critical,
                    "SSL 3.0 - Obsolete and vulnerable (POODLE attack)",
                ),
                "SSLV2" | "SSL 2.0" => (
                    FindingSeverity::Critical,
                    "SSL 2.0 - Severely broken, must be disabled",
                ),
                _ => (FindingSeverity::Info, "Unknown TLS version"),
            };

            result.add_finding(
                Finding::new(FindingType::Discovery, &format!("TLS Version: {}", version))
                    .with_description(desc)
                    .with_severity(severity),
            );

            // Add remediation for old protocols
            if severity >= FindingSeverity::Medium {
                let finding = result.findings.last_mut().unwrap();
                finding.remediation = Some("Disable TLS 1.1 and older. Enable only TLS 1.2 and TLS 1.3".to_string());
            }
        }

        // Cipher suite analysis
        if let Some(cipher) = cipher_suite {
            result.extract("cipher_suite", cipher);

            let cipher_upper = cipher.to_uppercase();
            let mut cipher_issues = Vec::new();

            // Check for weak ciphers
            if cipher_upper.contains("NULL") {
                cipher_issues.push(("NULL cipher", FindingSeverity::Critical));
            }
            if cipher_upper.contains("EXPORT") {
                cipher_issues.push(("EXPORT cipher (weak)", FindingSeverity::Critical));
            }
            if cipher_upper.contains("DES") && !cipher_upper.contains("3DES") {
                cipher_issues.push(("Single DES (weak)", FindingSeverity::Critical));
            }
            if cipher_upper.contains("3DES") {
                cipher_issues.push(("3DES cipher (deprecated)", FindingSeverity::Medium));
            }
            if cipher_upper.contains("RC4") {
                cipher_issues.push(("RC4 cipher (broken)", FindingSeverity::High));
            }
            if cipher_upper.contains("MD5") {
                cipher_issues.push(("MD5 in cipher suite", FindingSeverity::Medium));
            }
            if cipher_upper.contains("CBC") && !cipher_upper.contains("GCM") {
                cipher_issues.push(("CBC mode (potential BEAST/Lucky13)", FindingSeverity::Low));
            }

            // Check for good ciphers
            let has_aead = cipher_upper.contains("GCM") || cipher_upper.contains("CHACHA20") || cipher_upper.contains("CCM");
            let has_pfs = cipher_upper.contains("DHE") || cipher_upper.contains("ECDHE");

            if cipher_issues.is_empty() && has_aead && has_pfs {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "Strong Cipher Suite")
                        .with_description(&format!("Cipher: {}\nAEAD: Yes, PFS: Yes", cipher))
                        .with_severity(FindingSeverity::Info),
                );
            } else {
                for (issue, severity) in cipher_issues {
                    result.add_finding(
                        Finding::new(FindingType::Misconfiguration, &format!("Weak Cipher: {}", issue))
                            .with_description(&format!("Cipher suite: {}", cipher))
                            .with_severity(severity)
                            .with_remediation("Configure server to use only strong AEAD ciphers with PFS"),
                    );
                }

                if !has_pfs {
                    result.add_finding(
                        Finding::new(FindingType::Misconfiguration, "No Perfect Forward Secrecy")
                            .with_description("Cipher suite does not provide forward secrecy")
                            .with_severity(FindingSeverity::Medium)
                            .with_remediation("Use ECDHE or DHE key exchange"),
                    );
                }
            }
        }

        // Certificate analysis
        if let Some(subject) = cert_subject {
            result.extract("cert_subject", subject);

            result.add_finding(
                Finding::new(FindingType::Discovery, "Certificate Subject")
                    .with_description(&format!("Subject: {}", subject))
                    .with_severity(FindingSeverity::Info),
            );
        }

        if let Some(issuer) = cert_issuer {
            result.extract("cert_issuer", issuer);

            // Check for self-signed
            if let Some(subject) = cert_subject {
                if issuer == subject {
                    result.add_finding(
                        Finding::new(FindingType::Misconfiguration, "Self-Signed Certificate")
                            .with_description("Certificate is self-signed and will not be trusted by browsers")
                            .with_severity(FindingSeverity::Medium)
                            .with_remediation("Obtain a certificate from a trusted Certificate Authority"),
                    );
                }
            }

            // Check for known test CAs
            let issuer_lower = issuer.to_lowercase();
            if issuer_lower.contains("test") || issuer_lower.contains("fake") || issuer_lower.contains("example") {
                result.add_finding(
                    Finding::new(FindingType::Misconfiguration, "Test/Fake Certificate")
                        .with_description("Certificate appears to be from a test or fake CA")
                        .with_severity(FindingSeverity::High)
                        .with_remediation("Use a valid certificate from a trusted CA"),
                );
            }
        }

        // Certificate validity
        if let Some(not_after) = cert_not_after {
            result.extract("cert_not_after", not_after);

            // Try to parse and check expiration
            // Simple check: if the date string contains a year less than current
            if let Some(year) = self.extract_year(not_after) {
                let current_year = 2024; // Approximate
                if year < current_year {
                    result.add_finding(
                        Finding::new(FindingType::Misconfiguration, "Expired Certificate")
                            .with_description(&format!("Certificate expired: {}", not_after))
                            .with_severity(FindingSeverity::Critical)
                            .with_remediation("Renew the certificate immediately"),
                    );
                } else if year == current_year {
                    result.add_finding(
                        Finding::new(FindingType::Misconfiguration, "Certificate Expiring Soon")
                            .with_description(&format!("Certificate expires: {}", not_after))
                            .with_severity(FindingSeverity::Medium)
                            .with_remediation("Plan certificate renewal"),
                    );
                }
            }
        }

        // SAN analysis
        if let Some(san) = cert_san {
            result.extract("cert_san", san);

            let san_count = san.split(',').count();
            result.add_finding(
                Finding::new(FindingType::Discovery, "Subject Alternative Names")
                    .with_description(&format!("{} SAN entries: {}", san_count, san))
                    .with_severity(FindingSeverity::Info),
            );

            // Check for wildcard
            if san.contains('*') {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "Wildcard Certificate")
                        .with_description("Certificate contains wildcard domain(s)")
                        .with_severity(FindingSeverity::Info),
                );
            }
        }

        result.add_output(&format!("TLS analysis complete for {}:{}", ctx.host, ctx.port));
        Ok(result)
    }
}

impl TlsInfoScript {
    fn extract_year(&self, date_str: &str) -> Option<u32> {
        // Try to find a 4-digit year in the string
        let mut digits = String::new();
        for c in date_str.chars() {
            if c.is_ascii_digit() {
                digits.push(c);
                if digits.len() == 4 {
                    if let Ok(year) = digits.parse::<u32>() {
                        if year >= 2000 && year <= 2100 {
                            return Some(year);
                        }
                    }
                    digits.clear();
                }
            } else {
                if digits.len() == 4 {
                    if let Ok(year) = digits.parse::<u32>() {
                        if year >= 2000 && year <= 2100 {
                            return Some(year);
                        }
                    }
                }
                digits.clear();
            }
        }

        if digits.len() == 4 {
            if let Ok(year) = digits.parse::<u32>() {
                if year >= 2000 && year <= 2100 {
                    return Some(year);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_info_script() {
        let script = TlsInfoScript::new();
        assert_eq!(script.id(), "tls-info");
        assert!(script.has_category(ScriptCategory::Discovery));
    }

    #[test]
    fn test_tls_version_detection() {
        let script = TlsInfoScript::new();
        let mut ctx = ScriptContext::new("example.com", 443);
        ctx.set_data("tls_version", "TLSv1.3");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(result.extracted.get("tls_version"), Some(&"TLSv1.3".to_string()));
    }

    #[test]
    fn test_old_tls_warning() {
        let script = TlsInfoScript::new();
        let mut ctx = ScriptContext::new("example.com", 443);
        ctx.set_data("tls_version", "TLSv1.0");

        let result = script.run(&ctx).unwrap();
        let has_high_severity = result
            .findings
            .iter()
            .any(|f| f.severity >= FindingSeverity::High);
        assert!(has_high_severity);
    }

    #[test]
    fn test_weak_cipher_detection() {
        let script = TlsInfoScript::new();
        let mut ctx = ScriptContext::new("example.com", 443);
        ctx.set_data("tls_version", "TLSv1.2");
        ctx.set_data("cipher_suite", "TLS_RSA_WITH_RC4_128_SHA");

        let result = script.run(&ctx).unwrap();
        let has_rc4_warning = result
            .findings
            .iter()
            .any(|f| f.title.contains("RC4"));
        assert!(has_rc4_warning);
    }

    #[test]
    fn test_self_signed_detection() {
        let script = TlsInfoScript::new();
        let mut ctx = ScriptContext::new("example.com", 443);
        ctx.set_data("cert_subject", "CN=example.com");
        ctx.set_data("cert_issuer", "CN=example.com");

        let result = script.run(&ctx).unwrap();
        let has_self_signed = result
            .findings
            .iter()
            .any(|f| f.title.contains("Self-Signed"));
        assert!(has_self_signed);
    }

    #[test]
    fn test_year_extraction() {
        let script = TlsInfoScript::new();
        assert_eq!(script.extract_year("Dec 31 2024"), Some(2024));
        assert_eq!(script.extract_year("2025-01-15"), Some(2025));
        assert_eq!(script.extract_year("Jan 1 00:00:00 2023 GMT"), Some(2023));
    }
}
