/// Mozilla TLS Compliance Profiles
///
/// Tests TLS configuration against Mozilla's recommended security profiles:
/// - Modern: TLS 1.3 only, strongest security
/// - Intermediate: TLS 1.2+, recommended for most servers
/// - Old: TLS 1.0+, for legacy compatibility
///
/// Reference: https://wiki.mozilla.org/Security/Server_Side_TLS
///
/// This module helps administrators verify their server configuration
/// matches Mozilla's security recommendations.
use std::collections::HashSet;

/// Mozilla TLS profile
#[derive(Debug, Clone, PartialEq)]
pub enum MozillaProfile {
    /// TLS 1.3 only, strongest ciphers
    /// For services that don't need legacy support
    Modern,

    /// TLS 1.2+, strong ciphers
    /// Recommended for most servers
    Intermediate,

    /// TLS 1.0+, broad compatibility
    /// Only for legacy systems that can't be upgraded
    Old,
}

impl MozillaProfile {
    pub fn as_str(&self) -> &str {
        match self {
            MozillaProfile::Modern => "Modern",
            MozillaProfile::Intermediate => "Intermediate",
            MozillaProfile::Old => "Old",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            MozillaProfile::Modern => {
                "TLS 1.3 only with strongest ciphers. Best for security-focused services."
            }
            MozillaProfile::Intermediate => {
                "TLS 1.2+ with strong ciphers. Recommended for most production servers."
            }
            MozillaProfile::Old => "TLS 1.0+ for legacy compatibility. Only use if required.",
        }
    }

    /// Minimum TLS version for this profile
    pub fn min_tls_version(&self) -> &str {
        match self {
            MozillaProfile::Modern => "TLS 1.3",
            MozillaProfile::Intermediate => "TLS 1.2",
            MozillaProfile::Old => "TLS 1.0",
        }
    }

    /// Recommended cipher suites for this profile
    pub fn recommended_ciphers(&self) -> Vec<CipherSuiteSpec> {
        match self {
            MozillaProfile::Modern => vec![
                // TLS 1.3 ciphers (all are strong)
                CipherSuiteSpec::new(0x1301, "TLS_AES_128_GCM_SHA256", true),
                CipherSuiteSpec::new(0x1302, "TLS_AES_256_GCM_SHA384", true),
                CipherSuiteSpec::new(0x1303, "TLS_CHACHA20_POLY1305_SHA256", true),
            ],
            MozillaProfile::Intermediate => vec![
                // TLS 1.3 ciphers
                CipherSuiteSpec::new(0x1301, "TLS_AES_128_GCM_SHA256", true),
                CipherSuiteSpec::new(0x1302, "TLS_AES_256_GCM_SHA384", true),
                CipherSuiteSpec::new(0x1303, "TLS_CHACHA20_POLY1305_SHA256", true),
                // TLS 1.2 ECDHE ciphers
                CipherSuiteSpec::new(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", true),
                CipherSuiteSpec::new(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", true),
                CipherSuiteSpec::new(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", true),
                CipherSuiteSpec::new(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", true),
                CipherSuiteSpec::new(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", true),
                CipherSuiteSpec::new(
                    0xCCA9,
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    true,
                ),
                // TLS 1.2 DHE ciphers (with strong DH)
                CipherSuiteSpec::new(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", false),
                CipherSuiteSpec::new(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", false),
            ],
            MozillaProfile::Old => vec![
                // All intermediate ciphers plus legacy
                CipherSuiteSpec::new(0x1301, "TLS_AES_128_GCM_SHA256", true),
                CipherSuiteSpec::new(0x1302, "TLS_AES_256_GCM_SHA384", true),
                CipherSuiteSpec::new(0x1303, "TLS_CHACHA20_POLY1305_SHA256", true),
                CipherSuiteSpec::new(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", true),
                CipherSuiteSpec::new(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", true),
                CipherSuiteSpec::new(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", true),
                CipherSuiteSpec::new(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", true),
                // Legacy CBC ciphers (for old compatibility)
                CipherSuiteSpec::new(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", false),
                CipherSuiteSpec::new(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", false),
                CipherSuiteSpec::new(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", false),
                CipherSuiteSpec::new(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", false),
                CipherSuiteSpec::new(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", false),
                CipherSuiteSpec::new(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", false),
                CipherSuiteSpec::new(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", false),
                CipherSuiteSpec::new(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", false),
            ],
        }
    }

    /// Forbidden cipher suites (must not be enabled)
    pub fn forbidden_ciphers(&self) -> Vec<&'static str> {
        match self {
            MozillaProfile::Modern => vec![
                // All TLS 1.2 and below ciphers are forbidden
                "TLS_RSA_*",
                "TLS_DHE_*",
                "TLS_ECDHE_*_CBC_*",
                "*_RC4_*",
                "*_3DES_*",
                "*_DES_*",
                "*_NULL_*",
                "*_EXPORT_*",
                "*_anon_*",
            ],
            MozillaProfile::Intermediate => vec![
                "*_RC4_*",
                "*_3DES_*",
                "*_DES_*",
                "*_NULL_*",
                "*_EXPORT_*",
                "*_anon_*",
                "TLS_RSA_*", // No forward secrecy
            ],
            MozillaProfile::Old => vec![
                "*_RC4_*",
                "*_3DES_*",
                "*_DES_*",
                "*_NULL_*",
                "*_EXPORT_*",
                "*_anon_*",
            ],
        }
    }

    /// Required HSTS max-age (in seconds)
    pub fn min_hsts_age(&self) -> u32 {
        match self {
            MozillaProfile::Modern => 63072000,       // 2 years
            MozillaProfile::Intermediate => 63072000, // 2 years
            MozillaProfile::Old => 15768000,          // 6 months
        }
    }

    /// Required ECDH curves
    pub fn required_curves(&self) -> Vec<&'static str> {
        match self {
            MozillaProfile::Modern => vec!["X25519", "secp256r1", "secp384r1"],
            MozillaProfile::Intermediate => vec!["X25519", "prime256v1", "secp384r1"],
            MozillaProfile::Old => vec!["prime256v1", "secp384r1", "secp521r1"],
        }
    }

    /// Minimum RSA key size
    pub fn min_rsa_key_size(&self) -> u32 {
        match self {
            MozillaProfile::Modern => 2048,
            MozillaProfile::Intermediate => 2048,
            MozillaProfile::Old => 2048,
        }
    }

    /// Minimum DH parameter size
    pub fn min_dh_param_size(&self) -> u32 {
        match self {
            MozillaProfile::Modern => 2048, // Not used (TLS 1.3 only)
            MozillaProfile::Intermediate => 2048,
            MozillaProfile::Old => 1024,
        }
    }
}

/// Cipher suite specification
#[derive(Debug, Clone)]
pub struct CipherSuiteSpec {
    pub code: u16,
    pub name: &'static str,
    pub preferred: bool, // Whether this is a preferred cipher for the profile
}

impl CipherSuiteSpec {
    pub fn new(code: u16, name: &'static str, preferred: bool) -> Self {
        Self {
            code,
            name,
            preferred,
        }
    }
}

/// Compliance check result
#[derive(Debug, Clone)]
pub struct ComplianceResult {
    pub profile: MozillaProfile,
    pub compliant: bool,
    pub score: u8, // 0-100
    pub issues: Vec<ComplianceIssue>,
    pub recommendations: Vec<String>,
}

/// Compliance issue
#[derive(Debug, Clone)]
pub struct ComplianceIssue {
    pub severity: ComplianceSeverity,
    pub category: IssueCategory,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceSeverity {
    Critical, // Fails compliance
    Warning,  // Compliance at risk
    Info,     // Best practice recommendation
}

impl ComplianceSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            ComplianceSeverity::Critical => "CRITICAL",
            ComplianceSeverity::Warning => "WARNING",
            ComplianceSeverity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IssueCategory {
    Protocol,
    Cipher,
    Certificate,
    Configuration,
}

impl IssueCategory {
    pub fn as_str(&self) -> &str {
        match self {
            IssueCategory::Protocol => "Protocol",
            IssueCategory::Cipher => "Cipher",
            IssueCategory::Certificate => "Certificate",
            IssueCategory::Configuration => "Configuration",
        }
    }
}

/// Mozilla profile compliance checker
pub struct MozillaComplianceChecker {
    profile: MozillaProfile,
}

impl MozillaComplianceChecker {
    pub fn new(profile: MozillaProfile) -> Self {
        Self { profile }
    }

    /// Check compliance against the profile
    pub fn check(
        &self,
        supported_versions: &[String],
        supported_ciphers: &[(u16, String)],
        certificate_info: Option<&CertificateCheckInfo>,
    ) -> ComplianceResult {
        let mut issues = Vec::new();
        let mut score: i32 = 100;

        // Check protocol versions
        self.check_protocols(supported_versions, &mut issues, &mut score);

        // Check cipher suites
        self.check_ciphers(supported_ciphers, &mut issues, &mut score);

        // Check certificate if provided
        if let Some(cert_info) = certificate_info {
            self.check_certificate(cert_info, &mut issues, &mut score);
        }

        // Build recommendations
        let recommendations = self.build_recommendations(&issues);

        let compliant = !issues
            .iter()
            .any(|i| i.severity == ComplianceSeverity::Critical);

        ComplianceResult {
            profile: self.profile.clone(),
            compliant,
            score: score.max(0).min(100) as u8,
            issues,
            recommendations,
        }
    }

    fn check_protocols(
        &self,
        supported_versions: &[String],
        issues: &mut Vec<ComplianceIssue>,
        score: &mut i32,
    ) {
        let supported: HashSet<&str> = supported_versions.iter().map(|s| s.as_str()).collect();

        match self.profile {
            MozillaProfile::Modern => {
                // Must support TLS 1.3
                if !supported.contains("TLS 1.3") {
                    issues.push(ComplianceIssue {
                        severity: ComplianceSeverity::Critical,
                        category: IssueCategory::Protocol,
                        title: "TLS 1.3 not supported".to_string(),
                        description: "Modern profile requires TLS 1.3 support".to_string(),
                        remediation: "Enable TLS 1.3 on the server".to_string(),
                    });
                    *score -= 40;
                }

                // Must NOT support TLS 1.2 or below
                for version in &["TLS 1.2", "TLS 1.1", "TLS 1.0", "SSLv3", "SSLv2"] {
                    if supported.contains(*version) {
                        issues.push(ComplianceIssue {
                            severity: ComplianceSeverity::Critical,
                            category: IssueCategory::Protocol,
                            title: format!("{} enabled", version),
                            description: format!("Modern profile forbids {} support", version),
                            remediation: format!("Disable {} on the server", version),
                        });
                        *score -= 20;
                    }
                }
            }
            MozillaProfile::Intermediate => {
                // Must support TLS 1.2 or 1.3
                if !supported.contains("TLS 1.2") && !supported.contains("TLS 1.3") {
                    issues.push(ComplianceIssue {
                        severity: ComplianceSeverity::Critical,
                        category: IssueCategory::Protocol,
                        title: "No modern TLS support".to_string(),
                        description: "Intermediate profile requires TLS 1.2 or TLS 1.3".to_string(),
                        remediation: "Enable TLS 1.2 and/or TLS 1.3".to_string(),
                    });
                    *score -= 40;
                }

                // Should support TLS 1.3
                if !supported.contains("TLS 1.3") {
                    issues.push(ComplianceIssue {
                        severity: ComplianceSeverity::Warning,
                        category: IssueCategory::Protocol,
                        title: "TLS 1.3 not supported".to_string(),
                        description: "TLS 1.3 is recommended for better security".to_string(),
                        remediation: "Enable TLS 1.3 on the server".to_string(),
                    });
                    *score -= 10;
                }

                // Must NOT support TLS 1.1 or below
                for version in &["TLS 1.1", "TLS 1.0", "SSLv3", "SSLv2"] {
                    if supported.contains(*version) {
                        issues.push(ComplianceIssue {
                            severity: ComplianceSeverity::Critical,
                            category: IssueCategory::Protocol,
                            title: format!("{} enabled", version),
                            description: format!(
                                "Intermediate profile forbids {} support",
                                version
                            ),
                            remediation: format!("Disable {} on the server", version),
                        });
                        *score -= 15;
                    }
                }
            }
            MozillaProfile::Old => {
                // Must support at least TLS 1.0
                if !supported.contains("TLS 1.0")
                    && !supported.contains("TLS 1.1")
                    && !supported.contains("TLS 1.2")
                    && !supported.contains("TLS 1.3")
                {
                    issues.push(ComplianceIssue {
                        severity: ComplianceSeverity::Critical,
                        category: IssueCategory::Protocol,
                        title: "No TLS support".to_string(),
                        description: "Server does not support any TLS version".to_string(),
                        remediation: "Enable TLS support on the server".to_string(),
                    });
                    *score -= 50;
                }

                // Must NOT support SSLv2/SSLv3
                for version in &["SSLv3", "SSLv2"] {
                    if supported.contains(*version) {
                        issues.push(ComplianceIssue {
                            severity: ComplianceSeverity::Critical,
                            category: IssueCategory::Protocol,
                            title: format!("{} enabled", version),
                            description: format!("{} is cryptographically broken", version),
                            remediation: format!("Disable {} immediately", version),
                        });
                        *score -= 25;
                    }
                }

                // Warn about TLS 1.0/1.1
                if supported.contains("TLS 1.0") || supported.contains("TLS 1.1") {
                    issues.push(ComplianceIssue {
                        severity: ComplianceSeverity::Warning,
                        category: IssueCategory::Protocol,
                        title: "Legacy TLS versions enabled".to_string(),
                        description: "TLS 1.0 and 1.1 are deprecated".to_string(),
                        remediation: "Plan migration to TLS 1.2+ when possible".to_string(),
                    });
                    *score -= 5;
                }
            }
        }
    }

    fn check_ciphers(
        &self,
        supported_ciphers: &[(u16, String)],
        issues: &mut Vec<ComplianceIssue>,
        score: &mut i32,
    ) {
        let forbidden_patterns = self.profile.forbidden_ciphers();
        let recommended = self.profile.recommended_ciphers();
        let recommended_codes: HashSet<u16> = recommended.iter().map(|c| c.code).collect();

        // Check for forbidden ciphers
        for (code, name) in supported_ciphers {
            for pattern in &forbidden_patterns {
                if matches_cipher_pattern(name, pattern) {
                    issues.push(ComplianceIssue {
                        severity: ComplianceSeverity::Critical,
                        category: IssueCategory::Cipher,
                        title: format!("Forbidden cipher: {}", name),
                        description: format!(
                            "Cipher {} is not allowed in {} profile",
                            name,
                            self.profile.as_str()
                        ),
                        remediation: format!("Disable cipher 0x{:04X} ({})", code, name),
                    });
                    *score -= 10;
                }
            }
        }

        // Check if any recommended ciphers are supported
        let supported_codes: HashSet<u16> = supported_ciphers.iter().map(|(c, _)| *c).collect();
        let has_recommended = recommended_codes
            .iter()
            .any(|c| supported_codes.contains(c));

        if !has_recommended && !supported_ciphers.is_empty() {
            issues.push(ComplianceIssue {
                severity: ComplianceSeverity::Warning,
                category: IssueCategory::Cipher,
                title: "No recommended ciphers".to_string(),
                description: format!(
                    "Server does not support any {} profile recommended ciphers",
                    self.profile.as_str()
                ),
                remediation: "Enable recommended cipher suites from Mozilla guidelines".to_string(),
            });
            *score -= 15;
        }

        // Check for preferred ciphers (TLS 1.3 or ECDHE with GCM)
        let preferred: Vec<&CipherSuiteSpec> = recommended.iter().filter(|c| c.preferred).collect();
        let has_preferred = preferred.iter().any(|c| supported_codes.contains(&c.code));

        if !has_preferred && !supported_ciphers.is_empty() {
            issues.push(ComplianceIssue {
                severity: ComplianceSeverity::Info,
                category: IssueCategory::Cipher,
                title: "No preferred ciphers".to_string(),
                description: "Consider enabling preferred cipher suites for better security"
                    .to_string(),
                remediation: "Enable TLS 1.3 ciphers or ECDHE with GCM mode".to_string(),
            });
            *score -= 5;
        }
    }

    fn check_certificate(
        &self,
        cert_info: &CertificateCheckInfo,
        issues: &mut Vec<ComplianceIssue>,
        score: &mut i32,
    ) {
        let min_rsa = self.profile.min_rsa_key_size();

        // Check RSA key size
        if let Some(rsa_size) = cert_info.rsa_key_size {
            if rsa_size < min_rsa {
                issues.push(ComplianceIssue {
                    severity: ComplianceSeverity::Critical,
                    category: IssueCategory::Certificate,
                    title: format!("RSA key too small ({} bits)", rsa_size),
                    description: format!(
                        "{} profile requires at least {} bit RSA keys",
                        self.profile.as_str(),
                        min_rsa
                    ),
                    remediation: format!("Generate new certificate with {} bit RSA key", min_rsa),
                });
                *score -= 20;
            }
        }

        // Check signature algorithm
        if let Some(ref sig_alg) = cert_info.signature_algorithm {
            if sig_alg.contains("SHA1") || sig_alg.contains("MD5") {
                issues.push(ComplianceIssue {
                    severity: ComplianceSeverity::Critical,
                    category: IssueCategory::Certificate,
                    title: format!("Weak signature algorithm: {}", sig_alg),
                    description: "SHA-1 and MD5 signatures are deprecated".to_string(),
                    remediation: "Use SHA-256 or stronger signature algorithm".to_string(),
                });
                *score -= 25;
            }
        }

        // Check certificate validity
        if cert_info.days_until_expiry < 0 {
            issues.push(ComplianceIssue {
                severity: ComplianceSeverity::Critical,
                category: IssueCategory::Certificate,
                title: "Certificate expired".to_string(),
                description: "The certificate has expired".to_string(),
                remediation: "Renew the certificate immediately".to_string(),
            });
            *score -= 50;
        } else if cert_info.days_until_expiry < 30 {
            issues.push(ComplianceIssue {
                severity: ComplianceSeverity::Warning,
                category: IssueCategory::Certificate,
                title: format!(
                    "Certificate expires in {} days",
                    cert_info.days_until_expiry
                ),
                description: "Certificate will expire soon".to_string(),
                remediation: "Renew the certificate before expiration".to_string(),
            });
            *score -= 10;
        }
    }

    fn build_recommendations(&self, issues: &[ComplianceIssue]) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Group issues by category
        let protocol_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.category == IssueCategory::Protocol)
            .collect();
        let cipher_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.category == IssueCategory::Cipher)
            .collect();

        if !protocol_issues.is_empty() {
            recommendations.push(format!(
                "Review TLS protocol configuration ({} issues)",
                protocol_issues.len()
            ));
        }

        if !cipher_issues.is_empty() {
            recommendations.push(format!(
                "Update cipher suite configuration ({} issues)",
                cipher_issues.len()
            ));
        }

        // Profile-specific recommendations
        match self.profile {
            MozillaProfile::Modern => {
                recommendations.push(
                    "Use Mozilla SSL Configuration Generator for optimal settings".to_string(),
                );
            }
            MozillaProfile::Intermediate => {
                recommendations.push(
                    "Consider upgrading to Modern profile if legacy support not needed".to_string(),
                );
            }
            MozillaProfile::Old => {
                recommendations
                    .push("Plan migration to Intermediate profile to improve security".to_string());
            }
        }

        recommendations
    }
}

/// Certificate information for compliance checking
#[derive(Debug, Clone)]
pub struct CertificateCheckInfo {
    pub rsa_key_size: Option<u32>,
    pub ec_curve: Option<String>,
    pub signature_algorithm: Option<String>,
    pub days_until_expiry: i32,
}

/// Check if cipher name matches a pattern
fn matches_cipher_pattern(cipher_name: &str, pattern: &str) -> bool {
    if pattern.starts_with('*') && pattern.ends_with('*') {
        // Contains pattern
        let middle = &pattern[1..pattern.len() - 1];
        cipher_name.contains(middle)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        // Ends with pattern
        cipher_name.ends_with(suffix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        // Starts with pattern
        cipher_name.starts_with(prefix)
    } else {
        // Exact match
        cipher_name == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_descriptions() {
        assert!(MozillaProfile::Modern.description().contains("TLS 1.3"));
        assert!(MozillaProfile::Intermediate
            .description()
            .contains("TLS 1.2"));
        assert!(MozillaProfile::Old.description().contains("legacy"));
    }

    #[test]
    fn test_modern_requires_tls13() {
        let checker = MozillaComplianceChecker::new(MozillaProfile::Modern);
        let result = checker.check(&["TLS 1.2".to_string()], &[], None);
        assert!(!result.compliant);
    }

    #[test]
    fn test_intermediate_allows_tls12() {
        let checker = MozillaComplianceChecker::new(MozillaProfile::Intermediate);
        let result = checker.check(&["TLS 1.2".to_string(), "TLS 1.3".to_string()], &[], None);
        // Should be compliant if TLS 1.2+ without forbidden ciphers
        assert!(result.compliant || result.score >= 50);
    }

    #[test]
    fn test_cipher_pattern_matching() {
        assert!(matches_cipher_pattern(
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_*"
        ));
        assert!(matches_cipher_pattern(
            "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
            "*_RC4_*"
        ));
        assert!(!matches_cipher_pattern(
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "*_RC4_*"
        ));
    }

    #[test]
    fn test_recommended_ciphers() {
        let modern = MozillaProfile::Modern.recommended_ciphers();
        assert!(modern
            .iter()
            .all(|c| c.name.starts_with("TLS_AES") || c.name.starts_with("TLS_CHACHA")));

        let intermediate = MozillaProfile::Intermediate.recommended_ciphers();
        assert!(intermediate.len() > modern.len());
    }
}
