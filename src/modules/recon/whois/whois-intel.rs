/// WHOIS Intelligence & Reputation Analysis
///
/// Extract threat intelligence from WHOIS data:
/// - Domain reputation scoring
/// - Phishing likelihood detection
/// - DGA (Domain Generation Algorithm) detection
/// - Bulletproof hosting detection
/// - Domain age analysis
/// - Registrar reputation
use crate::protocols::whois::{WhoisClient, WhoisResult};

#[derive(Debug)]
pub struct WhoisIntelligence {
    pub domain: String,
    pub whois_data: WhoisResult,
    pub reputation_score: ReputationScore,
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
pub struct ReputationScore {
    pub overall: u8,         // 0-100 (0 = very risky, 100 = trustworthy)
    pub age_score: u8,       // Domain age contribution
    pub registrar_score: u8, // Registrar reputation
    pub privacy_score: u8,   // Privacy protection impact
}

#[derive(Debug, Clone, PartialEq)]
pub enum SuspiciousIndicator {
    RecentlyRegistered,    // < 30 days
    VeryNewDomain,         // < 7 days (high phishing risk)
    FrequentlyUpdated,     // Updated within last 30 days
    BulletproofRegistrar,  // Known abuse-tolerant registrar
    PrivacyProtected,      // WHOIS privacy enabled
    ExpiresSoon,           // < 30 days to expiration
    ShortRegistration,     // Only 1 year registration
    SuspiciousNameservers, // Known malicious NS
    HighEntropyDomain,     // DGA-like domain name
    FreeEmailRegistrant,   // gmail/yahoo in registrant email
    MismatchedData,        // Registrant location vs hosting
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Critical, // 0-25 - Likely malicious
    High,     // 26-50 - High risk
    Medium,   // 51-75 - Moderate risk
    Low,      // 76-100 - Low risk/legitimate
}

impl WhoisIntelligence {
    /// Analyze WHOIS data for a domain
    pub fn analyze(domain: &str) -> Result<Self, String> {
        let client = WhoisClient::new();
        let whois_data = client.query(domain)?;

        let mut indicators = Vec::new();

        // Check domain age
        if let Some(age_indicator) = Self::check_domain_age(&whois_data) {
            indicators.push(age_indicator);
        }

        // Check registrar reputation
        if let Some(reg_indicator) = Self::check_registrar_reputation(&whois_data) {
            indicators.push(reg_indicator);
        }

        // Check for privacy protection
        if Self::has_privacy_protection(&whois_data) {
            indicators.push(SuspiciousIndicator::PrivacyProtected);
        }

        // Check expiration date
        if let Some(exp_indicator) = Self::check_expiration(&whois_data) {
            indicators.push(exp_indicator);
        }

        // Check domain entropy (DGA detection)
        if Self::is_high_entropy_domain(domain) {
            indicators.push(SuspiciousIndicator::HighEntropyDomain);
        }

        // Calculate reputation score
        let reputation_score = Self::calculate_reputation(&whois_data, &indicators);

        // Determine risk level
        let risk_level = Self::determine_risk_level(reputation_score.overall);

        Ok(WhoisIntelligence {
            domain: domain.to_string(),
            whois_data,
            reputation_score,
            suspicious_indicators: indicators,
            risk_level,
        })
    }

    /// Check domain age for suspicious patterns
    fn check_domain_age(whois: &WhoisResult) -> Option<SuspiciousIndicator> {
        let creation_date = whois.creation_date.as_ref()?;

        // Parse date (simplified - assumes ISO format or common patterns)
        // In production, we'd use proper date parsing
        let days_old = Self::parse_days_since(creation_date)?;

        if days_old < 7 {
            Some(SuspiciousIndicator::VeryNewDomain)
        } else if days_old < 30 {
            Some(SuspiciousIndicator::RecentlyRegistered)
        } else {
            None
        }
    }

    /// Check registrar reputation
    fn check_registrar_reputation(whois: &WhoisResult) -> Option<SuspiciousIndicator> {
        let registrar = whois.registrar.as_ref()?.to_lowercase();

        // Known bulletproof/abuse-tolerant registrars
        let bulletproof_patterns = [
            "pdr ltd",
            "publicdomainregistry",
            "alpnames",
            "internet.bs",
            "regru",
            "reg.ru",
        ];

        for pattern in &bulletproof_patterns {
            if registrar.contains(pattern) {
                return Some(SuspiciousIndicator::BulletproofRegistrar);
            }
        }

        None
    }

    /// Check if privacy protection is enabled
    fn has_privacy_protection(whois: &WhoisResult) -> bool {
        let raw_lower = whois.raw.to_lowercase();

        raw_lower.contains("privacy")
            || raw_lower.contains("redacted for privacy")
            || raw_lower.contains("whoisguard")
            || raw_lower.contains("domains by proxy")
    }

    /// Check expiration date
    fn check_expiration(whois: &WhoisResult) -> Option<SuspiciousIndicator> {
        let expiration = whois.expiration_date.as_ref()?;
        let days_until = Self::parse_days_until(expiration)?;

        if days_until < 30 {
            Some(SuspiciousIndicator::ExpiresSoon)
        } else {
            None
        }
    }

    /// Detect high-entropy domains (DGA characteristic)
    fn is_high_entropy_domain(domain: &str) -> bool {
        // Remove TLD
        let domain_name = domain.split('.').next().unwrap_or(domain);

        if domain_name.len() < 8 {
            return false; // Short domains are not DGA
        }

        // Calculate character diversity (simplified entropy)
        let unique_chars: std::collections::HashSet<char> = domain_name
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect();

        let entropy_ratio = unique_chars.len() as f32 / domain_name.len() as f32;

        // High entropy + long length = possible DGA
        entropy_ratio > 0.7 && domain_name.len() >= 12
    }

    /// Calculate reputation score
    fn calculate_reputation(
        _whois: &WhoisResult,
        indicators: &[SuspiciousIndicator],
    ) -> ReputationScore {
        let mut age_score = 100u8;
        let mut registrar_score = 100u8;
        let mut privacy_score = 100u8;

        for indicator in indicators {
            match indicator {
                SuspiciousIndicator::VeryNewDomain => age_score = age_score.saturating_sub(50),
                SuspiciousIndicator::RecentlyRegistered => age_score = age_score.saturating_sub(30),
                SuspiciousIndicator::BulletproofRegistrar => {
                    registrar_score = registrar_score.saturating_sub(60)
                }
                SuspiciousIndicator::PrivacyProtected => {
                    privacy_score = privacy_score.saturating_sub(20)
                }
                SuspiciousIndicator::ExpiresSoon => age_score = age_score.saturating_sub(10),
                SuspiciousIndicator::HighEntropyDomain => {
                    registrar_score = registrar_score.saturating_sub(40)
                }
                _ => {}
            }
        }

        let overall = (age_score as u16 + registrar_score as u16 + privacy_score as u16) / 3;

        ReputationScore {
            overall: overall as u8,
            age_score,
            registrar_score,
            privacy_score,
        }
    }

    /// Determine risk level from score
    fn determine_risk_level(score: u8) -> RiskLevel {
        match score {
            0..=25 => RiskLevel::Critical,
            26..=50 => RiskLevel::High,
            51..=75 => RiskLevel::Medium,
            76..=100 => RiskLevel::Low,
            _ => RiskLevel::Medium,
        }
    }

    /// Parse days since a date string (simplified)
    fn parse_days_since(_date_str: &str) -> Option<u64> {
        // Simplified date parsing - in production use proper date library
        // For now, return None (requires full implementation)
        None
    }

    /// Parse days until a date string (simplified)
    fn parse_days_until(_date_str: &str) -> Option<u64> {
        // Simplified - return None (requires full implementation)
        None
    }

    /// Generate human-readable threat assessment
    pub fn threat_assessment(&self) -> String {
        let mut assessment = String::new();

        assessment.push_str(&format!("Domain: {}\n", self.domain));
        assessment.push_str(&format!("Risk Level: {:?}\n", self.risk_level));
        assessment.push_str(&format!(
            "Overall Score: {}/100\n\n",
            self.reputation_score.overall
        ));

        if !self.suspicious_indicators.is_empty() {
            assessment.push_str("Suspicious Indicators:\n");
            for indicator in &self.suspicious_indicators {
                let emoji = match indicator {
                    SuspiciousIndicator::VeryNewDomain => "🔴",
                    SuspiciousIndicator::BulletproofRegistrar => "🔴",
                    SuspiciousIndicator::HighEntropyDomain => "🔴",
                    SuspiciousIndicator::RecentlyRegistered => "⚠️",
                    SuspiciousIndicator::PrivacyProtected => "⚠️",
                    _ => "ℹ️",
                };
                assessment.push_str(&format!("  {} {:?}\n", emoji, indicator));
            }
        }

        if let Some(registrar) = &self.whois_data.registrar {
            assessment.push_str(&format!("\nRegistrar: {}\n", registrar));
        }

        if let Some(created) = &self.whois_data.creation_date {
            assessment.push_str(&format!("Created: {}\n", created));
        }

        assessment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_entropy_domain() {
        assert!(WhoisIntelligence::is_high_entropy_domain(
            "xkj92msldf8q.com"
        ));
        assert!(!WhoisIntelligence::is_high_entropy_domain("google.com"));
        assert!(!WhoisIntelligence::is_high_entropy_domain("facebook.com"));
    }

    #[test]
    fn test_risk_level_determination() {
        assert_eq!(
            WhoisIntelligence::determine_risk_level(10),
            RiskLevel::Critical
        );
        assert_eq!(WhoisIntelligence::determine_risk_level(40), RiskLevel::High);
        assert_eq!(
            WhoisIntelligence::determine_risk_level(65),
            RiskLevel::Medium
        );
        assert_eq!(WhoisIntelligence::determine_risk_level(90), RiskLevel::Low);
    }
}
