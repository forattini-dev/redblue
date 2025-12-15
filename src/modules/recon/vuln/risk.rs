//! Risk Score Calculator
//!
//! Calculate composite risk scores for vulnerability prioritization.
//!
//! Formula:
//! ```text
//! risk_score = (cvss_base * 10)
//!            + (exploit_available ? 25 : 0)
//!            + (cisa_kev ? 30 : 0)
//!            + age_penalty(days_since_publish)
//!            + impact_modifier(rce: +20, auth_bypass: +15, info_leak: +5)
//! ```
//!
//! Range: 0-100, higher = more critical

use super::types::Vulnerability;

/// Risk score configuration
#[derive(Debug, Clone)]
pub struct RiskConfig {
    /// Base weight for CVSS score (default: 10)
    pub cvss_weight: f32,
    /// Bonus for available exploit (default: 25)
    pub exploit_bonus: u8,
    /// Bonus for CISA KEV entry (default: 30)
    pub kev_bonus: u8,
    /// Maximum age penalty (default: 10)
    pub max_age_penalty: u8,
    /// Days after which age penalty is at maximum (default: 365)
    pub age_penalty_days: u32,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            cvss_weight: 10.0,
            exploit_bonus: 25,
            kev_bonus: 30,
            max_age_penalty: 10,
            age_penalty_days: 365,
        }
    }
}

/// Calculate risk score for a vulnerability
pub fn calculate_risk_score(vuln: &Vulnerability) -> u8 {
    calculate_risk_score_with_config(vuln, &RiskConfig::default())
}

/// Calculate risk score with custom configuration
pub fn calculate_risk_score_with_config(vuln: &Vulnerability, config: &RiskConfig) -> u8 {
    let mut score: f32 = 0.0;

    // Base CVSS score (0-100 points scaled from 0-10)
    if let Some(cvss) = vuln.best_cvss() {
        score += cvss * config.cvss_weight;
    }

    // Exploit availability bonus
    if vuln.has_exploit() {
        score += config.exploit_bonus as f32;
    }

    // CISA KEV bonus (actively exploited in the wild)
    if vuln.cisa_kev {
        score += config.kev_bonus as f32;
    }

    // Age penalty (older unpatched vulns are more serious)
    if let Some(ref published) = vuln.published {
        if let Some(days) = days_since_published(published) {
            let age_factor = (days as f32 / config.age_penalty_days as f32).min(1.0);
            score += age_factor * config.max_age_penalty as f32;
        }
    }

    // Impact modifier based on CWE
    score += impact_modifier_from_cwes(&vuln.cwes);

    // Clamp to 0-100
    score.clamp(0.0, 100.0) as u8
}

/// Calculate impact modifier based on CWE IDs
fn impact_modifier_from_cwes(cwes: &[String]) -> f32 {
    let mut modifier = 0.0f32;

    for cwe in cwes {
        let cwe_num: Option<u32> = cwe.strip_prefix("CWE-").and_then(|s| s.parse().ok());

        if let Some(num) = cwe_num {
            modifier += match num {
                // Remote Code Execution related
                94 | 95 | 96 | 78 | 77 | 20 => 20.0, // Code injection, command injection
                502 => 20.0,                         // Deserialization
                434 => 18.0,                         // Unrestricted file upload

                // Authentication/Authorization bypass
                287 | 288 | 290 | 863 | 862 => 15.0, // Auth bypass
                306 => 15.0,                         // Missing authentication
                269 | 266 | 250 => 12.0,             // Privilege escalation

                // SQL Injection
                89 => 15.0,

                // XSS
                79 => 8.0,

                // Information disclosure
                200 | 201 | 209 | 532 => 5.0,

                // Path traversal
                22 | 23 | 36 => 10.0,

                // SSRF
                918 => 12.0,

                // XXE
                611 => 10.0,

                // Buffer overflow
                120 | 121 | 122 | 119 => 15.0,

                // Use after free
                416 => 15.0,

                _ => 0.0,
            };
        }
    }

    // Cap at 20 to not over-weight
    modifier.min(20.0)
}

/// Calculate days since publication
fn days_since_published(published: &str) -> Option<u32> {
    // Parse ISO 8601 date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)
    let date_part = published.split('T').next()?;
    let parts: Vec<&str> = date_part.split('-').collect();

    if parts.len() < 3 {
        return None;
    }

    let year: i32 = parts[0].parse().ok()?;
    let month: u32 = parts[1].parse().ok()?;
    let day: u32 = parts[2].parse().ok()?;

    // Get current date (simplified - using system time)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    // Convert to days since epoch (approximate)
    let now_days = now / 86400;

    // Convert published date to days since epoch (simplified)
    let pub_days = days_since_epoch(year, month, day)?;

    if now_days >= pub_days as u64 {
        Some((now_days - pub_days as u64) as u32)
    } else {
        Some(0)
    }
}

/// Calculate days since Unix epoch for a date
fn days_since_epoch(year: i32, month: u32, day: u32) -> Option<u32> {
    // Simplified calculation
    if year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }

    let mut days: u32 = 0;

    // Add days for each year since 1970
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for each month in current year
    let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += days_in_month[m as usize];
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    // Add days
    days += day - 1;

    Some(days)
}

/// Check if year is a leap year
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Critical, // 80-100
    High,     // 60-79
    Medium,   // 40-59
    Low,      // 20-39
    Info,     // 0-19
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            80..=100 => RiskLevel::Critical,
            60..=79 => RiskLevel::High,
            40..=59 => RiskLevel::Medium,
            20..=39 => RiskLevel::Low,
            _ => RiskLevel::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "CRITICAL",
            RiskLevel::High => "HIGH",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::Low => "LOW",
            RiskLevel::Info => "INFO",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "\x1b[91m", // Bright red
            RiskLevel::High => "\x1b[31m",     // Red
            RiskLevel::Medium => "\x1b[33m",   // Yellow
            RiskLevel::Low => "\x1b[36m",      // Cyan
            RiskLevel::Info => "\x1b[37m",     // White
        }
    }
}

/// Batch calculate risk scores and update vulnerabilities
pub fn calculate_risk_scores(vulns: &mut [Vulnerability]) {
    for vuln in vulns {
        vuln.risk_score = Some(calculate_risk_score(vuln));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::recon::vuln::types::ExploitRef;

    #[test]
    fn test_risk_score_cvss_only() {
        let mut vuln = Vulnerability::new("CVE-2024-1234");
        vuln.cvss_v3 = Some(9.8);

        let score = calculate_risk_score(&vuln);
        assert!(score >= 98); // 9.8 * 10 = 98
    }

    #[test]
    fn test_risk_score_with_exploit() {
        let mut vuln = Vulnerability::new("CVE-2024-1234");
        vuln.cvss_v3 = Some(5.0);
        vuln.exploits.push(ExploitRef {
            source: "exploit-db".to_string(),
            url: "https://exploit-db.com/123".to_string(),
            title: None,
            exploit_type: None,
        });

        let score = calculate_risk_score(&vuln);
        assert!(score >= 75); // 50 + 25 exploit bonus
    }

    #[test]
    fn test_risk_score_with_kev() {
        let mut vuln = Vulnerability::new("CVE-2024-1234");
        vuln.cvss_v3 = Some(5.0);
        vuln.cisa_kev = true;

        let score = calculate_risk_score(&vuln);
        assert!(score >= 80); // 50 + 30 KEV bonus
    }

    #[test]
    fn test_risk_score_max() {
        let mut vuln = Vulnerability::new("CVE-2024-1234");
        vuln.cvss_v3 = Some(10.0);
        vuln.cisa_kev = true;
        vuln.exploits.push(ExploitRef {
            source: "test".to_string(),
            url: "test".to_string(),
            title: None,
            exploit_type: None,
        });
        vuln.cwes.push("CWE-94".to_string()); // Code injection

        let score = calculate_risk_score(&vuln);
        assert_eq!(score, 100); // Clamped to 100
    }

    #[test]
    fn test_risk_level() {
        assert_eq!(RiskLevel::from_score(95), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(70), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(30), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(10), RiskLevel::Info);
    }

    #[test]
    fn test_days_since_epoch() {
        // Jan 1, 1970 = day 0
        assert_eq!(days_since_epoch(1970, 1, 1), Some(0));

        // Jan 2, 1970 = day 1
        assert_eq!(days_since_epoch(1970, 1, 2), Some(1));
    }

    #[test]
    fn test_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        assert!(!is_leap_year(1900));
    }
}
