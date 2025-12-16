//! Assessment Output Formatting
//!
//! Provides beautiful, formatted output for assessment results.

use crate::assess::cache::CacheStatus;
use crate::assess::engine::AssessmentResult;
use crate::cli::output::Output;
use crate::modules::web::fingerprinter::{Confidence, Technology};
use crate::playbooks::recommender::PlaybookRecommendation;
use crate::playbooks::types::RiskLevel;
use crate::storage::records::{Severity, VulnerabilityRecord};

/// Assessment output formatter
pub struct AssessmentOutput;

impl AssessmentOutput {
    // Color codes
    const RESET: &'static str = "\x1b[0m";
    const BOLD: &'static str = "\x1b[1m";
    const DIM: &'static str = "\x1b[2m";
    const RED: &'static str = "\x1b[31m";
    const GREEN: &'static str = "\x1b[32m";
    const YELLOW: &'static str = "\x1b[33m";
    const BLUE: &'static str = "\x1b[34m";
    const MAGENTA: &'static str = "\x1b[35m";
    const CYAN: &'static str = "\x1b[36m";

    /// Print the full assessment result
    pub fn print(result: &AssessmentResult) {
        Self::print_banner(&result.target);
        Self::print_technologies(&result.technologies, &result.fingerprint_cache_status);
        Self::print_vulnerabilities(&result.vuln_records, &result.vuln_cache_status);
        Self::print_risk_score(result.risk_score);
        Self::print_recommendations(&result.recommendations.recommendations);
        Self::print_summary(result);
    }

    /// Print the assessment banner
    fn print_banner(target: &str) {
        println!();
        println!(
            "{}{}🔴🔵 redblue Assessment: {}{}",
            Self::BOLD,
            Self::CYAN,
            target,
            Self::RESET
        );
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            Self::DIM,
            Self::RESET
        );
    }

    /// Print Phase 1: Technologies
    fn print_technologies(technologies: &[Technology], cache_status: &CacheStatus) {
        Output::phase(&format!("Phase 1: Technology Discovery [{}]", cache_status));

        if technologies.is_empty() {
            println!("  {}No technologies detected{}", Self::DIM, Self::RESET);
            return;
        }

        for tech in technologies {
            let version = tech.version.as_deref().unwrap_or("?");
            let confidence_color = match tech.confidence {
                Confidence::High => Self::GREEN,
                Confidence::Medium => Self::YELLOW,
                Confidence::Low => Self::DIM,
            };

            println!(
                "  {}✓{} {}{}{} {} {}({}){}",
                Self::GREEN,
                Self::RESET,
                Self::BOLD,
                tech.name,
                Self::RESET,
                version,
                confidence_color,
                tech.confidence,
                Self::RESET
            );
        }
    }

    /// Print Phase 2: Vulnerabilities
    fn print_vulnerabilities(vulns: &[VulnerabilityRecord], cache_status: &CacheStatus) {
        Output::phase(&format!(
            "Phase 2: Vulnerability Correlation [{}]",
            cache_status
        ));

        if vulns.is_empty() {
            println!("  {}No vulnerabilities found{}", Self::GREEN, Self::RESET);
            return;
        }

        // Group by severity
        let critical: Vec<_> = vulns
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .collect();
        let high: Vec<_> = vulns
            .iter()
            .filter(|v| v.severity == Severity::High)
            .collect();
        let medium: Vec<_> = vulns
            .iter()
            .filter(|v| v.severity == Severity::Medium)
            .collect();
        let low: Vec<_> = vulns
            .iter()
            .filter(|v| v.severity == Severity::Low)
            .collect();

        // Print critical
        if !critical.is_empty() {
            println!(
                "\n  {}{}CRITICAL ({}){}",
                Self::BOLD,
                Self::RED,
                critical.len(),
                Self::RESET
            );
            for v in critical.iter().take(5) {
                Self::print_vuln_line(v);
            }
            if critical.len() > 5 {
                println!(
                    "    {}... and {} more{}",
                    Self::DIM,
                    critical.len() - 5,
                    Self::RESET
                );
            }
        }

        // Print high
        if !high.is_empty() {
            println!(
                "\n  {}{}HIGH ({}){}",
                Self::BOLD,
                Self::YELLOW,
                high.len(),
                Self::RESET
            );
            for v in high.iter().take(5) {
                Self::print_vuln_line(v);
            }
            if high.len() > 5 {
                println!(
                    "    {}... and {} more{}",
                    Self::DIM,
                    high.len() - 5,
                    Self::RESET
                );
            }
        }

        // Print medium (compact)
        if !medium.is_empty() {
            println!("\n  {}MEDIUM ({}){}", Self::BLUE, medium.len(), Self::RESET);
            for v in medium.iter().take(3) {
                Self::print_vuln_line(v);
            }
            if medium.len() > 3 {
                println!(
                    "    {}... and {} more{}",
                    Self::DIM,
                    medium.len() - 3,
                    Self::RESET
                );
            }
        }

        // Print low (summary only)
        if !low.is_empty() {
            println!("\n  {}LOW ({}){}", Self::DIM, low.len(), Self::RESET);
        }
    }

    /// Print a single vulnerability line
    fn print_vuln_line(v: &VulnerabilityRecord) {
        let mut tags = Vec::new();

        // CVSS tag
        tags.push(format!("CVSS {:.1}", v.cvss));

        // KEV tag
        if v.in_kev {
            tags.push(format!("{}KEV{}", Self::RED, Self::RESET));
        }

        // Exploit tag
        if v.exploit_available {
            tags.push(format!("{}Exploit{}", Self::MAGENTA, Self::RESET));
        }

        let tech_info = if let Some(ver) = &v.version {
            format!("{} {}", v.technology, ver)
        } else {
            v.technology.clone()
        };

        println!("    {} - {} [{}]", v.cve_id, tech_info, tags.join("] ["));
    }

    /// Print overall risk score
    fn print_risk_score(score: u8) {
        let (color, label) = match score {
            90..=100 => (Self::RED, "Critical"),
            70..=89 => (Self::YELLOW, "High"),
            40..=69 => (Self::BLUE, "Medium"),
            1..=39 => (Self::GREEN, "Low"),
            0 => (Self::GREEN, "None"),
            _ => (Self::DIM, "Unknown"),
        };

        println!(
            "\n  {}Risk Score: {}{}{}/100 ({}){}",
            Self::BOLD,
            color,
            Self::BOLD,
            score,
            label,
            Self::RESET
        );
    }

    /// Print Phase 3: Playbook Recommendations
    fn print_recommendations(recommendations: &[PlaybookRecommendation]) {
        Output::phase("Phase 3: Playbook Recommendations");

        if recommendations.is_empty() {
            println!("  {}No playbooks matched{}", Self::DIM, Self::RESET);
            return;
        }

        // Table header
        println!(
            "\n  {}Score │ Playbook              │ Risk   │ Reasons{}",
            Self::DIM,
            Self::RESET
        );
        println!(
            "  {}──────┼───────────────────────┼────────┼─────────────────────{}",
            Self::DIM,
            Self::RESET
        );

        for (i, rec) in recommendations.iter().take(10).enumerate() {
            let risk_color = match rec.risk_level {
                RiskLevel::Critical => Self::RED,
                RiskLevel::High => Self::YELLOW,
                RiskLevel::Medium => Self::BLUE,
                RiskLevel::Low => Self::GREEN,
                RiskLevel::Passive => Self::DIM,
            };

            let risk_str = format!("{:?}", rec.risk_level);
            let reasons = if rec.reasons.is_empty() {
                "—".to_string()
            } else {
                rec.reasons
                    .iter()
                    .take(2)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            // Truncate playbook name if too long
            let name = if rec.playbook_name.len() > 20 {
                format!("{}…", &rec.playbook_name[..19])
            } else {
                rec.playbook_name.clone()
            };

            let apt_marker = if rec.is_apt_playbook { "⚔ " } else { "" };

            println!(
                "  {:>4}  │ {}{:<20}{} │ {}{:<6}{} │ {}",
                rec.score,
                Self::BOLD,
                format!("{}{}", apt_marker, name),
                Self::RESET,
                risk_color,
                risk_str,
                Self::RESET,
                reasons
            );

            // Show selection hint for top recommendations
            if i < 4 {
                print!("");
            }
        }

        if recommendations.len() > 10 {
            println!(
                "\n  {}... and {} more playbooks{}",
                Self::DIM,
                recommendations.len() - 10,
                Self::RESET
            );
        }

        // Selection prompt
        println!();
        println!(
            "  {}[1-{}] Select playbook to execute{}",
            Self::CYAN,
            recommendations.len().min(10),
            Self::RESET
        );
        println!("  {}[m]   View more playbooks{}", Self::CYAN, Self::RESET);
        println!("  {}[q]   Quit{}", Self::CYAN, Self::RESET);
    }

    /// Print summary statistics
    fn print_summary(result: &AssessmentResult) {
        println!();
        println!(
            "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
            Self::DIM,
            Self::RESET
        );

        let elapsed_ms = result.elapsed.as_millis();
        let elapsed_str = if elapsed_ms > 1000 {
            format!("{:.1}s", elapsed_ms as f64 / 1000.0)
        } else {
            format!("{}ms", elapsed_ms)
        };

        println!(
            "  {}Completed in {}{}{} │ {} technologies │ {} vulnerabilities │ {} playbooks{}",
            Self::DIM,
            Self::RESET,
            elapsed_str,
            Self::DIM,
            result.technologies.len(),
            result.vuln_records.len(),
            result.recommendations.recommendations.len(),
            Self::RESET
        );
    }

    /// Prompt for playbook selection (returns selected index or None)
    pub fn prompt_selection(max: usize) -> Option<usize> {
        use std::io::{self, Write};

        print!("\n  {}>{} ", Self::CYAN, Self::RESET);
        io::stdout().flush().ok()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).ok()?;

        let input = input.trim().to_lowercase();

        match input.as_str() {
            "q" | "quit" | "exit" => None,
            "m" | "more" => {
                // Return special value to indicate "show more"
                Some(usize::MAX)
            }
            _ => {
                // Try to parse as number
                input.parse::<usize>().ok().filter(|&n| n >= 1 && n <= max)
            }
        }
    }

    /// Print execution confirmation prompt
    pub fn confirm_execution(playbook_name: &str, target: &str) -> bool {
        use std::io::{self, Write};

        println!();
        println!(
            "  {}⚠ About to execute: {}{}{} against {}{}{}",
            Self::YELLOW,
            Self::BOLD,
            playbook_name,
            Self::RESET,
            Self::BOLD,
            target,
            Self::RESET
        );
        print!("  {}Continue? [y/N]:{} ", Self::YELLOW, Self::RESET);
        io::stdout().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return false;
        }

        let input = input.trim().to_lowercase();
        matches!(input.as_str(), "y" | "yes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_status_display() {
        let fresh = CacheStatus::Fresh(std::time::Duration::from_secs(3600));
        assert!(format!("{}", fresh).contains("1h"));

        let stale = CacheStatus::Stale(std::time::Duration::from_secs(86400));
        assert!(format!("{}", stale).contains("24h"));

        let miss = CacheStatus::Miss;
        assert_eq!(format!("{}", miss), "No cache");
    }
}
