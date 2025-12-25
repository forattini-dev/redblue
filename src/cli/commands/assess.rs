//! Assessment Workflow Command
//!
//! Continuous assessment workflow integrating:
//! - Technology fingerprinting
//! - Vulnerability correlation
//! - Playbook recommendations
//! - Interactive execution
//!
//! ## Usage
//!
//! ```bash
//! rb assess target run example.com          # Full assessment
//! rb assess target run example.com --skip-fingerprint  # Use cached fingerprints
//! rb assess target run example.com --skip-vuln         # Use cached vulnerabilities
//! rb assess target run example.com --refresh           # Force refresh all
//! rb assess target run example.com --dry-run           # Don't execute playbooks
//! rb assess target show example.com         # Show cached assessment
//! ```

use crate::assess::{AssessOptions, AssessmentEngine, AssessmentOutput};
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::playbooks::types::RiskLevel;
use crate::playbooks::{PlaybookContext, PlaybookExecutor};
use crate::storage::service::StorageService;

pub struct AssessCommand;

impl Command for AssessCommand {
    fn domain(&self) -> &str {
        "assess"
    }

    fn resource(&self) -> &str {
        "target"
    }

    fn description(&self) -> &str {
        "Continuous assessment workflow: fingerprint → vulns → playbooks → execute"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "run",
                summary: "Run full assessment workflow",
                usage: "rb assess target run <target>",
            },
            Route {
                verb: "show",
                summary: "Show cached assessment results",
                usage: "rb assess target show <target>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("skip-fingerprint", "Skip fingerprinting (use cache only)"),
            Flag::new("skip-vuln", "Skip vulnerability lookup (use cache only)"),
            Flag::new("refresh", "Force refresh all data regardless of cache"),
            Flag::new(
                "dry-run",
                "Don't execute playbooks, just show recommendations",
            ),
            Flag::new("risk", "Maximum risk level for playbook recommendations")
                .with_short('r')
                .with_default("high"),
            Flag::new("nvd-api-key", "NVD API key for higher rate limits"),
            Flag::new("format", "Output format (text, json)")
                .with_short('f')
                .with_default("text"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Full assessment workflow",
                "rb assess target run example.com",
            ),
            (
                "Skip fingerprinting (use cache)",
                "rb assess target run example.com --skip-fingerprint",
            ),
            (
                "Skip vuln lookup (use cache)",
                "rb assess target run example.com --skip-vuln",
            ),
            (
                "Force refresh all data",
                "rb assess target run example.com --refresh",
            ),
            (
                "Dry run (no execution)",
                "rb assess target run example.com --dry-run",
            ),
            ("Show cached results", "rb assess target show example.com"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "Missing verb. Use: rb assess target <run|show>".to_string()
        })?;

        match verb.as_str() {
            "run" => self.run_assessment(ctx),
            "show" => self.show_cached(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use: rb assess target help",
                verb
            )),
        }
    }
}

impl AssessCommand {
    /// Run the full assessment workflow
    fn run_assessment(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb assess target run <target>\nExample: rb assess target run example.com"
        )?;

        // Parse flags
        let opts = self.parse_options(ctx);

        // Get database path
        let db_path = StorageService::db_path(target);
        let db_path_str = db_path.to_string_lossy();

        // Create engine and run
        let engine = AssessmentEngine::new(target, &db_path_str);
        let result = engine.run(opts.clone())?;

        if is_json {
            self.print_json(&result, target);
            return Ok(());
        }

        // Print results
        AssessmentOutput::print(&result);

        // Interactive playbook selection (unless dry-run)
        if !opts.dry_run && !result.recommendations.recommendations.is_empty() {
            self.interactive_selection(&result, target)?;
        }

        Ok(())
    }

    /// Show cached assessment results
    fn show_cached(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb assess target show <target>\nExample: rb assess target show example.com"
        )?;

        // Run with skip flags to only use cache
        let opts = AssessOptions {
            skip_fingerprint: true,
            skip_vuln: true,
            refresh: false,
            dry_run: true,
            max_risk: RiskLevel::High,
            nvd_api_key: None,
        };

        let db_path = StorageService::db_path(target);
        let db_path_str = db_path.to_string_lossy();
        let engine = AssessmentEngine::new(target, &db_path_str);
        let result = engine.run(opts)?;

        if is_json {
            self.print_json(&result, target);
            return Ok(());
        }

        AssessmentOutput::print(&result);

        Ok(())
    }

    /// Print assessment result as JSON
    fn print_json(&self, result: &crate::assess::AssessmentResult, target: &str) {
        println!("{{");
        println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
        println!("  \"risk_score\": {},", result.risk_score);
        println!("  \"technologies\": [");
        for (i, tech) in result.technologies.iter().enumerate() {
            let comma = if i < result.technologies.len() - 1 {
                ","
            } else {
                ""
            };
            println!("    {{");
            println!("      \"name\": \"{}\",", tech.name.replace('"', "\\\""));
            if let Some(ref v) = tech.version {
                println!("      \"version\": \"{}\",", v.replace('"', "\\\""));
            } else {
                println!("      \"version\": null,");
            }
            println!("      \"category\": \"{:?}\",", tech.category);
            println!("      \"confidence\": \"{:?}\"", tech.confidence);
            println!("    }}{}", comma);
        }
        println!("  ],");
        println!("  \"vulnerabilities\": [");
        for (i, vuln) in result.vuln_records.iter().enumerate() {
            let comma = if i < result.vuln_records.len() - 1 {
                ","
            } else {
                ""
            };
            println!("    {{");
            println!(
                "      \"cve_id\": \"{}\",",
                vuln.cve_id.replace('"', "\\\"")
            );
            println!(
                "      \"technology\": \"{}\",",
                vuln.technology.replace('"', "\\\"")
            );
            println!("      \"cvss\": {},", vuln.cvss);
            println!("      \"risk_score\": {},", vuln.risk_score);
            println!("      \"severity\": \"{:?}\",", vuln.severity);
            println!("      \"exploit_available\": {},", vuln.exploit_available);
            println!("      \"in_kev\": {},", vuln.in_kev);
            println!("      \"source\": \"{}\"", vuln.source.replace('"', "\\\""));
            println!("    }}{}", comma);
        }
        println!("  ],");
        println!("  \"recommendations\": [");
        for (i, rec) in result.recommendations.recommendations.iter().enumerate() {
            let comma = if i < result.recommendations.recommendations.len() - 1 {
                ","
            } else {
                ""
            };
            println!("    {{");
            println!(
                "      \"playbook_id\": \"{}\",",
                rec.playbook_id.replace('"', "\\\"")
            );
            println!(
                "      \"playbook_name\": \"{}\",",
                rec.playbook_name.replace('"', "\\\"")
            );
            println!("      \"score\": {},", rec.score);
            println!("      \"risk_level\": \"{:?}\",", rec.risk_level);
            println!("      \"reasons\": [");
            for (j, reason) in rec.reasons.iter().enumerate() {
                let comma2 = if j < rec.reasons.len() - 1 { "," } else { "" };
                println!("        \"{}\"{}", reason.replace('"', "\\\""), comma2);
            }
            println!("      ]");
            println!("    }}{}", comma);
        }
        println!("  ]");
        println!("}}");
    }

    /// Parse command options from context
    fn parse_options(&self, ctx: &CliContext) -> AssessOptions {
        let skip_fingerprint = ctx.flags.contains_key("skip-fingerprint");
        let skip_vuln = ctx.flags.contains_key("skip-vuln");
        let refresh = ctx.flags.contains_key("refresh");
        let dry_run = ctx.flags.contains_key("dry-run");

        let max_risk = ctx
            .flags
            .get("risk")
            .map(|s| match s.to_lowercase().as_str() {
                "passive" => RiskLevel::Passive,
                "low" => RiskLevel::Low,
                "medium" => RiskLevel::Medium,
                "high" => RiskLevel::High,
                "critical" => RiskLevel::Critical,
                _ => RiskLevel::High,
            })
            .unwrap_or(RiskLevel::High);

        let nvd_api_key = ctx.flags.get("nvd-api-key").cloned();

        AssessOptions {
            skip_fingerprint,
            skip_vuln,
            refresh,
            dry_run,
            max_risk,
            nvd_api_key,
        }
    }

    /// Interactive playbook selection and execution
    fn interactive_selection(
        &self,
        result: &crate::assess::AssessmentResult,
        target: &str,
    ) -> Result<(), String> {
        let max = result.recommendations.recommendations.len().min(10);

        loop {
            match AssessmentOutput::prompt_selection(max) {
                Some(usize::MAX) => {
                    // Show more playbooks
                    self.show_all_playbooks(result);
                }
                Some(n) if n >= 1 && n <= max => {
                    // Execute selected playbook
                    let rec = &result.recommendations.recommendations[n - 1];

                    if AssessmentOutput::confirm_execution(&rec.playbook_name, target) {
                        self.execute_playbook(&rec.playbook_id, target)?;
                    }
                    break;
                }
                Some(_) => {
                    Output::warning("Invalid selection. Please choose a number or 'q' to quit.");
                }
                None => {
                    // User quit
                    Output::raw("\n  Exiting assessment.");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Show all available playbooks
    fn show_all_playbooks(&self, result: &crate::assess::AssessmentResult) {
        Output::header("All Matched Playbooks");

        for (i, rec) in result.recommendations.recommendations.iter().enumerate() {
            println!(
                "  {:>2}. {} (Score: {}, Risk: {:?})",
                i + 1,
                rec.playbook_name,
                rec.score,
                rec.risk_level
            );

            if !rec.reasons.is_empty() {
                for reason in &rec.reasons {
                    println!("      • {}", reason);
                }
            }
        }
    }

    /// Execute a playbook
    fn execute_playbook(&self, playbook_id: &str, target: &str) -> Result<(), String> {
        Output::spinner_start(&format!("Executing playbook: {}", playbook_id));

        // Try standard playbook first
        let playbook = crate::playbooks::get_playbook(playbook_id)
            .or_else(|| crate::playbooks::get_apt_playbook(playbook_id))
            .ok_or_else(|| format!("Playbook not found: {}", playbook_id))?;

        let mut ctx = PlaybookContext::new(target);
        let executor = PlaybookExecutor::new();

        let report = executor.execute(&playbook, &mut ctx);

        Output::spinner_done();
        let total = report.steps_completed + report.steps_skipped + report.steps_failed;
        Output::success(&format!(
            "Playbook completed: {} steps ({} succeeded, {} skipped, {} failed)",
            total, report.steps_completed, report.steps_skipped, report.steps_failed
        ));

        Ok(())
    }
}
