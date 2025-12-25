/// Attack Workflow Commands
///
/// Unified workflow for reconnaissance, planning, and playbook execution.
///
/// ## Flow
/// ```
/// rb recon full <target>     → Complete reconnaissance
/// rb recon show <target>     → View consolidated findings
/// rb attack plan <target>    → Get playbook recommendations
/// rb attack run <playbook> <target> → Execute playbook
/// ```
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::playbooks::{
    all_playbooks, get_apt_playbook, get_playbook, list_apt_groups, DetectedOS, PlaybookContext,
    PlaybookExecutor, PlaybookRecommendation, PlaybookRecommender, ReconFindings, RiskLevel,
};
use crate::storage::records::{
    PortScanRecord, PortStatus, Severity as StorageSeverity, VulnerabilityRecord,
};
use crate::storage::service::StorageService;
use crate::storage::RedDb;
use std::net::IpAddr;

pub struct AttackCommand;

impl Command for AttackCommand {
    fn domain(&self) -> &str {
        "attack"
    }

    fn resource(&self) -> &str {
        "target"
    }

    fn description(&self) -> &str {
        "Attack planning and playbook execution workflow"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "plan",
                summary: "Analyze findings and recommend playbooks (standard + APT)",
                usage: "rb attack target plan <target>",
            },
            Route {
                verb: "run",
                summary: "Execute a playbook against target",
                usage: "rb attack target run <playbook-id> <target>",
            },
            Route {
                verb: "playbooks",
                summary: "List all available playbooks",
                usage: "rb attack target playbooks [--apt]",
            },
            Route {
                verb: "apt",
                summary: "List APT adversary emulation playbooks",
                usage: "rb attack target apt [group-id]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new(
                "risk",
                "Maximum risk level (passive|low|medium|high|critical)",
            )
            .with_short('r')
            .with_default("high"),
            Flag::new("min-score", "Minimum recommendation score (0-100)").with_default("20"),
            Flag::new("limit", "Maximum recommendations to show").with_default("10"),
            Flag::new("apt", "Show only APT playbooks"),
            Flag::new("dry-run", "Show what would be executed without running"),
            Flag::new("format", "Output format (text, json)")
                .with_short('f')
                .with_default("text"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Get playbook recommendations",
                "rb attack target plan example.com",
            ),
            (
                "Show only high-confidence matches",
                "rb attack target plan example.com --min-score 60",
            ),
            ("Run a playbook", "rb attack target run apt29 example.com"),
            ("List all playbooks", "rb attack target playbooks"),
            ("Show APT playbooks", "rb attack target apt"),
            ("View APT29 details", "rb attack target apt apt29"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "Missing verb. Use: rb attack target <plan|run|playbooks|apt>".to_string()
        })?;

        match verb.as_str() {
            "plan" => self.plan(ctx),
            "run" => self.run_playbook(ctx),
            "playbooks" => self.list_playbooks(ctx),
            "apt" => self.list_apt(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use: rb attack target help",
                verb
            )),
        }
    }
}

impl AttackCommand {
    /// Analyze findings and recommend playbooks
    fn plan(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb attack target plan <target>\nExample: rb attack target plan example.com"
        )?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if !is_json {
            Output::header(&format!("Attack Planning: {}", target));
        }

        // Load findings from storage
        let db_path = StorageService::db_path(target);
        let findings = match RedDb::open(&db_path) {
            Ok(mut store) => {
                if !is_json {
                    Output::spinner_start("Loading reconnaissance data...");
                }

                // Get target IP for port lookup
                let target_ip: Option<std::net::IpAddr> =
                    if target.parse::<std::net::IpAddr>().is_ok() {
                        target.parse().ok()
                    } else {
                        // Try to resolve domain
                        let dns = crate::protocols::dns::DnsClient::new("8.8.8.8");
                        dns.query(target, crate::protocols::dns::DnsRecordType::A)
                            .ok()
                            .and_then(|answers| {
                                answers.into_iter().find_map(|ans| {
                                    if let crate::protocols::dns::DnsRdata::A(ip_str) = ans.data {
                                        ip_str.parse::<std::net::IpAddr>().ok()
                                    } else {
                                        None
                                    }
                                })
                            })
                    };

                let ports = if let Some(ip) = target_ip {
                    store.ports().get_by_ip(ip).unwrap_or_default()
                } else {
                    Vec::new()
                };
                let vulns = store.vulns().all().unwrap_or_default();

                if !is_json {
                    Output::spinner_done();
                }

                // Convert to ReconFindings
                let detected_os = self.detect_os_from_ports(&ports);

                // Get unique technologies from vulnerability data
                let fp_strings: Vec<String> = vulns
                    .iter()
                    .map(|v| {
                        let ver = v.version.as_deref().unwrap_or("");
                        format!("{} {}", v.technology, ver)
                    })
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                let vuln_records: Vec<VulnerabilityRecord> = vulns;

                ReconFindings {
                    target: target.to_string(),
                    ports,
                    vulns: vuln_records,
                    fingerprints: fp_strings,
                    detected_os,
                    target_type: Some(self.detect_target_type(target)),
                    is_internal: self.is_internal_target(target),
                }
            }
            Err(_) => {
                if is_json {
                    println!("{{");
                    println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
                    println!("  \"error\": \"no_recon_data\",");
                    println!("  \"message\": \"No reconnaissance data found for target\"");
                    println!("}}");
                    return Ok(());
                }
                println!();
                Output::warning(&format!("No reconnaissance data found for '{}'", target));
                println!();
                Output::info("Run reconnaissance first:");
                println!("  \x1b[1;36mrb recon full {}\x1b[0m", target);
                println!();
                Output::info("Or run individual scans:");
                println!("  \x1b[36mrb network ports scan {}\x1b[0m", target);
                println!("  \x1b[36mrb recon domain vuln http://{}\x1b[0m", target);
                return Ok(());
            }
        };

        // Get recommendations
        let max_risk = ctx
            .get_flag("risk")
            .map(|r| self.parse_risk_level(&r))
            .unwrap_or(RiskLevel::High);

        let min_score: u8 = ctx
            .get_flag("min-score")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        let max_results: usize = ctx
            .get_flag("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        if !is_json {
            Output::spinner_start("Analyzing attack surface...");
        }

        let recommender = PlaybookRecommender::new()
            .with_max_risk(max_risk)
            .with_min_score(min_score)
            .with_max_results(max_results);

        let result = recommender.recommend(&findings);

        if !is_json {
            Output::spinner_done();
        }

        // JSON output
        if is_json {
            println!("{{");
            println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
            println!("  \"findings\": {{");
            println!(
                "    \"open_ports\": {},",
                findings
                    .ports
                    .iter()
                    .filter(|p| p.status == PortStatus::Open)
                    .count()
            );
            println!("    \"vulnerabilities\": {},", findings.vulns.len());
            println!("    \"fingerprints\": {},", findings.fingerprints.len());
            if let Some(ref os) = findings.detected_os {
                println!("    \"detected_os\": \"{:?}\"", os);
            } else {
                println!("    \"detected_os\": null");
            }
            println!("  }},");
            println!("  \"recommendations\": [");
            for (i, rec) in result.recommendations.iter().enumerate() {
                let comma = if i < result.recommendations.len() - 1 {
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
                    let rcomma = if j < rec.reasons.len() - 1 { "," } else { "" };
                    println!("        \"{}\"{}", reason.replace('"', "\\\""), rcomma);
                }
                println!("      ]");
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // Display findings summary
        self.display_findings_summary(&findings);

        // Display recommendations
        self.display_recommendations(&result, target);

        Ok(())
    }

    /// Execute a playbook
    fn run_playbook(&self, ctx: &CliContext) -> Result<(), String> {
        let playbook_id = ctx
            .target
            .as_ref()
            .ok_or("Missing playbook ID.\nUsage: rb attack target run <playbook-id> <target>")?;

        let target = ctx
            .args
            .get(0)
            .ok_or("Missing target.\nUsage: rb attack target run <playbook-id> <target>")?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        // Find playbook (standard or APT)
        let playbook = get_playbook(playbook_id)
            .or_else(|| get_apt_playbook(playbook_id))
            .ok_or_else(|| {
                format!(
                    "Playbook '{}' not found.\n\nAvailable playbooks:\n  rb attack target playbooks\n  rb attack target apt",
                    playbook_id
                )
            })?;

        let is_apt = get_apt_playbook(playbook_id).is_some();

        if !is_json {
            let apt_badge = if is_apt {
                " \x1b[1;35m[APT]\x1b[0m"
            } else {
                ""
            };

            Output::header(&format!(
                "Executing: {}{}",
                playbook.metadata.name, apt_badge
            ));
            println!();

            Output::item("Target", target);
            Output::item("Playbook", &playbook.metadata.id);
            Output::item("Objective", &playbook.metadata.objective);
            Output::item("Risk Level", playbook.metadata.risk_level.as_str());
            Output::item("Steps", &playbook.steps.len().to_string());

            // Risk warning
            if playbook.metadata.risk_level.requires_consent() {
                println!();
                Output::warning("⚠️  HIGH RISK playbook - ensure you have authorization!");
            }
        }

        // Dry run check
        if ctx.has_flag("dry-run") {
            if is_json {
                println!("{{");
                println!(
                    "  \"playbook_id\": \"{}\",",
                    playbook.metadata.id.replace('"', "\\\"")
                );
                println!(
                    "  \"playbook_name\": \"{}\",",
                    playbook.metadata.name.replace('"', "\\\"")
                );
                println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
                println!("  \"dry_run\": true,");
                println!("  \"is_apt\": {},", is_apt);
                println!("  \"steps\": [");
                for (i, step) in playbook.steps.iter().enumerate() {
                    let comma = if i < playbook.steps.len() - 1 {
                        ","
                    } else {
                        ""
                    };
                    println!("    {{");
                    println!("      \"number\": {},", step.number);
                    println!("      \"name\": \"{}\",", step.name.replace('"', "\\\""));
                    println!("      \"phase\": \"{}\",", step.phase.as_str());
                    println!(
                        "      \"description\": \"{}\"",
                        step.description.replace('"', "\\\"").replace('\n', " ")
                    );
                    println!("    }}{}", comma);
                }
                println!("  ]");
                println!("}}");
                return Ok(());
            }
            println!();
            Output::info("DRY RUN - showing steps without execution:");
            println!();

            for step in &playbook.steps {
                println!(
                    "  {}. \x1b[1m{}\x1b[0m [{}]",
                    step.number,
                    step.name,
                    step.phase.as_str()
                );
                println!("     {}", step.description);
                if !step.commands.is_empty() {
                    println!("     Commands: {}", step.commands.join(", "));
                }
            }
            return Ok(());
        }

        // Execute
        if !is_json {
            println!();
            Output::spinner_start("Executing playbook...");
        }

        let mut context = PlaybookContext::new(target);
        for (k, v) in &ctx.flags {
            context.set_arg(k, v);
        }

        let executor = PlaybookExecutor::new();
        let result = executor.execute(&playbook, &mut context);

        if !is_json {
            Output::spinner_done();
        }

        // JSON output
        if is_json {
            println!("{{");
            println!(
                "  \"playbook_id\": \"{}\",",
                playbook.metadata.id.replace('"', "\\\"")
            );
            println!(
                "  \"playbook_name\": \"{}\",",
                playbook.metadata.name.replace('"', "\\\"")
            );
            println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
            println!("  \"is_apt\": {},", is_apt);
            println!("  \"success\": {},", result.success);
            println!(
                "  \"summary\": \"{}\",",
                result.summary.replace('"', "\\\"")
            );
            println!("  \"steps_completed\": {},", result.steps_completed);
            println!("  \"steps_skipped\": {},", result.steps_skipped);
            println!("  \"steps_failed\": {},", result.steps_failed);
            println!("  \"duration_secs\": {:.2},", result.duration.as_secs_f64());
            println!("  \"step_results\": [");
            for (i, step) in result.step_results.iter().enumerate() {
                let comma = if i < result.step_results.len() - 1 {
                    ","
                } else {
                    ""
                };
                println!("    {{");
                println!("      \"step_number\": {},", step.step_number);
                println!(
                    "      \"step_name\": \"{}\",",
                    step.step_name.replace('"', "\\\"")
                );
                println!(
                    "      \"status\": \"{}\",",
                    step.status.replace('"', "\\\"")
                );
                if let Some(ref err) = step.error {
                    println!(
                        "      \"error\": \"{}\"",
                        err.replace('"', "\\\"").replace('\n', " ")
                    );
                } else {
                    println!("      \"error\": null");
                }
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // Display results
        println!();
        if result.success {
            Output::success(&format!("Playbook completed: {}", result.summary));
        } else {
            Output::error(&format!("Playbook failed: {}", result.summary));
        }

        println!();
        Output::section("Step Results");

        for step in &result.step_results {
            let status_icon = match step.status.as_str() {
                "completed" => "\x1b[32m✓\x1b[0m",
                "failed" => "\x1b[31m✗\x1b[0m",
                "skipped" => "\x1b[33m⊘\x1b[0m",
                _ => "•",
            };

            println!(
                "  {} Step {}: {} - {}",
                status_icon, step.step_number, step.step_name, step.status
            );

            for line in &step.output {
                if !line.is_empty() {
                    println!("    {}", line);
                }
            }

            if let Some(err) = &step.error {
                println!("    \x1b[31mError: {}\x1b[0m", err);
            }
        }

        // Summary stats
        println!();
        Output::item("Steps completed", &result.steps_completed.to_string());
        Output::item("Steps skipped", &result.steps_skipped.to_string());
        Output::item("Steps failed", &result.steps_failed.to_string());
        Output::item(
            "Duration",
            &format!("{:.2}s", result.duration.as_secs_f64()),
        );

        Ok(())
    }

    /// List all playbooks
    fn list_playbooks(&self, ctx: &CliContext) -> Result<(), String> {
        if ctx.has_flag("apt") {
            return self.list_apt(ctx);
        }

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        // JSON output
        if is_json {
            let playbooks = all_playbooks();
            let apt_groups = list_apt_groups();

            println!("{{");
            println!("  \"playbooks\": [");
            for (i, pb) in playbooks.iter().enumerate() {
                let comma = if i < playbooks.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"id\": \"{}\",", pb.metadata.id.replace('"', "\\\""));
                println!(
                    "      \"name\": \"{}\",",
                    pb.metadata.name.replace('"', "\\\"")
                );
                println!("      \"risk_level\": \"{:?}\",", pb.metadata.risk_level);
                println!("      \"steps\": {}", pb.steps.len());
                println!("    }}{}", comma);
            }
            println!("  ],");
            println!("  \"apt_groups\": [");
            for (i, (id, name)) in apt_groups.iter().enumerate() {
                let comma = if i < apt_groups.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"id\": \"{}\",", id.replace('"', "\\\""));
                println!("      \"name\": \"{}\"", name.replace('"', "\\\""));
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        Output::header("Available Playbooks");

        // Standard playbooks
        println!();
        println!("\x1b[1;36m📋 Standard Playbooks\x1b[0m");
        println!();

        for pb in all_playbooks() {
            let risk_color = self.risk_color(&pb.metadata.risk_level);
            println!(
                "  \x1b[1m{:<25}\x1b[0m {}{:?}\x1b[0m  {} steps",
                pb.metadata.id,
                risk_color,
                pb.metadata.risk_level,
                pb.steps.len()
            );
            println!("    {}", pb.metadata.name);
        }

        // APT playbooks summary
        println!();
        println!(
            "\x1b[1;35m🎭 APT Adversary Emulation ({} groups)\x1b[0m",
            list_apt_groups().len()
        );
        println!();

        for (id, name) in list_apt_groups() {
            println!("  \x1b[1m{:<20}\x1b[0m {}", id, name);
        }

        println!();
        Output::info("View APT details: rb attack target apt <group-id>");
        Output::info("Run playbook: rb attack target run <playbook-id> <target>");

        Ok(())
    }

    /// List APT playbooks
    fn list_apt(&self, ctx: &CliContext) -> Result<(), String> {
        let group_id = ctx.target.as_ref();
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if let Some(id) = group_id {
            // Show specific APT playbook
            let playbook = get_apt_playbook(id).ok_or_else(|| {
                format!(
                    "APT group '{}' not found. Use 'rb attack target apt' to list groups.",
                    id
                )
            })?;

            // JSON output for specific playbook
            if is_json {
                println!("{{");
                println!(
                    "  \"id\": \"{}\",",
                    playbook.metadata.id.replace('"', "\\\"")
                );
                println!(
                    "  \"name\": \"{}\",",
                    playbook.metadata.name.replace('"', "\\\"")
                );
                println!(
                    "  \"objective\": \"{}\",",
                    playbook.metadata.objective.replace('"', "\\\"")
                );
                println!(
                    "  \"risk_level\": \"{}\",",
                    playbook.metadata.risk_level.as_str()
                );
                println!("  \"preconditions\": [");
                for (i, cond) in playbook.preconditions.iter().enumerate() {
                    let comma = if i < playbook.preconditions.len() - 1 {
                        ","
                    } else {
                        ""
                    };
                    println!("    \"{}\"{}", cond.description.replace('"', "\\\""), comma);
                }
                println!("  ],");
                println!("  \"steps\": [");
                for (i, step) in playbook.steps.iter().enumerate() {
                    let comma = if i < playbook.steps.len() - 1 {
                        ","
                    } else {
                        ""
                    };
                    println!("    {{");
                    println!("      \"number\": {},", step.number);
                    println!("      \"name\": \"{}\",", step.name.replace('"', "\\\""));
                    println!("      \"phase\": \"{}\",", step.phase.as_str());
                    println!(
                        "      \"description\": \"{}\",",
                        step.description.replace('"', "\\\"").replace('\n', " ")
                    );
                    if let Some(ref tech) = step.mitre_technique {
                        println!(
                            "      \"mitre_technique\": \"{}\"",
                            tech.replace('"', "\\\"")
                        );
                    } else {
                        println!("      \"mitre_technique\": null");
                    }
                    println!("    }}{}", comma);
                }
                println!("  ],");
                println!("  \"evidence\": [");
                for (i, ev) in playbook.evidence.iter().enumerate() {
                    let comma = if i < playbook.evidence.len() - 1 {
                        ","
                    } else {
                        ""
                    };
                    println!("    \"{}\"{}", ev.description.replace('"', "\\\""), comma);
                }
                println!("  ],");
                println!("  \"failed_controls\": [");
                for (i, ctrl) in playbook.failed_controls.iter().enumerate() {
                    let comma = if i < playbook.failed_controls.len() - 1 {
                        ","
                    } else {
                        ""
                    };
                    println!("    {{");
                    println!("      \"name\": \"{}\",", ctrl.name.replace('"', "\\\""));
                    println!("      \"reason\": \"{}\"", ctrl.reason.replace('"', "\\\""));
                    println!("    }}{}", comma);
                }
                println!("  ]");
                println!("}}");
                return Ok(());
            }

            Output::header(&format!("APT Playbook: {}", playbook.metadata.name));
            println!();

            Output::item("ID", &playbook.metadata.id);
            Output::item("Objective", &playbook.metadata.objective);
            Output::item("Risk", playbook.metadata.risk_level.as_str());
            Output::item("Steps", &playbook.steps.len().to_string());

            // Pre-conditions
            if !playbook.preconditions.is_empty() {
                println!();
                println!("\x1b[1;33m⚡ Pre-conditions:\x1b[0m");
                for cond in &playbook.preconditions {
                    println!("  • {}", cond.description);
                }
            }

            // Attack flow
            println!();
            println!("\x1b[1;36m🎯 Attack Flow:\x1b[0m");

            for step in &playbook.steps {
                let phase_color = self.phase_color(&step.phase);
                println!();
                println!(
                    "  \x1b[1m{}. {}\x1b[0m {}[{}]\x1b[0m",
                    step.number,
                    step.name,
                    phase_color,
                    step.phase.as_str()
                );
                println!("     {}", step.description);

                if let Some(technique) = &step.mitre_technique {
                    println!("     \x1b[2mMITRE: {}\x1b[0m", technique);
                }
            }

            // Evidence
            if !playbook.evidence.is_empty() {
                println!();
                println!("\x1b[1;32m✓ Evidence of Success:\x1b[0m");
                for ev in &playbook.evidence {
                    println!("  • {}", ev.description);
                }
            }

            // Failed controls
            if !playbook.failed_controls.is_empty() {
                println!();
                println!("\x1b[1;31m✗ Common Defensive Gaps:\x1b[0m");
                for ctrl in &playbook.failed_controls {
                    println!("  • {} - {}", ctrl.name, ctrl.reason);
                }
            }

            println!();
            Output::info(&format!("Run: rb attack target run {} <target>", id));
        } else {
            // JSON output for listing all APT groups
            if is_json {
                let apt_groups = list_apt_groups();
                println!("{{");
                println!("  \"apt_groups\": [");
                for (i, (id, name)) in apt_groups.iter().enumerate() {
                    let comma = if i < apt_groups.len() - 1 { "," } else { "" };
                    println!("    {{");
                    println!("      \"id\": \"{}\",", id.replace('"', "\\\""));
                    println!("      \"name\": \"{}\"", name.replace('"', "\\\""));
                    println!("    }}{}", comma);
                }
                println!("  ]");
                println!("}}");
                return Ok(());
            }

            // List all APT groups
            Output::header("APT Adversary Emulation Playbooks");
            println!();
            println!("Real-world threat actor TTPs from MITRE ATT&CK v18.1");
            println!();

            println!("\x1b[1;31m🇷🇺 Russia\x1b[0m");
            println!("  apt28          Fancy Bear (GRU Unit 26165)");
            println!("  apt29          Cozy Bear (SVR)");
            println!("  sandworm-team  BlackEnergy (GRU Unit 74455)");
            println!("  turla          Waterbug (FSB)");
            println!("  wizard-spider  TrickBot/Ryuk");
            println!();

            println!("\x1b[1;33m🇨🇳 China\x1b[0m");
            println!("  apt3           Gothic Panda (MSS)");
            println!("  apt41          Wicked Panda (MSS contractor)");
            println!("  volt-typhoon   BRONZE SILHOUETTE (PLA)");
            println!();

            println!("\x1b[1;34m🇰🇵 North Korea\x1b[0m");
            println!("  kimsuky        Velvet Chollima (RGB)");
            println!("  lazarus-group  HIDDEN COBRA (RGB)");
            println!();

            println!("\x1b[1;32m🇮🇷 Iran\x1b[0m");
            println!("  muddywater     MOIS");
            println!("  oilrig         APT34 (MOIS)");
            println!();

            println!("\x1b[1;35m🇻🇳 Vietnam\x1b[0m");
            println!("  apt32          OceanLotus");
            println!();

            println!("\x1b[1;36m💰 Financially Motivated\x1b[0m");
            println!("  fin7           Carbanak");
            println!("  scattered-spider  Social Engineering");
            println!();

            Output::info("View details: rb attack target apt <group-id>");
            Output::info("Example: rb attack target apt apt29");
        }

        Ok(())
    }

    // === Helper Methods ===

    fn display_findings_summary(&self, findings: &ReconFindings) {
        println!();
        Output::section("Reconnaissance Summary");

        // Ports
        let open_ports: Vec<_> = findings
            .ports
            .iter()
            .filter(|p| p.status == PortStatus::Open)
            .collect();

        if !open_ports.is_empty() {
            let port_list: Vec<String> = open_ports
                .iter()
                .take(10)
                .map(|p| p.port.to_string())
                .collect();
            let suffix = if open_ports.len() > 10 {
                format!(" (+{} more)", open_ports.len() - 10)
            } else {
                String::new()
            };
            Output::item("Open Ports", &format!("{}{}", port_list.join(", "), suffix));
        } else {
            Output::item("Open Ports", "None found");
        }

        // OS Detection
        if let Some(os) = &findings.detected_os {
            Output::item("Detected OS", &format!("{:?}", os));
        }

        // Fingerprints
        if !findings.fingerprints.is_empty() {
            let fp_list: String = findings
                .fingerprints
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if findings.fingerprints.len() > 5 {
                format!(" (+{} more)", findings.fingerprints.len() - 5)
            } else {
                String::new()
            };
            Output::item("Technologies", &format!("{}{}", fp_list, suffix));
        }

        // Vulnerabilities
        if !findings.vulns.is_empty() {
            let critical = findings
                .vulns
                .iter()
                .filter(|v| v.severity == StorageSeverity::Critical)
                .count();
            let high = findings
                .vulns
                .iter()
                .filter(|v| v.severity == StorageSeverity::High)
                .count();
            let medium = findings
                .vulns
                .iter()
                .filter(|v| v.severity == StorageSeverity::Medium)
                .count();

            Output::item(
                "Vulnerabilities",
                &format!(
                    "{} total (\x1b[31m{} critical\x1b[0m, \x1b[33m{} high\x1b[0m, {} medium)",
                    findings.vulns.len(),
                    critical,
                    high,
                    medium
                ),
            );

            // Show top CVEs
            let mut sorted_vulns = findings.vulns.clone();
            sorted_vulns.sort_by(|a, b| {
                b.cvss
                    .partial_cmp(&a.cvss)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            for vuln in sorted_vulns.iter().take(3) {
                let sev_color = match vuln.severity {
                    StorageSeverity::Critical => "\x1b[1;31m",
                    StorageSeverity::High => "\x1b[31m",
                    StorageSeverity::Medium => "\x1b[33m",
                    _ => "\x1b[0m",
                };
                println!(
                    "    {}• {} (CVSS {:.1})\x1b[0m",
                    sev_color, vuln.cve_id, vuln.cvss
                );
            }
        } else {
            Output::item("Vulnerabilities", "None found");
        }

        // Target type
        if let Some(tt) = &findings.target_type {
            Output::item("Target Type", &format!("{:?}", tt));
        }

        if findings.is_internal {
            Output::item("Network", "Internal");
        }
    }

    fn display_recommendations(
        &self,
        result: &crate::playbooks::RecommendationResult,
        target: &str,
    ) {
        println!();
        Output::section("Playbook Recommendations");

        // Summary
        Output::item("Total matches", &result.summary.total_matched.to_string());
        if result.summary.apt_playbooks_matched > 0 {
            Output::item(
                "APT playbooks",
                &result.summary.apt_playbooks_matched.to_string(),
            );
        }

        if result.summary.has_critical_findings {
            println!();
            Output::warning(
                "⚠️  Critical vulnerabilities detected - prioritize high-risk playbooks",
            );
        }

        if result.recommendations.is_empty() {
            println!();
            Output::info("No playbooks matched. Run more reconnaissance:");
            println!("  \x1b[36mrb recon full {}\x1b[0m", target);
            return;
        }

        // Group by score
        let strong: Vec<_> = result
            .recommendations
            .iter()
            .filter(|r| r.score >= 70)
            .collect();
        let moderate: Vec<_> = result
            .recommendations
            .iter()
            .filter(|r| r.score >= 40 && r.score < 70)
            .collect();
        let weak: Vec<_> = result
            .recommendations
            .iter()
            .filter(|r| r.score < 40)
            .collect();

        if !strong.is_empty() {
            println!();
            println!("\x1b[1;32m🎯 STRONG MATCHES (≥70)\x1b[0m");
            for rec in &strong {
                self.display_recommendation(rec);
            }
        }

        if !moderate.is_empty() {
            println!();
            println!("\x1b[1;33m📋 MODERATE MATCHES (40-69)\x1b[0m");
            for rec in &moderate {
                self.display_recommendation(rec);
            }
        }

        if !weak.is_empty() {
            println!();
            println!("\x1b[1;34m💡 WEAK MATCHES (<40)\x1b[0m");
            for rec in weak.iter().take(3) {
                self.display_recommendation(rec);
            }
            if weak.len() > 3 {
                println!("  \x1b[2m... and {} more\x1b[0m", weak.len() - 3);
            }
        }

        // Next steps
        if let Some(top) = result.recommendations.first() {
            println!();
            Output::section("Recommended Next Step");
            println!("  Run the top playbook:");
            println!(
                "  \x1b[1;36mrb attack target run {} {}\x1b[0m",
                top.playbook_id, target
            );
        }
    }

    fn display_recommendation(&self, rec: &PlaybookRecommendation) {
        let risk_color = self.risk_color(&rec.risk_level);
        let apt_badge = if rec.is_apt_playbook {
            " \x1b[35m[APT]\x1b[0m"
        } else {
            ""
        };

        println!();
        println!(
            "  \x1b[1m{}\x1b[0m{} (Score: {}/100)",
            rec.playbook_name, apt_badge, rec.score
        );
        println!(
            "    ID: {}  Risk: {}{:?}\x1b[0m",
            rec.playbook_id, risk_color, rec.risk_level
        );

        if !rec.reasons.is_empty() {
            for reason in rec.reasons.iter().take(3) {
                println!("    \x1b[32m•\x1b[0m {}", reason);
            }
        }
    }

    fn detect_os_from_ports(&self, ports: &[PortScanRecord]) -> Option<DetectedOS> {
        let has_ssh = ports
            .iter()
            .any(|p| p.port == 22 && p.status == PortStatus::Open);
        let has_smb = ports
            .iter()
            .any(|p| (p.port == 445 || p.port == 139) && p.status == PortStatus::Open);
        let has_rdp = ports
            .iter()
            .any(|p| p.port == 3389 && p.status == PortStatus::Open);

        if has_rdp || (has_smb && !has_ssh) {
            Some(DetectedOS::Windows)
        } else if has_ssh && !has_smb && !has_rdp {
            Some(DetectedOS::Linux)
        } else if has_ssh && has_smb {
            Some(DetectedOS::Unknown)
        } else {
            None
        }
    }

    fn detect_target_type(&self, target: &str) -> crate::playbooks::TargetType {
        if target.starts_with("http://") || target.starts_with("https://") {
            crate::playbooks::TargetType::WebApp
        } else if target.parse::<IpAddr>().is_ok() {
            crate::playbooks::TargetType::Host
        } else if target.contains('.') {
            crate::playbooks::TargetType::Domain
        } else {
            crate::playbooks::TargetType::Host
        }
    }

    fn is_internal_target(&self, target: &str) -> bool {
        if let Ok(ip) = target.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback(),
                IpAddr::V6(ipv6) => ipv6.is_loopback(),
            }
        } else {
            // Check for common internal domain patterns
            target.ends_with(".local")
                || target.ends_with(".internal")
                || target.ends_with(".corp")
                || target.ends_with(".lan")
        }
    }

    fn parse_risk_level(&self, s: &str) -> RiskLevel {
        match s.to_lowercase().as_str() {
            "passive" => RiskLevel::Passive,
            "low" => RiskLevel::Low,
            "medium" => RiskLevel::Medium,
            "high" => RiskLevel::High,
            "critical" => RiskLevel::Critical,
            _ => RiskLevel::High,
        }
    }

    fn risk_color(&self, risk: &RiskLevel) -> &'static str {
        match risk {
            RiskLevel::Critical => "\x1b[1;31m",
            RiskLevel::High => "\x1b[31m",
            RiskLevel::Medium => "\x1b[33m",
            RiskLevel::Low => "\x1b[32m",
            RiskLevel::Passive => "\x1b[36m",
        }
    }

    fn phase_color(&self, phase: &crate::playbooks::PlaybookPhase) -> &'static str {
        use crate::playbooks::PlaybookPhase::*;
        match phase {
            InitialAccess => "\x1b[31m",
            Execution => "\x1b[33m",
            Persistence => "\x1b[35m",
            PrivilegeEscalation => "\x1b[1;31m",
            DefenseEvasion => "\x1b[36m",
            CredentialAccess => "\x1b[1;33m",
            Discovery => "\x1b[34m",
            LateralMovement => "\x1b[1;35m",
            Collection => "\x1b[32m",
            C2 => "\x1b[1;36m",
            Exfiltration => "\x1b[1;32m",
            Impact => "\x1b[1;31m",
            _ => "\x1b[0m",
        }
    }
}
