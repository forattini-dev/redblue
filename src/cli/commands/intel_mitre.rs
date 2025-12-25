//! MITRE ATT&CK Intelligence Command
//!
//! Query MITRE ATT&CK framework data:
//! - Techniques (T1059, T1059.001)
//! - Tactics (TA0001)
//! - Threat Groups (G0016, APT29)
//! - Software (S0154, Cobalt Strike)
//! - Mitigations (M1036)

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::intel::attack_database::{
    self, AttackTechnique, Software, Tactic, ThreatGroup,
};
use crate::modules::intel::{Confidence, Findings, NavigatorLayer, TechniqueMapper};

pub struct IntelMitreCommand;

impl Command for IntelMitreCommand {
    fn domain(&self) -> &str {
        "intelligence" // Short alias: "intel"
    }

    fn resource(&self) -> &str {
        "mitre"
    }

    fn description(&self) -> &str {
        "MITRE ATT&CK threat intelligence - techniques, tactics, groups, software"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "technique",
                summary: "Get technique details by ID (T1059, T1059.001)",
                usage: "rb intel mitre technique <ID>",
            },
            Route {
                verb: "tactic",
                summary: "Get tactic details by ID or name (TA0002, execution)",
                usage: "rb intel mitre tactic <ID>",
            },
            Route {
                verb: "group",
                summary: "Get threat group details by ID or name (G0016, APT29)",
                usage: "rb intel mitre group <ID>",
            },
            Route {
                verb: "software",
                summary: "Get software/malware details by ID or name (S0154, Cobalt Strike)",
                usage: "rb intel mitre software <ID>",
            },
            Route {
                verb: "search",
                summary: "Search across all ATT&CK objects",
                usage: "rb intel mitre search <query>",
            },
            Route {
                verb: "matrix",
                summary: "Display ATT&CK matrix overview",
                usage: "rb intel mitre matrix [--full]",
            },
            Route {
                verb: "coverage",
                summary: "Show tactic coverage based on mapped findings",
                usage: "rb intel mitre coverage [ports=...] [cves=...] [tech=...]",
            },
            Route {
                verb: "mitigations",
                summary: "Get mitigations for a technique",
                usage: "rb intel mitre mitigations <technique_id>",
            },
            Route {
                verb: "detection",
                summary: "Get detection strategies for a technique",
                usage: "rb intel mitre detection <technique_id>",
            },
            Route {
                verb: "stats",
                summary: "Show ATT&CK data statistics",
                usage: "rb intel mitre stats",
            },
            Route {
                verb: "map",
                summary: "Map findings (ports, CVEs, fingerprints) to ATT&CK techniques",
                usage:
                    "rb intel mitre map [ports=22,80,443] [cves=CVE-2021-44228] [tech=wordpress]",
            },
            Route {
                verb: "ports",
                summary: "Show port-to-technique mapping table",
                usage: "rb intel mitre ports [port]",
            },
            Route {
                verb: "export",
                summary: "Export mapped techniques to ATT&CK Navigator layer (JSON)",
                usage: "rb intel mitre export [output=file.json] [ports=...] [cves=...] [tech=...]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("output", "Output format (text, json, yaml)")
                .with_short('o')
                .with_default("text"),
            Flag::new("matrix", "ATT&CK matrix to query (enterprise, mobile, ics)")
                .with_short('m')
                .with_default("enterprise"),
            Flag::new("full", "Show full details including description"),
            Flag::new("limit", "Maximum results to show").with_default("20"),
            Flag::new("ports", "Comma-separated list of ports to map").with_short('p'),
            Flag::new("cves", "Comma-separated list of CVE IDs to map"),
            Flag::new(
                "tech",
                "Comma-separated list of technologies/fingerprints to map",
            )
            .with_short('t'),
            Flag::new("banner", "Service banner to analyze"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Get technique details", "rb intel mitre technique T1059"),
            ("Get sub-technique", "rb intel mitre technique T1059.001"),
            ("Get tactic by name", "rb intel mitre tactic execution"),
            ("Get threat group", "rb intel mitre group APT29"),
            ("Get software/tool", "rb intel mitre software \"Cobalt Strike\""),
            ("Search ATT&CK", "rb intel mitre search lateral"),
            ("Show matrix overview", "rb intel mitre matrix"),
            ("Show tactic coverage", "rb intel mitre coverage ports=22,80,443 tech=wordpress"),
            ("Get mitigations", "rb intel mitre mitigations T1059"),
            ("Get detection info", "rb intel mitre detection T1059.001"),
            ("Show statistics", "rb intel mitre stats"),
            ("Map ports to techniques", "rb intel mitre map ports=22,80,443,3389"),
            ("Map CVE to techniques", "rb intel mitre map cves=CVE-2021-44228"),
            ("Map technology", "rb intel mitre map tech=wordpress,nginx"),
            ("Combined mapping", "rb intel mitre map ports=22,80 tech=wordpress"),
            ("Show port mappings", "rb intel mitre ports"),
            ("Query specific port", "rb intel mitre ports 22"),
            ("Export to Navigator layer", "rb intel mitre export output=findings.json ports=22,80,443"),
            ("Export with all findings", "rb intel mitre export output=report.json ports=22 cves=CVE-2021-44228 tech=wordpress"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "technique" => self.get_technique(ctx),
            "tactic" => self.get_tactic(ctx),
            "group" => self.get_group(ctx),
            "software" => self.get_software(ctx),
            "search" => self.search(ctx),
            "matrix" => self.show_matrix(ctx),
            "coverage" => self.show_coverage(ctx),
            "mitigations" => self.get_mitigations(ctx),
            "detection" => self.get_detection(ctx),
            "stats" => self.show_stats(ctx),
            "map" => self.map_findings(ctx),
            "ports" => self.show_port_mappings(ctx),
            "export" => self.export_navigator(ctx),
            _ => {
                print_help(self);
                Err(format!("Unknown verb: {}", verb))
            }
        }
    }
}

impl IntelMitreCommand {
    /// Get technique details
    fn get_technique(&self, ctx: &CliContext) -> Result<(), String> {
        let tech_id = ctx
            .target
            .as_ref()
            .ok_or("Missing technique ID (e.g., T1059)")?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if !is_json {
            Output::header(&format!("MITRE ATT&CK Technique: {}", tech_id));
            println!();
            Output::spinner_start("Fetching ATT&CK data...");
        }

        let db = attack_database::db();
        let tech = db
            .get_technique(tech_id)
            .or_else(|| db.get_technique_by_name(tech_id));

        if !is_json {
            Output::spinner_done();
        }

        if is_json {
            match tech {
                Some(t) => {
                    println!("{{");
                    println!("  \"found\": true,");
                    println!("  \"technique_id\": \"{}\",", t.technique_id);
                    println!(
                        "  \"name\": \"{}\",",
                        t.name.replace('\\', "\\\\").replace('"', "\\\"")
                    );
                    println!("  \"is_subtechnique\": {},", t.is_subtechnique);
                    if let Some(ref parent) = t.parent_technique {
                        println!("  \"parent_technique\": \"{}\",", parent);
                    }
                    println!(
                        "  \"tactics\": [{}],",
                        t.tactics
                            .iter()
                            .map(|s| format!("\"{}\"", s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!(
                        "  \"platforms\": [{}],",
                        t.platforms
                            .iter()
                            .map(|s| format!("\"{}\"", s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!(
                        "  \"data_sources\": [{}],",
                        t.data_sources
                            .iter()
                            .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    if let Some(ref url) = t.url {
                        println!("  \"url\": \"{}\",", url);
                    }
                    println!("  \"deprecated\": {},", t.deprecated);
                    println!("  \"revoked\": {},", t.revoked);
                    println!(
                        "  \"description\": \"{}\"",
                        t.description
                            .replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('\n', "\\n")
                    );
                    println!("}}");
                }
                None => {
                    println!("{{");
                    println!("  \"found\": false,");
                    println!("  \"query\": \"{}\"", tech_id);
                    println!("}}");
                }
            }
            return Ok(());
        }

        match tech {
            Some(t) => self.display_technique(t, ctx.has_flag("full")),
            None => {
                Output::warning(&format!("Technique {} not found", tech_id));
                Output::info("Try searching: rb intel mitre search <query>");
            }
        }

        Ok(())
    }

    /// Get tactic details
    fn get_tactic(&self, _ctx: &CliContext) -> Result<(), String> {
        Output::info("Tactic lookup is not yet implemented with the embedded database.");
        Ok(())
    }

    /// Get threat group details
    fn get_group(&self, ctx: &CliContext) -> Result<(), String> {
        let group_id = ctx
            .target
            .as_ref()
            .ok_or("Missing group ID or name (e.g., G0016 or APT29)")?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if !is_json {
            Output::header(&format!("MITRE ATT&CK Threat Group: {}", group_id));
            println!();
            Output::spinner_start("Fetching ATT&CK data...");
        }

        let db = attack_database::db();
        let group = db
            .get_group(group_id)
            .or_else(|| db.get_group_by_name(group_id));

        if !is_json {
            Output::spinner_done();
        }

        if is_json {
            match group {
                Some(g) => {
                    println!("{{");
                    println!("  \"found\": true,");
                    println!("  \"group_id\": \"{}\",", g.group_id);
                    println!(
                        "  \"name\": \"{}\",",
                        g.name.replace('\\', "\\\\").replace('"', "\\\"")
                    );
                    println!(
                        "  \"aliases\": [{}],",
                        g.aliases
                            .iter()
                            .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!(
                        "  \"associated_techniques\": [{}],",
                        g.associated_techniques
                            .iter()
                            .map(|s| format!("\"{}\"", s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!(
                        "  \"url\": \"https://attack.mitre.org/groups/{}/\",",
                        g.group_id
                    );
                    println!(
                        "  \"description\": \"{}\"",
                        g.description
                            .replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('\n', "\\n")
                    );
                    println!("}}");
                }
                None => {
                    println!("{{");
                    println!("  \"found\": false,");
                    println!("  \"query\": \"{}\"", group_id);
                    println!("}}");
                }
            }
            return Ok(());
        }

        match group {
            Some(g) => self.display_group(g, ctx.has_flag("full")),
            None => {
                Output::warning(&format!("Group {} not found", group_id));
                Output::info("Try searching: rb intel mitre search <query>");
            }
        }

        Ok(())
    }

    /// Get software details
    fn get_software(&self, _ctx: &CliContext) -> Result<(), String> {
        Output::info("Software lookup is not yet implemented with the embedded database.");
        Ok(())
    }

    /// Search ATT&CK
    fn search(&self, ctx: &CliContext) -> Result<(), String> {
        let query = ctx.target.as_ref().ok_or("Missing search query")?;
        let limit: usize = ctx
            .get_flag_with_config("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if !is_json {
            Output::header(&format!("MITRE ATT&CK Search: {}", query));
            println!();
            Output::spinner_start("Searching ATT&CK data...");
        }

        let db = attack_database::db();
        let techniques = db.search_techniques(query);
        let groups = db.search_groups(query);

        if !is_json {
            Output::spinner_done();
        }

        if is_json {
            println!("{{");
            println!("  \"query\": \"{}\",", query);
            println!("  \"total_results\": {},", techniques.len() + groups.len());
            println!("  \"techniques\": [");
            for (i, t) in techniques.iter().take(limit).enumerate() {
                let comma = if i < techniques.len().min(limit) - 1 {
                    ","
                } else {
                    ""
                };
                println!(
                    "    {{\"technique_id\": \"{}\", \"name\": \"{}\", \"tactics\": [{}]}}{}",
                    t.technique_id,
                    t.name.replace('"', "\\\""),
                    t.tactics
                        .iter()
                        .map(|s| format!("\"{}\"", s))
                        .collect::<Vec<_>>()
                        .join(", "),
                    comma
                );
            }
            println!("  ],");
            println!("  \"groups\": [");
            for (i, g) in groups.iter().take(limit).enumerate() {
                let comma = if i < groups.len().min(limit) - 1 {
                    ","
                } else {
                    ""
                };
                println!(
                    "    {{\"group_id\": \"{}\", \"name\": \"{}\", \"aliases\": [{}]}}{}",
                    g.group_id,
                    g.name.replace('"', "\\\""),
                    g.aliases
                        .iter()
                        .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                        .collect::<Vec<_>>()
                        .join(", "),
                    comma
                );
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        if techniques.is_empty() && groups.is_empty() {
            Output::info("No results found.");
            return Ok(());
        }

        Output::success(&format!(
            "Found {} results",
            techniques.len() + groups.len()
        ));
        println!();

        if !techniques.is_empty() {
            Output::section(&format!("Techniques ({})", techniques.len()));
            for t in techniques.iter().take(limit) {
                let tactics_str = if t.tactics.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", t.tactics.join(", "))
                };
                println!("  {} - {}{}", t.technique_id, t.name, tactics_str);
            }
            if techniques.len() > limit {
                Output::info(&format!("  ... and {} more", techniques.len() - limit));
            }
            println!();
        }

        if !groups.is_empty() {
            Output::section(&format!("Groups ({})", groups.len()));
            for g in groups.iter().take(limit) {
                let aliases = if g.aliases.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", g.aliases.join(", "))
                };
                println!("  {} - {}{}", g.group_id, g.name, aliases);
            }
            if groups.len() > limit {
                Output::info(&format!("  ... and {} more", groups.len() - limit));
            }
            println!();
        }

        Ok(())
    }

    /// Show ATT&CK matrix overview (ASCII representation)
    fn show_matrix(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if !is_json {
            Output::header("MITRE ATT&CK Enterprise Matrix");
            println!();
            Output::spinner_start("Loading ATT&CK data...");
        }

        let db = attack_database::db();

        if !is_json {
            Output::spinner_done();
        }

        // Enterprise ATT&CK tactics in kill chain order
        // The tactics field in techniques uses lowercase with hyphens
        let tactics_order = [
            ("reconnaissance", "TA0043", "Recon"),
            ("resource-development", "TA0042", "Resource Dev"),
            ("initial-access", "TA0001", "Initial Access"),
            ("execution", "TA0002", "Execution"),
            ("persistence", "TA0003", "Persistence"),
            ("privilege-escalation", "TA0004", "Priv Esc"),
            ("defense-evasion", "TA0005", "Defense Evasion"),
            ("credential-access", "TA0006", "Cred Access"),
            ("discovery", "TA0007", "Discovery"),
            ("lateral-movement", "TA0008", "Lateral Move"),
            ("collection", "TA0009", "Collection"),
            ("command-and-control", "TA0011", "C2"),
            ("exfiltration", "TA0010", "Exfiltration"),
            ("impact", "TA0040", "Impact"),
        ];

        // Count techniques per tactic (exclude subtechniques for cleaner view)
        let mut tactic_counts: std::collections::HashMap<&str, Vec<&AttackTechnique>> =
            std::collections::HashMap::new();

        for tech in db.techniques.values() {
            if tech.deprecated || tech.revoked {
                continue;
            }
            for tactic in &tech.tactics {
                tactic_counts.entry(tactic.as_str()).or_default().push(tech);
            }
        }

        let show_full = ctx.has_flag("full");
        let limit: usize = ctx
            .get_flag_with_config("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        // Show statistics summary first
        let total_techniques = db
            .techniques
            .values()
            .filter(|t| !t.deprecated && !t.revoked)
            .count();
        let parent_techniques = db
            .techniques
            .values()
            .filter(|t| !t.deprecated && !t.revoked && !t.is_subtechnique)
            .count();
        let subtechniques = total_techniques - parent_techniques;

        if is_json {
            println!("{{");
            println!("  \"summary\": {{");
            println!("    \"total_techniques\": {},", total_techniques);
            println!("    \"parent_techniques\": {},", parent_techniques);
            println!("    \"subtechniques\": {},", subtechniques);
            println!("    \"threat_groups\": {}", db.groups.len());
            println!("  }},");
            println!("  \"tactics\": [");
            for (i, (tactic_key, tactic_id, display_name)) in tactics_order.iter().enumerate() {
                let techs = tactic_counts
                    .get(*tactic_key)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let count = techs.len();
                let parent_count = techs.iter().filter(|t| !t.is_subtechnique).count();
                let comma = if i < tactics_order.len() - 1 { "," } else { "" };
                println!(
                    "    {{\"id\": \"{}\", \"name\": \"{}\", \"technique_count\": {}, \"parent_count\": {}}}{}",
                    tactic_id, display_name, count, parent_count, comma
                );
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        Output::section("Summary");
        Output::item("Total Techniques", &total_techniques.to_string());
        Output::item("Parent Techniques", &parent_techniques.to_string());
        Output::item("Sub-techniques", &subtechniques.to_string());
        Output::item("Threat Groups", &db.groups.len().to_string());
        println!();

        // Display matrix overview (horizontal bar chart)
        Output::section("Tactics Coverage (techniques per tactic)");
        println!();

        let max_count = tactic_counts.values().map(|v| v.len()).max().unwrap_or(1);

        // Column width for the bar chart
        let bar_width = 40;

        for (tactic_key, tactic_id, display_name) in &tactics_order {
            let techs = tactic_counts
                .get(*tactic_key)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let count = techs.len();

            // Count only parent techniques for display
            let parent_count = techs.iter().filter(|t| !t.is_subtechnique).count();

            // Calculate bar length proportional to count
            let bar_len = if max_count > 0 {
                (count * bar_width) / max_count
            } else {
                0
            };

            // Create visual bar
            let bar: String = "█".repeat(bar_len.min(bar_width));

            // Color based on count (high = red, medium = yellow, low = green)
            let color = if count > 50 {
                "\x1b[31m" // Red
            } else if count > 20 {
                "\x1b[33m" // Yellow
            } else {
                "\x1b[32m" // Green
            };

            println!(
                "  {:<14} {:<7} {}{}\x1b[0m  {:>3} ({} parent)",
                display_name, tactic_id, color, bar, count, parent_count
            );
        }

        println!();

        // If --full flag, show techniques for each tactic
        if show_full {
            Output::section("Techniques by Tactic");
            println!();

            for (tactic_key, tactic_id, display_name) in &tactics_order {
                let techs = match tactic_counts.get(*tactic_key) {
                    Some(t) => t,
                    None => continue,
                };

                if techs.is_empty() {
                    continue;
                }

                // Sort: parent techniques first, then subtechniques
                let mut sorted_techs: Vec<_> = techs.iter().collect();
                sorted_techs.sort_by(|a, b| match (a.is_subtechnique, b.is_subtechnique) {
                    (false, true) => std::cmp::Ordering::Less,
                    (true, false) => std::cmp::Ordering::Greater,
                    _ => a.technique_id.cmp(&b.technique_id),
                });

                println!(
                    "  \x1b[1m{} ({})\x1b[0m - {} techniques",
                    display_name,
                    tactic_id,
                    techs.len()
                );

                for tech in sorted_techs.iter().take(limit) {
                    let prefix = if tech.is_subtechnique {
                        "  └"
                    } else {
                        "  ├"
                    };
                    println!("    {} {} - {}", prefix, tech.technique_id, tech.name);
                }

                if sorted_techs.len() > limit {
                    println!("    ... and {} more", sorted_techs.len() - limit);
                }
                println!();
            }
        } else {
            Output::info("Use --full to show techniques for each tactic");
            Output::info("Use --limit <n> to control how many techniques to show per tactic");
        }

        Ok(())
    }

    /// Show tactic coverage based on mapped findings
    fn show_coverage(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("MITRE ATT&CK Tactic Coverage Report");
        println!();

        let mapper = TechniqueMapper::new();
        let mut findings = Findings::default();

        // Helper to parse a key=value pair
        let parse_kv = |arg: &str, findings: &mut Findings| {
            if let Some(eq_pos) = arg.find('=') {
                let (key, value) = arg.split_at(eq_pos);
                let value = &value[1..]; // Skip the '='

                match key {
                    "ports" | "p" => {
                        for part in value.split(',') {
                            if let Ok(port) = part.trim().parse::<u16>() {
                                findings.ports.push(port);
                            }
                        }
                    }
                    "cves" | "cve" => {
                        for cve in value.split(',') {
                            let cve = cve.trim().to_string();
                            let desc = format!("{} vulnerability", cve);
                            findings.cves.push((cve, desc));
                        }
                    }
                    "tech" | "t" | "fingerprint" | "fp" => {
                        for tech in value.split(',') {
                            findings.fingerprints.push(tech.trim().to_string());
                        }
                    }
                    "banner" | "b" => {
                        findings.banners.push(value.to_string());
                    }
                    _ => {} // Ignore unknown keys
                }
            }
        };

        // Parse key=value pairs from target and args
        if let Some(ref target) = ctx.target {
            parse_kv(target, &mut findings);
        }
        for arg in &ctx.args {
            parse_kv(arg, &mut findings);
        }

        // Check if any findings were provided
        if findings.ports.is_empty()
            && findings.cves.is_empty()
            && findings.fingerprints.is_empty()
            && findings.banners.is_empty()
        {
            Output::warning("No findings provided. Use flags to specify what to analyze:");
            println!();
            Output::info("  ports=22,80,443        Map open ports");
            Output::info("  cves=CVE-2021-44228    Map CVE IDs");
            Output::info("  tech=wordpress         Map technologies");
            Output::info("  banner=\"Apache/2\"      Map service banner");
            println!();
            Output::info("Example: rb intel mitre coverage ports=22,80,443 tech=wordpress");
            return Ok(());
        }

        // Show what we're analyzing
        Output::section("Input Findings");
        if !findings.ports.is_empty() {
            Output::item(
                "Ports",
                &findings
                    .ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        if !findings.cves.is_empty() {
            Output::item(
                "CVEs",
                &findings
                    .cves
                    .iter()
                    .map(|(id, _)| id.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        if !findings.fingerprints.is_empty() {
            Output::item("Technologies", &findings.fingerprints.join(", "));
        }
        if !findings.banners.is_empty() {
            Output::item("Banners", &findings.banners.join(", "));
        }
        println!();

        // Perform mapping
        Output::spinner_start("Mapping to ATT&CK techniques...");
        let result = mapper.map_findings(&findings);
        Output::spinner_done();

        if result.techniques.is_empty() {
            Output::info("No techniques mapped for these findings.");
            return Ok(());
        }

        // Enterprise ATT&CK tactics in kill chain order
        let tactics_order = [
            ("Reconnaissance", "TA0043"),
            ("Resource Development", "TA0042"),
            ("Initial Access", "TA0001"),
            ("Execution", "TA0002"),
            ("Persistence", "TA0003"),
            ("Privilege Escalation", "TA0004"),
            ("Defense Evasion", "TA0005"),
            ("Credential Access", "TA0006"),
            ("Discovery", "TA0007"),
            ("Lateral Movement", "TA0008"),
            ("Collection", "TA0009"),
            ("Command and Control", "TA0011"),
            ("Exfiltration", "TA0010"),
            ("Impact", "TA0040"),
        ];

        // Calculate coverage
        let total_tactics = tactics_order.len();
        let covered_tactics = result.by_tactic.len();
        let coverage_pct = (covered_tactics as f64 / total_tactics as f64) * 100.0;

        Output::section("Coverage Summary");
        Output::item(
            "Techniques Mapped",
            &result.unique_technique_ids().len().to_string(),
        );
        Output::item(
            "Tactics Covered",
            &format!(
                "{}/{} ({:.0}%)",
                covered_tactics, total_tactics, coverage_pct
            ),
        );
        println!();

        // Display tactic coverage bar chart
        Output::section("Tactic Coverage");
        println!();

        let bar_width = 30;

        for (tactic_name, tactic_id) in &tactics_order {
            let tech_count = result
                .by_tactic
                .get(*tactic_name)
                .map(|v| v.len())
                .unwrap_or(0);

            let (bar, color) = if tech_count > 0 {
                // Calculate bar based on number of techniques (max 10 for full bar)
                let bar_len = (tech_count * bar_width / 10).min(bar_width);
                let bar = "█".repeat(bar_len) + &"░".repeat(bar_width - bar_len);

                let color = if tech_count >= 5 {
                    "\x1b[31m" // Red - high coverage
                } else if tech_count >= 2 {
                    "\x1b[33m" // Yellow - medium coverage
                } else {
                    "\x1b[32m" // Green - low coverage
                };
                (bar, color)
            } else {
                // Not covered - show empty bar in gray
                ("░".repeat(bar_width), "\x1b[90m")
            };

            let status = if tech_count > 0 {
                format!("{:>2} techniques", tech_count)
            } else {
                "Not covered".to_string()
            };

            println!(
                "  {:<22} {:<7} {}{}  {}\x1b[0m",
                tactic_name, tactic_id, color, bar, status
            );
        }

        println!();

        // Show technique details per covered tactic
        Output::section("Technique Details");
        println!();

        for (tactic_name, tactic_id) in &tactics_order {
            if let Some(techs) = result.by_tactic.get(*tactic_name) {
                println!("  \x1b[1m{} ({})\x1b[0m", tactic_name, tactic_id);
                for tech in techs {
                    let conf_badge = match tech.confidence {
                        Confidence::High => "\x1b[32m●\x1b[0m",
                        Confidence::Medium => "\x1b[33m●\x1b[0m",
                        Confidence::Low => "\x1b[90m●\x1b[0m",
                    };
                    println!(
                        "    {} {} - {} (from {})",
                        conf_badge, tech.technique_id, tech.name, tech.original_value
                    );
                }
                println!();
            }
        }

        // Summary recommendations
        Output::section("Assessment");
        if coverage_pct >= 70.0 {
            Output::success("High tactic coverage detected. Multiple attack vectors are possible.");
        } else if coverage_pct >= 40.0 {
            Output::warning("Moderate tactic coverage. Some attack vectors identified.");
        } else {
            Output::info("Low tactic coverage. Limited attack surface mapped.");
        }

        let uncovered: Vec<_> = tactics_order
            .iter()
            .filter(|(name, _)| !result.by_tactic.contains_key(*name))
            .map(|(name, _)| *name)
            .collect();

        if !uncovered.is_empty() && uncovered.len() <= 5 {
            println!();
            Output::info(&format!("Uncovered tactics: {}", uncovered.join(", ")));
        }

        Ok(())
    }

    /// Get mitigations for a technique
    fn get_mitigations(&self, _ctx: &CliContext) -> Result<(), String> {
        Output::info("Mitigations lookup is not yet implemented with the embedded database.");
        Ok(())
    }

    /// Get detection strategies for a technique
    fn get_detection(&self, ctx: &CliContext) -> Result<(), String> {
        let tech_id = ctx.target.as_ref().ok_or("Missing technique ID")?;

        Output::header(&format!("Detection Strategies for {}", tech_id));
        println!();

        Output::spinner_start("Fetching technique data...");
        let db = attack_database::db();
        let tech = db
            .get_technique(tech_id)
            .or_else(|| db.get_technique_by_name(tech_id));
        Output::spinner_done();

        // Clone technique ID before borrowing again
        let _tech_id_owned = tech.as_ref().map(|t| t.technique_id.clone());

        match tech {
            Some(t) => {
                Output::section("Technique");
                Output::item("ID", &t.technique_id);
                Output::item("Name", &t.name);
                println!();

                if !t.data_sources.is_empty() {
                    Output::section("Data Sources");
                    for ds in &t.data_sources {
                        println!("  • {}", ds);
                    }
                    println!();
                }

                if let Some(ref detection) = t.detection {
                    Output::section("Detection Strategy");
                    println!("{}", wrap_text(detection, 80));
                    println!();
                } else {
                    Output::info("No specific detection guidance available.");
                }
            }
            None => {
                Output::warning(&format!("Technique {} not found", tech_id));
            }
        }

        // Show groups using this technique (useful for threat hunting)
        // Note: Reverse lookup (group -> tech) is available, but tech -> group requires iteration
        // We will skip this for now or implement it efficiently later
        /*
        if let Some(tid) = tech_id_owned {
            let groups = client.groups_for_technique(&tid)?;
            if !groups.is_empty() {
                Output::section(&format!("Used by Groups ({})", groups.len()));
                for group in groups.iter().take(10) {
                    println!("  {} - {}", group.id, group.name);
                }
                if groups.len() > 10 {
                    Output::info(&format!("  ... and {} more", groups.len() - 10));
                }
            }
        }
        */

        Ok(())
    }

    /// Show ATT&CK statistics
    fn show_stats(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if !is_json {
            Output::header("MITRE ATT&CK Statistics");
            println!();
            Output::spinner_start("Loading ATT&CK data...");
        }

        let db = attack_database::db();

        if !is_json {
            Output::spinner_done();
        }

        if is_json {
            println!("{{");
            println!("  \"techniques\": {},", db.techniques.len());
            println!("  \"groups\": {},", db.groups.len());
            println!("  \"data_source\": \"Embedded Enterprise ATT&CK Data\"");
            println!("}}");
            return Ok(());
        }

        Output::section("Object Counts");
        Output::item("Techniques", &db.techniques.len().to_string());
        Output::item("Groups", &db.groups.len().to_string());
        println!();

        Output::item("Data Source", "Embedded Enterprise ATT&CK Data");

        Ok(())
    }

    /// Display technique details
    fn display_technique(&self, tech: &AttackTechnique, full: bool) {
        Output::section("Overview");
        Output::item("ID", &tech.technique_id);
        Output::item("Name", &tech.name);
        if let Some(url) = &tech.url {
            Output::item("URL", url);
        }

        if tech.is_subtechnique {
            if let Some(ref parent) = tech.parent_technique {
                Output::item("Parent", parent);
            }
        }

        if !tech.tactics.is_empty() {
            Output::item("Tactics", &tech.tactics.join(", "));
        }

        if !tech.platforms.is_empty() {
            Output::item("Platforms", &tech.platforms.join(", "));
        }

        if tech.deprecated {
            println!();
            Output::warning("This technique is DEPRECATED");
        }

        if tech.revoked {
            println!();
            Output::warning("This technique is REVOKED");
        }

        if full && !tech.description.is_empty() {
            println!();
            Output::section("Description");
            println!("{}", wrap_text(&tech.description, 80));
        }

        if !tech.data_sources.is_empty() {
            println!();
            Output::section("Data Sources");
            for ds in &tech.data_sources {
                println!("  • {}", ds);
            }
        }

        if full {
            if let Some(ref detection) = tech.detection {
                println!();
                Output::section("Detection");
                println!("{}", wrap_text(detection, 80));
            }
        }
    }

    /// Display tactic details
    fn display_tactic(&self, tactic: &Tactic, full: bool) {
        Output::section("Overview");
        Output::item("ID", &tactic.id);
        Output::item("Name", &tactic.name);

        let url = format!("https://attack.mitre.org/tactics/{}/", tactic.id);
        Output::item("URL", &url);

        if full && !tactic.description.is_empty() {
            println!();
            Output::section("Description");
            println!("{}", wrap_text(&tactic.description, 80));
        }
    }

    /// Display group details
    fn display_group(&self, group: &ThreatGroup, full: bool) {
        Output::section("Overview");
        Output::item("ID", &group.group_id);
        Output::item("Name", &group.name);

        if !group.aliases.is_empty() {
            Output::item("Aliases", &group.aliases.join(", "));
        }

        let url = format!("https://attack.mitre.org/groups/{}/", group.group_id);
        Output::item("URL", &url);

        if full && !group.description.is_empty() {
            println!();
            Output::section("Description");
            println!("{}", wrap_text(&group.description, 80));
        }

        if !group.associated_techniques.is_empty() {
            println!();
            Output::section(&format!(
                "Techniques ({})",
                group.associated_techniques.len()
            ));
            for tech in group.associated_techniques.iter().take(15) {
                println!("  • {}", tech);
            }
            if group.associated_techniques.len() > 15 {
                Output::info(&format!(
                    "  ... and {} more",
                    group.associated_techniques.len() - 15
                ));
            }
        }
    }

    /// Display software details
    fn display_software(&self, software: &Software, full: bool) {
        Output::section("Overview");
        Output::item("ID", &software.id);
        Output::item("Name", &software.name);

        let url = format!("https://attack.mitre.org/software/{}/", software.id);
        Output::item("URL", &url);

        if full && !software.description.is_empty() {
            println!();
            Output::section("Description");
            println!("{}", wrap_text(&software.description, 80));
        }
    }

    /// Map findings to MITRE ATT&CK techniques
    fn map_findings(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if !is_json {
            Output::header("MITRE ATT&CK Technique Mapping");
            println!();
        }

        let mapper = TechniqueMapper::new();
        let mut findings = Findings::default();

        // Helper to parse a key=value pair
        let parse_kv = |arg: &str, findings: &mut Findings| {
            if let Some(eq_pos) = arg.find('=') {
                let (key, value) = arg.split_at(eq_pos);
                let value = &value[1..]; // Skip the '='

                match key {
                    "ports" | "p" => {
                        for part in value.split(',') {
                            if let Ok(port) = part.trim().parse::<u16>() {
                                findings.ports.push(port);
                            }
                        }
                    }
                    "cves" | "cve" => {
                        for cve in value.split(',') {
                            let cve = cve.trim().to_string();
                            let desc = format!("{} vulnerability", cve);
                            findings.cves.push((cve, desc));
                        }
                    }
                    "tech" | "t" | "fingerprint" | "fp" => {
                        for tech in value.split(',') {
                            findings.fingerprints.push(tech.trim().to_string());
                        }
                    }
                    "banner" | "b" => {
                        findings.banners.push(value.to_string());
                    }
                    _ => {} // Ignore unknown keys
                }
            }
        };

        // Parse key=value pairs from target (first positional after verb)
        if let Some(ref target) = ctx.target {
            parse_kv(target, &mut findings);
        }

        // Parse key=value pairs from args (remaining positionals)
        for arg in &ctx.args {
            parse_kv(arg, &mut findings);
        }

        // Check if any findings were provided
        if findings.ports.is_empty()
            && findings.cves.is_empty()
            && findings.fingerprints.is_empty()
            && findings.banners.is_empty()
        {
            if is_json {
                println!("{{\"error\": \"No findings provided\", \"techniques\": []}}");
                return Ok(());
            }
            Output::warning("No findings provided. Use flags to specify what to map:");
            println!();
            Output::info("  ports=22,80,443        Map open ports");
            Output::info("  cves=CVE-2021-44228    Map CVE IDs");
            Output::info("  tech=wordpress         Map technologies");
            Output::info("  banner=\"Apache/2\"      Map service banner");
            println!();
            Output::info("Example: rb intel mitre map ports=22,80,443 tech=wordpress");
            return Ok(());
        }

        if !is_json {
            // Show what we're mapping
            Output::section("Input Findings");
            if !findings.ports.is_empty() {
                Output::item(
                    "Ports",
                    &findings
                        .ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            if !findings.cves.is_empty() {
                Output::item(
                    "CVEs",
                    &findings
                        .cves
                        .iter()
                        .map(|(id, _)| id.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            if !findings.fingerprints.is_empty() {
                Output::item("Technologies", &findings.fingerprints.join(", "));
            }
            if !findings.banners.is_empty() {
                Output::item("Banners", &findings.banners.join(", "));
            }
            println!();

            // Perform mapping
            Output::spinner_start("Mapping to ATT&CK techniques...");
        }

        let result = mapper.map_findings(&findings);

        if !is_json {
            Output::spinner_done();
        }

        if is_json {
            println!("{{");
            println!("  \"input\": {{");
            println!(
                "    \"ports\": [{}],",
                findings
                    .ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "    \"cves\": [{}],",
                findings
                    .cves
                    .iter()
                    .map(|(id, _)| format!("\"{}\"", id))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "    \"technologies\": [{}],",
                findings
                    .fingerprints
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "    \"banners\": [{}]",
                findings
                    .banners
                    .iter()
                    .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("  }},");
            println!(
                "  \"unique_technique_ids\": [{}],",
                result
                    .unique_technique_ids()
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("  \"techniques\": [");
            let all_techs: Vec<_> = result.techniques.iter().collect();
            for (i, tech) in all_techs.iter().enumerate() {
                let conf_str = match tech.confidence {
                    Confidence::High => "high",
                    Confidence::Medium => "medium",
                    Confidence::Low => "low",
                };
                let comma = if i < all_techs.len() - 1 { "," } else { "" };
                println!(
                    "    {{\"technique_id\": \"{}\", \"name\": \"{}\", \"tactic\": \"{}\", \"confidence\": \"{}\", \"reason\": \"{}\", \"source\": \"{}\"}}{}",
                    tech.technique_id,
                    tech.name.replace('"', "\\\""),
                    tech.tactic,
                    conf_str,
                    tech.reason.replace('"', "\\\""),
                    tech.original_value.replace('"', "\\\""),
                    comma
                );
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        if result.techniques.is_empty() {
            Output::info("No techniques mapped for these findings.");
            return Ok(());
        }

        // Show results
        Output::success(&format!(
            "Mapped {} techniques across {} tactics",
            result.unique_technique_ids().len(),
            result.by_tactic.len()
        ));
        println!();

        // Show by tactic (kill chain order)
        for (tactic, count, percentage) in &result.coverage {
            if *count == 0 {
                continue;
            }

            Output::section(&format!(
                "{} ({} techniques, {:.0}%)",
                tactic, count, percentage
            ));

            if let Some(techs) = result.by_tactic.get(tactic) {
                for tech in techs {
                    let conf_badge = match tech.confidence {
                        Confidence::High => "\x1b[32m[HIGH]\x1b[0m",
                        Confidence::Medium => "\x1b[33m[MED]\x1b[0m",
                        Confidence::Low => "\x1b[90m[LOW]\x1b[0m",
                    };
                    println!("  {} {} - {}", conf_badge, tech.technique_id, tech.name);
                    println!("      → {} (from {})", tech.reason, tech.original_value);
                }
            }
            println!();
        }

        // Show unique techniques summary
        Output::section("Unique Techniques");
        let unique_ids = result.unique_technique_ids();
        println!("  {}", unique_ids.join(", "));

        Ok(())
    }

    /// Show port-to-technique mapping table
    fn show_port_mappings(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;
        let mapper = TechniqueMapper::new();

        // Check if a specific port was requested
        if let Some(port_str) = ctx.target.as_ref() {
            let port: u16 = port_str
                .parse()
                .map_err(|_| format!("Invalid port number: {}", port_str))?;

            let techniques = mapper.map_port(port);

            if is_json {
                println!("{{");
                println!("  \"port\": {},", port);
                println!("  \"techniques\": [");
                for (i, tech) in techniques.iter().enumerate() {
                    let conf_str = match tech.confidence {
                        Confidence::High => "high",
                        Confidence::Medium => "medium",
                        Confidence::Low => "low",
                    };
                    let comma = if i < techniques.len() - 1 { "," } else { "" };
                    println!(
                        "    {{\"technique_id\": \"{}\", \"name\": \"{}\", \"tactic\": \"{}\", \"confidence\": \"{}\", \"reason\": \"{}\"}}{}",
                        tech.technique_id,
                        tech.name.replace('"', "\\\""),
                        tech.tactic,
                        conf_str,
                        tech.reason.replace('"', "\\\""),
                        comma
                    );
                }
                println!("  ]");
                println!("}}");
                return Ok(());
            }

            Output::header(&format!("ATT&CK Mapping for Port {}", port));
            println!();

            if techniques.is_empty() {
                Output::info(&format!("No ATT&CK mapping for port {}", port));
                return Ok(());
            }

            Output::success(&format!("Found {} mapped techniques", techniques.len()));
            println!();

            for tech in techniques {
                let conf_badge = match tech.confidence {
                    Confidence::High => "\x1b[32m[HIGH]\x1b[0m",
                    Confidence::Medium => "\x1b[33m[MED]\x1b[0m",
                    Confidence::Low => "\x1b[90m[LOW]\x1b[0m",
                };
                Output::section(&format!("{} {}", tech.technique_id, tech.name));
                Output::item("Tactic", &tech.tactic);
                Output::item("Confidence", conf_badge);
                Output::item("Reason", &tech.reason);
                println!();
            }

            return Ok(());
        }

        // Show all mapped ports
        let ports = mapper.mapped_ports();

        // Group by technique for better overview
        let mut by_tactic: std::collections::HashMap<String, Vec<(u16, String, String)>> =
            std::collections::HashMap::new();

        for port in &ports {
            let techs = mapper.map_port(*port);
            for tech in techs {
                by_tactic.entry(tech.tactic.clone()).or_default().push((
                    *port,
                    tech.technique_id,
                    tech.name,
                ));
            }
        }

        let techs = mapper.mapped_technologies();

        if is_json {
            println!("{{");
            println!("  \"total_ports\": {},", ports.len());
            println!(
                "  \"ports\": [{}],",
                ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "  \"technologies\": [{}],",
                techs
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("  \"by_tactic\": {{");
            let tactics_order = [
                "Initial Access",
                "Execution",
                "Persistence",
                "Privilege Escalation",
                "Defense Evasion",
                "Credential Access",
                "Discovery",
                "Lateral Movement",
                "Collection",
                "Command and Control",
                "Exfiltration",
                "Impact",
            ];
            let mut first_tactic = true;
            for tactic in tactics_order {
                if let Some(entries) = by_tactic.get(tactic) {
                    if !first_tactic {
                        println!(",");
                    }
                    first_tactic = false;
                    print!("    \"{}\": [", tactic);
                    for (i, (port, tech_id, name)) in entries.iter().enumerate() {
                        let comma = if i < entries.len() - 1 { ", " } else { "" };
                        print!(
                            "{{\"port\": {}, \"technique_id\": \"{}\", \"name\": \"{}\"}}{}",
                            port,
                            tech_id,
                            name.replace('"', "\\\""),
                            comma
                        );
                    }
                    print!("]");
                }
            }
            println!();
            println!("  }}");
            println!("}}");
            return Ok(());
        }

        Output::header("Port-to-ATT&CK Mapping Table");
        println!();

        Output::success(&format!("{} ports have ATT&CK mappings", ports.len()));
        println!();

        // Print organized by tactic
        let tactics_order = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ];

        for tactic in tactics_order {
            if let Some(entries) = by_tactic.get(tactic) {
                Output::section(tactic);
                for (port, tech_id, name) in entries {
                    println!("  {:>5} → {} {}", port, tech_id, name);
                }
                println!();
            }
        }

        // Show mapped technologies too
        Output::section(&format!("Mapped Technologies ({} total)", techs.len()));
        let mut line = String::new();
        for (i, tech) in techs.iter().enumerate() {
            if i > 0 {
                line.push_str(", ");
            }
            line.push_str(tech);
            if line.len() > 70 {
                println!("  {}", line);
                line.clear();
            }
        }
        if !line.is_empty() {
            println!("  {}", line);
        }

        Ok(())
    }

    /// Export mapped techniques to ATT&CK Navigator layer
    fn export_navigator(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("ATT&CK Navigator Layer Export");
        println!();

        let mapper = TechniqueMapper::new();
        let mut findings = Findings::default();
        let mut output_file: Option<String> = None;
        let mut layer_name = String::from("redblue Findings");

        // Helper to parse a key=value pair
        let parse_kv =
            |arg: &str, findings: &mut Findings, output: &mut Option<String>, name: &mut String| {
                if let Some(eq_pos) = arg.find('=') {
                    let (key, value) = arg.split_at(eq_pos);
                    let value = &value[1..]; // Skip the '='

                    match key {
                        "output" | "o" | "file" => {
                            *output = Some(value.to_string());
                        }
                        "name" | "layer" => {
                            *name = value.to_string();
                        }
                        "ports" | "p" => {
                            for part in value.split(',') {
                                if let Ok(port) = part.trim().parse::<u16>() {
                                    findings.ports.push(port);
                                }
                            }
                        }
                        "cves" | "cve" => {
                            for cve in value.split(',') {
                                let cve = cve.trim().to_string();
                                let desc = format!("{} vulnerability", cve);
                                findings.cves.push((cve, desc));
                            }
                        }
                        "tech" | "t" | "fingerprint" | "fp" => {
                            for tech in value.split(',') {
                                findings.fingerprints.push(tech.trim().to_string());
                            }
                        }
                        "banner" | "b" => {
                            findings.banners.push(value.to_string());
                        }
                        _ => {} // Ignore unknown keys
                    }
                }
            };

        // Parse key=value pairs from target (first positional after verb)
        if let Some(ref target) = ctx.target {
            parse_kv(target, &mut findings, &mut output_file, &mut layer_name);
        }

        // Parse key=value pairs from args (remaining positionals)
        for arg in &ctx.args {
            parse_kv(arg, &mut findings, &mut output_file, &mut layer_name);
        }

        // Check if any findings were provided
        if findings.ports.is_empty()
            && findings.cves.is_empty()
            && findings.fingerprints.is_empty()
            && findings.banners.is_empty()
        {
            Output::warning("No findings provided. Use flags to specify what to export:");
            println!();
            Output::info("  output=file.json       Output file path (required)");
            Output::info("  name=\"Layer Name\"      Layer name (optional)");
            Output::info("  ports=22,80,443        Map open ports");
            Output::info("  cves=CVE-2021-44228    Map CVE IDs");
            Output::info("  tech=wordpress         Map technologies");
            Output::info("  banner=\"Apache/2\"      Map service banner");
            println!();
            Output::info("Example: rb intel mitre export output=findings.json ports=22,80,443 tech=wordpress");
            return Ok(());
        }

        // Default output file
        let output_path = output_file.unwrap_or_else(|| "attack-layer.json".to_string());

        // Show what we're mapping
        Output::section("Input Findings");
        if !findings.ports.is_empty() {
            Output::item(
                "Ports",
                &findings
                    .ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        if !findings.cves.is_empty() {
            Output::item(
                "CVEs",
                &findings
                    .cves
                    .iter()
                    .map(|(id, _)| id.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        if !findings.fingerprints.is_empty() {
            Output::item("Technologies", &findings.fingerprints.join(", "));
        }
        if !findings.banners.is_empty() {
            Output::item("Banners", &findings.banners.join(", "));
        }
        println!();

        // Perform mapping
        Output::spinner_start("Mapping to ATT&CK techniques...");
        let result = mapper.map_findings(&findings);
        Output::spinner_done();

        if result.techniques.is_empty() {
            Output::info("No techniques mapped for these findings. Nothing to export.");
            return Ok(());
        }

        Output::success(&format!(
            "Mapped {} techniques across {} tactics",
            result.unique_technique_ids().len(),
            result.by_tactic.len()
        ));
        println!();

        // Create Navigator layer
        Output::spinner_start("Generating Navigator layer...");
        let layer = NavigatorLayer::from_mapping_result(&result, &layer_name, "target");
        Output::spinner_done();

        // Export to file
        Output::spinner_start(&format!("Writing to {}...", output_path));
        layer.to_file(&output_path)?;
        Output::spinner_done();

        // Show summary
        Output::section("Export Summary");
        Output::item("Output File", &output_path);
        Output::item("Layer Name", &layer_name);
        Output::item("Techniques", &layer.techniques.len().to_string());
        Output::item("Format", "ATT&CK Navigator v4.4");
        println!();

        Output::success("Layer exported successfully!");
        println!();
        Output::info("Import the layer at: https://mitre-attack.github.io/attack-navigator/");

        Ok(())
    }
}

/// Wrap text to specified width
fn wrap_text(s: &str, width: usize) -> String {
    let mut result = String::new();
    let mut current_line = String::new();

    for word in s.split_whitespace() {
        if current_line.len() + word.len() + 1 > width {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&current_line);
            current_line = word.to_string();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
    }

    if !current_line.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&current_line);
    }

    result
}
