//! Mapping commands for MITRE ATT&CK
//!
//! Map findings (ports, CVEs, technologies) to ATT&CK techniques.

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::intel::{Confidence, Findings, TechniqueMapper};
use crate::modules::recon::mitre::{CorrelationEngine, MitreClient};
use crate::serde_json::Value;

/// Map findings to MITRE ATT&CK techniques
pub fn map_findings(ctx: &CliContext) -> Result<(), String> {
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
            let value = &value[1..];

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
                _ => {}
            }
        }
    };

    if let Some(ref target) = ctx.target {
        parse_kv(target, &mut findings);
    }
    for arg in &ctx.args {
        parse_kv(arg, &mut findings);
    }

    if findings.ports.is_empty()
        && findings.cves.is_empty()
        && findings.fingerprints.is_empty()
        && findings.banners.is_empty()
    {
        if is_json {
            Output::json_value(&json!({
                "error": "No findings provided",
                "techniques": [],
            }));
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

        Output::spinner_start("Mapping to ATT&CK techniques...");
    }

    let result = mapper.map_findings(&findings);

    if !is_json {
        Output::spinner_done();
    }

    if is_json {
        let techniques_json: Vec<_> = result
            .techniques
            .iter()
            .map(|tech| {
                json!({
                    "technique_id": tech.technique_id.clone(),
                    "name": tech.name.clone(),
                    "tactic": tech.tactic.clone(),
                    "confidence": confidence_label(tech.confidence),
                    "reason": tech.reason.clone(),
                    "source": tech.original_value.clone(),
                })
            })
            .collect();
        let input_json = json!({
            "ports": findings.ports.clone(),
            "cves": findings
                .cves
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>(),
            "technologies": findings.fingerprints.clone(),
            "banners": findings.banners.clone(),
        });
        Output::json_value(&json!({
            "input": input_json,
            "unique_technique_ids": result.unique_technique_ids(),
            "techniques": techniques_json,
        }));
        return Ok(());
    }

    if result.techniques.is_empty() {
        Output::info("No techniques mapped for these findings.");
        return Ok(());
    }

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
pub fn show_port_mappings(ctx: &CliContext) -> Result<(), String> {
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
            let techniques_json: Vec<_> = techniques
                .iter()
                .map(|tech| {
                    json!({
                        "technique_id": tech.technique_id.clone(),
                        "name": tech.name.clone(),
                        "tactic": tech.tactic.clone(),
                        "confidence": confidence_label(tech.confidence),
                        "reason": tech.reason.clone(),
                    })
                })
                .collect();
            Output::json_value(&json!({
                "port": port,
                "techniques": techniques_json,
            }));
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
        let mut by_tactic_fields = Vec::new();
        for tactic in tactics_order {
            if let Some(entries) = by_tactic.get(tactic) {
                let entries_json: Vec<_> = entries
                    .iter()
                    .map(|(port, tech_id, name)| {
                        json!({
                            "port": *port,
                            "technique_id": tech_id.clone(),
                            "name": name.clone(),
                        })
                    })
                    .collect();
                by_tactic_fields.push((tactic.to_string(), json!(entries_json)));
            }
        }
        let by_tactic_json = Value::Object(by_tactic_fields.into_iter().collect());
        Output::json_value(&json!({
            "total_ports": ports.len(),
            "ports": ports.clone(),
            "technologies": techs.clone(),
            "by_tactic": by_tactic_json,
        }));
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

/// Correlate a finding text to MITRE ATT&CK techniques
pub fn correlate_finding(ctx: &CliContext) -> Result<(), String> {
    let finding = ctx
        .target
        .as_ref()
        .ok_or("Missing finding text to correlate")?;

    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    if !is_json {
        Output::header("MITRE ATT&CK Finding Correlation");
        println!();
        Output::spinner_start("Fetching ATT&CK data from STIX...");
    }

    // Fetch STIX data (respecting --refresh flag)
    let mut client = MitreClient::new();
    let attack_data = if ctx.has_flag("refresh") {
        client.fetch_fresh()
    } else {
        client.fetch()
    }
    .map_err(|e| format!("Failed to fetch ATT&CK data: {}", e))?;

    if !is_json {
        Output::spinner_done();
        Output::spinner_start("Correlating finding...");
    }

    // Create correlation engine and run correlation
    let engine = CorrelationEngine::new(&attack_data);
    let result = engine.correlate(finding);

    if !is_json {
        Output::spinner_done();
    }

    if is_json {
        let matches_json: Vec<_> = result
            .matches
            .iter()
            .map(|m| {
                json!({
                    "technique_id": m.technique_id.clone(),
                    "technique_name": m.technique_name.clone(),
                    "confidence": m.confidence,
                    "match_type": m.match_type.as_str(),
                    "reason": m.reason.clone(),
                    "tactics": m.tactics.clone(),
                })
            })
            .collect();
        Output::json_value(&json!({
            "finding": finding,
            "match_count": result.matches.len(),
            "matches": matches_json,
        }));
        return Ok(());
    }

    // Display results
    Output::section("Finding");
    println!("  {}", finding);
    println!();

    if result.matches.is_empty() {
        Output::info("No MITRE ATT&CK techniques matched for this finding.");
        Output::info(
            "Try a finding containing tool names (mimikatz, cobalt strike) or attack keywords.",
        );
        return Ok(());
    }

    Output::success(&format!("Matched {} techniques", result.matches.len()));
    println!();

    Output::section("Matched Techniques");
    for m in &result.matches {
        let conf_color = if m.confidence >= 80 {
            "\x1b[32m"
        } else if m.confidence >= 50 {
            "\x1b[33m"
        } else {
            "\x1b[90m"
        };

        println!(
            "  {}[{:>3}%]\x1b[0m {} - {}",
            conf_color, m.confidence, m.technique_id, m.technique_name
        );
        println!("         Match: {} ({})", m.match_type.as_str(), m.reason);
        if !m.tactics.is_empty() {
            println!("         Tactics: {}", m.tactics.join(", "));
        }
        println!();
    }

    // Show unique tactics
    let mut unique_tactics: Vec<String> = result
        .matches
        .iter()
        .flat_map(|m| m.tactics.iter().cloned())
        .collect();
    unique_tactics.sort();
    unique_tactics.dedup();

    if !unique_tactics.is_empty() {
        Output::section("Affected Tactics");
        for tactic in &unique_tactics {
            println!("  • {}", tactic);
        }
    }

    Ok(())
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}
