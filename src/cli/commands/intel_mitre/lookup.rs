//! Lookup commands for MITRE ATT&CK objects
//!
//! Query techniques, tactics, groups, and software.

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::intel::attack_database;

use super::display;

/// Get technique details
pub fn get_technique(ctx: &CliContext) -> Result<(), String> {
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
        Some(t) => display::display_technique(t, ctx.has_flag("full")),
        None => {
            Output::warning(&format!("Technique {} not found", tech_id));
            Output::info("Try searching: rb intel mitre search <query>");
        }
    }

    Ok(())
}

/// Get tactic details
pub fn get_tactic(_ctx: &CliContext) -> Result<(), String> {
    Output::info("Tactic lookup is not yet implemented with the embedded database.");
    Ok(())
}

/// Get threat group details
pub fn get_group(ctx: &CliContext) -> Result<(), String> {
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
        Some(g) => display::display_group(g, ctx.has_flag("full")),
        None => {
            Output::warning(&format!("Group {} not found", group_id));
            Output::info("Try searching: rb intel mitre search <query>");
        }
    }

    Ok(())
}

/// Get software details
pub fn get_software(_ctx: &CliContext) -> Result<(), String> {
    Output::info("Software lookup is not yet implemented with the embedded database.");
    Ok(())
}

/// Search ATT&CK
pub fn search(ctx: &CliContext) -> Result<(), String> {
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
