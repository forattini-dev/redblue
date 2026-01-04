//! MITRE ATT&CK Intelligence Command
//!
//! Query MITRE ATT&CK framework data:
//! - Techniques (T1059, T1059.001)
//! - Tactics (TA0001)
//! - Threat Groups (G0016, APT29)
//! - Software (S0154, Cobalt Strike)
//! - Mitigations (M1036)

mod cache;
mod display;
mod export;
mod gaps;
mod helpers;
mod lookup;
mod mapping;
mod matrix;

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::CliContext;

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
            Route {
                verb: "correlate",
                summary: "Correlate a finding text to ATT&CK techniques (tool/keyword matching)",
                usage: "rb intel mitre correlate <finding_text>",
            },
            Route {
                verb: "gaps",
                summary: "Analyze detection coverage gaps based on data sources",
                usage: "rb intel mitre gaps [--platform windows] [--priority critical]",
            },
            Route {
                verb: "navigator",
                summary: "Generate Navigator layer for a threat group or tactic",
                usage: "rb intel mitre navigator --group APT29 | --tactic execution [--output layer.json]",
            },
            Route {
                verb: "cache",
                summary: "Show cache status or clear the cache",
                usage: "rb intel mitre cache [--clear]",
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
            Flag::new("group", "Threat group for Navigator layer (e.g., APT29)").with_short('g'),
            Flag::new("tactic", "Tactic for Navigator layer (e.g., execution)"),
            Flag::new(
                "platform",
                "Platform filter for gap analysis (e.g., windows, linux)",
            ),
            Flag::new(
                "priority",
                "Gap priority filter (critical, high, medium, low)",
            ),
            Flag::new(
                "data-sources",
                "Comma-separated list of available data sources",
            ),
            Flag::new("refresh", "Force fresh download from GitHub (bypass cache)").with_short('r'),
            Flag::new("clear", "Clear the ATT&CK cache"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Get technique details", "rb intel mitre technique T1059"),
            ("Get sub-technique", "rb intel mitre technique T1059.001"),
            ("Get tactic by name", "rb intel mitre tactic execution"),
            ("Get threat group", "rb intel mitre group APT29"),
            (
                "Get software/tool",
                "rb intel mitre software \"Cobalt Strike\"",
            ),
            ("Search ATT&CK", "rb intel mitre search lateral"),
            ("Show matrix overview", "rb intel mitre matrix"),
            (
                "Show tactic coverage",
                "rb intel mitre coverage ports=22,80,443 tech=wordpress",
            ),
            ("Get mitigations", "rb intel mitre mitigations T1059"),
            ("Get detection info", "rb intel mitre detection T1059.001"),
            ("Show statistics", "rb intel mitre stats"),
            (
                "Map ports to techniques",
                "rb intel mitre map ports=22,80,443,3389",
            ),
            (
                "Map CVE to techniques",
                "rb intel mitre map cves=CVE-2021-44228",
            ),
            ("Map technology", "rb intel mitre map tech=wordpress,nginx"),
            (
                "Combined mapping",
                "rb intel mitre map ports=22,80 tech=wordpress",
            ),
            ("Show port mappings", "rb intel mitre ports"),
            ("Query specific port", "rb intel mitre ports 22"),
            (
                "Export to Navigator layer",
                "rb intel mitre export output=findings.json ports=22,80,443",
            ),
            (
                "Export with all findings",
                "rb intel mitre export output=report.json ports=22 cves=CVE-2021-44228 tech=wordpress",
            ),
            (
                "Correlate finding text",
                "rb intel mitre correlate \"Detected mimikatz.exe execution\"",
            ),
            (
                "Correlate tool detection",
                "rb intel mitre correlate \"PowerShell encoded command execution\"",
            ),
            ("Show coverage gaps", "rb intel mitre gaps"),
            (
                "Show Windows gaps only",
                "rb intel mitre gaps --platform windows",
            ),
            ("Show critical gaps", "rb intel mitre gaps --priority critical"),
            (
                "Navigator for APT29",
                "rb intel mitre navigator --group APT29 --output apt29.json",
            ),
            (
                "Navigator for execution",
                "rb intel mitre navigator --tactic execution",
            ),
            ("Show cache status", "rb intel mitre cache"),
            ("Clear ATT&CK cache", "rb intel mitre cache --clear"),
            ("Force refresh data", "rb intel mitre stats --refresh"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            // Lookup
            "technique" => lookup::get_technique(ctx),
            "tactic" => lookup::get_tactic(ctx),
            "group" => lookup::get_group(ctx),
            "software" => lookup::get_software(ctx),
            "search" => lookup::search(ctx),

            // Matrix and stats
            "matrix" => matrix::show_matrix(ctx),
            "coverage" => matrix::show_coverage(ctx),
            "mitigations" => matrix::get_mitigations(ctx),
            "detection" => matrix::get_detection(ctx),
            "stats" => matrix::show_stats(ctx),

            // Mapping
            "map" => mapping::map_findings(ctx),
            "ports" => mapping::show_port_mappings(ctx),
            "correlate" => mapping::correlate_finding(ctx),

            // Export
            "export" => export::export_navigator(ctx),
            "navigator" => export::generate_navigator(ctx),

            // Gap analysis
            "gaps" => gaps::show_gaps(ctx),

            // Cache
            "cache" => cache::manage_cache(ctx),

            _ => {
                print_help(self);
                Err(format!("Unknown verb: {}", verb))
            }
        }
    }
}
