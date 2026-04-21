//! Vulnerability Intelligence Command
//!
//! Search and analyze vulnerabilities from multiple sources:
//! - NVD (National Vulnerability Database)
//! - OSV (Open Source Vulnerabilities)
//! - CISA KEV (Known Exploited Vulnerabilities)
//! - Exploit-DB

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::serde_json::Value;
use crate::modules::recon::fingerprint::FingerprintEngine;
use crate::modules::recon::vuln::{
    correlator::{CorrelatorConfig, CorrelationReport, VulnCorrelator},
    cpe::{generate_cpe, get_all_cpe_mappings, TechCategory},
    exploitdb::ExploitDbClient,
    kev::KevClient,
    nvd::NvdClient,
    osv::{Ecosystem, OsvClient},
    risk::{calculate_risk_score, RiskLevel},
    types::{DetectedTech, Severity, VulnCollection, Vulnerability},
};

pub struct VulnCommand;

impl Command for VulnCommand {
    fn domain(&self) -> &str {
        "vuln"
    }

    fn resource(&self) -> &str {
        "intel"
    }

    fn description(&self) -> &str {
        "Vulnerability intelligence - search CVEs, check exploits, assess risk"
    }

    fn metadata(&self) -> crate::cli::schema::CommandMetadata {
        crate::cli::schema::CommandMetadata::new().with_machine_output(
            crate::cli::schema::MachineOutputMetadata::new()
                .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
                .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
                .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
        )
    }

    fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
        let json_support = match verb {
            "search" | "cve" | "kev" | "exploit" | "cpe" | "correlate" | "scan" | "report" => {
                crate::cli::schema::JsonSupport::Guaranteed
            }
            _ => crate::cli::schema::JsonSupport::BestEffort,
        };

        crate::cli::schema::RouteMetadata::new().with_machine_output(
            crate::cli::schema::MachineOutputMetadata::new()
                .with_json_support(json_support)
                .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
                .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
        )
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "search",
                summary: "Search vulnerabilities by technology/product name",
                usage: "rb vuln intel search <tech> [version] [--source nvd|osv|all]",
            },
            Route {
                verb: "cve",
                summary: "Get detailed information about a specific CVE",
                usage: "rb vuln intel cve <CVE-ID>",
            },
            Route {
                verb: "kev",
                summary: "Check CISA Known Exploited Vulnerabilities catalog",
                usage: "rb vuln intel kev [--vendor <name>] [--product <name>] [--stats]",
            },
            Route {
                verb: "exploit",
                summary: "Search Exploit-DB for exploits",
                usage: "rb vuln intel exploit <query>",
            },
            Route {
                verb: "cpe",
                summary: "List supported CPE mappings for technologies",
                usage: "rb vuln intel cpe [--category <cat>] [--search <term>]",
            },
            Route {
                verb: "correlate",
                summary: "Correlate detected technologies with vulnerabilities",
                usage: "rb vuln intel correlate <url> [--sources all|nvd|osv|kev]",
            },
            Route {
                verb: "scan",
                summary: "Full vulnerability scan (fingerprint + correlate)",
                usage: "rb vuln intel scan <url> [--deep] [--json]",
            },
            Route {
                verb: "report",
                summary: "Generate vulnerability report for target",
                usage: "rb vuln intel report <url> [--format text|json|markdown]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("source", "Vulnerability source (nvd, osv, kev, exploitdb, all)")
                .with_short('s')
                .with_default("nvd"),
            Flag::new("version", "Specific version to check").with_short('v'),
            Flag::new("ecosystem", "Package ecosystem for OSV (npm, pypi, cargo, etc.)"),
            Flag::new("vendor", "Filter by vendor name"),
            Flag::new("product", "Filter by product name"),
            Flag::new("category", "CPE category filter (webserver, framework, cms, etc.)"),
            Flag::new("search", "Search term for CPE lookup"),
            Flag::new("stats", "Show statistics"),
            Flag::new("limit", "Maximum results to show").with_default("20"),
            Flag::new("api-key", "NVD API key for higher rate limits"),
            Flag::new("deep", "Deep scan (all sources, slower)"),
            Flag::new("json", "Output in JSON format"),
            Flag::new("format", "Output format (text, json, markdown)").with_default("text"),
            Flag::new("sources", "Vulnerability sources (nvd,osv,kev,exploitdb)").with_default("all"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Search vulnerabilities for nginx", "rb vuln intel search nginx"),
            ("Search with version", "rb vuln intel search nginx 1.18.0"),
            ("Get CVE details", "rb vuln intel cve CVE-2021-44228"),
            ("Check CISA KEV stats", "rb vuln intel kev --stats"),
            ("KEV by vendor", "rb vuln intel kev --vendor Microsoft"),
            ("Search Exploit-DB", "rb vuln intel exploit \"Apache Struts\""),
            ("List CPE mappings", "rb vuln intel cpe"),
            ("CPE by category", "rb vuln intel cpe --category webserver"),
            ("OSV package search", "rb vuln intel search lodash --source osv --ecosystem npm"),
            ("Correlate URL techs", "rb vuln intel correlate https://example.com"),
            ("Full vuln scan", "rb vuln intel scan https://target.com --deep"),
            ("Generate report", "rb vuln intel report https://target.com --format markdown"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "search" => self.search_vulns(ctx),
            "cve" => self.get_cve(ctx),
            "kev" => self.check_kev(ctx),
            "exploit" => self.search_exploits(ctx),
            "cpe" => self.list_cpe(ctx),
            "correlate" => self.correlate_techs(ctx),
            "scan" => self.vuln_scan(ctx),
            "report" => self.vuln_report(ctx),
            _ => {
                print_help(self);
                Err(format!("Unknown verb: {}", verb))
            }
        }
    }
}

