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

impl VulnCommand {
    /// Search vulnerabilities by technology name
    fn search_vulns(&self, ctx: &CliContext) -> Result<(), String> {
        let tech = ctx.target.as_ref().ok_or("Missing technology name")?;
        let version = ctx.get_flag_with_config("version").or_else(|| {
            // Check if version is provided as second positional arg
            ctx.args.get(4).cloned()
        });
        let source = ctx.get_flag_or("source", "nvd");
        let limit: usize = ctx.get_flag_with_config("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);
        let format = ctx.get_flag_or("format", "text");
        let is_json = format == "json" || ctx.has_flag("json");

        if !is_json {
            Output::header(&format!("Vulnerability Search: {}", tech));
            if let Some(ref ver) = version {
                Output::item("Version", ver);
            }
            Output::item("Source", &source);
            println!();
        }

        let mut collection = VulnCollection::new();

        match source.as_str() {
            "nvd" | "all" => {
                Output::spinner_start("Querying NVD...");

                // Generate CPE for this technology
                if let Some(cpe) = generate_cpe(tech, version.as_deref()) {
                    let mut nvd = NvdClient::new();
                    if let Some(api_key) = ctx.get_flag_with_config("api-key") {
                        nvd = nvd.with_api_key(&api_key);
                    }

                    match nvd.query_by_cpe(&cpe) {
                        Ok(vulns) => {
                            Output::spinner_done();
                            Output::success(&format!("Found {} vulnerabilities from NVD", vulns.len()));
                            for vuln in vulns {
                                collection.add(vuln);
                            }
                        }
                        Err(e) => {
                            Output::spinner_done();
                            Output::warning(&format!("NVD query failed: {}", e));
                        }
                    }
                } else {
                    Output::spinner_done();
                    Output::warning(&format!("No CPE mapping found for '{}'. Trying keyword search...", tech));

                    // Fallback to keyword search
                    let mut nvd = NvdClient::new();
                    if let Some(api_key) = ctx.get_flag_with_config("api-key") {
                        nvd = nvd.with_api_key(&api_key);
                    }

                    let keyword = if let Some(ref ver) = version {
                        format!("{} {}", tech, ver)
                    } else {
                        tech.clone()
                    };

                    match nvd.query_by_keyword(&keyword) {
                        Ok(vulns) => {
                            Output::success(&format!("Found {} vulnerabilities from NVD", vulns.len()));
                            for vuln in vulns {
                                collection.add(vuln);
                            }
                        }
                        Err(e) => {
                            Output::warning(&format!("NVD keyword search failed: {}", e));
                        }
                    }
                }
            }
            _ => {}
        }

        match source.as_str() {
            "osv" | "all" => {
                Output::spinner_start("Querying OSV...");

                let ecosystem = ctx.get_flag_with_config("ecosystem")
                    .and_then(|e| parse_ecosystem(&e));

                if let Some(eco) = ecosystem {
                    let osv = OsvClient::new();
                    match osv.query_package(tech, version.as_deref(), eco) {
                        Ok(vulns) => {
                            Output::spinner_done();
                            Output::success(&format!("Found {} vulnerabilities from OSV", vulns.len()));
                            for vuln in vulns {
                                collection.add(vuln);
                            }
                        }
                        Err(e) => {
                            Output::spinner_done();
                            Output::warning(&format!("OSV query failed: {}", e));
                        }
                    }
                } else {
                    Output::spinner_done();
                    if source == "osv" {
                        Output::warning("OSV requires --ecosystem flag (npm, pypi, cargo, etc.)");
                    }
                }
            }
            _ => {}
        }

        // Enrich with CISA KEV
        if !collection.is_empty() {
            Output::spinner_start("Checking CISA KEV...");
            let mut kev = KevClient::new();
            for vuln in collection.iter_mut() {
                let _ = kev.enrich_vulnerability(vuln);
            }
            Output::spinner_done();
        }

        // Calculate risk scores
        for vuln in collection.iter_mut() {
            vuln.risk_score = Some(calculate_risk_score(vuln));
        }

        // Sort by risk score (highest first)
        let mut vulns: Vec<_> = collection.into_iter().collect();
        vulns.sort_by(|a, b| {
            b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0))
        });

        // Display results
        if vulns.is_empty() {
            let payload = vuln_search_payload(tech, version.as_ref(), &source, &vulns, limit);
            if render::render_machine_output(ctx, "rb vuln intel search", &payload)? {
                return Ok(());
            } else {
                println!();
                Output::info("No vulnerabilities found.");
            }
            return Ok(());
        }

        if is_json {
            let payload = vuln_search_payload(tech, version.as_ref(), &source, &vulns, limit);
            render::render_machine_output(ctx, "rb vuln intel search", &payload)?;
            return Ok(());
        }

        println!();
        Output::header(&format!("Results ({} total, showing top {})", vulns.len(), limit.min(vulns.len())));
        println!();

        for vuln in vulns.iter().take(limit) {
            self.display_vuln_summary(vuln);
        }

        Ok(())
    }

    /// Get detailed CVE information
    fn get_cve(&self, ctx: &CliContext) -> Result<(), String> {
        let cve_id = ctx.target.as_ref().ok_or("Missing CVE ID")?;
        let format = ctx.get_flag_or("format", "text");
        let is_json = format == "json" || ctx.has_flag("json");

        // Validate CVE format
        if !cve_id.to_uppercase().starts_with("CVE-") {
            return Err(format!("Invalid CVE ID format: {}. Expected: CVE-YYYY-NNNNN", cve_id));
        }

        if !is_json {
            Output::header(&format!("CVE Details: {}", cve_id));
            println!();
            Output::spinner_start("Querying NVD...");
        }

        // Query NVD
        let mut nvd = NvdClient::new();
        if let Some(api_key) = ctx.get_flag_with_config("api-key") {
            nvd = nvd.with_api_key(&api_key);
        }

        let vuln = match nvd.query_by_cve(cve_id)? {
            Some(v) => v,
            None => {
                let payload = cve_not_found_payload(cve_id);
                if render::render_machine_output(ctx, "rb vuln intel cve", &payload)? {
                    return Ok(());
                }
                if !is_json {
                    Output::spinner_done();
                    Output::warning(&format!("CVE {} not found in NVD", cve_id));
                }
                return Ok(());
            }
        };
        if !is_json {
            Output::spinner_done();
        }

        // Enrich with KEV
        let mut vuln = vuln;
        let mut kev = KevClient::new();
        let _ = kev.enrich_vulnerability(&mut vuln);

        // Enrich with Exploit-DB
        if !is_json {
            Output::spinner_start("Checking Exploit-DB...");
        }
        let exploitdb = ExploitDbClient::new();
        let _ = exploitdb.enrich_vulnerability(&mut vuln);
        if !is_json {
            Output::spinner_done();
        }

        // Calculate risk score
        vuln.risk_score = Some(calculate_risk_score(&vuln));

        // Output
        if is_json {
            let payload = vuln_detail_payload(&vuln);
            render::render_machine_output(ctx, "rb vuln intel cve", &payload)?;
            return Ok(());
        }

        // Display detailed info
        self.display_vuln_detail(&vuln);

        Ok(())
    }

    /// Check CISA KEV catalog
    fn check_kev(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json" || ctx.has_flag("json");

        let vendor = ctx.get_flag_with_config("vendor");
        let product = ctx.get_flag_with_config("product");
        let show_stats = ctx.has_flag("stats");
        let limit: usize = ctx.get_flag_with_config("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        if !is_json {
            Output::header("CISA Known Exploited Vulnerabilities");
            println!();
        }

        let mut kev = KevClient::new();

        if !is_json {
            Output::spinner_start("Fetching KEV catalog...");
        }
        kev.fetch_catalog()?;
        if !is_json {
            Output::spinner_done();
        }

        if show_stats {
            let stats = kev.stats()?;

            if is_json {
                let payload = kev_stats_payload(&stats);
                render::render_machine_output(ctx, "rb vuln intel kev", &payload)?;
                return Ok(());
            }

            Output::section("Catalog Statistics");
            Output::item("Total CVEs", &stats.total.to_string());
            Output::item("Used in Ransomware", &stats.ransomware_count.to_string());
            println!();

            Output::section("Top Vendors");
            for (vendor, count) in stats.top_vendors.iter().take(10) {
                Output::item(vendor, &count.to_string());
            }
            println!();
            return Ok(());
        }

        let entries = if let Some(ref v) = vendor {
            kev.get_by_vendor(v)?
        } else if let Some(ref p) = product {
            kev.get_by_product(p)?
        } else {
            kev.get_all()?
        };

        if is_json {
            let payload = kev_entries_payload(vendor.as_ref(), product.as_ref(), &entries, limit);
            render::render_machine_output(ctx, "rb vuln intel kev", &payload)?;
            return Ok(());
        }

        Output::success(&format!("Found {} KEV entries", entries.len()));
        println!();

        for entry in entries.iter().take(limit) {
            Output::section(&entry.cve_id);
            Output::item("Title", &entry.vulnerability_name);
            Output::item("Vendor", &entry.vendor_project);
            Output::item("Product", &entry.product);
            Output::item("Date Added", &entry.date_added);
            Output::item("Due Date", &entry.due_date);
            if entry.known_ransomware_use {
                Output::warning("  Known ransomware use!");
            }
            println!();
        }

        Ok(())
    }

    /// Search Exploit-DB
    fn search_exploits(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json" || ctx.has_flag("json");

        let query = ctx.target.as_ref().ok_or("Missing search query")?;
        let limit: usize = ctx.get_flag_with_config("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        if !is_json {
            Output::header(&format!("Exploit-DB Search: {}", query));
            println!();
            Output::spinner_start("Searching Exploit-DB...");
        }

        let client = ExploitDbClient::new();
        let results = client.search(query)?;

        if !is_json {
            Output::spinner_done();
        }

        if results.is_empty() {
            if is_json {
                let payload = exploit_search_payload(query, &results, limit);
                render::render_machine_output(ctx, "rb vuln intel exploit", &payload)?;
                return Ok(());
            }
            Output::info("No exploits found.");
            return Ok(());
        }

        if is_json {
            let payload = exploit_search_payload(query, &results, limit);
            render::render_machine_output(ctx, "rb vuln intel exploit", &payload)?;
            return Ok(());
        }

        Output::success(&format!("Found {} exploits", results.len()));
        println!();

        for entry in results.iter().take(limit) {
            Output::section(&format!("EDB-{}", entry.id));
            Output::item("Title", &entry.title);
            if let Some(ref platform) = entry.platform {
                Output::item("Platform", platform);
            }
            if let Some(ref etype) = entry.exploit_type {
                Output::item("Type", etype);
            }
            if let Some(ref date) = entry.date {
                Output::item("Date", date);
            }
            if !entry.cve_ids.is_empty() {
                Output::item("CVEs", &entry.cve_ids.join(", "));
            }
            if entry.verified {
                Output::success("  Verified by Exploit-DB");
            }
            println!();
        }

        Ok(())
    }

    /// List CPE mappings
    fn list_cpe(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json" || ctx.has_flag("json");

        let category = ctx.get_flag_with_config("category");
        let search = ctx.get_flag_with_config("search");

        if !is_json {
            Output::header("CPE Technology Mappings");
            println!();
        }

        let all_cpes = get_all_cpe_mappings();

        let filtered: Vec<_> = all_cpes.iter()
            .filter(|cpe| {
                // Filter by category
                if let Some(ref cat) = category {
                    let cat_match = match cat.to_lowercase().as_str() {
                        "webserver" | "web" => cpe.category == TechCategory::WebServer,
                        "proxy" => cpe.category == TechCategory::Proxy,
                        "cdn" => cpe.category == TechCategory::Cdn,
                        "framework" => cpe.category == TechCategory::Framework,
                        "runtime" => cpe.category == TechCategory::Runtime,
                        "cms" => cpe.category == TechCategory::Cms,
                        "js" | "javascript" => cpe.category == TechCategory::JsLibrary,
                        "database" | "db" => cpe.category == TechCategory::Database,
                        "os" | "operating" => cpe.category == TechCategory::OperatingSystem,
                        _ => true,
                    };
                    if !cat_match {
                        return false;
                    }
                }

                // Filter by search term
                if let Some(ref term) = search {
                    let term_lower = term.to_lowercase();
                    if !cpe.tech_name.to_lowercase().contains(&term_lower)
                        && !cpe.product.to_lowercase().contains(&term_lower)
                        && !cpe.vendor.to_lowercase().contains(&term_lower)
                    {
                        return false;
                    }
                }

                true
            })
            .collect();

        if is_json {
            let payload = cpe_mappings_payload(category.as_ref(), search.as_ref(), &filtered);
            render::render_machine_output(ctx, "rb vuln intel cpe", &payload)?;
            return Ok(());
        }

        Output::info(&format!("Showing {} CPE mappings", filtered.len()));
        println!();

        // Group by category
        let mut by_category: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
        for cpe in filtered {
            let cat_name = format!("{:?}", cpe.category);
            by_category.entry(cat_name).or_default().push(cpe);
        }

        for (category, cpes) in by_category {
            Output::section(&category);
            for cpe in cpes {
                let example_cpe = generate_cpe(cpe.tech_name, Some("1.0")).unwrap_or_default();
                Output::item(cpe.tech_name, &format!("{} ({})", cpe.product, example_cpe));
            }
            println!();
        }

        Ok(())
    }

    /// Display vulnerability summary (one line per vuln)
    fn display_vuln_summary(&self, vuln: &Vulnerability) {
        let risk = vuln.risk_score.unwrap_or(0);
        let level = RiskLevel::from_score(risk);
        let color = level.color_code();
        let reset = "\x1b[0m";

        let severity_str = match vuln.severity {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Low => "LOW ",
            Severity::Info => "INFO",
        };

        let kev_marker = if vuln.cisa_kev { " [KEV]" } else { "" };
        let exploit_marker = if vuln.has_exploit() { " [EXP]" } else { "" };

        println!(
            "{}[{:3}]{} {} {} - {}{}{}",
            color,
            risk,
            reset,
            severity_str,
            vuln.id,
            truncate(&vuln.title, 60),
            kev_marker,
            exploit_marker
        );
    }

    /// Display detailed vulnerability information
    fn display_vuln_detail(&self, vuln: &Vulnerability) {
        let risk = vuln.risk_score.unwrap_or(0);
        let level = RiskLevel::from_score(risk);

        Output::section("Overview");
        Output::item("CVE ID", &vuln.id);
        Output::item("Title", &vuln.title);
        Output::item("Risk Score", &format!("{}/100 ({})", risk, level.as_str()));

        if let Some(cvss) = vuln.cvss_v3 {
            Output::item("CVSS v3", &format!("{:.1}", cvss));
        }
        if let Some(cvss) = vuln.cvss_v2 {
            Output::item("CVSS v2", &format!("{:.1}", cvss));
        }

        Output::item("Severity", &format!("{:?}", vuln.severity));

        if vuln.cisa_kev {
            println!();
            Output::warning("CISA KEV: This vulnerability is actively exploited in the wild!");
            if let Some(ref due_date) = vuln.kev_due_date {
                Output::item("Remediation Due", due_date);
            }
        }

        println!();
        Output::section("Description");
        println!("{}", wrap_text(&vuln.description, 80));

        if !vuln.cwes.is_empty() {
            println!();
            Output::section("CWE IDs");
            for cwe in &vuln.cwes {
                Output::item("-", cwe);
            }
        }

        if !vuln.exploits.is_empty() {
            println!();
            Output::section(&format!("Exploits ({} found)", vuln.exploits.len()));
            for exp in &vuln.exploits {
                Output::item(&exp.source, &exp.url);
                if let Some(ref title) = exp.title {
                    Output::item("  Title", title);
                }
            }
        }

        if !vuln.references.is_empty() {
            println!();
            Output::section("References");
            for (i, ref_url) in vuln.references.iter().take(5).enumerate() {
                Output::item(&format!("[{}]", i + 1), ref_url);
            }
            if vuln.references.len() > 5 {
                Output::info(&format!("  ... and {} more", vuln.references.len() - 5));
            }
        }

        println!();
    }

    /// Correlate detected technologies with vulnerabilities
    fn correlate_techs(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or("Missing URL")?;

        if !ctx.wants_machine_output() {
            Output::header(&format!("Vulnerability Correlation: {}", url));
            println!();
        }

        // Parse URL to get host
        let _host = extract_host(url)?;

        // Step 1: Fingerprint the target
        if !ctx.wants_machine_output() {
            Output::spinner_start("Fingerprinting target...");
        }
        let techs = self.fingerprint_target(url)?;
        if !ctx.wants_machine_output() {
            Output::spinner_done();
        }

        if techs.is_empty() {
            let report = CorrelationReport {
                tech_correlations: Vec::new(),
                all_vulnerabilities: VulnCollection::new(),
                source_stats: Vec::new(),
                total_time_ms: 0,
                clean_techs: Vec::new(),
                summary: Default::default(),
            };
            let payload = vuln_correlation_payload(url, &techs, &report);
            if render::render_machine_output(ctx, "rb vuln intel correlate", &payload)? {
                return Ok(());
            }
            Output::warning("No technologies detected. Try using --deep for more thorough scanning.");
            return Ok(());
        }

        if !ctx.wants_machine_output() {
            Output::success(&format!("Detected {} technologies", techs.len()));
            println!();

            // Display detected technologies
            Output::section("Detected Technologies");
            for tech in &techs {
                let version_str = tech.version.as_deref().unwrap_or("unknown");
                let conf_str = format!("{:.0}%", tech.confidence * 100.0);
                Output::item(&tech.name, &format!("{} (confidence: {})", version_str, conf_str));
            }
            println!();
        }

        // Step 2: Correlate with vulnerability sources
        let sources = ctx.get_flag_or("sources", "all");
        let config = self.build_correlator_config(&sources);

        if !ctx.wants_machine_output() {
            Output::spinner_start("Correlating with vulnerability databases...");
        }
        let mut correlator = VulnCorrelator::with_config(config);
        let report = correlator.correlate(&techs);
        if !ctx.wants_machine_output() {
            Output::spinner_done();
        }

        let payload = vuln_correlation_payload(url, &techs, &report);
        if render::render_machine_output(ctx, "rb vuln intel correlate", &payload)? {
            return Ok(());
        }

        // Display results
        self.display_correlation_report(&report);

        Ok(())
    }

    /// Full vulnerability scan (fingerprint + correlate)
    fn vuln_scan(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or("Missing URL")?;
        let deep = ctx.has_flag("deep");

        if !ctx.wants_machine_output() {
            Output::header(&format!("Vulnerability Scan: {}", url));
            if deep {
                Output::info("Deep scan mode enabled");
            }
            println!();
        }

        // Step 1: Fingerprint
        if !ctx.wants_machine_output() {
            Output::spinner_start("Phase 1: Fingerprinting target...");
        }
        let techs = self.fingerprint_target(url)?;
        if !ctx.wants_machine_output() {
            Output::spinner_done();
        }

        if techs.is_empty() {
            let report = CorrelationReport {
                tech_correlations: Vec::new(),
                all_vulnerabilities: VulnCollection::new(),
                source_stats: Vec::new(),
                total_time_ms: 0,
                clean_techs: Vec::new(),
                summary: Default::default(),
            };
            let payload = vuln_scan_payload(url, deep, &techs, &report);
            if render::render_machine_output(ctx, "rb vuln intel scan", &payload)? {
                return Ok(());
            }
            Output::warning("No technologies detected.");
            return Ok(());
        }

        if !ctx.wants_machine_output() {
            Output::success(&format!("Phase 1 complete: {} technologies detected", techs.len()));
        }

        // Step 2: Correlate
        let sources = if deep { "all" } else { "nvd,kev" };
        let config = self.build_correlator_config(sources);

        if !ctx.wants_machine_output() {
            Output::spinner_start("Phase 2: Querying vulnerability databases...");
        }
        let mut correlator = VulnCorrelator::with_config(config);
        let report = correlator.correlate(&techs);
        if !ctx.wants_machine_output() {
            Output::spinner_done();
        }

        if !ctx.wants_machine_output() {
            Output::success(&format!(
                "Phase 2 complete: {} vulnerabilities found across {} technologies",
                report.summary.total_vulns,
                report.tech_correlations.len()
            ));
            println!();
        }

        let payload = vuln_scan_payload(url, deep, &techs, &report);
        if render::render_machine_output(ctx, "rb vuln intel scan", &payload)? {
            return Ok(());
        }

        // Display summary
        self.display_scan_summary(&report);

        // Show top risks
        let top_risks = report.top_risks(10);
        if !top_risks.is_empty() {
            Output::section(&format!("Top {} Risks", top_risks.len()));
            for vuln in top_risks {
                self.display_vuln_summary(vuln);
            }
        }

        Ok(())
    }

    /// Generate vulnerability report
    fn vuln_report(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or("Missing URL")?;
        let format = ctx.get_flag_or("format", "text");

        if !ctx.wants_machine_output() {
            Output::header(&format!("Vulnerability Report: {}", url));
            println!();
        }

        // Step 1: Fingerprint
        if !ctx.wants_machine_output() {
            Output::spinner_start("Fingerprinting target...");
        }
        let techs = self.fingerprint_target(url)?;
        if !ctx.wants_machine_output() {
            Output::spinner_done();
        }

        if techs.is_empty() {
            let report = CorrelationReport {
                tech_correlations: Vec::new(),
                all_vulnerabilities: VulnCollection::new(),
                source_stats: Vec::new(),
                total_time_ms: 0,
                clean_techs: Vec::new(),
                summary: Default::default(),
            };
            let payload = vuln_report_payload(url, &techs, &report);
            if render::render_machine_output(ctx, "rb vuln intel report", &payload)? {
                return Ok(());
            }
            Output::warning("No technologies detected.");
            return Ok(());
        }

        // Step 2: Full correlation
        if !ctx.wants_machine_output() {
            Output::spinner_start("Correlating vulnerabilities (all sources)...");
        }
        let config = self.build_correlator_config("all");
        let mut correlator = VulnCorrelator::with_config(config);
        let report = correlator.correlate(&techs);
        if !ctx.wants_machine_output() {
            Output::spinner_done();
        }

        let payload = vuln_report_payload(url, &techs, &report);
        if render::render_machine_output(ctx, "rb vuln intel report", &payload)? {
            return Ok(());
        }

        match format.as_str() {
            "markdown" | "md" => self.output_report_markdown(url, &techs, &report),
            _ => self.output_report_text(url, &techs, &report),
        }

        Ok(())
    }

    /// Build correlator config from sources string
    fn build_correlator_config(&self, sources: &str) -> CorrelatorConfig {
        let mut config = CorrelatorConfig::default();

        if sources == "all" {
            return config;
        }

        // Parse comma-separated sources
        let enabled: Vec<&str> = sources.split(',').map(|s| s.trim()).collect();

        config.use_nvd = enabled.iter().any(|&s| s == "nvd");
        config.use_osv = enabled.iter().any(|&s| s == "osv");
        config.use_kev = enabled.iter().any(|&s| s == "kev");
        config.use_exploitdb = enabled.iter().any(|&s| s == "exploitdb");

        config
    }

    /// Display correlation report
    fn display_correlation_report(&self, report: &CorrelationReport) {
        let summary = &report.summary;

        Output::section("Correlation Summary");
        Output::item("Technologies Scanned", &summary.techs_scanned.to_string());
        Output::item("With Vulnerabilities", &summary.techs_vulnerable.to_string());
        Output::item("Total Vulnerabilities", &summary.total_vulns.to_string());
        Output::item("Critical", &summary.critical_count.to_string());
        Output::item("High", &summary.high_count.to_string());
        Output::item("Medium", &summary.medium_count.to_string());
        Output::item("In CISA KEV", &summary.kev_count.to_string());
        Output::item("With Exploits", &summary.exploitable_count.to_string());
        println!();

        // Show per-technology breakdown
        if !report.tech_correlations.is_empty() {
            Output::section("Per-Technology Breakdown");
            for corr in &report.tech_correlations {
                let tech_str = if let Some(ref ver) = corr.tech.version {
                    format!("{} {}", corr.tech.name, ver)
                } else {
                    corr.tech.name.clone()
                };

                if corr.vulnerabilities.is_empty() {
                    Output::item(&tech_str, "No vulnerabilities found");
                } else {
                    let critical = corr.vulnerabilities.iter()
                        .filter(|v| matches!(v.severity, Severity::Critical))
                        .count();
                    let high = corr.vulnerabilities.iter()
                        .filter(|v| matches!(v.severity, Severity::High))
                        .count();

                    Output::item(
                        &tech_str,
                        &format!(
                            "{} vulns ({} critical, {} high)",
                            corr.vulnerabilities.len(),
                            critical,
                            high
                        ),
                    );
                }
            }
            println!();
        }

        // Show top risks
        let top = report.top_risks(5);
        if !top.is_empty() {
            Output::section("Top 5 Risks");
            for vuln in top {
                self.display_vuln_summary(vuln);
            }
        }
    }

    /// Display scan summary
    fn display_scan_summary(&self, report: &CorrelationReport) {
        let summary = &report.summary;

        Output::section("Scan Summary");

        // Risk breakdown
        let critical_color = if summary.critical_count > 0 { "\x1b[91m" } else { "" };
        let high_color = if summary.high_count > 0 { "\x1b[93m" } else { "" };
        let reset = "\x1b[0m";

        println!(
            "  {}CRITICAL: {}{}  {}HIGH: {}{}  MEDIUM: {}  LOW: {}",
            critical_color, summary.critical_count, reset,
            high_color, summary.high_count, reset,
            summary.medium_count,
            summary.low_count
        );

        if summary.kev_count > 0 {
            Output::warning(&format!("{} vulnerabilities in CISA KEV (actively exploited)", summary.kev_count));
        }

        if summary.exploitable_count > 0 {
            Output::warning(&format!("{} vulnerabilities have public exploits", summary.exploitable_count));
        }

        println!();
    }

    /// Output report as Markdown
    fn output_report_markdown(
        &self,
        url: &str,
        techs: &[DetectedTech],
        report: &CorrelationReport,
    ) {
        let summary = &report.summary;

        println!("# Vulnerability Report");
        println!();
        println!("**Target:** {}", url);
        println!("**Generated:** {}", chrono_now());
        println!();

        println!("## Executive Summary");
        println!();
        println!("| Metric | Count |");
        println!("|--------|-------|");
        println!("| Technologies Detected | {} |", techs.len());
        println!("| Total Vulnerabilities | {} |", summary.total_vulns);
        println!("| Critical | {} |", summary.critical_count);
        println!("| High | {} |", summary.high_count);
        println!("| Medium | {} |", summary.medium_count);
        println!("| CISA KEV | {} |", summary.kev_count);
        println!("| Public Exploits | {} |", summary.exploitable_count);
        println!();

        println!("## Detected Technologies");
        println!();
        for tech in techs {
            let version = tech.version.as_deref().unwrap_or("unknown");
            println!("- **{}** {}", tech.name, version);
        }
        println!();

        println!("## Top Risks");
        println!();
        let top = report.top_risks(10);
        for vuln in top {
            let kev_badge = if vuln.cisa_kev { " 🔴 **KEV**" } else { "" };
            let exp_badge = if vuln.has_exploit() { " ⚠️ **Exploit**" } else { "" };
            println!(
                "### {} (Risk: {}/100){}{}",
                vuln.id,
                vuln.risk_score.unwrap_or(0),
                kev_badge,
                exp_badge
            );
            println!();
            println!("**Severity:** {:?}  ", vuln.severity);
            if let Some(cvss) = vuln.cvss_v3 {
                println!("**CVSS v3:** {:.1}  ", cvss);
            }
            println!();
            println!("{}", vuln.description);
            println!();
        }
    }

    /// Output report as text
    fn output_report_text(
        &self,
        url: &str,
        techs: &[DetectedTech],
        report: &CorrelationReport,
    ) {
        let summary = &report.summary;

        Output::header("VULNERABILITY REPORT");
        println!();
        Output::item("Target", url);
        Output::item("Generated", &chrono_now());
        println!();

        Output::section("Executive Summary");
        Output::item("Technologies Detected", &techs.len().to_string());
        Output::item("Total Vulnerabilities", &summary.total_vulns.to_string());
        Output::item("Critical", &summary.critical_count.to_string());
        Output::item("High", &summary.high_count.to_string());
        Output::item("Medium", &summary.medium_count.to_string());
        Output::item("In CISA KEV", &summary.kev_count.to_string());
        Output::item("With Exploits", &summary.exploitable_count.to_string());
        println!();

        Output::section("Detected Technologies");
        for tech in techs {
            let version = tech.version.as_deref().unwrap_or("unknown");
            Output::item(&tech.name, version);
        }
        println!();

        Output::section("Top Risks");
        let top = report.top_risks(10);
        for vuln in top {
            self.display_vuln_summary(vuln);
        }
    }

    /// Fingerprint a target URL using HTTP client and fingerprint engine
    fn fingerprint_target(&self, url: &str) -> Result<Vec<DetectedTech>, String> {
        use crate::protocols::http::HttpClient;
        use std::collections::HashMap;

        // Make HTTP request to get headers
        let client = HttpClient::new();
        let response = client.get(url).map_err(|e| format!("HTTP request failed: {}", e))?;

        // Extract headers into a HashMap
        let mut headers: HashMap<String, String> = HashMap::new();
        for (key, value) in &response.headers {
            headers.insert(key.clone(), value.clone());
        }

        // Create fingerprint engine and extract from HTTP headers
        let mut engine = FingerprintEngine::new();
        engine.extract_from_http_headers(&headers);

        // Also extract from HTML body if present
        if !response.body.is_empty() {
            let body_str = String::from_utf8_lossy(&response.body);
            engine.extract_from_html(&body_str);
        }

        Ok(engine.into_results())
    }
}

/// Extract host from URL
fn extract_host(url: &str) -> Result<String, String> {
    let url = url.trim();

    // Remove protocol
    let without_proto = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };

    // Remove path
    let host = if let Some(pos) = without_proto.find('/') {
        &without_proto[..pos]
    } else {
        without_proto
    };

    // Remove port
    let host = if let Some(pos) = host.find(':') {
        &host[..pos]
    } else {
        host
    };

    if host.is_empty() {
        return Err("Invalid URL: could not extract host".to_string());
    }

    Ok(host.to_string())
}

/// Get current timestamp
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    let days = secs / 86400;
    let years_since_1970 = days / 365;
    let year = 1970 + years_since_1970;

    // Rough month/day calculation
    let remaining_days = days % 365;
    let month = (remaining_days / 30) + 1;
    let day = (remaining_days % 30) + 1;

    format!("{}-{:02}-{:02}", year, month.min(12), day.min(31))
}

/// Parse ecosystem string to Ecosystem enum
fn parse_ecosystem(s: &str) -> Option<Ecosystem> {
    match s.to_lowercase().as_str() {
        "npm" => Some(Ecosystem::Npm),
        "pypi" | "pip" | "python" => Some(Ecosystem::PyPI),
        "cargo" | "crates" | "rust" => Some(Ecosystem::Cargo),
        "go" | "golang" => Some(Ecosystem::Go),
        "maven" | "java" => Some(Ecosystem::Maven),
        "nuget" | "dotnet" | ".net" => Some(Ecosystem::NuGet),
        "packagist" | "composer" | "php" => Some(Ecosystem::Packagist),
        "rubygems" | "gem" | "ruby" => Some(Ecosystem::RubyGems),
        "pub" | "dart" | "flutter" => Some(Ecosystem::Pub),
        "hex" | "elixir" | "erlang" => Some(Ecosystem::Hex),
        _ => None,
    }
}

/// Truncate string to max length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
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

fn vuln_summary_to_json(vuln: &Vulnerability) -> crate::serde_json::Value {
    json!({
        "id": vuln.id.clone(),
        "title": vuln.title.replace('\n', " "),
        "severity": format!("{:?}", vuln.severity),
        "risk_score": vuln.risk_score.unwrap_or(0),
        "cvss_v3": vuln.cvss_v3,
        "cisa_kev": vuln.cisa_kev,
        "has_exploit": vuln.has_exploit()
    })
}

fn vuln_detail_to_json(vuln: &Vulnerability) -> crate::serde_json::Value {
    json!({
        "id": vuln.id.clone(),
        "title": vuln.title.replace('\n', " "),
        "description": vuln.description.replace('\n', " "),
        "severity": format!("{:?}", vuln.severity),
        "risk_score": vuln.risk_score.unwrap_or(0),
        "cvss_v3": vuln.cvss_v3,
        "cvss_v2": vuln.cvss_v2,
        "cisa_kev": vuln.cisa_kev,
        "kev_due_date": vuln.kev_due_date.clone(),
        "has_exploit": vuln.has_exploit(),
        "exploit_count": vuln.exploits.len(),
        "cwes": vuln.cwes.clone(),
        "references": vuln.references.iter().take(5).cloned().collect::<Vec<_>>()
    })
}

fn kev_entry_to_json(
    entry: &crate::modules::recon::vuln::kev::KevEntry,
) -> crate::serde_json::Value {
    json!({
        "cve_id": entry.cve_id.clone(),
        "vulnerability_name": entry.vulnerability_name.replace('\n', " "),
        "vendor": entry.vendor_project.clone(),
        "product": entry.product.clone(),
        "date_added": entry.date_added.clone(),
        "due_date": entry.due_date.clone(),
        "known_ransomware_use": entry.known_ransomware_use
    })
}

fn exploit_entry_to_json(
    entry: &crate::modules::recon::vuln::exploitdb::ExploitDbEntry,
) -> crate::serde_json::Value {
    json!({
        "id": entry.id.clone(),
        "title": entry.title.replace('\n', " "),
        "platform": entry.platform.clone(),
        "type": entry.exploit_type.clone(),
        "date": entry.date.clone(),
        "cve_ids": entry.cve_ids.clone(),
        "verified": entry.verified
    })
}

fn cpe_mapping_to_json(
    cpe: &&crate::modules::recon::vuln::cpe::CpeMapping,
) -> crate::serde_json::Value {
    let example_cpe = generate_cpe(cpe.tech_name, Some("1.0")).unwrap_or_default();
    json!({
        "tech_name": cpe.tech_name,
        "vendor": cpe.vendor,
        "product": cpe.product,
        "example_cpe": example_cpe
    })
}

fn top_risk_to_json(vuln: &&Vulnerability) -> crate::serde_json::Value {
    json!({
        "id": vuln.id.clone(),
        "risk_score": vuln.risk_score.unwrap_or(0),
        "severity": format!("{:?}", vuln.severity),
        "kev": vuln.cisa_kev,
        "title": vuln.title.clone()
    })
}

fn vuln_search_payload(
    tech: &str,
    version: Option<&String>,
    source: &str,
    vulns: &[Vulnerability],
    limit: usize,
) -> Value {
    let vulnerabilities: Vec<Value> = vulns.iter().take(limit).map(vuln_summary_to_json).collect();
    json!({
        "technology": tech,
        "version": version.cloned(),
        "source": source,
        "total": vulns.len(),
        "showing": limit.min(vulns.len()),
        "vulnerabilities": vulnerabilities
    })
}

fn cve_not_found_payload(cve_id: &str) -> Value {
    json!({
        "status": "not_found",
        "error": "CVE not found",
        "cve_id": cve_id
    })
}

fn vuln_detail_payload(vuln: &Vulnerability) -> Value {
    vuln_detail_to_json(vuln)
}

fn kev_stats_payload(stats: &crate::modules::recon::vuln::kev::KevStats) -> Value {
    let top_vendors: Vec<Value> = stats
        .top_vendors
        .iter()
        .take(10)
        .map(|(vendor, count)| json!({"vendor": vendor, "count": count}))
        .collect();
    json!({
        "type": "kev_stats",
        "total": stats.total,
        "ransomware_count": stats.ransomware_count,
        "top_vendors": top_vendors
    })
}

fn kev_entries_payload(
    vendor: Option<&String>,
    product: Option<&String>,
    entries: &[crate::modules::recon::vuln::kev::KevEntry],
    limit: usize,
) -> Value {
    let listed: Vec<Value> = entries.iter().take(limit).map(kev_entry_to_json).collect();
    let mut payload = crate::serde_json::Map::new();
    payload.insert("type".to_string(), json!("kev_entries"));
    if let Some(vendor) = vendor {
        payload.insert("filter_vendor".to_string(), json!(vendor));
    }
    if let Some(product) = product {
        payload.insert("filter_product".to_string(), json!(product));
    }
    payload.insert("total".to_string(), json!(entries.len()));
    payload.insert("showing".to_string(), json!(limit.min(entries.len())));
    payload.insert("entries".to_string(), json!(listed));
    Value::Object(payload)
}

fn exploit_search_payload(
    query: &str,
    results: &[crate::modules::recon::vuln::exploitdb::ExploitDbEntry],
    limit: usize,
) -> Value {
    let exploits: Vec<Value> = results.iter().take(limit).map(exploit_entry_to_json).collect();
    json!({
        "query": query,
        "total": results.len(),
        "showing": limit.min(results.len()),
        "exploits": exploits
    })
}

fn cpe_mappings_payload(
    category: Option<&String>,
    search: Option<&String>,
    filtered: &[&crate::modules::recon::vuln::cpe::CpeMapping],
) -> Value {
    let mut by_category: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
    for cpe in filtered {
        let cat_name = format!("{:?}", cpe.category);
        by_category.entry(cat_name).or_default().push(*cpe);
    }
    let mut categories_json = crate::serde_json::Map::new();
    let mut category_names: Vec<_> = by_category.keys().cloned().collect();
    category_names.sort();
    for cat in category_names {
        let cpes = by_category.get(&cat).unwrap();
        let cpes_json: Vec<Value> = cpes.iter().map(cpe_mapping_to_json).collect();
        categories_json.insert(cat, json!(cpes_json));
    }

    let mut payload = crate::serde_json::Map::new();
    if let Some(category) = category {
        payload.insert("filter_category".to_string(), json!(category));
    }
    if let Some(search) = search {
        payload.insert("filter_search".to_string(), json!(search));
    }
    payload.insert("total".to_string(), json!(filtered.len()));
    payload.insert("categories".to_string(), Value::Object(categories_json));
    Value::Object(payload)
}

fn detected_tech_to_json(tech: &DetectedTech) -> Value {
    json!({
        "name": tech.name,
        "category": format!("{:?}", tech.category),
        "version": tech.version,
        "confidence": tech.confidence,
        "source": tech.source
    })
}

fn source_stat_to_json(stat: &crate::modules::recon::vuln::correlator::SourceStats) -> Value {
    json!({
        "source": stat.source,
        "found": stat.found,
        "duration_ms": stat.duration_ms,
        "error": stat.error
    })
}

fn tech_correlation_to_json(
    corr: &crate::modules::recon::vuln::correlator::TechCorrelation,
) -> Value {
    let vulnerabilities: Vec<Value> = corr.vulnerabilities.iter().map(vuln_summary_to_json).collect();
    json!({
        "technology": detected_tech_to_json(&corr.tech),
        "cpe": corr.cpe,
        "cve_count": corr.cve_count,
        "critical_count": corr.critical_count,
        "high_count": corr.high_count,
        "exploitable_count": corr.exploitable_count,
        "kev_count": corr.kev_count,
        "query_time_ms": corr.query_time_ms,
        "max_risk_score": corr.max_risk_score(),
        "max_severity": format!("{:?}", corr.max_severity()),
        "vulnerabilities": vulnerabilities
    })
}

fn correlation_report_payload(report: &CorrelationReport) -> Value {
    let summary = &report.summary;
    let tech_correlations: Vec<Value> = report
        .tech_correlations
        .iter()
        .map(tech_correlation_to_json)
        .collect();
    let source_stats: Vec<Value> = report.source_stats.iter().map(source_stat_to_json).collect();
    let top_risks: Vec<Value> = report.top_risks(10).iter().map(top_risk_to_json).collect();

    json!({
        "summary": {
            "techs_scanned": summary.techs_scanned,
            "techs_vulnerable": summary.techs_vulnerable,
            "total_vulns": summary.total_vulns,
            "critical_count": summary.critical_count,
            "high_count": summary.high_count,
            "medium_count": summary.medium_count,
            "low_count": summary.low_count,
            "exploitable_count": summary.exploitable_count,
            "kev_count": summary.kev_count,
            "avg_risk_score": summary.avg_risk_score,
            "max_risk_score": summary.max_risk_score
        },
        "total_time_ms": report.total_time_ms,
        "clean_techs": report.clean_techs,
        "source_stats": source_stats,
        "tech_correlations": tech_correlations,
        "top_risks": top_risks
    })
}

fn vuln_correlation_payload(url: &str, techs: &[DetectedTech], report: &CorrelationReport) -> Value {
    let detected_techs: Vec<Value> = techs.iter().map(detected_tech_to_json).collect();
    json!({
        "target": url,
        "detected_technologies": detected_techs,
        "correlation": correlation_report_payload(report)
    })
}

fn vuln_scan_payload(
    url: &str,
    deep: bool,
    techs: &[DetectedTech],
    report: &CorrelationReport,
) -> Value {
    json!({
        "target": url,
        "deep": deep,
        "detected_technologies": techs.iter().map(detected_tech_to_json).collect::<Vec<_>>(),
        "report": correlation_report_payload(report)
    })
}

fn vuln_report_payload(url: &str, techs: &[DetectedTech], report: &CorrelationReport) -> Value {
    json!({
        "target": url,
        "generated_at": chrono_now(),
        "detected_technologies": techs.iter().map(detected_tech_to_json).collect::<Vec<_>>(),
        "report": correlation_report_payload(report)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::common::Severity;
    use crate::modules::recon::fingerprint::FingerprintSource;
    use crate::modules::recon::vuln::correlator::{CorrelationSummary, SourceStats, TechCorrelation};

    fn sample_vuln(id: &str) -> Vulnerability {
        let mut vuln = Vulnerability::new(id, "Sample vuln", "demo");
        vuln.severity = Severity::High;
        vuln.risk_score = Some(72);
        vuln
    }

    fn sample_tech() -> DetectedTech {
        DetectedTech {
            name: "nginx".to_string(),
            version: Some("1.24.0".to_string()),
            category: TechCategory::WebServer,
            confidence: 0.95,
            source: FingerprintSource::HttpHeader,
        }
    }

    #[test]
    fn vuln_search_payload_includes_showing_count() {
        let vulns = vec![sample_vuln("CVE-2024-0001"), sample_vuln("CVE-2024-0002")];
        let payload = vuln_search_payload("nginx", None, "nvd", &vulns, 1);
        assert_eq!(payload["total"], json!(2));
        assert_eq!(payload["showing"], json!(1));
    }

    #[test]
    fn cve_not_found_payload_marks_status() {
        let payload = cve_not_found_payload("CVE-2024-9999");
        assert_eq!(payload["status"], json!("not_found"));
        assert_eq!(payload["cve_id"], json!("CVE-2024-9999"));
    }

    #[test]
    fn correlation_report_payload_contains_summary_and_top_risks() {
        let mut corr = TechCorrelation::new(sample_tech());
        corr.vulnerabilities.push(sample_vuln("CVE-2024-0001"));
        corr.calculate_stats();

        let mut collection = VulnCollection::new();
        collection.add(sample_vuln("CVE-2024-0001"));

        let report = CorrelationReport {
            tech_correlations: vec![corr],
            all_vulnerabilities: collection,
            source_stats: vec![SourceStats {
                source: "nvd".to_string(),
                found: 1,
                duration_ms: 42,
                error: None,
            }],
            total_time_ms: 99,
            clean_techs: vec!["redis".to_string()],
            summary: CorrelationSummary {
                techs_scanned: 2,
                techs_vulnerable: 1,
                total_vulns: 1,
                critical_count: 0,
                high_count: 1,
                medium_count: 0,
                low_count: 0,
                exploitable_count: 0,
                kev_count: 0,
                avg_risk_score: 72.0,
                max_risk_score: 72,
            },
        };

        let payload = correlation_report_payload(&report);
        assert_eq!(payload["summary"]["techs_scanned"], json!(2));
        assert_eq!(payload["source_stats"][0]["source"], json!("nvd"));
        assert_eq!(payload["top_risks"][0]["id"], json!("CVE-2024-0001"));
    }
}
