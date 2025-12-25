//! Vulnerability Intelligence Command
//!
//! Search and analyze vulnerabilities from multiple sources:
//! - NVD (National Vulnerability Database)
//! - OSV (Open Source Vulnerabilities)
//! - CISA KEV (Known Exploited Vulnerabilities)
//! - Exploit-DB

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
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
            if is_json {
                println!("{{\"technology\": \"{}\", \"version\": {}, \"source\": \"{}\", \"total\": 0, \"vulnerabilities\": []}}",
                    tech.replace('"', "\\\""),
                    version.as_ref().map(|v| format!("\"{}\"", v.replace('"', "\\\""))).unwrap_or_else(|| "null".to_string()),
                    source
                );
            } else {
                println!();
                Output::info("No vulnerabilities found.");
            }
            return Ok(());
        }

        if is_json {
            println!("{{");
            println!("  \"technology\": \"{}\",", tech.replace('"', "\\\""));
            if let Some(ref ver) = version {
                println!("  \"version\": \"{}\",", ver.replace('"', "\\\""));
            } else {
                println!("  \"version\": null,");
            }
            println!("  \"source\": \"{}\",", source);
            println!("  \"total\": {},", vulns.len());
            println!("  \"showing\": {},", limit.min(vulns.len()));
            println!("  \"vulnerabilities\": [");
            for (i, vuln) in vulns.iter().take(limit).enumerate() {
                let comma = if i < limit.min(vulns.len()) - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"id\": \"{}\",", vuln.id.replace('"', "\\\""));
                println!("      \"title\": \"{}\",", vuln.title.replace('"', "\\\"").replace('\n', " "));
                println!("      \"severity\": \"{:?}\",", vuln.severity);
                println!("      \"risk_score\": {},", vuln.risk_score.unwrap_or(0));
                if let Some(cvss) = vuln.cvss_v3 {
                    println!("      \"cvss_v3\": {:.1},", cvss);
                } else {
                    println!("      \"cvss_v3\": null,");
                }
                println!("      \"cisa_kev\": {},", vuln.cisa_kev);
                println!("      \"has_exploit\": {}", vuln.has_exploit());
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
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
                if !is_json {
                    Output::spinner_done();
                    Output::warning(&format!("CVE {} not found in NVD", cve_id));
                } else {
                    println!("{{\"error\": \"CVE not found\", \"cve_id\": \"{}\"}}",
                        cve_id.replace('"', "\\\""));
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
            println!("{{");
            println!("  \"id\": \"{}\",", vuln.id.replace('"', "\\\""));
            println!("  \"title\": \"{}\",", vuln.title.replace('"', "\\\"").replace('\n', " "));
            println!("  \"description\": \"{}\",", vuln.description.replace('"', "\\\"").replace('\n', " "));
            println!("  \"severity\": \"{:?}\",", vuln.severity);
            println!("  \"risk_score\": {},", vuln.risk_score.unwrap_or(0));
            if let Some(cvss) = vuln.cvss_v3 {
                println!("  \"cvss_v3\": {:.1},", cvss);
            } else {
                println!("  \"cvss_v3\": null,");
            }
            if let Some(cvss) = vuln.cvss_v2 {
                println!("  \"cvss_v2\": {:.1},", cvss);
            } else {
                println!("  \"cvss_v2\": null,");
            }
            println!("  \"cisa_kev\": {},", vuln.cisa_kev);
            if let Some(ref due) = vuln.kev_due_date {
                println!("  \"kev_due_date\": \"{}\",", due.replace('"', "\\\""));
            } else {
                println!("  \"kev_due_date\": null,");
            }
            println!("  \"has_exploit\": {},", vuln.has_exploit());
            println!("  \"exploit_count\": {},", vuln.exploits.len());
            println!("  \"cwes\": [{}],", vuln.cwes.iter()
                .map(|c| format!("\"{}\"", c.replace('"', "\\\"")))
                .collect::<Vec<_>>().join(", "));
            println!("  \"references\": [{}]", vuln.references.iter().take(5)
                .map(|r| format!("\"{}\"", r.replace('"', "\\\"")))
                .collect::<Vec<_>>().join(", "));
            println!("}}");
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
                println!("{{");
                println!("  \"type\": \"kev_stats\",");
                println!("  \"total\": {},", stats.total);
                println!("  \"ransomware_count\": {},", stats.ransomware_count);
                println!("  \"top_vendors\": [");
                for (i, (vendor, count)) in stats.top_vendors.iter().take(10).enumerate() {
                    let comma = if i < stats.top_vendors.len().min(10) - 1 { "," } else { "" };
                    println!("    {{ \"vendor\": \"{}\", \"count\": {} }}{}", vendor.replace('"', "\\\""), count, comma);
                }
                println!("  ]");
                println!("}}");
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
            println!("{{");
            println!("  \"type\": \"kev_entries\",");
            if let Some(ref v) = vendor {
                println!("  \"filter_vendor\": \"{}\",", v.replace('"', "\\\""));
            }
            if let Some(ref p) = product {
                println!("  \"filter_product\": \"{}\",", p.replace('"', "\\\""));
            }
            println!("  \"total\": {},", entries.len());
            println!("  \"showing\": {},", limit.min(entries.len()));
            println!("  \"entries\": [");
            for (i, entry) in entries.iter().take(limit).enumerate() {
                let comma = if i < limit.min(entries.len()) - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"cve_id\": \"{}\",", entry.cve_id.replace('"', "\\\""));
                println!("      \"vulnerability_name\": \"{}\",", entry.vulnerability_name.replace('"', "\\\"").replace('\n', " "));
                println!("      \"vendor\": \"{}\",", entry.vendor_project.replace('"', "\\\""));
                println!("      \"product\": \"{}\",", entry.product.replace('"', "\\\""));
                println!("      \"date_added\": \"{}\",", entry.date_added.replace('"', "\\\""));
                println!("      \"due_date\": \"{}\",", entry.due_date.replace('"', "\\\""));
                println!("      \"known_ransomware_use\": {}", entry.known_ransomware_use);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
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
                println!("{{");
                println!("  \"query\": \"{}\",", query.replace('"', "\\\""));
                println!("  \"total\": 0,");
                println!("  \"exploits\": []");
                println!("}}");
                return Ok(());
            }
            Output::info("No exploits found.");
            return Ok(());
        }

        if is_json {
            println!("{{");
            println!("  \"query\": \"{}\",", query.replace('"', "\\\""));
            println!("  \"total\": {},", results.len());
            println!("  \"showing\": {},", limit.min(results.len()));
            println!("  \"exploits\": [");
            for (i, entry) in results.iter().take(limit).enumerate() {
                let comma = if i < limit.min(results.len()) - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"id\": \"{}\",", entry.id.replace('"', "\\\""));
                println!("      \"title\": \"{}\",", entry.title.replace('"', "\\\"").replace('\n', " "));
                if let Some(ref platform) = entry.platform {
                    println!("      \"platform\": \"{}\",", platform.replace('"', "\\\""));
                } else {
                    println!("      \"platform\": null,");
                }
                if let Some(ref etype) = entry.exploit_type {
                    println!("      \"type\": \"{}\",", etype.replace('"', "\\\""));
                } else {
                    println!("      \"type\": null,");
                }
                if let Some(ref date) = entry.date {
                    println!("      \"date\": \"{}\",", date.replace('"', "\\\""));
                } else {
                    println!("      \"date\": null,");
                }
                println!("      \"cve_ids\": [");
                for (j, cve) in entry.cve_ids.iter().enumerate() {
                    let cve_comma = if j < entry.cve_ids.len() - 1 { "," } else { "" };
                    println!("        \"{}\"{}", cve.replace('"', "\\\""), cve_comma);
                }
                println!("      ],");
                println!("      \"verified\": {}", entry.verified);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
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
            // Group by category for JSON output
            let mut by_category: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for cpe in &filtered {
                let cat_name = format!("{:?}", cpe.category);
                by_category.entry(cat_name).or_default().push(*cpe);
            }

            println!("{{");
            if let Some(ref cat) = category {
                println!("  \"filter_category\": \"{}\",", cat.replace('"', "\\\""));
            }
            if let Some(ref s) = search {
                println!("  \"filter_search\": \"{}\",", s.replace('"', "\\\""));
            }
            println!("  \"total\": {},", filtered.len());
            println!("  \"categories\": {{");
            let cat_count = by_category.len();
            for (i, (cat, cpes)) in by_category.iter().enumerate() {
                let cat_comma = if i < cat_count - 1 { "," } else { "" };
                println!("    \"{}\": [", cat);
                for (j, cpe) in cpes.iter().enumerate() {
                    let cpe_comma = if j < cpes.len() - 1 { "," } else { "" };
                    let example_cpe = generate_cpe(cpe.tech_name, Some("1.0")).unwrap_or_default();
                    println!("      {{");
                    println!("        \"tech_name\": \"{}\",", cpe.tech_name.replace('"', "\\\""));
                    println!("        \"vendor\": \"{}\",", cpe.vendor.replace('"', "\\\""));
                    println!("        \"product\": \"{}\",", cpe.product.replace('"', "\\\""));
                    println!("        \"example_cpe\": \"{}\"", example_cpe.replace('"', "\\\""));
                    println!("      }}{}", cpe_comma);
                }
                println!("    ]{}", cat_comma);
            }
            println!("  }}");
            println!("}}");
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
            Severity::None => "NONE",
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

        Output::header(&format!("Vulnerability Correlation: {}", url));
        println!();

        // Parse URL to get host
        let _host = extract_host(url)?;

        // Step 1: Fingerprint the target
        Output::spinner_start("Fingerprinting target...");
        let techs = self.fingerprint_target(url)?;
        Output::spinner_done();

        if techs.is_empty() {
            Output::warning("No technologies detected. Try using --deep for more thorough scanning.");
            return Ok(());
        }

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

        // Step 2: Correlate with vulnerability sources
        let sources = ctx.get_flag_or("sources", "all");
        let config = self.build_correlator_config(&sources);

        Output::spinner_start("Correlating with vulnerability databases...");
        let mut correlator = VulnCorrelator::with_config(config);
        let report = correlator.correlate(&techs);
        Output::spinner_done();

        // Display results
        self.display_correlation_report(&report);

        Ok(())
    }

    /// Full vulnerability scan (fingerprint + correlate)
    fn vuln_scan(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or("Missing URL")?;
        let deep = ctx.has_flag("deep");
        let json_output = ctx.has_flag("json");

        Output::header(&format!("Vulnerability Scan: {}", url));
        if deep {
            Output::info("Deep scan mode enabled");
        }
        println!();

        // Step 1: Fingerprint
        Output::spinner_start("Phase 1: Fingerprinting target...");
        let techs = self.fingerprint_target(url)?;
        Output::spinner_done();

        if techs.is_empty() {
            Output::warning("No technologies detected.");
            return Ok(());
        }

        Output::success(&format!("Phase 1 complete: {} technologies detected", techs.len()));

        // Step 2: Correlate
        let sources = if deep { "all" } else { "nvd,kev" };
        let config = self.build_correlator_config(sources);

        Output::spinner_start("Phase 2: Querying vulnerability databases...");
        let mut correlator = VulnCorrelator::with_config(config);
        let report = correlator.correlate(&techs);
        Output::spinner_done();

        Output::success(&format!(
            "Phase 2 complete: {} vulnerabilities found across {} technologies",
            report.summary.total_vulns,
            report.tech_correlations.len()
        ));
        println!();

        if json_output {
            // Output JSON format
            self.output_report_json(&report);
        } else {
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
        }

        Ok(())
    }

    /// Generate vulnerability report
    fn vuln_report(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or("Missing URL")?;
        let format = ctx.get_flag_or("format", "text");

        Output::header(&format!("Vulnerability Report: {}", url));
        println!();

        // Step 1: Fingerprint
        Output::spinner_start("Fingerprinting target...");
        let techs = self.fingerprint_target(url)?;
        Output::spinner_done();

        if techs.is_empty() {
            Output::warning("No technologies detected.");
            return Ok(());
        }

        // Step 2: Full correlation
        Output::spinner_start("Correlating vulnerabilities (all sources)...");
        let config = self.build_correlator_config("all");
        let mut correlator = VulnCorrelator::with_config(config);
        let report = correlator.correlate(&techs);
        Output::spinner_done();

        match format.as_str() {
            "json" => self.output_report_json(&report),
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

    /// Output report as JSON
    fn output_report_json(&self, report: &CorrelationReport) {
        let summary = &report.summary;

        println!("{{");
        println!("  \"total_technologies\": {},", summary.techs_scanned);
        println!("  \"technologies_with_vulns\": {},", summary.techs_vulnerable);
        println!("  \"total_vulnerabilities\": {},", summary.total_vulns);
        println!("  \"critical\": {},", summary.critical_count);
        println!("  \"high\": {},", summary.high_count);
        println!("  \"medium\": {},", summary.medium_count);
        println!("  \"low\": {},", summary.low_count);
        println!("  \"kev_count\": {},", summary.kev_count);
        println!("  \"exploit_count\": {},", summary.exploitable_count);

        println!("  \"top_risks\": [");
        let top = report.top_risks(10);
        for (i, vuln) in top.iter().enumerate() {
            let comma = if i < top.len() - 1 { "," } else { "" };
            println!(
                "    {{\"id\": \"{}\", \"risk_score\": {}, \"severity\": \"{:?}\", \"kev\": {}, \"title\": \"{}\"}}{}",
                vuln.id,
                vuln.risk_score.unwrap_or(0),
                vuln.severity,
                vuln.cisa_kev,
                vuln.title.replace('"', "\\\""),
                comma
            );
        }
        println!("  ]");
        println!("}}");
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
