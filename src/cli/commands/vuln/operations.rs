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

