impl IntelCommand {

  /// List CPE mappings
  fn list_cpe(&self, ctx: &CliContext) -> Result<(), String> {
    let category = ctx.get_flag_with_config("category");
    let search = ctx.get_flag_with_config("search");
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    if !is_json {
      Output::header("CPE Technology Mappings");
      println!();
    }

    let all_cpes = get_all_cpe_mappings();

    let filtered: Vec<_> = all_cpes
      .iter()
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
      let mappings_json: Vec<crate::serde_json::Value> =
        filtered.iter().map(intel_cpe_mapping_to_json).collect();
      let mut payload = crate::serde_json::Map::new();
      if let Some(ref cat) = category {
        payload.insert("category_filter".to_string(), json!(cat.clone()));
      }
      if let Some(ref term) = search {
        payload.insert("search_filter".to_string(), json!(term.clone()));
      }
      payload.insert("total_count".to_string(), json!(filtered.len()));
      payload.insert("mappings".to_string(), json!(mappings_json));
      render::render_machine_output(
        ctx,
        "rb intel vuln cpe",
        &crate::serde_json::Value::Object(payload),
      )?;
      return Ok(());
    }

    Output::info(&format!("Showing {} CPE mappings", filtered.len()));
    println!();

    // Group by category
    let mut by_category: std::collections::HashMap<String, Vec<_>> =
      std::collections::HashMap::new();
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
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    if !is_json {
      Output::header(&format!("Vulnerability Correlation: {}", url));
      println!();
    }

    // Parse URL to get host
    let _host = extract_host(url)?;

    // Step 1: Fingerprint the target
    if !is_json {
      Output::spinner_start("Fingerprinting target...");
    }
    let techs = self.fingerprint_target(url)?;
    if !is_json {
      Output::spinner_done();
    }

    if techs.is_empty() {
      if is_json {
        render::render_machine_output(
          ctx,
          "rb intel vuln correlate",
          &json!({
            "error": "No technologies detected",
            "url": url.clone()
          }),
        )?;
      } else {
        Output::warning("No technologies detected. Try using --deep for more thorough scanning.");
      }
      return Ok(());
    }

    if !is_json {
      Output::success(&format!("Detected {} technologies", techs.len()));
      println!();

      // Display detected technologies
      Output::section("Detected Technologies");
      for tech in &techs {
        let version_str = tech.version.as_deref().unwrap_or("unknown");
        let conf_str = format!("{:.0}%", tech.confidence * 100.0);
        Output::item(
          &tech.name,
          &format!("{} (confidence: {})", version_str, conf_str),
        );
      }
      println!();
    }

    // Step 2: Correlate with vulnerability sources
    let sources = ctx.get_flag_or("sources", "all");
    let config = self.build_correlator_config(&sources);

    if !is_json {
      Output::spinner_start("Correlating with vulnerability databases...");
    }
    let mut correlator = VulnCorrelator::with_config(config);
    let report = correlator.correlate(&techs);
    if !is_json {
      Output::spinner_done();
    }

    let payload = self.output_correlation_json(url, &techs, &report);
    if render::render_machine_output(ctx, "rb intel vuln correlate", &payload)? {
      return Ok(());
    }

    // Display results
    self.display_correlation_report(&report);

    Ok(())
  }

  /// Output correlation report as JSON
  fn output_correlation_json(
    &self,
    url: &str,
    techs: &[DetectedTech],
    report: &CorrelationReport,
  ) -> crate::serde_json::Value {
    let summary = &report.summary;
    let technologies_json: Vec<crate::serde_json::Value> =
      techs.iter().map(detected_tech_to_json).collect();
    let top_risks_json: Vec<crate::serde_json::Value> = report
      .top_risks(10)
      .iter()
      .map(intel_top_risk_to_json)
      .collect();
    let summary_json = json!({
        "techs_scanned": summary.techs_scanned,
        "techs_vulnerable": summary.techs_vulnerable,
        "total_vulns": summary.total_vulns,
        "critical": summary.critical_count,
        "high": summary.high_count,
        "medium": summary.medium_count,
        "low": summary.low_count,
        "kev_count": summary.kev_count,
        "exploitable_count": summary.exploitable_count
    });
    json!({
        "url": url.to_string(),
        "technologies": technologies_json,
        "summary": summary_json,
        "top_risks": top_risks_json
    })
  }

  /// Full vulnerability scan (fingerprint + correlate)
  fn vuln_scan(&self, ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or("Missing URL")?;
    let deep = ctx.has_flag("deep");
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    if !is_json {
      Output::header(&format!("Vulnerability Scan: {}", url));
      if deep {
        Output::info("Deep scan mode enabled");
      }
      println!();
    }

    // Step 1: Fingerprint
    if !is_json {
      Output::spinner_start("Phase 1: Fingerprinting target...");
    }
    let techs = self.fingerprint_target(url)?;
    if !is_json {
      Output::spinner_done();
    }

    if techs.is_empty() {
      if is_json {
        render::render_machine_output(
          ctx,
          "rb intel vuln scan",
          &json!({
            "error": "No technologies detected",
            "url": url.clone()
          }),
        )?;
      } else {
        Output::warning("No technologies detected.");
      }
      return Ok(());
    }

    if !is_json {
      Output::success(&format!(
        "Phase 1 complete: {} technologies detected",
        techs.len()
      ));
    }

    // Step 2: Correlate
    let sources = if deep { "all" } else { "nvd,kev" };
    let config = self.build_correlator_config(sources);

    if !is_json {
      Output::spinner_start("Phase 2: Querying vulnerability databases...");
    }
    let mut correlator = VulnCorrelator::with_config(config);
    let report = correlator.correlate(&techs);
    if !is_json {
      Output::spinner_done();

      Output::success(&format!(
        "Phase 2 complete: {} vulnerabilities found across {} technologies",
        report.summary.total_vulns,
        report.tech_correlations.len()
      ));
      println!();
    }

    if is_json {
      let payload = self.output_report_json(&report);
      render::render_machine_output(ctx, "rb intel vuln scan", &payload)?;
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
      if render::render_machine_output(
        ctx,
        "rb intel vuln report",
        &json!({
          "error": "No technologies detected",
          "url": url
        }),
      )? {
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

    let json_payload = self.output_report_json(&report);
    if render::render_machine_output(ctx, "rb intel vuln report", &json_payload)? {
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
    Output::item(
      "With Vulnerabilities",
      &summary.techs_vulnerable.to_string(),
    );
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
          let critical = corr
            .vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, Severity::Critical))
            .count();
          let high = corr
            .vulnerabilities
            .iter()
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
    let critical_color = if summary.critical_count > 0 {
      "\x1b[91m"
    } else {
      ""
    };
    let high_color = if summary.high_count > 0 {
      "\x1b[93m"
    } else {
      ""
    };
    let reset = "\x1b[0m";

    println!(
      "  {}CRITICAL: {}{}  {}HIGH: {}{}  MEDIUM: {}  LOW: {}",
      critical_color,
      summary.critical_count,
      reset,
      high_color,
      summary.high_count,
      reset,
      summary.medium_count,
      summary.low_count
    );

    if summary.kev_count > 0 {
      Output::warning(&format!(
        "{} vulnerabilities in CISA KEV (actively exploited)",
        summary.kev_count
      ));
    }

    if summary.exploitable_count > 0 {
      Output::warning(&format!(
        "{} vulnerabilities have public exploits",
        summary.exploitable_count
      ));
    }

    println!();
  }
}
