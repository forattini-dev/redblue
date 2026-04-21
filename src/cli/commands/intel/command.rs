// Intelligence Command
//
// Unified intelligence domain for:
// - vuln: Vulnerability intelligence (NVD, OSV, KEV, Exploit-DB)
// - mitre: MITRE ATT&CK threat intelligence (planned)
// - ioc: Indicators of Compromise (planned)
// - taxii: TAXII threat feed client (planned)

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::common::Severity;
use crate::modules::recon::fingerprint::FingerprintEngine;
use crate::modules::recon::vuln::{
  correlator::{CorrelationReport, CorrelatorConfig, VulnCorrelator},
  cpe::{generate_cpe, get_all_cpe_mappings, TechCategory},
  exploitdb::ExploitDbClient,
  kev::KevClient,
  nvd::NvdClient,
  osv::{Ecosystem, OsvClient},
  risk::{calculate_risk_score, RiskLevel},
  types::{DetectedTech, VulnCollection, Vulnerability},
};

pub struct IntelCommand;

impl Command for IntelCommand {
  fn domain(&self) -> &str {
    "intelligence" // Short alias: "intel"
  }

  fn resource(&self) -> &str {
    "vuln"
  }

  fn description(&self) -> &str {
    "Vulnerability intelligence - search CVEs, check exploits, assess risk"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
      .with_aliases(crate::cli::aliases::resource_aliases_for(self.resource()))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let aliases = crate::cli::aliases::verb_aliases_for(verb);
    match verb {
      "search" | "cve" | "kev" | "exploit" | "cpe" | "correlate" | "scan" | "report" => {
        crate::cli::schema::RouteMetadata::new()
          .with_aliases(aliases)
          .with_machine_output(
            crate::cli::schema::MachineOutputMetadata::new()
              .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
              .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
              .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
          )
      }
      _ => crate::cli::schema::RouteMetadata::new()
        .with_aliases(aliases)
        .with_machine_output(self.metadata().machine_output),
    }
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "search",
        summary: "Search vulnerabilities by technology/product name",
        usage: "rb intel vuln search <tech> [version] [--source nvd|osv|all]",
      },
      Route {
        verb: "cve",
        summary: "Get detailed information about a specific CVE",
        usage: "rb intel vuln cve <CVE-ID>",
      },
      Route {
        verb: "kev",
        summary: "Check CISA Known Exploited Vulnerabilities catalog",
        usage: "rb intel vuln kev [--vendor <name>] [--product <name>] [--stats]",
      },
      Route {
        verb: "exploit",
        summary: "Search Exploit-DB for exploits",
        usage: "rb intel vuln exploit <query>",
      },
      Route {
        verb: "cpe",
        summary: "List supported CPE mappings for technologies",
        usage: "rb intel vuln cpe [--category <cat>] [--search <term>]",
      },
      Route {
        verb: "correlate",
        summary: "Correlate detected technologies with vulnerabilities",
        usage: "rb intel vuln correlate <url> [--sources all|nvd|osv|kev]",
      },
      Route {
        verb: "scan",
        summary: "Full vulnerability scan (fingerprint + correlate)",
        usage: "rb intel vuln scan <url> [--deep] [--json]",
      },
      Route {
        verb: "report",
        summary: "Generate vulnerability report for target",
        usage: "rb intel vuln report <url> [--format text|json|markdown]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output format (text, json, yaml)")
        .with_short('o')
        .with_default("text"),
      Flag::new(
        "source",
        "Vulnerability source (nvd, osv, kev, exploitdb, all)",
      )
      .with_short('s')
      .with_default("nvd"),
      Flag::new("version", "Specific version to check").with_short('v'),
      Flag::new(
        "ecosystem",
        "Package ecosystem for OSV (npm, pypi, cargo, etc.)",
      ),
      Flag::new("vendor", "Filter by vendor name"),
      Flag::new("product", "Filter by product name"),
      Flag::new(
        "category",
        "CPE category filter (webserver, framework, cms, etc.)",
      ),
      Flag::new("search", "Search term for CPE lookup"),
      Flag::new("stats", "Show statistics"),
      Flag::new("limit", "Maximum results to show").with_default("20"),
      Flag::new("api-key", "NVD API key for higher rate limits"),
      Flag::new("deep", "Deep scan (all sources, slower)"),
      Flag::new("sources", "Vulnerability sources (nvd,osv,kev,exploitdb)").with_default("all"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Search vulnerabilities for nginx",
        "rb intel vuln search nginx",
      ),
      ("Search with version", "rb intel vuln search nginx 1.18.0"),
      ("Get CVE details", "rb intel vuln cve CVE-2021-44228"),
      ("Check CISA KEV stats", "rb intel vuln kev --stats"),
      ("KEV by vendor", "rb intel vuln kev --vendor Microsoft"),
      (
        "Search Exploit-DB",
        "rb intel vuln exploit \"Apache Struts\"",
      ),
      ("List CPE mappings", "rb intel vuln cpe"),
      ("CPE by category", "rb intel vuln cpe --category webserver"),
      (
        "OSV package search",
        "rb intel vuln search lodash --source osv --ecosystem npm",
      ),
      (
        "Correlate URL techs",
        "rb intel vuln correlate https://example.com",
      ),
      (
        "Full vuln scan",
        "rb intel vuln scan https://target.com --deep",
      ),
      (
        "Generate report",
        "rb intel vuln report https://target.com --format markdown",
      ),
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

impl IntelCommand {
  /// Search vulnerabilities by technology name
  fn search_vulns(&self, ctx: &CliContext) -> Result<(), String> {
    let tech = ctx.target.as_ref().ok_or("Missing technology name")?;
    let version = ctx.get_flag_with_config("version").or_else(|| {
      // Check if version is provided as second positional arg
      ctx.args.get(4).cloned()
    });
    let source = ctx.get_flag_or("source", "nvd");
    let limit: usize = ctx
      .get_flag_with_config("limit")
      .and_then(|s| s.parse().ok())
      .unwrap_or(20);
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

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
        if !is_json {
          Output::spinner_start("Querying NVD...");
        }

        // Generate CPE for this technology
        if let Some(cpe) = generate_cpe(tech, version.as_deref()) {
          let mut nvd = NvdClient::new();
          if let Some(api_key) = ctx.get_flag_with_config("api-key") {
            nvd = nvd.with_api_key(&api_key);
          }

          match nvd.query_by_cpe(&cpe) {
            Ok(vulns) => {
              if !is_json {
                Output::spinner_done();
                Output::success(&format!("Found {} vulnerabilities from NVD", vulns.len()));
              }
              for vuln in vulns {
                collection.add(vuln);
              }
            }
            Err(e) => {
              if !is_json {
                Output::spinner_done();
                Output::warning(&format!("NVD query failed: {}", e));
              }
            }
          }
        } else {
          if !is_json {
            Output::spinner_done();
            Output::warning(&format!(
              "No CPE mapping found for '{}'. Trying keyword search...",
              tech
            ));
          }

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
              if !is_json {
                Output::success(&format!("Found {} vulnerabilities from NVD", vulns.len()));
              }
              for vuln in vulns {
                collection.add(vuln);
              }
            }
            Err(e) => {
              if !is_json {
                Output::warning(&format!("NVD keyword search failed: {}", e));
              }
            }
          }
        }
      }
      _ => {}
    }

    match source.as_str() {
      "osv" | "all" => {
        if !is_json {
          Output::spinner_start("Querying OSV...");
        }

        let ecosystem = ctx
          .get_flag_with_config("ecosystem")
          .and_then(|e| parse_ecosystem(&e));

        if let Some(eco) = ecosystem {
          let osv = OsvClient::new();
          match osv.query_package(tech, version.as_deref(), eco) {
            Ok(vulns) => {
              if !is_json {
                Output::spinner_done();
                Output::success(&format!("Found {} vulnerabilities from OSV", vulns.len()));
              }
              for vuln in vulns {
                collection.add(vuln);
              }
            }
            Err(e) => {
              if !is_json {
                Output::spinner_done();
                Output::warning(&format!("OSV query failed: {}", e));
              }
            }
          }
        } else {
          if !is_json {
            Output::spinner_done();
            if source == "osv" {
              Output::warning("OSV requires --ecosystem flag (npm, pypi, cargo, etc.)");
            }
          }
        }
      }
      _ => {}
    }

    // Enrich with CISA KEV
    if !collection.is_empty() {
      if !is_json {
        Output::spinner_start("Checking CISA KEV...");
      }
      let mut kev = KevClient::new();
      for vuln in collection.iter_mut() {
        let _ = kev.enrich_vulnerability(vuln);
      }
      if !is_json {
        Output::spinner_done();
      }
    }

    // Calculate risk scores
    for vuln in collection.iter_mut() {
      vuln.risk_score = Some(calculate_risk_score(vuln));
    }

    // Sort by risk score (highest first)
    let mut vulns: Vec<_> = collection.into_iter().collect();
    vulns.sort_by(|a, b| b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0)));

    let vulnerabilities_json: Vec<crate::serde_json::Value> = vulns
      .iter()
      .take(limit)
      .map(intel_vuln_summary_to_json)
      .collect();
    let payload = json!({
        "technology": tech.clone(),
        "version": version.clone(),
        "source": source.clone(),
        "total_count": vulns.len(),
        "vulnerabilities": vulnerabilities_json
    });
    if render::render_machine_output(ctx, "rb intel vuln search", &payload)? {
      return Ok(());
    }

    // Display results
    println!();
    if vulns.is_empty() {
      Output::info("No vulnerabilities found.");
      return Ok(());
    }

    Output::header(&format!(
      "Results ({} total, showing top {})",
      vulns.len(),
      limit.min(vulns.len())
    ));
    println!();

    for vuln in vulns.iter().take(limit) {
      self.display_vuln_summary(vuln);
    }

  Ok(())
  }

  /// Get detailed CVE information
  fn get_cve(&self, ctx: &CliContext) -> Result<(), String> {
    let cve_id = ctx.target.as_ref().ok_or("Missing CVE ID")?;
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    // Validate CVE format
    if !cve_id.to_uppercase().starts_with("CVE-") {
      return Err(format!(
        "Invalid CVE ID format: {}. Expected: CVE-YYYY-NNNNN",
        cve_id
      ));
    }

    if !is_json {
      Output::header(&format!("CVE Details: {}", cve_id));
      println!();
    }

    // Query NVD
    if !is_json {
      Output::spinner_start("Querying NVD...");
    }
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
          render::render_machine_output(
            ctx,
            "rb intel vuln cve",
            &json!({
              "error": "CVE not found",
              "cve_id": cve_id.clone()
            }),
          )?;
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

    let payload = intel_vuln_detail_to_json(&vuln);
    if render::render_machine_output(ctx, "rb intel vuln cve", &payload)? {
      return Ok(());
    }

    // Display detailed info
    self.display_vuln_detail(&vuln);

    Ok(())
  }

  /// Check CISA KEV catalog
  fn check_kev(&self, ctx: &CliContext) -> Result<(), String> {
    let vendor = ctx.get_flag_with_config("vendor");
    let product = ctx.get_flag_with_config("product");
    let show_stats = ctx.has_flag("stats");
    let limit: usize = ctx
      .get_flag_with_config("limit")
      .and_then(|s| s.parse().ok())
      .unwrap_or(20);
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

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
        let mut vendors_json = crate::serde_json::Map::new();
        for (vendor, count) in stats.top_vendors.iter().take(10) {
          vendors_json.insert(vendor.clone(), json!(*count));
        }
        let payload = json!({
            "total": stats.total,
            "ransomware_count": stats.ransomware_count,
            "top_vendors": crate::serde_json::Value::Object(vendors_json)
        });
        render::render_machine_output(ctx, "rb intel vuln kev", &payload)?;
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
      let entries_json: Vec<crate::serde_json::Value> = entries
        .iter()
        .take(limit)
        .map(intel_kev_entry_to_json)
        .collect();
      let mut payload = crate::serde_json::Map::new();
      payload.insert("total_count".to_string(), json!(entries.len()));
      if let Some(ref v) = vendor {
        payload.insert("vendor_filter".to_string(), json!(v.clone()));
      }
      if let Some(ref p) = product {
        payload.insert("product_filter".to_string(), json!(p.clone()));
      }
      payload.insert("entries".to_string(), json!(entries_json));
      render::render_machine_output(
        ctx,
        "rb intel vuln kev",
        &crate::serde_json::Value::Object(payload),
      )?;
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
    let query = ctx.target.as_ref().ok_or("Missing search query")?;
    let limit: usize = ctx
      .get_flag_with_config("limit")
      .and_then(|s| s.parse().ok())
      .unwrap_or(20);
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

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

    if is_json {
      let exploits_json: Vec<crate::serde_json::Value> = results
        .iter()
        .take(limit)
        .map(intel_exploit_entry_to_json)
        .collect();
      let payload = json!({
          "query": query.clone(),
          "total_count": results.len(),
          "exploits": exploits_json
      });
      render::render_machine_output(ctx, "rb intel vuln exploit", &payload)?;
      return Ok(());
    }

    if results.is_empty() {
      Output::info("No exploits found.");
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

}
