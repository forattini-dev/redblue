impl IntelCommand {
  /// Output report as JSON
  fn output_report_json(&self, report: &CorrelationReport) -> crate::serde_json::Value {
    let summary = &report.summary;
    let top_risks_json: Vec<crate::serde_json::Value> = report
      .top_risks(10)
      .iter()
      .map(intel_report_top_risk_to_json)
      .collect();
    json!({
        "total_technologies": summary.techs_scanned,
        "technologies_with_vulns": summary.techs_vulnerable,
        "total_vulnerabilities": summary.total_vulns,
        "critical": summary.critical_count,
        "high": summary.high_count,
        "medium": summary.medium_count,
        "low": summary.low_count,
        "kev_count": summary.kev_count,
        "exploit_count": summary.exploitable_count,
        "top_risks": top_risks_json
    })
  }

  /// Output report as Markdown
  fn output_report_markdown(&self, url: &str, techs: &[DetectedTech], report: &CorrelationReport) {
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
      let exp_badge = if vuln.has_exploit() {
        " ⚠️ **Exploit**"
      } else {
        ""
      };
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
  fn output_report_text(&self, url: &str, techs: &[DetectedTech], report: &CorrelationReport) {
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
    let response = client
      .get(url)
      .map_err(|e| format!("HTTP request failed: {}", e))?;

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

fn intel_vuln_summary_to_json(vuln: &Vulnerability) -> crate::serde_json::Value {
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

fn intel_vuln_detail_to_json(vuln: &Vulnerability) -> crate::serde_json::Value {
  let exploits_json: Vec<crate::serde_json::Value> = vuln
    .exploits
    .iter()
    .map(|exp| {
      json!({
          "source": exp.source.clone(),
          "url": exp.url.clone(),
          "title": exp.title.clone().unwrap_or_default()
      })
    })
    .collect();
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
      "cwes": vuln.cwes.clone(),
      "exploits": exploits_json,
      "references": vuln.references.clone()
  })
}

fn intel_kev_entry_to_json(
  entry: &crate::modules::recon::vuln::kev::KevEntry,
) -> crate::serde_json::Value {
  json!({
      "cve_id": entry.cve_id.clone(),
      "title": entry.vulnerability_name.replace('\n', " "),
      "vendor": entry.vendor_project.clone(),
      "product": entry.product.clone(),
      "date_added": entry.date_added.clone(),
      "due_date": entry.due_date.clone(),
      "ransomware": entry.known_ransomware_use
  })
}

fn intel_exploit_entry_to_json(
  entry: &crate::modules::recon::vuln::exploitdb::ExploitDbEntry,
) -> crate::serde_json::Value {
  json!({
      "id": entry.id.clone(),
      "title": entry.title.replace('\n', " "),
      "platform": entry.platform.clone(),
      "type": entry.exploit_type.clone(),
      "date": entry.date.clone(),
      "cves": entry.cve_ids.clone(),
      "verified": entry.verified
  })
}

fn intel_cpe_mapping_to_json(
  cpe: &&crate::modules::recon::vuln::cpe::CpeMapping,
) -> crate::serde_json::Value {
  let example_cpe = generate_cpe(cpe.tech_name, Some("1.0")).unwrap_or_default();
  json!({
      "tech_name": cpe.tech_name,
      "vendor": cpe.vendor,
      "product": cpe.product,
      "category": format!("{:?}", cpe.category),
      "cpe_example": example_cpe
  })
}

fn detected_tech_to_json(tech: &DetectedTech) -> crate::serde_json::Value {
  json!({
      "name": tech.name.clone(),
      "version": tech.version.clone(),
      "confidence": tech.confidence
  })
}

fn intel_top_risk_to_json(vuln: &&Vulnerability) -> crate::serde_json::Value {
  json!({
      "id": vuln.id.clone(),
      "risk_score": vuln.risk_score.unwrap_or(0),
      "severity": format!("{:?}", vuln.severity),
      "kev": vuln.cisa_kev,
      "has_exploit": vuln.has_exploit()
  })
}

fn intel_report_top_risk_to_json(vuln: &&Vulnerability) -> crate::serde_json::Value {
  json!({
      "id": vuln.id.clone(),
      "risk_score": vuln.risk_score.unwrap_or(0),
      "severity": format!("{:?}", vuln.severity),
      "kev": vuln.cisa_kev,
      "title": vuln.title.clone()
  })
}
