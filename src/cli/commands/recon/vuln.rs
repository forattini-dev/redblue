//! Vulnerability scanning for web targets

use super::map_to_osv_ecosystem;
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::recon::vuln::{NvdClient, OsvClient, Vulnerability};
use crate::modules::web::fingerprinter::{FingerprintResult, WebFingerprinter};

/// Generate CPE identifier for a technology
fn generate_cpe(name: &str, version: Option<&str>) -> Option<String> {
  let name_lower = name.to_lowercase();
  let version_str = version.unwrap_or("*");

  // Map common technology names to CPE vendor:product format
  let (vendor, product) = match name_lower.as_str() {
    "nginx" => ("nginx", "nginx"),
    "apache" | "apache httpd" => ("apache", "http_server"),
    "php" => ("php", "php"),
    "python" => ("python", "python"),
    "node.js" | "nodejs" => ("nodejs", "node.js"),
    "jquery" => ("jquery", "jquery"),
    "wordpress" => ("wordpress", "wordpress"),
    "drupal" => ("drupal", "drupal"),
    "joomla" => ("joomla", "joomla"),
    "react" => ("facebook", "react"),
    "angular" => ("google", "angular"),
    "vue.js" | "vue" => ("vuejs", "vue.js"),
    "express" => ("expressjs", "express"),
    "django" => ("djangoproject", "django"),
    "flask" => ("palletsprojects", "flask"),
    "spring" => ("vmware", "spring_framework"),
    "tomcat" => ("apache", "tomcat"),
    "iis" => ("microsoft", "iis"),
    "openssl" => ("openssl", "openssl"),
    _ => return None,
  };

  Some(format!(
    "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
    vendor, product, version_str
  ))
}

/// Vulnerability scan based on web fingerprinting
pub fn vuln(ctx: &CliContext) -> Result<(), String> {
  let target = ctx.target.as_ref().ok_or(
        "Missing URL.\nUsage: rb recon domain vuln <URL> [--source nvd|osv|all] [--limit N]\nExample: rb recon domain vuln http://example.com",
    )?;

  // Basic URL validation
  if !target.starts_with("http://") && !target.starts_with("https://") {
    return Err("Invalid URL. Must start with http:// or https://".to_string());
  }

  let source = ctx.get_flag("source").unwrap_or_else(|| "nvd".to_string());
  let limit: usize = ctx
    .get_flag("limit")
    .unwrap_or_else(|| "20".to_string())
    .parse()
    .unwrap_or(20);

  if !ctx.wants_machine_output() {
    Output::header(&format!("Vulnerability Scan: {}", target));
    Output::item("Source", &source);
    Output::item("Limit", &limit.to_string());
    println!();
  }

  let fingerprinter = WebFingerprinter::new();
  let mut nvd_client = NvdClient::new();
  let osv_client = OsvClient::new();

  // Get API keys from flags if provided
  if let Some(api_key) = ctx.get_flag("api-key") {
    nvd_client = nvd_client.with_api_key(&api_key);
  }

  if !ctx.wants_machine_output() {
    Output::spinner_start("Fingerprinting target...");
  }
  let fingerprint_result = fingerprinter.fingerprint(target)?;
  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  if render::render_machine_output(
    ctx,
    "rb recon domain vuln",
    &vuln_scan_payload(target, &source, limit, &fingerprint_result, &[]),
  )? && fingerprint_result.technologies.is_empty()
  {
    return Ok(());
  }

  if fingerprint_result.technologies.is_empty() {
    Output::warning("No technologies detected on target.");
    return Ok(());
  }

  println!();
  Output::subheader(&format!(
    "Detected Technologies ({})",
    fingerprint_result.technologies.len()
  ));
  for tech in &fingerprint_result.technologies {
    let conf = match tech.confidence {
      crate::modules::web::fingerprinter::Confidence::High => "High",
      crate::modules::web::fingerprinter::Confidence::Medium => "Medium",
      crate::modules::web::fingerprinter::Confidence::Low => "Low",
    };
    println!("  • {} (Confidence: {})", tech.name, conf);
  }
  println!();

  let mut all_vulns: Vec<Vulnerability> = Vec::new();

  // Scan NVD if requested
  if source == "nvd" || source == "all" {
    if !ctx.wants_machine_output() {
      Output::spinner_start("Querying NVD for vulnerabilities...");
    }
    for tech in &fingerprint_result.technologies {
      if let Some(cpe) = generate_cpe(&tech.name, tech.version.as_deref()) {
        match nvd_client.query_by_cpe(&cpe) {
          Ok(mut vulns) => {
            all_vulns.append(&mut vulns);
          }
          Err(e) => {
            eprintln!("Warning: NVD query failed for {}: {}", cpe, e);
          }
        }
      }
    }
    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }
  }

  // Scan OSV if requested
  if source == "osv" || source == "all" {
    if !ctx.wants_machine_output() {
      Output::spinner_start("Querying OSV for vulnerabilities...");
    }
    for tech in &fingerprint_result.technologies {
      if let Some(ecosystem) = map_to_osv_ecosystem(&tech.name) {
        match osv_client.query_package(&tech.name, tech.version.as_deref(), ecosystem) {
          Ok(mut vulns) => {
            all_vulns.append(&mut vulns);
          }
          Err(e) => {
            eprintln!("Warning: OSV query failed for tech {}: {}", tech.name, e);
          }
        }
      }
    }
    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }
  }

  // Deduplicate and sort vulnerabilities
  all_vulns.sort_by(|a, b| a.id.cmp(&b.id));
  all_vulns.dedup_by(|a, b| a.id == b.id);
  all_vulns.sort_by(|a, b| {
    let cvss_a = a.cvss_v3.or(a.cvss_v2).unwrap_or(0.0);
    let cvss_b = b.cvss_v3.or(b.cvss_v2).unwrap_or(0.0);
    cvss_b
      .partial_cmp(&cvss_a)
      .unwrap_or(std::cmp::Ordering::Equal)
  });

  let payload = vuln_scan_payload(target, &source, limit, &fingerprint_result, &all_vulns);
  if render::render_machine_output(ctx, "rb recon domain vuln", &payload)? {
    return Ok(());
  }

  if all_vulns.is_empty() {
    Output::info("No known vulnerabilities found for detected technologies.");
    return Ok(());
  }

  println!();
  Output::subheader(&format!(
    "Found {} Vulnerabilities (Top {})",
    all_vulns.len(),
    limit
  ));
  println!();

  for vuln in all_vulns.iter().take(limit) {
    let cvss_score = vuln.cvss_v3.or(vuln.cvss_v2).unwrap_or(0.0);
    let severity = match cvss_score {
      s if s >= 9.0 => "CRITICAL",
      s if s >= 7.0 => "HIGH",
      s if s >= 4.0 => "MEDIUM",
      _ => "LOW",
    };
    let severity_color = match severity {
      "CRITICAL" => "\x1b[1;31m",
      "HIGH" => "\x1b[31m",
      "MEDIUM" => "\x1b[33m",
      _ => "\x1b[36m",
    };

    println!(
      "  {}{}● {} (CVSS {:.1})\x1b[0m",
      severity_color, severity_color, vuln.id, cvss_score
    );
    println!(
      "    └─ {}",
      vuln.description.chars().take(100).collect::<String>()
    );
    println!();
  }

  if all_vulns.len() > limit {
    println!(
      "  ... and {} more vulnerabilities found.\n",
      all_vulns.len() - limit
    );
  }

  Output::success(&format!("Found {} vulnerabilities", all_vulns.len()));

  Ok(())
}

fn fingerprint_payload(fingerprint_result: &FingerprintResult) -> crate::serde_json::Value {
  let technologies: Vec<_> = fingerprint_result
    .technologies
    .iter()
    .map(|tech| {
      json!({
        "name": tech.name,
        "category": format!("{:?}", tech.category),
        "version": tech.version,
        "confidence": tech.confidence.to_string(),
      })
    })
    .collect();

  json!({
    "url": fingerprint_result.url,
    "technologies": technologies,
    "cms": fingerprint_result.cms,
    "web_server": fingerprint_result.web_server,
    "programming_language": fingerprint_result.programming_language,
    "frameworks": fingerprint_result.frameworks,
  })
}

fn vulnerability_payload(vuln: &Vulnerability) -> crate::serde_json::Value {
  let exploits: Vec<_> = vuln
    .exploits
    .iter()
    .map(|exploit| {
      json!({
        "source": exploit.source,
        "url": exploit.url,
        "title": exploit.title,
        "exploit_type": exploit.exploit_type,
      })
    })
    .collect();
  let sources: Vec<_> = vuln.sources.iter().map(|source| source.as_str()).collect();

  json!({
    "id": vuln.id,
    "title": vuln.title,
    "description": vuln.description,
    "cvss_v3": vuln.cvss_v3,
    "cvss_v2": vuln.cvss_v2,
    "severity": vuln.severity.as_str(),
    "published": vuln.published,
    "modified": vuln.modified,
    "references": vuln.references,
    "exploits": exploits,
    "cisa_kev": vuln.cisa_kev,
    "kev_due_date": vuln.kev_due_date,
    "affected_cpes": vuln.affected_cpes,
    "sources": sources,
    "cwes": vuln.cwes,
    "risk_score": vuln.risk_score,
  })
}

fn vuln_scan_payload(
  target: &str,
  source: &str,
  limit: usize,
  fingerprint_result: &FingerprintResult,
  vulnerabilities: &[Vulnerability],
) -> crate::serde_json::Value {
  let vulnerabilities_json: Vec<_> = vulnerabilities
    .iter()
    .take(limit)
    .map(vulnerability_payload)
    .collect();

  json!({
    "target": target,
    "source": source,
    "limit": limit,
    "fingerprint": fingerprint_payload(fingerprint_result),
    "vulnerability_count": vulnerabilities.len(),
    "vulnerabilities": vulnerabilities_json,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::modules::common::Severity;
  use crate::modules::recon::vuln::{ExploitRef, VulnSource};
  use crate::modules::web::fingerprinter::{Confidence, TechCategory, Technology};

  #[test]
  fn fingerprint_payload_includes_technologies() {
    let payload = fingerprint_payload(&FingerprintResult {
      url: "https://example.com".to_string(),
      technologies: vec![Technology {
        name: "Nginx".to_string(),
        category: TechCategory::WebServer,
        version: Some("1.24.0".to_string()),
        confidence: Confidence::High,
      }],
      cms: None,
      web_server: Some("Nginx".to_string()),
      programming_language: None,
      frameworks: vec![],
    });

    assert_eq!(payload["technologies"][0]["name"].as_str(), Some("Nginx"));
    assert_eq!(
      payload["technologies"][0]["confidence"].as_str(),
      Some("HIGH")
    );
  }

  #[test]
  fn vuln_scan_payload_includes_vulnerabilities() {
    let payload = vuln_scan_payload(
      "https://example.com",
      "nvd",
      10,
      &FingerprintResult {
        url: "https://example.com".to_string(),
        technologies: vec![],
        cms: None,
        web_server: None,
        programming_language: None,
        frameworks: vec![],
      },
      &[Vulnerability {
        id: "CVE-2026-0001".to_string(),
        title: "Example vuln".to_string(),
        description: "Example description".to_string(),
        cvss_v3: Some(9.8),
        cvss_v2: None,
        severity: Severity::Critical,
        published: Some("2026-01-01".to_string()),
        modified: None,
        references: vec!["https://example.com/advisory".to_string()],
        exploits: vec![ExploitRef {
          source: "exploit-db".to_string(),
          url: "https://exploit-db.com/exploits/1".to_string(),
          title: Some("Exploit".to_string()),
          exploit_type: Some("poc".to_string()),
        }],
        cisa_kev: false,
        kev_due_date: None,
        affected_versions: vec![],
        affected_cpes: vec!["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*".to_string()],
        sources: vec![VulnSource::Nvd],
        cwes: vec!["CWE-79".to_string()],
        risk_score: Some(95),
      }],
    );

    assert_eq!(payload["vulnerability_count"].as_u64(), Some(1));
    assert_eq!(
      payload["vulnerabilities"][0]["id"].as_str(),
      Some("CVE-2026-0001")
    );
    assert_eq!(
      payload["vulnerabilities"][0]["severity"].as_str(),
      Some("critical")
    );
  }
}
