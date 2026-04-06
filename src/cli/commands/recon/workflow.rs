//! Full recon workflow and findings display

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::common::Severity;
use crate::modules::network::scanner::PortScanner;
use crate::modules::recon::vuln::{calculate_risk_score, generate_cpe, NvdClient};
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::protocols::dns::{DnsClient, DnsRdata, DnsRecordType};
use crate::storage::records::{PortScanRecord, VulnerabilityRecord};
use crate::storage::service::StorageService;
use crate::storage::PersistenceConfig;
use std::collections::HashSet;
use std::net::IpAddr;

/// Full reconnaissance workflow - runs all scans and saves to database
pub fn full_recon(ctx: &CliContext) -> Result<(), String> {
  let target = ctx.target.as_ref().ok_or(
        "Missing target.\nUsage: rb recon domain full <target>\nExample: rb recon domain full example.com",
    )?;

  let start_time = std::time::Instant::now();

  Output::header(&format!("Full Reconnaissance: {}", target));
  println!();
  println!("This will run: Port Scan → DNS → Web Fingerprint → Vulnerability Scan");
  println!("All results are saved automatically for attack planning.");
  println!();

  // Determine if target is IP or domain
  let target_is_ip = target.parse::<std::net::IpAddr>().is_ok();
  let scan_url = if target.starts_with("http://") || target.starts_with("https://") {
    target.to_string()
  } else if target_is_ip {
    format!("http://{}", target)
  } else {
    format!("http://{}", target)
  };

  // Initialize storage
  let db_path = StorageService::db_path(target);
  let mut store = StorageService::global()
    .persistence_with_config(
      target,
      PersistenceConfig {
        force_save: true,
        ..Default::default()
      },
      Vec::<(String, String)>::new(),
    )
    .map_err(|e| format!("Failed to open database: {}", e))?;

  // === PHASE 1: Port Scan ===
  println!("\x1b[1;36m[1/4] Port Scanning\x1b[0m");
  Output::spinner_start("Scanning common ports...");

  // Common ports preset
  let common_ports: Vec<u16> = vec![
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432,
    5900, 8080, 8443, 8888,
  ];

  let mut port_results = Vec::new();
  let mut resolved_ip: Option<IpAddr> = None;

  if target_is_ip {
    resolved_ip = Some(target.parse().unwrap());
  } else {
    // Resolve domain
    let dns_client = DnsClient::new("8.8.8.8");
    if let Ok(ips) = dns_client.query(target, DnsRecordType::A).map(|answers| {
      answers
        .into_iter()
        .filter_map(|ans| ans.as_ip().and_then(|ip_str| ip_str.parse::<IpAddr>().ok()))
        .collect::<Vec<_>>()
    }) {
      if let Some(ip) = ips.first() {
        resolved_ip = Some(*ip);
      }
    }
  }

  if let Some(ip) = resolved_ip {
    let scanner = PortScanner::new(ip).with_threads(200).with_timeout(1000);

    let results = scanner.scan_ports(&common_ports);
    let open_count = results.iter().filter(|r| r.is_open).count();

    for result in &results {
      if result.is_open {
        let record = PortScanRecord {
          ip,
          port: result.port,
          status: crate::storage::records::PortStatus::Open,
          service_id: 0,
          timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32,
        };
        port_results.push(record.clone());
        let _ = store.add_port_scan(ip, result.port, 0, record.service_id);
      }
    }

    Output::spinner_done();
    println!("  ✓ Found {} open ports", open_count);

    if open_count > 0 {
      let ports_str: Vec<String> = port_results.iter().map(|p| p.port.to_string()).collect();
      println!("    Ports: {}", ports_str.join(", "));
    }
  } else {
    Output::spinner_done();
    println!("  ⚠ Could not resolve target IP");
  }

  // === PHASE 2: DNS Enumeration ===
  println!();
  println!("\x1b[1;36m[2/4] DNS Enumeration\x1b[0m");

  if !target_is_ip {
    Output::spinner_start("Querying DNS records...");

    let dns_client = DnsClient::new("8.8.8.8");

    // Get A records
    let a_answers = dns_client
      .query(target, DnsRecordType::A)
      .unwrap_or_default();
    let a_records = a_answers
      .iter()
      .filter_map(|ans| ans.as_ip().and_then(|ip_str| ip_str.parse::<IpAddr>().ok()))
      .collect::<Vec<_>>();

    for ans in &a_answers {
      let value = ans.display_value();
      let _ = store.add_dns_record(target, ans.record_type, ans.ttl, &value);
    }

    // Get MX records
    let mx_answers = dns_client
      .query(target, DnsRecordType::MX)
      .unwrap_or_default();
    let mx_count = mx_answers.len();
    for ans in &mx_answers {
      let value = ans.display_value();
      let _ = store.add_dns_record(target, ans.record_type, ans.ttl, &value);
    }

    // Get NS records
    let ns_answers = dns_client
      .query(target, DnsRecordType::NS)
      .unwrap_or_default();
    let ns_count = ns_answers.len();
    for ans in &ns_answers {
      let value = ans.display_value();
      let _ = store.add_dns_record(target, ans.record_type, ans.ttl, &value);
    }

    Output::spinner_done();
    println!("  ✓ A records: {}", a_records.len());
    println!("  ✓ MX records: {}", mx_count);
    println!("  ✓ NS records: {}", ns_count);

    if !a_records.is_empty() {
      let ips: Vec<String> = a_records.iter().map(|ip| ip.to_string()).collect();
      if !ips.is_empty() {
        println!("    IPs: {}", ips.join(", "));
      }
    }
  } else {
    println!("  ⊘ Skipped (target is IP)");
  }

  // === PHASE 3: Web Fingerprinting ===
  println!();
  println!("\x1b[1;36m[3/4] Web Fingerprinting\x1b[0m");

  let has_web = port_results
    .iter()
    .any(|p| matches!(p.port, 80 | 443 | 8080 | 8443));

  // Store fingerprints as simple structs
  #[derive(Clone)]
  struct TechFingerprint {
    technology: String,
    version: Option<String>,
    #[allow(dead_code)]
    confidence: u8,
  }

  let mut fingerprints: Vec<TechFingerprint> = Vec::new();
  if has_web || !target_is_ip {
    Output::spinner_start("Detecting technologies...");

    let fingerprinter = WebFingerprinter::new();

    // Try HTTPS first, then HTTP
    let urls_to_try = if scan_url.starts_with("http") {
      vec![scan_url.clone()]
    } else {
      vec![format!("https://{}", target), format!("http://{}", target)]
    };

    for url in urls_to_try {
      if let Ok(result) = fingerprinter.fingerprint(&url) {
        for tech in result.technologies {
          use crate::modules::web::fingerprinter::Confidence;
          let conf_num = match tech.confidence {
            Confidence::High => 90,
            Confidence::Medium => 60,
            Confidence::Low => 30,
          };
          let fp = TechFingerprint {
            technology: tech.name.clone(),
            version: tech.version.clone(),
            confidence: conf_num,
          };
          fingerprints.push(fp);
        }
        if !fingerprints.is_empty() {
          break;
        }
      }
    }

    Output::spinner_done();

    if fingerprints.is_empty() {
      println!("  ⚠ No technologies detected");
    } else {
      println!("  ✓ Detected {} technologies", fingerprints.len());
      for fp in fingerprints.iter().take(5) {
        let version = fp.version.as_deref().unwrap_or("");
        println!("    • {} {}", fp.technology, version);
      }
      if fingerprints.len() > 5 {
        println!("    ... and {} more", fingerprints.len() - 5);
      }
    }
  } else {
    println!("  ⊘ Skipped (no web ports detected)");
  }

  // === PHASE 4: Vulnerability Scan ===
  println!();
  println!("\x1b[1;36m[4/4] Vulnerability Scan\x1b[0m");

  let mut vulns = Vec::new();
  if !fingerprints.is_empty() {
    Output::spinner_start("Searching vulnerabilities...");

    let mut nvd_client = NvdClient::new();

    for fp in &fingerprints {
      let version = fp.version.as_deref();
      if let Some(cpe) = generate_cpe(&fp.technology, version) {
        if let Ok(cve_list) = nvd_client.query_by_cpe(&cpe) {
          for cve in cve_list.into_iter().take(5) {
            let cvss_score = cve.cvss_v3.or(cve.cvss_v2).unwrap_or(0.0);

            let severity = match cvss_score {
              s if s >= 9.0 => Severity::Critical,
              s if s >= 7.0 => Severity::High,
              s if s >= 4.0 => Severity::Medium,
              s if s > 0.0 => Severity::Low,
              _ => Severity::Info,
            };

            let risk_score = calculate_risk_score(&cve);

            let record = VulnerabilityRecord {
              cve_id: cve.id.clone(),
              technology: fp.technology.clone(),
              version: fp.version.clone(),
              cvss: cvss_score,
              risk_score,
              severity,
              description: cve.description.chars().take(200).collect(),
              references: cve.references.clone(),
              exploit_available: false,
              in_kev: false,
              discovered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32,
              source: "nvd".to_string(),
            };
            vulns.push(record.clone());
            let _ = store.add_vulnerability(record.clone());
          }
        }
      }
    }

    Output::spinner_done();

    if vulns.is_empty() {
      println!("  ✓ No known vulnerabilities found");
    } else {
      let critical = vulns
        .iter()
        .filter(|v| matches!(v.severity, Severity::Critical))
        .count();
      let high = vulns
        .iter()
        .filter(|v| matches!(v.severity, Severity::High))
        .count();

      println!("  ⚠ Found {} vulnerabilities", vulns.len());
      if critical > 0 {
        println!("    \x1b[1;31m• {} CRITICAL\x1b[0m", critical);
      }
      if high > 0 {
        println!("    \x1b[31m• {} HIGH\x1b[0m", high);
      }

      // Show top CVEs
      let mut sorted = vulns.clone();
      sorted.sort_by(|a, b| {
        b.cvss
          .partial_cmp(&a.cvss)
          .unwrap_or(std::cmp::Ordering::Equal)
      });
      for v in sorted.iter().take(3) {
        println!("    • {} (CVSS {:.1})", v.cve_id, v.cvss);
      }
    }
  } else {
    println!("  ⊘ Skipped (no technologies to check)");
  }

  // === SUMMARY ===
  let elapsed = std::time::Instant::now().duration_since(start_time);
  println!();
  Output::header("Reconnaissance Complete");
  println!();
  Output::item("Target", target);
  Output::item("Duration", &format!("{:.1}s", elapsed.as_secs_f64()));
  Output::item("Open Ports", &port_results.len().to_string());
  Output::item("Technologies", &fingerprints.len().to_string());
  Output::item("Vulnerabilities", &vulns.len().to_string());
  Output::item("Database", &db_path.to_string_lossy());

  println!();
  Output::success("Data saved. Next steps:");
  println!();
  println!("  \x1b[1;36m1. View findings:\x1b[0m");
  println!("     rb recon domain show {}", target);
  println!();
  println!("  \x1b[1;36m2. Get attack recommendations:\x1b[0m");
  println!("     rb attack target plan {}", target);
  println!();
  println!("  \x1b[1;36m3. Execute a playbook:\x1b[0m");
  println!("     rb attack target run <playbook> {}", target);

  Ok(())
}

/// Show consolidated findings for a target
pub fn show_findings(ctx: &CliContext) -> Result<(), String> {
  let target = ctx.target.as_ref().ok_or(
        "Missing target.\nUsage: rb recon domain show <target>\nExample: rb recon domain show example.com",
    )?;

  Output::header(&format!("Reconnaissance Findings: {}", target));

  let db_path = StorageService::db_path(target);
  let mut store = match StorageService::global().open_query_manager(db_path) {
    Ok(s) => s,
    Err(_) => {
      println!();
      Output::warning(&format!("No data found for '{}'", target));
      println!();
      Output::info("Run reconnaissance first:");
      println!("  \x1b[1;36mrb recon domain full {}\x1b[0m", target);
      return Ok(());
    }
  };

  // === PORTS ===
  println!();
  Output::section("Open Ports");

  // Get ports by trying to resolve target IP
  let target_ip: Option<std::net::IpAddr> = if target.parse::<std::net::IpAddr>().is_ok() {
    target.parse().ok()
  } else {
    // Try to resolve domain
    let dns = DnsClient::new("8.8.8.8");
    dns
      .query(target, DnsRecordType::A)
      .ok()
      .and_then(|answers| {
        answers.into_iter().find_map(|ans| {
          if let DnsRdata::A(ip_str) = ans.data {
            ip_str.parse::<std::net::IpAddr>().ok()
          } else {
            None
          }
        })
      })
  };

  let port_scans = store.list_port_scans().unwrap_or_default();
  let ports = if let Some(ip) = target_ip {
    port_scans
      .into_iter()
      .filter(|record| record.ip == ip)
      .collect()
  } else {
    Vec::new()
  };
  let open_ports: Vec<_> = ports
    .iter()
    .filter(|p| p.status == crate::storage::records::PortStatus::Open)
    .collect();

  if open_ports.is_empty() {
    println!("  No open ports found");
  } else {
    for port in &open_ports {
      let service = match port.port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        _ => "Unknown",
      };
      println!(
        "  \x1b[32m●\x1b[0m {} ({}) - {}",
        port.port, service, port.ip
      );
    }
  }

  // === OS DETECTION ===
  let detected_os = if open_ports.iter().any(|p| p.port == 3389)
    || (open_ports.iter().any(|p| p.port == 445) && !open_ports.iter().any(|p| p.port == 22))
  {
    Some("Windows")
  } else if open_ports.iter().any(|p| p.port == 22) && !open_ports.iter().any(|p| p.port == 445) {
    Some("Linux")
  } else {
    None
  };

  if let Some(os) = detected_os {
    println!();
    Output::section("Detected OS");
    println!("  \x1b[1m{}\x1b[0m (inferred from ports)", os);
  }

  // === TECHNOLOGIES ===
  println!();
  Output::section("Technologies");

  let vulns = store.list_vulnerabilities().unwrap_or_default();
  let unique_techs: HashSet<&String> = vulns.iter().map(|v| &v.technology).collect();

  if unique_techs.is_empty() {
    println!("  No technologies detected (run full recon to detect)");
  } else {
    for tech in unique_techs {
      println!("  • \x1b[1m{}\x1b[0m (from vulnerability data)", tech);
    }
  }

  // === VULNERABILITIES ===
  println!();
  Output::section("Vulnerabilities");
  if vulns.is_empty() {
    println!("  \x1b[32m✓\x1b[0m No known vulnerabilities");
  } else {
    let mut sorted = vulns.clone();
    sorted.sort_by(|a, b| {
      b.cvss
        .partial_cmp(&a.cvss)
        .unwrap_or(std::cmp::Ordering::Equal)
    });

    let critical = sorted
      .iter()
      .filter(|v| matches!(v.severity, Severity::Critical))
      .count();
    let high = sorted
      .iter()
      .filter(|v| matches!(v.severity, Severity::High))
      .count();
    let medium = sorted
      .iter()
      .filter(|v| matches!(v.severity, Severity::Medium))
      .count();

    println!("  Found {} vulnerabilities:", sorted.len());
    if critical > 0 {
      println!("    \x1b[1;31m● {} CRITICAL\x1b[0m", critical);
    }
    if high > 0 {
      println!("    \x1b[31m● {} HIGH\x1b[0m", high);
    }
    if medium > 0 {
      println!("    \x1b[33m● {} MEDIUM\x1b[0m", medium);
    }

    println!();
    println!("  Top CVEs:");
    for v in sorted.iter().take(10) {
      let sev_color = match v.severity {
        Severity::Critical => "\x1b[1;31m",
        Severity::High => "\x1b[31m",
        Severity::Medium => "\x1b[33m",
        _ => "\x1b[0m",
      };
      println!(
        "  {}• {}\x1b[0m (CVSS {:.1}) - {}",
        sev_color, v.cve_id, v.cvss, v.technology
      );
    }
    if sorted.len() > 10 {
      println!("  ... and {} more", sorted.len() - 10);
    }
  }

  // === NEXT STEPS ===
  println!();
  Output::section("Next Steps");
  println!();
  Output::success("1. View findings:");
  println!("     rb recon domain show {}", target);
  println!();
  Output::success("2. Get attack recommendations:");
  println!("     rb attack target plan {}", target);
  println!();
  Output::success("3. Execute a playbook:");
  println!("     rb attack target run <playbook> {}", target);

  Ok(())
}
