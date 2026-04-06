//! Database query commands for recon data

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::storage::records::SubdomainSource;
use crate::storage::service::StorageService;

/// List subdomains from the database
pub fn list_subdomains(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain list <DOMAIN> [--db <file>]\nExample: rb recon domain list example.com",
    )?;

  let db_path = StorageService::db_path(domain);
  let mut store = StorageService::global()
    .open_query_manager(&db_path)
    .map_err(|e| format!("Failed to open database: {}", e))?;

  Output::header(&format!("Listing Subdomains for {}", domain));
  Output::item("Database", &db_path.to_string_lossy());
  println!();

  let subdomains = store
    .list_subdomain_records(domain)
    .map_err(|e| format!("Failed to read subdomains: {}", e))?;

  if subdomains.is_empty() {
    Output::info("No subdomains found in the database.");
    return Ok(());
  }

  println!("  {:<40} {:<15} IP ADDRESSES", "SUBDOMAIN", "SOURCE");
  println!("  {}", "─".repeat(75));

  for subdomain in &subdomains {
    let source_str = match subdomain.source {
      SubdomainSource::DnsBruteforce => "Bruteforce",
      SubdomainSource::CertTransparency => "CT Logs",
      SubdomainSource::SearchEngine => "Search Engine",
      SubdomainSource::WebCrawl => "Web Crawl",
    };
    let ips_str = subdomain
      .ips
      .iter()
      .map(|ip| ip.to_string())
      .collect::<Vec<_>>()
      .join(", ");
    println!(
      "  {:<40} {:<15} {}",
      subdomain.subdomain, source_str, ips_str
    );
  }

  Output::success(&format!("Found {} subdomains", subdomains.len()));

  Ok(())
}

/// Get details for a specific subdomain
pub fn get_subdomain(ctx: &CliContext) -> Result<(), String> {
  let subdomain_target = ctx.target.as_ref().ok_or(
        "Missing subdomain.\nUsage: rb recon domain get <SUBDOMAIN> [--db <file>]\nExample: rb recon domain get api.example.com",
    )?;

  // Extract the base domain for db_path
  let domain_for_db = {
    let parts: Vec<&str> = subdomain_target.split('.').collect();
    if parts.len() > 1 {
      parts[parts.len() - 2..].join(".")
    } else {
      subdomain_target.to_string()
    }
  };

  let db_path = StorageService::db_path(&domain_for_db);
  let mut store = StorageService::global()
    .open_query_manager(&db_path)
    .map_err(|e| format!("Failed to open database: {}", e))?;

  Output::header(&format!("Getting Subdomain Info: {}", subdomain_target));
  Output::item("Database", &db_path.to_string_lossy());
  println!();

  // Get all subdomains for the base domain and filter for the specific subdomain
  let all_subdomains_for_domain = store
    .list_subdomain_records(&domain_for_db)
    .map_err(|e| format!("Failed to read subdomains: {}", e))?;
  let subdomain_info: Vec<_> = all_subdomains_for_domain
    .into_iter()
    .filter(|rec| rec.subdomain.as_str() == subdomain_target)
    .collect();

  if subdomain_info.is_empty() {
    Output::info("Subdomain not found in the database.");
    return Ok(());
  }

  let info = &subdomain_info[0];

  let source_str = match info.source {
    SubdomainSource::DnsBruteforce => "Bruteforce",
    SubdomainSource::CertTransparency => "CT Logs",
    SubdomainSource::SearchEngine => "Search Engine",
    SubdomainSource::WebCrawl => "Web Crawl",
  };
  let ips_str = info
    .ips
    .iter()
    .map(|ip| ip.to_string())
    .collect::<Vec<_>>()
    .join(", ");

  println!("  Subdomain: {}", info.subdomain);
  println!("  Source: {}", source_str);
  println!("  IP Addresses: {}", ips_str);

  Ok(())
}

/// Describe domain with summary statistics
pub fn describe_domain(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain describe <DOMAIN> [--db <file>]\nExample: rb recon domain describe example.com",
    )?;

  let db_path = StorageService::db_path(domain);
  let mut store = StorageService::global()
    .open_query_manager(&db_path)
    .map_err(|e| format!("Failed to open database: {}", e))?;

  Output::header(&format!("Describing Domain: {}", domain));
  Output::item("Database", &db_path.to_string_lossy());
  println!();

  let subdomains = store
    .list_subdomain_records(domain)
    .map_err(|e| format!("Failed to read subdomains: {}", e))?;
  let vulns = store
    .list_vulnerabilities()
    .map_err(|e| format!("Failed to read vulnerabilities: {}", e))?;

  println!("\x1b[1mSubdomains:\x1b[0m {}", subdomains.len());
  println!("\x1b[1mVulnerabilities:\x1b[0m {}", vulns.len());

  // Print top 5 subdomains
  if !subdomains.is_empty() {
    println!();
    println!("  Top 5 Subdomains:");
    for subdomain in subdomains.iter().take(5) {
      println!("    • {}", subdomain.subdomain);
    }
    if subdomains.len() > 5 {
      println!("    ... and {} more", subdomains.len() - 5);
    }
  }

  // Print top 5 vulnerabilities
  if !vulns.is_empty() {
    println!();
    println!("  Top 5 Vulnerabilities:");
    let mut sorted_vulns = vulns;
    sorted_vulns.sort_by(|a, b| {
      b.cvss
        .partial_cmp(&a.cvss)
        .unwrap_or(std::cmp::Ordering::Equal)
    });
    for vuln in sorted_vulns.iter().take(5) {
      println!(
        "    • {} (CVSS {:.1}) - {}",
        vuln.cve_id, vuln.cvss, vuln.technology
      );
    }
    if sorted_vulns.len() > 5 {
      println!("    ... and {} more", sorted_vulns.len() - 5);
    }
  }

  Ok(())
}

/// Display domain recon data as a tree graph
pub fn graph(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain graph <DOMAIN> [--db <file>] [--depth N]\nExample: rb recon domain graph example.com",
    )?;

  let db_path = StorageService::db_path(domain);
  let depth: usize = ctx
    .get_flag("depth")
    .unwrap_or_else(|| "5".to_string())
    .parse()
    .unwrap_or(5)
    .max(1);
  let _no_color = ctx.has_flag("no-color");

  let mut store = StorageService::global()
    .open_query_manager(&db_path)
    .map_err(|e| format!("Failed to open database: {}", e))?;

  Output::header(&format!("Domain Graph: {}", domain));
  Output::item("Database", &db_path.to_string_lossy());
  println!();

  let subdomains = store
    .list_subdomain_records(domain)
    .map_err(|e| format!("Failed to read subdomains: {}", e))?;
  let dns_records = store
    .list_dns_records(domain)
    .map_err(|e| format!("Failed to read DNS records: {}", e))?;
  let all_ports = store
    .list_port_scans()
    .map_err(|e| format!("Failed to read ports: {}", e))?;

  println!("{}  {}", "└──", domain);

  let mut lines: Vec<String> = Vec::new();

  let max_subdomains = depth.min(subdomains.len());
  for sub in subdomains.iter().take(max_subdomains) {
    let sub_ips = sub
      .ips
      .iter()
      .map(|ip| ip.to_string())
      .collect::<Vec<_>>()
      .join(", ");
    lines.push(format!("{} ({})", sub.subdomain, sub_ips));
  }
  if max_subdomains < subdomains.len() {
    lines.push(format!(
      "... and {} more subdomains",
      subdomains.len() - max_subdomains
    ));
  }

  // Print DNS records summary
  let ns_count = dns_records
    .iter()
    .filter(|r| r.record_type == crate::storage::records::DnsRecordType::NS)
    .count();
  let mx_count = dns_records
    .iter()
    .filter(|r| r.record_type == crate::storage::records::DnsRecordType::MX)
    .count();
  if ns_count > 0 || mx_count > 0 {
    lines.push(format!("DNS: {} NS, {} MX records", ns_count, mx_count));
  }

  // Print ports summary
  if !all_ports.is_empty() {
    lines.push(format!("Ports: {} discovered", all_ports.len()));
  }

  for (i, line) in lines.iter().enumerate() {
    let prefix = if i + 1 == lines.len() {
      "   └──"
    } else {
      "   ├──"
    };
    println!("{} {}", prefix, line);
  }

  if lines.is_empty() {
    println!("   └── No related records found");
  }

  Ok(())
}
