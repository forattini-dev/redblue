use super::IntelIocCommand;
use crate::cli::{output::Output, render, CliContext};
use crate::modules::intel::{Ioc, IocCollection, IocConfidence, IocExtractor, IocSource, IocType};
use std::net::Ipv4Addr;

pub(super) fn extract_iocs(_self: &IntelIocCommand, ctx: &CliContext) -> Result<(), String> {
  if !ctx.wants_machine_output() {
    Output::header("IOC Extraction");
    println!();
  }

  let mut collection = IocCollection::new();
  let mut target = String::from("target");

  // Parse key=value pairs
  let parse_args = |args: &[&str], collection: &mut IocCollection, target: &mut String| {
    for arg in args {
      if let Some(eq_pos) = arg.find('=') {
        let (key, value) = arg.split_at(eq_pos);
        let value = &value[1..];

        match key {
          "target" | "t" => {
            *target = value.to_string();
          }
          "ip" => {
            let _extractor = IocExtractor::new(target.as_str());
            // Try to parse and add IP
            let ioc_type = if value.contains(':') {
              IocType::IPv6
            } else {
              IocType::IPv4
            };
            let _ioc = Ioc::new(ioc_type, value, IocSource::PortScan, 85, target.as_str())
              .with_tag("manual_input");
            collection.add(_ioc);
          }
          "ports" | "p" => {
            // Extract ports and add as context to existing IP IOCs
            let ports: Vec<u16> = value
              .split(',')
              .filter_map(|p| p.trim().parse().ok())
              .collect();

            for port in &ports {
              let _ioc = Ioc::new(
                IocType::IPv4,
                "scan_target", // placeholder
                IocSource::PortScan,
                70,
                target.as_str(),
              )
              .with_tag(format!("port:{}", port));
              // Don't add placeholder, just note port info
            }

            // Add port information to notes
            Output::info(&format!(
              "Ports noted: {}",
              ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
            ));
          }
          "dns" | "domain" => {
            let _extractor = IocExtractor::new(target.as_str());
            // Add domain as IOC
            let ioc = Ioc::new(
              IocType::Domain,
              value,
              IocSource::DnsQuery,
              90,
              target.as_str(),
            )
            .with_technique("T1071.004")
            .with_tag("dns_input");
            collection.add(ioc);
          }
          "email" => {
            let ioc = Ioc::new(
              IocType::Email,
              value,
              IocSource::Manual,
              75,
              target.as_str(),
            )
            .with_technique("T1589.002")
            .with_tag("manual_input");
            collection.add(ioc);
          }
          "url" => {
            let ioc = Ioc::new(IocType::Url, value, IocSource::Manual, 80, target.as_str())
              .with_technique("T1071.001")
              .with_tag("manual_input");
            collection.add(ioc);
          }
          "hash" => {
            let hash_type = match value.len() {
              32 => IocType::HashMD5,
              40 => IocType::HashSHA1,
              64 => IocType::HashSHA256,
              _ => IocType::HashSHA256,
            };
            let ioc = Ioc::new(hash_type, value, IocSource::Manual, 90, target.as_str())
              .with_tag("manual_input");
            collection.add(ioc);
          }
          _ => {}
        }
      }
    }
  };

  // Collect args
  let mut all_args: Vec<&str> = Vec::new();
  if let Some(ref t) = ctx.target {
    all_args.push(t.as_str());
  }
  for arg in &ctx.args {
    all_args.push(arg.as_str());
  }

  parse_args(&all_args, &mut collection, &mut target);

  if collection.is_empty() {
    let payload = super::payloads::ioc_extract_empty_payload();
    if render::render_machine_output(ctx, "rb intel ioc extract", &payload)? {
      return Ok(());
    }
    Output::warning("No IOCs extracted. Provide data using key=value pairs:");
    println!();
    Output::info("  target=example.com     Set target context");
    Output::info("  ip=192.168.1.1         Add IP address");
    Output::info("  dns=example.com        Add domain from DNS");
    Output::info("  email=admin@test.com   Add email address");
    Output::info("  url=http://...         Add URL");
    Output::info("  hash=abc123...         Add file hash");
    println!();
    Output::info(
      "Example: rb intel ioc extract target=example.com ip=93.184.216.34 dns=example.com",
    );
    return Ok(());
  }

  let payload = super::payloads::ioc_extract_payload(&target, &collection);
  if render::render_machine_output(ctx, "rb intel ioc extract", &payload)? {
    return Ok(());
  }

  // Show extraction results
  Output::success(&format!("Extracted {} IOCs", collection.len()));
  println!();

  // Show by type
  let counts = collection.count_by_type();
  Output::section("IOCs by Type");
  for (ioc_type, count) in &counts {
    println!("  {:12} {}", format!("{}:", ioc_type), count);
  }
  println!();

  // Show individual IOCs
  Output::section("Extracted IOCs");
  for ioc in collection.all() {
    let conf_badge = match ioc.confidence {
      IocConfidence::High => "\x1b[32m[HIGH]\x1b[0m",
      IocConfidence::Medium => "\x1b[33m[MED]\x1b[0m",
      IocConfidence::Low => "\x1b[90m[LOW]\x1b[0m",
    };
    println!(
      "  {} {:8} {}",
      conf_badge,
      format!("[{}]", ioc.ioc_type),
      ioc.value
    );
    if !ioc.mitre_techniques.is_empty() {
      println!("      ATT&CK: {}", ioc.mitre_techniques.join(", "));
    }
    if !ioc.tags.is_empty() {
      println!("      Tags: {}", ioc.tags.join(", "));
    }
  }

  Ok(())
}

/// Export IOCs to file
pub(super) fn export_iocs(_self: &IntelIocCommand, ctx: &CliContext) -> Result<(), String> {
  if !ctx.wants_machine_output() {
    Output::header("IOC Export");
    println!();
  }

  // For now, generate some sample IOCs to export
  let mut collection = IocCollection::new();
  let target = ctx.target.clone().unwrap_or_else(|| "target".to_string());
  let export_format = ctx.get_flag_or("export-format", "json");
  let output_file: Option<String> = ctx.get_flag("file");

  // If no output file specified, print to stdout
  let output_path = output_file.clone().unwrap_or_else(|| {
    format!(
      "iocs.{}",
      match export_format.as_str() {
        "csv" => "csv",
        "stix" => "stix.json",
        _ => "json",
      }
    )
  });

  // Add sample IOCs (in real usage, would load from database)
  collection.add(
    Ioc::new(
      IocType::IPv4,
      "93.184.216.34",
      IocSource::DnsQuery,
      90,
      &target,
    )
    .with_technique("T1071.004")
    .with_tag("dns_resolved"),
  );
  collection.add(
    Ioc::new(
      IocType::Domain,
      "example.com",
      IocSource::DnsQuery,
      95,
      &target,
    )
    .with_technique("T1071.004")
    .with_tag("primary_domain"),
  );

  if collection.is_empty() {
    let payload = super::payloads::ioc_export_empty_payload(&target, &export_format);
    if render::render_machine_output(ctx, "rb intel ioc export", &payload)? {
      return Ok(());
    }
    Output::info("No IOCs to export. Extract IOCs first with 'rb intel ioc extract'");
    return Ok(());
  }

  // Generate export content
  let content = match export_format.as_str() {
    "csv" => collection.to_csv(),
    "stix" => super::converters::to_stix_bundle(&collection, &target),
    _ => collection.to_json(),
  };

  // Write to file
  std::fs::write(&output_path, &content).map_err(|e| format!("Failed to write file: {}", e))?;

  let payload = super::payloads::ioc_export_payload(
    &target,
    &export_format,
    &output_path,
    content.len(),
    &collection,
  );
  if render::render_machine_output(ctx, "rb intel ioc export", &payload)? {
    return Ok(());
  }

  Output::success(&format!(
    "Exported {} IOCs to {}",
    collection.len(),
    output_path
  ));
  println!();
  Output::item("Format", &export_format);
  Output::item("File", &output_path);
  Output::item("Size", &format!("{} bytes", content.len()));

  Ok(())
}

/// Show supported IOC types
pub(super) fn show_types(_self: &IntelIocCommand, ctx: &CliContext) -> Result<(), String> {
  let types = [
    ("ipv4", "IPv4 address", "192.168.1.1", "network"),
    ("ipv6", "IPv6 address", "2001:db8::1", "network"),
    ("domain", "Domain name", "example.com", "network"),
    ("url", "Full URL", "https://example.com/path", "network"),
    ("email", "Email address", "user@example.com", "network"),
    ("md5", "MD5 hash", "d41d8cd98f00b204...", "network"),
    ("sha1", "SHA-1 hash", "da39a3ee5e6b4b0d...", "file"),
    ("sha256", "SHA-256 hash", "e3b0c44298fc1c14...", "file"),
    (
      "certificate",
      "TLS certificate fingerprint",
      "SHA256 fingerprint",
      "file",
    ),
    (
      "ja3",
      "JA3 client fingerprint",
      "TLS client fingerprint",
      "file",
    ),
    (
      "ja3s",
      "JA3S server fingerprint",
      "TLS server fingerprint",
      "file",
    ),
    (
      "user-agent",
      "HTTP User-Agent string",
      "Mozilla/5.0...",
      "file",
    ),
    ("asn", "Autonomous System Number", "AS12345", "file"),
    ("cidr", "CIDR network range", "192.168.0.0/24", "behavioral"),
    ("filename", "File name", "malware.exe", "behavioral"),
    ("filepath", "File path", "/tmp/malicious.sh", "behavioral"),
    (
      "registry",
      "Windows registry key",
      "HKLM\\Software\\...",
      "behavioral",
    ),
    ("mutex", "Mutex name", "Global\\SomeMutex", "behavioral"),
    ("namedpipe", "Named pipe", "\\\\.\\pipe\\evil", "behavioral"),
  ];

  let payload = super::payloads::ioc_types_payload(&types);
  if render::render_machine_output(ctx, "rb intel ioc types", &payload)? {
    return Ok(());
  }

  Output::header("Supported IOC Types");
  println!();

  Output::section("Network IOCs");
  for (name, desc, example, _) in types.iter().take(6) {
    println!("  {:12} {} (e.g., {})", name, desc, example);
  }
  println!();

  Output::section("File IOCs");
  for (name, desc, example, _) in types.iter().skip(6).take(7) {
    println!("  {:12} {} (e.g., {})", name, desc, example);
  }
  println!();

  Output::section("Behavioral IOCs");
  for (name, desc, example, _) in types.iter().skip(13) {
    println!("  {:12} {} (e.g., {})", name, desc, example);
  }

  Ok(())
}

/// Run demo extraction
pub(super) fn run_demo(_self: &IntelIocCommand, ctx: &CliContext) -> Result<(), String> {
  let target = ctx.target.as_deref().unwrap_or("example.com");

  let mut collection = IocCollection::new();
  let extractor = IocExtractor::new(target);

  // Extract from various sources
  let port_iocs = extractor.extract_from_port_scan("93.184.216.34", &[22, 80, 443, 8080]);
  for ioc in &port_iocs {
    collection.add(ioc.clone());
  }

  let dns_iocs = extractor.extract_from_dns(
    target,
    &[Ipv4Addr::new(93, 184, 216, 34)],
    &[],
    &["10 mail.example.com".to_string()],
    &["ns1.example.com".to_string(), "ns2.example.com".to_string()],
    &[],
  );
  for ioc in &dns_iocs {
    collection.add(ioc.clone());
  }

  let tls_iocs = extractor.extract_from_tls(
    target,
    &["www.example.com".to_string(), "api.example.com".to_string()],
    "DigiCert Inc",
    "abc123def456",
    "1234567890",
  );
  for ioc in &tls_iocs {
    collection.add(ioc.clone());
  }

  let subdomain_iocs = extractor.extract_from_subdomains(&[
    "www.example.com".to_string(),
    "api.example.com".to_string(),
    "mail.example.com".to_string(),
    "dev.example.com".to_string(),
  ]);
  for ioc in &subdomain_iocs {
    collection.add(ioc.clone());
  }

  let payload = super::payloads::ioc_demo_payload(
    target,
    &collection,
    port_iocs.len(),
    dns_iocs.len(),
    tls_iocs.len(),
    subdomain_iocs.len(),
  );
  if render::render_machine_output(ctx, "rb intel ioc demo", &payload)? {
    return Ok(());
  }

  Output::header(&format!("IOC Extraction Demo: {}", target));
  println!();

  // Simulate port scan results
  Output::section("1. Port Scan IOCs");
  Output::success(&format!(
    "Extracted {} IOCs from port scan",
    port_iocs.len()
  ));
  for ioc in &port_iocs {
    println!(
      "  • {} [{}] - {} tags",
      ioc.value,
      ioc.ioc_type,
      ioc.tags.len()
    );
  }
  println!();

  // Simulate DNS results
  Output::section("2. DNS IOCs");
  Output::success(&format!("Extracted {} IOCs from DNS", dns_iocs.len()));
  for ioc in &dns_iocs {
    let tech_str = if ioc.mitre_techniques.is_empty() {
      String::new()
    } else {
      format!(" → {}", ioc.mitre_techniques.join(", "))
    };
    println!("  • {} [{}]{}", ioc.value, ioc.ioc_type, tech_str);
  }
  println!();

  // Simulate TLS certificate
  Output::section("3. TLS Certificate IOCs");
  Output::success(&format!("Extracted {} IOCs from TLS", tls_iocs.len()));
  for ioc in &tls_iocs {
    println!("  • {} [{}]", ioc.value, ioc.ioc_type);
  }
  println!();

  // Simulate subdomain enumeration
  Output::section("4. Subdomain IOCs");
  Output::success(&format!(
    "Extracted {} IOCs from subdomains",
    subdomain_iocs.len()
  ));
  for ioc in &subdomain_iocs {
    println!("  • {} [{}]", ioc.value, ioc.ioc_type);
  }
  println!();

  // Summary
  Output::section("Summary");
  Output::item("Total IOCs", &collection.len().to_string());

  let counts = collection.count_by_type();
  for (ioc_type, count) in &counts {
    Output::item(&format!("  {}", ioc_type), &count.to_string());
  }
  println!();

  let conf_counts = collection.count_by_confidence();
  Output::item(
    "High confidence",
    &conf_counts
      .get(&IocConfidence::High)
      .unwrap_or(&0)
      .to_string(),
  );
  Output::item(
    "Medium confidence",
    &conf_counts
      .get(&IocConfidence::Medium)
      .unwrap_or(&0)
      .to_string(),
  );
  Output::item(
    "Low confidence",
    &conf_counts
      .get(&IocConfidence::Low)
      .unwrap_or(&0)
      .to_string(),
  );
  println!();

  // Show STIX patterns for a few IOCs
  Output::section("Sample STIX Patterns");
  for ioc in collection.all().iter().take(3) {
    println!("  {}", ioc.to_stix_pattern());
  }
  println!();

  Output::info("Export with: rb intel ioc export format=stix output=demo-iocs.json");

  Ok(())
}

/// Import IOCs from external file (JSON, CSV, STIX)
pub(super) fn import_iocs(_self: &IntelIocCommand, ctx: &CliContext) -> Result<(), String> {
  // Get file path from target or args
  let file_path = ctx
    .target
    .as_ref()
    .or_else(|| ctx.args.first())
    .ok_or_else(|| {
      if ctx.wants_machine_output() {
        let payload = super::payloads::ioc_import_missing_file_payload();
        let _ = render::render_machine_output(ctx, "rb intel ioc import", &payload);
      } else {
        Output::error("No file specified");
        println!();
        Output::info("Usage: rb intel ioc import <file> [format=auto|json|csv|stix]");
      }
      "Missing file argument".to_string()
    })?;

  // Determine format
  let mut file_format = String::from("auto");
  for arg in ctx
    .args
    .iter()
    .skip(if ctx.target.is_some() { 0 } else { 1 })
  {
    if let Some(eq_pos) = arg.find('=') {
      let (key, value) = arg.split_at(eq_pos);
      let value = &value[1..];
      if key == "format" || key == "f" {
        file_format = value.to_string();
      }
    }
  }

  // Auto-detect format from file extension if not specified
  if file_format == "auto" {
    file_format = if file_path.ends_with(".csv") {
      "csv"
    } else if file_path.ends_with(".stix.json") || file_path.contains("stix") {
      "stix"
    } else {
      "json"
    }
    .to_string();
  }

  if !ctx.wants_machine_output() {
    Output::header("IOC Import");
    println!();
    Output::item("File", file_path);
    Output::item("Format", &file_format);
    println!();
  }

  // Read file content
  let content =
    std::fs::read_to_string(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

  if !ctx.wants_machine_output() {
    Output::spinner_start("Parsing IOCs");
  }

  let mut collection = IocCollection::new();
  let import_count = match file_format.as_str() {
    "csv" => parse_csv_iocs(&content, &mut collection)?,
    "stix" => parse_stix_iocs(&content, &mut collection)?,
    _ => parse_json_iocs(&content, &mut collection)?,
  };

  if !ctx.wants_machine_output() {
    Output::spinner_done();
    println!();
  }

  if import_count == 0 {
    let payload = super::payloads::ioc_import_empty_payload(file_path, &file_format);
    if render::render_machine_output(ctx, "rb intel ioc import", &payload)? {
      return Ok(());
    } else {
      Output::warning("No IOCs found in file");
    }
    return Ok(());
  }

  let payload =
    super::payloads::ioc_import_payload(file_path, &file_format, import_count, &collection);
  if render::render_machine_output(ctx, "rb intel ioc import", &payload)? {
    return Ok(());
  }

  Output::success(&format!("Imported {} IOCs", import_count));
  println!();

  // Show summary by type
  Output::section("IOCs by Type");
  let counts = collection.count_by_type();
  for (ioc_type, count) in &counts {
    println!("  {:12} {}", format!("{}:", ioc_type), count);
  }
  println!();

  // Show first few IOCs
  Output::section("Sample Imported IOCs (first 5)");
  for ioc in collection.all().iter().take(5) {
    let conf_badge = match ioc.confidence {
      IocConfidence::High => "\x1b[32m[HIGH]\x1b[0m",
      IocConfidence::Medium => "\x1b[33m[MED]\x1b[0m",
      IocConfidence::Low => "\x1b[90m[LOW]\x1b[0m",
    };
    println!(
      "  {} {:8} {}",
      conf_badge,
      format!("[{}]", ioc.ioc_type),
      ioc.value
    );
  }

  if import_count > 5 {
    println!("  ... and {} more", import_count - 5);
  }

  Ok(())
}

/// Parse IOCs from CSV content
fn parse_csv_iocs(content: &str, collection: &mut IocCollection) -> Result<usize, String> {
  let mut count = 0;
  let lines: Vec<&str> = content.lines().collect();

  if lines.is_empty() {
    return Ok(0);
  }

  // Parse header to find column indices
  let header: Vec<&str> = lines[0].split(',').map(|s| s.trim()).collect();
  let type_idx = header
    .iter()
    .position(|&h| h.to_lowercase() == "type" || h.to_lowercase() == "ioc_type");
  let value_idx = header
    .iter()
    .position(|&h| h.to_lowercase() == "value" || h.to_lowercase() == "indicator");
  let confidence_idx = header
    .iter()
    .position(|&h| h.to_lowercase() == "confidence");
  let tags_idx = header.iter().position(|&h| h.to_lowercase() == "tags");

  let value_col = value_idx.unwrap_or(0);
  let type_col = type_idx.unwrap_or(1);

  // Parse data rows
  for line in lines.iter().skip(1) {
    if line.trim().is_empty() {
      continue;
    }

    let cols: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if cols.len() <= value_col {
      continue;
    }

    let value = cols.get(value_col).unwrap_or(&"").trim_matches('"');
    if value.is_empty() {
      continue;
    }

    let type_str = cols.get(type_col).unwrap_or(&"unknown").trim_matches('"');
    let ioc_type = parse_ioc_type(type_str);

    let confidence_score: u8 = confidence_idx
      .and_then(|idx| cols.get(idx))
      .and_then(|s| s.trim_matches('"').parse().ok())
      .unwrap_or(50);

    let mut ioc = Ioc::new(
      ioc_type,
      value,
      IocSource::External("import".to_string()),
      confidence_score,
      "imported",
    );

    // Add tags if present
    if let Some(idx) = tags_idx {
      if let Some(tags_str) = cols.get(idx) {
        for tag in tags_str.trim_matches('"').split(';') {
          let tag = tag.trim();
          if !tag.is_empty() {
            ioc = ioc.with_tag(tag);
          }
        }
      }
    }

    collection.add(ioc);
    count += 1;
  }

  Ok(count)
}

/// Parse IOCs from JSON content
fn parse_json_iocs(content: &str, collection: &mut IocCollection) -> Result<usize, String> {
  let mut count = 0;

  // Simple JSON parsing for IOC arrays
  // Expected format: [{"type": "...", "value": "...", ...}, ...]
  let content = content.trim();

  if !content.starts_with('[') {
    return Err("Expected JSON array of IOCs".to_string());
  }

  // Extract objects between []
  let inner = &content[1..content.len().saturating_sub(1)];

  // Split by }, { pattern (simplified parser)
  for obj_str in inner.split("},") {
    let obj_str = obj_str
      .trim()
      .trim_start_matches('{')
      .trim_end_matches('}')
      .trim_end_matches(']');
    if obj_str.is_empty() {
      continue;
    }

    let mut ioc_type = IocType::Domain;
    let mut value = String::new();
    let mut confidence: u8 = 50;
    let mut tags: Vec<String> = Vec::new();

    // Parse key-value pairs
    for pair in obj_str.split(',') {
      let pair = pair.trim();
      if let Some(colon_pos) = pair.find(':') {
        let key = pair[..colon_pos].trim().trim_matches('"');
        let val = pair[colon_pos + 1..].trim().trim_matches('"');

        match key {
          "type" | "ioc_type" => ioc_type = parse_ioc_type(val),
          "value" | "indicator" => value = val.to_string(),
          "confidence" | "confidence_score" => {
            confidence = val.parse().unwrap_or(50);
          }
          "tags" => {
            // Simple tag extraction from JSON array
            let tags_str = val.trim_matches('[').trim_matches(']');
            for tag in tags_str.split(',') {
              let tag = tag.trim().trim_matches('"');
              if !tag.is_empty() {
                tags.push(tag.to_string());
              }
            }
          }
          _ => {}
        }
      }
    }

    if !value.is_empty() {
      let mut ioc = Ioc::new(
        ioc_type,
        &value,
        IocSource::External("import".to_string()),
        confidence,
        "imported",
      );
      for tag in tags {
        ioc = ioc.with_tag(&tag);
      }
      collection.add(ioc);
      count += 1;
    }
  }

  Ok(count)
}

/// Parse IOCs from STIX bundle content
fn parse_stix_iocs(content: &str, collection: &mut IocCollection) -> Result<usize, String> {
  let mut count = 0;

  // Look for indicator objects with patterns
  // Pattern: [ipv4-addr:value = 'x.x.x.x'] or [domain-name:value = 'example.com']
  for line in content.lines() {
    let line = line.trim();

    // Look for pattern field
    if line.contains("\"pattern\"") {
      // Extract pattern value
      if let Some(start) = line.find('[') {
        if let Some(end) = line.rfind(']') {
          let pattern = &line[start..=end];

          // Parse STIX pattern
          if let Some(ioc) = parse_stix_pattern(pattern) {
            collection.add(ioc);
            count += 1;
          }
        }
      }
    }
  }

  Ok(count)
}

/// Parse STIX pattern to IOC
fn parse_stix_pattern(pattern: &str) -> Option<Ioc> {
  // Pattern format: [type:property = 'value']
  let pattern = pattern.trim_matches(|c| c == '[' || c == ']' || c == '\\');

  // Extract type and value
  let parts: Vec<&str> = pattern.split('=').collect();
  if parts.len() != 2 {
    return None;
  }

  let type_part = parts[0].trim();
  let value = parts[1].trim().trim_matches('\'').trim_matches('"');

  let ioc_type = if type_part.contains("ipv4-addr") {
    IocType::IPv4
  } else if type_part.contains("ipv6-addr") {
    IocType::IPv6
  } else if type_part.contains("domain-name") {
    IocType::Domain
  } else if type_part.contains("url") {
    IocType::Url
  } else if type_part.contains("email-addr") {
    IocType::Email
  } else if type_part.contains("file:hashes.MD5") {
    IocType::HashMD5
  } else if type_part.contains("file:hashes.SHA-1") || type_part.contains("file:hashes.'SHA-1'") {
    IocType::HashSHA1
  } else if type_part.contains("file:hashes.SHA-256") || type_part.contains("file:hashes.'SHA-256'")
  {
    IocType::HashSHA256
  } else {
    IocType::Domain // Default
  };

  Some(
    Ioc::new(
      ioc_type,
      value,
      IocSource::External("stix".to_string()),
      75,
      "stix_import",
    )
    .with_tag("stix"),
  )
}

/// Parse IOC type string to IocType enum
fn parse_ioc_type(type_str: &str) -> IocType {
  match type_str.to_lowercase().as_str() {
    "ipv4" | "ip" | "ipv4-addr" => IocType::IPv4,
    "ipv6" | "ipv6-addr" => IocType::IPv6,
    "domain" | "domain-name" | "hostname" => IocType::Domain,
    "url" | "uri" => IocType::Url,
    "email" | "email-addr" => IocType::Email,
    "md5" | "hash-md5" | "hashmd5" => IocType::HashMD5,
    "sha1" | "hash-sha1" | "hashsha1" => IocType::HashSHA1,
    "sha256" | "hash-sha256" | "hashsha256" => IocType::HashSHA256,
    "certificate" | "cert" => IocType::Certificate,
    "ja3" => IocType::JA3,
    "ja3s" => IocType::JA3S,
    "user-agent" | "useragent" | "ua" => IocType::UserAgent,
    "asn" => IocType::ASN,
    "cidr" | "network" => IocType::CIDR,
    _ => IocType::Domain, // Default
  }
}

/// Search IOCs by value, type, or tag
pub(super) fn search_iocs(_self: &IntelIocCommand, ctx: &CliContext) -> Result<(), String> {
  // Get search query
  let query = ctx
    .target
    .as_ref()
    .or_else(|| ctx.args.first())
    .ok_or_else(|| {
      if ctx.wants_machine_output() {
        let payload = super::payloads::ioc_search_missing_query_payload();
        let _ = render::render_machine_output(ctx, "rb intel ioc search", &payload);
      } else {
        Output::error("No search query specified");
        println!();
        Output::info("Usage: rb intel ioc search <query> [type=...] [tag=...]");
      }
      "Missing search query".to_string()
    })?;

  // Parse filter options
  let mut type_filter: Option<String> = None;
  let mut tag_filter: Option<String> = None;
  let mut confidence_filter: Option<String> = None;

  for arg in &ctx.args {
    if let Some(eq_pos) = arg.find('=') {
      let (key, value) = arg.split_at(eq_pos);
      let value = &value[1..];

      match key {
        "type" | "t" => type_filter = Some(value.to_lowercase()),
        "tag" => tag_filter = Some(value.to_string()),
        "confidence" | "conf" | "c" => confidence_filter = Some(value.to_lowercase()),
        _ => {}
      }
    }
  }

  // Generate sample IOC database for demonstration
  // In a real implementation, this would search the persistent storage
  let mut collection = IocCollection::new();
  super::converters::populate_sample_database(&mut collection);

  // Search and filter
  let query_lower = query.to_lowercase();
  let mut results: Vec<&Ioc> = collection
    .all()
    .into_iter()
    .filter(|ioc| {
      // Match query against value
      let value_match = ioc.value.to_lowercase().contains(&query_lower);

      // Type filter
      let type_match = type_filter
        .as_ref()
        .map(|t| ioc.ioc_type.to_string().to_lowercase().contains(t))
        .unwrap_or(true);

      // Tag filter
      let tag_match = tag_filter
        .as_ref()
        .map(|t| {
          ioc
            .tags
            .iter()
            .any(|tag| tag.to_lowercase().contains(&t.to_lowercase()))
        })
        .unwrap_or(true);

      // Confidence filter
      let conf_match = confidence_filter
        .as_ref()
        .map(|c| match c.as_str() {
          "high" | "h" => matches!(ioc.confidence, IocConfidence::High),
          "medium" | "med" | "m" => matches!(ioc.confidence, IocConfidence::Medium),
          "low" | "l" => matches!(ioc.confidence, IocConfidence::Low),
          _ => true,
        })
        .unwrap_or(true);

      value_match && type_match && tag_match && conf_match
    })
    .collect();

  // Sort by confidence score descending
  results.sort_by(|a, b| b.confidence_score.cmp(&a.confidence_score));

  let payload = super::payloads::ioc_search_payload(
    query,
    type_filter.as_deref(),
    tag_filter.as_deref(),
    confidence_filter.as_deref(),
    &results,
  );
  if render::render_machine_output(ctx, "rb intel ioc search", &payload)? {
    return Ok(());
  }

  Output::header("IOC Search");
  println!();

  Output::item("Query", query);
  if let Some(ref t) = type_filter {
    Output::item("Type filter", t);
  }
  if let Some(ref t) = tag_filter {
    Output::item("Tag filter", t);
  }
  println!();

  if results.is_empty() {
    Output::warning("No matching IOCs found");
    println!();
    Output::info("Try a different query or relax the filters");
    return Ok(());
  }

  Output::success(&format!("Found {} matching IOCs", results.len()));
  println!();

  // Display results
  Output::section("Search Results");
  for (i, ioc) in results.iter().take(20).enumerate() {
    let conf_badge = match ioc.confidence {
      IocConfidence::High => "\x1b[32m[HIGH]\x1b[0m",
      IocConfidence::Medium => "\x1b[33m[MED]\x1b[0m",
      IocConfidence::Low => "\x1b[90m[LOW]\x1b[0m",
    };
    println!(
      "{}. {} {:10} {}",
      i + 1,
      conf_badge,
      format!("[{}]", ioc.ioc_type),
      ioc.value
    );

    // Show additional details
    if !ioc.tags.is_empty() {
      println!("   Tags: {}", ioc.tags.join(", "));
    }
    if !ioc.mitre_techniques.is_empty() {
      println!("   ATT&CK: {}", ioc.mitre_techniques.join(", "));
    }
    println!(
      "   Source: {} | Context: {}",
      ioc.source,
      ioc.context.as_deref().unwrap_or("-")
    );
    println!();
  }

  if results.len() > 20 {
    Output::info(&format!(
      "... and {} more results (showing first 20)",
      results.len() - 20
    ));
  }

  Ok(())
}
