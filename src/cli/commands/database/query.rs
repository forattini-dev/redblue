//! Query mode handlers (rb database query <dataset>)

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::cli::commands::annotate_query_partition;
use crate::cli::output::Output;
use crate::cli::{render, CliContext};
use crate::json;
use crate::serde_json::Value;
use crate::storage::client::query::format as query_format;
use crate::storage::service::StorageService;

use super::helpers::{
  describe_partition_key, dns_type_label, open_db, parse_attr_filter, parse_ip_range,
  parse_segment_kind, port_status_label, read_dns_records, read_port_scans, read_subdomains,
  segment_label,
};
use super::DatabaseCommand;

impl DatabaseCommand {
  /// Execute query mode commands
  pub(super) fn execute_query(&self, ctx: &CliContext) -> Result<(), String> {
    let dataset = ctx
      .verb
      .as_deref()
      .unwrap_or("summary")
      .to_ascii_lowercase();

    if dataset == "partitions" {
      return self.query_partitions(ctx);
    }

    let db_path = self.resolve_db_path(ctx)?;

    match dataset.as_str() {
      "summary" => self.query_summary(ctx, &db_path),
      "ports" => self.query_ports(ctx, &db_path),
      "dns" => self.query_dns(ctx, &db_path),
      "subdomains" => self.query_subdomains(ctx, &db_path),
      "http" => self.query_http(ctx, &db_path),
      "tls" => self.query_tls(ctx, &db_path),
      "whois" => self.query_whois(ctx, &db_path),
      "hosts" => self.query_hosts(ctx, &db_path),
      other => Err(format!(
        "Unknown dataset '{}'. See `rb database query help`.",
        other
      )),
    }
  }

  pub(super) fn resolve_db_path(&self, ctx: &CliContext) -> Result<PathBuf, String> {
    if let Some(path) = ctx.get_flag_with_config("db") {
      return Ok(PathBuf::from(path));
    }
    if let Some(path) = ctx.get_flag_with_config("database") {
      return Ok(PathBuf::from(path));
    }
    if let Some(target) = ctx.target.as_ref() {
      return Ok(PathBuf::from(target));
    }
    Err("Missing database file. Provide --db <file.rdb> or set it in .redblue.yaml".to_string())
  }

  fn query_partitions(&self, ctx: &CliContext) -> Result<(), String> {
    let service = StorageService::global();

    let mut partitions = service.partitions();

    if let Some(segment_name) = ctx.get_flag("segment") {
      let segment = parse_segment_kind(&segment_name)?;
      partitions.retain(|meta| meta.segments.contains(&segment));
    }

    if let Some(attr_filter) = ctx.get_flag("attr") {
      let (key, value) = parse_attr_filter(&attr_filter)?;
      partitions.retain(|meta| {
        meta
          .attributes
          .get(key)
          .map(|candidate| candidate == value)
          .unwrap_or(false)
      });
    }

    partitions.sort_by(|a, b| a.label.cmp(&b.label));

    let payload =
      query_partitions_payload(&partitions, ctx.get_flag("segment"), ctx.get_flag("attr"));
    if render::render_machine_output(ctx, "rb database query partitions", &payload)? {
      return Ok(());
    }

    if partitions.is_empty() {
      Output::warning("No partitions matched the requested filters");
      return Ok(());
    }

    Output::header("Known Storage Partitions");
    Output::info(&format!(
      "Total: {} (filtered by segment: {}, attr: {})",
      partitions.len(),
      ctx.get_flag("segment").as_deref().unwrap_or("any"),
      ctx.get_flag("attr").as_deref().unwrap_or("any")
    ));
    println!();

    for meta in partitions {
      println!("• {} ({})", meta.label, describe_partition_key(&meta.key));
      println!("  path: {}", meta.storage_path.display());

      if !meta.segments.is_empty() {
        let segments = meta
          .segments
          .iter()
          .map(|kind| segment_label(*kind))
          .collect::<Vec<_>>()
          .join(", ");
        println!("  segments: {}", segments);
      } else {
        println!("  segments: (none)");
      }

      if let Some(ts) = meta.last_refreshed {
        let epoch = ts
          .duration_since(UNIX_EPOCH)
          .unwrap_or_else(|_| std::time::Duration::from_secs(0))
          .as_secs();
        println!("  last_refreshed: {}s", epoch);
      } else {
        println!("  last_refreshed: never");
      }

      if !meta.attributes.is_empty() {
        let pairs = meta
          .attributes
          .iter()
          .map(|(key, value)| format!("{}={}", key, value))
          .collect::<Vec<_>>()
          .join(", ");
        println!("  attributes: {}", pairs);
      }

      println!();
    }

    Ok(())
  }

  fn query_summary(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
    let service = StorageService::global();
    let label = format!("custom:{}", db_path.display());
    let _ = service.refresh_partition(StorageService::key_for_path(db_path), label, db_path);

    annotate_query_partition(
      ctx,
      db_path,
      [
        ("query_category", "database"),
        ("query_dataset", "summary"),
        ("query_mode", self.mode_label()),
      ],
    );
    if !ctx.wants_machine_output() {
      Output::spinner_start("Reading database");
    }
    let mut db = open_db(db_path)?;
    let port_scans = read_port_scans(&mut db)?;
    let dns_records = read_dns_records(&mut db)?;
    let subdomains = read_subdomains(&mut db)?;
    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }

    let metadata =
      fs::metadata(db_path).map_err(|e| format!("Failed to read file metadata: {}", e))?;
    let file_size_kb = metadata.len() / 1024;

    let payload = query_summary_payload(
      db_path,
      file_size_kb,
      port_scans.len(),
      dns_records.len(),
      subdomains.len(),
    );
    if render::render_machine_output(ctx, "rb database query summary", &payload)? {
      return Ok(());
    }

    Output::header(&format!("Summary: {}", db_path.display()));

    Output::summary_line(&[
      ("Size", &format!("{} KB", file_size_kb)),
      ("Ports", &port_scans.len().to_string()),
      ("DNS", &dns_records.len().to_string()),
      ("Subdomains", &subdomains.len().to_string()),
    ]);

    Ok(())
  }

  fn query_ports(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
    let range = ctx
      .get_flag_with_config("ip-range")
      .map(|value| parse_ip_range(&value))
      .transpose()?;

    annotate_query_partition(
      ctx,
      db_path,
      [
        ("query_category", "database"),
        ("query_dataset", "ports"),
        ("query_mode", self.mode_label()),
      ],
    );

    let mut db = open_db(db_path)?;
    let all_records = db
      .list_port_scans()
      .map_err(|e| format!("Failed to read ports: {}", e))?;

    // Filter by IP range if specified
    let records: Vec<_> = if let Some((start_ip, end_ip)) = range {
      all_records
        .into_iter()
        .filter(|r| {
          // Simple IP range check (assumes IPv4)
          match (r.ip, start_ip, end_ip) {
            (IpAddr::V4(ip), IpAddr::V4(start), IpAddr::V4(end)) => {
              let ip_u32 = u32::from(ip);
              let start_u32 = u32::from(start);
              let end_u32 = u32::from(end);
              ip_u32 >= start_u32 && ip_u32 <= end_u32
            }
            _ => false, // Skip IPv6 or mixed ranges for now
          }
        })
        .collect()
    } else {
      all_records
    };

    let payload = query_ports_payload(&records);
    if render::render_machine_output(ctx, "rb database query ports", &payload)? {
      return Ok(());
    }

    if records.is_empty() {
      Output::warning("No ports matched the requested filters");
      return Ok(());
    }

    Output::header(&format!("Ports ({})", records.len()));
    for record in records.iter().take(50) {
      let state = port_status_label(record.status);
      println!("  {}:{} [{}]", record.ip, record.port, state);
    }
    if records.len() > 50 {
      println!("  ... and {} more", records.len() - 50);
    }
    Ok(())
  }

  fn query_dns(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
    let prefix = ctx.get_flag_with_config("dns-prefix");

    annotate_query_partition(
      ctx,
      db_path,
      [
        ("query_category", "database"),
        ("query_dataset", "dns"),
        ("query_mode", self.mode_label()),
      ],
    );

    let mut db = open_db(db_path)?;
    let all_records = db
      .list_dns_records_all()
      .map_err(|e| format!("Failed to read DNS records: {}", e))?;

    // Filter by domain prefix if specified
    let records: Vec<_> = if let Some(prefix) = prefix.as_deref() {
      all_records
        .into_iter()
        .filter(|r| r.domain.starts_with(prefix))
        .collect()
    } else {
      all_records
    };

    let payload = query_dns_payload(&records);
    if render::render_machine_output(ctx, "rb database query dns", &payload)? {
      return Ok(());
    }

    if records.is_empty() {
      Output::warning("No DNS records matched the requested filters");
      return Ok(());
    }

    Output::header(&format!("DNS Records ({})", records.len()));
    for record in records.iter().take(50) {
      println!(
        "  {} {} {} (TTL: {})",
        record.domain,
        dns_type_label(record.record_type),
        record.value,
        record.ttl
      );
    }
    if records.len() > 50 {
      println!("  ... and {} more", records.len() - 50);
    }
    Ok(())
  }

  fn query_subdomains(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
    let prefix = ctx.get_flag_with_config("subdomain-prefix");

    annotate_query_partition(
      ctx,
      db_path,
      [
        ("query_category", "database"),
        ("query_dataset", "subdomains"),
        ("query_mode", self.mode_label()),
      ],
    );

    let mut db = open_db(db_path)?;
    let all_records = db
      .list_subdomains_all()
      .map_err(|e| format!("Failed to read subdomains: {}", e))?;

    // Filter by subdomain prefix if specified
    let records: Vec<_> = if let Some(prefix) = prefix.as_deref() {
      all_records
        .into_iter()
        .filter(|r| r.subdomain.starts_with(prefix))
        .collect()
    } else {
      all_records
    };

    let payload = query_subdomains_payload(&records);
    if render::render_machine_output(ctx, "rb database query subdomains", &payload)? {
      return Ok(());
    }

    if records.is_empty() {
      Output::warning("No subdomains matched the requested filters");
      return Ok(());
    }

    Output::header(&format!("Subdomains ({})", records.len()));
    for record in records.iter().take(50) {
      println!("  {}", record.subdomain);
    }
    if records.len() > 50 {
      println!("  ... and {} more", records.len() - 50);
    }
    Ok(())
  }

  fn query_http(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
    let host_filter = ctx.get_flag_with_config("host");
    let mut manager = StorageService::global()
      .open_query_manager(db_path)
      .map_err(|e| format!("Failed to open {}: {}", db_path.display(), e))?;

    annotate_query_partition(
      ctx,
      db_path,
      [
        ("query_category", "database"),
        ("query_dataset", "http"),
        ("query_mode", self.mode_label()),
      ],
    );

    let host = host_filter
      .or_else(|| ctx.target.clone())
      .ok_or_else(|| "Specify --host when querying HTTP captures".to_string())?;

    let records = manager
      .list_http_records(&host)
      .map_err(|e| format!("HTTP query failed: {}", e))?;

    let payload = query_http_payload(&host, &records);
    if render::render_machine_output(ctx, "rb database query http", &payload)? {
      return Ok(());
    }

    if records.is_empty() {
      Output::warning("No HTTP captures stored for this host");
      return Ok(());
    }

    Output::header(&format!("HTTP Captures for {}", host));
    for record in records.iter().take(20) {
      println!(
        "  {} {} {} -> {} {}",
        record.method, record.url, record.http_version, record.status_code, record.status_text
      );
      if let Some(server) = &record.server {
        println!("    Server: {}", server);
      }
    }
    if records.len() > 20 {
      println!("  ... and {} more", records.len() - 20);
    }
    Ok(())
  }

  fn query_tls(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
    let host = ctx
      .get_flag_with_config("host")
      .or_else(|| ctx.target.clone())
      .ok_or_else(|| "Specify --host when querying TLS scans".to_string())?;

    let mut manager = StorageService::global()
      .open_query_manager(db_path)
      .map_err(|e| format!("Failed to open {}: {}", db_path.display(), e))?;

    annotate_query_partition(
      ctx,
      db_path,
      [
        ("query_category", "database"),
        ("query_dataset", "tls"),
        ("query_mode", self.mode_label()),
      ],
    );

    let scans = manager
      .list_tls_scans(&host)
      .map_err(|e| format!("TLS query failed: {}", e))?;

    if scans.is_empty() {
      let payload = query_tls_payload(&host, &scans);
      if render::render_machine_output(ctx, "rb database query tls", &payload)? {
        return Ok(());
      }
      Output::warning("No TLS scans stored for this host");
      return Ok(());
    }

    let payload = query_tls_payload(&host, &scans);
    if render::render_machine_output(ctx, "rb database query tls", &payload)? {
      return Ok(());
    }

    Output::header(&format!("TLS Scans for {}", host));
    for scan in scans.iter().take(10) {
      let cipher = scan
        .negotiated_cipher
        .as_deref()
        .unwrap_or("unknown cipher");
      let version = scan
        .negotiated_version
        .as_deref()
        .unwrap_or("unknown protocol");
      println!(
        "  Port {} - {} / {} (valid cert: {})",
        scan.port, version, cipher, scan.certificate_valid
      );
    }
    if scans.len() > 10 {
      println!("  ... and {} more", scans.len() - 10);
    }
    Ok(())
  }

  fn query_whois(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
    let domain = ctx
      .get_flag_with_config("domain")
      .or_else(|| ctx.target.clone())
      .ok_or_else(|| "Specify --domain when querying WHOIS records".to_string())?;

    let mut manager = StorageService::global()
      .open_query_manager(db_path)
      .map_err(|e| format!("Failed to open {}: {}", db_path.display(), e))?;

    annotate_query_partition(
      ctx,
      db_path,
      [
        ("query_category", "database"),
        ("query_dataset", "whois"),
        ("query_mode", self.mode_label()),
      ],
    );

    match manager
      .get_whois(&domain)
      .map_err(|e| format!("WHOIS query failed: {}", e))?
    {
      Some(record) => {
        let payload = query_whois_found_payload(&domain, &record);
        if render::render_machine_output(ctx, "rb database query whois", &payload)? {
          return Ok(());
        }

        Output::header(&format!("WHOIS for {}", domain));
        println!("  Registrar: {}", record.registrar);
        println!("  Created:   {}", record.created_date);
        println!("  Expires:   {}", record.expires_date);
        println!("  Nameservers:");
        for ns in &record.nameservers {
          println!("    - {}", ns);
        }
      }
      None => {
        let payload = query_whois_missing_payload(&domain);
        if render::render_machine_output(ctx, "rb database query whois", &payload)? {
          return Ok(());
        }
        Output::warning("No WHOIS record stored for this domain");
      }
    }
    Ok(())
  }

  fn query_hosts(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
    let ip_filter = ctx
      .get_flag_with_config("ip")
      .or_else(|| ctx.target.clone());

    let mut manager = StorageService::global()
      .open_query_manager(db_path)
      .map_err(|e| format!("Failed to open {}: {}", db_path.display(), e))?;

    annotate_query_partition(
      ctx,
      db_path,
      [
        ("query_category", "database"),
        ("query_dataset", "hosts"),
        ("query_mode", self.mode_label()),
      ],
    );

    if let Some(ip) = ip_filter {
      let ip_addr: IpAddr = ip
        .parse()
        .map_err(|_| format!("Invalid IP address: {}", ip))?;
      match manager
        .get_host_fingerprint(ip_addr)
        .map_err(|e| format!("Host query failed: {}", e))?
      {
        Some(record) => {
          let payload = host_record_to_json(&record);
          if render::render_machine_output(ctx, "rb database query hosts", &payload)? {
            return Ok(());
          }
          let formatted = query_format::format_host(&record);
          println!("{}", formatted);
        }
        None => {
          let payload = query_host_missing_payload(&ip);
          if render::render_machine_output(ctx, "rb database query hosts", &payload)? {
            return Ok(());
          }
          Output::warning("No fingerprint stored for target");
        }
      }
    } else {
      let records = manager
        .list_hosts()
        .map_err(|e| format!("Host query failed: {}", e))?;
      if records.is_empty() {
        let payload = query_hosts_payload(&records);
        if render::render_machine_output(ctx, "rb database query hosts", &payload)? {
          return Ok(());
        }
        Output::warning("No host fingerprints stored in this database");
      } else {
        let payload = query_hosts_payload(&records);
        if render::render_machine_output(ctx, "rb database query hosts", &payload)? {
          return Ok(());
        }
        Output::header(&format!(
          "Stored Host Fingerprints ({}) - {}",
          records.len(),
          db_path.display()
        ));
        for record in records {
          println!("{}\n", query_format::format_host(&record));
        }
      }
    }
    Ok(())
  }
}

fn host_record_to_json(
  record: &crate::storage::records::HostIntelRecord,
) -> crate::serde_json::Value {
  let services_json: Vec<crate::serde_json::Value> = record
    .services
    .iter()
    .map(|svc| {
      json!({
          "port": svc.port,
          "service_name": svc.service_name.clone().unwrap_or_default(),
          "banner": svc.banner.clone().unwrap_or_default(),
          "os_hints": svc.os_hints.clone()
      })
    })
    .collect();
  json!({
      "ip": record.ip.to_string(),
      "os_family": record.os_family.clone().unwrap_or_default(),
      "confidence": record.confidence,
      "last_seen": record.last_seen,
      "services": services_json
  })
}

fn query_partitions_payload(
  partitions: &[crate::storage::PartitionMetadata],
  segment_filter: Option<String>,
  attr_filter: Option<String>,
) -> Value {
  let partitions_json: Vec<Value> = partitions
    .iter()
    .map(|meta| {
      let segments: Vec<String> = meta
        .segments
        .iter()
        .map(|k| segment_label(*k).to_string())
        .collect();
      let last_refreshed = meta.last_refreshed.map(|ts| {
        ts.duration_since(UNIX_EPOCH)
          .unwrap_or_else(|_| std::time::Duration::from_secs(0))
          .as_secs()
      });
      let mut attributes = crate::serde_json::Map::new();
      let mut attr_items: Vec<_> = meta.attributes.iter().collect();
      attr_items.sort_by(|a, b| a.0.cmp(b.0));
      for (key, value) in attr_items {
        attributes.insert(key.clone(), json!(value.clone()));
      }
      json!({
        "label": meta.label.clone(),
        "key": describe_partition_key(&meta.key),
        "path": meta.storage_path.display().to_string(),
        "segments": segments,
        "last_refreshed": last_refreshed,
        "attributes": Value::Object(attributes)
      })
    })
    .collect();

  json!({
    "count": partitions.len(),
    "segment_filter": segment_filter,
    "attr_filter": attr_filter,
    "partitions": partitions_json
  })
}

fn query_summary_payload(
  db_path: &Path,
  file_size_kb: u64,
  port_count: usize,
  dns_count: usize,
  subdomain_count: usize,
) -> Value {
  json!({
    "file": db_path.display().to_string(),
    "size_kb": file_size_kb,
    "ports": port_count,
    "dns": dns_count,
    "subdomains": subdomain_count
  })
}

fn query_ports_payload(records: &[crate::storage::PortScanRecord]) -> Value {
  let ports_json: Vec<Value> = records
    .iter()
    .map(|record| {
      json!({
        "ip": record.ip.to_string(),
        "port": record.port,
        "status": port_status_label(record.status),
        "timestamp": record.timestamp
      })
    })
    .collect();

  json!({
    "count": records.len(),
    "ports": ports_json
  })
}

fn query_dns_payload(records: &[crate::storage::records::DnsRecordData]) -> Value {
  let records_json: Vec<Value> = records
    .iter()
    .map(|record| {
      json!({
        "domain": record.domain.clone(),
        "type": dns_type_label(record.record_type),
        "value": record.value.clone(),
        "ttl": record.ttl,
        "timestamp": record.timestamp
      })
    })
    .collect();

  json!({
    "count": records.len(),
    "records": records_json
  })
}

fn query_subdomains_payload(records: &[crate::storage::SubdomainRecord]) -> Value {
  let subdomains_json: Vec<String> = records
    .iter()
    .map(|record| record.subdomain.clone())
    .collect();
  json!({
    "count": records.len(),
    "subdomains": subdomains_json
  })
}

fn query_http_payload(host: &str, records: &[crate::storage::records::HttpHeadersRecord]) -> Value {
  let records_json: Vec<Value> = records
    .iter()
    .map(|record| {
      json!({
        "method": record.method.clone(),
        "url": record.url.clone(),
        "http_version": record.http_version.clone(),
        "status_code": record.status_code,
        "status_text": record.status_text.clone(),
        "server": record.server.clone()
      })
    })
    .collect();

  json!({
    "host": host,
    "count": records.len(),
    "records": records_json
  })
}

fn query_tls_payload(host: &str, scans: &[crate::storage::records::TlsScanRecord]) -> Value {
  let scans_json: Vec<Value> = scans
    .iter()
    .map(|scan| {
      json!({
        "port": scan.port,
        "protocol": scan.negotiated_version.clone().unwrap_or_default(),
        "cipher": scan.negotiated_cipher.clone().unwrap_or_default(),
        "certificate_valid": scan.certificate_valid
      })
    })
    .collect();

  json!({
    "host": host,
    "count": scans.len(),
    "scans": scans_json
  })
}

fn query_whois_found_payload(domain: &str, record: &crate::storage::WhoisRecord) -> Value {
  json!({
    "domain": domain,
    "found": true,
    "registrar": record.registrar.clone(),
    "created_date": record.created_date,
    "expires_date": record.expires_date,
    "nameservers": record.nameservers.clone()
  })
}

fn query_whois_missing_payload(domain: &str) -> Value {
  json!({
    "domain": domain,
    "found": false
  })
}

fn query_host_missing_payload(ip: &str) -> Value {
  json!({
    "ip": ip,
    "found": false
  })
}

fn query_hosts_payload(records: &[crate::storage::records::HostIntelRecord]) -> Value {
  let hosts_json: Vec<Value> = records.iter().map(host_record_to_json).collect();
  json!({
    "count": records.len(),
    "hosts": hosts_json
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn query_summary_payload_reports_counts() {
    let payload = query_summary_payload(Path::new("/tmp/sample.rdb"), 128, 10, 20, 30);
    assert_eq!(payload["size_kb"], json!(128));
    assert_eq!(payload["ports"], json!(10));
    assert_eq!(payload["subdomains"], json!(30));
  }

  #[test]
  fn query_host_missing_payload_marks_not_found() {
    let payload = query_host_missing_payload("192.0.2.10");
    assert_eq!(payload["ip"], json!("192.0.2.10"));
    assert_eq!(payload["found"], json!(false));
  }
}
