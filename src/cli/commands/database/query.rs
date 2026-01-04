//! Query mode handlers (rb database query <dataset>)

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::cli::commands::annotate_query_partition;
use crate::cli::output::Output;
use crate::cli::CliContext;
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
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let service = StorageService::global();

        let mut partitions = service.partitions();

        if let Some(segment_name) = ctx.get_flag("segment") {
            let segment = parse_segment_kind(&segment_name)?;
            partitions.retain(|meta| meta.segments.contains(&segment));
        }

        if let Some(attr_filter) = ctx.get_flag("attr") {
            let (key, value) = parse_attr_filter(&attr_filter)?;
            partitions.retain(|meta| {
                meta.attributes
                    .get(key)
                    .map(|candidate| candidate == value)
                    .unwrap_or(false)
            });
        }

        partitions.sort_by(|a, b| a.label.cmp(&b.label));

        if is_json {
            println!("{{");
            println!("  \"count\": {},", partitions.len());
            println!(
                "  \"segment_filter\": {},",
                ctx.get_flag("segment")
                    .map(|s| format!("\"{}\"", s))
                    .unwrap_or_else(|| "null".to_string())
            );
            println!(
                "  \"attr_filter\": {},",
                ctx.get_flag("attr")
                    .map(|s| format!("\"{}\"", s))
                    .unwrap_or_else(|| "null".to_string())
            );
            println!("  \"partitions\": [");
            for (i, meta) in partitions.iter().enumerate() {
                let comma = if i < partitions.len() - 1 { "," } else { "" };
                let segments: Vec<_> = meta.segments.iter().map(|k| segment_label(*k)).collect();
                let last_refreshed = meta.last_refreshed.map(|ts| {
                    ts.duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                        .as_secs()
                });
                println!("    {{");
                println!("      \"label\": \"{}\",", meta.label.replace('"', "\\\""));
                println!("      \"key\": \"{}\",", describe_partition_key(&meta.key));
                println!(
                    "      \"path\": \"{}\",",
                    meta.storage_path
                        .display()
                        .to_string()
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                );
                println!(
                    "      \"segments\": [{}],",
                    segments
                        .iter()
                        .map(|s| format!("\"{}\"", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if let Some(epoch) = last_refreshed {
                    println!("      \"last_refreshed\": {},", epoch);
                } else {
                    println!("      \"last_refreshed\": null,");
                }
                println!("      \"attributes\": {{");
                let attr_items: Vec<_> = meta.attributes.iter().collect();
                for (ai, (key, value)) in attr_items.iter().enumerate() {
                    let attr_comma = if ai < attr_items.len() - 1 { "," } else { "" };
                    println!(
                        "        \"{}\": \"{}\"{}",
                        key,
                        value.replace('"', "\\\""),
                        attr_comma
                    );
                }
                println!("      }}");
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
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
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

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
        if !is_json {
            Output::spinner_start("Reading database");
        }
        let mut db = open_db(db_path)?;
        let port_scans = read_port_scans(&mut db)?;
        let dns_records = read_dns_records(&mut db)?;
        let subdomains = read_subdomains(&mut db)?;
        if !is_json {
            Output::spinner_done();
        }

        let metadata =
            fs::metadata(db_path).map_err(|e| format!("Failed to read file metadata: {}", e))?;
        let file_size_kb = metadata.len() / 1024;

        if is_json {
            println!("{{");
            println!(
                "  \"file\": \"{}\",",
                db_path
                    .display()
                    .to_string()
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
            );
            println!("  \"size_kb\": {},", file_size_kb);
            println!("  \"ports\": {},", port_scans.len());
            println!("  \"dns\": {},", dns_records.len());
            println!("  \"subdomains\": {}", subdomains.len());
            println!("}}");
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
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

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

        if is_json {
            println!("{{");
            println!("  \"count\": {},", records.len());
            println!("  \"ports\": [");
            for (i, record) in records.iter().enumerate() {
                let comma = if i < records.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"ip\": \"{}\",", record.ip);
                println!("      \"port\": {},", record.port);
                println!(
                    "      \"status\": \"{}\",",
                    port_status_label(record.status)
                );
                println!("      \"timestamp\": {}", record.timestamp);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
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
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

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

        if is_json {
            println!("{{");
            println!("  \"count\": {},", records.len());
            println!("  \"records\": [");
            for (i, record) in records.iter().enumerate() {
                let comma = if i < records.len() - 1 { "," } else { "" };
                println!("    {{");
                println!(
                    "      \"domain\": \"{}\",",
                    record.domain.replace('"', "\\\"")
                );
                println!(
                    "      \"type\": \"{}\",",
                    dns_type_label(record.record_type)
                );
                println!(
                    "      \"value\": \"{}\",",
                    record.value.replace('"', "\\\"")
                );
                println!("      \"ttl\": {},", record.ttl);
                println!("      \"timestamp\": {}", record.timestamp);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
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
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

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

        if is_json {
            println!("{{");
            println!("  \"count\": {},", records.len());
            println!("  \"subdomains\": [");
            for (i, record) in records.iter().enumerate() {
                let comma = if i < records.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", record.subdomain.replace('"', "\\\""), comma);
            }
            println!("  ]");
            println!("}}");
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
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

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

        if is_json {
            println!("{{");
            println!("  \"host\": \"{}\",", host.replace('"', "\\\""));
            println!("  \"count\": {},", records.len());
            println!("  \"records\": [");
            for (i, record) in records.iter().enumerate() {
                let comma = if i < records.len() - 1 { "," } else { "" };
                println!("    {{");
                println!(
                    "      \"method\": \"{}\",",
                    record.method.replace('"', "\\\"")
                );
                println!("      \"url\": \"{}\",", record.url.replace('"', "\\\""));
                println!(
                    "      \"http_version\": \"{}\",",
                    record.http_version.replace('"', "\\\"")
                );
                println!("      \"status_code\": {},", record.status_code);
                println!(
                    "      \"status_text\": \"{}\",",
                    record.status_text.replace('"', "\\\"")
                );
                if let Some(server) = &record.server {
                    println!("      \"server\": \"{}\"", server.replace('"', "\\\""));
                } else {
                    println!("      \"server\": null");
                }
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
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
                record.method,
                record.url,
                record.http_version,
                record.status_code,
                record.status_text
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
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

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
            if is_json {
                println!("{{");
                println!("  \"host\": \"{}\",", host.replace('"', "\\\""));
                println!("  \"count\": 0,");
                println!("  \"scans\": []");
                println!("}}");
                return Ok(());
            }
            Output::warning("No TLS scans stored for this host");
            return Ok(());
        }

        if is_json {
            println!("{{");
            println!("  \"host\": \"{}\",", host.replace('"', "\\\""));
            println!("  \"count\": {},", scans.len());
            println!("  \"scans\": [");
            for (i, scan) in scans.iter().enumerate() {
                let comma = if i < scans.len() - 1 { "," } else { "" };
                let cipher = scan.negotiated_cipher.as_deref().unwrap_or("");
                let version = scan.negotiated_version.as_deref().unwrap_or("");
                println!("    {{");
                println!("      \"port\": {},", scan.port);
                println!("      \"protocol\": \"{}\",", version.replace('"', "\\\""));
                println!("      \"cipher\": \"{}\",", cipher.replace('"', "\\\""));
                println!("      \"certificate_valid\": {}", scan.certificate_valid);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
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
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

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
                if is_json {
                    println!("{{");
                    println!("  \"domain\": \"{}\",", domain.replace('"', "\\\""));
                    println!(
                        "  \"registrar\": \"{}\",",
                        record.registrar.replace('"', "\\\"")
                    );
                    println!("  \"created_date\": {},", record.created_date);
                    println!("  \"expires_date\": {},", record.expires_date);
                    println!("  \"nameservers\": [");
                    for (i, ns) in record.nameservers.iter().enumerate() {
                        let comma = if i < record.nameservers.len() - 1 {
                            ","
                        } else {
                            ""
                        };
                        println!("    \"{}\"{}", ns.replace('"', "\\\""), comma);
                    }
                    println!("  ]");
                    println!("}}");
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
                if is_json {
                    println!("{{");
                    println!("  \"domain\": \"{}\",", domain.replace('"', "\\\""));
                    println!("  \"found\": false");
                    println!("}}");
                    return Ok(());
                }
                Output::warning("No WHOIS record stored for this domain");
            }
        }
        Ok(())
    }

    fn query_hosts(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

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
                    if is_json {
                        self.output_host_json(&record);
                        return Ok(());
                    }
                    let formatted = query_format::format_host(&record);
                    println!("{}", formatted);
                }
                None => {
                    if is_json {
                        println!("{{");
                        println!("  \"ip\": \"{}\",", ip);
                        println!("  \"found\": false");
                        println!("}}");
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
                if is_json {
                    println!("{{");
                    println!("  \"count\": 0,");
                    println!("  \"hosts\": []");
                    println!("}}");
                    return Ok(());
                }
                Output::warning("No host fingerprints stored in this database");
            } else {
                if is_json {
                    println!("{{");
                    println!("  \"count\": {},", records.len());
                    println!("  \"hosts\": [");
                    for (i, record) in records.iter().enumerate() {
                        let comma = if i < records.len() - 1 { "," } else { "" };
                        print!("    ");
                        self.output_host_json_inline(record);
                        println!("{}", comma);
                    }
                    println!("  ]");
                    println!("}}");
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

    pub(super) fn output_host_json(&self, record: &crate::storage::records::HostIntelRecord) {
        let os = record.os_family.as_deref().unwrap_or("");
        println!("{{");
        println!("  \"ip\": \"{}\",", record.ip);
        println!("  \"os_family\": \"{}\",", os.replace('"', "\\\""));
        println!("  \"confidence\": {},", record.confidence);
        println!("  \"last_seen\": {},", record.last_seen);
        println!("  \"services\": [");
        for (i, svc) in record.services.iter().enumerate() {
            let comma = if i < record.services.len() - 1 {
                ","
            } else {
                ""
            };
            let svc_name = svc.service_name.as_deref().unwrap_or("");
            let banner = svc.banner.as_deref().unwrap_or("");
            println!("    {{");
            println!("      \"port\": {},", svc.port);
            println!(
                "      \"service_name\": \"{}\",",
                svc_name.replace('"', "\\\"")
            );
            println!(
                "      \"banner\": \"{}\",",
                banner.replace('"', "\\\"").replace('\n', "\\n")
            );
            println!("      \"os_hints\": [");
            for (j, hint) in svc.os_hints.iter().enumerate() {
                let hint_comma = if j < svc.os_hints.len() - 1 { "," } else { "" };
                println!("        \"{}\"{}", hint.replace('"', "\\\""), hint_comma);
            }
            println!("      ]");
            println!("    }}{}", comma);
        }
        println!("  ]");
        println!("}}");
    }

    pub(super) fn output_host_json_inline(
        &self,
        record: &crate::storage::records::HostIntelRecord,
    ) {
        let os = record.os_family.as_deref().unwrap_or("");
        print!("{{\"ip\":\"{}\",\"os_family\":\"{}\",\"confidence\":{},\"last_seen\":{},\"services\":[",
            record.ip, os.replace('"', "\\\""), record.confidence, record.last_seen);
        for (i, svc) in record.services.iter().enumerate() {
            let comma = if i < record.services.len() - 1 {
                ","
            } else {
                ""
            };
            let svc_name = svc.service_name.as_deref().unwrap_or("");
            let banner = svc.banner.as_deref().unwrap_or("");
            print!(
                "{{\"port\":{},\"service_name\":\"{}\",\"banner\":\"{}\",\"os_hints\":[",
                svc.port,
                svc_name.replace('"', "\\\""),
                banner.replace('"', "\\\"").replace('\n', "\\n")
            );
            for (j, hint) in svc.os_hints.iter().enumerate() {
                let hint_comma = if j < svc.os_hints.len() - 1 { "," } else { "" };
                print!("\"{}\"{}", hint.replace('"', "\\\""), hint_comma);
            }
            print!("]}}{}", comma);
        }
        print!("]}}");
    }
}
