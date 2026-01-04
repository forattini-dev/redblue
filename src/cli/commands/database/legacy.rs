//! Legacy data mode handlers (rb database data <verb>)

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::cli::commands::print_help;
use crate::cli::output::Output;
use crate::cli::CliContext;

use super::helpers::{
    collect_rdb_files, dns_type_label, open_db, port_status_label, read_dns_records,
    read_port_scans, read_subdomains, read_summary, DbSummary,
};
use super::DatabaseCommand;

impl DatabaseCommand {
    /// Execute legacy data mode commands
    pub(super) fn execute_legacy(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "query" => self.legacy_query(ctx),
            "export" => self.export(ctx),
            "list" => self.list(ctx),
            "subnets" => self.list_subnets(ctx),
            "doctor" => self.doctor(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                Err("Invalid verb".to_string())
            }
        }
    }

    fn legacy_query(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing database file.\nUsage: rb database data query <file.rdb>\nExample: rb database data query 192.168.1.1.rdb",
        )?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("Database file not found: {}", file_path));
        }

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        if !is_json {
            Output::spinner_start("Reading database");
        }
        let mut db = open_db(path)?;
        let port_scans = read_port_scans(&mut db)?;
        let dns_records = read_dns_records(&mut db)?;
        let subdomains = read_subdomains(&mut db)?;
        if !is_json {
            Output::spinner_done();
        }

        let metadata =
            fs::metadata(path).map_err(|e| format!("Failed to read file metadata: {}", e))?;
        let file_size_kb = metadata.len() / 1024;
        let total_records = port_scans.len() + dns_records.len() + subdomains.len();

        if is_json {
            println!("{{");
            println!(
                "  \"file\": \"{}\",",
                file_path.replace('\\', "\\\\").replace('"', "\\\"")
            );
            println!("  \"size_kb\": {},", file_size_kb);
            println!("  \"format\": \"REDBLUE v1\",");
            println!("  \"total_records\": {},", total_records);
            println!("  \"statistics\": {{");
            println!("    \"port_scans\": {},", port_scans.len());
            println!("    \"dns_records\": {},", dns_records.len());
            println!("    \"subdomains\": {}", subdomains.len());
            println!("  }},");
            println!("  \"port_scans\": [");
            for (i, record) in port_scans.iter().enumerate() {
                let comma = if i < port_scans.len() - 1 { "," } else { "" };
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
            println!("  ],");
            println!("  \"dns_records\": [");
            for (i, record) in dns_records.iter().enumerate() {
                let comma = if i < dns_records.len() - 1 { "," } else { "" };
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
            println!("  ],");
            println!("  \"subdomains\": [");
            for (i, record) in subdomains.iter().enumerate() {
                let comma = if i < subdomains.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", record.subdomain.replace('"', "\\\""), comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        Output::header(&format!("Database: {}", file_path));

        Output::summary_line(&[
            ("Size", &format!("{} KB", file_size_kb)),
            ("Format", "REDBLUE v1"),
            ("Records", &total_records.to_string()),
        ]);

        println!();
        Output::subheader("Statistics");
        println!("  Port scans: {}", port_scans.len());
        println!("  DNS records: {}", dns_records.len());
        println!("  Subdomains: {}", subdomains.len());

        if !port_scans.is_empty() {
            println!();
            Output::subheader(&format!(
                "Port Scans ({}) - showing first 10",
                port_scans.len()
            ));
            for record in port_scans.iter().take(10) {
                let state = port_status_label(record.status);
                println!(
                    "  {}:{} - {} (timestamp: {})",
                    record.ip, record.port, state, record.timestamp
                );
            }
            if port_scans.len() > 10 {
                println!("  ... and {} more", port_scans.len() - 10);
            }
        }

        if !dns_records.is_empty() {
            println!();
            Output::subheader(&format!("DNS Records ({})", dns_records.len()));
            println!("  {} DNS records stored", dns_records.len());
        }

        println!();
        Output::success("Query completed");
        Ok(())
    }

    fn export(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing database file.\nUsage: rb database data export <file.rdb>\nExample: rb database data export 192.168.1.1.rdb",
        )?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("Database file not found: {}", file_path));
        }

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let output_path = if let Some(output) = ctx.get_flag("output") {
            output.to_string()
        } else {
            format!("{}.csv", file_path.trim_end_matches(".rdb"))
        };

        if !is_json {
            Output::spinner_start("Exporting database");
        }
        let mut db = open_db(path)?;
        let port_scans = read_port_scans(&mut db)?;
        let dns_records = read_dns_records(&mut db)?;
        if !is_json {
            Output::spinner_done();
        }

        let mut csv_content = String::new();

        if !port_scans.is_empty() {
            csv_content.push_str("# Port Scans\n");
            csv_content.push_str("IP,Port,State,Service,Timestamp\n");
            for record in &port_scans {
                let state = port_status_label(record.status);
                let service = "unknown";
                csv_content.push_str(&format!(
                    "{},{},{},{},{}\n",
                    record.ip, record.port, state, service, record.timestamp
                ));
            }
            csv_content.push('\n');
        }

        if !dns_records.is_empty() {
            csv_content.push_str("# DNS Records\n");
            csv_content.push_str("Domain,Type,Value,TTL,Timestamp\n");
            for record in &dns_records {
                csv_content.push_str(&format!(
                    "{},{},{},{},{}\n",
                    record.domain,
                    dns_type_label(record.record_type),
                    record.value,
                    record.ttl,
                    record.timestamp
                ));
            }
            csv_content.push('\n');
        }

        fs::write(&output_path, &csv_content)
            .map_err(|e| format!("Failed to write CSV file {}: {}", output_path, e))?;

        if is_json {
            println!("{{");
            println!(
                "  \"source\": \"{}\",",
                file_path.replace('\\', "\\\\").replace('"', "\\\"")
            );
            println!(
                "  \"output\": \"{}\",",
                output_path.replace('\\', "\\\\").replace('"', "\\\"")
            );
            println!("  \"port_scans_exported\": {},", port_scans.len());
            println!("  \"dns_records_exported\": {},", dns_records.len());
            println!("  \"bytes_written\": {},", csv_content.len());
            println!("  \"success\": true");
            println!("}}");
            return Ok(());
        }

        Output::success(&format!("Exported database to {}", output_path));
        Ok(())
    }

    pub(super) fn doctor(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing database file.\nUsage: rb database data doctor <file.rdb>\nExample: rb database data doctor recon.rdb",
        )?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("Database file not found: {}", file_path));
        }

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let bytes = fs::read(path).map_err(|e| format!("Failed to read {}: {}", file_path, e))?;

        let mut db = open_db(path)?;

        let ports = db
            .count_collection("ports")
            .map_err(|e| format!("Failed to read ports: {}", e))?;
        let subdomains = db
            .count_collection("domains")
            .map_err(|e| format!("Failed to read subdomains: {}", e))?;
        let dns = db
            .count_collection("dns")
            .map_err(|e| format!("Failed to read DNS records: {}", e))?;
        let http = db
            .count_collection("http")
            .map_err(|e| format!("Failed to read HTTP records: {}", e))?;
        let tls = db
            .count_collection("tls")
            .map_err(|e| format!("Failed to read TLS records: {}", e))?;
        let whois = db
            .count_collection("whois")
            .map_err(|e| format!("Failed to read WHOIS records: {}", e))?;
        let hosts = db
            .count_collection("hosts")
            .map_err(|e| format!("Failed to read host intel: {}", e))?;

        if is_json {
            println!("{{");
            println!(
                "  \"file\": \"{}\",",
                file_path.replace('\\', "\\\\").replace('"', "\\\"")
            );
            println!("  \"size_bytes\": {},", bytes.len());
            println!("  \"record_counts\": {{");
            println!("    \"ports\": {},", ports);
            println!("    \"subdomains\": {},", subdomains);
            println!("    \"dns\": {},", dns);
            println!("    \"http\": {},", http);
            println!("    \"tls\": {},", tls);
            println!("    \"whois\": {},", whois);
            println!("    \"hosts\": {}", hosts);
            println!("  }},");
            println!("  \"valid\": true");
            println!("}}");
            return Ok(());
        }

        Output::header(&format!("Database Doctor: {}", file_path));
        let size_str = format!("{} bytes", bytes.len());
        Output::summary_line(&[("Size", &size_str), ("Format", "UnifiedStore")]);

        println!();
        Output::subheader("Record Counts");
        println!("  Ports ............ {}", ports);
        println!("  Subdomains ....... {}", subdomains);
        println!("  DNS Records ...... {}", dns);
        println!("  HTTP Captures .... {}", http);
        println!("  TLS Scans ........ {}", tls);
        println!("  WHOIS Records .... {}", whois);
        println!("  Host Fingerprints  {}", hosts);

        println!();
        Output::success("Validation completed");
        Ok(())
    }

    fn list(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let current_dir = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;

        let rdb_files = collect_rdb_files(&current_dir)?;

        if is_json {
            println!("{{");
            println!(
                "  \"directory\": \"{}\",",
                current_dir
                    .display()
                    .to_string()
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
            );
            println!("  \"count\": {},", rdb_files.len());
            println!("  \"files\": [");
            for (i, file) in rdb_files.iter().enumerate() {
                let comma = if i < rdb_files.len() - 1 { "," } else { "" };
                println!(
                    "    \"{}\"{}",
                    file.display()
                        .to_string()
                        .replace('\\', "\\\\")
                        .replace('"', "\\\""),
                    comma
                );
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        Output::header("Available Database Files");

        if rdb_files.is_empty() {
            Output::warning("No .rdb files found in current directory");
            return Ok(());
        }

        for file in &rdb_files {
            println!("  {}", file.display());
        }

        Output::success(&format!("Found {} database file(s)", rdb_files.len()));
        Ok(())
    }

    fn list_subnets(&self, ctx: &CliContext) -> Result<(), String> {
        use std::collections::HashMap;

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let current_dir = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;

        let rdb_files = collect_rdb_files(&current_dir)?;

        let mut subnets: HashMap<String, Vec<String>> = HashMap::new();
        let mut summaries: HashMap<String, DbSummary> = HashMap::new();

        for path in &rdb_files {
            let file_name = path.file_stem().unwrap().to_string_lossy().to_string();

            if let Ok(ip) = file_name.parse::<Ipv4Addr>() {
                let octets = ip.octets();
                let subnet_key = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);

                subnets
                    .entry(subnet_key)
                    .or_insert_with(Vec::new)
                    .push(file_name.clone());

                if let Ok(summary) = read_summary(path) {
                    summaries.insert(file_name, summary);
                }
            }
        }

        if is_json {
            let mut sorted_subnets: Vec<_> = subnets.iter().collect();
            sorted_subnets.sort_by_key(|(k, _)| *k);

            println!("{{");
            println!("  \"total_subnets\": {},", subnets.len());
            println!("  \"total_hosts\": {},", rdb_files.len());
            println!("  \"subnets\": [");
            for (si, (subnet, hosts)) in sorted_subnets.iter().enumerate() {
                let subnet_comma = if si < sorted_subnets.len() - 1 {
                    ","
                } else {
                    ""
                };
                let mut sorted_hosts = (*hosts).clone();
                sorted_hosts.sort_by_key(|ip_str| {
                    ip_str
                        .parse::<Ipv4Addr>()
                        .map(|ip| ip.octets()[3])
                        .unwrap_or(0)
                });
                println!("    {{");
                println!("      \"subnet\": \"{}\",", subnet);
                println!("      \"host_count\": {},", hosts.len());
                println!("      \"hosts\": [");
                for (hi, host) in sorted_hosts.iter().enumerate() {
                    let host_comma = if hi < sorted_hosts.len() - 1 { "," } else { "" };
                    if let Some(summary) = summaries.get(host) {
                        println!("        {{");
                        println!("          \"ip\": \"{}\",", host);
                        println!("          \"port_scans\": {},", summary.port_scans);
                        println!("          \"dns_records\": {},", summary.dns_records);
                        println!("          \"subdomains\": {}", summary.subdomains);
                        println!("        }}{}", host_comma);
                    } else {
                        println!("        {{");
                        println!("          \"ip\": \"{}\"", host);
                        println!("        }}{}", host_comma);
                    }
                }
                println!("      ]");
                println!("    }}{}", subnet_comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        Output::header("Discovered Subnets");

        if rdb_files.is_empty() {
            Output::warning("No .rdb files found in current directory");
            return Ok(());
        }

        if subnets.is_empty() {
            Output::warning(
                "No IP-based databases found (databases must be named like 192.168.1.1.rdb)",
            );
            return Ok(());
        }

        let mut sorted_subnets: Vec<_> = subnets.iter().collect();
        sorted_subnets.sort_by_key(|(k, _)| *k);

        println!();
        for (subnet, hosts) in sorted_subnets {
            println!("  {} - {} host(s)", subnet, hosts.len());
            let mut sorted_hosts = hosts.clone();
            sorted_hosts.sort_by_key(|ip_str| {
                ip_str
                    .parse::<Ipv4Addr>()
                    .map(|ip| ip.octets()[3])
                    .unwrap_or(0)
            });

            for host in sorted_hosts {
                if let Some(summary) = summaries.get(&host) {
                    let mut info_parts = Vec::new();
                    if summary.port_scans > 0 {
                        info_parts.push(format!("{} ports", summary.port_scans));
                    }
                    if summary.dns_records > 0 {
                        info_parts.push(format!("{} DNS", summary.dns_records));
                    }
                    if summary.subdomains > 0 {
                        info_parts.push(format!("{} subdomains", summary.subdomains));
                    }

                    let info = if info_parts.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", info_parts.join(", "))
                    };

                    println!("    • {}{}", host, info);
                } else {
                    println!("    • {}", host);
                }
            }
            println!();
        }

        Output::success(&format!(
            "Found {} subnet(s) with {} total host(s)",
            subnets.len(),
            rdb_files.len()
        ));
        Ok(())
    }
}
