/// Database commands - RedDb inspection, legacy tooling compatibility.
use crate::cli::commands::{annotate_query_partition, print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::storage::client::query::format as query_format;
use crate::storage::encoding::IpKey;
use crate::storage::layout::{FileHeader, SegmentKind, SectionEntry, SegmentMetadata};
use crate::storage::reddb::RedDb;
use crate::storage::records::{
    DnsRecordData, DnsRecordType, PortScanRecord, PortStatus, SubdomainRecord,
};
use crate::storage::service::{PartitionKey, StorageService};
use std::fs;
use std::io::Cursor;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Two faces for the database command:
/// - `data`: legacy interface (`rb database data query file.rdb`)
/// - `query`: new resource-first interface (`rb database query dns --db file.rdb`)
#[derive(Clone, Copy)]
pub enum DatabaseMode {
    Data,
    Query,
}

pub struct DatabaseCommand {
    mode: DatabaseMode,
}

impl DatabaseCommand {
    pub const fn new(mode: DatabaseMode) -> Self {
        Self { mode }
    }

    const fn mode_label(&self) -> &'static str {
        match self.mode {
            DatabaseMode::Data => "data",
            DatabaseMode::Query => "query",
        }
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(DatabaseCommand::new(DatabaseMode::Data)),
        Box::new(DatabaseCommand::new(DatabaseMode::Query)),
    ]
}

impl Command for DatabaseCommand {
    fn domain(&self) -> &str {
        "database"
    }

    fn resource(&self) -> &str {
        match self.mode {
            DatabaseMode::Data => "data",
            DatabaseMode::Query => "query",
        }
    }

    fn description(&self) -> &str {
        match self.mode {
            DatabaseMode::Data => "Query and export binary database files (.rdb)",
            DatabaseMode::Query => "Filter RedDb contents by dataset (ports, dns, subdomains, ...)",
        }
    }

    fn routes(&self) -> Vec<Route> {
        match self.mode {
            DatabaseMode::Data => vec![
                Route {
                    verb: "query",
                    summary: "Display database contents and statistics",
                    usage: "rb database data query <file.rdb>",
                },
                Route {
                    verb: "export",
                    summary: "Export database to CSV format",
                    usage: "rb database data export <file.rdb> [--output file.csv]",
                },
                Route {
                    verb: "list",
                    summary: "List .rdb files in the current directory",
                    usage: "rb database data list",
                },
                Route {
                    verb: "subnets",
                    summary: "List discovered subnets with host counts",
                    usage: "rb database data subnets",
                },
                Route {
                    verb: "doctor",
                    summary: "Validate RedDb structure and show segment health",
                    usage: "rb database data doctor <file.rdb>",
                },
            ],
            DatabaseMode::Query => vec![
                Route {
                    verb: "summary",
                    summary: "Show RedDb summary (size, record counts)",
                    usage: "rb database query summary --db scan.rdb",
                },
                Route {
                    verb: "ports",
                    summary: "List ports, optionally constrained by IP range",
                    usage: "rb database query ports --db scan.rdb [--ip-range 192.0.2.1-192.0.2.200]",
                },
                Route {
                    verb: "dns",
                    summary: "List DNS records (supports --dns-prefix)",
                    usage: "rb database query dns --db scan.rdb [--dns-prefix mail.]",
                },
                Route {
                    verb: "subdomains",
                    summary: "List subdomains (supports --subdomain-prefix)",
                    usage: "rb database query subdomains --db scan.rdb [--subdomain-prefix api.]",
                },
                Route {
                    verb: "http",
                    summary: "List HTTP captures (supports --host)",
                    usage: "rb database query http --db scan.rdb [--host example.com]",
                },
                Route {
                    verb: "tls",
                    summary: "List TLS scan results (supports --host)",
                    usage: "rb database query tls --db scan.rdb [--host example.com]",
                },
                Route {
                    verb: "whois",
                    summary: "List WHOIS records (supports --domain)",
                    usage: "rb database query whois --db scan.rdb [--domain example.com]",
                },
                Route {
                    verb: "hosts",
                    summary: "List host fingerprints (supports --ip)",
                    usage: "rb database query hosts --db scan.rdb [--ip 192.0.2.10]",
                },
            ],
        }
    }

    fn flags(&self) -> Vec<Flag> {
        match self.mode {
            DatabaseMode::Data => vec![
                Flag::new("output", "Output file path for export").with_short('o'),
                Flag::new("format", "Output format (text, json)").with_default("text"),
            ],
            DatabaseMode::Query => vec![
                Flag::new("db", "Path to the RedDb file to query"),
                Flag::new("database", "Alias for --db"),
                Flag::new("ip-range", "Filter ports by inclusive IP range (start-end)"),
                Flag::new(
                    "subdomain-prefix",
                    "Only include subdomains that start with the provided prefix",
                ),
                Flag::new(
                    "dns-prefix",
                    "Only include DNS records whose domain starts with the provided prefix",
                ),
                Flag::new("host", "Filter HTTP/TLS/host intel by hostname"),
                Flag::new("domain", "Filter WHOIS/DNS by domain"),
                Flag::new("ip", "Filter host intel by IP address"),
                Flag::new(
                    "segment",
                    "Filter partition listings by segment (ports|dns|http|tls|subdomains|whois|host)",
                ),
                Flag::new(
                    "attr",
                    "Filter partition listings by attribute key=value (e.g., category=target)",
                ),
                Flag::new("format", "Output format (text, json)").with_default("text"),
            ],
        }
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        match self.mode {
            DatabaseMode::Data => vec![
                ("Query database", "rb database data query 192.168.1.1.rdb"),
                (
                    "Export to CSV",
                    "rb database data export 192.168.1.1.rdb --output scan.csv",
                ),
                ("List databases", "rb database data list"),
                ("List subnets", "rb database data subnets"),
                ("Validate database", "rb database data doctor recon.rdb"),
            ],
            DatabaseMode::Query => vec![
                ("Summary", "rb database query summary --db recon.rdb"),
                (
                    "Ports in a CIDR window",
                    "rb database query ports --db recon.rdb --ip-range 10.0.0.1-10.0.0.255",
                ),
                (
                    "DNS prefix match",
                    "rb database query dns --db recon.rdb --dns-prefix mail.",
                ),
                (
                    "Subdomain prefix match",
                    "rb database query subdomains --db recon.rdb --subdomain-prefix api.",
                ),
                (
                    "TLS scans for host",
                    "rb database query tls --db recon.rdb --host example.com",
                ),
                (
                    "Partition overview",
                    "rb database query partitions --db recon.rdb --segment tls",
                ),
            ],
        }
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        match self.mode {
            DatabaseMode::Data => self.execute_legacy(ctx),
            DatabaseMode::Query => self.execute_query(ctx),
        }
    }
}

// ----------------------------------------------------------------------------- //
// Legacy handlers (rb database data <verb>)
// ----------------------------------------------------------------------------- //
struct DbSummary {
    total_records: usize,
    port_scans: usize,
    dns_records: usize,
    subdomains: usize,
}

impl DatabaseCommand {
    fn execute_legacy(&self, ctx: &CliContext) -> Result<(), String> {
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
        let mut db = Self::open_db(path)?;
        let port_scans = Self::read_port_scans(&mut db)?;
        let dns_records = Self::read_dns_records(&mut db)?;
        let subdomains = Self::read_subdomains(&mut db)?;
        if !is_json {
            Output::spinner_done();
        }

        let metadata =
            fs::metadata(path).map_err(|e| format!("Failed to read file metadata: {}", e))?;
        let file_size_kb = metadata.len() / 1024;
        let total_records = port_scans.len() + dns_records.len() + subdomains.len();

        if is_json {
            println!("{{");
            println!("  \"file\": \"{}\",", file_path.replace('\\', "\\\\").replace('"', "\\\""));
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
                println!("      \"status\": \"{}\",", Self::port_status_label(record.status));
                println!("      \"timestamp\": {}", record.timestamp);
                println!("    }}{}", comma);
            }
            println!("  ],");
            println!("  \"dns_records\": [");
            for (i, record) in dns_records.iter().enumerate() {
                let comma = if i < dns_records.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"domain\": \"{}\",", record.domain.replace('"', "\\\""));
                println!("      \"type\": \"{}\",", Self::dns_type_label(record.record_type));
                println!("      \"value\": \"{}\",", record.value.replace('"', "\\\""));
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
                let state = Self::port_status_label(record.status);
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
        let mut db = Self::open_db(path)?;
        let port_scans = Self::read_port_scans(&mut db)?;
        let dns_records = Self::read_dns_records(&mut db)?;
        if !is_json {
            Output::spinner_done();
        }

        let mut csv_content = String::new();

        if !port_scans.is_empty() {
            csv_content.push_str("# Port Scans\n");
            csv_content.push_str("IP,Port,State,Service,Timestamp\n");
            for record in &port_scans {
                let state = Self::port_status_label(record.status);
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
                    Self::dns_type_label(record.record_type),
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
            println!("  \"source\": \"{}\",", file_path.replace('\\', "\\\\").replace('"', "\\\""));
            println!("  \"output\": \"{}\",", output_path.replace('\\', "\\\\").replace('"', "\\\""));
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

    fn doctor(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing database file.\nUsage: rb database data doctor <file.rdb>\nExample: rb database data doctor recon.rdb",
        )?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("Database file not found: {}", file_path));
        }

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let bytes = fs::read(path)
            .map_err(|e| format!("Failed to read {}: {}", file_path, e))?;
        if bytes.len() < FileHeader::SIZE {
            return Err("File too small to be a valid RedDb archive".to_string());
        }

        let header = FileHeader::read(Cursor::new(&bytes[..]))
            .map_err(|e| format!("Corrupted header: {}", e.0))?;
        let dir_start = header.directory_offset as usize;
        let dir_len =
            header.section_count as usize * SectionEntry::size_for_version(header.version);
        if dir_start + dir_len > bytes.len() {
            return Err("Section directory extends beyond file bounds".to_string());
        }
        let directory = SectionEntry::read_all(
            &bytes[dir_start..dir_start + dir_len],
            header.section_count as usize,
            header.version,
        )
        .map_err(|e| format!("Failed to parse directory: {}", e.0))?;

        let mut db = RedDb::open(path).map_err(|e| format!("Failed to open database: {}", e))?;

        let ports = {
            let mut table = db.ports();
            table
                .count()
                .map_err(|e| format!("Failed to read ports: {}", e))?
        };

        let subdomains = {
            let mut table = db.subdomains();
            table
                .get_all()
                .map_err(|e| format!("Failed to read subdomains: {}", e))?
                .len()
        };

        let dns = {
            let mut table = db.dns();
            table.iter().count()
        };

        let http = {
            let mut table = db.http();
            table.iter().count()
        };

        let tls = {
            let table = db.tls();
            table.iter().count()
        };

        let whois = {
            let table = db.whois();
            table.iter().count()
        };

        let hosts = {
            let mut table = db.hosts();
            table
                .all()
                .map_err(|e| format!("Failed to read host intel: {}", e))?
                .len()
        };

        if is_json {
            println!("{{");
            println!("  \"file\": \"{}\",", file_path.replace('\\', "\\\\").replace('"', "\\\""));
            println!("  \"size_bytes\": {},", bytes.len());
            println!("  \"version\": {},", header.version);
            println!("  \"segment_count\": {},", header.section_count);
            println!("  \"segments\": [");
            for (i, entry) in directory.iter().enumerate() {
                let label = Self::segment_label(entry.kind);
                let end = entry.offset.checked_add(entry.length).unwrap_or(u64::MAX);
                let valid = end as usize <= bytes.len();
                let comma = if i < directory.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"name\": \"{}\",", label);
                println!("      \"offset\": {},", entry.offset);
                println!("      \"length\": {},", entry.length);
                println!("      \"valid\": {}", valid);
                println!("    }}{}", comma);
            }
            println!("  ],");
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
        let version_str = header.version.to_string();
        let segment_str = header.section_count.to_string();
        Output::summary_line(&[("Size", &size_str), ("Version", &version_str), ("Segments", &segment_str)]);

        println!();
        Output::subheader("Segment Directory");
        for entry in &directory {
            let label = Self::segment_label(entry.kind);
            let end = entry
                .offset
                .checked_add(entry.length)
                .unwrap_or(u64::MAX);
            let status = if end as usize > bytes.len() {
                "INVALID"
            } else {
                "ok"
            };
            println!(
                "  {:<12} offset {:>10} len {:>10} [{}]",
                label, entry.offset, entry.length, status
            );
            if entry.metadata_length > 0 {
                let start = entry.metadata_offset as usize;
                let end = start + entry.metadata_length as usize;
                if end <= bytes.len() {
                    match SegmentMetadata::decode(&bytes[start..end]) {
                        Ok(pairs) => {
                            for (key, value) in pairs {
                                println!("      {} = {}", key, value);
                            }
                        }
                        Err(err) => {
                            println!("      <metadata decode error: {}>", err.0);
                        }
                    }
                } else {
                    println!("      <metadata out of bounds>");
                }
            }
        }

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

    fn segment_label(kind: SegmentKind) -> &'static str {
        match kind {
            SegmentKind::Ports => "ports",
            SegmentKind::Subdomains => "subdomains",
            SegmentKind::Whois => "whois",
            SegmentKind::Tls => "tls",
            SegmentKind::Dns => "dns",
            SegmentKind::Http => "http",
            SegmentKind::Host => "hosts",
        }
    }

    fn list(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let current_dir = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;

        let rdb_files = Self::collect_rdb_files(&current_dir)?;

        if is_json {
            println!("{{");
            println!("  \"directory\": \"{}\",", current_dir.display().to_string().replace('\\', "\\\\").replace('"', "\\\""));
            println!("  \"count\": {},", rdb_files.len());
            println!("  \"files\": [");
            for (i, file) in rdb_files.iter().enumerate() {
                let comma = if i < rdb_files.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", file.display().to_string().replace('\\', "\\\\").replace('"', "\\\""), comma);
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
        use std::net::Ipv4Addr;

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let current_dir = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;

        let rdb_files = Self::collect_rdb_files(&current_dir)?;

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

                if let Ok(summary) = Self::read_summary(path) {
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
                let subnet_comma = if si < sorted_subnets.len() - 1 { "," } else { "" };
                let mut sorted_hosts = hosts.clone();
                sorted_hosts.sort_by_key(|ip_str| {
                    ip_str.parse::<Ipv4Addr>().map(|ip| ip.octets()[3]).unwrap_or(0)
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

// ----------------------------------------------------------------------------- //
// Query-mode handlers (rb database query <dataset> [--db file])
// ----------------------------------------------------------------------------- //
impl DatabaseCommand {
    fn execute_query(&self, ctx: &CliContext) -> Result<(), String> {
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
            other => Err(format!("Unknown dataset '{}'. See `rb database query help`.", other)),
        }
    }

    fn query_partitions(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let service = StorageService::global();

        let mut partitions = service.partitions();

        if let Some(segment_name) = ctx.get_flag("segment") {
            let segment = Self::parse_segment_kind(segment_name)?;
            partitions.retain(|meta| meta.segments.contains(&segment));
        }

        if let Some(attr_filter) = ctx.get_flag("attr") {
            let (key, value) = Self::parse_attr_filter(attr_filter)?;
            partitions.retain(|meta| meta
                .attributes
                .get(key)
                .map(|candidate| candidate == value)
                .unwrap_or(false));
        }

        partitions.sort_by(|a, b| a.label.cmp(&b.label));

        if is_json {
            println!("{{");
            println!("  \"count\": {},", partitions.len());
            println!("  \"segment_filter\": {},", ctx.get_flag("segment").map(|s| format!("\"{}\"", s)).unwrap_or_else(|| "null".to_string()));
            println!("  \"attr_filter\": {},", ctx.get_flag("attr").map(|s| format!("\"{}\"", s)).unwrap_or_else(|| "null".to_string()));
            println!("  \"partitions\": [");
            for (i, meta) in partitions.iter().enumerate() {
                let comma = if i < partitions.len() - 1 { "," } else { "" };
                let segments: Vec<_> = meta.segments.iter().map(|k| Self::segment_label(*k)).collect();
                let last_refreshed = meta.last_refreshed.map(|ts| {
                    ts.duration_since(UNIX_EPOCH).unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs()
                });
                println!("    {{");
                println!("      \"label\": \"{}\",", meta.label.replace('"', "\\\""));
                println!("      \"key\": \"{}\",", Self::describe_partition_key(&meta.key));
                println!("      \"path\": \"{}\",", meta.storage_path.display().to_string().replace('\\', "\\\\").replace('"', "\\\""));
                println!("      \"segments\": [{}],", segments.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", "));
                if let Some(epoch) = last_refreshed {
                    println!("      \"last_refreshed\": {},", epoch);
                } else {
                    println!("      \"last_refreshed\": null,");
                }
                println!("      \"attributes\": {{");
                let attr_items: Vec<_> = meta.attributes.iter().collect();
                for (ai, (key, value)) in attr_items.iter().enumerate() {
                    let attr_comma = if ai < attr_items.len() - 1 { "," } else { "" };
                    println!("        \"{}\": \"{}\"{}", key, value.replace('"', "\\\""), attr_comma);
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
            ctx.get_flag("segment")
                .map(|s| s.as_str())
                .unwrap_or("any"),
            ctx.get_flag("attr")
                .map(|s| s.as_str())
                .unwrap_or("any")
        ));
        println!();

        for meta in partitions {
            println!(
                "• {} ({})",
                meta.label,
                Self::describe_partition_key(&meta.key)
            );
            println!("  path: {}", meta.storage_path.display());

            if !meta.segments.is_empty() {
                let segments = meta
                    .segments
                    .iter()
                    .map(|kind| Self::segment_label(*kind))
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

    fn parse_segment_kind(name: &str) -> Result<SegmentKind, String> {
        match name.to_ascii_lowercase().as_str() {
            "ports" => Ok(SegmentKind::Ports),
            "subdomains" => Ok(SegmentKind::Subdomains),
            "whois" => Ok(SegmentKind::Whois),
            "tls" => Ok(SegmentKind::Tls),
            "dns" => Ok(SegmentKind::Dns),
            "http" => Ok(SegmentKind::Http),
            "host" | "hosts" => Ok(SegmentKind::Host),
            other => Err(format!(
                "Unknown segment '{}'. Expected one of: ports, subdomains, whois, tls, dns, http, host",
                other
            )),
        }
    }

    fn parse_attr_filter(filter: &str) -> Result<(&str, &str), String> {
        let mut parts = filter.splitn(2, '=');
        let key = parts.next().unwrap().trim();
        let value = parts
            .next()
            .ok_or_else(|| "Attribute filter must use key=value syntax".to_string())?
            .trim();
        if key.is_empty() || value.is_empty() {
            return Err("Attribute filter must use key=value syntax".to_string());
        }
        Ok((key, value))
    }

    fn segment_label(kind: SegmentKind) -> &'static str {
        match kind {
            SegmentKind::Ports => "ports",
            SegmentKind::Subdomains => "subdomains",
            SegmentKind::Whois => "whois",
            SegmentKind::Tls => "tls",
            SegmentKind::Dns => "dns",
            SegmentKind::Http => "http",
            SegmentKind::Host => "host",
        }
    }

    fn describe_partition_key(key: &PartitionKey) -> String {
        match key {
            PartitionKey::Domain(domain) => format!("domain:{}", domain),
            PartitionKey::Target(target) => format!("target:{}", target),
            PartitionKey::Date(epoch) => format!("date:{}", epoch),
            PartitionKey::Custom(label) => format!("custom:{}", label),
        }
    }

    fn query_summary(&self, ctx: &CliContext, db_path: &Path) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let service = StorageService::global();
        let label = format!("custom:{}", db_path.display());
        let _ = service.refresh_partition(
            StorageService::key_for_path(db_path),
            label,
            db_path,
        );

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
        let mut db = Self::open_db(db_path)?;
        let port_scans = Self::read_port_scans(&mut db)?;
        let dns_records = Self::read_dns_records(&mut db)?;
        let subdomains = Self::read_subdomains(&mut db)?;
        if !is_json {
            Output::spinner_done();
        }

        let metadata = fs::metadata(db_path)
            .map_err(|e| format!("Failed to read file metadata: {}", e))?;
        let file_size_kb = metadata.len() / 1024;

        if is_json {
            println!("{{");
            println!("  \"file\": \"{}\",", db_path.display().to_string().replace('\\', "\\\\").replace('"', "\\\""));
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
            .map(|value| Self::parse_ip_range(&value))
            .transpose()?;

        let mut manager = StorageService::global()
            .open_query_manager(db_path)
            .map_err(|e| format!("Failed to open {}: {}", db_path.display(), e))?;

        annotate_query_partition(
            ctx,
            db_path,
            [
                ("query_category", "database"),
                ("query_dataset", "ports"),
                ("query_mode", self.mode_label()),
            ],
        );

        let records = if let Some((start, end)) = range {
            manager
                .list_ports_in_range(start, end)
                .map_err(|e| format!("Port query failed: {}", e))?
        } else {
            let mut db = Self::open_db(db_path)?;
            let mut table = db.ports();
            table
                .get_all()
                .map_err(|e| format!("Failed to read ports: {}", e))?
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
                println!("      \"status\": \"{}\",", Self::port_status_label(record.status));
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
            let state = Self::port_status_label(record.status);
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
        let mut manager = StorageService::global()
            .open_query_manager(db_path)
            .map_err(|e| format!("Failed to open {}: {}", db_path.display(), e))?;

        annotate_query_partition(
            ctx,
            db_path,
            [
                ("query_category", "database"),
                ("query_dataset", "dns"),
                ("query_mode", self.mode_label()),
            ],
        );

        let records = if let Some(prefix) = prefix.as_deref() {
            manager
                .list_dns_with_prefix(prefix)
                .map_err(|e| format!("DNS query failed: {}", e))?
        } else {
            let mut db = Self::open_db(db_path)?;
            let mut table = db.dns();
            table.iter().collect()
        };

        if is_json {
            println!("{{");
            println!("  \"count\": {},", records.len());
            println!("  \"records\": [");
            for (i, record) in records.iter().enumerate() {
                let comma = if i < records.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"domain\": \"{}\",", record.domain.replace('"', "\\\""));
                println!("      \"type\": \"{}\",", Self::dns_type_label(record.record_type));
                println!("      \"value\": \"{}\",", record.value.replace('"', "\\\""));
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
                Self::dns_type_label(record.record_type),
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
        let mut manager = StorageService::global()
            .open_query_manager(db_path)
            .map_err(|e| format!("Failed to open {}: {}", db_path.display(), e))?;

        annotate_query_partition(
            ctx,
            db_path,
            [
                ("query_category", "database"),
                ("query_dataset", "subdomains"),
                ("query_mode", self.mode_label()),
            ],
        );

        let records = if let Some(prefix) = prefix.as_deref() {
            manager
                .list_subdomains_with_prefix(prefix)
                .map_err(|e| format!("Subdomain query failed: {}", e))?
        } else {
            let mut db = Self::open_db(db_path)?;
            let mut table = db.subdomains();
            table
                .get_all()
                .map_err(|e| format!("Failed to read subdomains: {}", e))?
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
                println!("      \"method\": \"{}\",", record.method.replace('"', "\\\""));
                println!("      \"url\": \"{}\",", record.url.replace('"', "\\\""));
                println!("      \"http_version\": \"{}\",", record.http_version.replace('"', "\\\""));
                println!("      \"status_code\": {},", record.status_code);
                println!("      \"status_text\": \"{}\",", record.status_text.replace('"', "\\\""));
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
                    println!("  \"registrar\": \"{}\",", record.registrar.replace('"', "\\\""));
                    println!("  \"created_date\": \"{}\",", record.created_date.replace('"', "\\\""));
                    println!("  \"expires_date\": \"{}\",", record.expires_date.replace('"', "\\\""));
                    println!("  \"nameservers\": [");
                    for (i, ns) in record.nameservers.iter().enumerate() {
                        let comma = if i < record.nameservers.len() - 1 { "," } else { "" };
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

    fn output_host_json(&self, record: &crate::storage::records::HostIntelRecord) {
        let os = record.os_family.as_deref().unwrap_or("");
        println!("{{");
        println!("  \"ip\": \"{}\",", record.ip);
        println!("  \"os_family\": \"{}\",", os.replace('"', "\\\""));
        println!("  \"confidence\": {},", record.confidence);
        println!("  \"last_seen\": {},", record.last_seen);
        println!("  \"services\": [");
        for (i, svc) in record.services.iter().enumerate() {
            let comma = if i < record.services.len() - 1 { "," } else { "" };
            let svc_name = svc.service_name.as_deref().unwrap_or("");
            let banner = svc.banner.as_deref().unwrap_or("");
            println!("    {{");
            println!("      \"port\": {},", svc.port);
            println!("      \"service_name\": \"{}\",", svc_name.replace('"', "\\\""));
            println!("      \"banner\": \"{}\",", banner.replace('"', "\\\"").replace('\n', "\\n"));
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

    fn output_host_json_inline(&self, record: &crate::storage::records::HostIntelRecord) {
        let os = record.os_family.as_deref().unwrap_or("");
        print!("{{\"ip\":\"{}\",\"os_family\":\"{}\",\"confidence\":{},\"last_seen\":{},\"services\":[",
            record.ip, os.replace('"', "\\\""), record.confidence, record.last_seen);
        for (i, svc) in record.services.iter().enumerate() {
            let comma = if i < record.services.len() - 1 { "," } else { "" };
            let svc_name = svc.service_name.as_deref().unwrap_or("");
            let banner = svc.banner.as_deref().unwrap_or("");
            print!("{{\"port\":{},\"service_name\":\"{}\",\"banner\":\"{}\",\"os_hints\":[",
                svc.port, svc_name.replace('"', "\\\""), banner.replace('"', "\\\"").replace('\n', "\\n"));
            for (j, hint) in svc.os_hints.iter().enumerate() {
                let hint_comma = if j < svc.os_hints.len() - 1 { "," } else { "" };
                print!("\"{}\"{}",  hint.replace('"', "\\\""), hint_comma);
            }
            print!("]}}{}", comma);
        }
        print!("]}}");
    }
}

// ----------------------------------------------------------------------------- //
// Shared helpers
// ----------------------------------------------------------------------------- //
impl DatabaseCommand {
    fn resolve_db_path(&self, ctx: &CliContext) -> Result<PathBuf, String> {
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

    fn open_db(path: &Path) -> Result<RedDb, String> {
        RedDb::open(path).map_err(|e| format!("Failed to open database {}: {}", path.display(), e))
    }

    fn read_port_scans(db: &mut RedDb) -> Result<Vec<PortScanRecord>, String> {
        let mut table = db.ports();
        table
            .get_all()
            .map_err(|e| format!("Failed to read port scans: {}", e))
    }

    fn read_dns_records(db: &mut RedDb) -> Result<Vec<DnsRecordData>, String> {
        let mut table = db.dns();
        Ok(table.iter().collect())
    }

    fn read_subdomains(db: &mut RedDb) -> Result<Vec<SubdomainRecord>, String> {
        let mut table = db.subdomains();
        table
            .get_all()
            .map_err(|e| format!("Failed to read subdomains: {}", e))
    }

    fn collect_rdb_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
        let entries = fs::read_dir(dir).map_err(|e| format!("Failed to read directory: {}", e))?;

        let mut files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|ext| ext == "rdb").unwrap_or(false) {
                files.push(path);
            }
        }

        files.sort();
        Ok(files)
    }

    fn read_summary(path: &Path) -> Result<DbSummary, String> {
        let mut db = Self::open_db(path)?;

        let port_scans = {
            let mut ports = db.ports();
            ports
                .count()
                .map_err(|e| format!("Failed to read port scans: {}", e))?
        };

        let dns_records = {
            let mut dns = db.dns();
            dns.iter().count()
        };

        let subdomains = {
            let mut subs = db.subdomains();
            subs.get_all()
                .map_err(|e| format!("Failed to read subdomains: {}", e))?
                .len()
        };

        Ok(DbSummary {
            total_records: port_scans + dns_records + subdomains,
            port_scans,
            dns_records,
            subdomains,
        })
    }

    fn port_status_label(status: PortStatus) -> &'static str {
        match status {
            PortStatus::Open => "OPEN",
            PortStatus::Closed => "CLOSED",
            PortStatus::Filtered => "FILTERED",
            PortStatus::OpenFiltered => "OPEN|FILTERED",
        }
    }

    fn dns_type_label(record_type: DnsRecordType) -> &'static str {
        match record_type {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::MX => "MX",
            DnsRecordType::NS => "NS",
            DnsRecordType::TXT => "TXT",
            DnsRecordType::CNAME => "CNAME",
        }
    }

    fn parse_ip_range(range: &str) -> Result<(IpAddr, IpAddr), String> {
        let mut parts = range.split('-');
        let start = parts
            .next()
            .ok_or_else(|| "Invalid IP range format. Expected start-end".to_string())?
            .trim();
        let end = parts
            .next()
            .ok_or_else(|| "Invalid IP range format. Expected start-end".to_string())?
            .trim();
        if parts.next().is_some() {
            return Err("Invalid IP range format. Expected start-end".to_string());
        }

        let start_ip: IpAddr = start
            .parse()
            .map_err(|_| format!("Invalid IP address: {}", start))?;
        let end_ip: IpAddr = end
            .parse()
            .map_err(|_| format!("Invalid IP address: {}", end))?;

        if start_ip.is_ipv4() != end_ip.is_ipv4() {
            return Err("IP range must use addresses from the same family".to_string());
        }

        let start_key = IpKey::from(&start_ip);
        let end_key = IpKey::from(&end_ip);
        if start_key > end_key {
            return Err("IP range start must be <= end".to_string());
        }

        Ok((start_ip, end_ip))
    }
}
