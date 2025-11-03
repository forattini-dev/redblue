/// Database command - Query and export binary databases
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::storage::reddb::RedDb;
use crate::storage::schema::{
    DnsRecordData, DnsRecordType, PortScanRecord, PortStatus, SubdomainRecord,
};
use std::fs;
use std::path::{Path, PathBuf};

pub struct DatabaseCommand;

impl Command for DatabaseCommand {
    fn domain(&self) -> &str {
        "database"
    }

    fn resource(&self) -> &str {
        "data"
    }

    fn description(&self) -> &str {
        "Query and export binary database files (.rdb)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
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
                summary: "List all .rdb files in current directory",
                usage: "rb database data list",
            },
            Route {
                verb: "subnets",
                summary: "List all discovered subnets with host counts",
                usage: "rb database data subnets",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![Flag::new("output", "Output file path for export").with_short('o')]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Query database", "rb database data query 192.168.1.1.rdb"),
            (
                "Export to CSV",
                "rb database data export 192.168.1.1.rdb --output scan.csv",
            ),
            ("List databases", "rb database data list"),
            ("List subnets", "rb database data subnets"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "query" => self.query(ctx),
            "export" => self.export(ctx),
            "list" => self.list(ctx),
            "subnets" => self.list_subnets(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                Err("Invalid verb".to_string())
            }
        }
    }
}

struct DbSummary {
    total_records: usize,
    port_scans: usize,
    dns_records: usize,
    subdomains: usize,
}

impl DatabaseCommand {
    fn query(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing database file.\nUsage: rb database data query <file.rdb>\nExample: rb database data query 192.168.1.1.rdb",
        )?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("Database file not found: {}", file_path));
        }

        Output::spinner_start("Reading database");
        let mut db = Self::open_db(path)?;
        let port_scans = Self::read_port_scans(&mut db)?;
        let dns_records = Self::read_dns_records(&mut db)?;
        let subdomains = Self::read_subdomains(&mut db)?;
        Output::spinner_done();

        Output::header(&format!("Database: {}", file_path));

        // Show file info
        let metadata =
            fs::metadata(path).map_err(|e| format!("Failed to read file metadata: {}", e))?;
        let file_size_kb = metadata.len() / 1024;
        let total_records = port_scans.len() + dns_records.len() + subdomains.len();

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

        // Show port scans (first 10)
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

        // Show DNS records count
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

        // Generate output filename
        let output_path = if let Some(output) = ctx.get_flag("output") {
            output.to_string()
        } else {
            format!("{}.csv", file_path.trim_end_matches(".rdb"))
        };

        Output::spinner_start("Exporting database");
        let mut db = Self::open_db(path)?;
        let port_scans = Self::read_port_scans(&mut db)?;
        let dns_records = Self::read_dns_records(&mut db)?;
        Output::spinner_done();

        let mut csv_content = String::new();

        // Export port scans
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

        // Export DNS records
        if !dns_records.is_empty() {
            csv_content.push_str("# DNS Records\n");
            csv_content.push_str("Domain,Type,TTL,Value\n");

            for record in &dns_records {
                let record_type = Self::dns_type_label(record.record_type);
                let value_clean = record.value.replace(',', ";").replace('\n', " ");

                csv_content.push_str(&format!(
                    "{},{},{},{}\n",
                    record.domain, record_type, record.ttl, value_clean
                ));
            }
            csv_content.push('\n');
        }

        // Write CSV file
        fs::write(&output_path, csv_content)
            .map_err(|e| format!("Failed to write CSV file: {}", e))?;

        println!();
        Output::success(&format!("✓ Exported to {}", output_path));

        Ok(())
    }

    fn list(&self, _ctx: &CliContext) -> Result<(), String> {
        let current_dir = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;

        Output::header("Database Files");

        let rdb_files = Self::collect_rdb_files(&current_dir)?;

        if rdb_files.is_empty() {
            Output::warning("No .rdb files found in current directory");
            return Ok(());
        }

        println!();
        for path in &rdb_files {
            let file_name = path.file_name().unwrap().to_string_lossy();

            if let Ok(metadata) = fs::metadata(path) {
                let size_kb = metadata.len() / 1024;

                match Self::read_summary(path) {
                    Ok(summary) => println!(
                        "  {} ({} KB) - {} records",
                        file_name, size_kb, summary.total_records
                    ),
                    Err(_) => println!("  {} ({} KB)", file_name, size_kb),
                }
            } else {
                println!("  {}", file_name);
            }
        }

        println!();
        Output::success(&format!("Found {} database(s)", rdb_files.len()));

        Ok(())
    }

    fn list_subnets(&self, _ctx: &CliContext) -> Result<(), String> {
        use std::collections::HashMap;
        use std::net::Ipv4Addr;

        let current_dir = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;

        Output::header("Discovered Subnets");

        let rdb_files = Self::collect_rdb_files(&current_dir)?;
        if rdb_files.is_empty() {
            Output::warning("No .rdb files found in current directory");
            return Ok(());
        }

        let mut subnets: HashMap<String, Vec<String>> = HashMap::new();
        let mut summaries = HashMap::new();

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
            println!("  \x1b[36m{}\x1b[0m - {} host(s)", subnet, hosts.len());

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
}
