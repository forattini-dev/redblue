/// Database command - Query and export binary databases
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::storage::BinaryReader;
use std::fs;
use std::path::Path;

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

impl DatabaseCommand {
    fn query(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing database file.\nUsage: rb database data query <file.rdb>\nExample: rb database data query 192.168.1.1.rdb",
        )?;

        if !Path::new(file_path).exists() {
            return Err(format!("Database file not found: {}", file_path));
        }

        Output::spinner_start("Reading database");
        let mut reader =
            BinaryReader::open(file_path).map_err(|e| format!("Failed to open database: {}", e))?;
        Output::spinner_done();

        Output::header(&format!("Database: {}", file_path));

        // Show file info
        let metadata =
            fs::metadata(file_path).map_err(|e| format!("Failed to read file metadata: {}", e))?;
        let file_size_kb = metadata.len() / 1024;

        Output::summary_line(&[
            ("Size", &format!("{} KB", file_size_kb)),
            ("Format", "REDBLUE v1"),
        ]);

        // Show statistics
        let stats = reader.stats();
        println!();
        Output::subheader("Statistics");
        println!("  Total records: {}", stats.total_records);
        println!("  Port scans: {}", stats.port_scans);
        println!("  DNS records: {}", stats.dns_records);
        println!("  Subdomains: {}", stats.subdomains);

        // Show port scans (first 10)
        if stats.port_scans > 0 {
            println!();
            Output::subheader(&format!(
                "Port Scans ({}) - showing first 10",
                stats.port_scans
            ));

            let mut count = 0;
            for port_scan in reader.port_scans() {
                if count >= 10 {
                    println!("  ... and {} more", stats.port_scans - 10);
                    break;
                }

                let ip = std::net::Ipv4Addr::from(port_scan.ip);
                let service = match port_scan.service_id {
                    1 => "http",
                    2 => "https",
                    3 => "ssh",
                    4 => "ftp",
                    5 => "smtp",
                    6 => "mysql",
                    _ => "unknown",
                };

                let state = if port_scan.state == 1 {
                    "OPEN"
                } else {
                    "CLOSED"
                };

                println!("  {}:{} - {} ({})", ip, port_scan.port, state, service);
                count += 1;
            }
        }

        // Show DNS records count
        if stats.dns_records > 0 {
            println!();
            Output::subheader(&format!("DNS Records ({})", stats.dns_records));
            println!("  {} DNS records stored", stats.dns_records);
        }

        println!();
        Output::success("Query completed");

        Ok(())
    }

    fn export(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing database file.\nUsage: rb database data export <file.rdb>\nExample: rb database data export 192.168.1.1.rdb",
        )?;

        if !Path::new(file_path).exists() {
            return Err(format!("Database file not found: {}", file_path));
        }

        // Generate output filename
        let output_path = if let Some(output) = ctx.get_flag("output") {
            output.to_string()
        } else {
            format!("{}.csv", file_path.trim_end_matches(".rdb"))
        };

        Output::spinner_start("Exporting database");
        let mut reader =
            BinaryReader::open(file_path).map_err(|e| format!("Failed to open database: {}", e))?;
        Output::spinner_done();

        let mut csv_content = String::new();
        let stats = reader.stats();

        // Export port scans
        if stats.port_scans > 0 {
            csv_content.push_str("# Port Scans\n");
            csv_content.push_str("IP,Port,State,Service,Timestamp\n");

            for port_scan in reader.port_scans() {
                let ip = std::net::Ipv4Addr::from(port_scan.ip);
                let service = match port_scan.service_id {
                    1 => "http",
                    2 => "https",
                    3 => "ssh",
                    4 => "ftp",
                    5 => "smtp",
                    6 => "mysql",
                    _ => "unknown",
                };
                let state = if port_scan.state == 1 {
                    "OPEN"
                } else {
                    "CLOSED"
                };

                csv_content.push_str(&format!(
                    "{},{},{},{},{}\n",
                    ip, port_scan.port, state, service, port_scan.timestamp
                ));
            }
            csv_content.push('\n');
        }

        // Export DNS records
        if stats.dns_records > 0 {
            csv_content.push_str("# DNS Records\n");
            csv_content.push_str("Domain,Type,TTL,Value\n");

            for dns_record in reader.dns_records() {
                let record_type = match dns_record.record_type {
                    1 => "A",
                    2 => "AAAA",
                    5 => "CNAME",
                    15 => "MX",
                    16 => "TXT",
                    _ => "UNKNOWN",
                };

                let value = String::from_utf8_lossy(&dns_record.data);
                let value_clean = value.replace(',', ";").replace('\n', " ");

                csv_content.push_str(&format!(
                    "{},{},{},{}\n",
                    dns_record.domain, record_type, dns_record.ttl, value_clean
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

        let entries =
            fs::read_dir(&current_dir).map_err(|e| format!("Failed to read directory: {}", e))?;

        let mut rdb_files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "rdb" {
                    rdb_files.push(path);
                }
            }
        }

        if rdb_files.is_empty() {
            Output::warning("No .rdb files found in current directory");
            return Ok(());
        }

        println!();
        for path in &rdb_files {
            let file_name = path.file_name().unwrap().to_string_lossy();

            if let Ok(metadata) = fs::metadata(path) {
                let size_kb = metadata.len() / 1024;

                // Try to read stats
                if let Ok(mut reader) = BinaryReader::open(path.to_str().unwrap()) {
                    let stats = reader.stats();
                    println!(
                        "  {} ({} KB) - {} records",
                        file_name, size_kb, stats.total_records
                    );
                } else {
                    println!("  {} ({} KB)", file_name, size_kb);
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

        let entries =
            fs::read_dir(&current_dir).map_err(|e| format!("Failed to read directory: {}", e))?;

        // Collect all .rdb files
        let mut rdb_files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "rdb" {
                    rdb_files.push(path);
                }
            }
        }

        if rdb_files.is_empty() {
            Output::warning("No .rdb files found in current directory");
            return Ok(());
        }

        // Parse IP addresses from filenames and group by /24 subnet
        let mut subnets: HashMap<String, Vec<String>> = HashMap::new();

        for path in &rdb_files {
            let file_name = path.file_stem().unwrap().to_string_lossy().to_string();

            // Try to parse as IP address
            if let Ok(ip) = file_name.parse::<Ipv4Addr>() {
                let octets = ip.octets();
                // Group by /24 (first 3 octets)
                let subnet_key = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);

                subnets
                    .entry(subnet_key)
                    .or_insert_with(Vec::new)
                    .push(file_name);
            }
        }

        if subnets.is_empty() {
            Output::warning(
                "No IP-based databases found (databases must be named like 192.168.1.1.rdb)",
            );
            return Ok(());
        }

        // Sort subnets by key
        let mut sorted_subnets: Vec<_> = subnets.iter().collect();
        sorted_subnets.sort_by_key(|(k, _)| *k);

        println!();
        for (subnet, hosts) in sorted_subnets {
            println!("  \x1b[36m{}\x1b[0m - {} host(s)", subnet, hosts.len());

            // Sort hosts numerically by last octet
            let mut sorted_hosts = hosts.clone();
            sorted_hosts.sort_by_key(|ip_str| {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    ip.octets()[3]
                } else {
                    0
                }
            });

            for host in sorted_hosts {
                // Try to read stats for this host
                let db_path = format!("{}.rdb", host);
                if let Ok(mut reader) = BinaryReader::open(&db_path) {
                    let stats = reader.stats();
                    let ports = stats.port_scans;
                    let dns = stats.dns_records;

                    let mut info_parts = Vec::new();
                    if ports > 0 {
                        info_parts.push(format!("{} ports", ports));
                    }
                    if dns > 0 {
                        info_parts.push(format!("{} DNS", dns));
                    }

                    let info = if !info_parts.is_empty() {
                        format!(" ({})", info_parts.join(", "))
                    } else {
                        String::new()
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
