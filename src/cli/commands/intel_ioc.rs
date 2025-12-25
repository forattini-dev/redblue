//! IOC (Indicators of Compromise) Intelligence Command
//!
//! Extract, manage, and export IOCs from scan data:
//! - Extract IOCs from port scans, DNS, TLS, HTTP
//! - Export to STIX, JSON, or CSV formats
//! - Search and filter IOCs
//! - Link to MITRE ATT&CK techniques

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::intel::{Ioc, IocCollection, IocConfidence, IocExtractor, IocSource, IocType};
use std::net::Ipv4Addr;

pub struct IntelIocCommand;

impl Command for IntelIocCommand {
    fn domain(&self) -> &str {
        "intelligence" // Short alias: "intel"
    }

    fn resource(&self) -> &str {
        "ioc"
    }

    fn description(&self) -> &str {
        "Extract and manage Indicators of Compromise (IOCs)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "extract",
                summary: "Extract IOCs from provided data",
                usage: "rb intel ioc extract [target=domain] [ip=...] [ports=...] [dns=...]",
            },
            Route {
                verb: "export",
                summary: "Export IOCs to STIX, JSON, or CSV format",
                usage: "rb intel ioc export [format=json|csv|stix] [output=file]",
            },
            Route {
                verb: "types",
                summary: "Show supported IOC types",
                usage: "rb intel ioc types",
            },
            Route {
                verb: "demo",
                summary: "Demonstrate IOC extraction with sample data",
                usage: "rb intel ioc demo [target]",
            },
            Route {
                verb: "import",
                summary: "Import IOCs from external file (JSON, CSV, STIX)",
                usage: "rb intel ioc import <file> [format=auto|json|csv|stix]",
            },
            Route {
                verb: "search",
                summary: "Search IOCs by value, type, or tag",
                usage: "rb intel ioc search <query> [type=...] [tag=...]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("output", "Output format (text, json, yaml)")
                .with_short('o')
                .with_default("text"),
            Flag::new("target", "Target domain or host for IOC context").with_short('t'),
            Flag::new("ip", "IP address from scan results"),
            Flag::new("ports", "Comma-separated open ports").with_short('p'),
            Flag::new("dns", "Domain to extract DNS IOCs from"),
            Flag::new(
                "export-format",
                "Export format for 'export' verb (json, csv, stix)",
            )
            .with_short('f')
            .with_default("json"),
            Flag::new("file", "Output file path for 'export' verb"),
            Flag::new(
                "confidence",
                "Filter by minimum confidence (low, medium, high)",
            )
            .with_short('c'),
            Flag::new("type", "Filter by IOC type (ipv4, domain, email, etc.)"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Extract from port scan",
                "rb intel ioc extract target=example.com ip=93.184.216.34 ports=22,80,443",
            ),
            (
                "Extract as JSON",
                "rb intel ioc extract target=example.com ip=93.184.216.34 ports=22,80,443 --output=json",
            ),
            ("Run demo extraction", "rb intel ioc demo example.com"),
            (
                "Export to JSON file",
                "rb intel ioc export --export-format=json --file=iocs.json",
            ),
            (
                "Export to CSV file",
                "rb intel ioc export --export-format=csv --file=iocs.csv",
            ),
            (
                "Export to STIX file",
                "rb intel ioc export --export-format=stix --file=iocs.stix.json",
            ),
            ("Show IOC types", "rb intel ioc types"),
            ("Show IOC types as JSON", "rb intel ioc types --output=json"),
            ("Import from JSON file", "rb intel ioc import iocs.json"),
            (
                "Import from STIX bundle",
                "rb intel ioc import threat-intel.stix.json --export-format=stix",
            ),
            (
                "Import from CSV",
                "rb intel ioc import indicators.csv --export-format=csv",
            ),
            ("Search by IP", "rb intel ioc search 192.168.1.1"),
            ("Search by type", "rb intel ioc search 192.168.1 type=ipv4"),
            ("Search as JSON", "rb intel ioc search 192.168.1 --output=json"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "extract" => self.extract_iocs(ctx),
            "export" => self.export_iocs(ctx),
            "types" => self.show_types(ctx),
            "demo" => self.run_demo(ctx),
            "import" => self.import_iocs(ctx),
            "search" => self.search_iocs(ctx),
            _ => {
                print_help(self);
                Err(format!("Unknown verb: {}", verb))
            }
        }
    }
}

impl IntelIocCommand {
    /// Extract IOCs from provided data
    fn extract_iocs(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if !is_json {
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
                            let _ioc =
                                Ioc::new(ioc_type, value, IocSource::PortScan, 85, target.as_str())
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
                            let ioc = Ioc::new(
                                IocType::Url,
                                value,
                                IocSource::Manual,
                                80,
                                target.as_str(),
                            )
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
                            let ioc =
                                Ioc::new(hash_type, value, IocSource::Manual, 90, target.as_str())
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
            if is_json {
                println!("{{\"error\": \"No IOCs extracted\", \"iocs\": []}}");
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

        if is_json {
            println!("{{");
            println!("  \"target\": \"{}\",", target);
            println!("  \"total\": {},", collection.len());
            let counts = collection.count_by_type();
            println!("  \"by_type\": {{");
            for (i, (ioc_type, count)) in counts.iter().enumerate() {
                let comma = if i < counts.len() - 1 { "," } else { "" };
                println!("    \"{}\": {}{}", ioc_type, count, comma);
            }
            println!("  }},");
            println!("  \"iocs\": [");
            let all_iocs = collection.all();
            for (i, ioc) in all_iocs.iter().enumerate() {
                let conf_str = match ioc.confidence {
                    IocConfidence::High => "high",
                    IocConfidence::Medium => "medium",
                    IocConfidence::Low => "low",
                };
                let comma = if i < all_iocs.len() - 1 { "," } else { "" };
                println!(
                    "    {{\"type\": \"{}\", \"value\": \"{}\", \"confidence\": \"{}\", \"source\": \"{}\", \"techniques\": [{}], \"tags\": [{}]}}{}",
                    ioc.ioc_type,
                    ioc.value.replace('"', "\\\""),
                    conf_str,
                    ioc.source,
                    ioc.mitre_techniques.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", "),
                    ioc.tags.iter().map(|s| format!("\"{}\"", s.replace('"', "\\\""))).collect::<Vec<_>>().join(", "),
                    comma
                );
            }
            println!("  ]");
            println!("}}");
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
    fn export_iocs(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("IOC Export");
        println!();

        // For now, generate some sample IOCs to export
        let mut collection = IocCollection::new();
        let mut target = String::from("target");
        let mut export_format = ctx.get_flag_or("export-format", "json");
        let mut output_file: Option<String> = ctx.get_flag("file");

        // Parse key=value pairs for backward compatibility
        for arg in ctx.target.iter().chain(ctx.args.iter()) {
            if let Some(eq_pos) = arg.find('=') {
                let (key, value) = arg.split_at(eq_pos);
                let value = &value[1..];

                match key {
                    "export-format" | "format" | "f" => export_format = value.to_string(),
                    "file" => output_file = Some(value.to_string()),
                    "target" | "t" => target = value.to_string(),
                    _ => {}
                }
            }
        }

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
            Output::info("No IOCs to export. Extract IOCs first with 'rb intel ioc extract'");
            return Ok(());
        }

        // Generate export content
        let content = match export_format.as_str() {
            "csv" => collection.to_csv(),
            "stix" => self.to_stix_bundle(&collection, &target),
            _ => collection.to_json(),
        };

        // Write to file
        std::fs::write(&output_path, &content)
            .map_err(|e| format!("Failed to write file: {}", e))?;

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
    fn show_types(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

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

        if is_json {
            println!("{{");
            println!("  \"types\": [");
            for (i, (name, desc, example, category)) in types.iter().enumerate() {
                let comma = if i < types.len() - 1 { "," } else { "" };
                println!(
                    "    {{\"name\": \"{}\", \"description\": \"{}\", \"example\": \"{}\", \"category\": \"{}\"}}{}",
                    name,
                    desc.replace('"', "\\\""),
                    example.replace('"', "\\\"").replace('\\', "\\\\"),
                    category,
                    comma
                );
            }
            println!("  ],");
            println!("  \"total\": {}", types.len());
            println!("}}");
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
    fn run_demo(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_deref().unwrap_or("example.com");
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

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

        if is_json {
            let counts = collection.count_by_type();
            let conf_counts = collection.count_by_confidence();

            println!("{{");
            println!("  \"target\": \"{}\",", target);
            println!("  \"sources\": {{");
            println!("    \"port_scan\": {},", port_iocs.len());
            println!("    \"dns\": {},", dns_iocs.len());
            println!("    \"tls\": {},", tls_iocs.len());
            println!("    \"subdomains\": {}", subdomain_iocs.len());
            println!("  }},");
            println!("  \"total\": {},", collection.len());
            println!("  \"by_type\": {{");
            for (i, (ioc_type, count)) in counts.iter().enumerate() {
                let comma = if i < counts.len() - 1 { "," } else { "" };
                println!("    \"{}\": {}{}", ioc_type, count, comma);
            }
            println!("  }},");
            println!("  \"by_confidence\": {{");
            println!(
                "    \"high\": {},",
                conf_counts.get(&IocConfidence::High).unwrap_or(&0)
            );
            println!(
                "    \"medium\": {},",
                conf_counts.get(&IocConfidence::Medium).unwrap_or(&0)
            );
            println!(
                "    \"low\": {}",
                conf_counts.get(&IocConfidence::Low).unwrap_or(&0)
            );
            println!("  }},");
            println!("  \"iocs\": [");
            let all_iocs = collection.all();
            for (i, ioc) in all_iocs.iter().enumerate() {
                let conf_str = match ioc.confidence {
                    IocConfidence::High => "high",
                    IocConfidence::Medium => "medium",
                    IocConfidence::Low => "low",
                };
                let comma = if i < all_iocs.len() - 1 { "," } else { "" };
                println!(
                    "    {{\"type\": \"{}\", \"value\": \"{}\", \"confidence\": \"{}\", \"source\": \"{}\", \"techniques\": [{}], \"tags\": [{}]}}{}",
                    ioc.ioc_type,
                    ioc.value.replace('"', "\\\""),
                    conf_str,
                    ioc.source,
                    ioc.mitre_techniques.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", "),
                    ioc.tags.iter().map(|s| format!("\"{}\"", s.replace('"', "\\\""))).collect::<Vec<_>>().join(", "),
                    comma
                );
            }
            println!("  ]");
            println!("}}");
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
    fn import_iocs(&self, ctx: &CliContext) -> Result<(), String> {
        let output_format = ctx.get_output_format();
        let is_json = output_format == crate::cli::format::OutputFormat::Json;

        // Get file path from target or args
        let file_path = ctx
            .target
            .as_ref()
            .or_else(|| ctx.args.first())
            .ok_or_else(|| {
                if is_json {
                    println!("{{\"error\": \"No file specified\"}}");
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

        if !is_json {
            Output::header("IOC Import");
            println!();
            Output::item("File", file_path);
            Output::item("Format", &file_format);
            println!();
        }

        // Read file content
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        if !is_json {
            Output::spinner_start("Parsing IOCs");
        }

        let mut collection = IocCollection::new();
        let import_count = match file_format.as_str() {
            "csv" => self.parse_csv_iocs(&content, &mut collection)?,
            "stix" => self.parse_stix_iocs(&content, &mut collection)?,
            _ => self.parse_json_iocs(&content, &mut collection)?,
        };

        if !is_json {
            Output::spinner_done();
            println!();
        }

        if import_count == 0 {
            if is_json {
                println!(
                    "{{\"file\": \"{}\", \"format\": \"{}\", \"imported\": 0, \"iocs\": []}}",
                    file_path.replace('"', "\\\""),
                    file_format
                );
            } else {
                Output::warning("No IOCs found in file");
            }
            return Ok(());
        }

        if is_json {
            let counts = collection.count_by_type();

            println!("{{");
            println!("  \"file\": \"{}\",", file_path.replace('"', "\\\""));
            println!("  \"format\": \"{}\",", file_format);
            println!("  \"imported\": {},", import_count);
            println!("  \"by_type\": {{");
            for (i, (ioc_type, count)) in counts.iter().enumerate() {
                let comma = if i < counts.len() - 1 { "," } else { "" };
                println!("    \"{}\": {}{}", ioc_type, count, comma);
            }
            println!("  }},");
            println!("  \"iocs\": [");
            let all_iocs = collection.all();
            for (i, ioc) in all_iocs.iter().enumerate() {
                let conf_str = match ioc.confidence {
                    IocConfidence::High => "high",
                    IocConfidence::Medium => "medium",
                    IocConfidence::Low => "low",
                };
                let comma = if i < all_iocs.len() - 1 { "," } else { "" };
                println!(
                    "    {{\"type\": \"{}\", \"value\": \"{}\", \"confidence\": \"{}\", \"source\": \"{}\", \"tags\": [{}]}}{}",
                    ioc.ioc_type,
                    ioc.value.replace('"', "\\\""),
                    conf_str,
                    ioc.source,
                    ioc.tags.iter().map(|s| format!("\"{}\"", s.replace('"', "\\\""))).collect::<Vec<_>>().join(", "),
                    comma
                );
            }
            println!("  ]");
            println!("}}");
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
    fn parse_csv_iocs(
        &self,
        content: &str,
        collection: &mut IocCollection,
    ) -> Result<usize, String> {
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
            let ioc_type = self.parse_ioc_type(type_str);

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
    fn parse_json_iocs(
        &self,
        content: &str,
        collection: &mut IocCollection,
    ) -> Result<usize, String> {
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
                        "type" | "ioc_type" => ioc_type = self.parse_ioc_type(val),
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
    fn parse_stix_iocs(
        &self,
        content: &str,
        collection: &mut IocCollection,
    ) -> Result<usize, String> {
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
                        if let Some(ioc) = self.parse_stix_pattern(pattern) {
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
    fn parse_stix_pattern(&self, pattern: &str) -> Option<Ioc> {
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
        } else if type_part.contains("file:hashes.SHA-1")
            || type_part.contains("file:hashes.'SHA-1'")
        {
            IocType::HashSHA1
        } else if type_part.contains("file:hashes.SHA-256")
            || type_part.contains("file:hashes.'SHA-256'")
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
    fn parse_ioc_type(&self, type_str: &str) -> IocType {
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
    fn search_iocs(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        // Get search query
        let query = ctx
            .target
            .as_ref()
            .or_else(|| ctx.args.first())
            .ok_or_else(|| {
                if is_json {
                    println!("{{\"error\": \"No search query specified\", \"results\": []}}");
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
        self.populate_sample_database(&mut collection);

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
                        ioc.tags
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

        if is_json {
            println!("{{");
            println!("  \"query\": \"{}\",", query.replace('"', "\\\""));
            if let Some(ref t) = type_filter {
                println!("  \"type_filter\": \"{}\",", t);
            }
            if let Some(ref t) = tag_filter {
                println!("  \"tag_filter\": \"{}\",", t.replace('"', "\\\""));
            }
            if let Some(ref c) = confidence_filter {
                println!("  \"confidence_filter\": \"{}\",", c);
            }
            println!("  \"total\": {},", results.len());
            println!("  \"results\": [");
            for (i, ioc) in results.iter().enumerate() {
                let conf_str = match ioc.confidence {
                    IocConfidence::High => "high",
                    IocConfidence::Medium => "medium",
                    IocConfidence::Low => "low",
                };
                let comma = if i < results.len() - 1 { "," } else { "" };
                println!(
                    "    {{\"type\": \"{}\", \"value\": \"{}\", \"confidence\": \"{}\", \"source\": \"{}\", \"context\": {}, \"techniques\": [{}], \"tags\": [{}]}}{}",
                    ioc.ioc_type,
                    ioc.value.replace('"', "\\\""),
                    conf_str,
                    ioc.source,
                    ioc.context.as_ref().map(|c| format!("\"{}\"", c.replace('"', "\\\""))).unwrap_or_else(|| "null".to_string()),
                    ioc.mitre_techniques.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", "),
                    ioc.tags.iter().map(|s| format!("\"{}\"", s.replace('"', "\\\""))).collect::<Vec<_>>().join(", "),
                    comma
                );
            }
            println!("  ]");
            println!("}}");
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

    /// Populate sample IOC database for search demonstration
    fn populate_sample_database(&self, collection: &mut IocCollection) {
        // Add diverse IOCs for search testing
        let sample_iocs = vec![
            (
                IocType::IPv4,
                "192.168.1.1",
                "port_scan",
                85,
                vec!["internal", "scan"],
            ),
            (
                IocType::IPv4,
                "192.168.1.100",
                "port_scan",
                75,
                vec!["internal", "ssh"],
            ),
            (
                IocType::IPv4,
                "10.0.0.1",
                "dns_query",
                90,
                vec!["gateway", "router"],
            ),
            (
                IocType::IPv4,
                "93.184.216.34",
                "dns_query",
                95,
                vec!["example", "public"],
            ),
            (
                IocType::IPv4,
                "8.8.8.8",
                "dns_server",
                80,
                vec!["google", "dns"],
            ),
            (
                IocType::IPv6,
                "2001:db8::1",
                "dns_query",
                70,
                vec!["ipv6", "test"],
            ),
            (
                IocType::Domain,
                "example.com",
                "dns_query",
                95,
                vec!["example", "public"],
            ),
            (
                IocType::Domain,
                "malware.bad.com",
                "threat_intel",
                99,
                vec!["malware", "c2"],
            ),
            (
                IocType::Domain,
                "api.example.com",
                "subdomain_enum",
                85,
                vec!["api", "subdomain"],
            ),
            (
                IocType::Domain,
                "mail.example.com",
                "dns_mx",
                80,
                vec!["mail", "mx"],
            ),
            (
                IocType::Domain,
                "cdn.example.com",
                "subdomain_enum",
                75,
                vec!["cdn", "subdomain"],
            ),
            (
                IocType::Url,
                "http://example.com/login",
                "web_crawl",
                70,
                vec!["login", "auth"],
            ),
            (
                IocType::Url,
                "https://api.example.com/v1/users",
                "web_crawl",
                65,
                vec!["api", "rest"],
            ),
            (
                IocType::Email,
                "admin@example.com",
                "whois",
                60,
                vec!["admin", "contact"],
            ),
            (
                IocType::Email,
                "security@example.com",
                "harvest",
                55,
                vec!["security", "contact"],
            ),
            (
                IocType::HashSHA256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_scan",
                90,
                vec!["empty", "hash"],
            ),
            (
                IocType::HashMD5,
                "d41d8cd98f00b204e9800998ecf8427e",
                "file_scan",
                85,
                vec!["empty", "md5"],
            ),
            (
                IocType::Certificate,
                "DigiCert:abc123def456",
                "tls_scan",
                80,
                vec!["tls", "cert"],
            ),
            (
                IocType::JA3,
                "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,0-10-11-35-15-13,23-24-25,0",
                "tls_fingerprint",
                75,
                vec!["ja3", "chrome"],
            ),
            (
                IocType::ASN,
                "AS15169",
                "ip_lookup",
                70,
                vec!["google", "asn"],
            ),
            (
                IocType::CIDR,
                "192.168.0.0/24",
                "network_scan",
                65,
                vec!["internal", "subnet"],
            ),
        ];

        for (ioc_type, value, context, confidence, tags) in sample_iocs {
            let mut ioc = Ioc::new(
                ioc_type,
                value,
                IocSource::PortScan, // Simplified for demo
                confidence,
                context,
            );
            for tag in tags {
                ioc = ioc.with_tag(tag);
            }
            collection.add(ioc);
        }
    }

    /// Generate STIX 2.1 bundle
    fn to_stix_bundle(&self, collection: &IocCollection, target: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let bundle_id = format!("bundle--redblue-{}", now);

        let mut objects = Vec::new();

        // Add identity object
        objects.push(format!(
            r#"{{
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--redblue-scanner",
      "created": "{}",
      "modified": "{}",
      "name": "redblue Scanner",
      "identity_class": "tool"
    }}"#,
            format_timestamp(now),
            format_timestamp(now),
        ));

        // Add indicator objects for each IOC
        for (i, ioc) in collection.all().iter().enumerate() {
            let indicator_id = format!("indicator--redblue-{}-{}", now, i);
            let pattern = ioc.to_stix_pattern();

            let labels: Vec<String> = ioc.tags.iter().map(|t| format!("\"{}\"", t)).collect();

            objects.push(format!(
                r#"{{
      "type": "indicator",
      "spec_version": "2.1",
      "id": "{}",
      "created": "{}",
      "modified": "{}",
      "name": "{} IOC",
      "description": "IOC extracted from {} by redblue",
      "indicator_types": ["unknown"],
      "pattern": "{}",
      "pattern_type": "stix",
      "valid_from": "{}",
      "labels": [{}],
      "confidence": {}
    }}"#,
                indicator_id,
                format_timestamp(ioc.first_seen),
                format_timestamp(ioc.last_seen),
                ioc.ioc_type,
                target,
                pattern.replace('"', "\\\""),
                format_timestamp(ioc.first_seen),
                labels.join(", "),
                ioc.confidence_score,
            ));
        }

        format!(
            r#"{{
  "type": "bundle",
  "id": "{}",
  "objects": [
    {}
  ]
}}"#,
            bundle_id,
            objects.join(",\n    ")
        )
    }
}

/// Format Unix timestamp as ISO 8601
fn format_timestamp(ts: u64) -> String {
    // Simple ISO 8601 formatting (YYYY-MM-DDTHH:MM:SSZ)
    let secs_per_day = 86400u64;
    let secs_per_hour = 3600u64;
    let secs_per_min = 60u64;

    // Days since Unix epoch
    let days = ts / secs_per_day;
    let remaining = ts % secs_per_day;

    let hours = remaining / secs_per_hour;
    let remaining = remaining % secs_per_hour;
    let minutes = remaining / secs_per_min;
    let seconds = remaining % secs_per_min;

    // Calculate year/month/day (simplified - doesn't handle leap years perfectly)
    let mut year = 1970u64;
    let mut remaining_days = days;

    loop {
        let days_in_year =
            if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) {
                366
            } else {
                365
            };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let is_leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_months = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0u64;
    for (i, &days_in_month) in days_in_months.iter().enumerate() {
        if remaining_days < days_in_month as u64 {
            month = (i + 1) as u64;
            break;
        }
        remaining_days -= days_in_month as u64;
    }

    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}
