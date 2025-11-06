/// DNS/record command - DNS reconnaissance and enumeration
use crate::cli::commands::{
    annotate_query_partition, build_partition_attributes, print_help, Command, Flag, Route,
};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::config;
use crate::intelligence::banner_analysis::analyze_dns_version;
use crate::protocols::dns::{DnsClient, DnsRecordType};
use crate::storage::schema::{DnsRecordType as StorageDnsRecordType, SubdomainSource};
use crate::storage::service::StorageService;
use crate::wordlists::WordlistManager;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct DnsCommand;

impl Command for DnsCommand {
    fn domain(&self) -> &str {
        "dns"
    }

    fn resource(&self) -> &str {
        "record"
    }

    fn description(&self) -> &str {
        "DNS reconnaissance and enumeration"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            // Action verbs - execute DNS queries
            Route {
                verb: "lookup",
                summary: "Query DNS records for a domain",
                usage: "rb dns record lookup <domain> [--type A]",
            },
            Route {
                verb: "all",
                summary:
                    "Query all DNS record types in parallel (A, AAAA, CNAME, MX, NS, TXT, SOA)",
                usage: "rb dns record all <domain>",
            },
            Route {
                verb: "resolve",
                summary: "Resolve a domain name to IP addresses",
                usage: "rb dns record resolve <domain>",
            },
            Route {
                verb: "reverse",
                summary: "Perform a reverse DNS lookup on an IP",
                usage: "rb dns record reverse <ip>",
            },
            Route {
                verb: "bruteforce",
                summary: "Enumerate subdomains using wordlists",
                usage: "rb dns record bruteforce <domain> --wordlist WORDS",
            },
            // RESTful verbs - query stored data
            Route {
                verb: "list",
                summary: "List all DNS records for a domain from database",
                usage: "rb dns record list <domain> [--db <file>]",
            },
            Route {
                verb: "get",
                summary: "Get specific DNS record type from database",
                usage: "rb dns record get <domain>:<type> [--db <file>]",
            },
            Route {
                verb: "describe",
                summary: "Get detailed DNS information from database",
                usage: "rb dns record describe <domain> [--db <file>]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("type", "Record type (A|AAAA|MX|NS|TXT|CNAME|ANY)")
                .with_short('t')
                .with_default("A"),
            Flag::new("server", "DNS server to use")
                .with_short('s')
                .with_default("8.8.8.8"),
            Flag::new("wordlist", "Wordlist for brute force").with_short('w'),
            Flag::new("threads", "Number of threads").with_default("50"),
            Flag::new("persist", "Save results to binary database (.rdb file)"),
            Flag::new("no-persist", "Don't save results (overrides config)"),
            Flag::new(
                "intel",
                "Perform DNS server fingerprinting using VERSION.BIND query",
            ),
            Flag::new(
                "db",
                "Database file path for RESTful queries (default: auto-detect)",
            )
            .with_short('d'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Lookup A records",
                "rb dns record lookup google.com --type A",
            ),
            (
                "Lookup and save to database",
                "rb dns record lookup example.com --persist",
            ),
            (
                "Get all record types at once",
                "rb dns record all google.com",
            ),
            (
                "Lookup MX records",
                "rb dns record lookup example.com --type MX",
            ),
            (
                "Use different DNS server",
                "rb dns record lookup example.com --server 1.1.1.1",
            ),
            ("Quick IP resolution", "rb dns record resolve github.com"),
            (
                "Subdomain brute force",
                "rb dns record bruteforce example.com --wordlist common",
            ),
            (
                "DNS server fingerprinting",
                "rb dns record lookup example.com --intel",
            ),
            // RESTful examples
            (
                "List all saved DNS records",
                "rb dns record list google.com",
            ),
            (
                "Get specific record type from database",
                "rb dns record get google.com:A",
            ),
            ("Describe all DNS data", "rb dns record describe google.com"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            // Action verbs
            "lookup" => self.lookup(ctx),
            "all" => self.lookup_all(ctx),
            "resolve" => self.resolve(ctx),
            "reverse" => self.reverse(ctx),
            "bruteforce" => self.bruteforce(ctx),
            // RESTful verbs
            "list" => self.list_records(ctx),
            "get" => self.get_record(ctx),
            "describe" => self.describe_records(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(
                        verb,
                        &[
                            "lookup",
                            "all",
                            "resolve",
                            "reverse",
                            "bruteforce",
                            "list",
                            "get",
                            "describe"
                        ]
                    )
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl DnsCommand {
    fn lookup(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb dns record lookup <DOMAIN>\nExample: rb dns record lookup example.com",
        )?;

        Validator::validate_domain(domain)?;

        // Clone domain for persistence
        let domain_owned = domain.to_string();

        let record_type_str = ctx.get_flag_or("type", "A");
        let record_type = Self::parse_record_type(&record_type_str)?;

        let cfg = config::get();
        let server = ctx
            .get_flag("server")
            .cloned()
            .unwrap_or_else(|| cfg.network.dns_resolver.clone());
        let format = ctx.get_output_format();

        let client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start("Querying DNS");
        }

        let answers = client
            .query(domain, record_type)
            .map_err(|e| format!("DNS query failed: {}", e))?;

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // Database persistence
        let persist_flag = if ctx.has_flag("persist") {
            Some(true)
        } else if ctx.has_flag("no-persist") {
            Some(false)
        } else {
            None
        };

        let storage = StorageService::global();
        let attributes = build_partition_attributes(
            ctx,
            &domain_owned,
            [
                ("operation", "lookup"),
                ("record_type", record_type_str.as_str()),
                ("resolver", server.as_str()),
            ],
        );
        let mut pm =
            storage.persistence_for_target_with(&domain_owned, persist_flag, None, attributes)?;

        // Save DNS records to database
        if pm.is_enabled() {
            for answer in &answers {
                let value = answer.display_value();
                if let Err(e) = pm.add_dns_record(domain, answer.record_type, answer.ttl, &value) {
                    eprintln!("Warning: Failed to save DNS record to database: {}", e);
                }
            }
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"domain\": \"{}\",", domain);
            println!("  \"record_type\": \"{}\",", record_type_str);
            println!("  \"server\": \"{}\",", server);
            println!("  \"count\": {},", answers.len());
            println!("  \"records\": [");
            for (i, answer) in answers.iter().enumerate() {
                let comma = if i < answers.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"type\": \"{}\",", answer.type_string());
                println!("      \"value\": \"{}\",", answer.display_value());
                println!("      \"ttl\": {}", answer.ttl);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");

            // Commit database for JSON output
            pm.commit()?;
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("domain: {}", domain);
            println!("record_type: {}", record_type_str);
            println!("server: {}", server);
            println!("count: {}", answers.len());
            println!("records:");
            for answer in &answers {
                println!("  - type: {}", answer.type_string());
                println!("    value: \"{}\"", answer.display_value());
                println!("    ttl: {}", answer.ttl);
            }

            // Commit database for YAML output
            pm.commit()?;
            return Ok(());
        }

        // Human output
        if answers.is_empty() {
            Output::warning("No records found");

            // Commit database even if no results
            if let Some(db_path) = pm.commit()? {
                Output::success(&format!("Database saved to {}", db_path.display()));
            }
            return Ok(());
        }

        Output::header(&format!(
            "DNS: {} ({}) @ {}",
            domain, record_type_str, server
        ));
        Output::summary_line(&[("Records", &answers.len().to_string())]);

        for answer in &answers {
            let record_type = answer.type_string();
            let value = answer.display_value();
            let ttl_str = format!("{}s", answer.ttl);

            println!("  {} {} \x1b[2m{}\x1b[0m", record_type, value, ttl_str);
        }

        // DNS server intelligence gathering
        if ctx.has_flag("intel") {
            println!();
            Output::header("DNS Server Intelligence");

            // Query VERSION.BIND using TXT record
            // This is a special query supported by most DNS servers to reveal version info
            Output::spinner_start("Fingerprinting DNS server");

            // Re-use existing client configuration
            let cfg = config::get();
            let intel_client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

            // VERSION.BIND is queried as a TXT record
            // Domain: "version.bind" or "version.server"
            match intel_client.query("version.bind", DnsRecordType::TXT) {
                Ok(txt_records) => {
                    Output::spinner_done();

                    if !txt_records.is_empty() {
                        // Extract TXT data from DNS answers and concatenate
                        let mut txt_strings = Vec::new();
                        for answer in &txt_records {
                            if let crate::protocols::dns::DnsRdata::TXT(strings) = &answer.data {
                                txt_strings.extend(strings.clone());
                            }
                        }
                        let version_response = txt_strings.join(" ");

                        // Analyze the version string
                        let banner_info = analyze_dns_version(&version_response);

                        // Display vendor
                        if let Some(vendor) = &banner_info.vendor {
                            Output::item("Vendor", vendor);
                        }

                        // Display version
                        if let Some(version) = &banner_info.version {
                            Output::item("Version", version);
                        }

                        // Display OS hints
                        if !banner_info.os_hints.is_empty() {
                            Output::item("Operating System", &banner_info.os_hints.join(", "));
                        }

                        // Display if banner was modified
                        if banner_info.is_modified {
                            Output::warning("⚠ Banner appears to be modified/customized");
                        }

                        // Display custom fields (e.g., build info)
                        for (key, value) in &banner_info.custom_fields {
                            let label = key
                                .chars()
                                .enumerate()
                                .map(|(i, c)| {
                                    if i == 0 {
                                        c.to_uppercase().to_string()
                                    } else {
                                        c.to_string()
                                    }
                                })
                                .collect::<String>();
                            Output::item(&label, value);
                        }

                        // Display raw banner if modified
                        if banner_info.is_modified {
                            Output::item("Raw Response", &banner_info.raw_banner);
                        }
                    } else {
                        Output::warning("Server responded but returned no version information");
                    }
                }
                Err(e) => {
                    Output::spinner_done();
                    Output::warning(&format!("Could not fingerprint DNS server: {}", e));
                    Output::info("Some DNS servers hide version information for security");
                }
            }
        }

        // Commit database
        if let Some(db_path) = pm.commit()? {
            println!();
            Output::success(&format!("✓ Results saved to {}", db_path.display()));
        }

        Ok(())
    }

    fn lookup_all(&self, ctx: &CliContext) -> Result<(), String> {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb dns record all <DOMAIN>\nExample: rb dns record all google.com",
        )?;

        Validator::validate_domain(domain)?;

        let cfg = config::get();
        let server = ctx
            .get_flag("server")
            .cloned()
            .unwrap_or_else(|| cfg.network.dns_resolver.clone());
        let format = ctx.get_output_format();

        // All record types to query
        let record_types = vec![
            DnsRecordType::A,
            DnsRecordType::AAAA,
            DnsRecordType::CNAME,
            DnsRecordType::MX,
            DnsRecordType::NS,
            DnsRecordType::TXT,
            DnsRecordType::SOA,
        ];
        let total_types = record_types.len();

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start(&format!(
                "Querying {} record types in parallel",
                total_types
            ));
        }

        // Parallel queries
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        for record_type in record_types.iter().copied() {
            let domain = domain.clone();
            let server = server.clone();
            let results = Arc::clone(&results);
            let timeout = cfg.network.dns_timeout_ms;

            let handle = thread::spawn(move || {
                let client = DnsClient::new(&server).with_timeout(timeout);

                if let Ok(answers) = client.query(&domain, record_type) {
                    if !answers.is_empty() {
                        let mut results = results.lock().unwrap();
                        results.push((record_type, answers));
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        let mut completed = 0usize;
        for handle in handles {
            let _ = handle.join();
            completed += 1;
            if format == crate::cli::format::OutputFormat::Human {
                Output::spinner_status(&format!(
                    "Fetched {}/{} record types",
                    completed, total_types
                ));
            }
        }

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // Collect results
        let all_results = match Arc::try_unwrap(results) {
            Ok(mutex) => mutex.into_inner().unwrap(),
            Err(arc) => arc.lock().unwrap().clone(),
        };

        if all_results.is_empty() {
            Output::warning("No DNS records found");
            return Ok(());
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"domain\": \"{}\",", domain);
            println!("  \"server\": \"{}\",", server);
            println!("  \"record_types\": [");

            for (i, (record_type, answers)) in all_results.iter().enumerate() {
                let comma = if i < all_results.len() - 1 { "," } else { "" };
                println!("    {{");
                println!(
                    "      \"type\": \"{}\",",
                    Self::record_type_to_string(*record_type)
                );
                println!("      \"count\": {},", answers.len());
                println!("      \"records\": [");

                for (j, answer) in answers.iter().enumerate() {
                    let comma2 = if j < answers.len() - 1 { "," } else { "" };
                    println!("        {{");
                    println!("          \"value\": \"{}\",", answer.display_value());
                    println!("          \"ttl\": {}", answer.ttl);
                    println!("        }}{}", comma2);
                }

                println!("      ]");
                println!("    }}{}", comma);
            }

            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("domain: {}", domain);
            println!("server: {}", server);
            println!("record_types:");

            for (record_type, answers) in &all_results {
                println!("  - type: {}", Self::record_type_to_string(*record_type));
                println!("    count: {}", answers.len());
                println!("    records:");
                for answer in answers {
                    println!("      - value: \"{}\"", answer.display_value());
                    println!("        ttl: {}", answer.ttl);
                }
            }
            return Ok(());
        }

        // Human output
        Output::header(&format!("DNS: {} (ALL TYPES) @ {}", domain, server));

        let total_records: usize = all_results.iter().map(|(_, answers)| answers.len()).sum();
        Output::summary_line(&[
            ("Record Types", &all_results.len().to_string()),
            ("Total Records", &total_records.to_string()),
        ]);
        println!();

        // Group by record type
        for (record_type, answers) in &all_results {
            let type_str = Self::record_type_to_string(*record_type);
            println!("  \x1b[1m{}\x1b[0m ({} records)", type_str, answers.len());

            for answer in answers {
                let value = answer.display_value();
                let ttl_str = format!("{}s", answer.ttl);
                println!("    {} \x1b[2m{}\x1b[0m", value, ttl_str);
            }
            println!();
        }

        Ok(())
    }

    fn resolve(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb dns record resolve <DOMAIN>\nExample: rb dns record resolve github.com",
        )?;

        Validator::validate_domain(domain)?;

        let cfg = config::get();
        let server = ctx
            .get_flag("server")
            .cloned()
            .unwrap_or_else(|| cfg.network.dns_resolver.clone());
        let client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

        Output::spinner_start(&format!("Resolving {}", domain));
        let answers = client
            .query(domain, DnsRecordType::A)
            .map_err(|e| format!("Resolution failed: {}", e))?;
        Output::spinner_done();

        let mut found = false;
        for answer in answers {
            if let Some(ip) = answer.as_ip() {
                Output::success(&format!("{} → {}", domain, ip));
                found = true;
            }
        }

        if !found {
            Output::error(&format!("{} does not resolve to any IP", domain));
        }

        Ok(())
    }

    fn reverse(&self, ctx: &CliContext) -> Result<(), String> {
        let ip = ctx.target.as_ref().ok_or(
            "Missing IP address.\nUsage: rb dns record reverse <IP>\nExample: rb dns record reverse 8.8.8.8",
        )?;

        let ip_addr = Validator::validate_ip(ip)?;
        let ptr_name = Self::build_ptr_name(ip_addr);

        let cfg = config::get();
        let server = ctx
            .get_flag("server")
            .cloned()
            .unwrap_or_else(|| cfg.network.dns_resolver.clone());
        let client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

        Output::spinner_start(&format!("Querying PTR for {}", ip));
        let answers = client
            .query(&ptr_name, DnsRecordType::PTR)
            .map_err(|e| format!("Reverse lookup failed: {}", e))?;
        Output::spinner_done();

        if answers.is_empty() {
            Output::warning("No PTR records found");
            return Ok(());
        }

        Output::subheader(&format!("PTR records for {}:", ip));
        println!();
        Output::table_header(&["HOST", "TTL"]);
        for answer in answers {
            let value = answer.display_value();
            let ttl = answer.ttl.to_string();
            Output::table_row(&[value.as_str(), ttl.as_str()]);
        }

        println!();
        Output::success("Reverse lookup completed");

        Ok(())
    }

    fn bruteforce(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx
            .target
            .as_ref()
            .ok_or("Missing domain.\nUsage: rb dns record bruteforce <DOMAIN> --wordlist WORDS")?;

        Validator::validate_domain(domain)?;

        // Get wordlist
        let default_wordlist = "subdomains-top100".to_string();
        let wordlist_name = ctx.get_flag("wordlist").unwrap_or(&default_wordlist);

        let wordlist_manager = WordlistManager::new()?;
        let wordlist = wordlist_manager.get(&wordlist_name)?;

        Output::header(&format!("Subdomain Brute Force: {}", domain));
        Output::item("Wordlist", &wordlist_name);
        Output::item("Entries", &wordlist.len().to_string());
        println!();

        // DNS server
        let default_server = "8.8.8.8".to_string();
        let dns_server = ctx.get_flag("server").unwrap_or(&default_server);

        // Thread count
        let thread_count = ctx
            .get_flag("threads")
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(50);

        Output::spinner_start(&format!(
            "Scanning {} subdomains with {} threads",
            wordlist.len(),
            thread_count
        ));

        // Shared results container
        let found_subdomains = Arc::new(Mutex::new(Vec::new()));
        let wordlist = Arc::new(wordlist);

        // Create work queue
        let work_index = Arc::new(Mutex::new(0));

        // Spawn worker threads
        let mut handles = vec![];
        for _ in 0..thread_count {
            let wordlist_clone = Arc::clone(&wordlist);
            let found_clone = Arc::clone(&found_subdomains);
            let work_clone = Arc::clone(&work_index);
            let domain_clone = domain.to_string();
            let dns_server_clone = dns_server.clone();

            let handle = thread::spawn(move || {
                let client = DnsClient::new(&dns_server_clone);

                loop {
                    // Get next work item
                    let index = {
                        let mut idx = work_clone.lock().unwrap();
                        if *idx >= wordlist_clone.len() {
                            break;
                        }
                        let current = *idx;
                        *idx += 1;
                        current
                    };

                    let subdomain_part = &wordlist_clone[index];
                    let full_subdomain = format!("{}.{}", subdomain_part, domain_clone);

                    // Try to resolve
                    if let Ok(response) = client.query(&full_subdomain, DnsRecordType::A) {
                        if !response.is_empty() {
                            // Extract IPs
                            let ips: Vec<String> = response
                                .iter()
                                .filter_map(|answer| answer.as_ip())
                                .collect();

                            if !ips.is_empty() {
                                found_clone.lock().unwrap().push((full_subdomain, ips));
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            let _ = handle.join();
        }

        Output::spinner_done();

        // Display results
        let results = found_subdomains.lock().unwrap();

        if results.is_empty() {
            Output::warning("No subdomains found");
            return Ok(());
        }

        Output::section(&format!("Found {} subdomains", results.len()));
        println!();

        for (subdomain, ips) in results.iter() {
            Output::success(&format!("{}", subdomain));
            for ip in ips {
                Output::dim(&format!("  → {}", ip));
            }
        }

        // Database persistence
        let persist_flag = if ctx.has_flag("persist") {
            Some(true)
        } else if ctx.has_flag("no-persist") {
            Some(false)
        } else {
            None
        };

        let attributes = build_partition_attributes(
            ctx,
            domain,
            [
                ("operation", "bruteforce"),
                ("wordlist", wordlist_name.as_str()),
            ],
        );
        let mut pm = StorageService::global().persistence_for_target_with(
            domain,
            persist_flag,
            None,
            attributes,
        )?;

        if pm.is_enabled() {
            for (subdomain, ips) in results.iter() {
                let ip_addrs: Vec<IpAddr> = ips
                    .iter()
                    .filter_map(|ip_str| ip_str.parse::<IpAddr>().ok())
                    .collect();

                if let Err(e) = pm.add_subdomain(domain, subdomain, 0, &ip_addrs) {
                    eprintln!("Warning: Failed to save subdomain to database: {}", e);
                }
            }

            Output::success(&format!(
                "✓ Saved {} subdomains to {}.rdb",
                results.len(),
                domain
            ));
        }

        println!();
        Output::success(&format!(
            "Scan complete: {}/{} found",
            results.len(),
            wordlist.len()
        ));

        Ok(())
    }

    fn parse_record_type(s: &str) -> Result<DnsRecordType, String> {
        match s.to_uppercase().as_str() {
            "A" => Ok(DnsRecordType::A),
            "AAAA" => Ok(DnsRecordType::AAAA),
            "MX" => Ok(DnsRecordType::MX),
            "NS" => Ok(DnsRecordType::NS),
            "TXT" => Ok(DnsRecordType::TXT),
            "CNAME" => Ok(DnsRecordType::CNAME),
            "ANY" => Ok(DnsRecordType::ANY),
            _ => Err(format!(
                "Invalid record type: {}\nSupported types: A, AAAA, MX, NS, TXT, CNAME, ANY",
                s
            )),
        }
    }

    fn record_type_to_string(record_type: DnsRecordType) -> &'static str {
        match record_type {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::MX => "MX",
            DnsRecordType::NS => "NS",
            DnsRecordType::TXT => "TXT",
            DnsRecordType::CNAME => "CNAME",
            DnsRecordType::SOA => "SOA",
            DnsRecordType::PTR => "PTR",
            DnsRecordType::SRV => "SRV",
            DnsRecordType::ANY => "ANY",
        }
    }

    fn build_ptr_name(addr: std::net::IpAddr) -> String {
        match addr {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            std::net::IpAddr::V6(v6) => {
                let mut labels = Vec::with_capacity(32);
                for byte in v6.octets().iter().rev() {
                    labels.push(format!("{:x}", byte & 0x0F));
                    labels.push(format!("{:x}", byte >> 4));
                }
                format!("{}.ip6.arpa", labels.join("."))
            }
        }
    }

    // ===== RESTful Commands - Query Stored Data =====

    fn list_records(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or("Missing target domain")?;

        let db_path = self.get_db_path(ctx, domain)?;

        Output::header(&format!("Listing DNS Records from Database: {}", domain));
        Output::info(&format!("Database: {}", db_path.display()));

        let mut query = StorageService::global()
            .open_query_manager(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        annotate_query_partition(
            ctx,
            &db_path,
            [("query_dataset", "dns"), ("query_operation", "list")],
        );

        let records = query
            .list_dns_records(domain)
            .map_err(|e| format!("Query failed: {}", e))?;

        if records.is_empty() {
            Output::warning("No DNS records found in database");
            Output::info(&format!(
                "Run a DNS lookup first: rb dns record lookup {} --persist",
                domain
            ));
            return Ok(());
        }

        Output::success(&format!("Found {} DNS record(s)", records.len()));
        println!();

        println!("TYPE     VALUE                                          TTL");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        for record in &records {
            let type_str = format!("{:?}", record.record_type);
            println!("{:<8} {:<46} {}", type_str, record.value, record.ttl);
        }

        Ok(())
    }

    fn get_record(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx
            .target
            .as_ref()
            .ok_or("Missing target (format: domain:TYPE)")?;

        let parts: Vec<&str> = target.split(':').collect();
        if parts.len() != 2 {
            return Err(
                "Invalid format. Use: rb dns record get <domain>:<type> (e.g., example.com:A)"
                    .to_string(),
            );
        }

        let domain = parts[0];
        let record_type_str = parts[1].to_uppercase();

        let record_type = match record_type_str.as_str() {
            "A" => StorageDnsRecordType::A,
            "AAAA" => StorageDnsRecordType::AAAA,
            "MX" => StorageDnsRecordType::MX,
            "NS" => StorageDnsRecordType::NS,
            "TXT" => StorageDnsRecordType::TXT,
            "CNAME" => StorageDnsRecordType::CNAME,
            _ => {
                return Err(format!(
                    "Invalid record type: {}. Valid types: A, AAAA, MX, NS, TXT, CNAME",
                    record_type_str
                ))
            }
        };

        let db_path = self.get_db_path(ctx, domain)?;

        Output::header(&format!(
            "Querying DNS Record: {} {}",
            domain, record_type_str
        ));

        let mut query = StorageService::global()
            .open_query_manager(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        annotate_query_partition(
            ctx,
            &db_path,
            [
                ("query_dataset", "dns"),
                ("query_operation", "get"),
                ("query_key", record_type_str.as_str()),
            ],
        );

        let all_records = query
            .list_dns_records(domain)
            .map_err(|e| format!("Query failed: {}", e))?;

        let matching_records: Vec<_> = all_records
            .iter()
            .filter(|r| {
                std::mem::discriminant(&r.record_type) == std::mem::discriminant(&record_type)
            })
            .collect();

        if matching_records.is_empty() {
            Output::warning(&format!("No {} records found in database", record_type_str));
            Output::info(&format!(
                "Run a DNS lookup first: rb dns record lookup {} --type {} --persist",
                domain, record_type_str
            ));
            return Ok(());
        }

        Output::success(&format!(
            "Found {} {} record(s)",
            matching_records.len(),
            record_type_str
        ));
        println!();

        for record in matching_records {
            Output::item("Domain", &record.domain);
            Output::item("Type", &format!("{:?}", record.record_type));
            Output::item("Value", &record.value);
            Output::item("TTL", &record.ttl.to_string());
            println!();
        }

        Ok(())
    }

    fn describe_records(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or("Missing target domain")?;

        let db_path = self.get_db_path(ctx, domain)?;

        Output::header(&format!("DNS Description: {}", domain));
        Output::info(&format!("Database: {}", db_path.display()));

        let mut query = StorageService::global()
            .open_query_manager(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        annotate_query_partition(
            ctx,
            &db_path,
            [("query_dataset", "dns"), ("query_operation", "describe")],
        );

        let records = query
            .list_dns_records(domain)
            .map_err(|e| format!("Query failed: {}", e))?;

        if records.is_empty() {
            Output::warning("No DNS data found in database");
            Output::info(&format!(
                "Run a DNS lookup first: rb dns record lookup {} --persist",
                domain
            ));
            return Ok(());
        }

        // Count records by type
        let mut type_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for record in &records {
            let type_str = format!("{:?}", record.record_type);
            *type_counts.entry(type_str).or_insert(0) += 1;
        }

        Output::success(&format!("Total DNS Records: {}", records.len()));
        println!();

        println!("📊 Record Summary:");
        println!("━━━━━━━━━━━━━━━━━━━");
        for (record_type, count) in &type_counts {
            println!("  {} records: {}", record_type, count);
        }
        println!();

        println!("📝 Detailed Records:");
        println!("━━━━━━━━━━━━━━━━━━━");
        for record in &records {
            println!(
                "  {:6} → {} (TTL: {})",
                format!("{:?}", record.record_type),
                record.value,
                record.ttl
            );
        }

        Ok(())
    }

    fn get_db_path(&self, ctx: &CliContext, domain: &str) -> Result<std::path::PathBuf, String> {
        if let Some(db_path) = ctx.get_flag("db") {
            return Ok(std::path::PathBuf::from(db_path));
        }

        let cwd = std::env::current_dir().map_err(|e| format!("Failed to get CWD: {}", e))?;
        let base = domain.trim_start_matches("www.").to_lowercase();
        let candidate = cwd.join(format!("{}.rdb", &base));
        if candidate.exists() {
            return Ok(candidate);
        }

        Err(format!(
            "Database not found: {}\nRun a scan first: rb dns record lookup {} --persist",
            candidate.display(),
            domain
        ))
    }
}
