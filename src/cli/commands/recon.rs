/// Recon/domain command - Information gathering and OSINT
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::recon::harvester::Harvester;
use crate::modules::recon::subdomain::{
    load_wordlist_from_file, EnumerationSource, SubdomainEnumerator,
};
use crate::modules::recon::urlharvest::UrlHarvester;
use crate::persistence::{PersistenceManager, QueryManager};
use crate::protocols::whois::WhoisClient;
use crate::storage::SubdomainSource;
use std::net::Ipv4Addr;

pub struct ReconCommand;

impl Command for ReconCommand {
    fn domain(&self) -> &str {
        "recon"
    }

    fn resource(&self) -> &str {
        "domain"
    }

    fn description(&self) -> &str {
        "Information gathering and baseline OSINT"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            // Action verbs - execute reconnaissance
            Route {
                verb: "whois",
                summary: "Query WHOIS information for a domain",
                usage: "rb recon domain whois <domain>",
            },
            Route {
                verb: "subdomains",
                summary: "Enumerate subdomains via CT logs and DNS bruteforce",
                usage: "rb recon domain subdomains <domain> [--passive] [--threads N]",
            },
            Route {
                verb: "harvest",
                summary: "OSINT data harvesting - emails, subdomains, URLs (theHarvester)",
                usage: "rb recon domain harvest <domain>",
            },
            Route {
                verb: "urls",
                summary: "Harvest historical URLs from Wayback, URLScan, etc (waybackurls/gau)",
                usage: "rb recon domain urls <domain> [--include PATTERN] [--exclude PATTERN]",
            },
            Route {
                verb: "osint",
                summary: "Run username OSINT helpers (coming soon)",
                usage: "rb recon domain osint <username>",
            },
            Route {
                verb: "email",
                summary: "Email reconnaissance helpers (coming soon)",
                usage: "rb recon domain email <email>",
            },
            // RESTful verbs - query stored data
            Route {
                verb: "list",
                summary: "List all reconnaissance data for a domain from database",
                usage: "rb recon domain list <domain> [--db <file>]",
            },
            Route {
                verb: "get",
                summary: "Get specific reconnaissance data (whois) from database",
                usage: "rb recon domain get <domain>:whois [--db <file>]",
            },
            Route {
                verb: "describe",
                summary: "Get detailed reconnaissance summary from database",
                usage: "rb recon domain describe <domain> [--db <file>]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("recursive", "Recursive enumeration").with_short('r'),
            Flag::new("wordlist", "Custom wordlist path").with_short('w'),
            Flag::new("threads", "Number of threads for DNS bruteforce").with_default("10"),
            Flag::new("passive", "Passive enumeration only (CT logs)").with_short('p'),
            Flag::new("raw", "Show raw WHOIS response"),
            Flag::new("include", "Include URLs matching pattern").with_short('i'),
            Flag::new("exclude", "Exclude URLs matching pattern").with_short('e'),
            Flag::new(
                "extensions",
                "Filter by extensions (comma-separated: js,php,asp)",
            ),
            Flag::new("persist", "Save results to binary database (.rdb file)"),
            Flag::new("no-persist", "Don't save results (overrides config)"),
            Flag::new(
                "db",
                "Database file path for RESTful queries (default: auto-detect)",
            )
            .with_short('d'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("WHOIS lookup", "rb recon domain whois example.com"),
            (
                "Subdomain enumeration (all methods)",
                "rb recon domain subdomains example.com",
            ),
            (
                "Passive enumeration only",
                "rb recon domain subdomains example.com --passive",
            ),
            (
                "Custom wordlist and threads",
                "rb recon domain subdomains example.com --wordlist my-list.txt --threads 20",
            ),
            (
                "OSINT harvesting (theHarvester-style)",
                "rb recon domain harvest example.com",
            ),
            (
                "Get historical URLs (waybackurls/gau)",
                "rb recon domain urls example.com",
            ),
            (
                "Filter URLs by pattern",
                "rb recon domain urls example.com --include /api/ --exclude .png",
            ),
            (
                "Filter by file extension",
                "rb recon domain urls example.com --extensions js,php,asp",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            // Action verbs
            "whois" => self.whois(ctx),
            "subdomains" => self.subdomains(ctx),
            "harvest" => self.harvest(ctx),
            "urls" => self.urls(ctx),
            "osint" => self.osint(ctx),
            "email" => self.email(ctx),
            // RESTful verbs
            "list" => self.list_recon(ctx),
            "get" => self.get_recon(ctx),
            "describe" => self.describe_recon(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(
                        verb,
                        &["whois", "subdomains", "harvest", "osint", "email", "list", "get", "describe"]
                    )
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl ReconCommand {
    fn whois(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain whois <DOMAIN>\nExample: rb recon domain whois example.com",
        )?;

        Validator::validate_domain(domain)?;

        // Clone domain for persistence
        let domain_owned = domain.to_string();

        let format = ctx.get_output_format();
        let client = WhoisClient::new();

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start(&format!("Querying WHOIS for {}", domain));
        }

        let result = client.query(domain)?;

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

        let mut pm = PersistenceManager::new(&domain_owned, persist_flag)?;

        // Save WHOIS data to database
        if pm.is_enabled() {
            // Serialize WHOIS result to bytes (simple format)
            let mut whois_data = String::new();
            whois_data.push_str(&format!("Domain: {}\n", domain));
            if let Some(ref registrar) = result.registrar {
                whois_data.push_str(&format!("Registrar: {}\n", registrar));
            }
            if let Some(ref org) = result.registrant_org {
                whois_data.push_str(&format!("Organization: {}\n", org));
            }
            if let Some(ref country) = result.registrant_country {
                whois_data.push_str(&format!("Country: {}\n", country));
            }
            if let Some(ref created) = result.creation_date {
                whois_data.push_str(&format!("Created: {}\n", created));
            }
            if let Some(ref updated) = result.updated_date {
                whois_data.push_str(&format!("Updated: {}\n", updated));
            }
            if let Some(ref expires) = result.expiration_date {
                whois_data.push_str(&format!("Expires: {}\n", expires));
            }
            for ns in &result.name_servers {
                whois_data.push_str(&format!("Nameserver: {}\n", ns));
            }
            for status in &result.status {
                whois_data.push_str(&format!("Status: {}\n", status));
            }

            if let Err(e) = pm.add_whois(domain, whois_data.as_bytes()) {
                eprintln!("Warning: Failed to save WHOIS data to database: {}", e);
            }
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"domain\": \"{}\",", domain);
            if let Some(ref registrar) = result.registrar {
                println!("  \"registrar\": \"{}\",", registrar);
            }
            if let Some(ref org) = result.registrant_org {
                println!("  \"registrant_org\": \"{}\",", org);
            }
            if let Some(ref country) = result.registrant_country {
                println!("  \"registrant_country\": \"{}\",", country);
            }
            if let Some(ref created) = result.creation_date {
                println!("  \"creation_date\": \"{}\",", created);
            }
            if let Some(ref updated) = result.updated_date {
                println!("  \"updated_date\": \"{}\",", updated);
            }
            if let Some(ref expires) = result.expiration_date {
                println!("  \"expiration_date\": \"{}\",", expires);
            }
            println!("  \"name_servers\": [");
            for (i, ns) in result.name_servers.iter().enumerate() {
                let comma = if i < result.name_servers.len() - 1 {
                    ","
                } else {
                    ""
                };
                println!("    \"{}\"{}", ns, comma);
            }
            println!("  ],");
            println!("  \"status\": [");
            for (i, status) in result.status.iter().enumerate() {
                let comma = if i < result.status.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", status, comma);
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
            if let Some(ref registrar) = result.registrar {
                println!("registrar: {}", registrar);
            }
            if let Some(ref org) = result.registrant_org {
                println!("registrant_org: {}", org);
            }
            if let Some(ref country) = result.registrant_country {
                println!("registrant_country: {}", country);
            }
            if let Some(ref created) = result.creation_date {
                println!("creation_date: {}", created);
            }
            if let Some(ref updated) = result.updated_date {
                println!("updated_date: {}", updated);
            }
            if let Some(ref expires) = result.expiration_date {
                println!("expiration_date: {}", expires);
            }
            println!("name_servers:");
            for ns in &result.name_servers {
                println!("  - {}", ns);
            }
            println!("status:");
            for status in &result.status {
                println!("  - {}", status);
            }

            // Commit database for YAML output
            pm.commit()?;
            return Ok(());
        }

        Output::header(&format!("WHOIS: {}", domain));

        // Compact summary line
        let mut summary_items = vec![];
        if let Some(ref registrar) = result.registrar {
            summary_items.push(("Registrar", registrar.as_str()));
        }
        if let Some(ref org) = result.registrant_org {
            summary_items.push(("Org", org.as_str()));
        }
        if let Some(ref country) = result.registrant_country {
            summary_items.push(("Country", country.as_str()));
        }

        if !summary_items.is_empty() {
            Output::summary_line(&summary_items);
        }

        // Compact dates on one line
        let mut date_items = vec![];
        if let Some(ref created) = result.creation_date {
            date_items.push(("Created", created.as_str()));
        }
        if let Some(ref expires) = result.expiration_date {
            date_items.push(("Expires", expires.as_str()));
        }

        if !date_items.is_empty() {
            Output::summary_line(&date_items);
        }

        if !result.name_servers.is_empty() {
            Output::subheader(&format!("Nameservers ({})", result.name_servers.len()));
            for ns in &result.name_servers {
                println!("  {}", ns);
            }
        }

        if !result.status.is_empty() {
            Output::subheader(&format!("Status ({})", result.status.len()));
            for (i, status) in result.status.iter().enumerate() {
                if i < 3 {
                    println!("  {}", status);
                } else if i == 3 {
                    println!("  ... and {} more", result.status.len() - 3);
                    break;
                }
            }
        }

        if ctx.has_flag("raw") {
            println!();
            Output::subheader("Raw WHOIS Response");
            println!();
            println!("{}", result.raw);
        }

        // Commit database
        if let Some(db_path) = pm.commit()? {
            println!();
            Output::success(&format!("✓ Results saved to {}", db_path.display()));
        } else {
            println!();
            Output::success("WHOIS lookup completed");
        }

        Ok(())
    }

    fn subdomains(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx
            .target
            .as_ref()
            .ok_or("Missing domain.\nUsage: rb recon domain subdomains <DOMAIN>")?;

        Validator::validate_domain(domain)?;

        let format = ctx.get_output_format();

        // Create enumerator
        let mut enumerator = SubdomainEnumerator::new(domain);

        // Apply flags
        if let Some(threads_str) = ctx.get_flag("threads") {
            let threads: usize = threads_str
                .parse()
                .map_err(|_| format!("Invalid threads value: {}", threads_str))?;
            enumerator = enumerator.with_threads(threads);
        }

        if let Some(wordlist_path) = ctx.get_flag("wordlist") {
            let wordlist = load_wordlist_from_file(wordlist_path)?;
            enumerator = enumerator.with_wordlist(wordlist);
        }

        let passive_only = ctx.has_flag("passive");

        // Run enumeration
        let results = if passive_only {
            enumerator.enumerate_ct_logs()?
        } else {
            enumerator.enumerate_all()?
        };

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"domain\": \"{}\",", domain);
            println!("  \"count\": {},", results.len());
            println!("  \"subdomains\": [");
            for (i, result) in results.iter().enumerate() {
                let comma = if i < results.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"subdomain\": \"{}\",", result.subdomain);
                println!("      \"ips\": [");
                for (j, ip) in result.ips.iter().enumerate() {
                    let ip_comma = if j < result.ips.len() - 1 { "," } else { "" };
                    println!("        \"{}\"{}", ip, ip_comma);
                }
                println!("      ],");
                println!("      \"source\": \"{}\"", result.source);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("domain: {}", domain);
            println!("count: {}", results.len());
            println!("subdomains:");
            for result in &results {
                println!("  - subdomain: {}", result.subdomain);
                println!("    ips:");
                for ip in &result.ips {
                    println!("      - {}", ip);
                }
                println!("    source: {}", result.source);
            }
            return Ok(());
        }

        // Human output
        if results.is_empty() {
            Output::warning("No subdomains found");
            return Ok(());
        }

        Output::header("Subdomain Enumeration");
        Output::item("Target Domain", domain);
        println!();

        println!();
        Output::subheader(&format!("Discovered Subdomains ({})", results.len()));
        println!();

        // Print table header
        println!(
            "  {:<40} {:<20} {:<10}",
            "SUBDOMAIN", "IP ADDRESSES", "SOURCE"
        );
        println!("  {}", "─".repeat(75));

        for result in &results {
            let ips = if result.ips.is_empty() {
                "N/A".to_string()
            } else if result.ips.len() == 1 {
                result.ips[0].clone()
            } else {
                format!("{} (+{})", result.ips[0], result.ips.len() - 1)
            };

            println!(
                "  {:<40} {:<20} {:<10}",
                result.subdomain,
                ips,
                result.source.to_string()
            );
        }

        println!();
        Output::success(&format!("Found {} unique subdomains", results.len()));

        // Persistence
        let persist_flag = if ctx.has_flag("persist") {
            Some(true)
        } else if ctx.has_flag("no-persist") {
            Some(false)
        } else {
            None
        };

        let mut pm = PersistenceManager::new(domain, persist_flag)?;
        if pm.is_enabled() {
            for result in &results {
                let source = map_subdomain_source(&result.source);
                let ips: Vec<u32> = result
                    .ips
                    .iter()
                    .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
                    .map(u32::from)
                    .collect();

                pm.add_subdomain(domain, &result.subdomain, source as u8, &ips)?;
            }

            if let Some(db_path) = pm.commit()? {
                Output::success(&format!("Results saved to {}", db_path.display()));
            }
        }

        Ok(())
    }

    fn harvest(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain harvest <DOMAIN>\nExample: rb recon domain harvest example.com",
        )?;

        Validator::validate_domain(domain)?;

        Output::header("OSINT Data Harvesting (theHarvester)");
        Output::item("Target Domain", domain);
        println!();

        let harvester = Harvester::new();

        Output::spinner_start(&format!("Harvesting OSINT data for {}", domain));
        let result = harvester.harvest(domain)?;
        Output::spinner_done();

        // Display emails
        if !result.emails.is_empty() {
            println!();
            Output::subheader(&format!("Email Addresses ({})", result.emails.len()));
            println!();
            for email in &result.emails {
                println!("  \x1b[36m✉\x1b[0m  {}", email);
            }
        }

        // Display subdomains
        if !result.subdomains.is_empty() {
            println!();
            Output::subheader(&format!("Subdomains ({})", result.subdomains.len()));
            println!();
            for subdomain in &result.subdomains {
                println!("  \x1b[32m●\x1b[0m  {}", subdomain);
            }
        }

        // Display IPs
        if !result.ips.is_empty() {
            println!();
            Output::subheader(&format!("IP Addresses ({})", result.ips.len()));
            println!();
            for ip in &result.ips {
                println!("  \x1b[33m◆\x1b[0m  {}", ip);
            }
        }

        // Display URLs
        if !result.urls.is_empty() {
            println!();
            Output::subheader(&format!("URLs ({})", result.urls.len()));
            println!();
            for url in &result.urls {
                println!("  \x1b[35m→\x1b[0m  {}", url);
            }
        }

        println!();
        let total =
            result.emails.len() + result.subdomains.len() + result.ips.len() + result.urls.len();
        Output::success(&format!("Harvested {} total items", total));

        Ok(())
    }

    fn urls(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain urls <DOMAIN>\nExample: rb recon domain urls example.com",
        )?;

        Validator::validate_domain(domain)?;

        Output::header("URL Harvester (waybackurls/gau)");
        Output::item("Target Domain", domain);
        println!();

        let harvester = UrlHarvester::new();

        Output::spinner_start(&format!("Harvesting historical URLs for {}", domain));
        let mut urls = harvester.harvest(domain)?;
        Output::spinner_done();

        // Apply filters
        let include_pattern = ctx.get_flag("include").or_else(|| ctx.get_flag("i"));
        let exclude_pattern = ctx.get_flag("exclude").or_else(|| ctx.get_flag("e"));

        if include_pattern.is_some() || exclude_pattern.is_some() {
            urls = harvester.filter_urls(
                urls,
                include_pattern.as_ref().map(|s| s.as_str()),
                exclude_pattern.as_ref().map(|s| s.as_str()),
            );
        }

        // Filter by extensions if specified
        if let Some(extensions_str) = ctx.get_flag("extensions") {
            let extensions: Vec<&str> = extensions_str.split(',').map(|s| s.trim()).collect();
            urls = harvester.filter_by_extension(urls, &extensions);
        }

        if urls.is_empty() {
            Output::warning("No URLs found");
            return Ok(());
        }

        // Group by source
        let mut by_source: std::collections::HashMap<
            String,
            Vec<&crate::modules::recon::urlharvest::HarvestedUrl>,
        > = std::collections::HashMap::new();

        for url in &urls {
            by_source
                .entry(url.source.clone())
                .or_insert_with(Vec::new)
                .push(url);
        }

        // Display results
        println!();
        Output::subheader(&format!("Discovered URLs ({})", urls.len()));
        println!();

        // Sort sources alphabetically
        let mut sources: Vec<_> = by_source.keys().collect();
        sources.sort();

        for source in &sources {
            let source_urls = by_source.get(*source).unwrap();
            println!("\x1b[1m\x1b[36m{}\x1b[0m ({})", source, source_urls.len());

            // Show first 100 URLs per source (or all if less)
            let display_count = source_urls.len().min(100);
            for url_obj in source_urls.iter().take(display_count) {
                if let Some(ref timestamp) = url_obj.timestamp {
                    println!("  \x1b[2m{}\x1b[0m  {}", timestamp, url_obj.url);
                } else {
                    println!("  {}", url_obj.url);
                }
            }

            if source_urls.len() > 100 {
                println!(
                    "  \x1b[2m... and {} more URLs\x1b[0m",
                    source_urls.len() - 100
                );
            }

            println!();
        }

        // Summary by source
        println!("\x1b[1mSummary by Source:\x1b[0m");
        for source in &sources {
            let count = by_source.get(*source).unwrap().len();
            println!("  {}: {}", source, count);
        }

        println!();
        Output::success(&format!("Found {} unique URLs", urls.len()));

        Ok(())
    }

    fn osint(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx
            .target
            .as_ref()
            .ok_or("Missing username.\nUsage: rb recon domain osint <USERNAME>")?;

        if target.is_empty() {
            return Err("Username cannot be empty".to_string());
        }

        Output::warning("OSINT helpers not yet implemented");
        println!("\nComing soon!");
        Ok(())
    }

    fn email(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx
            .target
            .as_ref()
            .ok_or("Missing email address.\nUsage: rb recon domain email <EMAIL>")?;

        if !target.contains('@') {
            return Err(format!("Invalid email address: {}", target));
        }

        Output::warning("Email reconnaissance not yet implemented");
        println!("\nComing soon!");
        Ok(())
    }
}

fn map_subdomain_source(source: &EnumerationSource) -> SubdomainSource {
    match source {
        EnumerationSource::CertificateTransparency => SubdomainSource::CertTransparency,
        EnumerationSource::DnsBruteforce => SubdomainSource::DnsBruteforce,
        EnumerationSource::VirusTotal
        | EnumerationSource::SecurityTrails
        | EnumerationSource::HackerTarget => SubdomainSource::SearchEngine,
        EnumerationSource::Manual => SubdomainSource::WebCrawl,
    }
}

    // ===== RESTful Commands - Query Stored Data =====

    fn list_recon(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or("Missing target domain")?;
        let db_path = self.get_db_path(ctx, domain)?;

        Output::header(&format!("Listing Reconnaissance Data: {}", domain));
        Output::info(&format!("Database: {}", db_path.display()));

        let mut query =
            QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        // Check for WHOIS data
        let whois = query.get_whois(domain).map_err(|e| format!("Query failed: {}", e))?;

        // Check for subdomains
        let subdomains = query.list_subdomains(domain).map_err(|e| format!("Query failed: {}", e))?;

        if whois.is_none() && subdomains.is_empty() {
            Output::warning("No reconnaissance data found in database");
            Output::info(&format!(
                "Run reconnaissance first: rb recon domain whois {} --persist",
                domain
            ));
            return Ok(());
        }

        println!();
        if let Some(_) = whois {
            Output::success("✓ WHOIS data available");
        }

        if !subdomains.is_empty() {
            Output::success(&format!("✓ {} subdomain(s) found", subdomains.len()));
        }

        Ok(())
    }

    fn get_recon(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx
            .target
            .as_ref()
            .ok_or("Missing target (format: domain:TYPE)")?;

        let parts: Vec<&str> = target.split(':').collect();
        if parts.len() != 2 {
            return Err(
                "Invalid format. Use: rb recon domain get <domain>:whois".to_string(),
            );
        }

        let domain = parts[0];
        let data_type = parts[1].to_lowercase();

        if data_type != "whois" {
            return Err(format!(
                "Invalid data type: {}. Valid types: whois",
                data_type
            ));
        }

        let db_path = self.get_db_path(ctx, domain)?;

        Output::header(&format!("Querying WHOIS Data: {}", domain));

        let mut query =
            QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        let whois = query
            .get_whois(domain)
            .map_err(|e| format!("Query failed: {}", e))?;

        match whois {
            Some(record) => {
                Output::success("WHOIS Record Found");
                println!();

                Output::item("Domain", &record.domain);
                Output::item("Registrar", &record.registrar);
                Output::item("Created", &record.creation_date);
                Output::item("Expires", &record.expiration_date);
                Output::item("Updated", &record.updated_date);

                if !record.name_servers.is_empty() {
                    println!("\nName Servers:");
                    for ns in &record.name_servers {
                        println!("  • {}", ns);
                    }
                }

                if !record.status.is_empty() {
                    println!("\nStatus:");
                    for status in &record.status {
                        println!("  • {}", status);
                    }
                }
            }
            None => {
                Output::warning("No WHOIS data found in database");
                Output::info(&format!(
                    "Run WHOIS first: rb recon domain whois {} --persist",
                    domain
                ));
            }
        }

        Ok(())
    }

    fn describe_recon(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or("Missing target domain")?;
        let db_path = self.get_db_path(ctx, domain)?;

        Output::header(&format!("Reconnaissance Summary: {}", domain));
        Output::info(&format!("Database: {}", db_path.display()));

        let mut query =
            QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        let whois = query.get_whois(domain).map_err(|e| format!("Query failed: {}", e))?;
        let subdomains = query.list_subdomains(domain).map_err(|e| format!("Query failed: {}", e))?;

        if whois.is_none() && subdomains.is_empty() {
            Output::warning("No reconnaissance data found in database");
            Output::info(&format!(
                "Run reconnaissance first: rb recon domain whois {} --persist",
                domain
            ));
            return Ok(());
        }

        println!();
        println!("📊 Data Summary:");
        println!("━━━━━━━━━━━━━━━━");

        if let Some(record) = whois {
            println!("  ✓ WHOIS");
            println!("    Registrar: {}", record.registrar);
            println!("    Expires: {}", record.expiration_date);
            println!("    Name Servers: {}", record.name_servers.len());
        } else {
            println!("  ✗ WHOIS (not available)");
        }

        if !subdomains.is_empty() {
            println!("  ✓ Subdomains: {}", subdomains.len());
            println!("\n    Top subdomains:");
            for (i, subdomain) in subdomains.iter().take(10).enumerate() {
                println!("      {}. {}", i + 1, subdomain);
            }
            if subdomains.len() > 10 {
                println!("      ... and {} more", subdomains.len() - 10);
            }
        } else {
            println!("  ✗ Subdomains (not available)");
        }

        Ok(())
    }

    fn get_db_path(
        &self,
        ctx: &CliContext,
        domain: &str,
    ) -> Result<std::path::PathBuf, String> {
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
            "Database not found: {}\nRun reconnaissance first: rb recon domain whois {} --persist",
            candidate.display(),
            domain
        ))
    }
}
