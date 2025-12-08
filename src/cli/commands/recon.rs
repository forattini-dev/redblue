/// Recon/domain command - Information gathering and OSINT
use crate::cli::commands::{build_partition_attributes, print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::recon::harvester::Harvester;
use crate::modules::recon::subdomain::{
    load_wordlist_from_file, EnumerationSource, SubdomainEnumerator,
};
use crate::modules::recon::subdomain_bruteforce::BruteforceResult; // Added import
use crate::modules::recon::urlharvest::UrlHarvester;
use crate::modules::recon::vuln::{
    generate_cpe, NvdClient, KevClient, ExploitDbClient,
    VulnCollection, calculate_risk_score, Severity,
};
use crate::modules::recon::vuln::osv::{OsvClient, Ecosystem};
use crate::modules::recon::asn::AsnClient;
use crate::modules::recon::breach::BreachClient;
use crate::modules::recon::dorks::DorksSearcher;
use crate::modules::recon::dnsdumpster::DnsDumpsterClient;
use crate::modules::recon::massdns::{MassDnsScanner, MassDnsConfig, common_subdomains, load_wordlist};
use crate::modules::recon::secrets::{SecretsScanner, SecretSeverity};
use crate::modules::recon::social::SocialMapper;
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::protocols::rdap::RdapClient;
use crate::protocols::whois::WhoisClient;
use crate::storage::service::StorageService;
use crate::storage::SubdomainSource;
use std::net::IpAddr;
use std::collections::HashSet; // Added import


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
            Route {
                verb: "whois",
                summary: "Query WHOIS information for a domain",
                usage: "rb recon domain whois <domain>",
            },
            Route {
                verb: "rdap",
                summary: "Query RDAP (modern WHOIS) for domain or IP",
                usage: "rb recon domain rdap <domain|ip>",
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
            Route {
                verb: "asn",
                summary: "ASN lookup for IP address (iptoasn.com)",
                usage: "rb recon domain asn <IP>",
            },
            Route {
                verb: "breach",
                summary: "Check if password/email appears in data breaches (HIBP)",
                usage: "rb recon domain breach <password|email> [--type password|email]",
            },
            Route {
                verb: "secrets",
                summary: "Scan URL for exposed secrets and credentials",
                usage: "rb recon domain secrets <URL>",
            },
            Route {
                verb: "dorks",
                summary: "Google/DuckDuckGo dork search for leaks and intel",
                usage: "rb recon domain dorks <domain>",
            },
            Route {
                verb: "social",
                summary: "Map social media presence for a company/brand",
                usage: "rb recon domain social <domain>",
            },
            Route {
                verb: "vuln",
                summary: "Fingerprint target and find vulnerabilities for detected technologies",
                usage: "rb recon domain vuln <url> [--source nvd|osv|all] [--limit N]",
            },
            Route {
                verb: "dnsdumpster",
                summary: "Query DNSDumpster for DNS intelligence (MX, TXT, DNS hosts, subdomains)",
                usage: "rb recon domain dnsdumpster <domain>",
            },
            Route {
                verb: "massdns",
                summary: "High-performance DNS bruteforce subdomain enumeration",
                usage: "rb recon domain massdns <domain> [--wordlist <file>] [--threads N]",
            },
            Route {
                verb: "bruteforce",
                summary: "Active DNS subdomain bruteforce (Phase 1.3)",
                usage: "rb recon domain bruteforce <domain> --wordlist <file> [--resolvers <list>]",
            },
            // RESTful verbs - query stored data
            Route {
                verb: "list",
                summary: "List all subdomains for a domain from database",
                usage: "rb recon domain list <domain> [--db <file>]",
            },
            Route {
                verb: "get",
                summary: "Get specific subdomain info from database",
                usage: "rb recon domain get <subdomain> [--db <file>]",
            },
            Route {
                verb: "describe",
                summary: "Get detailed OSINT data from database",
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
            Flag::new("source", "Vulnerability source for vuln command (nvd, osv, all)")
                .with_short('s')
                .with_default("nvd"),
            Flag::new("limit", "Maximum vulnerabilities to show").with_default("20"),
            Flag::new("api-key", "NVD API key for higher rate limits"),
            Flag::new("hibp-key", "HIBP API key for email breach checks"),
            Flag::new("type", "Breach check type: password or email")
                .with_short('t')
                .with_default("password"),
            Flag::new(
                "db",
                "Database file path for RESTful queries (default: auto-detect)",
            )
            .with_short('d'),
            // MassDNS flags
            Flag::new("resolvers", "Comma-separated DNS resolvers for massdns")
                .with_default("8.8.8.8,1.1.1.1,9.9.9.9"),
            Flag::new("timeout-ms", "DNS query timeout in milliseconds for massdns")
                .with_default("2000"),
            Flag::new("delay", "Delay between queries in ms for rate limiting")
                .with_default("10"),
            Flag::new("filter-wildcards", "Enable wildcard detection and filtering (for subdomains command)"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("WHOIS lookup", "rb recon domain whois example.com"),
            ("RDAP domain lookup", "rb recon domain rdap example.com"),
            ("RDAP IP lookup", "rb recon domain rdap 8.8.8.8"),
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
            // ASN lookup
            (
                "ASN lookup for IP",
                "rb recon domain asn 8.8.8.8",
            ),
            (
                "ASN lookup for hostname",
                "rb recon domain asn google.com",
            ),
            // Breach checking
            (
                "Check password breach (HIBP)",
                "rb recon domain breach password123",
            ),
            (
                "Check email breach (requires API key)",
                "rb recon domain breach user@example.com --type email --hibp-key YOUR_KEY",
            ),
            // Secrets scanning
            (
                "Scan URL for exposed secrets",
                "rb recon domain secrets http://example.com/config.js",
            ),
            // Username OSINT - now at rb recon username
            (
                "Search username across platforms",
                "rb recon username search johndoe",
            ),
            // Google Dorks
            (
                "Google dorks search for domain",
                "rb recon domain dorks example.com",
            ),
            // Social media mapping
            (
                "Map social media presence",
                "rb recon domain social example.com",
            ),
            // Vulnerability scanning
            (
                "Fingerprint and find vulns",
                "rb recon domain vuln http://example.com",
            ),
            (
                "Vuln scan with OSV source",
                "rb recon domain vuln http://example.com --source osv",
            ),
            // DNSDumpster
            (
                "Query DNSDumpster for DNS intel",
                "rb recon domain dnsdumpster example.com",
            ),
            // MassDNS
            (
                "Mass DNS bruteforce with defaults",
                "rb recon domain massdns example.com",
            ),
            (
                "MassDNS with custom wordlist",
                "rb recon domain massdns example.com --wordlist subdomains.txt --threads 50",
            ),
            (
                "MassDNS with custom resolvers",
                "rb recon domain massdns example.com --resolvers 8.8.8.8,1.1.1.1",
            ),
            // RESTful examples
            (
                "List all saved subdomains",
                "rb recon domain list example.com",
            ),
            (
                "Get specific subdomain info",
                "rb recon domain get api.example.com",
            ),
            (
                "Describe all recon data",
                "rb recon domain describe example.com",
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
            "rdap" => self.rdap(ctx),
            "subdomains" => self.subdomains(ctx),
            "harvest" => self.harvest(ctx),
            "urls" => self.urls(ctx),
            "osint" => self.osint(ctx),
            "email" => self.email(ctx),
            "asn" => self.asn(ctx),
            "breach" => self.breach(ctx),
            "secrets" => self.secrets(ctx),
            "username" => {
                Output::warning("'rb recon domain username' has moved to 'rb recon username'");
                println!("\nUse: rb recon username search <username>");
                println!("     rb recon username search johndoe --category coding");
                Err("Command moved. Use 'rb recon username' instead.".to_string())
            }
            "dorks" => self.dorks(ctx),
            "social" => self.social(ctx),
            "vuln" => self.vuln(ctx),
            "dnsdumpster" => self.dnsdumpster(ctx),
            "massdns" => self.massdns(ctx),
            // RESTful verbs
            "list" => self.list_subdomains(ctx),
            "get" => self.get_subdomain(ctx),
            "describe" => self.describe_domain(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(
                        verb,
                        &[
                            "whois",
                            "rdap",
                            "subdomains",
                            "harvest",
                            "urls",
                            "osint",
                            "email",
                            "asn",
                            "breach",
                            "secrets",
                            "username",
                            "dorks",
                            "social",
                            "vuln",
                            "dnsdumpster",
                            "massdns",
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

        let registrar_attr = result.registrar.as_deref().unwrap_or("unknown");
        let attributes = build_partition_attributes(
            ctx,
            &domain_owned,
            [("operation", "whois"), ("registrar", registrar_attr)],
        );
        let mut pm = StorageService::global().persistence_for_target_with(
            &domain_owned,
            persist_flag,
            None,
            attributes,
        )?;

        // Save WHOIS data to database
        if pm.is_enabled() {
            let registrar = result
                .registrar
                .clone()
                .unwrap_or_else(|| "Unknown".to_string());
            let created = parse_whois_timestamp(result.creation_date.as_deref());
            let expires = parse_whois_timestamp(result.expiration_date.as_deref());
            let nameservers = result.name_servers.clone();

            if let Err(e) = pm.add_whois(domain, &registrar, created, expires, &nameservers) {
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

    /// RDAP lookup - modern WHOIS alternative (RFC 7480-7484)
    fn rdap(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb recon domain rdap <DOMAIN|IP>\nExample: rb recon domain rdap example.com",
        )?;

        let format = ctx.get_output_format();
        let mut client = RdapClient::new();

        // Detect if target is IP or domain
        let is_ip = target.parse::<std::net::IpAddr>().is_ok();

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start(&format!(
                "Querying RDAP for {} ({})",
                target,
                if is_ip { "IP" } else { "domain" }
            ));
        }

        if is_ip {
            // IP lookup
            let result = client.query_ip(target)?;

            if format == crate::cli::format::OutputFormat::Human {
                Output::spinner_done();
            }

            // JSON output
            if format == crate::cli::format::OutputFormat::Json {
                println!("{{");
                println!("  \"type\": \"ip\",");
                println!("  \"query\": \"{}\",", target);
                println!("  \"handle\": \"{}\",", result.handle);
                println!("  \"start_address\": \"{}\",", result.start_address);
                println!("  \"end_address\": \"{}\",", result.end_address);
                println!("  \"ip_version\": \"{}\",", result.ip_version);
                if let Some(ref name) = result.name {
                    println!("  \"name\": \"{}\",", name);
                }
                if let Some(ref country) = result.country {
                    println!("  \"country\": \"{}\",", country);
                }
                println!("  \"status\": [");
                for (i, status) in result.status.iter().enumerate() {
                    let comma = if i < result.status.len() - 1 { "," } else { "" };
                    println!("    \"{}\"{}", status, comma);
                }
                println!("  ],");
                println!("  \"events\": [");
                for (i, event) in result.events.iter().enumerate() {
                    let comma = if i < result.events.len() - 1 { "," } else { "" };
                    println!("    {{ \"action\": \"{}\", \"date\": \"{}\" }}{}", event.action, event.date, comma);
                }
                println!("  ]");
                println!("}}");
                return Ok(());
            }

            // YAML output
            if format == crate::cli::format::OutputFormat::Yaml {
                println!("type: ip");
                println!("query: {}", target);
                println!("handle: {}", result.handle);
                println!("start_address: {}", result.start_address);
                println!("end_address: {}", result.end_address);
                println!("ip_version: {}", result.ip_version);
                if let Some(ref name) = result.name {
                    println!("name: {}", name);
                }
                if let Some(ref country) = result.country {
                    println!("country: {}", country);
                }
                println!("status:");
                for status in &result.status {
                    println!("  - {}", status);
                }
                println!("events:");
                for event in &result.events {
                    println!("  - action: {}", event.action);
                    println!("    date: {}", event.date);
                }
                return Ok(());
            }

            // Human output
            Output::header(&format!("RDAP: {} (IP)", target));

            // Summary line
            let range_str = format!("{} - {}", result.start_address, result.end_address);
            let mut summary: Vec<(&str, &str)> = vec![];
            summary.push(("Handle", result.handle.as_str()));
            summary.push(("Range", &range_str));
            if let Some(ref name) = result.name {
                summary.push(("Name", name.as_str()));
            }
            if let Some(ref country) = result.country {
                summary.push(("Country", country.as_str()));
            }
            Output::summary_line(&summary);

            if !result.status.is_empty() {
                Output::subheader("Status");
                for status in &result.status {
                    println!("  {}", status);
                }
            }

            if !result.events.is_empty() {
                Output::subheader("Events");
                for event in &result.events {
                    println!("  {} - {}", event.action, event.date);
                }
            }

            if !result.entities.is_empty() {
                Output::subheader("Entities");
                for entity in &result.entities {
                    let name = entity.name.as_deref().or(entity.organization.as_deref()).unwrap_or("Unknown");
                    let roles = entity.roles.join(", ");
                    println!("  {} ({})", name, roles);
                }
            }

            if ctx.has_flag("raw") {
                println!();
                Output::subheader("Raw RDAP Response");
                println!("{}", result.raw_json);
            }
        } else {
            // Domain lookup
            Validator::validate_domain(target)?;
            let result = client.query_domain(target)?;

            if format == crate::cli::format::OutputFormat::Human {
                Output::spinner_done();
            }

            // JSON output
            if format == crate::cli::format::OutputFormat::Json {
                println!("{{");
                println!("  \"type\": \"domain\",");
                println!("  \"domain\": \"{}\",", result.domain);
                if let Some(ref registrar) = result.registrar {
                    println!("  \"registrar\": \"{}\",", registrar);
                }
                println!("  \"status\": [");
                for (i, status) in result.status.iter().enumerate() {
                    let comma = if i < result.status.len() - 1 { "," } else { "" };
                    println!("    \"{}\"{}", status, comma);
                }
                println!("  ],");
                println!("  \"nameservers\": [");
                for (i, ns) in result.nameservers.iter().enumerate() {
                    let comma = if i < result.nameservers.len() - 1 { "," } else { "" };
                    println!("    \"{}\"{}", ns, comma);
                }
                println!("  ],");
                println!("  \"events\": [");
                for (i, event) in result.events.iter().enumerate() {
                    let comma = if i < result.events.len() - 1 { "," } else { "" };
                    println!("    {{ \"action\": \"{}\", \"date\": \"{}\" }}{}", event.action, event.date, comma);
                }
                println!("  ]");
                println!("}}");
                return Ok(());
            }

            // YAML output
            if format == crate::cli::format::OutputFormat::Yaml {
                println!("type: domain");
                println!("domain: {}", result.domain);
                if let Some(ref registrar) = result.registrar {
                    println!("registrar: {}", registrar);
                }
                println!("status:");
                for status in &result.status {
                    println!("  - {}", status);
                }
                println!("nameservers:");
                for ns in &result.nameservers {
                    println!("  - {}", ns);
                }
                println!("events:");
                for event in &result.events {
                    println!("  - action: {}", event.action);
                    println!("    date: {}", event.date);
                }
                return Ok(());
            }

            // Human output
            Output::header(&format!("RDAP: {}", result.domain));

            // Summary
            if let Some(ref registrar) = result.registrar {
                Output::item("Registrar", registrar);
            }

            if !result.status.is_empty() {
                Output::subheader(&format!("Status ({})", result.status.len()));
                for (i, status) in result.status.iter().enumerate() {
                    if i < 5 {
                        println!("  {}", status);
                    } else if i == 5 {
                        println!("  ... and {} more", result.status.len() - 5);
                        break;
                    }
                }
            }

            if !result.nameservers.is_empty() {
                Output::subheader(&format!("Nameservers ({})", result.nameservers.len()));
                for ns in &result.nameservers {
                    println!("  {}", ns);
                }
            }

            if !result.events.is_empty() {
                Output::subheader("Events");
                for event in &result.events {
                    let action_display = match event.action.as_str() {
                        "registration" => "Registered",
                        "expiration" => "Expires",
                        "last changed" => "Updated",
                        "last update of RDAP database" => "RDAP Updated",
                        other => other,
                    };
                    // Format date nicely
                    let date_display = if event.date.len() > 10 {
                        &event.date[..10]
                    } else {
                        &event.date
                    };
                    println!("  {} : {}", action_display, date_display);
                }
            }

            if let Some(ref registrant) = result.registrant {
                Output::subheader("Registrant");
                if let Some(ref name) = registrant.name {
                    println!("  Name: {}", name);
                }
                if let Some(ref org) = registrant.organization {
                    println!("  Organization: {}", org);
                }
            }

            if ctx.has_flag("raw") {
                println!();
                Output::subheader("Raw RDAP Response");
                println!("{}", result.raw_json);
            }
        }

        println!();
        Output::success("RDAP lookup completed");
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
            let wordlist = load_wordlist_from_file(&wordlist_path)?;
            enumerator = enumerator.with_wordlist(wordlist);
        }
        
        // Apply wildcard filtering flag
        let filter_wildcards = ctx.has_flag("filter-wildcards");
        enumerator = enumerator.with_wildcard_filtering(filter_wildcards);

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
                println!("      \"cname_chain\": [");
                for (j, cname) in result.cname_chain.iter().enumerate() {
                    let cname_comma = if j < result.cname_chain.len() - 1 { "," } else { "" };
                    println!("        \"{}\"{}", cname, cname_comma);
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
                if !result.cname_chain.is_empty() {
                    println!("    cname_chain:");
                    for cname in &result.cname_chain {
                        println!("      - {}", cname);
                    }
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

            // Show CNAME chain if present
            if !result.cname_chain.is_empty() {
                println!(
                    "    └─ CNAME: {}",
                    result.cname_chain.join(" → ")
                );
            }
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

        let mode_value = if passive_only { "passive" } else { "hybrid" };
        let attributes = build_partition_attributes(
            ctx,
            domain,
            [("operation", "subdomains"), ("mode", mode_value)],
        );
        let mut pm = StorageService::global().persistence_for_target_with(
            domain,
            persist_flag,
            None,
            attributes,
        )?;
        if pm.is_enabled() {
            for result in &results {
                let source = map_subdomain_source(&result.source);
                let ips: Vec<IpAddr> = result
                    .ips
                    .iter()
                    .filter_map(|ip| ip.parse::<IpAddr>().ok())
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

    /// ASN lookup for IP address or hostname
    fn asn(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing IP address or hostname.\nUsage: rb recon domain asn <IP|HOSTNAME>\nExample: rb recon domain asn 8.8.8.8",
        )?;

        let format = ctx.get_output_format();
        let client = AsnClient::new();

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start(&format!("Looking up ASN for {}", target));
        }

        // Check if it's an IP or hostname
        let is_ip = target.parse::<std::net::IpAddr>().is_ok();

        let results = if is_ip {
            vec![client.lookup_ip(target)?]
        } else {
            client.lookup_host(target)?
        };

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"query\": \"{}\",", target);
            println!("  \"results\": [");
            for (i, info) in results.iter().enumerate() {
                let comma = if i < results.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"ip\": \"{}\",", info.ip);
                println!("      \"announced\": {},", info.announced);
                if let Some(asn) = info.asn {
                    println!("      \"asn\": {},", asn);
                }
                if let Some(ref org) = info.organization {
                    println!("      \"organization\": \"{}\",", org);
                }
                if let Some(ref country) = info.country {
                    println!("      \"country\": \"{}\",", country);
                }
                if let Some(ref cidr) = info.cidr {
                    println!("      \"cidr\": \"{}\"", cidr);
                }
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // Human output
        Output::header(&format!("ASN Lookup: {}", target));
        println!();

        for info in &results {
            if !info.announced {
                Output::warning(&format!("IP {} is not announced (not routed)", info.ip));
                continue;
            }

            let mut summary: Vec<(&str, String)> = vec![];
            summary.push(("IP", info.ip.clone()));

            if let Some(asn) = info.asn {
                summary.push(("ASN", format!("AS{}", asn)));
            }
            if let Some(ref org) = info.organization {
                summary.push(("Organization", org.clone()));
            }
            if let Some(ref country) = info.country {
                summary.push(("Country", country.clone()));
            }
            if let Some(ref cidr) = info.cidr {
                summary.push(("Network", cidr.clone()));
            }

            // Print as table
            println!("  {:<15} {}", "IP:", info.ip);
            if let Some(asn) = info.asn {
                println!("  {:<15} AS{}", "ASN:", asn);
            }
            if let Some(ref org) = info.organization {
                println!("  {:<15} {}", "Organization:", org);
            }
            if let Some(ref country) = info.country {
                println!("  {:<15} {}", "Country:", country);
            }
            if let Some(ref cidr) = info.cidr {
                println!("  {:<15} {}", "Network:", cidr);
            }
            println!();
        }

        Output::success("ASN lookup completed");
        Ok(())
    }

    /// Check if password or email appears in data breaches (HIBP)
    fn breach(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing password or email.\nUsage: rb recon domain breach <PASSWORD|EMAIL> [--type password|email]",
        )?;

        let check_type = ctx.get_flag("type").unwrap_or_else(|| "password".to_string());
        let format = ctx.get_output_format();

        let mut client = BreachClient::new();

        // Add API key if provided (required for email checks)
        if let Some(api_key) = ctx.get_flag("hibp-key") {
            client = client.with_api_key(&api_key);
        }

        match check_type.as_str() {
            "password" => {
                if format == crate::cli::format::OutputFormat::Human {
                    Output::spinner_start("Checking password against HIBP breach database");
                }

                let result = client.check_password(target)?;

                if format == crate::cli::format::OutputFormat::Human {
                    Output::spinner_done();
                }

                // JSON output
                if format == crate::cli::format::OutputFormat::Json {
                    println!("{{");
                    println!("  \"type\": \"password\",");
                    println!("  \"pwned\": {},", result.pwned);
                    println!("  \"count\": {}", result.count);
                    println!("}}");
                    return Ok(());
                }

                // Human output
                Output::header("Password Breach Check (HIBP)");
                println!();

                if result.pwned {
                    Output::error(&format!(
                        "Password found in {} breaches!",
                        result.count
                    ));
                    println!();
                    Output::warning("This password has been exposed in data breaches.");
                    Output::warning("Do NOT use this password anywhere!");
                } else {
                    Output::success("Password NOT found in any known breaches");
                    println!();
                    Output::info("This password has not been seen in HIBP's database.");
                    Output::info("Note: This doesn't guarantee the password is secure.");
                }
            }
            "email" => {
                if ctx.get_flag("hibp-key").is_none() {
                    return Err(
                        "Email breach checks require an HIBP API key.\n\
                        Get one at: https://haveibeenpwned.com/API/Key ($3.50/month)\n\
                        Usage: rb recon domain breach user@example.com --type email --hibp-key YOUR_KEY".to_string()
                    );
                }

                if !target.contains('@') {
                    return Err(format!("Invalid email address: {}", target));
                }

                if format == crate::cli::format::OutputFormat::Human {
                    Output::spinner_start(&format!("Checking email {} against HIBP", target));
                }

                let result = client.check_email(target)?;

                if format == crate::cli::format::OutputFormat::Human {
                    Output::spinner_done();
                }

                // JSON output
                if format == crate::cli::format::OutputFormat::Json {
                    println!("{{");
                    println!("  \"type\": \"email\",");
                    println!("  \"email\": \"{}\",", result.email);
                    println!("  \"pwned\": {},", result.pwned);
                    println!("  \"breach_count\": {},", result.breach_count);
                    println!("  \"breaches\": [");
                    for (i, breach) in result.breaches.iter().enumerate() {
                        let comma = if i < result.breaches.len() - 1 { "," } else { "" };
                        println!("    {{");
                        println!("      \"name\": \"{}\",", breach.name);
                        println!("      \"domain\": \"{}\",", breach.domain);
                        println!("      \"breach_date\": \"{}\",", breach.breach_date);
                        println!("      \"pwn_count\": {}", breach.pwn_count);
                        println!("    }}{}", comma);
                    }
                    println!("  ]");
                    println!("}}");
                    return Ok(());
                }

                // Human output
                Output::header(&format!("Email Breach Check: {}", target));
                println!();

                if result.pwned {
                    Output::error(&format!(
                        "Email found in {} breaches!",
                        result.breach_count
                    ));
                    println!();

                    Output::subheader("Breaches");
                    for breach in &result.breaches {
                        let date = &breach.breach_date;
                        let count = if breach.pwn_count > 1_000_000 {
                            format!("{}M accounts", breach.pwn_count / 1_000_000)
                        } else if breach.pwn_count > 1_000 {
                            format!("{}K accounts", breach.pwn_count / 1_000)
                        } else {
                            format!("{} accounts", breach.pwn_count)
                        };

                        println!(
                            "  \x1b[31m●\x1b[0m {} ({}) - {} - {}",
                            breach.name, breach.domain, date, count
                        );

                        // Show compromised data types
                        if !breach.data_classes.is_empty() {
                            let types = breach.data_classes.join(", ");
                            println!("    Exposed: {}", types);
                        }
                    }
                } else {
                    Output::success("Email NOT found in any known breaches");
                }
            }
            _ => {
                return Err(format!(
                    "Invalid breach check type: {}. Use 'password' or 'email'",
                    check_type
                ));
            }
        }

        println!();
        Output::success("Breach check completed");
        Ok(())
    }

    /// Scan URL for exposed secrets and credentials
    fn secrets(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb recon domain secrets <URL>\nExample: rb recon domain secrets http://example.com/config.js",
        )?;

        // Validate URL format
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!(
                "Invalid URL: {}. Must start with http:// or https://",
                url
            ));
        }

        let format = ctx.get_output_format();
        let scanner = SecretsScanner::new();

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start(&format!("Scanning {} for secrets", url));
        }

        let findings = scanner.scan_url(url)?;

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"url\": \"{}\",", url);
            println!("  \"findings_count\": {},", findings.len());
            println!("  \"findings\": [");
            for (i, finding) in findings.iter().enumerate() {
                let comma = if i < findings.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"type\": \"{}\",", finding.secret_type);
                println!("      \"severity\": \"{}\",", finding.severity);
                println!("      \"matched\": \"{}\",", finding.matched.replace('"', "\\\""));
                if let Some(line) = finding.line {
                    println!("      \"line\": {},", line);
                }
                println!("      \"pattern\": \"{}\"", finding.pattern_name);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // Human output
        Output::header(&format!("Secrets Scan: {}", url));
        println!();

        if findings.is_empty() {
            Output::success("No secrets detected in target URL");
            return Ok(());
        }

        Output::warning(&format!("Found {} potential secrets!", findings.len()));
        println!();

        // Group by severity
        let critical: Vec<_> = findings.iter().filter(|f| matches!(f.severity, SecretSeverity::Critical)).collect();
        let high: Vec<_> = findings.iter().filter(|f| matches!(f.severity, SecretSeverity::High)).collect();
        let medium: Vec<_> = findings.iter().filter(|f| matches!(f.severity, SecretSeverity::Medium)).collect();
        let low: Vec<_> = findings.iter().filter(|f| matches!(f.severity, SecretSeverity::Low)).collect();

        // Print by severity
        if !critical.is_empty() {
            Output::subheader(&format!("Critical ({})", critical.len()));
            for finding in &critical {
                println!(
                    "  \x1b[91m●\x1b[0m {} (line {})",
                    finding.secret_type,
                    finding.line.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string())
                );
                println!("    Matched: \x1b[90m{}\x1b[0m", finding.matched);
            }
            println!();
        }

        if !high.is_empty() {
            Output::subheader(&format!("High ({})", high.len()));
            for finding in &high {
                println!(
                    "  \x1b[31m●\x1b[0m {} (line {})",
                    finding.secret_type,
                    finding.line.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string())
                );
                println!("    Matched: \x1b[90m{}\x1b[0m", finding.matched);
            }
            println!();
        }

        if !medium.is_empty() {
            Output::subheader(&format!("Medium ({})", medium.len()));
            for finding in &medium {
                println!(
                    "  \x1b[33m●\x1b[0m {} (line {})",
                    finding.secret_type,
                    finding.line.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string())
                );
                println!("    Matched: \x1b[90m{}\x1b[0m", finding.matched);
            }
            println!();
        }

        if !low.is_empty() {
            Output::subheader(&format!("Low ({})", low.len()));
            for finding in &low[..low.len().min(5)] {
                println!(
                    "  \x1b[36m●\x1b[0m {} (line {})",
                    finding.secret_type,
                    finding.line.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string())
                );
            }
            if low.len() > 5 {
                println!("  ... and {} more", low.len() - 5);
            }
            println!();
        }

        // Summary
        Output::subheader("Summary");
        println!(
            "  Critical: {} | High: {} | Medium: {} | Low: {}",
            critical.len(),
            high.len(),
            medium.len(),
            low.len()
        );

        println!();
        Output::success("Secrets scan completed");
        Ok(())
    }

    /// Google Dorks search for domain intelligence
    fn dorks(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain dorks <domain>\nExample: rb recon domain dorks example.com",
        )?;

        Output::header(&format!("Google Dorks Search: {}", domain));

        Output::spinner_start(&format!("Searching for {} intelligence", domain));

        let searcher = DorksSearcher::new()
            .with_delay(2000)
            .with_max_results(10);

        let result = searcher.search(domain);

        Output::spinner_done();

        // Check for JSON output
        if ctx.get_flag("output").map(|o| o == "json").unwrap_or(false) {
            println!("{{");
            println!("  \"domain\": \"{}\",", result.domain);
            println!("  \"company_name\": \"{}\",", result.company_name);
            println!("  \"summary\": {{");
            println!("    \"total_results\": {},", result.summary.total_results);
            println!("    \"github\": {},", result.summary.github_count);
            println!("    \"pastebin\": {},", result.summary.pastebin_count);
            println!("    \"linkedin\": {},", result.summary.linkedin_count);
            println!("    \"documents\": {},", result.summary.documents_count);
            println!("    \"subdomains\": {},", result.summary.subdomains_count);
            println!("    \"login_pages\": {},", result.summary.login_pages_count);
            println!("    \"configs\": {},", result.summary.configs_count);
            println!("    \"errors\": {}", result.summary.errors_count);
            println!("  }}");
            println!("}}");
            return Ok(());
        }

        // Display results
        println!();
        Output::item("Domain", &result.domain);
        Output::item("Company", &result.company_name);
        Output::item("Total Results", &format!("{}", result.summary.total_results));
        println!();

        // GitHub
        if result.summary.github_count > 0 {
            Output::subheader(&format!("GitHub Leaks ({})", result.summary.github_count));
            for dork_result in &result.categories.github {
                for url in &dork_result.urls {
                    println!("  \x1b[31m●\x1b[0m {}", url);
                }
            }
            println!();
        }

        // Pastebin
        if result.summary.pastebin_count > 0 {
            Output::subheader(&format!("Pastebin Leaks ({})", result.summary.pastebin_count));
            for dork_result in &result.categories.pastebin {
                for url in &dork_result.urls {
                    println!("  \x1b[31m●\x1b[0m {}", url);
                }
            }
            println!();
        }

        // LinkedIn
        if result.summary.linkedin_count > 0 {
            Output::subheader(&format!("LinkedIn Profiles ({})", result.summary.linkedin_count));
            for dork_result in &result.categories.linkedin {
                for url in &dork_result.urls {
                    println!("  \x1b[34m●\x1b[0m {}", url);
                }
            }
            println!();
        }

        // Documents
        if result.summary.documents_count > 0 {
            Output::subheader(&format!("Exposed Documents ({})", result.summary.documents_count));
            for dork_result in &result.categories.documents {
                for url in &dork_result.urls {
                    println!("  \x1b[33m●\x1b[0m {}", url);
                }
            }
            println!();
        }

        // Subdomains
        if result.summary.subdomains_count > 0 {
            Output::subheader(&format!("Subdomains Found ({})", result.summary.subdomains_count));
            for subdomain in &result.categories.subdomains {
                println!("  \x1b[36m●\x1b[0m {}", subdomain);
            }
            println!();
        }

        // Login Pages
        if result.summary.login_pages_count > 0 {
            Output::subheader(&format!("Login/Admin Pages ({})", result.summary.login_pages_count));
            for dork_result in &result.categories.login_pages {
                for url in &dork_result.urls {
                    println!("  \x1b[35m●\x1b[0m {}", url);
                }
            }
            println!();
        }

        // Config Files
        if result.summary.configs_count > 0 {
            Output::subheader(&format!("Config Files ({})", result.summary.configs_count));
            for dork_result in &result.categories.configs {
                for url in &dork_result.urls {
                    println!("  \x1b[31m●\x1b[0m {}", url);
                }
            }
            println!();
        }

        // Errors
        if result.summary.errors_count > 0 {
            Output::subheader(&format!("Error Pages ({})", result.summary.errors_count));
            for dork_result in &result.categories.errors {
                for url in dork_result.urls.iter().take(5) {
                    println!("  \x1b[33m●\x1b[0m {}", url);
                }
            }
            println!();
        }

        if result.summary.total_results == 0 {
            Output::info("No results found (this is good - less exposure!)");
        } else {
            Output::warning(&format!(
                "Found {} exposed resources - review for sensitive information",
                result.summary.total_results
            ));
        }

        Ok(())
    }

    /// Map social media presence for a company/brand
    fn social(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain social <domain>\nExample: rb recon domain social example.com",
        )?;

        Output::header(&format!("Social Media Mapping: {}", domain));

        Output::spinner_start(&format!("Mapping social presence for {}", domain));

        let mapper = SocialMapper::new();
        let result = mapper.map(domain);

        Output::spinner_done();

        // Check for JSON output
        if ctx.get_flag("output").map(|o| o == "json").unwrap_or(false) {
            println!("{{");
            println!("  \"domain\": \"{}\",", result.domain);
            println!("  \"company_name\": \"{}\",", result.company_name);
            println!("  \"found_count\": {},", result.found_count);
            println!("  \"total_checked\": {},", result.total_checked);
            println!("  \"profiles\": {{");
            let profiles: Vec<_> = result.profiles.iter().collect();
            for (i, (platform, profile)) in profiles.iter().enumerate() {
                println!("    \"{}\": {{", platform);
                println!("      \"found\": {},", profile.found);
                println!("      \"url\": \"{}\"", profile.url);
                if i < profiles.len() - 1 {
                    println!("    }},");
                } else {
                    println!("    }}");
                }
            }
            println!("  }}");
            println!("}}");
            return Ok(());
        }

        // Display results
        println!();
        Output::item("Domain", &result.domain);
        Output::item("Company", &result.company_name);
        Output::item(
            "Profiles Found",
            &format!("{}/{}", result.found_count, result.total_checked),
        );
        println!();

        // Found profiles
        Output::subheader("Found Profiles");
        let mut found_any = false;
        for (platform, profile) in &result.profiles {
            if profile.found {
                found_any = true;
                let username = profile
                    .username
                    .as_ref()
                    .map(|u| format!(" (@{})", u))
                    .unwrap_or_default();
                println!(
                    "  \x1b[32m✓\x1b[0m {}{} - \x1b[36m{}\x1b[0m",
                    Self::capitalize(platform),
                    username,
                    profile.url
                );
            }
        }
        if !found_any {
            println!("  \x1b[90mNo profiles found\x1b[0m");
        }
        println!();

        // Not found
        Output::subheader("Not Found");
        for (platform, profile) in &result.profiles {
            if !profile.found {
                println!("  \x1b[90m✗\x1b[0m {} - {}", Self::capitalize(platform), profile.url);
            }
        }
        println!();

        if result.found_count > 0 {
            Output::success(&format!(
                "Found {} social media profiles",
                result.found_count
            ));
        } else {
            Output::info("No social media profiles found for this company name");
        }

        Ok(())
    }

    fn capitalize(s: &str) -> String {
        let mut chars = s.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }

    /// Fingerprint target and find vulnerabilities for detected technologies
    fn vuln(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb recon domain vuln <URL>\nExample: rb recon domain vuln http://example.com",
        )?;

        // Validate URL format
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!(
                "Invalid URL: {}. Must start with http:// or https://",
                url
            ));
        }

        let source = ctx.get_flag("source").unwrap_or_else(|| "nvd".to_string());
        let limit: usize = ctx
            .get_flag("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);
        let api_key = ctx.get_flag("api-key");

        Output::header("Vulnerability Scanner");
        Output::item("Target", url);
        Output::item("Source", &source);
        println!();

        // Step 1: Fingerprint the target
        Output::spinner_start("Fingerprinting target technologies");
        let fingerprinter = WebFingerprinter::new();
        let fingerprint = fingerprinter.fingerprint(url)?;
        Output::spinner_done();

        if fingerprint.technologies.is_empty() {
            Output::warning("No technologies detected on target");
            return Ok(());
        }

        // Display detected technologies
        println!();
        Output::subheader(&format!(
            "Detected Technologies ({})",
            fingerprint.technologies.len()
        ));
        println!();

        for tech in &fingerprint.technologies {
            let version_str = tech
                .version
                .as_ref()
                .map(|v| format!(" v{}", v))
                .unwrap_or_default();
            let confidence_color = match tech.confidence {
                crate::modules::web::fingerprinter::Confidence::High => "\x1b[32m",   // green
                crate::modules::web::fingerprinter::Confidence::Medium => "\x1b[33m", // yellow
                crate::modules::web::fingerprinter::Confidence::Low => "\x1b[90m",    // gray
            };
            println!(
                "  {}[{}]\x1b[0m {}{} ({:?})",
                confidence_color, tech.confidence, tech.name, version_str, tech.category
            );
        }

        // Step 2: Map technologies to CPEs and query vulnerability databases
        println!();
        Output::spinner_start("Searching vulnerability databases");

        let mut collection = VulnCollection::new();
        let mut nvd_client = NvdClient::new();
        let mut osv_client = OsvClient::new();
        let mut kev_client = KevClient::new();
        let mut exploit_client = ExploitDbClient::new();

        if let Some(key) = api_key {
            nvd_client = nvd_client.with_api_key(&key);
        }

        let mut techs_with_cpe = 0;

        for tech in &fingerprint.technologies {
            // Generate CPE for this technology
            if let Some(cpe) = generate_cpe(&tech.name, tech.version.as_deref()) {
                techs_with_cpe += 1;

                // Query based on source preference
                match source.as_str() {
                    "nvd" => {
                        if let Ok(vulns) = nvd_client.query_by_cpe(&cpe) {
                            for vuln in vulns {
                                collection.add(vuln);
                            }
                        }
                    }
                    "osv" => {
                        // Map tech category to OSV ecosystem
                        let ecosystem = map_tech_to_ecosystem(&tech.name);
                        if let Ok(vulns) = osv_client.query_package(
                            &tech.name.to_lowercase(),
                            tech.version.as_deref(),
                            ecosystem,
                        ) {
                            for vuln in vulns {
                                collection.add(vuln);
                            }
                        }
                    }
                    "all" | _ => {
                        // Query both NVD and OSV
                        if let Ok(vulns) = nvd_client.query_by_cpe(&cpe) {
                            for vuln in vulns {
                                collection.add(vuln);
                            }
                        }

                        let ecosystem = map_tech_to_ecosystem(&tech.name);
                        if let Ok(vulns) = osv_client.query_package(
                            &tech.name.to_lowercase(),
                            tech.version.as_deref(),
                            ecosystem,
                        ) {
                            for vuln in vulns {
                                collection.add(vuln);
                            }
                        }
                    }
                }
            }
        }

        Output::spinner_done();

        // Step 3: Enrich with KEV and Exploit-DB data
        Output::spinner_start("Enriching with KEV and exploit data");

        let mut vulns = collection.into_sorted();

        for vuln in &mut vulns {
            // Check KEV
            let _ = kev_client.enrich_vulnerability(vuln);

            // Check Exploit-DB
            let _ = exploit_client.enrich_vulnerability(vuln);

            // Recalculate risk score after enrichment
            vuln.risk_score = Some(calculate_risk_score(vuln));
        }

        // Re-sort by risk score after enrichment
        vulns.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

        Output::spinner_done();

        // Step 4: Display results
        println!();
        if vulns.is_empty() {
            Output::success(&format!(
                "No known vulnerabilities found for {} technologies ({} with CPE mapping)",
                fingerprint.technologies.len(),
                techs_with_cpe
            ));
            return Ok(());
        }

        Output::subheader(&format!(
            "Vulnerabilities Found ({} total, showing top {})",
            vulns.len(),
            limit.min(vulns.len())
        ));
        println!();

        // Print table header
        println!(
            "  {:<5} {:<8} {:<18} {}",
            "RISK", "SEV", "CVE", "DESCRIPTION"
        );
        println!("  {}", "─".repeat(80));

        for vuln in vulns.iter().take(limit) {
            let severity_color = match vuln.severity {
                Severity::Critical => "\x1b[91m", // bright red
                Severity::High => "\x1b[31m",     // red
                Severity::Medium => "\x1b[33m",   // yellow
                Severity::Low => "\x1b[36m",      // cyan
                Severity::None => "\x1b[90m",     // gray
            };

            let severity_str = format!("{:?}", vuln.severity).to_uppercase();

            // Truncate description
            let desc = if vuln.description.len() > 50 {
                format!("{}...", &vuln.description[..47])
            } else {
                vuln.description.clone()
            };

            // Indicators
            let mut indicators = String::new();
            if vuln.cisa_kev {
                indicators.push_str(" \x1b[91m[KEV]\x1b[0m");
            }
            if !vuln.exploits.is_empty() {
                indicators.push_str(" \x1b[95m[EXP]\x1b[0m");
            }

            println!(
                "  [{:>3}] {}{}",
                vuln.risk_score.unwrap_or(0),
                format!(
                    "{}{:<8}\x1b[0m {:<18} {}",
                    severity_color, severity_str, vuln.id, desc
                ),
                indicators
            );
        }

        // Summary
        println!();
        let critical_count = vulns
            .iter()
            .filter(|v| matches!(v.severity, Severity::Critical))
            .count();
        let high_count = vulns
            .iter()
            .filter(|v| matches!(v.severity, Severity::High))
            .count();
        let kev_count = vulns.iter().filter(|v| v.cisa_kev).count();
        let exploit_count = vulns.iter().filter(|v| !v.exploits.is_empty()).count();

        Output::subheader("Summary");
        println!(
            "  Technologies: {} detected, {} with CPE mapping",
            fingerprint.technologies.len(),
            techs_with_cpe
        );
        println!(
            "  Vulnerabilities: {} total ({} critical, {} high)",
            vulns.len(),
            critical_count,
            high_count
        );
        if kev_count > 0 {
            println!(
                "  \x1b[91m⚠ {} in CISA KEV (actively exploited)\x1b[0m",
                kev_count
            );
        }
        if exploit_count > 0 {
            println!(
                "  \x1b[95m⚡ {} with public exploits\x1b[0m",
                exploit_count
            );
        }

        println!();
        Output::success("Vulnerability scan completed");

        Ok(())
    }

    /// Query DNSDumpster for DNS intelligence
    fn dnsdumpster(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain dnsdumpster <domain>\nExample: rb recon domain dnsdumpster example.com",
        )?;

        Validator::validate_domain(domain)?;

        let format = ctx.get_output_format();
        let client = DnsDumpsterClient::new();

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start(&format!("Querying DNSDumpster for {}", domain));
        }

        let result = client.query(domain)?;

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // Get unique subdomains for display
        let unique_subdomains = result.unique_subdomains();

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"domain\": \"{}\",", domain);
            println!("  \"dns_records\": {{");
            println!("    \"count\": {},", result.dns_records.len());
            println!("    \"records\": [");
            for (i, record) in result.dns_records.iter().enumerate() {
                let comma = if i < result.dns_records.len() - 1 { "," } else { "" };
                println!("      {{");
                println!("        \"host\": \"{}\",", record.host);
                println!("        \"type\": \"{}\",", record.record_type);
                println!("        \"value\": \"{}\",", record.value);
                if let Some(ref ip) = record.ip {
                    println!("        \"ip\": \"{}\",", ip);
                }
                if let Some(ref country) = record.country {
                    println!("        \"country\": \"{}\"", country);
                }
                println!("      }}{}", comma);
            }
            println!("    ]");
            println!("  }},");
            println!("  \"mx_records\": {{");
            println!("    \"count\": {},", result.mx_records.len());
            println!("    \"records\": [");
            for (i, record) in result.mx_records.iter().enumerate() {
                let comma = if i < result.mx_records.len() - 1 { "," } else { "" };
                println!("      {{");
                println!("        \"host\": \"{}\",", record.host);
                println!("        \"value\": \"{}\",", record.value);
                if let Some(ref ip) = record.ip {
                    println!("        \"ip\": \"{}\"", ip);
                }
                println!("      }}{}", comma);
            }
            println!("    ]");
            println!("  }},");
            println!("  \"txt_records\": [");
            for (i, txt) in result.txt_records.iter().enumerate() {
                let comma = if i < result.txt_records.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", txt.replace('"', "\\\""), comma);
            }
            println!("  ],");
            println!("  \"subdomains\": {{");
            println!("    \"count\": {},", unique_subdomains.len());
            println!("    \"list\": [");
            for (i, sub) in unique_subdomains.iter().enumerate() {
                let comma = if i < unique_subdomains.len() - 1 { "," } else { "" };
                println!("      \"{}\"{}", sub, comma);
            }
            println!("    ]");
            println!("  }}");
            println!("}}");
            return Ok(());
        }

        // Human output
        Output::header(&format!("DNSDumpster: {}", domain));
        println!();

        // DNS Hosts
        if !result.dns_records.is_empty() {
            Output::subheader(&format!("DNS Records ({})", result.dns_records.len()));
            println!();
            println!("  {:<35} {:<8} {:<30} {}", "HOST", "TYPE", "VALUE", "COUNTRY");
            println!("  {}", "─".repeat(85));
            for record in &result.dns_records {
                let country = record.country.as_deref().unwrap_or("-");
                let value_display = if record.value.len() > 28 {
                    format!("{}...", &record.value[..25])
                } else {
                    record.value.clone()
                };
                println!(
                    "  {:<35} {:<8} {:<30} {}",
                    record.host, record.record_type, value_display, country
                );
            }
            println!();
        }

        // MX Records
        if !result.mx_records.is_empty() {
            Output::subheader(&format!("MX Records ({})", result.mx_records.len()));
            println!();
            for record in &result.mx_records {
                let ip_str = record.ip.as_deref().unwrap_or("N/A");
                println!("  \x1b[36m✉\x1b[0m  {} → {} ({})", record.host, record.value, ip_str);
            }
            println!();
        }

        // TXT Records
        if !result.txt_records.is_empty() {
            Output::subheader(&format!("TXT Records ({})", result.txt_records.len()));
            println!();
            for txt in &result.txt_records {
                // Truncate long TXT records
                let display = if txt.len() > 80 {
                    format!("{}...", &txt[..77])
                } else {
                    txt.clone()
                };
                println!("  \x1b[33m📝\x1b[0m {}", display);
            }
            println!();
        }

        // Subdomains
        if !unique_subdomains.is_empty() {
            Output::subheader(&format!("Discovered Subdomains ({})", unique_subdomains.len()));
            println!();
            for subdomain in &unique_subdomains {
                println!("  \x1b[32m●\x1b[0m  {}", subdomain);
            }
            println!();
        }

        // Summary
        Output::success(&format!(
            "Found {} DNS records, {} MX records, {} TXT records, {} unique subdomains",
            result.dns_records.len(),
            result.mx_records.len(),
            result.txt_records.len(),
            unique_subdomains.len()
        ));

        Ok(())
    }

    /// High-performance Mass DNS bruteforce
    fn massdns(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain massdns <domain> [--wordlist <file>] [--threads N]\nExample: rb recon domain massdns example.com",
        )?;

        Validator::validate_domain(domain)?;

        let format = ctx.get_output_format();

        // Build scanner config
        let mut config = MassDnsConfig::default();

        if let Some(threads_str) = ctx.get_flag("threads") {
            config.threads = threads_str
                .parse()
                .map_err(|_| format!("Invalid threads value: {}", threads_str))?;
        }

        if let Some(resolvers_str) = ctx.get_flag("resolvers") {
            config.resolvers = resolvers_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        if let Some(timeout_str) = ctx.get_flag("timeout-ms") {
            let timeout_ms: u64 = timeout_str
                .parse()
                .map_err(|_| format!("Invalid timeout value: {}", timeout_str))?;
            config.timeout = std::time::Duration::from_millis(timeout_ms);
        }

        if let Some(delay_str) = ctx.get_flag("delay") {
            let delay_ms: u64 = delay_str
                .parse()
                .map_err(|_| format!("Invalid delay value: {}", delay_str))?;
            config.delay = std::time::Duration::from_millis(delay_ms);
        }

        config.filter_wildcards = ctx.has_flag("filter-wildcards");

        // Load wordlist
        let wordlist = if let Some(wordlist_path) = ctx.get_flag("wordlist") {
            load_wordlist(&wordlist_path)?
        } else {
            common_subdomains()
        };

        let wordlist_count = wordlist.len();

        let scanner = MassDnsScanner::with_config(config.clone());

        if format == crate::cli::format::OutputFormat::Human {
            Output::header("Mass DNS Bruteforce");
            Output::item("Target", domain);
            Output::item("Wordlist Size", &wordlist_count.to_string());
            Output::item("Threads", &config.threads.to_string());
            Output::item("Resolvers", &config.resolvers.join(", "));
            println!();
            Output::spinner_start(&format!("Bruteforcing {} subdomains", wordlist_count));
        }

        let result = scanner.bruteforce(domain, &wordlist)?;

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"domain\": \"{}\",", result.domain);
            println!("  \"total_attempts\": {},", result.total_attempts);
            println!("  \"wildcard_detected\": {},", result.wildcard_detected);
            println!("  \"duration_ms\": {},", result.duration_ms);
            println!("  \"resolved_count\": {},", result.resolved.len());
            println!("  \"resolved\": [");
            for (i, sub) in result.resolved.iter().enumerate() {
                let comma = if i < result.resolved.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"subdomain\": \"{}\",", sub.subdomain);
                println!("      \"ips\": [");
                for (j, ip) in sub.ips.iter().enumerate() {
                    let ip_comma = if j < sub.ips.len() - 1 { "," } else { "" };
                    println!("        \"{}\"{}", ip, ip_comma);
                }
                println!("      ],");
                if let Some(ref cname) = sub.cname {
                    println!("      \"cname\": \"{}\",", cname);
                }
                println!("      \"resolve_time_ms\": {}", sub.resolve_time_ms);
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // Human output
        if result.wildcard_detected {
            Output::warning(&format!(
                "Wildcard DNS detected! IPs: {}",
                result.wildcard_ips.join(", ")
            ));
            println!();
        }

        if result.resolved.is_empty() {
            Output::info("No subdomains resolved");
            return Ok(());
        }

        Output::subheader(&format!(
            "Resolved Subdomains ({}/{})",
            result.resolved.len(),
            result.total_attempts
        ));
        println!();

        // Print table header
        println!(
            "  {:<40} {:<20} {:<8} {}",
            "SUBDOMAIN", "IP ADDRESSES", "TIME", "CNAME"
        );
        println!("  {}", "─".repeat(85));

        for sub in &result.resolved {
            let ips = if sub.ips.is_empty() {
                "N/A".to_string()
            } else if sub.ips.len() == 1 {
                sub.ips[0].clone()
            } else {
                format!("{} (+{})", sub.ips[0], sub.ips.len() - 1)
            };

            let cname = sub.cname.as_deref().unwrap_or("-");
            let cname_display = if cname.len() > 25 {
                format!("{}...", &cname[..22])
            } else {
                cname.to_string()
            };

            println!(
                "  {:<40} {:<20} {:<8} {}",
                sub.subdomain,
                ips,
                format!("{}ms", sub.resolve_time_ms),
                cname_display
            );
        }

        println!();

        // Summary
        let duration_sec = result.duration_ms as f64 / 1000.0;
        let rate = result.total_attempts as f64 / duration_sec;

        Output::success(&format!(
            "Found {} subdomains in {:.2}s ({:.0} queries/sec)",
            result.resolved.len(),
            duration_sec,
            rate
        ));

        if !result.errors.is_empty() {
            Output::warning(&format!("{} errors occurred", result.errors.len()));
        }

        Ok(())
    }
}

/// Map technology name to OSV ecosystem
fn map_tech_to_ecosystem(tech_name: &str) -> Ecosystem {
    let name_lower = tech_name.to_lowercase();

    if name_lower.contains("node") || name_lower.contains("npm") || name_lower.contains("express") {
        Ecosystem::Npm
    } else if name_lower.contains("python")
        || name_lower.contains("django")
        || name_lower.contains("flask")
    {
        Ecosystem::PyPI
    } else if name_lower.contains("ruby") || name_lower.contains("rails") {
        Ecosystem::RubyGems
    } else if name_lower.contains("php") || name_lower.contains("laravel") {
        Ecosystem::Packagist
    } else if name_lower.contains("java") || name_lower.contains("spring") {
        Ecosystem::Maven
    } else if name_lower.contains("go") || name_lower.contains("golang") {
        Ecosystem::Go
    } else if name_lower.contains("rust") || name_lower.contains("cargo") {
        Ecosystem::Cargo
    } else {
        Ecosystem::Npm // Default to npm for JS libraries
    }
}

fn map_subdomain_source(source: &EnumerationSource) -> SubdomainSource {
    match source {
        EnumerationSource::CertificateTransparency => SubdomainSource::CertTransparency,
        EnumerationSource::DnsBruteforce => SubdomainSource::DnsBruteforce,
        EnumerationSource::VirusTotal
        | EnumerationSource::SecurityTrails
        | EnumerationSource::HackerTarget
        | EnumerationSource::AlienVaultOtx
        | EnumerationSource::ThreatCrowd
        | EnumerationSource::WaybackMachine => SubdomainSource::SearchEngine,
        EnumerationSource::Manual => SubdomainSource::WebCrawl,
    }
}

fn parse_whois_timestamp(value: Option<&str>) -> u32 {
    value.and_then(parse_whois_date).unwrap_or(0)
}

fn parse_whois_date(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts_iter = trimmed.split(|c| c == 'T' || c == ' ' || c == '\t');
    let date_part = parts_iter.next()?.trim();
    if date_part.is_empty() {
        return None;
    }

    let mut segments: Vec<&str> = date_part
        .split(|c| c == '-' || c == '/')
        .filter(|segment| !segment.is_empty())
        .collect();

    if segments.len() != 3 {
        return None;
    }

    let year = segments[0].parse::<i32>().ok()?;
    let month = segments[1].parse::<u32>().ok()?;
    let day_str = segments[2]
        .trim_end_matches(|c: char| !c.is_ascii_digit())
        .trim();
    let day = day_str.parse::<u32>().ok()?;

    if year < 1970 || month == 0 || month > 12 || day == 0 {
        return None;
    }

    let mut month_lengths = [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if is_leap_year(year) {
        month_lengths[1] = 29;
    }

    if day > month_lengths[(month - 1) as usize] {
        return None;
    }

    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 1..month {
        days += month_lengths[(m - 1) as usize] as u64;
    }
    days += (day - 1) as u64;

    Some((days * 86_400) as u32)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

impl ReconCommand {
    /// Active DNS bruteforce
    fn bruteforce(&self, ctx: &CliContext) -> Result<(), String> {
        use crate::modules::recon::subdomain_bruteforce::SubdomainBruteforcer;
        use crate::modules::recon::subdomain::load_wordlist_from_file;
        use std::sync::Arc;

        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain bruteforce <DOMAIN> --wordlist <FILE>",
        )?;

        let wordlist_path = ctx.get_flag("wordlist").ok_or("Missing --wordlist")?;
        let wordlist = load_wordlist_from_file(&wordlist_path)?;
        let total_words = wordlist.len() as u64; // Get total for progress bar
        
        let resolvers = if let Some(r) = ctx.get_flag("resolvers") {
            r.split(',').map(|s| s.trim().to_string()).collect()
        } else {
            vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()]
        };
        
        let threads: usize = ctx.get_flag("threads").and_then(|s| s.parse().ok()).unwrap_or(20);
        let wildcard = !ctx.has_flag("no-wildcard"); // Default enabled

        Output::header(&format!("DNS Bruteforce: {}", domain));
        Output::item("Wordlist", &format!("{} entries", total_words));
        Output::item("Threads", &threads.to_string());
        Output::item("Resolvers", &resolvers.join(", ")); // Display resolvers

        let mut engine = SubdomainBruteforcer::new(domain, wordlist)
            .with_resolvers(resolvers)
            .with_threads(threads)
            .with_wildcard_detection(wildcard);
            
        Output::spinner_start("Detecting wildcards...");
        if let Err(e) = engine.detect_wildcards() {
            Output::warning(&format!("Wildcard detection failed: {}", e));
        }
        Output::spinner_done();
        
        Output::info("Starting enumeration...");
        let progress_bar = Arc::new(Output::progress_bar("Bruteforcing", total_words, true));

        let raw_results = engine.run(progress_bar.clone()); // Get raw results
        let mut results: Vec<BruteforceResult> = Vec::new();
        let mut seen_subdomains = HashSet::new();

        for res in raw_results {
            if seen_subdomains.insert(res.subdomain.clone()) {
                results.push(res);
            }
        }
        results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain)); // Sort for consistent output

        progress_bar.finish();
        
        if results.is_empty() {
            Output::warning("No subdomains found.");
            return Ok(());
        }
        
        println!();
        Output::subheader(&format!("Found {} unique Subdomains", results.len()));
        println!("{:<40} {:<20} {:<15}", "SUBDOMAIN", "IP", "RESOLVER");
        println!("{}", "─".repeat(80));
        
        for res in results {
            let ip_str = res.ips.join(", ");
            println!("{:<40} {:<20} {:<15}", res.subdomain, ip_str, res.resolved_by);
        }
        
        Ok(())
    }

    /// List all subdomains for a domain from database (RESTful)
    fn list_subdomains(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx
            .target
            .as_ref()
            .ok_or("Missing domain. Usage: rb recon domain list <domain> [--db file]")?;

        // TODO: Implement database query for subdomains
        // For now, return a placeholder message
        Output::header(&format!("Subdomains for {}", domain));
        Output::info("[COMING SOON] Query database for saved subdomains");
        Output::info(&format!("Command: rb recon domain list {}", domain));

        Ok(())
    }

    /// Get specific subdomain info from database (RESTful)
    fn get_subdomain(&self, ctx: &CliContext) -> Result<(), String> {
        let subdomain = ctx
            .target
            .as_ref()
            .ok_or("Missing subdomain. Usage: rb recon domain get <subdomain> [--db file]")?;

        // TODO: Implement database query for specific subdomain
        Output::header(&format!("Subdomain Info: {}", subdomain));
        Output::info("[COMING SOON] Query database for subdomain details");
        Output::info(&format!("Command: rb recon domain get {}", subdomain));

        Ok(())
    }

    /// Get detailed OSINT data from database (RESTful)
    fn describe_domain(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx
            .target
            .as_ref()
            .ok_or("Missing domain. Usage: rb recon domain describe <domain> [--db file]")?;

        // TODO: Implement comprehensive database query
        Output::header(&format!("Domain Intelligence: {}", domain));
        Output::info("[COMING SOON] Query database for all recon data");
        Output::info(&format!("Command: rb recon domain describe {}", domain));
        Output::info("Will include: subdomains, WHOIS, harvested data, URLs");

        Ok(())
    }
}
