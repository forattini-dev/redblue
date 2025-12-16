/// Recon/domain command - Information gathering and OSINT
use crate::cli::commands::{build_partition_attributes, print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::network::scanner::PortScanner;
use crate::modules::recon::asn::AsnClient;
use crate::modules::recon::breach::BreachClient;
use crate::modules::recon::dnsdumpster::DnsDumpsterClient;
use crate::modules::recon::dorks::{DorksSearchResult, DorksSearcher};
use crate::modules::recon::harvester::Harvester;
use crate::modules::recon::massdns::common_subdomains;
use crate::modules::recon::massdns::MassDnsScanner;
use crate::modules::recon::osint::{EmailIntel, OsintConfig as EmailOsintConfig};
use crate::modules::recon::secrets::{SecretSeverity, SecretsScanner};
use crate::modules::recon::social::{SocialMapper, SocialMappingResult};
use crate::modules::recon::subdomain::{load_wordlist_from_file, SubdomainEnumerator};
use crate::modules::recon::urlharvest::UrlHarvester;
use crate::modules::recon::vuln::osv::{Ecosystem, OsvClient};
use crate::modules::recon::vuln::{calculate_risk_score, generate_cpe, NvdClient};
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::protocols::dns::{DnsClient, DnsRdata, DnsRecordType};
use crate::protocols::rdap::{RdapClient, RdapDomainResponse, RdapIpResponse};
use crate::protocols::whois::WhoisClient;
use crate::storage::records::{PortScanRecord, Severity, SubdomainSource, VulnerabilityRecord};
use crate::storage::service::StorageService;
use crate::ui::{ReconTreeBuilder, TreeNode, TreeRenderer};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

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
            // === FULL RECON WORKFLOW ===
            Route {
                verb: "full",
                summary: "🎯 Complete reconnaissance workflow (ports, dns, fingerprint, vulns)",
                usage: "rb recon domain full <target>",
            },
            Route {
                verb: "show",
                summary: "📊 Show consolidated findings for a target",
                usage: "rb recon domain show <target>",
            },
            // === Individual Recon Commands ===
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
                summary:
                    "Email intelligence - provider detection, service registrations (holehe-style)",
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
            Route {
                verb: "graph",
                summary: "Visualize domain/subdomain tree from database",
                usage: "rb recon domain graph <domain> [--db <file>] [--depth N]",
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
                "source",
                "Vulnerability source for vuln command (nvd, osv, all)",
            )
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
            Flag::new(
                "timeout-ms",
                "DNS query timeout in milliseconds for massdns",
            )
            .with_default("2000"),
            Flag::new("delay", "Delay between queries in ms for rate limiting").with_default("10"),
            Flag::new(
                "filter-wildcards",
                "Enable wildcard detection and filtering (for subdomains command)",
            ),
            Flag::new("depth", "Maximum tree depth for graph command").with_default("5"),
            Flag::new("no-color", "Disable colored output in graph"),
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
            ("ASN lookup for IP", "rb recon domain asn 8.8.8.8"),
            ("ASN lookup for hostname", "rb recon domain asn google.com"),
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
                "Fingerprint target and find vulnerabilities for detected technologies",
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
            // Full workflow
            "full" => self.full_recon(ctx),
            "show" => self.show_findings(ctx),
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
            "graph" => self.graph(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(
                        verb,
                        &[
                            "full",
                            "show",
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
                            "describe",
                            "graph"
                        ]
                    )
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl ReconCommand {
    /// Full reconnaissance workflow - runs all scans and saves to database
    fn full_recon(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb recon domain full <target>\nExample: rb recon domain full example.com"
        )?;

        let start_time = std::time::Instant::now();

        Output::header(&format!("Full Reconnaissance: {}", target));
        println!();
        println!("This will run: Port Scan → DNS → Web Fingerprint → Vulnerability Scan");
        println!("All results are saved automatically for attack planning.");
        println!();

        // Determine if target is IP or domain
        let target_is_ip = target.parse::<std::net::IpAddr>().is_ok();
        let scan_url = if target.starts_with("http://") || target.starts_with("https://") {
            target.to_string()
        } else if target_is_ip {
            format!("http://{}", target)
        } else {
            format!("http://{}", target)
        };

        // Initialize storage
        let db_path = StorageService::db_path(target);
        let mut store = crate::storage::RedDb::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        // === PHASE 1: Port Scan ===
        println!("\x1b[1;36m[1/4] Port Scanning\x1b[0m");
        Output::spinner_start("Scanning common ports...");

        // Common ports preset
        let common_ports: Vec<u16> = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
            5432, 5900, 8080, 8443, 8888,
        ];

        let mut port_results = Vec::new();
        let mut resolved_ip: Option<IpAddr> = None;

        if target_is_ip {
            resolved_ip = Some(target.parse().unwrap());
        } else {
            // Resolve domain
            let dns_client = DnsClient::new("8.8.8.8"); // Use default resolver
            if let Ok(ips) = dns_client.query(target, DnsRecordType::A).map(|answers| {
                answers
                    .into_iter()
                    .filter_map(|ans| ans.as_ip().and_then(|ip_str| ip_str.parse::<IpAddr>().ok()))
                    .collect::<Vec<_>>()
            }) {
                if let Some(ip) = ips.first() {
                    resolved_ip = Some(*ip);
                }
            }
        }

        if let Some(ip) = resolved_ip {
            let scanner = PortScanner::new(ip).with_threads(200).with_timeout(1000); // Expects u64 millis

            let results = scanner.scan_ports(&common_ports);
            let open_count = results.iter().filter(|r| r.is_open).count();

            for result in &results {
                if result.is_open {
                    let record = PortScanRecord {
                        ip,
                        port: result.port,
                        status: crate::storage::records::PortStatus::Open,
                        service_id: 0,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as u32,
                    };
                    port_results.push(record.clone());
                    let _ = store.ports().insert(
                        ip,
                        result.port,
                        crate::storage::records::PortStatus::Open,
                    ); // Use the RedDb API
                }
            }

            Output::spinner_done();
            println!("  ✓ Found {} open ports", open_count);

            if open_count > 0 {
                let ports_str: Vec<String> =
                    port_results.iter().map(|p| p.port.to_string()).collect();
                println!("    Ports: {}", ports_str.join(", "));
            }
        } else {
            Output::spinner_done();
            println!("  ⚠ Could not resolve target IP");
        }

        // === PHASE 2: DNS Enumeration ===
        println!();
        println!("\x1b[1;36m[2/4] DNS Enumeration\x1b[0m");

        if !target_is_ip {
            Output::spinner_start("Querying DNS records...");

            let dns_client = DnsClient::new("8.8.8.8"); // Use default resolver

            // Get A records
            let a_records = dns_client
                .query(target, DnsRecordType::A)
                .map(|answers| {
                    answers
                        .into_iter()
                        .filter_map(|ans| {
                            ans.as_ip().and_then(|ip_str| ip_str.parse::<IpAddr>().ok())
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            // Get MX records
            let mx_response = dns_client.query(target, DnsRecordType::MX);
            let mx_count = mx_response.map(|r| r.len()).unwrap_or(0);

            // Get NS records
            let ns_response = dns_client.query(target, DnsRecordType::NS);
            let ns_count = ns_response.map(|r| r.len()).unwrap_or(0);

            Output::spinner_done();
            println!("  ✓ A records: {}", a_records.len());
            println!("  ✓ MX records: {}", mx_count);
            println!("  ✓ NS records: {}", ns_count);

            if !a_records.is_empty() {
                let ips: Vec<String> = a_records.iter().map(|ip| ip.to_string()).collect();
                if !ips.is_empty() {
                    println!("    IPs: {}", ips.join(", "));
                }
            }
        } else {
            println!("  ⊘ Skipped (target is IP)");
        }

        // === PHASE 3: Web Fingerprinting ===
        println!();
        println!("\x1b[1;36m[3/4] Web Fingerprinting\x1b[0m");

        let has_web = port_results
            .iter()
            .any(|p| matches!(p.port, 80 | 443 | 8080 | 8443));

        // Store fingerprints as simple structs (not persisted to DB in this implementation)
        #[derive(Clone)]
        struct TechFingerprint {
            technology: String,
            version: Option<String>,
            confidence: u8,
        }

        let mut fingerprints: Vec<TechFingerprint> = Vec::new();
        if has_web || !target_is_ip {
            Output::spinner_start("Detecting technologies...");

            let fingerprinter = WebFingerprinter::new();

            // Try HTTPS first, then HTTP
            let urls_to_try = if scan_url.starts_with("http") {
                vec![scan_url.clone()]
            } else {
                vec![format!("https://{}", target), format!("http://{}", target)]
            };

            for url in urls_to_try {
                if let Ok(result) = fingerprinter.fingerprint(&url) {
                    for tech in result.technologies {
                        use crate::modules::web::fingerprinter::Confidence;
                        let conf_num = match tech.confidence {
                            Confidence::High => 90,
                            Confidence::Medium => 60,
                            Confidence::Low => 30,
                        };
                        let fp = TechFingerprint {
                            technology: tech.name.clone(),
                            version: tech.version.clone(),
                            confidence: conf_num,
                        };
                        fingerprints.push(fp);
                    }
                    if !fingerprints.is_empty() {
                        break; // Stop if we got results
                    }
                }
            }

            Output::spinner_done();

            if fingerprints.is_empty() {
                println!("  ⚠ No technologies detected");
            } else {
                println!("  ✓ Detected {} technologies", fingerprints.len());
                for fp in fingerprints.iter().take(5) {
                    let version = fp.version.as_deref().unwrap_or("");
                    println!("    • {} {}", fp.technology, version);
                }
                if fingerprints.len() > 5 {
                    println!("    ... and {} more", fingerprints.len() - 5);
                }
            }
        } else {
            println!("  ⊘ Skipped (no web ports detected)");
        }

        // === PHASE 4: Vulnerability Scan ===
        println!();
        println!("\x1b[1;36m[4/4] Vulnerability Scan\x1b[0m");

        let mut vulns = Vec::new();
        if !fingerprints.is_empty() {
            Output::spinner_start("Searching vulnerabilities...");

            let mut nvd_client = NvdClient::new();

            for fp in &fingerprints {
                let version = fp.version.as_deref();
                if let Some(cpe) = generate_cpe(&fp.technology, version) {
                    if let Ok(cve_list) = nvd_client.query_by_cpe(&cpe) {
                        for cve in cve_list.into_iter().take(5) {
                            // Get CVSS score (prefer v3, fallback to v2)
                            let cvss_score = cve.cvss_v3.or(cve.cvss_v2).unwrap_or(0.0);

                            let severity = match cvss_score {
                                s if s >= 9.0 => Severity::Critical,
                                s if s >= 7.0 => Severity::High,
                                s if s >= 4.0 => Severity::Medium,
                                s if s > 0.0 => Severity::Low,
                                _ => Severity::Info,
                            };

                            // Calculate risk score
                            let risk_score = calculate_risk_score(&cve);

                            let record = VulnerabilityRecord {
                                cve_id: cve.id.clone(),
                                technology: fp.technology.clone(),
                                version: fp.version.clone(),
                                cvss: cvss_score,
                                risk_score,
                                severity,
                                description: cve.description.chars().take(200).collect(),
                                references: cve.references.clone(),
                                exploit_available: false, // Default to false if not directly available
                                in_kev: false, // Default to false if not directly available
                                discovered_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                                    as u32,
                                source: "nvd".to_string(),
                            };
                            vulns.push(record.clone());
                            let _ = store.vulns().insert(record);
                        }
                    }
                }
            }

            Output::spinner_done();

            if vulns.is_empty() {
                println!("  ✓ No known vulnerabilities found");
            } else {
                let critical = vulns
                    .iter()
                    .filter(|v| matches!(v.severity, Severity::Critical))
                    .count();
                let high = vulns
                    .iter()
                    .filter(|v| matches!(v.severity, Severity::High))
                    .count();

                println!("  ⚠ Found {} vulnerabilities", vulns.len());
                if critical > 0 {
                    println!("    \x1b[1;31m• {} CRITICAL\x1b[0m", critical);
                }
                if high > 0 {
                    println!("    \x1b[31m• {} HIGH\x1b[0m", high);
                }

                // Show top CVEs
                let mut sorted = vulns.clone();
                sorted.sort_by(|a, b| {
                    b.cvss
                        .partial_cmp(&a.cvss)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                for v in sorted.iter().take(3) {
                    println!("    • {} (CVSS {:.1})", v.cve_id, v.cvss);
                }
            }
        } else {
            println!("  ⊘ Skipped (no technologies to check)");
        }

        // === SUMMARY ===
        let elapsed = std::time::Instant::now().duration_since(start_time); // Recalculate elapsed time
        println!();
        Output::header("Reconnaissance Complete");
        println!();
        Output::item("Target", target);
        Output::item("Duration", &format!("{:.1}s", elapsed.as_secs_f64()));
        Output::item("Open Ports", &port_results.len().to_string());
        Output::item("Technologies", &fingerprints.len().to_string());
        Output::item("Vulnerabilities", &vulns.len().to_string());
        Output::item("Database", &db_path.to_string_lossy());

        println!();
        Output::success("Data saved. Next steps:");
        println!();
        println!("  \x1b[1;36m1. View findings:\x1b[0m");
        println!("     rb recon domain show {}", target);
        println!();
        println!("  \x1b[1;36m2. Get attack recommendations:\x1b[0m");
        println!("     rb attack target plan {}", target);
        println!();
        println!("  \x1b[1;36m3. Execute a playbook:\x1b[0m");
        println!("     rb attack target run <playbook> {}", target);

        Ok(())
    }

    /// Show consolidated findings for a target
    fn show_findings(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb recon domain show <target>\nExample: rb recon domain show example.com"
        )?;

        Output::header(&format!("Reconnaissance Findings: {}", target));

        let db_path = StorageService::db_path(target);
        let mut store = match crate::storage::RedDb::open(&db_path) {
            Ok(s) => s,
            Err(_) => {
                println!();
                Output::warning(&format!("No data found for '{}'", target));
                println!();
                Output::info("Run reconnaissance first:");
                println!("  \x1b[1;36mrb recon domain full {}\x1b[0m", target);
                return Ok(());
            }
        };

        // === PORTS ===
        println!();
        Output::section("Open Ports");

        // Get ports by trying to resolve target IP
        let target_ip: Option<std::net::IpAddr> = if target.parse::<std::net::IpAddr>().is_ok() {
            target.parse().ok()
        } else {
            // Try to resolve domain
            let dns = DnsClient::new("8.8.8.8");
            dns.query(target, DnsRecordType::A)
                .ok()
                .and_then(|answers| {
                    answers.into_iter().find_map(|ans| {
                        if let DnsRdata::A(ip_str) = ans.data {
                            ip_str.parse::<std::net::IpAddr>().ok()
                        } else {
                            None
                        }
                    })
                })
        };

        let ports = if let Some(ip) = target_ip {
            store.ports().get_by_ip(ip).unwrap_or_default()
        } else {
            Vec::new()
        };
        let open_ports: Vec<_> = ports
            .iter()
            .filter(|p| p.status == crate::storage::records::PortStatus::Open)
            .collect();

        if open_ports.is_empty() {
            println!("  No open ports found");
        } else {
            // Group by common services
            for port in &open_ports {
                let service = match port.port {
                    21 => "FTP",
                    22 => "SSH",
                    23 => "Telnet",
                    25 => "SMTP",
                    53 => "DNS",
                    80 => "HTTP",
                    110 => "POP3",
                    139 => "NetBIOS",
                    143 => "IMAP",
                    443 => "HTTPS",
                    445 => "SMB",
                    3306 => "MySQL",
                    3389 => "RDP",
                    5432 => "PostgreSQL",
                    8080 => "HTTP-Alt",
                    8443 => "HTTPS-Alt",
                    _ => "Unknown",
                };
                println!(
                    "  \x1b[32m●\x1b[0m {} ({}) - {}",
                    port.port, service, port.ip
                );
            }
        }

        // === OS DETECTION ===
        let detected_os = if open_ports.iter().any(|p| p.port == 3389)
            || (open_ports.iter().any(|p| p.port == 445)
                && !open_ports.iter().any(|p| p.port == 22))
        {
            Some("Windows")
        } else if open_ports.iter().any(|p| p.port == 22)
            && !open_ports.iter().any(|p| p.port == 445)
        {
            Some("Linux")
        } else {
            None
        };

        if let Some(os) = detected_os {
            println!();
            Output::section("Detected OS");
            println!("  \x1b[1m{}\x1b[0m (inferred from ports)", os);
        }

        // === TECHNOLOGIES ===
        println!();
        Output::section("Technologies");

        // Technologies are inferred from vulnerabilities (since we don't have a fingerprints table)
        let vulns = store.vulns().all().unwrap_or_default();
        let unique_techs: HashSet<&String> = vulns.iter().map(|v| &v.technology).collect();

        if unique_techs.is_empty() {
            println!("  No technologies detected (run full recon to detect)");
        } else {
            for tech in unique_techs {
                println!("  • \x1b[1m{}\x1b[0m (from vulnerability data)", tech);
            }
        }

        // === VULNERABILITIES ===
        println!();
        Output::section("Vulnerabilities");
        if vulns.is_empty() {
            println!("  \x1b[32m✓\x1b[0m No known vulnerabilities");
        } else {
            // Sort by CVSS
            let mut sorted = vulns.clone();
            sorted.sort_by(|a, b| {
                b.cvss
                    .partial_cmp(&a.cvss)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Stats
            let critical = sorted
                .iter()
                .filter(|v| matches!(v.severity, Severity::Critical))
                .count();
            let high = sorted
                .iter()
                .filter(|v| matches!(v.severity, Severity::High))
                .count();
            let medium = sorted
                .iter()
                .filter(|v| matches!(v.severity, Severity::Medium))
                .count();

            println!("  Found {} vulnerabilities:", sorted.len());
            if critical > 0 {
                println!("    \x1b[1;31m● {} CRITICAL\x1b[0m", critical);
            }
            if high > 0 {
                println!("    \x1b[31m● {} HIGH\x1b[0m", high);
            }
            if medium > 0 {
                println!("    \x1b[33m● {} MEDIUM\x1b[0m", medium);
            }

            println!();
            println!("  Top CVEs:");
            for v in sorted.iter().take(10) {
                let sev_color = match v.severity {
                    Severity::Critical => "\x1b[1;31m",
                    Severity::High => "\x1b[31m",
                    Severity::Medium => "\x1b[33m",
                    _ => "\x1b[0m",
                };
                println!(
                    "  {}• {}\x1b[0m (CVSS {:.1}) - {}",
                    sev_color, v.cve_id, v.cvss, v.technology
                );
            }
            if sorted.len() > 10 {
                println!("  ... and {} more", sorted.len() - 10);
            }
        }

        // === NEXT STEPS ===
        println!();
        Output::section("Next Steps");
        println!();
        Output::success("1. View findings:");
        println!("     rb recon domain show {}", target);
        println!();
        Output::success("2. Get attack recommendations:");
        println!("     rb attack target plan {}", target);
        println!();
        Output::success("3. Execute a playbook:");
        println!("     rb attack target run <playbook> {}", target);

        Ok(())
    }

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
            let created = parse_whois_timestamp(result.creation_date.as_deref()).unwrap_or(0);
            let expires = parse_whois_timestamp(result.expiration_date.as_deref()).unwrap_or(0);
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
                println!("country: {}", country);
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
            "Missing target.\nUsage: rb recon domain rdap <DOMAIN|IP>\nExample: rb recon domain rdap example.com".to_string(),
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
            let result: RdapIpResponse = client.query_ip(target)?;

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
                    println!(
                        "    {{ \"action\": \"{}\", \"date\": \"{}\" }}{}",
                        event.action, event.date, comma
                    );
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
                    let name = entity
                        .name
                        .as_deref()
                        .or(entity.organization.as_deref())
                        .unwrap_or("Unknown");
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
            let result: RdapDomainResponse = client.query_domain(target)?;

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
                    let comma = if i < result.nameservers.len() - 1 {
                        ","
                    } else {
                        ""
                    };
                    println!("    \"{}\"{}", ns, comma);
                }
                println!("  ],");
                println!("  \"events\": [");
                for (i, event) in result.events.iter().enumerate() {
                    let comma = if i < result.events.len() - 1 { "," } else { "" };
                    println!(
                        "    {{ \"action\": \"{}\", \"date\": \"{}\" }}{}",
                        event.action, event.date, comma
                    );
                }
                println!("  ]");
                println!("}}");
                return Ok(());
            }

            // YAML output
            if format == crate::cli::format::OutputFormat::Yaml {
                println!("type: domain");
                println!("query: {}", target);
                // RdapDomainResponse doesn't have handle, start_address, end_address, ip_version, name, country
                // So, removed these lines from here
                println!("name: {}", result.domain); // Using domain as name for now
                if let Some(ref registrar) = result.registrar {
                    // Using registrar as country for now
                    println!("country: {}", registrar);
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
                    let cname_comma = if j < result.cname_chain.len() - 1 {
                        ","
                    } else {
                        ""
                    };
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
                println!("    └─ CNAME: {}", result.cname_chain.join(" → "));
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
                let source = map_subdomain_source(&result.source.to_string());
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
            urls =
                harvester.filter_urls(urls, include_pattern.as_deref(), exclude_pattern.as_deref());
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

        Output::header(&format!("Email Intelligence: {}", target));

        let config = EmailOsintConfig::default();
        let intel = EmailIntel::new(config);

        // Check for JSON output
        let format = ctx.get_output_format();

        // Validate email format
        if !intel.is_valid_format(target) {
            return Err(format!("Invalid email format: {}", target));
        }

        Output::spinner_start(&format!("Investigating {}", target));

        let result = intel.investigate(target);

        Output::spinner_done();

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"email\": \"{}\",", result.email);
            println!("  \"valid\": {},", result.valid);
            if let Some(ref provider) = result.provider {
                println!("  \"provider\": \"{}\",", provider);
            }
            println!("  \"services\": [");
            for (i, service) in result.services.iter().enumerate() {
                let comma = if i < result.services.len() - 1 {
                    ","
                } else {
                    ""
                };
                println!("    \"{}\"{}", service, comma);
            }
            println!("  ],");
            println!("  \"social_profiles\": [");
            for (i, profile) in result.social_profiles.iter().enumerate() {
                let url = profile.url.as_deref().unwrap_or("");
                let comma = if i < result.social_profiles.len() - 1 {
                    ","
                } else {
                    ""
                };
                println!(
                    "    {{ \"platform\": \"{}\", \"url\": \"{}\" }}{}",
                    profile.platform, url, comma
                );
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // Human output
        println!();
        Output::item("Email", &result.email);
        Output::item("Valid", if result.valid { "Yes" } else { "No" });

        if let Some(provider) = &result.provider {
            Output::item("Provider", provider);
        }

        // Check if disposable
        if intel.is_disposable(target) {
            Output::warning("This appears to be a disposable email address");
        }

        // Services found
        if !result.services.is_empty() {
            println!();
            Output::subheader(&format!("Registered Services ({})", result.services.len()));
            for service in &result.services {
                println!("  \x1b[32m✓\x1b[0m {}", service);
            }
        }

        // Social profiles linked
        if !result.social_profiles.is_empty() {
            println!();
            Output::subheader(&format!(
                "Social Profiles ({})",
                result.social_profiles.len()
            ));
            for profile in &result.social_profiles {
                let url = profile.url.as_deref().unwrap_or("N/A");
                println!(
                    "  \x1b[32m✓\x1b[0m {} - \x1b[36m{}\x1b[0m",
                    profile.platform, url
                );
            }
        }

        // Summary
        println!();
        let total = result.services.len() + result.social_profiles.len();
        if total > 0 {
            Output::success(&format!(
                "Found {} service(s) and {} profile(s)",
                result.services.len(),
                result.social_profiles.len()
            ));
        } else {
            Output::info("No service registrations or profiles found");
        }

        // Extract username and suggest related search
        if let Some(username) = intel.extract_username(target) {
            println!();
            Output::info(&format!(
                "Tip: Try 'rb recon username search {}' for broader search",
                username
            ));
        }

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

        let check_type = ctx
            .get_flag("type")
            .unwrap_or_else(|| "password".to_string());
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
                    Output::error(&format!("Password found in {} breaches!", result.count));
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
                        r#"Email breach checks require an HIBP API key.
                        Get one at: https://haveibeenpwned.com/API/Key ($3.50/month)
                        Usage: rb recon domain breach user@example.com --type email --hibp-key YOUR_KEY"#.to_string()
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
                        let comma = if i < result.breaches.len() - 1 {
                            ","
                        } else {
                            ""
                        };
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
                    Output::error(&format!("Email found in {} breaches!", result.breach_count));
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
                    }
                } else {
                    Output::success("Email NOT found in any known breaches");
                    println!();
                    Output::info("This email address has not been seen in HIBP's data breaches.");
                }
            }
            _ => {
                return Err(format!(
                    "Invalid check type: {}. Use 'password' or 'email'.",
                    check_type
                ));
            }
        }

        Ok(())
    }

    fn secrets(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb recon domain secrets <URL>\nExample: rb recon domain secrets http://example.com/config.js",
        )?;

        // Basic URL validation
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err("Invalid URL. Must start with http:// or https://".to_string());
        }

        Output::header("Secrets Scanner");
        Output::item("Target URL", url);
        println!();

        let scanner = SecretsScanner::new();

        Output::spinner_start(&format!("Scanning {} for exposed secrets", url));
        let results = scanner.scan_url(url)?; // Corrected: Use scan_url and '?'
        Output::spinner_done();

        if results.is_empty() {
            Output::info("No secrets found.");
            return Ok(());
        }

        // Sort results by severity
        let mut sorted_results = results;
        sorted_results.sort_by(|a, b| b.severity.cmp(&a.severity));

        println!();
        Output::subheader(&format!("Found {} potential secrets", sorted_results.len()));
        println!();

        for result in &sorted_results {
            let severity_color = match result.severity {
                SecretSeverity::Critical => "\x1b[1;31m",
                SecretSeverity::High => "\x1b[31m",
                SecretSeverity::Medium => "\x1b[33m",
                SecretSeverity::Low => "\x1b[36m",
            };
            let severity_str = match result.severity {
                SecretSeverity::Critical => "CRITICAL",
                SecretSeverity::High => "HIGH",
                SecretSeverity::Medium => "MEDIUM",
                SecretSeverity::Low => "LOW",
            };

            println!(
                "  {}{}● {} [{}]\x1b[0m",
                severity_color, severity_color, result.matched, severity_str
            ); // Corrected: result.matched
            if let Some(line) = result.line {
                // Corrected: result.line is Option<usize>
                println!("    └─ Line: {}", line);
            }
            println!("    └─ Type: {}", result.secret_type);
            println!();
        }

        Output::success(&format!("Found {} potential secrets", sorted_results.len()));

        Ok(())
    }

    fn dorks(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain dorks <DOMAIN>\nExample: rb recon domain dorks example.com",
        )?;

        Validator::validate_domain(domain)?;

        Output::header(&format!("Google Dorks Search: {}", domain));
        println!();

        let searcher = DorksSearcher::new();

        Output::spinner_start(&format!("Searching Google for {} ...", domain));
        let results: DorksSearchResult = searcher.search(domain); // Corrected: Removed '?'
        Output::spinner_done();
        // let results = results?; // Removed as it returns DorksSearchResult directly

        if results.summary.total_results == 0 {
            // Corrected check for empty results
            Output::info("No results found.");
            return Ok(());
        }

        println!();
        Output::subheader(&format!(
            "Found {} potential leaks/intel:",
            results.summary.total_results
        )); // Corrected
        println!();

        // Display results by category
        if !results.categories.github.is_empty() {
            println!("\x1b[1;36mGitHub:\x1b[0m");
            for dork_result in &results.categories.github {
                for url in &dork_result.urls {
                    println!("  \x1b[36m→\x1b[0m {}", url);
                }
            }
            println!();
        }
        if !results.categories.pastebin.is_empty() {
            println!("\x1b[1;36mPastebin:\x1b[0m");
            for dork_result in &results.categories.pastebin {
                for url in &dork_result.urls {
                    println!("  \x1b[36m→\x1b[0m {}", url);
                }
            }
            println!();
        }
        if !results.categories.linkedin.is_empty() {
            println!("\x1b[1;36mLinkedIn:\x1b[0m");
            for dork_result in &results.categories.linkedin {
                for url in &dork_result.urls {
                    println!("  \x1b[36m→\x1b[0m {}", url);
                }
            }
            println!();
        }
        if !results.categories.documents.is_empty() {
            println!("\x1b[1;36mDocuments:\x1b[0m");
            for dork_result in &results.categories.documents {
                for url in &dork_result.urls {
                    println!("  \x1b[36m→\x1b[0m {}", url);
                }
            }
            println!();
        }
        if !results.categories.subdomains.is_empty() {
            println!("\x1b[1;36mSubdomains:\x1b[0m");
            for url in &results.categories.subdomains {
                println!("  \x1b[36m→\x1b[0m {}", url);
            }
            println!();
        }
        if !results.categories.login_pages.is_empty() {
            println!("\x1b[1;36mLogin Pages:\x1b[0m");
            for dork_result in &results.categories.login_pages {
                for url in &dork_result.urls {
                    println!("  \x1b[36m→\x1b[0m {}", url);
                }
            }
            println!();
        }
        if !results.categories.configs.is_empty() {
            println!("\x1b[1;36mConfig Files:\x1b[0m");
            for dork_result in &results.categories.configs {
                for url in &dork_result.urls {
                    println!("  \x1b[36m→\x1b[0m {}", url);
                }
            }
            println!();
        }
        if !results.categories.errors.is_empty() {
            println!("\x1b[1;36mError Pages:\x1b[0m");
            for dork_result in &results.categories.errors {
                for url in &dork_result.urls {
                    println!("  \x1b[36m→\x1b[0m {}", url);
                }
            }
            println!();
        }

        Output::success(&format!(
            "Found {} potential leaks/intel",
            results.summary.total_results
        ));

        Ok(())
    }

    fn social(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain social <DOMAIN>\nExample: rb recon domain social example.com",
        )?;

        Validator::validate_domain(domain)?;

        Output::header(&format!("Social Media Mapping: {}", domain));
        println!();

        let mapper = SocialMapper::new();

        Output::spinner_start(&format!("Mapping social media for {}", domain));
        let results: SocialMappingResult = mapper.map(domain); // Corrected: Removed '?'
        Output::spinner_done();
        // let results = results?; // Removed as it returns SocialMappingResult directly

        if results.profiles.is_empty() {
            // Corrected check for empty results
            Output::info("No social media profiles found.");
            return Ok(());
        }

        println!();
        Output::subheader(&format!(
            "Found {} social media profiles:",
            results.profiles.len()
        )); // Corrected
        println!();

        for profile in results.profiles.values() {
            // Iterate over values directly
            if profile.found {
                println!(
                    "  \x1b[36m{}\x1b[0m - \x1b[1m{}\x1b[0m",
                    profile.platform, profile.url
                );
            }
        }

        Output::success(&format!(
            "Found {} social media profiles",
            results.profiles.len()
        ));

        Ok(())
    }

    fn vuln(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb recon domain vuln <URL> [--source nvd|osv|all] [--limit N]\nExample: rb recon domain vuln http://example.com",
        )?;

        // Basic URL validation
        if !target.starts_with("http://") && !target.starts_with("https://") {
            return Err("Invalid URL. Must start with http:// or https://".to_string());
        }

        let source = ctx.get_flag("source").unwrap_or_else(|| "nvd".to_string());
        let limit: usize = ctx
            .get_flag("limit")
            .unwrap_or_else(|| "20".to_string())
            .parse()
            .unwrap_or(20);

        Output::header(&format!("Vulnerability Scan: {}", target));
        Output::item("Source", &source);
        Output::item("Limit", &limit.to_string());
        println!();

        let fingerprinter = WebFingerprinter::new();
        let mut nvd_client = NvdClient::new();
        let osv_client = OsvClient::new();

        // Get API keys from flags if provided
        if let Some(api_key) = ctx.get_flag("api-key") {
            nvd_client = nvd_client.with_api_key(&api_key);
        }

        Output::spinner_start("Fingerprinting target...");
        let fingerprint_result = fingerprinter.fingerprint(target)?;
        Output::spinner_done();

        if fingerprint_result.technologies.is_empty() {
            Output::warning("No technologies detected on target.");
            return Ok(());
        }

        println!();
        Output::subheader(&format!(
            "Detected Technologies ({})",
            fingerprint_result.technologies.len()
        ));
        for tech in &fingerprint_result.technologies {
            let conf = match tech.confidence {
                crate::modules::web::fingerprinter::Confidence::High => "High",
                crate::modules::web::fingerprinter::Confidence::Medium => "Medium",
                crate::modules::web::fingerprinter::Confidence::Low => "Low",
            };
            println!("  • {} (Confidence: {})", tech.name, conf);
        }
        println!();

        let mut all_vulns: Vec<crate::modules::recon::vuln::Vulnerability> = Vec::new();

        // Scan NVD if requested
        if source == "nvd" || source == "all" {
            Output::spinner_start("Querying NVD for vulnerabilities...");
            for tech in &fingerprint_result.technologies {
                if let Some(cpe) = generate_cpe(&tech.name, tech.version.as_deref()) {
                    match nvd_client.query_by_cpe(&cpe) {
                        Ok(mut vulns) => {
                            all_vulns.append(&mut vulns);
                        }
                        Err(e) => {
                            eprintln!("Warning: NVD query failed for {}: {}", cpe, e);
                        }
                    }
                }
            }
            Output::spinner_done();
        }

        // Scan OSV if requested
        if source == "osv" || source == "all" {
            Output::spinner_start("Querying OSV for vulnerabilities...");
            for tech in &fingerprint_result.technologies {
                if let Some(ecosystem) = map_to_osv_ecosystem(&tech.name) {
                    // Call query_package directly
                    match osv_client.query_package(&tech.name, tech.version.as_deref(), ecosystem) {
                        Ok(mut vulns) => {
                            all_vulns.append(&mut vulns);
                        }
                        Err(e) => {
                            eprintln!("Warning: OSV query failed for tech {}: {}", tech.name, e);
                        }
                    }
                }
            }
            Output::spinner_done();
        }

        // Deduplicate and sort vulnerabilities
        all_vulns.sort_by(|a, b| a.id.cmp(&b.id));
        all_vulns.dedup_by(|a, b| a.id == b.id);
        all_vulns.sort_by(|a, b| {
            let cvss_a = a.cvss_v3.or(a.cvss_v2).unwrap_or(0.0);
            let cvss_b = b.cvss_v3.or(b.cvss_v2).unwrap_or(0.0);
            cvss_b
                .partial_cmp(&cvss_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        if all_vulns.is_empty() {
            Output::info("No known vulnerabilities found for detected technologies.");
            return Ok(());
        }

        println!();
        Output::subheader(&format!(
            "Found {} Vulnerabilities (Top {})",
            all_vulns.len(),
            limit
        ));
        println!();

        for vuln in all_vulns.iter().take(limit) {
            let cvss_score = vuln.cvss_v3.or(vuln.cvss_v2).unwrap_or(0.0);
            let severity = match cvss_score {
                s if s >= 9.0 => "CRITICAL",
                s if s >= 7.0 => "HIGH",
                s if s >= 4.0 => "MEDIUM",
                _ => "LOW",
            };
            let severity_color = match severity {
                "CRITICAL" => "\x1b[1;31m",
                "HIGH" => "\x1b[31m",
                "MEDIUM" => "\x1b[33m",
                _ => "\x1b[36m",
            };

            println!(
                "  {}{}● {} (CVSS {:.1})\x1b[0m",
                severity_color, severity_color, vuln.id, cvss_score
            );
            println!(
                "    └─ {}",
                vuln.description.chars().take(100).collect::<String>()
            );
            // Removed exploit_available and in_kev as they are not fields of Vulnerability
            println!();
        }

        if all_vulns.len() > limit {
            println!(
                "  ... and {} more vulnerabilities found.\n",
                all_vulns.len() - limit
            );
        }

        Output::success(&format!("Found {} vulnerabilities", all_vulns.len()));

        Ok(())
    }

    fn dnsdumpster(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain dnsdumpster <DOMAIN>\nExample: rb recon domain dnsdumpster example.com",
        )?;

        Validator::validate_domain(domain)?;

        Output::header(&format!("DNSDumpster Lookup: {}", domain));
        println!();

        let client = DnsDumpsterClient::new();

        Output::spinner_start(&format!("Querying DNSDumpster for {}", domain));
        let results = client.query(domain)?;
        Output::spinner_done();

        if results.dns_records.is_empty() && results.host_records.is_empty() {
            Output::info("No DNS records found.");
            return Ok(());
        }

        println!();
        Output::subheader(&format!(
            "DNS Records ({})",
            results.dns_records.len() + results.host_records.len()
        ));
        println!();

        for record in &results.dns_records {
            println!("  \x1b[1m{}: {}\x1b[0m", record.record_type, record.value);
        }
        for record in &results.host_records {
            println!(
                "  \x1b[1mHost: {}\x1b[0m ({})",
                record.host,
                record.ip.as_deref().unwrap_or("N/A")
            );
        }

        Output::success(&format!(
            "Found {} DNS records",
            results.dns_records.len() + results.host_records.len()
        ));

        Ok(())
    }

    fn massdns(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain massdns <DOMAIN> [--wordlist <file>] [--threads N]\nExample: rb recon domain massdns example.com",
        )?;

        Validator::validate_domain(domain)?;

        let wordlist_path = ctx.get_flag("wordlist");
        let threads: usize = ctx
            .get_flag("threads")
            .unwrap_or_else(|| "10".to_string())
            .parse()
            .unwrap_or(10);
        let resolvers: Vec<String> = ctx
            .get_flag("resolvers")
            .unwrap_or_else(|| "8.8.8.8,1.1.1.1,9.9.9.9".to_string())
            .split(',')
            .map(|s| s.to_string())
            .collect();
        let timeout_ms: u64 = ctx
            .get_flag("timeout-ms")
            .unwrap_or_else(|| "2000".to_string())
            .parse()
            .unwrap_or(2000);
        let delay: u64 = ctx
            .get_flag("delay")
            .unwrap_or_else(|| "10".to_string())
            .parse()
            .unwrap_or(10);

        Output::header(&format!("MassDNS Subdomain Enumeration: {}", domain));
        Output::item("Threads", &threads.to_string());
        Output::item("Resolvers", &resolvers.join(", "));
        Output::item("Timeout (ms)", &timeout_ms.to_string());
        Output::item("Delay (ms)", &delay.to_string());
        if let Some(path) = &wordlist_path {
            Output::item("Wordlist", path);
        } else {
            Output::item("Wordlist", "Default (common subdomains)");
        }
        println!();

        let scanner = MassDnsScanner::new() // Corrected: new() takes no arguments
            .with_threads(threads)
            .with_resolvers(resolvers)
            .with_timeout(Duration::from_millis(timeout_ms)) // Convert to Duration
            .with_delay(Duration::from_millis(delay)); // Convert to Duration

        let wordlist: Vec<String>;
        if let Some(path) = wordlist_path {
            wordlist = load_wordlist_from_file(&path)?;
        } else {
            wordlist = common_subdomains(); // common_subdomains returns Vec<String> directly
        }

        Output::spinner_start("Starting MassDNS scan...");
        let results = scanner.bruteforce(domain, &wordlist)?; // Corrected: call bruteforce
        Output::spinner_done();

        if results.resolved.is_empty() {
            // Check resolved subdomains
            Output::info("No subdomains found.");
            return Ok(());
        }

        println!();
        Output::subheader(&format!("Found {} Subdomains", results.resolved.len()));
        println!();

        for result in &results.resolved {
            // Iterate over resolved subdomains
            let ips = result.ips.join(", ");
            println!("  \x1b[32m●\x1b[0m {} ({})", result.subdomain, ips);
        }

        Output::success(&format!("Found {} subdomains", results.resolved.len()));

        Ok(())
    }

    // RESTful verbs
    fn list_subdomains(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain list <DOMAIN> [--db <file>]\nExample: rb recon domain list example.com",
        )?;

        let db_path = StorageService::db_path(domain);
        let mut store = crate::storage::RedDb::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        Output::header(&format!("Listing Subdomains for {}", domain));
        Output::item("Database", &db_path.to_string_lossy());
        println!();

        let subdomains = store.subdomains().get_by_domain(domain).unwrap_or_default();

        if subdomains.is_empty() {
            Output::info("No subdomains found in the database.");
            return Ok(());
        }

        println!("  {:<40} {:<15} IP ADDRESSES", "SUBDOMAIN", "SOURCE");
        println!("  {}", "─".repeat(75));

        for subdomain in &subdomains {
            let source_str = match subdomain.source {
                SubdomainSource::DnsBruteforce => "Bruteforce",
                SubdomainSource::CertTransparency => "CT Logs",
                SubdomainSource::SearchEngine => "Search Engine",
                SubdomainSource::WebCrawl => "Web Crawl",
            };
            let ips_str = subdomain
                .ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "  {:<40} {:<15} {}",
                subdomain.subdomain, source_str, ips_str
            );
        }

        Output::success(&format!("Found {} subdomains", subdomains.len()));

        Ok(())
    }

    fn get_subdomain(&self, ctx: &CliContext) -> Result<(), String> {
        let subdomain_target = ctx.target.as_ref().ok_or(
            "Missing subdomain.\nUsage: rb recon domain get <SUBDOMAIN> [--db <file>]\nExample: rb recon domain get api.example.com",
        )?;

        // Need to extract the base domain for db_path and get_by_domain
        // This is a simplified extraction; a more robust solution might involve public suffix list
        let domain_for_db = {
            let parts: Vec<&str> = subdomain_target.split('.').collect();
            if parts.len() > 1 {
                parts[parts.len() - 2..].join(".")
            } else {
                subdomain_target.to_string() // If it's a single word, treat as domain
            }
        };

        let db_path = StorageService::db_path(&domain_for_db); // Use extracted domain for db_path
        let mut store = crate::storage::RedDb::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        Output::header(&format!("Getting Subdomain Info: {}", subdomain_target));
        Output::item("Database", &db_path.to_string_lossy());
        println!();

        // Get all subdomains for the base domain and filter for the specific subdomain
        let all_subdomains_for_domain = store
            .subdomains()
            .get_by_domain(&domain_for_db)
            .unwrap_or_default();
        let subdomain_info: Vec<_> = all_subdomains_for_domain
            .into_iter()
            .filter(|rec| rec.subdomain.as_str() == subdomain_target) // Corrected comparison
            .collect();

        if subdomain_info.is_empty() {
            Output::info("Subdomain not found in the database.");
            return Ok(());
        }

        // Assuming only one entry for a given subdomain name after filtering
        let info = &subdomain_info[0];

        let source_str = match info.source {
            SubdomainSource::DnsBruteforce => "Bruteforce",
            SubdomainSource::CertTransparency => "CT Logs",
            SubdomainSource::SearchEngine => "Search Engine",
            SubdomainSource::WebCrawl => "Web Crawl",
        };
        let ips_str = info
            .ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        println!("  Subdomain: {}", info.subdomain);
        // Removed `println!("  Domain: {}", info.domain);` as SubdomainRecord doesn't have a direct 'domain' field.
        println!("  Source: {}", source_str);
        println!("  IP Addresses: {}", ips_str);

        Ok(())
    }

    fn describe_domain(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain describe <DOMAIN> [--db <file>]\nExample: rb recon domain describe example.com",
        )?;

        let db_path = StorageService::db_path(domain);
        let mut store = crate::storage::RedDb::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        Output::header(&format!("Describing Domain: {}", domain));
        Output::item("Database", &db_path.to_string_lossy());
        println!();

        let subdomains = store.subdomains().get_by_domain(domain).unwrap_or_default();
        let vulns = store.vulns().all().unwrap_or_default();

        println!("\x1b[1mSubdomains:\x1b[0m {}", subdomains.len());
        println!("\x1b[1mVulnerabilities:\x1b[0m {}", vulns.len());

        // Print top 5 subdomains
        if !subdomains.is_empty() {
            println!();
            println!("  Top 5 Subdomains:");
            for subdomain in subdomains.iter().take(5) {
                println!("    • {}", subdomain.subdomain);
            }
            if subdomains.len() > 5 {
                println!("    ... and {} more", subdomains.len() - 5);
            }
        }

        // Print top 5 vulnerabilities
        if !vulns.is_empty() {
            println!();
            println!("  Top 5 Vulnerabilities:");
            let mut sorted_vulns = vulns;
            sorted_vulns.sort_by(|a, b| {
                b.cvss
                    .partial_cmp(&a.cvss)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            for vuln in sorted_vulns.iter().take(5) {
                println!(
                    "    • {} (CVSS {:.1}) - {}",
                    vuln.cve_id, vuln.cvss, vuln.technology
                );
            }
            if sorted_vulns.len() > 5 {
                println!("    ... and {} more", sorted_vulns.len() - 5);
            }
        }

        Ok(())
    }

    fn graph(&self, ctx: &CliContext) -> Result<(), String> {
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb recon domain graph <DOMAIN> [--db <file>] [--depth N]\nExample: rb recon domain graph example.com",
        )?;

        let db_path = StorageService::db_path(domain);
        let depth: u8 = ctx
            .get_flag("depth")
            .unwrap_or_else(|| "5".to_string())
            .parse()
            .unwrap_or(5);
        let no_color = ctx.has_flag("no-color");

        let mut store = crate::storage::RedDb::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        Output::header(&format!("Domain Graph: {}", domain));
        Output::item("Database", &db_path.to_string_lossy());
        Output::item("Depth", &depth.to_string());
        println!();

        let mut builder = ReconTreeBuilder::new(domain.to_string());

        // Add subdomains
        let subdomains = store.subdomains().get_by_domain(domain).unwrap_or_default();
        for sub in subdomains {
            // Find or create IP nodes for subdomains
            for ip in &sub.ips {
                if builder.root().find(&ip.to_string()).is_none() {
                    builder.root_mut().add_child(TreeNode::ip(*ip));
                }
            }
            builder.add_subdomain(sub.subdomain, &sub.ips);
        }

        // Add ports to IPs (find IP node first)
        let all_ports = store.ports().get_all().unwrap_or_default();
        for port_record in all_ports {
            // Find parent node for the IP
            if let Some(ip_node) = builder.root_mut().find_mut(&port_record.ip.to_string()) {
                ip_node.add_child(TreeNode::port(
                    port_record.port,
                    Some(&format!("{:?}", port_record.status)),
                ));
            } else {
                // If IP node doesn't exist, create it under root domain and add port
                let mut ip_node = TreeNode::ip(port_record.ip);
                ip_node.add_child(TreeNode::port(
                    port_record.port,
                    Some(&format!("{:?}", port_record.status)),
                ));
                builder.root_mut().add_child(ip_node);
            }
        }

        // Add nameservers/mailservers to the root domain or relevant subdomain
        let dns_records = store.dns().get_by_domain(domain).unwrap_or_default();
        for dns_rec in dns_records {
            if dns_rec.record_type == crate::storage::records::DnsRecordType::NS {
                builder
                    .root_mut()
                    .add_child(TreeNode::nameserver(dns_rec.value));
            } else if dns_rec.record_type == crate::storage::records::DnsRecordType::MX {
                // Assuming priority is not stored directly in dns_rec, just pass None
                builder
                    .root_mut()
                    .add_child(TreeNode::mail_server(dns_rec.value, None));
            }
        }

        // Set depth limit for the TreeRenderer, as ReconTreeBuilder doesn't have it
        let mut renderer = TreeRenderer::new();
        renderer = renderer.with_color(!no_color);
        renderer = renderer.collapse_after(depth as usize); // Use depth for collapse threshold

        let tree = builder.build(); // build() returns TreeNode directly

        // Need to display the tree, not just return it as a string
        renderer.display(&tree);

        Ok(())
    }
}

// Helper function to parse WHOIS timestamps (simplified)
fn parse_whois_timestamp(date_str: Option<&str>) -> Option<u32> {
    date_str.and_then(|s| {
        // Attempt to parse common formats like YYYY-MM-DD
        if s.len() >= 10 {
            if let Ok(ts) = chrono::NaiveDateTime::parse_from_str(&s[..10], "%Y-%m-%d") {
                return Some(ts.and_utc().timestamp() as u32);
            }
        }
        // Add more formats as needed
        None
    })
}

// Helper function to map subdomain source strings to enum values
fn map_subdomain_source(source: &str) -> SubdomainSource {
    match source {
        "DnsBruteforce" => SubdomainSource::DnsBruteforce,
        "CertTransparency" => SubdomainSource::CertTransparency,
        "SearchEngine" => SubdomainSource::SearchEngine,
        "WebCrawl" => SubdomainSource::WebCrawl,
        _ => SubdomainSource::SearchEngine, // Default to SearchEngine for unknown/new sources
    }
}

// Helper function to map technology names to OSV ecosystems
fn map_to_osv_ecosystem(tech_name: &str) -> Option<Ecosystem> {
    match tech_name.to_lowercase().as_str() {
        "npm" | "nodejs" => Some(Ecosystem::Npm),
        "python" | "pypi" => Some(Ecosystem::PyPI),
        "rust" | "cargo" => Some(Ecosystem::Cargo),
        "go" => Some(Ecosystem::Go),
        "java" | "maven" => Some(Ecosystem::Maven),
        "nuget" => Some(Ecosystem::NuGet),
        "php" | "packagist" => Some(Ecosystem::Packagist),
        "ruby" | "rubygems" => Some(Ecosystem::RubyGems),
        "dart" | "pub" => Some(Ecosystem::Pub),
        "elixir" | "hex" => Some(Ecosystem::Hex),
        "cpp" | "conancenter" => Some(Ecosystem::ConanCenter),
        _ => None,
    }
}
