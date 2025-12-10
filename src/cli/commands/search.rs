// Global search command - Search across all stored data
//
// Usage:
//   rb search query <pattern>          Search across all databases
//   rb search query <pattern> --db X   Search in specific database
//   rb search query <pattern> --type X Filter by data type
//   rb search list                     List available databases
//   rb search stats                    Show database statistics

use crate::cli::commands::{Command, Flag, Route};
use crate::cli::format::OutputFormat;
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::storage::QueryManager;
use std::env;
use std::fs;
use std::path::PathBuf;

pub struct SearchCommand;

impl Command for SearchCommand {
    fn domain(&self) -> &str {
        "search"
    }

    fn resource(&self) -> &str {
        "data"
    }

    fn description(&self) -> &str {
        "Search across all stored reconnaissance data"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "query",
                summary: "Search for a pattern across all data types",
                usage: "rb search data query api.example.com",
            },
            Route {
                verb: "list",
                summary: "List all available database files",
                usage: "rb search data list",
            },
            Route {
                verb: "stats",
                summary: "Show statistics for a database",
                usage: "rb search data stats example.com.rdb",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("db", "Specific database file to search")
                .with_short('d')
                .with_arg("FILE"),
            Flag::new("type", "Filter by data type: subdomains, ports, dns, whois, tls, hosts, http")
                .with_short('t')
                .with_arg("TYPE"),
            Flag::new("output", "Output format: human, json, yaml")
                .with_short('o')
                .with_default("human"),
            Flag::new("all", "Search all databases in current directory")
                .with_short('a'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Search for a subdomain pattern",
                "rb search data query api --type subdomains",
            ),
            (
                "Search across all databases",
                "rb search data query nginx --all",
            ),
            (
                "Search in specific database",
                "rb search data query example.com --db google.com.rdb",
            ),
            (
                "List available databases",
                "rb search data list",
            ),
            (
                "Show database statistics",
                "rb search data stats google.com.rdb",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().ok_or_else(|| {
            crate::cli::commands::print_help(self);
            String::new()
        })?;

        match verb {
            "query" => self.search_query(ctx),
            "list" => self.list_databases(ctx),
            "stats" => self.show_stats(ctx),
            "help" => {
                crate::cli::commands::print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use: query, list, stats",
                verb
            )),
        }
    }
}

impl SearchCommand {
    /// Search for a pattern across stored data
    fn search_query(&self, ctx: &CliContext) -> Result<(), String> {
        let pattern = ctx.target.as_deref().ok_or(
            "Missing search pattern.\n\nUsage: rb search data query <pattern> [--type TYPE] [--db FILE]",
        )?;

        let output_format = ctx.get_output_format();
        let data_type = ctx.get_flag("type");
        let search_all = ctx.has_flag("all");

        // Collect databases to search
        let databases = if let Some(db_path) = ctx.get_flag("db") {
            let path = PathBuf::from(&db_path);
            if !path.exists() {
                return Err(format!("Database file not found: {}", db_path));
            }
            vec![path]
        } else if search_all {
            self.find_all_databases()?
        } else {
            // Try to find a database matching the pattern domain
            self.find_all_databases()?
        };

        if databases.is_empty() {
            return Err(
                "No database files found.\n\n\
                 Run a scan with --persist first:\n  \
                 rb recon domain subdomains example.com --persist\n  \
                 rb recon domain whois example.com --persist"
                    .to_string(),
            );
        }

        let mut all_results = SearchResults::new(pattern.to_string());

        for db_path in &databases {
            let db_name = db_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            match QueryManager::open(db_path) {
                Ok(mut qm) => {
                    self.search_in_database(&mut qm, pattern, data_type.as_deref(), db_name, &mut all_results)?;
                }
                Err(e) => {
                    if output_format == OutputFormat::Human {
                        Output::warning(&format!("Skipping {}: {}", db_name, e));
                    }
                }
            }
        }

        // Output results
        match output_format {
            OutputFormat::Json => {
                println!("{}", all_results.to_json());
            }
            OutputFormat::Yaml => {
                println!("{}", all_results.to_yaml());
            }
            OutputFormat::Human => {
                all_results.print_human();
            }
        }

        Ok(())
    }

    /// Search within a single database
    fn search_in_database(
        &self,
        qm: &mut QueryManager,
        pattern: &str,
        data_type: Option<&str>,
        db_name: &str,
        results: &mut SearchResults,
    ) -> Result<(), String> {
        let pattern_lower = pattern.to_lowercase();

        // Search subdomains
        if data_type.is_none() || data_type == Some("subdomains") {
            // Extract domain from db name for subdomain lookup
            let domain = db_name.trim_end_matches(".rdb");
            if let Ok(subdomains) = qm.list_subdomains(domain) {
                for sub in subdomains {
                    if sub.to_lowercase().contains(&pattern_lower) {
                        results.add_subdomain(db_name, &sub);
                    }
                }
            }
        }

        // Search DNS records
        if data_type.is_none() || data_type == Some("dns") {
            let domain = db_name.trim_end_matches(".rdb");
            if let Ok(records) = qm.list_dns_records(domain) {
                for record in records {
                    let record_str = format!("{:?}", record);
                    if record_str.to_lowercase().contains(&pattern_lower)
                        || record.domain.to_lowercase().contains(&pattern_lower)
                    {
                        results.add_dns(db_name, &record.domain, &format!("{:?}", record.record_type));
                    }
                }
            }
        }

        // Search WHOIS
        if data_type.is_none() || data_type == Some("whois") {
            let domain = db_name.trim_end_matches(".rdb");
            if let Ok(Some(whois)) = qm.get_whois(domain) {
                let whois_str = format!(
                    "{} {} {} {:?}",
                    whois.registrar, whois.created_date, whois.expires_date, whois.nameservers
                );
                if whois_str.to_lowercase().contains(&pattern_lower) {
                    results.add_whois(db_name, domain, &whois.registrar);
                }
            }
        }

        // Search hosts
        if data_type.is_none() || data_type == Some("hosts") {
            if let Ok(hosts) = qm.list_hosts() {
                for host in hosts {
                    let ip_str = host.ip.to_string();
                    let os_str = host.os_family.as_deref().unwrap_or("");
                    if ip_str.contains(&pattern_lower) || os_str.to_lowercase().contains(&pattern_lower) {
                        results.add_host(db_name, &ip_str, os_str);
                    }
                }
            }
        }

        // Search TLS scans
        if data_type.is_none() || data_type == Some("tls") {
            let host = db_name.trim_end_matches(".rdb");
            if let Ok(scans) = qm.list_tls_scans(host) {
                for scan in scans {
                    // Build searchable string from available TLS fields
                    let version_str = scan.negotiated_version.as_deref().unwrap_or("");
                    let cipher_str = scan.negotiated_cipher.as_deref().unwrap_or("");
                    let cert_subject = scan.certificate_chain.first()
                        .map(|c| c.subject.as_str())
                        .unwrap_or("");
                    let scan_str = format!(
                        "{} {} {} {}",
                        scan.host,
                        version_str,
                        cipher_str,
                        cert_subject
                    );
                    if scan_str.to_lowercase().contains(&pattern_lower) {
                        results.add_tls(
                            db_name,
                            &scan.host,
                            cert_subject,
                        );
                    }
                }
            }
        }

        // Search HTTP records
        if data_type.is_none() || data_type == Some("http") {
            let host = db_name.trim_end_matches(".rdb");
            if let Ok(records) = qm.list_http_records(host) {
                for record in records {
                    let headers_str = record
                        .headers
                        .iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join(" ");
                    if headers_str.to_lowercase().contains(&pattern_lower)
                        || record.url.to_lowercase().contains(&pattern_lower)
                    {
                        results.add_http(db_name, &record.url, record.status_code);
                    }
                }
            }
        }

        Ok(())
    }

    /// List all database files in current directory
    fn list_databases(&self, ctx: &CliContext) -> Result<(), String> {
        let databases = self.find_all_databases()?;
        let output_format = ctx.get_output_format();

        if databases.is_empty() {
            if output_format == OutputFormat::Human {
                Output::info("No database files found in current directory.");
                println!("\nRun a scan with --persist to create one:");
                println!("  rb recon domain subdomains example.com --persist");
            }
            return Ok(());
        }

        match output_format {
            OutputFormat::Json => {
                let items: Vec<_> = databases
                    .iter()
                    .filter_map(|p| {
                        p.file_name().and_then(|n| n.to_str()).map(|name| {
                            let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                            format!(r#"{{"name":"{}","size":{}}}"#, name, size)
                        })
                    })
                    .collect();
                println!("[{}]", items.join(","));
            }
            OutputFormat::Yaml => {
                println!("databases:");
                for path in &databases {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                        println!("  - name: {}", name);
                        println!("    size: {}", size);
                    }
                }
            }
            OutputFormat::Human => {
                Output::header("Available Databases");
                println!();
                println!("{:<40} {:>10}", "DATABASE", "SIZE");
                println!("{}", "─".repeat(52));
                for path in &databases {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                        let size_str = format_size(size);
                        println!("{:<40} {:>10}", name, size_str);
                    }
                }
                println!();
                Output::info(&format!("Found {} database(s)", databases.len()));
            }
        }

        Ok(())
    }

    /// Show statistics for a database
    fn show_stats(&self, ctx: &CliContext) -> Result<(), String> {
        // First check target, then fall back to --db flag
        let db_path: String = if let Some(target) = ctx.target.as_ref() {
            target.clone()
        } else if let Some(db_flag) = ctx.get_flag("db") {
            db_flag
        } else {
            return Err("Missing database path.\n\nUsage: rb search data stats <database.rdb>".to_string());
        };

        let path = PathBuf::from(&db_path);
        if !path.exists() {
            // Try adding .rdb extension
            let with_ext = PathBuf::from(format!("{}.rdb", db_path));
            if with_ext.exists() {
                return self.show_stats_for_path(&with_ext, ctx);
            }
            return Err(format!("Database file not found: {}", db_path));
        }

        self.show_stats_for_path(&path, ctx)
    }

    fn show_stats_for_path(&self, path: &PathBuf, ctx: &CliContext) -> Result<(), String> {
        let output_format = ctx.get_output_format();
        let db_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let domain = db_name.trim_end_matches(".rdb");

        let mut qm = QueryManager::open(path).map_err(|e| format!("Failed to open database: {}", e))?;

        let mut stats = DbStats::new(db_name.to_string());

        // Count subdomains
        if let Ok(subs) = qm.list_subdomains(domain) {
            stats.subdomain_count = subs.len();
        }

        // Count DNS records
        if let Ok(dns) = qm.list_dns_records(domain) {
            stats.dns_count = dns.len();
        }

        // Check WHOIS
        if let Ok(Some(_)) = qm.get_whois(domain) {
            stats.has_whois = true;
        }

        // Count hosts
        if let Ok(hosts) = qm.list_hosts() {
            stats.host_count = hosts.len();
        }

        // Count TLS scans
        if let Ok(tls) = qm.list_tls_scans(domain) {
            stats.tls_count = tls.len();
        }

        // Count HTTP records
        if let Ok(http) = qm.list_http_records(domain) {
            stats.http_count = http.len();
        }

        // File size
        stats.file_size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        match output_format {
            OutputFormat::Json => println!("{}", stats.to_json()),
            OutputFormat::Yaml => println!("{}", stats.to_yaml()),
            OutputFormat::Human => stats.print_human(),
        }

        Ok(())
    }

    /// Find all .rdb files in current directory
    fn find_all_databases(&self) -> Result<Vec<PathBuf>, String> {
        let cwd = env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?;

        let mut databases = Vec::new();
        if let Ok(entries) = fs::read_dir(&cwd) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("rdb") {
                    databases.push(path);
                }
            }
        }

        databases.sort_by(|a, b| {
            a.file_name()
                .and_then(|n| n.to_str())
                .cmp(&b.file_name().and_then(|n| n.to_str()))
        });

        Ok(databases)
    }
}

/// Search results container
struct SearchResults {
    pattern: String,
    subdomains: Vec<SearchMatch>,
    dns: Vec<SearchMatch>,
    whois: Vec<SearchMatch>,
    hosts: Vec<SearchMatch>,
    tls: Vec<SearchMatch>,
    http: Vec<SearchMatch>,
}

struct SearchMatch {
    database: String,
    value: String,
    extra: String,
}

impl SearchResults {
    fn new(pattern: String) -> Self {
        Self {
            pattern,
            subdomains: Vec::new(),
            dns: Vec::new(),
            whois: Vec::new(),
            hosts: Vec::new(),
            tls: Vec::new(),
            http: Vec::new(),
        }
    }

    fn add_subdomain(&mut self, db: &str, subdomain: &str) {
        self.subdomains.push(SearchMatch {
            database: db.to_string(),
            value: subdomain.to_string(),
            extra: String::new(),
        });
    }

    fn add_dns(&mut self, db: &str, domain: &str, record_type: &str) {
        self.dns.push(SearchMatch {
            database: db.to_string(),
            value: domain.to_string(),
            extra: record_type.to_string(),
        });
    }

    fn add_whois(&mut self, db: &str, domain: &str, registrar: &str) {
        self.whois.push(SearchMatch {
            database: db.to_string(),
            value: domain.to_string(),
            extra: registrar.to_string(),
        });
    }

    fn add_host(&mut self, db: &str, ip: &str, os: &str) {
        self.hosts.push(SearchMatch {
            database: db.to_string(),
            value: ip.to_string(),
            extra: os.to_string(),
        });
    }

    fn add_tls(&mut self, db: &str, host: &str, subject: &str) {
        self.tls.push(SearchMatch {
            database: db.to_string(),
            value: host.to_string(),
            extra: subject.to_string(),
        });
    }

    fn add_http(&mut self, db: &str, url: &str, status: u16) {
        self.http.push(SearchMatch {
            database: db.to_string(),
            value: url.to_string(),
            extra: status.to_string(),
        });
    }

    fn total_count(&self) -> usize {
        self.subdomains.len()
            + self.dns.len()
            + self.whois.len()
            + self.hosts.len()
            + self.tls.len()
            + self.http.len()
    }

    fn to_json(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!(r#""pattern":"{}""#, self.pattern));
        parts.push(format!(r#""total_matches":{}"#, self.total_count()));

        if !self.subdomains.is_empty() {
            let items: Vec<String> = self
                .subdomains
                .iter()
                .map(|m| format!(r#"{{"db":"{}","subdomain":"{}"}}"#, m.database, m.value))
                .collect();
            parts.push(format!(r#""subdomains":[{}]"#, items.join(",")));
        }

        if !self.dns.is_empty() {
            let items: Vec<String> = self
                .dns
                .iter()
                .map(|m| {
                    format!(
                        r#"{{"db":"{}","domain":"{}","type":"{}"}}"#,
                        m.database, m.value, m.extra
                    )
                })
                .collect();
            parts.push(format!(r#""dns":[{}]"#, items.join(",")));
        }

        if !self.whois.is_empty() {
            let items: Vec<String> = self
                .whois
                .iter()
                .map(|m| {
                    format!(
                        r#"{{"db":"{}","domain":"{}","registrar":"{}"}}"#,
                        m.database, m.value, m.extra
                    )
                })
                .collect();
            parts.push(format!(r#""whois":[{}]"#, items.join(",")));
        }

        if !self.hosts.is_empty() {
            let items: Vec<String> = self
                .hosts
                .iter()
                .map(|m| {
                    format!(
                        r#"{{"db":"{}","ip":"{}","os":"{}"}}"#,
                        m.database, m.value, m.extra
                    )
                })
                .collect();
            parts.push(format!(r#""hosts":[{}]"#, items.join(",")));
        }

        if !self.tls.is_empty() {
            let items: Vec<String> = self
                .tls
                .iter()
                .map(|m| {
                    format!(
                        r#"{{"db":"{}","host":"{}","subject":"{}"}}"#,
                        m.database, m.value, m.extra
                    )
                })
                .collect();
            parts.push(format!(r#""tls":[{}]"#, items.join(",")));
        }

        if !self.http.is_empty() {
            let items: Vec<String> = self
                .http
                .iter()
                .map(|m| {
                    format!(
                        r#"{{"db":"{}","url":"{}","status":{}}}"#,
                        m.database, m.value, m.extra
                    )
                })
                .collect();
            parts.push(format!(r#""http":[{}]"#, items.join(",")));
        }

        format!("{{{}}}", parts.join(","))
    }

    fn to_yaml(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("pattern: \"{}\"", self.pattern));
        lines.push(format!("total_matches: {}", self.total_count()));

        if !self.subdomains.is_empty() {
            lines.push("subdomains:".to_string());
            for m in &self.subdomains {
                lines.push(format!("  - db: {}", m.database));
                lines.push(format!("    subdomain: {}", m.value));
            }
        }

        if !self.dns.is_empty() {
            lines.push("dns:".to_string());
            for m in &self.dns {
                lines.push(format!("  - db: {}", m.database));
                lines.push(format!("    domain: {}", m.value));
                lines.push(format!("    type: {}", m.extra));
            }
        }

        if !self.whois.is_empty() {
            lines.push("whois:".to_string());
            for m in &self.whois {
                lines.push(format!("  - db: {}", m.database));
                lines.push(format!("    domain: {}", m.value));
                lines.push(format!("    registrar: {}", m.extra));
            }
        }

        if !self.hosts.is_empty() {
            lines.push("hosts:".to_string());
            for m in &self.hosts {
                lines.push(format!("  - db: {}", m.database));
                lines.push(format!("    ip: {}", m.value));
                lines.push(format!("    os: \"{}\"", m.extra));
            }
        }

        if !self.tls.is_empty() {
            lines.push("tls:".to_string());
            for m in &self.tls {
                lines.push(format!("  - db: {}", m.database));
                lines.push(format!("    host: {}", m.value));
                lines.push(format!("    subject: \"{}\"", m.extra));
            }
        }

        if !self.http.is_empty() {
            lines.push("http:".to_string());
            for m in &self.http {
                lines.push(format!("  - db: {}", m.database));
                lines.push(format!("    url: {}", m.value));
                lines.push(format!("    status: {}", m.extra));
            }
        }

        lines.join("\n")
    }

    fn print_human(&self) {
        Output::header(&format!("Search Results for '{}'", self.pattern));
        println!();

        let total = self.total_count();
        if total == 0 {
            Output::info("No matches found.");
            return;
        }

        if !self.subdomains.is_empty() {
            println!(
                "\x1b[1;36mSubdomains ({})\x1b[0m",
                self.subdomains.len()
            );
            println!("{}", "─".repeat(50));
            for m in &self.subdomains {
                println!("  \x1b[32m{}\x1b[0m  \x1b[2m({})\x1b[0m", m.value, m.database);
            }
            println!();
        }

        if !self.dns.is_empty() {
            println!("\x1b[1;36mDNS Records ({})\x1b[0m", self.dns.len());
            println!("{}", "─".repeat(50));
            for m in &self.dns {
                println!(
                    "  \x1b[32m{}\x1b[0m \x1b[33m{}\x1b[0m  \x1b[2m({})\x1b[0m",
                    m.value, m.extra, m.database
                );
            }
            println!();
        }

        if !self.whois.is_empty() {
            println!("\x1b[1;36mWHOIS Records ({})\x1b[0m", self.whois.len());
            println!("{}", "─".repeat(50));
            for m in &self.whois {
                println!(
                    "  \x1b[32m{}\x1b[0m → \x1b[33m{}\x1b[0m  \x1b[2m({})\x1b[0m",
                    m.value, m.extra, m.database
                );
            }
            println!();
        }

        if !self.hosts.is_empty() {
            println!("\x1b[1;36mHosts ({})\x1b[0m", self.hosts.len());
            println!("{}", "─".repeat(50));
            for m in &self.hosts {
                let os_display = if m.extra.is_empty() {
                    "unknown".to_string()
                } else {
                    m.extra.clone()
                };
                println!(
                    "  \x1b[32m{}\x1b[0m \x1b[33m{}\x1b[0m  \x1b[2m({})\x1b[0m",
                    m.value, os_display, m.database
                );
            }
            println!();
        }

        if !self.tls.is_empty() {
            println!("\x1b[1;36mTLS Certificates ({})\x1b[0m", self.tls.len());
            println!("{}", "─".repeat(50));
            for m in &self.tls {
                println!(
                    "  \x1b[32m{}\x1b[0m → \x1b[33m{}\x1b[0m  \x1b[2m({})\x1b[0m",
                    m.value, m.extra, m.database
                );
            }
            println!();
        }

        if !self.http.is_empty() {
            println!("\x1b[1;36mHTTP Records ({})\x1b[0m", self.http.len());
            println!("{}", "─".repeat(50));
            for m in &self.http {
                let status_color = match m.extra.parse::<u16>().unwrap_or(0) {
                    200..=299 => "\x1b[32m",
                    300..=399 => "\x1b[33m",
                    400..=499 => "\x1b[31m",
                    500..=599 => "\x1b[35m",
                    _ => "\x1b[0m",
                };
                println!(
                    "  {}[{}]\x1b[0m \x1b[36m{}\x1b[0m  \x1b[2m({})\x1b[0m",
                    status_color, m.extra, m.value, m.database
                );
            }
            println!();
        }

        Output::success(&format!("Found {} match(es) across {} data type(s)", total, self.count_types()));
    }

    fn count_types(&self) -> usize {
        let mut count = 0;
        if !self.subdomains.is_empty() {
            count += 1;
        }
        if !self.dns.is_empty() {
            count += 1;
        }
        if !self.whois.is_empty() {
            count += 1;
        }
        if !self.hosts.is_empty() {
            count += 1;
        }
        if !self.tls.is_empty() {
            count += 1;
        }
        if !self.http.is_empty() {
            count += 1;
        }
        count
    }
}

/// Database statistics
struct DbStats {
    name: String,
    file_size: u64,
    subdomain_count: usize,
    dns_count: usize,
    has_whois: bool,
    host_count: usize,
    tls_count: usize,
    http_count: usize,
}

impl DbStats {
    fn new(name: String) -> Self {
        Self {
            name,
            file_size: 0,
            subdomain_count: 0,
            dns_count: 0,
            has_whois: false,
            host_count: 0,
            tls_count: 0,
            http_count: 0,
        }
    }

    fn to_json(&self) -> String {
        format!(
            r#"{{"name":"{}","file_size":{},"subdomains":{},"dns_records":{},"whois":{},"hosts":{},"tls_scans":{},"http_records":{}}}"#,
            self.name,
            self.file_size,
            self.subdomain_count,
            self.dns_count,
            self.has_whois,
            self.host_count,
            self.tls_count,
            self.http_count
        )
    }

    fn to_yaml(&self) -> String {
        format!(
            "name: {}\nfile_size: {}\nsubdomains: {}\ndns_records: {}\nwhois: {}\nhosts: {}\ntls_scans: {}\nhttp_records: {}",
            self.name,
            self.file_size,
            self.subdomain_count,
            self.dns_count,
            self.has_whois,
            self.host_count,
            self.tls_count,
            self.http_count
        )
    }

    fn print_human(&self) {
        Output::header(&format!("Database: {}", self.name));
        println!();
        println!("{:<20} {:>10}", "SEGMENT", "COUNT");
        println!("{}", "─".repeat(32));
        println!("{:<20} {:>10}", "Subdomains", self.subdomain_count);
        println!("{:<20} {:>10}", "DNS Records", self.dns_count);
        println!(
            "{:<20} {:>10}",
            "WHOIS",
            if self.has_whois { "Yes" } else { "No" }
        );
        println!("{:<20} {:>10}", "Hosts", self.host_count);
        println!("{:<20} {:>10}", "TLS Scans", self.tls_count);
        println!("{:<20} {:>10}", "HTTP Records", self.http_count);
        println!("{}", "─".repeat(32));
        println!("{:<20} {:>10}", "File Size", format_size(self.file_size));
    }
}

/// Format file size in human-readable form
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
    }

    #[test]
    fn test_search_results_count() {
        let mut results = SearchResults::new("test".to_string());
        assert_eq!(results.total_count(), 0);

        results.add_subdomain("test.rdb", "api.example.com");
        assert_eq!(results.total_count(), 1);

        results.add_dns("test.rdb", "example.com", "A");
        assert_eq!(results.total_count(), 2);
    }
}
