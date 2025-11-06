// Magic scan command - The most intelligent way to scan
// Usage: rb <target>  (automatically detects type and runs appropriate scans)

use crate::cli::{output::Output, CliContext};
use crate::config;
use crate::config::presets::{Module, ScanPreset};
use crate::config::yaml::YamlConfig;
use crate::modules::ct_logs::CTLogsClient;
use crate::modules::network::scanner::{PortScanResult, PortScanner};
use crate::modules::recon::harvester::Harvester;
use crate::protocols::dns::{DnsClient, DnsRecordType};
use crate::protocols::http::HttpClient;
use crate::protocols::whois::WhoisClient;
use crate::storage::session::SessionFile;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const DNS_ENUM_WORDS: &[&str] = &[
    "www", "mail", "ftp", "dev", "test", "api", "vpn", "stage", "admin", "portal", "beta",
    "secure", "infra", "gw", "db",
];

struct PhaseResult {
    summary: String,
    details: Vec<String>,
}

impl PhaseResult {
    fn new(summary: String, details: Vec<String>) -> Self {
        Self { summary, details }
    }
}

pub struct MagicScan {
    target: String,
    preset: ScanPreset,
    yaml_config: Option<YamlConfig>,
    session: SessionFile,
}

impl MagicScan {
    /// Create new magic scan
    pub fn new(
        target: String,
        command_args: &[String],
        preset_flag: Option<&str>,
    ) -> Result<Self, String> {
        // Try to load YAML config from current directory
        let yaml_config = YamlConfig::load_from_cwd_cached().cloned();

        // Determine preset (CLI flag > YAML > default)
        let preset = if let Some(preset_name) = preset_flag {
            ScanPreset::from_name(preset_name).unwrap_or_default()
        } else if let Some(ref config) = yaml_config {
            if let Some(ref preset_name) = config.preset {
                ScanPreset::from_name(preset_name).unwrap_or_default()
            } else {
                ScanPreset::default()
            }
        } else {
            ScanPreset::default()
        };

        // Create session file
        let session = SessionFile::create(&target, command_args)?;

        Ok(Self {
            target,
            preset,
            yaml_config,
            session,
        })
    }

    /// Execute magic scan
    pub fn run(&self) -> Result<(), String> {
        let start = Instant::now();

        Output::header(&format!("🔴🔵 RedBlue Magic Scan: {}", self.target));
        Output::info(&format!(
            "Preset: {} ({})",
            self.preset.name, self.preset.description
        ));

        if self.yaml_config.is_some() {
            Output::success("✓ Loaded config from .redblue.yaml");
        }

        // Show session file location
        Output::info(&format!(
            "💾 Saving results to: {}",
            self.session.path().display()
        ));

        println!();

        // Phase 1: Passive reconnaissance
        if self.has_passive_modules() {
            self.run_passive_phase()?;
        }

        // Phase 2: Stealth active scanning
        if self.has_stealth_modules() {
            self.run_stealth_phase()?;
        }

        // Phase 3: Aggressive scanning
        if self.has_aggressive_modules() {
            self.run_aggressive_phase()?;
        }

        let elapsed = start.elapsed();
        println!();
        Output::success(&format!("✓ Scan complete in {:.2}s", elapsed.as_secs_f64()));

        // Mark session as complete
        self.session.mark_complete(elapsed.as_secs_f64())?;
        Output::info(&format!(
            "💾 Results saved to: {}",
            self.session.path().display()
        ));

        Ok(())
    }

    fn has_passive_modules(&self) -> bool {
        self.preset.has_module(&Module::DnsPassive)
            || self.preset.has_module(&Module::WhoisLookup)
            || self.preset.has_module(&Module::CertTransparency)
            || self.preset.has_module(&Module::SearchEngines)
            || self.preset.has_module(&Module::ArchiveOrg)
    }

    fn has_stealth_modules(&self) -> bool {
        self.preset.has_module(&Module::TlsCert)
            || self.preset.has_module(&Module::HttpHeaders)
            || self.preset.has_module(&Module::DnsEnumeration)
            || self.preset.has_module(&Module::PortScanCommon)
    }

    fn has_aggressive_modules(&self) -> bool {
        self.preset.has_module(&Module::PortScanFull)
            || self.preset.has_module(&Module::DirFuzzing)
            || self.preset.has_module(&Module::VulnScanning)
            || self.preset.has_module(&Module::WebCrawling)
    }

    /// Phase 1: Passive reconnaissance (zero contact)
    fn run_passive_phase(&self) -> Result<(), String> {
        self.session
            .append_section("Phase 1: Passive Reconnaissance")?;
        Output::phase("Phase 1: Passive Reconnaissance");
        println!("  ℹ  100% OSINT - no direct contact with target\n");

        // DNS Passive
        if self.preset.has_module(&Module::DnsPassive) {
            Output::task_start("DNS Records");
            match self.collect_dns_records() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session
                        .append_result("passive", "dns", "success", &outcome.summary)?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("passive", "dns", "error", &err)?;
                }
            }
        }

        // WHOIS
        if self.preset.has_module(&Module::WhoisLookup) {
            Output::task_start("WHOIS Lookup");
            match self.perform_whois_lookup() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session
                        .append_result("passive", "whois", "success", &outcome.summary)?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("passive", "whois", "error", &err)?;
                }
            }
        }

        // Certificate Transparency
        if self.preset.has_module(&Module::CertTransparency) {
            Output::task_start("Certificate Transparency Logs");
            match self.query_ct_logs() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session.append_result(
                        "passive",
                        "ct_logs",
                        "success",
                        &outcome.summary,
                    )?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("passive", "ct_logs", "error", &err)?;
                }
            }
        }

        // Search Engines
        if self.preset.has_module(&Module::SearchEngines) {
            Output::task_start("Search Engine Dorking");
            match self.harvest_osint() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session
                        .append_result("passive", "search", "success", &outcome.summary)?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("passive", "search", "error", &err)?;
                }
            }
        }

        // Archive.org
        if self.preset.has_module(&Module::ArchiveOrg) {
            Output::task_start("Wayback Machine");
            match self.query_archive_org() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session.append_result(
                        "passive",
                        "archive",
                        "success",
                        &outcome.summary,
                    )?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("passive", "archive", "error", &err)?;
                }
            }
        }

        println!();
        Ok(())
    }

    fn collect_dns_records(&self) -> Result<PhaseResult, String> {
        let host = self.target_hostname();
        if host.is_empty() {
            return Err("Target host is empty".to_string());
        }

        let client = self.build_dns_client();
        let queries = [
            (DnsRecordType::A, "A"),
            (DnsRecordType::AAAA, "AAAA"),
            (DnsRecordType::MX, "MX"),
            (DnsRecordType::NS, "NS"),
            (DnsRecordType::TXT, "TXT"),
        ];

        let mut summary_parts = Vec::new();
        let mut details = Vec::new();

        for (record_type, label) in queries {
            match client.query(&host, record_type) {
                Ok(answers) => {
                    summary_parts.push(format!("{}:{}", label, answers.len()));
                    for answer in answers.iter().take(5) {
                        details.push(format!(
                            "{} {} → {}",
                            label,
                            answer.name,
                            answer.display_value()
                        ));
                    }
                    if answers.len() > 5 {
                        details.push(format!("{} … ({} records total)", label, answers.len()));
                    }
                }
                Err(err) => {
                    summary_parts.push(format!("{}:err", label));
                    details.push(format!("{} lookup failed: {}", label, err));
                }
            }
        }

        let summary = summary_parts.join(" | ");
        Ok(PhaseResult::new(summary, details))
    }

    fn perform_whois_lookup(&self) -> Result<PhaseResult, String> {
        if !self.is_probable_domain() {
            return Err("Target does not look like a domain name".to_string());
        }

        let host = self.target_hostname();
        let client = WhoisClient::new().with_timeout(Duration::from_secs(15));
        let result = client.query(&host)?;

        let registrar = result
            .registrar
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        let expires = result
            .expiration_date
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());

        let mut details = Vec::new();

        if let Some(created) = result.creation_date.clone() {
            details.push(format!("Created: {}", created));
        }
        if let Some(updated) = result.updated_date.clone() {
            details.push(format!("Updated: {}", updated));
        }
        if !result.name_servers.is_empty() {
            let ns_preview = result
                .name_servers
                .iter()
                .take(5)
                .map(|ns| ns.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            details.push(format!("Name servers: {}", ns_preview));
        }
        if !result.status.is_empty() {
            let status_preview = result
                .status
                .iter()
                .take(5)
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            details.push(format!("Status: {}", status_preview));
        }

        let summary = format!("Registrar: {} | Expires: {}", registrar, expires);
        Ok(PhaseResult::new(summary, details))
    }

    fn query_ct_logs(&self) -> Result<PhaseResult, String> {
        if !self.is_probable_domain() {
            return Err("Target does not look like a domain name".to_string());
        }

        let host = self.target_hostname();
        let client = CTLogsClient::new();
        let subdomains = match client.query_subdomains(&host) {
            Ok(list) => list,
            Err(err) => {
                if err.contains("No certificates") {
                    Vec::new()
                } else {
                    return Err(err);
                }
            }
        };

        let count = subdomains.len();
        let summary = if count > 0 {
            format!("{} subdomains from CT logs", count)
        } else {
            "No Certificate Transparency hits".to_string()
        };

        let mut details = Vec::new();
        for entry in subdomains.iter().take(10) {
            details.push(entry.clone());
        }
        if count > 10 {
            details.push(format!("... and {} more", count - 10));
        }

        Ok(PhaseResult::new(summary, details))
    }

    fn harvest_osint(&self) -> Result<PhaseResult, String> {
        if !self.is_probable_domain() {
            return Err("Target does not look like a domain name".to_string());
        }

        let host = self.target_hostname();
        let harvester = Harvester::new();
        let result = harvester.harvest(&host)?;

        let summary = format!(
            "Emails: {} | Subdomains: {} | URLs: {}",
            result.emails.len(),
            result.subdomains.len(),
            result.urls.len()
        );

        let mut details = Vec::new();

        for email in result.emails.iter().take(5) {
            details.push(format!("Email: {}", email));
        }
        if result.emails.len() > 5 {
            details.push(format!("... {} more emails", result.emails.len() - 5));
        }

        for subdomain in result.subdomains.iter().take(5) {
            details.push(format!("Subdomain: {}", subdomain));
        }
        if result.subdomains.len() > 5 {
            details.push(format!(
                "... {} more subdomains",
                result.subdomains.len() - 5
            ));
        }

        for url in result.urls.iter().take(5) {
            details.push(format!("URL: {}", url));
        }
        if result.urls.len() > 5 {
            details.push(format!("... {} more URLs", result.urls.len() - 5));
        }

        Ok(PhaseResult::new(summary, details))
    }

    fn query_archive_org(&self) -> Result<PhaseResult, String> {
        if !self.is_probable_domain() {
            return Err("Target does not look like a domain name".to_string());
        }

        let host = self.target_hostname();
        let client = HttpClient::new();
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?url={}/*&output=txt&limit=20&filter=statuscode:200",
            host
        );

        let response = client
            .get(&url)
            .map_err(|e| format!("Wayback request failed: {}", e))?;

        if response.status_code != 200 {
            return Err(format!(
                "Wayback Machine returned HTTP {}",
                response.status_code
            ));
        }

        let body = String::from_utf8_lossy(&response.body);
        let mut count = 0usize;
        let mut details = Vec::new();

        for line in body.lines() {
            if line.trim().is_empty() || line.starts_with("urlkey") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            count += 1;
            if details.len() < 5 {
                details.push(format!("{} → {}", parts[1], parts[2]));
            }
        }

        if count > 5 {
            details.push(format!("... and {} more snapshots", count - 5));
        }

        let summary = if count > 0 {
            format!("{} snapshots via Wayback Machine", count)
        } else {
            "No Wayback snapshots available".to_string()
        };

        Ok(PhaseResult::new(summary, details))
    }

    fn inspect_tls_certificate(&self) -> Result<PhaseResult, String> {
        let (host, port) = self.parse_host_port(443);
        if host.is_empty() {
            return Err("Target host is empty".to_string());
        }

        let connector = Self::build_ssl_connector()?;
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr).map_err(|e| format!("TCP connect failed: {}", e))?;
        let timeout = Duration::from_secs(10);
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let ssl_stream = connector
            .connect(&host, stream)
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        let cert = ssl_stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| "Server did not present a certificate".to_string())?;

        self.summarize_certificate(&cert, &host)
    }

    fn analyze_http_headers(&self) -> Result<PhaseResult, String> {
        let client = HttpClient::new();
        let mut attempts = Vec::new();
        if self.target.trim_start().starts_with("http://")
            || self.target.trim_start().starts_with("https://")
        {
            attempts.push(self.target.clone());
        } else {
            attempts.push(self.ensure_url("https"));
            attempts.push(self.ensure_url("http"));
        }

        let mut last_error = None;

        for url in attempts {
            match client.get(&url) {
                Ok(response) => {
                    let summary = format!(
                        "{} {} ({} headers)",
                        response.status_code,
                        response.status_text,
                        response.headers.len()
                    );

                    let mut details = Vec::new();
                    for header in [
                        "Server",
                        "Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                    ] {
                        if let Some(value) = response.headers.get(header) {
                            details.push(format!("{}: {}", header, value));
                        }
                    }
                    if details.is_empty() {
                        details.push("No security headers detected".to_string());
                    }

                    return Ok(PhaseResult::new(summary, details));
                }
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| "HTTP request failed".to_string()))
    }

    fn enumerate_subdomains(&self) -> Result<PhaseResult, String> {
        if !self.is_probable_domain() {
            return Err("Target does not look like a domain name".to_string());
        }

        let host = self.target_hostname();
        let client = self.build_dns_client();
        let mut found = Vec::new();

        for prefix in DNS_ENUM_WORDS {
            let subdomain = format!("{}.{}", prefix, host);
            if let Ok(answers) = client.query(&subdomain, DnsRecordType::A) {
                if !answers.is_empty() {
                    let ips: Vec<String> = answers.iter().filter_map(|a| a.as_ip()).collect();
                    found.push((subdomain, ips));
                }
            }
        }

        let count = found.len();
        let summary = if count > 0 {
            format!("{} subdomains resolved from wordlist", count)
        } else {
            "No subdomains resolved from wordlist".to_string()
        };

        let mut details = Vec::new();
        for (sub, ips) in found.into_iter().take(10) {
            if ips.is_empty() {
                details.push(sub);
            } else {
                details.push(format!("{} → {}", sub, ips.join(", ")));
            }
        }
        if count > 10 {
            details.push(format!("... and {} more", count - 10));
        }

        Ok(PhaseResult::new(summary, details))
    }

    fn port_scan_common(&self) -> Result<PhaseResult, String> {
        let ip = self.resolve_target_ip()?;
        let scanner = PortScanner::new(ip);
        let start = Instant::now();
        let results = scanner.scan_common();
        Ok(Self::summarize_port_results(
            results,
            start.elapsed(),
            "common",
        ))
    }

    fn port_scan_full(&self) -> Result<PhaseResult, String> {
        let ip = self.resolve_target_ip()?;
        let scanner = PortScanner::new(ip);
        let start = Instant::now();
        let end_port = 4096u16;
        let results = scanner.scan_range(1, end_port);
        let mut outcome = Self::summarize_port_results(results, start.elapsed(), "ports 1-4096");
        if !outcome.summary.contains("ports 1-4096") {
            outcome.summary = format!("{} (ports 1-4096)", outcome.summary);
        }
        Ok(outcome)
    }

    fn summarize_port_results(
        results: Vec<PortScanResult>,
        elapsed: Duration,
        scope: &str,
    ) -> PhaseResult {
        let open: Vec<&PortScanResult> = results.iter().filter(|r| r.is_open).collect();
        let summary = if open.is_empty() {
            format!(
                "No open {} ports detected ({:.2}s)",
                scope,
                elapsed.as_secs_f64()
            )
        } else {
            let ports = open
                .iter()
                .map(|r| r.port.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{} open {} port(s): {} ({:.2}s)",
                open.len(),
                scope,
                ports,
                elapsed.as_secs_f64()
            )
        };

        let mut details = Vec::new();
        for entry in open.iter().take(10) {
            let mut line = format!("Port {}", entry.port);
            if let Some(service) = &entry.service {
                line.push_str(&format!(" ({})", service));
            }
            if let Some(banner) = &entry.banner {
                line.push_str(&format!(" → {}", banner));
            }
            details.push(line);
        }
        if open.len() > 10 {
            details.push(format!("... and {} more", open.len() - 10));
        }

        PhaseResult::new(summary, details)
    }

    fn build_dns_client(&self) -> DnsClient {
        let cfg = config::get();
        DnsClient::new(&cfg.network.dns_resolver).with_timeout(cfg.network.dns_timeout_ms)
    }

    fn resolve_target_ip(&self) -> Result<IpAddr, String> {
        let host = self.target_hostname();
        if host.is_empty() {
            return Err("Target host is empty".to_string());
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }

        let endpoint = format!("{}:0", host);
        let mut addrs = endpoint
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {}: {}", host, e))?;

        addrs
            .find(|addr| matches!(addr.ip(), IpAddr::V4(_) | IpAddr::V6(_)))
            .map(|addr| addr.ip())
            .ok_or_else(|| format!("No IP addresses resolved for {}", host))
    }

    fn raw_host(&self) -> String {
        let mut host = self.target.trim();
        if let Some(idx) = host.find("://") {
            host = &host[idx + 3..];
        }
        if let Some(idx) = host.find('/') {
            host = &host[..idx];
        }
        host.trim().trim_end_matches('.').to_string()
    }

    fn target_hostname(&self) -> String {
        let raw = self.raw_host();
        if raw.starts_with('[') && raw.ends_with(']') && raw.len() > 2 {
            return raw[1..raw.len() - 1].to_string();
        }
        if raw.matches(':').count() == 1 {
            let idx = raw.rfind(':').unwrap();
            if raw[..idx].contains(':') {
                return raw;
            }
            if raw[idx + 1..].parse::<u16>().is_ok() {
                return raw[..idx].to_string();
            }
        }
        raw
    }

    fn parse_host_port(&self, default_port: u16) -> (String, u16) {
        let raw = self.raw_host();
        if raw.starts_with('[') && raw.ends_with(']') {
            let host = raw[1..raw.len() - 1].to_string();
            return (host, default_port);
        }
        if raw.matches(':').count() == 1 {
            let idx = raw.rfind(':').unwrap();
            if raw[..idx].contains(':') {
                return (raw, default_port);
            }
            if let Ok(port) = raw[idx + 1..].parse::<u16>() {
                return (raw[..idx].to_string(), port);
            }
        }
        (raw, default_port)
    }

    fn ensure_url(&self, scheme: &str) -> String {
        let trimmed = self.target.trim();
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("{}://{}", scheme, trimmed)
        }
    }

    fn is_probable_domain(&self) -> bool {
        let host = self.target_hostname();
        host.chars().any(|c| c.is_ascii_alphabetic()) && host.contains('.')
    }

    fn build_ssl_connector() -> Result<SslConnector, String> {
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("Failed to create TLS connector: {}", e))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| format!("Failed to set min TLS version: {}", e))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("Failed to set max TLS version: {}", e))?;
        builder.set_verify(SslVerifyMode::NONE);
        Ok(builder.build())
    }

    fn summarize_certificate(
        &self,
        cert: &X509,
        fallback_host: &str,
    ) -> Result<PhaseResult, String> {
        let subject = Self::extract_name(cert.subject_name(), Nid::COMMONNAME)
            .unwrap_or_else(|| fallback_host.to_string());
        let issuer = Self::extract_name(cert.issuer_name(), Nid::COMMONNAME)
            .unwrap_or_else(|| "Unknown".to_string());

        let not_before = cert.not_before().to_string();
        let not_after = cert.not_after().to_string();

        let sans = cert
            .subject_alt_names()
            .map(|names| {
                let mut list = Vec::new();
                for name in names {
                    if let Some(dns) = name.dnsname() {
                        list.push(dns.to_string());
                    } else if let Some(ip) = name.ipaddress() {
                        if let Some(formatted) = Self::format_ip_address(ip) {
                            list.push(formatted);
                        }
                    }
                }
                list
            })
            .unwrap_or_default();

        let summary = format!(
            "Subject: {} | Issuer: {} | Expires: {}",
            subject, issuer, not_after
        );

        let mut details = vec![
            format!("Not before: {}", not_before),
            format!("Not after: {}", not_after),
        ];

        if !sans.is_empty() {
            details.push(format!(
                "SANs: {}",
                sans.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
            ));
            if sans.len() > 8 {
                details.push(format!("... {} more SAN entries", sans.len() - 8));
            }
        }

        Ok(PhaseResult::new(summary, details))
    }

    fn extract_name(name: &openssl::x509::X509NameRef, nid: Nid) -> Option<String> {
        name.entries_by_nid(nid)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|data| data.to_string())
    }

    fn format_ip_address(bytes: &[u8]) -> Option<String> {
        match bytes.len() {
            4 => Some(IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()),
            16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Some(IpAddr::from(arr).to_string())
            }
            _ => None,
        }
    }

    fn print_details(details: &[String]) {
        for detail in details.iter().take(8) {
            Output::item("", detail);
        }
        if details.len() > 8 {
            Output::item("", &format!("... and {} more", details.len() - 8));
        }
    }

    /// Phase 2: Stealth active scanning (minimal contact)
    fn run_stealth_phase(&self) -> Result<(), String> {
        self.session.append_section("Phase 2: Stealth Scanning")?;
        Output::phase("Phase 2: Stealth Scanning");
        println!("  ℹ  Minimal contact - looks like normal traffic\n");

        // TLS Certificate
        if self.preset.has_module(&Module::TlsCert) {
            Output::task_start("TLS Certificate Check");
            match self.inspect_tls_certificate() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session.append_result(
                        "stealth",
                        "tls_cert",
                        "success",
                        &outcome.summary,
                    )?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("stealth", "tls_cert", "error", &err)?;
                }
            }
        }

        // HTTP Headers
        if self.preset.has_module(&Module::HttpHeaders) {
            Output::task_start("HTTP Headers Analysis");
            match self.analyze_http_headers() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session.append_result(
                        "stealth",
                        "http_headers",
                        "success",
                        &outcome.summary,
                    )?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("stealth", "http_headers", "error", &err)?;
                }
            }
        }

        // DNS Enumeration
        if self.preset.has_module(&Module::DnsEnumeration) {
            Output::task_start("Subdomain Enumeration (stealth)");
            match self.enumerate_subdomains() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session.append_result(
                        "stealth",
                        "dns_enum",
                        "success",
                        &outcome.summary,
                    )?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("stealth", "dns_enum", "error", &err)?;
                }
            }
        }

        // Common ports
        if self.preset.has_module(&Module::PortScanCommon) {
            Output::task_start("Port Scan (common ports only)");
            match self.port_scan_common() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session.append_result(
                        "stealth",
                        "port_scan",
                        "success",
                        &outcome.summary,
                    )?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("stealth", "port_scan", "error", &err)?;
                }
            }
        }

        println!();
        Ok(())
    }

    /// Phase 3: Aggressive scanning (full speed)
    fn run_aggressive_phase(&self) -> Result<(), String> {
        self.session
            .append_section("Phase 3: Aggressive Scanning")?;
        Output::phase("Phase 3: Aggressive Scanning");
        println!("  ⚠  Full-speed scanning - may trigger alerts\n");

        // Full port scan
        if self.preset.has_module(&Module::PortScanFull) {
            Output::task_start("Full Port Scan (1-65535)");
            match self.port_scan_full() {
                Ok(outcome) => {
                    Output::task_done(&outcome.summary);
                    Self::print_details(&outcome.details);
                    self.session.append_result(
                        "aggressive",
                        "port_scan_full",
                        "success",
                        &outcome.summary,
                    )?;
                }
                Err(err) => {
                    Output::task_done("failed");
                    Output::warning(&format!("    {}", err));
                    self.session
                        .append_result("aggressive", "port_scan_full", "error", &err)?;
                }
            }
        }

        // Directory fuzzing
        if self.preset.has_module(&Module::DirFuzzing) {
            Output::task_start("Directory Fuzzing");
            let message =
                "Skipped (directory fuzzing module not yet implemented in core)".to_string();
            Output::task_done("skipped");
            Output::warning(&format!("    {}", message));
            self.session
                .append_result("aggressive", "dir_fuzz", "skipped", &message)?;
        }

        // Vulnerability scanning
        if self.preset.has_module(&Module::VulnScanning) {
            Output::task_start("Vulnerability Scanning");
            let message = "Skipped (web vulnerability scanner scheduled in roadmap)".to_string();
            Output::task_done("skipped");
            Output::warning(&format!("    {}", message));
            self.session
                .append_result("aggressive", "vuln_scan", "skipped", &message)?;
        }

        // Web crawling
        if self.preset.has_module(&Module::WebCrawling) {
            Output::task_start("Web Crawling");
            let message = "Skipped (web crawler subsystem pending implementation)".to_string();
            Output::task_done("skipped");
            Output::warning(&format!("    {}", message));
            self.session
                .append_result("aggressive", "web_crawl", "skipped", &message)?;
        }

        println!();
        Ok(())
    }
}

/// Execute magic scan from CLI
pub fn execute(ctx: &CliContext) -> Result<(), String> {
    // When magic scan is triggered, the URL/domain is in ctx.domain
    // (because it's the first positional argument)
    let target = ctx
        .domain
        .as_ref()
        .or(ctx.target.as_ref())
        .ok_or("No target specified")?;

    // Get preset from --preset flag
    let preset_flag = ctx.get_flag("preset").map(|s| s.as_str());

    let scan = MagicScan::new(target.to_string(), &ctx.raw, preset_flag)?;
    scan.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_scan_creation() {
        let args: Vec<String> = vec![];
        let scan = MagicScan::new("example.com".to_string(), &args, None);
        assert!(scan.is_ok());
        let scan = scan.unwrap();
        assert_eq!(scan.target, "example.com");
        assert_eq!(scan.preset.name, "stealth"); // Default
    }
}
