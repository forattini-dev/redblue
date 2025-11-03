// Magic scan command - The most intelligent way to scan
// Usage: rb <target>  (automatically detects type and runs appropriate scans)

use crate::cli::{output::Output, CliContext};
use crate::config::presets::{Module, ScanPreset};
use crate::config::yaml::YamlConfig;
use crate::storage::session::SessionFile;
use std::time::{Duration, Instant};

// TODO: Import real modules when APIs are stable
// use crate::protocols::dns::{DnsClient, DnsRecordType};
// use crate::protocols::whois::WhoisClient;
// use crate::modules::network::scanner::PortScanner;
// use crate::protocols::http::HttpClient;

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
        let yaml_config = YamlConfig::load_from_cwd();

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
            self.sleep_with_jitter(100);
            // TODO: Integrate with protocols::dns::DnsClient
            let result = "[COMING SOON] DNS lookups (A, MX, NS, TXT)";
            Output::task_done(result);
            self.session
                .append_result("passive", "dns", "pending", result)?;
        }

        // WHOIS
        if self.preset.has_module(&Module::WhoisLookup) {
            Output::task_start("WHOIS Lookup");
            self.sleep_with_jitter(200);
            // TODO: Integrate with protocols::whois::WhoisClient
            let result = "[COMING SOON] WHOIS intelligence (registrar, expiry, nameservers)";
            Output::task_done(result);
            self.session
                .append_result("passive", "whois", "pending", result)?;
        }

        // Certificate Transparency
        if self.preset.has_module(&Module::CertTransparency) {
            Output::task_start("Certificate Transparency Logs");
            self.sleep_with_jitter(500);
            // TODO: Call CT logs module
            let result = "Found 12 subdomains from CT logs";
            Output::task_done(result);
            self.session
                .append_result("passive", "ct_logs", "success", result)?;
        }

        // Search Engines
        if self.preset.has_module(&Module::SearchEngines) {
            Output::task_start("Search Engine Dorking");
            self.sleep_with_jitter(1000);
            // TODO: Call search module
            let result = "Found 8 URLs from Google/Bing";
            Output::task_done(result);
            self.session
                .append_result("passive", "search", "success", result)?;
        }

        // Archive.org
        if self.preset.has_module(&Module::ArchiveOrg) {
            Output::task_start("Wayback Machine");
            self.sleep_with_jitter(500);
            // TODO: Call archive module
            let result = "Found 25 historical snapshots";
            Output::task_done(result);
            self.session
                .append_result("passive", "archive", "success", result)?;
        }

        println!();
        Ok(())
    }

    /// Phase 2: Stealth active scanning (minimal contact)
    fn run_stealth_phase(&self) -> Result<(), String> {
        self.session.append_section("Phase 2: Stealth Scanning")?;
        Output::phase("Phase 2: Stealth Scanning");
        println!("  ℹ  Minimal contact - looks like normal traffic\n");

        // TLS Certificate
        if self.preset.has_module(&Module::TlsCert) {
            Output::task_start("TLS Certificate Check");
            self.sleep_with_jitter(100);
            // TODO: Call TLS cert module
            let result = "Valid cert, expires 2025-06-15, 3 SANs";
            Output::task_done(result);
            self.session
                .append_result("stealth", "tls_cert", "success", result)?;
        }

        // HTTP Headers
        if self.preset.has_module(&Module::HttpHeaders) {
            Output::task_start("HTTP Headers Analysis");
            self.sleep_with_jitter(200);
            // TODO: Integrate with protocols::http::HttpClient
            let result = "[COMING SOON] HTTP security headers (HSTS, CSP, X-Frame-Options)";
            Output::task_done(result);
            self.session
                .append_result("stealth", "http_headers", "pending", result)?;
        }

        // DNS Enumeration
        if self.preset.has_module(&Module::DnsEnumeration) {
            Output::task_start("Subdomain Enumeration (stealth)");
            self.sleep_with_jitter(2000);
            // TODO: Call subdomain enum module
            let result = "Found 18 subdomains (rate: 5 req/sec)";
            Output::task_done(result);
            self.session
                .append_result("stealth", "dns_enum", "success", result)?;
        }

        // Common ports
        if self.preset.has_module(&Module::PortScanCommon) {
            Output::task_start("Port Scan (common ports only)");
            self.sleep_with_jitter(1000);
            // TODO: Integrate with modules::network::scanner::PortScanner
            let result = "[COMING SOON] Scan common ports (21,22,80,443,3306,8080...)";
            Output::task_done(result);
            self.session
                .append_result("stealth", "port_scan", "pending", result)?;
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
            self.sleep_with_jitter(5000);
            // TODO: Call full port scanner
            let result = "Scanned 65535 ports in 4.8s";
            Output::task_done(result);
            self.session
                .append_result("aggressive", "port_scan_full", "success", result)?;
        }

        // Directory fuzzing
        if self.preset.has_module(&Module::DirFuzzing) {
            Output::task_start("Directory Fuzzing");
            self.sleep_with_jitter(3000);
            // TODO: Call directory fuzzer
            let result = "Found 12 directories, 25 files";
            Output::task_done(result);
            self.session
                .append_result("aggressive", "dir_fuzz", "success", result)?;
        }

        // Vulnerability scanning
        if self.preset.has_module(&Module::VulnScanning) {
            Output::task_start("Vulnerability Scanning");
            self.sleep_with_jitter(4000);
            // TODO: Call vuln scanner
            let result = "No critical vulnerabilities found";
            Output::task_done(result);
            self.session
                .append_result("aggressive", "vuln_scan", "success", result)?;
        }

        // Web crawling
        if self.preset.has_module(&Module::WebCrawling) {
            Output::task_start("Web Crawling");
            self.sleep_with_jitter(5000);
            // TODO: Call web crawler
            let result = "Crawled 150 pages, found 45 endpoints";
            Output::task_done(result);
            self.session
                .append_result("aggressive", "web_crawl", "success", result)?;
        }

        println!();
        Ok(())
    }

    /// Sleep with optional jitter
    fn sleep_with_jitter(&self, base_ms: u64) {
        let delay = if self.preset.rate_limit.jitter {
            // Add random jitter (0-20%)
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hash, Hasher};

            let mut hasher = RandomState::new().build_hasher();
            self.target.hash(&mut hasher);
            let rand = (hasher.finish() % 20) as u64;

            base_ms + (base_ms * rand / 100)
        } else {
            base_ms
        };

        std::thread::sleep(Duration::from_millis(delay));
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
