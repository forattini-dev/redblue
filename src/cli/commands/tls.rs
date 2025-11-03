/// TLS/SSL security testing command
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::tls::auditor::{CipherStrength, Severity, TlsAuditor};
use crate::storage::client::{PersistenceManager, QueryManager};
use crate::protocols::tls_cert::CertificateInfo;
use crate::protocols::x509::parse_x509_time;
use crate::storage::schema::{
    TlsCertRecord, TlsCipherRecord, TlsCipherStrength, TlsScanRecord, TlsSeverity,
    TlsVersionRecord, TlsVulnerabilityRecord,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TlsCommand;

impl Command for TlsCommand {
    fn domain(&self) -> &str {
        "tls"
    }

    fn resource(&self) -> &str {
        "security"
    }

    fn description(&self) -> &str {
        "TLS/SSL security testing and cipher enumeration"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "audit",
                summary: "Full TLS security audit (sslyze replacement)",
                usage: "rb tls security audit <host[:port]> [--timeout SEC]",
            },
            Route {
                verb: "ciphers",
                summary: "Enumerate supported cipher suites (sslscan replacement)",
                usage: "rb tls security ciphers <host[:port]>",
            },
            Route {
                verb: "vuln",
                summary: "Check for known TLS vulnerabilities",
                usage: "rb tls security vuln <host[:port]>",
            },
            // RESTful verbs - query stored data
            Route {
                verb: "list",
                summary: "List all stored TLS scans for a host",
                usage: "rb tls security list <host> [--db <file>]",
            },
            Route {
                verb: "get",
                summary: "Show stored TLS certificate chain for a host",
                usage: "rb tls security get <host>:cert [--db <file>]",
            },
            Route {
                verb: "describe",
                summary: "Summarize stored TLS findings for a host",
                usage: "rb tls security describe <host> [--db <file>]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("timeout", "Connection timeout in seconds").with_default("10"),
            Flag::new("port", "Target port").with_default("443"),
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
            ("Full TLS audit", "rb tls security audit google.com"),
            (
                "Audit with custom port",
                "rb tls security audit example.com:8443",
            ),
            (
                "Cipher enumeration only",
                "rb tls security ciphers google.com",
            ),
            (
                "Vulnerability scan",
                "rb tls security vuln example.com --timeout 15",
            ),
            ("List stored TLS scans", "rb tls security list example.com"),
            (
                "Show TLS summary from database",
                "rb tls security describe example.com",
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
            "audit" => self.audit(ctx),
            "ciphers" => self.ciphers(ctx),
            "vuln" => self.vuln(ctx),
            "list" => self.list_tls(ctx),
            "get" => self.get_tls(ctx),
            "describe" => self.describe_tls(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(
                        verb,
                        &["audit", "ciphers", "vuln", "list", "get", "describe"]
                    )
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl TlsCommand {
    fn audit(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security audit <HOST[:PORT]>\nExample: rb tls security audit google.com",
        )?;

        let (host, port) = Self::parse_host_port(target, 443)?;
        let timeout = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10);

        Output::header(&format!("TLS Security Audit: {}:{}", host, port));

        let auditor = TlsAuditor::new().with_timeout(std::time::Duration::from_secs(timeout));

        Output::spinner_start("Running TLS audit");
        let result = auditor
            .audit(&host, port)
            .map_err(|e| format!("TLS audit failed: {}", e))?;
        Output::spinner_done();

        // Display TLS versions
        Output::section("Supported TLS Versions");
        for version in &result.supported_versions {
            if version.supported {
                Output::success(&format!("  ✓ {}", version.version));
            } else if let Some(ref err) = version.error {
                Output::dim(&format!("  ✗ {} ({})", version.version, err));
            }
        }

        // Display cipher suites
        if !result.supported_ciphers.is_empty() {
            Output::section(&format!(
                "Supported Cipher Suites ({})",
                result.supported_ciphers.len()
            ));
            for cipher in &result.supported_ciphers {
                let color = match cipher.strength {
                    CipherStrength::Strong => "\x1b[32m", // Green
                    CipherStrength::Medium => "\x1b[33m", // Yellow
                    CipherStrength::Weak => "\x1b[31m",   // Red
                };
                println!(
                    "  {}● {:?} - {} (0x{:04X})\x1b[0m",
                    color, cipher.strength, cipher.name, cipher.code
                );
            }
        }

        // Display vulnerabilities
        if !result.vulnerabilities.is_empty() {
            Output::section(&format!(
                "Vulnerabilities Found ({})",
                result.vulnerabilities.len()
            ));
            for vuln in &result.vulnerabilities {
                let color = match vuln.severity {
                    Severity::Critical => "\x1b[35m", // Magenta
                    Severity::High => "\x1b[31m",     // Red
                    Severity::Medium => "\x1b[33m",   // Yellow
                    Severity::Low => "\x1b[36m",      // Cyan
                };
                println!("  {}{} [{}]\x1b[0m", color, vuln.name, vuln.severity);
                println!("    {}", vuln.description);
            }
        } else {
            Output::success("\nNo known vulnerabilities detected");
        }

        // Certificate validation
        Output::section("Certificate Validation");
        if result.certificate_valid {
            Output::success("  ✓ Certificate chain is valid");
        } else {
            Output::error("  ✗ Certificate validation failed");
        }

        if !result.certificate_chain.is_empty() {
            Output::dim(&format!(
                "  Chain length: {} certificate(s)",
                result.certificate_chain.len()
            ));
        }

        // Persistence
        self.save_if_enabled(ctx, &host, &result)?;

        Ok(())
    }

    fn ciphers(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security ciphers <HOST[:PORT]>\nExample: rb tls security ciphers google.com",
        )?;

        let (host, port) = Self::parse_host_port(target, 443)?;
        let timeout = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10);

        Output::header(&format!("TLS Cipher Enumeration: {}:{}", host, port));

        let auditor = TlsAuditor::new().with_timeout(std::time::Duration::from_secs(timeout));

        Output::spinner_start("Enumerating cipher suites");
        let result = auditor
            .audit(&host, port)
            .map_err(|e| format!("Cipher enumeration failed: {}", e))?;
        Output::spinner_done();

        if result.supported_ciphers.is_empty() {
            Output::warning("No cipher suites detected");
            return Ok(());
        }

        // Group by strength
        let mut strong = Vec::new();
        let mut medium = Vec::new();
        let mut weak = Vec::new();

        for cipher in &result.supported_ciphers {
            match cipher.strength {
                CipherStrength::Strong => strong.push(cipher),
                CipherStrength::Medium => medium.push(cipher),
                CipherStrength::Weak => weak.push(cipher),
            }
        }

        Output::section(&format!(
            "Cipher Suites Summary (Total: {})",
            result.supported_ciphers.len()
        ));
        println!(
            "  \x1b[32m● Strong:\x1b[0m  {}\n  \x1b[33m● Medium:\x1b[0m  {}\n  \x1b[31m● Weak:\x1b[0m    {}",
            strong.len(),
            medium.len(),
            weak.len()
        );

        if !strong.is_empty() {
            Output::section("Strong Ciphers");
            for cipher in strong {
                println!("  \x1b[32m✓\x1b[0m {} (0x{:04X})", cipher.name, cipher.code);
            }
        }

        if !medium.is_empty() {
            Output::section("Medium Strength Ciphers");
            for cipher in medium {
                println!("  \x1b[33m●\x1b[0m {} (0x{:04X})", cipher.name, cipher.code);
            }
        }

        if !weak.is_empty() {
            Output::section("Weak Ciphers (AVOID!)");
            for cipher in weak {
                println!("  \x1b[31m✗\x1b[0m {} (0x{:04X})", cipher.name, cipher.code);
            }
        }

        self.save_if_enabled(ctx, &host, &result)?;

        Ok(())
    }

    fn vuln(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security vuln <HOST[:PORT]>\nExample: rb tls security vuln example.com",
        )?;

        let (host, port) = Self::parse_host_port(target, 443)?;
        let timeout = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10);

        Output::header(&format!("TLS Vulnerability Scan: {}:{}", host, port));

        let auditor = TlsAuditor::new().with_timeout(std::time::Duration::from_secs(timeout));

        Output::spinner_start("Scanning for TLS vulnerabilities");
        let result = auditor
            .audit(&host, port)
            .map_err(|e| format!("Vulnerability scan failed: {}", e))?;
        Output::spinner_done();

        if result.vulnerabilities.is_empty() {
            Output::success("\n✓ No known TLS vulnerabilities detected");
            Output::dim("  The TLS configuration appears secure");
            return Ok(());
        }

        // Group by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();

        for vuln in &result.vulnerabilities {
            match vuln.severity {
                Severity::Critical => critical.push(vuln),
                Severity::High => high.push(vuln),
                Severity::Medium => medium.push(vuln),
                Severity::Low => low.push(vuln),
            }
        }

        Output::section(&format!(
            "Vulnerabilities Summary (Total: {})",
            result.vulnerabilities.len()
        ));
        println!(
            "  \x1b[35m● Critical:\x1b[0m {}\n  \x1b[31m● High:\x1b[0m     {}\n  \x1b[33m● Medium:\x1b[0m   {}\n  \x1b[36m● Low:\x1b[0m      {}",
            critical.len(),
            high.len(),
            medium.len(),
            low.len()
        );

        if !critical.is_empty() {
            Output::section("CRITICAL Vulnerabilities");
            for vuln in critical {
                println!("  \x1b[35m✗ {}\x1b[0m", vuln.name);
                println!("    {}", vuln.description);
            }
        }

        if !high.is_empty() {
            Output::section("HIGH Severity Vulnerabilities");
            for vuln in high {
                println!("  \x1b[31m✗ {}\x1b[0m", vuln.name);
                println!("    {}", vuln.description);
            }
        }

        if !medium.is_empty() {
            Output::section("MEDIUM Severity Vulnerabilities");
            for vuln in medium {
                println!("  \x1b[33m● {}\x1b[0m", vuln.name);
                println!("    {}", vuln.description);
            }
        }

        if !low.is_empty() {
            Output::section("LOW Severity Vulnerabilities");
            for vuln in low {
                println!("  \x1b[36m○ {}\x1b[0m", vuln.name);
                println!("    {}", vuln.description);
            }
        }

        self.save_if_enabled(ctx, &host, &result)?;

        Ok(())
    }

    fn parse_host_port(target: &str, default_port: u16) -> Result<(String, u16), String> {
        if let Some(colon_pos) = target.rfind(':') {
            let host = target[..colon_pos].to_string();
            let port_str = &target[colon_pos + 1..];
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", port_str))?;
            Ok((host, port))
        } else {
            Ok((target.to_string(), default_port))
        }
    }

    fn save_if_enabled(
        &self,
        ctx: &CliContext,
        host: &str,
        result: &crate::modules::tls::auditor::TlsAuditResult,
    ) -> Result<(), String> {
        let persist_flag = if ctx.has_flag("persist") {
            Some(true)
        } else if ctx.has_flag("no-persist") {
            Some(false)
        } else {
            None
        };

        let mut pm = PersistenceManager::new(host, persist_flag)?;

        if pm.is_enabled() {
            let record = self.build_tls_scan_record(host, result);
            pm.add_tls_scan(record)?;
            if let Some(path) = pm.commit()? {
                Output::success(&format!("TLS results saved to {}", path.display()));
            }
        }

        Ok(())
    }

    fn build_tls_scan_record(
        &self,
        host: &str,
        result: &crate::modules::tls::auditor::TlsAuditResult,
    ) -> TlsScanRecord {
        let timestamp = Self::current_timestamp();

        let versions = result
            .supported_versions
            .iter()
            .map(|version| TlsVersionRecord {
                version: version.version.clone(),
                supported: version.supported,
                error: version.error.clone(),
            })
            .collect();

        let ciphers = result
            .supported_ciphers
            .iter()
            .map(|cipher| TlsCipherRecord {
                name: cipher.name.clone(),
                code: cipher.code,
                strength: Self::convert_cipher_strength(&cipher.strength),
            })
            .collect();

        let vulnerabilities = result
            .vulnerabilities
            .iter()
            .map(|vuln| TlsVulnerabilityRecord {
                name: vuln.name.clone(),
                severity: Self::convert_severity(&vuln.severity),
                description: vuln.description.clone(),
            })
            .collect();

        let certificate_chain = result
            .certificate_chain
            .iter()
            .map(|cert| self.convert_certificate(host, cert, timestamp))
            .collect();

        TlsScanRecord {
            host: host.to_string(),
            port: result.port,
            timestamp,
            negotiated_version: result.negotiated_version.clone(),
            negotiated_cipher: result.negotiated_cipher.clone(),
            negotiated_cipher_code: result.negotiated_cipher_code,
            negotiated_cipher_strength: result
                .negotiated_cipher_strength
                .as_ref()
                .map(Self::convert_cipher_strength)
                .unwrap_or(TlsCipherStrength::Medium),
            certificate_valid: result.certificate_valid,
            versions,
            ciphers,
            vulnerabilities,
            certificate_chain,
        }
    }

    fn convert_certificate(
        &self,
        host: &str,
        cert: &CertificateInfo,
        timestamp: u32,
    ) -> TlsCertRecord {
        TlsCertRecord {
            domain: host.to_string(),
            issuer: cert.issuer.clone(),
            subject: cert.subject.clone(),
            serial_number: cert.serial_number.clone(),
            signature_algorithm: cert.signature_algorithm.clone(),
            public_key_algorithm: cert.public_key_algorithm.clone(),
            version: cert.version,
            not_before: Self::x509_timestamp(&cert.valid_from),
            not_after: Self::x509_timestamp(&cert.valid_until),
            sans: cert.san.clone(),
            self_signed: cert.is_self_signed,
            timestamp,
        }
    }

    fn convert_cipher_strength(strength: &CipherStrength) -> TlsCipherStrength {
        match strength {
            CipherStrength::Strong => TlsCipherStrength::Strong,
            CipherStrength::Medium => TlsCipherStrength::Medium,
            CipherStrength::Weak => TlsCipherStrength::Weak,
        }
    }

    fn convert_severity(severity: &Severity) -> TlsSeverity {
        match severity {
            Severity::Low => TlsSeverity::Low,
            Severity::Medium => TlsSeverity::Medium,
            Severity::High => TlsSeverity::High,
            Severity::Critical => TlsSeverity::Critical,
        }
    }

    fn x509_timestamp(value: &str) -> u32 {
        parse_x509_time(value)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs() as u32)
            .unwrap_or(0)
    }

    fn current_timestamp() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs() as u32
    }

    fn format_timestamp(epoch: u32) -> String {
        if epoch == 0 {
            "unknown".to_string()
        } else {
            format!("{}", epoch)
        }
    }

    fn render_cipher_strength(strength: TlsCipherStrength) -> &'static str {
        match strength {
            TlsCipherStrength::Weak => "WEAK",
            TlsCipherStrength::Medium => "MEDIUM",
            TlsCipherStrength::Strong => "STRONG",
        }
    }

    fn render_severity(severity: TlsSeverity) -> &'static str {
        match severity {
            TlsSeverity::Low => "LOW",
            TlsSeverity::Medium => "MEDIUM",
            TlsSeverity::High => "HIGH",
            TlsSeverity::Critical => "CRITICAL",
        }
    }

    // ============================================================================
    // RESTful Commands - Query stored TLS data from .rdb files
    // ============================================================================

    fn list_tls(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or(
            "Missing target host.\nUsage: rb tls security list <HOST> [--db <file>]\nExample: rb tls security list google.com",
        )?;

        let db_path = self.get_db_path(ctx, host)?;

        let mut query =
            QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        let mut scans = query
            .list_tls_scans(host)
            .map_err(|e| format!("Query failed: {}", e))?;

        if scans.is_empty() {
            Output::warning(&format!("No TLS scans found for {} in database", host));
            Output::dim(&format!("  Database: {}", db_path.display()));
            return Ok(());
        }

        scans.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Output::header(&format!("TLS Scans for {}", host));
        Output::dim(&format!("Database: {}\n", db_path.display()));

        println!(
            "{:<12}  {:<10}  {:<30}  {}",
            "Timestamp", "Version", "Cipher", "Certificate"
        );
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        for scan in &scans {
            let version = scan.negotiated_version.as_deref().unwrap_or("unknown");
            let cipher = scan.negotiated_cipher.as_deref().unwrap_or("n/a");
            let cert_status = if scan.certificate_valid {
                "valid"
            } else {
                "invalid"
            };
            println!(
                "{:<12}  {:<10}  {:<30}  {}",
                Self::format_timestamp(scan.timestamp),
                version,
                cipher,
                cert_status
            );
        }

        println!("\n  Total: {} scan(s)", scans.len());
        Ok(())
    }

    fn get_tls(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security get <HOST>:cert [--db <file>]\nExample: rb tls security get google.com:cert",
        )?;

        let parts: Vec<&str> = target.split(':').collect();
        if parts.len() != 2 || parts[1] != "cert" {
            return Err(format!(
                "Invalid target format: {}\nExpected format: <host>:cert\nExample: google.com:cert",
                target
            ));
        }

        let host = parts[0];
        let db_path = self.get_db_path(ctx, host)?;

        let mut query =
            QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        let scan = query
            .latest_tls_scan(host)
            .map_err(|e| format!("Query failed: {}", e))?;

        let Some(scan) = scan else {
            Output::warning(&format!(
                "No TLS data found for {} in database",
                host
            ));
            Output::dim(&format!("  Database: {}", db_path.display()));
            return Err("TLS scan not found".to_string());
        };

        if scan.certificate_chain.is_empty() {
            Output::warning("TLS scan does not contain certificate chain data");
            return Err("No certificate data available".to_string());
        }

        Output::header(&format!("TLS Certificate Chain for {}", host));
        Output::dim(&format!("Database: {}\n", db_path.display()));

        for (index, cert) in scan.certificate_chain.iter().enumerate() {
            Output::section(&format!("Certificate #{}", index + 1));
            Output::item("Subject", &cert.subject);
            Output::item("Issuer", &cert.issuer);
            Output::item("Serial Number", &cert.serial_number);
            Output::item("Version", &format!("{}", cert.version));
            Output::item("Signature Algorithm", &cert.signature_algorithm);
            Output::item("Public Key Algorithm", &cert.public_key_algorithm);
            Output::item("Valid From", &Self::format_timestamp(cert.not_before));
            Output::item("Valid Until", &Self::format_timestamp(cert.not_after));
            Output::item("Self-Signed", if cert.self_signed { "yes" } else { "no" });

            if !cert.sans.is_empty() {
                println!("  Subject Alternative Names:");
                for san in &cert.sans {
                    println!("    • {}", san);
                }
            }

            println!();
        }

        Ok(())
    }

    fn describe_tls(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or(
            "Missing target host.\nUsage: rb tls security describe <HOST> [--db <file>]\nExample: rb tls security describe google.com",
        )?;

        let db_path = self.get_db_path(ctx, host)?;

        let mut query =
            QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        let scan = query
            .latest_tls_scan(host)
            .map_err(|e| format!("Query failed: {}", e))?;

        let Some(scan) = scan else {
            Output::warning(&format!("No TLS data found for {} in database", host));
            Output::dim(&format!("  Database: {}", db_path.display()));
            return Ok(());
        };

        Output::header(&format!("TLS Security Summary for {}", host));
        Output::dim(&format!("Database: {}\n", db_path.display()));

        Output::section("Negotiated Parameters");
        Output::item(
            "Version",
            scan.negotiated_version.as_deref().unwrap_or("unknown"),
        );
        Output::item("Cipher", scan.negotiated_cipher.as_deref().unwrap_or("n/a"));
        Output::item(
            "Cipher Strength",
            Self::render_cipher_strength(scan.negotiated_cipher_strength),
        );
        Output::item(
            "Certificate Valid",
            if scan.certificate_valid { "yes" } else { "no" },
        );

        if !scan.versions.is_empty() {
            Output::section("Version Support Matrix");
            for version in &scan.versions {
                let status = if version.supported { "✓" } else { "✗" };
                if let Some(error) = &version.error {
                    println!("  {} {} ({})", status, version.version, error);
                } else {
                    println!("  {} {}", status, version.version);
                }
            }
        }

        if !scan.ciphers.is_empty() {
            Output::section("Supported Ciphers");
            for cipher in &scan.ciphers {
                println!(
                    "  {:<32} 0x{:04X} ({})",
                    cipher.name,
                    cipher.code,
                    Self::render_cipher_strength(cipher.strength)
                );
            }
        }

        if !scan.vulnerabilities.is_empty() {
            Output::section("Vulnerabilities");
            for vuln in &scan.vulnerabilities {
                println!("  [{}] {}", Self::render_severity(vuln.severity), vuln.name);
                println!("    {}", vuln.description);
            }
        } else {
            Output::success("No vulnerabilities recorded for this scan");
        }

        Ok(())
    }

    fn get_db_path(&self, ctx: &CliContext, host: &str) -> Result<std::path::PathBuf, String> {
        use std::env;
        use std::path::PathBuf;

        if let Some(db_path) = ctx.get_flag("db") {
            return Ok(PathBuf::from(db_path));
        }

        let cwd =
            env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?;

        let base = host
            .trim_start_matches("www.")
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split(':')
            .next()
            .unwrap_or(host)
            .to_lowercase();

        let candidate = cwd.join(format!("{}.rdb", &base));
        if candidate.exists() {
            return Ok(candidate);
        }

        Err(format!(
            "Database file not found: {}.rdb\nRun `rb tls security audit {}` first to collect data",
            base, host
        ))
    }
}
