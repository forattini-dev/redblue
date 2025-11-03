/// TLS/SSL security testing command
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::tls::auditor::{CipherStrength, Severity, TlsAuditor};

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
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("timeout", "Connection timeout in seconds").with_default("10"),
            Flag::new("port", "Target port").with_default("443"),
            Flag::new("persist", "Save results to binary database (.rdb file)"),
            Flag::new("no-persist", "Don't save results (overrides config)"),
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
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "audit" => self.audit(ctx),
            "ciphers" => self.ciphers(ctx),
            "vuln" => self.vuln(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(verb, &["audit", "ciphers", "vuln"])
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
        _ctx: &CliContext,
        _host: &str,
        _result: &crate::modules::tls::auditor::TlsAuditResult,
    ) -> Result<(), String> {
        // TODO: Implement TLS audit persistence
        // For now, TLS audit results are not persisted to .rdb files
        // This will be implemented in a future update
        Ok(())
    }
}
