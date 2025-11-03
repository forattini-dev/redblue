/// Network/ports command - Port scanning and network discovery
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{
    format::OutputFormat,
    output::{Output, ProgressBar},
    validator::Validator,
    CliContext,
};
use crate::config;
use crate::intelligence::{banner_analysis, service_detection, timing_analysis};
use crate::modules::network::scanner::PortScanner;
use crate::persistence::PersistenceManager;
use std::collections::HashMap;
use std::sync::Arc;

pub struct ScanCommand;

impl Command for ScanCommand {
    fn domain(&self) -> &str {
        "network"
    }

    fn resource(&self) -> &str {
        "ports"
    }

    fn description(&self) -> &str {
        "Port scanning and network discovery"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "scan",
                summary: "Scan a host using predefined port presets",
                usage: "rb network ports scan <host> [--preset common]",
            },
            Route {
                verb: "range",
                summary: "Scan an arbitrary port range on a host",
                usage: "rb network ports range <host> <start> <end>",
            },
            Route {
                verb: "subnet",
                summary: "Discover and scan all hosts in a subnet (CIDR notation)",
                usage: "rb network ports subnet <cidr> [--preset common]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        let cfg = config::get();
        let threads_default = cfg.network.threads.to_string();
        let timeout_default = cfg.network.timeout_ms.to_string();

        vec![
            Flag::new("threads", "Number of concurrent threads")
                .with_short('t')
                .with_default(&threads_default),
            Flag::new("timeout", "Timeout in milliseconds").with_default(&timeout_default),
            Flag::new("preset", "Use port preset (common|full|web)").with_short('p'),
            Flag::new(
                "fast",
                "Fast mode (masscan-style): 1000 threads, 300ms timeout",
            )
            .with_short('f'),
            Flag::new("output", "Output format (text|json)")
                .with_short('o')
                .with_default("text"),
            Flag::new("persist", "Save results to binary database (.rdb file)"),
            Flag::new("no-persist", "Don't save results (overrides config)"),
            Flag::new(
                "intel",
                "Gather intelligence on discovered services (timing, banners, OS hints)",
            )
            .with_short('i'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Scan common ports",
                "rb network ports scan 192.168.1.1 --preset common",
            ),
            (
                "Scan and save to database",
                "rb network ports scan 192.168.1.1 --preset common --persist",
            ),
            (
                "Fast scan (masscan-style)",
                "rb network ports scan 10.0.0.1 --fast",
            ),
            (
                "Fast scan with more threads",
                "rb network ports scan 10.0.0.1 --threads 500",
            ),
            (
                "Scan specific range",
                "rb network ports range 192.168.1.1 80 443",
            ),
            (
                "Full port scan (slow)",
                "rb network ports range 192.168.1.1 1 65535 --timeout 500",
            ),
            (
                "Fast full scan (masscan-style)",
                "rb network ports range 192.168.1.1 1 65535 --fast",
            ),
            (
                "JSON output",
                "rb network ports scan 127.0.0.1 --preset common -o json",
            ),
            (
                "Intelligence gathering",
                "rb network ports scan 192.168.1.1 --preset common --intel",
            ),
            (
                "Subnet discovery and scan",
                "rb network ports subnet 192.168.1.0/24 --preset common",
            ),
            (
                "Subnet scan with persistence",
                "rb network ports subnet 10.0.0.0/24 --preset common --persist",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "scan" => self.scan_ports(ctx),
            "range" => self.scan_range(ctx),
            "subnet" => self.scan_subnet(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(verb, &["scan", "range", "subnet"])
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl ScanCommand {
    fn scan_ports(&self, ctx: &CliContext) -> Result<(), String> {
        let target_str = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network ports scan <HOST>\nExample: rb network ports scan 192.168.1.1",
        )?;

        // Clone target_str for later use in persistence
        let target_str_owned = target_str.to_string();
        let target = Validator::resolve_host(target_str)?;

        // Fast mode overrides threads and timeout
        let (threads, timeout) = if ctx.has_flag("fast") {
            (1000, 300) // masscan-style: 1000 threads, 300ms timeout
        } else {
            let cfg = config::get();
            let default_threads = cfg.network.threads.to_string();
            let default_timeout = cfg.network.timeout_ms.to_string();
            let threads = ctx
                .get_flag_or("threads", &default_threads)
                .parse::<usize>()
                .map_err(|_| "Invalid threads value")?;

            let timeout = ctx
                .get_flag_or("timeout", &default_timeout)
                .parse::<u64>()
                .map_err(|_| "Invalid timeout value")?;

            (threads, timeout)
        };

        let preset = ctx
            .get_flag("preset")
            .map(|s| s.as_str())
            .unwrap_or("common");

        let format = ctx.get_output_format();

        let scanner = PortScanner::new(target)
            .with_threads(threads)
            .with_timeout(timeout);

        let total_ports = match preset {
            "common" => PortScanner::get_common_ports().len(),
            "full" => 65_535,
            "web" => 6,
            _ => 0,
        };

        let progress_label = format!("Scanning {}", target_str);
        let progress = if format == OutputFormat::Human {
            Some(Arc::new(Output::progress_bar(
                progress_label,
                total_ports as u64,
                true,
            )))
        } else {
            None
        };

        let results = match preset {
            "common" => {
                let progress_clone = progress.as_ref().map(|p| {
                    let cloned: Arc<ProgressBar> = Arc::clone(p);
                    cloned as Arc<dyn crate::modules::network::scanner::ScanProgress>
                });
                scanner.scan_common_with_progress(progress_clone)
            }
            "full" => {
                let progress_clone = progress.as_ref().map(|p| {
                    let cloned: Arc<ProgressBar> = Arc::clone(p);
                    cloned as Arc<dyn crate::modules::network::scanner::ScanProgress>
                });
                scanner.scan_range_with_progress(1, 65_535, progress_clone)
            }
            "web" => {
                let progress_clone = progress.as_ref().map(|p| {
                    let cloned: Arc<ProgressBar> = Arc::clone(p);
                    cloned as Arc<dyn crate::modules::network::scanner::ScanProgress>
                });
                scanner.scan_ports_with_progress(&[80, 443, 8080, 8443, 3000, 5000], progress_clone)
            }
            _ => {
                return Err(format!(
                    "Unknown preset: {}\nAvailable presets: common, full, web",
                    preset
                ))
            }
        };

        if let Some(progress_bar) = progress {
            progress_bar.finish();
        }

        let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();

        // Database persistence
        let persist_flag = if ctx.has_flag("persist") {
            Some(true)
        } else if ctx.has_flag("no-persist") {
            Some(false)
        } else {
            None
        };

        let mut pm = PersistenceManager::new(&target_str_owned, persist_flag)?;

        // Save port scan results to database
        if pm.is_enabled() {
            for result in &open_ports {
                // Convert service name to service ID (simplified)
                let service_id = match result.service.as_deref() {
                    Some("http") => 1,
                    Some("https") => 2,
                    Some("ssh") => 3,
                    Some("ftp") => 4,
                    Some("smtp") => 5,
                    Some("mysql") => 6,
                    _ => 0, // unknown
                };

                // Convert IpAddr to u32 (IPv4 only for now)
                if let std::net::IpAddr::V4(ipv4) = target {
                    let ip_u32 = u32::from(ipv4);
                    if let Err(e) = pm.add_port_scan(ip_u32, result.port, 1, service_id) {
                        // Log error but don't fail the scan
                        eprintln!("Warning: Failed to save to database: {}", e);
                    }
                }
            }
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"target\": \"{}\",", target);
            println!("  \"preset\": \"{}\",", preset);
            println!("  \"open_count\": {},", open_ports.len());
            println!("  \"ports\": [");
            for (i, result) in open_ports.iter().enumerate() {
                let comma = if i < open_ports.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"port\": {},", result.port);
                println!(
                    "      \"service\": \"{}\",",
                    result.service.as_deref().unwrap_or("unknown")
                );
                if let Some(banner) = &result.banner {
                    let banner_escaped = banner
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', "\\n");
                    println!("      \"banner\": \"{}\"", banner_escaped);
                } else {
                    println!("      \"banner\": null");
                }
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("target: {}", target);
            println!("preset: {}", preset);
            println!("open_count: {}", open_ports.len());
            println!("ports:");
            for result in &open_ports {
                println!("  - port: {}", result.port);
                println!(
                    "    service: {}",
                    result.service.as_deref().unwrap_or("unknown")
                );
                if let Some(banner) = &result.banner {
                    println!("    banner: \"{}\"", banner.replace('"', "\\\""));
                } else {
                    println!("    banner: null");
                }
            }
            return Ok(());
        }

        // Human output
        if open_ports.is_empty() {
            Output::warning("No open ports found");

            // Commit database even if no results
            if let Some(db_path) = pm.commit()? {
                Output::success(&format!("Database saved to {}", db_path.display()));
            }

            return Ok(());
        }

        Output::header(&format!("Scan: {} ({} open)", target, open_ports.len()));

        // Check if intelligence gathering is enabled
        let intel_enabled = ctx.has_flag("intel");

        for result in open_ports {
            let service = result
                .service
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            let port_service = format!("{}/{}", result.port, service);

            if let Some(banner) = &result.banner {
                let banner_display = truncate_banner(banner, 60);
                println!("  \x1b[32m●\x1b[0m {:<20} {}", port_service, banner_display);
            } else {
                println!("  \x1b[32m●\x1b[0m {}", port_service);
            }

            // Gather and display intelligence if flag is set
            if intel_enabled {
                if let Some(intel) = gather_port_intelligence(
                    &target_str_owned,
                    result.port,
                    result.service.as_deref(),
                    result.banner.as_deref(),
                ) {
                    // Display vendor and version
                    if let Some(vendor) = &intel.vendor {
                        let version_str = intel
                            .version
                            .as_ref()
                            .map(|v| format!(" {}", v))
                            .unwrap_or_default();
                        println!("    \x1b[36m└─\x1b[0m Vendor: {}{}", vendor, version_str);
                    }

                    // Display OS hint
                    if let Some(os) = &intel.os_hint {
                        println!("    \x1b[36m└─\x1b[0m OS: {}", os);
                    }

                    // Display timing information
                    if let Some(timing) = &intel.timing {
                        let conn_time_ms = timing.connection_time.as_millis();
                        if let Some(resp_time) = timing.first_response_time {
                            let resp_time_ms = resp_time.as_millis();
                            println!(
                                "    \x1b[36m└─\x1b[0m Timing: conn={}ms, resp={}ms",
                                conn_time_ms, resp_time_ms
                            );
                        } else {
                            println!("    \x1b[36m└─\x1b[0m Timing: conn={}ms", conn_time_ms);
                        }
                    }

                    // Display confidence
                    let confidence_pct = (intel.confidence * 100.0) as u8;
                    if confidence_pct > 30 {
                        println!("    \x1b[36m└─\x1b[0m Confidence: {}%", confidence_pct);
                    }
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

    fn scan_range(&self, ctx: &CliContext) -> Result<(), String> {
        let target_str = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network ports range <HOST> <START> <END>\nExample: rb network ports range 192.168.1.1 1 1024",
        )?;

        let target = Validator::resolve_host(target_str)?;

        let start_str = ctx
            .args
            .get(0)
            .ok_or("Missing start port.\nUsage: rb network ports range <HOST> <START> <END>")?;
        let start = Validator::validate_port(start_str)?;

        let end_str = ctx
            .args
            .get(1)
            .ok_or("Missing end port.\nUsage: rb network ports range <HOST> <START> <END>")?;
        let end = Validator::validate_port(end_str)?;

        Validator::validate_port_range(start, end)?;

        // Fast mode overrides threads and timeout
        let (threads, timeout) = if ctx.has_flag("fast") {
            (1000, 300) // masscan-style: 1000 threads, 300ms timeout
        } else {
            let cfg = config::get();
            let default_threads = cfg.network.threads.to_string();
            let default_timeout = cfg.network.timeout_ms.to_string();
            let threads = ctx
                .get_flag_or("threads", &default_threads)
                .parse::<usize>()
                .map_err(|_| "Invalid threads value")?;

            let timeout = ctx
                .get_flag_or("timeout", &default_timeout)
                .parse::<u64>()
                .map_err(|_| "Invalid timeout value")?;

            (threads, timeout)
        };

        Output::header("Port Range Scan");
        Output::item("Target", &target.to_string());
        Output::item("Range", &format!("{}-{}", start, end));
        if ctx.has_flag("fast") {
            Output::item("Mode", "FAST (masscan-style)");
        }
        Output::item("Threads", &threads.to_string());
        Output::item("Timeout", &format!("{}ms", timeout));
        println!();

        let scanner = PortScanner::new(target)
            .with_threads(threads)
            .with_timeout(timeout);

        let format = ctx.get_output_format();
        let total_ports = (end - start + 1) as u64;
        let progress_label = format!("Scanning {}", target_str);
        let progress = if format == OutputFormat::Human {
            Some(Arc::new(Output::progress_bar(
                progress_label,
                total_ports,
                true,
            )))
        } else {
            None
        };

        let progress_for_scan = progress.as_ref().map(|p| {
            let cloned: Arc<ProgressBar> = Arc::clone(p);
            cloned as Arc<dyn crate::modules::network::scanner::ScanProgress>
        });

        let results = scanner.scan_range_with_progress(start, end, progress_for_scan);

        if let Some(progress_bar) = progress {
            progress_bar.finish();
        }

        let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();

        if open_ports.is_empty() {
            Output::warning("No open ports found");
            return Ok(());
        }

        Output::subheader(&format!("Open ports ({}):", open_ports.len()));
        println!();

        Output::table_header(&["PORT", "STATE", "SERVICE", "BANNER"]);
        for result in open_ports {
            let service = result
                .service
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let port_display = result.port.to_string();
            let banner_display = result
                .banner
                .as_ref()
                .map(|b| truncate_banner(b, 40))
                .unwrap_or_else(|| "-".to_string());
            Output::table_row(&[
                port_display.as_str(),
                "open",
                service,
                banner_display.as_str(),
            ]);
        }

        println!();
        Output::success("Scan completed");

        Ok(())
    }

    fn scan_subnet(&self, ctx: &CliContext) -> Result<(), String> {
        let cidr = ctx.target.as_ref().ok_or(
            "Missing CIDR notation.\nUsage: rb network ports subnet <CIDR>\nExample: rb network ports subnet 192.168.1.0/24",
        )?;

        // Parse CIDR notation
        let (network, mask) = cidr
            .split_once('/')
            .ok_or("Invalid CIDR notation. Use format: 192.168.1.0/24")?;

        let mask_bits: u8 = mask
            .parse()
            .map_err(|_| "Invalid subnet mask. Must be between 0-32")?;

        if mask_bits > 32 {
            return Err("Subnet mask must be between 0-32".to_string());
        }

        // Parse network address
        let network_parts: Vec<&str> = network.split('.').collect();
        if network_parts.len() != 4 {
            return Err("Invalid IP address format".to_string());
        }

        let octets: Result<Vec<u8>, _> = network_parts.iter().map(|s| s.parse::<u8>()).collect();

        let octets = octets.map_err(|_| "Invalid IP address")?;
        let network_ip = ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32);

        // Calculate network mask and range
        let mask = !((1u32 << (32 - mask_bits)) - 1);
        let network_addr = network_ip & mask;
        let broadcast_addr = network_addr | !mask;
        let num_hosts = (broadcast_addr - network_addr).saturating_sub(1);

        if num_hosts == 0 {
            return Err("Subnet too small (no usable hosts)".to_string());
        }

        if num_hosts > 1024 {
            Output::warning(&format!(
                "Large subnet: {} hosts. This may take a while...",
                num_hosts
            ));
        }

        let preset = ctx
            .get_flag("preset")
            .map(|s| s.as_str())
            .unwrap_or("common");

        Output::header(&format!("Subnet Discovery: {}", cidr));
        Output::summary_line(&[
            (
                "Network",
                &format!(
                    "{}.{}.{}.{}",
                    (network_addr >> 24) & 0xFF,
                    (network_addr >> 16) & 0xFF,
                    (network_addr >> 8) & 0xFF,
                    network_addr & 0xFF
                ),
            ),
            ("Hosts", &num_hosts.to_string()),
            ("Preset", preset),
        ]);

        println!();
        Output::subheader("Phase 1: Host Discovery");

        // Discover alive hosts (ping sweep)
        let mut alive_hosts = Vec::new();
        let start_ip = network_addr + 1;
        let end_ip = broadcast_addr;

        let progress = Arc::new(Output::progress_bar(
            "Discovering hosts".to_string(),
            num_hosts as u64,
            true,
        ));

        // Simple TCP SYN to port 80 for host discovery (fast)
        use std::net::{IpAddr, Ipv4Addr, TcpStream};
        use std::time::Duration;

        for ip_num in start_ip..end_ip {
            let ip = Ipv4Addr::from(ip_num);
            let addr = format!("{}:80", ip);

            // Try quick connect
            if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500))
                .is_ok()
            {
                alive_hosts.push(ip);
            }

            progress.tick(1);
        }

        progress.finish();

        if alive_hosts.is_empty() {
            println!();
            Output::warning("No alive hosts found in subnet");
            return Ok(());
        }

        println!();
        Output::success(&format!("✓ Found {} alive host(s)", alive_hosts.len()));

        for host in &alive_hosts {
            println!("  • {}", host);
        }

        // Database persistence setup
        let persist_flag = if ctx.has_flag("persist") {
            Some(true)
        } else if ctx.has_flag("no-persist") {
            Some(false)
        } else {
            None
        };

        println!();
        Output::subheader("Phase 2: Port Scanning");

        let cfg = config::get();
        let threads = ctx
            .get_flag_or("threads", &cfg.network.threads.to_string())
            .parse::<usize>()
            .map_err(|_| "Invalid threads value")?;

        let timeout = ctx
            .get_flag_or("timeout", &cfg.network.timeout_ms.to_string())
            .parse::<u64>()
            .map_err(|_| "Invalid timeout value")?;

        // Scan each alive host
        for (idx, host_ip) in alive_hosts.iter().enumerate() {
            println!();
            println!(
                "[{}/{}] Scanning {}...",
                idx + 1,
                alive_hosts.len(),
                host_ip
            );

            let scanner = PortScanner::new(IpAddr::V4(*host_ip))
                .with_threads(threads)
                .with_timeout(timeout);

            let results = match preset {
                "common" => scanner.scan_common(),
                "web" => scanner.scan_ports(&[80, 443, 8080, 8443, 3000, 5000]),
                "full" => scanner.scan_range(1, 65535),
                _ => return Err(format!("Unknown preset: {}", preset)),
            };

            let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();

            if open_ports.is_empty() {
                println!("  No open ports found");
                continue;
            }

            println!("  {} open port(s):", open_ports.len());

            // Check if intelligence gathering is enabled
            let intel_enabled = ctx.has_flag("intel");

            for result in &open_ports {
                let service = result
                    .service
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                println!("    • {}/{}", result.port, service);

                // Gather and display intelligence if flag is set
                if intel_enabled {
                    let host_str = host_ip.to_string();
                    if let Some(intel) = gather_port_intelligence(
                        &host_str,
                        result.port,
                        result.service.as_deref(),
                        result.banner.as_deref(),
                    ) {
                        // Display vendor and version
                        if let Some(vendor) = &intel.vendor {
                            let version_str = intel
                                .version
                                .as_ref()
                                .map(|v| format!(" {}", v))
                                .unwrap_or_default();
                            println!("      \x1b[36m└─\x1b[0m Vendor: {}{}", vendor, version_str);
                        }

                        // Display OS hint
                        if let Some(os) = &intel.os_hint {
                            println!("      \x1b[36m└─\x1b[0m OS: {}", os);
                        }

                        // Display timing information
                        if let Some(timing) = &intel.timing {
                            let conn_time_ms = timing.connection_time.as_millis();
                            if let Some(resp_time) = timing.first_response_time {
                                let resp_time_ms = resp_time.as_millis();
                                println!(
                                    "      \x1b[36m└─\x1b[0m Timing: conn={}ms, resp={}ms",
                                    conn_time_ms, resp_time_ms
                                );
                            } else {
                                println!("      \x1b[36m└─\x1b[0m Timing: conn={}ms", conn_time_ms);
                            }
                        }

                        // Display confidence
                        let confidence_pct = (intel.confidence * 100.0) as u8;
                        if confidence_pct > 30 {
                            println!("      \x1b[36m└─\x1b[0m Confidence: {}%", confidence_pct);
                        }
                    }
                }
            }

            // Save to database if persistence is enabled
            if persist_flag.is_some() {
                let host_str = host_ip.to_string();
                let mut pm = PersistenceManager::new(&host_str, persist_flag)?;

                for result in &open_ports {
                    let service_id = match result.service.as_deref() {
                        Some("http") => 1,
                        Some("https") => 2,
                        Some("ssh") => 3,
                        Some("ftp") => 4,
                        Some("smtp") => 5,
                        Some("mysql") => 6,
                        _ => 0,
                    };

                    let ip_u32 = u32::from(*host_ip);
                    if let Err(e) = pm.add_port_scan(ip_u32, result.port, 1, service_id) {
                        eprintln!("    Warning: Failed to save: {}", e);
                    }
                }

                if let Some(db_path) = pm.commit()? {
                    println!("    ✓ Saved to {}", db_path.display());
                }
            }
        }

        println!();
        Output::success(&format!(
            "✓ Subnet scan completed - {} host(s) scanned",
            alive_hosts.len()
        ));

        Ok(())
    }
}

fn truncate_banner(input: &str, max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }

    let sanitized = input.replace('\n', " ").replace('\r', " ");
    if sanitized.len() <= max_len {
        return sanitized;
    }

    let mut truncated: String = sanitized.chars().take(max_len.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

/// Gather intelligence for a specific port/service
fn gather_port_intelligence(
    host: &str,
    port: u16,
    service: Option<&str>,
    banner: Option<&str>,
) -> Option<PortIntelligence> {
    let service_name = service.unwrap_or("unknown");

    // Try to gather timing analysis
    let timing_result = match service_name {
        "ssh" => timing_analysis::fingerprint_ssh_timing(host, port).ok(),
        "ftp" => timing_analysis::fingerprint_ftp_timing(host, port)
            .ok()
            .map(|(_, time)| timing_analysis::TimingSignature {
                connection_time: time,
                first_response_time: Some(time),
                timeout_behavior: timing_analysis::TimeoutBehavior::Silent,
                keep_alive_interval: None,
            }),
        "http" | "https" => timing_analysis::fingerprint_http_timing(host, port).ok(),
        "mysql" | "postgres" | "mssql" | "mongodb" => {
            timing_analysis::fingerprint_database_timing(host, port).ok()
        }
        "telnet" => timing_analysis::fingerprint_telnet_timeout(host, port)
            .ok()
            .map(|(_, duration)| timing_analysis::TimingSignature {
                connection_time: duration,
                first_response_time: None,
                timeout_behavior: timing_analysis::TimeoutBehavior::Timeout(duration),
                keep_alive_interval: None,
            }),
        _ => None,
    };

    // Analyze banner if available
    let banner_info = banner.and_then(|b| {
        match service_name {
            "ssh" => Some(banner_analysis::analyze_ssh_banner(b)),
            "ftp" => Some(banner_analysis::analyze_ftp_banner(b)),
            "http" | "https" => {
                // Extract server header from HTTP response
                let server = b
                    .lines()
                    .find(|line| line.to_lowercase().starts_with("server:"))
                    .and_then(|line| line.split(':').nth(1))
                    .unwrap_or("")
                    .trim();
                if !server.is_empty() {
                    Some(banner_analysis::analyze_http_server(server))
                } else {
                    None
                }
            }
            _ => None,
        }
    });

    // Combine into service detection
    let probe_responses = HashMap::new();
    let service_info = service_detection::detect_service(
        port,
        banner.map(|s| s.to_string()),
        timing_result.clone(),
        &probe_responses,
    );

    // Only return intelligence if we found something useful
    if timing_result.is_some() || banner_info.is_some() || service_info.confidence > 0.3 {
        Some(PortIntelligence {
            vendor: service_info.vendor,
            version: service_info.version,
            os_hint: service_info.os_hint,
            timing: timing_result,
            confidence: service_info.confidence,
        })
    } else {
        None
    }
}

/// Intelligence gathered for a single port
#[derive(Debug, Clone)]
struct PortIntelligence {
    vendor: Option<String>,
    version: Option<String>,
    os_hint: Option<String>,
    timing: Option<timing_analysis::TimingSignature>,
    confidence: f32,
}
