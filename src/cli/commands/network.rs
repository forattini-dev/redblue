/// Network/host command - Host discovery and connectivity testing
use crate::cli::commands::{
    annotate_query_partition, build_partition_attributes, print_help, Command, Flag, Route,
};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::network::fingerprint::HostFingerprint;
use crate::modules::network::ping::{ping_system, PingConfig, PingSystemResult};
use crate::modules::recon::ip_intel::{IpClassification, IpIntel};
use crate::storage::client::query::format as query_format;
use crate::storage::records::{HostIntelRecord, ServiceIntelRecord};
use crate::storage::service::StorageService;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct NetworkCommand;

impl Command for NetworkCommand {
    fn domain(&self) -> &str {
        "network"
    }

    fn resource(&self) -> &str {
        "host"
    }

    fn description(&self) -> &str {
        "Host discovery and connectivity testing"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "ping",
                summary: "ICMP ping test with statistics (fping replacement)",
                usage: "rb network host ping <host> [--count 4] [--timeout 1]",
            },
            Route {
                verb: "discover",
                summary: "Network discovery scan (netdiscover/arp-scan replacement)",
                usage: "rb network host discover <cidr> [--timeout 1]",
            },
            Route {
                verb: "fingerprint",
                summary: "Active host fingerprinting (banner + timing)",
                usage: "rb network host fingerprint <host> [--persist]",
            },
            Route {
                verb: "list",
                summary: "List stored host fingerprints",
                usage: "rb network host list [host] [--db <file>]",
            },
            Route {
                verb: "intel",
                summary: "IP intelligence: bogon detection, classification, and info",
                usage: "rb network host intel <ip> [--bogons]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("count", "Number of ping packets to send")
                .with_short('c')
                .with_default("4"),
            Flag::new("timeout", "Timeout per packet in seconds")
                .with_short('t')
                .with_default("1"),
            Flag::new("interval", "Interval between packets in seconds")
                .with_short('i')
                .with_default("1"),
            Flag::new("size", "Packet size in bytes")
                .with_short('s')
                .with_default("56"),
            Flag::new("persist", "Save host fingerprint to database"),
            Flag::new("db", "Database file to read host fingerprints from"),
            Flag::new("bogons", "Show all bogon ranges (IPv4 and IPv6)"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Ping a host (4 packets)", "rb network host ping google.com"),
            (
                "Ping with custom count",
                "rb network host ping 8.8.8.8 --count 10",
            ),
            (
                "Fast ping (1 second timeout)",
                "rb network host ping example.com --timeout 1 --count 3",
            ),
            (
                "Network discovery (subnet)",
                "rb network host discover 192.168.1.0/24",
            ),
            (
                "Fast discovery",
                "rb network host discover 10.0.0.0/24 --timeout 1",
            ),
            ("IP intelligence", "rb network host intel 8.8.8.8"),
            ("Check if IP is bogon", "rb network host intel 10.0.0.1"),
            ("List all bogon ranges", "rb network host intel --bogons"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "ping" => self.ping(ctx),
            "discover" => self.discover(ctx),
            "fingerprint" => self.fingerprint(ctx),
            "list" => self.list(ctx),
            "intel" => self.intel(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(
                        verb,
                        &["ping", "discover", "fingerprint", "list", "intel"]
                    )
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl NetworkCommand {
    fn ping(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or(
            "Missing host.\nUsage: rb network host ping <HOST> [--count 4]\nExample: rb network host ping google.com",
        )?;

        Validator::validate_host(host)?;

        let count = ctx
            .flags
            .get("count")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4);

        let timeout_secs = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);

        let interval_secs = ctx
            .flags
            .get("interval")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);

        let packet_size = ctx
            .flags
            .get("size")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(56);

        let config = PingConfig {
            count,
            interval: Duration::from_secs(interval_secs),
            timeout: Duration::from_secs(timeout_secs),
            packet_size,
        };

        Output::header(&format!("ICMP Ping: {}", host));
        Output::info(&format!(
            "Sending {} packets (size: {} bytes, timeout: {}s)",
            count, packet_size, timeout_secs
        ));
        println!();

        Output::spinner_start("Pinging");
        let result = ping_system(host, &config)?;
        Output::spinner_done();

        // Display results
        self.display_ping_results(&result)?;

        Ok(())
    }

    fn display_ping_results(&self, result: &PingSystemResult) -> Result<(), String> {
        Output::section("Ping Statistics");

        println!(
            "  Host:              {}",
            Output::colorize(&result.host, "cyan")
        );
        println!("  Packets Sent:      {}", result.packets_sent);
        println!(
            "  Packets Received:  {}",
            Output::colorize(&result.packets_received.to_string(), "green")
        );

        let loss_color = if result.packet_loss_percent > 50.0 {
            "red"
        } else if result.packet_loss_percent > 0.0 {
            "yellow"
        } else {
            "green"
        };
        println!(
            "  Packet Loss:       {}",
            Output::colorize(&format!("{:.1}%", result.packet_loss_percent), loss_color)
        );

        if result.packets_received > 0 {
            println!();
            Output::section("Round Trip Time (RTT)");
            println!("  Min:     {:.3} ms", result.min_rtt_ms);
            println!("  Avg:     {:.3} ms", result.avg_rtt_ms);
            println!("  Max:     {:.3} ms", result.max_rtt_ms);

            // Status message
            println!();
            if result.packet_loss_percent == 0.0 {
                Output::success("✓ Host is reachable with no packet loss");
            } else if result.packet_loss_percent < 100.0 {
                Output::warning(&format!(
                    "⚠️  Host is reachable but experiencing {:.1}% packet loss",
                    result.packet_loss_percent
                ));
            } else {
                Output::error("✗ Host is unreachable (100% packet loss)");
            }
        } else {
            println!();
            Output::error("✗ Host is unreachable - no packets received");
        }

        Ok(())
    }

    fn discover(&self, ctx: &CliContext) -> Result<(), String> {
        let cidr = ctx.target.as_ref().ok_or(
            "Missing CIDR.\nUsage: rb network host discover <CIDR>\nExample: rb network host discover 192.168.1.0/24",
        )?;

        // Validate CIDR format
        if !cidr.contains('/') {
            return Err(format!(
                "Invalid CIDR notation: '{}'\nExpected format: IP/MASK (e.g., 192.168.1.0/24)",
                cidr
            ));
        }

        let timeout_secs = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);

        Output::header(&format!("Network Discovery: {}", cidr));
        Output::info(&format!(
            "Scanning network range (timeout: {}s)",
            timeout_secs
        ));
        Output::warning("Note: Network discovery requires root/admin privileges for ARP scanning");
        println!();

        // Parse CIDR to get IP range
        let (_network, mask) = cidr.split_once('/').unwrap();
        let mask_bits = mask
            .parse::<u8>()
            .map_err(|_| format!("Invalid subnet mask: '{}'. Must be 0-32", mask))?;

        if mask_bits > 32 {
            return Err("Subnet mask must be between 0 and 32".to_string());
        }

        // Calculate number of hosts
        let num_hosts = if mask_bits == 32 {
            1
        } else {
            2u32.pow((32 - mask_bits) as u32) - 2 // Exclude network and broadcast
        };

        Output::info(&format!(
            "Scanning {} possible hosts in {}",
            num_hosts, cidr
        ));
        println!();

        Output::section("Discovery Method");
        Output::info("🔍 Using ICMP ping sweep (requires no special privileges)");
        Output::dim("   Alternative: ARP scanning (requires root/admin - coming soon)");
        println!();

        // For now, we'll use ping sweep approach
        // In a full implementation, we'd iterate through the IP range
        Output::warning("⚠️  Network discovery sweep not yet fully implemented");
        Output::info("💡 Workaround: Use rb network ports scan with CIDR notation");
        Output::dim(&format!(
            "   Example: rb network ports scan {} --preset common",
            cidr
        ));

        Ok(())
    }

    fn fingerprint(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or(
            "Missing host.\nUsage: rb network host fingerprint <HOST>\nExample: rb network host fingerprint example.com",
        )?;

        Validator::validate_host(host)?;

        Output::header(&format!("Host Fingerprint: {}", host));
        Output::spinner_start("Collecting intelligence");
        let fingerprint = HostFingerprint::run(host, &[])?;
        Output::spinner_done();

        self.display_fingerprint(&fingerprint);

        if ctx.flags.contains_key("persist") {
            let attributes = build_partition_attributes(ctx, host, [("operation", "fingerprint")]);
            let mut manager = StorageService::global().persistence_for_target_with(
                host,
                Some(true),
                None,
                attributes,
            )?;
            let record = self.fingerprint_to_record(&fingerprint);
            manager
                .add_host_intel(record)
                .map_err(|e| format!("Failed to persist host intel: {}", e))?;

            if let Some(path) = manager.commit()? {
                Output::success(&format!("Fingerprint saved to {}", path.display()));
            }
        }

        Ok(())
    }

    fn list(&self, ctx: &CliContext) -> Result<(), String> {
        let target_ip = if let Some(target) = ctx.target.as_ref() {
            Some(IpAddr::from_str(target).map_err(|_| {
                "Invalid IP address. Usage: rb network host list <IP> [--db file]".to_string()
            })?)
        } else {
            None
        };

        let db_path = if let Some(ip) = target_ip {
            self.detect_db_path(ctx, &ip.to_string())?
        } else if let Some(db) = ctx.flags.get("db") {
            std::path::PathBuf::from(db)
        } else {
            return Err(
                "Missing database file. Use --db <file> when listing all hosts.".to_string(),
            );
        };

        let mut query = StorageService::global()
            .open_query_manager(&db_path)
            .map_err(|e| format!("Failed to open database {}: {}", db_path.display(), e))?;

        annotate_query_partition(
            ctx,
            &db_path,
            [("query_dataset", "host_intel"), ("query_operation", "list")],
        );

        if let Some(ip) = target_ip {
            match query
                .get_host_fingerprint(ip)
                .map_err(|e| format!("Query failed: {}", e))?
            {
                Some(record) => {
                    let formatted = query_format::format_host(&record);
                    println!("{}", formatted);
                }
                None => {
                    Output::warning("No fingerprint stored for target");
                }
            }
        } else {
            let records = query
                .list_hosts()
                .map_err(|e| format!("Query failed: {}", e))?;
            if records.is_empty() {
                Output::warning("No host fingerprints stored in this database");
            } else {
                Output::header(&format!(
                    "Stored Host Fingerprints ({}) - {}",
                    records.len(),
                    db_path.display()
                ));
                for record in records {
                    println!("{}\n", query_format::format_host(&record));
                }
            }
        }

        Ok(())
    }

    fn fingerprint_to_record(&self, fingerprint: &HostFingerprint) -> HostIntelRecord {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let mut services = Vec::with_capacity(fingerprint.services.len());
        for svc in &fingerprint.services {
            let mut hints = Vec::new();
            if let Some(banner) = &svc.banner {
                hints.extend(banner.os_hints.clone());
            }
            if let Some(timing) = &svc.timing {
                let name = timing.inferred_os.name();
                if name != "Unknown" {
                    hints.push(format!("Timing: {}", name));
                }
            }

            let banner_text = svc.banner.as_ref().map(|b| b.banner.clone());
            let service_name = svc
                .service_label
                .clone()
                .or_else(|| svc.banner.as_ref().map(|b| format!("{:?}", b.service)));

            services.push(ServiceIntelRecord {
                port: svc.port,
                service_name,
                banner: banner_text,
                os_hints: hints,
            });
        }

        HostIntelRecord {
            ip: fingerprint.ip,
            os_family: fingerprint
                .os_guess
                .as_ref()
                .map(|guess| guess.os_family.name().to_string()),
            confidence: fingerprint
                .os_guess
                .as_ref()
                .map(|guess| guess.confidence)
                .unwrap_or(0.0),
            last_seen: timestamp,
            services,
        }
    }

    fn display_fingerprint(&self, fingerprint: &HostFingerprint) {
        Output::section("Summary");
        println!("Host: {}", fingerprint.host);
        println!("IP:   {}", fingerprint.ip);
        match &fingerprint.os_guess {
            Some(guess) => println!(
                "OS Guess: {} ({:.0}% confidence)",
                guess.os_family.name(),
                guess.confidence * 100.0
            ),
            None => println!("OS Guess: unknown"),
        }
        println!("Open Ports: {}", fingerprint.open_ports.len());

        println!();
        Output::section("Services");
        if fingerprint.services.is_empty() {
            Output::warning("No open services detected");
            return;
        }
        println!("PORT     SERVICE          BANNER SNIPPET");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        for svc in &fingerprint.services {
            let name = svc.service_label.as_deref().unwrap_or("unknown");
            let banner = svc.banner.as_ref().map(|b| b.banner.trim()).unwrap_or("");
            let banner_preview = if banner.len() > 40 {
                format!("{}…", &banner[..40])
            } else {
                banner.to_string()
            };
            println!("{:<7} {:<15} {}", svc.port, name, banner_preview);
        }
    }

    fn detect_db_path(
        &self,
        ctx: &CliContext,
        identifier: &str,
    ) -> Result<std::path::PathBuf, String> {
        if let Some(path) = ctx.flags.get("db") {
            return Ok(std::path::PathBuf::from(path));
        }

        let base = identifier.replace(':', "_");
        let cwd = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;
        let candidate = cwd.join(format!("{}.rdb", &base));
        if candidate.exists() {
            return Ok(candidate);
        }

        Err(format!(
            "Database file not found. Expected: {}",
            candidate.display()
        ))
    }

    /// IP Intelligence - bogon detection and IP classification
    fn intel(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();

        // If --bogons flag is set, show all bogon ranges
        if ctx.has_flag("bogons") {
            return self.show_bogon_ranges(format);
        }

        let ip = ctx.target.as_ref().ok_or(
            "Missing IP address.\nUsage: rb network host intel <IP>\nExample: rb network host intel 8.8.8.8\n\nTip: Use --bogons to see all bogon ranges",
        )?;

        let intel = IpIntel::new();
        let result = intel.analyze(ip)?;

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"ip\": \"{}\",", result.ip);
            println!("  \"version\": \"{}\",", result.version);
            println!("  \"is_bogon\": {},", result.is_bogon);
            if let Some(ref reason) = result.bogon_reason {
                println!("  \"bogon_reason\": \"{}\",", reason);
            }
            println!("  \"classification\": \"{}\"", result.classification);
            println!("}}");
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("ip: {}", result.ip);
            println!("version: {}", result.version);
            println!("is_bogon: {}", result.is_bogon);
            if let Some(ref reason) = result.bogon_reason {
                println!("bogon_reason: {}", reason);
            }
            println!("classification: {}", result.classification);
            return Ok(());
        }

        // Human output
        Output::header(&format!("IP Intelligence: {}", result.ip));

        // IP Version
        println!("  Version: {}", result.version);
        println!();

        // Bogon status - prominent display
        if result.is_bogon {
            Output::error("BOGON DETECTED");
            if let Some(ref reason) = result.bogon_reason {
                println!("  Range: {}", reason);
            }
            println!();
            Output::warning("This IP should NOT appear on the public internet!");
        } else {
            Output::success("NOT A BOGON - Globally routable");
        }

        println!();

        // Classification
        Output::subheader("Classification");
        let class_color = match result.classification {
            IpClassification::Public => "\x1b[32m",          // Green
            IpClassification::Private => "\x1b[33m",         // Yellow
            IpClassification::Loopback => "\x1b[36m",        // Cyan
            IpClassification::LinkLocal => "\x1b[36m",       // Cyan
            IpClassification::Multicast => "\x1b[35m",       // Magenta
            IpClassification::Reserved => "\x1b[31m",        // Red
            IpClassification::Documentation => "\x1b[34m",   // Blue
            IpClassification::CarrierGradeNat => "\x1b[33m", // Yellow
            IpClassification::Benchmarking => "\x1b[34m",    // Blue
            IpClassification::Unknown => "\x1b[90m",         // Gray
        };
        println!("  {}{}\x1b[0m", class_color, result.classification);

        // Security implications
        println!();
        Output::subheader("Security Notes");
        match result.classification {
            IpClassification::Public => {
                println!("  - Globally routable IP address");
                println!("  - Can be reached from the internet");
                println!("  - May be subject to internet-based attacks");
            }
            IpClassification::Private => {
                println!("  - RFC 1918 private address space");
                println!("  - Not routable on the public internet");
                println!("  - Typically used in internal networks");
                println!("  - Requires NAT for internet access");
            }
            IpClassification::Loopback => {
                println!("  - Loopback address (localhost)");
                println!("  - Traffic never leaves the host");
                println!("  - Used for local testing and services");
            }
            IpClassification::LinkLocal => {
                println!("  - Link-local address (APIPA)");
                println!("  - Auto-configured when DHCP unavailable");
                println!("  - Only valid on the local network segment");
            }
            IpClassification::Multicast => {
                println!("  - Multicast address range");
                println!("  - Used for one-to-many communication");
                println!("  - Not a unicast host address");
            }
            IpClassification::Reserved => {
                println!("  - Reserved address space");
                println!("  - Should not be used for normal traffic");
            }
            IpClassification::Documentation => {
                println!("  - Documentation/test address");
                println!("  - Should only appear in documentation");
                println!("  - Examples: TEST-NET-1, TEST-NET-2, TEST-NET-3");
            }
            IpClassification::CarrierGradeNat => {
                println!("  - Carrier-Grade NAT (CGNAT) range");
                println!("  - RFC 6598 - shared address space");
                println!("  - Used by ISPs for NAT444");
            }
            IpClassification::Benchmarking => {
                println!("  - Benchmarking address range");
                println!("  - RFC 2544 - for network device testing");
            }
            IpClassification::Unknown => {
                println!("  - Unknown classification");
            }
        }

        println!();
        Output::success("IP intelligence complete");
        Ok(())
    }

    /// Show all bogon ranges
    fn show_bogon_ranges(&self, format: crate::cli::format::OutputFormat) -> Result<(), String> {
        let ipv4_bogons = IpIntel::get_ipv4_bogon_ranges();
        let ipv6_bogons = IpIntel::get_ipv6_bogon_ranges();

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"ipv4_bogons\": [");
            for (i, (cidr, desc)) in ipv4_bogons.iter().enumerate() {
                let comma = if i < ipv4_bogons.len() - 1 { "," } else { "" };
                println!(
                    "    {{ \"cidr\": \"{}\", \"description\": \"{}\" }}{}",
                    cidr, desc, comma
                );
            }
            println!("  ],");
            println!("  \"ipv6_bogons\": [");
            for (i, (cidr, desc)) in ipv6_bogons.iter().enumerate() {
                let comma = if i < ipv6_bogons.len() - 1 { "," } else { "" };
                println!(
                    "    {{ \"cidr\": \"{}\", \"description\": \"{}\" }}{}",
                    cidr, desc, comma
                );
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("ipv4_bogons:");
            for (cidr, desc) in &ipv4_bogons {
                println!("  - cidr: {}", cidr);
                println!("    description: {}", desc);
            }
            println!("ipv6_bogons:");
            for (cidr, desc) in &ipv6_bogons {
                println!("  - cidr: {}", cidr);
                println!("    description: {}", desc);
            }
            return Ok(());
        }

        // Human output
        Output::header("Bogon Ranges (IANA Reserved)");
        println!();
        println!("Bogon IPs are addresses that should NEVER appear on the public internet.");
        println!("Seeing these in internet traffic indicates misconfiguration or spoofing.");
        println!();

        Output::subheader(&format!("IPv4 Bogon Ranges ({})", ipv4_bogons.len()));
        println!();
        println!("  {:<20} {}", "CIDR", "DESCRIPTION");
        println!("  {}", "─".repeat(60));
        for (cidr, desc) in &ipv4_bogons {
            println!("  {:<20} {}", cidr, desc);
        }

        println!();
        Output::subheader(&format!("IPv6 Bogon Ranges ({})", ipv6_bogons.len()));
        println!();
        println!("  {:<25} {}", "PREFIX", "DESCRIPTION");
        println!("  {}", "─".repeat(60));
        for (cidr, desc) in &ipv6_bogons {
            println!("  {:<25} {}", cidr, desc);
        }

        println!();
        Output::success(&format!(
            "Total: {} IPv4 + {} IPv6 = {} bogon ranges",
            ipv4_bogons.len(),
            ipv6_bogons.len(),
            ipv4_bogons.len() + ipv6_bogons.len()
        ));
        Ok(())
    }
}
