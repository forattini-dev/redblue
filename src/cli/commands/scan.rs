/// Network/ports command - Port scanning and network discovery
use crate::cli::commands::{build_partition_attributes, print_help, Command, Flag, Route};
use crate::cli::{
  format::OutputFormat,
  output::{Output, ProgressBar},
  render,
  validator::Validator,
  CliContext,
};
use crate::config;
use crate::intelligence::{
  banner_analysis, os_probes, os_signatures, service_detection, timing_analysis,
};
use crate::json;
use crate::modules::network::highspeed::{
  DeduplicationCache, RandomScanIterator, ScanRange, SynCookie, TokenBucket,
};
use crate::modules::network::scanner::{AdvancedScanner, PortScanner, ScanType, TimingTemplate};
use crate::serde_json::Value;
use crate::storage::service::StorageService;
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

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let machine_output = match verb {
      "scan" | "range" | "syn-scan" | "udp-scan" | "stealth" => {
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly)
      }
      _ => self.metadata().machine_output,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(machine_output)
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
        verb: "syn-scan",
        summary: "TCP SYN scan (half-open, requires root/CAP_NET_RAW)",
        usage: "rb network ports syn-scan <host> [--preset common]",
      },
      Route {
        verb: "udp-scan",
        summary: "UDP scan with ICMP unreachable detection",
        usage: "rb network ports udp-scan <host> [--preset common]",
      },
      Route {
        verb: "stealth",
        summary: "Stealth scan (FIN/NULL/XMAS, requires root)",
        usage: "rb network ports stealth <host> --type fin|null|xmas",
      },
      Route {
        verb: "subnet",
        summary: "Discover and scan all hosts in a subnet (CIDR notation)",
        usage: "rb network ports subnet <cidr> [--preset common]",
      },
      Route {
        verb: "mass-scan",
        summary: "High-speed masscan-style scan with BlackRock IP randomization",
        usage: "rb network ports mass-scan <cidr> [--rate 1000] [--ports 1-1000]",
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
      Flag::new("save", "Force save to database (overrides config)"),
      Flag::new("no-save", "Disable auto-save for this command"),
      Flag::new("db", "Custom database file path").with_short('d'),
      Flag::new(
        "db-password",
        "Database encryption password (overrides keyring)",
      ),
      Flag::new(
        "intel",
        "Gather intelligence on discovered services (timing, banners, OS hints)",
      )
      .with_short('i'),
      Flag::new("type", "Stealth scan type (fin|null|xmas) for stealth verb"),
      Flag::new(
        "timing",
        "Timing template: T0=paranoid, T1=sneaky, T2=polite, T3=normal, T4=aggressive, T5=insane",
      )
      .with_short('T'),
      Flag::new(
        "os-detect",
        "Enable OS fingerprinting (TCP/IP stack analysis, requires open port)",
      )
      .with_short('O'),
      // High-speed scanning flags
      Flag::new("rate", "Packets per second for mass-scan (default: 1000)").with_short('r'),
      Flag::new(
        "ports",
        "Port specification for mass-scan (e.g., 1-1000,8080,8443)",
      ),
      Flag::new("resume", "Resume mass-scan from index"),
      Flag::new(
        "shard",
        "Distributed shard: N/M (e.g., 1/4 for first of 4 shards)",
      ),
      Flag::new("seed", "Random seed for reproducible IP ordering"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Scan common ports",
        "rb network ports scan 192.168.1.1 --preset common",
      ),
      (
        "Scan and save to encrypted database",
        "rb network ports scan 192.168.1.1 --preset common --save",
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
        "rb network ports subnet 10.0.0.0/24 --preset common --save",
      ),
      (
        "SYN scan (requires root)",
        "rb network ports syn-scan 192.168.1.1 --preset common",
      ),
      ("UDP scan", "rb network ports udp-scan 192.168.1.1"),
      (
        "FIN stealth scan",
        "rb network ports stealth 192.168.1.1 --type fin",
      ),
      (
        "XMAS stealth scan",
        "rb network ports stealth 192.168.1.1 --type xmas",
      ),
      (
        "Paranoid timing (IDS evasion)",
        "rb network ports syn-scan 192.168.1.1 --timing T0",
      ),
      (
        "Aggressive timing (fast scan)",
        "rb network ports syn-scan 192.168.1.1 --timing T4",
      ),
      (
        "Insane timing (maximum speed)",
        "rb network ports syn-scan 192.168.1.1 --timing T5 --preset full",
      ),
      (
        "OS fingerprinting",
        "rb network ports scan 192.168.1.1 --preset common --os-detect",
      ),
      (
        "Full scan with OS detection",
        "rb network ports scan 192.168.1.1 -O --intel",
      ),
      (
        "Mass scan subnet (BlackRock randomization)",
        "rb network ports mass-scan 192.168.1.0/24 --rate 1000 --ports 1-1000",
      ),
      (
        "Mass scan with resume capability",
        "rb network ports mass-scan 10.0.0.0/8 --rate 10000 --resume 1000000",
      ),
      (
        "Distributed shard scan (1st of 4 workers)",
        "rb network ports mass-scan 10.0.0.0/8 --shard 1/4",
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
      "syn-scan" => self.advanced_scan(ctx, ScanType::Syn),
      "udp-scan" => self.advanced_scan(ctx, ScanType::Udp),
      "stealth" => self.stealth_scan(ctx),
      "subnet" => self.scan_subnet(ctx),
      "mass-scan" => self.mass_scan(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        println!(
          "{}",
          Validator::suggest_command(
            verb,
            &["scan", "range", "syn-scan", "udp-scan", "stealth", "subnet"]
          )
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

    let preset_str = ctx.get_flag("preset");
    let preset = preset_str.as_deref().unwrap_or("common");

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

    // Database persistence using unified PersistenceConfig
    let persistence_config = ctx.get_persistence_config();
    let storage = StorageService::global();
    let attributes = build_partition_attributes(
      ctx,
      &target_str_owned,
      [("preset", preset), ("mode", "scan")],
    );
    let mut pm =
      storage.persistence_with_config(&target_str_owned, persistence_config, attributes)?;

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

        // Persist open port (state 0 = Open)
        if let Err(e) = pm.add_port_scan(target, result.port, 0, service_id) {
          // Log error but don't fail the scan
          eprintln!("Warning: Failed to save to database: {}", e);
        }
      }
    }

    let payload = scan_ports_payload(target, preset, &open_ports);
    if render::render_machine_output_with_yaml(ctx, "rb network ports scan", &payload, || {
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
      Ok(())
    })? {
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

    for result in &open_ports {
      let service = result.service.as_deref().unwrap_or("unknown");

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

    // OS Detection if --os-detect flag is set
    let os_detect_enabled = ctx.has_flag("os-detect");
    if os_detect_enabled && !open_ports.is_empty() {
      println!();
      Output::subheader("OS Detection");

      // Get first open port for probing
      let open_port = open_ports.first().map(|r| r.port);

      // Try to find a closed port (use a high port that's likely closed)
      let closed_port = Some(61234u16);

      // Convert target to Ipv4Addr for OS prober
      if let std::net::IpAddr::V4(target_v4) = target {
        match os_probes::OsProber::new(target_v4) {
          Ok(prober) => {
            Output::spinner_start("Running TCP/IP stack analysis");

            let result = prober.probe(open_port, closed_port);

            Output::spinner_done();

            if !result.matches.is_empty() {
              println!();
              Output::success(&format!(
                "Top {} OS match{}:",
                result.matches.len().min(3),
                if result.matches.len() > 1 { "es" } else { "" }
              ));

              for (idx, os_match) in result.matches.iter().take(3).enumerate() {
                let confidence_pct = (os_match.confidence * 100.0) as u8;
                let marker = if idx == 0 { "●" } else { "○" };

                println!(
                  "  \x1b[32m{}\x1b[0m {} ({}%)",
                  marker, os_match.signature.name, confidence_pct
                );

                // Show matching points for top match
                if idx == 0 && !os_match.matching_points.is_empty() {
                  for point in os_match.matching_points.iter().take(3) {
                    println!("    \x1b[90m└─ {}\x1b[0m", point);
                  }
                }
              }

              // Show estimated initial TTL
              if let Some(ttl) = result.initial_ttl {
                println!();
                Output::item("Initial TTL", &ttl.to_string());
              }

              // Show IP ID behavior
              println!("  IP ID Sequence: {:?}", result.ip_id_behavior);
            } else {
              Output::warning("No confident OS match found");

              // Try quick OS detection from database
              if let Some(first_port) = open_ports.first() {
                let db = os_signatures::OsSignatureDb::new();
                let quick_matches = db.find_matches(
                  first_port
                    .banner
                    .as_ref()
                    .and_then(|_| Some(64))
                    .unwrap_or(64),
                  65535,
                  Some(1460),
                  Some(7),
                  "MSNWT",
                );

                if !quick_matches.is_empty() {
                  println!();
                  Output::info("Passive fingerprint hints:");
                  for (sig, score) in quick_matches.iter().take(3) {
                    let score_pct = (score * 100.0) as u8;
                    println!("    {} ({}%)", sig.name, score_pct);
                  }
                }
              }
            }
          }
          Err(e) => {
            Output::warning(&format!("OS detection requires elevated privileges: {}", e));
          }
        }
      } else {
        Output::warning("OS detection currently only supports IPv4 targets");
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

    let format = ctx.get_output_format();

    if format == OutputFormat::Human {
      Output::header("Port Range Scan");
      Output::item("Target", &target.to_string());
      Output::item("Range", &format!("{}-{}", start, end));
      if ctx.has_flag("fast") {
        Output::item("Mode", "FAST (masscan-style)");
      }
      Output::item("Threads", &threads.to_string());
      Output::item("Timeout", &format!("{}ms", timeout));
      println!();
    }

    let scanner = PortScanner::new(target)
      .with_threads(threads)
      .with_timeout(timeout);
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

    let payload = scan_range_payload(target, start, end, threads, timeout, &open_ports);
    if render::render_machine_output(ctx, "rb network ports range", &payload)? {
      return Ok(());
    }

    if open_ports.is_empty() {
      Output::warning("No open ports found");
      return Ok(());
    }

    Output::subheader(&format!("Open ports ({}):", open_ports.len()));
    println!();

    Output::table_header(&["PORT", "STATE", "SERVICE", "BANNER"]);
    for result in open_ports {
      let service = result.service.as_deref().unwrap_or("unknown");
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

    let preset_str = ctx.get_flag("preset");
    let preset = preset_str.as_deref().unwrap_or("common");

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
      if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500)).is_ok() {
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

    // Database persistence setup using unified PersistenceConfig
    let persistence_config = ctx.get_persistence_config();

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
        let service = result.service.as_deref().unwrap_or("unknown");
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
      if persistence_config.force_save {
        let host_str = host_ip.to_string();
        let attributes =
          build_partition_attributes(ctx, &host_str, [("mode", "subnet"), ("cidr", cidr)]);
        let mut pm = StorageService::global().persistence_with_config(
          &host_str,
          persistence_config.clone(),
          attributes,
        )?;

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

          // Persist open port (state 0 = Open)
          if let Err(e) =
            pm.add_port_scan(std::net::IpAddr::V4(*host_ip), result.port, 0, service_id)
          {
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

  /// Advanced scan (SYN or UDP) using raw sockets
  fn advanced_scan(&self, ctx: &CliContext, scan_type: ScanType) -> Result<(), String> {
    let format = ctx.get_output_format();

    let target_str = ctx.target.as_ref().ok_or_else(|| {
            format!(
                "Missing target.\nUsage: rb network ports {} <HOST>\nExample: rb network ports {} 192.168.1.1",
                if scan_type == ScanType::Syn { "syn-scan" } else { "udp-scan" },
                if scan_type == ScanType::Syn { "syn-scan" } else { "udp-scan" }
            )
        })?;

    let target = Validator::resolve_host(target_str)?;

    // Parse timing template first - it overrides other settings
    let timing = ctx
      .get_flag("timing")
      .and_then(|t| TimingTemplate::from_str(&t));

    // Get configuration - timing template overrides defaults
    let cfg = config::get();
    let (threads, timeout) = if let Some(ref tmpl) = timing {
      (tmpl.parallelism(), tmpl.timeout_ms())
    } else {
      let threads = ctx
        .get_flag_or("threads", &cfg.network.threads.to_string())
        .parse::<usize>()
        .map_err(|_| "Invalid threads value")?;

      let timeout = ctx
        .get_flag_or("timeout", &cfg.network.timeout_ms.to_string())
        .parse::<u64>()
        .map_err(|_| "Invalid timeout value")?;

      (threads, timeout)
    };

    let preset_str = ctx.get_flag("preset");
    let preset = preset_str.as_deref().unwrap_or("common");

    let scan_name = match scan_type {
      ScanType::Syn => "SYN Scan",
      ScanType::Udp => "UDP Scan",
      _ => "Advanced Scan",
    };

    if format == OutputFormat::Human {
      Output::header(scan_name);
      Output::item("Target", &target.to_string());
      if let Some(ref tmpl) = timing {
        Output::item("Timing", &format!("{:?} - {}", tmpl, tmpl.description()));
      }
      Output::item("Preset", preset);
      Output::item("Threads", &threads.to_string());
      Output::item("Timeout", &format!("{}ms", timeout));

      if scan_type == ScanType::Syn {
        Output::warning("⚠ SYN scan requires root/CAP_NET_RAW privileges");
      }

      println!();
    }

    // Get ports based on preset
    let ports: Vec<u16> = match preset {
      "common" => {
        if scan_type == ScanType::Udp {
          AdvancedScanner::get_common_udp_ports()
        } else {
          PortScanner::get_common_ports()
        }
      }
      "full" => (1..=65535).collect(),
      "web" => vec![80, 443, 8080, 8443, 3000, 5000],
      _ => {
        return Err(format!(
          "Unknown preset: {}\nAvailable presets: common, full, web",
          preset
        ))
      }
    };

    let mut scanner = AdvancedScanner::new(target)
      .with_scan_type(scan_type)
      .with_threads(threads)
      .with_timeout(timeout);

    // Apply timing template if specified
    if let Some(tmpl) = timing {
      scanner = scanner.with_timing(tmpl);
    }

    if format == OutputFormat::Human {
      Output::spinner_start(&format!("Scanning {} ports", ports.len()));
    }

    let results = scanner.scan_ports(&ports);

    if format == OutputFormat::Human {
      Output::spinner_done();
    }

    // Filter interesting results (open, open|filtered for stealth, or closed for UDP)
    use crate::protocols::raw::PortState;
    let interesting: Vec<_> = results
      .iter()
      .filter(|r| {
        matches!(
          r.state,
          PortState::Open | PortState::OpenFiltered | PortState::Unfiltered
        ) || (scan_type == ScanType::Udp && r.state == PortState::Closed)
      })
      .collect();

    let payload = advanced_scan_payload(
      scan_type,
      target,
      preset,
      threads,
      timeout,
      ports.len(),
      &interesting,
    );
    let route_name = match scan_type {
      ScanType::Syn => "rb network ports syn-scan",
      ScanType::Udp => "rb network ports udp-scan",
      _ => "rb network ports advanced-scan",
    };
    if render::render_machine_output(ctx, route_name, &payload)? {
      return Ok(());
    }

    if interesting.is_empty() {
      Output::warning("No interesting ports found");
      return Ok(());
    }

    println!();
    Output::subheader(&format!(
      "Results ({} interesting / {} scanned)",
      interesting.len(),
      ports.len()
    ));
    println!();

    Output::table_header(&["PORT", "STATE", "SERVICE", "RTT", "TTL"]);

    for result in interesting {
      let service = result.service.as_deref().unwrap_or("-");

      let rtt = result
        .rtt_ms
        .map(|r| format!("{:.1}ms", r))
        .unwrap_or_else(|| "-".to_string());

      let ttl = result
        .ttl
        .map(|t| t.to_string())
        .unwrap_or_else(|| "-".to_string());

      // Color the state
      let state_str = format!("{}", result.state);
      let state_colored = match result.state {
        PortState::Open => format!("\x1b[32m{}\x1b[0m", state_str),
        PortState::OpenFiltered => format!("\x1b[33m{}\x1b[0m", state_str),
        PortState::Closed => format!("\x1b[31m{}\x1b[0m", state_str),
        PortState::Filtered => format!("\x1b[90m{}\x1b[0m", state_str),
        _ => state_str,
      };

      println!(
        "  {:>5}  {:15}  {:12}  {:>8}  {:>4}",
        result.port, state_colored, service, rtt, ttl
      );
    }

    println!();
    Output::success(&format!(
      "✓ {} scan completed",
      if scan_type == ScanType::Syn {
        "SYN"
      } else {
        "UDP"
      }
    ));

    Ok(())
  }

  /// Stealth scan (FIN/NULL/XMAS) using raw sockets
  fn stealth_scan(&self, ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();

    let target_str = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network ports stealth <HOST> --type fin|null|xmas\nExample: rb network ports stealth 192.168.1.1 --type xmas",
        )?;

    let target = Validator::resolve_host(target_str)?;

    // Get scan type from --type flag
    let scan_type_str = ctx.get_flag("type").ok_or(
            "Missing scan type.\nUsage: rb network ports stealth <HOST> --type fin|null|xmas\nExample: rb network ports stealth 192.168.1.1 --type fin",
        )?;

    let scan_type = match scan_type_str.to_lowercase().as_str() {
      "fin" => ScanType::Fin,
      "null" => ScanType::Null,
      "xmas" => ScanType::Xmas,
      _ => {
        return Err(format!(
          "Unknown stealth scan type: {}\nAvailable types: fin, null, xmas",
          scan_type_str
        ))
      }
    };

    // Parse timing template first - it overrides other settings
    let timing = ctx
      .get_flag("timing")
      .and_then(|t| TimingTemplate::from_str(&t));

    // Get configuration - timing template overrides defaults
    let cfg = config::get();
    let (threads, timeout) = if let Some(ref tmpl) = timing {
      (tmpl.parallelism(), tmpl.timeout_ms())
    } else {
      let threads = ctx
        .get_flag_or("threads", &cfg.network.threads.to_string())
        .parse::<usize>()
        .map_err(|_| "Invalid threads value")?;

      let timeout = ctx
        .get_flag_or("timeout", &cfg.network.timeout_ms.to_string())
        .parse::<u64>()
        .map_err(|_| "Invalid timeout value")?;

      (threads, timeout)
    };

    let preset_str = ctx.get_flag("preset");
    let preset = preset_str.as_deref().unwrap_or("common");

    let scan_name = match scan_type {
      ScanType::Fin => "FIN Stealth Scan",
      ScanType::Null => "NULL Stealth Scan",
      ScanType::Xmas => "XMAS Stealth Scan",
      _ => "Stealth Scan",
    };

    if format == OutputFormat::Human {
      Output::header(scan_name);
      Output::item("Target", &target.to_string());
      if let Some(ref tmpl) = timing {
        Output::item("Timing", &format!("{:?} - {}", tmpl, tmpl.description()));
      }
      Output::item("Type", &format!("{}", scan_type));
      Output::item("Preset", preset);
      Output::item("Timeout", &format!("{}ms", timeout));
      Output::warning("⚠ Stealth scans require root/CAP_NET_RAW privileges");

      println!();

      // Explanation of stealth scan behavior
      match scan_type {
        ScanType::Fin => {
          Output::info("FIN scan: No response = open|filtered, RST = closed");
        }
        ScanType::Null => {
          Output::info("NULL scan: No response = open|filtered, RST = closed");
        }
        ScanType::Xmas => {
          Output::info("XMAS scan (FIN+PSH+URG): No response = open|filtered, RST = closed");
        }
        _ => {}
      }

      println!();
    }

    // Get ports based on preset
    let ports: Vec<u16> = match preset {
      "common" => PortScanner::get_common_ports(),
      "full" => (1..=65535).collect(),
      "web" => vec![80, 443, 8080, 8443, 3000, 5000],
      _ => {
        return Err(format!(
          "Unknown preset: {}\nAvailable presets: common, full, web",
          preset
        ))
      }
    };

    let mut scanner = AdvancedScanner::new(target)
      .with_scan_type(scan_type)
      .with_threads(threads)
      .with_timeout(timeout);

    // Apply timing template if specified
    if let Some(tmpl) = timing {
      scanner = scanner.with_timing(tmpl);
    }

    if format == OutputFormat::Human {
      Output::spinner_start(&format!("Scanning {} ports", ports.len()));
    }

    let results = scanner.scan_ports(&ports);

    if format == OutputFormat::Human {
      Output::spinner_done();
    }

    // For stealth scans, we're interested in:
    // - OpenFiltered (no response = potentially open)
    // - Closed (got RST)
    use crate::protocols::raw::PortState;
    let open_filtered: Vec<_> = results
      .iter()
      .filter(|r| r.state == PortState::OpenFiltered)
      .collect();

    let closed: Vec<_> = results
      .iter()
      .filter(|r| r.state == PortState::Closed)
      .collect();

    let payload = stealth_scan_payload(
      scan_type,
      target,
      preset,
      threads,
      timeout,
      ports.len(),
      &open_filtered,
      closed.len(),
    );
    if render::render_machine_output(ctx, "rb network ports stealth", &payload)? {
      return Ok(());
    }

    println!();
    Output::subheader(&format!(
      "Results: {} open|filtered, {} closed / {} scanned",
      open_filtered.len(),
      closed.len(),
      ports.len()
    ));

    if !open_filtered.is_empty() {
      println!();
      Output::success(&format!(
        "Potentially open ports ({}):",
        open_filtered.len()
      ));
      println!();

      Output::table_header(&["PORT", "STATE", "SERVICE", "RTT", "TTL"]);

      for result in &open_filtered {
        let service = result.service.as_deref().unwrap_or("-");

        let rtt = result
          .rtt_ms
          .map(|r| format!("{:.1}ms", r))
          .unwrap_or_else(|| "-".to_string());

        let ttl = result
          .ttl
          .map(|t| t.to_string())
          .unwrap_or_else(|| "-".to_string());

        println!(
          "  {:>5}  \x1b[33mopen|filtered\x1b[0m  {:12}  {:>8}  {:>4}",
          result.port, service, rtt, ttl
        );
      }
    }

    if open_filtered.is_empty() && closed.is_empty() {
      Output::warning("No responses received (all ports filtered)");
    } else if open_filtered.is_empty() {
      Output::info("No open|filtered ports found - all scanned ports returned RST (closed)");
    }

    println!();
    Output::success(&format!("✓ {} completed", scan_name));

    Ok(())
  }

  /// High-speed mass scan using BlackRock cipher for IP randomization
  fn mass_scan(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or_else(|| {
      "Missing target CIDR. Usage: rb network ports mass-scan <cidr> [--rate 1000]".to_string()
    })?;

    // Parse rate (packets per second)
    let rate: f64 = ctx
      .flags
      .get("rate")
      .and_then(|s| s.parse().ok())
      .unwrap_or(1000.0);

    // Parse port specification (default: common ports)
    let ports: Vec<u16> = if let Some(port_spec) = ctx.flags.get("ports") {
      parse_port_spec(port_spec)?
    } else {
      vec![
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443,
      ]
    };

    // Parse resume index
    let resume_idx: u64 = ctx
      .flags
      .get("resume")
      .and_then(|s| s.parse().ok())
      .unwrap_or(0);

    // Parse shard (e.g., "1/4" for first of 4 shards)
    let (shard_num, shard_total) = if let Some(shard_spec) = ctx.flags.get("shard") {
      let parts: Vec<&str> = shard_spec.split('/').collect();
      if parts.len() == 2 {
        let n = parts[0].parse().unwrap_or(1);
        let total = parts[1].parse().unwrap_or(1);
        (n.max(1), total.max(1))
      } else {
        (1, 1)
      }
    } else {
      (1, 1)
    };

    // Parse seed for reproducible randomization
    let seed: u64 = ctx
      .flags
      .get("seed")
      .and_then(|s| s.parse().ok())
      .unwrap_or_else(|| {
        std::time::SystemTime::now()
          .duration_since(std::time::UNIX_EPOCH)
          .unwrap_or_default()
          .as_nanos() as u64
      });

    Output::header("High-Speed Mass Scan (BlackRock)");
    Output::item("Target", target);
    Output::item("Rate", &format!("{} pps", rate));
    Output::item("Ports", &format!("{} ports", ports.len()));
    if resume_idx > 0 {
      Output::item("Resume from", &resume_idx.to_string());
    }
    if shard_total > 1 {
      Output::item("Shard", &format!("{}/{}", shard_num, shard_total));
    }
    Output::item("Seed", &seed.to_string());
    println!();

    // Parse CIDR into IP range
    let scan_range =
      ScanRange::from_cidr(target, ports).map_err(|e| format!("Invalid CIDR: {}", e))?;

    let total_targets = scan_range.total_targets();
    Output::item("Total targets", &format!("{}", total_targets));

    // Calculate shard range
    let shard_size = total_targets / shard_total as u64;
    let shard_start = (shard_num - 1) as u64 * shard_size;
    let shard_end = if shard_num as u64 == shard_total as u64 {
      total_targets
    } else {
      shard_start + shard_size
    };

    // Create scanner components
    let mut rate_limiter = TokenBucket::new(rate);
    let syn_cookie = SynCookie::new();
    let mut dedup = DeduplicationCache::new();

    // Create randomized iterator with BlackRock cipher
    let mut iterator = RandomScanIterator::new(scan_range, seed);

    // Skip to resume position
    if resume_idx > 0 {
      for _ in 0..resume_idx {
        let _ = iterator.next();
      }
    }

    // Progress tracking
    let mut scanned = resume_idx;
    let mut open_ports = 0_u64;
    let start_time = std::time::Instant::now();

    Output::info(&format!("Scanning {} targets...", shard_end - shard_start));

    // Scan loop
    for (ip, port, _seq) in iterator {
      if scanned >= shard_end {
        break;
      }

      // Rate limiting
      while rate_limiter.acquire(1) == 0 {
        std::thread::sleep(std::time::Duration::from_micros(100));
      }

      // Generate SYN cookie for stateless tracking
      let ip_u32 = u32::from(ip);
      let _cookie = syn_cookie.generate(ip_u32, port, ip_u32, port);

      // Quick TCP connect check (simplified - full implementation would use raw sockets)
      let addr_str = format!("{}:{}", ip, port);
      if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
        if let Ok(_) =
          std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100))
        {
          // Deduplicate - insert() returns true if NEW (not seen before)
          if dedup.insert(ip_u32, port) {
            open_ports += 1;
            println!("\x1b[32mOPEN\x1b[0m {}:{}", ip, port);
          }
        }
      }

      scanned += 1;

      // Progress every 10000 targets
      if scanned % 10000 == 0 {
        let elapsed = start_time.elapsed().as_secs_f64();
        let actual_rate = scanned as f64 / elapsed;
        eprint!(
          "\r  Progress: {} / {} ({:.0} pps)",
          scanned, shard_end, actual_rate
        );
      }
    }

    let elapsed = start_time.elapsed();
    println!();
    println!();
    Output::success(&format!(
      "Scan complete: {} open ports found in {:.2}s",
      open_ports,
      elapsed.as_secs_f64()
    ));
    Output::item(
      "Average rate",
      &format!("{:.0} pps", scanned as f64 / elapsed.as_secs_f64()),
    );

    Ok(())
  }
}

fn port_result_to_json(
  result: &crate::modules::network::scanner::PortScanResult,
) -> crate::serde_json::Value {
  json!({
      "port": result.port,
      "service": result.service.clone().unwrap_or_else(|| "unknown".to_string()),
      "banner": result.banner.clone()
  })
}

fn range_result_to_json(
  result: &crate::modules::network::scanner::PortScanResult,
) -> crate::serde_json::Value {
  json!({
      "port": result.port,
      "state": "open",
      "service": result.service.clone().unwrap_or_else(|| "unknown".to_string()),
      "banner": result.banner.clone().unwrap_or_default().replace('\n', " ")
  })
}

fn advanced_result_to_json(
  result: &crate::modules::network::scanner::AdvancedScanResult,
) -> crate::serde_json::Value {
  json!({
      "port": result.port,
      "state": format!("{}", result.state),
      "service": result.service.clone().unwrap_or_default(),
      "rtt_ms": result.rtt_ms,
      "ttl": result.ttl
  })
}

fn scan_ports_payload(
  target: std::net::IpAddr,
  preset: &str,
  open_ports: &[&crate::modules::network::scanner::PortScanResult],
) -> Value {
  let ports_json: Vec<Value> = open_ports
    .iter()
    .map(|result| port_result_to_json(result))
    .collect();
  json!({
    "target": target.to_string(),
    "preset": preset,
    "open_count": open_ports.len(),
    "ports": ports_json
  })
}

fn scan_range_payload(
  target: std::net::IpAddr,
  start: u16,
  end: u16,
  threads: usize,
  timeout: u64,
  open_ports: &[&crate::modules::network::scanner::PortScanResult],
) -> Value {
  let ports_json: Vec<Value> = open_ports
    .iter()
    .map(|result| range_result_to_json(result))
    .collect();
  json!({
    "target": target.to_string(),
    "range_start": start,
    "range_end": end,
    "threads": threads,
    "timeout_ms": timeout,
    "total_scanned": end - start + 1,
    "open_count": open_ports.len(),
    "ports": ports_json
  })
}

fn advanced_scan_payload(
  scan_type: ScanType,
  target: std::net::IpAddr,
  preset: &str,
  threads: usize,
  timeout: u64,
  total_scanned: usize,
  interesting: &[&crate::modules::network::scanner::AdvancedScanResult],
) -> Value {
  let scan_type_str = match scan_type {
    ScanType::Syn => "syn",
    ScanType::Udp => "udp",
    _ => "advanced",
  };
  let ports_json: Vec<Value> = interesting
    .iter()
    .map(|result| advanced_result_to_json(result))
    .collect();
  json!({
    "scan_type": scan_type_str,
    "target": target.to_string(),
    "preset": preset,
    "threads": threads,
    "timeout_ms": timeout,
    "total_scanned": total_scanned,
    "interesting_count": interesting.len(),
    "ports": ports_json
  })
}

fn stealth_scan_payload(
  scan_type: ScanType,
  target: std::net::IpAddr,
  preset: &str,
  threads: usize,
  timeout: u64,
  total_scanned: usize,
  open_filtered: &[&crate::modules::network::scanner::AdvancedScanResult],
  closed_count: usize,
) -> Value {
  let scan_type_str = match scan_type {
    ScanType::Fin => "fin",
    ScanType::Null => "null",
    ScanType::Xmas => "xmas",
    _ => "stealth",
  };
  let open_filtered_json: Vec<Value> = open_filtered
    .iter()
    .map(|result| advanced_result_to_json(result))
    .collect();
  json!({
    "scan_type": scan_type_str,
    "target": target.to_string(),
    "preset": preset,
    "threads": threads,
    "timeout_ms": timeout,
    "total_scanned": total_scanned,
    "open_filtered_count": open_filtered.len(),
    "closed_count": closed_count,
    "open_filtered_ports": open_filtered_json
  })
}

/// Parse port specification like "1-1000,8080,8443"
fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
  let mut ports = Vec::new();
  for part in spec.split(',') {
    let part = part.trim();
    if part.contains('-') {
      let range: Vec<&str> = part.split('-').collect();
      if range.len() == 2 {
        let start: u16 = range[0]
          .parse()
          .map_err(|_| format!("Invalid port: {}", range[0]))?;
        let end: u16 = range[1]
          .parse()
          .map_err(|_| format!("Invalid port: {}", range[1]))?;
        for p in start..=end {
          ports.push(p);
        }
      }
    } else {
      let p: u16 = part
        .parse()
        .map_err(|_| format!("Invalid port: {}", part))?;
      ports.push(p);
    }
  }
  Ok(ports)
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn scan_ports_payload_reports_open_count() {
    let result = crate::modules::network::scanner::PortScanResult {
      port: 443,
      is_open: true,
      service: Some("https".to_string()),
      banner: Some("nginx".to_string()),
    };
    let payload = scan_ports_payload(
      std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
      "common",
      &[&result],
    );
    assert_eq!(payload["open_count"], 1);
    assert_eq!(payload["ports"][0]["service"], "https");
  }

  #[test]
  fn advanced_scan_payload_reports_scan_type() {
    let result = crate::modules::network::scanner::AdvancedScanResult {
      port: 22,
      state: crate::protocols::raw::PortState::Open,
      service: Some("ssh".to_string()),
      rtt_ms: Some(12.5),
      ttl: Some(64),
      banner: None,
    };
    let payload = advanced_scan_payload(
      ScanType::Syn,
      std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
      "common",
      100,
      500,
      1000,
      &[&result],
    );
    assert_eq!(payload["scan_type"], "syn");
    assert_eq!(payload["interesting_count"], 1);
    assert_eq!(payload["ports"][0]["port"], 22);
  }
}
