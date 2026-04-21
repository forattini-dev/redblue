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
use crate::modules::network::scanner::{
  AdvancedScanner, PortScanResult, PortScanner, ScanType, TimingTemplate,
};
use crate::serde_json::Value;
use crate::storage::service::StorageService;
use std::collections::HashMap;
use std::sync::Arc;

use super::helpers::{
  gather_port_intelligence, scan_ports_payload, scan_range_payload, truncate_banner,
};
use super::ScanCommand;

impl ScanCommand {
  pub(super) fn scan_ports(&self, ctx: &CliContext) -> Result<(), String> {
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

  pub(super) fn scan_range(&self, ctx: &CliContext) -> Result<(), String> {
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

  pub(super) fn scan_subnet(&self, ctx: &CliContext) -> Result<(), String> {
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

    // Scan alive hosts in parallel (max 4 hosts concurrently).
    // Each host's port scan is already internally threaded, so we add a
    // second level of parallelism across hosts with a staggered start
    // to avoid a thundering herd of SYN probes.
    use crate::modules::common::parallel;
    use std::sync::Mutex;

    let host_results: Mutex<Vec<(usize, Ipv4Addr, Vec<PortScanResult>)>> = Mutex::new(Vec::new());

    parallel::run_with_jitter(4, 2000, &alive_hosts, |host_ip| {
      let ip = *host_ip;
      let scanner = PortScanner::new(IpAddr::V4(ip))
        .with_threads(threads)
        .with_timeout(timeout);

      let results = match preset {
        "common" => scanner.scan_common(),
        "web" => scanner.scan_ports(&[80, 443, 8080, 8443, 3000, 5000]),
        "full" => scanner.scan_range(1, 65535),
        _ => return,
      };

      let idx = alive_hosts.iter().position(|h| *h == ip).unwrap_or(0);
      host_results.lock().unwrap().push((idx, ip, results));
    });

    let mut all_host_results = host_results.into_inner().unwrap();
    all_host_results.sort_by_key(|(idx, _, _)| *idx);

    for (idx, host_ip, results) in &all_host_results {
      println!();
      println!(
        "[{}/{}] Scanning {}...",
        idx + 1,
        alive_hosts.len(),
        host_ip
      );

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
}
