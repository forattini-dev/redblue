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
  advanced_scan_payload, gather_port_intelligence, parse_port_spec, stealth_scan_payload,
  truncate_banner,
};
use super::ScanCommand;

impl ScanCommand {
  pub(super) fn advanced_scan(&self, ctx: &CliContext, scan_type: ScanType) -> Result<(), String> {
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
}

impl ScanCommand {
  pub(super) fn stealth_scan(&self, ctx: &CliContext) -> Result<(), String> {
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
  pub(super) fn mass_scan(&self, ctx: &CliContext) -> Result<(), String> {
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
