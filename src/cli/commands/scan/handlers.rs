impl ScanCommand {
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
    assert_eq!(payload["open_count"], json!(1));
    assert_eq!(
      payload["ports"].as_array().unwrap()[0]["service"],
      json!("https")
    );
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
      scan_type: ScanType::Syn,
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
    assert_eq!(payload["scan_type"], json!("syn"));
    assert_eq!(payload["interesting_count"], json!(1));
    assert_eq!(payload["ports"].as_array().unwrap()[0]["port"], json!(22));
  }
}
