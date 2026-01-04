//! Network MCP Tools
//!
//! Port scanning, ping, health checks, traceroute, and sweep tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::modules::network::highspeed::{
    DeduplicationCache, RandomScanIterator, ScanRange, TokenBucket,
};
use crate::modules::network::scanner::PortScanner;
use crate::utils::json::JsonValue;
use std::net::IpAddr;
use std::time::Duration;

/// Register network tools with the server
pub fn register_network_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.network.scan",
            description: "Scan target for open ports. Supports common, web, full, or custom port specifications.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target IP address or hostname to scan.",
                    required: true,
                },
                ToolField {
                    name: "ports",
                    field_type: "string",
                    description: "Ports to scan: 'common', 'web', 'full', or custom (e.g., '22,80,443' or '1-1000').",
                    required: false,
                },
                ToolField {
                    name: "timeout",
                    field_type: "number",
                    description: "Connection timeout in milliseconds (default: 1000).",
                    required: false,
                },
                ToolField {
                    name: "threads",
                    field_type: "number",
                    description: "Number of concurrent scan threads (default: 100).",
                    required: false,
                },
            ],
            handler: tool_network_scan,
        },
        ToolDefinition {
            name: "rb.network.ping",
            description: "Check if a host is reachable by attempting TCP connections to common ports.",
            fields: &[ToolField {
                name: "target",
                field_type: "string",
                description: "Target IP address or hostname to ping.",
                required: true,
            }],
            handler: tool_network_ping,
        },
        ToolDefinition {
            name: "rb.network.health",
            description: "Check health of specific ports on a target.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target IP address or hostname.",
                    required: true,
                },
                ToolField {
                    name: "ports",
                    field_type: "string",
                    description: "Comma-separated list of ports to check (e.g., '80,443,3306').",
                    required: true,
                },
            ],
            handler: tool_network_health,
        },
        ToolDefinition {
            name: "rb.network.traceroute",
            description: "Trace the network path to a target.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target IP address or hostname.",
                    required: true,
                },
                ToolField {
                    name: "max_hops",
                    field_type: "number",
                    description: "Maximum number of hops (default: 30).",
                    required: false,
                },
                ToolField {
                    name: "timeout_ms",
                    field_type: "number",
                    description: "Timeout per hop in milliseconds (default: 1000).",
                    required: false,
                },
            ],
            handler: tool_network_traceroute,
        },
        ToolDefinition {
            name: "rb.network.sweep",
            description: "Ping sweep a CIDR range to find live hosts.",
            fields: &[
                ToolField {
                    name: "cidr",
                    field_type: "string",
                    description: "CIDR range to sweep (e.g., '192.168.1.0/24').",
                    required: true,
                },
                ToolField {
                    name: "timeout_ms",
                    field_type: "number",
                    description: "Timeout per host in milliseconds (default: 1000).",
                    required: false,
                },
            ],
            handler: tool_network_sweep,
        },
        ToolDefinition {
            name: "rb.network.scan.fast",
            description: "High-speed mass scan using BlackRock cipher for IP randomization. \
                         Supports resume, sharding for distributed scans, and rate limiting.",
            fields: &[
                ToolField {
                    name: "cidr",
                    field_type: "string",
                    description: "Target CIDR range (e.g., '192.168.1.0/24' or '10.0.0.0/8').",
                    required: true,
                },
                ToolField {
                    name: "ports",
                    field_type: "string",
                    description: "Ports to scan: 'common', 'web', or custom (e.g., '22,80,443').",
                    required: false,
                },
                ToolField {
                    name: "rate",
                    field_type: "number",
                    description: "Packets per second rate limit (default: 1000).",
                    required: false,
                },
                ToolField {
                    name: "shard",
                    field_type: "string",
                    description: "Shard specification for distributed scanning (e.g., '1/4' for first of 4 shards).",
                    required: false,
                },
                ToolField {
                    name: "resume",
                    field_type: "number",
                    description: "Resume from target index (for resumable scans).",
                    required: false,
                },
                ToolField {
                    name: "seed",
                    field_type: "number",
                    description: "Seed for deterministic IP randomization (default: random).",
                    required: false,
                },
            ],
            handler: tool_network_scan_fast,
        },
    ]
}

fn tool_network_scan(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let target_str = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    // Resolve hostname to IP if needed
    let target_ip: IpAddr = target_str.parse().or_else(|_| {
        use std::net::ToSocketAddrs;
        format!("{}:80", target_str)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|addr| addr.ip())
            .ok_or_else(|| format!("Could not resolve hostname: {}", target_str))
    })?;

    let mut scanner = PortScanner::new(target_ip);

    if let Some(timeout) = args.get("timeout").and_then(|v| v.as_f64()) {
        scanner = scanner.with_timeout(timeout as u64);
    }

    if let Some(threads) = args.get("threads").and_then(|v| v.as_f64()) {
        scanner = scanner.with_threads(threads as usize);
    }

    let ports_arg = args
        .get("ports")
        .and_then(|v| v.as_str())
        .unwrap_or("common");

    let ports: Vec<u16> = match ports_arg {
        "common" => PortScanner::get_common_ports(),
        "web" => vec![80, 443, 8080, 8443, 8000, 8888, 3000, 5000],
        "full" => (1..=65535).collect(),
        custom => parse_port_spec(custom),
    };

    let results = scanner.scan_ports(&ports);
    let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();

    let ports_json: Vec<JsonValue> = open_ports
        .iter()
        .map(|r| {
            JsonValue::object(vec![
                ("port".to_string(), JsonValue::Number(r.port as f64)),
                ("state".to_string(), JsonValue::String("open".to_string())),
                (
                    "service".to_string(),
                    r.service
                        .as_ref()
                        .map(|s| JsonValue::String(s.clone()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "banner".to_string(),
                    r.banner
                        .as_ref()
                        .map(|b| JsonValue::String(b.clone()))
                        .unwrap_or(JsonValue::Null),
                ),
            ])
        })
        .collect();

    let text = format!(
        "Port scan of {}: {} open ports found out of {} scanned",
        target_str,
        open_ports.len(),
        ports.len()
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "target".to_string(),
                JsonValue::String(target_str.to_string()),
            ),
            (
                "target_ip".to_string(),
                JsonValue::String(target_ip.to_string()),
            ),
            (
                "ports_scanned".to_string(),
                JsonValue::Number(ports.len() as f64),
            ),
            (
                "open_count".to_string(),
                JsonValue::Number(open_ports.len() as f64),
            ),
            ("open_ports".to_string(), JsonValue::array(ports_json)),
        ]),
    })
}

fn tool_network_ping(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let common_ports = [80, 443, 22, 21, 25, 8080];
    let timeout = Duration::from_millis(2000);

    let mut reachable = false;
    let mut open_port = None;
    let mut response_time = Duration::ZERO;

    for port in &common_ports {
        let start = std::time::Instant::now();
        let addr = format!("{}:{}", target, port);

        let is_reachable = if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
            std::net::TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
        } else {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|sa| std::net::TcpStream::connect_timeout(&sa, timeout).is_ok())
                .unwrap_or(false)
        };

        if is_reachable {
            reachable = true;
            open_port = Some(*port);
            response_time = start.elapsed();
            break;
        }
    }

    let text = if reachable {
        format!(
            "Host {} is UP (port {} responded in {}ms)",
            target,
            open_port.unwrap_or(0),
            response_time.as_millis()
        )
    } else {
        format!("Host {} appears to be DOWN or filtered", target)
    };

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("target".to_string(), JsonValue::String(target.to_string())),
            ("reachable".to_string(), JsonValue::Bool(reachable)),
            (
                "responding_port".to_string(),
                open_port
                    .map(|p| JsonValue::Number(p as f64))
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "response_time_ms".to_string(),
                JsonValue::Number(response_time.as_millis() as f64),
            ),
        ]),
    })
}

fn tool_network_health(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let ports_str = args
        .get("ports")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: ports")?;

    let ports: Vec<u16> = ports_str
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();

    if ports.is_empty() {
        return Err("No valid ports provided".to_string());
    }

    let timeout = Duration::from_millis(2000);
    let mut results = Vec::new();

    for port in &ports {
        let start = std::time::Instant::now();
        let addr = format!("{}:{}", target, port);

        let is_open = if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
            std::net::TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
        } else {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|sa| std::net::TcpStream::connect_timeout(&sa, timeout).is_ok())
                .unwrap_or(false)
        };

        let elapsed = start.elapsed();
        results.push(JsonValue::object(vec![
            ("port".to_string(), JsonValue::Number(*port as f64)),
            (
                "status".to_string(),
                JsonValue::String(if is_open { "open" } else { "closed" }.to_string()),
            ),
            (
                "response_time_ms".to_string(),
                JsonValue::Number(elapsed.as_millis() as f64),
            ),
        ]));
    }

    let open_count = results
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("open"))
        .count();

    let text = format!(
        "Health check for {}: {}/{} ports open",
        target,
        open_count,
        ports.len()
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("target".to_string(), JsonValue::String(target.to_string())),
            (
                "total_ports".to_string(),
                JsonValue::Number(ports.len() as f64),
            ),
            (
                "open_count".to_string(),
                JsonValue::Number(open_count as f64),
            ),
            ("results".to_string(), JsonValue::array(results)),
        ]),
    })
}

fn tool_network_traceroute(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let _max_hops = args
        .get("max_hops")
        .and_then(|v| v.as_f64())
        .map(|n| n as u8)
        .unwrap_or(30);

    let _timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_f64())
        .map(|n| n as u64)
        .unwrap_or(1000);

    // Traceroute requires raw sockets which need root privileges
    // For now, return a placeholder indicating this limitation
    Ok(ToolResult {
        text: format!("Traceroute to {} requires elevated privileges", target),
        data: JsonValue::object(vec![
            ("target".to_string(), JsonValue::String(target.to_string())),
            (
                "note".to_string(),
                JsonValue::String("Traceroute requires raw socket access (root/admin)".to_string()),
            ),
        ]),
    })
}

fn tool_network_sweep(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let cidr = args
        .get("cidr")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: cidr")?;

    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_f64())
        .map(|n| n as u64)
        .unwrap_or(1000);

    // Parse CIDR
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format. Expected format: 192.168.1.0/24".to_string());
    }

    let base_ip: std::net::Ipv4Addr = parts[0].parse().map_err(|_| "Invalid IP address in CIDR")?;
    let prefix_len: u8 = parts[1]
        .parse()
        .map_err(|_| "Invalid prefix length in CIDR")?;

    if prefix_len > 32 {
        return Err("Prefix length must be <= 32".to_string());
    }

    // Calculate host range
    let host_bits = 32 - prefix_len;
    let num_hosts = if host_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << host_bits) - 2
    }; // Exclude network and broadcast

    if num_hosts > 65534 {
        return Err("CIDR range too large. Maximum /16 (65534 hosts) supported".to_string());
    }

    let base_u32 = u32::from(base_ip);
    let timeout = Duration::from_millis(timeout_ms);
    let mut live_hosts = Vec::new();

    // Sweep the range
    for i in 1..=num_hosts {
        let ip_u32 = base_u32 + i;
        let ip = std::net::Ipv4Addr::from(ip_u32);
        let addr = format!("{}:80", ip);

        if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
            if std::net::TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
                live_hosts.push(ip.to_string());
            }
        }
    }

    let text = format!(
        "Sweep of {}: {} live hosts found out of {} scanned",
        cidr,
        live_hosts.len(),
        num_hosts
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("cidr".to_string(), JsonValue::String(cidr.to_string())),
            (
                "hosts_scanned".to_string(),
                JsonValue::Number(num_hosts as f64),
            ),
            (
                "live_count".to_string(),
                JsonValue::Number(live_hosts.len() as f64),
            ),
            (
                "live_hosts".to_string(),
                JsonValue::array(live_hosts.into_iter().map(JsonValue::String).collect()),
            ),
        ]),
    })
}

fn parse_port_spec(spec: &str) -> Vec<u16> {
    let mut result = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() == 2 {
                if let (Ok(start), Ok(end)) = (bounds[0].parse::<u16>(), bounds[1].parse::<u16>()) {
                    result.extend(start..=end);
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            result.push(port);
        }
    }
    if result.is_empty() {
        PortScanner::get_common_ports()
    } else {
        result
    }
}

/// High-speed mass scan using BlackRock cipher for IP randomization
fn tool_network_scan_fast(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let cidr = args
        .get("cidr")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: cidr")?;

    // Parse ports
    let ports: Vec<u16> = if let Some(port_spec) = args.get("ports").and_then(|v| v.as_str()) {
        match port_spec {
            "common" => PortScanner::get_common_ports(),
            "web" => vec![80, 443, 8080, 8443, 8000, 8888, 3000, 5000],
            custom => parse_port_spec(custom),
        }
    } else {
        vec![
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443,
        ]
    };

    // Parse rate limit
    let rate = args.get("rate").and_then(|v| v.as_f64()).unwrap_or(1000.0);

    // Parse shard specification
    let (shard_num, shard_total) =
        if let Some(shard_spec) = args.get("shard").and_then(|v| v.as_str()) {
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

    // Parse resume index
    let resume_idx = args
        .get("resume")
        .and_then(|v| v.as_f64())
        .map(|n| n as u64)
        .unwrap_or(0);

    // Parse seed
    let seed = args
        .get("seed")
        .and_then(|v| v.as_f64())
        .map(|n| n as u64)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        });

    // Parse CIDR into scan range
    let scan_range =
        ScanRange::from_cidr(cidr, ports).map_err(|e| format!("Invalid CIDR: {}", e))?;

    let total_targets = scan_range.total_targets();

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
    let mut dedup = DeduplicationCache::new();

    // Create randomized iterator with BlackRock cipher
    let mut iterator = RandomScanIterator::new(scan_range, seed);

    // Skip to resume position
    if resume_idx > 0 {
        for _ in 0..resume_idx {
            let _ = iterator.next();
        }
    }

    // Limit scan time for MCP (max 30 seconds or 10000 targets)
    let max_targets = 10000u64.min(shard_end - shard_start);
    let mut scanned = resume_idx;
    let mut open_ports = Vec::new();
    let start_time = std::time::Instant::now();
    let max_duration = Duration::from_secs(30);

    // Scan loop
    for (ip, port, _seq) in iterator {
        if scanned >= shard_start + max_targets {
            break;
        }
        if start_time.elapsed() > max_duration {
            break;
        }

        // Rate limiting
        while rate_limiter.acquire(1) == 0 {
            std::thread::sleep(Duration::from_micros(100));
        }

        // Quick TCP connect check
        let addr_str = format!("{}:{}", ip, port);
        if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                let ip_u32 = u32::from(ip);
                if dedup.insert(ip_u32, port) {
                    open_ports.push(format!("{}:{}", ip, port));
                }
            }
        }

        scanned += 1;
    }

    let elapsed = start_time.elapsed();
    let scanned_count = scanned - resume_idx;
    let actual_rate = if elapsed.as_secs_f64() > 0.0 {
        scanned_count as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let text = format!(
        "High-speed scan of {}: {} targets scanned, {} open ports found ({:.0} pps)",
        cidr,
        scanned_count,
        open_ports.len(),
        actual_rate
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("cidr".to_string(), JsonValue::String(cidr.to_string())),
            (
                "total_targets".to_string(),
                JsonValue::Number(total_targets as f64),
            ),
            (
                "scanned".to_string(),
                JsonValue::Number(scanned_count as f64),
            ),
            (
                "open_count".to_string(),
                JsonValue::Number(open_ports.len() as f64),
            ),
            (
                "open_ports".to_string(),
                JsonValue::array(open_ports.into_iter().map(JsonValue::String).collect()),
            ),
            ("seed".to_string(), JsonValue::Number(seed as f64)),
            (
                "shard".to_string(),
                JsonValue::String(format!("{}/{}", shard_num, shard_total)),
            ),
            ("resume_at".to_string(), JsonValue::Number(scanned as f64)),
            (
                "elapsed_secs".to_string(),
                JsonValue::Number(elapsed.as_secs_f64()),
            ),
            (
                "actual_rate_pps".to_string(),
                JsonValue::Number(actual_rate),
            ),
        ]),
    })
}
