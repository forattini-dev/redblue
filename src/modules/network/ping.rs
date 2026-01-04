/// ICMP Ping Module
///
/// Provides ping functionality using the internal ICMP implementation
/// - ICMP protocol implementation (raw sockets)
/// - RTT statistics
/// - Packet loss tracking
use crate::protocols::icmp::IcmpPinger;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

/// Ping configuration
#[derive(Debug, Clone)]
pub struct PingConfig {
    pub count: usize,
    pub interval: Duration,
    pub timeout: Duration,
    pub packet_size: usize,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            count: 4,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            packet_size: 56,
        }
    }
}

/// Ping using internal ICMP implementation (no external binaries)
pub fn ping_system(host: &str, config: &PingConfig) -> Result<PingSystemResult, String> {
    let target = resolve_host(host)?;
    let pinger = IcmpPinger::new(target)
        .with_timeout(config.timeout)
        .with_packet_size(config.packet_size);
    let stats = pinger.ping(config.count, config.interval)?;

    let (min_rtt_ms, max_rtt_ms, avg_rtt_ms) = if stats.packets_received > 0 {
        (
            duration_to_ms(stats.min_rtt),
            duration_to_ms(stats.max_rtt),
            duration_to_ms(stats.avg_rtt),
        )
    } else {
        (0.0, 0.0, 0.0)
    };

    Ok(PingSystemResult {
        host: host.to_string(),
        packets_sent: stats.packets_sent,
        packets_received: stats.packets_received,
        packet_loss_percent: stats.packet_loss_percent,
        min_rtt_ms,
        max_rtt_ms,
        avg_rtt_ms,
        output: format!(
            "ICMP echo ({} sent, {} received)",
            stats.packets_sent, stats.packets_received
        ),
    })
}

/// System ping result
#[derive(Debug, Clone)]
pub struct PingSystemResult {
    pub host: String,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packet_loss_percent: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub avg_rtt_ms: f64,
    pub output: String,
}

fn resolve_host(host: &str) -> Result<IpAddr, String> {
    if let Ok(addr) = host.parse::<IpAddr>() {
        return Ok(addr);
    }

    let mut addrs = (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve host '{}': {}", host, e))?;
    addrs
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| format!("No IPs found for host '{}'", host))
}

fn duration_to_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

// ============================================================================
// TCP Ping Fallback - For when ICMP is unavailable
// ============================================================================

use std::net::TcpStream;
use std::time::Instant;

/// TCP Ping Configuration
#[derive(Debug, Clone)]
pub struct TcpPingConfig {
    pub count: usize,
    pub timeout: Duration,
    pub port: u16,
}

impl Default for TcpPingConfig {
    fn default() -> Self {
        Self {
            count: 4,
            timeout: Duration::from_secs(2),
            port: 443, // HTTPS by default
        }
    }
}

/// TCP Ping Result
#[derive(Debug, Clone)]
pub struct TcpPingResult {
    pub host: String,
    pub port: u16,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packet_loss_percent: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub avg_rtt_ms: f64,
    pub rtt_samples: Vec<f64>,
}

/// TCP Ping - measures TCP connection time as a proxy for latency
/// Works without root/admin privileges (unlike ICMP)
pub fn tcp_ping(host: &str, config: &TcpPingConfig) -> Result<TcpPingResult, String> {
    // Resolve hostname to IP
    let addr = format!("{}:{}", host, config.port);
    let socket_addrs: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {}: {}", host, e))?
        .collect();

    if socket_addrs.is_empty() {
        return Err(format!("No addresses found for {}", host));
    }

    let socket_addr = socket_addrs[0];

    let mut rtt_samples = Vec::with_capacity(config.count);
    let mut success_count = 0;

    for _ in 0..config.count {
        let start = Instant::now();

        match TcpStream::connect_timeout(&socket_addr, config.timeout) {
            Ok(_stream) => {
                let elapsed = start.elapsed();
                let rtt_ms = elapsed.as_secs_f64() * 1000.0;
                rtt_samples.push(rtt_ms);
                success_count += 1;
            }
            Err(_) => {
                // Connection failed - count as packet loss
            }
        }

        // Brief delay between probes (100ms)
        std::thread::sleep(Duration::from_millis(100));
    }

    // Calculate statistics
    let packets_sent = config.count;
    let packets_received = success_count;
    let packet_loss_percent = if packets_sent > 0 {
        ((packets_sent - packets_received) as f64 / packets_sent as f64) * 100.0
    } else {
        100.0
    };

    let (min_rtt_ms, max_rtt_ms, avg_rtt_ms) = if !rtt_samples.is_empty() {
        let min = rtt_samples.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtt_samples
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let avg = rtt_samples.iter().sum::<f64>() / rtt_samples.len() as f64;
        (min, max, avg)
    } else {
        (0.0, 0.0, 0.0)
    };

    Ok(TcpPingResult {
        host: host.to_string(),
        port: config.port,
        packets_sent,
        packets_received,
        packet_loss_percent,
        min_rtt_ms,
        max_rtt_ms,
        avg_rtt_ms,
        rtt_samples,
    })
}

/// Combined ping result (can be ICMP or TCP)
#[derive(Debug, Clone)]
pub struct SmartPingResult {
    pub host: String,
    pub method: PingMethod,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packet_loss_percent: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub avg_rtt_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingMethod {
    Icmp,
    TcpPort(u16),
}

impl std::fmt::Display for PingMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PingMethod::Icmp => write!(f, "ICMP"),
            PingMethod::TcpPort(port) => write!(f, "TCP/{}", port),
        }
    }
}

/// Smart ping - tries ICMP first, falls back to TCP if ICMP fails
/// This is useful for unprivileged users or when ICMP is blocked
pub fn smart_ping(host: &str, icmp_config: &PingConfig) -> Result<SmartPingResult, String> {
    // First, try ICMP ping
    match ping_system(host, icmp_config) {
        Ok(result) => {
            // ICMP succeeded
            Ok(SmartPingResult {
                host: result.host,
                method: PingMethod::Icmp,
                packets_sent: result.packets_sent,
                packets_received: result.packets_received,
                packet_loss_percent: result.packet_loss_percent,
                min_rtt_ms: result.min_rtt_ms,
                max_rtt_ms: result.max_rtt_ms,
                avg_rtt_ms: result.avg_rtt_ms,
            })
        }
        Err(_icmp_err) => {
            // ICMP failed, try TCP fallback
            // Try port 443 first (HTTPS), then 80 (HTTP)
            let ports = [443, 80];

            for port in ports {
                let tcp_config = TcpPingConfig {
                    count: icmp_config.count,
                    timeout: icmp_config.timeout,
                    port,
                };

                match tcp_ping(host, &tcp_config) {
                    Ok(result) if result.packets_received > 0 => {
                        return Ok(SmartPingResult {
                            host: result.host,
                            method: PingMethod::TcpPort(port),
                            packets_sent: result.packets_sent,
                            packets_received: result.packets_received,
                            packet_loss_percent: result.packet_loss_percent,
                            min_rtt_ms: result.min_rtt_ms,
                            max_rtt_ms: result.max_rtt_ms,
                            avg_rtt_ms: result.avg_rtt_ms,
                        });
                    }
                    _ => continue,
                }
            }

            Err(format!(
                "Host {} unreachable via ICMP and TCP (ports 443, 80)",
                host
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_config_default() {
        let config = PingConfig::default();
        assert_eq!(config.count, 4);
        assert_eq!(config.interval, Duration::from_secs(1));
        assert_eq!(config.timeout, Duration::from_secs(1));
        assert_eq!(config.packet_size, 56);
    }

    #[test]
    fn test_duration_to_ms() {
        let duration = Duration::from_millis(1500);
        assert!((duration_to_ms(duration) - 1500.0).abs() < 0.001);
    }

    #[test]
    fn test_resolve_host_ip_literal() {
        let ip = resolve_host("127.0.0.1").expect("resolve");
        assert_eq!(ip, "127.0.0.1".parse().unwrap());
    }
}
