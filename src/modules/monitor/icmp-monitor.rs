/// ICMP Monitoring and Analysis
/// Monitor ICMP traffic, track ping/traceroute, analyze network health
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// ICMP Packet Type Statistics
#[derive(Debug, Clone, Default)]
pub struct IcmpTypeStats {
    pub echo_request: u64,     // Type 8
    pub echo_reply: u64,       // Type 0
    pub dest_unreachable: u64, // Type 3
    pub time_exceeded: u64,    // Type 11
    pub redirect: u64,         // Type 5
    pub other: u64,
}

/// ICMP Host Statistics
#[derive(Debug, Clone)]
pub struct IcmpHostStats {
    pub host: IpAddr,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub avg_rtt_ms: f64,
    pub last_seen: Instant,
    pub type_stats: IcmpTypeStats,
}

impl IcmpHostStats {
    pub fn new(host: IpAddr) -> Self {
        Self {
            host,
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
            min_rtt_ms: f64::MAX,
            max_rtt_ms: 0.0,
            avg_rtt_ms: 0.0,
            last_seen: Instant::now(),
            type_stats: IcmpTypeStats::default(),
        }
    }

    pub fn packet_loss_rate(&self) -> f64 {
        if self.packets_sent > 0 {
            self.packets_lost as f64 / self.packets_sent as f64 * 100.0
        } else {
            0.0
        }
    }

    pub fn update_rtt(&mut self, rtt_ms: f64) {
        if rtt_ms < self.min_rtt_ms {
            self.min_rtt_ms = rtt_ms;
        }
        if rtt_ms > self.max_rtt_ms {
            self.max_rtt_ms = rtt_ms;
        }

        // Update running average
        let total_received = self.packets_received as f64;
        self.avg_rtt_ms =
            (self.avg_rtt_ms * (total_received - 1.0) + rtt_ms) / total_received;
    }
}

/// Ping Result
#[derive(Debug, Clone)]
pub struct PingResult {
    pub host: IpAddr,
    pub sequence: u16,
    pub ttl: u8,
    pub rtt_ms: f64,
    pub success: bool,
    pub error: Option<String>,
}

/// Traceroute Hop
#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_num: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
    pub ttl: u8,
    pub timeout: bool,
}

/// ICMP Monitor
pub struct IcmpMonitor {
    hosts: HashMap<IpAddr, IcmpHostStats>,
    max_hosts: usize,
}

impl IcmpMonitor {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            max_hosts: 1000,
        }
    }

    pub fn with_max_hosts(mut self, max: usize) -> Self {
        self.max_hosts = max;
        self
    }

    /// Track ICMP packet sent
    pub fn record_sent(&mut self, host: IpAddr, packet_type: u8) {
        let stats = self
            .hosts
            .entry(host)
            .or_insert_with(|| IcmpHostStats::new(host));

        stats.packets_sent += 1;
        stats.last_seen = Instant::now();

        match packet_type {
            8 => stats.type_stats.echo_request += 1,
            _ => stats.type_stats.other += 1,
        }
    }

    /// Track ICMP packet received
    pub fn record_received(
        &mut self,
        host: IpAddr,
        packet_type: u8,
        rtt_ms: Option<f64>,
    ) {
        let stats = self
            .hosts
            .entry(host)
            .or_insert_with(|| IcmpHostStats::new(host));

        stats.packets_received += 1;
        stats.last_seen = Instant::now();

        if let Some(rtt) = rtt_ms {
            stats.update_rtt(rtt);
        }

        match packet_type {
            0 => stats.type_stats.echo_reply += 1,
            3 => stats.type_stats.dest_unreachable += 1,
            5 => stats.type_stats.redirect += 1,
            11 => stats.type_stats.time_exceeded += 1,
            _ => stats.type_stats.other += 1,
        }
    }

    /// Record packet loss
    pub fn record_loss(&mut self, host: IpAddr) {
        let stats = self
            .hosts
            .entry(host)
            .or_insert_with(|| IcmpHostStats::new(host));

        stats.packets_lost += 1;
    }

    /// Get statistics for a host
    pub fn host_stats(&self, host: &IpAddr) -> Option<&IcmpHostStats> {
        self.hosts.get(host)
    }

    /// Get all monitored hosts
    pub fn all_hosts(&self) -> Vec<&IcmpHostStats> {
        self.hosts.values().collect()
    }

    /// Get hosts with packet loss
    pub fn hosts_with_loss(&self) -> Vec<&IcmpHostStats> {
        self.hosts
            .values()
            .filter(|s| s.packet_loss_rate() > 0.0)
            .collect()
    }

    /// Cleanup old hosts
    pub fn cleanup_old(&mut self, max_age: Duration) {
        self.hosts
            .retain(|_, stats| stats.last_seen.elapsed() < max_age);
    }

    /// Get overall statistics
    pub fn overall_stats(&self) -> OverallIcmpStats {
        let mut stats = OverallIcmpStats {
            total_hosts: self.hosts.len(),
            total_packets_sent: 0,
            total_packets_received: 0,
            total_packets_lost: 0,
            average_rtt_ms: 0.0,
            type_stats: IcmpTypeStats::default(),
        };

        let mut rtt_sum = 0.0;
        let mut rtt_count = 0;

        for host_stats in self.hosts.values() {
            stats.total_packets_sent += host_stats.packets_sent;
            stats.total_packets_received += host_stats.packets_received;
            stats.total_packets_lost += host_stats.packets_lost;

            if host_stats.packets_received > 0 {
                rtt_sum += host_stats.avg_rtt_ms;
                rtt_count += 1;
            }

            // Aggregate type stats
            stats.type_stats.echo_request += host_stats.type_stats.echo_request;
            stats.type_stats.echo_reply += host_stats.type_stats.echo_reply;
            stats.type_stats.dest_unreachable += host_stats.type_stats.dest_unreachable;
            stats.type_stats.time_exceeded += host_stats.type_stats.time_exceeded;
            stats.type_stats.redirect += host_stats.type_stats.redirect;
            stats.type_stats.other += host_stats.type_stats.other;
        }

        if rtt_count > 0 {
            stats.average_rtt_ms = rtt_sum / rtt_count as f64;
        }

        stats
    }
}

impl Default for IcmpMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct OverallIcmpStats {
    pub total_hosts: usize,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
    pub total_packets_lost: u64,
    pub average_rtt_ms: f64,
    pub type_stats: IcmpTypeStats,
}

/// Ping utility (uses existing ICMP client)
/// TODO: Implement when IcmpClient is available in protocols/icmp.rs
/*
pub struct Pinger {
    client: IcmpClient,
    timeout: Duration,
    count: usize,
}

impl Pinger {
    pub fn new() -> Self {
        Self {
            client: IcmpClient::new(),
            timeout: Duration::from_secs(2),
            count: 4,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }

    /// Ping a host multiple times
    pub fn ping(&self, host: &str) -> Result<Vec<PingResult>, String> {
        let ip: IpAddr = host
            .parse()
            .map_err(|_| format!("Invalid IP address: {}", host))?;

        let mut results = Vec::new();

        for seq in 0..self.count {
            let start = Instant::now();

            match self.client.ping(&ip.to_string()) {
                Ok((reply_ip, ttl)) => {
                    let rtt = start.elapsed();
                    results.push(PingResult {
                        host: reply_ip,
                        sequence: seq as u16,
                        ttl,
                        rtt_ms: rtt.as_secs_f64() * 1000.0,
                        success: true,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(PingResult {
                        host: ip,
                        sequence: seq as u16,
                        ttl: 0,
                        rtt_ms: 0.0,
                        success: false,
                        error: Some(e),
                    });
                }
            }

            // Wait before next ping
            if seq < self.count - 1 {
                std::thread::sleep(Duration::from_secs(1));
            }
        }

        Ok(results)
    }

    /// Calculate ping statistics
    pub fn ping_stats(results: &[PingResult]) -> PingStatistics {
        let mut stats = PingStatistics {
            packets_sent: results.len(),
            packets_received: 0,
            packet_loss_percent: 0.0,
            min_rtt_ms: f64::MAX,
            max_rtt_ms: 0.0,
            avg_rtt_ms: 0.0,
            mdev_rtt_ms: 0.0,
        };

        let mut rtt_sum = 0.0;
        let mut rtt_values = Vec::new();

        for result in results {
            if result.success {
                stats.packets_received += 1;
                let rtt = result.rtt_ms;
                rtt_sum += rtt;
                rtt_values.push(rtt);

                if rtt < stats.min_rtt_ms {
                    stats.min_rtt_ms = rtt;
                }
                if rtt > stats.max_rtt_ms {
                    stats.max_rtt_ms = rtt;
                }
            }
        }

        if stats.packets_received > 0 {
            stats.avg_rtt_ms = rtt_sum / stats.packets_received as f64;

            // Calculate mean deviation
            let mut deviation_sum = 0.0;
            for &rtt in &rtt_values {
                deviation_sum += (rtt - stats.avg_rtt_ms).abs();
            }
            stats.mdev_rtt_ms = deviation_sum / rtt_values.len() as f64;
        } else {
            stats.min_rtt_ms = 0.0;
        }

        stats.packet_loss_percent =
            ((stats.packets_sent - stats.packets_received) as f64 / stats.packets_sent as f64)
                * 100.0;

        stats
    }
}

impl Default for Pinger {
    fn default() -> Self {
        Self::new()
    }
}
*/

#[derive(Debug, Clone)]
pub struct PingStatistics {
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packet_loss_percent: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub avg_rtt_ms: f64,
    pub mdev_rtt_ms: f64, // Mean deviation
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_icmp_monitor_creation() {
        let monitor = IcmpMonitor::new();
        assert_eq!(monitor.hosts.len(), 0);
    }

    #[test]
    fn test_record_sent_received() {
        let mut monitor = IcmpMonitor::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        monitor.record_sent(ip, 8); // Echo request
        monitor.record_received(ip, 0, Some(15.5)); // Echo reply

        let stats = monitor.host_stats(&ip).unwrap();
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.avg_rtt_ms, 15.5);
        assert_eq!(stats.type_stats.echo_request, 1);
        assert_eq!(stats.type_stats.echo_reply, 1);
    }

    #[test]
    fn test_packet_loss() {
        let mut monitor = IcmpMonitor::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        monitor.record_sent(ip, 8);
        monitor.record_sent(ip, 8);
        monitor.record_sent(ip, 8);
        monitor.record_sent(ip, 8);
        monitor.record_received(ip, 0, Some(10.0));
        monitor.record_loss(ip);
        monitor.record_loss(ip);
        monitor.record_loss(ip);

        let stats = monitor.host_stats(&ip).unwrap();
        assert_eq!(stats.packets_sent, 4);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.packets_lost, 3);
        assert_eq!(stats.packet_loss_rate(), 75.0);
    }

    #[test]
    fn test_rtt_statistics() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let mut stats = IcmpHostStats::new(ip);

        stats.packets_received = 1;
        stats.update_rtt(10.0);
        assert_eq!(stats.min_rtt_ms, 10.0);
        assert_eq!(stats.max_rtt_ms, 10.0);
        assert_eq!(stats.avg_rtt_ms, 10.0);

        stats.packets_received = 2;
        stats.update_rtt(20.0);
        assert_eq!(stats.min_rtt_ms, 10.0);
        assert_eq!(stats.max_rtt_ms, 20.0);
        assert_eq!(stats.avg_rtt_ms, 15.0);
    }
}
