/// Protocol Monitoring Module
/// Monitor and analyze network protocols: TCP, UDP, ICMP, DNS
///
/// This module provides real-time monitoring capabilities for various network protocols,
/// allowing observation of connection states, traffic patterns, packet loss, and performance metrics.

pub mod icmp_monitor;
pub mod tcp_monitor;
pub mod udp_monitor;

pub use icmp_monitor::{IcmpMonitor, IcmpHostStats, PingResult, PingStatistics};
// TODO: Re-enable when IcmpClient is implemented
// pub use icmp_monitor::Pinger;
pub use tcp_monitor::{TcpConnection, TcpConnectionTester, TcpMonitor, TcpState, TcpStats};
pub use udp_monitor::{UdpFlow, UdpMonitor, UdpPortTester, UdpStats};

use std::time::Duration;

/// Protocol Monitor - Unified interface for all protocol monitoring
pub struct ProtocolMonitor {
    pub tcp: TcpMonitor,
    pub udp: UdpMonitor,
    pub icmp: IcmpMonitor,
}

impl ProtocolMonitor {
    pub fn new() -> Self {
        Self {
            tcp: TcpMonitor::new(),
            udp: UdpMonitor::new(),
            icmp: IcmpMonitor::new(),
        }
    }

    /// Cleanup idle connections across all protocols
    pub fn cleanup_all(&mut self, max_idle: Duration) {
        self.tcp.cleanup_idle(max_idle);
        self.udp.cleanup_idle(max_idle);
        self.icmp.cleanup_old(max_idle);
    }

    /// Get unified statistics
    pub fn get_stats(&self) -> ProtocolStats {
        ProtocolStats {
            tcp: self.tcp.stats(),
            udp: self.udp.stats(),
            icmp: self.icmp.overall_stats(),
        }
    }
}

impl Default for ProtocolMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Unified protocol statistics
#[derive(Debug, Clone)]
pub struct ProtocolStats {
    pub tcp: TcpStats,
    pub udp: UdpStats,
    pub icmp: icmp_monitor::OverallIcmpStats,
}

impl ProtocolStats {
    pub fn total_connections(&self) -> usize {
        self.tcp.total_connections + self.udp.total_flows
    }

    pub fn total_packets(&self) -> u64 {
        self.udp.total_packets_sent
            + self.udp.total_packets_received
            + self.icmp.total_packets_sent
            + self.icmp.total_packets_received
    }

    pub fn total_bytes(&self) -> u64 {
        self.tcp.total_bytes_sent
            + self.tcp.total_bytes_received
            + self.udp.total_bytes_sent
            + self.udp.total_bytes_received
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_monitor_creation() {
        let monitor = ProtocolMonitor::new();
        let stats = monitor.get_stats();
        assert_eq!(stats.total_connections(), 0);
        assert_eq!(stats.total_packets(), 0);
        assert_eq!(stats.total_bytes(), 0);
    }
}
