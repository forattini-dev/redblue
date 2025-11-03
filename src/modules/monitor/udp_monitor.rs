/// UDP Packet Monitoring and Analysis
/// Monitor UDP traffic, track packets, analyze patterns
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// UDP Flow (bi-directional communication between two endpoints)
#[derive(Debug, Clone)]
pub struct UdpFlow {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub started_at: Instant,
    pub last_activity: Instant,
    pub packet_loss: u64,
    pub out_of_order: u64,
}

impl UdpFlow {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            local_addr,
            remote_addr,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            started_at: now,
            last_activity: now,
            packet_loss: 0,
            out_of_order: 0,
        }
    }

    pub fn duration(&self) -> Duration {
        self.last_activity.duration_since(self.started_at)
    }

    pub fn idle_time(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }

    pub fn packet_loss_rate(&self) -> f64 {
        if self.packets_sent > 0 {
            self.packet_loss as f64 / self.packets_sent as f64
        } else {
            0.0
        }
    }

    pub fn throughput_bps(&self) -> f64 {
        let duration_secs = self.duration().as_secs_f64();
        if duration_secs > 0.0 {
            (self.bytes_sent + self.bytes_received) as f64 * 8.0 / duration_secs
        } else {
            0.0
        }
    }

    pub fn packets_per_second(&self) -> f64 {
        let duration_secs = self.duration().as_secs_f64();
        if duration_secs > 0.0 {
            (self.packets_sent + self.packets_received) as f64 / duration_secs
        } else {
            0.0
        }
    }
}

/// UDP Packet Information
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub size: usize,
    pub timestamp: Instant,
    pub sequence: Option<u64>, // Optional sequence number for tracking
}

/// UDP Monitor Statistics
#[derive(Debug, Clone)]
pub struct UdpStats {
    pub total_flows: usize,
    pub active_flows: usize,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub average_packet_size: f64,
    pub total_packet_loss: u64,
    pub average_throughput_bps: f64,
}

/// UDP Monitor
pub struct UdpMonitor {
    flows: HashMap<String, UdpFlow>,
    packets: Vec<UdpPacket>,
    max_flows: usize,
    max_packets: usize,
}

impl UdpMonitor {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            packets: Vec::new(),
            max_flows: 10000,
            max_packets: 100000,
        }
    }

    pub fn with_limits(mut self, max_flows: usize, max_packets: usize) -> Self {
        self.max_flows = max_flows;
        self.max_packets = max_packets;
        self
    }

    /// Track a UDP flow
    pub fn track_flow(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> String {
        let flow_id = Self::flow_id(&local_addr, &remote_addr);

        if !self.flows.contains_key(&flow_id) {
            // Check flow limit
            if self.flows.len() >= self.max_flows {
                self.evict_oldest_flow();
            }

            let flow = UdpFlow::new(local_addr, remote_addr);
            self.flows.insert(flow_id.clone(), flow);
        }

        flow_id
    }

    /// Record a sent packet
    pub fn record_sent(&mut self, flow_id: &str, bytes: u64, sequence: Option<u64>) {
        if let Some(flow) = self.flows.get_mut(flow_id) {
            flow.packets_sent += 1;
            flow.bytes_sent += bytes;
            flow.last_activity = Instant::now();

            // Track packet
            if let Some(flow_obj) = self.flows.get(flow_id) {
                self.track_packet(UdpPacket {
                    source: flow_obj.local_addr,
                    destination: flow_obj.remote_addr,
                    size: bytes as usize,
                    timestamp: Instant::now(),
                    sequence,
                });
            }
        }
    }

    /// Record a received packet
    pub fn record_received(&mut self, flow_id: &str, bytes: u64, sequence: Option<u64>) {
        if let Some(flow) = self.flows.get_mut(flow_id) {
            flow.packets_received += 1;
            flow.bytes_received += bytes;
            flow.last_activity = Instant::now();

            // Track packet
            if let Some(flow_obj) = self.flows.get(flow_id) {
                self.track_packet(UdpPacket {
                    source: flow_obj.remote_addr,
                    destination: flow_obj.local_addr,
                    size: bytes as usize,
                    timestamp: Instant::now(),
                    sequence,
                });
            }
        }
    }

    /// Record packet loss
    pub fn record_loss(&mut self, flow_id: &str, count: u64) {
        if let Some(flow) = self.flows.get_mut(flow_id) {
            flow.packet_loss += count;
        }
    }

    /// Record out-of-order packet
    pub fn record_out_of_order(&mut self, flow_id: &str) {
        if let Some(flow) = self.flows.get_mut(flow_id) {
            flow.out_of_order += 1;
        }
    }

    /// Get flow by ID
    pub fn get_flow(&self, flow_id: &str) -> Option<&UdpFlow> {
        self.flows.get(flow_id)
    }

    /// Get all active flows
    pub fn active_flows(&self, max_idle: Duration) -> Vec<&UdpFlow> {
        self.flows
            .values()
            .filter(|f| f.idle_time() < max_idle)
            .collect()
    }

    /// Get recent packets
    pub fn recent_packets(&self, limit: usize) -> Vec<&UdpPacket> {
        self.packets.iter().rev().take(limit).collect()
    }

    /// Cleanup idle flows
    pub fn cleanup_idle(&mut self, max_idle: Duration) {
        self.flows.retain(|_, flow| flow.idle_time() < max_idle);
    }

    /// Get statistics
    pub fn stats(&self) -> UdpStats {
        let mut stats = UdpStats {
            total_flows: self.flows.len(),
            active_flows: 0,
            total_packets_sent: 0,
            total_packets_received: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            average_packet_size: 0.0,
            total_packet_loss: 0,
            average_throughput_bps: 0.0,
        };

        let max_idle = Duration::from_secs(300); // 5 minutes
        let mut throughput_sum = 0.0;
        let mut throughput_count = 0;

        for flow in self.flows.values() {
            stats.total_packets_sent += flow.packets_sent;
            stats.total_packets_received += flow.packets_received;
            stats.total_bytes_sent += flow.bytes_sent;
            stats.total_bytes_received += flow.bytes_received;
            stats.total_packet_loss += flow.packet_loss;

            if flow.idle_time() < max_idle {
                stats.active_flows += 1;
                throughput_sum += flow.throughput_bps();
                throughput_count += 1;
            }
        }

        let total_packets = stats.total_packets_sent + stats.total_packets_received;
        let total_bytes = stats.total_bytes_sent + stats.total_bytes_received;

        if total_packets > 0 {
            stats.average_packet_size = total_bytes as f64 / total_packets as f64;
        }

        if throughput_count > 0 {
            stats.average_throughput_bps = throughput_sum / throughput_count as f64;
        }

        stats
    }

    /// Track a packet
    fn track_packet(&mut self, packet: UdpPacket) {
        if self.packets.len() >= self.max_packets {
            // Remove oldest 10%
            let remove_count = self.max_packets / 10;
            self.packets.drain(0..remove_count);
        }
        self.packets.push(packet);
    }

    /// Evict oldest flow
    fn evict_oldest_flow(&mut self) {
        if let Some((oldest_id, _)) = self
            .flows
            .iter()
            .min_by_key(|(_, flow)| flow.last_activity)
        {
            let oldest_id = oldest_id.clone();
            self.flows.remove(&oldest_id);
        }
    }

    /// Generate flow ID
    fn flow_id(local: &SocketAddr, remote: &SocketAddr) -> String {
        format!("{}->{}", local, remote)
    }
}

impl Default for UdpMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// UDP Port Tester
pub struct UdpPortTester {
    timeout: Duration,
}

impl UdpPortTester {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(2),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Test if a UDP port is responding
    pub fn test_port(&self, host: &str, port: u16) -> Result<UdpTestResult, String> {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();

        // Bind to any local port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        // Send probe packet
        let probe = b"PROBE";
        match socket.send_to(probe, &addr) {
            Ok(bytes_sent) => {
                // Try to receive response
                let mut buf = [0u8; 1024];
                match socket.recv_from(&mut buf) {
                    Ok((bytes_received, peer)) => {
                        let rtt = start.elapsed();
                        Ok(UdpTestResult {
                            host: host.to_string(),
                            port,
                            responding: true,
                            rtt_ms: Some(rtt.as_millis() as f64),
                            bytes_sent,
                            bytes_received: Some(bytes_received),
                            peer_addr: Some(peer),
                            error: None,
                        })
                    }
                    Err(e) => {
                        // No response (could be filtered, or no service)
                        Ok(UdpTestResult {
                            host: host.to_string(),
                            port,
                            responding: false,
                            rtt_ms: None,
                            bytes_sent,
                            bytes_received: None,
                            peer_addr: None,
                            error: Some(format!("No response: {}", e)),
                        })
                    }
                }
            }
            Err(e) => Ok(UdpTestResult {
                host: host.to_string(),
                port,
                responding: false,
                rtt_ms: None,
                bytes_sent: 0,
                bytes_received: None,
                peer_addr: None,
                error: Some(format!("Send failed: {}", e)),
            }),
        }
    }

    /// Test multiple UDP ports
    pub fn test_ports(&self, host: &str, ports: &[u16]) -> Vec<UdpTestResult> {
        ports
            .iter()
            .map(|&port| self.test_port(host, port).unwrap_or_else(|e| UdpTestResult {
                host: host.to_string(),
                port,
                responding: false,
                rtt_ms: None,
                bytes_sent: 0,
                bytes_received: None,
                peer_addr: None,
                error: Some(e),
            }))
            .collect()
    }
}

impl Default for UdpPortTester {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct UdpTestResult {
    pub host: String,
    pub port: u16,
    pub responding: bool,
    pub rtt_ms: Option<f64>,
    pub bytes_sent: usize,
    pub bytes_received: Option<usize>,
    pub peer_addr: Option<SocketAddr>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_udp_monitor_creation() {
        let monitor = UdpMonitor::new();
        assert_eq!(monitor.flows.len(), 0);
    }

    #[test]
    fn test_track_flow() {
        let mut monitor = UdpMonitor::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);

        let flow_id = monitor.track_flow(local, remote);
        assert_eq!(monitor.flows.len(), 1);
        assert!(monitor.get_flow(&flow_id).is_some());
    }

    #[test]
    fn test_flow_stats() {
        let mut monitor = UdpMonitor::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);

        let flow_id = monitor.track_flow(local, remote);
        monitor.record_sent(&flow_id, 512, Some(1));
        monitor.record_received(&flow_id, 1024, Some(2));
        monitor.record_loss(&flow_id, 1);

        let stats = monitor.stats();
        assert_eq!(stats.total_flows, 1);
        assert_eq!(stats.total_packets_sent, 1);
        assert_eq!(stats.total_packets_received, 1);
        assert_eq!(stats.total_bytes_sent, 512);
        assert_eq!(stats.total_bytes_received, 1024);
        assert_eq!(stats.total_packet_loss, 1);
    }

    #[test]
    fn test_packet_loss_rate() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let mut flow = UdpFlow::new(local, remote);

        flow.packets_sent = 100;
        flow.packet_loss = 5;

        assert_eq!(flow.packet_loss_rate(), 0.05);
    }
}
