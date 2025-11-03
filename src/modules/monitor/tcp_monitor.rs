/// TCP Stream Monitoring and Analysis
/// Monitor TCP connections, track states, analyze traffic patterns
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// TCP Connection State (RFC 793)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    pub fn as_str(&self) -> &str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECEIVED",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
        }
    }
}

/// TCP Connection Information
#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: TcpState,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub started_at: Instant,
    pub last_activity: Instant,
    pub rtt_ms: Option<f64>, // Round-trip time
}

impl TcpConnection {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            local_addr,
            remote_addr,
            state: TcpState::SynSent,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            started_at: now,
            last_activity: now,
            rtt_ms: None,
        }
    }

    pub fn duration(&self) -> Duration {
        self.last_activity.duration_since(self.started_at)
    }

    pub fn idle_time(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }

    pub fn throughput_bps(&self) -> f64 {
        let duration_secs = self.duration().as_secs_f64();
        if duration_secs > 0.0 {
            (self.bytes_sent + self.bytes_received) as f64 * 8.0 / duration_secs
        } else {
            0.0
        }
    }
}

/// TCP Connection Statistics
#[derive(Debug, Clone)]
pub struct TcpStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub established_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub average_rtt_ms: Option<f64>,
    pub connections_by_state: HashMap<String, usize>,
}

/// TCP Stream Monitor
pub struct TcpMonitor {
    connections: HashMap<String, TcpConnection>,
    max_connections: usize,
}

impl TcpMonitor {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            max_connections: 10000,
        }
    }

    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Track a new TCP connection
    pub fn track_connection(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> String {
        let conn_id = Self::connection_id(&local_addr, &remote_addr);

        if !self.connections.contains_key(&conn_id) {
            // Check connection limit
            if self.connections.len() >= self.max_connections {
                // Remove oldest inactive connection
                self.evict_oldest();
            }

            let conn = TcpConnection::new(local_addr, remote_addr);
            self.connections.insert(conn_id.clone(), conn);
        }

        conn_id
    }

    /// Update connection state
    pub fn update_state(&mut self, conn_id: &str, state: TcpState) {
        if let Some(conn) = self.connections.get_mut(conn_id) {
            conn.state = state;
            conn.last_activity = Instant::now();
        }
    }

    /// Record sent data
    pub fn record_sent(&mut self, conn_id: &str, bytes: u64) {
        if let Some(conn) = self.connections.get_mut(conn_id) {
            conn.bytes_sent += bytes;
            conn.packets_sent += 1;
            conn.last_activity = Instant::now();
        }
    }

    /// Record received data
    pub fn record_received(&mut self, conn_id: &str, bytes: u64) {
        if let Some(conn) = self.connections.get_mut(conn_id) {
            conn.bytes_received += bytes;
            conn.packets_received += 1;
            conn.last_activity = Instant::now();
        }
    }

    /// Update RTT measurement
    pub fn update_rtt(&mut self, conn_id: &str, rtt_ms: f64) {
        if let Some(conn) = self.connections.get_mut(conn_id) {
            conn.rtt_ms = Some(rtt_ms);
        }
    }

    /// Get connection by ID
    pub fn get_connection(&self, conn_id: &str) -> Option<&TcpConnection> {
        self.connections.get(conn_id)
    }

    /// Get all active connections
    pub fn active_connections(&self) -> Vec<&TcpConnection> {
        self.connections
            .values()
            .filter(|c| c.state == TcpState::Established)
            .collect()
    }

    /// Get connections by state
    pub fn connections_by_state(&self, state: TcpState) -> Vec<&TcpConnection> {
        self.connections
            .values()
            .filter(|c| c.state == state)
            .collect()
    }

    /// Remove closed connections
    pub fn cleanup_closed(&mut self) {
        self.connections
            .retain(|_, conn| conn.state != TcpState::Closed);
    }

    /// Remove idle connections
    pub fn cleanup_idle(&mut self, max_idle: Duration) {
        self.connections
            .retain(|_, conn| conn.idle_time() < max_idle);
    }

    /// Get statistics
    pub fn stats(&self) -> TcpStats {
        let mut stats = TcpStats {
            total_connections: self.connections.len(),
            active_connections: 0,
            established_connections: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            average_rtt_ms: None,
            connections_by_state: HashMap::new(),
        };

        let mut rtt_sum = 0.0;
        let mut rtt_count = 0;

        for conn in self.connections.values() {
            // Count by state
            let state_str = conn.state.as_str().to_string();
            *stats.connections_by_state.entry(state_str).or_insert(0) += 1;

            // Count established
            if conn.state == TcpState::Established {
                stats.established_connections += 1;
                stats.active_connections += 1;
            }

            // Sum bytes
            stats.total_bytes_sent += conn.bytes_sent;
            stats.total_bytes_received += conn.bytes_received;

            // Average RTT
            if let Some(rtt) = conn.rtt_ms {
                rtt_sum += rtt;
                rtt_count += 1;
            }
        }

        if rtt_count > 0 {
            stats.average_rtt_ms = Some(rtt_sum / rtt_count as f64);
        }

        stats
    }

    /// Evict oldest inactive connection
    fn evict_oldest(&mut self) {
        if let Some((oldest_id, _)) = self
            .connections
            .iter()
            .min_by_key(|(_, conn)| conn.last_activity)
        {
            let oldest_id = oldest_id.clone();
            self.connections.remove(&oldest_id);
        }
    }

    /// Generate connection ID
    fn connection_id(local: &SocketAddr, remote: &SocketAddr) -> String {
        format!("{}->{}", local, remote)
    }
}

impl Default for TcpMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP Connection Tester
pub struct TcpConnectionTester {
    timeout: Duration,
}

impl TcpConnectionTester {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Test if a TCP port is open
    pub fn test_port(&self, host: &str, port: u16) -> Result<TcpTestResult, String> {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();

        match TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| format!("Invalid address: {}", e))?,
            self.timeout,
        ) {
            Ok(stream) => {
                let connect_time = start.elapsed();
                let local_addr = stream
                    .local_addr()
                    .map_err(|e| format!("Failed to get local addr: {}", e))?;
                let peer_addr = stream
                    .peer_addr()
                    .map_err(|e| format!("Failed to get peer addr: {}", e))?;

                Ok(TcpTestResult {
                    host: host.to_string(),
                    port,
                    open: true,
                    connect_time_ms: connect_time.as_millis() as f64,
                    local_addr: Some(local_addr),
                    peer_addr: Some(peer_addr),
                    error: None,
                })
            }
            Err(e) => Ok(TcpTestResult {
                host: host.to_string(),
                port,
                open: false,
                connect_time_ms: 0.0,
                local_addr: None,
                peer_addr: None,
                error: Some(e.to_string()),
            }),
        }
    }

    /// Test multiple ports
    pub fn test_ports(&self, host: &str, ports: &[u16]) -> Vec<TcpTestResult> {
        ports
            .iter()
            .map(|&port| self.test_port(host, port).unwrap_or_else(|e| TcpTestResult {
                host: host.to_string(),
                port,
                open: false,
                connect_time_ms: 0.0,
                local_addr: None,
                peer_addr: None,
                error: Some(e),
            }))
            .collect()
    }
}

impl Default for TcpConnectionTester {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TcpTestResult {
    pub host: String,
    pub port: u16,
    pub open: bool,
    pub connect_time_ms: f64,
    pub local_addr: Option<SocketAddr>,
    pub peer_addr: Option<SocketAddr>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_tcp_monitor_creation() {
        let monitor = TcpMonitor::new();
        assert_eq!(monitor.connections.len(), 0);
    }

    #[test]
    fn test_track_connection() {
        let mut monitor = TcpMonitor::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);

        let conn_id = monitor.track_connection(local, remote);
        assert_eq!(monitor.connections.len(), 1);
        assert!(monitor.get_connection(&conn_id).is_some());
    }

    #[test]
    fn test_connection_stats() {
        let mut monitor = TcpMonitor::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);

        let conn_id = monitor.track_connection(local, remote);
        monitor.update_state(&conn_id, TcpState::Established);
        monitor.record_sent(&conn_id, 1024);
        monitor.record_received(&conn_id, 2048);

        let stats = monitor.stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.established_connections, 1);
        assert_eq!(stats.total_bytes_sent, 1024);
        assert_eq!(stats.total_bytes_received, 2048);
    }

    #[test]
    fn test_tcp_state_display() {
        assert_eq!(TcpState::Established.as_str(), "ESTABLISHED");
        assert_eq!(TcpState::Closed.as_str(), "CLOSED");
    }
}
