//! Connection Tracker
//!
//! Maintains state of all active proxy connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::modules::proxy::{
    Address, ConnectionId, ConnectionIdGenerator, ConnectionInfo, ConnectionState,
    FlowStats, Protocol,
};

/// Connection tracker for managing active connections
pub struct ConnectionTracker {
    /// Active connections by ID
    connections: RwLock<HashMap<ConnectionId, Arc<Mutex<ConnectionInfo>>>>,
    /// Connection ID generator
    id_generator: ConnectionIdGenerator,
    /// Global flow statistics
    flow_stats: Arc<FlowStats>,
    /// Connection timeout
    timeout: Duration,
}

impl ConnectionTracker {
    /// Create new connection tracker
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            id_generator: ConnectionIdGenerator::new(),
            flow_stats: Arc::new(FlowStats::new()),
            timeout: Duration::from_secs(300), // 5 minutes default
        }
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get shared flow statistics
    pub fn flow_stats(&self) -> Arc<FlowStats> {
        self.flow_stats.clone()
    }

    /// Register a new TCP connection
    pub fn register_tcp(
        &self,
        src_addr: SocketAddr,
        dst_addr: Address,
    ) -> (ConnectionId, Arc<Mutex<ConnectionInfo>>) {
        let id = self.id_generator.next_tcp();
        let info = ConnectionInfo::new(id, src_addr, dst_addr, Protocol::Tcp);
        let info = Arc::new(Mutex::new(info));

        self.connections.write().unwrap().insert(id, info.clone());
        self.flow_stats.connection_opened(Protocol::Tcp);

        (id, info)
    }

    /// Register a new UDP connection
    pub fn register_udp(
        &self,
        src_addr: SocketAddr,
        dst_addr: Address,
    ) -> (ConnectionId, Arc<Mutex<ConnectionInfo>>) {
        let id = self.id_generator.next_udp();
        let info = ConnectionInfo::new(id, src_addr, dst_addr, Protocol::Udp);
        let info = Arc::new(Mutex::new(info));

        self.connections.write().unwrap().insert(id, info.clone());
        self.flow_stats.connection_opened(Protocol::Udp);

        (id, info)
    }

    /// Get connection info by ID
    pub fn get(&self, id: ConnectionId) -> Option<Arc<Mutex<ConnectionInfo>>> {
        self.connections.read().unwrap().get(&id).cloned()
    }

    /// Update connection state
    pub fn update_state(&self, id: ConnectionId, state: ConnectionState) {
        if let Some(info) = self.get(id) {
            info.lock().unwrap().state = state;
        }
    }

    /// Mark connection as closed and remove it
    pub fn close(&self, id: ConnectionId) -> Option<Arc<Mutex<ConnectionInfo>>> {
        let info = self.connections.write().unwrap().remove(&id);
        if info.is_some() {
            self.flow_stats.connection_closed();
        }
        info
    }

    /// Get all active connections
    pub fn active_connections(&self) -> Vec<ConnectionSnapshot> {
        self.connections
            .read()
            .unwrap()
            .iter()
            .map(|(_, info)| {
                let info = info.lock().unwrap();
                ConnectionSnapshot {
                    id: info.id,
                    src_addr: info.src_addr,
                    dst_addr: info.dst_addr.clone(),
                    protocol: info.protocol,
                    state: info.state,
                    duration: info.duration(),
                    bytes_sent: info.total_sent(),
                    bytes_received: info.total_received(),
                }
            })
            .collect()
    }

    /// Get connection count
    pub fn count(&self) -> usize {
        self.connections.read().unwrap().len()
    }

    /// Cleanup expired connections
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        {
            let connections = self.connections.read().unwrap();
            for (id, info) in connections.iter() {
                let info = info.lock().unwrap();
                if info.duration() > self.timeout {
                    to_remove.push(*id);
                }
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            self.close(id);
        }

        count
    }

    /// Get statistics summary
    pub fn stats_summary(&self) -> TrackerStats {
        let connections = self.active_connections();
        let flow = self.flow_stats.summary();

        TrackerStats {
            active_connections: connections.len(),
            total_connections: flow.total_connections,
            total_bytes_sent: flow.total_bytes_sent,
            total_bytes_received: flow.total_bytes_received,
            tcp_connections: connections.iter().filter(|c| c.protocol == Protocol::Tcp).count(),
            udp_connections: connections.iter().filter(|c| c.protocol == Protocol::Udp).count(),
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of a connection (for reporting)
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub id: ConnectionId,
    pub src_addr: SocketAddr,
    pub dst_addr: Address,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub duration: Duration,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl ConnectionSnapshot {
    /// Get throughput in bytes per second
    pub fn throughput(&self) -> (f64, f64) {
        let secs = self.duration.as_secs_f64();
        if secs > 0.0 {
            (
                self.bytes_sent as f64 / secs,
                self.bytes_received as f64 / secs,
            )
        } else {
            (0.0, 0.0)
        }
    }
}

/// Tracker statistics summary
#[derive(Debug, Clone)]
pub struct TrackerStats {
    pub active_connections: usize,
    pub total_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub tcp_connections: usize,
    pub udp_connections: usize,
}

impl TrackerStats {
    /// Format bytes as human-readable string
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_tracker() {
        let tracker = ConnectionTracker::new();

        // Register TCP connection
        let (id1, _) = tracker.register_tcp(
            "127.0.0.1:12345".parse().unwrap(),
            Address::from_socket("8.8.8.8:443".parse().unwrap()),
        );

        // Register UDP connection
        let (id2, _) = tracker.register_udp(
            "127.0.0.1:12346".parse().unwrap(),
            Address::from_socket("8.8.8.8:53".parse().unwrap()),
        );

        assert!(id1.is_tcp());
        assert!(id2.is_udp());
        assert_eq!(tracker.count(), 2);

        // Close one connection
        tracker.close(id1);
        assert_eq!(tracker.count(), 1);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(TrackerStats::format_bytes(500), "500 B");
        assert_eq!(TrackerStats::format_bytes(1024), "1.00 KB");
        assert_eq!(TrackerStats::format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(TrackerStats::format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }
}
