/// Port Health Check Module
///
/// Re-scans stored ports to detect state changes over time.
/// Supports check, diff, and watch operations.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::storage::records::{PortHealthRecord, PortScanRecord, PortStateChange, PortStatus};

/// Result of a port health check
#[derive(Debug, Clone)]
pub struct PortCheckResult {
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub is_open: bool,
    pub response_time_ms: u32,
    pub change: PortStateChange,
    pub service: Option<String>,
}

/// Summary of port diff between scans
#[derive(Debug, Clone, Default)]
pub struct PortDiff {
    /// Ports that are still open
    pub still_open: Vec<PortCheckResult>,
    /// Ports that were open, now closed
    pub now_closed: Vec<PortCheckResult>,
    /// Ports that were closed, now open
    pub now_open: Vec<PortCheckResult>,
    /// Ports seen for the first time
    pub new_ports: Vec<PortCheckResult>,
}

impl PortDiff {
    pub fn total_changes(&self) -> usize {
        self.now_closed.len() + self.now_open.len() + self.new_ports.len()
    }

    pub fn has_changes(&self) -> bool {
        self.total_changes() > 0
    }
}

/// Port health checker
pub struct PortHealthChecker {
    timeout: Duration,
    threads: usize,
}

impl Default for PortHealthChecker {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1000),
            threads: 50,
        }
    }
}

impl PortHealthChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    /// Check a single port
    pub fn check_port(&self, host: &str, port: u16) -> PortCheckResult {
        let start = Instant::now();
        let (is_open, resolved_ip) = self.try_connect(host, port);
        let response_time = if is_open {
            start.elapsed().as_millis() as u32
        } else {
            0
        };

        PortCheckResult {
            host: host.to_string(),
            ip: resolved_ip,
            port,
            is_open,
            response_time_ms: response_time,
            change: PortStateChange::New, // Will be updated by caller based on history
            service: self.detect_service(port),
        }
    }

    /// Check multiple ports in parallel
    pub fn check_ports(&self, host: &str, ports: &[u16]) -> Vec<PortCheckResult> {
        let results = Arc::new(Mutex::new(Vec::new()));
        let ports_queue = Arc::new(Mutex::new(ports.to_vec()));
        let host = host.to_string();
        let timeout = self.timeout;

        let mut handles = Vec::new();

        for _ in 0..self.threads.min(ports.len()) {
            let results = Arc::clone(&results);
            let ports_queue = Arc::clone(&ports_queue);
            let host = host.clone();

            let handle = thread::spawn(move || loop {
                let port = {
                    let mut queue = ports_queue.lock().unwrap();
                    queue.pop()
                };

                match port {
                    Some(p) => {
                        let result = Self::check_port_internal(&host, p, timeout);
                        results.lock().unwrap().push(result);
                    }
                    None => break,
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        let mut final_results = results.lock().unwrap().clone();
        final_results.sort_by_key(|r| r.port);
        final_results
    }

    /// Internal port check with timeout
    fn check_port_internal(host: &str, port: u16, timeout: Duration) -> PortCheckResult {
        let start = Instant::now();
        let (is_open, resolved_ip) = Self::try_connect_with_timeout(host, port, timeout);
        let response_time = if is_open {
            start.elapsed().as_millis() as u32
        } else {
            0
        };

        PortCheckResult {
            host: host.to_string(),
            ip: resolved_ip,
            port,
            is_open,
            response_time_ms: response_time,
            change: PortStateChange::New,
            service: Self::detect_service_static(port),
        }
    }

    fn try_connect(&self, host: &str, port: u16) -> (bool, Option<IpAddr>) {
        Self::try_connect_with_timeout(host, port, self.timeout)
    }

    fn try_connect_with_timeout(
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> (bool, Option<IpAddr>) {
        let addr = format!("{}:{}", host, port);

        // Try to resolve and connect
        match addr.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(socket_addr) = addrs.next() {
                    let ip = socket_addr.ip();
                    let is_open = TcpStream::connect_timeout(&socket_addr, timeout).is_ok();
                    (is_open, Some(ip))
                } else {
                    (false, None)
                }
            }
            Err(_) => {
                // Try direct IP parsing
                if let Ok(socket_addr) = format!("{}:{}", host, port).parse::<SocketAddr>() {
                    let ip = socket_addr.ip();
                    let is_open = TcpStream::connect_timeout(&socket_addr, timeout).is_ok();
                    (is_open, Some(ip))
                } else {
                    (false, None)
                }
            }
        }
    }

    /// Compare current scan with previous scan to calculate diff
    pub fn calculate_diff(
        &self,
        previous: &[PortScanRecord],
        current: &[PortCheckResult],
    ) -> PortDiff {
        let mut diff = PortDiff::default();

        // Create map of previous port states (port -> was_open)
        let previous_map: HashMap<u16, bool> = previous
            .iter()
            .map(|r| (r.port, r.status == PortStatus::Open))
            .collect();

        // Check current ports against previous
        for result in current {
            let mut result = result.clone();

            match previous_map.get(&result.port) {
                Some(was_open) => {
                    if *was_open && result.is_open {
                        result.change = PortStateChange::StillOpen;
                        diff.still_open.push(result);
                    } else if *was_open && !result.is_open {
                        result.change = PortStateChange::Closed;
                        diff.now_closed.push(result);
                    } else if !was_open && result.is_open {
                        result.change = PortStateChange::Opened;
                        diff.now_open.push(result);
                    }
                    // StillClosed is not tracked (no change)
                }
                None => {
                    // New port not in previous scan
                    if result.is_open {
                        result.change = PortStateChange::New;
                        diff.new_ports.push(result);
                    }
                }
            }
        }

        diff
    }

    /// Convert check result to health record
    pub fn to_health_record(
        &self,
        result: &PortCheckResult,
        previous_record: Option<&PortHealthRecord>,
    ) -> PortHealthRecord {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let (change, previous_check, consecutive) = match previous_record {
            Some(prev) => {
                let was_open = prev.is_open;
                let now_open = result.is_open;

                let change = if was_open && now_open {
                    PortStateChange::StillOpen
                } else if was_open && !now_open {
                    PortStateChange::Closed
                } else if !was_open && now_open {
                    PortStateChange::Opened
                } else {
                    PortStateChange::StillClosed
                };

                let consecutive = if was_open == now_open {
                    prev.consecutive_same_state.saturating_add(1)
                } else {
                    1
                };

                (change, prev.checked_at, consecutive)
            }
            None => (PortStateChange::New, 0, 1),
        };

        PortHealthRecord {
            host: result.host.clone(),
            port: result.port,
            is_open: result.is_open,
            change,
            response_time_ms: result.response_time_ms,
            service: result.service.clone(),
            previous_check,
            checked_at: now,
            consecutive_same_state: consecutive,
        }
    }

    fn detect_service(&self, port: u16) -> Option<String> {
        Self::detect_service_static(port)
    }

    fn detect_service_static(port: u16) -> Option<String> {
        match port {
            20 | 21 => Some("FTP".to_string()),
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            25 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            80 => Some("HTTP".to_string()),
            110 => Some("POP3".to_string()),
            111 => Some("RPC".to_string()),
            135 => Some("MSRPC".to_string()),
            139 => Some("NetBIOS".to_string()),
            143 => Some("IMAP".to_string()),
            161 | 162 => Some("SNMP".to_string()),
            389 => Some("LDAP".to_string()),
            443 => Some("HTTPS".to_string()),
            445 => Some("SMB".to_string()),
            465 => Some("SMTPS".to_string()),
            587 => Some("Submission".to_string()),
            636 => Some("LDAPS".to_string()),
            993 => Some("IMAPS".to_string()),
            995 => Some("POP3S".to_string()),
            1433 => Some("MSSQL".to_string()),
            1521 => Some("Oracle".to_string()),
            2049 => Some("NFS".to_string()),
            3306 => Some("MySQL".to_string()),
            3389 => Some("RDP".to_string()),
            5432 => Some("PostgreSQL".to_string()),
            5900 => Some("VNC".to_string()),
            5985 | 5986 => Some("WinRM".to_string()),
            6379 => Some("Redis".to_string()),
            8080 => Some("HTTP-Proxy".to_string()),
            8443 => Some("HTTPS-Alt".to_string()),
            9200 | 9300 => Some("Elasticsearch".to_string()),
            27017 => Some("MongoDB".to_string()),
            _ => None,
        }
    }
}

/// Port watch configuration
#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub interval: Duration,
    pub max_iterations: Option<u32>,
    pub alert_on_change: bool,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            max_iterations: None,
            alert_on_change: true,
        }
    }
}

/// Port watcher for continuous monitoring
pub struct PortWatcher {
    checker: PortHealthChecker,
    config: WatchConfig,
}

impl PortWatcher {
    pub fn new(checker: PortHealthChecker, config: WatchConfig) -> Self {
        Self { checker, config }
    }

    /// Start watching ports (blocking)
    pub fn watch(
        &self,
        host: &str,
        ports: &[u16],
        mut on_check: impl FnMut(&[PortCheckResult], &PortDiff, u32),
    ) {
        let mut previous_results: Vec<PortCheckResult> = Vec::new();
        let mut iteration = 0u32;

        loop {
            iteration += 1;

            // Check all ports
            let current_results = self.checker.check_ports(host, ports);

            // Calculate diff
            let diff = if previous_results.is_empty() {
                // First iteration - all are "new"
                PortDiff {
                    new_ports: current_results
                        .iter()
                        .filter(|r| r.is_open)
                        .cloned()
                        .collect(),
                    ..Default::default()
                }
            } else {
                // Convert previous results to PortScanRecord format for comparison
                let prev_records: Vec<PortScanRecord> = previous_results
                    .iter()
                    .filter_map(|r| {
                        r.ip.map(|ip| PortScanRecord {
                            ip,
                            port: r.port,
                            status: if r.is_open {
                                PortStatus::Open
                            } else {
                                PortStatus::Closed
                            },
                            service_id: 0, // Will be derived from port
                            timestamp: 0,
                        })
                    })
                    .collect();

                self.checker.calculate_diff(&prev_records, &current_results)
            };

            // Call callback
            on_check(&current_results, &diff, iteration);

            // Check if we should stop
            if let Some(max) = self.config.max_iterations {
                if iteration >= max {
                    break;
                }
            }

            // Store for next iteration
            previous_results = current_results;

            // Sleep until next check
            thread::sleep(self.config.interval);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_port_state_change_serialization() {
        assert_eq!(PortStateChange::StillOpen.to_byte(), 0);
        assert_eq!(PortStateChange::from_byte(0), PortStateChange::StillOpen);

        assert_eq!(PortStateChange::Closed.to_byte(), 3);
        assert_eq!(PortStateChange::from_byte(3), PortStateChange::Closed);
    }

    #[test]
    fn test_detect_service() {
        assert_eq!(
            PortHealthChecker::detect_service_static(22),
            Some("SSH".to_string())
        );
        assert_eq!(
            PortHealthChecker::detect_service_static(80),
            Some("HTTP".to_string())
        );
        assert_eq!(
            PortHealthChecker::detect_service_static(443),
            Some("HTTPS".to_string())
        );
        assert_eq!(
            PortHealthChecker::detect_service_static(3306),
            Some("MySQL".to_string())
        );
        assert_eq!(PortHealthChecker::detect_service_static(12345), None);
    }

    #[test]
    fn test_port_diff_calculation() {
        let checker = PortHealthChecker::new();
        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let previous = vec![
            PortScanRecord {
                ip: test_ip,
                port: 22,
                status: PortStatus::Open,
                service_id: 1, // SSH
                timestamp: 0,
            },
            PortScanRecord {
                ip: test_ip,
                port: 80,
                status: PortStatus::Open,
                service_id: 2, // HTTP
                timestamp: 0,
            },
            PortScanRecord {
                ip: test_ip,
                port: 443,
                status: PortStatus::Closed,
                service_id: 3, // HTTPS
                timestamp: 0,
            },
        ];

        let current = vec![
            PortCheckResult {
                host: "test".to_string(),
                ip: Some(test_ip),
                port: 22,
                is_open: true, // still open
                response_time_ms: 12,
                change: PortStateChange::New,
                service: Some("SSH".to_string()),
            },
            PortCheckResult {
                host: "test".to_string(),
                ip: Some(test_ip),
                port: 80,
                is_open: false, // was open, now closed
                response_time_ms: 0,
                change: PortStateChange::New,
                service: None,
            },
            PortCheckResult {
                host: "test".to_string(),
                ip: Some(test_ip),
                port: 443,
                is_open: true, // was closed, now open
                response_time_ms: 8,
                change: PortStateChange::New,
                service: Some("HTTPS".to_string()),
            },
            PortCheckResult {
                host: "test".to_string(),
                ip: Some(test_ip),
                port: 8080,
                is_open: true, // new port
                response_time_ms: 15,
                change: PortStateChange::New,
                service: Some("HTTP-Proxy".to_string()),
            },
        ];

        let diff = checker.calculate_diff(&previous, &current);

        assert_eq!(diff.still_open.len(), 1);
        assert_eq!(diff.still_open[0].port, 22);

        assert_eq!(diff.now_closed.len(), 1);
        assert_eq!(diff.now_closed[0].port, 80);

        assert_eq!(diff.now_open.len(), 1);
        assert_eq!(diff.now_open[0].port, 443);

        assert_eq!(diff.new_ports.len(), 1);
        assert_eq!(diff.new_ports[0].port, 8080);

        assert!(diff.has_changes());
        assert_eq!(diff.total_changes(), 3);
    }

    #[test]
    fn test_health_record_conversion() {
        let checker = PortHealthChecker::new();
        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let result = PortCheckResult {
            host: "192.168.1.1".to_string(),
            ip: Some(test_ip),
            port: 22,
            is_open: true,
            response_time_ms: 10,
            change: PortStateChange::New,
            service: Some("SSH".to_string()),
        };

        let record = checker.to_health_record(&result, None);

        assert_eq!(record.host, "192.168.1.1");
        assert_eq!(record.port, 22);
        assert!(record.is_open);
        assert_eq!(record.change, PortStateChange::New);
        assert_eq!(record.consecutive_same_state, 1);
    }
}
