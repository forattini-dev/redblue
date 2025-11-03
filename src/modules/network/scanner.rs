/// High-performance TCP port scanner implemented with the standard library only.
/// Provides a worker-pool based TCP connect scanner with lightweight banner capture.
use crate::config;
use std::collections::VecDeque;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub port: u16,
    pub is_open: bool,
    pub service: Option<String>,
    pub banner: Option<String>,
}

pub trait ScanProgress: Send + Sync {
    fn inc(&self, delta: usize);
}

pub struct NoOpProgress;

impl ScanProgress for NoOpProgress {
    fn inc(&self, _delta: usize) {}
}

pub struct PortScanner {
    target: IpAddr,
    timeout_ms: u64,
    threads: usize,
}

impl PortScanner {
    pub fn new(target: IpAddr) -> Self {
        let cfg = config::get();
        Self {
            target,
            timeout_ms: cfg.network.timeout_ms.max(1),
            threads: cfg.network.threads.max(1),
        }
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1);
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.max(1);
        self
    }

    /// Scan a continuous range of ports (inclusive).
    pub fn scan_range(&self, start_port: u16, end_port: u16) -> Vec<PortScanResult> {
        self.scan_range_with_progress(start_port, end_port, None)
    }

    pub fn scan_range_with_progress(
        &self,
        start_port: u16,
        end_port: u16,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Vec<PortScanResult> {
        if start_port > end_port {
            return Vec::new();
        }
        let ports: Vec<u16> = (start_port..=end_port).collect();
        self.run_scan_with_progress(ports, progress)
    }

    /// Scan a specific list of ports.
    pub fn scan_ports(&self, ports: &[u16]) -> Vec<PortScanResult> {
        self.scan_ports_with_progress(ports, None)
    }

    pub fn scan_ports_with_progress(
        &self,
        ports: &[u16],
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Vec<PortScanResult> {
        if ports.is_empty() {
            return Vec::new();
        }
        self.run_scan_with_progress(ports.to_vec(), progress)
    }

    /// Scan commonly used ports (top 50 from industry datasets).
    pub fn scan_common(&self) -> Vec<PortScanResult> {
        self.scan_common_with_progress(None)
    }

    pub fn scan_common_with_progress(
        &self,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Vec<PortScanResult> {
        let common_ports = Self::get_common_ports();
        self.run_scan_with_progress(common_ports, progress)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn run_scan(&self, ports: Vec<u16>) -> Vec<PortScanResult> {
        self.run_scan_with_progress(ports, None)
    }

    fn run_scan_with_progress(
        &self,
        ports: Vec<u16>,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Vec<PortScanResult> {
        if ports.is_empty() {
            return Vec::new();
        }

        let progress: Arc<dyn ScanProgress> = match progress {
            Some(p) => p,
            None => Arc::new(NoOpProgress),
        };

        let worker_count = self.threads.min(ports.len()).max(1);
        let queue = Arc::new(Mutex::new(VecDeque::from(ports)));
        let results = Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let results = Arc::clone(&results);
            let progress = Arc::clone(&progress);
            let target = self.target;
            let timeout_ms = self.timeout_ms;

            let handle = thread::spawn(move || {
                let mut local_results = Vec::new();
                loop {
                    let port = {
                        let mut guard = queue.lock().unwrap();
                        guard.pop_front()
                    };

                    let port = match port {
                        Some(port) => port,
                        None => break,
                    };

                    local_results.push(Self::scan_port(target, port, timeout_ms));
                    progress.inc(1);
                }

                if !local_results.is_empty() {
                    let mut guard = results.lock().unwrap();
                    guard.extend(local_results);
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            if let Err(err) = handle.join() {
                eprintln!("redblue: scan worker panicked: {:?}", err);
            }
        }

        let mut final_results = match Arc::try_unwrap(results) {
            Ok(mutex) => mutex.into_inner().unwrap_or_default(),
            Err(arc) => arc.lock().unwrap().clone(),
        };
        final_results.sort_by_key(|r| r.port);
        final_results
    }

    fn scan_port(target: IpAddr, port: u16, timeout_ms: u64) -> PortScanResult {
        let addr = SocketAddr::new(target, port);
        let timeout = Duration::from_millis(timeout_ms);
        let mut banner = None;
        let is_open = match TcpStream::connect_timeout(&addr, timeout) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms.min(500))));
                let mut buf = [0u8; 512];
                if let Ok(bytes) = stream.read(&mut buf) {
                    if bytes > 0 {
                        let snippet = String::from_utf8_lossy(&buf[..bytes])
                            .trim_matches(char::from(0))
                            .trim()
                            .to_string();
                        if !snippet.is_empty() {
                            banner = Some(snippet);
                        }
                    }
                }
                true
            }
            Err(_) => false,
        };

        let service = if is_open {
            Self::guess_service(port)
        } else {
            None
        };

        PortScanResult {
            port,
            is_open,
            service,
            banner,
        }
    }

    fn guess_service(port: u16) -> Option<String> {
        let service = match port {
            20 => "ftp-data",
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            26 => "smtp-alt",
            53 => "dns",
            80 | 8080 => "http",
            110 => "pop3",
            135 => "rpc",
            139 => "netbios",
            143 => "imap",
            161 => "snmp",
            389 => "ldap",
            443 | 8443 => "https",
            445 => "smb",
            465 => "smtps",
            500 => "isakmp",
            587 => "submission",
            631 => "ipp",
            636 => "ldaps",
            993 => "imaps",
            995 => "pop3s",
            1433 => "mssql",
            1521 => "oracle",
            1723 => "pptp",
            1883 => "mqtt",
            2375 => "docker",
            2376 => "docker-tls",
            3000 => "http-alt",
            3128 => "proxy",
            3306 => "mysql",
            3389 => "rdp",
            4242 => "vars",
            5000 => "http-alt",
            5432 => "postgresql",
            5672 => "amqp",
            5900 => "vnc",
            6379 => "redis",
            8000 => "http-alt",
            8081 => "http-alt",
            8888 => "http-alt",
            9200 => "elasticsearch",
            10000 => "webmin",
            27017 => "mongodb",
            _ => return None,
        };
        Some(service.to_string())
    }

    pub fn get_common_ports() -> Vec<u16> {
        vec![
            20, 21, 22, 23, 25, 26, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
            500, 587, 631, 636, 993, 995, 1025, 1026, 1433, 1521, 1723, 1883, 2375, 2376, 3000,
            3128, 3306, 3389, 4242, 5000, 5432, 5672, 5900, 6379, 8080, 8081, 8443, 8888, 9200,
            10000, 27017,
        ]
    }
}

/// Ultra-fast SYN scanner (requires raw sockets - root/admin).
/// Placeholder for a future raw socket implementation.
#[allow(dead_code)]
pub struct SynScanner {
    target: IpAddr,
}

impl SynScanner {
    #[allow(dead_code)]
    pub fn new(target: IpAddr) -> Self {
        Self { target }
    }

    #[allow(dead_code)]
    pub fn scan(&self, _ports: &[u16]) -> Vec<PortScanResult> {
        // Raw socket SYN scanning implementation - Future enhancement
        // Requires CAP_NET_RAW (Linux) or administrator privileges (Windows/Unix)
        // For now, use TcpScanner which uses TCP connect() scanning
        let _ = self.target;
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_scanner_creation_defaults() {
        let scanner = PortScanner::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(scanner.timeout_ms, 1000);
        assert_eq!(scanner.threads, 100);
    }

    #[test]
    fn test_service_lookup() {
        assert_eq!(PortScanner::guess_service(443), Some("https".to_string()));
        assert_eq!(PortScanner::guess_service(65000), None);
    }
}
