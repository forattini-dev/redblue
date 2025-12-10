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

    /// Guess service by port number (60+ protocols supported)
    fn guess_service(port: u16) -> Option<String> {
        let service = match port {
            // Core network services
            7 => "echo",
            9 => "discard",
            13 => "daytime",
            17 => "qotd",
            19 => "chargen",
            20 => "ftp-data",
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            26 => "smtp-alt",
            37 => "time",
            43 => "whois",
            49 => "tacacs",
            53 => "dns",
            70 => "gopher",
            79 => "finger",
            80 | 8080 => "http",
            88 => "kerberos",
            109 => "pop2",
            110 => "pop3",
            111 => "rpcbind",
            113 => "ident",
            119 => "nntp",
            123 => "ntp",
            135 => "msrpc",
            137 => "netbios-ns",
            138 => "netbios-dgm",
            139 => "netbios-ssn",
            143 => "imap",
            161 => "snmp",
            162 => "snmptrap",
            179 => "bgp",
            194 => "irc",
            201 => "at-rtmp",
            264 => "bgmp",
            389 => "ldap",
            443 | 8443 => "https",
            445 => "smb",
            465 => "smtps",
            500 => "isakmp",
            512 => "rexec",
            513 => "rlogin",
            514 => "rsh",
            515 => "printer",
            520 => "route",
            548 => "afp",
            554 => "rtsp",
            587 => "submission",
            631 => "ipp",
            636 => "ldaps",
            646 => "ldp",
            873 => "rsync",
            902 => "vmware-auth",
            990 => "ftps",
            993 => "imaps",
            995 => "pop3s",
            1080 => "socks",
            1099 => "rmiregistry",
            1194 => "openvpn",
            1433 => "mssql",
            1434 => "mssql-m",
            1521 => "oracle",
            1701 => "l2tp",
            1723 => "pptp",
            1812 => "radius",
            1813 => "radius-acct",
            1883 => "mqtt",
            2049 => "nfs",
            2181 => "zookeeper",
            2222 => "ssh-alt",
            2375 => "docker",
            2376 => "docker-tls",
            2379 => "etcd-client",
            2380 => "etcd-server",
            3000 => "grafana",
            3128 => "squid",
            3268 => "ldap-gc",
            3269 => "ldaps-gc",
            3306 => "mysql",
            3389 => "rdp",
            3690 => "svn",
            4000 => "remoteanything",
            4242 => "vrml",
            4369 => "epmd",
            4443 => "pharos",
            4444 => "krb524",
            4500 => "nat-t-ike",
            4505 | 4506 => "salt",
            5000 => "upnp",
            5005 => "jdwp",
            5060 => "sip",
            5061 => "sips",
            5222 => "xmpp-client",
            5269 => "xmpp-server",
            5432 => "postgresql",
            5601 => "kibana",
            5672 => "amqp",
            5683 => "coap",
            5900..=5909 => "vnc",
            5984 => "couchdb",
            5985 => "winrm",
            5986 => "winrm-s",
            6000..=6010 => "x11",
            6379 => "redis",
            6443 => "kubernetes-api",
            6514 => "syslog-tls",
            6667 => "irc",
            6697 => "irc-s",
            7001 | 7002 => "weblogic",
            7070 => "realserver",
            7474 => "neo4j",
            7687 => "neo4j-bolt",
            8000 => "http-alt",
            8008 => "http",
            8009 => "ajp13",
            8010 => "xmpp-bosh",
            8020 => "hdfs-nn",
            8025 => "mailhog",
            8042 => "yarn-nm",
            8081 => "http-alt",
            8088 => "yarn-rm",
            8123 => "polipo",
            8139 => "puppet",
            8140 => "puppet-master",
            8200 => "vault",
            8300..=8302 => "consul",
            8443 => "https-alt",
            8500 => "consul-http",
            8501 => "consul-https",
            8600 => "consul-dns",
            8834 => "nessus",
            8888 => "http-alt",
            9000 => "sonarqube",
            9001 => "tor-orport",
            9042 => "cassandra",
            9043 => "websphere",
            9050 => "tor-socks",
            9051 => "tor-control",
            9090 => "prometheus",
            9092 => "kafka",
            9100 => "jetdirect",
            9200 => "elasticsearch",
            9300 => "elasticsearch-t",
            9418 => "git",
            9999 => "abyss",
            10000 => "webmin",
            10250 => "kubelet",
            10255 => "kubelet-ro",
            11211 => "memcached",
            11214 | 11215 => "memcached-s",
            15672 => "rabbitmq-mgmt",
            16000 => "hbase-master",
            16010 => "hbase-master-ui",
            16020 => "hbase-region",
            27017 => "mongodb",
            27018 | 27019 => "mongodb",
            28017 => "mongodb-http",
            50000 => "jenkins-agent",
            50070 => "hdfs-nn-ui",
            50075 => "hdfs-dn-ui",
            50051 => "grpc",
            61616 => "activemq",
            _ => return None,
        };
        Some(service.to_string())
    }

    /// Get common TCP ports for scanning (top 100 ports)
    pub fn get_common_ports() -> Vec<u16> {
        vec![
            // Core services
            20, 21, 22, 23, 25, 26, 53, 80, 88, 110, 111, 113, 119, 135, 139, 143, 161, 179,
            // Secure services
            389, 443, 445, 465, 500, 514, 554, 587, 631, 636, 873, 902, 990, 993, 995,
            // Databases & messaging
            1080, 1433, 1434, 1521, 1723, 1812, 1883, 2049, 2181, 2222, 2375, 2376, 2379,
            // Web & apps
            3000, 3128, 3268, 3306, 3389, 3690, 4369, 4443, 5000, 5005, 5060, 5222, 5432,
            5601, 5672, 5900, 5984, 5985, 6379, 6443, 6667,
            // Management & monitoring
            7001, 7474, 7687, 8000, 8008, 8009, 8080, 8081, 8088, 8123, 8139, 8140, 8200,
            8443, 8500, 8834, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418,
            // Infrastructure
            10000, 10250, 11211, 15672, 27017, 50000, 50051, 50070, 61616,
        ]
    }
}

/// Scan type for raw socket scanning
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanType {
    /// TCP Connect scan (default, no root required)
    Connect,
    /// TCP SYN scan (half-open, requires root)
    Syn,
    /// TCP FIN scan (stealth, requires root)
    Fin,
    /// TCP NULL scan (no flags, requires root)
    Null,
    /// TCP XMAS scan (FIN+PSH+URG, requires root)
    Xmas,
    /// UDP scan (with ICMP response handling)
    Udp,
    /// TCP ACK scan (firewall detection)
    Ack,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Connect => write!(f, "connect"),
            ScanType::Syn => write!(f, "syn"),
            ScanType::Fin => write!(f, "fin"),
            ScanType::Null => write!(f, "null"),
            ScanType::Xmas => write!(f, "xmas"),
            ScanType::Udp => write!(f, "udp"),
            ScanType::Ack => write!(f, "ack"),
        }
    }
}

/// Timing templates for scan speed/stealth tradeoffs
/// Similar to nmap's -T0 through -T5 options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimingTemplate {
    /// T0: Paranoid - 5 minute delay between probes, single thread
    /// Use for IDS evasion, extremely slow but stealthy
    Paranoid,
    /// T1: Sneaky - 15 second delay between probes, single thread
    /// Use for IDS evasion, very slow but stealthy
    Sneaky,
    /// T2: Polite - 400ms delay between probes, limited parallelism
    /// Use to reduce bandwidth and be nice to target
    Polite,
    /// T3: Normal - Default balanced settings
    /// Good balance of speed and reliability
    Normal,
    /// T4: Aggressive - Faster timeouts, more parallelism
    /// Assumes reliable network, may miss ports on slow networks
    Aggressive,
    /// T5: Insane - Maximum speed, very short timeouts
    /// May miss ports, use only on fast reliable networks
    Insane,
}

impl TimingTemplate {
    /// Get timeout in milliseconds for this template
    pub fn timeout_ms(&self) -> u64 {
        match self {
            TimingTemplate::Paranoid => 300_000, // 5 minutes
            TimingTemplate::Sneaky => 15_000,    // 15 seconds
            TimingTemplate::Polite => 2_000,     // 2 seconds
            TimingTemplate::Normal => 1_000,     // 1 second (default)
            TimingTemplate::Aggressive => 500,   // 500ms
            TimingTemplate::Insane => 250,       // 250ms
        }
    }

    /// Get inter-probe delay in milliseconds
    pub fn delay_ms(&self) -> u64 {
        match self {
            TimingTemplate::Paranoid => 300_000, // 5 minutes between probes
            TimingTemplate::Sneaky => 15_000,    // 15 seconds
            TimingTemplate::Polite => 400,       // 400ms
            TimingTemplate::Normal => 0,         // No delay
            TimingTemplate::Aggressive => 0,
            TimingTemplate::Insane => 0,
        }
    }

    /// Get number of parallel threads/connections
    pub fn parallelism(&self) -> usize {
        match self {
            TimingTemplate::Paranoid => 1,
            TimingTemplate::Sneaky => 1,
            TimingTemplate::Polite => 10,
            TimingTemplate::Normal => 100,
            TimingTemplate::Aggressive => 500,
            TimingTemplate::Insane => 1000,
        }
    }

    /// Get number of retries for failed probes
    pub fn retries(&self) -> u8 {
        match self {
            TimingTemplate::Paranoid => 10,
            TimingTemplate::Sneaky => 5,
            TimingTemplate::Polite => 3,
            TimingTemplate::Normal => 2,
            TimingTemplate::Aggressive => 1,
            TimingTemplate::Insane => 0,
        }
    }

    /// Get host timeout (max time to scan one host) in seconds
    pub fn host_timeout_secs(&self) -> u64 {
        match self {
            TimingTemplate::Paranoid => 0, // No limit
            TimingTemplate::Sneaky => 0,   // No limit
            TimingTemplate::Polite => 0,   // No limit
            TimingTemplate::Normal => 0,   // No limit
            TimingTemplate::Aggressive => 900,  // 15 minutes
            TimingTemplate::Insane => 300,      // 5 minutes
        }
    }

    /// Parse timing template from string (T0-T5 or name)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "t0" | "paranoid" => Some(TimingTemplate::Paranoid),
            "t1" | "sneaky" => Some(TimingTemplate::Sneaky),
            "t2" | "polite" => Some(TimingTemplate::Polite),
            "t3" | "normal" | "default" => Some(TimingTemplate::Normal),
            "t4" | "aggressive" => Some(TimingTemplate::Aggressive),
            "t5" | "insane" => Some(TimingTemplate::Insane),
            _ => None,
        }
    }

    /// Get description for display
    pub fn description(&self) -> &'static str {
        match self {
            TimingTemplate::Paranoid => "Paranoid (T0) - IDS evasion, extremely slow",
            TimingTemplate::Sneaky => "Sneaky (T1) - IDS evasion, very slow",
            TimingTemplate::Polite => "Polite (T2) - Reduced bandwidth, slow",
            TimingTemplate::Normal => "Normal (T3) - Default balanced",
            TimingTemplate::Aggressive => "Aggressive (T4) - Fast, may miss on slow networks",
            TimingTemplate::Insane => "Insane (T5) - Maximum speed, unreliable",
        }
    }
}

impl Default for TimingTemplate {
    fn default() -> Self {
        TimingTemplate::Normal
    }
}

impl std::fmt::Display for TimingTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimingTemplate::Paranoid => write!(f, "T0/paranoid"),
            TimingTemplate::Sneaky => write!(f, "T1/sneaky"),
            TimingTemplate::Polite => write!(f, "T2/polite"),
            TimingTemplate::Normal => write!(f, "T3/normal"),
            TimingTemplate::Aggressive => write!(f, "T4/aggressive"),
            TimingTemplate::Insane => write!(f, "T5/insane"),
        }
    }
}

/// Extended port scan result with state classification
#[derive(Debug, Clone)]
pub struct AdvancedScanResult {
    pub port: u16,
    pub state: crate::protocols::raw::PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub rtt_ms: Option<f64>,
    pub ttl: Option<u8>,
    pub scan_type: ScanType,
}

/// Advanced multi-technique port scanner
/// Supports SYN, FIN, NULL, XMAS, UDP, and Connect scans
pub struct AdvancedScanner {
    target: IpAddr,
    timeout_ms: u64,
    threads: usize,
    scan_type: ScanType,
    timing: TimingTemplate,
    delay_ms: u64,
}

impl AdvancedScanner {
    pub fn new(target: IpAddr) -> Self {
        let cfg = config::get();
        Self {
            target,
            timeout_ms: cfg.network.timeout_ms.max(1),
            threads: cfg.network.threads.max(1),
            scan_type: ScanType::Connect,
            timing: TimingTemplate::Normal,
            delay_ms: 0,
        }
    }

    pub fn with_scan_type(mut self, scan_type: ScanType) -> Self {
        self.scan_type = scan_type;
        self
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1);
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.max(1);
        self
    }

    /// Apply a timing template (overrides threads, timeout, delay)
    pub fn with_timing(mut self, timing: TimingTemplate) -> Self {
        self.timing = timing;
        self.timeout_ms = timing.timeout_ms();
        self.threads = timing.parallelism();
        self.delay_ms = timing.delay_ms();
        self
    }

    /// Get the current timing template
    pub fn timing(&self) -> TimingTemplate {
        self.timing
    }

    /// Scan ports using the configured scan type
    pub fn scan_ports(&self, ports: &[u16]) -> Vec<AdvancedScanResult> {
        use crate::protocols::raw::PortState;

        match self.scan_type {
            ScanType::Connect => {
                // Use existing TCP connect scanner
                let scanner = PortScanner::new(self.target)
                    .with_threads(self.threads)
                    .with_timeout(self.timeout_ms);

                scanner.scan_ports(ports)
                    .into_iter()
                    .map(|r| AdvancedScanResult {
                        port: r.port,
                        state: if r.is_open { PortState::Open } else { PortState::Closed },
                        service: r.service,
                        banner: r.banner,
                        rtt_ms: None,
                        ttl: None,
                        scan_type: ScanType::Connect,
                    })
                    .collect()
            }
            #[cfg(target_family = "unix")]
            ScanType::Syn => self.raw_syn_scan(ports),
            #[cfg(target_family = "unix")]
            ScanType::Fin | ScanType::Null | ScanType::Xmas => self.raw_stealth_scan(ports),
            #[cfg(target_family = "unix")]
            ScanType::Udp => self.udp_scan(ports),
            #[cfg(target_family = "unix")]
            ScanType::Ack => self.raw_ack_scan(ports),
            #[cfg(not(target_family = "unix"))]
            _ => {
                eprintln!("Raw socket scans require Unix/Linux. Falling back to connect scan.");
                self.with_scan_type(ScanType::Connect).scan_ports(ports)
            }
        }
    }

    #[cfg(target_family = "unix")]
    fn raw_syn_scan(&self, ports: &[u16]) -> Vec<AdvancedScanResult> {
        use crate::protocols::raw::{SynScanner, get_source_ip, PortState};
        use std::net::Ipv4Addr;

        let dst_ip = match self.target {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                eprintln!("SYN scan only supports IPv4");
                return Vec::new();
            }
        };

        let src_ip = match get_source_ip(dst_ip) {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("Could not determine source IP: {}", e);
                return Vec::new();
            }
        };

        let scanner = SynScanner::new(src_ip, dst_ip)
            .with_timeout(Duration::from_millis(self.timeout_ms));

        let mut results = Vec::with_capacity(ports.len());

        for &port in ports {
            match scanner.scan_port(port) {
                Ok(raw_result) => {
                    results.push(AdvancedScanResult {
                        port,
                        state: raw_result.state,
                        service: if raw_result.state == PortState::Open {
                            PortScanner::guess_service(port)
                        } else {
                            None
                        },
                        banner: None, // SYN scan doesn't grab banners
                        rtt_ms: raw_result.rtt.map(|d| d.as_secs_f64() * 1000.0),
                        ttl: raw_result.ttl,
                        scan_type: ScanType::Syn,
                    });
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        eprintln!("SYN scan requires root/CAP_NET_RAW. Falling back to connect scan.");
                        return AdvancedScanner::new(self.target)
                            .with_scan_type(ScanType::Connect)
                            .with_threads(self.threads)
                            .with_timeout(self.timeout_ms)
                            .scan_ports(ports);
                    }
                    results.push(AdvancedScanResult {
                        port,
                        state: PortState::Filtered,
                        service: None,
                        banner: None,
                        rtt_ms: None,
                        ttl: None,
                        scan_type: ScanType::Syn,
                    });
                }
            }
        }

        results
    }

    #[cfg(target_family = "unix")]
    fn raw_stealth_scan(&self, ports: &[u16]) -> Vec<AdvancedScanResult> {
        use crate::protocols::raw::{StealthScanner, StealthScanType, get_source_ip, PortState};

        let dst_ip = match self.target {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                eprintln!("Stealth scan only supports IPv4");
                return Vec::new();
            }
        };

        let src_ip = match get_source_ip(dst_ip) {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("Could not determine source IP: {}", e);
                return Vec::new();
            }
        };

        let stealth_type = match self.scan_type {
            ScanType::Fin => StealthScanType::Fin,
            ScanType::Null => StealthScanType::Null,
            ScanType::Xmas => StealthScanType::Xmas,
            _ => unreachable!(),
        };

        let scanner = StealthScanner::new(src_ip, dst_ip, stealth_type)
            .with_timeout(Duration::from_millis(self.timeout_ms));

        let mut results = Vec::with_capacity(ports.len());

        for &port in ports {
            match scanner.scan_port(port) {
                Ok(raw_result) => {
                    results.push(AdvancedScanResult {
                        port,
                        state: raw_result.state,
                        service: if raw_result.state == PortState::Open || raw_result.state == PortState::OpenFiltered {
                            PortScanner::guess_service(port)
                        } else {
                            None
                        },
                        banner: None,
                        rtt_ms: raw_result.rtt.map(|d| d.as_secs_f64() * 1000.0),
                        ttl: raw_result.ttl,
                        scan_type: self.scan_type,
                    });
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        eprintln!("Stealth scan requires root/CAP_NET_RAW.");
                        return Vec::new();
                    }
                    results.push(AdvancedScanResult {
                        port,
                        state: PortState::Filtered,
                        service: None,
                        banner: None,
                        rtt_ms: None,
                        ttl: None,
                        scan_type: self.scan_type,
                    });
                }
            }
        }

        results
    }

    #[cfg(target_family = "unix")]
    fn udp_scan(&self, ports: &[u16]) -> Vec<AdvancedScanResult> {
        use crate::protocols::raw::{UdpScanner, get_source_ip, PortState};

        let dst_ip = match self.target {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                eprintln!("UDP scan only supports IPv4");
                return Vec::new();
            }
        };

        let src_ip = match get_source_ip(dst_ip) {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("Could not determine source IP: {}", e);
                return Vec::new();
            }
        };

        let scanner = UdpScanner::new(src_ip, dst_ip)
            .with_timeout(Duration::from_millis(self.timeout_ms));

        let mut results = Vec::with_capacity(ports.len());

        for &port in ports {
            match scanner.scan_port(port) {
                Ok(raw_result) => {
                    results.push(AdvancedScanResult {
                        port,
                        state: raw_result.state,
                        service: Self::guess_udp_service(port),
                        banner: None,
                        rtt_ms: raw_result.rtt.map(|d| d.as_secs_f64() * 1000.0),
                        ttl: raw_result.ttl,
                        scan_type: ScanType::Udp,
                    });
                }
                Err(_) => {
                    results.push(AdvancedScanResult {
                        port,
                        state: PortState::OpenFiltered,
                        service: None,
                        banner: None,
                        rtt_ms: None,
                        ttl: None,
                        scan_type: ScanType::Udp,
                    });
                }
            }
        }

        results
    }

    #[cfg(target_family = "unix")]
    fn raw_ack_scan(&self, ports: &[u16]) -> Vec<AdvancedScanResult> {
        use crate::protocols::raw::PortState;

        // ACK scan sends ACK packets - if RST comes back, port is unfiltered
        // If nothing comes back, port is filtered (firewall dropping)
        // This doesn't distinguish open vs closed, only filtered vs unfiltered

        let mut results = Vec::with_capacity(ports.len());

        for &port in ports {
            // For now, fallback to filtered - full implementation requires
            // similar raw socket logic to SYN scan
            results.push(AdvancedScanResult {
                port,
                state: PortState::Filtered, // TODO: implement ACK scan
                service: None,
                banner: None,
                rtt_ms: None,
                ttl: None,
                scan_type: ScanType::Ack,
            });
        }

        results
    }

    /// Guess UDP service by port (30+ protocols supported)
    fn guess_udp_service(port: u16) -> Option<String> {
        let service = match port {
            7 => "echo",
            9 => "discard",
            13 => "daytime",
            17 => "qotd",
            19 => "chargen",
            37 => "time",
            49 => "tacacs",
            53 => "dns",
            67 => "dhcp-server",
            68 => "dhcp-client",
            69 => "tftp",
            88 => "kerberos",
            111 => "rpcbind",
            123 => "ntp",
            137 => "netbios-ns",
            138 => "netbios-dgm",
            161 => "snmp",
            162 => "snmp-trap",
            177 => "xdmcp",
            389 => "ldap",
            443 => "https-udp",
            464 => "kpasswd",
            500 => "isakmp",
            514 => "syslog",
            520 => "rip",
            623 => "ipmi",
            636 => "ldaps",
            751 | 752 => "kerberos",
            853 => "dns-tls",
            1194 => "openvpn",
            1434 => "mssql-m",
            1645 | 1646 => "radius-old",
            1701 => "l2tp",
            1812 => "radius",
            1813 => "radius-acct",
            1900 => "ssdp",
            2049 => "nfs",
            2123 | 2152 => "gtp",
            3389 => "rdp-udp",
            3478 => "stun",
            3544 => "teredo",
            4500 => "nat-t-ike",
            4789 => "vxlan",
            5000 => "upnp",
            5060 => "sip",
            5353 => "mdns",
            5683 => "coap",
            6343 => "sflow",
            8125 => "statsd",
            8472 => "otv",
            8767 => "teamspeak",
            9987 => "teamspeak3",
            10161 | 10162 => "snmp-tls",
            27015..=27030 => "steam",
            33434..=33534 => "traceroute",
            _ => return None,
        };
        Some(service.to_string())
    }

    /// Get common UDP ports for scanning (expanded list)
    pub fn get_common_udp_ports() -> Vec<u16> {
        vec![
            53, 67, 68, 69, 88, 111, 123, 137, 138, 161, 162, 177, 389,
            464, 500, 514, 520, 623, 636, 853, 1194, 1434, 1701, 1812,
            1813, 1900, 2049, 3478, 4500, 5060, 5353, 5683, 6343, 8125,
        ]
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
