// Schema definitions for compact storage
// Each data type has optimized binary format

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::storage::encoding::{read_varu32, write_varu32, DecodeError};

/// Data types supported by RedDB
#[derive(Debug, Clone)]
pub enum RecordType {
    /// Port scan result: IP + port + status + timestamp
    PortScan(PortScanRecord),
    /// Subdomain: domain + IPs + source + timestamp
    Subdomain(SubdomainRecord),
    /// WHOIS: domain + registrar + dates + NS
    WhoisInfo(WhoisRecord),
    /// TLS scan result with full metadata
    TlsScan(TlsScanRecord),
    /// HTTP headers: URL + headers map
    HttpHeaders(HttpHeadersRecord),
    /// DNS record: domain + type + value
    DnsRecord(DnsRecordData),
    /// Generic key-value for flexibility
    KeyValue(Vec<u8>, Vec<u8>),
    /// Host fingerprint/intel data
    HostIntel(HostIntelRecord),
    /// Service fingerprint with CPE
    Fingerprint(FingerprintRecord),
    /// Vulnerability with risk score
    Vulnerability(VulnerabilityRecord),
    /// Exploit execution attempt
    ExploitAttempt(ExploitAttemptRecord),
    /// Interactive session state
    Session(SessionRecord),
    /// Playbook execution history
    PlaybookRun(PlaybookRunRecord),
    /// MITRE ATT&CK Technique detection
    MitreAttack(MitreAttackRecord),
    /// Indicator of Compromise
    Ioc(IocRecord),
}

/// Port scan result - 20 bytes for IPv4 payloads.
#[derive(Debug, Clone)]
pub struct PortScanRecord {
    pub ip: IpAddr,         // 4 or 16 bytes
    pub port: u16,          // 2 bytes
    pub status: PortStatus, // 1 byte
    pub service_id: u8,     // 1 byte (service classification enum)
    pub timestamp: u32,     // 4 bytes (Unix time)
}

impl PortScanRecord {
    pub fn new(ip: u32, port: u16, state: u8, service_id: u8) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let status = match state {
            0 => PortStatus::Open,
            1 => PortStatus::Closed,
            2 => PortStatus::Filtered,
            _ => PortStatus::OpenFiltered,
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        Self {
            ip: IpAddr::V4(std::net::Ipv4Addr::from(ip)),
            port,
            status,
            service_id,
            timestamp,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    Open = 0,
    Closed = 1,
    Filtered = 2,
    OpenFiltered = 3,
}

/// Subdomain record - variable size, compressed
#[derive(Debug, Clone)]
pub struct SubdomainRecord {
    pub subdomain: String,
    pub ips: Vec<IpAddr>,
    pub source: SubdomainSource,
    pub timestamp: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SubdomainSource {
    DnsBruteforce = 0,
    CertTransparency = 1,
    SearchEngine = 2,
    WebCrawl = 3,
}

/// WHOIS record - compact
#[derive(Debug, Clone)]
pub struct WhoisRecord {
    pub domain: String,
    pub registrar: String,
    pub created_date: u32, // Unix timestamp
    pub expires_date: u32,
    pub nameservers: Vec<String>,
    pub timestamp: u32, // When we fetched this
}

/// TLS certificate - compact
#[derive(Debug, Clone)]
pub struct TlsCertRecord {
    pub domain: String,
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub version: u8,
    pub not_before: u32,
    pub not_after: u32,
    pub sans: Vec<String>, // Subject Alternative Names
    pub self_signed: bool,
    pub timestamp: u32,
}

/// TLS scan result persisted from the auditor.
#[derive(Debug, Clone)]
pub struct TlsScanRecord {
    pub host: String,
    pub port: u16,
    pub timestamp: u32,
    pub negotiated_version: Option<String>,
    pub negotiated_cipher: Option<String>,
    pub negotiated_cipher_code: Option<u16>,
    pub negotiated_cipher_strength: TlsCipherStrength,
    pub certificate_valid: bool,
    pub versions: Vec<TlsVersionRecord>,
    pub ciphers: Vec<TlsCipherRecord>,
    pub vulnerabilities: Vec<TlsVulnerabilityRecord>,
    pub certificate_chain: Vec<TlsCertRecord>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja3s_raw: Option<String>,
    pub peer_fingerprints: Vec<String>,
    pub certificate_chain_pem: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TlsVersionRecord {
    pub version: String,
    pub supported: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TlsCipherRecord {
    pub name: String,
    pub code: u16,
    pub strength: TlsCipherStrength,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsCipherStrength {
    Weak = 0,
    Medium = 1,
    Strong = 2,
}

#[derive(Debug, Clone)]
pub struct TlsVulnerabilityRecord {
    pub name: String,
    pub severity: TlsSeverity,
    pub description: String,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Snapshot of TLS handshake data captured alongside an HTTP request.
#[derive(Debug, Clone, Default)]
pub struct HttpTlsSnapshot {
    pub authority: Option<String>,
    pub tls_version: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    pub peer_subjects: Vec<String>,
    pub peer_fingerprints: Vec<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja3s_raw: Option<String>,
    pub certificate_chain_pem: Vec<String>,
}

/// HTTP capture - response metadata + headers
#[derive(Debug, Clone)]
pub struct HttpHeadersRecord {
    pub host: String,
    pub url: String,
    pub method: String,
    pub scheme: String,
    pub http_version: String,
    pub status_code: u16,
    pub status_text: String,
    pub server: Option<String>,
    pub body_size: u32,
    pub headers: Vec<(String, String)>,
    pub timestamp: u32,
    pub tls: Option<HttpTlsSnapshot>,
}

/// DNS record
#[derive(Debug, Clone)]
pub struct DnsRecordData {
    pub domain: String,
    pub record_type: DnsRecordType,
    pub value: String,
    pub ttl: u32,
    pub timestamp: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsRecordType {
    A = 1,
    AAAA = 2,
    MX = 3,
    NS = 4,
    TXT = 5,
    CNAME = 6,
}

/// Service-level fingerprint information captured during host analysis.
#[derive(Debug, Clone)]
pub struct ServiceIntelRecord {
    pub port: u16,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub os_hints: Vec<String>,
}

/// Aggregated host fingerprint/intelligence record.
#[derive(Debug, Clone)]
pub struct HostIntelRecord {
    pub ip: IpAddr,
    pub os_family: Option<String>,
    pub confidence: f32,
    pub last_seen: u32,
    pub services: Vec<ServiceIntelRecord>,
}

// ==================== Pentest Workflow Records ====================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Fingerprint record from service detection
#[derive(Debug, Clone)]
pub struct FingerprintRecord {
    pub host: String,
    pub port: u16,
    pub technology: String,       // e.g., "nginx"
    pub version: Option<String>,  // e.g., "1.21.0"
    pub cpe: Option<String>,      // e.g., "cpe:2.3:a:nginx:nginx:1.21.0"
    pub confidence: u8,           // 0-100
    pub source: String,           // banner/header/probe
    pub detected_at: u32,
}

/// Vulnerability record from CVE correlation
#[derive(Debug, Clone)]
pub struct VulnerabilityRecord {
    pub cve_id: String,           // e.g., "CVE-2021-44228"
    pub technology: String,       // e.g., "log4j"
    pub version: Option<String>,  // e.g., "2.14.0"
    pub cvss: f32,                // e.g., 10.0
    pub risk_score: u8,           // 0-100
    pub severity: Severity,       // Critical/High/Medium/Low
    pub description: String,
    pub references: Vec<String>,  // URLs
    pub exploit_available: bool,
    pub in_kev: bool,             // CISA Known Exploited
    pub discovered_at: u32,       // timestamp
    pub source: String,           // nvd/osv/kev/exploitdb
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExploitStatus {
    Pending = 0,
    Running = 1,
    Success = 2,
    Failed = 3,
}

/// Exploit attempt record
#[derive(Debug, Clone)]
pub struct ExploitAttemptRecord {
    pub target: String,
    pub cve_id: Option<String>,
    pub exploit_name: String,
    pub status: ExploitStatus,
    pub output: Option<String>,
    pub attempted_at: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Active = 0,
    Closed = 1,
    Dead = 2,
}

/// Session record for active shells
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: String,               // uuid
    pub target: String,
    pub shell_type: String,       // tcp/http/dns/icmp
    pub local_port: u16,
    pub remote_ip: String,
    pub status: SessionStatus,
    pub created_at: u32,
    pub last_activity: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaybookStatus {
    Running = 0,
    Completed = 1,
    Failed = 2,
}

#[derive(Debug, Clone)]
pub struct StepResult {
    pub name: String,
    pub status: String, // "success", "failed", "skipped"
    pub output: Option<String>,
}

/// Playbook execution record
#[derive(Debug, Clone)]
pub struct PlaybookRunRecord {
    pub playbook_name: String,
    pub target: String,
    pub status: PlaybookStatus,
    pub current_phase: u8,
    pub started_at: u32,
    pub completed_at: Option<u32>,
    pub results: Vec<StepResult>,
}

// ==================== Threat Intelligence Records ====================

#[derive(Debug, Clone)]
pub struct MitreAttackRecord {
    pub technique_id: String,     // e.g., "T1059.001"
    pub technique_name: String,   // e.g., "PowerShell"
    pub tactic: String,           // e.g., "Execution"
    pub target: String,           // e.g., "example.com"
    pub source_finding: String,   // e.g., "port_scan:5985"
    pub cve_id: Option<String>,   // e.g., "CVE-2021-44228"
    pub confidence: u8,           // 0-100
    pub score: u8,                // 0-100 (for Navigator)
    pub detected_at: u32,         // Unix timestamp
    pub evidence: String,         // Detail string
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocType {
    IPv4 = 0,
    IPv6 = 1,
    Domain = 2,
    URL = 3,
    Email = 4,
    HashMD5 = 5,
    HashSHA1 = 6,
    HashSHA256 = 7,
    Certificate = 8,
    JA3 = 9,
}

#[derive(Debug, Clone)]
pub struct IocRecord {
    pub ioc_type: IocType,
    pub value: String,            // e.g., "192.168.1.1"
    pub target: String,           // e.g., "example.com"
    pub confidence: u8,           // 0-100
    pub source: String,           // e.g., "port_scan", "dns_lookup"
    pub mitre_techniques: Vec<String>, // List of T-codes
    pub tags: Vec<String>,        // e.g., ["phishing", "apt29"]
    pub first_seen: u32,
    pub last_seen: u32,
    pub stix_id: Option<String>,
}

// ==================== Port Health Records ====================

/// Port state change type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStateChange {
    /// Port is still open (no change)
    StillOpen,
    /// Port is still closed (no change)
    StillClosed,
    /// Port was closed, now open
    Opened,
    /// Port was open, now closed
    Closed,
    /// First time seeing this port
    New,
}

impl PortStateChange {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortStateChange::StillOpen => "still_open",
            PortStateChange::StillClosed => "still_closed",
            PortStateChange::Opened => "opened",
            PortStateChange::Closed => "closed",
            PortStateChange::New => "new",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "still_open" => PortStateChange::StillOpen,
            "still_closed" => PortStateChange::StillClosed,
            "opened" => PortStateChange::Opened,
            "closed" => PortStateChange::Closed,
            "new" => PortStateChange::New,
            _ => PortStateChange::New,
        }
    }

    pub fn to_byte(&self) -> u8 {
        match self {
            PortStateChange::StillOpen => 0,
            PortStateChange::StillClosed => 1,
            PortStateChange::Opened => 2,
            PortStateChange::Closed => 3,
            PortStateChange::New => 4,
        }
    }

    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => PortStateChange::StillOpen,
            1 => PortStateChange::StillClosed,
            2 => PortStateChange::Opened,
            3 => PortStateChange::Closed,
            _ => PortStateChange::New,
        }
    }
}

/// Port health check record - tracks port state changes over time
#[derive(Debug, Clone)]
pub struct PortHealthRecord {
    /// Target host IP or hostname
    pub host: String,
    /// Port number
    pub port: u16,
    /// Current state (open/closed)
    pub is_open: bool,
    /// State change type from last check
    pub change: PortStateChange,
    /// Response time in milliseconds (0 if closed)
    pub response_time_ms: u32,
    /// Service detected (if any)
    pub service: Option<String>,
    /// Previous check timestamp
    pub previous_check: u32,
    /// Current check timestamp
    pub checked_at: u32,
    /// Number of consecutive checks with same state
    pub consecutive_same_state: u16,
}

impl PortHealthRecord {
    pub fn new(host: String, port: u16, is_open: bool) -> Self {
        Self {
            host,
            port,
            is_open,
            change: PortStateChange::New,
            response_time_ms: 0,
            service: None,
            previous_check: 0,
            checked_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32,
            consecutive_same_state: 1,
        }
    }

    /// Convert to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Host (length-prefixed)
        let host_bytes = self.host.as_bytes();
        bytes.extend_from_slice(&(host_bytes.len() as u16).to_le_bytes());
        bytes.extend_from_slice(host_bytes);

        // Port
        bytes.extend_from_slice(&self.port.to_le_bytes());

        // is_open
        bytes.push(self.is_open as u8);

        // change
        bytes.push(self.change.to_byte());

        // response_time_ms
        bytes.extend_from_slice(&self.response_time_ms.to_le_bytes());

        // Service (length-prefixed, 0 if None)
        if let Some(ref service) = self.service {
            let service_bytes = service.as_bytes();
            bytes.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
            bytes.extend_from_slice(service_bytes);
        } else {
            bytes.extend_from_slice(&0u16.to_le_bytes());
        }

        // previous_check
        bytes.extend_from_slice(&self.previous_check.to_le_bytes());

        // checked_at
        bytes.extend_from_slice(&self.checked_at.to_le_bytes());

        // consecutive_same_state
        bytes.extend_from_slice(&self.consecutive_same_state.to_le_bytes());

        bytes
    }

    /// Create from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let mut offset = 0;

        // Host
        let host_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + host_len > data.len() {
            return None;
        }
        let host = String::from_utf8(data[offset..offset + host_len].to_vec()).ok()?;
        offset += host_len;

        // Port
        if offset + 2 > data.len() {
            return None;
        }
        let port = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // is_open
        if offset >= data.len() {
            return None;
        }
        let is_open = data[offset] != 0;
        offset += 1;

        // change
        if offset >= data.len() {
            return None;
        }
        let change = PortStateChange::from_byte(data[offset]);
        offset += 1;

        // response_time_ms
        if offset + 4 > data.len() {
            return None;
        }
        let response_time_ms = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        // Service
        if offset + 2 > data.len() {
            return None;
        }
        let service_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let service = if service_len > 0 {
            if offset + service_len > data.len() {
                return None;
            }
            Some(String::from_utf8(data[offset..offset + service_len].to_vec()).ok()?)
        } else {
            None
        };
        offset += service_len;

        // previous_check
        if offset + 4 > data.len() {
            return None;
        }
        let previous_check = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        // checked_at
        if offset + 4 > data.len() {
            return None;
        }
        let checked_at = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        // consecutive_same_state
        if offset + 2 > data.len() {
            return None;
        }
        let consecutive_same_state = u16::from_le_bytes([data[offset], data[offset + 1]]);

        Some(Self {
            host,
            port,
            is_open,
            change,
            response_time_ms,
            service,
            previous_check,
            checked_at,
            consecutive_same_state,
        })
    }
}

// ==================== Proxy Records ====================

/// Proxy connection record - tracks intercepted connections
#[derive(Debug, Clone)]
pub struct ProxyConnectionRecord {
    /// Unique connection ID
    pub connection_id: u64,
    /// Source IP:port
    pub src_ip: IpAddr,
    pub src_port: u16,
    /// Destination host (domain or IP)
    pub dst_host: String,
    pub dst_port: u16,
    /// Protocol (TCP=0, UDP=1)
    pub protocol: u8,
    /// Connection start timestamp
    pub started_at: u32,
    /// Connection end timestamp (0 if still active)
    pub ended_at: u32,
    /// Total bytes sent (client -> target)
    pub bytes_sent: u64,
    /// Total bytes received (target -> client)
    pub bytes_received: u64,
    /// TLS intercepted (true if MITM'd)
    pub tls_intercepted: bool,
}

/// Proxy HTTP request record - intercepted HTTP request
#[derive(Debug, Clone)]
pub struct ProxyHttpRequestRecord {
    /// Reference to connection ID
    pub connection_id: u64,
    /// Request sequence number within connection
    pub request_seq: u32,
    /// HTTP method (GET, POST, etc)
    pub method: String,
    /// Request path (URL path + query string)
    pub path: String,
    /// HTTP version
    pub http_version: String,
    /// Host header value
    pub host: String,
    /// Request headers (key-value pairs)
    pub headers: Vec<(String, String)>,
    /// Request body (may be empty)
    pub body: Vec<u8>,
    /// Request timestamp
    pub timestamp: u32,
    /// Client IP address making this request
    pub client_addr: Option<String>,
}

/// Proxy HTTP response record - intercepted HTTP response
#[derive(Debug, Clone)]
pub struct ProxyHttpResponseRecord {
    /// Reference to connection ID
    pub connection_id: u64,
    /// Request sequence number this responds to
    pub request_seq: u32,
    /// HTTP status code
    pub status_code: u16,
    /// Status text (e.g., "OK", "Not Found")
    pub status_text: String,
    /// HTTP version
    pub http_version: String,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Response body (may be truncated for large responses)
    pub body: Vec<u8>,
    /// Response timestamp
    pub timestamp: u32,
    /// Content-Type header value
    pub content_type: Option<String>,
}

/// Proxy WebSocket frame record
#[derive(Debug, Clone)]
pub struct ProxyWebSocketRecord {
    /// Reference to connection ID
    pub connection_id: u64,
    /// Frame sequence number
    pub frame_seq: u64,
    /// Direction: 0 = client->server, 1 = server->client
    pub direction: u8,
    /// Frame opcode (0=continuation, 1=text, 2=binary, 8=close, 9=ping, 10=pong)
    pub opcode: u8,
    /// Frame payload (may be truncated)
    pub payload: Vec<u8>,
    /// Frame timestamp
    pub timestamp: u32,
}

/// Compact binary serialization for each type
impl PortScanRecord {
    /// Serialize to bytes (19 bytes for IPv4)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);

        // IP address
        match self.ip {
            IpAddr::V4(ip) => {
                buf.push(4); // IPv4 marker
                buf.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.push(6); // IPv6 marker
                buf.extend_from_slice(&ip.octets());
            }
        }

        // Port
        buf.extend_from_slice(&self.port.to_le_bytes());

        // Status + service
        buf.push(self.status as u8);
        buf.push(self.service_id);

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }

        let ip_version = buf[0];

        let (ip, offset) = if ip_version == 4 {
            if buf.len() < 1 + 4 {
                return None;
            }
            let octets = [buf[1], buf[2], buf[3], buf[4]];
            (IpAddr::V4(Ipv4Addr::from(octets)), 5)
        } else if ip_version == 6 {
            if buf.len() < 1 + 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            (IpAddr::V6(Ipv6Addr::from(octets)), 17)
        } else {
            return None;
        };

        if buf.len() < offset + 8 {
            return None;
        }

        let port = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        let status = match buf[offset + 2] {
            0 => PortStatus::Open,
            1 => PortStatus::Closed,
            2 => PortStatus::Filtered,
            3 => PortStatus::OpenFiltered,
            _ => return None,
        };
        let service_id = buf.get(offset + 3).copied()?;
        let timestamp = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);

        Some(Self {
            ip,
            port,
            status,
            service_id,
            timestamp,
        })
    }
}

impl SubdomainRecord {
    /// Serialize with compression
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Subdomain length + data
        let subdomain_bytes = self.subdomain.as_bytes();
        buf.push(subdomain_bytes.len() as u8);
        buf.extend_from_slice(subdomain_bytes);

        // Number of IPs
        buf.push(self.ips.len() as u8);
        for ip in &self.ips {
            match ip {
                IpAddr::V4(ip) => {
                    buf.push(4);
                    buf.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    buf.push(6);
                    buf.extend_from_slice(&ip.octets());
                }
            }
        }

        // Source
        buf.push(self.source as u8);

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }

        let mut offset = 0;

        // Read subdomain
        let subdomain_len = buf[offset] as usize;
        offset += 1;
        if buf.len() < offset + subdomain_len {
            return None;
        }
        let subdomain = String::from_utf8(buf[offset..offset + subdomain_len].to_vec()).ok()?;
        offset += subdomain_len;

        // Read IPs
        if buf.len() < offset + 1 {
            return None;
        }
        let ip_count = buf[offset] as usize;
        offset += 1;

        let mut ips = Vec::new();
        for _ in 0..ip_count {
            if buf.len() < offset + 1 {
                return None;
            }
            let ip_version = buf[offset];
            offset += 1;

            if ip_version == 4 {
                if buf.len() < offset + 4 {
                    return None;
                }
                let octets = [
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ];
                ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
                offset += 4;
            } else if ip_version == 6 {
                if buf.len() < offset + 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                offset += 16;
            }
        }

        // Source
        if buf.len() < offset + 1 {
            return None;
        }
        let source = match buf[offset] {
            0 => SubdomainSource::DnsBruteforce,
            1 => SubdomainSource::CertTransparency,
            2 => SubdomainSource::SearchEngine,
            3 => SubdomainSource::WebCrawl,
            _ => return None,
        };
        offset += 1;

        // Timestamp
        if buf.len() < offset + 4 {
            return None;
        }
        let timestamp = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);

        Some(Self {
            subdomain,
            ips,
            source,
            timestamp,
        })
    }
}

impl ServiceIntelRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.port.to_le_bytes());
        write_optional_string(&mut buf, &self.service_name);
        write_optional_string(&mut buf, &self.banner);
        write_varu32(&mut buf, self.os_hints.len() as u32);
        for hint in &self.os_hints {
            write_string(&mut buf, hint);
        }
        buf
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < 2 {
            return Err(DecodeError("service record too small"));
        }
        let port = u16::from_le_bytes([bytes[0], bytes[1]]);
        let mut pos = 2usize;
        let service_name = read_optional_string(bytes, &mut pos)?;
        let banner = read_optional_string(bytes, &mut pos)?;

        let hint_count = read_varu32(bytes, &mut pos)? as usize;
        let mut os_hints = Vec::with_capacity(hint_count);
        for _ in 0..hint_count {
            let value = read_string(bytes, &mut pos)?;
            os_hints.push(value);
        }

        Ok(Self {
            port,
            service_name,
            banner,
            os_hints,
        })
    }
}

impl HostIntelRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self.ip {
            IpAddr::V4(ip) => {
                buf.push(4);
                buf.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.push(6);
                buf.extend_from_slice(&ip.octets());
            }
        }

        buf.extend_from_slice(&self.last_seen.to_le_bytes());
        buf.extend_from_slice(&self.confidence.to_bits().to_le_bytes());
        write_optional_string(&mut buf, &self.os_family);

        write_varu32(&mut buf, self.services.len() as u32);
        for service in &self.services {
            let svc_bytes = service.to_bytes();
            write_varu32(&mut buf, svc_bytes.len() as u32);
            buf.extend_from_slice(&svc_bytes);
        }

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError("empty host record"));
        }

        let ip_version = bytes[0];
        let mut pos = 1usize;
        let ip = match ip_version {
            4 => {
                if bytes.len() < pos + 4 {
                    return Err(DecodeError("truncated IPv4 address"));
                }
                let octets = [bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]];
                pos += 4;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                if bytes.len() < pos + 16 {
                    return Err(DecodeError("truncated IPv6 address"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[pos..pos + 16]);
                pos += 16;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(DecodeError("invalid IP version")),
        };

        if bytes.len() < pos + 8 {
            return Err(DecodeError("truncated host record metadata"));
        }

        let last_seen =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        let confidence_bits =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        let confidence = f32::from_bits(confidence_bits);

        let os_family = read_optional_string(bytes, &mut pos)?;

        let service_count = read_varu32(bytes, &mut pos)? as usize;
        let mut services = Vec::with_capacity(service_count);
        for _ in 0..service_count {
            let svc_len = read_varu32(bytes, &mut pos)? as usize;
            if bytes.len() < pos + svc_len {
                return Err(DecodeError("truncated service entry"));
            }
            let record = ServiceIntelRecord::from_slice(&bytes[pos..pos + svc_len])?;
            pos += svc_len;
            services.push(record);
        }

        Ok(Self {
            ip,
            os_family,
            confidence,
            last_seen,
            services,
        })
    }
}

// ==================== Pentest Workflow Serialization ====================

impl FingerprintRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.host);
        buf.extend_from_slice(&self.port.to_le_bytes());
        write_string(&mut buf, &self.technology);
        write_optional_string(&mut buf, &self.version);
        write_optional_string(&mut buf, &self.cpe);
        buf.push(self.confidence);
        write_string(&mut buf, &self.source);
        buf.extend_from_slice(&self.detected_at.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError("empty fingerprint record"));
        }
        let mut pos = 0;
        let host = read_string(bytes, &mut pos)?;
        
        if bytes.len() < pos + 2 {
            return Err(DecodeError("truncated port"));
        }
        let port = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;

        let technology = read_string(bytes, &mut pos)?;
        let version = read_optional_string(bytes, &mut pos)?;
        let cpe = read_optional_string(bytes, &mut pos)?;
        
        if pos >= bytes.len() {
            return Err(DecodeError("truncated confidence"));
        }
        let confidence = bytes[pos];
        pos += 1;

        let source = read_string(bytes, &mut pos)?;
        
        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated timestamp"));
        }
        let detected_at = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);

        Ok(Self {
            host,
            port,
            technology,
            version,
            cpe,
            confidence,
            source,
            detected_at,
        })
    }
}

impl VulnerabilityRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.cve_id);
        write_string(&mut buf, &self.technology);
        write_optional_string(&mut buf, &self.version);
        buf.extend_from_slice(&self.cvss.to_bits().to_le_bytes());
        buf.push(self.risk_score);
        buf.push(self.severity as u8);
        write_string(&mut buf, &self.description);
        
        write_varu32(&mut buf, self.references.len() as u32);
        for ref_url in &self.references {
            write_string(&mut buf, ref_url);
        }

        buf.push(if self.exploit_available { 1 } else { 0 });
        buf.push(if self.in_kev { 1 } else { 0 });
        buf.extend_from_slice(&self.discovered_at.to_le_bytes());
        write_string(&mut buf, &self.source);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0;
        let cve_id = read_string(bytes, &mut pos)?;
        let technology = read_string(bytes, &mut pos)?;
        let version = read_optional_string(bytes, &mut pos)?;
        
        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated cvss"));
        }
        let cvss_bits = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        let cvss = f32::from_bits(cvss_bits);
        pos += 4;

        if bytes.len() < pos + 2 {
            return Err(DecodeError("truncated risk/severity"));
        }
        let risk_score = bytes[pos];
        pos += 1;
        let severity = match bytes[pos] {
            0 => Severity::Info,
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            4 => Severity::Critical,
            _ => Severity::Info,
        };
        pos += 1;

        let description = read_string(bytes, &mut pos)?;

        let ref_count = read_varu32(bytes, &mut pos)? as usize;
        let mut references = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            references.push(read_string(bytes, &mut pos)?);
        }

        if bytes.len() < pos + 2 {
            return Err(DecodeError("truncated flags"));
        }
        let exploit_available = bytes[pos] != 0;
        pos += 1;
        let in_kev = bytes[pos] != 0;
        pos += 1;

        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated timestamp"));
        }
        let discovered_at = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        let source = read_string(bytes, &mut pos)?;

        Ok(Self {
            cve_id,
            technology,
            version,
            cvss,
            risk_score,
            severity,
            description,
            references,
            exploit_available,
            in_kev,
            discovered_at,
            source,
        })
    }
}

impl ExploitAttemptRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.target);
        write_optional_string(&mut buf, &self.cve_id);
        write_string(&mut buf, &self.exploit_name);
        buf.push(self.status as u8);
        write_optional_string(&mut buf, &self.output);
        buf.extend_from_slice(&self.attempted_at.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0;
        let target = read_string(bytes, &mut pos)?;
        let cve_id = read_optional_string(bytes, &mut pos)?;
        let exploit_name = read_string(bytes, &mut pos)?;
        
        if pos >= bytes.len() {
            return Err(DecodeError("truncated status"));
        }
        let status = match bytes[pos] {
            0 => ExploitStatus::Pending,
            1 => ExploitStatus::Running,
            2 => ExploitStatus::Success,
            3 => ExploitStatus::Failed,
            _ => ExploitStatus::Failed,
        };
        pos += 1;

        let output = read_optional_string(bytes, &mut pos)?;
        
        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated timestamp"));
        }
        let attempted_at = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);

        Ok(Self {
            target,
            cve_id,
            exploit_name,
            status,
            output,
            attempted_at,
        })
    }
}

impl SessionRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.id);
        write_string(&mut buf, &self.target);
        write_string(&mut buf, &self.shell_type);
        buf.extend_from_slice(&self.local_port.to_le_bytes());
        write_string(&mut buf, &self.remote_ip);
        buf.push(self.status as u8);
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.last_activity.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0;
        let id = read_string(bytes, &mut pos)?;
        let target = read_string(bytes, &mut pos)?;
        let shell_type = read_string(bytes, &mut pos)?;
        
        if bytes.len() < pos + 2 {
            return Err(DecodeError("truncated port"));
        }
        let local_port = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;

        let remote_ip = read_string(bytes, &mut pos)?;
        
        if pos >= bytes.len() {
            return Err(DecodeError("truncated status"));
        }
        let status = match bytes[pos] {
            0 => SessionStatus::Active,
            1 => SessionStatus::Closed,
            2 => SessionStatus::Dead,
            _ => SessionStatus::Closed,
        };
        pos += 1;

        if bytes.len() < pos + 8 {
            return Err(DecodeError("truncated timestamps"));
        }
        let created_at = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        let last_activity = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);

        Ok(Self {
            id,
            target,
            shell_type,
            local_port,
            remote_ip,
            status,
            created_at,
            last_activity,
        })
    }
}

impl PlaybookRunRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.playbook_name);
        write_string(&mut buf, &self.target);
        buf.push(self.status as u8);
        buf.push(self.current_phase);
        buf.extend_from_slice(&self.started_at.to_le_bytes());
        
        match self.completed_at {
            Some(ts) => {
                buf.push(1);
                buf.extend_from_slice(&ts.to_le_bytes());
            }
            None => buf.push(0),
        }

        write_varu32(&mut buf, self.results.len() as u32);
        for res in &self.results {
            write_string(&mut buf, &res.name);
            write_string(&mut buf, &res.status);
            write_optional_string(&mut buf, &res.output);
        }
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0;
        let playbook_name = read_string(bytes, &mut pos)?;
        let target = read_string(bytes, &mut pos)?;
        
        if pos >= bytes.len() {
            return Err(DecodeError("truncated status"));
        }
        let status = match bytes[pos] {
            0 => PlaybookStatus::Running,
            1 => PlaybookStatus::Completed,
            2 => PlaybookStatus::Failed,
            _ => PlaybookStatus::Failed,
        };
        pos += 1;

        if pos >= bytes.len() {
            return Err(DecodeError("truncated phase"));
        }
        let current_phase = bytes[pos];
        pos += 1;

        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated start time"));
        }
        let started_at = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        if pos >= bytes.len() {
            return Err(DecodeError("truncated completed flag"));
        }
        let has_completed = bytes[pos] != 0;
        pos += 1;
        
        let completed_at = if has_completed {
            if bytes.len() < pos + 4 {
                return Err(DecodeError("truncated completed time"));
            }
            let ts = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            pos += 4;
            Some(ts)
        } else {
            None
        };

        let result_count = read_varu32(bytes, &mut pos)? as usize;
        let mut results = Vec::with_capacity(result_count);
        for _ in 0..result_count {
            let name = read_string(bytes, &mut pos)?;
            let status = read_string(bytes, &mut pos)?;
            let output = read_optional_string(bytes, &mut pos)?;
            results.push(StepResult { name, status, output });
        }

        Ok(Self {
            playbook_name,
            target,
            status,
            current_phase,
            started_at,
            completed_at,
            results,
        })
    }
}

// ==================== Threat Intelligence Serialization ====================

impl MitreAttackRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.technique_id);
        write_string(&mut buf, &self.technique_name);
        write_string(&mut buf, &self.tactic);
        write_string(&mut buf, &self.target);
        write_string(&mut buf, &self.source_finding);
        write_optional_string(&mut buf, &self.cve_id);
        buf.push(self.confidence);
        buf.push(self.score);
        buf.extend_from_slice(&self.detected_at.to_le_bytes());
        write_string(&mut buf, &self.evidence);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0;
        let technique_id = read_string(bytes, &mut pos)?;
        let technique_name = read_string(bytes, &mut pos)?;
        let tactic = read_string(bytes, &mut pos)?;
        let target = read_string(bytes, &mut pos)?;
        let source_finding = read_string(bytes, &mut pos)?;
        let cve_id = read_optional_string(bytes, &mut pos)?;
        
        if bytes.len() < pos + 2 {
            return Err(DecodeError("truncated confidence/score"));
        }
        let confidence = bytes[pos];
        pos += 1;
        let score = bytes[pos];
        pos += 1;

        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated timestamp"));
        }
        let detected_at = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        let evidence = read_string(bytes, &mut pos)?;

        Ok(Self {
            technique_id,
            technique_name,
            tactic,
            target,
            source_finding,
            cve_id,
            confidence,
            score,
            detected_at,
            evidence,
        })
    }
}

impl IocRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.ioc_type as u8);
        write_string(&mut buf, &self.value);
        write_string(&mut buf, &self.target);
        buf.push(self.confidence);
        write_string(&mut buf, &self.source);
        
        write_varu32(&mut buf, self.mitre_techniques.len() as u32);
        for tech in &self.mitre_techniques {
            write_string(&mut buf, tech);
        }

        write_varu32(&mut buf, self.tags.len() as u32);
        for tag in &self.tags {
            write_string(&mut buf, tag);
        }

        buf.extend_from_slice(&self.first_seen.to_le_bytes());
        buf.extend_from_slice(&self.last_seen.to_le_bytes());
        write_optional_string(&mut buf, &self.stix_id);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError("empty ioc record"));
        }
        let mut pos = 0;
        let ioc_type = match bytes[pos] {
            0 => IocType::IPv4,
            1 => IocType::IPv6,
            2 => IocType::Domain,
            3 => IocType::URL,
            4 => IocType::Email,
            5 => IocType::HashMD5,
            6 => IocType::HashSHA1,
            7 => IocType::HashSHA256,
            8 => IocType::Certificate,
            9 => IocType::JA3,
            _ => IocType::Domain,
        };
        pos += 1;

        let value = read_string(bytes, &mut pos)?;
        let target = read_string(bytes, &mut pos)?;
        
        if pos >= bytes.len() {
            return Err(DecodeError("truncated confidence"));
        }
        let confidence = bytes[pos];
        pos += 1;

        let source = read_string(bytes, &mut pos)?;

        let tech_count = read_varu32(bytes, &mut pos)? as usize;
        let mut mitre_techniques = Vec::with_capacity(tech_count);
        for _ in 0..tech_count {
            mitre_techniques.push(read_string(bytes, &mut pos)?);
        }

        let tag_count = read_varu32(bytes, &mut pos)? as usize;
        let mut tags = Vec::with_capacity(tag_count);
        for _ in 0..tag_count {
            tags.push(read_string(bytes, &mut pos)?);
        }

        if bytes.len() < pos + 8 {
            return Err(DecodeError("truncated timestamps"));
        }
        let first_seen = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        let last_seen = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        let stix_id = read_optional_string(bytes, &mut pos)?;

        Ok(Self {
            ioc_type,
            value,
            target,
            confidence,
            source,
            mitre_techniques,
            tags,
            first_seen,
            last_seen,
            stix_id,
        })
    }
}

// ==================== Proxy Record Serialization ====================

impl ProxyConnectionRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Connection ID (8 bytes)
        buf.extend_from_slice(&self.connection_id.to_le_bytes());

        // Source IP
        match self.src_ip {
            IpAddr::V4(ip) => {
                buf.push(4);
                buf.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.push(6);
                buf.extend_from_slice(&ip.octets());
            }
        }

        // Source port (2 bytes)
        buf.extend_from_slice(&self.src_port.to_le_bytes());

        // Destination host (length-prefixed string)
        write_string(&mut buf, &self.dst_host);

        // Destination port (2 bytes)
        buf.extend_from_slice(&self.dst_port.to_le_bytes());

        // Protocol (1 byte)
        buf.push(self.protocol);

        // Timestamps (4 bytes each)
        buf.extend_from_slice(&self.started_at.to_le_bytes());
        buf.extend_from_slice(&self.ended_at.to_le_bytes());

        // Bytes sent/received (8 bytes each)
        buf.extend_from_slice(&self.bytes_sent.to_le_bytes());
        buf.extend_from_slice(&self.bytes_received.to_le_bytes());

        // TLS intercepted (1 byte)
        buf.push(if self.tls_intercepted { 1 } else { 0 });

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < 8 {
            return Err(DecodeError("truncated proxy connection record"));
        }

        let mut pos = 0;

        // Connection ID
        let connection_id = u64::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
            bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7],
        ]);
        pos += 8;

        // Source IP
        if pos >= bytes.len() {
            return Err(DecodeError("truncated src_ip version"));
        }
        let ip_version = bytes[pos];
        pos += 1;

        let src_ip = match ip_version {
            4 => {
                if bytes.len() < pos + 4 {
                    return Err(DecodeError("truncated src IPv4"));
                }
                let octets = [bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]];
                pos += 4;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                if bytes.len() < pos + 16 {
                    return Err(DecodeError("truncated src IPv6"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[pos..pos + 16]);
                pos += 16;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(DecodeError("invalid IP version")),
        };

        // Source port
        if bytes.len() < pos + 2 {
            return Err(DecodeError("truncated src port"));
        }
        let src_port = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;

        // Destination host
        let dst_host = read_string(bytes, &mut pos)?;

        // Destination port
        if bytes.len() < pos + 2 {
            return Err(DecodeError("truncated dst port"));
        }
        let dst_port = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;

        // Protocol
        if pos >= bytes.len() {
            return Err(DecodeError("truncated protocol"));
        }
        let protocol = bytes[pos];
        pos += 1;

        // Timestamps
        if bytes.len() < pos + 8 {
            return Err(DecodeError("truncated timestamps"));
        }
        let started_at = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        let ended_at = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        // Bytes sent/received
        if bytes.len() < pos + 16 {
            return Err(DecodeError("truncated byte counters"));
        }
        let bytes_sent = u64::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
            bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7],
        ]);
        pos += 8;
        let bytes_received = u64::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
            bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7],
        ]);
        pos += 8;

        // TLS intercepted
        if pos >= bytes.len() {
            return Err(DecodeError("truncated tls flag"));
        }
        let tls_intercepted = bytes[pos] != 0;

        Ok(Self {
            connection_id,
            src_ip,
            src_port,
            dst_host,
            dst_port,
            protocol,
            started_at,
            ended_at,
            bytes_sent,
            bytes_received,
            tls_intercepted,
        })
    }
}

impl ProxyHttpRequestRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Connection ID + request seq
        buf.extend_from_slice(&self.connection_id.to_le_bytes());
        buf.extend_from_slice(&self.request_seq.to_le_bytes());

        // Method, path, version, host
        write_string(&mut buf, &self.method);
        write_string(&mut buf, &self.path);
        write_string(&mut buf, &self.http_version);
        write_string(&mut buf, &self.host);

        // Headers count + headers
        write_varu32(&mut buf, self.headers.len() as u32);
        for (key, value) in &self.headers {
            write_string(&mut buf, key);
            write_string(&mut buf, value);
        }

        // Body length + body
        write_varu32(&mut buf, self.body.len() as u32);
        buf.extend_from_slice(&self.body);

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        // Client addr
        write_optional_string(&mut buf, &self.client_addr);

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < 12 {
            return Err(DecodeError("truncated http request record"));
        }

        let mut pos = 0;

        // Connection ID
        let connection_id = u64::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
            bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7],
        ]);
        pos += 8;

        // Request seq
        let request_seq = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        // Strings
        let method = read_string(bytes, &mut pos)?;
        let path = read_string(bytes, &mut pos)?;
        let http_version = read_string(bytes, &mut pos)?;
        let host = read_string(bytes, &mut pos)?;

        // Headers
        let header_count = read_varu32(bytes, &mut pos)? as usize;
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            let key = read_string(bytes, &mut pos)?;
            let value = read_string(bytes, &mut pos)?;
            headers.push((key, value));
        }

        // Body
        let body_len = read_varu32(bytes, &mut pos)? as usize;
        if bytes.len() < pos + body_len {
            return Err(DecodeError("truncated body"));
        }
        let body = bytes[pos..pos + body_len].to_vec();
        pos += body_len;

        // Timestamp
        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated timestamp"));
        }
        let timestamp = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        // Client addr
        let client_addr = read_optional_string(bytes, &mut pos)?;

        Ok(Self {
            connection_id,
            request_seq,
            method,
            path,
            http_version,
            host,
            headers,
            body,
            timestamp,
            client_addr,
        })
    }
}

impl ProxyHttpResponseRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Connection ID + request seq
        buf.extend_from_slice(&self.connection_id.to_le_bytes());
        buf.extend_from_slice(&self.request_seq.to_le_bytes());

        // Status
        buf.extend_from_slice(&self.status_code.to_le_bytes());
        write_string(&mut buf, &self.status_text);
        write_string(&mut buf, &self.http_version);

        // Headers
        write_varu32(&mut buf, self.headers.len() as u32);
        for (key, value) in &self.headers {
            write_string(&mut buf, key);
            write_string(&mut buf, value);
        }

        // Body
        write_varu32(&mut buf, self.body.len() as u32);
        buf.extend_from_slice(&self.body);

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        // Content type
        write_optional_string(&mut buf, &self.content_type);

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < 14 {
            return Err(DecodeError("truncated http response record"));
        }

        let mut pos = 0;

        // Connection ID
        let connection_id = u64::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
            bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7],
        ]);
        pos += 8;

        // Request seq
        let request_seq = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        // Status
        let status_code = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;

        let status_text = read_string(bytes, &mut pos)?;
        let http_version = read_string(bytes, &mut pos)?;

        // Headers
        let header_count = read_varu32(bytes, &mut pos)? as usize;
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            let key = read_string(bytes, &mut pos)?;
            let value = read_string(bytes, &mut pos)?;
            headers.push((key, value));
        }

        // Body
        let body_len = read_varu32(bytes, &mut pos)? as usize;
        if bytes.len() < pos + body_len {
            return Err(DecodeError("truncated body"));
        }
        let body = bytes[pos..pos + body_len].to_vec();
        pos += body_len;

        // Timestamp
        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated timestamp"));
        }
        let timestamp = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        // Content type
        let content_type = read_optional_string(bytes, &mut pos)?;

        Ok(Self {
            connection_id,
            request_seq,
            status_code,
            status_text,
            http_version,
            headers,
            body,
            timestamp,
            content_type,
        })
    }
}

impl ProxyWebSocketRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Connection ID + frame seq
        buf.extend_from_slice(&self.connection_id.to_le_bytes());
        buf.extend_from_slice(&self.frame_seq.to_le_bytes());

        // Direction + opcode
        buf.push(self.direction);
        buf.push(self.opcode);

        // Payload
        write_varu32(&mut buf, self.payload.len() as u32);
        buf.extend_from_slice(&self.payload);

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < 18 {
            return Err(DecodeError("truncated websocket record"));
        }

        let mut pos = 0;

        // Connection ID
        let connection_id = u64::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
            bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7],
        ]);
        pos += 8;

        // Frame seq
        let frame_seq = u64::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
            bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7],
        ]);
        pos += 8;

        // Direction + opcode
        let direction = bytes[pos];
        pos += 1;
        let opcode = bytes[pos];
        pos += 1;

        // Payload
        let payload_len = read_varu32(bytes, &mut pos)? as usize;
        if bytes.len() < pos + payload_len {
            return Err(DecodeError("truncated payload"));
        }
        let payload = bytes[pos..pos + payload_len].to_vec();
        pos += payload_len;

        // Timestamp
        if bytes.len() < pos + 4 {
            return Err(DecodeError("truncated timestamp"));
        }
        let timestamp = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);

        Ok(Self {
            connection_id,
            frame_seq,
            direction,
            opcode,
            payload,
            timestamp,
        })
    }
}

fn write_optional_string(buf: &mut Vec<u8>, value: &Option<String>) {
    match value {
        Some(text) => {
            buf.push(1);
            write_string(buf, text);
        }
        None => buf.push(0),
    }
}

fn read_optional_string(bytes: &[u8], pos: &mut usize) -> Result<Option<String>, DecodeError> {
    if *pos >= bytes.len() {
        return Err(DecodeError("unexpected eof (optional string flag)"));
    }
    let flag = bytes[*pos];
    *pos += 1;
    if flag == 0 {
        return Ok(None);
    }
    read_string(bytes, pos).map(Some)
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    let data = value.as_bytes();
    write_varu32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

fn read_string(bytes: &[u8], pos: &mut usize) -> Result<String, DecodeError> {
    let len = read_varu32(bytes, pos)? as usize;
    if bytes.len() < *pos + len {
        return Err(DecodeError("truncated string"));
    }
    let slice = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(String::from_utf8_lossy(slice).to_string())
}

/// Helper to write length-prefixed strings
pub fn write_string_u16(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(65535) as u16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

/// Helper to read length-prefixed strings
pub fn read_string_u16(buf: &[u8], offset: &mut usize) -> Option<String> {
    if buf.len() < *offset + 2 {
        return None;
    }

    let len = u16::from_le_bytes([buf[*offset], buf[*offset + 1]]) as usize;
    *offset += 2;

    if buf.len() < *offset + len {
        return None;
    }

    let s = String::from_utf8(buf[*offset..*offset + len].to_vec()).ok()?;
    *offset += len;

    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    // ==================== PortScanRecord Tests ====================

    #[test]
    fn test_port_scan_serialization() {
        let record = PortScanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            port: 80,
            status: PortStatus::Open,
            service_id: 1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
        };

        let bytes = record.to_bytes();
        println!("PortScan size: {} bytes", bytes.len());

        let decoded = PortScanRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.port, 80);
    }

    #[test]
    fn test_port_scan_new() {
        let record = PortScanRecord::new(0xC0A80101, 443, 0, 2); // 192.168.1.1
        assert_eq!(record.port, 443);
        assert!(matches!(record.status, PortStatus::Open));
        assert_eq!(record.service_id, 2);
    }

    #[test]
    fn test_port_scan_all_statuses() {
        for (status_byte, expected) in [(0, PortStatus::Open), (1, PortStatus::Closed),
                                        (2, PortStatus::Filtered), (3, PortStatus::OpenFiltered)] {
            let record = PortScanRecord::new(0x7F000001, 22, status_byte, 0);
            assert!(matches!(record.status, _ if std::mem::discriminant(&record.status) == std::mem::discriminant(&expected)));
        }
    }

    #[test]
    fn test_port_scan_ipv4_roundtrip() {
        let record = PortScanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 22,
            status: PortStatus::Open,
            service_id: 5,
            timestamp: 1700000000,
        };

        let bytes = record.to_bytes();
        let decoded = PortScanRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(decoded.port, 22);
        assert!(matches!(decoded.status, PortStatus::Open));
        assert_eq!(decoded.service_id, 5);
        assert_eq!(decoded.timestamp, 1700000000);
    }

    #[test]
    fn test_port_scan_ipv6_roundtrip() {
        let record = PortScanRecord {
            ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port: 8080,
            status: PortStatus::Filtered,
            service_id: 10,
            timestamp: 1600000000,
        };

        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), 25); // 1 + 16 + 2 + 1 + 1 + 4

        let decoded = PortScanRecord::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded.ip, IpAddr::V6(_)));
        assert_eq!(decoded.port, 8080);
    }

    #[test]
    fn test_port_scan_from_bytes_empty() {
        assert!(PortScanRecord::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_port_scan_from_bytes_invalid_ip_version() {
        let buf = vec![99, 0, 0, 0, 0]; // Invalid IP version
        assert!(PortScanRecord::from_bytes(&buf).is_none());
    }

    #[test]
    fn test_port_scan_from_bytes_truncated() {
        let buf = vec![4, 192, 168]; // Incomplete IPv4
        assert!(PortScanRecord::from_bytes(&buf).is_none());
    }

    // ==================== SubdomainRecord Tests ====================

    #[test]
    fn test_subdomain_serialization() {
        let record = SubdomainRecord {
            subdomain: "api.example.com".to_string(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            source: SubdomainSource::DnsBruteforce,
            timestamp: 1234567890,
        };

        let bytes = record.to_bytes();
        println!("Subdomain size: {} bytes", bytes.len());

        let decoded = SubdomainRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.subdomain, "api.example.com");
    }

    #[test]
    fn test_subdomain_all_sources() {
        for source in [SubdomainSource::DnsBruteforce, SubdomainSource::CertTransparency,
                       SubdomainSource::SearchEngine, SubdomainSource::WebCrawl] {
            let record = SubdomainRecord {
                subdomain: "test.example.com".to_string(),
                ips: vec![],
                source,
                timestamp: 1000,
            };

            let bytes = record.to_bytes();
            let decoded = SubdomainRecord::from_bytes(&bytes).unwrap();
            assert!(std::mem::discriminant(&decoded.source) == std::mem::discriminant(&source));
        }
    }

    #[test]
    fn test_subdomain_multiple_ips() {
        let record = SubdomainRecord {
            subdomain: "multi.example.com".to_string(),
            ips: vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ],
            source: SubdomainSource::CertTransparency,
            timestamp: 1700000000,
        };

        let bytes = record.to_bytes();
        let decoded = SubdomainRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.ips.len(), 3);
        assert_eq!(decoded.ips[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(matches!(decoded.ips[2], IpAddr::V6(_)));
    }

    #[test]
    fn test_subdomain_empty_ips() {
        let record = SubdomainRecord {
            subdomain: "noip.example.com".to_string(),
            ips: vec![],
            source: SubdomainSource::WebCrawl,
            timestamp: 1500000000,
        };

        let bytes = record.to_bytes();
        let decoded = SubdomainRecord::from_bytes(&bytes).unwrap();

        assert!(decoded.ips.is_empty());
        assert_eq!(decoded.subdomain, "noip.example.com");
    }

    #[test]
    fn test_subdomain_from_bytes_empty() {
        assert!(SubdomainRecord::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_subdomain_from_bytes_truncated() {
        let buf = vec![5, b'h', b'e', b'l']; // Incomplete subdomain
        assert!(SubdomainRecord::from_bytes(&buf).is_none());
    }

    // ==================== HostIntelRecord Tests ====================

    #[test]
    fn test_host_intel_roundtrip() {
        let record = HostIntelRecord {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            os_family: Some("Linux".to_string()),
            confidence: 0.85,
            last_seen: 1700000000,
            services: vec![
                ServiceIntelRecord {
                    port: 22,
                    service_name: Some("SSH".to_string()),
                    banner: Some("OpenSSH 8.2".to_string()),
                    os_hints: vec!["Ubuntu".to_string()],
                },
                ServiceIntelRecord {
                    port: 80,
                    service_name: Some("HTTP".to_string()),
                    banner: None,
                    os_hints: vec![],
                },
            ],
        };

        let bytes = record.to_bytes();
        let decoded = HostIntelRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(decoded.os_family, Some("Linux".to_string()));
        assert!((decoded.confidence - 0.85).abs() < 0.001);
        assert_eq!(decoded.services.len(), 2);
        assert_eq!(decoded.services[0].port, 22);
        assert_eq!(decoded.services[0].banner, Some("OpenSSH 8.2".to_string()));
    }

    #[test]
    fn test_host_intel_ipv6() {
        let record = HostIntelRecord {
            ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            os_family: None,
            confidence: 0.0,
            last_seen: 1600000000,
            services: vec![],
        };

        let bytes = record.to_bytes();
        let decoded = HostIntelRecord::from_bytes(&bytes).unwrap();

        assert!(matches!(decoded.ip, IpAddr::V6(_)));
        assert!(decoded.os_family.is_none());
        assert!(decoded.services.is_empty());
    }

    #[test]
    fn test_host_intel_empty() {
        assert!(HostIntelRecord::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_host_intel_invalid_ip_version() {
        let buf = vec![99]; // Invalid IP version
        assert!(HostIntelRecord::from_bytes(&buf).is_err());
    }

    // ==================== ServiceIntelRecord Tests ====================

    #[test]
    fn test_service_intel_roundtrip() {
        let record = ServiceIntelRecord {
            port: 443,
            service_name: Some("HTTPS".to_string()),
            banner: Some("nginx/1.18.0".to_string()),
            os_hints: vec!["Debian".to_string(), "Ubuntu".to_string()],
        };

        let bytes = record.to_bytes();
        let decoded = ServiceIntelRecord::from_slice(&bytes).unwrap();

        assert_eq!(decoded.port, 443);
        assert_eq!(decoded.service_name, Some("HTTPS".to_string()));
        assert_eq!(decoded.banner, Some("nginx/1.18.0".to_string()));
        assert_eq!(decoded.os_hints.len(), 2);
    }

    #[test]
    fn test_service_intel_minimal() {
        let record = ServiceIntelRecord {
            port: 8080,
            service_name: None,
            banner: None,
            os_hints: vec![],
        };

        let bytes = record.to_bytes();
        let decoded = ServiceIntelRecord::from_slice(&bytes).unwrap();

        assert_eq!(decoded.port, 8080);
        assert!(decoded.service_name.is_none());
        assert!(decoded.banner.is_none());
        assert!(decoded.os_hints.is_empty());
    }

    // ==================== String Helper Tests ====================

    #[test]
    fn test_write_read_string_u16() {
        let mut buf = Vec::new();
        write_string_u16(&mut buf, "Hello, World!");

        let mut offset = 0;
        let result = read_string_u16(&buf, &mut offset).unwrap();
        assert_eq!(result, "Hello, World!");
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_write_read_string_u16_empty() {
        let mut buf = Vec::new();
        write_string_u16(&mut buf, "");

        let mut offset = 0;
        let result = read_string_u16(&buf, &mut offset).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_write_read_string_u16_unicode() {
        let mut buf = Vec::new();
        write_string_u16(&mut buf, "日本語テスト 🚀");

        let mut offset = 0;
        let result = read_string_u16(&buf, &mut offset).unwrap();
        assert_eq!(result, "日本語テスト 🚀");
    }

    #[test]
    fn test_read_string_u16_truncated() {
        let buf = vec![0x05, 0x00, b'h', b'e']; // Says 5 bytes but only 2
        let mut offset = 0;
        assert!(read_string_u16(&buf, &mut offset).is_none());
    }

    // ==================== DnsRecordType Tests ====================

    #[test]
    fn test_dns_record_type_values() {
        assert_eq!(DnsRecordType::A as u8, 1);
        assert_eq!(DnsRecordType::AAAA as u8, 2);
        assert_eq!(DnsRecordType::MX as u8, 3);
        assert_eq!(DnsRecordType::NS as u8, 4);
        assert_eq!(DnsRecordType::TXT as u8, 5);
        assert_eq!(DnsRecordType::CNAME as u8, 6);
    }

    // ==================== TLS Types Tests ====================

    #[test]
    fn test_tls_cipher_strength_values() {
        assert_eq!(TlsCipherStrength::Weak as u8, 0);
        assert_eq!(TlsCipherStrength::Medium as u8, 1);
        assert_eq!(TlsCipherStrength::Strong as u8, 2);
    }

    #[test]
    fn test_tls_severity_values() {
        assert_eq!(TlsSeverity::Low as u8, 0);
        assert_eq!(TlsSeverity::Medium as u8, 1);
        assert_eq!(TlsSeverity::High as u8, 2);
        assert_eq!(TlsSeverity::Critical as u8, 3);
    }

    #[test]
    fn test_http_tls_snapshot_default() {
        let snapshot = HttpTlsSnapshot::default();
        assert!(snapshot.authority.is_none());
        assert!(snapshot.tls_version.is_none());
        assert!(snapshot.peer_subjects.is_empty());
    }

    // ==================== RecordType Tests ====================

    #[test]
    fn test_record_type_port_scan() {
        let record = RecordType::PortScan(PortScanRecord::new(0x7F000001, 80, 0, 1));
        assert!(matches!(record, RecordType::PortScan(_)));
    }

    #[test]
    fn test_record_type_subdomain() {
        let record = RecordType::Subdomain(SubdomainRecord {
            subdomain: "test.com".to_string(),
            ips: vec![],
            source: SubdomainSource::DnsBruteforce,
            timestamp: 0,
        });
        assert!(matches!(record, RecordType::Subdomain(_)));
    }

    #[test]
    fn test_record_type_key_value() {
        let record = RecordType::KeyValue(b"key".to_vec(), b"value".to_vec());
        if let RecordType::KeyValue(k, v) = record {
            assert_eq!(k, b"key");
            assert_eq!(v, b"value");
        } else {
            panic!("Expected KeyValue");
        }
    }

    // ==================== Proxy Record Tests ====================

    #[test]
    fn test_proxy_connection_record_roundtrip_ipv4() {
        let record = ProxyConnectionRecord {
            connection_id: 12345,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            src_port: 54321,
            dst_host: "example.com".to_string(),
            dst_port: 443,
            protocol: 0, // TCP
            started_at: 1700000000,
            ended_at: 1700000060,
            bytes_sent: 1024,
            bytes_received: 4096,
            tls_intercepted: true,
        };

        let bytes = record.to_bytes();
        let decoded = ProxyConnectionRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.connection_id, 12345);
        assert_eq!(decoded.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(decoded.src_port, 54321);
        assert_eq!(decoded.dst_host, "example.com");
        assert_eq!(decoded.dst_port, 443);
        assert_eq!(decoded.protocol, 0);
        assert_eq!(decoded.started_at, 1700000000);
        assert_eq!(decoded.ended_at, 1700000060);
        assert_eq!(decoded.bytes_sent, 1024);
        assert_eq!(decoded.bytes_received, 4096);
        assert!(decoded.tls_intercepted);
    }

    #[test]
    fn test_proxy_connection_record_roundtrip_ipv6() {
        let record = ProxyConnectionRecord {
            connection_id: 99999,
            src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            src_port: 12345,
            dst_host: "ipv6.example.org".to_string(),
            dst_port: 80,
            protocol: 1, // UDP
            started_at: 1600000000,
            ended_at: 0,
            bytes_sent: 256,
            bytes_received: 512,
            tls_intercepted: false,
        };

        let bytes = record.to_bytes();
        let decoded = ProxyConnectionRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.connection_id, 99999);
        assert!(matches!(decoded.src_ip, IpAddr::V6(_)));
        assert_eq!(decoded.dst_host, "ipv6.example.org");
        assert!(!decoded.tls_intercepted);
    }

    #[test]
    fn test_proxy_connection_record_empty() {
        assert!(ProxyConnectionRecord::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_proxy_http_request_record_roundtrip() {
        let record = ProxyHttpRequestRecord {
            connection_id: 1000,
            request_seq: 1,
            method: "GET".to_string(),
            path: "/api/users?page=1".to_string(),
            http_version: "HTTP/1.1".to_string(),
            host: "api.example.com".to_string(),
            headers: vec![
                ("user-agent".to_string(), "Mozilla/5.0".to_string()),
                ("accept".to_string(), "application/json".to_string()),
            ],
            body: vec![],
            timestamp: 1700000000,
            client_addr: Some("192.168.1.100:54321".to_string()),
        };

        let bytes = record.to_bytes();
        let decoded = ProxyHttpRequestRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.connection_id, 1000);
        assert_eq!(decoded.request_seq, 1);
        assert_eq!(decoded.method, "GET");
        assert_eq!(decoded.path, "/api/users?page=1");
        assert_eq!(decoded.http_version, "HTTP/1.1");
        assert_eq!(decoded.host, "api.example.com");
        assert_eq!(decoded.headers.len(), 2);
        assert_eq!(decoded.headers[0].0, "user-agent");
        assert!(decoded.body.is_empty());
        assert_eq!(decoded.client_addr, Some("192.168.1.100:54321".to_string()));
    }

    #[test]
    fn test_proxy_http_request_record_with_body() {
        let record = ProxyHttpRequestRecord {
            connection_id: 2000,
            request_seq: 3,
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            http_version: "HTTP/1.1".to_string(),
            host: "auth.example.com".to_string(),
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
            ],
            body: b"{\"username\":\"test\"}".to_vec(),
            timestamp: 1700000100,
            client_addr: None,
        };

        let bytes = record.to_bytes();
        let decoded = ProxyHttpRequestRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.method, "POST");
        assert_eq!(decoded.body, b"{\"username\":\"test\"}");
        assert!(decoded.client_addr.is_none());
    }

    #[test]
    fn test_proxy_http_response_record_roundtrip() {
        let record = ProxyHttpResponseRecord {
            connection_id: 1000,
            request_seq: 1,
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("content-length".to_string(), "42".to_string()),
            ],
            body: b"{\"users\":[{\"id\":1,\"name\":\"Test\"}]}".to_vec(),
            timestamp: 1700000001,
            content_type: Some("application/json".to_string()),
        };

        let bytes = record.to_bytes();
        let decoded = ProxyHttpResponseRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.connection_id, 1000);
        assert_eq!(decoded.request_seq, 1);
        assert_eq!(decoded.status_code, 200);
        assert_eq!(decoded.status_text, "OK");
        assert_eq!(decoded.headers.len(), 2);
        assert!(!decoded.body.is_empty());
        assert_eq!(decoded.content_type, Some("application/json".to_string()));
    }

    #[test]
    fn test_proxy_http_response_record_error() {
        let record = ProxyHttpResponseRecord {
            connection_id: 3000,
            request_seq: 5,
            status_code: 404,
            status_text: "Not Found".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            body: b"Page not found".to_vec(),
            timestamp: 1700000200,
            content_type: Some("text/plain".to_string()),
        };

        let bytes = record.to_bytes();
        let decoded = ProxyHttpResponseRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.status_code, 404);
        assert_eq!(decoded.status_text, "Not Found");
    }

    #[test]
    fn test_proxy_websocket_record_roundtrip() {
        let record = ProxyWebSocketRecord {
            connection_id: 5000,
            frame_seq: 42,
            direction: 0, // client -> server
            opcode: 1, // text
            payload: b"Hello WebSocket!".to_vec(),
            timestamp: 1700000300,
        };

        let bytes = record.to_bytes();
        let decoded = ProxyWebSocketRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.connection_id, 5000);
        assert_eq!(decoded.frame_seq, 42);
        assert_eq!(decoded.direction, 0);
        assert_eq!(decoded.opcode, 1);
        assert_eq!(decoded.payload, b"Hello WebSocket!");
        assert_eq!(decoded.timestamp, 1700000300);
    }

    #[test]
    fn test_proxy_websocket_record_binary() {
        let record = ProxyWebSocketRecord {
            connection_id: 6000,
            frame_seq: 100,
            direction: 1, // server -> client
            opcode: 2, // binary
            payload: vec![0x00, 0x01, 0x02, 0x03, 0xFF],
            timestamp: 1700000400,
        };

        let bytes = record.to_bytes();
        let decoded = ProxyWebSocketRecord::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.opcode, 2);
        assert_eq!(decoded.payload, vec![0x00, 0x01, 0x02, 0x03, 0xFF]);
    }

    #[test]
    fn test_proxy_websocket_record_ping_pong() {
        for (opcode, name) in [(9, "ping"), (10, "pong")] {
            let record = ProxyWebSocketRecord {
                connection_id: 7000,
                frame_seq: 0,
                direction: 0,
                opcode,
                payload: vec![],
                timestamp: 1700000500,
            };

            let bytes = record.to_bytes();
            let decoded = ProxyWebSocketRecord::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.opcode, opcode, "Failed for {}", name);
        }
    }

    #[test]
    fn test_proxy_websocket_record_empty() {
        assert!(ProxyWebSocketRecord::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_proxy_websocket_record_truncated() {
        // Only 10 bytes, needs at least 18
        let buf = vec![0u8; 10];
        assert!(ProxyWebSocketRecord::from_bytes(&buf).is_err());
    }
}
