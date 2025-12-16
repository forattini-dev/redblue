/// Active OS Fingerprinting Probes
///
/// Implements nmap-style TCP/IP stack fingerprinting probes.
/// Sends specially-crafted packets and analyzes responses to identify OS.
///
/// Probe types:
/// - TCP SYN with options to open port (SEQ, OPS, WIN, T1)
/// - TCP NULL/FIN/XMAS to open port
/// - TCP SYN to closed port (T2)
/// - TCP ACK to open port (T3)
/// - TCP ACK to closed port (T4)
/// - TCP SYN with ECN to open port (ECN)
/// - UDP probe to closed port (U1)
/// - ICMP Echo probe (IE)
///
/// Reference: https://nmap.org/book/osdetect-methods.html
use crate::intelligence::os_signatures::{
    IpIdPattern, MssMatch, OsSignature, OsSignatureDb, TtlMatch, WindowMatch,
};
use crate::intelligence::tcp_fingerprint::{IpIdBehavior, TcpOption};
use crate::protocols::raw::{
    get_source_ip, internet_checksum, Ipv4Header, TcpHeader, IPPROTO_TCP, TCP_ACK, TCP_FIN,
    TCP_PSH, TCP_SYN, TCP_URG,
};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// TCP Options for fingerprinting probes
/// Reference: RFC 793, 1323, 2018, 3168
#[derive(Debug, Clone)]
pub struct TcpOptionsBuilder {
    options: Vec<u8>,
}

impl TcpOptionsBuilder {
    pub fn new() -> Self {
        Self {
            options: Vec::new(),
        }
    }

    /// Add MSS option (kind=2, len=4)
    pub fn mss(mut self, value: u16) -> Self {
        self.options.push(2); // MSS kind
        self.options.push(4); // Length
        self.options.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Add NOP option (kind=1)
    pub fn nop(mut self) -> Self {
        self.options.push(1);
        self
    }

    /// Add Window Scale option (kind=3, len=3)
    pub fn window_scale(mut self, scale: u8) -> Self {
        self.options.push(3); // WScale kind
        self.options.push(3); // Length
        self.options.push(scale);
        self
    }

    /// Add SACK Permitted option (kind=4, len=2)
    pub fn sack_permitted(mut self) -> Self {
        self.options.push(4); // SACK Permitted kind
        self.options.push(2); // Length
        self
    }

    /// Add Timestamp option (kind=8, len=10)
    pub fn timestamp(mut self, ts_val: u32, ts_echo: u32) -> Self {
        self.options.push(8); // Timestamp kind
        self.options.push(10); // Length
        self.options.extend_from_slice(&ts_val.to_be_bytes());
        self.options.extend_from_slice(&ts_echo.to_be_bytes());
        self
    }

    /// Add End-of-Options (kind=0)
    pub fn eol(mut self) -> Self {
        self.options.push(0);
        self
    }

    /// Pad to 4-byte boundary
    pub fn pad_to_boundary(mut self) -> Self {
        while !self.options.len().is_multiple_of(4) {
            self.options.push(0); // NOP or EOL padding
        }
        self
    }

    /// Build and return options bytes
    pub fn build(self) -> Vec<u8> {
        self.pad_to_boundary().options
    }

    /// Create standard Linux-style options
    pub fn linux_style() -> Vec<u8> {
        Self::new()
            .mss(1460)
            .sack_permitted()
            .timestamp(0, 0)
            .nop()
            .window_scale(7)
            .build()
    }

    /// Create Windows-style options
    pub fn windows_style() -> Vec<u8> {
        Self::new()
            .mss(1460)
            .nop()
            .window_scale(8)
            .nop()
            .nop()
            .sack_permitted()
            .build()
    }

    /// Create BSD-style options
    pub fn bsd_style() -> Vec<u8> {
        Self::new()
            .mss(1460)
            .nop()
            .window_scale(6)
            .sack_permitted()
            .timestamp(0, 0)
            .build()
    }

    /// Create minimal options (MSS only)
    pub fn minimal() -> Vec<u8> {
        Self::new().mss(265).build()
    }
}

impl Default for TcpOptionsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// OS fingerprinting probe result
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    /// Probe identifier
    pub probe_id: String,
    /// Response received
    pub received: bool,
    /// Response time
    pub rtt: Option<Duration>,
    /// IP header from response
    pub ip_ttl: Option<u8>,
    pub ip_id: Option<u16>,
    pub ip_df: Option<bool>,
    /// TCP header from response
    pub tcp_flags: Option<u8>,
    pub tcp_window: Option<u16>,
    pub tcp_options: Vec<TcpOption>,
    /// Derived values
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub has_timestamp: bool,
    pub has_sack: bool,
    pub timestamp_value: Option<u32>,
}

impl ProbeResponse {
    pub fn empty(probe_id: &str) -> Self {
        Self {
            probe_id: probe_id.to_string(),
            received: false,
            rtt: None,
            ip_ttl: None,
            ip_id: None,
            ip_df: None,
            tcp_flags: None,
            tcp_window: None,
            tcp_options: Vec::new(),
            mss: None,
            window_scale: None,
            has_timestamp: false,
            has_sack: false,
            timestamp_value: None,
        }
    }

    pub fn timeout(probe_id: &str) -> Self {
        Self::empty(probe_id)
    }
}

/// OS fingerprint result from probing
#[derive(Debug, Clone)]
pub struct OsProbeResult {
    /// Target IP address
    pub target: Ipv4Addr,
    /// Open port used for probing
    pub open_port: Option<u16>,
    /// Closed port used for probing
    pub closed_port: Option<u16>,
    /// Individual probe responses
    pub probes: Vec<ProbeResponse>,
    /// Matched OS signatures with confidence
    pub matches: Vec<OsMatch>,
    /// IP ID sequence behavior
    pub ip_id_behavior: IpIdBehavior,
    /// Estimated initial TTL
    pub initial_ttl: Option<u8>,
    /// TCP/IP stack fingerprint string
    pub fingerprint_string: String,
}

/// OS match with confidence score
#[derive(Debug, Clone)]
pub struct OsMatch {
    pub signature: OsSignature,
    pub confidence: f32,
    pub matching_points: Vec<String>,
}

impl OsMatch {
    pub fn new(signature: OsSignature, confidence: f32, points: Vec<String>) -> Self {
        Self {
            signature,
            confidence,
            matching_points: points,
        }
    }
}

/// Active OS fingerprinting prober
pub struct OsProber {
    target: Ipv4Addr,
    src_ip: Ipv4Addr,
    timeout: Duration,
    retries: u8,
}

impl OsProber {
    /// Create new OS prober for target
    pub fn new(target: Ipv4Addr) -> Result<Self, String> {
        let src_ip =
            get_source_ip(target).map_err(|e| format!("Failed to get source IP: {}", e))?;

        Ok(Self {
            target,
            src_ip,
            timeout: Duration::from_secs(2),
            retries: 2,
        })
    }

    /// Set probe timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set number of retries
    pub fn with_retries(mut self, retries: u8) -> Self {
        self.retries = retries;
        self
    }

    /// Run full OS fingerprinting probe sequence
    pub fn probe(&self, open_port: Option<u16>, closed_port: Option<u16>) -> OsProbeResult {
        let mut probes = Vec::new();
        let mut ip_ids = Vec::new();

        // Probe 1: SEQ - TCP SYN to open port with options (6 packets for IP ID analysis)
        if let Some(port) = open_port {
            for i in 0..6 {
                let response = self.send_syn_probe(port, &format!("SEQ{}", i + 1));
                if let Some(id) = response.ip_id {
                    ip_ids.push(id);
                }
                probes.push(response);
            }
        }

        // Probe 2: ECN - TCP SYN with ECN flags to open port
        if let Some(port) = open_port {
            probes.push(self.send_ecn_probe(port));
        }

        // Probe 3: T1 - TCP SYN with specific options to open port
        if let Some(port) = open_port {
            probes.push(self.send_t1_probe(port));
        }

        // Probe 4: T2 - TCP NULL to open port
        if let Some(port) = open_port {
            probes.push(self.send_t2_probe(port));
        }

        // Probe 5: T3 - TCP SYN|FIN|URG|PSH to open port
        if let Some(port) = open_port {
            probes.push(self.send_t3_probe(port));
        }

        // Probe 6: T4 - TCP ACK to open port
        if let Some(port) = open_port {
            probes.push(self.send_t4_probe(port));
        }

        // Probe 7: T5 - TCP SYN to closed port
        if let Some(port) = closed_port {
            probes.push(self.send_t5_probe(port));
        }

        // Probe 8: T6 - TCP ACK to closed port
        if let Some(port) = closed_port {
            probes.push(self.send_t6_probe(port));
        }

        // Probe 9: T7 - TCP FIN|PSH|URG to closed port
        if let Some(port) = closed_port {
            probes.push(self.send_t7_probe(port));
        }

        // Probe 10: U1 - UDP to closed port
        if let Some(port) = closed_port {
            probes.push(self.send_u1_probe(port));
        }

        // Analyze IP ID behavior
        let ip_id_behavior = self.analyze_ip_id_sequence(&ip_ids);

        // Generate fingerprint string
        let fingerprint_string = self.generate_fingerprint_string(&probes);

        // Match against signature database
        let matches = self.match_signatures(&probes, &ip_id_behavior);

        // Estimate initial TTL
        let initial_ttl = self.estimate_initial_ttl(&probes);

        OsProbeResult {
            target: self.target,
            open_port,
            closed_port,
            probes,
            matches,
            ip_id_behavior,
            initial_ttl,
            fingerprint_string,
        }
    }

    /// Quick probe using just SEQ probes (faster, less accurate)
    pub fn quick_probe(&self, open_port: u16) -> OsProbeResult {
        let mut probes = Vec::new();
        let mut ip_ids = Vec::new();

        // Send 3 SYN probes for basic fingerprinting
        for i in 0..3 {
            let response = self.send_syn_probe(open_port, &format!("QUICK{}", i + 1));
            if let Some(id) = response.ip_id {
                ip_ids.push(id);
            }
            probes.push(response);
        }

        let ip_id_behavior = self.analyze_ip_id_sequence(&ip_ids);
        let fingerprint_string = self.generate_fingerprint_string(&probes);
        let matches = self.match_signatures(&probes, &ip_id_behavior);
        let initial_ttl = self.estimate_initial_ttl(&probes);

        OsProbeResult {
            target: self.target,
            open_port: Some(open_port),
            closed_port: None,
            probes,
            matches,
            ip_id_behavior,
            initial_ttl,
            fingerprint_string,
        }
    }

    /// Send TCP SYN probe with standard options
    fn send_syn_probe(&self, port: u16, probe_id: &str) -> ProbeResponse {
        self.send_tcp_probe(
            port,
            TCP_SYN,
            &TcpOptionsBuilder::linux_style(),
            65535,
            probe_id,
        )
    }

    /// Send ECN probe (SYN with ECE and CWR flags)
    fn send_ecn_probe(&self, port: u16) -> ProbeResponse {
        // ECN flags: ECE (0x40) and CWR (0x80)
        let flags = TCP_SYN | 0x40 | 0x80;
        self.send_tcp_probe(port, flags, &TcpOptionsBuilder::linux_style(), 3, "ECN")
    }

    /// T1: SYN with specific options
    fn send_t1_probe(&self, port: u16) -> ProbeResponse {
        let options = TcpOptionsBuilder::new()
            .mss(1460)
            .nop()
            .window_scale(10)
            .nop()
            .nop()
            .timestamp(0xFFFFFFFF, 0)
            .sack_permitted()
            .eol()
            .build();
        self.send_tcp_probe(port, TCP_SYN, &options, 1, "T1")
    }

    /// T2: NULL packet to open port
    fn send_t2_probe(&self, port: u16) -> ProbeResponse {
        let options = TcpOptionsBuilder::new()
            .mss(265)
            .sack_permitted()
            .timestamp(0xFFFFFFFF, 0)
            .nop()
            .window_scale(10)
            .build();
        self.send_tcp_probe(port, 0, &options, 128, "T2")
    }

    /// T3: SYN|FIN|URG|PSH to open port
    fn send_t3_probe(&self, port: u16) -> ProbeResponse {
        let flags = TCP_SYN | TCP_FIN | TCP_URG | TCP_PSH;
        let options = TcpOptionsBuilder::new()
            .mss(265)
            .sack_permitted()
            .timestamp(0xFFFFFFFF, 0)
            .nop()
            .window_scale(10)
            .build();
        self.send_tcp_probe(port, flags, &options, 256, "T3")
    }

    /// T4: ACK to open port
    fn send_t4_probe(&self, port: u16) -> ProbeResponse {
        let options = TcpOptionsBuilder::new()
            .mss(265)
            .sack_permitted()
            .timestamp(0xFFFFFFFF, 0)
            .nop()
            .window_scale(10)
            .build();
        self.send_tcp_probe(port, TCP_ACK, &options, 1024, "T4")
    }

    /// T5: SYN to closed port
    fn send_t5_probe(&self, port: u16) -> ProbeResponse {
        let options = TcpOptionsBuilder::new()
            .mss(265)
            .sack_permitted()
            .timestamp(0xFFFFFFFF, 0)
            .nop()
            .window_scale(10)
            .build();
        self.send_tcp_probe(port, TCP_SYN, &options, 31337, "T5")
    }

    /// T6: ACK to closed port
    fn send_t6_probe(&self, port: u16) -> ProbeResponse {
        let options = TcpOptionsBuilder::new()
            .mss(265)
            .sack_permitted()
            .timestamp(0xFFFFFFFF, 0)
            .nop()
            .window_scale(10)
            .build();
        self.send_tcp_probe(port, TCP_ACK, &options, 32768, "T6")
    }

    /// T7: FIN|PSH|URG to closed port
    fn send_t7_probe(&self, port: u16) -> ProbeResponse {
        let flags = TCP_FIN | TCP_PSH | TCP_URG;
        let options = TcpOptionsBuilder::new()
            .mss(265)
            .sack_permitted()
            .timestamp(0xFFFFFFFF, 0)
            .nop()
            .window_scale(15)
            .build();
        self.send_tcp_probe(port, flags, &options, 65535, "T7")
    }

    /// U1: UDP probe to closed port
    fn send_u1_probe(&self, port: u16) -> ProbeResponse {
        // Send UDP packet with 'C' repeated 300 times
        let payload = vec![0x43u8; 300]; // 'C' = 0x43
        self.send_udp_probe(port, &payload, "U1")
    }

    /// Send a TCP probe with specified options and flags
    #[cfg(target_family = "unix")]
    fn send_tcp_probe(
        &self,
        port: u16,
        flags: u8,
        tcp_options: &[u8],
        window: u16,
        probe_id: &str,
    ) -> ProbeResponse {
        use crate::protocols::raw::raw_socket::RawSocket;

        let socket = match RawSocket::new_raw() {
            Ok(s) => s,
            Err(_) => return ProbeResponse::empty(probe_id),
        };

        if socket.set_timeout(self.timeout).is_err() {
            return ProbeResponse::empty(probe_id);
        }

        let src_port = 40000 + (rand_u16() % 10000);

        // Build TCP header with options
        let tcp_header_len = 20 + tcp_options.len();
        let data_offset = (tcp_header_len / 4) as u8;

        let mut tcp = TcpHeader::new(src_port, port, flags);
        tcp.window = window;
        tcp.data_offset = data_offset;

        // Build complete TCP segment with options
        let mut tcp_bytes = tcp.to_bytes().to_vec();
        tcp_bytes.extend_from_slice(tcp_options);

        // Calculate checksum with options
        let checksum = self.calculate_tcp_checksum(&tcp_bytes);
        tcp_bytes[16] = (checksum >> 8) as u8;
        tcp_bytes[17] = (checksum & 0xFF) as u8;

        // Build IP header
        let ip = Ipv4Header::new(
            self.src_ip,
            self.target,
            IPPROTO_TCP,
            tcp_bytes.len() as u16,
        );

        // Combine headers
        let mut packet = Vec::with_capacity(20 + tcp_bytes.len());
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&tcp_bytes);

        let start = Instant::now();

        // Send probe
        if socket.send_to(&packet, self.target).is_err() {
            return ProbeResponse::empty(probe_id);
        }

        // Wait for response
        let mut buf = [0u8; 1500];
        let deadline = Instant::now() + self.timeout;

        while Instant::now() < deadline {
            match socket.recv(&mut buf) {
                Ok(len) if len >= 40 => {
                    if let Ok(resp_ip) = Ipv4Header::from_bytes(&buf[..20]) {
                        if resp_ip.src_addr != self.target {
                            continue;
                        }

                        let ip_hdr_len = (resp_ip.ihl as usize) * 4;
                        if len >= ip_hdr_len + 20 {
                            if let Ok(resp_tcp) = TcpHeader::from_bytes(&buf[ip_hdr_len..]) {
                                if resp_tcp.src_port == port && resp_tcp.dst_port == src_port {
                                    let rtt = start.elapsed();

                                    // Parse TCP options from response
                                    let tcp_options = self.parse_tcp_options(
                                        &buf[ip_hdr_len + 20
                                            ..ip_hdr_len + (resp_tcp.data_offset as usize * 4)],
                                    );

                                    let mut response = ProbeResponse {
                                        probe_id: probe_id.to_string(),
                                        received: true,
                                        rtt: Some(rtt),
                                        ip_ttl: Some(resp_ip.ttl),
                                        ip_id: Some(resp_ip.identification),
                                        ip_df: Some((resp_ip.flags & 0x02) != 0),
                                        tcp_flags: Some(resp_tcp.flags),
                                        tcp_window: Some(resp_tcp.window),
                                        tcp_options: tcp_options.clone(),
                                        mss: None,
                                        window_scale: None,
                                        has_timestamp: false,
                                        has_sack: false,
                                        timestamp_value: None,
                                    };

                                    // Extract derived values from options
                                    for opt in &tcp_options {
                                        match opt {
                                            TcpOption::MaxSegmentSize(mss) => {
                                                response.mss = Some(*mss)
                                            }
                                            TcpOption::WindowScale(ws) => {
                                                response.window_scale = Some(*ws)
                                            }
                                            TcpOption::Timestamp { value, .. } => {
                                                response.has_timestamp = true;
                                                response.timestamp_value = Some(*value);
                                            }
                                            TcpOption::SackPermitted | TcpOption::Sack(_) => {
                                                response.has_sack = true;
                                            }
                                            _ => {}
                                        }
                                    }

                                    return response;
                                }
                            }
                        }
                    }
                }
                Ok(_) => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(_) => break,
            }
        }

        ProbeResponse::timeout(probe_id)
    }

    #[cfg(not(target_family = "unix"))]
    fn send_tcp_probe(
        &self,
        _port: u16,
        _flags: u8,
        _tcp_options: &[u8],
        _window: u16,
        probe_id: &str,
    ) -> ProbeResponse {
        ProbeResponse::empty(probe_id)
    }

    /// Send UDP probe
    #[cfg(target_family = "unix")]
    fn send_udp_probe(&self, port: u16, payload: &[u8], probe_id: &str) -> ProbeResponse {
        use std::net::{IpAddr, SocketAddr, UdpSocket};

        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return ProbeResponse::empty(probe_id),
        };

        if socket.set_read_timeout(Some(self.timeout)).is_err() {
            return ProbeResponse::empty(probe_id);
        }

        let dest = SocketAddr::new(IpAddr::V4(self.target), port);
        let start = Instant::now();

        if socket.send_to(payload, dest).is_err() {
            return ProbeResponse::empty(probe_id);
        }

        // Wait for ICMP response (will show as connection refused error)
        let mut buf = [0u8; 1500];
        match socket.recv_from(&mut buf) {
            Ok((_len, _)) => {
                // Got UDP response (rare, but possible for some services)
                ProbeResponse {
                    probe_id: probe_id.to_string(),
                    received: true,
                    rtt: Some(start.elapsed()),
                    ip_ttl: None, // Can't get TTL from UDP response easily
                    ip_id: None,
                    ip_df: None,
                    tcp_flags: None,
                    tcp_window: None,
                    tcp_options: Vec::new(),
                    mss: None,
                    window_scale: None,
                    has_timestamp: false,
                    has_sack: false,
                    timestamp_value: None,
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                // ICMP port unreachable - this is what we expect
                ProbeResponse {
                    probe_id: probe_id.to_string(),
                    received: true,
                    rtt: Some(start.elapsed()),
                    ip_ttl: None,
                    ip_id: None,
                    ip_df: None,
                    tcp_flags: None,
                    tcp_window: None,
                    tcp_options: Vec::new(),
                    mss: None,
                    window_scale: None,
                    has_timestamp: false,
                    has_sack: false,
                    timestamp_value: None,
                }
            }
            Err(_) => ProbeResponse::timeout(probe_id),
        }
    }

    #[cfg(not(target_family = "unix"))]
    fn send_udp_probe(&self, _port: u16, _payload: &[u8], probe_id: &str) -> ProbeResponse {
        ProbeResponse::empty(probe_id)
    }

    /// Calculate TCP checksum with pseudo-header
    fn calculate_tcp_checksum(&self, tcp_bytes: &[u8]) -> u16 {
        let tcp_len = tcp_bytes.len();

        // Build pseudo-header + TCP segment
        let mut data = Vec::with_capacity(12 + tcp_len);

        // Pseudo-header (12 bytes)
        data.extend_from_slice(&self.src_ip.octets());
        data.extend_from_slice(&self.target.octets());
        data.push(0); // Reserved
        data.push(IPPROTO_TCP);
        data.extend_from_slice(&(tcp_len as u16).to_be_bytes());

        // TCP segment with checksum = 0
        let mut tcp_copy = tcp_bytes.to_vec();
        if tcp_copy.len() >= 18 {
            tcp_copy[16] = 0;
            tcp_copy[17] = 0;
        }
        data.extend_from_slice(&tcp_copy);

        internet_checksum(&data)
    }

    /// Parse TCP options from raw bytes
    fn parse_tcp_options(&self, bytes: &[u8]) -> Vec<TcpOption> {
        let mut options = Vec::new();
        let mut i = 0;

        while i < bytes.len() {
            match bytes[i] {
                0 => {
                    // End of Option List
                    options.push(TcpOption::EndOfOptions);
                    break;
                }
                1 => {
                    // No-Operation
                    options.push(TcpOption::NoOp);
                    i += 1;
                }
                2 => {
                    // Maximum Segment Size
                    if i + 3 < bytes.len() && bytes[i + 1] == 4 {
                        let mss = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]);
                        options.push(TcpOption::MaxSegmentSize(mss));
                    }
                    i += 4;
                }
                3 => {
                    // Window Scale
                    if i + 2 < bytes.len() && bytes[i + 1] == 3 {
                        options.push(TcpOption::WindowScale(bytes[i + 2]));
                    }
                    i += 3;
                }
                4 => {
                    // SACK Permitted
                    options.push(TcpOption::SackPermitted);
                    i += 2;
                }
                5 => {
                    // SACK
                    if i + 1 < bytes.len() {
                        let len = bytes[i + 1] as usize;
                        if i + len <= bytes.len() {
                            // Parse SACK blocks
                            let mut blocks = Vec::new();
                            let mut j = i + 2;
                            while j + 8 <= i + len {
                                let left = u32::from_be_bytes([
                                    bytes[j],
                                    bytes[j + 1],
                                    bytes[j + 2],
                                    bytes[j + 3],
                                ]);
                                let right = u32::from_be_bytes([
                                    bytes[j + 4],
                                    bytes[j + 5],
                                    bytes[j + 6],
                                    bytes[j + 7],
                                ]);
                                blocks.push((left, right));
                                j += 8;
                            }
                            options.push(TcpOption::Sack(blocks));
                        }
                        i += len;
                    } else {
                        i += 1;
                    }
                }
                8 => {
                    // Timestamp
                    if i + 9 < bytes.len() && bytes[i + 1] == 10 {
                        let ts_val = u32::from_be_bytes([
                            bytes[i + 2],
                            bytes[i + 3],
                            bytes[i + 4],
                            bytes[i + 5],
                        ]);
                        let ts_echo = u32::from_be_bytes([
                            bytes[i + 6],
                            bytes[i + 7],
                            bytes[i + 8],
                            bytes[i + 9],
                        ]);
                        options.push(TcpOption::Timestamp {
                            value: ts_val,
                            echo: ts_echo,
                        });
                    }
                    i += 10;
                }
                kind => {
                    // Unknown option
                    if i + 1 < bytes.len() {
                        let len = bytes[i + 1] as usize;
                        if len > 2 && i + len <= bytes.len() {
                            options.push(TcpOption::Unknown(kind, bytes[i + 2..i + len].to_vec()));
                            i += len;
                        } else {
                            i += 1;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
        }

        options
    }

    /// Analyze IP ID sequence behavior
    fn analyze_ip_id_sequence(&self, ip_ids: &[u16]) -> IpIdBehavior {
        if ip_ids.len() < 3 {
            return IpIdBehavior::Unknown;
        }

        // Check if all zeros
        if ip_ids.iter().all(|&id| id == 0) {
            return IpIdBehavior::Zero;
        }

        // Calculate differences
        let diffs: Vec<i32> = ip_ids
            .windows(2)
            .map(|w| (w[1] as i32).wrapping_sub(w[0] as i32))
            .collect();

        let avg_diff: i32 = diffs.iter().sum::<i32>() / diffs.len() as i32;

        // Calculate variance
        let mean = diffs.iter().sum::<i32>() as f64 / diffs.len() as f64;
        let variance: f64 = diffs
            .iter()
            .map(|&d| {
                let diff = d as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / diffs.len() as f64;

        // Random: high variance
        if variance > 10000.0 {
            return IpIdBehavior::Random;
        }

        // Sequential: low variance, small positive increments
        if avg_diff > 0 && avg_diff < 100 && variance < 100.0 {
            return IpIdBehavior::Sequential;
        }

        // Global counter: larger jumps
        if avg_diff > 100 {
            return IpIdBehavior::GlobalCounter;
        }

        IpIdBehavior::Unknown
    }

    /// Estimate initial TTL from observed TTL
    fn estimate_initial_ttl(&self, probes: &[ProbeResponse]) -> Option<u8> {
        let ttls: Vec<u8> = probes.iter().filter_map(|p| p.ip_ttl).collect();

        if ttls.is_empty() {
            return None;
        }

        let observed_ttl = ttls[0];

        // Common initial TTLs: 32, 64, 128, 255
        let initial_ttls = [32, 64, 128, 255];

        for &initial in &initial_ttls {
            if observed_ttl <= initial {
                return Some(initial);
            }
        }

        Some(255)
    }

    /// Generate fingerprint string from probes
    fn generate_fingerprint_string(&self, probes: &[ProbeResponse]) -> String {
        let mut parts = Vec::new();

        for probe in probes {
            if probe.received {
                let mut probe_str = format!("{}(", probe.probe_id);

                if let Some(ttl) = probe.ip_ttl {
                    probe_str.push_str(&format!("TTL={}", ttl));
                }
                if let Some(win) = probe.tcp_window {
                    probe_str.push_str(&format!("%W={:X}", win));
                }
                if let Some(mss) = probe.mss {
                    probe_str.push_str(&format!("%MSS={}", mss));
                }
                if let Some(ws) = probe.window_scale {
                    probe_str.push_str(&format!("%WS={}", ws));
                }
                if let Some(flags) = probe.tcp_flags {
                    probe_str.push_str(&format!("%F={:02X}", flags));
                }

                probe_str.push(')');
                parts.push(probe_str);
            } else {
                parts.push(format!("{}()", probe.probe_id));
            }
        }

        parts.join("\n")
    }

    /// Match probes against OS signature database
    fn match_signatures(
        &self,
        probes: &[ProbeResponse],
        ip_id_behavior: &IpIdBehavior,
    ) -> Vec<OsMatch> {
        let db = OsSignatureDb::new();
        let mut matches = Vec::new();

        // Get representative values from first successful SYN probe
        let syn_probe = probes
            .iter()
            .find(|p| p.received && p.probe_id.starts_with("SEQ"));

        if syn_probe.is_none() {
            return matches;
        }

        let probe = syn_probe.unwrap();

        for sig in db.signatures() {
            let mut confidence = 0.0f32;
            let mut points = Vec::new();

            // Match TTL
            if let Some(ttl) = probe.ip_ttl {
                match &sig.ttl {
                    TtlMatch::Exact(expected) => {
                        if ttl == *expected {
                            confidence += 0.2;
                            points.push(format!("TTL exact match: {}", ttl));
                        }
                    }
                    TtlMatch::Initial(initial) => {
                        // Check if TTL is close to expected initial value
                        if ttl <= *initial && ttl > initial.saturating_sub(30) {
                            confidence += 0.15;
                            points.push(format!("TTL matches initial {}", initial));
                        }
                    }
                    TtlMatch::Range(min, max) => {
                        if ttl >= *min && ttl <= *max {
                            confidence += 0.12;
                            points.push(format!("TTL in range {}-{}: {}", min, max, ttl));
                        }
                    }
                    TtlMatch::Any => {
                        confidence += 0.05;
                    }
                }
            }

            // Match Window Size
            if let Some(win) = probe.tcp_window {
                match &sig.window_size {
                    WindowMatch::Exact(expected) => {
                        if win == *expected {
                            confidence += 0.15;
                            points.push(format!("Window exact match: {}", win));
                        }
                    }
                    WindowMatch::Range(min, max) => {
                        if win >= *min && win <= *max {
                            confidence += 0.1;
                            points.push(format!("Window in range: {}", win));
                        }
                    }
                    WindowMatch::Multiple(divisor) => {
                        // Multiple means window should be a multiple of this value
                        if *divisor > 0 && win % *divisor == 0 {
                            confidence += 0.12;
                            points.push(format!("Window multiple of {}", divisor));
                        }
                    }
                    WindowMatch::Any => {
                        confidence += 0.02;
                    }
                }
            }

            // Match MSS
            if let Some(mss) = probe.mss {
                match &sig.mss {
                    MssMatch::Exact(expected) => {
                        if mss == *expected {
                            confidence += 0.15;
                            points.push(format!("MSS exact match: {}", mss));
                        }
                    }
                    MssMatch::Range(min, max) => {
                        if mss >= *min && mss <= *max {
                            confidence += 0.1;
                            points.push(format!("MSS in range: {}", mss));
                        }
                    }
                    MssMatch::None => {
                        // Signature expects no MSS but we got one - slight penalty
                        confidence -= 0.05;
                    }
                    MssMatch::Any => {
                        confidence += 0.02;
                    }
                }
            }

            // Match Window Scale
            if let Some(ws) = probe.window_scale {
                if let Some(expected_ws) = sig.window_scale {
                    if ws == expected_ws {
                        confidence += 0.15;
                        points.push(format!("Window Scale match: {}", ws));
                    }
                }
            }

            // Match TCP Options pattern
            let options_pattern = self.get_options_pattern_string(&probe.tcp_options);
            if sig.tcp_options.matches(&options_pattern) {
                confidence += 0.15;
                points.push(format!("TCP Options pattern match: {}", options_pattern));
            }

            // Match DF bit
            if let (Some(df), Some(expected_df)) = (probe.ip_df, sig.df_bit) {
                if df == expected_df {
                    confidence += 0.1;
                    points.push(format!("DF bit match: {}", df));
                }
            }

            // Match IP ID behavior
            let sig_ip_id_match = match (&sig.ip_id, ip_id_behavior) {
                (IpIdPattern::Zero, IpIdBehavior::Zero) => true,
                (IpIdPattern::Random, IpIdBehavior::Random) => true,
                (IpIdPattern::Sequential, IpIdBehavior::Sequential) => true,
                (IpIdPattern::GlobalIncrement, IpIdBehavior::GlobalCounter) => true,
                (IpIdPattern::PerHostIncrement, IpIdBehavior::Sequential) => true,
                _ => false,
            };

            if sig_ip_id_match {
                confidence += 0.1;
                points.push(format!("IP ID pattern match: {:?}", ip_id_behavior));
            }

            // Apply signature weight
            confidence *= sig.confidence_weight;

            // Only include if confidence > 0.3
            if confidence > 0.3 {
                matches.push(OsMatch::new(sig.clone(), confidence, points));
            }
        }

        // Sort by confidence descending
        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Return top 5 matches
        matches.truncate(5);
        matches
    }

    /// Convert TCP options to pattern string
    /// M=MSS, W=WS, N=NOP, S=SACK, T=TS, E=EOL
    fn get_options_pattern_string(&self, options: &[TcpOption]) -> String {
        let mut pattern = String::new();

        for opt in options {
            match opt {
                TcpOption::MaxSegmentSize(_) => pattern.push('M'),
                TcpOption::NoOp => pattern.push('N'),
                TcpOption::WindowScale(_) => pattern.push('W'),
                TcpOption::SackPermitted => pattern.push('S'),
                TcpOption::Sack(_) => pattern.push('S'),
                TcpOption::Timestamp { .. } => pattern.push('T'),
                TcpOption::EndOfOptions => pattern.push('E'),
                TcpOption::Unknown(_, _) => {}
            }
        }

        pattern
    }
}

/// Generate random u16
fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    ((nanos ^ (nanos >> 16)) & 0xFFFF) as u16
}

/// Perform quick OS detection from a single TCP response
pub fn quick_os_detect(
    ttl: u8,
    window_size: u16,
    mss: Option<u16>,
    window_scale: Option<u8>,
    _has_sack: bool,
    _has_timestamp: bool,
) -> Vec<OsMatch> {
    let db = OsSignatureDb::new();
    let mut matches = Vec::new();

    for sig in db.signatures() {
        let mut confidence = 0.0f32;
        let mut points = Vec::new();

        // Match TTL
        match &sig.ttl {
            TtlMatch::Exact(expected) if ttl == *expected => {
                confidence += 0.25;
                points.push(format!("TTL exact: {}", ttl));
            }
            TtlMatch::Initial(initial) if ttl <= *initial && ttl > initial.saturating_sub(30) => {
                confidence += 0.2;
                points.push(format!("TTL ~ {}", initial));
            }
            _ => {}
        }

        // Match Window Size
        match &sig.window_size {
            WindowMatch::Exact(expected) if window_size == *expected => {
                confidence += 0.2;
                points.push(format!("Win: {}", window_size));
            }
            WindowMatch::Range(min, max) if window_size >= *min && window_size <= *max => {
                confidence += 0.15;
                points.push("Win in range".to_string());
            }
            WindowMatch::Multiple(divisor)
                if *divisor > 0 && window_size.is_multiple_of(*divisor) =>
            {
                confidence += 0.15;
                points.push(format!("Win multiple of {}", divisor));
            }
            _ => {}
        }

        // Match MSS
        if let Some(mss_val) = mss {
            match &sig.mss {
                MssMatch::Exact(expected) if mss_val == *expected => {
                    confidence += 0.2;
                    points.push(format!("MSS: {}", mss_val));
                }
                MssMatch::Range(min, max) if mss_val >= *min && mss_val <= *max => {
                    confidence += 0.1;
                }
                _ => {}
            }
        }

        // Match Window Scale
        if let (Some(ws), Some(expected_ws)) = (window_scale, sig.window_scale) {
            if ws == expected_ws {
                confidence += 0.2;
                points.push(format!("WS: {}", ws));
            }
        }

        confidence *= sig.confidence_weight;

        if confidence > 0.3 {
            matches.push(OsMatch::new(sig.clone(), confidence, points));
        }
    }

    matches.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    matches.truncate(5);
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_options_builder() {
        let opts = TcpOptionsBuilder::new()
            .mss(1460)
            .nop()
            .window_scale(7)
            .build();

        assert!(opts.len() >= 7);
        assert_eq!(opts[0], 2); // MSS kind
        assert_eq!(opts[1], 4); // MSS length
    }

    #[test]
    fn test_linux_style_options() {
        let opts = TcpOptionsBuilder::linux_style();
        assert!(!opts.is_empty());
    }

    #[test]
    fn test_windows_style_options() {
        let opts = TcpOptionsBuilder::windows_style();
        assert!(!opts.is_empty());
    }

    #[test]
    fn test_probe_response_empty() {
        let response = ProbeResponse::empty("TEST");
        assert!(!response.received);
        assert_eq!(response.probe_id, "TEST");
    }

    #[test]
    fn test_ip_id_analysis_zero() {
        let prober = OsProber::new(Ipv4Addr::new(127, 0, 0, 1)).unwrap();
        let ids = vec![0, 0, 0, 0, 0];
        assert_eq!(prober.analyze_ip_id_sequence(&ids), IpIdBehavior::Zero);
    }

    #[test]
    fn test_ip_id_analysis_sequential() {
        let prober = OsProber::new(Ipv4Addr::new(127, 0, 0, 1)).unwrap();
        let ids = vec![100, 101, 102, 103, 104];
        assert_eq!(
            prober.analyze_ip_id_sequence(&ids),
            IpIdBehavior::Sequential
        );
    }

    #[test]
    fn test_quick_os_detect() {
        // Linux-like fingerprint
        let matches = quick_os_detect(64, 65535, Some(1460), Some(7), true, true);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_options_pattern() {
        let prober = OsProber::new(Ipv4Addr::new(127, 0, 0, 1)).unwrap();

        let options = vec![
            TcpOption::MaxSegmentSize(1460),
            TcpOption::SackPermitted,
            TcpOption::NoOp,
            TcpOption::WindowScale(7),
            TcpOption::Timestamp { value: 0, echo: 0 },
        ];

        let pattern = prober.get_options_pattern_string(&options);
        // Should contain M (MSS), S (SACK), N (NOP), W (Window Scale), T (Timestamp)
        assert!(pattern.contains('M'));
        assert!(pattern.contains('S'));
        assert!(pattern.contains('N'));
        assert!(pattern.contains('W'));
        assert!(pattern.contains('T'));
    }
}
