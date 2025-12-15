/// Raw Socket Packet Crafting Layer
///
/// Implements low-level packet construction for:
/// - TCP SYN/FIN/NULL/XMAS scans
/// - UDP scanning with ICMP response handling
/// - IP header crafting
///
/// Requires CAP_NET_RAW on Linux or root privileges.
/// Reference: RFC 791 (IP), RFC 793 (TCP), RFC 768 (UDP)
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

// Protocol numbers
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// TCP flags
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

/// Port state as determined by scan response
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Port is open (received SYN-ACK for SYN scan, or response for connect scan)
    Open,
    /// Port is closed (received RST)
    Closed,
    /// Port is filtered (no response, or ICMP unreachable)
    Filtered,
    /// Port is unfiltered (ACK scan got RST, meaning no firewall)
    Unfiltered,
    /// Port is open or filtered (FIN/NULL/XMAS got no response)
    OpenFiltered,
    /// Port is closed or filtered
    ClosedFiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::Unfiltered => write!(f, "unfiltered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
            PortState::ClosedFiltered => write!(f, "closed|filtered"),
        }
    }
}

/// IPv4 header (20 bytes without options)
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,          // 4 bits: always 4
    pub ihl: u8,              // 4 bits: header length in 32-bit words (5 for no options)
    pub tos: u8,              // Type of Service
    pub total_length: u16,    // Total packet length
    pub identification: u16,  // Fragment identification
    pub flags: u8,            // 3 bits: fragmentation flags
    pub fragment_offset: u16, // 13 bits: fragment offset
    pub ttl: u8,              // Time to Live
    pub protocol: u8,         // Protocol (6=TCP, 17=UDP, 1=ICMP)
    pub checksum: u16,        // Header checksum
    pub src_addr: Ipv4Addr,   // Source IP
    pub dst_addr: Ipv4Addr,   // Destination IP
}

impl Ipv4Header {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: u16) -> Self {
        let mut header = Self {
            version: 4,
            ihl: 5, // 20 bytes, no options
            tos: 0,
            total_length: 20 + payload_len,
            identification: rand_u16(),
            flags: 0x02, // Don't fragment
            fragment_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src_addr: src,
            dst_addr: dst,
        };
        header.checksum = header.calculate_checksum();
        header
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];

        bytes[0] = (self.version << 4) | self.ihl;
        bytes[1] = self.tos;
        bytes[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.identification.to_be_bytes());

        let flags_offset = ((self.flags as u16) << 13) | self.fragment_offset;
        bytes[6..8].copy_from_slice(&flags_offset.to_be_bytes());

        bytes[8] = self.ttl;
        bytes[9] = self.protocol;
        bytes[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.src_addr.octets());
        bytes[16..20].copy_from_slice(&self.dst_addr.octets());

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 20 {
            return Err("IP header too short".to_string());
        }

        let version = bytes[0] >> 4;
        let ihl = bytes[0] & 0x0F;
        let tos = bytes[1];
        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let identification = u16::from_be_bytes([bytes[4], bytes[5]]);
        let flags_offset = u16::from_be_bytes([bytes[6], bytes[7]]);
        let flags = (flags_offset >> 13) as u8;
        let fragment_offset = flags_offset & 0x1FFF;
        let ttl = bytes[8];
        let protocol = bytes[9];
        let checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        let src_addr = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        let dst_addr = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);

        Ok(Self {
            version,
            ihl,
            tos,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_addr,
            dst_addr,
        })
    }

    fn calculate_checksum(&self) -> u16 {
        let mut bytes = self.to_bytes();
        bytes[10] = 0; // Zero checksum field
        bytes[11] = 0;
        internet_checksum(&bytes)
    }
}

/// TCP header (20 bytes without options)
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8, // 4 bits: header length in 32-bit words
    pub reserved: u8,    // 3 bits
    pub flags: u8,       // 9 bits (ECN + 6 control flags)
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn new(src_port: u16, dst_port: u16, flags: u8) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num: rand_u32(),
            ack_num: 0,
            data_offset: 5, // 20 bytes, no options
            reserved: 0,
            flags,
            window: 65535,
            checksum: 0, // Calculated later with pseudo-header
            urgent_ptr: 0,
        }
    }

    pub fn syn(src_port: u16, dst_port: u16) -> Self {
        Self::new(src_port, dst_port, TCP_SYN)
    }

    pub fn fin(src_port: u16, dst_port: u16) -> Self {
        Self::new(src_port, dst_port, TCP_FIN)
    }

    pub fn null(src_port: u16, dst_port: u16) -> Self {
        Self::new(src_port, dst_port, 0)
    }

    pub fn xmas(src_port: u16, dst_port: u16) -> Self {
        Self::new(src_port, dst_port, TCP_FIN | TCP_PSH | TCP_URG)
    }

    pub fn ack(src_port: u16, dst_port: u16) -> Self {
        Self::new(src_port, dst_port, TCP_ACK)
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];

        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.ack_num.to_be_bytes());

        let offset_reserved = (self.data_offset << 4) | (self.reserved >> 1);
        bytes[12] = offset_reserved;
        bytes[13] = self.flags;

        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 20 {
            return Err("TCP header too short".to_string());
        }

        let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let seq_num = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack_num = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let data_offset = bytes[12] >> 4;
        let reserved = (bytes[12] & 0x0E) << 1;
        let flags = bytes[13];
        let window = u16::from_be_bytes([bytes[14], bytes[15]]);
        let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        let urgent_ptr = u16::from_be_bytes([bytes[18], bytes[19]]);

        Ok(Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_ptr,
        })
    }

    /// Calculate TCP checksum with pseudo-header
    pub fn calculate_checksum(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload: &[u8]) -> u16 {
        let tcp_len = 20 + payload.len();

        // Build pseudo-header + TCP header + payload
        let mut data = Vec::with_capacity(12 + tcp_len);

        // Pseudo-header (12 bytes)
        data.extend_from_slice(&src_ip.octets());
        data.extend_from_slice(&dst_ip.octets());
        data.push(0); // Reserved
        data.push(IPPROTO_TCP);
        data.extend_from_slice(&(tcp_len as u16).to_be_bytes());

        // TCP header with checksum = 0
        let mut tcp_bytes = self.to_bytes();
        tcp_bytes[16] = 0;
        tcp_bytes[17] = 0;
        data.extend_from_slice(&tcp_bytes);

        // Payload
        data.extend_from_slice(payload);

        internet_checksum(&data)
    }

    /// Check if this is a SYN-ACK response
    pub fn is_syn_ack(&self) -> bool {
        (self.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)
    }

    /// Check if this is a RST response
    pub fn is_rst(&self) -> bool {
        (self.flags & TCP_RST) != 0
    }
}

/// UDP header (8 bytes)
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn new(src_port: u16, dst_port: u16, payload_len: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length: 8 + payload_len,
            checksum: 0, // Optional for IPv4
        }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.length.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("UDP header too short".to_string());
        }

        Ok(Self {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}

/// ICMP Destination Unreachable message (for UDP scan responses)
#[derive(Debug, Clone)]
pub struct IcmpDestUnreachable {
    pub icmp_type: u8, // 3 for dest unreachable
    pub code: u8,      // 3 = port unreachable
    pub checksum: u16,
    pub unused: u32,
    pub original_ip: Vec<u8>, // Original IP header + 8 bytes of original datagram
}

impl IcmpDestUnreachable {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("ICMP dest unreachable too short".to_string());
        }

        Ok(Self {
            icmp_type: bytes[0],
            code: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            unused: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            original_ip: bytes[8..].to_vec(),
        })
    }

    /// Check if this is a port unreachable message
    pub fn is_port_unreachable(&self) -> bool {
        self.icmp_type == 3 && self.code == 3
    }

    /// Check if this is administratively filtered
    pub fn is_admin_prohibited(&self) -> bool {
        self.icmp_type == 3 && (self.code == 9 || self.code == 10 || self.code == 13)
    }
}

/// Internet checksum (RFC 1071)
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() {
        if i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum += word as u32;
        } else {
            sum += (data[i] as u32) << 8;
        }
        i += 2;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Generate random u16 for port/identification
fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    ((nanos ^ (nanos >> 16)) & 0xFFFF) as u16
}

/// Generate random u32 for sequence numbers
fn rand_u32() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    ((nanos ^ (nanos >> 32)) & 0xFFFFFFFF) as u32
}

/// Raw socket wrapper for sending/receiving packets
/// Note: Requires root/CAP_NET_RAW on Linux
#[cfg(target_family = "unix")]
pub mod raw_socket {
    use super::*;
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

    /// Raw socket for packet injection
    pub struct RawSocket {
        fd: RawFd,
        protocol: i32,
    }

    impl RawSocket {
        /// Create a raw socket for TCP
        pub fn new_tcp() -> io::Result<Self> {
            Self::new(libc::IPPROTO_TCP)
        }

        /// Create a raw socket for ICMP
        pub fn new_icmp() -> io::Result<Self> {
            Self::new(libc::IPPROTO_ICMP)
        }

        /// Create a raw socket for UDP (for receiving ICMP responses)
        pub fn new_udp() -> io::Result<Self> {
            Self::new(libc::IPPROTO_UDP)
        }

        /// Create a raw socket with IP header inclusion
        pub fn new_raw() -> io::Result<Self> {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };

            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Enable IP_HDRINCL - we craft our own IP header
            let on: libc::c_int = 1;
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };

            if result < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            Ok(Self {
                fd,
                protocol: libc::IPPROTO_RAW,
            })
        }

        fn new(protocol: i32) -> io::Result<Self> {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, protocol) };

            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self { fd, protocol })
        }

        /// Set socket receive timeout
        pub fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
            let tv = libc::timeval {
                tv_sec: timeout.as_secs() as libc::time_t,
                tv_usec: timeout.subsec_micros() as libc::suseconds_t,
            };

            let result = unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };

            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        /// Send raw packet to destination
        pub fn send_to(&self, packet: &[u8], dest: Ipv4Addr) -> io::Result<usize> {
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            let dest_addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(dest.octets()),
                },
                sin_zero: [0; 8],
            };

            #[cfg(any(target_os = "macos", target_os = "ios"))]
            let dest_addr = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(dest.octets()),
                },
                sin_zero: [0; 8],
            };

            let result = unsafe {
                libc::sendto(
                    self.fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &dest_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };

            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as usize)
            }
        }

        /// Receive raw packet
        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let result =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as usize)
            }
        }

        /// Receive with source address
        pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Ipv4Addr)> {
            let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

            let result = unsafe {
                libc::recvfrom(
                    self.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut src_addr as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };

            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                let ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
                Ok((result as usize, ip))
            }
        }
    }

    impl Drop for RawSocket {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }

    impl AsRawFd for RawSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }
}

/// Scan result from raw socket scanning
#[derive(Debug, Clone)]
pub struct RawScanResult {
    pub port: u16,
    pub state: PortState,
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
}

/// TCP SYN Scanner using raw sockets
#[cfg(target_family = "unix")]
pub struct SynScanner {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    timeout: Duration,
}

#[cfg(target_family = "unix")]
impl SynScanner {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Self {
        Self {
            src_ip,
            dst_ip,
            timeout: Duration::from_secs(2),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Scan a single port using SYN technique
    pub fn scan_port(&self, port: u16) -> io::Result<RawScanResult> {
        use raw_socket::RawSocket;

        let socket = RawSocket::new_raw()?;
        socket.set_timeout(self.timeout)?;

        // Use ephemeral source port
        let src_port = 40000 + (rand_u16() % 10000);

        // Build TCP SYN packet
        let mut tcp = TcpHeader::syn(src_port, port);
        tcp.checksum = tcp.calculate_checksum(self.src_ip, self.dst_ip, &[]);

        // Build IP header
        let ip = Ipv4Header::new(self.src_ip, self.dst_ip, IPPROTO_TCP, 20);

        // Combine headers
        let mut packet = Vec::with_capacity(40);
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&tcp.to_bytes());

        let start = Instant::now();

        // Send SYN packet
        socket.send_to(&packet, self.dst_ip)?;

        // Wait for response
        let mut buf = [0u8; 1500];
        let deadline = Instant::now() + self.timeout;

        while Instant::now() < deadline {
            match socket.recv(&mut buf) {
                Ok(len) if len >= 40 => {
                    // Parse IP header
                    if let Ok(resp_ip) = Ipv4Header::from_bytes(&buf[..20]) {
                        // Check if from our target
                        if resp_ip.src_addr != self.dst_ip {
                            continue;
                        }

                        // Parse TCP header
                        let ip_hdr_len = (resp_ip.ihl as usize) * 4;
                        if len >= ip_hdr_len + 20 {
                            if let Ok(resp_tcp) = TcpHeader::from_bytes(&buf[ip_hdr_len..]) {
                                // Check if response to our port
                                if resp_tcp.src_port == port && resp_tcp.dst_port == src_port {
                                    let rtt = start.elapsed();

                                    if resp_tcp.is_syn_ack() {
                                        // Port is open - send RST to clean up
                                        // (In production, we'd send RST here)
                                        return Ok(RawScanResult {
                                            port,
                                            state: PortState::Open,
                                            rtt: Some(rtt),
                                            ttl: Some(resp_ip.ttl),
                                        });
                                    } else if resp_tcp.is_rst() {
                                        return Ok(RawScanResult {
                                            port,
                                            state: PortState::Closed,
                                            rtt: Some(rtt),
                                            ttl: Some(resp_ip.ttl),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(_) => continue,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => break,
                Err(e) => return Err(e),
            }
        }

        // No response = filtered
        Ok(RawScanResult {
            port,
            state: PortState::Filtered,
            rtt: None,
            ttl: None,
        })
    }

    /// Scan multiple ports
    pub fn scan_ports(&self, ports: &[u16]) -> io::Result<Vec<RawScanResult>> {
        let mut results = Vec::with_capacity(ports.len());
        for &port in ports {
            results.push(self.scan_port(port)?);
        }
        Ok(results)
    }
}

/// Stealth scanner for FIN/NULL/XMAS scans
#[cfg(target_family = "unix")]
pub struct StealthScanner {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    timeout: Duration,
    scan_type: StealthScanType,
}

#[derive(Debug, Clone, Copy)]
pub enum StealthScanType {
    Fin,
    Null,
    Xmas,
}

#[cfg(target_family = "unix")]
impl StealthScanner {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, scan_type: StealthScanType) -> Self {
        Self {
            src_ip,
            dst_ip,
            timeout: Duration::from_secs(3),
            scan_type,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Scan a single port using stealth technique
    pub fn scan_port(&self, port: u16) -> io::Result<RawScanResult> {
        use raw_socket::RawSocket;

        let socket = RawSocket::new_raw()?;
        socket.set_timeout(self.timeout)?;

        let src_port = 40000 + (rand_u16() % 10000);

        // Build TCP header based on scan type
        let mut tcp = match self.scan_type {
            StealthScanType::Fin => TcpHeader::fin(src_port, port),
            StealthScanType::Null => TcpHeader::null(src_port, port),
            StealthScanType::Xmas => TcpHeader::xmas(src_port, port),
        };
        tcp.checksum = tcp.calculate_checksum(self.src_ip, self.dst_ip, &[]);

        let ip = Ipv4Header::new(self.src_ip, self.dst_ip, IPPROTO_TCP, 20);

        let mut packet = Vec::with_capacity(40);
        packet.extend_from_slice(&ip.to_bytes());
        packet.extend_from_slice(&tcp.to_bytes());

        let start = Instant::now();
        socket.send_to(&packet, self.dst_ip)?;

        // Wait for RST response
        let mut buf = [0u8; 1500];
        let deadline = Instant::now() + self.timeout;

        while Instant::now() < deadline {
            match socket.recv(&mut buf) {
                Ok(len) if len >= 40 => {
                    if let Ok(resp_ip) = Ipv4Header::from_bytes(&buf[..20]) {
                        if resp_ip.src_addr != self.dst_ip {
                            continue;
                        }

                        let ip_hdr_len = (resp_ip.ihl as usize) * 4;
                        if len >= ip_hdr_len + 20 {
                            if let Ok(resp_tcp) = TcpHeader::from_bytes(&buf[ip_hdr_len..]) {
                                if resp_tcp.src_port == port && resp_tcp.dst_port == src_port {
                                    if resp_tcp.is_rst() {
                                        return Ok(RawScanResult {
                                            port,
                                            state: PortState::Closed,
                                            rtt: Some(start.elapsed()),
                                            ttl: Some(resp_ip.ttl),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(_) => continue,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => break,
                Err(e) => return Err(e),
            }
        }

        // No response = open|filtered (per RFC 793)
        Ok(RawScanResult {
            port,
            state: PortState::OpenFiltered,
            rtt: None,
            ttl: None,
        })
    }
}

/// UDP Scanner with ICMP response handling
#[cfg(target_family = "unix")]
pub struct UdpScanner {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    timeout: Duration,
}

#[cfg(target_family = "unix")]
impl UdpScanner {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Self {
        Self {
            src_ip,
            dst_ip,
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Scan a UDP port
    pub fn scan_port(&self, port: u16) -> io::Result<RawScanResult> {
        // For UDP, we use a regular socket but listen for ICMP responses
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout))?;

        let dest = SocketAddr::new(IpAddr::V4(self.dst_ip), port);

        // Send empty UDP packet (or protocol-specific probe)
        let probe = Self::get_probe(port);
        let start = Instant::now();
        socket.send_to(&probe, dest)?;

        // Try to receive response
        let mut buf = [0u8; 1500];
        match socket.recv_from(&mut buf) {
            Ok((len, _)) if len > 0 => {
                // Got response - port is open
                Ok(RawScanResult {
                    port,
                    state: PortState::Open,
                    rtt: Some(start.elapsed()),
                    ttl: None,
                })
            }
            Ok(_) => Ok(RawScanResult {
                port,
                state: PortState::OpenFiltered,
                rtt: None,
                ttl: None,
            }),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                // ICMP port unreachable - closed
                Ok(RawScanResult {
                    port,
                    state: PortState::Closed,
                    rtt: Some(start.elapsed()),
                    ttl: None,
                })
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(RawScanResult {
                port,
                state: PortState::OpenFiltered,
                rtt: None,
                ttl: None,
            }),
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => Ok(RawScanResult {
                port,
                state: PortState::OpenFiltered,
                rtt: None,
                ttl: None,
            }),
            Err(e) => Err(e),
        }
    }

    /// Get protocol-specific probe for common UDP services
    fn get_probe(port: u16) -> Vec<u8> {
        match port {
            // DNS query for version.bind
            53 => {
                vec![
                    0x00, 0x01, // Transaction ID
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs
                    0x00, 0x00, // Authority RRs
                    0x00, 0x00, // Additional RRs
                    0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd',
                    0x00, // version.bind
                    0x00, 0x10, // Type: TXT
                    0x00, 0x03, // Class: CH
                ]
            }
            // SNMP GetRequest
            161 => {
                vec![
                    0x30, 0x29, // SEQUENCE
                    0x02, 0x01, 0x00, // INTEGER version (0 = SNMPv1)
                    0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community
                    0xa0, 0x1c, // GetRequest
                    0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id
                    0x02, 0x01, 0x00, // error-status
                    0x02, 0x01, 0x00, // error-index
                    0x30, 0x0e, // variable bindings
                    0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
                    0x00, // sysDescr.0
                    0x05, 0x00, // NULL
                ]
            }
            // NTP version query
            123 => {
                let mut ntp = vec![0u8; 48];
                ntp[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
                ntp
            }
            // Empty probe for unknown services
            _ => vec![0u8; 0],
        }
    }
}

/// Get local IP address that can reach a destination
pub fn get_source_ip(dest: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(SocketAddr::new(IpAddr::V4(dest), 80))?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            "Could not determine local IPv4 address",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_header() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let header = Ipv4Header::new(src, dst, IPPROTO_TCP, 20);

        assert_eq!(header.version, 4);
        assert_eq!(header.ihl, 5);
        assert_eq!(header.total_length, 40);
        assert_eq!(header.protocol, IPPROTO_TCP);

        let bytes = header.to_bytes();
        let parsed = Ipv4Header::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.src_addr, src);
        assert_eq!(parsed.dst_addr, dst);
    }

    #[test]
    fn test_tcp_header() {
        let header = TcpHeader::syn(12345, 80);

        assert_eq!(header.src_port, 12345);
        assert_eq!(header.dst_port, 80);
        assert_eq!(header.flags, TCP_SYN);

        let bytes = header.to_bytes();
        let parsed = TcpHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 80);
        assert!(!parsed.is_syn_ack());
        assert!(!parsed.is_rst());
    }

    #[test]
    fn test_tcp_flags() {
        let syn = TcpHeader::syn(1, 2);
        assert_eq!(syn.flags, TCP_SYN);

        let fin = TcpHeader::fin(1, 2);
        assert_eq!(fin.flags, TCP_FIN);

        let null = TcpHeader::null(1, 2);
        assert_eq!(null.flags, 0);

        let xmas = TcpHeader::xmas(1, 2);
        assert_eq!(xmas.flags, TCP_FIN | TCP_PSH | TCP_URG);
    }

    #[test]
    fn test_udp_header() {
        let header = UdpHeader::new(12345, 53, 100);

        assert_eq!(header.src_port, 12345);
        assert_eq!(header.dst_port, 53);
        assert_eq!(header.length, 108); // 8 header + 100 payload

        let bytes = header.to_bytes();
        let parsed = UdpHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 53);
    }

    #[test]
    fn test_checksum() {
        // Test with known values
        let data = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let checksum = internet_checksum(&data);
        // Checksum should be non-zero
        assert!(checksum != 0);
    }

    #[test]
    fn test_port_state_display() {
        assert_eq!(format!("{}", PortState::Open), "open");
        assert_eq!(format!("{}", PortState::Closed), "closed");
        assert_eq!(format!("{}", PortState::Filtered), "filtered");
        assert_eq!(format!("{}", PortState::OpenFiltered), "open|filtered");
    }
}
