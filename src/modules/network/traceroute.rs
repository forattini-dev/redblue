use crate::config;
use crate::protocols::dns::{DnsClient, DnsRecordType};
#[cfg(target_os = "linux")]
use crate::protocols::icmp::IcmpEchoPacket;
/// Traceroute / MTR implementation
/// Uses TTL with UDP/TCP to avoid needing raw sockets (root)
use std::io::{self, ErrorKind};
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
mod linux_raw {
    use std::os::raw::{c_int, c_long, c_uchar, c_uint, c_ushort, c_void};

    pub const AF_INET: c_int = 2;
    pub const SOCK_RAW: c_int = 3;
    pub const IPPROTO_ICMP: c_int = 1;
    pub const IPPROTO_IP: c_int = 0;
    pub const IP_TTL: c_int = 2;
    pub const SOL_SOCKET: c_int = 1;
    pub const SO_RCVTIMEO: c_int = 20;
    pub const EPERM: c_int = 1;
    pub const EACCES: c_int = 13;

    #[repr(C)]
    pub struct SockAddr {
        pub sa_family: c_ushort,
        pub sa_data: [c_uchar; 14],
    }

    #[repr(C)]
    pub struct InAddr {
        pub s_addr: c_uint,
    }

    #[repr(C)]
    pub struct SockAddrIn {
        pub sin_family: c_ushort,
        pub sin_port: c_ushort,
        pub sin_addr: InAddr,
        pub sin_zero: [c_uchar; 8],
    }

    #[repr(C)]
    pub struct TimeVal {
        pub tv_sec: c_long,
        pub tv_usec: c_long,
    }

    extern "C" {
        pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        pub fn setsockopt(
            fd: c_int,
            level: c_int,
            optname: c_int,
            optval: *const c_void,
            optlen: c_uint,
        ) -> c_int;
        pub fn sendto(
            fd: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            addr: *const SockAddr,
            addrlen: c_uint,
        ) -> isize;
        pub fn recvfrom(
            fd: c_int,
            buf: *mut c_void,
            len: usize,
            flags: c_int,
            addr: *mut SockAddr,
            addrlen: *mut c_uint,
        ) -> isize;
        pub fn close(fd: c_int) -> c_int;
    }
}

#[cfg(target_os = "linux")]
enum ProbeError {
    PermissionDenied(String),
    Other(String),
}

#[cfg(target_os = "linux")]
struct RawFdGuard(std::os::raw::c_int);

#[cfg(target_os = "linux")]
impl Drop for RawFdGuard {
    fn drop(&mut self) {
        unsafe {
            linux_raw::close(self.0);
        }
    }
}

#[derive(Debug, Clone)]
pub struct HopInfo {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub latency_ms: Option<f64>,
    pub responded: bool,
}

pub struct Traceroute {
    target: String,
    max_hops: u8,
    timeout_ms: u64,
    dns_resolve: bool,
}

impl Traceroute {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            max_hops: 30,
            timeout_ms: 2000,
            dns_resolve: true,
        }
    }

    pub fn with_max_hops(mut self, max_hops: u8) -> Self {
        self.max_hops = max_hops;
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_dns_resolve(mut self, resolve: bool) -> Self {
        self.dns_resolve = resolve;
        self
    }

    pub fn run(&self) -> Result<Vec<HopInfo>, String> {
        let target_ip = self.resolve_target()?;
        let mut hops = Vec::new();

        for ttl in 1..=self.max_hops {
            let hop = self.probe_hop(ttl, &target_ip)?;
            let reached_target = hop.ip == Some(target_ip);

            hops.push(hop);

            if reached_target {
                break;
            }
        }

        Ok(hops)
    }

    fn resolve_target(&self) -> Result<IpAddr, String> {
        // Try to parse as IP first
        if let Ok(ip) = self.target.parse::<IpAddr>() {
            return Ok(ip);
        }

        // Resolve DNS using configured resolver
        let cfg = config::get();
        let dns =
            DnsClient::new(&cfg.network.dns_resolver).with_timeout(cfg.network.dns_timeout_ms);
        let answers = dns
            .query(&self.target, DnsRecordType::A)
            .map_err(|e| format!("Failed to resolve {}: {}", self.target, e))?;

        answers
            .first()
            .and_then(|a| a.as_ip())
            .and_then(|ip_str| ip_str.parse().ok())
            .ok_or_else(|| format!("No IP found for {}", self.target))
    }

    fn probe_hop(&self, ttl: u8, target: &IpAddr) -> Result<HopInfo, String> {
        #[cfg(target_os = "linux")]
        {
            match self.probe_hop_icmp_linux(ttl, target) {
                Ok(mut hop) => {
                    if self.dns_resolve {
                        if let Some(ip) = hop.ip {
                            hop.hostname = self.reverse_dns(&ip);
                        }
                    }
                    return Ok(hop);
                }
                Err(ProbeError::PermissionDenied(msg)) => {
                    return Err(msg);
                }
                Err(ProbeError::Other(_)) => {
                    // Fall back to UDP probing below
                }
            }
        }

        let mut hop = self.probe_hop_udp(ttl, target)?;

        if self.dns_resolve {
            if let Some(ip) = hop.ip {
                hop.hostname = self.reverse_dns(&ip);
            }
        }

        Ok(hop)
    }

    #[cfg(target_os = "linux")]
    fn probe_hop_icmp_linux(&self, ttl: u8, target: &IpAddr) -> Result<HopInfo, ProbeError> {
        use linux_raw::*;
        use std::mem;
        use std::os::raw::{c_int, c_long, c_void};

        let target_v4 = match target {
            IpAddr::V4(v4) => *v4,
            IpAddr::V6(_) => {
                return Err(ProbeError::Other(
                    "ICMP traceroute currently supports IPv4 only".to_string(),
                ))
            }
        };

        fn map_errno(context: &str) -> ProbeError {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(EPERM) | Some(EACCES) => ProbeError::PermissionDenied(format!(
                    "{} failed: {} (requires root/CAP_NET_RAW)",
                    context, err
                )),
                _ => ProbeError::Other(format!("{} failed: {}", context, err)),
            }
        }

        let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
        if fd < 0 {
            return Err(map_errno("socket(AF_INET, SOCK_RAW)"));
        }
        let _guard = RawFdGuard(fd);

        let ttl_value: c_int = ttl as c_int;
        let ttl_result = unsafe {
            setsockopt(
                fd,
                IPPROTO_IP,
                IP_TTL,
                &ttl_value as *const _ as *const c_void,
                mem::size_of::<c_int>() as u32,
            )
        };
        if ttl_result < 0 {
            return Err(map_errno("setsockopt(IP_TTL)"));
        }

        let timeout_ms = self.timeout_ms.max(1);
        let timeval = TimeVal {
            tv_sec: (timeout_ms / 1000) as c_long,
            tv_usec: ((timeout_ms % 1000) * 1000) as c_long,
        };
        let timeval_result = unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &timeval as *const _ as *const c_void,
                mem::size_of::<TimeVal>() as u32,
            )
        };
        if timeval_result < 0 {
            return Err(map_errno("setsockopt(SO_RCVTIMEO)"));
        }

        let identifier = (std::process::id() & 0xFFFF) as u16;
        let sequence = ttl as u16;
        let packet = IcmpEchoPacket::new_echo_request(identifier, sequence, 32);
        let bytes = packet.to_bytes();

        let dest = SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: InAddr {
                s_addr: u32::from_be_bytes(target_v4.octets()),
            },
            sin_zero: [0; 8],
        };

        let send_result = unsafe {
            sendto(
                fd,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                0,
                &dest as *const _ as *const SockAddr,
                mem::size_of::<SockAddrIn>() as u32,
            )
        };

        if send_result < 0 {
            return Err(map_errno("sendto(ICMP Echo)"));
        }

        let start = Instant::now();
        let mut buffer = [0u8; 1024];

        loop {
            let mut from = SockAddrIn {
                sin_family: 0,
                sin_port: 0,
                sin_addr: InAddr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            let mut addr_len = mem::size_of::<SockAddrIn>() as u32;
            let recv_len = unsafe {
                recvfrom(
                    fd,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len(),
                    0,
                    &mut from as *mut _ as *mut SockAddr,
                    &mut addr_len,
                )
            };

            if recv_len < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                    return Ok(HopInfo {
                        ttl,
                        ip: None,
                        hostname: None,
                        latency_ms: None,
                        responded: false,
                    });
                }
                return Err(map_errno("recvfrom(ICMP)"));
            }

            let recv_len = recv_len as usize;
            if recv_len < 28 {
                continue;
            }

            let ip_header_len = (buffer[0] & 0x0F) as usize * 4;
            if recv_len < ip_header_len + 8 {
                continue;
            }

            let icmp_type = buffer[ip_header_len];
            let icmp_code = buffer[ip_header_len + 1];

            let hop_ip = IpAddr::V4(Ipv4Addr::from(from.sin_addr.s_addr.to_be_bytes()));
            let latency = start.elapsed().as_secs_f64() * 1000.0;

            match icmp_type {
                0 => {
                    // Echo reply from destination
                    if recv_len < ip_header_len + 8 {
                        continue;
                    }
                    let resp_id =
                        u16::from_be_bytes([buffer[ip_header_len + 4], buffer[ip_header_len + 5]]);
                    let resp_seq =
                        u16::from_be_bytes([buffer[ip_header_len + 6], buffer[ip_header_len + 7]]);
                    if resp_id != identifier || resp_seq != sequence {
                        continue;
                    }

                    return Ok(HopInfo {
                        ttl,
                        ip: Some(hop_ip),
                        hostname: None,
                        latency_ms: Some(latency),
                        responded: true,
                    });
                }
                11 | 3 => {
                    // Time exceeded or destination unreachable
                    let inner_ip_offset = ip_header_len + 8;
                    if recv_len < inner_ip_offset + 28 {
                        continue;
                    }
                    let inner_ip_header_len = (buffer[inner_ip_offset] & 0x0F) as usize * 4;
                    if recv_len < inner_ip_offset + inner_ip_header_len + 8 {
                        continue;
                    }
                    let inner_icmp_offset = inner_ip_offset + inner_ip_header_len;
                    let inner_id = u16::from_be_bytes([
                        buffer[inner_icmp_offset + 4],
                        buffer[inner_icmp_offset + 5],
                    ]);
                    let inner_seq = u16::from_be_bytes([
                        buffer[inner_icmp_offset + 6],
                        buffer[inner_icmp_offset + 7],
                    ]);
                    if inner_id != identifier || inner_seq != sequence {
                        continue;
                    }

                    return Ok(HopInfo {
                        ttl,
                        ip: Some(hop_ip),
                        hostname: None,
                        latency_ms: Some(latency),
                        responded: true,
                    });
                }
                _ => {
                    // Ignore unrelated ICMP traffic
                    let _ = icmp_code;
                    continue;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_hop_udp(&self, ttl: u8, target: &IpAddr) -> Result<HopInfo, String> {
        let start = Instant::now();
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to create socket: {}", e))?;

        socket
            .set_ttl(ttl as u32)
            .map_err(|e| format!("Failed to set TTL: {}", e))?;

        socket
            .set_read_timeout(Some(Duration::from_millis(self.timeout_ms)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        let dest = SocketAddr::new(*target, 33434);
        let _ = socket.send_to(&[0u8; 32], dest);

        let mut hop_ip: Option<IpAddr> = None;
        let mut responded = false;
        let mut buffer = [0u8; 512];

        match socket.recv_from(&mut buffer) {
            Ok((_size, addr)) => {
                hop_ip = Some(addr.ip());
                responded = true;
            }
            Err(err) => {
                if err.kind() != ErrorKind::WouldBlock {
                    return Err(format!("Failed to receive response: {}", err));
                }
            }
        }

        if self.try_tcp_probe(ttl, target) {
            responded = true;
            if hop_ip.is_none() {
                hop_ip = Some(*target);
            }
        }

        Ok(HopInfo {
            ttl,
            ip: hop_ip,
            hostname: None,
            latency_ms: responded.then_some(start.elapsed().as_secs_f64() * 1000.0),
            responded,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn probe_hop_udp(&self, ttl: u8, target: &IpAddr) -> Result<HopInfo, String> {
        let start = Instant::now();
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to create socket: {}", e))?;

        socket
            .set_ttl(ttl as u32)
            .map_err(|e| format!("Failed to set TTL: {}", e))?;

        socket
            .set_read_timeout(Some(Duration::from_millis(self.timeout_ms)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        let dest = SocketAddr::new(*target, 33434);
        let _ = socket.send_to(&[0u8; 32], dest);

        let mut hop_ip: Option<IpAddr> = None;
        let mut responded = false;
        let mut buffer = [0u8; 512];

        match socket.recv_from(&mut buffer) {
            Ok((_size, addr)) => {
                hop_ip = Some(addr.ip());
                responded = true;
            }
            Err(err) => {
                if err.kind() != ErrorKind::WouldBlock {
                    return Err(format!("Failed to receive response: {}", err));
                }
            }
        }

        if self.try_tcp_probe(ttl, target) {
            responded = true;
            if hop_ip.is_none() {
                hop_ip = Some(*target);
            }
        }

        Ok(HopInfo {
            ttl,
            ip: hop_ip,
            hostname: None,
            latency_ms: responded.then_some(start.elapsed().as_secs_f64() * 1000.0),
            responded,
        })
    }

    fn try_tcp_probe(&self, _ttl: u8, target: &IpAddr) -> bool {
        for port in [80u16, 443u16] {
            let addr = SocketAddr::new(*target, port);
            if TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms)).is_ok() {
                return true;
            }
        }
        false
    }

    fn reverse_dns(&self, ip: &IpAddr) -> Option<String> {
        let ptr_name = match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(v6) => {
                let mut labels = Vec::with_capacity(32);
                for byte in v6.octets().iter().rev() {
                    labels.push(format!("{:x}", byte & 0x0F));
                    labels.push(format!("{:x}", byte >> 4));
                }
                format!("{}.ip6.arpa", labels.join("."))
            }
        };

        let cfg = config::get();
        let resolver =
            DnsClient::new(&cfg.network.dns_resolver).with_timeout(cfg.network.dns_timeout_ms);
        let answers = resolver.query(&ptr_name, DnsRecordType::PTR).ok()?;
        answers
            .iter()
            .map(|answer| answer.display_value())
            .map(|name| name.trim_end_matches('.').to_string())
            .find(|name| !name.is_empty())
    }
}

/// MTR-style continuous monitoring
pub struct Mtr {
    traceroute: Traceroute,
    iterations: usize,
}

impl Mtr {
    pub fn new(target: &str) -> Self {
        Self {
            traceroute: Traceroute::new(target),
            iterations: 10,
        }
    }

    pub fn with_iterations(mut self, iterations: usize) -> Self {
        self.iterations = iterations;
        self
    }

    pub fn run(&self) -> Result<Vec<MtrHopStats>, String> {
        let mut stats_map: std::collections::HashMap<u8, MtrHopStats> =
            std::collections::HashMap::new();

        for _ in 0..self.iterations {
            let hops = self.traceroute.run()?;

            for hop in hops {
                let stats = stats_map.entry(hop.ttl).or_insert_with(|| MtrHopStats {
                    ttl: hop.ttl,
                    ip: hop.ip,
                    hostname: hop.hostname.clone(),
                    sent: 0,
                    received: 0,
                    latencies: Vec::new(),
                });

                stats.sent += 1;
                if hop.responded {
                    stats.received += 1;
                    if let Some(lat) = hop.latency_ms {
                        stats.latencies.push(lat);
                    }
                }
            }
        }

        let mut results: Vec<_> = stats_map.into_iter().map(|(_, v)| v).collect();
        results.sort_by_key(|s| s.ttl);

        Ok(results)
    }
}

#[derive(Debug, Clone)]
pub struct MtrHopStats {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub sent: usize,
    pub received: usize,
    pub latencies: Vec<f64>,
}

impl MtrHopStats {
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        ((self.sent - self.received) as f64 / self.sent as f64) * 100.0
    }

    pub fn avg_latency(&self) -> f64 {
        if self.latencies.is_empty() {
            return 0.0;
        }
        self.latencies.iter().sum::<f64>() / self.latencies.len() as f64
    }

    pub fn min_latency(&self) -> f64 {
        if self.latencies.is_empty() {
            0.0
        } else {
            self.latencies.iter().cloned().fold(f64::INFINITY, f64::min)
        }
    }

    pub fn max_latency(&self) -> f64 {
        if self.latencies.is_empty() {
            0.0
        } else {
            self.latencies
                .iter()
                .cloned()
                .fold(f64::NEG_INFINITY, f64::max)
        }
    }
}
