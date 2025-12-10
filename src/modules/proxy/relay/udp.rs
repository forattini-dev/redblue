//! UDP Relay Implementation
//!
//! Provides UDP relay for SOCKS5 UDP ASSOCIATE and transparent proxy modes.
//!
//! # SOCKS5 UDP Relay Format (RFC 1928)
//!
//! ```text
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//! ```
//!
//! RSV: Reserved (0x0000)
//! FRAG: Fragment number (0x00 for no fragmentation)
//! ATYP: Address type (1=IPv4, 3=Domain, 4=IPv6)
//! DST.ADDR: Desired destination address
//! DST.PORT: Desired destination port
//! DATA: User data

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::modules::proxy::{Address, ConnectionId, ConnectionIdGenerator, FlowStats, Protocol};
use crate::{debug, info, error};

/// Default UDP association timeout (5 minutes)
const UDP_ASSOCIATION_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum UDP packet size
const MAX_UDP_PACKET_SIZE: usize = 65535;

/// UDP relay header size (minimum)
const UDP_RELAY_HEADER_MIN: usize = 10; // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2)

/// SOCKS5 UDP relay packet
#[derive(Debug, Clone)]
pub struct UdpRelayPacket {
    /// Fragment number (0 = no fragmentation)
    pub fragment: u8,
    /// Destination address
    pub address: Address,
    /// Payload data
    pub data: Vec<u8>,
}

impl UdpRelayPacket {
    /// Parse UDP relay packet from bytes
    pub fn parse(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < UDP_RELAY_HEADER_MIN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP packet too short",
            ));
        }

        // RSV (2 bytes) - must be 0x0000
        if buf[0] != 0 || buf[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid RSV field",
            ));
        }

        let fragment = buf[2];
        let atype = buf[3];

        let (address, data_offset) = match atype {
            0x01 => {
                // IPv4
                if buf.len() < 10 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPv4 packet too short",
                    ));
                }
                let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                (Address::Socket(SocketAddr::V4(SocketAddrV4::new(ip, port))), 10)
            }
            0x03 => {
                // Domain
                let len = buf[4] as usize;
                if buf.len() < 7 + len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Domain packet too short",
                    ));
                }
                let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
                let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
                (Address::Domain(domain, port), 7 + len)
            }
            0x04 => {
                // IPv6
                if buf.len() < 22 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPv6 packet too short",
                    ));
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[4..20]);
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([buf[20], buf[21]]);
                (Address::Socket(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))), 22)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unknown address type: {:#x}", atype),
                ));
            }
        };

        let data = buf[data_offset..].to_vec();

        Ok(Self {
            fragment,
            address,
            data,
        })
    }

    /// Serialize UDP relay packet to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.data.len() + 32);

        // RSV (2 bytes)
        buf.push(0x00);
        buf.push(0x00);

        // FRAG
        buf.push(self.fragment);

        // Address
        match &self.address {
            Address::Socket(SocketAddr::V4(addr)) => {
                buf.push(0x01); // ATYP
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::Socket(SocketAddr::V6(addr)) => {
                buf.push(0x04); // ATYP
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::Domain(domain, port) => {
                buf.push(0x03); // ATYP
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        // Data
        buf.extend_from_slice(&self.data);

        buf
    }
}

/// UDP association state
#[derive(Debug)]
pub struct UdpAssociation {
    /// Unique connection ID
    pub id: ConnectionId,
    /// Client address (who initiated the association)
    pub client_addr: SocketAddr,
    /// Relay socket for this association
    pub relay_socket: UdpSocket,
    /// Last activity timestamp
    pub last_active: Instant,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

impl UdpAssociation {
    pub fn new(id: ConnectionId, client_addr: SocketAddr) -> io::Result<Self> {
        let relay_socket = UdpSocket::bind("0.0.0.0:0")?;
        relay_socket.set_nonblocking(true)?;

        Ok(Self {
            id,
            client_addr,
            relay_socket,
            last_active: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    pub fn is_expired(&self) -> bool {
        self.last_active.elapsed() > UDP_ASSOCIATION_TIMEOUT
    }

    pub fn touch(&mut self) {
        self.last_active = Instant::now();
    }
}

/// UDP relay server for SOCKS5
pub struct UdpRelayServer {
    /// Listening socket for client requests
    socket: UdpSocket,
    /// Active associations (client_addr -> association)
    associations: Arc<Mutex<HashMap<SocketAddr, UdpAssociation>>>,
    /// ID generator
    id_generator: Arc<ConnectionIdGenerator>,
    /// Flow statistics
    flow_stats: Arc<FlowStats>,
}

impl UdpRelayServer {
    /// Create new UDP relay server bound to the given address
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            socket,
            associations: Arc::new(Mutex::new(HashMap::new())),
            id_generator: Arc::new(ConnectionIdGenerator::new()),
            flow_stats: Arc::new(FlowStats::new()),
        })
    }

    /// Get the bound address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Run the UDP relay server (blocking)
    pub fn run(&self) -> io::Result<()> {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];

        loop {
            // Cleanup expired associations periodically
            self.cleanup_expired();

            // Receive packet
            match self.socket.recv_from(&mut buf) {
                Ok((len, src_addr)) => {
                    if let Err(e) = self.handle_packet(&buf[..len], src_addr) {
                        debug!("UDP packet error from {}: {}", src_addr, e);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    error!("UDP recv error: {}", e);
                }
            }
        }
    }

    /// Handle incoming UDP packet
    fn handle_packet(&self, buf: &[u8], src_addr: SocketAddr) -> io::Result<()> {
        // Parse SOCKS5 UDP relay packet
        let packet = UdpRelayPacket::parse(buf)?;

        // Get or create association
        let mut associations = self.associations.lock().unwrap();

        let assoc = associations.entry(src_addr).or_insert_with(|| {
            let id = self.id_generator.next_udp();
            self.flow_stats.connection_opened(Protocol::Udp);
            info!("[{}] New UDP association from {}", id, src_addr);
            UdpAssociation::new(id, src_addr).expect("Failed to create UDP association")
        });

        assoc.touch();

        // Resolve target address
        let target_addr = match &packet.address {
            Address::Socket(addr) => *addr,
            Address::Domain(domain, port) => {
                use std::net::ToSocketAddrs;
                format!("{}:{}", domain, port)
                    .to_socket_addrs()?
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "Failed to resolve domain")
                    })?
            }
        };

        // Send to target
        let sent = assoc.relay_socket.send_to(&packet.data, target_addr)?;
        assoc.bytes_sent += sent as u64;
        self.flow_stats.add_sent(sent as u64);

        debug!(
            "[{}] UDP {} -> {}: {} bytes",
            assoc.id,
            src_addr,
            target_addr,
            sent
        );

        Ok(())
    }

    /// Cleanup expired associations
    fn cleanup_expired(&self) {
        let mut associations = self.associations.lock().unwrap();
        let expired: Vec<SocketAddr> = associations
            .iter()
            .filter(|(_, assoc)| assoc.is_expired())
            .map(|(addr, _)| *addr)
            .collect();

        for addr in expired {
            if let Some(assoc) = associations.remove(&addr) {
                self.flow_stats.connection_closed();
                info!(
                    "[{}] UDP association expired: {} sent, {} received",
                    assoc.id,
                    assoc.bytes_sent,
                    assoc.bytes_received
                );
            }
        }
    }
}

/// Simple UDP forwarder (for transparent proxy mode)
pub struct UdpForwarder {
    /// Source socket (client side)
    client_socket: UdpSocket,
    /// Destination address
    target_addr: SocketAddr,
}

impl UdpForwarder {
    pub fn new(listen_addr: SocketAddr, target_addr: SocketAddr) -> io::Result<Self> {
        let client_socket = UdpSocket::bind(listen_addr)?;

        Ok(Self {
            client_socket,
            target_addr,
        })
    }

    /// Forward all UDP packets to target
    pub fn run(&self) -> io::Result<()> {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];

        loop {
            let (len, src_addr) = self.client_socket.recv_from(&mut buf)?;

            // Forward to target
            let target_socket = UdpSocket::bind("0.0.0.0:0")?;
            target_socket.send_to(&buf[..len], self.target_addr)?;

            // Wait for response
            target_socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            match target_socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    self.client_socket.send_to(&buf[..len], src_addr)?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    debug!("UDP response timeout for {}", src_addr);
                }
                Err(e) => {
                    error!("UDP forward error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_packet_parse_ipv4() {
        // RSV(0x0000) + FRAG(0x00) + ATYP(0x01) + IPv4(127.0.0.1) + PORT(8080) + DATA
        let buf = [
            0x00, 0x00, // RSV
            0x00, // FRAG
            0x01, // ATYP (IPv4)
            127, 0, 0, 1, // IP
            0x1F, 0x90, // Port (8080)
            0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
        ];

        let packet = UdpRelayPacket::parse(&buf).unwrap();

        assert_eq!(packet.fragment, 0);
        assert_eq!(
            packet.address,
            Address::Socket("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(packet.data, b"Hello");
    }

    #[test]
    fn test_udp_packet_parse_domain() {
        // RSV(0x0000) + FRAG(0x00) + ATYP(0x03) + LEN(11) + "example.com" + PORT(443) + DATA
        let buf = [
            0x00, 0x00, // RSV
            0x00, // FRAG
            0x03, // ATYP (Domain)
            11,   // Domain length
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xBB, // Port (443)
            0x48, 0x69, // "Hi"
        ];

        let packet = UdpRelayPacket::parse(&buf).unwrap();

        assert_eq!(packet.fragment, 0);
        assert_eq!(packet.address, Address::Domain("example.com".to_string(), 443));
        assert_eq!(packet.data, b"Hi");
    }

    #[test]
    fn test_udp_packet_serialize_roundtrip() {
        let original = UdpRelayPacket {
            fragment: 0,
            address: Address::Socket("192.168.1.1:8080".parse().unwrap()),
            data: b"Test data".to_vec(),
        };

        let serialized = original.serialize();
        let parsed = UdpRelayPacket::parse(&serialized).unwrap();

        assert_eq!(parsed.fragment, original.fragment);
        assert_eq!(parsed.address, original.address);
        assert_eq!(parsed.data, original.data);
    }
}
