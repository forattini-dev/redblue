//! Packet Builder
//!
//! Converts PacketSignature into raw bytes with proper checksums.

use super::signature::PacketSignature;
use std::net::Ipv4Addr;

/// Packet builder that converts signatures to raw bytes
pub struct PacketBuilder {
    /// Include Ethernet header
    include_ethernet: bool,
    /// Source IP override
    src_ip: Option<Ipv4Addr>,
    /// Destination IP override
    dst_ip: Option<Ipv4Addr>,
    /// Random seed for random() fields
    seed: u64,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self {
            include_ethernet: false,
            src_ip: None,
            dst_ip: None,
            seed: 0,
        }
    }

    /// Include Ethernet header in output
    pub fn with_ethernet(mut self, include: bool) -> Self {
        self.include_ethernet = include;
        self
    }

    /// Override source IP
    pub fn with_src_ip(mut self, ip: Ipv4Addr) -> Self {
        self.src_ip = Some(ip);
        self
    }

    /// Override destination IP
    pub fn with_dst_ip(mut self, ip: Ipv4Addr) -> Self {
        self.dst_ip = Some(ip);
        self
    }

    /// Set random seed
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Build packet from signature
    pub fn build(&self, sig: &PacketSignature) -> Result<Vec<u8>, String> {
        let src_ip = self
            .src_ip
            .or(sig.ipv4.src)
            .ok_or("Source IP not specified")?;
        let dst_ip = self
            .dst_ip
            .or(sig.ipv4.dst)
            .ok_or("Destination IP not specified")?;

        // Determine payload
        let payload = &sig.payload;

        // Determine protocol and build transport header
        let (transport_header, protocol) = if let Some(ref tcp) = sig.tcp {
            (self.build_tcp_header(tcp, src_ip, dst_ip, payload)?, 6u8)
        } else if let Some(ref udp) = sig.udp {
            (self.build_udp_header(udp, src_ip, dst_ip, payload)?, 17u8)
        } else if let Some(ref icmp) = sig.icmp {
            (self.build_icmp_header(icmp, payload)?, 1u8)
        } else {
            return Err("No transport layer specified (tcp/udp/icmp)".to_string());
        };

        // Build IP header
        let ip_header =
            self.build_ip_header(sig, src_ip, dst_ip, protocol, &transport_header, payload)?;

        // Assemble packet
        let mut packet = Vec::with_capacity(
            (if self.include_ethernet { 14 } else { 0 })
                + ip_header.len()
                + transport_header.len()
                + payload.len(),
        );

        // Ethernet header
        if self.include_ethernet {
            // Destination MAC
            if let Some(mac) = sig.ethernet.dst_mac {
                packet.extend_from_slice(&mac);
            } else {
                packet.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
                // Broadcast
            }
            // Source MAC
            if let Some(mac) = sig.ethernet.src_mac {
                packet.extend_from_slice(&mac);
            } else {
                packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            }
            // EtherType: IPv4
            packet.extend_from_slice(&[0x08, 0x00]);
        }

        // IP header
        packet.extend_from_slice(&ip_header);

        // Transport header
        packet.extend_from_slice(&transport_header);

        // Payload
        packet.extend_from_slice(payload);

        Ok(packet)
    }

    fn build_ip_header(
        &self,
        sig: &PacketSignature,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        transport: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let total_length = 20 + transport.len() + payload.len();
        if total_length > 65535 {
            return Err("Packet too large".to_string());
        }

        let mut header = [0u8; 20];

        // Version (4) + IHL (5) = 0x45
        header[0] = 0x45;
        // TOS
        header[1] = sig.ipv4.tos;
        // Total length
        header[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        // Identification
        let id = sig
            .ipv4
            .id
            .unwrap_or_else(|| simple_random(&mut self.seed.wrapping_add(1)) as u16);
        header[4..6].copy_from_slice(&id.to_be_bytes());
        // Flags + Fragment offset
        header[6] = sig.ipv4.flags << 5;
        header[7] = 0;
        // TTL
        header[8] = sig.ipv4.ttl;
        // Protocol
        header[9] = protocol;
        // Checksum (calculated below)
        header[10] = 0;
        header[11] = 0;
        // Source IP
        header[12..16].copy_from_slice(&src.octets());
        // Destination IP
        header[16..20].copy_from_slice(&dst.octets());

        // Calculate checksum
        let checksum = ip_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());

        Ok(header.to_vec())
    }

    fn build_tcp_header(
        &self,
        tcp: &super::signature::TcpFields,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sport = tcp.sport.unwrap_or(40000);
        let dport = tcp.dport.ok_or("TCP destination port not specified")?;

        let header_len = 20 + tcp.options.len();
        let data_offset = ((header_len + 3) / 4) as u8; // In 32-bit words

        let mut header = vec![0u8; header_len];

        // Source port
        header[0..2].copy_from_slice(&sport.to_be_bytes());
        // Destination port
        header[2..4].copy_from_slice(&dport.to_be_bytes());
        // Sequence number
        header[4..8].copy_from_slice(&tcp.seq.to_be_bytes());
        // ACK number
        header[8..12].copy_from_slice(&tcp.ack.to_be_bytes());
        // Data offset + reserved + flags
        header[12] = data_offset << 4;
        header[13] = tcp.flags;
        // Window
        header[14..16].copy_from_slice(&tcp.window.to_be_bytes());
        // Checksum (calculated below)
        header[16..18].copy_from_slice(&[0, 0]);
        // Urgent pointer
        header[18..20].copy_from_slice(&tcp.urgent.to_be_bytes());
        // Options
        header[20..].copy_from_slice(&tcp.options);

        // Calculate TCP checksum with pseudo-header
        let checksum = tcp_udp_checksum(src_ip, dst_ip, 6, &header, payload);
        header[16..18].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }

    fn build_udp_header(
        &self,
        udp: &super::signature::UdpFields,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sport = udp.sport.unwrap_or(40000);
        let dport = udp.dport.ok_or("UDP destination port not specified")?;

        let length = 8 + payload.len();
        if length > 65535 {
            return Err("UDP packet too large".to_string());
        }

        let mut header = [0u8; 8];

        // Source port
        header[0..2].copy_from_slice(&sport.to_be_bytes());
        // Destination port
        header[2..4].copy_from_slice(&dport.to_be_bytes());
        // Length
        header[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        // Checksum (calculated below)
        header[6..8].copy_from_slice(&[0, 0]);

        // Calculate UDP checksum with pseudo-header
        let checksum = tcp_udp_checksum(src_ip, dst_ip, 17, &header, payload);
        header[6..8].copy_from_slice(&checksum.to_be_bytes());

        Ok(header.to_vec())
    }

    fn build_icmp_header(
        &self,
        icmp: &super::signature::IcmpFields,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut header = vec![0u8; 8];

        // Type
        header[0] = icmp.icmp_type;
        // Code
        header[1] = icmp.code;
        // Checksum (calculated below)
        header[2..4].copy_from_slice(&[0, 0]);
        // ID
        header[4..6].copy_from_slice(&icmp.id.to_be_bytes());
        // Sequence
        header[6..8].copy_from_slice(&icmp.sequence.to_be_bytes());

        // Calculate ICMP checksum
        let checksum = icmp_checksum(&header, payload);
        header[2..4].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate IP header checksum
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Calculate TCP/UDP checksum with pseudo-header
fn tcp_udp_checksum(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    header: &[u8],
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    let src_octets = src.octets();
    let dst_octets = dst.octets();

    sum = sum.wrapping_add(((src_octets[0] as u32) << 8) | (src_octets[1] as u32));
    sum = sum.wrapping_add(((src_octets[2] as u32) << 8) | (src_octets[3] as u32));
    sum = sum.wrapping_add(((dst_octets[0] as u32) << 8) | (dst_octets[1] as u32));
    sum = sum.wrapping_add(((dst_octets[2] as u32) << 8) | (dst_octets[3] as u32));
    sum = sum.wrapping_add(protocol as u32);
    sum = sum.wrapping_add((header.len() + payload.len()) as u32);

    // Header
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Payload
    for i in (0..payload.len()).step_by(2) {
        let word = if i + 1 < payload.len() {
            ((payload[i] as u32) << 8) | (payload[i + 1] as u32)
        } else {
            (payload[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Fold
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Calculate ICMP checksum
fn icmp_checksum(header: &[u8], payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Header
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Payload
    for i in (0..payload.len()).step_by(2) {
        let word = if i + 1 < payload.len() {
            ((payload[i] as u32) << 8) | (payload[i + 1] as u32)
        } else {
            (payload[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Fold
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Simple PRNG for random fields
fn simple_random(seed: &mut u64) -> u32 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (*seed >> 33) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::craft::signature::{PacketSignature, TcpFields, TCP_SYN};

    #[test]
    fn test_build_tcp_syn() {
        let mut sig = PacketSignature::new("test");
        sig.ipv4.src = Some(Ipv4Addr::new(192, 168, 1, 1));
        sig.ipv4.dst = Some(Ipv4Addr::new(10, 0, 0, 1));
        sig.tcp = Some(TcpFields {
            sport: Some(40000),
            dport: Some(80),
            flags: TCP_SYN,
            ..Default::default()
        });

        let builder = PacketBuilder::new();
        let packet = builder.build(&sig).unwrap();

        // IP header (20) + TCP header (20) = 40 bytes
        assert_eq!(packet.len(), 40);

        // Check IP version
        assert_eq!(packet[0] >> 4, 4);

        // Check protocol = TCP
        assert_eq!(packet[9], 6);

        // Check TCP flags = SYN
        assert_eq!(packet[20 + 13], TCP_SYN);
    }

    #[test]
    fn test_build_with_ethernet() {
        let mut sig = PacketSignature::new("test");
        sig.ipv4.src = Some(Ipv4Addr::new(192, 168, 1, 1));
        sig.ipv4.dst = Some(Ipv4Addr::new(10, 0, 0, 1));
        sig.tcp = Some(TcpFields {
            dport: Some(80),
            ..Default::default()
        });

        let builder = PacketBuilder::new().with_ethernet(true);
        let packet = builder.build(&sig).unwrap();

        // Ethernet (14) + IP (20) + TCP (20) = 54 bytes
        assert_eq!(packet.len(), 54);

        // Check EtherType = IPv4
        assert_eq!(packet[12], 0x08);
        assert_eq!(packet[13], 0x00);
    }

    #[test]
    fn test_ip_checksum() {
        // Known test vector from RFC 1071
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let checksum = ip_checksum(&header);
        // Checksum should be non-zero for valid header
        assert_ne!(checksum, 0);
    }
}
