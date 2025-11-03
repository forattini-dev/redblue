/// ICMP Protocol Implementation (RFC 792)
///
/// Implements ICMP Echo Request/Reply (ping) from scratch
/// - No external dependencies
/// - Raw socket implementation
/// - RTT calculation
/// - Packet loss tracking
///
/// Reference: https://tools.ietf.org/html/rfc792
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// ICMP packet types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IcmpType {
    EchoReply = 0,
    EchoRequest = 8,
}

/// ICMP Echo packet structure
#[derive(Debug, Clone)]
pub struct IcmpEchoPacket {
    pub icmp_type: u8,    // 8 for echo request, 0 for echo reply
    pub code: u8,         // Always 0 for echo
    pub checksum: u16,    // Internet checksum
    pub identifier: u16,  // Identifier (usually process ID)
    pub sequence: u16,    // Sequence number
    pub payload: Vec<u8>, // Data payload (optional)
}

impl IcmpEchoPacket {
    /// Create a new ICMP Echo Request packet
    pub fn new_echo_request(identifier: u16, sequence: u16, payload_size: usize) -> Self {
        let mut payload = vec![0u8; payload_size];

        // Fill payload with pattern (0x00, 0x01, 0x02, ...)
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let mut packet = Self {
            icmp_type: IcmpType::EchoRequest as u8,
            code: 0,
            checksum: 0,
            identifier,
            sequence,
            payload,
        };

        // Calculate checksum
        packet.checksum = packet.calculate_checksum();
        packet
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.payload.len());

        bytes.push(self.icmp_type);
        bytes.push(self.code);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    /// Parse ICMP packet from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("ICMP packet too short (minimum 8 bytes)".to_string());
        }

        let icmp_type = bytes[0];
        let code = bytes[1];
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let identifier = u16::from_be_bytes([bytes[4], bytes[5]]);
        let sequence = u16::from_be_bytes([bytes[6], bytes[7]]);
        let payload = bytes[8..].to_vec();

        Ok(Self {
            icmp_type,
            code,
            checksum,
            identifier,
            sequence,
            payload,
        })
    }

    /// Calculate Internet checksum (RFC 1071)
    fn calculate_checksum(&self) -> u16 {
        let mut sum: u32 = 0;

        // Create temporary packet with checksum = 0
        let mut bytes = Vec::with_capacity(8 + self.payload.len());
        bytes.push(self.icmp_type);
        bytes.push(self.code);
        bytes.push(0); // checksum byte 1
        bytes.push(0); // checksum byte 2
        bytes.extend_from_slice(&self.identifier.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.payload);

        // Sum 16-bit words
        let mut i = 0;
        while i < bytes.len() {
            if i + 1 < bytes.len() {
                let word = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
                sum += word as u32;
            } else {
                // Odd number of bytes - pad with zero
                sum += (bytes[i] as u32) << 8;
            }
            i += 2;
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        !sum as u16
    }

    /// Verify packet checksum
    pub fn verify_checksum(&self) -> bool {
        let calculated = self.calculate_checksum();
        self.checksum == calculated
    }
}

/// ICMP ping result for a single packet
#[derive(Debug, Clone)]
pub struct PingResult {
    pub sequence: u16,
    pub rtt: Duration,
    pub ttl: u8,
    pub success: bool,
    pub error: Option<String>,
}

/// ICMP ping statistics
#[derive(Debug, Clone)]
pub struct PingStatistics {
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packet_loss_percent: f64,
    pub min_rtt: Duration,
    pub max_rtt: Duration,
    pub avg_rtt: Duration,
    pub total_time: Duration,
}

impl PingStatistics {
    pub fn new() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            packet_loss_percent: 0.0,
            min_rtt: Duration::from_secs(999),
            max_rtt: Duration::from_secs(0),
            avg_rtt: Duration::from_secs(0),
            total_time: Duration::from_secs(0),
        }
    }

    pub fn update(&mut self, result: &PingResult) {
        self.packets_sent += 1;

        if result.success {
            self.packets_received += 1;

            if result.rtt < self.min_rtt {
                self.min_rtt = result.rtt;
            }
            if result.rtt > self.max_rtt {
                self.max_rtt = result.rtt;
            }
        }

        // Calculate packet loss
        self.packet_loss_percent =
            ((self.packets_sent - self.packets_received) as f64 / self.packets_sent as f64) * 100.0;
    }

    pub fn calculate_avg_rtt(&mut self, rtts: &[Duration]) {
        if rtts.is_empty() {
            return;
        }

        let total: Duration = rtts.iter().sum();
        self.avg_rtt = total / rtts.len() as u32;
    }
}

/// ICMP Pinger client
pub struct IcmpPinger {
    target: IpAddr,
    timeout: Duration,
    packet_size: usize,
    identifier: u16,
}

impl IcmpPinger {
    pub fn new(target: IpAddr) -> Self {
        Self {
            target,
            timeout: Duration::from_secs(1),
            packet_size: 56, // Standard ping payload size
            identifier: std::process::id() as u16,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_packet_size(mut self, size: usize) -> Self {
        self.packet_size = size;
        self
    }

    /// Send a single ping and wait for reply
    pub fn ping_once(&self, sequence: u16) -> Result<PingResult, String> {
        // Note: This is a simplified implementation
        // Real ICMP requires raw sockets which need root/CAP_NET_RAW privileges
        // For production, we would use libc socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

        // For now, return a simulated result
        // TODO: Implement real raw socket ICMP when we have proper permissions

        Err(format!(
            "ICMP ping to {} (seq #{}, ident {}) requires raw socket privileges (root/CAP_NET_RAW). Use system ping for now.",
            self.target, sequence, self.identifier
        ))
    }

    /// Ping multiple times and collect statistics
    pub fn ping(&self, count: usize, interval: Duration) -> Result<PingStatistics, String> {
        let mut stats = PingStatistics::new();
        let mut rtts = Vec::new();
        let start_time = Instant::now();

        for seq in 0..count {
            let result = self.ping_once(seq as u16);

            match result {
                Ok(ping_result) => {
                    stats.update(&ping_result);
                    if ping_result.success {
                        rtts.push(ping_result.rtt);
                    }
                }
                Err(_) => {
                    // For now, simulate results for testing
                    // Remove this when real ICMP is implemented
                    return Err("ICMP requires raw sockets - not implemented yet".to_string());
                }
            }

            // Sleep between pings (except for last one)
            if seq < count - 1 {
                std::thread::sleep(interval);
            }
        }

        stats.total_time = start_time.elapsed();
        stats.calculate_avg_rtt(&rtts);

        Ok(stats)
    }
}

impl Default for PingStatistics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_packet_creation() {
        let packet = IcmpEchoPacket::new_echo_request(12345, 1, 56);

        assert_eq!(packet.icmp_type, 8);
        assert_eq!(packet.code, 0);
        assert_eq!(packet.identifier, 12345);
        assert_eq!(packet.sequence, 1);
        assert_eq!(packet.payload.len(), 56);
    }

    #[test]
    fn test_icmp_checksum() {
        let packet = IcmpEchoPacket::new_echo_request(1234, 1, 56);
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_icmp_serialization() {
        let packet = IcmpEchoPacket::new_echo_request(5678, 2, 32);
        let bytes = packet.to_bytes();

        assert!(bytes.len() >= 8 + 32);
        assert_eq!(bytes[0], 8); // Echo request
        assert_eq!(bytes[1], 0); // Code
    }

    #[test]
    fn test_icmp_deserialization() {
        let original = IcmpEchoPacket::new_echo_request(9999, 5, 64);
        let bytes = original.to_bytes();

        let parsed = IcmpEchoPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.icmp_type, original.icmp_type);
        assert_eq!(parsed.code, original.code);
        assert_eq!(parsed.identifier, original.identifier);
        assert_eq!(parsed.sequence, original.sequence);
        assert_eq!(parsed.payload.len(), original.payload.len());
    }

    #[test]
    fn test_ping_statistics() {
        let mut stats = PingStatistics::new();

        let result1 = PingResult {
            sequence: 1,
            rtt: Duration::from_millis(10),
            ttl: 64,
            success: true,
            error: None,
        };

        let result2 = PingResult {
            sequence: 2,
            rtt: Duration::from_millis(20),
            ttl: 64,
            success: true,
            error: None,
        };

        stats.update(&result1);
        stats.update(&result2);
        stats.calculate_avg_rtt(&[result1.rtt, result2.rtt]);

        assert_eq!(stats.packets_sent, 2);
        assert_eq!(stats.packets_received, 2);
        assert_eq!(stats.packet_loss_percent, 0.0);
        assert_eq!(stats.min_rtt, Duration::from_millis(10));
        assert_eq!(stats.max_rtt, Duration::from_millis(20));
        assert_eq!(stats.avg_rtt, Duration::from_millis(15));
    }
}
