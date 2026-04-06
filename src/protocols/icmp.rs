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
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::{io, mem, ptr};

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
    #[cfg(unix)]
    {
      self.ping_once_unix(sequence)
    }

    #[cfg(not(unix))]
    {
      Err("ICMP raw sockets are not supported on this platform".to_string())
    }
  }

  /// Ping multiple times and collect statistics
  pub fn ping(&self, count: usize, interval: Duration) -> Result<PingStatistics, String> {
    let mut stats = PingStatistics::new();
    let mut rtts = Vec::new();
    let start_time = Instant::now();

    for seq in 0..count {
      let result = self.ping_once(seq as u16);

      let ping_result = match result {
        Ok(ping_result) => ping_result,
        Err(err) => return Err(err),
      };

      stats.update(&ping_result);
      if ping_result.success {
        rtts.push(ping_result.rtt);
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

#[cfg(unix)]
impl IcmpPinger {
  fn ping_once_unix(&self, sequence: u16) -> Result<PingResult, String> {
    let target = match self.target {
      IpAddr::V4(addr) => addr,
      IpAddr::V6(_) => {
        return Err("ICMPv6 echo is not implemented yet".to_string());
      }
    };

    let socket = RawSocket::open()?;
    let packet = IcmpEchoPacket::new_echo_request(self.identifier, sequence, self.packet_size);
    let bytes = packet.to_bytes();

    let mut addr = libc::sockaddr_in {
      sin_family: libc::AF_INET as u16,
      sin_port: 0,
      sin_addr: libc::in_addr {
        s_addr: u32::from_be_bytes(target.octets()),
      },
      sin_zero: [0; 8],
    };

    let start = Instant::now();
    let sent = unsafe {
      libc::sendto(
        socket.fd,
        bytes.as_ptr() as *const _,
        bytes.len(),
        0,
        &mut addr as *mut _ as *mut libc::sockaddr,
        mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
      )
    };

    if sent < 0 {
      return Err(format!("Failed to send ICMP packet: {}", last_io_error()));
    }

    let deadline = start + self.timeout;
    let mut buffer = [0u8; 1500];

    loop {
      let remaining = deadline.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        return Ok(PingResult {
          sequence,
          rtt: self.timeout,
          ttl: 0,
          success: false,
          error: Some("Request timed out".to_string()),
        });
      }

      let ready = poll_readable(socket.fd, remaining);
      if ready == 0 {
        return Ok(PingResult {
          sequence,
          rtt: self.timeout,
          ttl: 0,
          success: false,
          error: Some("Request timed out".to_string()),
        });
      }
      if ready < 0 {
        return Err(format!("ICMP poll failed: {}", last_io_error()));
      }

      let received = unsafe {
        libc::recvfrom(
          socket.fd,
          buffer.as_mut_ptr() as *mut _,
          buffer.len(),
          0,
          ptr::null_mut(),
          ptr::null_mut(),
        )
      };
      if received < 0 {
        let err = last_io_error();
        if is_timeout_error(&err) {
          return Ok(PingResult {
            sequence,
            rtt: self.timeout,
            ttl: 0,
            success: false,
            error: Some("Request timed out".to_string()),
          });
        }
        return Err(format!("ICMP receive failed: {}", err));
      }

      let received = received as usize;
      if received < 20 {
        continue;
      }

      let header_len = (buffer[0] & 0x0F) as usize * 4;
      if header_len < 20 || header_len >= received {
        continue;
      }

      let ttl = buffer[8];
      let icmp_bytes = &buffer[header_len..received];
      let reply = match IcmpEchoPacket::from_bytes(icmp_bytes) {
        Ok(reply) => reply,
        Err(_) => continue,
      };

      if reply.icmp_type != IcmpType::EchoReply as u8 {
        continue;
      }
      if reply.identifier != self.identifier || reply.sequence != sequence {
        continue;
      }
      if !reply.verify_checksum() {
        continue;
      }

      let rtt = start.elapsed();
      return Ok(PingResult {
        sequence,
        rtt,
        ttl,
        success: true,
        error: None,
      });
    }
  }
}

#[cfg(unix)]
struct RawSocket {
  fd: RawFd,
}

#[cfg(unix)]
impl RawSocket {
  fn open() -> Result<Self, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
      let err = last_io_error();
      return Err(classify_socket_error(&err));
    }
    Ok(Self { fd })
  }
}

#[cfg(unix)]
impl Drop for RawSocket {
  fn drop(&mut self) {
    unsafe {
      libc::close(self.fd);
    }
  }
}

#[cfg(unix)]
fn poll_readable(fd: RawFd, timeout: Duration) -> i32 {
  let mut fds = libc::pollfd {
    fd,
    events: libc::POLLIN,
    revents: 0,
  };
  let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
  unsafe { libc::poll(&mut fds, 1, timeout_ms) }
}

#[cfg(unix)]
fn last_io_error() -> io::Error {
  io::Error::last_os_error()
}

#[cfg(unix)]
fn is_timeout_error(err: &io::Error) -> bool {
  matches!(
      err.raw_os_error(),
      Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK
  )
}

#[cfg(unix)]
fn classify_socket_error(err: &io::Error) -> String {
  match err.raw_os_error() {
    Some(libc::EPERM) | Some(libc::EACCES) => {
      "ICMP requires raw socket privileges (root/CAP_NET_RAW)".to_string()
    }
    _ => format!("Failed to open raw ICMP socket: {}", err),
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

  #[test]
  #[cfg(unix)]
  fn test_permission_error_mapping() {
    let err = std::io::Error::from_raw_os_error(libc::EACCES);
    assert!(classify_socket_error(&err).contains("raw socket"));
  }
}
