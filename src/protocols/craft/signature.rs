//! Packet Signature Types
//!
//! Defines the structure of packet signatures for crafting.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A complete packet signature
#[derive(Debug, Clone, Default)]
pub struct PacketSignature {
  /// Signature name/identifier
  pub name: String,
  /// Description of what this signature does
  pub description: String,
  /// Category (DoS, DDoS, Backdoor, etc.)
  pub category: String,
  /// Ethernet layer fields
  pub ethernet: EthernetFields,
  /// IPv4 layer fields
  pub ipv4: Ipv4Fields,
  /// TCP layer fields (if TCP)
  pub tcp: Option<TcpFields>,
  /// UDP layer fields (if UDP)
  pub udp: Option<UdpFields>,
  /// ICMP layer fields (if ICMP)
  pub icmp: Option<IcmpFields>,
  /// Raw payload
  pub payload: Vec<u8>,
  /// Variables for dynamic substitution
  pub variables: HashMap<String, String>,
}

/// Ethernet layer fields
#[derive(Debug, Clone, Default)]
pub struct EthernetFields {
  /// Source MAC address (6 bytes)
  pub src_mac: Option<[u8; 6]>,
  /// Destination MAC address (6 bytes)
  pub dst_mac: Option<[u8; 6]>,
  /// EtherType (0x0800 for IPv4)
  pub ether_type: Option<u16>,
}

/// IPv4 layer fields
#[derive(Debug, Clone)]
pub struct Ipv4Fields {
  /// Source IP address
  pub src: Option<Ipv4Addr>,
  /// Destination IP address
  pub dst: Option<Ipv4Addr>,
  /// Time to Live
  pub ttl: u8,
  /// Protocol (6=TCP, 17=UDP, 1=ICMP)
  pub protocol: u8,
  /// Identification field
  pub id: Option<u16>,
  /// Flags (DF, MF)
  pub flags: u8,
  /// Type of Service
  pub tos: u8,
}

impl Default for Ipv4Fields {
  fn default() -> Self {
    Self {
      src: None,
      dst: None,
      ttl: 64,
      protocol: 6, // TCP by default
      id: None,
      flags: 0x02, // Don't Fragment
      tos: 0,
    }
  }
}

/// TCP layer fields
#[derive(Debug, Clone)]
pub struct TcpFields {
  /// Source port
  pub sport: Option<u16>,
  /// Destination port
  pub dport: Option<u16>,
  /// Sequence number
  pub seq: u32,
  /// Acknowledgment number
  pub ack: u32,
  /// TCP flags (SYN, ACK, FIN, RST, PSH, URG)
  pub flags: u8,
  /// Window size
  pub window: u16,
  /// Urgent pointer
  pub urgent: u16,
  /// TCP options
  pub options: Vec<u8>,
}

impl Default for TcpFields {
  fn default() -> Self {
    Self {
      sport: None,
      dport: None,
      seq: 0,
      ack: 0,
      flags: 0x02, // SYN
      window: 65535,
      urgent: 0,
      options: Vec::new(),
    }
  }
}

/// UDP layer fields
#[derive(Debug, Clone, Default)]
pub struct UdpFields {
  /// Source port
  pub sport: Option<u16>,
  /// Destination port
  pub dport: Option<u16>,
}

/// ICMP layer fields
#[derive(Debug, Clone)]
pub struct IcmpFields {
  /// ICMP type
  pub icmp_type: u8,
  /// ICMP code
  pub code: u8,
  /// ICMP ID (for echo)
  pub id: u16,
  /// ICMP sequence (for echo)
  pub sequence: u16,
}

impl Default for IcmpFields {
  fn default() -> Self {
    Self {
      icmp_type: 8, // Echo Request
      code: 0,
      id: 0,
      sequence: 0,
    }
  }
}

/// Layer field identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LayerField {
  // Ethernet
  EthSrc,
  EthDst,
  EthType,
  // IPv4
  IpSrc,
  IpDst,
  IpTtl,
  IpProto,
  IpId,
  IpFlags,
  IpTos,
  // TCP
  TcpSport,
  TcpDport,
  TcpSeq,
  TcpAck,
  TcpFlags,
  TcpWindow,
  TcpUrgent,
  // UDP
  UdpSport,
  UdpDport,
  // ICMP
  IcmpType,
  IcmpCode,
  IcmpId,
  IcmpSeq,
  // Payload
  Payload,
  PayloadHex,
}

impl LayerField {
  /// Parse a field name string
  pub fn from_str(s: &str) -> Option<Self> {
    match s.to_lowercase().as_str() {
      "eth.src" | "ethernet.src" => Some(Self::EthSrc),
      "eth.dst" | "ethernet.dst" => Some(Self::EthDst),
      "eth.type" | "ethernet.type" => Some(Self::EthType),
      "ip.src" | "ipv4.src" => Some(Self::IpSrc),
      "ip.dst" | "ipv4.dst" => Some(Self::IpDst),
      "ip.ttl" | "ipv4.ttl" => Some(Self::IpTtl),
      "ip.proto" | "ipv4.proto" | "ip.protocol" => Some(Self::IpProto),
      "ip.id" | "ipv4.id" => Some(Self::IpId),
      "ip.flags" | "ipv4.flags" => Some(Self::IpFlags),
      "ip.tos" | "ipv4.tos" => Some(Self::IpTos),
      "tcp.sport" | "tcp.srcport" => Some(Self::TcpSport),
      "tcp.dport" | "tcp.dstport" => Some(Self::TcpDport),
      "tcp.seq" | "tcp.sequence" => Some(Self::TcpSeq),
      "tcp.ack" => Some(Self::TcpAck),
      "tcp.flags" => Some(Self::TcpFlags),
      "tcp.window" | "tcp.win" => Some(Self::TcpWindow),
      "tcp.urgent" | "tcp.urg" => Some(Self::TcpUrgent),
      "udp.sport" | "udp.srcport" => Some(Self::UdpSport),
      "udp.dport" | "udp.dstport" => Some(Self::UdpDport),
      "icmp.type" => Some(Self::IcmpType),
      "icmp.code" => Some(Self::IcmpCode),
      "icmp.id" => Some(Self::IcmpId),
      "icmp.seq" | "icmp.sequence" => Some(Self::IcmpSeq),
      "payload" | "data" => Some(Self::Payload),
      "payload_hex" | "data_hex" => Some(Self::PayloadHex),
      _ => None,
    }
  }
}

/// Field value types
#[derive(Debug, Clone)]
pub enum FieldValue {
  /// IPv4 address
  Ipv4(Ipv4Addr),
  /// MAC address
  Mac([u8; 6]),
  /// 8-bit unsigned
  U8(u8),
  /// 16-bit unsigned
  U16(u16),
  /// 32-bit unsigned
  U32(u32),
  /// String value
  String(String),
  /// Raw bytes
  Bytes(Vec<u8>),
  /// TCP flags (SYN, ACK, etc.)
  TcpFlags(u8),
  /// Variable reference ($varname)
  Variable(String),
}

impl PacketSignature {
  /// Create a new empty signature
  pub fn new(name: &str) -> Self {
    Self {
      name: name.to_string(),
      ..Default::default()
    }
  }

  /// Set a field value
  pub fn set_field(&mut self, field: LayerField, value: FieldValue) -> Result<(), String> {
    match field {
      LayerField::EthSrc => {
        if let FieldValue::Mac(mac) = value {
          self.ethernet.src_mac = Some(mac);
        } else {
          return Err("Expected MAC address for eth.src".to_string());
        }
      }
      LayerField::EthDst => {
        if let FieldValue::Mac(mac) = value {
          self.ethernet.dst_mac = Some(mac);
        } else {
          return Err("Expected MAC address for eth.dst".to_string());
        }
      }
      LayerField::EthType => {
        if let FieldValue::U16(v) = value {
          self.ethernet.ether_type = Some(v);
        } else {
          return Err("Expected u16 for eth.type".to_string());
        }
      }
      LayerField::IpSrc => {
        if let FieldValue::Ipv4(ip) = value {
          self.ipv4.src = Some(ip);
        } else {
          return Err("Expected IPv4 for ip.src".to_string());
        }
      }
      LayerField::IpDst => {
        if let FieldValue::Ipv4(ip) = value {
          self.ipv4.dst = Some(ip);
        } else {
          return Err("Expected IPv4 for ip.dst".to_string());
        }
      }
      LayerField::IpTtl => {
        if let FieldValue::U8(v) = value {
          self.ipv4.ttl = v;
        } else {
          return Err("Expected u8 for ip.ttl".to_string());
        }
      }
      LayerField::IpProto => {
        if let FieldValue::U8(v) = value {
          self.ipv4.protocol = v;
        } else {
          return Err("Expected u8 for ip.proto".to_string());
        }
      }
      LayerField::IpId => {
        if let FieldValue::U16(v) = value {
          self.ipv4.id = Some(v);
        } else {
          return Err("Expected u16 for ip.id".to_string());
        }
      }
      LayerField::IpFlags => {
        if let FieldValue::U8(v) = value {
          self.ipv4.flags = v;
        } else {
          return Err("Expected u8 for ip.flags".to_string());
        }
      }
      LayerField::IpTos => {
        if let FieldValue::U8(v) = value {
          self.ipv4.tos = v;
        } else {
          return Err("Expected u8 for ip.tos".to_string());
        }
      }
      LayerField::TcpSport => {
        let tcp = self.tcp.get_or_insert_with(TcpFields::default);
        if let FieldValue::U16(v) = value {
          tcp.sport = Some(v);
        } else {
          return Err("Expected u16 for tcp.sport".to_string());
        }
      }
      LayerField::TcpDport => {
        let tcp = self.tcp.get_or_insert_with(TcpFields::default);
        if let FieldValue::U16(v) = value {
          tcp.dport = Some(v);
        } else {
          return Err("Expected u16 for tcp.dport".to_string());
        }
      }
      LayerField::TcpSeq => {
        let tcp = self.tcp.get_or_insert_with(TcpFields::default);
        if let FieldValue::U32(v) = value {
          tcp.seq = v;
        } else {
          return Err("Expected u32 for tcp.seq".to_string());
        }
      }
      LayerField::TcpAck => {
        let tcp = self.tcp.get_or_insert_with(TcpFields::default);
        if let FieldValue::U32(v) = value {
          tcp.ack = v;
        } else {
          return Err("Expected u32 for tcp.ack".to_string());
        }
      }
      LayerField::TcpFlags => {
        let tcp = self.tcp.get_or_insert_with(TcpFields::default);
        if let FieldValue::TcpFlags(v) = value {
          tcp.flags = v;
        } else if let FieldValue::U8(v) = value {
          tcp.flags = v;
        } else {
          return Err("Expected flags for tcp.flags".to_string());
        }
      }
      LayerField::TcpWindow => {
        let tcp = self.tcp.get_or_insert_with(TcpFields::default);
        if let FieldValue::U16(v) = value {
          tcp.window = v;
        } else {
          return Err("Expected u16 for tcp.window".to_string());
        }
      }
      LayerField::TcpUrgent => {
        let tcp = self.tcp.get_or_insert_with(TcpFields::default);
        if let FieldValue::U16(v) = value {
          tcp.urgent = v;
        } else {
          return Err("Expected u16 for tcp.urgent".to_string());
        }
      }
      LayerField::UdpSport => {
        let udp = self.udp.get_or_insert_with(UdpFields::default);
        if let FieldValue::U16(v) = value {
          udp.sport = Some(v);
        } else {
          return Err("Expected u16 for udp.sport".to_string());
        }
      }
      LayerField::UdpDport => {
        let udp = self.udp.get_or_insert_with(UdpFields::default);
        if let FieldValue::U16(v) = value {
          udp.dport = Some(v);
        } else {
          return Err("Expected u16 for udp.dport".to_string());
        }
      }
      LayerField::IcmpType => {
        let icmp = self.icmp.get_or_insert_with(IcmpFields::default);
        if let FieldValue::U8(v) = value {
          icmp.icmp_type = v;
        } else {
          return Err("Expected u8 for icmp.type".to_string());
        }
      }
      LayerField::IcmpCode => {
        let icmp = self.icmp.get_or_insert_with(IcmpFields::default);
        if let FieldValue::U8(v) = value {
          icmp.code = v;
        } else {
          return Err("Expected u8 for icmp.code".to_string());
        }
      }
      LayerField::IcmpId => {
        let icmp = self.icmp.get_or_insert_with(IcmpFields::default);
        if let FieldValue::U16(v) = value {
          icmp.id = v;
        } else {
          return Err("Expected u16 for icmp.id".to_string());
        }
      }
      LayerField::IcmpSeq => {
        let icmp = self.icmp.get_or_insert_with(IcmpFields::default);
        if let FieldValue::U16(v) = value {
          icmp.sequence = v;
        } else {
          return Err("Expected u16 for icmp.seq".to_string());
        }
      }
      LayerField::Payload => {
        if let FieldValue::String(s) = value {
          self.payload = s.into_bytes();
        } else if let FieldValue::Bytes(b) = value {
          self.payload = b;
        } else {
          return Err("Expected string or bytes for payload".to_string());
        }
      }
      LayerField::PayloadHex => {
        if let FieldValue::Bytes(b) = value {
          self.payload = b;
        } else {
          return Err("Expected hex bytes for payload_hex".to_string());
        }
      }
    }
    Ok(())
  }

  /// Get the protocol for this signature
  pub fn protocol(&self) -> u8 {
    if self.tcp.is_some() {
      6 // TCP
    } else if self.udp.is_some() {
      17 // UDP
    } else if self.icmp.is_some() {
      1 // ICMP
    } else {
      self.ipv4.protocol
    }
  }
}

// TCP flag constants
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;
pub const TCP_ECE: u8 = 0x40;
pub const TCP_CWR: u8 = 0x80;

/// Parse TCP flags from string
pub fn parse_tcp_flags(s: &str) -> u8 {
  let mut flags = 0u8;
  let s_upper = s.to_uppercase();

  for token in s_upper
    .split(|c: char| c == ',' || c == '|' || c.is_ascii_whitespace())
    .filter(|token| !token.is_empty())
  {
    match token {
      "FIN" => flags |= TCP_FIN,
      "SYN" => flags |= TCP_SYN,
      "RST" => flags |= TCP_RST,
      "PSH" => flags |= TCP_PSH,
      "ACK" => flags |= TCP_ACK,
      "URG" => flags |= TCP_URG,
      "ECE" => flags |= TCP_ECE,
      "CWR" => flags |= TCP_CWR,
      _ => {
        for c in token.chars() {
          match c {
            'S' => flags |= TCP_SYN,
            'A' => flags |= TCP_ACK,
            'F' => flags |= TCP_FIN,
            'P' => flags |= TCP_PSH,
            'R' => flags |= TCP_RST,
            'U' => flags |= TCP_URG,
            _ => {}
          }
        }
      }
    }
  }

  flags
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_tcp_flags() {
    assert_eq!(parse_tcp_flags("SYN"), TCP_SYN);
    assert_eq!(parse_tcp_flags("SYN,ACK"), TCP_SYN | TCP_ACK);
    assert_eq!(parse_tcp_flags("SA"), TCP_SYN | TCP_ACK);
    assert_eq!(parse_tcp_flags("FIN,PSH,ACK"), TCP_FIN | TCP_PSH | TCP_ACK);
  }

  #[test]
  fn test_layer_field_parsing() {
    assert_eq!(LayerField::from_str("ip.src"), Some(LayerField::IpSrc));
    assert_eq!(
      LayerField::from_str("tcp.dport"),
      Some(LayerField::TcpDport)
    );
    assert_eq!(LayerField::from_str("payload"), Some(LayerField::Payload));
    assert_eq!(LayerField::from_str("invalid"), None);
  }

  #[test]
  fn test_signature_set_field() {
    let mut sig = PacketSignature::new("test");
    sig
      .set_field(LayerField::IpTtl, FieldValue::U8(128))
      .unwrap();
    assert_eq!(sig.ipv4.ttl, 128);

    sig
      .set_field(LayerField::TcpDport, FieldValue::U16(80))
      .unwrap();
    assert!(sig.tcp.is_some());
    assert_eq!(sig.tcp.as_ref().unwrap().dport, Some(80));
  }
}
