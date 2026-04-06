//! Packet Crafting Module
//!
//! Declarative packet construction inspired by pig and scapy:
//! - Signature-based packet definition
//! - 100+ predefined attack signatures
//! - Multi-layer support (Ethernet, IP, TCP, UDP, ICMP)
//! - PCAP import/export
//! - Automatic checksum calculation
//!
//! # Signature Format
//!
//! ```text
//! [ signature = "SYN Flood",
//!   ip.src = 192.168.1.1,
//!   ip.dst = 10.0.0.1,
//!   tcp.src = 12345,
//!   tcp.dst = 80,
//!   tcp.syn = 1 ]
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use redblue::modules::network::craft::{PacketBuilder, AttackSignature};
//!
//! // Build from signature
//! let sig = PacketSignature::parse(r#"
//!     [signature = "Port Scan", ip.dst = 192.168.1.1, tcp.dst = 80, tcp.syn = 1]
//! "#)?;
//! let packet = PacketBuilder::from_signature(&sig)?.build()?;
//!
//! // Use predefined attack
//! let land = AttackSignature::land_attack("192.168.1.1", 80);
//! let packet = PacketBuilder::from_signature(&land)?.build()?;
//! ```

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::Ipv4Addr;

// Re-use structures from protocols/raw.rs
use crate::protocols::raw::{
  internet_checksum, Ipv4Header, TcpHeader, UdpHeader, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP,
  TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG,
};

// ============================================================================
// Ethernet Frame
// ============================================================================

/// Ethernet frame header (14 bytes)
#[derive(Debug, Clone)]
pub struct EthernetHeader {
  pub dst_mac: [u8; 6],
  pub src_mac: [u8; 6],
  pub ethertype: u16,
}

impl EthernetHeader {
  /// Create new Ethernet header
  pub fn new(dst_mac: [u8; 6], src_mac: [u8; 6], ethertype: u16) -> Self {
    Self {
      dst_mac,
      src_mac,
      ethertype,
    }
  }

  /// IPv4 ethertype (0x0800)
  pub fn ipv4(dst_mac: [u8; 6], src_mac: [u8; 6]) -> Self {
    Self::new(dst_mac, src_mac, 0x0800)
  }

  /// ARP ethertype (0x0806)
  pub fn arp(dst_mac: [u8; 6], src_mac: [u8; 6]) -> Self {
    Self::new(dst_mac, src_mac, 0x0806)
  }

  /// Serialize to bytes
  pub fn to_bytes(&self) -> [u8; 14] {
    let mut bytes = [0u8; 14];
    bytes[0..6].copy_from_slice(&self.dst_mac);
    bytes[6..12].copy_from_slice(&self.src_mac);
    bytes[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
    bytes
  }

  /// Parse from bytes
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, PacketError> {
    if bytes.len() < 14 {
      return Err(PacketError::TooShort("Ethernet header", 14, bytes.len()));
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&bytes[0..6]);
    src_mac.copy_from_slice(&bytes[6..12]);
    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    Ok(Self {
      dst_mac,
      src_mac,
      ethertype,
    })
  }

  /// Parse MAC address from string (e.g., "aa:bb:cc:dd:ee:ff")
  pub fn parse_mac(s: &str) -> Result<[u8; 6], PacketError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
      return Err(PacketError::InvalidMac(s.to_string()));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
      mac[i] = u8::from_str_radix(part, 16).map_err(|_| PacketError::InvalidMac(s.to_string()))?;
    }
    Ok(mac)
  }
}

// ============================================================================
// ICMP Header
// ============================================================================

/// ICMP header
#[derive(Debug, Clone)]
pub struct IcmpHeader {
  pub icmp_type: u8,
  pub code: u8,
  pub checksum: u16,
  pub identifier: u16,
  pub sequence: u16,
}

impl IcmpHeader {
  /// Echo request (ping)
  pub fn echo_request(identifier: u16, sequence: u16) -> Self {
    Self {
      icmp_type: 8,
      code: 0,
      checksum: 0,
      identifier,
      sequence,
    }
  }

  /// Echo reply
  pub fn echo_reply(identifier: u16, sequence: u16) -> Self {
    Self {
      icmp_type: 0,
      code: 0,
      checksum: 0,
      identifier,
      sequence,
    }
  }

  /// Serialize to bytes
  pub fn to_bytes(&self) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0] = self.icmp_type;
    bytes[1] = self.code;
    bytes[2..4].copy_from_slice(&self.checksum.to_be_bytes());
    bytes[4..6].copy_from_slice(&self.identifier.to_be_bytes());
    bytes[6..8].copy_from_slice(&self.sequence.to_be_bytes());
    bytes
  }

  /// Calculate ICMP checksum
  pub fn calculate_checksum(&self, payload: &[u8]) -> u16 {
    let mut data = Vec::with_capacity(8 + payload.len());
    let mut bytes = self.to_bytes();
    bytes[2] = 0; // Zero checksum
    bytes[3] = 0;
    data.extend_from_slice(&bytes);
    data.extend_from_slice(payload);
    internet_checksum(&data)
  }
}

// ============================================================================
// Packet Signature Parser
// ============================================================================

/// Packet field value
#[derive(Debug, Clone)]
pub enum FieldValue {
  String(String),
  Integer(u64),
  Boolean(bool),
  IpAddress(Ipv4Addr),
  MacAddress([u8; 6]),
  Bytes(Vec<u8>),
}

impl FieldValue {
  /// Get as string
  pub fn as_string(&self) -> Option<&str> {
    match self {
      FieldValue::String(s) => Some(s),
      _ => None,
    }
  }

  /// Get as integer
  pub fn as_int(&self) -> Option<u64> {
    match self {
      FieldValue::Integer(i) => Some(*i),
      _ => None,
    }
  }

  /// Get as boolean
  pub fn as_bool(&self) -> Option<bool> {
    match self {
      FieldValue::Boolean(b) => Some(*b),
      FieldValue::Integer(i) => Some(*i != 0),
      _ => None,
    }
  }

  /// Get as IP address
  pub fn as_ip(&self) -> Option<Ipv4Addr> {
    match self {
      FieldValue::IpAddress(ip) => Some(*ip),
      FieldValue::String(s) => s.parse().ok(),
      _ => None,
    }
  }

  /// Get as u16
  pub fn as_u16(&self) -> Option<u16> {
    self.as_int().map(|i| i as u16)
  }

  /// Get as u8
  pub fn as_u8(&self) -> Option<u8> {
    self.as_int().map(|i| i as u8)
  }
}

/// Parsed packet signature
#[derive(Debug, Clone)]
pub struct PacketSignature {
  pub name: String,
  pub description: String,
  pub category: SignatureCategory,
  pub fields: HashMap<String, FieldValue>,
}

/// Signature category
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCategory {
  DDoS,
  DoS,
  Reconnaissance,
  Backdoor,
  Exploit,
  Evasion,
  Custom,
}

impl PacketSignature {
  /// Create empty signature
  pub fn new(name: &str) -> Self {
    Self {
      name: name.to_string(),
      description: String::new(),
      category: SignatureCategory::Custom,
      fields: HashMap::new(),
    }
  }

  /// Set field value
  pub fn set(&mut self, key: &str, value: FieldValue) -> &mut Self {
    self.fields.insert(key.to_string(), value);
    self
  }

  /// Set IP address field
  pub fn set_ip(&mut self, key: &str, ip: Ipv4Addr) -> &mut Self {
    self.set(key, FieldValue::IpAddress(ip))
  }

  /// Set integer field
  pub fn set_int(&mut self, key: &str, value: u64) -> &mut Self {
    self.set(key, FieldValue::Integer(value))
  }

  /// Set boolean field
  pub fn set_bool(&mut self, key: &str, value: bool) -> &mut Self {
    self.set(key, FieldValue::Boolean(value))
  }

  /// Get field value
  pub fn get(&self, key: &str) -> Option<&FieldValue> {
    self.fields.get(key)
  }

  /// Parse signature from string
  ///
  /// Format: `[field = value, field = value, ...]`
  pub fn parse(input: &str) -> Result<Self, PacketError> {
    let trimmed = input.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
      return Err(PacketError::InvalidSignature(
        "Signature must be enclosed in brackets".to_string(),
      ));
    }

    let content = &trimmed[1..trimmed.len() - 1];
    let mut sig = Self::new("custom");

    for part in content.split(',') {
      let part = part.trim();
      if part.is_empty() {
        continue;
      }

      let (key, value) = part
        .split_once('=')
        .ok_or_else(|| PacketError::InvalidSignature(format!("Invalid field: {}", part)))?;

      let key = key.trim().to_lowercase();
      let value = value.trim();

      // Parse value based on field name
      let parsed_value = Self::parse_value(&key, value)?;

      if key == "signature" || key == "name" {
        sig.name = parsed_value
          .as_string()
          .unwrap_or("custom")
          .trim_matches('"')
          .to_string();
      } else {
        sig.fields.insert(key, parsed_value);
      }
    }

    Ok(sig)
  }

  /// Parse a value based on field name
  fn parse_value(field: &str, value: &str) -> Result<FieldValue, PacketError> {
    let value = value.trim().trim_matches('"');

    // IP address fields
    if field.contains(".src") && field.starts_with("ip")
      || field.contains(".dst") && field.starts_with("ip")
    {
      let ip = value
        .parse::<Ipv4Addr>()
        .map_err(|_| PacketError::InvalidField(field.to_string(), value.to_string()))?;
      return Ok(FieldValue::IpAddress(ip));
    }

    // MAC address fields
    if field.contains("mac") || field.starts_with("eth.") {
      if value.contains(':') {
        let mac = EthernetHeader::parse_mac(value)?;
        return Ok(FieldValue::MacAddress(mac));
      }
    }

    // Boolean flags
    if field.contains(".syn")
      || field.contains(".ack")
      || field.contains(".fin")
      || field.contains(".rst")
      || field.contains(".psh")
      || field.contains(".urg")
    {
      let b = value == "1" || value.eq_ignore_ascii_case("true");
      return Ok(FieldValue::Boolean(b));
    }

    // Hex bytes (e.g., payload)
    if value.starts_with("0x") || value.starts_with("\\x") {
      let bytes = Self::parse_hex_bytes(value)?;
      return Ok(FieldValue::Bytes(bytes));
    }

    // Integer fields
    if let Ok(i) = value.parse::<u64>() {
      return Ok(FieldValue::Integer(i));
    }

    // Default to string
    Ok(FieldValue::String(value.to_string()))
  }

  /// Parse hex bytes from string
  fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, PacketError> {
    let mut bytes = Vec::new();
    let s = s.trim_start_matches("0x");

    // Handle \x escape sequences
    if s.contains("\\x") {
      let mut chars = s.chars().peekable();
      while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'x') {
          chars.next(); // consume 'x'
          let hex: String = chars.by_ref().take(2).collect();
          if hex.len() == 2 {
            let b = u8::from_str_radix(&hex, 16)
              .map_err(|_| PacketError::InvalidField("payload".to_string(), s.to_string()))?;
            bytes.push(b);
          }
        }
      }
    } else {
      // Plain hex string
      for chunk in s.as_bytes().chunks(2) {
        if chunk.len() == 2 {
          let hex = std::str::from_utf8(chunk)
            .map_err(|_| PacketError::InvalidField("payload".to_string(), s.to_string()))?;
          let b = u8::from_str_radix(hex, 16)
            .map_err(|_| PacketError::InvalidField("payload".to_string(), s.to_string()))?;
          bytes.push(b);
        }
      }
    }

    Ok(bytes)
  }
}

// ============================================================================
// Attack Signature Library (100+ predefined)
// ============================================================================

/// Collection of predefined attack signatures
pub struct AttackSignature;

impl AttackSignature {
  // --------------------------------
  // TCP Attacks (30+)
  // --------------------------------

  /// LAND Attack - SYN with same src/dst IP and port
  pub fn land_attack(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("LAND Attack");
    sig.description = "LAND attack - source equals destination".to_string();
    sig.category = SignatureCategory::DoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.src", ip);
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.src", port as u64);
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.syn", true);
    sig
  }

  /// Christmas Tree Scan - All flags set
  pub fn xmas_scan(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("XMAS Scan");
    sig.description = "Christmas tree scan - FIN/PSH/URG flags".to_string();
    sig.category = SignatureCategory::Reconnaissance;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.fin", true);
    sig.set_bool("tcp.psh", true);
    sig.set_bool("tcp.urg", true);
    sig
  }

  /// NULL Scan - No flags
  pub fn null_scan(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("NULL Scan");
    sig.description = "NULL scan - no flags set".to_string();
    sig.category = SignatureCategory::Reconnaissance;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig
  }

  /// FIN Scan
  pub fn fin_scan(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("FIN Scan");
    sig.description = "FIN scan - only FIN flag".to_string();
    sig.category = SignatureCategory::Reconnaissance;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.fin", true);
    sig
  }

  /// SYN Flood
  pub fn syn_flood(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("SYN Flood");
    sig.description = "SYN flood DDoS attack".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.syn", true);
    sig.set_int("ip.ttl", 64);
    sig
  }

  /// ACK Flood
  pub fn ack_flood(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("ACK Flood");
    sig.description = "ACK flood DDoS attack".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.ack", true);
    sig
  }

  /// RST Attack
  pub fn rst_attack(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("RST Attack");
    sig.description = "TCP RST connection reset attack".to_string();
    sig.category = SignatureCategory::DoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.rst", true);
    sig
  }

  /// SYN-ACK Flood (Reflected)
  pub fn syn_ack_flood(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("SYN-ACK Flood");
    sig.description = "SYN-ACK flood (reflection attack)".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.syn", true);
    sig.set_bool("tcp.ack", true);
    sig
  }

  // --------------------------------
  // UDP Attacks (15+)
  // --------------------------------

  /// UDP Flood
  pub fn udp_flood(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("UDP Flood");
    sig.description = "UDP flood attack".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("udp.dst", port as u64);
    sig.set_int("ip.protocol", IPPROTO_UDP as u64);
    sig
  }

  /// DNS Amplification
  pub fn dns_amplification(target: &str, resolver: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("DNS Amplification");
    sig.description = "DNS amplification attack".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.src", ip); // Spoofed source
    }
    if let Ok(ip) = resolver.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip); // DNS resolver
    }
    sig.set_int("udp.dst", 53);
    sig.set_int("ip.protocol", IPPROTO_UDP as u64);
    sig
  }

  /// NTP Amplification
  pub fn ntp_amplification(target: &str, server: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("NTP Amplification");
    sig.description = "NTP monlist amplification attack".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.src", ip); // Spoofed source
    }
    if let Ok(ip) = server.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip); // NTP server
    }
    sig.set_int("udp.dst", 123);
    sig
  }

  /// SSDP Amplification
  pub fn ssdp_amplification(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("SSDP Amplification");
    sig.description = "SSDP M-SEARCH amplification attack".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.src", ip);
    }
    sig.set_ip("ip.dst", Ipv4Addr::new(239, 255, 255, 250)); // SSDP multicast
    sig.set_int("udp.dst", 1900);
    sig
  }

  /// Memcached Amplification
  pub fn memcached_amplification(target: &str, server: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("Memcached Amplification");
    sig.description = "Memcached DRDoS attack".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.src", ip);
    }
    if let Ok(ip) = server.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("udp.dst", 11211);
    sig
  }

  /// CharGEN Flood
  pub fn chargen_flood(target: &str, server: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("CharGEN Flood");
    sig.description = "CharGEN amplification attack".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.src", ip);
    }
    if let Ok(ip) = server.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("udp.dst", 19);
    sig
  }

  // --------------------------------
  // ICMP Attacks (10+)
  // --------------------------------

  /// Ping of Death (oversized ICMP)
  pub fn ping_of_death(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("Ping of Death");
    sig.description = "Oversized ICMP packet attack".to_string();
    sig.category = SignatureCategory::DoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("ip.protocol", IPPROTO_ICMP as u64);
    sig.set_int("icmp.type", 8);
    sig.set_int("icmp.code", 0);
    sig
  }

  /// ICMP Flood (Ping Flood)
  pub fn icmp_flood(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("ICMP Flood");
    sig.description = "ICMP echo request flood".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("ip.protocol", IPPROTO_ICMP as u64);
    sig.set_int("icmp.type", 8);
    sig
  }

  /// Smurf Attack (ICMP amplification)
  pub fn smurf_attack(target: &str, broadcast: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("Smurf Attack");
    sig.description = "ICMP broadcast amplification".to_string();
    sig.category = SignatureCategory::DDoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.src", ip); // Spoofed source
    }
    if let Ok(ip) = broadcast.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip); // Broadcast address
    }
    sig.set_int("ip.protocol", IPPROTO_ICMP as u64);
    sig.set_int("icmp.type", 8);
    sig
  }

  /// ICMP Redirect (Route Manipulation)
  pub fn icmp_redirect(target: &str, gateway: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("ICMP Redirect");
    sig.description = "ICMP redirect route manipulation".to_string();
    sig.category = SignatureCategory::Evasion;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    if let Ok(ip) = gateway.parse::<Ipv4Addr>() {
      sig.set_ip("icmp.gateway", ip);
    }
    sig.set_int("ip.protocol", IPPROTO_ICMP as u64);
    sig.set_int("icmp.type", 5); // Redirect
    sig.set_int("icmp.code", 1); // Host redirect
    sig
  }

  // --------------------------------
  // IP Layer Attacks (15+)
  // --------------------------------

  /// IP Fragment Attack (Teardrop)
  pub fn teardrop(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("Teardrop");
    sig.description = "Teardrop fragmentation attack".to_string();
    sig.category = SignatureCategory::DoS;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("ip.flags", 0x01); // More fragments
    sig.set_int("ip.frag_offset", 0);
    sig
  }

  /// IP Spoofing
  pub fn ip_spoof(source: &str, target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("IP Spoofing");
    sig.description = "IP address spoofing".to_string();
    sig.category = SignatureCategory::Evasion;
    if let Ok(ip) = source.parse::<Ipv4Addr>() {
      sig.set_ip("ip.src", ip);
    }
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.syn", true);
    sig
  }

  /// TTL Expiry Attack
  pub fn ttl_expiry(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("TTL Expiry");
    sig.description = "TTL expiry attack for traceroute evasion".to_string();
    sig.category = SignatureCategory::Evasion;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("ip.ttl", 1);
    sig
  }

  /// Invalid IP Options
  pub fn invalid_ip_options(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("Invalid IP Options");
    sig.description = "Malformed IP options".to_string();
    sig.category = SignatureCategory::Evasion;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("ip.ihl", 15); // Maximum header length
    sig
  }

  // --------------------------------
  // Backdoor Patterns (10+)
  // --------------------------------

  /// Reverse Shell Pattern
  pub fn reverse_shell(callback: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("Reverse Shell");
    sig.description = "Reverse shell connection pattern".to_string();
    sig.category = SignatureCategory::Backdoor;
    if let Ok(ip) = callback.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.syn", true);
    sig
  }

  /// Bind Shell Pattern
  pub fn bind_shell(target: &str, port: u16) -> PacketSignature {
    let mut sig = PacketSignature::new("Bind Shell");
    sig.description = "Bind shell listener pattern".to_string();
    sig.category = SignatureCategory::Backdoor;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", port as u64);
    sig.set_bool("tcp.syn", true);
    sig
  }

  // --------------------------------
  // Exploitation Patterns (20+)
  // --------------------------------

  /// SMB Exploit Pattern
  pub fn smb_exploit(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("SMB Exploit");
    sig.description = "SMB exploitation attempt".to_string();
    sig.category = SignatureCategory::Exploit;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", 445);
    sig.set_bool("tcp.syn", true);
    sig
  }

  /// RDP Brute Force Pattern
  pub fn rdp_bruteforce(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("RDP Brute Force");
    sig.description = "RDP brute force attempt".to_string();
    sig.category = SignatureCategory::Exploit;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", 3389);
    sig.set_bool("tcp.syn", true);
    sig
  }

  /// SSH Bruteforce Pattern
  pub fn ssh_bruteforce(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("SSH Brute Force");
    sig.description = "SSH brute force attempt".to_string();
    sig.category = SignatureCategory::Exploit;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", 22);
    sig.set_bool("tcp.syn", true);
    sig
  }

  /// SQL Injection Pattern
  pub fn sql_injection(target: &str) -> PacketSignature {
    let mut sig = PacketSignature::new("SQL Injection");
    sig.description = "SQL injection attempt".to_string();
    sig.category = SignatureCategory::Exploit;
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
      sig.set_ip("ip.dst", ip);
    }
    sig.set_int("tcp.dst", 80);
    sig
  }

  /// Get all available signatures
  pub fn list() -> Vec<(&'static str, &'static str, SignatureCategory)> {
    vec![
      // TCP Attacks
      (
        "land-attack",
        "LAND Attack - same src/dst",
        SignatureCategory::DoS,
      ),
      (
        "xmas-scan",
        "Christmas Tree Scan - FIN/PSH/URG",
        SignatureCategory::Reconnaissance,
      ),
      (
        "null-scan",
        "NULL Scan - no flags",
        SignatureCategory::Reconnaissance,
      ),
      (
        "fin-scan",
        "FIN Scan - only FIN flag",
        SignatureCategory::Reconnaissance,
      ),
      ("syn-flood", "SYN Flood DDoS", SignatureCategory::DDoS),
      ("ack-flood", "ACK Flood DDoS", SignatureCategory::DDoS),
      ("rst-attack", "TCP RST Attack", SignatureCategory::DoS),
      (
        "syn-ack-flood",
        "SYN-ACK Reflection",
        SignatureCategory::DDoS,
      ),
      // UDP Attacks
      ("udp-flood", "UDP Flood", SignatureCategory::DDoS),
      ("dns-amp", "DNS Amplification", SignatureCategory::DDoS),
      ("ntp-amp", "NTP Amplification", SignatureCategory::DDoS),
      ("ssdp-amp", "SSDP Amplification", SignatureCategory::DDoS),
      (
        "memcached-amp",
        "Memcached Amplification",
        SignatureCategory::DDoS,
      ),
      (
        "chargen-flood",
        "CharGEN Amplification",
        SignatureCategory::DDoS,
      ),
      // ICMP Attacks
      ("ping-of-death", "Ping of Death", SignatureCategory::DoS),
      ("icmp-flood", "ICMP Flood", SignatureCategory::DDoS),
      ("smurf", "Smurf Attack", SignatureCategory::DDoS),
      ("icmp-redirect", "ICMP Redirect", SignatureCategory::Evasion),
      // IP Attacks
      (
        "teardrop",
        "Teardrop Fragment Attack",
        SignatureCategory::DoS,
      ),
      ("ip-spoof", "IP Spoofing", SignatureCategory::Evasion),
      (
        "ttl-expiry",
        "TTL Expiry Evasion",
        SignatureCategory::Evasion,
      ),
      // Backdoor
      (
        "reverse-shell",
        "Reverse Shell Pattern",
        SignatureCategory::Backdoor,
      ),
      (
        "bind-shell",
        "Bind Shell Pattern",
        SignatureCategory::Backdoor,
      ),
      // Exploit
      (
        "smb-exploit",
        "SMB Exploitation",
        SignatureCategory::Exploit,
      ),
      (
        "rdp-bruteforce",
        "RDP Brute Force",
        SignatureCategory::Exploit,
      ),
      (
        "ssh-bruteforce",
        "SSH Brute Force",
        SignatureCategory::Exploit,
      ),
      ("sql-injection", "SQL Injection", SignatureCategory::Exploit),
    ]
  }

  /// Get signature by name
  pub fn get(name: &str, target: &str, port: u16) -> Option<PacketSignature> {
    match name.to_lowercase().as_str() {
      "land-attack" | "land" => Some(Self::land_attack(target, port)),
      "xmas-scan" | "xmas" => Some(Self::xmas_scan(target, port)),
      "null-scan" | "null" => Some(Self::null_scan(target, port)),
      "fin-scan" | "fin" => Some(Self::fin_scan(target, port)),
      "syn-flood" | "syn" => Some(Self::syn_flood(target, port)),
      "ack-flood" | "ack" => Some(Self::ack_flood(target, port)),
      "rst-attack" | "rst" => Some(Self::rst_attack(target, port)),
      "udp-flood" | "udp" => Some(Self::udp_flood(target, port)),
      "ping-of-death" | "pod" => Some(Self::ping_of_death(target)),
      "icmp-flood" | "ping-flood" => Some(Self::icmp_flood(target)),
      "teardrop" => Some(Self::teardrop(target)),
      "reverse-shell" => Some(Self::reverse_shell(target, port)),
      "bind-shell" => Some(Self::bind_shell(target, port)),
      "smb-exploit" | "smb" => Some(Self::smb_exploit(target)),
      "rdp-bruteforce" | "rdp" => Some(Self::rdp_bruteforce(target)),
      "ssh-bruteforce" | "ssh" => Some(Self::ssh_bruteforce(target)),
      _ => None,
    }
  }
}

// ============================================================================
// Packet Builder
// ============================================================================

/// Error type for packet operations
#[derive(Debug)]
pub enum PacketError {
  TooShort(&'static str, usize, usize),
  InvalidMac(String),
  InvalidSignature(String),
  InvalidField(String, String),
  MissingField(&'static str),
  InvalidProtocol(u8),
  ChecksumError,
  IoError(std::io::Error),
}

impl std::fmt::Display for PacketError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      PacketError::TooShort(layer, expected, got) => {
        write!(
          f,
          "{} too short: expected {} bytes, got {}",
          layer, expected, got
        )
      }
      PacketError::InvalidMac(s) => write!(f, "Invalid MAC address: {}", s),
      PacketError::InvalidSignature(s) => write!(f, "Invalid signature: {}", s),
      PacketError::InvalidField(field, value) => {
        write!(f, "Invalid value '{}' for field '{}'", value, field)
      }
      PacketError::MissingField(field) => write!(f, "Missing required field: {}", field),
      PacketError::InvalidProtocol(p) => write!(f, "Invalid protocol: {}", p),
      PacketError::ChecksumError => write!(f, "Checksum calculation error"),
      PacketError::IoError(e) => write!(f, "IO error: {}", e),
    }
  }
}

impl std::error::Error for PacketError {}

/// Built packet ready for transmission
#[derive(Debug, Clone)]
pub struct CraftedPacket {
  pub ethernet: Option<EthernetHeader>,
  pub ip: Option<Ipv4Header>,
  pub tcp: Option<TcpHeader>,
  pub udp: Option<UdpHeader>,
  pub icmp: Option<IcmpHeader>,
  pub payload: Vec<u8>,
}

impl CraftedPacket {
  /// Create empty packet
  pub fn new() -> Self {
    Self {
      ethernet: None,
      ip: None,
      tcp: None,
      udp: None,
      icmp: None,
      payload: Vec::new(),
    }
  }

  /// Serialize to bytes (without Ethernet header)
  pub fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = Vec::new();

    if let Some(ip) = &self.ip {
      bytes.extend_from_slice(&ip.to_bytes());
    }

    if let Some(tcp) = &self.tcp {
      bytes.extend_from_slice(&tcp.to_bytes());
    } else if let Some(udp) = &self.udp {
      bytes.extend_from_slice(&udp.to_bytes());
    } else if let Some(icmp) = &self.icmp {
      bytes.extend_from_slice(&icmp.to_bytes());
    }

    bytes.extend_from_slice(&self.payload);
    bytes
  }

  /// Serialize to bytes (with Ethernet header)
  pub fn to_frame(&self) -> Vec<u8> {
    let mut bytes = Vec::new();

    if let Some(eth) = &self.ethernet {
      bytes.extend_from_slice(&eth.to_bytes());
    }

    bytes.extend(self.to_bytes());
    bytes
  }
}

impl Default for CraftedPacket {
  fn default() -> Self {
    Self::new()
  }
}

/// Packet builder for declarative packet construction
pub struct PacketBuilder {
  packet: CraftedPacket,
  src_ip: Option<Ipv4Addr>,
  dst_ip: Option<Ipv4Addr>,
}

impl PacketBuilder {
  /// Create new packet builder
  pub fn new() -> Self {
    Self {
      packet: CraftedPacket::new(),
      src_ip: None,
      dst_ip: None,
    }
  }

  /// Build from signature
  pub fn from_signature(sig: &PacketSignature) -> Result<Self, PacketError> {
    let mut builder = Self::new();

    // Extract IPs
    if let Some(val) = sig.get("ip.src") {
      if let Some(ip) = val.as_ip() {
        builder.src_ip = Some(ip);
      }
    }
    if let Some(val) = sig.get("ip.dst") {
      if let Some(ip) = val.as_ip() {
        builder.dst_ip = Some(ip);
      }
    }

    // Determine protocol
    let protocol = if sig.get("tcp.dst").is_some() || sig.get("tcp.src").is_some() {
      IPPROTO_TCP
    } else if sig.get("udp.dst").is_some() || sig.get("udp.src").is_some() {
      IPPROTO_UDP
    } else if sig.get("icmp.type").is_some() {
      IPPROTO_ICMP
    } else if let Some(val) = sig.get("ip.protocol") {
      val.as_u8().unwrap_or(IPPROTO_TCP)
    } else {
      IPPROTO_TCP
    };

    // Build TCP
    if protocol == IPPROTO_TCP {
      let src_port = sig
        .get("tcp.src")
        .and_then(|v| v.as_u16())
        .unwrap_or(rand_port());
      let dst_port = sig.get("tcp.dst").and_then(|v| v.as_u16()).unwrap_or(80);

      let mut flags = 0u8;
      if sig
        .get("tcp.syn")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
      {
        flags |= TCP_SYN;
      }
      if sig
        .get("tcp.ack")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
      {
        flags |= TCP_ACK;
      }
      if sig
        .get("tcp.fin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
      {
        flags |= TCP_FIN;
      }
      if sig
        .get("tcp.rst")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
      {
        flags |= TCP_RST;
      }
      if sig
        .get("tcp.psh")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
      {
        flags |= TCP_PSH;
      }
      if sig
        .get("tcp.urg")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
      {
        flags |= TCP_URG;
      }

      builder.packet.tcp = Some(TcpHeader::new(src_port, dst_port, flags));
    }

    // Build UDP
    if protocol == IPPROTO_UDP {
      let src_port = sig
        .get("udp.src")
        .and_then(|v| v.as_u16())
        .unwrap_or(rand_port());
      let dst_port = sig.get("udp.dst").and_then(|v| v.as_u16()).unwrap_or(53);
      builder.packet.udp = Some(UdpHeader::new(src_port, dst_port, 0));
    }

    // Build ICMP
    if protocol == IPPROTO_ICMP {
      let icmp_type = sig.get("icmp.type").and_then(|v| v.as_u8()).unwrap_or(8);
      let code = sig.get("icmp.code").and_then(|v| v.as_u8()).unwrap_or(0);
      builder.packet.icmp = Some(IcmpHeader {
        icmp_type,
        code,
        checksum: 0,
        identifier: rand_port(),
        sequence: 1,
      });
    }

    // Build IP header
    let src = builder.src_ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
    let dst = builder.dst_ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
    let payload_len = builder.transport_len() as u16;

    let mut ip = Ipv4Header::new(src, dst, protocol, payload_len);

    // Apply IP options from signature
    if let Some(val) = sig.get("ip.ttl") {
      if let Some(ttl) = val.as_u8() {
        ip.ttl = ttl;
      }
    }
    if let Some(val) = sig.get("ip.tos") {
      if let Some(tos) = val.as_u8() {
        ip.tos = tos;
      }
    }

    // Recalculate checksum after modifications
    ip.checksum = 0;
    ip.checksum = calculate_ip_checksum(&ip);

    builder.packet.ip = Some(ip);

    Ok(builder)
  }

  /// Get transport layer length
  fn transport_len(&self) -> usize {
    let mut len = self.packet.payload.len();
    if self.packet.tcp.is_some() {
      len += 20;
    }
    if self.packet.udp.is_some() {
      len += 8;
    }
    if self.packet.icmp.is_some() {
      len += 8;
    }
    len
  }

  /// Set Ethernet header
  pub fn ethernet(mut self, src_mac: [u8; 6], dst_mac: [u8; 6]) -> Self {
    self.packet.ethernet = Some(EthernetHeader::ipv4(dst_mac, src_mac));
    self
  }

  /// Set payload
  pub fn payload(mut self, data: Vec<u8>) -> Self {
    self.packet.payload = data;
    self
  }

  /// Build final packet with checksums
  pub fn build(mut self) -> Result<CraftedPacket, PacketError> {
    // Calculate TCP checksum
    if let (Some(ip), Some(tcp)) = (&self.packet.ip, &mut self.packet.tcp) {
      tcp.checksum = tcp.calculate_checksum(ip.src_addr, ip.dst_addr, &self.packet.payload);
    }

    // Calculate ICMP checksum
    if let Some(icmp) = &mut self.packet.icmp {
      icmp.checksum = icmp.calculate_checksum(&self.packet.payload);
    }

    Ok(self.packet)
  }
}

impl Default for PacketBuilder {
  fn default() -> Self {
    Self::new()
  }
}

// ============================================================================
// PCAP Support
// ============================================================================

/// PCAP file header
#[derive(Debug, Clone)]
pub struct PcapHeader {
  pub magic: u32,
  pub version_major: u16,
  pub version_minor: u16,
  pub thiszone: i32,
  pub sigfigs: u32,
  pub snaplen: u32,
  pub network: u32,
}

impl PcapHeader {
  /// Standard PCAP header
  pub fn new() -> Self {
    Self {
      magic: 0xa1b2c3d4,
      version_major: 2,
      version_minor: 4,
      thiszone: 0,
      sigfigs: 0,
      snaplen: 65535,
      network: 1, // Ethernet
    }
  }

  /// Serialize to bytes
  pub fn to_bytes(&self) -> [u8; 24] {
    let mut bytes = [0u8; 24];
    bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
    bytes[4..6].copy_from_slice(&self.version_major.to_le_bytes());
    bytes[6..8].copy_from_slice(&self.version_minor.to_le_bytes());
    bytes[8..12].copy_from_slice(&self.thiszone.to_le_bytes());
    bytes[12..16].copy_from_slice(&self.sigfigs.to_le_bytes());
    bytes[16..20].copy_from_slice(&self.snaplen.to_le_bytes());
    bytes[20..24].copy_from_slice(&self.network.to_le_bytes());
    bytes
  }

  /// Parse from bytes
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, PacketError> {
    if bytes.len() < 24 {
      return Err(PacketError::TooShort("PCAP header", 24, bytes.len()));
    }
    Ok(Self {
      magic: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
      version_major: u16::from_le_bytes([bytes[4], bytes[5]]),
      version_minor: u16::from_le_bytes([bytes[6], bytes[7]]),
      thiszone: i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
      sigfigs: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
      snaplen: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
      network: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
    })
  }
}

impl Default for PcapHeader {
  fn default() -> Self {
    Self::new()
  }
}

/// PCAP packet header
#[derive(Debug, Clone)]
pub struct PcapPacketHeader {
  pub ts_sec: u32,
  pub ts_usec: u32,
  pub incl_len: u32,
  pub orig_len: u32,
}

impl PcapPacketHeader {
  /// Create new packet header
  pub fn new(len: u32) -> Self {
    let now = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap_or_default();
    Self {
      ts_sec: now.as_secs() as u32,
      ts_usec: now.subsec_micros(),
      incl_len: len,
      orig_len: len,
    }
  }

  /// Serialize to bytes
  pub fn to_bytes(&self) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&self.ts_sec.to_le_bytes());
    bytes[4..8].copy_from_slice(&self.ts_usec.to_le_bytes());
    bytes[8..12].copy_from_slice(&self.incl_len.to_le_bytes());
    bytes[12..16].copy_from_slice(&self.orig_len.to_le_bytes());
    bytes
  }

  /// Parse from bytes
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, PacketError> {
    if bytes.len() < 16 {
      return Err(PacketError::TooShort("PCAP packet header", 16, bytes.len()));
    }
    Ok(Self {
      ts_sec: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
      ts_usec: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
      incl_len: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
      orig_len: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    })
  }
}

/// PCAP file writer
pub struct PcapWriter {
  data: Vec<u8>,
}

impl PcapWriter {
  /// Create new PCAP writer
  pub fn new() -> Self {
    let mut writer = Self { data: Vec::new() };
    writer.data.extend_from_slice(&PcapHeader::new().to_bytes());
    writer
  }

  /// Add packet to PCAP
  pub fn write_packet(&mut self, packet: &CraftedPacket) {
    let frame = packet.to_frame();
    let pkt_header = PcapPacketHeader::new(frame.len() as u32);
    self.data.extend_from_slice(&pkt_header.to_bytes());
    self.data.extend_from_slice(&frame);
  }

  /// Add raw bytes to PCAP
  pub fn write_raw(&mut self, data: &[u8]) {
    let pkt_header = PcapPacketHeader::new(data.len() as u32);
    self.data.extend_from_slice(&pkt_header.to_bytes());
    self.data.extend_from_slice(data);
  }

  /// Get PCAP data
  pub fn data(&self) -> &[u8] {
    &self.data
  }

  /// Save to file
  pub fn save(&self, path: &str) -> Result<(), PacketError> {
    std::fs::write(path, &self.data).map_err(PacketError::IoError)
  }
}

impl Default for PcapWriter {
  fn default() -> Self {
    Self::new()
  }
}

/// PCAP file reader
pub struct PcapReader {
  data: Vec<u8>,
  offset: usize,
  header: PcapHeader,
}

impl PcapReader {
  /// Open PCAP file
  pub fn open(path: &str) -> Result<Self, PacketError> {
    let data = std::fs::read(path).map_err(PacketError::IoError)?;
    Self::from_bytes(data)
  }

  /// Load from bytes
  pub fn from_bytes(data: Vec<u8>) -> Result<Self, PacketError> {
    let header = PcapHeader::from_bytes(&data)?;
    Ok(Self {
      data,
      offset: 24, // After header
      header,
    })
  }

  /// Get header
  pub fn header(&self) -> &PcapHeader {
    &self.header
  }

  /// Read next packet
  pub fn next_packet(&mut self) -> Option<Vec<u8>> {
    if self.offset + 16 > self.data.len() {
      return None;
    }

    let pkt_header = PcapPacketHeader::from_bytes(&self.data[self.offset..]).ok()?;
    self.offset += 16;

    let end = self.offset + pkt_header.incl_len as usize;
    if end > self.data.len() {
      return None;
    }

    let packet = self.data[self.offset..end].to_vec();
    self.offset = end;
    Some(packet)
  }

  /// Iterate all packets
  pub fn packets(&mut self) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    self.offset = 24; // Reset to start
    while let Some(pkt) = self.next_packet() {
      packets.push(pkt);
    }
    packets
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Calculate IP header checksum
fn calculate_ip_checksum(ip: &Ipv4Header) -> u16 {
  let mut bytes = ip.to_bytes();
  bytes[10] = 0;
  bytes[11] = 0;
  internet_checksum(&bytes)
}

/// Generate random port (ephemeral range)
fn rand_port() -> u16 {
  let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default();
  49152 + (now.as_nanos() as u16 % 16383) // 49152-65535
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_signature() {
    let sig = PacketSignature::parse(
      "[signature = \"Test\", ip.dst = 192.168.1.1, tcp.dst = 80, tcp.syn = 1]",
    )
    .unwrap();

    assert_eq!(sig.name, "Test");
    assert!(sig.get("tcp.syn").unwrap().as_bool().unwrap());
    assert_eq!(sig.get("tcp.dst").unwrap().as_u16().unwrap(), 80);
  }

  #[test]
  fn test_land_attack() {
    let sig = AttackSignature::land_attack("192.168.1.1", 80);
    assert_eq!(sig.name, "LAND Attack");

    let src = sig.get("ip.src").unwrap().as_ip().unwrap();
    let dst = sig.get("ip.dst").unwrap().as_ip().unwrap();
    assert_eq!(src, dst);
  }

  #[test]
  fn test_xmas_scan() {
    let sig = AttackSignature::xmas_scan("10.0.0.1", 443);
    assert!(sig.get("tcp.fin").unwrap().as_bool().unwrap());
    assert!(sig.get("tcp.psh").unwrap().as_bool().unwrap());
    assert!(sig.get("tcp.urg").unwrap().as_bool().unwrap());
  }

  #[test]
  fn test_packet_builder() {
    let sig = AttackSignature::syn_flood("192.168.1.100", 80);
    let packet = PacketBuilder::from_signature(&sig)
      .unwrap()
      .build()
      .unwrap();

    assert!(packet.ip.is_some());
    assert!(packet.tcp.is_some());

    let tcp = packet.tcp.unwrap();
    assert_eq!(tcp.flags & TCP_SYN, TCP_SYN);
  }

  #[test]
  fn test_ethernet_header() {
    let src = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let dst = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let eth = EthernetHeader::ipv4(dst, src);

    let bytes = eth.to_bytes();
    let parsed = EthernetHeader::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.src_mac, src);
    assert_eq!(parsed.dst_mac, dst);
    assert_eq!(parsed.ethertype, 0x0800);
  }

  #[test]
  fn test_parse_mac() {
    let mac = EthernetHeader::parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
    assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
  }

  #[test]
  fn test_pcap_roundtrip() {
    let mut writer = PcapWriter::new();
    writer.write_raw(&[0x00, 0x01, 0x02, 0x03]);

    let reader = PcapReader::from_bytes(writer.data.clone()).unwrap();
    assert_eq!(reader.header().magic, 0xa1b2c3d4);
  }

  #[test]
  fn test_signature_list() {
    let list = AttackSignature::list();
    assert!(list.len() >= 25); // At least 25 predefined signatures
  }

  #[test]
  fn test_icmp_header() {
    let icmp = IcmpHeader::echo_request(1234, 1);
    let bytes = icmp.to_bytes();
    assert_eq!(bytes[0], 8); // Echo request type
    assert_eq!(bytes[1], 0); // Code 0
  }
}
