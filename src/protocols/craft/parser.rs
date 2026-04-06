//! Pigsty-style Signature Parser
//!
//! Parses packet signatures in a simple field=value format.
//!
//! Syntax:
//! ```text
//! # Comment
//! name = "SYN Flood";
//! description = "TCP SYN flood packet";
//! category = "DoS";
//!
//! ip.src = 192.168.1.1;
//! ip.dst = $TARGET;
//! ip.ttl = 64;
//!
//! tcp.sport = random(1024, 65535);
//! tcp.dport = 80;
//! tcp.flags = SYN;
//!
//! payload = "GET / HTTP/1.0\r\n\r\n";
//! ```

use super::signature::{parse_tcp_flags, FieldValue, LayerField, PacketSignature};
use std::net::Ipv4Addr;

/// Parse error types
#[derive(Debug)]
pub enum ParseError {
  /// Invalid field name
  InvalidField(String),
  /// Invalid value for field
  InvalidValue(String, String),
  /// Syntax error
  SyntaxError(usize, String),
  /// Missing required field
  MissingField(String),
  /// Unexpected end of input
  UnexpectedEof,
}

impl std::fmt::Display for ParseError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ParseError::InvalidField(field) => write!(f, "Invalid field: {}", field),
      ParseError::InvalidValue(field, value) => {
        write!(f, "Invalid value '{}' for field '{}'", value, field)
      }
      ParseError::SyntaxError(line, msg) => write!(f, "Line {}: {}", line, msg),
      ParseError::MissingField(field) => write!(f, "Missing required field: {}", field),
      ParseError::UnexpectedEof => write!(f, "Unexpected end of input"),
    }
  }
}

impl std::error::Error for ParseError {}

/// Signature parser
pub struct SignatureParser {
  /// Current line number for error reporting
  line: usize,
}

impl SignatureParser {
  pub fn new() -> Self {
    Self { line: 0 }
  }

  /// Parse a signature string into a PacketSignature
  pub fn parse(&mut self, input: &str) -> Result<PacketSignature, ParseError> {
    let mut sig = PacketSignature::default();
    self.line = 0;

    for line in input.lines() {
      self.line += 1;
      let line = line.trim();

      // Skip empty lines and comments
      if line.is_empty() || line.starts_with('#') {
        continue;
      }

      // Parse field = value
      self.parse_line(line, &mut sig)?;
    }

    Ok(sig)
  }

  /// Parse a single line
  fn parse_line(&self, line: &str, sig: &mut PacketSignature) -> Result<(), ParseError> {
    // Find the '=' separator
    let eq_pos = line
      .find('=')
      .ok_or_else(|| ParseError::SyntaxError(self.line, format!("Expected '=' in: {}", line)))?;

    let field_str = line[..eq_pos].trim();
    let mut value_str = line[eq_pos + 1..].trim();

    // Remove trailing semicolon
    if value_str.ends_with(';') {
      value_str = &value_str[..value_str.len() - 1].trim_end();
    }

    // Handle metadata fields
    match field_str.to_lowercase().as_str() {
      "name" => {
        sig.name = self.parse_string(value_str)?;
        return Ok(());
      }
      "description" | "desc" => {
        sig.description = self.parse_string(value_str)?;
        return Ok(());
      }
      "category" | "cat" => {
        sig.category = self.parse_string(value_str)?;
        return Ok(());
      }
      _ => {}
    }

    // Parse layer field
    let field = LayerField::from_str(field_str)
      .ok_or_else(|| ParseError::InvalidField(field_str.to_string()))?;

    // Parse value based on field type
    let value = self.parse_value(&field, value_str)?;

    sig
      .set_field(field, value)
      .map_err(|e| ParseError::InvalidValue(field_str.to_string(), e))
  }

  /// Parse a quoted string
  fn parse_string(&self, s: &str) -> Result<String, ParseError> {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
      Ok(unescape_string(&s[1..s.len() - 1]))
    } else if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
      Ok(unescape_string(&s[1..s.len() - 1]))
    } else {
      Ok(s.to_string())
    }
  }

  /// Parse a field value
  fn parse_value(&self, field: &LayerField, s: &str) -> Result<FieldValue, ParseError> {
    let s = s.trim();

    // Check for variable reference
    if s.starts_with('$') {
      return Ok(FieldValue::Variable(s[1..].to_string()));
    }

    // Check for random() function
    if s.starts_with("random(") && s.ends_with(')') {
      // For now, return a default value; actual random would be at build time
      return self.parse_random(field, s);
    }

    match field {
      LayerField::IpSrc | LayerField::IpDst => {
        let ip: Ipv4Addr = s
          .parse()
          .map_err(|_| ParseError::InvalidValue(format!("{:?}", field), s.to_string()))?;
        Ok(FieldValue::Ipv4(ip))
      }
      LayerField::EthSrc | LayerField::EthDst => {
        let mac = parse_mac(s)?;
        Ok(FieldValue::Mac(mac))
      }
      LayerField::EthType
      | LayerField::IpId
      | LayerField::TcpSport
      | LayerField::TcpDport
      | LayerField::TcpWindow
      | LayerField::TcpUrgent
      | LayerField::UdpSport
      | LayerField::UdpDport
      | LayerField::IcmpId
      | LayerField::IcmpSeq => {
        let v = self.parse_u16(s)?;
        Ok(FieldValue::U16(v))
      }
      LayerField::IpTtl
      | LayerField::IpProto
      | LayerField::IpFlags
      | LayerField::IpTos
      | LayerField::IcmpType
      | LayerField::IcmpCode => {
        let v = self.parse_u8(s)?;
        Ok(FieldValue::U8(v))
      }
      LayerField::TcpSeq | LayerField::TcpAck => {
        let v = self.parse_u32(s)?;
        Ok(FieldValue::U32(v))
      }
      LayerField::TcpFlags => {
        let flags = parse_tcp_flags(s);
        Ok(FieldValue::TcpFlags(flags))
      }
      LayerField::Payload => {
        let payload = self.parse_string(s)?;
        Ok(FieldValue::String(payload))
      }
      LayerField::PayloadHex => {
        let bytes = parse_hex(s)?;
        Ok(FieldValue::Bytes(bytes))
      }
    }
  }

  /// Parse a random() function call
  fn parse_random(&self, field: &LayerField, s: &str) -> Result<FieldValue, ParseError> {
    // Extract arguments from random(min, max)
    let args = &s[7..s.len() - 1]; // Remove "random(" and ")"
    let parts: Vec<&str> = args.split(',').map(|p| p.trim()).collect();

    if parts.len() != 2 {
      return Err(ParseError::SyntaxError(
        self.line,
        "random() expects two arguments".to_string(),
      ));
    }

    // Return the minimum value as default (actual random at build time)
    match field {
      LayerField::TcpSport | LayerField::TcpDport | LayerField::UdpSport | LayerField::UdpDport => {
        let min: u16 = parts[0]
          .parse()
          .map_err(|_| ParseError::SyntaxError(self.line, "Invalid min value".to_string()))?;
        Ok(FieldValue::U16(min))
      }
      _ => Err(ParseError::SyntaxError(
        self.line,
        "random() not supported for this field".to_string(),
      )),
    }
  }

  fn parse_u8(&self, s: &str) -> Result<u8, ParseError> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
      u8::from_str_radix(&s[2..], 16)
    } else {
      s.parse()
    }
    .map_err(|_| ParseError::SyntaxError(self.line, format!("Invalid u8: {}", s)))
  }

  fn parse_u16(&self, s: &str) -> Result<u16, ParseError> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
      u16::from_str_radix(&s[2..], 16)
    } else {
      s.parse()
    }
    .map_err(|_| ParseError::SyntaxError(self.line, format!("Invalid u16: {}", s)))
  }

  fn parse_u32(&self, s: &str) -> Result<u32, ParseError> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
      u32::from_str_radix(&s[2..], 16)
    } else {
      s.parse()
    }
    .map_err(|_| ParseError::SyntaxError(self.line, format!("Invalid u32: {}", s)))
  }
}

impl Default for SignatureParser {
  fn default() -> Self {
    Self::new()
  }
}

/// Parse a MAC address string (e.g., "00:11:22:33:44:55")
fn parse_mac(s: &str) -> Result<[u8; 6], ParseError> {
  let s = s.trim();
  let parts: Vec<&str> = s.split(|c| c == ':' || c == '-').collect();

  if parts.len() != 6 {
    return Err(ParseError::InvalidValue("MAC".to_string(), s.to_string()));
  }

  let mut mac = [0u8; 6];
  for (i, part) in parts.iter().enumerate() {
    mac[i] = u8::from_str_radix(part, 16)
      .map_err(|_| ParseError::InvalidValue("MAC".to_string(), s.to_string()))?;
  }

  Ok(mac)
}

/// Parse hex string (e.g., "deadbeef" or "de ad be ef")
fn parse_hex(s: &str) -> Result<Vec<u8>, ParseError> {
  let s = s.trim();

  // Remove quotes if present
  let s = if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))
  {
    &s[1..s.len() - 1]
  } else {
    s
  };

  // Remove spaces
  let hex_str: String = s.chars().filter(|c| !c.is_whitespace()).collect();

  if hex_str.len() % 2 != 0 {
    return Err(ParseError::InvalidValue(
      "hex".to_string(),
      "odd number of hex digits".to_string(),
    ));
  }

  let mut result = Vec::with_capacity(hex_str.len() / 2);
  for i in (0..hex_str.len()).step_by(2) {
    let byte = u8::from_str_radix(&hex_str[i..i + 2], 16)
      .map_err(|_| ParseError::InvalidValue("hex".to_string(), s.to_string()))?;
    result.push(byte);
  }

  Ok(result)
}

/// Unescape a string (handle \n, \r, \t, \\, \")
fn unescape_string(s: &str) -> String {
  let mut result = String::with_capacity(s.len());
  let mut chars = s.chars().peekable();

  while let Some(c) = chars.next() {
    if c == '\\' {
      match chars.next() {
        Some('n') => result.push('\n'),
        Some('r') => result.push('\r'),
        Some('t') => result.push('\t'),
        Some('\\') => result.push('\\'),
        Some('"') => result.push('"'),
        Some('\'') => result.push('\''),
        Some('0') => result.push('\0'),
        Some('x') => {
          // \xHH
          let mut hex = String::new();
          if let Some(h1) = chars.next() {
            hex.push(h1);
          }
          if let Some(h2) = chars.next() {
            hex.push(h2);
          }
          if let Ok(byte) = u8::from_str_radix(&hex, 16) {
            result.push(byte as char);
          }
        }
        Some(other) => {
          result.push('\\');
          result.push(other);
        }
        None => result.push('\\'),
      }
    } else {
      result.push(c);
    }
  }

  result
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_basic_signature() {
    let input = r#"
            name = "Test Packet";
            ip.src = 192.168.1.1;
            ip.dst = 10.0.0.1;
            ip.ttl = 64;
            tcp.dport = 80;
            tcp.flags = SYN;
        "#;

    let mut parser = SignatureParser::new();
    let sig = parser.parse(input).unwrap();

    assert_eq!(sig.name, "Test Packet");
    assert_eq!(sig.ipv4.src, Some(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(sig.ipv4.dst, Some(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(sig.ipv4.ttl, 64);
    assert!(sig.tcp.is_some());
    assert_eq!(sig.tcp.as_ref().unwrap().dport, Some(80));
  }

  #[test]
  fn test_parse_hex_values() {
    let input = "ip.flags = 0x02;";
    let mut parser = SignatureParser::new();
    let sig = parser.parse(input).unwrap();
    assert_eq!(sig.ipv4.flags, 2);
  }

  #[test]
  fn test_parse_mac_address() {
    let input = "eth.src = 00:11:22:33:44:55;";
    let mut parser = SignatureParser::new();
    let sig = parser.parse(input).unwrap();
    assert_eq!(
      sig.ethernet.src_mac,
      Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
  }

  #[test]
  fn test_parse_payload() {
    let input = r#"payload = "GET / HTTP/1.0\r\n\r\n";"#;
    let mut parser = SignatureParser::new();
    let sig = parser.parse(input).unwrap();
    assert_eq!(sig.payload, b"GET / HTTP/1.0\r\n\r\n");
  }

  #[test]
  fn test_unescape_string() {
    assert_eq!(unescape_string(r"hello\nworld"), "hello\nworld");
    assert_eq!(unescape_string(r"\r\n"), "\r\n");
    assert_eq!(unescape_string(r"\x41\x42"), "AB");
  }
}
