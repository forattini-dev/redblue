//! JA3/JA3S Fingerprinting
//!
//! Calculate JA3 (client) and JA3S (server) fingerprints from TLS handshake data.
//!
//! JA3 Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//! JA3S Format: SSLVersion,Cipher,Extensions

use crate::crypto::md5;

/// JA3 fingerprint (TLS client fingerprint)
#[derive(Debug, Clone)]
pub struct Ja3Fingerprint {
  /// TLS version
  pub version: u16,
  /// Cipher suites offered
  pub ciphers: Vec<u16>,
  /// Extensions
  pub extensions: Vec<u16>,
  /// Elliptic curves (supported groups)
  pub elliptic_curves: Vec<u16>,
  /// EC point formats
  pub ec_point_formats: Vec<u8>,
  /// Raw JA3 string
  pub ja3_string: String,
  /// MD5 hash of JA3 string
  pub ja3_hash: String,
}

/// JA3S fingerprint (TLS server fingerprint)
#[derive(Debug, Clone)]
pub struct Ja3sFingerprint {
  /// TLS version
  pub version: u16,
  /// Selected cipher suite
  pub cipher: u16,
  /// Extensions
  pub extensions: Vec<u16>,
  /// Raw JA3S string
  pub ja3s_string: String,
  /// MD5 hash of JA3S string
  pub ja3s_hash: String,
}

/// TLS fingerprinter
pub struct TlsFingerprinter;

impl TlsFingerprinter {
  /// Calculate JA3 fingerprint from ClientHello data
  ///
  /// Input should be the raw ClientHello handshake message (without record layer)
  pub fn ja3(client_hello: &[u8]) -> Result<Ja3Fingerprint, String> {
    if client_hello.len() < 38 {
      return Err("ClientHello too short".to_string());
    }

    // Parse ClientHello
    // Handshake type (1) + length (3) + version (2) + random (32)
    let mut pos = 0;

    // Skip handshake header if present
    if client_hello[0] == 0x01 {
      pos = 4; // Skip type + length
    }

    // TLS version
    let version = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
    pos += 2;

    // Skip random (32 bytes)
    pos += 32;

    // Session ID length + skip
    if pos >= client_hello.len() {
      return Err("Invalid ClientHello: truncated at session ID".to_string());
    }
    let session_id_len = client_hello[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > client_hello.len() {
      return Err("Invalid ClientHello: truncated at cipher suites".to_string());
    }
    let cipher_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2;

    let mut ciphers = Vec::new();
    let cipher_end = pos + cipher_len;
    while pos + 2 <= cipher_end && pos + 2 <= client_hello.len() {
      let cipher = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
      // Skip GREASE values (0x?a?a pattern)
      if !Self::is_grease(cipher) {
        ciphers.push(cipher);
      }
      pos += 2;
    }
    pos = cipher_end;

    // Compression methods (skip)
    if pos >= client_hello.len() {
      return Err("Invalid ClientHello: truncated at compression".to_string());
    }
    let comp_len = client_hello[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    if pos + 2 <= client_hello.len() {
      let ext_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
      pos += 2;

      let ext_end = pos + ext_len;
      while pos + 4 <= ext_end && pos + 4 <= client_hello.len() {
        let ext_type = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
        let ext_data_len =
          u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
        pos += 4;

        // Skip GREASE
        if !Self::is_grease(ext_type) {
          extensions.push(ext_type);

          // Parse supported_groups (0x000a)
          if ext_type == 0x000a && pos + ext_data_len <= client_hello.len() {
            let curves = Self::parse_supported_groups(&client_hello[pos..pos + ext_data_len]);
            elliptic_curves = curves;
          }

          // Parse ec_point_formats (0x000b)
          if ext_type == 0x000b && pos + ext_data_len <= client_hello.len() {
            ec_point_formats = Self::parse_ec_point_formats(&client_hello[pos..pos + ext_data_len]);
          }
        }

        pos += ext_data_len;
      }
    }

    // Build JA3 string
    let ja3_string = format!(
      "{},{},{},{},{}",
      version,
      ciphers
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-"),
      extensions
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-"),
      elliptic_curves
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-"),
      ec_point_formats
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-"),
    );

    // Calculate MD5 hash
    let hash = md5::md5(ja3_string.as_bytes());
    let ja3_hash = hash.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(Ja3Fingerprint {
      version,
      ciphers,
      extensions,
      elliptic_curves,
      ec_point_formats,
      ja3_string,
      ja3_hash,
    })
  }

  /// Calculate JA3S fingerprint from ServerHello data
  pub fn ja3s(server_hello: &[u8]) -> Result<Ja3sFingerprint, String> {
    if server_hello.len() < 38 {
      return Err("ServerHello too short".to_string());
    }

    let mut pos = 0;

    // Skip handshake header if present
    if server_hello[0] == 0x02 {
      pos = 4;
    }

    // TLS version
    let version = u16::from_be_bytes([server_hello[pos], server_hello[pos + 1]]);
    pos += 2;

    // Skip random (32 bytes)
    pos += 32;

    // Session ID
    if pos >= server_hello.len() {
      return Err("Invalid ServerHello".to_string());
    }
    let session_id_len = server_hello[pos] as usize;
    pos += 1 + session_id_len;

    // Selected cipher suite
    if pos + 2 > server_hello.len() {
      return Err("Invalid ServerHello: truncated at cipher".to_string());
    }
    let cipher = u16::from_be_bytes([server_hello[pos], server_hello[pos + 1]]);
    pos += 2;

    // Compression method (skip)
    pos += 1;

    // Extensions
    let mut extensions = Vec::new();

    if pos + 2 <= server_hello.len() {
      let ext_len = u16::from_be_bytes([server_hello[pos], server_hello[pos + 1]]) as usize;
      pos += 2;

      let ext_end = pos + ext_len;
      while pos + 4 <= ext_end && pos + 4 <= server_hello.len() {
        let ext_type = u16::from_be_bytes([server_hello[pos], server_hello[pos + 1]]);
        let ext_data_len =
          u16::from_be_bytes([server_hello[pos + 2], server_hello[pos + 3]]) as usize;
        pos += 4;

        if !Self::is_grease(ext_type) {
          extensions.push(ext_type);
        }

        pos += ext_data_len;
      }
    }

    // Build JA3S string
    let ja3s_string = format!(
      "{},{},{}",
      version,
      cipher,
      extensions
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-"),
    );

    // Calculate MD5 hash
    let hash = md5::md5(ja3s_string.as_bytes());
    let ja3s_hash = hash.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(Ja3sFingerprint {
      version,
      cipher,
      extensions,
      ja3s_string,
      ja3s_hash,
    })
  }

  /// Check if value is a GREASE value
  fn is_grease(value: u16) -> bool {
    // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, etc.
    let high = (value >> 8) as u8;
    let low = (value & 0xff) as u8;
    high == low && (high & 0x0f) == 0x0a
  }

  /// Parse supported_groups extension
  fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    let mut groups = Vec::new();
    if data.len() < 2 {
      return groups;
    }

    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;

    while pos + 2 <= data.len() && pos < 2 + len {
      let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
      if !Self::is_grease(group) {
        groups.push(group);
      }
      pos += 2;
    }

    groups
  }

  /// Parse ec_point_formats extension
  fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
      return Vec::new();
    }

    let len = data[0] as usize;
    data[1..].iter().take(len).copied().collect()
  }

  /// Get human-readable cipher suite name
  pub fn cipher_name(cipher: u16) -> &'static str {
    match cipher {
      0x1301 => "TLS_AES_128_GCM_SHA256",
      0x1302 => "TLS_AES_256_GCM_SHA384",
      0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
      0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
      0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
      0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
      0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
      _ => "Unknown",
    }
  }

  /// Get TLS version name
  pub fn version_name(version: u16) -> &'static str {
    match version {
      0x0300 => "SSL 3.0",
      0x0301 => "TLS 1.0",
      0x0302 => "TLS 1.1",
      0x0303 => "TLS 1.2",
      0x0304 => "TLS 1.3",
      _ => "Unknown",
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_is_grease() {
    assert!(TlsFingerprinter::is_grease(0x0a0a));
    assert!(TlsFingerprinter::is_grease(0x1a1a));
    assert!(TlsFingerprinter::is_grease(0xfafa));
    assert!(!TlsFingerprinter::is_grease(0x0001));
    assert!(!TlsFingerprinter::is_grease(0x1301));
  }

  #[test]
  fn test_version_name() {
    assert_eq!(TlsFingerprinter::version_name(0x0303), "TLS 1.2");
    assert_eq!(TlsFingerprinter::version_name(0x0304), "TLS 1.3");
  }

  #[test]
  fn test_cipher_name() {
    assert_eq!(
      TlsFingerprinter::cipher_name(0x1301),
      "TLS_AES_128_GCM_SHA256"
    );
  }
}
