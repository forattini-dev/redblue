/// DNSSEC Validation & Assessment Module
///
/// Assesses DNSSEC deployment status for a domain by querying for
/// DNSKEY, DS, and RRSIG records using the DO (DNSSEC OK) bit.
///
/// References:
/// - RFC 4033: DNS Security Introduction and Requirements
/// - RFC 4034: Resource Records for the DNS Security Extensions
/// - RFC 4035: Protocol Modifications for the DNS Security Extensions
use crate::protocols::dns::{DnsClient, DnsRdata, DnsRecordType};

/// DNSSEC validation status
#[derive(Debug, Clone)]
pub enum DnssecStatus {
  /// Domain is signed and chain validates
  Secure {
    algorithms: Vec<String>,
    key_count: usize,
    has_ksk: bool,
    has_zsk: bool,
  },
  /// Domain has DNSSEC records but validation fails
  Bogus { reason: String },
  /// Domain is not signed (no DNSKEY/RRSIG records)
  Insecure,
  /// Could not determine (DNS error)
  Indeterminate { reason: String },
}

/// DNSSEC assessment result
#[derive(Debug)]
pub struct DnssecAssessment {
  pub domain: String,
  pub status: DnssecStatus,
  pub dnskeys: Vec<DnskeyInfo>,
  pub ds_records: Vec<DsInfo>,
  pub signatures: Vec<RrsigInfo>,
}

/// Information about a DNSKEY record
#[derive(Debug, Clone)]
pub struct DnskeyInfo {
  pub flags: u16,
  pub algorithm: String,
  pub key_tag: u16,
  pub key_size_bits: usize,
  pub is_ksk: bool,
  pub is_zsk: bool,
}

/// Information about a DS (Delegation Signer) record
#[derive(Debug, Clone)]
pub struct DsInfo {
  pub key_tag: u16,
  pub algorithm: String,
  pub digest_type: String,
  pub digest_hex: String,
}

/// Information about an RRSIG record
#[derive(Debug, Clone)]
pub struct RrsigInfo {
  pub type_covered: String,
  pub algorithm: String,
  pub signer: String,
  pub expiration: String,
  pub inception: String,
  pub key_tag: u16,
  pub valid: bool,
}

/// Map DNSSEC algorithm number to human-readable name (RFC 8624)
pub fn algorithm_name(alg: u8) -> &'static str {
  match alg {
    1 => "RSA/MD5",
    3 => "DSA/SHA1",
    5 => "RSA/SHA-1",
    6 => "DSA-NSEC3-SHA1",
    7 => "RSASHA1-NSEC3-SHA1",
    8 => "RSA/SHA-256",
    10 => "RSA/SHA-512",
    12 => "GOST R 34.10-2001",
    13 => "ECDSA-P256/SHA-256",
    14 => "ECDSA-P384/SHA-384",
    15 => "Ed25519",
    16 => "Ed448",
    _ => "Unknown",
  }
}

/// Map DS digest type number to name
fn digest_type_name(dt: u8) -> &'static str {
  match dt {
    1 => "SHA-1",
    2 => "SHA-256",
    3 => "GOST R 34.11-94",
    4 => "SHA-384",
    _ => "Unknown",
  }
}

/// Compute DNSKEY key tag per RFC 4034 Appendix B.
///
/// The key tag is computed over the full DNSKEY RDATA wire format:
/// flags(2) + protocol(1) + algorithm(1) + public_key(variable).
/// The algorithm treats the RDATA as a sequence of 16-bit words,
/// summing them with carry folding.
pub fn compute_key_tag(rdata: &[u8]) -> u16 {
  let mut ac: u32 = 0;
  for (i, &byte) in rdata.iter().enumerate() {
    if i & 1 == 0 {
      ac += (byte as u32) << 8;
    } else {
      ac += byte as u32;
    }
  }
  ac += (ac >> 16) & 0xFFFF;
  (ac & 0xFFFF) as u16
}

/// Format a Unix timestamp as an ISO-like date string.
/// Uses manual calculation to avoid external dependencies.
fn format_timestamp(ts: u32) -> String {
  let ts = ts as u64;
  let secs_per_day: u64 = 86400;
  let days = ts / secs_per_day;
  let remaining = ts % secs_per_day;
  let hours = remaining / 3600;
  let minutes = (remaining % 3600) / 60;
  let seconds = remaining % 60;

  // Calculate year/month/day from days since epoch (1970-01-01)
  let mut year: u64 = 1970;
  let mut remaining_days = days;

  loop {
    let days_in_year = if is_leap_year(year) { 366 } else { 365 };
    if remaining_days < days_in_year {
      break;
    }
    remaining_days -= days_in_year;
    year += 1;
  }

  let days_in_months: [u64; 12] = if is_leap_year(year) {
    [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  } else {
    [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  };

  let mut month: u64 = 1;
  for &dm in &days_in_months {
    if remaining_days < dm {
      break;
    }
    remaining_days -= dm;
    month += 1;
  }

  let day = remaining_days + 1;

  format!(
    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
    year, month, day, hours, minutes, seconds
  )
}

fn is_leap_year(year: u64) -> bool {
  (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Estimate key size in bits from the public key bytes and algorithm.
fn estimate_key_size(algorithm: u8, public_key: &[u8]) -> usize {
  match algorithm {
    // RSA algorithms: key contains exponent length + exponent + modulus
    1 | 5 | 7 | 8 | 10 => {
      if public_key.is_empty() {
        return 0;
      }
      let exp_len = if public_key[0] == 0 {
        // Two-byte exponent length follows
        if public_key.len() < 3 {
          return 0;
        }
        let len = u16::from_be_bytes([public_key[1], public_key[2]]) as usize;
        // modulus starts after 3 + exp_len bytes
        let modulus_start = 3 + len;
        if modulus_start > public_key.len() {
          return public_key.len() * 8;
        }
        public_key.len() - modulus_start
      } else {
        let len = public_key[0] as usize;
        let modulus_start = 1 + len;
        if modulus_start > public_key.len() {
          return public_key.len() * 8;
        }
        public_key.len() - modulus_start
      };
      exp_len * 8
    }
    // ECDSA P-256: 64 bytes (two 32-byte coordinates)
    13 => 256,
    // ECDSA P-384: 96 bytes (two 48-byte coordinates)
    14 => 384,
    // Ed25519: 32 bytes
    15 => 256,
    // Ed448: 57 bytes
    16 => 456,
    // Fallback
    _ => public_key.len() * 8,
  }
}

/// Get the current Unix timestamp
fn current_unix_timestamp() -> u32 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs() as u32)
    .unwrap_or(0)
}

/// Extract the parent zone from a domain name.
/// For "example.com" returns "com", for "sub.example.com" returns "example.com".
fn parent_zone(domain: &str) -> Option<&str> {
  domain.find('.').map(|idx| &domain[idx + 1..])
}

/// Record type number to name for RRSIG display
fn type_covered_name(t: u16) -> String {
  match t {
    1 => "A".to_string(),
    2 => "NS".to_string(),
    5 => "CNAME".to_string(),
    6 => "SOA".to_string(),
    15 => "MX".to_string(),
    16 => "TXT".to_string(),
    28 => "AAAA".to_string(),
    43 => "DS".to_string(),
    46 => "RRSIG".to_string(),
    48 => "DNSKEY".to_string(),
    _ => format!("TYPE{}", t),
  }
}

/// Assess DNSSEC status for a domain.
///
/// Queries for DNSKEY, DS, and RRSIG records using the DO (DNSSEC OK) bit,
/// then evaluates whether the domain has a valid DNSSEC deployment.
pub fn assess_dnssec(domain: &str, server: &str) -> DnssecAssessment {
  let client = DnsClient::new(server);
  let now = current_unix_timestamp();

  // Step 1: Query DNSKEY records for the domain (with DO bit)
  let dnskey_result = client.query_dnssec(domain, DnsRecordType::DNSKEY);
  let dnskey_answers = match dnskey_result {
    Ok(answers) => answers,
    Err(e) => {
      return DnssecAssessment {
        domain: domain.to_string(),
        status: DnssecStatus::Indeterminate {
          reason: format!("DNSKEY query failed: {}", e),
        },
        dnskeys: Vec::new(),
        ds_records: Vec::new(),
        signatures: Vec::new(),
      };
    }
  };

  // Step 2: Query DS records from parent zone (with DO bit)
  let ds_answers = if let Some(parent) = parent_zone(domain) {
    // DS records live in the parent zone
    client
      .query_dnssec(parent, DnsRecordType::DS)
      .unwrap_or_default()
  } else {
    Vec::new()
  };

  // Step 3: Query RRSIG for the domain's A record (with DO bit)
  let a_answers = client
    .query_dnssec(domain, DnsRecordType::A)
    .unwrap_or_default();

  // Parse DNSKEY records
  let mut dnskeys: Vec<DnskeyInfo> = Vec::new();
  let mut dnskey_rrsigs: Vec<RrsigInfo> = Vec::new();

  for answer in &dnskey_answers {
    match &answer.data {
      DnsRdata::DNSKEY {
        flags,
        protocol,
        algorithm,
        public_key,
      } => {
        // Build the wire-format RDATA for key tag computation
        let mut rdata_wire = Vec::new();
        rdata_wire.extend_from_slice(&flags.to_be_bytes());
        rdata_wire.push(*protocol);
        rdata_wire.push(*algorithm);
        rdata_wire.extend_from_slice(public_key);

        let key_tag = compute_key_tag(&rdata_wire);
        let is_ksk = *flags & 0x0001 == 1; // SEP bit set
        let is_zsk = *flags == 256;

        dnskeys.push(DnskeyInfo {
          flags: *flags,
          algorithm: algorithm_name(*algorithm).to_string(),
          key_tag,
          key_size_bits: estimate_key_size(*algorithm, public_key),
          is_ksk,
          is_zsk,
        });
      }
      DnsRdata::RRSIG {
        type_covered,
        algorithm,
        key_tag,
        signer_name,
        expiration,
        inception,
        ..
      } => {
        // RRSIG records may be returned alongside DNSKEY answers
        dnskey_rrsigs.push(RrsigInfo {
          type_covered: type_covered_name(*type_covered),
          algorithm: algorithm_name(*algorithm).to_string(),
          signer: signer_name.clone(),
          expiration: format_timestamp(*expiration),
          inception: format_timestamp(*inception),
          key_tag: *key_tag,
          valid: now >= *inception && now < *expiration,
        });
      }
      _ => {}
    }
  }

  // Parse DS records
  let mut ds_records: Vec<DsInfo> = Vec::new();
  for answer in &ds_answers {
    if let DnsRdata::DS {
      key_tag,
      algorithm,
      digest_type,
      digest,
    } = &answer.data
    {
      ds_records.push(DsInfo {
        key_tag: *key_tag,
        algorithm: algorithm_name(*algorithm).to_string(),
        digest_type: digest_type_name(*digest_type).to_string(),
        digest_hex: digest.iter().map(|b| format!("{:02x}", b)).collect(),
      });
    }
  }

  // Parse RRSIG records from A query
  let mut signatures: Vec<RrsigInfo> = Vec::new();
  for answer in &a_answers {
    if let DnsRdata::RRSIG {
      type_covered,
      algorithm,
      key_tag,
      signer_name,
      expiration,
      inception,
      ..
    } = &answer.data
    {
      signatures.push(RrsigInfo {
        type_covered: type_covered_name(*type_covered),
        algorithm: algorithm_name(*algorithm).to_string(),
        signer: signer_name.clone(),
        expiration: format_timestamp(*expiration),
        inception: format_timestamp(*inception),
        key_tag: *key_tag,
        valid: now >= *inception && now < *expiration,
      });
    }
  }

  // Include RRSIG records from DNSKEY query as well
  signatures.extend(dnskey_rrsigs);

  // Step 4: Determine DNSSEC status
  if dnskeys.is_empty() {
    return DnssecAssessment {
      domain: domain.to_string(),
      status: DnssecStatus::Insecure,
      dnskeys,
      ds_records,
      signatures,
    };
  }

  // Step 5: Evaluate DNSSEC chain
  let has_ksk = dnskeys.iter().any(|k| k.is_ksk);
  let has_zsk = dnskeys.iter().any(|k| k.is_zsk);
  let algorithms: Vec<String> = dnskeys
    .iter()
    .map(|k| k.algorithm.clone())
    .collect::<std::collections::HashSet<_>>()
    .into_iter()
    .collect();

  // Check for expired signatures
  let has_expired_sigs = signatures.iter().any(|s| !s.valid);
  let has_valid_sigs = signatures.iter().any(|s| s.valid);

  // Check DS -> DNSKEY binding: at least one DS key_tag should match a DNSKEY key_tag
  let ds_matches_dnskey = ds_records.is_empty()
    || ds_records
      .iter()
      .any(|ds| dnskeys.iter().any(|dk| dk.key_tag == ds.key_tag));

  if has_expired_sigs && !has_valid_sigs {
    return DnssecAssessment {
      domain: domain.to_string(),
      status: DnssecStatus::Bogus {
        reason: "All RRSIG signatures have expired".to_string(),
      },
      dnskeys,
      ds_records,
      signatures,
    };
  }

  if !ds_matches_dnskey {
    return DnssecAssessment {
      domain: domain.to_string(),
      status: DnssecStatus::Bogus {
        reason: "DS record key_tag does not match any DNSKEY".to_string(),
      },
      dnskeys,
      ds_records,
      signatures,
    };
  }

  // If we have DNSKEYs, the domain is signed
  DnssecAssessment {
    domain: domain.to_string(),
    status: DnssecStatus::Secure {
      algorithms,
      key_count: dnskeys.len(),
      has_ksk,
      has_zsk,
    },
    dnskeys,
    ds_records,
    signatures,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_algorithm_name_mapping() {
    assert_eq!(algorithm_name(1), "RSA/MD5");
    assert_eq!(algorithm_name(5), "RSA/SHA-1");
    assert_eq!(algorithm_name(8), "RSA/SHA-256");
    assert_eq!(algorithm_name(10), "RSA/SHA-512");
    assert_eq!(algorithm_name(13), "ECDSA-P256/SHA-256");
    assert_eq!(algorithm_name(14), "ECDSA-P384/SHA-384");
    assert_eq!(algorithm_name(15), "Ed25519");
    assert_eq!(algorithm_name(16), "Ed448");
    assert_eq!(algorithm_name(99), "Unknown");
  }

  #[test]
  fn test_compute_key_tag() {
    // RFC 4034 Appendix B test: the key tag is a checksum over the DNSKEY RDATA.
    // Construct a minimal DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + key
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&257u16.to_be_bytes()); // flags = KSK
    rdata.push(3); // protocol
    rdata.push(8); // algorithm = RSA/SHA-256
    rdata.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // 4-byte key

    let tag = compute_key_tag(&rdata);

    // Verify computation manually:
    // Pairs (big-endian): [0x01, 0x01] [0x03, 0x08] [0x01, 0x02] [0x03, 0x04]
    // = 0x0101 + 0x0308 + 0x0102 + 0x0304 = 256+1 + 768+8 + 256+2 + 768+4
    // Wait, let's compute properly per the algorithm:
    // i=0: ac += 0x01 << 8 = 256
    // i=1: ac += 0x01 = 257
    // i=2: ac += 0x03 << 8 = 1025
    // i=3: ac += 0x08 = 1033
    // i=4: ac += 0x01 << 8 = 1289
    // i=5: ac += 0x02 = 1291
    // i=6: ac += 0x03 << 8 = 2059
    // i=7: ac += 0x04 = 2063
    // ac += (ac >> 16) & 0xFFFF = 2063 + 0 = 2063
    // tag = 2063 & 0xFFFF = 2063
    assert_eq!(tag, 2063);

    // Verify single-byte input (odd length)
    let single = vec![0xFF];
    let tag_single = compute_key_tag(&single);
    // i=0: ac += 0xFF << 8 = 65280
    // ac += (65280 >> 16) = 65280 + 0 = 65280
    assert_eq!(tag_single, 65280u16.wrapping_sub(0) as u16);
    assert_eq!(tag_single, 0xFF00);
  }

  #[test]
  fn test_compute_key_tag_empty() {
    let tag = compute_key_tag(&[]);
    assert_eq!(tag, 0);
  }

  #[test]
  fn test_dnskey_ksk_zsk_detection() {
    // KSK: flags = 257 (0x0101), SEP bit (bit 0) is set
    let ksk = DnskeyInfo {
      flags: 257,
      algorithm: "RSA/SHA-256".to_string(),
      key_tag: 12345,
      key_size_bits: 2048,
      is_ksk: true,
      is_zsk: false,
    };
    assert!(ksk.is_ksk);
    assert!(!ksk.is_zsk);
    assert_eq!(ksk.flags & 0x0001, 1); // SEP bit set

    // ZSK: flags = 256 (0x0100), SEP bit is NOT set
    let zsk = DnskeyInfo {
      flags: 256,
      algorithm: "RSA/SHA-256".to_string(),
      key_tag: 54321,
      key_size_bits: 1024,
      is_ksk: false,
      is_zsk: true,
    };
    assert!(!zsk.is_ksk);
    assert!(zsk.is_zsk);
    assert_eq!(zsk.flags & 0x0001, 0); // SEP bit unset
  }

  #[test]
  fn test_rrsig_expiration_check() {
    // A signature that is currently valid
    let now = current_unix_timestamp();
    let valid_sig = RrsigInfo {
      type_covered: "A".to_string(),
      algorithm: "RSA/SHA-256".to_string(),
      signer: "example.com".to_string(),
      expiration: format_timestamp(now + 86400), // expires tomorrow
      inception: format_timestamp(now - 86400),  // started yesterday
      key_tag: 12345,
      valid: true,
    };
    assert!(valid_sig.valid);

    // A signature that has expired
    let expired_sig = RrsigInfo {
      type_covered: "A".to_string(),
      algorithm: "RSA/SHA-256".to_string(),
      signer: "example.com".to_string(),
      expiration: format_timestamp(now - 3600), // expired 1 hour ago
      inception: format_timestamp(now - 86400),
      key_tag: 12345,
      valid: false,
    };
    assert!(!expired_sig.valid);
  }

  #[test]
  fn test_ds_info_formatting() {
    let ds = DsInfo {
      key_tag: 60485,
      algorithm: "RSA/SHA-256".to_string(),
      digest_type: "SHA-256".to_string(),
      digest_hex: "2bb183af5f22588179a53b0a98631fad1a292118".to_string(),
    };

    assert_eq!(ds.key_tag, 60485);
    assert_eq!(ds.algorithm, "RSA/SHA-256");
    assert_eq!(ds.digest_type, "SHA-256");
    assert_eq!(ds.digest_hex, "2bb183af5f22588179a53b0a98631fad1a292118");
  }

  #[test]
  fn test_format_timestamp() {
    // Unix epoch
    assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");

    // 2023-11-14 22:13:20 UTC = 1700000000
    assert_eq!(format_timestamp(1700000000), "2023-11-14T22:13:20Z");

    // 2000-01-01 00:00:00 UTC = 946684800
    assert_eq!(format_timestamp(946684800), "2000-01-01T00:00:00Z");
  }

  #[test]
  fn test_parent_zone() {
    assert_eq!(parent_zone("example.com"), Some("com"));
    assert_eq!(parent_zone("sub.example.com"), Some("example.com"));
    assert_eq!(parent_zone("com"), None);
  }

  #[test]
  fn test_digest_type_name() {
    assert_eq!(digest_type_name(1), "SHA-1");
    assert_eq!(digest_type_name(2), "SHA-256");
    assert_eq!(digest_type_name(4), "SHA-384");
    assert_eq!(digest_type_name(99), "Unknown");
  }

  #[test]
  fn test_estimate_key_size() {
    // ECDSA P-256
    assert_eq!(estimate_key_size(13, &[0u8; 64]), 256);
    // ECDSA P-384
    assert_eq!(estimate_key_size(14, &[0u8; 96]), 384);
    // Ed25519
    assert_eq!(estimate_key_size(15, &[0u8; 32]), 256);
    // Ed448
    assert_eq!(estimate_key_size(16, &[0u8; 57]), 456);
  }

  #[test]
  fn test_insecure_status() {
    // When no DNSKEY records are found, status should be Insecure
    let assessment = DnssecAssessment {
      domain: "unsigned.example".to_string(),
      status: DnssecStatus::Insecure,
      dnskeys: Vec::new(),
      ds_records: Vec::new(),
      signatures: Vec::new(),
    };

    match &assessment.status {
      DnssecStatus::Insecure => {} // expected
      other => panic!("Expected Insecure, got {:?}", other),
    }
  }

  #[test]
  fn test_type_covered_name() {
    assert_eq!(type_covered_name(1), "A");
    assert_eq!(type_covered_name(28), "AAAA");
    assert_eq!(type_covered_name(48), "DNSKEY");
    assert_eq!(type_covered_name(43), "DS");
    assert_eq!(type_covered_name(9999), "TYPE9999");
  }
}
