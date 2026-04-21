use super::payloads::format_timestamp;
use crate::modules::intel::{Ioc, IocCollection, IocSource, IocType};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn populate_sample_database(collection: &mut IocCollection) {
  // Add diverse IOCs for search testing
  let sample_iocs = vec![
    (
      IocType::IPv4,
      "192.168.1.1",
      "port_scan",
      85,
      vec!["internal", "scan"],
    ),
    (
      IocType::IPv4,
      "192.168.1.100",
      "port_scan",
      75,
      vec!["internal", "ssh"],
    ),
    (
      IocType::IPv4,
      "10.0.0.1",
      "dns_query",
      90,
      vec!["gateway", "router"],
    ),
    (
      IocType::IPv4,
      "93.184.216.34",
      "dns_query",
      95,
      vec!["example", "public"],
    ),
    (
      IocType::IPv4,
      "8.8.8.8",
      "dns_server",
      80,
      vec!["google", "dns"],
    ),
    (
      IocType::IPv6,
      "2001:db8::1",
      "dns_query",
      70,
      vec!["ipv6", "test"],
    ),
    (
      IocType::Domain,
      "example.com",
      "dns_query",
      95,
      vec!["example", "public"],
    ),
    (
      IocType::Domain,
      "malware.bad.com",
      "threat_intel",
      99,
      vec!["malware", "c2"],
    ),
    (
      IocType::Domain,
      "api.example.com",
      "subdomain_enum",
      85,
      vec!["api", "subdomain"],
    ),
    (
      IocType::Domain,
      "mail.example.com",
      "dns_mx",
      80,
      vec!["mail", "mx"],
    ),
    (
      IocType::Domain,
      "cdn.example.com",
      "subdomain_enum",
      75,
      vec!["cdn", "subdomain"],
    ),
    (
      IocType::Url,
      "http://example.com/login",
      "web_crawl",
      70,
      vec!["login", "auth"],
    ),
    (
      IocType::Url,
      "https://api.example.com/v1/users",
      "web_crawl",
      65,
      vec!["api", "rest"],
    ),
    (
      IocType::Email,
      "admin@example.com",
      "whois",
      60,
      vec!["admin", "contact"],
    ),
    (
      IocType::Email,
      "security@example.com",
      "harvest",
      55,
      vec!["security", "contact"],
    ),
    (
      IocType::HashSHA256,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "file_scan",
      90,
      vec!["empty", "hash"],
    ),
    (
      IocType::HashMD5,
      "d41d8cd98f00b204e9800998ecf8427e",
      "file_scan",
      85,
      vec!["empty", "md5"],
    ),
    (
      IocType::Certificate,
      "DigiCert:abc123def456",
      "tls_scan",
      80,
      vec!["tls", "cert"],
    ),
    (
      IocType::JA3,
      "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,0-10-11-35-15-13,23-24-25,0",
      "tls_fingerprint",
      75,
      vec!["ja3", "chrome"],
    ),
    (
      IocType::ASN,
      "AS15169",
      "ip_lookup",
      70,
      vec!["google", "asn"],
    ),
    (
      IocType::CIDR,
      "192.168.0.0/24",
      "network_scan",
      65,
      vec!["internal", "subnet"],
    ),
  ];

  for (ioc_type, value, context, confidence, tags) in sample_iocs {
    let mut ioc = Ioc::new(
      ioc_type,
      value,
      IocSource::PortScan, // Simplified for demo
      confidence,
      context,
    );
    for tag in tags {
      ioc = ioc.with_tag(tag);
    }
    collection.add(ioc);
  }
}

/// Generate STIX 2.1 bundle
pub(super) fn to_stix_bundle(collection: &IocCollection, target: &str) -> String {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs();

  let bundle_id = format!("bundle--redblue-{}", now);

  let mut objects = Vec::new();

  // Add identity object
  objects.push(format!(
    r#"{{
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--redblue-scanner",
      "created": "{}",
      "modified": "{}",
      "name": "redblue Scanner",
      "identity_class": "tool"
    }}"#,
    format_timestamp(now),
    format_timestamp(now),
  ));

  // Add indicator objects for each IOC
  for (i, ioc) in collection.all().iter().enumerate() {
    let indicator_id = format!("indicator--redblue-{}-{}", now, i);
    let pattern = ioc.to_stix_pattern();

    let labels: Vec<String> = ioc.tags.iter().map(|t| format!("\"{}\"", t)).collect();

    objects.push(format!(
      r#"{{
      "type": "indicator",
      "spec_version": "2.1",
      "id": "{}",
      "created": "{}",
      "modified": "{}",
      "name": "{} IOC",
      "description": "IOC extracted from {} by redblue",
      "indicator_types": ["unknown"],
      "pattern": "{}",
      "pattern_type": "stix",
      "valid_from": "{}",
      "labels": [{}],
      "confidence": {}
    }}"#,
      indicator_id,
      format_timestamp(ioc.first_seen),
      format_timestamp(ioc.last_seen),
      ioc.ioc_type,
      target,
      pattern.replace('"', "\\\""),
      format_timestamp(ioc.first_seen),
      labels.join(", "),
      ioc.confidence_score,
    ));
  }

  format!(
    r#"{{
  "type": "bundle",
  "id": "{}",
  "objects": [
    {}
  ]
}}"#,
    bundle_id,
    objects.join(",\n    ")
  )
}
