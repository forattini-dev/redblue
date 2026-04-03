//! Shared helper utilities for database commands

use std::net::IpAddr;
use std::path::Path;

use crate::storage::layout::SegmentKind;
use crate::storage::primitives::encoding::IpKey;
use crate::storage::records::{
    DnsRecordData, DnsRecordType, PortScanRecord, PortStatus, SubdomainRecord,
};
use crate::storage::service::PartitionKey;
use crate::storage::QueryManager;

/// Open a RedDB database file
pub fn open_db(path: &Path) -> Result<QueryManager, String> {
    QueryManager::open(path)
        .map_err(|e| format!("Failed to open database {}: {}", path.display(), e))
}

/// Read all port scan records from database
pub fn read_port_scans(db: &mut QueryManager) -> Result<Vec<PortScanRecord>, String> {
    db.list_port_scans()
        .map_err(|e| format!("Failed to read port scans: {}", e))
}

/// Read all DNS records from database
pub fn read_dns_records(db: &mut QueryManager) -> Result<Vec<DnsRecordData>, String> {
    db.list_dns_records_all()
        .map_err(|e| format!("Failed to read DNS records: {}", e))
}

/// Read all subdomain records from database
pub fn read_subdomains(db: &mut QueryManager) -> Result<Vec<SubdomainRecord>, String> {
    db.list_subdomains_all()
        .map_err(|e| format!("Failed to read subdomains: {}", e))
}

/// Get label for port status
pub fn port_status_label(status: PortStatus) -> &'static str {
    match status {
        PortStatus::Open => "OPEN",
        PortStatus::Closed => "CLOSED",
        PortStatus::Filtered => "FILTERED",
        PortStatus::OpenFiltered => "OPEN|FILTERED",
    }
}

/// Get label for DNS record type
pub fn dns_type_label(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::MX => "MX",
        DnsRecordType::NS => "NS",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::CNAME => "CNAME",
    }
}

/// Get label for segment kind
pub fn segment_label(kind: SegmentKind) -> &'static str {
    kind.as_str()
}

/// Parse an IP range string (e.g., "192.168.1.1-192.168.1.255")
pub fn parse_ip_range(range: &str) -> Result<(IpAddr, IpAddr), String> {
    let mut parts = range.split('-');
    let start = parts
        .next()
        .ok_or_else(|| "Invalid IP range format. Expected start-end".to_string())?
        .trim();
    let end = parts
        .next()
        .ok_or_else(|| "Invalid IP range format. Expected start-end".to_string())?
        .trim();
    if parts.next().is_some() {
        return Err("Invalid IP range format. Expected start-end".to_string());
    }

    let start_ip: IpAddr = start
        .parse()
        .map_err(|_| format!("Invalid IP address: {}", start))?;
    let end_ip: IpAddr = end
        .parse()
        .map_err(|_| format!("Invalid IP address: {}", end))?;

    if start_ip.is_ipv4() != end_ip.is_ipv4() {
        return Err("IP range must use addresses from the same family".to_string());
    }

    let start_key = IpKey::from(&start_ip);
    let end_key = IpKey::from(&end_ip);
    if start_key > end_key {
        return Err("IP range start must be <= end".to_string());
    }

    Ok((start_ip, end_ip))
}

/// Parse segment kind from string
pub fn parse_segment_kind(name: &str) -> Result<SegmentKind, String> {
    match name.to_ascii_lowercase().as_str() {
        "ports" => Ok(SegmentKind::Ports),
        "subdomains" => Ok(SegmentKind::Subdomains),
        "whois" => Ok(SegmentKind::Whois),
        "tls" => Ok(SegmentKind::Tls),
        "dns" => Ok(SegmentKind::Dns),
        "http" => Ok(SegmentKind::Http),
        "host" | "hosts" => Ok(SegmentKind::Host),
        other => Err(format!(
            "Unknown segment '{}'. Expected one of: ports, subdomains, whois, tls, dns, http, host",
            other
        )),
    }
}

/// Parse attribute filter (key=value)
pub fn parse_attr_filter(filter: &str) -> Result<(&str, &str), String> {
    let mut parts = filter.splitn(2, '=');
    let key = parts.next().unwrap().trim();
    let value = parts
        .next()
        .ok_or_else(|| "Attribute filter must use key=value syntax".to_string())?
        .trim();
    if key.is_empty() || value.is_empty() {
        return Err("Attribute filter must use key=value syntax".to_string());
    }
    Ok((key, value))
}

/// Describe partition key for display
pub fn describe_partition_key(key: &PartitionKey) -> String {
    match key {
        PartitionKey::Domain(domain) => format!("domain:{}", domain),
        PartitionKey::Target(target) => format!("target:{}", target),
        PartitionKey::Date(epoch) => format!("date:{}", epoch),
        PartitionKey::Custom(label) => format!("custom:{}", label),
    }
}
