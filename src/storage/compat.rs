use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocols::x509::{parse_x509_time, X509Certificate};
use crate::storage::schema::{
    DnsRecordData, DnsRecordType, HostIntelRecord, HttpHeadersRecord, PortScanRecord, PortStatus,
    SubdomainSource,
};
use crate::storage::store::Database;

fn now_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn decode_status(state: u8) -> PortStatus {
    match state {
        1 => PortStatus::Open,
        2 => PortStatus::Filtered,
        3 => PortStatus::OpenFiltered,
        _ => PortStatus::Closed,
    }
}

fn encode_status(status: PortStatus) -> u8 {
    match status {
        PortStatus::Open => 1,
        PortStatus::Filtered => 2,
        PortStatus::OpenFiltered => 3,
        PortStatus::Closed => 0,
    }
}

fn map_dns_type(id: u8) -> Option<DnsRecordType> {
    match id {
        1 => Some(DnsRecordType::A),
        2 => Some(DnsRecordType::AAAA),
        5 => Some(DnsRecordType::CNAME),
        6 => Some(DnsRecordType::NS),
        15 => Some(DnsRecordType::MX),
        16 => Some(DnsRecordType::TXT),
        _ => None,
    }
}

fn dns_type_id(kind: DnsRecordType) -> u8 {
    match kind {
        DnsRecordType::A => 1,
        DnsRecordType::AAAA => 2,
        DnsRecordType::CNAME => 5,
        DnsRecordType::NS => 6,
        DnsRecordType::MX => 15,
        DnsRecordType::TXT => 16,
    }
}

fn map_subdomain_source(tag: u8) -> SubdomainSource {
    match tag {
        1 => SubdomainSource::CertTransparency,
        2 => SubdomainSource::SearchEngine,
        3 => SubdomainSource::WebCrawl,
        _ => SubdomainSource::DnsBruteforce,
    }
}

fn system_time_to_unix(time: SystemTime) -> u32 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs() as u32
}

fn parse_http_status_line(line: &str) -> Option<u16> {
    if !line.starts_with("HTTP/") {
        return None;
    }
    let mut parts = line.split_whitespace();
    parts.next()?;
    let code = parts.next()?;
    code.parse().ok()
}

fn parse_status_header(line: &str) -> Option<u16> {
    let (name, value) = line.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("status") {
        return None;
    }
    value.trim().split_whitespace().next()?.parse().ok()
}

#[derive(Debug, Clone)]
pub struct BinaryPortScanRecord {
    pub ip: u32,
    pub port: u16,
    pub state: u8,
    pub service_id: u8,
    pub timestamp: u32,
}

impl BinaryPortScanRecord {
    pub fn new(ip: u32, port: u16, state: u8, service_id: u8) -> Self {
        Self {
            ip,
            port,
            state,
            service_id,
            timestamp: now_timestamp(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BinaryDnsRecord {
    pub domain: String,
    pub record_type: u8,
    pub ttl: u32,
    pub data: Vec<u8>,
    pub timestamp: u32,
}

#[derive(Debug, Clone, Default)]
pub struct BinaryStats {
    pub total_records: u64,
    pub port_scans: u64,
    pub dns_records: u64,
    pub subdomains: u64,
    pub whois_records: u64,
    pub tls_certs: u64,
    pub http_headers: u64,
    pub host_fingerprints: u64,
    pub total_bytes: u64,
    pub file_size: u64,
}

fn collect_stats(db: &mut Database, file_size: u64) -> BinaryStats {
    let ports = db.all_ports().len() as u64;
    let subs = db.all_subdomains().len() as u64;
    let dns = db.dns_records().count() as u64;
    let whois = db.whois_records().count() as u64;
    let tls = db.tls_records().count() as u64;
    let http = db.http_records().count() as u64;

    let hosts = db.all_hosts().len() as u64;

    let total = ports + subs + dns + whois + tls + http + hosts;

    BinaryStats {
        total_records: total,
        port_scans: ports,
        dns_records: dns,
        subdomains: subs,
        whois_records: whois,
        tls_certs: tls,
        http_headers: http,
        host_fingerprints: hosts,
        total_bytes: 0,
        file_size,
    }
}

pub struct BinaryWriter {
    db: Database,
}

impl BinaryWriter {
    pub fn create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let db = Database::open(path_ref)?;
        Ok(Self { db })
    }

    pub fn add_port_scan(&mut self, record: BinaryPortScanRecord) -> io::Result<()> {
        let ip = IpAddr::V4(Ipv4Addr::from(record.ip));
        self.db.insert_port_scan(PortScanRecord {
            ip,
            port: record.port,
            status: decode_status(record.state),
            service_id: record.service_id,
            timestamp: record.timestamp,
        });
        Ok(())
    }

    pub fn add_dns_record(
        &mut self,
        domain: &str,
        record_type: u8,
        ttl: u32,
        data: &[u8],
    ) -> io::Result<()> {
        if let Some(kind) = map_dns_type(record_type) {
            let value = String::from_utf8_lossy(data).to_string();
            self.db.insert_dns(DnsRecordData {
                domain: domain.to_string(),
                record_type: kind,
                value,
                ttl,
                timestamp: now_timestamp(),
            });
        }
        Ok(())
    }

    pub fn add_subdomain(
        &mut self,
        parent: &str,
        subdomain: &str,
        status: u8,
        ips: &[u32],
    ) -> io::Result<()> {
        let ip_list: Vec<IpAddr> = ips
            .iter()
            .map(|ip| IpAddr::V4(Ipv4Addr::from(*ip)))
            .collect();
        self.db.insert_subdomain(
            parent,
            subdomain,
            ip_list,
            map_subdomain_source(status),
            now_timestamp(),
        );
        Ok(())
    }

    pub fn add_whois(&mut self, domain: &str, data: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(data);
        let mut registrar = String::from("unknown");
        let mut nameservers = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("Registrar:") {
                let value = rest.trim();
                if !value.is_empty() {
                    registrar = value.to_string();
                }
            } else if let Some(rest) = line.strip_prefix("Nameserver:") {
                let value = rest.trim();
                if !value.is_empty() {
                    nameservers.push(value.to_string());
                }
            }
        }

        self.db
            .insert_whois(domain, &registrar, 0, 0, nameservers, now_timestamp());
        Ok(())
    }

    pub fn add_tls_cert(&mut self, domain: &str, data: &[u8]) -> io::Result<()> {
        let mut issuer = "unknown".to_string();
        let mut subject = domain.to_string();
        let mut not_before = 0;
        let mut not_after = 0;
        let mut sans = Vec::new();
        let mut self_signed = false;

        if !data.is_empty() {
            if let Ok(cert) = X509Certificate::from_der(data) {
                issuer = cert.issuer_string();
                subject = cert.subject_string();
                sans = cert.get_subject_alt_names();
                self_signed = cert.is_self_signed();
                if let Some(start) = parse_x509_time(&cert.validity.not_before) {
                    not_before = system_time_to_unix(start);
                }
                if let Some(end) = parse_x509_time(&cert.validity.not_after) {
                    not_after = system_time_to_unix(end);
                }
            }
        }

        self.db.insert_tls(
            domain,
            &issuer,
            &subject,
            not_before,
            not_after,
            sans,
            self_signed,
            now_timestamp(),
        );
        Ok(())
    }

    pub fn add_http_headers(&mut self, url: &str, headers: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(headers);
        let mut status_code = text
            .lines()
            .next()
            .and_then(|line| parse_http_status_line(line.trim()))
            .unwrap_or(0);
        let mut header_pairs = Vec::new();
        let mut server = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if status_code == 0 {
                if let Some(code) = parse_status_header(trimmed) {
                    status_code = code;
                }
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let name_trim = name.trim().to_string();
                let value_trim = value.trim().to_string();
                if name_trim.eq_ignore_ascii_case("server") {
                    server = Some(value_trim.clone());
                }
                header_pairs.push((name_trim, value_trim));
            }
        }

        self.db.insert_http(HttpHeadersRecord {
            url: url.to_string(),
            status_code,
            server,
            headers: header_pairs,
            timestamp: now_timestamp(),
        });
        Ok(())
    }

    pub fn add_host_intel(&mut self, record: HostIntelRecord) -> io::Result<()> {
        self.db.insert_host(record);
        Ok(())
    }

    pub fn stats(&mut self) -> BinaryStats {
        collect_stats(&mut self.db, 0)
    }

    pub fn commit(mut self) -> io::Result<()> {
        self.db.flush()
    }
}

pub struct BinaryReader {
    db: Database,
    file_size: u64,
}

impl BinaryReader {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path_ref = path.as_ref();
        let file_size = fs::metadata(path_ref).map(|m| m.len()).unwrap_or(0);
        let db = Database::open(path_ref)?;
        Ok(Self { db, file_size })
    }

    pub fn stats(&mut self) -> BinaryStats {
        collect_stats(&mut self.db, self.file_size)
    }

    pub fn port_scans(&mut self) -> Vec<BinaryPortScanRecord> {
        self.db
            .all_ports()
            .into_iter()
            .map(|record| {
                let ip = match record.ip {
                    IpAddr::V4(addr) => u32::from(addr),
                    IpAddr::V6(_) => 0,
                };
                BinaryPortScanRecord {
                    ip,
                    port: record.port,
                    state: encode_status(record.status),
                    service_id: record.service_id,
                    timestamp: record.timestamp,
                }
            })
            .collect()
    }

    pub fn dns_records(&mut self) -> Vec<BinaryDnsRecord> {
        self.db
            .dns_records()
            .map(|record| BinaryDnsRecord {
                domain: record.domain,
                record_type: dns_type_id(record.record_type),
                ttl: record.ttl,
                data: record.value.into_bytes(),
                timestamp: record.timestamp,
            })
            .collect()
    }
}
