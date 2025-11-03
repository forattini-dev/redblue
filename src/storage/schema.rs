// Schema definitions for compact storage
// Each data type has optimized binary format

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::storage::encoding::{read_varu32, write_varu32, DecodeError};

/// Data types supported by RedDB
#[derive(Debug, Clone)]
pub enum RecordType {
    /// Port scan result: IP + port + status + timestamp
    PortScan(PortScanRecord),
    /// Subdomain: domain + IPs + source + timestamp
    Subdomain(SubdomainRecord),
    /// WHOIS: domain + registrar + dates + NS
    WhoisInfo(WhoisRecord),
    /// TLS cert: domain + issuer + valid dates + SANs
    TlsCert(TlsCertRecord),
    /// HTTP headers: URL + headers map
    HttpHeaders(HttpHeadersRecord),
    /// DNS record: domain + type + value
    DnsRecord(DnsRecordData),
    /// Generic key-value for flexibility
    KeyValue(Vec<u8>, Vec<u8>),
    /// Host fingerprint/intel data
    HostIntel(HostIntelRecord),
}

/// Port scan result - 20 bytes for IPv4 payloads.
#[derive(Debug, Clone)]
pub struct PortScanRecord {
    pub ip: IpAddr,         // 4 or 16 bytes
    pub port: u16,          // 2 bytes
    pub status: PortStatus, // 1 byte
    pub service_id: u8,     // 1 byte (service classification enum)
    pub timestamp: u32,     // 4 bytes (Unix time)
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PortStatus {
    Open = 0,
    Closed = 1,
    Filtered = 2,
    OpenFiltered = 3,
}

/// Subdomain record - variable size, compressed
#[derive(Debug, Clone)]
pub struct SubdomainRecord {
    pub subdomain: String,
    pub ips: Vec<IpAddr>,
    pub source: SubdomainSource,
    pub timestamp: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SubdomainSource {
    DnsBruteforce = 0,
    CertTransparency = 1,
    SearchEngine = 2,
    WebCrawl = 3,
}

/// WHOIS record - compact
#[derive(Debug, Clone)]
pub struct WhoisRecord {
    pub domain: String,
    pub registrar: String,
    pub created_date: u32, // Unix timestamp
    pub expires_date: u32,
    pub nameservers: Vec<String>,
    pub timestamp: u32, // When we fetched this
}

/// TLS certificate - compact
#[derive(Debug, Clone)]
pub struct TlsCertRecord {
    pub domain: String,
    pub issuer: String,
    pub subject: String,
    pub not_before: u32,
    pub not_after: u32,
    pub sans: Vec<String>, // Subject Alternative Names
    pub self_signed: bool,
    pub timestamp: u32,
}

/// HTTP headers - compressed
#[derive(Debug, Clone)]
pub struct HttpHeadersRecord {
    pub url: String,
    pub status_code: u16,
    pub server: Option<String>,
    pub headers: Vec<(String, String)>,
    pub timestamp: u32,
}

/// DNS record
#[derive(Debug, Clone)]
pub struct DnsRecordData {
    pub domain: String,
    pub record_type: DnsRecordType,
    pub value: String,
    pub ttl: u32,
    pub timestamp: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DnsRecordType {
    A = 1,
    AAAA = 2,
    MX = 3,
    NS = 4,
    TXT = 5,
    CNAME = 6,
}

/// Service-level fingerprint information captured during host analysis.
#[derive(Debug, Clone)]
pub struct ServiceIntelRecord {
    pub port: u16,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub os_hints: Vec<String>,
}

/// Aggregated host fingerprint/intelligence record.
#[derive(Debug, Clone)]
pub struct HostIntelRecord {
    pub ip: IpAddr,
    pub os_family: Option<String>,
    pub confidence: f32,
    pub last_seen: u32,
    pub services: Vec<ServiceIntelRecord>,
}

/// Compact binary serialization for each type
impl PortScanRecord {
    /// Serialize to bytes (19 bytes for IPv4)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);

        // IP address
        match self.ip {
            IpAddr::V4(ip) => {
                buf.push(4); // IPv4 marker
                buf.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.push(6); // IPv6 marker
                buf.extend_from_slice(&ip.octets());
            }
        }

        // Port
        buf.extend_from_slice(&self.port.to_le_bytes());

        // Status + service
        buf.push(self.status as u8);
        buf.push(self.service_id);

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }

        let ip_version = buf[0];

        let (ip, offset) = if ip_version == 4 {
            if buf.len() < 1 + 4 {
                return None;
            }
            let octets = [buf[1], buf[2], buf[3], buf[4]];
            (IpAddr::V4(Ipv4Addr::from(octets)), 5)
        } else if ip_version == 6 {
            if buf.len() < 1 + 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            (IpAddr::V6(Ipv6Addr::from(octets)), 17)
        } else {
            return None;
        };

        if buf.len() < offset + 8 {
            return None;
        }

        let port = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        let status = match buf[offset + 2] {
            0 => PortStatus::Open,
            1 => PortStatus::Closed,
            2 => PortStatus::Filtered,
            3 => PortStatus::OpenFiltered,
            _ => return None,
        };
        let service_id = buf.get(offset + 3).copied()?;
        let timestamp = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);

        Some(Self {
            ip,
            port,
            status,
            service_id,
            timestamp,
        })
    }
}

impl SubdomainRecord {
    /// Serialize with compression
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Subdomain length + data
        let subdomain_bytes = self.subdomain.as_bytes();
        buf.push(subdomain_bytes.len() as u8);
        buf.extend_from_slice(subdomain_bytes);

        // Number of IPs
        buf.push(self.ips.len() as u8);
        for ip in &self.ips {
            match ip {
                IpAddr::V4(ip) => {
                    buf.push(4);
                    buf.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    buf.push(6);
                    buf.extend_from_slice(&ip.octets());
                }
            }
        }

        // Source
        buf.push(self.source as u8);

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }

        let mut offset = 0;

        // Read subdomain
        let subdomain_len = buf[offset] as usize;
        offset += 1;
        if buf.len() < offset + subdomain_len {
            return None;
        }
        let subdomain = String::from_utf8(buf[offset..offset + subdomain_len].to_vec()).ok()?;
        offset += subdomain_len;

        // Read IPs
        if buf.len() < offset + 1 {
            return None;
        }
        let ip_count = buf[offset] as usize;
        offset += 1;

        let mut ips = Vec::new();
        for _ in 0..ip_count {
            if buf.len() < offset + 1 {
                return None;
            }
            let ip_version = buf[offset];
            offset += 1;

            if ip_version == 4 {
                if buf.len() < offset + 4 {
                    return None;
                }
                let octets = [
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ];
                ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
                offset += 4;
            } else if ip_version == 6 {
                if buf.len() < offset + 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                offset += 16;
            }
        }

        // Source
        if buf.len() < offset + 1 {
            return None;
        }
        let source = match buf[offset] {
            0 => SubdomainSource::DnsBruteforce,
            1 => SubdomainSource::CertTransparency,
            2 => SubdomainSource::SearchEngine,
            3 => SubdomainSource::WebCrawl,
            _ => return None,
        };
        offset += 1;

        // Timestamp
        if buf.len() < offset + 4 {
            return None;
        }
        let timestamp = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);

        Some(Self {
            subdomain,
            ips,
            source,
            timestamp,
        })
    }
}

impl ServiceIntelRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.port.to_le_bytes());
        write_optional_string(&mut buf, &self.service_name);
        write_optional_string(&mut buf, &self.banner);
        write_varu32(&mut buf, self.os_hints.len() as u32);
        for hint in &self.os_hints {
            write_string(&mut buf, hint);
        }
        buf
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < 2 {
            return Err(DecodeError("service record too small"));
        }
        let port = u16::from_le_bytes([bytes[0], bytes[1]]);
        let mut pos = 2usize;
        let service_name = read_optional_string(bytes, &mut pos)?;
        let banner = read_optional_string(bytes, &mut pos)?;

        let hint_count = read_varu32(bytes, &mut pos)? as usize;
        let mut os_hints = Vec::with_capacity(hint_count);
        for _ in 0..hint_count {
            let value = read_string(bytes, &mut pos)?;
            os_hints.push(value);
        }

        Ok(Self {
            port,
            service_name,
            banner,
            os_hints,
        })
    }
}

impl HostIntelRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self.ip {
            IpAddr::V4(ip) => {
                buf.push(4);
                buf.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.push(6);
                buf.extend_from_slice(&ip.octets());
            }
        }

        buf.extend_from_slice(&self.last_seen.to_le_bytes());
        buf.extend_from_slice(&self.confidence.to_bits().to_le_bytes());
        write_optional_string(&mut buf, &self.os_family);

        write_varu32(&mut buf, self.services.len() as u32);
        for service in &self.services {
            let svc_bytes = service.to_bytes();
            write_varu32(&mut buf, svc_bytes.len() as u32);
            buf.extend_from_slice(&svc_bytes);
        }

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError("empty host record"));
        }

        let ip_version = bytes[0];
        let mut pos = 1usize;
        let ip = match ip_version {
            4 => {
                if bytes.len() < pos + 4 {
                    return Err(DecodeError("truncated IPv4 address"));
                }
                let octets = [bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]];
                pos += 4;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                if bytes.len() < pos + 16 {
                    return Err(DecodeError("truncated IPv6 address"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[pos..pos + 16]);
                pos += 16;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(DecodeError("invalid IP version")),
        };

        if bytes.len() < pos + 8 {
            return Err(DecodeError("truncated host record metadata"));
        }

        let last_seen =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;

        let confidence_bits =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        let confidence = f32::from_bits(confidence_bits);

        let os_family = read_optional_string(bytes, &mut pos)?;

        let service_count = read_varu32(bytes, &mut pos)? as usize;
        let mut services = Vec::with_capacity(service_count);
        for _ in 0..service_count {
            let svc_len = read_varu32(bytes, &mut pos)? as usize;
            if bytes.len() < pos + svc_len {
                return Err(DecodeError("truncated service entry"));
            }
            let record = ServiceIntelRecord::from_slice(&bytes[pos..pos + svc_len])?;
            pos += svc_len;
            services.push(record);
        }

        Ok(Self {
            ip,
            os_family,
            confidence,
            last_seen,
            services,
        })
    }
}

fn write_optional_string(buf: &mut Vec<u8>, value: &Option<String>) {
    match value {
        Some(text) => {
            buf.push(1);
            write_string(buf, text);
        }
        None => buf.push(0),
    }
}

fn read_optional_string(bytes: &[u8], pos: &mut usize) -> Result<Option<String>, DecodeError> {
    if *pos >= bytes.len() {
        return Err(DecodeError("unexpected eof (optional string flag)"));
    }
    let flag = bytes[*pos];
    *pos += 1;
    if flag == 0 {
        return Ok(None);
    }
    read_string(bytes, pos).map(Some)
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    let data = value.as_bytes();
    write_varu32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

fn read_string(bytes: &[u8], pos: &mut usize) -> Result<String, DecodeError> {
    let len = read_varu32(bytes, pos)? as usize;
    if bytes.len() < *pos + len {
        return Err(DecodeError("truncated string"));
    }
    let slice = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(String::from_utf8_lossy(slice).to_string())
}

/// Helper to write length-prefixed strings
pub fn write_string_u16(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(65535) as u16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

/// Helper to read length-prefixed strings
pub fn read_string_u16(buf: &[u8], offset: &mut usize) -> Option<String> {
    if buf.len() < *offset + 2 {
        return None;
    }

    let len = u16::from_le_bytes([buf[*offset], buf[*offset + 1]]) as usize;
    *offset += 2;

    if buf.len() < *offset + len {
        return None;
    }

    let s = String::from_utf8(buf[*offset..*offset + len].to_vec()).ok()?;
    *offset += len;

    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_port_scan_serialization() {
        let record = PortScanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            port: 80,
            status: PortStatus::Open,
            service_id: 1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
        };

        let bytes = record.to_bytes();
        println!("PortScan size: {} bytes", bytes.len());

        let decoded = PortScanRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.port, 80);
    }

    #[test]
    fn test_subdomain_serialization() {
        let record = SubdomainRecord {
            subdomain: "api.example.com".to_string(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            source: SubdomainSource::DnsBruteforce,
            timestamp: 1234567890,
        };

        let bytes = record.to_bytes();
        println!("Subdomain size: {} bytes", bytes.len());

        let decoded = SubdomainRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.subdomain, "api.example.com");
    }
}
