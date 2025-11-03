use std::collections::HashMap;
use std::net::IpAddr;

use crate::storage::encoding::{
    read_ip, read_string, read_varu32, write_ip, write_string, write_varu32, DecodeError,
};
use crate::storage::schema::{SubdomainRecord, SubdomainSource};
use crate::storage::segments::utils::StringTable;

#[derive(Debug, Clone)]
struct Entry {
    domain_id: u32,
    label_id: u32,
    ips: Vec<IpAddr>,
    source: SubdomainSource,
    timestamp: u32,
}

#[derive(Debug, Clone)]
struct DomainRange {
    start: usize,
    len: usize,
}

#[derive(Debug, Default, Clone)]
pub struct SubdomainSegment {
    strings: StringTable,
    records: Vec<Entry>,
    domain_index: HashMap<u32, DomainRange>,
    sorted: bool,
}

impl SubdomainSegment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn insert(
        &mut self,
        domain: &str,
        subdomain: &str,
        ips: Vec<IpAddr>,
        source: SubdomainSource,
        timestamp: u32,
    ) {
        let domain_id = self.strings.intern(domain);
        let label_id = self.strings.intern(subdomain);
        self.records.push(Entry {
            domain_id,
            label_id,
            ips,
            source,
            timestamp,
        });
        self.sorted = false;
    }

    fn ensure_index(&mut self) {
        if self.sorted {
            return;
        }
        self.records
            .sort_by(|a, b| match a.domain_id.cmp(&b.domain_id) {
                std::cmp::Ordering::Equal => a.label_id.cmp(&b.label_id),
                other => other,
            });
        self.domain_index.clear();
        let mut current: Option<u32> = None;
        let mut start = 0usize;
        for (idx, entry) in self.records.iter().enumerate() {
            if current == Some(entry.domain_id) {
                continue;
            }
            if let Some(active) = current {
                self.domain_index.insert(
                    active,
                    DomainRange {
                        start,
                        len: idx - start,
                    },
                );
                start = idx;
            } else {
                start = idx;
            }
            current = Some(entry.domain_id);
        }
        if let Some(active) = current {
            self.domain_index.insert(
                active,
                DomainRange {
                    start,
                    len: self.records.len() - start,
                },
            );
        }
        self.sorted = true;
    }

    pub fn get_by_domain(&mut self, domain: &str) -> Vec<SubdomainRecord> {
        self.ensure_index();
        let Some(domain_id) = self.strings.get_id(domain) else {
            return Vec::new();
        };
        let Some(range) = self.domain_index.get(&domain_id) else {
            return Vec::new();
        };
        self.records[range.start..range.start + range.len]
            .iter()
            .map(|entry| SubdomainRecord {
                subdomain: self.strings.get(entry.label_id).to_string(),
                ips: entry.ips.clone(),
                source: entry.source,
                timestamp: entry.timestamp,
            })
            .collect()
    }

    pub fn all_records(&mut self) -> Vec<SubdomainRecord> {
        self.ensure_index();
        self.records
            .iter()
            .map(|entry| SubdomainRecord {
                subdomain: self.strings.get(entry.label_id).to_string(),
                ips: entry.ips.clone(),
                source: entry.source,
                timestamp: entry.timestamp,
            })
            .collect()
    }

    pub fn serialize(&mut self) -> Vec<u8> {
        self.ensure_index();
        let mut buf = Vec::new();

        // String table
        write_varu32(&mut buf, self.strings.len() as u32);
        for value in self.strings.entries() {
            write_string(&mut buf, value);
        }

        // Records
        write_varu32(&mut buf, self.records.len() as u32);
        for entry in &self.records {
            write_varu32(&mut buf, entry.domain_id);
            write_varu32(&mut buf, entry.label_id);
            write_varu32(&mut buf, entry.timestamp);
            buf.push(entry.source as u8);
            write_varu32(&mut buf, entry.ips.len() as u32);
            for ip in &entry.ips {
                write_ip(&mut buf, ip);
            }
        }

        // Domain index
        write_varu32(&mut buf, self.domain_index.len() as u32);
        for (domain_id, range) in &self.domain_index {
            write_varu32(&mut buf, *domain_id);
            write_varu32(&mut buf, range.start as u32);
            write_varu32(&mut buf, range.len as u32);
        }

        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0usize;
        let string_count = read_varu32(bytes, &mut pos)? as usize;
        let mut strings = StringTable::new();
        for _ in 0..string_count {
            let value = read_string(bytes, &mut pos)?;
            strings.intern(value);
        }

        let record_count = read_varu32(bytes, &mut pos)? as usize;
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let domain_id = read_varu32(bytes, &mut pos)?;
            let label_id = read_varu32(bytes, &mut pos)?;
            let timestamp = read_varu32(bytes, &mut pos)?;
            if pos >= bytes.len() {
                return Err(DecodeError("unexpected eof (subdomain source)"));
            }
            let source = decode_source(bytes[pos])?;
            pos += 1;
            let ip_count = read_varu32(bytes, &mut pos)? as usize;
            let mut ips = Vec::with_capacity(ip_count);
            for _ in 0..ip_count {
                let ip = read_ip(bytes, &mut pos)?;
                ips.push(ip);
            }
            records.push(Entry {
                domain_id,
                label_id,
                ips,
                source,
                timestamp,
            });
        }

        let index_count = read_varu32(bytes, &mut pos)? as usize;
        let mut domain_index = HashMap::with_capacity(index_count);
        for _ in 0..index_count {
            let domain_id = read_varu32(bytes, &mut pos)?;
            let start = read_varu32(bytes, &mut pos)? as usize;
            let len = read_varu32(bytes, &mut pos)? as usize;
            domain_index.insert(domain_id, DomainRange { start, len });
        }

        Ok(Self {
            strings,
            records,
            domain_index,
            sorted: true,
        })
    }
}

fn decode_source(byte: u8) -> Result<SubdomainSource, DecodeError> {
    match byte {
        0 => Ok(SubdomainSource::DnsBruteforce),
        1 => Ok(SubdomainSource::CertTransparency),
        2 => Ok(SubdomainSource::SearchEngine),
        3 => Ok(SubdomainSource::WebCrawl),
        _ => Err(DecodeError("invalid subdomain source")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn roundtrip_subdomains() {
        let mut segment = SubdomainSegment::new();
        segment.insert(
            "example.com",
            "api.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            SubdomainSource::DnsBruteforce,
            100,
        );
        segment.insert(
            "example.com",
            "cdn.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))],
            SubdomainSource::WebCrawl,
            120,
        );
        segment.insert(
            "corp.local",
            "vpn.corp.local",
            vec![IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))],
            SubdomainSource::SearchEngine,
            200,
        );

        let encoded = segment.serialize();
        let mut decoded = SubdomainSegment::deserialize(&encoded).expect("decode");
        let subs = decoded.get_by_domain("example.com");
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].subdomain, "api.example.com");
    }
}
