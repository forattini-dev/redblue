use std::collections::HashMap;

use crate::storage::encoding::{read_string, read_varu32, write_string, write_varu32, DecodeError};
use crate::storage::schema::{DnsRecordData, DnsRecordType};
use crate::storage::segments::utils::StringTable;

#[derive(Debug, Clone)]
struct Entry {
    domain_id: u32,
    value_id: u32,
    record_type: DnsRecordType,
    ttl: u32,
    timestamp: u32,
}

#[derive(Debug, Clone)]
struct DomainRange {
    start: usize,
    len: usize,
}

#[derive(Debug, Default, Clone)]
pub struct DnsSegment {
    strings: StringTable,
    records: Vec<Entry>,
    domain_index: HashMap<u32, DomainRange>,
    sorted: bool,
}

impl DnsSegment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, record: DnsRecordData) {
        let domain_id = self.strings.intern(&record.domain);
        let value_id = self.strings.intern(&record.value);
        self.records.push(Entry {
            domain_id,
            value_id,
            record_type: record.record_type,
            ttl: record.ttl,
            timestamp: record.timestamp,
        });
        self.sorted = false;
    }

    fn ensure_index(&mut self) {
        if self.sorted {
            return;
        }

        self.records
            .sort_by(|a, b| match a.domain_id.cmp(&b.domain_id) {
                std::cmp::Ordering::Equal => {
                    match (a.record_type as u8).cmp(&(b.record_type as u8)) {
                        std::cmp::Ordering::Equal => a.value_id.cmp(&b.value_id),
                        other => other,
                    }
                }
                other => other,
            });

        self.domain_index.clear();
        let mut current_domain: Option<u32> = None;
        let mut start = 0usize;
        for (idx, entry) in self.records.iter().enumerate() {
            if current_domain == Some(entry.domain_id) {
                continue;
            }
            if let Some(active) = current_domain {
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
            current_domain = Some(entry.domain_id);
        }
        if let Some(active) = current_domain {
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

    pub fn records_for_domain(&mut self, domain: &str) -> Vec<DnsRecordData> {
        self.ensure_index();
        let Some(domain_id) = self.strings.get_id(domain) else {
            return Vec::new();
        };
        let Some(range) = self.domain_index.get(&domain_id) else {
            return Vec::new();
        };

        self.records[range.start..range.start + range.len]
            .iter()
            .map(|entry| DnsRecordData {
                domain: self.strings.get(entry.domain_id).to_string(),
                record_type: entry.record_type,
                value: self.strings.get(entry.value_id).to_string(),
                ttl: entry.ttl,
                timestamp: entry.timestamp,
            })
            .collect()
    }

    pub fn all_records(&mut self) -> Vec<DnsRecordData> {
        self.ensure_index();
        self.records
            .iter()
            .map(|entry| DnsRecordData {
                domain: self.strings.get(entry.domain_id).to_string(),
                record_type: entry.record_type,
                value: self.strings.get(entry.value_id).to_string(),
                ttl: entry.ttl,
                timestamp: entry.timestamp,
            })
            .collect()
    }

    pub fn iter_mut(&mut self) -> DnsIter<'_> {
        self.ensure_index();
        DnsIter {
            segment: self,
            pos: 0,
        }
    }

    pub fn serialize(&mut self) -> Vec<u8> {
        self.ensure_index();
        let mut buf = Vec::new();

        write_varu32(&mut buf, self.strings.len() as u32);
        for value in self.strings.entries() {
            write_string(&mut buf, value);
        }

        write_varu32(&mut buf, self.records.len() as u32);
        for entry in &self.records {
            write_varu32(&mut buf, entry.domain_id);
            buf.push(entry.record_type as u8);
            write_varu32(&mut buf, entry.value_id);
            write_varu32(&mut buf, entry.ttl);
            write_varu32(&mut buf, entry.timestamp);
        }

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
            let record_type = bytes
                .get(pos)
                .copied()
                .ok_or(DecodeError("unexpected eof (dns type)"))
                .and_then(decode_type)?;
            pos += 1;
            let value_id = read_varu32(bytes, &mut pos)?;
            let ttl = read_varu32(bytes, &mut pos)?;
            let timestamp = read_varu32(bytes, &mut pos)?;
            records.push(Entry {
                domain_id,
                value_id,
                record_type,
                ttl,
                timestamp,
            });
        }

        let index_count = read_varu32(bytes, &mut pos)? as usize;
        let mut domain_index = HashMap::with_capacity(index_count);
        for _ in 0..index_count {
            let domain_id = read_varu32(bytes, &mut pos)?;
            let start = read_varu32(bytes, &mut pos)?;
            let len = read_varu32(bytes, &mut pos)?;
            domain_index.insert(
                domain_id,
                DomainRange {
                    start: start as usize,
                    len: len as usize,
                },
            );
        }

        Ok(Self {
            strings,
            records,
            domain_index,
            sorted: true,
        })
    }
}

pub struct DnsIter<'a> {
    segment: &'a mut DnsSegment,
    pos: usize,
}

impl<'a> Iterator for DnsIter<'a> {
    type Item = DnsRecordData;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.segment.records.len() {
            return None;
        }
        let entry = &self.segment.records[self.pos];
        self.pos += 1;
        Some(DnsRecordData {
            domain: self.segment.strings.get(entry.domain_id).to_string(),
            record_type: entry.record_type,
            value: self.segment.strings.get(entry.value_id).to_string(),
            ttl: entry.ttl,
            timestamp: entry.timestamp,
        })
    }
}

fn decode_type(byte: u8) -> Result<DnsRecordType, DecodeError> {
    match byte {
        1 => Ok(DnsRecordType::A),
        2 => Ok(DnsRecordType::AAAA),
        3 => Ok(DnsRecordType::MX),
        4 => Ok(DnsRecordType::NS),
        5 => Ok(DnsRecordType::TXT),
        6 => Ok(DnsRecordType::CNAME),
        _ => Err(DecodeError("invalid dns record type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_segment_roundtrip_and_index() {
        let mut segment = DnsSegment::new();
        segment.insert(DnsRecordData {
            domain: "example.com".into(),
            record_type: DnsRecordType::A,
            value: "93.184.216.34".into(),
            ttl: 300,
            timestamp: 1_700_000_000,
        });
        segment.insert(DnsRecordData {
            domain: "example.com".into(),
            record_type: DnsRecordType::MX,
            value: "mx1.example.com".into(),
            ttl: 600,
            timestamp: 1_700_000_100,
        });
        segment.insert(DnsRecordData {
            domain: "other.org".into(),
            record_type: DnsRecordType::AAAA,
            value: "2001:db8::1".into(),
            ttl: 1200,
            timestamp: 1_700_000_200,
        });

        // Query before serialization
        let mut before = segment.clone();
        let example_records = before.records_for_domain("example.com");
        assert_eq!(example_records.len(), 2);
        assert!(example_records
            .iter()
            .any(|r| matches!(r.record_type, DnsRecordType::MX)));

        // Round-trip through bytes
        let mut to_encode = segment.clone();
        let bytes = to_encode.serialize();
        let mut decoded = DnsSegment::deserialize(&bytes).expect("decode dns segment");
        let all = decoded.iter_mut().collect::<Vec<_>>();
        assert_eq!(all.len(), 3);

        let other = decoded.records_for_domain("other.org");
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].value, "2001:db8::1");
    }
}
