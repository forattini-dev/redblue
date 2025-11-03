use std::collections::HashMap;

use crate::storage::encoding::{read_string, read_varu32, write_string, write_varu32, DecodeError};
use crate::storage::schema::TlsCertRecord;
use crate::storage::segments::utils::StringTable;

#[derive(Debug, Clone)]
struct Entry {
    domain_id: u32,
    issuer_id: u32,
    subject_id: u32,
    not_before: u32,
    not_after: u32,
    timestamp: u32,
    sans: Vec<u32>,
    self_signed: bool,
}

#[derive(Debug, Default, Clone)]
pub struct TlsSegment {
    strings: StringTable,
    records: HashMap<u32, Entry>,
}

impl TlsSegment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        domain: &str,
        issuer: &str,
        subject: &str,
        not_before: u32,
        not_after: u32,
        sans: Vec<String>,
        self_signed: bool,
        timestamp: u32,
    ) {
        let domain_id = self.strings.intern(domain);
        let issuer_id = self.strings.intern(issuer);
        let subject_id = self.strings.intern(subject);
        let san_ids = sans.into_iter().map(|s| self.strings.intern(s)).collect();

        self.records.insert(
            domain_id,
            Entry {
                domain_id,
                issuer_id,
                subject_id,
                not_before,
                not_after,
                timestamp,
                sans: san_ids,
                self_signed,
            },
        );
    }

    pub fn get(&self, domain: &str) -> Option<TlsCertRecord> {
        let domain_id = self.strings.get_id(domain)?;
        let entry = self.records.get(&domain_id)?;
        Some(TlsCertRecord {
            domain: domain.to_string(),
            issuer: self.strings.get(entry.issuer_id).to_string(),
            subject: self.strings.get(entry.subject_id).to_string(),
            not_before: entry.not_before,
            not_after: entry.not_after,
            sans: entry
                .sans
                .iter()
                .map(|id| self.strings.get(*id).to_string())
                .collect(),
            self_signed: entry.self_signed,
            timestamp: entry.timestamp,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = TlsCertRecord> + '_ {
        self.records.values().map(|entry| TlsCertRecord {
            domain: self.strings.get(entry.domain_id).to_string(),
            issuer: self.strings.get(entry.issuer_id).to_string(),
            subject: self.strings.get(entry.subject_id).to_string(),
            not_before: entry.not_before,
            not_after: entry.not_after,
            sans: entry
                .sans
                .iter()
                .map(|id| self.strings.get(*id).to_string())
                .collect(),
            self_signed: entry.self_signed,
            timestamp: entry.timestamp,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varu32(&mut buf, self.strings.len() as u32);
        for value in self.strings.entries() {
            write_string(&mut buf, value);
        }

        write_varu32(&mut buf, self.records.len() as u32);
        let mut entries: Vec<&Entry> = self.records.values().collect();
        entries.sort_by_key(|e| e.domain_id);
        for entry in entries {
            write_varu32(&mut buf, entry.domain_id);
            write_varu32(&mut buf, entry.issuer_id);
            write_varu32(&mut buf, entry.subject_id);
            write_varu32(&mut buf, entry.not_before);
            write_varu32(&mut buf, entry.not_after);
            buf.push(entry.self_signed as u8);
            write_varu32(&mut buf, entry.timestamp);
            write_varu32(&mut buf, entry.sans.len() as u32);
            for san in &entry.sans {
                write_varu32(&mut buf, *san);
            }
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
        let mut records = HashMap::with_capacity(record_count);
        for _ in 0..record_count {
            let domain_id = read_varu32(bytes, &mut pos)?;
            let issuer_id = read_varu32(bytes, &mut pos)?;
            let subject_id = read_varu32(bytes, &mut pos)?;
            let not_before = read_varu32(bytes, &mut pos)?;
            let not_after = read_varu32(bytes, &mut pos)?;
            if pos >= bytes.len() {
                return Err(DecodeError("unexpected eof (self_signed)"));
            }
            let self_signed = bytes[pos] != 0;
            pos += 1;
            let timestamp = read_varu32(bytes, &mut pos)?;
            let san_count = read_varu32(bytes, &mut pos)? as usize;
            let mut sans = Vec::with_capacity(san_count);
            for _ in 0..san_count {
                sans.push(read_varu32(bytes, &mut pos)?);
            }
            records.insert(
                domain_id,
                Entry {
                    domain_id,
                    issuer_id,
                    subject_id,
                    not_before,
                    not_after,
                    timestamp,
                    sans,
                    self_signed,
                },
            );
        }

        Ok(Self { strings, records })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_tls() {
        let mut segment = TlsSegment::new();
        segment.insert(
            "example.com",
            "Example CA",
            "CN=example.com",
            1_600_000_000,
            1_900_000_000,
            vec!["example.com".into(), "www.example.com".into()],
            false,
            1_700_000_000,
        );

        let encoded = segment.serialize();
        let decoded = TlsSegment::deserialize(&encoded).expect("decode");
        let cert = decoded.get("example.com").expect("record");
        assert_eq!(cert.subject, "CN=example.com");
        assert_eq!(cert.sans.len(), 2);
    }
}
