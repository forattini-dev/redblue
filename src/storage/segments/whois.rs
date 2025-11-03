use std::collections::HashMap;

use crate::storage::encoding::{read_string, read_varu32, write_string, write_varu32, DecodeError};
use crate::storage::schema::WhoisRecord;
use crate::storage::segments::utils::StringTable;

#[derive(Debug, Clone)]
struct Entry {
    domain_id: u32,
    registrar_id: u32,
    created: u32,
    expires: u32,
    timestamp: u32,
    nameserver_ids: Vec<u32>,
}

#[derive(Debug, Default, Clone)]
pub struct WhoisSegment {
    strings: StringTable,
    records: HashMap<u32, Entry>,
}

impl WhoisSegment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        domain: &str,
        registrar: &str,
        created: u32,
        expires: u32,
        nameservers: Vec<String>,
        timestamp: u32,
    ) {
        let domain_id = self.strings.intern(domain);
        let registrar_id = self.strings.intern(registrar);
        let ns_ids = nameservers
            .into_iter()
            .map(|ns| self.strings.intern(ns))
            .collect();

        self.records.insert(
            domain_id,
            Entry {
                domain_id,
                registrar_id,
                created,
                expires,
                timestamp,
                nameserver_ids: ns_ids,
            },
        );
    }

    pub fn get(&self, domain: &str) -> Option<WhoisRecord> {
        let domain_id = self.strings.get_id(domain)?;
        let entry = self.records.get(&domain_id)?;
        Some(WhoisRecord {
            domain: domain.to_string(),
            registrar: self.strings.get(entry.registrar_id).to_string(),
            created_date: entry.created,
            expires_date: entry.expires,
            nameservers: entry
                .nameserver_ids
                .iter()
                .map(|id| self.strings.get(*id).to_string())
                .collect(),
            timestamp: entry.timestamp,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = WhoisRecord> + '_ {
        self.records.values().map(|entry| WhoisRecord {
            domain: self.strings.get(entry.domain_id).to_string(),
            registrar: self.strings.get(entry.registrar_id).to_string(),
            created_date: entry.created,
            expires_date: entry.expires,
            nameservers: entry
                .nameserver_ids
                .iter()
                .map(|id| self.strings.get(*id).to_string())
                .collect(),
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
            write_varu32(&mut buf, entry.registrar_id);
            write_varu32(&mut buf, entry.created);
            write_varu32(&mut buf, entry.expires);
            write_varu32(&mut buf, entry.timestamp);
            write_varu32(&mut buf, entry.nameserver_ids.len() as u32);
            for ns in &entry.nameserver_ids {
                write_varu32(&mut buf, *ns);
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
            let registrar_id = read_varu32(bytes, &mut pos)?;
            let created = read_varu32(bytes, &mut pos)?;
            let expires = read_varu32(bytes, &mut pos)?;
            let timestamp = read_varu32(bytes, &mut pos)?;
            let ns_count = read_varu32(bytes, &mut pos)? as usize;
            let mut nameserver_ids = Vec::with_capacity(ns_count);
            for _ in 0..ns_count {
                nameserver_ids.push(read_varu32(bytes, &mut pos)?);
            }
            records.insert(
                domain_id,
                Entry {
                    domain_id,
                    registrar_id,
                    created,
                    expires,
                    timestamp,
                    nameserver_ids,
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
    fn roundtrip_whois() {
        let mut segment = WhoisSegment::new();
        segment.insert(
            "example.com",
            "Example Registrar",
            1_600_000_000,
            1_900_000_000,
            vec!["ns1.example.com".into(), "ns2.example.com".into()],
            1_700_000_000,
        );

        let encoded = segment.serialize();
        let decoded = WhoisSegment::deserialize(&encoded).expect("decode");
        let rec = decoded.get("example.com").expect("entry");
        assert_eq!(rec.registrar, "Example Registrar");
        assert_eq!(rec.nameservers.len(), 2);
    }
}
