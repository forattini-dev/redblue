use std::collections::HashMap;
use std::net::IpAddr;

use crate::storage::encoding::{read_varu32, write_varu32, DecodeError, IpKey};
use crate::storage::schema::HostIntelRecord;

/// Compact in-memory representation for host intelligence records.
#[derive(Debug, Clone, Default)]
pub struct HostSegment {
    records: HashMap<IpKey, HostIntelRecord>,
}

impl HostSegment {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn insert(&mut self, record: HostIntelRecord) {
        let key = IpKey::from(&record.ip);
        self.records.insert(key, record);
    }

    pub fn get(&self, ip: IpAddr) -> Option<HostIntelRecord> {
        let key = IpKey::from(&ip);
        self.records.get(&key).cloned()
    }

    pub fn all(&self) -> Vec<HostIntelRecord> {
        let mut items: Vec<_> = self.records.values().cloned().collect();
        items.sort_by_key(|record| IpKey::from(&record.ip));
        items
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut records: Vec<_> = self.records.values().collect();
        records.sort_by_key(|record| IpKey::from(&record.ip));

        write_varu32(&mut buf, records.len() as u32);
        for record in records {
            let bytes = record.to_bytes();
            write_varu32(&mut buf, bytes.len() as u32);
            buf.extend_from_slice(&bytes);
        }
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0usize;
        let count = read_varu32(bytes, &mut pos)? as usize;
        let mut records = HashMap::with_capacity(count);

        for _ in 0..count {
            let len = read_varu32(bytes, &mut pos)? as usize;
            if bytes.len() < pos + len {
                return Err(DecodeError("truncated host segment entry"));
            }
            let record = HostIntelRecord::from_bytes(&bytes[pos..pos + len])?;
            pos += len;
            records.insert(IpKey::from(&record.ip), record);
        }

        Ok(Self { records })
    }
}
