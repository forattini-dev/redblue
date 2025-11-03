use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::storage::encoding::{read_varu32, write_varu32, DecodeError, IpKey};
use crate::storage::schema::{PortScanRecord, PortStatus};

/// Compact representation for a port scan sample
#[derive(Debug, Clone)]
struct PortEntry {
    ip: IpAddr,
    port: u16,
    status: PortStatus,
    service_id: u8,
    timestamp: u32,
}

impl From<PortScanRecord> for PortEntry {
    fn from(rec: PortScanRecord) -> Self {
        Self {
            ip: rec.ip,
            port: rec.port,
            status: rec.status,
            service_id: rec.service_id,
            timestamp: rec.timestamp,
        }
    }
}

impl From<&PortEntry> for PortScanRecord {
    fn from(entry: &PortEntry) -> Self {
        Self {
            ip: entry.ip,
            port: entry.port,
            status: entry.status,
            service_id: entry.service_id,
            timestamp: entry.timestamp,
        }
    }
}

/// Index entry describing the range of records associated with a given IP.
#[derive(Debug, Clone)]
struct IpRange {
    start: usize,
    len: usize,
}

/// Mutable builder + in-memory view for port scan data.
#[derive(Debug, Default, Clone)]
pub struct PortSegment {
    records: Vec<PortEntry>,
    index: HashMap<IpKey, IpRange>,
    sorted: bool,
}

impl PortSegment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, record: PortScanRecord) {
        self.records.push(PortEntry::from(record));
        self.sorted = false;
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn ensure_index(&mut self) {
        if self.sorted {
            return;
        }
        self.records
            .sort_by(|a, b| match IpKey::from(&a.ip).cmp(&IpKey::from(&b.ip)) {
                Ordering::Equal => a.port.cmp(&b.port),
                other => other,
            });
        self.index.clear();
        let mut current_key = None;
        let mut start = 0usize;
        for (idx, entry) in self.records.iter().enumerate() {
            let key = IpKey::from(&entry.ip);
            if let Some(active) = current_key {
                if active != key {
                    let range = IpRange {
                        start,
                        len: idx - start,
                    };
                    self.index.insert(active, range);
                    current_key = Some(key);
                    start = idx;
                }
            } else {
                current_key = Some(key);
                start = idx;
            }
        }
        if let Some(active) = current_key {
            let range = IpRange {
                start,
                len: self.records.len() - start,
            };
            self.index.insert(active, range);
        }
        self.sorted = true;
    }

    pub fn find(&mut self, ip: IpAddr, port: u16) -> Option<PortScanRecord> {
        self.ensure_index();
        let key = IpKey::from(&ip);
        let range = self.index.get(&key)?;
        let slice = &self.records[range.start..range.start + range.len];
        let idx = slice.binary_search_by(|entry| entry.port.cmp(&port)).ok()?;
        Some(PortScanRecord::from(&slice[idx]))
    }

    pub fn get_open_ports(&mut self, ip: IpAddr) -> Vec<u16> {
        self.ensure_index();
        let key = IpKey::from(&ip);
        match self.index.get(&key) {
            Some(range) => self.records[range.start..range.start + range.len]
                .iter()
                .filter(|entry| matches!(entry.status, PortStatus::Open))
                .map(|entry| entry.port)
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn iter_ip(&mut self, ip: IpAddr) -> Vec<PortScanRecord> {
        self.ensure_index();
        let key = IpKey::from(&ip);
        match self.index.get(&key) {
            Some(range) => self.records[range.start..range.start + range.len]
                .iter()
                .map(PortScanRecord::from)
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn all_records(&mut self) -> Vec<PortScanRecord> {
        self.ensure_index();
        self.records.iter().map(PortScanRecord::from).collect()
    }

    pub fn serialize(&mut self) -> Vec<u8> {
        self.ensure_index();
        let mut buf = Vec::new();
        write_varu32(&mut buf, self.records.len() as u32);

        // Encode by IP groups
        for (key, range) in &self.index {
            buf.push(key.len);
            buf.extend_from_slice(&key.bytes[..key.len as usize]);
            write_varu32(&mut buf, range.len as u32);

            let records = &self.records[range.start..range.start + range.len];
            if records.is_empty() {
                continue;
            }

            // Baseline record
            let first = &records[0];
            write_varu32(&mut buf, first.port as u32);
            write_varu32(&mut buf, first.timestamp);
            buf.push(first.status as u8);
            buf.push(first.service_id);

            let mut prev_port = first.port as i32;
            let mut prev_ts = first.timestamp as i64;

            for rec in &records[1..] {
                let port_delta = (rec.port as i32) - prev_port;
                let ts_delta = (rec.timestamp as i64) - prev_ts;
                crate::storage::encoding::write_vari32(&mut buf, port_delta);
                crate::storage::encoding::write_vari64(&mut buf, ts_delta);
                buf.push(rec.status as u8);
                buf.push(rec.service_id);
                prev_port = rec.port as i32;
                prev_ts = rec.timestamp as i64;
            }
        }

        // Index
        write_varu32(&mut buf, self.index.len() as u32);
        for (key, range) in &self.index {
            buf.push(key.len);
            buf.extend_from_slice(&key.bytes[..key.len as usize]);
            write_varu32(&mut buf, range.start as u32);
            write_varu32(&mut buf, range.len as u32);
        }

        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0usize;
        let total = read_varu32(bytes, &mut pos)? as usize;
        let mut records = Vec::with_capacity(total);

        let mut groups: Vec<(IpKey, IpRange)> = Vec::new();
        let mut consumed = 0usize;
        while consumed < total {
            if pos >= bytes.len() {
                return Err(DecodeError("unexpected eof (port groups)"));
            }
            let len = bytes[pos];
            pos += 1;
            if pos + len as usize > bytes.len() {
                return Err(DecodeError("unexpected eof (ip bytes)"));
            }
            let mut key_bytes = [0u8; 16];
            key_bytes[..len as usize].copy_from_slice(&bytes[pos..pos + len as usize]);
            pos += len as usize;
            let count = read_varu32(bytes, &mut pos)? as usize;
            if count == 0 {
                continue;
            }

            let start = records.len();
            let mut prev_port = 0i32;
            let mut prev_ts = 0i64;
            for idx in 0..count {
                if idx == 0 {
                    let port = read_varu32(bytes, &mut pos)? as u16;
                    let ts = read_varu32(bytes, &mut pos)?;
                    let status = bytes
                        .get(pos)
                        .copied()
                        .ok_or(DecodeError("unexpected eof (status)"))
                        .and_then(decode_status)?;
                    pos += 1;
                    let service_id = *bytes
                        .get(pos)
                        .ok_or(DecodeError("unexpected eof (service id)"))?;
                    pos += 1;
                    prev_port = port as i32;
                    prev_ts = ts as i64;
                    records.push(PortEntry {
                        ip: ip_from_bytes(len, &key_bytes),
                        port,
                        status,
                        service_id,
                        timestamp: ts,
                    });
                } else {
                    let port_delta = crate::storage::encoding::read_vari32(bytes, &mut pos)?;
                    let ts_delta = crate::storage::encoding::read_vari64(bytes, &mut pos)?;
                    let status = bytes
                        .get(pos)
                        .copied()
                        .ok_or(DecodeError("unexpected eof (status)"))
                        .and_then(decode_status)?;
                    pos += 1;
                    let service_id = *bytes
                        .get(pos)
                        .ok_or(DecodeError("unexpected eof (service id)"))?;
                    pos += 1;
                    prev_port += port_delta;
                    prev_ts += ts_delta;
                    records.push(PortEntry {
                        ip: ip_from_bytes(len, &key_bytes),
                        port: prev_port as u16,
                        status,
                        service_id,
                        timestamp: prev_ts as u32,
                    });
                }
            }
            consumed += count;
            groups.push((
                IpKey {
                    bytes: key_bytes,
                    len,
                },
                IpRange { start, len: count },
            ));
        }

        // Skip explicit index (present for forward compatibility)
        let idx_count = read_varu32(bytes, &mut pos)? as usize;
        for _ in 0..idx_count {
            let len = bytes
                .get(pos)
                .ok_or(DecodeError("unexpected eof (idx len)"))?;
            pos += 1;
            pos += *len as usize; // ip bytes
            pos += 4; // start
            pos += 4; // len
            if pos > bytes.len() {
                return Err(DecodeError("unexpected eof (index skip)"));
            }
        }

        let mut segment = PortSegment {
            records,
            index: HashMap::new(),
            sorted: true,
        };
        for (key, range) in groups {
            segment.index.insert(key, range);
        }
        Ok(segment)
    }
}

fn decode_status(byte: u8) -> Result<PortStatus, DecodeError> {
    match byte {
        0 => Ok(PortStatus::Open),
        1 => Ok(PortStatus::Closed),
        2 => Ok(PortStatus::Filtered),
        3 => Ok(PortStatus::OpenFiltered),
        _ => Err(DecodeError("invalid port status")),
    }
}

fn ip_from_bytes(len: u8, bytes: &[u8; 16]) -> IpAddr {
    if len == 4 {
        IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(*bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn roundtrip_ports() {
        let mut segment = PortSegment::new();
        for port in [22u16, 80, 443, 8080] {
            segment.push(PortScanRecord {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port,
                status: if port == 8080 {
                    PortStatus::Closed
                } else {
                    PortStatus::Open
                },
                service_id: match port {
                    80 | 8080 => 1,
                    443 => 2,
                    _ => 0,
                },
                timestamp: 1_700_000_000 + port as u32,
            });
        }
        segment.push(PortScanRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5)),
            port: 445,
            status: PortStatus::Filtered,
            service_id: 3,
            timestamp: 1_700_123_456,
        });

        let encoded = segment.serialize();
        let mut decoded = PortSegment::deserialize(&encoded).expect("decode");

        let hit = decoded
            .find(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)
            .unwrap();
        assert_eq!(hit.port, 443);
        assert!(matches!(hit.status, PortStatus::Open));
        assert_eq!(
            decoded
                .get_open_ports(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                .len(),
            3
        );
    }
}
