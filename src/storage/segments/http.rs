use std::collections::HashMap;

use crate::storage::encoding::{read_string, read_varu32, write_string, write_varu32, DecodeError};
use crate::storage::schema::HttpHeadersRecord;
use crate::storage::segments::utils::StringTable;

#[derive(Debug, Clone)]
struct HeaderEntry {
    name_id: u32,
    value_id: u32,
}

#[derive(Debug, Clone)]
struct Entry {
    url_id: u32,
    host_id: u32,
    server_id: Option<u32>,
    status_code: u16,
    timestamp: u32,
    headers: Vec<HeaderEntry>,
}

#[derive(Debug, Clone)]
struct HostRange {
    start: usize,
    len: usize,
}

#[derive(Debug, Default, Clone)]
pub struct HttpSegment {
    strings: StringTable,
    entries: Vec<Entry>,
    host_index: HashMap<u32, HostRange>,
    sorted: bool,
}

impl HttpSegment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, record: HttpHeadersRecord) {
        let url_id = self.strings.intern(&record.url);
        let host = extract_host(&record.url);
        let host_id = self.strings.intern(host);
        let server_id = record
            .server
            .as_ref()
            .map(|value| self.strings.intern(value));
        let headers = record
            .headers
            .into_iter()
            .map(|(name, value)| HeaderEntry {
                name_id: self.strings.intern(name),
                value_id: self.strings.intern(value),
            })
            .collect();

        self.entries.push(Entry {
            url_id,
            host_id,
            server_id,
            status_code: record.status_code,
            timestamp: record.timestamp,
            headers,
        });
        self.sorted = false;
    }

    fn ensure_index(&mut self) {
        if self.sorted {
            return;
        }

        self.entries
            .sort_by(|a, b| match a.host_id.cmp(&b.host_id) {
                std::cmp::Ordering::Equal => a.url_id.cmp(&b.url_id),
                other => other,
            });

        self.host_index.clear();
        let mut current_host: Option<u32> = None;
        let mut start = 0usize;
        for (idx, entry) in self.entries.iter().enumerate() {
            if current_host == Some(entry.host_id) {
                continue;
            }
            if let Some(active) = current_host {
                self.host_index.insert(
                    active,
                    HostRange {
                        start,
                        len: idx - start,
                    },
                );
                start = idx;
            } else {
                start = idx;
            }
            current_host = Some(entry.host_id);
        }
        if let Some(active) = current_host {
            self.host_index.insert(
                active,
                HostRange {
                    start,
                    len: self.entries.len() - start,
                },
            );
        }

        self.sorted = true;
    }

    pub fn records_for_host(&mut self, host: &str) -> Vec<HttpHeadersRecord> {
        self.ensure_index();
        let Some(host_id) = self.strings.get_id(host) else {
            return Vec::new();
        };
        let Some(range) = self.host_index.get(&host_id) else {
            return Vec::new();
        };
        self.entries[range.start..range.start + range.len]
            .iter()
            .map(|entry| self.to_record(entry))
            .collect()
    }

    pub fn all_records(&mut self) -> Vec<HttpHeadersRecord> {
        self.ensure_index();
        self.entries
            .iter()
            .map(|entry| self.to_record(entry))
            .collect()
    }

    pub fn iter_mut(&mut self) -> HttpIter<'_> {
        self.ensure_index();
        HttpIter {
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

        write_varu32(&mut buf, self.entries.len() as u32);
        for entry in &self.entries {
            write_varu32(&mut buf, entry.url_id);
            write_varu32(&mut buf, entry.host_id);
            write_varu32(&mut buf, entry.status_code as u32);
            write_varu32(&mut buf, entry.timestamp);
            match entry.server_id {
                Some(id) => {
                    buf.push(1);
                    write_varu32(&mut buf, id);
                }
                None => buf.push(0),
            }
            write_varu32(&mut buf, entry.headers.len() as u32);
            for header in &entry.headers {
                write_varu32(&mut buf, header.name_id);
                write_varu32(&mut buf, header.value_id);
            }
        }

        write_varu32(&mut buf, self.host_index.len() as u32);
        for (host_id, range) in &self.host_index {
            write_varu32(&mut buf, *host_id);
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
        let mut entries = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let url_id = read_varu32(bytes, &mut pos)?;
            let host_id = read_varu32(bytes, &mut pos)?;
            let status_code = read_varu32(bytes, &mut pos)? as u16;
            let timestamp = read_varu32(bytes, &mut pos)?;
            let server_flag = bytes
                .get(pos)
                .copied()
                .ok_or(DecodeError("unexpected eof (server flag)"))?;
            pos += 1;
            let server_id = if server_flag == 1 {
                Some(read_varu32(bytes, &mut pos)?)
            } else {
                None
            };
            let header_count = read_varu32(bytes, &mut pos)? as usize;
            let mut headers = Vec::with_capacity(header_count);
            for _ in 0..header_count {
                let name_id = read_varu32(bytes, &mut pos)?;
                let value_id = read_varu32(bytes, &mut pos)?;
                headers.push(HeaderEntry { name_id, value_id });
            }
            entries.push(Entry {
                url_id,
                host_id,
                server_id,
                status_code,
                timestamp,
                headers,
            });
        }

        let index_count = read_varu32(bytes, &mut pos)? as usize;
        let mut host_index = HashMap::with_capacity(index_count);
        for _ in 0..index_count {
            let host_id = read_varu32(bytes, &mut pos)?;
            let start = read_varu32(bytes, &mut pos)?;
            let len = read_varu32(bytes, &mut pos)?;
            host_index.insert(
                host_id,
                HostRange {
                    start: start as usize,
                    len: len as usize,
                },
            );
        }

        Ok(Self {
            strings,
            entries,
            host_index,
            sorted: true,
        })
    }

    fn to_record(&self, entry: &Entry) -> HttpHeadersRecord {
        HttpHeadersRecord {
            url: self.strings.get(entry.url_id).to_string(),
            status_code: entry.status_code,
            server: entry.server_id.map(|id| self.strings.get(id).to_string()),
            headers: entry
                .headers
                .iter()
                .map(|header| {
                    (
                        self.strings.get(header.name_id).to_string(),
                        self.strings.get(header.value_id).to_string(),
                    )
                })
                .collect(),
            timestamp: entry.timestamp,
        }
    }
}

pub struct HttpIter<'a> {
    segment: &'a mut HttpSegment,
    pos: usize,
}

impl<'a> Iterator for HttpIter<'a> {
    type Item = HttpHeadersRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.segment.entries.len() {
            return None;
        }
        let entry = &self.segment.entries[self.pos];
        self.pos += 1;
        Some(self.segment.to_record(entry))
    }
}

fn extract_host(url: &str) -> &str {
    let bytes = url.as_bytes();
    let mut start = 0usize;

    if let Some(pos) = url.find("://") {
        start = pos + 3;
    } else if url.starts_with("//") {
        start = 2;
    }

    let mut end = bytes.len();
    for (idx, &byte) in bytes[start..].iter().enumerate() {
        match byte {
            b'/' | b'?' | b'#' => {
                end = start + idx;
                break;
            }
            _ => {}
        }
    }

    &url[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_segment_roundtrip_and_host_lookup() {
        let mut segment = HttpSegment::new();
        segment.insert(HttpHeadersRecord {
            url: "https://example.com/index.html".into(),
            status_code: 200,
            server: Some("nginx".into()),
            headers: vec![("content-type".into(), "text/html".into())],
            timestamp: 1_700_000_000,
        });
        segment.insert(HttpHeadersRecord {
            url: "https://example.com/admin".into(),
            status_code: 403,
            server: None,
            headers: vec![("content-length".into(), "0".into())],
            timestamp: 1_700_000_123,
        });
        segment.insert(HttpHeadersRecord {
            url: "http://api.other.org/v1".into(),
            status_code: 200,
            server: Some("apache".into()),
            headers: vec![("content-type".into(), "application/json".into())],
            timestamp: 1_700_000_456,
        });

        let mut before = segment.clone();
        let example = before.records_for_host("example.com");
        assert_eq!(example.len(), 2);
        assert!(example.iter().any(|r| r.status_code == 403));

        let mut to_encode = segment.clone();
        let bytes = to_encode.serialize();
        let mut decoded = HttpSegment::deserialize(&bytes).expect("decode http segment");
        let records = decoded.iter_mut().collect::<Vec<_>>();
        assert_eq!(records.len(), 3);

        let other = decoded.records_for_host("api.other.org");
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].server.as_deref(), Some("apache"));
    }

    #[test]
    fn extract_host_variants() {
        assert_eq!(extract_host("https://example.com/path"), "example.com");
        assert_eq!(extract_host("http://example.com:8080/"), "example.com:8080");
        assert_eq!(extract_host("//cdn.example.com/assets"), "cdn.example.com");
        assert_eq!(extract_host("/relative/path"), "");
    }
}
