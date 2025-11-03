use std::collections::HashMap;

use crate::storage::encoding::{read_string, read_varu32, write_string, write_varu32, DecodeError};
use crate::storage::schema::HttpHeadersRecord;
use crate::storage::segments::utils::StringTable;

fn encode_string_table(table: &StringTable) -> Vec<u8> {
    let mut buf = Vec::new();
    write_varu32(&mut buf, table.len() as u32);
    for value in table.entries() {
        write_string(&mut buf, value);
    }
    buf
}

fn decode_string_table(bytes: &[u8]) -> Result<StringTable, DecodeError> {
    let mut pos = 0usize;
    let count = read_varu32(bytes, &mut pos)? as usize;
    let mut table = StringTable::new();
    for _ in 0..count {
        let value = read_string(bytes, &mut pos)?;
        table.intern(value);
    }
    Ok(table)
}

#[derive(Debug, Clone)]
struct HeaderEntry {
    name_id: u32,
    value_id: u32,
}

#[derive(Debug, Clone)]
struct Entry {
    host_id: u32,
    url_id: u32,
    method_id: u32,
    scheme_id: u32,
    version_id: u32,
    status_code: u16,
    status_text_id: u32,
    server_id: Option<u32>,
    body_size: u32,
    timestamp: u32,
    headers: Vec<HeaderEntry>,
}

#[derive(Debug, Clone, Copy)]
struct HostRange {
    start: usize,
    len: usize,
}

#[derive(Debug, Clone, Copy)]
struct HttpDirEntry {
    host_id: u32,
    record_count: u32,
    payload_offset: u64,
    payload_len: u64,
}

impl HttpDirEntry {
    const SIZE: usize = 4 + 4 + 8 + 8;

    fn write_all(entries: &[Self], buf: &mut Vec<u8>) {
        for entry in entries {
            buf.extend_from_slice(&entry.host_id.to_le_bytes());
            buf.extend_from_slice(&entry.record_count.to_le_bytes());
            buf.extend_from_slice(&entry.payload_offset.to_le_bytes());
            buf.extend_from_slice(&entry.payload_len.to_le_bytes());
        }
    }

    fn read_all(bytes: &[u8], count: usize) -> Result<Vec<Self>, DecodeError> {
        if bytes.len() != count * Self::SIZE {
            return Err(DecodeError("invalid http directory size"));
        }
        let mut entries = Vec::with_capacity(count);
        let mut offset = 0usize;
        for _ in 0..count {
            let host_id = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let record_count = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let payload_offset = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let payload_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;
            entries.push(Self {
                host_id,
                record_count,
                payload_offset,
                payload_len,
            });
        }
        Ok(entries)
    }
}

#[derive(Debug, Clone, Copy)]
struct HttpSegmentHeader {
    host_count: u32,
    record_count: u32,
    directory_len: u64,
    payload_len: u64,
    strings_len: u64,
}

impl HttpSegmentHeader {
    const MAGIC: [u8; 4] = *b"HT01";
    const VERSION: u16 = 1;
    const SIZE: usize = 4 + 2 + 2 + 4 + 4 + 8 + 8 + 8;

    fn write(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&Self::MAGIC);
        buf.extend_from_slice(&Self::VERSION.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
        buf.extend_from_slice(&self.host_count.to_le_bytes());
        buf.extend_from_slice(&self.record_count.to_le_bytes());
        buf.extend_from_slice(&self.directory_len.to_le_bytes());
        buf.extend_from_slice(&self.payload_len.to_le_bytes());
        buf.extend_from_slice(&self.strings_len.to_le_bytes());
    }

    fn read(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < Self::SIZE {
            return Err(DecodeError("http header too small"));
        }
        if &bytes[0..4] != Self::MAGIC {
            return Err(DecodeError("invalid http segment magic"));
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        if version != Self::VERSION {
            return Err(DecodeError("unsupported http segment version"));
        }
        let host_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let record_count = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let directory_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let payload_len = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let strings_len = u64::from_le_bytes(bytes[32..40].try_into().unwrap());

        Ok(Self {
            host_count,
            record_count,
            directory_len,
            payload_len,
            strings_len,
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct HttpSegment {
    strings: StringTable,
    entries: Vec<Entry>,
    host_index: HashMap<u32, HostRange>,
    sorted: bool,
}

pub struct HttpSegmentView {
    strings: StringTable,
    directory: Vec<HttpDirEntry>,
    payload: Vec<u8>,
}

pub struct HttpIter<'a> {
    segment: &'a mut HttpSegment,
    pos: usize,
}

impl HttpSegment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, mut record: HttpHeadersRecord) {
        if record.host.is_empty() {
            record.host = extract_host(&record.url).to_string();
        }
        if record.scheme.is_empty() {
            record.scheme = extract_scheme(&record.url).to_string();
        }

        let host_id = self.strings.intern(&record.host);
        let url_id = self.strings.intern(&record.url);
        let method_id = self.strings.intern(&record.method);
        let scheme_id = self.strings.intern(&record.scheme);
        let version_id = self.strings.intern(&record.http_version);
        let status_text_id = self.strings.intern(&record.status_text);
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
            host_id,
            url_id,
            method_id,
            scheme_id,
            version_id,
            status_code: record.status_code,
            status_text_id,
            server_id,
            body_size: record.body_size,
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

    pub fn iter(&mut self) -> HttpIter<'_> {
        self.ensure_index();
        HttpIter {
            segment: self,
            pos: 0,
        }
    }

    pub fn iter_mut(&mut self) -> HttpIter<'_> {
        self.iter()
    }

    pub fn serialize(&mut self) -> Vec<u8> {
        self.ensure_index();

        let mut hosts: Vec<(u32, HostRange)> = self
            .host_index
            .iter()
            .map(|(host_id, range)| (*host_id, *range))
            .collect();
        hosts.sort_by_key(|(host_id, _)| *host_id);

        let mut directory = Vec::with_capacity(hosts.len());
        let mut payload = Vec::new();

        for (host_id, range) in hosts {
            let start_offset = payload.len() as u64;
            let records_slice = &self.entries[range.start..range.start + range.len];

            let mut block = Vec::new();
            write_varu32(&mut block, records_slice.len() as u32);
            for entry in records_slice {
                write_varu32(&mut block, entry.url_id);
                write_varu32(&mut block, entry.method_id);
                write_varu32(&mut block, entry.scheme_id);
                write_varu32(&mut block, entry.version_id);
                write_varu32(&mut block, entry.status_code as u32);
                write_varu32(&mut block, entry.status_text_id);
                match entry.server_id {
                    Some(id) => {
                        block.push(1);
                        write_varu32(&mut block, id);
                    }
                    None => block.push(0),
                }
                write_varu32(&mut block, entry.body_size);
                write_varu32(&mut block, entry.timestamp);
                write_varu32(&mut block, entry.headers.len() as u32);
                for header in &entry.headers {
                    write_varu32(&mut block, header.name_id);
                    write_varu32(&mut block, header.value_id);
                }
            }

            let block_len = block.len() as u64;
            payload.extend_from_slice(&block);
            directory.push(HttpDirEntry {
                host_id,
                record_count: records_slice.len() as u32,
                payload_offset: start_offset,
                payload_len: block_len,
            });
        }

        let string_section = encode_string_table(&self.strings);
        let directory_len = (directory.len() * HttpDirEntry::SIZE) as u64;
        let payload_len = payload.len() as u64;
        let strings_len = string_section.len() as u64;

        let header = HttpSegmentHeader {
            host_count: directory.len() as u32,
            record_count: self.entries.len() as u32,
            directory_len,
            payload_len,
            strings_len,
        };

        let mut buf = Vec::with_capacity(
            HttpSegmentHeader::SIZE + directory_len as usize + payload.len() + string_section.len(),
        );
        header.write(&mut buf);
        HttpDirEntry::write_all(&directory, &mut buf);
        buf.extend_from_slice(&payload);
        buf.extend_from_slice(&string_section);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HttpSegmentHeader::SIZE {
            return Err(DecodeError("http segment too small"));
        }
        let header = HttpSegmentHeader::read(bytes)?;

        let mut offset = HttpSegmentHeader::SIZE;
        let dir_end = offset
            .checked_add(header.directory_len as usize)
            .ok_or(DecodeError("http directory overflow"))?;
        if dir_end > bytes.len() {
            return Err(DecodeError("http directory out of bounds"));
        }
        let directory_bytes = &bytes[offset..dir_end];
        offset = dir_end;

        let payload_end = offset
            .checked_add(header.payload_len as usize)
            .ok_or(DecodeError("http payload overflow"))?;
        if payload_end > bytes.len() {
            return Err(DecodeError("http payload out of bounds"));
        }
        let payload_bytes = &bytes[offset..payload_end];
        offset = payload_end;

        let strings_end = offset
            .checked_add(header.strings_len as usize)
            .ok_or(DecodeError("http string table overflow"))?;
        if strings_end > bytes.len() {
            return Err(DecodeError("http string table out of bounds"));
        }
        let strings_bytes = &bytes[offset..strings_end];

        let strings = decode_string_table(strings_bytes)?;
        let directory = HttpDirEntry::read_all(directory_bytes, header.host_count as usize)?;

        let mut entries = Vec::with_capacity(header.record_count as usize);
        let mut host_index = HashMap::with_capacity(directory.len());

        for entry in &directory {
            let mut cursor = entry.payload_offset as usize;
            let end = cursor + entry.payload_len as usize;
            if end > payload_bytes.len() {
                return Err(DecodeError("http payload slice out of bounds"));
            }
            let record_count = read_varu32(payload_bytes, &mut cursor)? as usize;
            if record_count as u32 != entry.record_count {
                return Err(DecodeError("http record count mismatch"));
            }

            let start_index = entries.len();
            for _ in 0..record_count {
                let record = decode_http_entry(payload_bytes, &mut cursor)?;
                entries.push(Entry {
                    host_id: entry.host_id,
                    ..record
                });
            }

            if cursor != end {
                return Err(DecodeError("http payload length mismatch"));
            }

            host_index.insert(
                entry.host_id,
                HostRange {
                    start: start_index,
                    len: record_count,
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
            host: self.strings.get(entry.host_id).to_string(),
            url: self.strings.get(entry.url_id).to_string(),
            method: self.strings.get(entry.method_id).to_string(),
            scheme: self.strings.get(entry.scheme_id).to_string(),
            http_version: self.strings.get(entry.version_id).to_string(),
            status_code: entry.status_code,
            status_text: self.strings.get(entry.status_text_id).to_string(),
            server: entry.server_id.map(|id| self.strings.get(id).to_string()),
            body_size: entry.body_size,
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

impl HttpSegmentView {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HttpSegmentHeader::SIZE {
            return Err(DecodeError("http segment too small"));
        }
        let header = HttpSegmentHeader::read(bytes)?;

        let mut offset = HttpSegmentHeader::SIZE;
        let dir_end = offset
            .checked_add(header.directory_len as usize)
            .ok_or(DecodeError("http directory overflow"))?;
        if dir_end > bytes.len() {
            return Err(DecodeError("http directory out of bounds"));
        }
        let directory_bytes = &bytes[offset..dir_end];
        offset = dir_end;

        let payload_end = offset
            .checked_add(header.payload_len as usize)
            .ok_or(DecodeError("http payload overflow"))?;
        if payload_end > bytes.len() {
            return Err(DecodeError("http payload out of bounds"));
        }
        let payload_bytes = &bytes[offset..payload_end];
        offset = payload_end;

        let strings_end = offset
            .checked_add(header.strings_len as usize)
            .ok_or(DecodeError("http string table overflow"))?;
        if strings_end > bytes.len() {
            return Err(DecodeError("http string table out of bounds"));
        }
        let strings_bytes = &bytes[offset..strings_end];

        let strings = decode_string_table(strings_bytes)?;
        let mut directory = HttpDirEntry::read_all(directory_bytes, header.host_count as usize)?;
        directory.sort_by_key(|entry| entry.host_id);

        Ok(Self {
            strings,
            directory,
            payload: payload_bytes.to_vec(),
        })
    }

    pub fn records_for_host(&self, host: &str) -> Result<Vec<HttpHeadersRecord>, DecodeError> {
        let Some(host_id) = self.strings.get_id(host) else {
            return Ok(Vec::new());
        };
        let Some(dir) = self.directory.iter().find(|entry| entry.host_id == host_id) else {
            return Ok(Vec::new());
        };

        decode_http_records(
            &self.payload,
            dir.payload_offset,
            dir.payload_len,
            dir.record_count,
            host_id,
            &self.strings,
        )
    }
}

impl<'a> Iterator for HttpIter<'a> {
    type Item = HttpHeadersRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.segment.entries.len() {
            return None;
        }
        let record = self.segment.to_record(&self.segment.entries[self.pos]);
        self.pos += 1;
        Some(record)
    }
}

fn decode_http_entry(bytes: &[u8], pos: &mut usize) -> Result<Entry, DecodeError> {
    let url_id = read_varu32(bytes, pos)?;
    let method_id = read_varu32(bytes, pos)?;
    let scheme_id = read_varu32(bytes, pos)?;
    let version_id = read_varu32(bytes, pos)?;
    let status_code = read_varu32(bytes, pos)? as u16;
    let status_text_id = read_varu32(bytes, pos)?;
    if *pos >= bytes.len() {
        return Err(DecodeError("unexpected eof (http server flag)"));
    }
    let server_id = if bytes[*pos] != 0 {
        *pos += 1;
        Some(read_varu32(bytes, pos)?)
    } else {
        *pos += 1;
        None
    };
    let body_size = read_varu32(bytes, pos)?;
    let timestamp = read_varu32(bytes, pos)?;
    let header_count = read_varu32(bytes, pos)? as usize;
    let mut headers = Vec::with_capacity(header_count);
    for _ in 0..header_count {
        let name_id = read_varu32(bytes, pos)?;
        let value_id = read_varu32(bytes, pos)?;
        headers.push(HeaderEntry { name_id, value_id });
    }
    Ok(Entry {
        host_id: 0,
        url_id,
        method_id,
        scheme_id,
        version_id,
        status_code,
        status_text_id,
        server_id,
        body_size,
        timestamp,
        headers,
    })
}

fn decode_http_records(
    payload: &[u8],
    offset: u64,
    length: u64,
    expected_count: u32,
    host_id: u32,
    strings: &StringTable,
) -> Result<Vec<HttpHeadersRecord>, DecodeError> {
    let mut cursor = offset as usize;
    let end = cursor + length as usize;
    if end > payload.len() {
        return Err(DecodeError("http payload slice out of bounds"));
    }
    let count = read_varu32(payload, &mut cursor)? as usize;
    if count as u32 != expected_count {
        return Err(DecodeError("http record count mismatch"));
    }

    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let entry = decode_http_entry(payload, &mut cursor)?;
        records.push(HttpHeadersRecord {
            host: strings.get(host_id).to_string(),
            url: strings.get(entry.url_id).to_string(),
            method: strings.get(entry.method_id).to_string(),
            scheme: strings.get(entry.scheme_id).to_string(),
            http_version: strings.get(entry.version_id).to_string(),
            status_code: entry.status_code,
            status_text: strings.get(entry.status_text_id).to_string(),
            server: entry.server_id.map(|id| strings.get(id).to_string()),
            body_size: entry.body_size,
            headers: entry
                .headers
                .iter()
                .map(|header| {
                    (
                        strings.get(header.name_id).to_string(),
                        strings.get(header.value_id).to_string(),
                    )
                })
                .collect(),
            timestamp: entry.timestamp,
        });
    }

    if cursor != end {
        return Err(DecodeError("http payload length mismatch"));
    }

    Ok(records)
}

fn extract_host(url: &str) -> &str {
    let without_scheme = if let Some(idx) = url.find("://") {
        &url[idx + 3..]
    } else {
        url
    };
    without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split('@')
        .last()
        .unwrap_or("")
}

fn extract_scheme(url: &str) -> &str {
    url.split("://").next().unwrap_or("http")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_http_segment() {
        let mut segment = HttpSegment::new();
        segment.insert(HttpHeadersRecord {
            host: "example.com".into(),
            url: "https://example.com/".into(),
            method: "GET".into(),
            scheme: "https".into(),
            http_version: "HTTP/1.1".into(),
            status_code: 200,
            status_text: "OK".into(),
            server: Some("ExampleServer".into()),
            body_size: 1234,
            headers: vec![
                ("content-type".into(), "text/html".into()),
                ("server".into(), "ExampleServer".into()),
            ],
            timestamp: 1_700_000_000,
        });

        let encoded = segment.serialize();
        let mut decoded = HttpSegment::deserialize(&encoded).expect("decode");
        let records = decoded.all_records();
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.host, "example.com");
        assert_eq!(rec.scheme, "https");
        assert_eq!(rec.method, "GET");
        assert_eq!(rec.status_text, "OK");
        assert_eq!(rec.body_size, 1234);
    }

    #[test]
    fn http_segment_view_reads_host() {
        let mut segment = HttpSegment::new();
        segment.insert(HttpHeadersRecord {
            host: "example.com".into(),
            url: "https://example.com/".into(),
            method: "GET".into(),
            scheme: "https".into(),
            http_version: "HTTP/1.1".into(),
            status_code: 200,
            status_text: "OK".into(),
            server: Some("ExampleServer".into()),
            body_size: 100,
            headers: vec![("content-type".into(), "text/html".into())],
            timestamp: 10,
        });
        segment.insert(HttpHeadersRecord {
            host: "api.example.com".into(),
            url: "https://api.example.com/v1".into(),
            method: "POST".into(),
            scheme: "https".into(),
            http_version: "HTTP/2".into(),
            status_code: 201,
            status_text: "Created".into(),
            server: None,
            body_size: 512,
            headers: vec![],
            timestamp: 20,
        });

        let encoded = segment.serialize();
        let view = HttpSegmentView::from_bytes(&encoded).expect("view");

        let records = view.records_for_host("api.example.com").expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status_code, 201);
    }
}
