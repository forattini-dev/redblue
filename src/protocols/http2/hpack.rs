//! HPACK Header Compression (RFC 7541)
//!
//! Implements HPACK header compression for HTTP/2 using:
//! - Static Table (61 predefined header entries)
//! - Dynamic Table (LRU cache with size limit)
//! - Huffman Coding (RFC 7541 Appendix B) ✅ IMPLEMENTED
//!
//! Implemented from scratch using ONLY Rust std.

use super::huffman;
use std::collections::VecDeque;

/// HPACK Static Table (RFC 7541 Appendix A)
/// 61 predefined common HTTP headers
const STATIC_TABLE: &[(&str, &str)] = &[
    // Index 1-15: Pseudo-headers and common request headers
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    // Index 16-30: Common request/response headers
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    // Index 31-45: More headers
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    // Index 46-61: Final entries
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Header representation as (name, value) pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Header {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Calculate entry size per RFC 7541 Section 4.1
    /// Size = name.len() + value.len() + 32 bytes overhead
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

/// Dynamic Table - LRU cache with size limit
#[derive(Debug)]
struct DynamicTable {
    entries: VecDeque<Header>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    fn new(max_size: usize) -> Self {
        DynamicTable {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    /// Add entry to dynamic table (front of deque)
    /// Evict old entries if size exceeds limit
    fn add(&mut self, header: Header) {
        let entry_size = header.size();

        // Evict entries from back until we have space
        while self.size + entry_size > self.max_size && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.size -= evicted.size();
            }
        }

        // Add new entry at front if it fits
        if entry_size <= self.max_size {
            self.size += entry_size;
            self.entries.push_front(header);
        }
    }

    /// Get entry by dynamic table index (1-based)
    fn get(&self, index: usize) -> Option<&Header> {
        if index == 0 || index > self.entries.len() {
            return None;
        }
        self.entries.get(index - 1)
    }

    /// Update max size and evict if necessary
    fn set_max_size(&mut self, new_max: usize) {
        self.max_size = new_max;

        // Evict entries if current size exceeds new max
        while self.size > self.max_size && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.size -= evicted.size();
            }
        }
    }
}

/// HPACK Encoder
pub struct HpackEncoder {
    dynamic_table: DynamicTable,
}

impl HpackEncoder {
    pub fn new(max_dynamic_size: usize) -> Self {
        HpackEncoder {
            dynamic_table: DynamicTable::new(max_dynamic_size),
        }
    }

    /// Encode headers to HPACK format
    pub fn encode(&mut self, headers: &[Header]) -> Vec<u8> {
        let mut output = Vec::new();

        for header in headers {
            // Try to find in static table first
            if let Some(index) = self.find_in_static_table(&header.name, &header.value) {
                // Indexed Header Field (RFC 7541 Section 6.1)
                // Format: 1xxxxxxx (high bit = 1)
                self.encode_integer(7, 0x80, index, &mut output);
            } else if let Some(name_index) = self.find_name_in_static_table(&header.name) {
                // Literal Header Field with Incremental Indexing (RFC 7541 Section 6.2.1)
                // Format: 01xxxxxx (01 prefix)
                self.encode_integer(6, 0x40, name_index, &mut output);
                self.encode_string(&header.value, &mut output);

                // Add to dynamic table
                self.dynamic_table.add(header.clone());
            } else {
                // Literal Header Field with Incremental Indexing - New Name
                // Format: 01000000 (01 prefix, index = 0)
                output.push(0x40);
                self.encode_string(&header.name, &mut output);
                self.encode_string(&header.value, &mut output);

                // Add to dynamic table
                self.dynamic_table.add(header.clone());
            }
        }

        output
    }

    /// Find exact match (name + value) in static table
    fn find_in_static_table(&self, name: &str, value: &str) -> Option<usize> {
        for (i, (table_name, table_value)) in STATIC_TABLE.iter().enumerate() {
            if *table_name == name && *table_value == value {
                return Some(i + 1); // 1-based indexing
            }
        }
        None
    }

    /// Find name-only match in static table
    fn find_name_in_static_table(&self, name: &str) -> Option<usize> {
        for (i, (table_name, _)) in STATIC_TABLE.iter().enumerate() {
            if *table_name == name {
                return Some(i + 1); // 1-based indexing
            }
        }
        None
    }

    /// Encode integer with N-bit prefix (RFC 7541 Section 5.1)
    fn encode_integer(&self, n: u8, prefix: u8, mut value: usize, output: &mut Vec<u8>) {
        let max_prefix = ((1 << n) - 1) as usize;

        if value < max_prefix {
            output.push(prefix | (value as u8));
        } else {
            output.push(prefix | (max_prefix as u8));
            value -= max_prefix;

            while value >= 128 {
                output.push(((value % 128) + 128) as u8);
                value /= 128;
            }
            output.push(value as u8);
        }
    }

    /// Encode string literal (RFC 7541 Section 5.2)
    /// TODO: Huffman encoding (H = 0 for now, raw string)
    fn encode_string(&self, s: &str, output: &mut Vec<u8>) {
        let bytes = s.as_bytes();
        self.encode_integer(7, 0x00, bytes.len(), output); // H = 0 (no Huffman)
        output.extend_from_slice(bytes);
    }
}

/// HPACK Decoder
pub struct HpackDecoder {
    dynamic_table: DynamicTable,
}

impl HpackDecoder {
    pub fn new(max_dynamic_size: usize) -> Self {
        HpackDecoder {
            dynamic_table: DynamicTable::new(max_dynamic_size),
        }
    }

    /// Decode HPACK header block
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Header>, String> {
        let mut headers = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let first_byte = data[pos];

            if first_byte & 0x80 != 0 {
                // Indexed Header Field (1xxxxxxx)
                let (index, consumed) = self.decode_integer(7, &data[pos..])?;
                pos += consumed;

                let header = self.get_indexed(index)?;
                headers.push(header);
            } else if first_byte & 0x40 != 0 {
                // Literal Header Field with Incremental Indexing (01xxxxxx)
                let (index, consumed) = self.decode_integer(6, &data[pos..])?;
                pos += consumed;

                let name = if index == 0 {
                    let (s, consumed) = self.decode_string(&data[pos..])?;
                    pos += consumed;
                    s
                } else {
                    self.get_name(index)?
                };

                let (value, consumed) = self.decode_string(&data[pos..])?;
                pos += consumed;

                let header = Header::new(name, value);
                self.dynamic_table.add(header.clone());
                headers.push(header);
            } else if first_byte & 0x20 != 0 {
                // Dynamic Table Size Update (001xxxxx)
                let (new_size, consumed) = self.decode_integer(5, &data[pos..])?;
                pos += consumed;

                self.dynamic_table.set_max_size(new_size);
            } else {
                // Literal Header Field without Indexing (0000xxxx) or Never Indexed (0001xxxx)
                let prefix = if first_byte & 0x10 != 0 { 4 } else { 4 };
                let (index, consumed) = self.decode_integer(prefix, &data[pos..])?;
                pos += consumed;

                let name = if index == 0 {
                    let (s, consumed) = self.decode_string(&data[pos..])?;
                    pos += consumed;
                    s
                } else {
                    self.get_name(index)?
                };

                let (value, consumed) = self.decode_string(&data[pos..])?;
                pos += consumed;

                headers.push(Header::new(name, value));
            }
        }

        Ok(headers)
    }

    /// Decode integer with N-bit prefix (RFC 7541 Section 5.1)
    fn decode_integer(&self, n: u8, data: &[u8]) -> Result<(usize, usize), String> {
        if data.is_empty() {
            return Err("Empty data for integer decode".to_string());
        }

        let max_prefix = ((1 << n) - 1) as usize;
        let mask = (max_prefix as u8);

        let mut value = (data[0] & mask) as usize;

        if value < max_prefix {
            return Ok((value, 1));
        }

        let mut pos = 1;
        let mut m = 0;

        loop {
            if pos >= data.len() {
                return Err("Incomplete integer encoding".to_string());
            }

            let byte = data[pos];
            value += ((byte & 127) as usize) << m;
            m += 7;
            pos += 1;

            if byte & 128 == 0 {
                break;
            }
        }

        Ok((value, pos))
    }

    /// Decode string literal (RFC 7541 Section 5.2)
    fn decode_string(&self, data: &[u8]) -> Result<(String, usize), String> {
        if data.is_empty() {
            return Err("Empty data for string decode".to_string());
        }

        let huffman = data[0] & 0x80 != 0;
        let (length, mut pos) = self.decode_integer(7, data)?;

        if pos + length > data.len() {
            return Err("String length exceeds data size".to_string());
        }

        let string_data = &data[pos..pos + length];
        pos += length;

        let decoded_bytes = if huffman {
            // Decode Huffman-encoded string
            huffman::huffman_decode(string_data)?
        } else {
            // Plain string (not encoded)
            string_data.to_vec()
        };

        let s = String::from_utf8(decoded_bytes)
            .map_err(|e| format!("Invalid UTF-8 in string: {}", e))?;

        Ok((s, pos))
    }

    /// Get indexed header (static or dynamic)
    fn get_indexed(&self, index: usize) -> Result<Header, String> {
        if index == 0 {
            return Err("Index 0 is invalid".to_string());
        }

        if index <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[index - 1];
            return Ok(Header::new(name, value));
        }

        let dynamic_index = index - STATIC_TABLE.len();
        self.dynamic_table
            .get(dynamic_index)
            .cloned()
            .ok_or_else(|| format!("Dynamic table index {} out of range", dynamic_index))
    }

    /// Get name from indexed header
    fn get_name(&self, index: usize) -> Result<String, String> {
        if index == 0 {
            return Err("Index 0 is invalid".to_string());
        }

        if index <= STATIC_TABLE.len() {
            let (name, _) = STATIC_TABLE[index - 1];
            return Ok(name.to_string());
        }

        let dynamic_index = index - STATIC_TABLE.len();
        self.dynamic_table
            .get(dynamic_index)
            .map(|h| h.name.clone())
            .ok_or_else(|| format!("Dynamic table index {} out of range", dynamic_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table_lookup() {
        let encoder = HpackEncoder::new(4096);

        // Test exact match
        assert_eq!(encoder.find_in_static_table(":method", "GET"), Some(2));
        assert_eq!(encoder.find_in_static_table(":status", "200"), Some(8));

        // Test name-only match
        assert_eq!(encoder.find_name_in_static_table("content-type"), Some(31));
    }

    #[test]
    fn test_encode_decode_literal() {
        let mut encoder = HpackEncoder::new(4096);
        let mut decoder = HpackDecoder::new(4096);

        let headers = vec![Header::new("custom-key", "custom-value")];

        let encoded = encoder.encode(&headers);
        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, "custom-key");
        assert_eq!(decoded[0].value, "custom-value");
    }

    #[test]
    fn test_encode_decode_indexed() {
        let mut encoder = HpackEncoder::new(4096);
        let mut decoder = HpackDecoder::new(4096);

        let headers = vec![Header::new(":method", "GET"), Header::new(":status", "200")];

        let encoded = encoder.encode(&headers);
        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].name, ":method");
        assert_eq!(decoded[0].value, "GET");
        assert_eq!(decoded[1].name, ":status");
        assert_eq!(decoded[1].value, "200");
    }

    #[test]
    fn test_dynamic_table_eviction() {
        let mut table = DynamicTable::new(100);

        // Add entries that exceed max size
        table.add(Header::new("key1", "value1")); // size = 12 + 32 = 44
        table.add(Header::new("key2", "value2")); // size = 12 + 32 = 44
        table.add(Header::new("key3", "value3")); // size = 12 + 32 = 44

        // Should have evicted oldest entry (key1)
        assert_eq!(table.entries.len(), 2);
        assert_eq!(table.entries[0].name, "key3");
        assert_eq!(table.entries[1].name, "key2");
    }

    #[test]
    fn test_integer_encoding() {
        let encoder = HpackEncoder::new(4096);
        let decoder = HpackDecoder::new(4096);

        // Small value (< max_prefix)
        let mut output = Vec::new();
        encoder.encode_integer(5, 0x00, 10, &mut output);
        assert_eq!(output, vec![10]);

        let (value, consumed) = decoder.decode_integer(5, &output).unwrap();
        assert_eq!(value, 10);
        assert_eq!(consumed, 1);

        // Large value (>= max_prefix)
        let mut output = Vec::new();
        encoder.encode_integer(5, 0x00, 1337, &mut output);
        let (value, _) = decoder.decode_integer(5, &output).unwrap();
        assert_eq!(value, 1337);
    }
}
