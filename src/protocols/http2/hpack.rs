/// HPACK: Header Compression for HTTP/2 (RFC 7541)
/// Pure Rust std implementation - ZERO external dependencies
use std::collections::VecDeque;

/// Static table (RFC 7541 Appendix A)
/// These are the 61 predefined header fields
const STATIC_TABLE: &[(&str, &str)] = &[
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

/// Dynamic table entry
#[derive(Debug, Clone)]
struct DynamicEntry {
    name: String,
    value: String,
    size: usize, // name.len() + value.len() + 32 (RFC 7541 Section 4.1)
}

impl DynamicEntry {
    fn new(name: String, value: String) -> Self {
        let size = name.len() + value.len() + 32;
        Self { name, value, size }
    }

    fn size(&self) -> usize {
        self.size
    }
}

/// HPACK Encoder/Decoder
pub struct HpackCodec {
    dynamic_table: VecDeque<DynamicEntry>,
    dynamic_table_size: usize,
    max_dynamic_table_size: usize,
}

impl HpackCodec {
    pub fn new() -> Self {
        Self {
            dynamic_table: VecDeque::new(),
            dynamic_table_size: 0,
            max_dynamic_table_size: 4096, // Default 4KB
        }
    }

    pub fn with_max_table_size(mut self, size: usize) -> Self {
        self.max_dynamic_table_size = size;
        self
    }

    /// Decode HPACK-encoded header block
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>, String> {
        let mut headers = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let byte = data[offset];

            if byte & 0x80 != 0 {
                // Indexed header field (RFC 7541 Section 6.1)
                let (index, consumed) = self.decode_integer(data, offset, 7)?;
                offset += consumed;

                let (name, value) = self.get_indexed(index)?;
                headers.push((name.to_string(), value.to_string()));
            } else if byte & 0x40 != 0 {
                // Literal header field with incremental indexing (RFC 7541 Section 6.2.1)
                offset += 1;
                let (name, value, consumed) = self.decode_literal(data, offset, 6)?;
                offset += consumed;

                self.add_to_dynamic_table(name.clone(), value.clone());
                headers.push((name, value));
            } else if byte & 0x20 != 0 {
                // Dynamic table size update (RFC 7541 Section 6.3)
                let (new_size, consumed) = self.decode_integer(data, offset, 5)?;
                offset += consumed;
                self.update_max_table_size(new_size)?;
            } else {
                // Literal header field without indexing (RFC 7541 Section 6.2.2)
                // OR Literal header field never indexed (RFC 7541 Section 6.2.3)
                offset += 1;
                let (name, value, consumed) = self.decode_literal(data, offset, 4)?;
                offset += consumed;
                headers.push((name, value));
            }
        }

        Ok(headers)
    }

    /// Encode headers to HPACK format
    pub fn encode(&mut self, headers: &[(String, String)]) -> Result<Vec<u8>, String> {
        let mut encoded = Vec::new();

        for (name, value) in headers {
            // Try to find in static or dynamic table
            if let Some(index) = self.find_indexed(name, value) {
                // Indexed header field
                self.encode_integer(&mut encoded, index, 7);
                encoded[0] |= 0x80; // Set indexed bit
            } else {
                // Literal header field with incremental indexing
                encoded.push(0x40); // Incremental indexing bit

                // Encode name
                if let Some(name_index) = self.find_name_indexed(name) {
                    self.encode_integer(&mut encoded, name_index, 6);
                } else {
                    self.encode_string(&mut encoded, name, false)?;
                }

                // Encode value
                self.encode_string(&mut encoded, value, false)?;

                // Add to dynamic table
                self.add_to_dynamic_table(name.clone(), value.clone());
            }
        }

        Ok(encoded)
    }

    /// Get indexed header (static or dynamic)
    fn get_indexed(&self, index: usize) -> Result<(&str, &str), String> {
        if index == 0 {
            return Err("Index 0 is invalid".to_string());
        }

        if index <= STATIC_TABLE.len() {
            // Static table (1-indexed)
            Ok(STATIC_TABLE[index - 1])
        } else {
            // Dynamic table
            let dyn_index = index - STATIC_TABLE.len() - 1;
            if dyn_index >= self.dynamic_table.len() {
                return Err(format!("Dynamic table index {} out of bounds", dyn_index));
            }
            let entry = &self.dynamic_table[dyn_index];
            Ok((&entry.name, &entry.value))
        }
    }

    /// Find exact match in tables
    fn find_indexed(&self, name: &str, value: &str) -> Option<usize> {
        // Search static table
        for (i, (static_name, static_value)) in STATIC_TABLE.iter().enumerate() {
            if *static_name == name && *static_value == value {
                return Some(i + 1); // 1-indexed
            }
        }

        // Search dynamic table
        for (i, entry) in self.dynamic_table.iter().enumerate() {
            if entry.name == name && entry.value == value {
                return Some(STATIC_TABLE.len() + i + 1);
            }
        }

        None
    }

    /// Find name-only match in tables
    fn find_name_indexed(&self, name: &str) -> Option<usize> {
        // Search static table
        for (i, (static_name, _)) in STATIC_TABLE.iter().enumerate() {
            if *static_name == name {
                return Some(i + 1); // 1-indexed
            }
        }

        // Search dynamic table
        for (i, entry) in self.dynamic_table.iter().enumerate() {
            if entry.name == name {
                return Some(STATIC_TABLE.len() + i + 1);
            }
        }

        None
    }

    /// Add entry to dynamic table
    fn add_to_dynamic_table(&mut self, name: String, value: String) {
        let entry = DynamicEntry::new(name, value);
        let entry_size = entry.size();

        // Evict entries if needed
        while self.dynamic_table_size + entry_size > self.max_dynamic_table_size
            && !self.dynamic_table.is_empty()
        {
            if let Some(removed) = self.dynamic_table.pop_back() {
                self.dynamic_table_size -= removed.size();
            }
        }

        // Add new entry if it fits
        if entry_size <= self.max_dynamic_table_size {
            self.dynamic_table_size += entry_size;
            self.dynamic_table.push_front(entry);
        }
    }

    /// Update maximum table size
    fn update_max_table_size(&mut self, new_size: usize) -> Result<(), String> {
        self.max_dynamic_table_size = new_size;

        // Evict entries if new size is smaller
        while self.dynamic_table_size > new_size && !self.dynamic_table.is_empty() {
            if let Some(removed) = self.dynamic_table.pop_back() {
                self.dynamic_table_size -= removed.size();
            }
        }

        Ok(())
    }

    /// Decode integer (RFC 7541 Section 5.1)
    fn decode_integer(
        &self,
        data: &[u8],
        offset: usize,
        prefix_bits: u8,
    ) -> Result<(usize, usize), String> {
        if offset >= data.len() {
            return Err("Insufficient data for integer".to_string());
        }

        let mask = (1 << prefix_bits) - 1;
        let mut value = (data[offset] & mask) as usize;
        let mut consumed = 1;

        if value < mask as usize {
            return Ok((value, consumed));
        }

        // Multi-byte integer
        let mut m = 0;
        loop {
            if offset + consumed >= data.len() {
                return Err("Incomplete integer encoding".to_string());
            }

            let byte = data[offset + consumed];
            consumed += 1;

            value += ((byte & 0x7F) as usize) << m;
            m += 7;

            if byte & 0x80 == 0 {
                break;
            }

            if m > 28 {
                return Err("Integer overflow".to_string());
            }
        }

        Ok((value, consumed))
    }

    /// Encode integer (RFC 7541 Section 5.1)
    fn encode_integer(&self, output: &mut Vec<u8>, mut value: usize, prefix_bits: u8) {
        let mask = (1 << prefix_bits) - 1;

        if value < mask {
            if output.is_empty() {
                output.push(value as u8);
            } else {
                let last = output.len() - 1;
                output[last] |= value as u8;
            }
            return;
        }

        // First byte
        if output.is_empty() {
            output.push(mask as u8);
        } else {
            let last = output.len() - 1;
            output[last] |= mask as u8;
        }

        value -= mask;

        // Additional bytes
        while value >= 128 {
            output.push(((value % 128) + 128) as u8);
            value /= 128;
        }
        output.push(value as u8);
    }

    /// Decode literal string (RFC 7541 Section 5.2)
    fn decode_literal(
        &mut self,
        data: &[u8],
        offset: usize,
        name_prefix: u8,
    ) -> Result<(String, String, usize), String> {
        let mut consumed = 0;

        // Decode name
        let name = if data[offset] & ((1 << name_prefix) - 1) != 0 {
            // Indexed name
            let (index, n) = self.decode_integer(data, offset, name_prefix)?;
            consumed += n;
            let (indexed_name, _) = self.get_indexed(index)?;
            indexed_name.to_string()
        } else {
            // Literal name
            consumed += 1;
            let (decoded_name, n) = self.decode_string(data, offset + consumed)?;
            consumed += n;
            decoded_name
        };

        // Decode value
        let (value, n) = self.decode_string(data, offset + consumed)?;
        consumed += n;

        Ok((name, value, consumed))
    }

    /// Decode string (RFC 7541 Section 5.2)
    fn decode_string(&self, data: &[u8], offset: usize) -> Result<(String, usize), String> {
        if offset >= data.len() {
            return Err("Insufficient data for string".to_string());
        }

        let huffman_encoded = (data[offset] & 0x80) != 0;
        let (length, consumed) = self.decode_integer(data, offset, 7)?;

        if offset + consumed + length > data.len() {
            return Err("String length exceeds available data".to_string());
        }

        let string_data = &data[offset + consumed..offset + consumed + length];

        let decoded = if huffman_encoded {
            // TODO: Implement Huffman decoding
            // For now, return error
            return Err("Huffman encoding not yet implemented".to_string());
        } else {
            String::from_utf8(string_data.to_vec())
                .map_err(|e| format!("Invalid UTF-8 in string: {}", e))?
        };

        Ok((decoded, consumed + length))
    }

    /// Encode string (RFC 7541 Section 5.2)
    fn encode_string(&self, output: &mut Vec<u8>, s: &str, huffman: bool) -> Result<(), String> {
        if huffman {
            // TODO: Implement Huffman encoding
            return Err("Huffman encoding not yet implemented".to_string());
        }

        // Literal string (no Huffman)
        let bytes = s.as_bytes();
        output.push(0x00); // H=0 (not Huffman encoded)
        self.encode_integer(output, bytes.len(), 7);
        output.extend_from_slice(bytes);

        Ok(())
    }
}

impl Default for HpackCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table_lookup() {
        let codec = HpackCodec::new();
        let (name, value) = codec.get_indexed(2).unwrap();
        assert_eq!(name, ":method");
        assert_eq!(value, "GET");
    }

    #[test]
    fn test_encode_indexed_header() {
        let mut codec = HpackCodec::new();
        let headers = vec![(":method".to_string(), "GET".to_string())];
        let encoded = codec.encode(&headers).unwrap();

        // :method GET is index 2 in static table
        // Indexed representation: 0x82 (10000010)
        assert_eq!(encoded[0], 0x82);
    }

    #[test]
    fn test_decode_indexed_header() {
        let mut codec = HpackCodec::new();
        let data = vec![0x82]; // :method GET
        let headers = codec.decode(&data).unwrap();

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, ":method");
        assert_eq!(headers[0].1, "GET");
    }

    #[test]
    fn test_integer_encoding() {
        let codec = HpackCodec::new();
        let mut output = Vec::new();

        // Encode 10 with 5-bit prefix
        output.push(0);
        codec.encode_integer(&mut output, 10, 5);
        assert_eq!(output[0], 10);

        // Encode 1337 with 5-bit prefix (example from RFC 7541)
        let mut output = Vec::new();
        output.push(0);
        codec.encode_integer(&mut output, 1337, 5);
        assert_eq!(output[0], 31); // 0x1F
        assert_eq!(output[1], 154); // 0x9A
        assert_eq!(output[2], 10); // 0x0A
    }

    #[test]
    fn test_integer_decoding() {
        let codec = HpackCodec::new();

        // Decode 10 with 5-bit prefix
        let data = vec![0x0A];
        let (value, consumed) = codec.decode_integer(&data, 0, 5).unwrap();
        assert_eq!(value, 10);
        assert_eq!(consumed, 1);

        // Decode 1337 with 5-bit prefix (example from RFC 7541)
        let data = vec![0x1F, 0x9A, 0x0A];
        let (value, consumed) = codec.decode_integer(&data, 0, 5).unwrap();
        assert_eq!(value, 1337);
        assert_eq!(consumed, 3);
    }
}
