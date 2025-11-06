/// Minimal QPACK encoder/decoder sufficient for literal header blocks.
///
/// This implementation only supports literal header fields without name reference
/// and does not maintain a dynamic table yet. It is enough to bootstrap HTTP/3
/// requests while we iterate on full QPACK compliance.

/// QPACK encoder that emits literal header field representations.
pub struct QpackEncoder;

impl QpackEncoder {
    pub fn new() -> Self {
        Self
    }

    /// Encode a header list into a QPACK header block section.
    pub fn encode(&self, headers: &[(String, String)]) -> Vec<u8> {
        let mut block = Vec::new();
        for (name, value) in headers {
            encode_literal(&mut block, name.as_bytes(), value.as_bytes());
        }
        block
    }
}

/// QPACK decoder for literal header blocks.
pub struct QpackDecoder;

impl QpackDecoder {
    pub fn new() -> Self {
        Self
    }

    pub fn decode(&self, block: &[u8]) -> Result<Vec<(String, String)>, String> {
        let mut cursor = 0usize;
        let mut headers = Vec::new();

        while cursor < block.len() {
            if block[cursor] & 0b1110_0000 != 0b0010_0000 {
                return Err("unsupported QPACK representation".to_string());
            }
            let (name_len, consumed) = decode_prefixed_integer(&block[cursor..], 3)?;
            cursor += consumed;
            if cursor + name_len as usize > block.len() {
                return Err("qpack name truncated".to_string());
            }
            let name =
                String::from_utf8(block[cursor..cursor + name_len as usize].to_vec()).map_err(
                    |_| "invalid header name encoding".to_string(),
                )?;
            cursor += name_len as usize;

            let (value_len, consumed) = decode_prefixed_integer(&block[cursor..], 7)?;
            cursor += consumed;
            if cursor + value_len as usize > block.len() {
                return Err("qpack value truncated".to_string());
            }
            let value =
                String::from_utf8(block[cursor..cursor + value_len as usize].to_vec()).map_err(
                    |_| "invalid header value encoding".to_string(),
                )?;
            cursor += value_len as usize;

            headers.push((name, value));
        }

        Ok(headers)
    }
}

fn encode_literal(block: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    // 0b0010NNNN literal header without name reference (no Huffman for now).
    block.push(0b0010_0000);
    encode_prefixed_integer(block, 3, name.len() as u64);
    block.extend_from_slice(name);
    block.push(0x00); // Huffman flag (0) + length prefix
    encode_prefixed_integer(block, 7, value.len() as u64);
    block.extend_from_slice(value);
}

fn encode_prefixed_integer(buffer: &mut Vec<u8>, prefix: u8, mut value: u64) {
    let mask = (1u8 << prefix) - 1;
    let last_index = buffer
        .len()
        .checked_sub(1)
        .expect("prefixed integer requires preceding byte");

    let max_first_value = mask as u64;
    if value < max_first_value {
        buffer[last_index] =
            (buffer[last_index] & !mask) | ((value as u8) & mask);
        return;
    }

    buffer[last_index] = (buffer[last_index] & !mask) | mask;
    value -= max_first_value;

    while value >= 128 {
        buffer.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

fn decode_prefixed_integer(data: &[u8], prefix: u8) -> Result<(u64, usize), String> {
    if data.is_empty() {
        return Err("prefixed integer truncated".to_string());
    }

    let mask = (1u8 << prefix) - 1;
    let mut value = (data[0] & mask) as u64;
    let mut consumed = 1usize;

    if value < mask as u64 {
        return Ok((value, consumed));
    }

    let mut multiplier = 0u32;
    loop {
        if consumed >= data.len() {
            return Err("prefixed integer continuation truncated".to_string());
        }
        let byte = data[consumed];
        consumed += 1;
        value += ((byte & 0x7f) as u64) << multiplier;
        if byte & 0x80 == 0 {
            break;
        }
        multiplier += 7;
    }

    Ok((value, consumed))
}
