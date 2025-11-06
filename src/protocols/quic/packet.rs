use std::fmt;

use crate::protocols::crypto::SecureRandom;

use super::constants::{MAX_CID_LENGTH, MIN_INITIAL_PACKET_SIZE, QUIC_VERSION_V1};

/// QUIC packet number spaces (RFC 9000 §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    Application,
}

/// QUIC packet number wrapper with helper conversions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PacketNumber(pub u64);

impl fmt::Debug for PacketNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pn({})", self.0)
    }
}

impl PacketNumber {
    pub fn new(value: u64) -> Self {
        PacketNumber(value)
    }

    pub fn encode_len(&self) -> usize {
        if self.0 < (1 << 8) {
            1
        } else if self.0 < (1 << 16) {
            2
        } else if self.0 < (1 << 24) {
            3
        } else {
            4
        }
    }

    pub fn to_bytes(&self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        for i in 0..len {
            buf[len - i - 1] = (self.0 >> (i * 8)) as u8;
        }
        buf
    }

    pub fn from_truncated(truncated: u64, expected: PacketNumber, pn_len: usize) -> PacketNumber {
        // RFC 9000 Appendix A: reconstruct full packet number from truncated bits.
        let pn_win = 1u64 << (pn_len * 8);
        let pn_hwin = pn_win / 2;
        let pn_mask = pn_win - 1;
        let mut candidate = (expected.0 & !pn_mask) | truncated;
        if candidate + pn_hwin <= expected.0 {
            candidate += pn_win;
        } else if candidate > expected.0 + pn_hwin && candidate >= pn_win {
            candidate -= pn_win;
        }
        PacketNumber(candidate)
    }
}

/// QUIC version currently supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVersion {
    V1,
}

impl QuicVersion {
    pub fn as_u32(&self) -> u32 {
        match self {
            QuicVersion::V1 => QUIC_VERSION_V1,
        }
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            QUIC_VERSION_V1 => Some(QuicVersion::V1),
            _ => None,
        }
    }
}

/// Connection identifier wrapper with validation.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(Vec<u8>);

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl ConnectionId {
    pub fn new(data: Vec<u8>) -> Result<Self, String> {
        if data.is_empty() {
            return Ok(ConnectionId(Vec::new()));
        }
        if data.len() > MAX_CID_LENGTH {
            return Err(format!(
                "connection id too long: {} bytes (max {})",
                data.len(),
                MAX_CID_LENGTH
            ));
        }
        Ok(ConnectionId(data))
    }

    pub fn random(len: usize) -> Self {
        let len = len.min(MAX_CID_LENGTH);
        let mut data = vec![0u8; len];

        match SecureRandom::new() {
            Ok(mut rng) => {
                if rng.fill_bytes(&mut data).is_err() {
                    fill_fallback(&mut data);
                }
            }
            Err(_) => fill_fallback(&mut data),
        }

        ConnectionId(data)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn fill_fallback(buffer: &mut [u8]) {
    let mut rng = SecureRandom::from_seed(&[0u8; 48]);
    let _ = rng.fill_bytes(buffer);
}

/// Types of long header packets (RFC 9000 §17.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongPacketType {
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(LongPacketType::Initial),
            1 => Some(LongPacketType::ZeroRtt),
            2 => Some(LongPacketType::Handshake),
            3 => Some(LongPacketType::Retry),
            _ => None,
        }
    }

    pub fn to_bits(self) -> u8 {
        match self {
            LongPacketType::Initial => 0,
            LongPacketType::ZeroRtt => 1,
            LongPacketType::Handshake => 2,
            LongPacketType::Retry => 3,
        }
    }
}

/// Encoded packet header variants.
#[derive(Debug, Clone)]
pub enum PacketHeader {
    Long(LongHeader),
    Short(ShortHeader),
}

/// Long header fields.
#[derive(Debug, Clone)]
pub struct LongHeader {
    pub packet_type: LongPacketType,
    pub version: QuicVersion,
    pub destination_connection_id: ConnectionId,
    pub source_connection_id: ConnectionId,
    pub token: Vec<u8>,
    pub payload_length: u64,
}

/// Short header fields.
#[derive(Debug, Clone)]
pub struct ShortHeader {
    pub destination_connection_id: ConnectionId,
    pub key_phase: bool,
    pub spin_bit: bool,
}

/// Encoded header representation helpful during encryption.
#[derive(Debug, Clone)]
pub struct EncodedHeader {
    pub bytes: Vec<u8>,
    pub packet_number_offset: usize,
}

/// QUIC packet container (header + payload frames).
#[derive(Debug, Clone)]
pub struct QuicPacket {
    pub header: PacketHeader,
    pub packet_number: PacketNumber,
    pub packet_number_len: usize,
    pub payload: Vec<u8>,
}

impl QuicPacket {
    pub fn new(header: PacketHeader, packet_number: PacketNumber, payload: Vec<u8>) -> Self {
        let pn_len = packet_number.encode_len();
        Self {
            header,
            packet_number,
            packet_number_len: pn_len,
            payload,
        }
    }

    /// Encode header into bytes and return offset where packet number starts.
    pub fn encode_header(&self) -> EncodedHeader {
        match &self.header {
            PacketHeader::Long(hdr) => encode_long_header(hdr, self.packet_number_len, &self.payload),
            PacketHeader::Short(hdr) => encode_short_header(hdr, self.packet_number_len),
        }
    }

    /// Encode full packet without applying header protection. The returned buffer
    /// contains header (with packet number) followed by payload. The caller must
    /// handle AEAD sealing before invoking header protection.
    pub fn encode_plaintext(&self) -> Vec<u8> {
        let mut header = self.encode_header();
        let pn_bytes = self.packet_number.to_bytes(self.packet_number_len);
        for (idx, value) in pn_bytes.iter().enumerate() {
            header.bytes[header.packet_number_offset + idx] = *value;
        }

        let mut buf = header.bytes;
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Ensure minimum size for Initial packets (padding with PADDING frames if needed).
    pub fn ensure_initial_minimum(&mut self) {
        match &self.header {
            PacketHeader::Long(long) if matches!(long.packet_type, LongPacketType::Initial) => {
                if self.payload.len() + self.packet_number_len + 20 < MIN_INITIAL_PACKET_SIZE {
                    let required = MIN_INITIAL_PACKET_SIZE
                        .saturating_sub(self.payload.len() + self.packet_number_len);
                    self.payload.resize(self.payload.len() + required, 0u8);
                }
            }
            _ => {}
        }
    }
}

fn encode_long_header(header: &LongHeader, pn_len: usize, payload: &[u8]) -> EncodedHeader {
    let mut buf = Vec::new();

    let mut first_byte: u8 = 0x80; // Long header form
    first_byte |= 0x40; // Fixed bit
    first_byte |= (header.packet_type.to_bits() & 0x03) << 4;
    first_byte |= ((pn_len - 1) & 0x03) as u8;
    buf.push(first_byte);

    buf.extend_from_slice(&header.version.as_u32().to_be_bytes());

    buf.push(header.destination_connection_id.len() as u8);
    buf.extend_from_slice(header.destination_connection_id.as_bytes());

    buf.push(header.source_connection_id.len() as u8);
    buf.extend_from_slice(header.source_connection_id.as_bytes());

    match header.packet_type {
        LongPacketType::Initial | LongPacketType::Handshake | LongPacketType::ZeroRtt => {
            encode_varint(header.token.len() as u64, &mut buf);
            buf.extend_from_slice(&header.token);

            let length_value = (pn_len + payload.len()) as u64;
            encode_varint(length_value, &mut buf);
        }
        LongPacketType::Retry => {
            buf.extend_from_slice(&header.token);
        }
    }

    let packet_number_offset = buf.len();
    buf.resize(packet_number_offset + pn_len, 0);

    EncodedHeader {
        bytes: buf,
        packet_number_offset,
    }
}

fn encode_short_header(header: &ShortHeader, pn_len: usize) -> EncodedHeader {
    let mut buf = Vec::new();

    let mut first_byte: u8 = 0x40; // Header form 0 + fixed bit 1
    if header.spin_bit {
        first_byte |= 0x20;
    }
    first_byte |= 0x10; // Reserved bit must be set to 1 for draft-29+ but set to 1 to avoid drop.
    if header.key_phase {
        first_byte |= 0x04;
    }
    first_byte |= ((pn_len - 1) as u8) & 0x03;
    buf.push(first_byte);

    buf.extend_from_slice(header.destination_connection_id.as_bytes());

    let packet_number_offset = buf.len();
    buf.resize(packet_number_offset + pn_len, 0);

    EncodedHeader {
        bytes: buf,
        packet_number_offset,
    }
}

fn parse_short_header_packet(data: &[u8], dcid_len: usize) -> Result<PacketDecodeInfo, String> {
    if data.len() < 1 + dcid_len + 1 {
        return Err("short header too short".to_string());
    }

    let first = data[0];
    let pn_len = ((first & 0x03) as usize) + 1;
    let mut cursor = 1usize;

    if cursor + dcid_len > data.len() {
        return Err("short header truncated connection id".to_string());
    }
    let dcid = ConnectionId::new(data[cursor..cursor + dcid_len].to_vec())
        .map_err(|e| format!("invalid short header dcid: {}", e))?;
    cursor += dcid_len;

    if cursor + pn_len > data.len() {
        return Err("short header truncated packet number".to_string());
    }
    let pn_offset = cursor;
    cursor += pn_len;

    let header = PacketHeader::Short(ShortHeader {
        destination_connection_id: dcid,
        key_phase: (first & 0x04) != 0,
        spin_bit: (first & 0x20) != 0,
    });

    Ok(PacketDecodeInfo {
        header,
        packet_number_offset: pn_offset,
        packet_number_length: pn_len,
        payload_offset: cursor,
    })
}

/// Encode a QUIC variable-length integer onto the buffer.
pub fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    if value < (1 << 6) {
        buf.push(value as u8 | 0b00 << 6);
    } else if value < (1 << 14) {
        let encoded = value | ((0b01 as u64) << 14);
        let bytes = encoded.to_be_bytes();
        buf.extend_from_slice(&bytes[6..]);
    } else if value < (1 << 30) {
        let encoded = value | ((0b10 as u64) << 30);
        let bytes = encoded.to_be_bytes();
        buf.extend_from_slice(&bytes[4..]);
    } else {
        let encoded = value | ((0b11 as u64) << 62);
        buf.extend_from_slice(&encoded.to_be_bytes());
    }
}

/// Decode a QUIC variable-length integer from slice, advancing cursor.
pub fn decode_varint(data: &[u8], cursor: &mut usize) -> Result<u64, String> {
    if *cursor >= data.len() {
        return Err("buffer underflow".to_string());
    }

    let first = data[*cursor];
    let prefix = first >> 6;
    match prefix {
        0b00 => {
            *cursor += 1;
            Ok((first & 0x3f) as u64)
        }
        0b01 => {
            if *cursor + 2 > data.len() {
                return Err("buffer underflow (2-byte varint)".to_string());
            }
            let mut value = ((first & 0x3f) as u64) << 8;
            value |= data[*cursor + 1] as u64;
            *cursor += 2;
            Ok(value)
        }
        0b10 => {
            if *cursor + 4 > data.len() {
                return Err("buffer underflow (4-byte varint)".to_string());
            }
            let mut value = ((first & 0x3f) as u64) << 24;
            value |= (data[*cursor + 1] as u64) << 16;
            value |= (data[*cursor + 2] as u64) << 8;
            value |= data[*cursor + 3] as u64;
            *cursor += 4;
            Ok(value)
        }
        0b11 => {
            if *cursor + 8 > data.len() {
                return Err("buffer underflow (8-byte varint)".to_string());
            }
            let mut value = ((first & 0x3f) as u64) << 56;
            for i in 1..8 {
                value |= (data[*cursor + i] as u64) << (8 * (7 - i));
            }
            *cursor += 8;
            Ok(value)
        }
        _ => unreachable!(),
    }
}

/// Parsed packet metadata used during decryption.
pub struct PacketDecodeInfo {
    pub header: PacketHeader,
    pub packet_number_offset: usize,
    pub packet_number_length: usize,
    pub payload_offset: usize,
}

/// Parse QUIC packet header. Supports long-header packets (Initial/Handshake/0-RTT/Retry).
pub fn parse_packet(data: &[u8], short_dcid_len: usize) -> Result<PacketDecodeInfo, String> {
    if data.is_empty() {
        return Err("packet too short".to_string());
    }

    let first = data[0];
    if (first & 0x80) == 0 {
        return parse_short_header_packet(data, short_dcid_len);
    }

    parse_long_header_packet(data)
}

fn parse_long_header_packet(data: &[u8]) -> Result<PacketDecodeInfo, String> {
    if data.len() < 6 {
        return Err("incomplete long header".to_string());
    }

    let first = data[0];
    let pn_len = ((first & 0x03) as usize) + 1;
    let packet_type_bits = (first >> 4) & 0x03;
    let packet_type = LongPacketType::from_bits(packet_type_bits)
        .ok_or_else(|| format!("unknown long packet type {}", packet_type_bits))?;

    let raw_version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let version = QuicVersion::from_u32(raw_version)
        .ok_or_else(|| format!("unsupported QUIC version {:08x}", raw_version))?;

    let mut cursor = 5usize;

    if cursor >= data.len() {
        return Err("missing destination connection id length".to_string());
    }
    let dcil = data[cursor] as usize;
    cursor += 1;
    if cursor + dcil > data.len() {
        return Err("truncated destination connection id".to_string());
    }
    let dcid = ConnectionId::new(data[cursor..cursor + dcil].to_vec())
        .map_err(|e| format!("invalid destination connection id: {}", e))?;
    cursor += dcil;

    if cursor >= data.len() {
        return Err("missing source connection id length".to_string());
    }
    let scil = data[cursor] as usize;
    cursor += 1;
    if cursor + scil > data.len() {
        return Err("truncated source connection id".to_string());
    }
    let scid = ConnectionId::new(data[cursor..cursor + scil].to_vec())
        .map_err(|e| format!("invalid source connection id: {}", e))?;
    cursor += scil;

    let mut token = Vec::new();
    let payload_length: u64;

    match packet_type {
        LongPacketType::Initial => {
            let mut token_cursor = cursor;
            let token_len = decode_varint(data, &mut token_cursor)? as usize;
            cursor = token_cursor;
            if cursor + token_len > data.len() {
                return Err("truncated initial token".to_string());
            }
            token = data[cursor..cursor + token_len].to_vec();
            cursor += token_len;
            payload_length = decode_varint(data, &mut cursor)?;
        }
        LongPacketType::ZeroRtt | LongPacketType::Handshake => {
            payload_length = decode_varint(data, &mut cursor)?;
        }
        LongPacketType::Retry => {
            let retry_token = data[cursor..].to_vec();
            let header = PacketHeader::Long(LongHeader {
                packet_type,
                version,
                destination_connection_id: dcid,
                source_connection_id: scid,
                token: retry_token,
                payload_length: 0,
            });
            return Ok(PacketDecodeInfo {
                header,
                packet_number_offset: cursor,
                packet_number_length: 0,
                payload_offset: data.len(),
            });
        }
    }

    if cursor + pn_len > data.len() {
        return Err("truncated packet number".to_string());
    }
    let pn_offset = cursor;
    cursor += pn_len;

    if cursor > data.len() {
        return Err("payload offset beyond packet length".to_string());
    }

    let header = PacketHeader::Long(LongHeader {
        packet_type,
        version,
        destination_connection_id: dcid,
        source_connection_id: scid,
        token,
        payload_length,
    });

    Ok(PacketDecodeInfo {
        header,
        packet_number_offset: pn_offset,
        packet_number_length: pn_len,
        payload_offset: cursor,
    })
}
