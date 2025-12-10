//! HTTP/2 Binary Framing (RFC 7540 Section 4)
//!
//! Frame structure:
//! +-----------------------------------------------+
//! |                 Length (24)                   |
//! +---------------+---------------+---------------+
//! |   Type (8)    |   Flags (8)   |
//! +-+-------------+---------------+-------------------------------+
//! |R|                 Stream Identifier (31)                      |
//! +=+=============================================================+
//! |                   Frame Payload (0...)                      ...
//! +---------------------------------------------------------------+

use std::io::{Read, Write};

/// Frame types (RFC 7540 Section 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    Goaway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

impl FrameType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(FrameType::Data),
            0x1 => Some(FrameType::Headers),
            0x2 => Some(FrameType::Priority),
            0x3 => Some(FrameType::RstStream),
            0x4 => Some(FrameType::Settings),
            0x5 => Some(FrameType::PushPromise),
            0x6 => Some(FrameType::Ping),
            0x7 => Some(FrameType::Goaway),
            0x8 => Some(FrameType::WindowUpdate),
            0x9 => Some(FrameType::Continuation),
            _ => None,
        }
    }
}

/// Frame flags
pub mod flags {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// HTTP/2 Frame
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame
    pub fn new(frame_type: FrameType, flags: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        Frame {
            frame_type,
            flags,
            stream_id,
            payload,
        }
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> Vec<u8> {
        let length = self.payload.len();
        let mut bytes = Vec::with_capacity(9 + length);

        // Length (24 bits, big-endian)
        bytes.push((length >> 16) as u8);
        bytes.push((length >> 8) as u8);
        bytes.push(length as u8);

        // Type (8 bits)
        bytes.push(self.frame_type as u8);

        // Flags (8 bits)
        bytes.push(self.flags);

        // Stream ID (31 bits, big-endian, R bit = 0)
        bytes.push(((self.stream_id >> 24) & 0x7F) as u8); // Mask R bit
        bytes.push((self.stream_id >> 16) as u8);
        bytes.push((self.stream_id >> 8) as u8);
        bytes.push(self.stream_id as u8);

        // Payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    /// Decode frame from stream
    pub fn decode<R: Read>(reader: &mut R) -> Result<Frame, String> {
        // Read 9-byte header
        let mut header = [0u8; 9];
        reader
            .read_exact(&mut header)
            .map_err(|e| format!("Failed to read frame header: {}", e))?;

        // Parse length (24 bits)
        let length = ((header[0] as u32) << 16) | ((header[1] as u32) << 8) | (header[2] as u32);

        // Parse type
        let frame_type = FrameType::from_u8(header[3])
            .ok_or_else(|| format!("Unknown frame type: 0x{:02x}", header[3]))?;

        // Parse flags
        let flags = header[4];

        // Parse stream ID (31 bits, ignore R bit)
        let stream_id = ((header[5] as u32 & 0x7F) << 24)
            | ((header[6] as u32) << 16)
            | ((header[7] as u32) << 8)
            | (header[8] as u32);

        // Read payload
        let mut payload = vec![0u8; length as usize];
        if length > 0 {
            reader
                .read_exact(&mut payload)
                .map_err(|e| format!("Failed to read frame payload: {}", e))?;
        }

        Ok(Frame {
            frame_type,
            flags,
            stream_id,
            payload,
        })
    }

    /// Write frame to stream
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), String> {
        let bytes = self.encode();
        writer
            .write_all(&bytes)
            .map_err(|e| format!("Failed to write frame: {}", e))?;
        Ok(())
    }

    /// Create SETTINGS frame
    pub fn settings(ack: bool, params: Vec<(u16, u32)>) -> Frame {
        let mut payload = Vec::new();

        if !ack {
            for (id, value) in params {
                // Each setting is 6 bytes: 2-byte ID + 4-byte value
                payload.push((id >> 8) as u8);
                payload.push(id as u8);
                payload.push((value >> 24) as u8);
                payload.push((value >> 16) as u8);
                payload.push((value >> 8) as u8);
                payload.push(value as u8);
            }
        }

        Frame::new(
            FrameType::Settings,
            if ack { flags::ACK } else { 0 },
            0, // Stream 0
            payload,
        )
    }

    /// Create WINDOW_UPDATE frame
    pub fn window_update(stream_id: u32, increment: u32) -> Frame {
        let mut payload = vec![0u8; 4];
        payload[0] = ((increment >> 24) & 0x7F) as u8; // Mask R bit
        payload[1] = (increment >> 16) as u8;
        payload[2] = (increment >> 8) as u8;
        payload[3] = increment as u8;

        Frame::new(FrameType::WindowUpdate, 0, stream_id, payload)
    }

    /// Create HEADERS frame
    pub fn headers(
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        header_block: Vec<u8>,
    ) -> Frame {
        let mut flags = 0;
        if end_stream {
            flags |= flags::END_STREAM;
        }
        if end_headers {
            flags |= flags::END_HEADERS;
        }

        Frame::new(FrameType::Headers, flags, stream_id, header_block)
    }

    /// Create DATA frame
    pub fn data(stream_id: u32, end_stream: bool, data: Vec<u8>) -> Frame {
        let flags = if end_stream { flags::END_STREAM } else { 0 };
        Frame::new(FrameType::Data, flags, stream_id, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let payload = vec![1, 2, 3, 4, 5];
        let frame = Frame::new(FrameType::Data, flags::END_STREAM, 1, payload.clone());

        let encoded = frame.encode();
        assert_eq!(encoded.len(), 9 + 5); // Header + payload

        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = Frame::decode(&mut cursor).unwrap();

        assert_eq!(decoded.frame_type as u8, FrameType::Data as u8);
        assert_eq!(decoded.flags, flags::END_STREAM);
        assert_eq!(decoded.stream_id, 1);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_settings_frame() {
        let params = vec![(0x3, 100), (0x4, 65535)];
        let frame = Frame::settings(false, params);

        assert_eq!(frame.frame_type as u8, FrameType::Settings as u8);
        assert_eq!(frame.stream_id, 0);
        assert_eq!(frame.payload.len(), 12); // 2 settings * 6 bytes
    }

    #[test]
    fn test_settings_ack() {
        let frame = Frame::settings(true, vec![]);
        assert_eq!(frame.flags, flags::ACK);
        assert_eq!(frame.payload.len(), 0);
    }
}
