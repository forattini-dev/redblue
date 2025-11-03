/// HTTP/2 Frame Layer Implementation (RFC 7540)
/// Pure Rust std implementation - ZERO external dependencies
// Frame types (RFC 7540 Section 6)
pub const FRAME_TYPE_DATA: u8 = 0x0;
pub const FRAME_TYPE_HEADERS: u8 = 0x1;
pub const FRAME_TYPE_PRIORITY: u8 = 0x2;
pub const FRAME_TYPE_RST_STREAM: u8 = 0x3;
pub const FRAME_TYPE_SETTINGS: u8 = 0x4;
pub const FRAME_TYPE_PUSH_PROMISE: u8 = 0x5;
pub const FRAME_TYPE_PING: u8 = 0x6;
pub const FRAME_TYPE_GOAWAY: u8 = 0x7;
pub const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;
pub const FRAME_TYPE_CONTINUATION: u8 = 0x9;

// Frame flags
pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_END_HEADERS: u8 = 0x4;
pub const FLAG_PADDED: u8 = 0x8;
pub const FLAG_PRIORITY: u8 = 0x20;
pub const FLAG_ACK: u8 = 0x1;

// Settings identifiers (RFC 7540 Section 6.5.2)
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

// Error codes (RFC 7540 Section 7)
pub const ERROR_NO_ERROR: u32 = 0x0;
pub const ERROR_PROTOCOL_ERROR: u32 = 0x1;
pub const ERROR_INTERNAL_ERROR: u32 = 0x2;
pub const ERROR_FLOW_CONTROL_ERROR: u32 = 0x3;
pub const ERROR_SETTINGS_TIMEOUT: u32 = 0x4;
pub const ERROR_STREAM_CLOSED: u32 = 0x5;
pub const ERROR_FRAME_SIZE_ERROR: u32 = 0x6;
pub const ERROR_REFUSED_STREAM: u32 = 0x7;
pub const ERROR_CANCEL: u32 = 0x8;
pub const ERROR_COMPRESSION_ERROR: u32 = 0x9;
pub const ERROR_CONNECT_ERROR: u32 = 0xa;
pub const ERROR_ENHANCE_YOUR_CALM: u32 = 0xb;
pub const ERROR_INADEQUATE_SECURITY: u32 = 0xc;
pub const ERROR_HTTP_1_1_REQUIRED: u32 = 0xd;

/// HTTP/2 frame header (9 bytes)
/// +-----------------------------------------------+
/// |                 Length (24)                   |
/// +---------------+---------------+---------------+
/// |   Type (8)    |   Flags (8)   |
/// +-+-------------+---------------+-------------------------------+
/// |R|                 Stream Identifier (31)                      |
/// +=+=============================================================+
/// |                   Frame Payload (0...)                      ...
/// +---------------------------------------------------------------+
#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub length: u32,    // 24-bit length (max 16,777,215 bytes)
    pub frame_type: u8, // 8-bit type
    pub flags: u8,      // 8-bit flags
    pub stream_id: u32, // 31-bit stream ID (R bit reserved)
}

impl FrameHeader {
    pub const SIZE: usize = 9;

    pub fn new(frame_type: u8, flags: u8, stream_id: u32) -> Self {
        Self {
            length: 0,
            frame_type,
            flags,
            stream_id: stream_id & 0x7FFF_FFFF, // Clear reserved bit
        }
    }

    /// Parse frame header from 9 bytes
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::SIZE {
            return Err(format!(
                "Frame header too short: {} bytes (need 9)",
                bytes.len()
            ));
        }

        // Length: 24 bits (3 bytes)
        let length = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);

        // Type: 8 bits
        let frame_type = bytes[3];

        // Flags: 8 bits
        let flags = bytes[4];

        // Stream ID: 31 bits (4 bytes with R bit)
        let stream_id = ((bytes[5] as u32) << 24)
            | ((bytes[6] as u32) << 16)
            | ((bytes[7] as u32) << 8)
            | (bytes[8] as u32);
        let stream_id = stream_id & 0x7FFF_FFFF; // Clear reserved bit

        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    /// Serialize frame header to 9 bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];

        // Length (24 bits)
        bytes[0] = ((self.length >> 16) & 0xFF) as u8;
        bytes[1] = ((self.length >> 8) & 0xFF) as u8;
        bytes[2] = (self.length & 0xFF) as u8;

        // Type
        bytes[3] = self.frame_type;

        // Flags
        bytes[4] = self.flags;

        // Stream ID (31 bits, R bit always 0)
        let stream_id = self.stream_id & 0x7FFF_FFFF;
        bytes[5] = ((stream_id >> 24) & 0xFF) as u8;
        bytes[6] = ((stream_id >> 16) & 0xFF) as u8;
        bytes[7] = ((stream_id >> 8) & 0xFF) as u8;
        bytes[8] = (stream_id & 0xFF) as u8;

        bytes
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }
}

/// HTTP/2 Frame
#[derive(Debug, Clone)]
pub enum Frame {
    Data(DataFrame),
    Headers(HeadersFrame),
    Priority(PriorityFrame),
    RstStream(RstStreamFrame),
    Settings(SettingsFrame),
    PushPromise(PushPromiseFrame),
    Ping(PingFrame),
    GoAway(GoAwayFrame),
    WindowUpdate(WindowUpdateFrame),
    Continuation(ContinuationFrame),
    Unknown(UnknownFrame),
}

impl Frame {
    /// Parse a complete frame (header + payload)
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        match header.frame_type {
            FRAME_TYPE_DATA => Ok(Frame::Data(DataFrame::parse(header, payload)?)),
            FRAME_TYPE_HEADERS => Ok(Frame::Headers(HeadersFrame::parse(header, payload)?)),
            FRAME_TYPE_PRIORITY => Ok(Frame::Priority(PriorityFrame::parse(header, payload)?)),
            FRAME_TYPE_RST_STREAM => Ok(Frame::RstStream(RstStreamFrame::parse(header, payload)?)),
            FRAME_TYPE_SETTINGS => Ok(Frame::Settings(SettingsFrame::parse(header, payload)?)),
            FRAME_TYPE_PUSH_PROMISE => Ok(Frame::PushPromise(PushPromiseFrame::parse(
                header, payload,
            )?)),
            FRAME_TYPE_PING => Ok(Frame::Ping(PingFrame::parse(header, payload)?)),
            FRAME_TYPE_GOAWAY => Ok(Frame::GoAway(GoAwayFrame::parse(header, payload)?)),
            FRAME_TYPE_WINDOW_UPDATE => Ok(Frame::WindowUpdate(WindowUpdateFrame::parse(
                header, payload,
            )?)),
            FRAME_TYPE_CONTINUATION => Ok(Frame::Continuation(ContinuationFrame::parse(
                header, payload,
            )?)),
            _ => Ok(Frame::Unknown(UnknownFrame {
                header,
                payload: payload.to_vec(),
            })),
        }
    }

    pub fn header(&self) -> &FrameHeader {
        match self {
            Frame::Data(f) => &f.header,
            Frame::Headers(f) => &f.header,
            Frame::Priority(f) => &f.header,
            Frame::RstStream(f) => &f.header,
            Frame::Settings(f) => &f.header,
            Frame::PushPromise(f) => &f.header,
            Frame::Ping(f) => &f.header,
            Frame::GoAway(f) => &f.header,
            Frame::WindowUpdate(f) => &f.header,
            Frame::Continuation(f) => &f.header,
            Frame::Unknown(f) => &f.header,
        }
    }
}

/// DATA frame (RFC 7540 Section 6.1)
#[derive(Debug, Clone)]
pub struct DataFrame {
    pub header: FrameHeader,
    pub data: Vec<u8>,
    pub pad_length: Option<u8>,
}

impl DataFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        let mut offset = 0;
        let pad_length = if header.has_flag(FLAG_PADDED) {
            if payload.is_empty() {
                return Err("PADDED flag set but no pad length byte".to_string());
            }
            offset += 1;
            Some(payload[0])
        } else {
            None
        };

        let data = payload[offset..].to_vec();

        Ok(Self {
            header,
            data,
            pad_length,
        })
    }
}

/// HEADERS frame (RFC 7540 Section 6.2)
#[derive(Debug, Clone)]
pub struct HeadersFrame {
    pub header: FrameHeader,
    pub header_block_fragment: Vec<u8>,
    pub pad_length: Option<u8>,
    pub priority: Option<PrioritySpec>,
}

#[derive(Debug, Clone)]
pub struct PrioritySpec {
    pub exclusive: bool,
    pub stream_dependency: u32,
    pub weight: u8,
}

impl HeadersFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        let mut offset = 0;

        let pad_length = if header.has_flag(FLAG_PADDED) {
            if payload.is_empty() {
                return Err("PADDED flag set but no pad length byte".to_string());
            }
            offset += 1;
            Some(payload[0])
        } else {
            None
        };

        let priority = if header.has_flag(FLAG_PRIORITY) {
            if payload.len() < offset + 5 {
                return Err("PRIORITY flag set but insufficient data".to_string());
            }
            let dep_bytes = &payload[offset..offset + 4];
            let stream_dependency = ((dep_bytes[0] as u32) << 24)
                | ((dep_bytes[1] as u32) << 16)
                | ((dep_bytes[2] as u32) << 8)
                | (dep_bytes[3] as u32);
            let exclusive = (stream_dependency & 0x8000_0000) != 0;
            let stream_dependency = stream_dependency & 0x7FFF_FFFF;
            let weight = payload[offset + 4];
            offset += 5;
            Some(PrioritySpec {
                exclusive,
                stream_dependency,
                weight,
            })
        } else {
            None
        };

        let header_block_fragment = payload[offset..].to_vec();

        Ok(Self {
            header,
            header_block_fragment,
            pad_length,
            priority,
        })
    }
}

/// PRIORITY frame (RFC 7540 Section 6.3)
#[derive(Debug, Clone)]
pub struct PriorityFrame {
    pub header: FrameHeader,
    pub priority: PrioritySpec,
}

impl PriorityFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        if payload.len() != 5 {
            return Err(format!(
                "PRIORITY frame must be 5 bytes, got {}",
                payload.len()
            ));
        }

        let stream_dependency = ((payload[0] as u32) << 24)
            | ((payload[1] as u32) << 16)
            | ((payload[2] as u32) << 8)
            | (payload[3] as u32);
        let exclusive = (stream_dependency & 0x8000_0000) != 0;
        let stream_dependency = stream_dependency & 0x7FFF_FFFF;
        let weight = payload[4];

        Ok(Self {
            header,
            priority: PrioritySpec {
                exclusive,
                stream_dependency,
                weight,
            },
        })
    }
}

/// RST_STREAM frame (RFC 7540 Section 6.4)
#[derive(Debug, Clone)]
pub struct RstStreamFrame {
    pub header: FrameHeader,
    pub error_code: u32,
}

impl RstStreamFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        if payload.len() != 4 {
            return Err(format!(
                "RST_STREAM frame must be 4 bytes, got {}",
                payload.len()
            ));
        }

        let error_code = ((payload[0] as u32) << 24)
            | ((payload[1] as u32) << 16)
            | ((payload[2] as u32) << 8)
            | (payload[3] as u32);

        Ok(Self { header, error_code })
    }
}

/// SETTINGS frame (RFC 7540 Section 6.5)
#[derive(Debug, Clone)]
pub struct SettingsFrame {
    pub header: FrameHeader,
    pub settings: Vec<Setting>,
}

#[derive(Debug, Clone)]
pub struct Setting {
    pub identifier: u16,
    pub value: u32,
}

impl SettingsFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        if payload.len() % 6 != 0 {
            return Err(format!(
                "SETTINGS frame payload must be multiple of 6 bytes, got {}",
                payload.len()
            ));
        }

        let mut settings = Vec::new();
        for chunk in payload.chunks(6) {
            let identifier = ((chunk[0] as u16) << 8) | (chunk[1] as u16);
            let value = ((chunk[2] as u32) << 24)
                | ((chunk[3] as u32) << 16)
                | ((chunk[4] as u32) << 8)
                | (chunk[5] as u32);
            settings.push(Setting { identifier, value });
        }

        Ok(Self { header, settings })
    }

    pub fn new_ack() -> Self {
        Self {
            header: FrameHeader {
                length: 0,
                frame_type: FRAME_TYPE_SETTINGS,
                flags: FLAG_ACK,
                stream_id: 0,
            },
            settings: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Header
        bytes.extend_from_slice(&self.header.to_bytes());

        // Payload
        for setting in &self.settings {
            bytes.push((setting.identifier >> 8) as u8);
            bytes.push((setting.identifier & 0xFF) as u8);
            bytes.push((setting.value >> 24) as u8);
            bytes.push((setting.value >> 16) as u8);
            bytes.push((setting.value >> 8) as u8);
            bytes.push((setting.value & 0xFF) as u8);
        }

        bytes
    }
}

/// PUSH_PROMISE frame (RFC 7540 Section 6.6)
#[derive(Debug, Clone)]
pub struct PushPromiseFrame {
    pub header: FrameHeader,
    pub promised_stream_id: u32,
    pub header_block_fragment: Vec<u8>,
}

impl PushPromiseFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        if payload.len() < 4 {
            return Err("PUSH_PROMISE frame too short".to_string());
        }

        let promised_stream_id = ((payload[0] as u32) << 24)
            | ((payload[1] as u32) << 16)
            | ((payload[2] as u32) << 8)
            | (payload[3] as u32);
        let promised_stream_id = promised_stream_id & 0x7FFF_FFFF;

        let header_block_fragment = payload[4..].to_vec();

        Ok(Self {
            header,
            promised_stream_id,
            header_block_fragment,
        })
    }
}

/// PING frame (RFC 7540 Section 6.7)
#[derive(Debug, Clone)]
pub struct PingFrame {
    pub header: FrameHeader,
    pub opaque_data: [u8; 8],
}

impl PingFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        if payload.len() != 8 {
            return Err(format!("PING frame must be 8 bytes, got {}", payload.len()));
        }

        let mut opaque_data = [0u8; 8];
        opaque_data.copy_from_slice(payload);

        Ok(Self {
            header,
            opaque_data,
        })
    }
}

/// GOAWAY frame (RFC 7540 Section 6.8)
#[derive(Debug, Clone)]
pub struct GoAwayFrame {
    pub header: FrameHeader,
    pub last_stream_id: u32,
    pub error_code: u32,
    pub additional_debug_data: Vec<u8>,
}

impl GoAwayFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        if payload.len() < 8 {
            return Err("GOAWAY frame too short".to_string());
        }

        let last_stream_id = ((payload[0] as u32) << 24)
            | ((payload[1] as u32) << 16)
            | ((payload[2] as u32) << 8)
            | (payload[3] as u32);
        let last_stream_id = last_stream_id & 0x7FFF_FFFF;

        let error_code = ((payload[4] as u32) << 24)
            | ((payload[5] as u32) << 16)
            | ((payload[6] as u32) << 8)
            | (payload[7] as u32);

        let additional_debug_data = payload[8..].to_vec();

        Ok(Self {
            header,
            last_stream_id,
            error_code,
            additional_debug_data,
        })
    }
}

/// WINDOW_UPDATE frame (RFC 7540 Section 6.9)
#[derive(Debug, Clone)]
pub struct WindowUpdateFrame {
    pub header: FrameHeader,
    pub window_size_increment: u32,
}

impl WindowUpdateFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        if payload.len() != 4 {
            return Err(format!(
                "WINDOW_UPDATE frame must be 4 bytes, got {}",
                payload.len()
            ));
        }

        let window_size_increment = ((payload[0] as u32) << 24)
            | ((payload[1] as u32) << 16)
            | ((payload[2] as u32) << 8)
            | (payload[3] as u32);
        let window_size_increment = window_size_increment & 0x7FFF_FFFF;

        Ok(Self {
            header,
            window_size_increment,
        })
    }
}

/// CONTINUATION frame (RFC 7540 Section 6.10)
#[derive(Debug, Clone)]
pub struct ContinuationFrame {
    pub header: FrameHeader,
    pub header_block_fragment: Vec<u8>,
}

impl ContinuationFrame {
    pub fn parse(header: FrameHeader, payload: &[u8]) -> Result<Self, String> {
        Ok(Self {
            header,
            header_block_fragment: payload.to_vec(),
        })
    }
}

/// Unknown frame type
#[derive(Debug, Clone)]
pub struct UnknownFrame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_parse() {
        let bytes = [
            0x00, 0x00, 0x0C, // Length: 12
            0x04, // Type: SETTINGS
            0x00, // Flags: none
            0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        ];

        let header = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(header.length, 12);
        assert_eq!(header.frame_type, FRAME_TYPE_SETTINGS);
        assert_eq!(header.flags, 0);
        assert_eq!(header.stream_id, 0);
    }

    #[test]
    fn test_frame_header_serialize() {
        let header = FrameHeader {
            length: 12,
            frame_type: FRAME_TYPE_SETTINGS,
            flags: 0,
            stream_id: 0,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0x0C);
        assert_eq!(bytes[3], FRAME_TYPE_SETTINGS);
        assert_eq!(bytes[4], 0);
        assert_eq!(bytes[5], 0);
        assert_eq!(bytes[6], 0);
        assert_eq!(bytes[7], 0);
        assert_eq!(bytes[8], 0);
    }

    #[test]
    fn test_settings_frame_parse() {
        let header = FrameHeader {
            length: 6,
            frame_type: FRAME_TYPE_SETTINGS,
            flags: 0,
            stream_id: 0,
        };

        let payload = vec![
            0x00, 0x03, // SETTINGS_MAX_CONCURRENT_STREAMS
            0x00, 0x00, 0x00, 0x64, // Value: 100
        ];

        let frame = SettingsFrame::parse(header, &payload).unwrap();
        assert_eq!(frame.settings.len(), 1);
        assert_eq!(
            frame.settings[0].identifier,
            SETTINGS_MAX_CONCURRENT_STREAMS
        );
        assert_eq!(frame.settings[0].value, 100);
    }
}
