use std::collections::BTreeMap;

use crate::protocols::quic::packet::{decode_varint, encode_varint};

/// HTTP/3 frame types (RFC 9114 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    CancelPush = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Goaway = 0x7,
    MaxPushId = 0xd,
}

#[derive(Debug, Clone)]
pub struct DataFrame {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HeadersFrame {
    pub block_fragment: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SettingsFrame {
    pub parameters: BTreeMap<u64, u64>,
}

#[derive(Debug, Clone)]
pub struct GoawayFrame {
    pub id: u64,
}

#[derive(Debug, Clone)]
pub enum Http3Frame {
    Data(DataFrame),
    Headers(HeadersFrame),
    Settings(SettingsFrame),
    Goaway(GoawayFrame),
    Unknown(u64, Vec<u8>),
}

impl Http3Frame {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Http3Frame::Data(frame) => encode_payload_frame(buf, FrameType::Data as u64, &frame.payload),
            Http3Frame::Headers(frame) => encode_payload_frame(buf, FrameType::Headers as u64, &frame.block_fragment),
            Http3Frame::Settings(frame) => encode_payload_frame(buf, FrameType::Settings as u64, &encode_settings(frame)),
            Http3Frame::Goaway(frame) => {
                let mut payload = Vec::new();
                encode_varint(frame.id, &mut payload);
                encode_payload_frame(buf, FrameType::Goaway as u64, &payload);
            }
            Http3Frame::Unknown(t, payload) => encode_payload_frame(buf, *t, payload),
        }
    }

    pub fn decode(data: &[u8], cursor: &mut usize) -> Result<Self, String> {
        let frame_type = decode_varint(data, cursor)?;
        let length = decode_varint(data, cursor)? as usize;
        if *cursor + length > data.len() {
            return Err("HTTP/3 frame truncated".to_string());
        }
        let payload = &data[*cursor..*cursor + length];
        *cursor += length;

        match frame_type {
            0x0 => Ok(Http3Frame::Data(DataFrame {
                payload: payload.to_vec(),
            })),
            0x1 => Ok(Http3Frame::Headers(HeadersFrame {
                block_fragment: payload.to_vec(),
            })),
            0x4 => Ok(Http3Frame::Settings(SettingsFrame {
                parameters: decode_settings(payload)?,
            })),
            0x7 => {
                let mut offset = 0usize;
                let id = decode_varint(payload, &mut offset)?;
                Ok(Http3Frame::Goaway(GoawayFrame { id }))
            }
            other => Ok(Http3Frame::Unknown(other, payload.to_vec())),
        }
    }
}

fn encode_payload_frame(buf: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    encode_varint(frame_type, buf);
    encode_varint(payload.len() as u64, buf);
    buf.extend_from_slice(payload);
}

fn encode_settings(frame: &SettingsFrame) -> Vec<u8> {
    let mut payload = Vec::new();
    for (identifier, value) in &frame.parameters {
        encode_varint(*identifier, &mut payload);
        encode_varint(*value, &mut payload);
    }
    payload
}

fn decode_settings(payload: &[u8]) -> Result<BTreeMap<u64, u64>, String> {
    let mut cursor = 0usize;
    let mut map = BTreeMap::new();
    while cursor < payload.len() {
        let identifier = decode_varint(payload, &mut cursor)?;
        let value = decode_varint(payload, &mut cursor)?;
        map.insert(identifier, value);
    }
    Ok(map)
}
