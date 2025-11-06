use super::packet::{decode_varint, encode_varint};

/// RFC 9000 frame type registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    StreamBase = 0x08,
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreamsBidi = 0x12,
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlockedBidi = 0x16,
    StreamsBlockedUni = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionCloseTransport = 0x1c,
    ConnectionCloseApplication = 0x1d,
    HandshakeDone = 0x1e,
}

/// ACK range (gap,length) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    pub gap: u64,
    pub length: u64,
}

#[derive(Debug, Clone)]
pub struct AckFrame {
    pub largest_acknowledged: u64,
    pub ack_delay: u64,
    pub ranges: Vec<AckRange>,
}

#[derive(Debug, Clone)]
pub struct CryptoFrame {
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub stream_id: u64,
    pub offset: u64,
    pub data: Vec<u8>,
    pub fin: bool,
}

#[derive(Debug, Clone)]
pub struct PingFrame;

#[derive(Debug, Clone)]
pub struct MaxDataFrame {
    pub maximum_data: u64,
}

#[derive(Debug, Clone)]
pub struct MaxStreamDataFrame {
    pub stream_id: u64,
    pub maximum_data: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Debug, Clone)]
pub struct MaxStreamsFrame {
    pub stream_type: StreamType,
    pub maximum_streams: u64,
}

#[derive(Debug, Clone)]
pub struct DataBlockedFrame {
    pub maximum_data: u64,
}

#[derive(Debug, Clone)]
pub struct StreamDataBlockedFrame {
    pub stream_id: u64,
    pub maximum_stream_data: u64,
}

#[derive(Debug, Clone)]
pub struct ResetStreamFrame {
    pub stream_id: u64,
    pub application_error_code: u64,
    pub final_size: u64,
}

#[derive(Debug, Clone)]
pub struct StopSendingFrame {
    pub stream_id: u64,
    pub application_error_code: u64,
}

#[derive(Debug, Clone)]
pub struct ConnectionCloseFrame {
    pub is_application: bool,
    pub error_code: u64,
    pub frame_type: Option<u64>,
    pub reason: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PathChallengeFrame {
    pub data: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct PathResponseFrame {
    pub data: [u8; 8],
}

/// High-level frame enumeration.
#[derive(Debug, Clone)]
pub enum Frame {
    Padding,
    Ping(PingFrame),
    Ack(AckFrame),
    Crypto(CryptoFrame),
    Stream(StreamFrame),
    MaxData(MaxDataFrame),
    MaxStreamData(MaxStreamDataFrame),
    MaxStreams(MaxStreamsFrame),
    DataBlocked(DataBlockedFrame),
    StreamDataBlocked(StreamDataBlockedFrame),
    ResetStream(ResetStreamFrame),
    StopSending(StopSendingFrame),
    ConnectionClose(ConnectionCloseFrame),
    PathChallenge(PathChallengeFrame),
    PathResponse(PathResponseFrame),
    HandshakeDone,
}

impl Frame {
    pub fn frame_type(&self) -> FrameType {
        match self {
            Frame::Padding => FrameType::Padding,
            Frame::Ping(_) => FrameType::Ping,
            Frame::Ack(_) => FrameType::Ack,
            Frame::Crypto(_) => FrameType::Crypto,
            Frame::Stream(_) => FrameType::StreamBase,
            Frame::MaxData(_) => FrameType::MaxData,
            Frame::MaxStreamData(_) => FrameType::MaxStreamData,
            Frame::MaxStreams(frame) => match frame.stream_type {
                StreamType::Bidirectional => FrameType::MaxStreamsBidi,
                StreamType::Unidirectional => FrameType::MaxStreamsUni,
            },
            Frame::DataBlocked(_) => FrameType::DataBlocked,
            Frame::StreamDataBlocked(_) => FrameType::StreamDataBlocked,
            Frame::ResetStream(_) => FrameType::ResetStream,
            Frame::StopSending(_) => FrameType::StopSending,
            Frame::ConnectionClose(frame) => {
                if frame.is_application {
                    FrameType::ConnectionCloseApplication
                } else {
                    FrameType::ConnectionCloseTransport
                }
            }
            Frame::PathChallenge(_) => FrameType::PathChallenge,
            Frame::PathResponse(_) => FrameType::PathResponse,
            Frame::HandshakeDone => FrameType::HandshakeDone,
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Frame::Padding => buf.push(FrameType::Padding as u8),
            Frame::Ping(_) => buf.push(FrameType::Ping as u8),
            Frame::Ack(frame) => encode_ack_frame(buf, frame),
            Frame::Crypto(frame) => encode_crypto_frame(buf, frame),
            Frame::Stream(frame) => encode_stream_frame(buf, frame),
            Frame::MaxData(frame) => encode_max_data_frame(buf, frame),
            Frame::MaxStreamData(frame) => encode_max_stream_data_frame(buf, frame),
            Frame::MaxStreams(frame) => encode_max_streams_frame(buf, frame),
            Frame::DataBlocked(frame) => encode_data_blocked_frame(buf, frame),
            Frame::StreamDataBlocked(frame) => encode_stream_data_blocked_frame(buf, frame),
            Frame::ResetStream(frame) => encode_reset_stream_frame(buf, frame),
            Frame::StopSending(frame) => encode_stop_sending_frame(buf, frame),
            Frame::ConnectionClose(frame) => encode_connection_close_frame(buf, frame),
            Frame::PathChallenge(frame) => encode_path_challenge_frame(buf, frame),
            Frame::PathResponse(frame) => encode_path_response_frame(buf, frame),
            Frame::HandshakeDone => buf.push(FrameType::HandshakeDone as u8),
        }
    }

    pub fn decode(data: &[u8], cursor: &mut usize) -> Result<Self, String> {
        if *cursor >= data.len() {
            return Err("frame decode underflow".to_string());
        }

        let frame_type = data[*cursor];
        *cursor += 1;

        match frame_type {
            0x00 => Ok(Frame::Padding),
            0x01 => Ok(Frame::Ping(PingFrame)),
            0x02 | 0x03 => decode_ack_frame(data, cursor, frame_type == 0x03).map(Frame::Ack),
            0x04 => decode_reset_stream_frame(data, cursor).map(Frame::ResetStream),
            0x05 => decode_stop_sending_frame(data, cursor).map(Frame::StopSending),
            0x06 => decode_crypto_frame(data, cursor).map(Frame::Crypto),
            0x07 => Err("NEW_TOKEN frame decoding not yet implemented".to_string()),
            0x08..=0x0f => decode_stream_frame(frame_type, data, cursor).map(Frame::Stream),
            0x10 => decode_max_data_frame(data, cursor).map(Frame::MaxData),
            0x11 => decode_max_stream_data_frame(data, cursor).map(Frame::MaxStreamData),
            0x12 => decode_max_streams_frame(StreamType::Bidirectional, data, cursor)
                .map(Frame::MaxStreams),
            0x13 => decode_max_streams_frame(StreamType::Unidirectional, data, cursor)
                .map(Frame::MaxStreams),
            0x14 => decode_data_blocked_frame(data, cursor).map(Frame::DataBlocked),
            0x15 => decode_stream_data_blocked_frame(data, cursor).map(Frame::StreamDataBlocked),
            0x1a => decode_path_challenge_frame(data, cursor).map(Frame::PathChallenge),
            0x1b => decode_path_response_frame(data, cursor).map(Frame::PathResponse),
            0x1c => decode_connection_close_frame(false, data, cursor).map(Frame::ConnectionClose),
            0x1d => decode_connection_close_frame(true, data, cursor).map(Frame::ConnectionClose),
            0x1e => Ok(Frame::HandshakeDone),
            _ => Err(format!("unsupported frame type 0x{:02x}", frame_type)),
        }
    }
}

fn encode_ack_frame(buf: &mut Vec<u8>, frame: &AckFrame) {
    buf.push(FrameType::Ack as u8);
    encode_varint(frame.largest_acknowledged, buf);
    encode_varint(frame.ack_delay, buf);
    encode_varint(frame.ranges.len().saturating_sub(1) as u64, buf);
    let first_range = frame.ranges.first().map(|r| r.length).unwrap_or(0);
    encode_varint(first_range, buf);

    for range in frame.ranges.iter().skip(1) {
        encode_varint(range.gap, buf);
        encode_varint(range.length, buf);
    }
}

fn decode_ack_frame(
    data: &[u8],
    cursor: &mut usize,
    _ecn: bool,
) -> Result<AckFrame, String> {
    let largest_acknowledged = decode_varint(data, cursor)?;
    let ack_delay = decode_varint(data, cursor)?;
    let range_count = decode_varint(data, cursor)? + 1;
    let first_range_length = decode_varint(data, cursor)?;

    let mut ranges = Vec::with_capacity(range_count as usize);
    ranges.push(AckRange {
        gap: 0,
        length: first_range_length,
    });

    for _ in 1..range_count {
        let gap = decode_varint(data, cursor)?;
        let length = decode_varint(data, cursor)?;
        ranges.push(AckRange { gap, length });
    }

    Ok(AckFrame {
        largest_acknowledged,
        ack_delay,
        ranges,
    })
}

fn encode_crypto_frame(buf: &mut Vec<u8>, frame: &CryptoFrame) {
    buf.push(FrameType::Crypto as u8);
    encode_varint(frame.offset, buf);
    encode_varint(frame.data.len() as u64, buf);
    buf.extend_from_slice(&frame.data);
}

fn decode_crypto_frame(data: &[u8], cursor: &mut usize) -> Result<CryptoFrame, String> {
    let offset = decode_varint(data, cursor)?;
    let length = decode_varint(data, cursor)? as usize;
    if *cursor + length > data.len() {
        return Err("CRYPTO frame truncated".to_string());
    }
    let payload = data[*cursor..*cursor + length].to_vec();
    *cursor += length;

    Ok(CryptoFrame {
        offset,
        data: payload,
    })
}

fn encode_stream_frame(buf: &mut Vec<u8>, frame: &StreamFrame) {
    let has_offset = frame.offset != 0;
    let has_length = true;

    let mut type_byte = FrameType::StreamBase as u8;
    if has_offset {
        type_byte |= 0x04;
    }
    if has_length {
        type_byte |= 0x02;
    }
    if frame.fin {
        type_byte |= 0x01;
    }
    buf.push(type_byte);

    encode_varint(frame.stream_id, buf);
    if has_offset {
        encode_varint(frame.offset, buf);
    }
    encode_varint(frame.data.len() as u64, buf);
    buf.extend_from_slice(&frame.data);
}

fn decode_stream_frame(
    type_byte: u8,
    data: &[u8],
    cursor: &mut usize,
) -> Result<StreamFrame, String> {
    let fin = (type_byte & 0x01) != 0;
    let has_length = (type_byte & 0x02) != 0;
    let has_offset = (type_byte & 0x04) != 0;

    let stream_id = decode_varint(data, cursor)?;
    let offset = if has_offset {
        decode_varint(data, cursor)?
    } else {
        0
    };

    let length = if has_length {
        decode_varint(data, cursor)? as usize
    } else {
        data.len().saturating_sub(*cursor)
    };

    if *cursor + length > data.len() {
        return Err("STREAM frame truncated".to_string());
    }
    let payload = data[*cursor..*cursor + length].to_vec();
    *cursor += length;

    Ok(StreamFrame {
        stream_id,
        offset,
        data: payload,
        fin,
    })
}

fn encode_max_data_frame(buf: &mut Vec<u8>, frame: &MaxDataFrame) {
    buf.push(FrameType::MaxData as u8);
    encode_varint(frame.maximum_data, buf);
}

fn decode_max_data_frame(data: &[u8], cursor: &mut usize) -> Result<MaxDataFrame, String> {
    let max = decode_varint(data, cursor)?;
    Ok(MaxDataFrame { maximum_data: max })
}

fn encode_max_stream_data_frame(buf: &mut Vec<u8>, frame: &MaxStreamDataFrame) {
    buf.push(FrameType::MaxStreamData as u8);
    encode_varint(frame.stream_id, buf);
    encode_varint(frame.maximum_data, buf);
}

fn decode_max_stream_data_frame(
    data: &[u8],
    cursor: &mut usize,
) -> Result<MaxStreamDataFrame, String> {
    let stream_id = decode_varint(data, cursor)?;
    let maximum = decode_varint(data, cursor)?;
    Ok(MaxStreamDataFrame {
        stream_id,
        maximum_data: maximum,
    })
}

fn encode_max_streams_frame(buf: &mut Vec<u8>, frame: &MaxStreamsFrame) {
    match frame.stream_type {
        StreamType::Bidirectional => buf.push(FrameType::MaxStreamsBidi as u8),
        StreamType::Unidirectional => buf.push(FrameType::MaxStreamsUni as u8),
    }
    encode_varint(frame.maximum_streams, buf);
}

fn decode_max_streams_frame(
    stream_type: StreamType,
    data: &[u8],
    cursor: &mut usize,
) -> Result<MaxStreamsFrame, String> {
    let maximum = decode_varint(data, cursor)?;
    Ok(MaxStreamsFrame {
        stream_type,
        maximum_streams: maximum,
    })
}

fn encode_data_blocked_frame(buf: &mut Vec<u8>, frame: &DataBlockedFrame) {
    buf.push(FrameType::DataBlocked as u8);
    encode_varint(frame.maximum_data, buf);
}

fn decode_data_blocked_frame(
    data: &[u8],
    cursor: &mut usize,
) -> Result<DataBlockedFrame, String> {
    let maximum_data = decode_varint(data, cursor)?;
    Ok(DataBlockedFrame { maximum_data })
}

fn encode_stream_data_blocked_frame(buf: &mut Vec<u8>, frame: &StreamDataBlockedFrame) {
    buf.push(FrameType::StreamDataBlocked as u8);
    encode_varint(frame.stream_id, buf);
    encode_varint(frame.maximum_stream_data, buf);
}

fn decode_stream_data_blocked_frame(
    data: &[u8],
    cursor: &mut usize,
) -> Result<StreamDataBlockedFrame, String> {
    let stream_id = decode_varint(data, cursor)?;
    let maximum = decode_varint(data, cursor)?;
    Ok(StreamDataBlockedFrame {
        stream_id,
        maximum_stream_data: maximum,
    })
}

fn encode_reset_stream_frame(buf: &mut Vec<u8>, frame: &ResetStreamFrame) {
    buf.push(FrameType::ResetStream as u8);
    encode_varint(frame.stream_id, buf);
    encode_varint(frame.application_error_code, buf);
    encode_varint(frame.final_size, buf);
}

fn decode_reset_stream_frame(
    data: &[u8],
    cursor: &mut usize,
) -> Result<ResetStreamFrame, String> {
    let stream_id = decode_varint(data, cursor)?;
    let error_code = decode_varint(data, cursor)?;
    let final_size = decode_varint(data, cursor)?;
    Ok(ResetStreamFrame {
        stream_id,
        application_error_code: error_code,
        final_size,
    })
}

fn encode_stop_sending_frame(buf: &mut Vec<u8>, frame: &StopSendingFrame) {
    buf.push(FrameType::StopSending as u8);
    encode_varint(frame.stream_id, buf);
    encode_varint(frame.application_error_code, buf);
}

fn decode_stop_sending_frame(
    data: &[u8],
    cursor: &mut usize,
) -> Result<StopSendingFrame, String> {
    let stream_id = decode_varint(data, cursor)?;
    let error_code = decode_varint(data, cursor)?;
    Ok(StopSendingFrame {
        stream_id,
        application_error_code: error_code,
    })
}

fn encode_connection_close_frame(buf: &mut Vec<u8>, frame: &ConnectionCloseFrame) {
    if frame.is_application {
        buf.push(FrameType::ConnectionCloseApplication as u8);
        encode_varint(frame.error_code, buf);
        encode_varint(frame.reason.len() as u64, buf);
    } else {
        buf.push(FrameType::ConnectionCloseTransport as u8);
        encode_varint(frame.error_code, buf);
        encode_varint(frame.frame_type.unwrap_or(0), buf);
        encode_varint(frame.reason.len() as u64, buf);
    }
    buf.extend_from_slice(&frame.reason);
}

fn decode_connection_close_frame(
    is_application: bool,
    data: &[u8],
    cursor: &mut usize,
) -> Result<ConnectionCloseFrame, String> {
    let error_code = decode_varint(data, cursor)?;
    let frame_type = if is_application {
        None
    } else {
        Some(decode_varint(data, cursor)?)
    };
    let reason_len = decode_varint(data, cursor)? as usize;
    if *cursor + reason_len > data.len() {
        return Err("CONNECTION_CLOSE reason truncated".to_string());
    }
    let reason = data[*cursor..*cursor + reason_len].to_vec();
    *cursor += reason_len;

    Ok(ConnectionCloseFrame {
        is_application,
        error_code,
        frame_type,
        reason,
    })
}

fn encode_path_challenge_frame(buf: &mut Vec<u8>, frame: &PathChallengeFrame) {
    buf.push(FrameType::PathChallenge as u8);
    buf.extend_from_slice(&frame.data);
}

fn decode_path_challenge_frame(
    data: &[u8],
    cursor: &mut usize,
) -> Result<PathChallengeFrame, String> {
    if *cursor + 8 > data.len() {
        return Err("PATH_CHALLENGE truncated".to_string());
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(PathChallengeFrame { data: bytes })
}

fn encode_path_response_frame(buf: &mut Vec<u8>, frame: &PathResponseFrame) {
    buf.push(FrameType::PathResponse as u8);
    buf.extend_from_slice(&frame.data);
}

fn decode_path_response_frame(
    data: &[u8],
    cursor: &mut usize,
) -> Result<PathResponseFrame, String> {
    if *cursor + 8 > data.len() {
        return Err("PATH_RESPONSE truncated".to_string());
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(PathResponseFrame { data: bytes })
}
