/// HTTP/3 protocol layer built on top of the QUIC transport.
pub mod frame;
pub mod qpack;

use std::collections::{BTreeMap, VecDeque};

use frame::{DataFrame, HeadersFrame, Http3Frame, SettingsFrame};
use qpack::{QpackDecoder, QpackEncoder};

use crate::protocols::quic::{QuicConfig, QuicConnection};
use crate::protocols::quic::connection::StreamEvent;
use crate::protocols::quic::packet::{decode_varint, encode_varint};
use crate::protocols::quic::stream::StreamId;

/// HTTP/3 SETTINGS parameters (RFC 9114 §7.2.4).
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;

#[derive(Debug, Clone)]
pub struct Http3Settings {
    pub initial_table_capacity: u64,
    pub max_blocked_streams: u64,
    pub max_field_section_size: Option<u64>,
}

impl Default for Http3Settings {
    fn default() -> Self {
        Self {
            initial_table_capacity: 0,
            max_blocked_streams: 0,
            max_field_section_size: None,
        }
    }
}

pub struct Http3Client {
    quic: QuicConnection,
    encoder: QpackEncoder,
    decoder: QpackDecoder,
    settings: Http3Settings,
    connected: bool,
    control_stream_id: Option<StreamId>,
    responses: BTreeMap<StreamId, ResponseState>,
    completed: VecDeque<Http3Response>,
}

impl Http3Client {
    pub fn new(quic_config: QuicConfig, settings: Http3Settings) -> Result<Self, String> {
        let quic = QuicConnection::new(quic_config)?;
        Ok(Self {
            quic,
            encoder: QpackEncoder::new(),
            decoder: QpackDecoder::new(),
            settings,
            connected: false,
            control_stream_id: None,
            responses: BTreeMap::new(),
            completed: VecDeque::new(),
        })
    }

    pub fn connect(&mut self) -> Result<(), String> {
        if self.connected {
            return Ok(());
        }
        self.quic.connect()?;

        // Add connection timeout (30 seconds max)
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(30);
        let mut attempts = 0;

        while !self.quic.is_connected() {
            if start.elapsed() > timeout {
                return Err(format!(
                    "QUIC connection timeout after {} attempts ({:.1}s). \
                    The server may not support HTTP/3, or UDP port 443 is filtered.",
                    attempts,
                    start.elapsed().as_secs_f64()
                ));
            }

            attempts += 1;
            match self.quic.poll_io() {
                Ok(()) => {
                    // Successfully received and processed a packet
                    eprintln!("[DEBUG] Attempt {}: packet received", attempts);
                }
                Err(err) => {
                    if err.contains("WouldBlock")
                        || err.contains("timed out")
                        || err.contains("Resource temporarily unavailable") {
                        // No data available, retry
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        eprintln!("[DEBUG] QUIC connection established after {} attempts", attempts);
        self.ensure_control_stream()?;
        self.process_stream_events()?;
        self.connected = true;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected && self.control_stream_id.is_some() && self.quic.is_connected()
    }

    /// Encode HTTP headers into QPACK block.
    pub fn encode_headers(&self, headers: &[(String, String)]) -> Vec<u8> {
        self.encoder.encode(headers)
    }

    pub fn local_settings_frame(&self) -> Http3Frame {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            self.settings.initial_table_capacity,
        );
        parameters.insert(
            SETTINGS_QPACK_BLOCKED_STREAMS,
            self.settings.max_blocked_streams,
        );
        if let Some(limit) = self.settings.max_field_section_size {
            parameters.insert(SETTINGS_MAX_FIELD_SECTION_SIZE, limit);
        }
        Http3Frame::Settings(SettingsFrame { parameters })
    }

    fn ensure_control_stream(&mut self) -> Result<(), String> {
        if self.control_stream_id.is_some() {
            return Ok(());
        }

        let mut payload = Vec::new();
        encode_varint(0, &mut payload); // Control stream type

        let mut settings_bytes = Vec::new();
        self.local_settings_frame().encode(&mut settings_bytes);
        payload.extend_from_slice(&settings_bytes);

        let stream_id = self.quic.send_unidirectional_stream(&payload)?;
        self.control_stream_id = Some(stream_id);

        // TODO: send QPACK encoder/decoder streams once dynamic table is implemented.
        Ok(())
    }

    pub fn get(&mut self, scheme: &str, authority: &str, path: &str) -> Result<StreamId, String> {
        self.request("GET", scheme, authority, path, None)
    }

    pub fn request(
        &mut self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<StreamId, String> {
        if !self.is_connected() {
            self.connect()?;
        }

        let stream_id = self.quic.open_bidirectional_stream();

        let mut headers = vec![
            (":method".to_string(), method.to_uppercase()),
            (":scheme".to_string(), scheme.to_string()),
            (":authority".to_string(), authority.to_string()),
            (":path".to_string(), path.to_string()),
        ];
        headers.push(("user-agent".to_string(), "redblue-http3/0.1".to_string()));
        headers.push(("accept".to_string(), "*/*".to_string()));

        let header_block = self.encode_headers(&headers);
        let mut payload = Vec::new();
        Http3Frame::Headers(HeadersFrame {
            block_fragment: header_block,
        })
        .encode(&mut payload);

        if let Some(body_bytes) = body {
            if !body_bytes.is_empty() {
                Http3Frame::Data(DataFrame {
                    payload: body_bytes.to_vec(),
                })
                .encode(&mut payload);
            }
        }

        self.quic.send_stream_data(stream_id, payload, true)?;

        Ok(stream_id)
    }

    pub fn poll(&mut self) -> Result<(), String> {
        self.process_stream_events()?;
        self.poll_transport()?;
        self.process_stream_events()?;
        Ok(())
    }

    pub fn poll_response(&mut self) -> Result<Option<Http3Response>, String> {
        if let Some(resp) = self.completed.pop_front() {
            return Ok(Some(resp));
        }

        self.poll()?;
        Ok(self.completed.pop_front())
    }

    pub fn take_response(&mut self) -> Option<Http3Response> {
        self.completed.pop_front()
    }

    fn poll_transport(&mut self) -> Result<(), String> {
        match self.quic.poll_io() {
            Ok(()) => Ok(()),
            Err(err) => {
                if err.contains("WouldBlock")
                    || err.contains("timed out")
                    || err.contains("Resource temporarily unavailable") {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    fn process_stream_events(&mut self) -> Result<(), String> {
        let events = self.quic.take_stream_events();
        for event in events {
            self.handle_stream_event(event)?;
        }
        Ok(())
    }

    fn handle_stream_event(&mut self, event: StreamEvent) -> Result<(), String> {
        let mut finished = false;
        {
            let state = self
                .responses
                .entry(event.stream_id)
                .or_insert_with(ResponseState::new);
            state.buffer.extend_from_slice(&event.data);
            if event.fin {
                state.fin = true;
            }

            let frames = consume_http3_frames(&mut state.buffer)?;
            for frame in frames {
                match frame {
                    Http3Frame::Headers(headers_frame) => {
                        let decoded = self
                            .decoder
                            .decode(&headers_frame.block_fragment)?;
                        state.headers = Some(decoded);
                    }
                    Http3Frame::Data(data_frame) => {
                        state.body.extend_from_slice(&data_frame.payload);
                    }
                    _ => {}
                }
            }

            finished = state.fin && state.headers.is_some();
        }

        if finished {
            if let Some(mut state) = self.responses.remove(&event.stream_id) {
                if let Some(response) = state.build_response(event.stream_id) {
                    self.completed.push_back(response);
                }
            }
        }

        Ok(())
    }
}

fn consume_http3_frames(buffer: &mut Vec<u8>) -> Result<Vec<Http3Frame>, String> {
    let mut frames = Vec::new();
    let mut consumed = 0usize;

    while consumed < buffer.len() {
        let slice = &buffer[consumed..];
        let mut cursor = 0usize;
        let frame_type = match decode_varint(slice, &mut cursor) {
            Ok(value) => value,
            Err(err) => {
                if err.contains("underflow") {
                    break;
                }
                return Err(err);
            }
        };

        let length = match decode_varint(slice, &mut cursor) {
            Ok(value) => value as usize,
            Err(err) => {
                if err.contains("underflow") {
                    break;
                }
                return Err(err);
            }
        };

        if cursor + length > slice.len() {
            break;
        }

        let frame_slice = &slice[..cursor + length];
        let mut local_cursor = 0usize;
        let frame = Http3Frame::decode(frame_slice, &mut local_cursor)?;
        frames.push(frame);
        consumed += cursor + length;
    }

    if consumed > 0 {
        buffer.drain(..consumed);
    }

    Ok(frames)
}

#[derive(Debug, Clone)]
pub struct Http3Response {
    pub stream_id: StreamId,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

struct ResponseState {
    buffer: Vec<u8>,
    headers: Option<Vec<(String, String)>>,
    body: Vec<u8>,
    fin: bool,
}

impl ResponseState {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            headers: None,
            body: Vec::new(),
            fin: false,
        }
    }

    fn build_response(&mut self, stream_id: StreamId) -> Option<Http3Response> {
        let headers = self.headers.take()?;
        let status = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(":status"))
            .and_then(|(_, value)| value.parse::<u16>().ok())
            .unwrap_or(0);

        Some(Http3Response {
            stream_id,
            status,
            headers,
            body: std::mem::take(&mut self.body),
        })
    }
}
