/// HTTP/2 Protocol Implementation (RFC 7540)
/// Pure Rust std - ZERO external dependencies
pub mod frame;
pub mod hpack;

pub use frame::{Frame, FrameHeader};
pub use hpack::HpackCodec;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

/// HTTP/2 connection preface
/// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Stream states (RFC 7540 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// HTTP/2 Stream
#[derive(Debug)]
pub struct Stream {
    pub id: u32,
    pub state: StreamState,
    pub headers: Vec<(String, String)>,
    pub data: Vec<u8>,
    pub window_size: i32,
}

impl Stream {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            headers: Vec::new(),
            data: Vec::new(),
            window_size: 65535, // Default initial window size
        }
    }
}

/// HTTP/2 Connection
pub struct Http2Connection {
    stream: TcpStream,
    hpack: HpackCodec,
    streams: HashMap<u32, Stream>,
    next_stream_id: u32,
    server_settings: HashMap<u16, u32>,
}

impl Http2Connection {
    /// Create new HTTP/2 connection
    pub fn new(mut stream: TcpStream) -> Result<Self, String> {
        // Send connection preface
        stream
            .write_all(CONNECTION_PREFACE)
            .map_err(|e| format!("Failed to send connection preface: {}", e))?;

        // Send initial SETTINGS frame
        let settings = frame::SettingsFrame {
            header: frame::FrameHeader {
                length: 0,
                frame_type: frame::FRAME_TYPE_SETTINGS,
                flags: 0,
                stream_id: 0,
            },
            settings: vec![],
        };

        stream
            .write_all(&settings.to_bytes())
            .map_err(|e| format!("Failed to send SETTINGS: {}", e))?;

        Ok(Self {
            stream,
            hpack: HpackCodec::new(),
            streams: HashMap::new(),
            next_stream_id: 1, // Client-initiated streams are odd
            server_settings: HashMap::new(),
        })
    }

    /// Send HTTP/2 GET request
    pub fn get(
        &mut self,
        path: &str,
        headers: Vec<(String, String)>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Skip to next odd number

        // Create stream
        let mut stream_obj = Stream::new(stream_id);
        stream_obj.state = StreamState::Open;

        // Build pseudo-headers
        let mut all_headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), path.to_string()),
            (":scheme".to_string(), "https".to_string()),
        ];
        all_headers.extend(headers);

        // Encode headers with HPACK
        let header_block = self
            .hpack
            .encode(&all_headers)
            .map_err(|e| format!("HPACK encoding failed: {}", e))?;

        // Create HEADERS frame
        let mut header_frame = frame::FrameHeader::new(
            frame::FRAME_TYPE_HEADERS,
            frame::FLAG_END_HEADERS | frame::FLAG_END_STREAM,
            stream_id,
        );
        header_frame.length = header_block.len() as u32;

        // Send HEADERS frame
        self.stream
            .write_all(&header_frame.to_bytes())
            .map_err(|e| format!("Failed to send HEADERS frame header: {}", e))?;

        self.stream
            .write_all(&header_block)
            .map_err(|e| format!("Failed to send HEADERS frame payload: {}", e))?;

        // Mark stream as half-closed local (we sent END_STREAM)
        stream_obj.state = StreamState::HalfClosedLocal;
        self.streams.insert(stream_id, stream_obj);

        // Read response frames
        self.read_response(stream_id)
    }

    /// Read response frames for a stream
    fn read_response(
        &mut self,
        stream_id: u32,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        let mut response_headers: Vec<(String, String)> = Vec::new();
        let mut response_data = Vec::new();
        let mut status_code = 0u16;

        loop {
            // Read frame header (9 bytes)
            let mut header_bytes = [0u8; 9];
            self.stream
                .read_exact(&mut header_bytes)
                .map_err(|e| format!("Failed to read frame header: {}", e))?;

            let header = frame::FrameHeader::parse(&header_bytes)?;

            // Read frame payload
            let mut payload = vec![0u8; header.length as usize];
            if header.length > 0 {
                self.stream
                    .read_exact(&mut payload)
                    .map_err(|e| format!("Failed to read frame payload: {}", e))?;
            }

            // Parse frame
            let frame = frame::Frame::parse(header, &payload)?;

            match frame {
                Frame::Settings(settings_frame) => {
                    // Handle SETTINGS frame
                    if settings_frame.header.has_flag(frame::FLAG_ACK) {
                        // SETTINGS ACK - ignore
                    } else {
                        // Server settings - send ACK
                        for setting in &settings_frame.settings {
                            self.server_settings
                                .insert(setting.identifier, setting.value);
                        }

                        let ack = frame::SettingsFrame::new_ack();
                        self.stream
                            .write_all(&ack.to_bytes())
                            .map_err(|e| format!("Failed to send SETTINGS ACK: {}", e))?;
                    }
                }
                Frame::Headers(headers_frame) => {
                    if headers_frame.header.stream_id == stream_id {
                        // Decode headers
                        let headers = self
                            .hpack
                            .decode(&headers_frame.header_block_fragment)
                            .map_err(|e| format!("HPACK decoding failed: {}", e))?;

                        // Extract status code from :status pseudo-header
                        for (name, value) in &headers {
                            if name == ":status" {
                                status_code = value
                                    .parse()
                                    .map_err(|_| format!("Invalid status code: {}", value))?;
                            } else if !name.starts_with(':') {
                                response_headers.push((name.clone(), value.clone()));
                            }
                        }

                        // Check if this is the end of headers
                        if headers_frame.header.has_flag(frame::FLAG_END_HEADERS) {
                            // Headers complete
                        }

                        // Check if stream is done
                        if headers_frame.header.has_flag(frame::FLAG_END_STREAM) {
                            break;
                        }
                    }
                }
                Frame::Data(data_frame) => {
                    if data_frame.header.stream_id == stream_id {
                        response_data.extend_from_slice(&data_frame.data);

                        if data_frame.header.has_flag(frame::FLAG_END_STREAM) {
                            break;
                        }
                    }
                }
                Frame::WindowUpdate(_) => {
                    // Handle WINDOW_UPDATE
                }
                Frame::GoAway(goaway) => {
                    return Err(format!(
                        "Server sent GOAWAY: error_code={}",
                        goaway.error_code
                    ));
                }
                Frame::RstStream(rst) => {
                    if rst.header.stream_id == stream_id {
                        return Err(format!("Stream reset: error_code={}", rst.error_code));
                    }
                }
                _ => {
                    // Ignore other frame types for now
                }
            }
        }

        Ok((status_code, response_headers, response_data))
    }

    /// Close connection gracefully
    pub fn close(&mut self) -> Result<(), String> {
        // Send GOAWAY frame
        let goaway_header = frame::FrameHeader {
            length: 8,
            frame_type: frame::FRAME_TYPE_GOAWAY,
            flags: 0,
            stream_id: 0,
        };

        let mut goaway_payload = Vec::new();
        // Last stream ID (31 bits)
        goaway_payload.extend_from_slice(&self.next_stream_id.to_be_bytes());
        // Error code: NO_ERROR
        goaway_payload.extend_from_slice(&frame::ERROR_NO_ERROR.to_be_bytes());

        self.stream
            .write_all(&goaway_header.to_bytes())
            .map_err(|e| format!("Failed to send GOAWAY header: {}", e))?;

        self.stream
            .write_all(&goaway_payload)
            .map_err(|e| format!("Failed to send GOAWAY payload: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_preface() {
        assert_eq!(CONNECTION_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    }

    #[test]
    fn test_stream_creation() {
        let stream = Stream::new(1);
        assert_eq!(stream.id, 1);
        assert_eq!(stream.state, StreamState::Idle);
        assert_eq!(stream.window_size, 65535);
    }
}
