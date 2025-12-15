//! HTTP/2 Connection Management
//!
//! Manages HTTP/2 connections over TLS with ALPN negotiation.
//! Implements connection preface, SETTINGS exchange, and request/response cycle.

use super::framing::{flags, Frame, FrameType};
use super::hpack::{Header, HpackDecoder, HpackEncoder};
use super::stream::{Stream, StreamEvent, StreamId, StreamManager, StreamState};
use super::{ALPN_H2, CONNECTION_PREFACE, DEFAULT_MAX_FRAME_SIZE, DEFAULT_WINDOW_SIZE};
use boring::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// HTTP/2 Client Connection
pub struct Http2Client {
    stream: SslStream<TcpStream>,
    encoder: HpackEncoder,
    decoder: HpackDecoder,
    stream_manager: StreamManager,
    connection_window: i32,
    max_frame_size: u32,
    settings_ack_received: bool,
}

impl Http2Client {
    /// Create new HTTP/2 client and connect to host
    pub fn connect(host: &str, port: u16) -> Result<Self, String> {
        // Step 1: Establish TCP connection
        let tcp_stream = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| format!("TCP connection failed: {}", e))?;

        tcp_stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .ok();
        tcp_stream
            .set_write_timeout(Some(Duration::from_secs(60)))
            .ok();

        // Step 2: TLS handshake with ALPN negotiation for "h2"
        let mut connector = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| format!("SSL connector creation failed: {}", e))?;

        connector.set_verify(SslVerifyMode::NONE); // TODO: Proper certificate validation
        connector
            .set_alpn_protos(ALPN_H2)
            .map_err(|e| format!("ALPN setup failed: {}", e))?;

        let connector = connector.build();
        let mut tls_stream = connector
            .connect(host, tcp_stream)
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        // Verify ALPN negotiation succeeded
        if let Some(protocol) = tls_stream.ssl().selected_alpn_protocol() {
            // selected_alpn_protocol() returns just "h2", not the wire format "\x02h2"
            if protocol != b"h2" {
                return Err(format!(
                    "Server does not support HTTP/2 (ALPN: {:?})",
                    String::from_utf8_lossy(protocol)
                ));
            }
        } else {
            return Err("Server did not negotiate ALPN protocol".to_string());
        }

        // Step 3: Send HTTP/2 connection preface
        tls_stream
            .write_all(CONNECTION_PREFACE)
            .map_err(|e| format!("Failed to send connection preface: {}", e))?;

        // Step 4: Send initial SETTINGS frame
        let settings_frame = Frame::settings(
            false,
            vec![
                (0x3, DEFAULT_MAX_CONCURRENT_STREAMS), // MAX_CONCURRENT_STREAMS
                (0x4, DEFAULT_MAX_FRAME_SIZE),         // INITIAL_WINDOW_SIZE
            ],
        );

        let encoded = settings_frame.encode();
        tls_stream
            .write_all(&encoded)
            .map_err(|e| format!("Failed to send SETTINGS frame: {}", e))?;
        tls_stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        // Initialize client
        let mut client = Http2Client {
            stream: tls_stream,
            encoder: HpackEncoder::new(4096), // Default dynamic table size
            decoder: HpackDecoder::new(4096),
            stream_manager: StreamManager::new(true, DEFAULT_WINDOW_SIZE as i32),
            connection_window: DEFAULT_WINDOW_SIZE as i32,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            settings_ack_received: false,
        };

        // Step 5: Read server's SETTINGS frame
        client.read_settings_frame()?;

        // Step 6: Send SETTINGS ACK
        let ack_frame = Frame::settings(true, vec![]);
        let encoded = ack_frame.encode();
        client
            .stream
            .write_all(&encoded)
            .map_err(|e| format!("Failed to send SETTINGS ACK: {}", e))?;
        client
            .stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(client)
    }

    /// Send HTTP/2 GET request
    pub fn get(&mut self, path: &str, authority: &str) -> Result<Http2Response, String> {
        let (response, _) = self.request("GET", path, authority, vec![], None, None)?;
        Ok(response)
    }

    /// Send HTTP/2 POST request
    pub fn post(
        &mut self,
        path: &str,
        authority: &str,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
    ) -> Result<Http2Response, String> {
        let (response, _) = self.request("POST", path, authority, headers, body, None)?;
        Ok(response)
    }

    /// Send HTTP/2 request with arbitrary method, headers, and optional body
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
    ) -> Result<Http2Response, String> {
        let (response, _) = self.request(method, path, authority, headers, body, None)?;
        Ok(response)
    }

    /// Send HTTP/2 request and capture timing information
    pub fn send_request_with_timing(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
        start_time: Instant,
    ) -> Result<(Http2Response, Duration), String> {
        self.request(method, path, authority, headers, body, Some(start_time))
    }

    /// Send HTTP/2 request and stream response chunks through a handler
    pub fn send_request_with_handler(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        self.request_with_handler(method, path, authority, headers, body, handler, None)
    }

    /// Send HTTP/2 request (generic)
    fn request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        extra_headers: Vec<Header>,
        body: Option<Vec<u8>>,
        start_time: Option<Instant>,
    ) -> Result<(Http2Response, Duration), String> {
        let stream_id = self.initiate_request(method, path, authority, extra_headers, body)?;

        self.read_response(stream_id, start_time)
    }

    fn request_with_handler(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        extra_headers: Vec<Header>,
        body: Option<Vec<u8>>,
        handler: &mut dyn Http2ResponseHandler,
        start_time: Option<Instant>,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        let stream_id = self.initiate_request(method, path, authority, extra_headers, body)?;

        self.read_response_streaming(stream_id, start_time, handler)
    }

    fn initiate_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        extra_headers: Vec<Header>,
        body: Option<Vec<u8>>,
    ) -> Result<StreamId, String> {
        let stream_id = self.stream_manager.create_stream()?;

        // Build headers (pseudo-headers first)
        let mut headers = vec![
            Header::new(":method", method),
            Header::new(":scheme", "https"),
            Header::new(":path", path),
            Header::new(":authority", authority),
        ];

        headers.extend(extra_headers);
        let header_block = self.encoder.encode(&headers);

        let end_stream = body.is_none();
        let headers_frame = Frame::headers(stream_id, end_stream, true, header_block);

        self.stream
            .write_all(&headers_frame.encode())
            .map_err(|e| format!("Failed to send HEADERS: {}", e))?;

        if let Some(stream) = self.stream_manager.get_stream_mut(stream_id) {
            if end_stream {
                stream.transition(StreamEvent::SendHeadersEndStream)?;
            } else {
                stream.transition(StreamEvent::SendHeaders)?;
            }
        }

        if let Some(body_data) = body {
            let data_frame = Frame::data(stream_id, true, body_data);
            self.stream
                .write_all(&data_frame.encode())
                .map_err(|e| format!("Failed to send DATA: {}", e))?;

            if let Some(stream) = self.stream_manager.get_stream_mut(stream_id) {
                stream.transition(StreamEvent::SendEndStream)?;
            }
        }

        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(stream_id)
    }

    /// Read HTTP/2 response for a stream
    fn read_response(
        &mut self,
        stream_id: StreamId,
        start_time: Option<Instant>,
    ) -> Result<(Http2Response, Duration), String> {
        let mut response_headers: Option<Vec<Header>> = None;
        let mut response_data = Vec::new();
        let mut status: Option<u16> = None;
        let mut ttfb_recorded = false;
        let mut ttfb = Duration::ZERO;

        loop {
            // Read frame
            let frame = Frame::decode(&mut self.stream)
                .map_err(|e| format!("Failed to decode frame: {}", e))?;

            // Handle different frame types
            match frame.frame_type {
                FrameType::Headers => {
                    if frame.stream_id != stream_id {
                        continue; // Not our stream
                    }

                    if !ttfb_recorded {
                        if let Some(start) = start_time {
                            ttfb = start.elapsed();
                        }
                        ttfb_recorded = true;
                    }

                    // Decode headers
                    let headers = self
                        .decoder
                        .decode(&frame.payload)
                        .map_err(|e| format!("HPACK decode failed: {}", e))?;

                    // Extract status
                    for header in &headers {
                        if header.name == ":status" {
                            status = Some(
                                header
                                    .value
                                    .parse()
                                    .map_err(|_| "Invalid status code".to_string())?,
                            );
                        }
                    }

                    response_headers = Some(headers);

                    // Update stream state
                    if let Some(stream) = self.stream_manager.get_stream_mut(stream_id) {
                        let has_end_stream = (frame.flags & 0x1) != 0;
                        if has_end_stream {
                            stream.transition(StreamEvent::ReceiveHeadersEndStream)?;
                            break; // Response complete (no body)
                        } else {
                            stream.transition(StreamEvent::ReceiveHeaders)?;
                        }
                    }
                }

                FrameType::Data => {
                    if frame.stream_id != stream_id {
                        continue; // Not our stream
                    }

                    // Append data
                    response_data.extend_from_slice(&frame.payload);

                    // Update stream state
                    let has_end_stream = (frame.flags & 0x1) != 0;
                    if has_end_stream {
                        if let Some(stream) = self.stream_manager.get_stream_mut(stream_id) {
                            stream.transition(StreamEvent::ReceiveEndStream)?;
                        }
                        break; // Response complete
                    }

                    // Send WINDOW_UPDATE for flow control
                    let window_update = Frame::window_update(stream_id, frame.payload.len() as u32);
                    self.stream
                        .write_all(&window_update.encode())
                        .map_err(|e| format!("Failed to send WINDOW_UPDATE: {}", e))?;
                }

                FrameType::Settings => {
                    // Handle SETTINGS frame
                    self.handle_settings_frame(&frame)?;
                }

                FrameType::WindowUpdate => {
                    // Update flow control window
                    if frame.stream_id == 0 {
                        // Connection-level window update
                        let increment = u32::from_be_bytes([
                            frame.payload[0],
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                        ]);
                        self.connection_window += increment as i32;
                    } else if frame.stream_id == stream_id {
                        // Stream-level window update
                        if let Some(stream) = self.stream_manager.get_stream_mut(stream_id) {
                            let increment = u32::from_be_bytes([
                                frame.payload[0],
                                frame.payload[1],
                                frame.payload[2],
                                frame.payload[3],
                            ]);
                            stream.update_window(increment as i32)?;
                        }
                    }
                }

                FrameType::Ping => {
                    // Respond to PING with PONG
                    let pong = Frame {
                        frame_type: FrameType::Ping,
                        flags: 0x1, // ACK flag
                        stream_id: 0,
                        payload: frame.payload.clone(),
                    };
                    self.stream
                        .write_all(&pong.encode())
                        .map_err(|e| format!("Failed to send PONG: {}", e))?;
                }

                FrameType::Goaway => {
                    return Err("Server sent GOAWAY".to_string());
                }

                FrameType::RstStream => {
                    if frame.stream_id == stream_id {
                        return Err("Stream reset by server".to_string());
                    }
                }

                _ => {
                    // Ignore other frame types for now
                }
            }
        }

        // Build response
        let headers = response_headers.ok_or("No response headers received")?;
        let status_code = status.ok_or("No status code in response")?;

        if !ttfb_recorded {
            if let Some(start) = start_time {
                ttfb = start.elapsed();
            }
        }

        Ok((
            Http2Response {
                status: status_code,
                headers,
                body: response_data,
            },
            ttfb,
        ))
    }

    fn read_response_streaming(
        &mut self,
        stream_id: StreamId,
        start_time: Option<Instant>,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        let mut head: Option<Http2ResponseHead> = None;
        let mut ttfb_recorded = false;
        let mut ttfb = Duration::ZERO;

        loop {
            let frame = Frame::decode(&mut self.stream)
                .map_err(|e| format!("Failed to decode frame: {}", e))?;

            match frame.frame_type {
                FrameType::Headers => {
                    if frame.stream_id != stream_id {
                        continue;
                    }

                    if !ttfb_recorded {
                        if let Some(start) = start_time {
                            ttfb = start.elapsed();
                        }
                        ttfb_recorded = true;
                    }

                    let headers = self
                        .decoder
                        .decode(&frame.payload)
                        .map_err(|e| format!("HPACK decode failed: {}", e))?;

                    let mut status = None;
                    for header in &headers {
                        if header.name == ":status" {
                            status = Some(
                                header
                                    .value
                                    .parse()
                                    .map_err(|_| "Invalid status code".to_string())?,
                            );
                        }
                    }

                    let response_head = Http2ResponseHead {
                        status: status.ok_or_else(|| "Missing :status header".to_string())?,
                        headers: headers.clone(),
                    };

                    if head.is_none() {
                        handler.on_head(&response_head)?;
                        head = Some(response_head);
                    }

                    if let Some(stream) = self.stream_manager.get_stream_mut(stream_id) {
                        let has_end_stream = (frame.flags & flags::END_STREAM) != 0;
                        if has_end_stream {
                            stream.transition(StreamEvent::ReceiveHeadersEndStream)?;
                            handler.on_complete()?;
                            return Ok((head.unwrap(), ttfb));
                        } else {
                            stream.transition(StreamEvent::ReceiveHeaders)?;
                        }
                    }
                }
                FrameType::Data => {
                    if frame.stream_id != stream_id {
                        continue;
                    }

                    handler.on_data(&frame.payload)?;

                    let has_end_stream = (frame.flags & flags::END_STREAM) != 0;
                    if has_end_stream {
                        if let Some(stream) = self.stream_manager.get_stream_mut(stream_id) {
                            stream.transition(StreamEvent::ReceiveEndStream)?;
                        }
                        handler.on_complete()?;
                        return Ok((
                            head.ok_or_else(|| "Missing response headers".to_string())?,
                            ttfb,
                        ));
                    }

                    let window_update = Frame::window_update(stream_id, frame.payload.len() as u32);
                    self.stream
                        .write_all(&window_update.encode())
                        .map_err(|e| format!("Failed to send WINDOW_UPDATE: {}", e))?;
                }
                FrameType::Settings => {
                    self.handle_settings_frame(&frame)?;
                }
                FrameType::WindowUpdate => {
                    if frame.stream_id == 0 {
                        let increment = u32::from_be_bytes([
                            frame.payload[0],
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                        ]);
                        self.connection_window += increment as i32;
                    } else if frame.stream_id == stream_id {
                        if let Some(stream) = self.stream_manager.get_stream_mut(stream_id) {
                            let increment = u32::from_be_bytes([
                                frame.payload[0],
                                frame.payload[1],
                                frame.payload[2],
                                frame.payload[3],
                            ]);
                            stream.update_window(increment as i32)?;
                        }
                    }
                }
                FrameType::Ping => {
                    if (frame.flags & flags::ACK) == 0 {
                        let pong =
                            Frame::new(FrameType::Ping, flags::ACK, 0, frame.payload.clone());
                        self.stream
                            .write_all(&pong.encode())
                            .map_err(|e| format!("Failed to send PING ACK: {}", e))?;
                    }
                }
                FrameType::Goaway => {
                    return Err("Server sent GOAWAY".to_string());
                }
                FrameType::RstStream => {
                    if frame.stream_id == stream_id {
                        return Err("Stream reset by server".to_string());
                    }
                }
                _ => {}
            }
        }
    }

    /// Read and handle initial SETTINGS frame from server
    fn read_settings_frame(&mut self) -> Result<(), String> {
        let frame = Frame::decode(&mut self.stream)
            .map_err(|e| format!("Failed to read SETTINGS frame: {}", e))?;

        if frame.frame_type != FrameType::Settings {
            return Err(format!(
                "Expected SETTINGS frame, got {:?}",
                frame.frame_type
            ));
        }

        self.handle_settings_frame(&frame)
    }

    /// Handle SETTINGS frame
    fn handle_settings_frame(&mut self, frame: &Frame) -> Result<(), String> {
        // ACK frame has no payload
        if (frame.flags & 0x1) != 0 {
            self.settings_ack_received = true;
            return Ok(());
        }

        // Parse SETTINGS parameters (6 bytes each)
        let mut pos = 0;
        while pos + 6 <= frame.payload.len() {
            let id = u16::from_be_bytes([frame.payload[pos], frame.payload[pos + 1]]);
            let value = u32::from_be_bytes([
                frame.payload[pos + 2],
                frame.payload[pos + 3],
                frame.payload[pos + 4],
                frame.payload[pos + 5],
            ]);

            match id {
                0x1 => {
                    // HEADER_TABLE_SIZE
                    // TODO: Update HPACK encoder/decoder table size
                }
                0x2 => {
                    // ENABLE_PUSH
                    // TODO: Handle server push
                }
                0x3 => {
                    // MAX_CONCURRENT_STREAMS
                    self.stream_manager
                        .set_max_concurrent_streams(value as usize);
                }
                0x4 => {
                    // INITIAL_WINDOW_SIZE
                    self.stream_manager
                        .update_initial_window_size(value as i32)?;
                }
                0x5 => {
                    // MAX_FRAME_SIZE
                    if value < 16384 || value > 16777215 {
                        return Err("Invalid MAX_FRAME_SIZE value".to_string());
                    }
                    self.max_frame_size = value;
                }
                0x6 => {
                    // MAX_HEADER_LIST_SIZE
                    // TODO: Enforce header list size limit
                }
                _ => {
                    // Unknown setting, ignore per RFC 7540
                }
            }

            pos += 6;
        }

        Ok(())
    }
}

/// HTTP/2 Response
#[derive(Debug, Clone)]
pub struct Http2Response {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

impl Http2Response {
    /// Get response body as string
    pub fn body_string(&self) -> Result<String, String> {
        String::from_utf8(self.body.clone()).map_err(|e| format!("Invalid UTF-8: {}", e))
    }

    /// Get header value by name
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Get all headers with a specific name
    pub fn headers_by_name(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
            .collect()
    }
}

/// HTTP/2 response head (status + headers)
#[derive(Debug, Clone)]
pub struct Http2ResponseHead {
    pub status: u16,
    pub headers: Vec<Header>,
}

/// Streaming handler for HTTP/2 responses
pub trait Http2ResponseHandler {
    fn on_head(&mut self, _head: &Http2ResponseHead) -> Result<(), String> {
        Ok(())
    }

    fn on_data(&mut self, _chunk: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn on_complete(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Default max concurrent streams
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_response_body_string() {
        let response = Http2Response {
            status: 200,
            headers: vec![],
            body: b"Hello, World!".to_vec(),
        };

        assert_eq!(response.body_string().unwrap(), "Hello, World!");
    }

    #[test]
    fn test_http2_response_headers() {
        let response = Http2Response {
            status: 200,
            headers: vec![
                Header::new("content-type", "text/html"),
                Header::new("content-length", "1234"),
            ],
            body: vec![],
        };

        assert_eq!(response.header("content-type"), Some("text/html"));
        assert_eq!(response.header("Content-Type"), Some("text/html")); // Case-insensitive
        assert_eq!(response.header("content-length"), Some("1234"));
        assert_eq!(response.header("x-missing"), None);
    }
}
