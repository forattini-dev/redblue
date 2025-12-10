//! HTTP/2 Stream Management (RFC 7540 Section 5)
//!
//! Manages HTTP/2 stream lifecycle and state transitions.
//! Implements stream multiplexing, flow control, and priority handling.

use std::collections::HashMap;

/// Stream identifier (31-bit unsigned integer)
pub type StreamId = u32;

/// HTTP/2 Stream
#[derive(Debug, Clone)]
pub struct Stream {
    pub id: StreamId,
    pub state: StreamState,
    pub window_size: i32,
    pub priority: Priority,
    pub data: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub trailers: Option<Vec<(String, String)>>,
}

/// Stream State Machine (RFC 7540 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Initial state before any frames sent/received
    Idle,

    /// Stream opened, can send/receive frames
    Open,

    /// Local endpoint closed (sent END_STREAM)
    HalfClosedLocal,

    /// Remote endpoint closed (received END_STREAM)
    HalfClosedRemote,

    /// Stream closed (both endpoints closed or RST_STREAM received)
    Closed,

    /// Reserved for server push (local)
    ReservedLocal,

    /// Reserved for server push (remote)
    ReservedRemote,
}

/// Stream Priority (RFC 7540 Section 5.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority {
    /// Stream dependency (0 = no dependency)
    pub stream_dependency: StreamId,

    /// Weight (1-256, higher = more resources)
    pub weight: u8,

    /// Exclusive flag (restructures priority tree)
    pub exclusive: bool,
}

impl Priority {
    pub fn default() -> Self {
        Priority {
            stream_dependency: 0,
            weight: 16, // Default weight
            exclusive: false,
        }
    }
}

impl Stream {
    /// Create new stream in IDLE state
    pub fn new(id: StreamId) -> Self {
        Stream {
            id,
            state: StreamState::Idle,
            window_size: 65535, // Default initial window size
            priority: Priority::default(),
            data: Vec::new(),
            headers: Vec::new(),
            trailers: None,
        }
    }

    /// Create new stream with custom initial window size
    pub fn with_window_size(id: StreamId, window_size: i32) -> Self {
        Stream {
            id,
            state: StreamState::Idle,
            window_size,
            priority: Priority::default(),
            data: Vec::new(),
            headers: Vec::new(),
            trailers: None,
        }
    }

    /// Transition stream state based on frame type and flags
    pub fn transition(&mut self, event: StreamEvent) -> Result<(), String> {
        let new_state = match (self.state, event) {
            // IDLE → OPEN (send/receive HEADERS)
            (StreamState::Idle, StreamEvent::SendHeaders) => StreamState::Open,
            (StreamState::Idle, StreamEvent::ReceiveHeaders) => StreamState::Open,

            // IDLE → HALF_CLOSED_REMOTE (send HEADERS with END_STREAM)
            (StreamState::Idle, StreamEvent::SendHeadersEndStream) => StreamState::HalfClosedRemote,

            // IDLE → HALF_CLOSED_LOCAL (receive HEADERS with END_STREAM)
            (StreamState::Idle, StreamEvent::ReceiveHeadersEndStream) => {
                StreamState::HalfClosedLocal
            }

            // OPEN → HALF_CLOSED_LOCAL (send END_STREAM)
            (StreamState::Open, StreamEvent::SendEndStream) => StreamState::HalfClosedLocal,

            // OPEN → HALF_CLOSED_REMOTE (receive END_STREAM)
            (StreamState::Open, StreamEvent::ReceiveEndStream) => StreamState::HalfClosedRemote,

            // HALF_CLOSED_LOCAL → CLOSED (receive END_STREAM)
            (StreamState::HalfClosedLocal, StreamEvent::ReceiveEndStream) => StreamState::Closed,

            // HALF_CLOSED_REMOTE → CLOSED (send END_STREAM or receive END_STREAM)
            (StreamState::HalfClosedRemote, StreamEvent::SendEndStream) => StreamState::Closed,
            (StreamState::HalfClosedRemote, StreamEvent::ReceiveEndStream) => StreamState::Closed,

            // HALF_CLOSED_REMOTE can receive trailers (trailing HEADERS)
            // RFC 7540 Section 8.1: Trailers are sent as HEADERS frames after END_STREAM
            (StreamState::HalfClosedRemote, StreamEvent::ReceiveHeaders) => {
                StreamState::HalfClosedRemote
            }
            (StreamState::HalfClosedRemote, StreamEvent::ReceiveHeadersEndStream) => {
                StreamState::Closed
            }

            // ANY → CLOSED (RST_STREAM)
            (_, StreamEvent::ResetStream) => StreamState::Closed,

            // IDLE → RESERVED_LOCAL (send PUSH_PROMISE)
            (StreamState::Idle, StreamEvent::SendPushPromise) => StreamState::ReservedLocal,

            // IDLE → RESERVED_REMOTE (receive PUSH_PROMISE)
            (StreamState::Idle, StreamEvent::ReceivePushPromise) => StreamState::ReservedRemote,

            // RESERVED_LOCAL → HALF_CLOSED_REMOTE (send HEADERS)
            (StreamState::ReservedLocal, StreamEvent::SendHeaders) => StreamState::HalfClosedRemote,

            // RESERVED_REMOTE → HALF_CLOSED_LOCAL (receive HEADERS)
            (StreamState::ReservedRemote, StreamEvent::ReceiveHeaders) => {
                StreamState::HalfClosedLocal
            }

            // Invalid transitions
            _ => {
                return Err(format!(
                    "Invalid stream transition: {:?} → {:?}",
                    self.state, event
                ));
            }
        };

        self.state = new_state;
        Ok(())
    }

    /// Check if stream can send frames
    pub fn can_send(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedRemote
        )
    }

    /// Check if stream can receive frames
    pub fn can_receive(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.state == StreamState::Closed
    }

    /// Update flow control window
    pub fn update_window(&mut self, delta: i32) -> Result<(), String> {
        let new_window = self
            .window_size
            .checked_add(delta)
            .ok_or_else(|| "Window size overflow".to_string())?;

        if new_window > 2147483647 {
            return Err("Window size exceeds maximum (2^31-1)".to_string());
        }

        self.window_size = new_window;
        Ok(())
    }

    /// Consume window size for sending data
    pub fn consume_window(&mut self, bytes: usize) -> Result<(), String> {
        if bytes as i32 > self.window_size {
            return Err("Insufficient window size for data".to_string());
        }

        self.window_size -= bytes as i32;
        Ok(())
    }
}

/// Stream State Transition Events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEvent {
    SendHeaders,
    ReceiveHeaders,
    SendHeadersEndStream,
    ReceiveHeadersEndStream,
    SendEndStream,
    ReceiveEndStream,
    ResetStream,
    SendPushPromise,
    ReceivePushPromise,
}

/// Stream Manager - manages multiple HTTP/2 streams
#[derive(Debug)]
pub struct StreamManager {
    streams: HashMap<StreamId, Stream>,
    next_local_stream_id: StreamId,
    next_remote_stream_id: StreamId,
    max_concurrent_streams: usize,
    initial_window_size: i32,
}

impl StreamManager {
    /// Create new stream manager
    /// - client_mode: true for client (odd stream IDs), false for server (even stream IDs)
    pub fn new(client_mode: bool, initial_window_size: i32) -> Self {
        StreamManager {
            streams: HashMap::new(),
            next_local_stream_id: if client_mode { 1 } else { 2 },
            next_remote_stream_id: if client_mode { 2 } else { 1 },
            max_concurrent_streams: 100, // Default limit
            initial_window_size,
        }
    }

    /// Create new local stream
    pub fn create_stream(&mut self) -> Result<StreamId, String> {
        if self.active_stream_count() >= self.max_concurrent_streams {
            return Err("Max concurrent streams limit reached".to_string());
        }

        let stream_id = self.next_local_stream_id;
        self.next_local_stream_id += 2; // Increment by 2 (odd for client, even for server)

        let stream = Stream::with_window_size(stream_id, self.initial_window_size);
        self.streams.insert(stream_id, stream);

        Ok(stream_id)
    }

    /// Get stream by ID
    pub fn get_stream(&self, stream_id: StreamId) -> Option<&Stream> {
        self.streams.get(&stream_id)
    }

    /// Get mutable stream by ID
    pub fn get_stream_mut(&mut self, stream_id: StreamId) -> Option<&mut Stream> {
        self.streams.get_mut(&stream_id)
    }

    /// Register remote stream (from peer)
    pub fn register_remote_stream(&mut self, stream_id: StreamId) -> Result<(), String> {
        if self.streams.contains_key(&stream_id) {
            return Err(format!("Stream {} already exists", stream_id));
        }

        if self.active_stream_count() >= self.max_concurrent_streams {
            return Err("Max concurrent streams limit reached".to_string());
        }

        let stream = Stream::with_window_size(stream_id, self.initial_window_size);
        self.streams.insert(stream_id, stream);

        // Update next remote stream ID if necessary
        if stream_id >= self.next_remote_stream_id {
            self.next_remote_stream_id = stream_id + 2;
        }

        Ok(())
    }

    /// Close stream
    pub fn close_stream(&mut self, stream_id: StreamId) -> Result<(), String> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = StreamState::Closed;
            Ok(())
        } else {
            Err(format!("Stream {} not found", stream_id))
        }
    }

    /// Remove closed streams (cleanup)
    pub fn cleanup_closed_streams(&mut self) {
        self.streams.retain(|_, stream| !stream.is_closed());
    }

    /// Get count of active (non-closed) streams
    pub fn active_stream_count(&self) -> usize {
        self.streams.values().filter(|s| !s.is_closed()).count()
    }

    /// Set max concurrent streams
    pub fn set_max_concurrent_streams(&mut self, max: usize) {
        self.max_concurrent_streams = max;
    }

    /// Update initial window size for all streams
    pub fn update_initial_window_size(&mut self, new_size: i32) -> Result<(), String> {
        let delta = new_size - self.initial_window_size;

        for stream in self.streams.values_mut() {
            stream.update_window(delta)?;
        }

        self.initial_window_size = new_size;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_creation() {
        let stream = Stream::new(1);
        assert_eq!(stream.id, 1);
        assert_eq!(stream.state, StreamState::Idle);
        assert_eq!(stream.window_size, 65535);
    }

    #[test]
    fn test_stream_state_transitions() {
        let mut stream = Stream::new(1);

        // IDLE → OPEN
        assert!(stream.transition(StreamEvent::SendHeaders).is_ok());
        assert_eq!(stream.state, StreamState::Open);

        // OPEN → HALF_CLOSED_LOCAL
        assert!(stream.transition(StreamEvent::SendEndStream).is_ok());
        assert_eq!(stream.state, StreamState::HalfClosedLocal);

        // HALF_CLOSED_LOCAL → CLOSED
        assert!(stream.transition(StreamEvent::ReceiveEndStream).is_ok());
        assert_eq!(stream.state, StreamState::Closed);
    }

    #[test]
    fn test_stream_can_send_receive() {
        let mut stream = Stream::new(1);
        stream.state = StreamState::Open;

        assert!(stream.can_send());
        assert!(stream.can_receive());

        stream.state = StreamState::HalfClosedLocal;
        assert!(!stream.can_send());
        assert!(stream.can_receive());

        stream.state = StreamState::HalfClosedRemote;
        assert!(stream.can_send());
        assert!(!stream.can_receive());

        stream.state = StreamState::Closed;
        assert!(!stream.can_send());
        assert!(!stream.can_receive());
    }

    #[test]
    fn test_flow_control() {
        let mut stream = Stream::new(1);
        assert_eq!(stream.window_size, 65535);

        // Consume window
        assert!(stream.consume_window(1000).is_ok());
        assert_eq!(stream.window_size, 64535);

        // Update window
        assert!(stream.update_window(5000).is_ok());
        assert_eq!(stream.window_size, 69535);

        // Try to consume more than available
        stream.window_size = 500;
        assert!(stream.consume_window(1000).is_err());
    }

    #[test]
    fn test_stream_manager_client() {
        let mut manager = StreamManager::new(true, 65535);

        // Create stream (should get ID 1, 3, 5...)
        let id1 = manager.create_stream().unwrap();
        assert_eq!(id1, 1);

        let id2 = manager.create_stream().unwrap();
        assert_eq!(id2, 3);

        assert_eq!(manager.active_stream_count(), 2);
    }

    #[test]
    fn test_stream_manager_server() {
        let mut manager = StreamManager::new(false, 65535);

        // Create stream (should get ID 2, 4, 6...)
        let id1 = manager.create_stream().unwrap();
        assert_eq!(id1, 2);

        let id2 = manager.create_stream().unwrap();
        assert_eq!(id2, 4);
    }

    #[test]
    fn test_max_concurrent_streams() {
        let mut manager = StreamManager::new(true, 65535);
        manager.set_max_concurrent_streams(2);

        assert!(manager.create_stream().is_ok());
        assert!(manager.create_stream().is_ok());
        assert!(manager.create_stream().is_err()); // Exceeds limit
    }

    #[test]
    fn test_cleanup_closed_streams() {
        let mut manager = StreamManager::new(true, 65535);

        let id1 = manager.create_stream().unwrap();
        let id2 = manager.create_stream().unwrap();

        manager.close_stream(id1).unwrap();
        assert_eq!(manager.active_stream_count(), 1);

        manager.cleanup_closed_streams();
        assert!(manager.get_stream(id1).is_none());
        assert!(manager.get_stream(id2).is_some());
    }
}
