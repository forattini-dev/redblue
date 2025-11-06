use std::collections::BTreeMap;
use std::fmt;

use super::frame::StreamFrame;

pub type StreamId = u64;

/// Stream type bits per RFC 9000 §2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

/// Stream initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInitiator {
    Client,
    Server,
}

/// Perspective of this endpoint for a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    Local,
    Remote,
}

/// Send state machine (RFC 9000 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    Ready,
    Send,
    DataSent,
    DataRecvd,
    ResetSent,
    ResetRecvd,
}

/// Receive state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    Recv,
    SizeKnown,
    DataRecvd,
    ResetRecvd,
    DataRead,
    ResetRead,
}

/// Transport stream with flow-control bookkeeping.
#[derive(Debug)]
pub struct TransportStream {
    pub id: StreamId,
    pub stream_type: StreamType,
    pub initiator: StreamInitiator,
    pub direction: StreamDirection,
    pub send_state: SendState,
    pub recv_state: RecvState,
    pub max_stream_data_local: u64,
    pub max_stream_data_remote: u64,
    send_buffer: Vec<u8>,
    recv_buffer: BTreeMap<u64, Vec<u8>>,
    send_offset: u64,
    recv_offset: u64,
    fin_sent: bool,
    fin_received: bool,
    final_size: Option<u64>,
}

impl TransportStream {
    pub fn new(
        id: StreamId,
        stream_type: StreamType,
        initiator: StreamInitiator,
        direction: StreamDirection,
        initial_local_budget: u64,
        initial_remote_budget: u64,
    ) -> Self {
        Self {
            id,
            stream_type,
            initiator,
            direction,
            send_state: SendState::Ready,
            recv_state: RecvState::Recv,
            max_stream_data_local: initial_local_budget,
            max_stream_data_remote: initial_remote_budget,
            send_buffer: Vec::new(),
            recv_buffer: BTreeMap::new(),
            send_offset: 0,
            recv_offset: 0,
            fin_sent: false,
            fin_received: false,
            final_size: None,
        }
    }

    /// Enqueue bytes for transmission, respecting flow control.
    pub fn push_send_data(&mut self, data: &[u8]) -> Result<(), String> {
        let remaining = self.max_stream_data_remote.saturating_sub(self.send_buffer.len() as u64);
        if data.len() as u64 > remaining {
            return Err("stream flow control exceeded".to_string());
        }
        self.send_buffer.extend_from_slice(data);
        if !data.is_empty() && matches!(self.send_state, SendState::Ready | SendState::DataRecvd) {
            self.send_state = SendState::Send;
        }
        Ok(())
    }

    /// Mark a FIN for transmission.
    pub fn set_fin(&mut self) {
        self.fin_sent = true;
        if self.send_buffer.is_empty() {
            self.send_state = SendState::DataSent;
        }
    }

    /// Pop next chunk for STREAM frame respecting `max_size`.
    pub fn next_stream_frame(&mut self, max_size: usize) -> Option<StreamFrame> {
        if self.send_buffer.is_empty() && !self.fin_sent {
            return None;
        }

        let chunk_len = self.send_buffer.len().min(max_size);
        let chunk = self.send_buffer.drain(..chunk_len).collect::<Vec<u8>>();

        let frame = StreamFrame {
            stream_id: self.id,
            offset: self.send_offset,
            data: chunk.clone(),
            fin: self.fin_sent && self.send_buffer.is_empty(),
        };

        self.send_offset += chunk.len() as u64;
        if frame.fin {
            self.send_state = SendState::DataSent;
            self.final_size = Some(self.send_offset);
        }

        Some(frame)
    }

    /// Account for ACKed data.
    pub fn on_data_acked(&mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        // Stream-level cwnd not tracked; ack just influences state.
        if bytes >= self.send_offset && self.fin_sent {
            self.send_state = SendState::DataRecvd;
        }
    }

    /// Handle a received STREAM frame.
    pub fn on_stream_frame(&mut self, frame: &StreamFrame) -> Result<(), String> {
        let end_offset = frame.offset + frame.data.len() as u64;

        if end_offset > self.max_stream_data_local {
            return Err("peer exceeded stream flow control".to_string());
        }

        if frame.offset < self.recv_offset {
            // Duplicate data; drop silently per spec.
            return Ok(());
        }

        self.recv_buffer
            .insert(frame.offset, frame.data.clone());

        if frame.fin {
            self.fin_received = true;
            self.final_size = Some(end_offset);
            if self.recv_state == RecvState::Recv {
                self.recv_state = RecvState::SizeKnown;
            }
        }

        while let Some(chunk) = self.recv_buffer.remove(&self.recv_offset) {
            self.recv_offset += chunk.len() as u64;
            if let Some(final_size) = self.final_size {
                if self.recv_offset >= final_size {
                    self.recv_state = RecvState::DataRecvd;
                    break;
                }
            }
        }

        Ok(())
    }

    /// Read contiguous bytes from receive buffer.
    pub fn read(&mut self, len: usize) -> Vec<u8> {
        let mut output = Vec::new();
        while let Some(chunk) = self.recv_buffer.remove(&self.recv_offset) {
            self.recv_offset += chunk.len() as u64;
            output.extend_from_slice(&chunk);
            if output.len() >= len {
                break;
            }
        }
        output.truncate(len);
        if self.fin_received && self.recv_offset == self.final_size.unwrap_or(self.recv_offset) {
            self.recv_state = RecvState::DataRead;
        }
        output
    }

    pub fn read_available(&mut self) -> Vec<u8> {
        self.read(usize::MAX)
    }

    /// Increase remote-advertised credit.
    pub fn update_max_stream_data_remote(&mut self, limit: u64) {
        self.max_stream_data_remote = self.max_stream_data_remote.max(limit);
    }

    /// Increase local credit from peer's MAX_STREAM_DATA frame.
    pub fn update_max_stream_data_local(&mut self, limit: u64) {
        self.max_stream_data_local = self.max_stream_data_local.max(limit);
    }
}

impl fmt::Display for TransportStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stream {} {:?}/{:?} send={:?} recv={:?} send_off={} recv_off={} fin_s={} fin_r={}",
            self.id,
            self.stream_type,
            self.direction,
            self.send_state,
            self.recv_state,
            self.send_offset,
            self.recv_offset,
            self.fin_sent,
            self.fin_received
        )
    }
}

/// Helper functions for stream IDs.
pub fn stream_id(initiator: StreamInitiator, stream_type: StreamType, index: u64) -> StreamId {
    let init_bit = match initiator {
        StreamInitiator::Client => 0,
        StreamInitiator::Server => 1,
    };
    let type_bit = match stream_type {
        StreamType::Bidirectional => 0,
        StreamType::Unidirectional => 1,
    };
    (index << 2) | ((type_bit as u64) << 1) | (init_bit as u64)
}

pub fn stream_type_from_id(id: StreamId) -> StreamType {
    if (id & 0x02) != 0 {
        StreamType::Unidirectional
    } else {
        StreamType::Bidirectional
    }
}

pub fn initiator_from_id(id: StreamId) -> StreamInitiator {
    if (id & 0x01) != 0 {
        StreamInitiator::Server
    } else {
        StreamInitiator::Client
    }
}

pub fn direction_for_id(id: StreamId, endpoint: StreamInitiator) -> StreamDirection {
    let initiator = initiator_from_id(id);
    if initiator == endpoint {
        StreamDirection::Local
    } else {
        StreamDirection::Remote
    }
}
