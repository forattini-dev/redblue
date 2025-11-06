/// QUIC Transport Stack
///
/// RFC 9000 (transport), RFC 9001 (TLS mapping), RFC 9002 (loss recovery)
/// Pure Rust, zero dependencies. This module exposes the low-level transport
/// used by HTTP/3 and any future UDP-based capabilities.
pub mod constants;
pub mod congestion;
pub mod connection;
pub mod crypto;
pub mod frame;
pub mod packet;
pub mod recovery;
pub mod stream;

pub use constants::*;
pub use congestion::{CongestionController, NewReno};
pub use connection::{QuicConfig, QuicConnection, QuicEndpointType};
pub use crypto::{ClientInitialKeys, PacketKeySet, ServerInitialKeys};
pub use frame::{
    AckFrame, AckRange, ConnectionCloseFrame, CryptoFrame, DataBlockedFrame, Frame, FrameType,
    MaxDataFrame, MaxStreamDataFrame, MaxStreamsFrame, PingFrame, ResetStreamFrame, StreamDataBlockedFrame,
    StreamFrame, StreamType as StreamLevelType,
};
pub use packet::{
    ConnectionId, LongPacketType, PacketHeader, PacketNumber, PacketNumberSpace, QuicPacket,
    QuicVersion,
    // ShortHeaderPacket, // Not exported from packet module
};
pub use recovery::{LossRecovery, SentPacket};
pub use stream::{
    StreamDirection, StreamId, StreamType, TransportStream,
    // StreamState, // Not exported from stream module
};
