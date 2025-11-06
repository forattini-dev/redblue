/// QUIC wire-format constants shared across the transport stack.
pub const QUIC_VERSION_V1: u32 = 0x0000_0001;

/// RFC 9001 - Initial Salt for QUIC version 1.
/// 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// HKDF labels for QUIC key derivation (RFC 9001 §5.1).
pub const LABEL_CLIENT_IN: &[u8] = b"client in";
pub const LABEL_SERVER_IN: &[u8] = b"server in";
pub const LABEL_QUIC_KEY: &[u8] = b"quic key";
pub const LABEL_QUIC_IV: &[u8] = b"quic iv";
pub const LABEL_QUIC_HP: &[u8] = b"quic hp";

/// Transport parameter identifiers (RFC 9000 §18.2).
pub const TP_ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x0000;
pub const TP_MAX_IDLE_TIMEOUT: u64 = 0x0001;
pub const TP_STATELESS_RESET_TOKEN: u64 = 0x0002;
pub const TP_MAX_PACKET_SIZE: u64 = 0x0003;
pub const TP_INITIAL_MAX_DATA: u64 = 0x0004;
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x0005;
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x0006;
pub const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x0007;
pub const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x0008;
pub const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x0009;
pub const TP_ACK_DELAY_EXPONENT: u64 = 0x000a;
pub const TP_MAX_ACK_DELAY: u64 = 0x000b;
pub const TP_DISABLE_ACTIVE_MIGRATION: u64 = 0x000c;
pub const TP_PREFERRED_ADDRESS: u64 = 0x000d;
pub const TP_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x000e;
pub const TP_INITIAL_SOURCE_CONNECTION_ID: u64 = 0x000f;
pub const TP_RETRY_SOURCE_CONNECTION_ID: u64 = 0x0010;
pub const TP_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x0020;

/// QUIC limits recommended by the spec.
pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const MIN_INITIAL_PACKET_SIZE: usize = 1200;
pub const MAX_CID_LENGTH: usize = 20;
pub const MAX_STREAM_ID: u64 = (1u64 << 62) - 1;

/// Loss recovery constants (RFC 9002).
pub const INITIAL_RTT: u64 = 333; // milliseconds
pub const DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;
pub const DEFAULT_MAX_ACK_DELAY: u16 = 25; // milliseconds

/// Application error codes commonly used by HTTP/3.
pub const APPLICATION_ERROR_NO_ERROR: u16 = 0x0000;
pub const APPLICATION_ERROR_GENERAL_PROTOCOL: u16 = 0x000a;
pub const APPLICATION_ERROR_INTERNAL: u16 = 0x000b;
