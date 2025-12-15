use serde::{Deserialize, Serialize};

pub const BEACON_MAGIC: u32 = 0x52424C55; // "RBLU"
pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Beacon = 1,
    Response = 2,
    Command = 3,
    KeyExchange = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconMessage {
    pub magic: u32,
    pub version: u8,
    pub msg_type: MessageType,
    pub flags: u16,
    pub session_id: u64,
    pub timestamp: u64,
    pub payload: Vec<u8>, // Encrypted payload
    pub tag: [u8; 16],    // Poly1305 auth tag
}

impl BeaconMessage {
    pub fn new(msg_type: MessageType, session_id: u64, payload: Vec<u8>, tag: [u8; 16]) -> Self {
        Self {
            magic: BEACON_MAGIC,
            version: PROTOCOL_VERSION,
            msg_type,
            flags: 0,
            session_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            payload,
            tag,
        }
    }
}

// Internal command structure (inside the encrypted payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCommand {
    pub id: String,
    pub action: String,
    pub args: Vec<String>,
}

// Internal response structure (inside the encrypted payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub command_id: String,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}
