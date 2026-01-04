pub mod client;
pub mod crew;
pub mod crypto;
pub mod protocol;
pub mod ratchet;
pub mod server;
pub mod transport;

// Shared agent definitions will go here
pub const AGENT_VERSION: &str = "1.0.0";
pub const DEFAULT_PORT: u16 = 4444;
