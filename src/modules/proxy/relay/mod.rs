//! Data Relay Module
//!
//! Provides bidirectional data relay for TCP and UDP connections.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐                        ┌────────────┐
//! │   Client   │◄─────── TCP ──────────►│   Server   │
//! │  (stream)  │        Relay           │  (stream)  │
//! └────────────┘                        └────────────┘
//!       ▲                                     ▲
//!       │                                     │
//!       └────────────┬───────────────────────┘
//!                    │
//!              ┌─────▼─────┐
//!              │ Flow Stats│
//!              └───────────┘
//! ```

pub mod tcp;
pub mod udp;

pub use tcp::relay_bidirectional;
