//! Packet Crafting Module
//!
//! Provides pigsty-style packet signature parsing and crafting.
//!
//! Signature format:
//! ```text
//! ip.src=192.168.1.1; ip.dst=10.0.0.1; ip.ttl=64;
//! tcp.sport=40000; tcp.dport=80; tcp.flags=SYN;
//! payload="GET / HTTP/1.0\r\n\r\n";
//! ```
//!
//! Supported layers:
//! - Ethernet (eth.src, eth.dst, eth.type)
//! - IPv4 (ip.src, ip.dst, ip.ttl, ip.proto, ip.id, ip.flags)
//! - TCP (tcp.sport, tcp.dport, tcp.flags, tcp.seq, tcp.ack, tcp.win)
//! - UDP (udp.sport, udp.dport)
//! - ICMP (icmp.type, icmp.code)
//! - Payload (payload, payload_hex)

mod builder;
mod library;
mod parser;
mod signature;

pub use builder::PacketBuilder;
pub use library::{SignatureCategory, SignatureLibrary};
pub use parser::{ParseError, SignatureParser};
pub use signature::{FieldValue, LayerField, PacketSignature};
