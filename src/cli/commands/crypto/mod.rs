//! Crypto commands - Encoding, ciphers, analysis, recipes, and vault
//!
//! Provides CTF-grade cryptographic tooling:
//! - Encoding/decoding (Base64, Hex, URL, HTML, Unicode)
//! - Classical ciphers (Caesar, ROT13, Vigenère, XOR, etc.)
//! - Analysis tools (hash identification, frequency analysis, auto-detect)
//! - Recipe system (CyberChef-style operation chains)
//! - File encryption vault (AES-256-GCM)
//! - Cyclic pattern generator (De Bruijn sequences for exploit dev)

mod analyze;
mod cipher;
mod codec;
mod cyclic;
mod helpers;
mod recipe;
mod vault;

pub use analyze::CryptoAnalyzeCommand;
pub use cipher::CryptoCipherCommand;
pub use codec::CryptoCodecCommand;
pub use cyclic::CryptoCyclicCommand;
pub use helpers::hex_encode;
pub use recipe::CryptoRecipeCommand;
pub use vault::{CryptoCommand, CryptoHashCommand};

/// Magic bytes for encrypted vault files
pub const VAULT_MAGIC: &[u8; 4] = b"RBVT";
/// Current vault format version
pub const VAULT_VERSION: u8 = 1;
/// PBKDF2 iterations (100k for good security)
pub const PBKDF2_ITERATIONS: u32 = 100_000;
/// Salt size in bytes
pub const SALT_SIZE: usize = 32;
/// Nonce size for AES-GCM
pub const NONCE_SIZE: usize = 12;
/// AES-256 key size
pub const KEY_SIZE: usize = 32;
/// GCM tag size
pub const TAG_SIZE: usize = 16;
