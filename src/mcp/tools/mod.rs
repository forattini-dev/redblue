//! MCP Tool Modules
//!
//! Tools are organized by domain for maintainability.

pub mod auto;
pub mod binary;
pub mod code;
pub mod core;
pub mod crypto;
pub mod dns;
pub mod evasion;
pub mod intel;
pub mod network;
pub mod password;
pub mod recon;
pub mod tls;
pub mod vuln;
pub mod web;
pub mod wordlist;

// Re-export tool registration
pub use auto::register_auto_tools;
pub use binary::register_binary_tools;
pub use code::register_code_tools;
pub use core::register_core_tools;
pub use crypto::register_crypto_tools;
pub use dns::register_dns_tools;
pub use evasion::register_evasion_tools;
pub use intel::register_intel_tools;
pub use network::register_network_tools;
pub use password::register_password_tools;
pub use recon::register_recon_tools;
pub use tls::register_tls_tools;
pub use vuln::register_vuln_tools;
pub use web::register_web_tools;
pub use wordlist::register_wordlist_tools;
