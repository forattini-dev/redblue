//! MCP Tool Modules
//!
//! Tools are organized by domain for maintainability.

pub mod agent;
pub mod auth;
pub mod auto;
pub mod binary;
pub mod code;
pub mod core;
pub mod crypto;
pub mod database;
pub mod dns;
pub mod evasion;
pub mod exploit;
pub mod file;
pub mod fuzz;
pub mod intel;
pub mod loot;
pub mod memory;
pub mod network;
pub mod password;
pub mod playbook;
pub mod proxy;
pub mod recon;
pub mod report;
pub mod service;
pub mod tls;
pub mod vector;
pub mod vuln;
pub mod web;
pub mod wordlist;

// Re-export tool registration
pub use agent::register_agent_tools;
pub use auth::register_auth_tools;
pub use auto::register_auto_tools;
pub use binary::register_binary_tools;
pub use code::register_code_tools;
pub use core::register_core_tools;
pub use crypto::register_crypto_tools;
pub use database::register_database_tools;
pub use dns::register_dns_tools;
pub use evasion::register_evasion_tools;
pub use exploit::register_exploit_tools;
pub use file::register_file_tools;
pub use fuzz::register_fuzz_tools;
pub use intel::register_intel_tools;
pub use loot::register_loot_tools;
pub use memory::register_memory_tools;
pub use network::register_network_tools;
pub use password::register_password_tools;
pub use playbook::register_playbook_tools;
pub use proxy::register_proxy_tools;
pub use recon::register_recon_tools;
pub use report::register_report_tools;
pub use service::register_service_tools;
pub use tls::register_tls_tools;
pub use vector::register_vector_tools;
pub use vuln::register_vuln_tools;
pub use web::register_web_tools;
pub use wordlist::register_wordlist_tools;
