//! MITRE ATT&CK Intelligence Module
//!
//! Query MITRE ATT&CK framework data including techniques, tactics, threat groups,
//! software, and mitigations.
//!
//! ## Data Source
//!
//! Data is fetched from MITRE's official GitHub repository:
//! `https://github.com/mitre-attack/attack-stix-data`
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use redblue::modules::recon::mitre::MitreClient;
//!
//! let mut client = MitreClient::new();
//!
//! // Get a specific technique
//! if let Ok(Some(tech)) = client.get_technique("T1059") {
//!     println!("{}: {}", tech.id, tech.name);
//! }
//!
//! // Search across all objects
//! let results = client.search("powershell")?;
//! ```

pub mod types;
pub mod client;

pub use types::*;
pub use client::MitreClient;
