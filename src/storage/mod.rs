// redblue persistent storage core
//
// This module exposes a compact, segment-oriented storage engine that is
// purpose-built for the telemetry collected by the CLI (ports, subdomains,
// WHOIS, TLS certificates, DNS records, HTTP metadata).  Each segment uses
// domain-specific encodings and on-disk indexes so lookups can be satisfied
// without materialising the whole dataset or issuing string-based scans.

pub mod client;
pub mod encoding;
pub mod layout;
pub mod segments;
pub mod service;
pub mod store;

pub mod reddb;
pub mod records;
pub mod session;
pub mod tables;
pub mod view;

// RedDB Storage Engine (page-based, B-tree indexed)
pub mod engine;

// Legacy Engine (append-only log, for backward compatibility)
// Disabled - requires old WAL implementation
// pub mod engine_legacy;
// pub mod serializer;

// Write-Ahead Log (Durability)
pub mod wal;

// Encryption Layer (Security)
pub mod encryption;

// Keyring integration for secure password storage
pub mod keyring;

// Schema System (Types, Tables, Registry)
pub mod schema;

// Vector Storage and Similarity Search
pub mod vector;

// Query Engine (Filters, Sorting, Similarity Search)
pub mod query;

// Public surface re-used by the rest of the codebase.
pub use client::{PersistenceConfig, PersistenceManager, QueryManager, PasswordSource};
pub use reddb::RedDb;
pub use records::{
    PortScanRecord, PortStatus, SubdomainRecord, SubdomainSource, TlsCertRecord, WhoisRecord,
    ProxyConnectionRecord, ProxyHttpRequestRecord, ProxyHttpResponseRecord, ProxyWebSocketRecord,
};
pub use service::{PartitionKey, PartitionMetadata, StorageService};
pub use session::{SessionFile, SessionMetadata};
pub use keyring::{resolve_password, save_to_keyring, clear_keyring, has_keyring_password};
