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
pub mod store;

pub mod reddb;
pub mod schema;
pub mod session;
pub mod tables;
pub mod view;

// Public surface re-used by the rest of the codebase.
pub use client::{PersistenceManager, QueryManager};
pub use reddb::RedDb;
pub use schema::{
    PortScanRecord, PortStatus, SubdomainRecord, SubdomainSource, TlsCertRecord, WhoisRecord,
};
pub use session::{SessionFile, SessionMetadata};
