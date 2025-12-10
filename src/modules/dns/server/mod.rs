//! DNS Server Module
//!
//! Implements a DNS server with hijacking capabilities for MITM attacks.
//!
//! # Features
//!
//! - UDP DNS server (port 53)
//! - TCP DNS server (port 53)
//! - DNS hijacking rules (override, block, redirect)
//! - Upstream resolver support
//! - Response caching
//!
//! # Example
//!
//! ```rust,no_run
//! use redblue::modules::dns::server::{DnsServer, DnsServerConfig, DnsRule};
//!
//! let config = DnsServerConfig::default()
//!     .with_upstream("8.8.8.8")
//!     .with_rule(DnsRule::override_a("*.target.com", "10.0.0.1"));
//!
//! let server = DnsServer::new(config);
//! server.run()?;
//! ```

pub mod server;
pub mod rules;
pub mod cache;
pub mod resolver;

pub use server::{DnsServer, DnsServerConfig};
pub use rules::{DnsRule, RuleAction, RuleMatch};
pub use cache::DnsCache;
pub use resolver::UpstreamResolver;
