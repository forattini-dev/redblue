//! Unified Storage Layer
//!
//! This module provides a unified abstraction over Tables, Graphs, and Vectors,
//! enabling queries that seamlessly combine all storage types.

mod builder;
mod config;
mod core;
mod errors;
mod file_io;
mod paged_io;
mod stats;

#[cfg(test)]
mod tests;

pub(crate) const STORE_MAGIC: &[u8; 4] = b"RDST";
pub(crate) const STORE_VERSION_V1: u32 = 1;
pub(crate) const STORE_VERSION_V2: u32 = 2;
pub(crate) const METADATA_MAGIC: &[u8; 4] = b"RDM2";

pub use builder::EntityBuilder;
pub use config::UnifiedStoreConfig;
pub use core::UnifiedStore;
pub use errors::StoreError;
pub use stats::StoreStats;
