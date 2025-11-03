// RedDB - High-performance embedded database from scratch
// ZERO external dependencies - pure Rust std only
//
// Architecture:
// - B+ Tree indexes (std::collections::BTreeMap)
// - Memory-mapped files (std::fs + mmap via raw syscalls)
// - Write-Ahead Log (WAL) for durability
// - Simple query language (no full SQL parser)
//
// Performance targets:
// - Writes: 1M+ records/sec (append-only + batch commits)
// - Reads: 10M+ records/sec (memory-mapped + B+ tree indexes)
// - Storage: ~50 bytes per record (compressed binary format)

pub mod engine;
pub mod btree;
pub mod wal;
pub mod mmap;
pub mod serializer;
pub mod query;

pub use engine::RedDB;
pub use query::{Query, QueryBuilder};

#[cfg(test)]
mod tests;
