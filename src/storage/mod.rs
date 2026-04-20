// redblue persistent storage core
//
// This module exposes the unified RedDB storage engine for tables, documents,
// graphs, and vectors with a single API surface.

// Low-level primitives (bloom filters, encoding, mmap, serialization)
pub mod primitives;

pub mod client;

pub mod layout;
pub mod segments;
pub mod service;

pub mod records;
pub mod session;

// RedDB Storage Engine (page-based, B-tree indexed)
pub mod engine;

// B+ Tree with MVCC (Concurrent Storage)
pub mod btree;

// Transaction Management (ACID)
pub mod transaction;

// Page Cache (SIEVE Algorithm)
pub mod cache;

// SQLite Import/Compatibility Layer
pub mod import;

// Write-ahead log - serializer is now integrated into storage primitives

// Write-Ahead Log (Durability)
pub mod wal;

// Encryption Layer (Security)
pub mod encryption;

// Keyring integration for secure password storage
pub mod keyring;

// Schema System (Types, Tables, Registry)
pub mod schema;

// Query Engine (Filters, Sorting, Similarity Search)
pub mod query;

// Unified Storage Layer (Tables + Graphs + Vectors)
pub(crate) mod unified;

// Public surface re-used by the rest of the codebase.
pub use client::{
  ActionConfig, ActionRecorder, PasswordSource, PersistenceConfig, PersistenceManager, QueryManager,
};
pub use keyring::{clear_keyring, has_keyring_password, resolve_password, save_to_keyring};
pub use records::{
  PortScanRecord, PortStatus, ProxyConnectionRecord, ProxyHttpRequestRecord,
  ProxyHttpResponseRecord, ProxyWebSocketRecord, SubdomainRecord, SubdomainSource, TlsCertRecord,
  WhoisRecord,
};
pub use service::{PartitionKey, PartitionMetadata, StorageService};
pub use session::{SessionFile, SessionMetadata};
pub use unified::RedDB;

/// Prefix that `UnifiedStore::load_from_file` tags on errors coming from a
/// foreign or obsolete DB file. Consumers that want to fall back to a live
/// collection path (instead of aborting) should check `err_message.starts_with(INCOMPATIBLE_DB_PREFIX)`.
pub const INCOMPATIBLE_DB_PREFIX: &str = "INCOMPATIBLE_DB:";

/// True if the given error message originated from a DB file whose format
/// redblue cannot read (missing/mismatched magic, unsupported version).
pub fn is_incompatible_db_error(err: impl AsRef<str>) -> bool {
  err.as_ref().starts_with(INCOMPATIBLE_DB_PREFIX)
}

/// Resolve the default on-disk location for persisted `.rdb` scan databases.
///
/// Order of precedence:
///   1. `REDBLUE_DB_DIR` environment variable (explicit override).
///   2. `config.database.db_dir` from `.redblue.yaml`.
///   3. `$XDG_DATA_HOME/redblue/dbs/` (typically `~/.local/share/redblue/dbs/` on Linux/macOS).
///   4. `$LOCALAPPDATA/redblue/dbs/` on Windows.
///   5. Last-resort fallback: `<cwd>/.redblue/dbs/` (scoped to a subdir, never bare CWD).
///
/// The current working directory is **never** used as a bare DB sink by default —
/// that behavior was the source of several surprises (stray `.rdb` files,
/// incompatible files shadowing fresh scans) and has been removed.
pub fn default_db_dir() -> std::path::PathBuf {
  use std::path::PathBuf;

  if let Ok(explicit) = std::env::var("REDBLUE_DB_DIR") {
    if !explicit.is_empty() {
      return PathBuf::from(explicit);
    }
  }

  if let Some(dir) = &crate::config::get().database.db_dir {
    return PathBuf::from(dir);
  }

  if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
    if !xdg.is_empty() {
      return PathBuf::from(xdg).join("redblue").join("dbs");
    }
  }

  if let Ok(home) = std::env::var("HOME") {
    if !home.is_empty() {
      return PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("redblue")
        .join("dbs");
    }
  }

  #[cfg(windows)]
  if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
    if !localappdata.is_empty() {
      return PathBuf::from(localappdata).join("redblue").join("dbs");
    }
  }

  std::env::current_dir()
    .unwrap_or_else(|_| PathBuf::from("."))
    .join(".redblue")
    .join("dbs")
}

/// Resolve the default on-disk path for a target's scan database file.
pub fn default_db_path(target: &str) -> std::path::PathBuf {
  let sanitized = target
    .replace('/', "_")
    .replace('\\', "_")
    .replace(':', "_")
    .trim_start_matches("www.")
    .to_lowercase();
  default_db_dir().join(format!("{}.rdb", sanitized))
}

// Unified intelligence layer exports
pub use segments::actions::{
  ActionOutcome, ActionRecord, ActionSource, ActionTrace, ActionType, IntoActionRecord,
  RecordPayload, Target,
};
pub use segments::convert::{
  DnsResults, FingerprintResults, HttpResults, PingResults, PortScanResults, TlsAuditResults,
  VulnResults, WhoisResults,
};

// =============================================================================
// UNIFIED STORAGE INTERFACE (PRIMARY API)
// =============================================================================
//
// The unified storage layer is THE primary interface for all storage operations.
// Use `storage::Store` and `storage::Query` for all new code.
//
// Use `storage::Store` and `storage::Query` for all new code.

pub use unified::{
  AdjacencyEntry,
  CrossRef,
  DslFilter,
  DslQueryResult as QueryResult,
  EdgeData,
  EdgeDirection,
  EmbeddingSlot,
  EntityData,
  // Entity types - Universal data model
  EntityId,
  EntityKind,
  FilterOp,
  FilterValue,
  // Graph adjacency index
  GraphAdjacencyIndex,
  GraphQueryBuilder,
  HybridQueryBuilder,
  IndexEvent,
  IndexEventKind,

  IndexStats,
  IndexStatus,
  // Index lifecycle management
  IndexType,
  IntegratedIndexConfig as IndexConfig,
  IntegratedIndexConfig,

  // Index Manager - Unified indexing (HNSW + Inverted + B-tree + Graph)
  IntegratedIndexManager as IndexManager,
  IntegratedIndexManager,
  InvertedIndex,
  LifecycleEvent,

  ManagerConfig,
  ManagerStats,
  MatchComponents,

  // Metadata
  Metadata,
  MetadataQueryFilter,
  MetadataStorage,
  MetadataType,

  MetadataValue,
  NodeData,
  QueryResultItem,
  RefQueryBuilder,
  RefType,

  RowData,
  ScanQueryBuilder,
  ScoredMatch,
  SegmentConfig as UnifiedSegmentConfig,
  SegmentError,

  SegmentId as UnifiedSegmentId,
  // Manager
  SegmentManager,
  SegmentState,
  SegmentStats,
  SortOrder,
  SparseVector,
  StoreError,

  StoreStats,
  TableQueryBuilder,
  TextSearchBuilder,
  TextSearchResult,
  TraversalDirection,
  UnifiedEntity,
  UnifiedEntity as Entity,
  UnifiedMetadataFilter,
  // Segments
  UnifiedSegment,
  // =========================================================================
  // PRIMARY INTERFACE - Use these for all new code
  // =========================================================================

  // Store - THE primary storage interface
  UnifiedStore as Store,
  VectorData,
  // Query builders (for advanced use)
  VectorQueryBuilder,
  VectorSearchResult,
  WhereClause,
  // Query DSL - Entry point for all queries
  Q as Query,
};
