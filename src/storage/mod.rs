// redblue persistent storage core
//
// This module exposes a compact, segment-oriented storage engine that is
// purpose-built for the telemetry collected by the CLI (ports, subdomains,
// WHOIS, TLS certificates, DNS records, HTTP metadata).  Each segment uses
// domain-specific encodings and on-disk indexes so lookups can be satisfied
// without materialising the whole dataset or issuing string-based scans.

// Low-level primitives (bloom filters, encoding, mmap, serialization)
pub mod primitives;

pub mod client;

// Encoding utilities - re-exported from primitives for backward compatibility
#[deprecated(since = "0.2.0", note = "Use storage::primitives::encoding instead")]
pub mod encoding;
pub mod layout;
pub mod segments;
pub mod service;
pub mod store;

pub mod records;
pub mod session;
pub mod view;

// Tables - DEPRECATED: Use storage::Store for table operations
#[deprecated(
    since = "0.2.0",
    note = "Use storage::Store for unified table operations"
)]
pub mod tables;

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

// Vector Storage - DEPRECATED: Use storage::engine::vector_store for new code
// Migration: DenseVector → engine::vector_store, FlatIndex → engine::ivf
// The query::similarity module wraps these for query operations
#[deprecated(
    since = "0.2.0",
    note = "Use storage::engine::vector_store for new vector operations. See engine/distance.rs for DistanceMetric."
)]
pub mod vector;

// Query Engine (Filters, Sorting, Similarity Search)
pub mod query;

// Unified Storage Layer (Tables + Graphs + Vectors)
pub mod unified;

// Public surface re-used by the rest of the codebase.
pub use client::{
    ActionConfig, ActionRecorder, PasswordSource, PersistenceConfig, PersistenceManager,
    QueryManager,
};
pub use keyring::{clear_keyring, has_keyring_password, resolve_password, save_to_keyring};
pub use records::{
    PortScanRecord, PortStatus, ProxyConnectionRecord, ProxyHttpRequestRecord,
    ProxyHttpResponseRecord, ProxyWebSocketRecord, SubdomainRecord, SubdomainSource, TlsCertRecord,
    WhoisRecord,
};
pub use service::{PartitionKey, PartitionMetadata, StorageService};
pub use session::{SessionFile, SessionMetadata};
pub use unified::RedDB as RedDb;

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
// Legacy modules (tables, engine::graph_store, vector) are deprecated.

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
    UnifiedEntity as Entity,
    UnifiedMetadataFilter,
    // Segments
    UnifiedSegment,
    // =========================================================================
    // PRIMARY INTERFACE - Use these for all new code
    // =========================================================================

    // Store - THE primary storage interface
    UnifiedStore as Store,
    // =========================================================================
    // BACKWARD COMPATIBILITY - Deprecated, use primary interface instead
    // =========================================================================
    UnifiedStore,
    UnifiedStoreConfig as StoreConfig,
    UnifiedStoreConfig,
    VectorData,
    // Query builders (for advanced use)
    VectorQueryBuilder,
    VectorSearchResult,
    WhereClause,
    // Query DSL - Entry point for all queries
    Q as Query,
};
