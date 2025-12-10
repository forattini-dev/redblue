# Turso/libSQL Code Reference Map

This document maps RedDB components to their corresponding Turso/libSQL implementation files in `docs/reference/turso/`. Use these references during implementation to learn patterns and avoid reinventing solutions.

## Core Storage Engine

### Page Structure & Layout

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| Page Header | `core/storage/btree.rs:54-102` | B-tree page header offsets |
| Page Types | `core/storage/sqlite3_ondisk.rs` | `PageType` enum definitions |
| Page Content | `core/storage/pager.rs:136-152` | `PageInner` struct |
| Page Flags | `core/storage/pager.rs:193-197` | `PAGE_LOCKED`, `PAGE_DIRTY`, `PAGE_LOADED` |
| Cell Encoding | `core/storage/sqlite3_ondisk.rs` | `BTreeCell`, `TableLeafCell`, `TableInteriorCell` |

**Key Insight from Turso:**
```rust
// From pager.rs:136
pub struct PageInner {
    pub flags: AtomicUsize,
    pub contents: Option<PageContent>,
    pub id: usize,
    pub pin_count: AtomicUsize,  // For cache eviction protection
    pub wal_tag: AtomicU64,      // WAL frame tracking
}
```

### Pager (Page I/O Manager)

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| Page Read/Write | `core/storage/pager.rs:54-134` | `HeaderRef::from_pager()` |
| Dirty Page Tracking | `core/storage/pager.rs:120` | `pager.add_dirty(&page)` |
| Page Allocation | `core/storage/pager.rs` | `BtreePageAllocMode` |
| Buffer Pool | `core/storage/buffer_pool.rs` | Memory management for pages |

**Key Pattern:** Turso uses `PageRef = Arc<Page>` with atomic flags for thread-safe page access.

### B-Tree Engine

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| B-tree Constants | `core/storage/btree.rs:104-117` | `BTCURSOR_MAX_DEPTH = 20`, `MAX_SIBLING_PAGES = 3` |
| Node Operations | `core/storage/btree.rs` | State machines for insert/delete |
| Delete State Machine | `core/storage/btree.rs:144-190` | `DeleteState` enum |
| Cell Overwrite | `core/storage/btree.rs:193-200` | `OverwriteCellState` |
| Cursor Traversal | `core/storage/state_machines.rs` | `RewindState`, `SeekToLastState`, etc. |
| Node Balancing | `core/storage/btree.rs` | Balance after insert/delete |

**Important Constants:**
```rust
// From btree.rs:104-117
pub const BTCURSOR_MAX_DEPTH: usize = 20;           // Max tree depth
pub const MAX_SIBLING_PAGES_TO_BALANCE: usize = 3;  // Balancing window
pub const MAX_NEW_SIBLING_PAGES_AFTER_BALANCE: usize = 5;
```

### Page Cache (SIEVE Algorithm)

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| Cache Structure | `core/storage/page_cache.rs:71-80` | `PageCache` struct |
| Cache Entry | `core/storage/page_cache.rs:24-60` | `PageCacheEntry` with `ref_bit` |
| SIEVE Eviction | `core/storage/page_cache.rs:129-150` | `advance_clock_hand()` |
| Default Capacity | `core/storage/page_cache.rs:11` | 100,000 pages |

**SIEVE Implementation Pattern:**
```rust
// From page_cache.rs
struct PageCacheEntry {
    key: PageCacheKey,
    page: PageRef,
    ref_bit: u8,  // 0-3, bumped on access, decremented on sweep
    link: LinkedListLink,
}

// Reference counting: 0 = evictable, 1-3 = recently used
const CLEAR: u8 = 0;
const REF_MAX: u8 = 3;
```

## Durability Layer

### Write-Ahead Log (WAL)

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| WAL Header | `core/storage/sqlite3_ondisk.rs` | `WalHeader`, `WAL_MAGIC_BE/LE` |
| Checkpoint Modes | `core/storage/wal.rs:73-104` | `CheckpointMode` enum |
| Checkpoint Result | `core/storage/wal.rs:34-71` | `CheckpointResult` struct |
| Read/Write Lock | `core/storage/wal.rs:106-200` | `TursoRwLock` (64-bit atomic) |
| Frame Format | `core/storage/sqlite3_ondisk.rs` | `WAL_FRAME_HEADER_SIZE`, `WAL_HEADER_SIZE` |

**Checkpoint Modes:**
```rust
// From wal.rs:73-104
pub enum CheckpointMode {
    Passive { upper_bound_inclusive: Option<u64> },  // Non-blocking
    Full,      // Wait for no writers, checkpoint all
    Restart,   // Full + block until readers done
    Truncate { upper_bound_inclusive: Option<u64> }, // Restart + truncate
}
```

**Custom Lock for WAL:**
```rust
// From wal.rs:106-125 - 64-bit atomic RwLock
pub struct TursoRwLock(AtomicU64);
// [63:32] Value bits, [31:1] Reader count, [0] Writer bit
```

## Security Layer

### Encryption

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| Encryption Key | `core/storage/encryption.rs:76-148` | `EncryptionKey` enum |
| Key from Hex | `core/storage/encryption.rs:90-109` | `from_hex_string()` |
| Key Zeroing | `core/storage/encryption.rs:149-150` | `Drop` trait implementation |
| Page Layout | `core/storage/encryption.rs:26-39` | Encrypted page diagram |
| Header Format | `core/storage/encryption.rs:49-65` | "Turso" header for encrypted DBs |

**Page Encryption Layout:**
```
// From encryption.rs:26-39
Unencrypted Page              Encrypted Page
┌───────────────┐            ┌───────────────┐
│ Page Content  │            │   Encrypted   │
│ (4048 bytes)  │  ────────► │    Content    │
├───────────────┤            ├───────────────┤
│   Reserved    │            │    Tag (16)   │
│  (48 bytes)   │            ├───────────────┤
│               │            │   Nonce (32)  │
└───────────────┘            └───────────────┘
```

**Key Secure Zeroing:**
```rust
// From encryption.rs (inferred from Drop trait)
impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // Zero out key bytes
        match self {
            Self::Key128(key) => key.iter_mut().for_each(|b| *b = 0),
            Self::Key256(key) => key.iter_mut().for_each(|b| *b = 0),
        }
    }
}
```

**Note:** Turso uses external crates (`aegis`, `aes_gcm`). RedDB MUST implement AES-256-GCM from scratch using `crypto/aes_gcm.rs`.

## Vector Support

### Distance Metrics

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| Vector Types | `core/vector/vector_types.rs` | `Vector`, `VectorSparse`, `VectorType` |
| Cosine Distance | `core/vector/operations/distance_cos.rs:53-64` | `vector_f32_distance_cos_rust()` |
| L2 Distance | `core/vector/operations/distance_l2.rs` | Euclidean distance |
| Dot Product | `core/vector/operations/distance_dot.rs` | Dot product |
| Sparse Vectors | `core/vector/operations/distance_cos.rs:86-100` | `vector_f32_sparse_distance_cos()` |

**Pure Rust Cosine (for WASM/no SIMD):**
```rust
// From distance_cos.rs:53-64
fn vector_f32_distance_cos_rust(v1: &[f32], v2: &[f32]) -> f64 {
    let (mut dot, mut norm1, mut norm2) = (0.0, 0.0, 0.0);
    for (a, b) in v1.iter().zip(v2.iter()) {
        dot += a * b;
        norm1 += a * a;
        norm2 += b * b;
    }
    if norm1 == 0.0 || norm2 == 0.0 {
        return 0.0;
    }
    (1.0 - dot / (norm1 * norm2).sqrt()) as f64
}
```

**Sparse Vector Distance:**
```rust
// From distance_cos.rs:86-100
fn vector_f32_sparse_distance_cos(v1: VectorSparse<f32>, v2: VectorSparse<f32>) -> f64 {
    // Two-pointer merge of sorted index arrays
    // Only overlapping indices contribute to dot product
}
```

### IVF Index

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| IVF Structure | `core/index_method/toy_vector_sparse_ivf.rs` | IVF index implementation |
| Backing B-tree | `core/index_method/backing_btree.rs` | B-tree for vector storage |

**Note:** Turso's IVF implementation is in `toy_vector_sparse_ivf.rs` - intended as a reference/toy implementation. RedDB should implement a production-grade IVF with proper k-means clustering.

## Query Engine

### Incremental View Maintenance

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| Query Compiler | `core/incremental/compiler.rs` | Query plan compilation |
| Operators | `core/incremental/operator.rs` | Base operator traits |
| Filter | `core/incremental/filter_operator.rs` | Filter predicate evaluation |
| Aggregate | `core/incremental/aggregate_operator.rs` | SUM, COUNT, AVG, etc. |
| Join | `core/incremental/join_operator.rs` | Join operator |
| Cursor | `core/incremental/cursor.rs` | Result iteration |

## I/O Layer

### Platform-Specific I/O

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| Unix I/O | `core/io/unix.rs` | POSIX file operations |
| Windows I/O | `core/io/windows.rs` | Windows file operations |
| io_uring | `core/io/io_uring.rs` | Linux async I/O |
| Memory I/O | `core/io/memory.rs` | In-memory database |
| VFS Abstraction | `core/io/vfs.rs` | Virtual file system layer |

## Error Handling

| RedDB Component | Turso Reference File | Key Lines/Functions |
|-----------------|---------------------|---------------------|
| Error Types | `core/error.rs` | `LimboError` enum |
| Result Type | `core/error.rs` | `Result<T> = Result<T, LimboError>` |
| Corruption Detection | `core/storage/btree.rs` | `return_corrupt!` macro |

## Documentation & Manuals

| Topic | Turso Reference File |
|-------|---------------------|
| Encryption Guide | `cli/manuals/encryption.md` |
| Vector Search | `cli/manuals/vector.md` |
| Materialized Views | `cli/manuals/materialized-views.md` |
| MVCC Design | `docs/internals/mvcc/DESIGN.md` |
| Performance | `PERF.md` |

---

## Implementation Guidelines

### What to Copy vs Implement Fresh

**Copy Patterns/Approach:**
- Page header layout (proven by SQLite/Turso)
- SIEVE cache algorithm structure
- WAL record format
- Checkpoint modes
- Distance metric formulas

**Implement Fresh (due to zero-dependency rule):**
- All cryptography (AES-256-GCM, BLAKE2b, Argon2id)
- All I/O operations (use std::fs only)
- All threading (use std::thread, std::sync)
- Data serialization (no serde)

### Key Differences from Turso

| Aspect | Turso | RedDB |
|--------|-------|-------|
| Encryption Library | `aegis`, `aes_gcm` crates | `crypto/aes_gcm.rs` (from scratch) |
| KDF | Not in scope | Argon2id (from scratch) |
| Hash Function | Uses crate | BLAKE2b (from scratch) |
| Vector SIMD | `simsimd` crate | Loop unrolling only |
| Threading | `parking_lot`, `arc_swap` | `std::sync` only |
| Collections | `rustc_hash`, `roaring` | `std::collections` only |

### File Size Reference

| Component | Turso LOC | Estimated RedDB LOC |
|-----------|-----------|---------------------|
| btree.rs | 10,602 | ~4,000 (simplified) |
| pager.rs | 3,361 | ~1,500 |
| wal.rs | 3,582 | ~1,200 |
| encryption.rs | 1,550 | ~800 + argon2id (~600) |
| page_cache.rs | ~500 | ~300 |
| vector/distance | ~400 | ~200 |
| **Total** | **~20,000** | **~8,600** |

---

## Quick Reference Card

```
TURSO FILE → REDDB IMPLEMENTATION
═══════════════════════════════════════════════════════════════════

Page Structure:
  btree.rs:54-102         → src/storage/engine/page.rs
  pager.rs:136-152        → src/storage/engine/page.rs

Pager:
  pager.rs                → src/storage/engine/pager.rs
  buffer_pool.rs          → src/storage/engine/buffer-pool.rs

B-tree:
  btree.rs                → src/storage/btree.rs (enhance)
  sqlite3_ondisk.rs       → src/storage/engine/ondisk.rs

Cache:
  page_cache.rs           → src/storage/engine/page-cache.rs

WAL:
  wal.rs                  → src/storage/wal/writer.rs, reader.rs
  subjournal.rs           → src/storage/wal/checkpoint.rs

Encryption:
  encryption.rs           → src/storage/encryption/page-encryptor.rs
  (N/A - implement)       → src/storage/encryption/argon2id.rs
  (N/A - implement)       → src/storage/encryption/blake2b.rs

Vectors:
  vector/operations/*.rs  → src/storage/vector/distance.rs
  toy_vector_sparse_ivf.rs → src/storage/vector/ivf-index.rs
```
