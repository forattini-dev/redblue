# Design: RedDB Embedded Database Engine

## Context

redblue needs to persist all security intelligence data it generates. The current storage (`src/storage/segments/`) uses a simple binary format with 7 segment types but lacks:
- B-tree indexing for fast queries
- WAL for durability and crash recovery
- Encryption for sensitive data
- Vector storage for embeddings/similarity search

We analyzed Turso/libSQL (`docs/reference/turso/`) to understand SQLite-like database architecture:
- 163K+ lines of Rust code
- Page-based storage with B-tree indexes
- WAL with checkpointing
- AES-GCM encryption support
- SIEVE cache algorithm

**Key Turso Reference Files (see [turso-references.md](./turso-references.md) for complete mapping):**
- `core/storage/btree.rs` - B-tree implementation (~10K LOC)
- `core/storage/pager.rs` - Page I/O and management (~3.3K LOC)
- `core/storage/wal.rs` - Write-ahead log (~3.5K LOC)
- `core/storage/page_cache.rs` - SIEVE cache (~500 LOC)
- `core/storage/encryption.rs` - Per-page encryption (~1.5K LOC)
- `core/vector/operations/` - Distance metrics

**Constraints:**
- ZERO external dependencies (project rule)
- Must use existing crypto primitives (`crypto/aes_gcm.rs`, `crypto/sha256.rs`, `crypto/hkdf.rs`)
- Implement BLAKE2b from scratch for Argon2id KDF
- Support migration from current `.rdb` format

## Goals / Non-Goals

### Goals
- Complete embedded database with ACID transactions
- Per-page AES-256-GCM encryption at rest
- B-tree indexing with O(log n) operations
- Vector storage with similarity search
- High performance (50K inserts/sec, <1ms indexed queries)
- Crash recovery via WAL
- Migration from existing segment format

### Non-Goals
- SQL language parser (use builder API instead)
- Client-server architecture (embedded only)
- Distributed/replicated storage
- Real-time streaming replication
- Multi-tenant isolation

## Decisions

### Decision 1: Page Size = 4KB
**What:** Use 4096-byte pages as the fundamental storage unit.
**Why:**
- Aligns with filesystem block size (most efficient I/O)
- Matches SSD page size (4KB or multiples)
- SQLite/Turso use 4KB by default
- Good balance between metadata overhead and usable space

**Alternatives considered:**
- 8KB pages: Better for large rows, but wastes space for small records
- Variable pages: Complex implementation, poor cache utilization

### Decision 2: SIEVE Cache Algorithm
**What:** Use SIEVE (NSDI '24) instead of LRU for page cache.
**Why:**
- Simpler implementation than LRU (no doubly-linked list)
- Better hit rate than LRU (proven in research)
- O(1) operations for lookup, insert, evict
- Single pass eviction (no promotion on access)

> **Turso Reference:** See `core/storage/page_cache.rs:24-60` for `PageCacheEntry` with `ref_bit` counter (0-3 scale) and `core/storage/page_cache.rs:71-80` for `PageCache` struct.

**Implementation:**
```rust
struct PageCache {
    entries: HashMap<u32, CacheEntry>,  // page_id -> entry
    fifo: VecDeque<u32>,                // insertion order
    hand: usize,                        // eviction pointer
    capacity: usize,
}

struct CacheEntry {
    page: Page,
    visited: bool,  // Set on access, cleared during eviction sweep
}

// SIEVE eviction: sweep from hand, skip if visited (clear flag), evict first non-visited
```

**Alternatives considered:**
- LRU: Requires doubly-linked list, O(n) worst case for some operations
- CLOCK: Similar to SIEVE but slightly worse hit rate
- ARC: Complex, patent encumbered

### Decision 3: WAL with Force-on-Commit
**What:** Write-ahead log with fsync on transaction commit.
**Why:**
- Durability guarantee: committed = persisted
- Crash recovery: replay WAL to recover
- Performance: sequential writes to WAL, random writes batched to DB

> **Turso Reference:** See `core/storage/wal.rs:73-104` for `CheckpointMode` enum (Passive, Full, Restart, Truncate) and `core/storage/wal.rs:106-200` for `TursoRwLock` - a custom 64-bit atomic read-write lock.

**WAL Record Format:**
```rust
enum WalRecord {
    Begin { txn_id: u64 },
    PageWrite { txn_id: u64, page_id: u32, old_data: Vec<u8>, new_data: Vec<u8> },
    Commit { txn_id: u64 },
    Rollback { txn_id: u64 },
    Checkpoint { lsn: u64 },
}
```

**Alternatives considered:**
- No-force commit (async): Better performance, but data loss on crash
- Shadow paging: Complex, bad for concurrent access

### Decision 4: Per-Page Encryption with AES-256-GCM
**What:** Encrypt each page independently using AES-256-GCM with unique nonce.
**Why:**
- AEAD provides confidentiality + integrity
- Per-page encryption allows random access (no need to decrypt entire file)
- Existing `crypto/aes_gcm.rs` implementation
- Industry standard (SQLCipher, Turso use similar approach)

> **Turso Reference:** See `core/storage/encryption.rs:26-39` for encrypted page layout diagram (content + tag + nonce) and `core/storage/encryption.rs:76-148` for `EncryptionKey` with secure zeroing on drop. **Note:** Turso uses external crates; RedDB implements from scratch.

**Nonce derivation:**
```rust
// 12-byte nonce = 8-byte page_id + 4-byte write_counter
fn derive_nonce(page_id: u64, write_counter: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&page_id.to_le_bytes());
    nonce[8..].copy_from_slice(&write_counter.to_le_bytes());
    nonce
}
```

**Alternatives considered:**
- Full-file encryption: No random access, must decrypt entire DB
- Block cipher (AES-CBC): No integrity protection
- ChaCha20-Poly1305: Not implemented in our crypto yet

### Decision 5: Argon2id for Password KDF
**What:** Use Argon2id (RFC 9106) to derive encryption key from passphrase.
**Why:**
- Winner of Password Hashing Competition (PHC)
- Memory-hard: resists GPU/ASIC attacks
- Argon2id hybrid: best of Argon2d (GPU-resistant) and Argon2i (side-channel resistant)
- Requires BLAKE2b (we'll implement from scratch)

**Parameters:**
```rust
struct Argon2idParams {
    memory_cost: u32,   // 64 MB (65536 KB)
    time_cost: u32,     // 3 iterations
    parallelism: u32,   // 4 lanes
    output_len: usize,  // 32 bytes
}
```

**Alternatives considered:**
- PBKDF2: CPU-bound only, vulnerable to GPU attacks
- bcrypt: Limited to 72 bytes input, lower memory cost
- scrypt: Complex, Argon2 is newer/better

### Decision 6: B-tree with Variable-Length Keys
**What:** B+ tree with variable-length keys stored in leaf pages.
**Why:**
- Standard for database indexing (SQLite, PostgreSQL, etc.)
- O(log n) search, insert, delete
- Range queries via cursor iteration
- Efficient for disk-based storage (minimize I/O)

> **Turso Reference:** See `core/storage/btree.rs:54-102` for B-tree page header offsets, `core/storage/btree.rs:104-117` for constants (`BTCURSOR_MAX_DEPTH=20`, `MAX_SIBLING_PAGES_TO_BALANCE=3`), and `core/storage/btree.rs:144-190` for `DeleteState` state machine.

**Node format:**
```
Leaf Page:
+--------+--------+--------+-----+--------+
| Header | Cell 1 | Cell 2 | ... | Cell N |
+--------+--------+--------+-----+--------+
         ^-- Cells grow from start
                                    Free space <--

Interior Page:
+--------+--------+--------+-----+--------+
| Header | Ptr0 | Key1 | Ptr1 | Key2 | ... |
+--------+--------+--------+-----+--------+
```

### Decision 7: IVF for Approximate Vector Search
**What:** Inverted File Index with k-means clustering.
**Why:**
- Good accuracy/speed tradeoff
- Simple to implement (compared to HNSW)
- Tunable via n_probes parameter
- Memory efficient (doesn't store graph)

> **Turso Reference:** See `core/vector/operations/distance_cos.rs:53-64` for pure Rust cosine distance implementation (no SIMD), `core/vector/operations/distance_cos.rs:86-100` for sparse vector distance, and `core/index_method/toy_vector_sparse_ivf.rs` for IVF reference.

**Training:**
1. Run k-means on sample vectors to find centroids
2. Assign each vector to nearest centroid
3. Build inverted list per centroid

**Search:**
1. Find n_probes nearest centroids to query
2. Search vectors in those clusters
3. Return top-k overall

**Alternatives considered:**
- Flat (brute force): O(n) search, fine for <10K vectors
- HNSW: Better accuracy, but complex graph construction
- Product Quantization: Requires training, complex

### Decision 8: Three Key Input Methods
**What:** Support passphrase, hex key, and environment variable.
**Why:**
- **Passphrase**: User-friendly, requires Argon2id KDF
- **Hex key**: Direct 32-byte key, for programmatic use
- **Environment variable**: CI/CD friendly, avoids key in command line

```rust
enum KeySource {
    Passphrase(String),           // Derive via Argon2id
    HexKey(String),               // Direct 32-byte hex
    EnvVar(String),               // Read from REDBLUE_DB_KEY
}
```

## Risks / Trade-offs

### Risk: BLAKE2b Implementation Complexity
**Mitigation:** BLAKE2b is well-documented (RFC 7693), ~500 LOC. Test against reference vectors.

### Risk: Argon2id Memory Usage
**Mitigation:** 64MB memory cost is high but acceptable. Make it configurable for low-memory environments.

### Risk: Performance vs. Durability
**Trade-off:** Force-on-commit ensures durability but adds latency (~1ms per commit for fsync).
**Mitigation:** Batch writes in transactions when possible.

### Risk: Migration Data Loss
**Mitigation:**
- Keep old format readable
- Verify migration with checksums
- Provide rollback option

## Migration Plan

### Phase 1: Parallel Operation
1. Implement new RedDB engine
2. Keep old segment storage functional
3. Test new engine in isolation

### Phase 2: Migration Tool
1. Add `rb database migrate <old.rdb> <new.rdb>` command
2. Read each segment type
3. Convert to new schema/tables
4. Verify with checksums

### Phase 3: Deprecation
1. Mark old segment code as deprecated
2. Update all CLI commands to use new engine
3. Remove old code in future release

### Rollback
- Keep old `.rdb` files unchanged during migration
- Migration creates new file, doesn't modify source
- Can revert by pointing to old file

## Open Questions

1. **Index Types**: Should we support secondary indexes on non-primary columns from the start?
   - Recommendation: Yes, implement basic secondary B-tree indexes

2. **Compression**: Should we compress pages before encryption?
   - Recommendation: No for v1, add zstd compression later

3. **Vector Index Persistence**: Store IVF centroids in database or rebuild on open?
   - Recommendation: Store in special metadata pages, avoid rebuild cost

4. **Concurrency**: Reader-writer locks or MVCC?
   - Recommendation: Simple RwLock for v1, MVCC is too complex

## Module Structure

```
src/storage/
├── mod.rs                      # Re-exports

# Core Engine
├── reddb/
│   ├── mod.rs                  # Database API
│   ├── database.rs             # Database handle
│   ├── transaction.rs          # ACID transactions
│   └── cursor.rs               # B-tree cursor

# Storage Engine
├── engine/
│   ├── mod.rs
│   ├── page.rs                 # 4KB page structure
│   ├── pager.rs                # Page read/write/cache
│   ├── page-cache.rs           # SIEVE eviction
│   └── freelist.rs             # Free page tracking

# Indexing
├── index/
│   ├── mod.rs
│   ├── btree.rs                # B-tree implementation
│   ├── btree-node.rs           # Node structure
│   └── btree-leaf.rs           # Leaf page layout

# WAL
├── wal/
│   ├── mod.rs
│   ├── writer.rs               # WAL writer
│   ├── reader.rs               # WAL reader
│   └── checkpoint.rs           # Checkpointing

# Security
├── encryption/
│   ├── mod.rs
│   ├── key.rs                  # SecureKey with volatile zeroing
│   ├── page-encryptor.rs       # Per-page AES-256-GCM
│   ├── argon2id.rs             # Password KDF
│   ├── blake2b.rs              # Required for Argon2id
│   └── header.rs               # Encrypted file header

# Schema
├── schema/
│   ├── mod.rs
│   ├── types.rs                # DataType enum
│   ├── table.rs                # TableDef
│   └── registry.rs             # Schema registry

# Vector Support
├── vector/
│   ├── mod.rs
│   ├── types.rs                # Dense, Sparse vectors
│   ├── dense.rs                # Dense vector storage
│   ├── distance.rs             # Cosine, L2, Dot
│   ├── flat-index.rs           # Exact search
│   ├── ivf-index.rs            # Approximate search
│   └── relation.rs             # Table-vector relationships

# Query Engine
├── query/
│   ├── mod.rs
│   ├── executor.rs             # Query execution
│   ├── filter.rs               # Filter predicates
│   ├── sort.rs                 # Sorting
│   └── similarity.rs           # Vector search

# Existing (keep for migration)
├── segments/
│   ├── ports.rs, subdomains.rs, ...
│   └── migration.rs            # Format migration
```

## Detailed File Format Specification

> **Turso Reference:** See `core/storage/pager.rs:136-152` for `PageInner` struct with flags, pin_count, and wal_tag. See `core/storage/sqlite3_ondisk.rs` for SQLite on-disk format compatibility.

### Database File Layout (.rdb)

```
┌─────────────────────────────────────────────────────────────────┐
│                    RedDB File Format v1                         │
├─────────────────────────────────────────────────────────────────┤
│ Offset 0x0000: Header Page (4096 bytes)                         │
│   ├─ Magic: "RDDB" (4 bytes)                                    │
│   ├─ Version: u32 (4 bytes) = 0x00010000                        │
│   ├─ Page Size: u32 (4 bytes) = 4096                            │
│   ├─ Page Count: u64 (8 bytes)                                  │
│   ├─ Freelist Head: u32 (4 bytes)                               │
│   ├─ Schema Root Page: u32 (4 bytes)                            │
│   ├─ WAL Checkpoint LSN: u64 (8 bytes)                          │
│   ├─ Flags: u32 (4 bytes)                                       │
│   │   ├─ Bit 0: Encrypted                                       │
│   │   ├─ Bit 1: Compressed                                      │
│   │   └─ Bits 2-31: Reserved                                    │
│   ├─ [If Encrypted] Salt: [u8; 32]                              │
│   ├─ [If Encrypted] Key Verification: [u8; 32]                  │
│   ├─ [If Encrypted] Argon2id Params:                            │
│   │   ├─ Memory Cost: u32 (KB)                                  │
│   │   ├─ Time Cost: u32                                         │
│   │   └─ Parallelism: u32                                       │
│   ├─ Creation Timestamp: i64 (Unix epoch)                       │
│   ├─ Last Modified: i64                                         │
│   ├─ Reserved: [u8; 3900]                                       │
│   └─ Header Checksum: u32 (CRC32)                               │
├─────────────────────────────────────────────────────────────────┤
│ Offset 0x1000: Page 1 (Schema Registry Root)                    │
│ Offset 0x2000: Page 2...                                        │
│ ...                                                             │
│ Offset N*0x1000: Page N                                         │
└─────────────────────────────────────────────────────────────────┘
```

### Page Structure (4096 bytes)

```rust
#[repr(C)]
pub struct PageHeader {
    pub page_type: u8,          // 0=Free, 1=BTreeLeaf, 2=BTreeInterior, 3=Overflow, 4=Vector
    pub flags: u8,              // Bit 0: dirty, Bit 1: pinned
    pub cell_count: u16,        // Number of cells in page
    pub free_start: u16,        // Offset to start of free space
    pub free_end: u16,          // Offset to end of free space (cell content area)
    pub page_id: u32,           // This page's ID
    pub parent_id: u32,         // Parent page (for B-tree navigation)
    pub right_child: u32,       // Rightmost child (interior pages) or next leaf (leaf pages)
    pub lsn: u64,               // Log Sequence Number (for WAL)
    pub checksum: u32,          // CRC32 of page content
    pub reserved: [u8; 4],      // Alignment padding
}
// Total header: 32 bytes

// Page layout:
// [Header: 32 bytes][Cell Pointers: 2*N bytes][Free Space][Cell Content Area]
//                                              ^           ^
//                                              |           |
//                                        free_start    free_end
```

### B-tree Cell Formats

```rust
// Leaf Cell (key-value pair)
struct LeafCell {
    key_size: u16,              // Size of key in bytes
    value_size: u32,            // Size of value in bytes (can be large)
    overflow_page: u32,         // If value > threshold, points to overflow chain
    key: [u8],                  // Variable-length key
    value: [u8],                // Variable-length value (inline if small)
}

// Interior Cell (key + child pointer)
struct InteriorCell {
    left_child: u32,            // Page ID of left subtree
    key_size: u16,              // Size of separator key
    key: [u8],                  // Separator key (copied from leaf)
}

// Overflow Page (for large values)
struct OverflowPage {
    next_page: u32,             // Next overflow page (0 if last)
    data_size: u16,             // Bytes used in this page
    data: [u8; 4058],           // Payload (4096 - header - metadata)
}
```

### WAL File Format (.rdb-wal)

```
┌─────────────────────────────────────────────────────────────────┐
│                    WAL File Format                              │
├─────────────────────────────────────────────────────────────────┤
│ WAL Header (32 bytes):                                          │
│   ├─ Magic: "RWAL" (4 bytes)                                    │
│   ├─ Version: u32                                               │
│   ├─ Database Size: u64 (pages at checkpoint)                   │
│   ├─ Checkpoint LSN: u64                                        │
│   ├─ Salt: [u8; 8] (for frame checksums)                        │
│   └─ Checksum: u32                                              │
├─────────────────────────────────────────────────────────────────┤
│ WAL Frame (4096 + 24 bytes each):                               │
│   ├─ Page ID: u32                                               │
│   ├─ Database Size: u32 (commit frame only)                     │
│   ├─ Salt1: u32                                                 │
│   ├─ Salt2: u32                                                 │
│   ├─ Checksum1: u32                                             │
│   ├─ Checksum2: u32                                             │
│   └─ Page Data: [u8; 4096]                                      │
└─────────────────────────────────────────────────────────────────┘
```

## BLAKE2b Algorithm Details (RFC 7693)

BLAKE2b is required for Argon2id. Implementation from scratch:

```rust
// BLAKE2b constants
const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

pub struct Blake2b {
    h: [u64; 8],           // State
    t: [u64; 2],           // Counter (bytes compressed)
    buf: [u8; 128],        // Buffer
    buf_len: usize,
    out_len: usize,        // Output length (32 or 64)
}

impl Blake2b {
    // G mixing function
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    // Compression function F
    fn compress(&mut self, block: &[u8; 128], last: bool) {
        let mut v = [0u64; 16];
        let mut m = [0u64; 16];

        // Initialize working vector
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&BLAKE2B_IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        if last { v[14] = !v[14]; }

        // Parse message block
        for i in 0..16 {
            m[i] = u64::from_le_bytes(block[i*8..(i+1)*8].try_into().unwrap());
        }

        // 12 rounds of mixing
        for round in 0..12 {
            let s = &SIGMA[round];
            Self::g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            Self::g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            Self::g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            Self::g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            Self::g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            Self::g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            Self::g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            Self::g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        // Finalize
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}
```

## Argon2id Algorithm Details (RFC 9106)

```rust
pub struct Argon2id {
    memory_cost: u32,      // Memory in KB (65536 = 64MB)
    time_cost: u32,        // Iterations (3)
    parallelism: u32,      // Lanes (4)
}

impl Argon2id {
    const BLOCK_SIZE: usize = 1024;  // 1KB blocks
    const SYNC_POINTS: u32 = 4;      // Slices per pass

    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> [u8; 32] {
        // 1. Compute H0 (initial 64-byte hash)
        let h0 = self.compute_h0(password, salt);

        // 2. Allocate memory (memory_cost KB)
        let block_count = (self.memory_cost / (self.parallelism * 4)) * (self.parallelism * 4);
        let lane_length = block_count / self.parallelism;
        let segment_length = lane_length / Self::SYNC_POINTS;

        let mut memory: Vec<[u8; Self::BLOCK_SIZE]> = vec![[0u8; Self::BLOCK_SIZE]; block_count as usize];

        // 3. Initialize first two blocks of each lane
        for lane in 0..self.parallelism {
            let block0 = self.h_prime(&h0, 0, lane);
            let block1 = self.h_prime(&h0, 1, lane);
            memory[(lane * lane_length) as usize] = block0;
            memory[(lane * lane_length + 1) as usize] = block1;
        }

        // 4. Fill memory (time_cost passes)
        for pass in 0..self.time_cost {
            for slice in 0..Self::SYNC_POINTS {
                for lane in 0..self.parallelism {
                    self.fill_segment(&mut memory, pass, lane, slice,
                                     lane_length, segment_length);
                }
            }
        }

        // 5. Finalize (XOR last blocks of all lanes, then H')
        let mut final_block = [0u8; Self::BLOCK_SIZE];
        for lane in 0..self.parallelism {
            let last_idx = ((lane + 1) * lane_length - 1) as usize;
            for i in 0..Self::BLOCK_SIZE {
                final_block[i] ^= memory[last_idx][i];
            }
        }

        self.h_prime_final(&final_block)
    }

    fn fill_segment(&self, memory: &mut [[u8; Self::BLOCK_SIZE]],
                    pass: u32, lane: u32, slice: u32,
                    lane_length: u32, segment_length: u32) {
        // Argon2id: first half of first pass uses Argon2i (data-independent)
        // second half and subsequent passes use Argon2d (data-dependent)
        let data_independent = pass == 0 && slice < Self::SYNC_POINTS / 2;

        for idx in 0..segment_length {
            let current_idx = lane * lane_length + slice * segment_length + idx;
            if pass == 0 && slice == 0 && idx < 2 { continue; } // Skip first two blocks

            // Compute reference block indices
            let (ref_lane, ref_idx) = if data_independent {
                self.index_argon2i(pass, lane, slice, idx, lane_length, segment_length)
            } else {
                self.index_argon2d(memory, pass, lane, slice, idx, lane_length, segment_length)
            };

            let prev_idx = if current_idx == lane * lane_length {
                (lane + 1) * lane_length - 1
            } else {
                current_idx - 1
            };

            // G compression: B[i] = G(B[i-1], B[ref])
            let new_block = self.compress_g(
                &memory[prev_idx as usize],
                &memory[(ref_lane * lane_length + ref_idx) as usize]
            );

            // XOR with previous value (passes > 0)
            if pass > 0 {
                for i in 0..Self::BLOCK_SIZE {
                    memory[current_idx as usize][i] ^= new_block[i];
                }
            } else {
                memory[current_idx as usize] = new_block;
            }
        }
    }

    fn compress_g(&self, x: &[u8; Self::BLOCK_SIZE], y: &[u8; Self::BLOCK_SIZE])
                  -> [u8; Self::BLOCK_SIZE] {
        // Blake2b-based compression function
        let mut r = [0u8; Self::BLOCK_SIZE];
        for i in 0..Self::BLOCK_SIZE {
            r[i] = x[i] ^ y[i];
        }

        // Apply permutation P (8 rows × 8 cols of 128-byte blocks)
        // Using Blake2b's G function on 16-byte groups
        self.permute_p(&mut r);

        // XOR with input
        for i in 0..Self::BLOCK_SIZE {
            r[i] ^= x[i] ^ y[i];
        }
        r
    }
}
```

## B-tree Split and Merge Details

```rust
impl BTree {
    /// Split a full leaf node into two nodes
    fn split_leaf(&mut self, page_id: u32) -> Result<(u32, Vec<u8>)> {
        let page = self.pager.get_page(page_id)?;
        let mid = page.cell_count / 2;

        // Allocate new page for right half
        let new_page_id = self.pager.allocate_page()?;
        let mut new_page = Page::new_leaf(new_page_id);

        // Move cells [mid..] to new page
        let mut median_key = Vec::new();
        for i in mid..page.cell_count {
            let cell = page.get_cell(i);
            if i == mid {
                median_key = cell.key.to_vec(); // Copy up to parent
            }
            new_page.insert_cell(&cell)?;
        }

        // Truncate original page
        let mut page = self.pager.get_page_mut(page_id)?;
        page.truncate_cells(mid);

        // Update sibling pointers
        new_page.right_sibling = page.right_sibling;
        page.right_sibling = new_page_id;

        self.pager.write_page(&new_page)?;

        Ok((new_page_id, median_key))
    }

    /// Split a full interior node
    fn split_interior(&mut self, page_id: u32) -> Result<(u32, Vec<u8>)> {
        let page = self.pager.get_page(page_id)?;
        let mid = page.cell_count / 2;

        let new_page_id = self.pager.allocate_page()?;
        let mut new_page = Page::new_interior(new_page_id);

        // Median key is pushed up (not copied)
        let median_key = page.get_cell(mid).key.to_vec();

        // Move cells [mid+1..] to new page
        for i in (mid + 1)..page.cell_count {
            let cell = page.get_cell(i);
            new_page.insert_cell(&cell)?;
        }

        // New page's leftmost child = median's right child
        new_page.left_child = page.get_cell(mid).right_child;

        // Truncate original page (remove median and right half)
        let mut page = self.pager.get_page_mut(page_id)?;
        page.truncate_cells(mid);

        self.pager.write_page(&new_page)?;

        Ok((new_page_id, median_key))
    }

    /// Merge two sibling nodes (inverse of split)
    fn merge_nodes(&mut self, left_id: u32, right_id: u32, parent_key: &[u8]) -> Result<()> {
        let right = self.pager.get_page(right_id)?;
        let mut left = self.pager.get_page_mut(left_id)?;

        // For interior nodes, demote parent key
        if left.page_type == PageType::Interior {
            left.insert_interior_cell(parent_key, right.left_child)?;
        }

        // Copy all cells from right to left
        for i in 0..right.cell_count {
            left.insert_cell(&right.get_cell(i))?;
        }

        // Update sibling pointer
        left.right_sibling = right.right_sibling;

        // Free the right page
        self.pager.free_page(right_id)?;

        Ok(())
    }

    /// Redistribute cells between siblings (avoid merge if possible)
    fn redistribute(&mut self, left_id: u32, right_id: u32, parent_key: &[u8])
                    -> Result<Vec<u8>> {
        let mut left = self.pager.get_page_mut(left_id)?;
        let mut right = self.pager.get_page_mut(right_id)?;

        let total_cells = left.cell_count + right.cell_count;
        let target_left = total_cells / 2;

        if left.cell_count < target_left {
            // Borrow from right
            while left.cell_count < target_left {
                let cell = right.remove_cell(0);
                left.insert_cell(&cell)?;
            }
        } else {
            // Lend to right
            while left.cell_count > target_left {
                let cell = left.remove_cell(left.cell_count - 1);
                right.insert_cell_at(0, &cell)?;
            }
        }

        // Return new separator key
        Ok(right.get_cell(0).key.to_vec())
    }
}
```

## Security Tables for redblue

Pre-defined schemas optimized for security intelligence:

```rust
pub fn create_default_schemas(db: &Database) -> Result<()> {
    // Hosts table - discovered hosts
    db.create_table(TableDef {
        name: "hosts".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("ip", IpAddr, Indexed, NotNull),
            col!("hostname", Text, Indexed),
            col!("mac_address", Text),
            col!("os_fingerprint", Text),
            col!("first_seen", Timestamp, NotNull),
            col!("last_seen", Timestamp, Indexed),
            col!("status", Text),  // "up", "down", "filtered"
        ],
        indexes: vec![
            index!("hosts_ip_idx", ["ip"], Unique),
            index!("hosts_last_seen_idx", ["last_seen"]),
        ],
    })?;

    // Ports table - open ports
    db.create_table(TableDef {
        name: "ports".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("host_id", U64, ForeignKey("hosts.id"), NotNull),
            col!("port", U16, NotNull),
            col!("protocol", Text, NotNull),  // "tcp", "udp"
            col!("state", Text, NotNull),     // "open", "closed", "filtered"
            col!("service", Text),
            col!("version", Text),
            col!("banner", Blob),
            col!("scanned_at", Timestamp, NotNull),
        ],
        indexes: vec![
            index!("ports_host_port_idx", ["host_id", "port", "protocol"], Unique),
            index!("ports_service_idx", ["service"]),
        ],
    })?;

    // HTTP Requests/Responses
    db.create_table(TableDef {
        name: "http_requests".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("host_id", U64, ForeignKey("hosts.id")),
            col!("method", Text, NotNull),
            col!("url", Text, NotNull, Indexed),
            col!("headers", Blob),            // CBOR-encoded
            col!("body", Blob),
            col!("timestamp", Timestamp, NotNull),
        ],
    })?;

    db.create_table(TableDef {
        name: "http_responses".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("request_id", U64, ForeignKey("http_requests.id"), NotNull),
            col!("status_code", U16, NotNull),
            col!("headers", Blob),
            col!("body", Blob),
            col!("body_hash", Blob),          // SHA-256
            col!("response_time_ms", U32),
        ],
    })?;

    // DNS Records
    db.create_table(TableDef {
        name: "dns_records".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("domain", Text, NotNull, Indexed),
            col!("record_type", Text, NotNull),  // "A", "AAAA", "MX", etc.
            col!("value", Text, NotNull),
            col!("ttl", U32),
            col!("queried_at", Timestamp, NotNull),
        ],
        indexes: vec![
            index!("dns_domain_type_idx", ["domain", "record_type"]),
        ],
    })?;

    // Subdomains
    db.create_table(TableDef {
        name: "subdomains".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("domain", Text, NotNull),
            col!("subdomain", Text, NotNull),
            col!("source", Text),             // "bruteforce", "crtsh", "passive"
            col!("resolved_ip", IpAddr),
            col!("discovered_at", Timestamp, NotNull),
        ],
        indexes: vec![
            index!("subdomains_domain_idx", ["domain"]),
            index!("subdomains_unique", ["domain", "subdomain"], Unique),
        ],
    })?;

    // TLS Certificates
    db.create_table(TableDef {
        name: "tls_certs".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("host_id", U64, ForeignKey("hosts.id")),
            col!("port", U16, NotNull),
            col!("serial_number", Text),
            col!("subject", Text),
            col!("issuer", Text),
            col!("not_before", Timestamp),
            col!("not_after", Timestamp),
            col!("san", Blob),                // JSON array of SANs
            col!("fingerprint_sha256", Blob),
            col!("raw_cert", Blob),           // DER-encoded
        ],
    })?;

    // Vulnerabilities
    db.create_table(TableDef {
        name: "vulnerabilities".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("host_id", U64, ForeignKey("hosts.id")),
            col!("port_id", U64, ForeignKey("ports.id")),
            col!("cve_id", Text, Indexed),
            col!("title", Text, NotNull),
            col!("severity", Text),           // "critical", "high", "medium", "low"
            col!("cvss_score", Float),
            col!("description", Text),
            col!("proof", Text),              // Evidence/PoC
            col!("discovered_at", Timestamp, NotNull),
        ],
    })?;

    // Credentials (encrypted column)
    db.create_table(TableDef {
        name: "credentials".into(),
        columns: vec![
            col!("id", U64, PrimaryKey, AutoIncrement),
            col!("host_id", U64, ForeignKey("hosts.id")),
            col!("service", Text),
            col!("username", Text),
            col!("password_encrypted", Blob), // Double-encrypted
            col!("source", Text),             // "bruteforce", "default", "leaked"
            col!("valid", Bool),
            col!("discovered_at", Timestamp),
        ],
    })?;

    // Vector table for host behavior embeddings
    db.create_vector_table(VectorTableDef {
        name: "host_embeddings".into(),
        dimensions: 128,
        dtype: VectorType::Float32Dense,
        index: IndexType::IVF { nlist: 100, nprobe: 10 },
        relation: Relation::OneToOne { table: "hosts", column: "id" },
    })?;

    // Vector table for request fingerprints
    db.create_vector_table(VectorTableDef {
        name: "request_fingerprints".into(),
        dimensions: 256,
        dtype: VectorType::Float32Dense,
        index: IndexType::Flat,  // Small dataset, exact search
        relation: Relation::OneToOne { table: "http_requests", column: "id" },
    })?;

    Ok(())
}
```

## Performance Benchmarks & Targets

| Operation | Target | Measurement Method |
|-----------|--------|-------------------|
| Sequential Insert | 50,000 rows/sec | 1M rows, single thread |
| Batch Insert (1000) | 200,000 rows/sec | 1M rows, batch commit |
| Primary Key Lookup | <100μs p99 | 10M rows, random access |
| Range Query (100 rows) | <1ms | 10M rows, indexed column |
| Full Table Scan | 500MB/s | In-memory pages |
| Vector Flat Search (10K) | <5ms | 128-dim, top-10 |
| Vector IVF Search (100K) | <10ms | 128-dim, nprobe=10, top-10 |
| Transaction Commit | <2ms | With fsync |
| Page Cache Hit | <1μs | SIEVE lookup |
| Page Encryption | <50μs/page | AES-256-GCM, 4KB |
| Argon2id KDF | 500-1000ms | 64MB, t=3, p=4 |

### Memory Targets

| Component | Memory Budget |
|-----------|---------------|
| Page Cache | 400MB (100K pages × 4KB) |
| B-tree Cursors | 1KB per cursor |
| Transaction Write Set | 10MB max |
| Vector Index (IVF) | centroids × dims × 4 bytes |
| WAL Buffer | 4MB |

## API Examples

```rust
// Open encrypted database
let db = Database::open_encrypted("target.rdb", KeySource::Passphrase("secret".into()))?;

// Create table
db.create_table(TableDef {
    name: "hosts".into(),
    columns: vec![
        ColumnDef { name: "ip".into(), data_type: DataType::IpAddr, nullable: false, .. },
        ColumnDef { name: "hostname".into(), data_type: DataType::Text, nullable: true, .. },
        ColumnDef { name: "ports".into(), data_type: DataType::Blob, nullable: true, .. },
    ],
    primary_key: vec!["ip".into()],
    ..
})?;

// Transaction
let txn = db.begin()?;
txn.insert("hosts", row![
    "ip" => IpAddr::from([192, 168, 1, 1]),
    "hostname" => "router",
])?;
txn.commit()?;

// Query
let results = db.select("hosts")
    .filter(Filter::Like("hostname".into(), "%server%".into()))
    .order_by("ip", Ascending)
    .limit(10)
    .fetch()?;

// Vector search
let similar = db.vector_search("host_embeddings")
    .query(&query_vector)
    .top_k(10)
    .distance(Distance::Cosine)
    .fetch()?;
```
