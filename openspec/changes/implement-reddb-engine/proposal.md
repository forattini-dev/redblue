# Change: Implement RedDB - Complete Embedded Database Engine

## Why

redblue needs a **production-grade embedded database** to persist ALL security intelligence data (scans, requests, responses, logs, vectors, etc.). The current segment-based storage (`src/storage/segments/`) is insufficient for:

1. **Complex queries** - No B-tree indexing, no range queries, no joins
2. **Durability** - No WAL, no crash recovery, no ACID transactions
3. **Security** - No encryption at rest (critical for sensitive security data)
4. **Vector search** - No support for similarity search on embeddings
5. **Scalability** - In-memory indexes don't scale for large datasets

We've analyzed Turso/libSQL architecture (`docs/reference/turso/`) to learn patterns for building a proper database engine from scratch.

## What Changes

### Core Database Engine (**BREAKING** - replaces current storage)
- **Page-based storage** - 4KB aligned pages for efficient I/O
- **B-tree indexing** - O(log n) lookups and range queries
- **SIEVE cache** - Modern eviction algorithm (better than LRU)
- **WAL durability** - Write-ahead log with checkpointing
- **ACID transactions** - Commit, rollback, crash recovery

### Security Layer (NEW)
- **Per-page AES-256-GCM encryption** - Using existing `crypto/aes_gcm.rs`
- **Argon2id KDF** - Password-based key derivation (requires BLAKE2b from scratch)
- **Secure key management** - Volatile zeroing on drop
- **Three key input methods**:
  - Passphrase (Argon2id KDF)
  - Hex key (direct 32-byte)
  - Environment variable (`REDBLUE_DB_KEY`)

### Vector Support (NEW)
- **Dense/Sparse vector storage** - Float32 optimized
- **Distance metrics** - Cosine, L2, Dot product (from scratch)
- **IVF index** - Approximate nearest neighbor search
- **Table-vector relationships** - OneToOne, OneToMany

### Schema System (ENHANCED)
- **Type system** - Integer, Float, Text, Blob, Timestamp, IpAddr, Vector
- **Table definitions** - Primary keys, indexes, constraints
- **Migration support** - From current `.rdb` format

### Query Engine (ENHANCED)
- **Filter predicates** - Eq, Lt, Gt, Between, Like, And, Or
- **Sorting** - Multi-column order by
- **Similarity search** - Vector nearest neighbors
- **Joins** - Table-vector relationships

## Impact

### Affected Specs
- `specs/storage` (NEW capability - to be created)

### Affected Code
- `src/storage/` - Major restructuring
  - Keep: `segments/` for migration compatibility
  - NEW: `reddb/`, `engine/`, `encryption/`, `vector/`, `query/`
- `src/crypto/` - Add BLAKE2b, Argon2id
- `src/cli/commands/` - Update database commands

### Dependencies
- **ZERO new external crates** - All implemented from scratch
- Uses existing: AES-256-GCM (`crypto/aes_gcm.rs`), SHA-256 (`crypto/sha256.rs`), HKDF (`crypto/hkdf.rs`)

### Migration
- Backward compatible migration from current segment format
- Old `.rdb` files can be converted to new format

## Estimated Effort

| Phase | Description | Duration |
|-------|-------------|----------|
| 1 | Core Storage (Page, Pager, B-tree, SIEVE) | 4-6 weeks |
| 2 | Durability (WAL, Transactions) | 3-4 weeks |
| 3 | Security (Encryption, Argon2id) | 2-3 weeks |
| 4 | Schema System | 2-3 weeks |
| 5 | Vector Support | 3-4 weeks |
| 6 | Query Engine | 2-3 weeks |
| 7 | Migration & Integration | 2 weeks |
| **Total** | | **18-25 weeks** |

## Success Criteria

### Performance
- Insert: 50K records/second
- Query: <1ms for indexed lookups
- Vector search: <10ms for 100K vectors
- Page cache hit rate: >90% (SIEVE algorithm)

### Security
- AES-256-GCM per-page encryption
- Argon2id with 64MB memory cost (t=3, p=4)
- Volatile key zeroing (prevents memory dumps)
- AEAD authentication tags (integrity verification)

### Functionality
- All 7 existing segment types migrated
- Full ACID transactions with crash recovery
- Vector similarity search with IVF indexing
- Type-safe schema with migrations
