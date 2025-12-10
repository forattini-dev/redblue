# Implementation Tasks

## 1. Phase 1: Core Storage Engine ✅ COMPLETED

### 1.1 Page Structure ✅
- [x] 1.1.1 Create `src/storage/engine/mod.rs` with module exports
- [x] 1.1.2 Implement `src/storage/engine/page.rs`:
  - Page struct (4KB, page_type, cell_count, free_start, checksum, page_id, lsn, data)
  - PageType enum (Leaf, Interior, Overflow, Free)
  - Page serialization/deserialization
  - Checksum calculation (CRC32)
- [x] 1.1.3 Add page layout constants and cell encoding

### 1.2 Pager (Page I/O Manager) ✅
- [x] 1.2.1 Implement `src/storage/engine/pager.rs`:
  - File handle management
  - Page read/write operations
  - Page allocation/deallocation
  - Integration with PageCache
- [x] 1.2.2 Add header page format (magic bytes, version, page count, freelist head)

### 1.3 Page Cache (SIEVE Algorithm) ✅
- [x] 1.3.1 Implement `src/storage/engine/page_cache.rs`:
  - SIEVE eviction algorithm (NSDI '24 paper)
  - CacheEntry with visited bit
  - FIFO queue with eviction hand
  - Capacity management (100K pages default)
- [x] 1.3.2 Add cache statistics (hits, misses, evictions)

### 1.4 Free List ✅
- [x] 1.4.1 Implement `src/storage/engine/freelist.rs`:
  - Free page tracking
  - Page allocation from freelist
  - Page return to freelist

### 1.5 B-tree Engine ✅
- [x] 1.5.1 Enhance `src/storage/engine/btree.rs` for page-based storage:
  - BTree struct with pager reference
  - Interior node operations (key routing)
  - Leaf node operations (key-value storage)
- [x] 1.5.2 Implement B-tree operations:
  - get(key) -> Option<Value>
  - insert(key, value) -> Result<()>
  - delete(key) -> Result<bool>
  - range(start, end) -> BTreeCursor
- [x] 1.5.3 Implement node splitting and merging
- [x] 1.5.4 Add B-tree cursor for iteration

**Phase 1 Tests: 61 passing** ✅

## 2. Phase 2: Durability (WAL & Transactions) ✅ COMPLETED

### 2.1 WAL Writer ✅
- [x] 2.1.1 Implement `src/storage/wal/writer.rs`:
  - WAL file format (header, records, checksum)
  - WalRecord enum (Begin, Commit, Rollback, PageWrite, Checkpoint)
  - Append-only writes
  - fsync for durability
- [x] 2.1.2 Add WAL record serialization

### 2.2 WAL Reader ✅
- [x] 2.2.1 Implement `src/storage/wal/reader.rs`:
  - Read WAL from start
  - Parse WAL records
  - Corruption detection

### 2.3 Checkpointing ✅
- [x] 2.3.1 Implement `src/storage/wal/checkpoint.rs`:
  - Checkpoint trigger conditions
  - Flush dirty pages to database file
  - WAL truncation after checkpoint
  - Incremental checkpointing

### 2.4 Transaction Manager ✅
- [x] 2.4.1 Implement `src/storage/wal/transaction.rs`:
  - Transaction struct (id, database, write_set, state)
  - TxnState enum (Active, Committed, Aborted)
  - begin() -> Transaction
  - commit(self) -> Result<()>
  - rollback(self) -> Result<()>
- [x] 2.4.2 Add crash recovery from WAL (in Database.open)

### 2.5 Database Engine ✅
- [x] 2.5.1 Implement `src/storage/engine/database.rs`:
  - Database struct integrating Pager, WAL, Transactions
  - Crash recovery on open
  - Auto-checkpoint support

**Phase 2 Tests: 12 passing** ✅

## 3. Phase 3: Security Layer ✅ COMPLETED

### 3.1 Secure Key Management ✅
- [x] 3.1.1 Implement `src/storage/encryption/key.rs`:
  - SecureKey struct with Box<[u8; 32]>
  - Drop trait with volatile zeroing
  - Memory fence after zeroing
- [x] 3.1.2 Add key derivation methods:
  - from_passphrase(password, salt) via Argon2id
  - from_hex(hex_string)
  - from_env(var_name)

### 3.2 BLAKE2b (Required for Argon2id) ✅
- [x] 3.2.1 Implement `src/storage/encryption/blake2b.rs`:
  - RFC 7693 compliant implementation
  - BLAKE2b-256 and BLAKE2b-512
  - Variable output length support
  - Keyed hashing

### 3.3 Argon2id KDF ✅
- [x] 3.3.1 Implement `src/storage/encryption/argon2id.rs`:
  - RFC 9106 compliant implementation
  - Argon2id hybrid mode
  - Parameters: memory_cost (64MB), time_cost (3), parallelism (4)
  - derive_key(password, salt) -> [u8; 32]
- [x] 3.3.2 Add Argon2 memory management (blocks, lanes)

### 3.4 Page Encryption ✅
- [x] 3.4.1 Implement `src/storage/encryption/page_encryptor.rs`:
  - Per-page AES-256-GCM encryption (using crypto/aes_gcm.rs)
  - Unique nonce per page (page_id + counter)
  - AEAD authentication tag verification
  - encrypt_page(page_id, plaintext) -> Vec<u8>
  - decrypt_page(page_id, ciphertext) -> Result<Vec<u8>>

### 3.5 Encrypted File Header ✅
- [x] 3.5.1 Implement `src/storage/encryption/header.rs`:
  - Salt for KDF (32 bytes)
  - Key verification data
  - Encryption parameters
  - Version information

### 3.6 Encrypted Pager ✅
- [x] 3.6.1 Implement `src/storage/engine/encrypted-pager.rs`:
  - Transparent page encryption/decryption
  - Encryption marker "RDBE" in page 0
  - Key validation on database open
  - Integration with Pager read/write methods

**Phase 3 Tests: 11 passing** ✅

---

## 4. Phase 4: Schema System ✅ COMPLETED

### 4.1 Type System ✅
- [x] 4.1.1 Implement `src/storage/schema/types.rs`:
  - DataType enum (Integer, UnsignedInteger, Float, Text, Blob, Boolean, Timestamp, Duration, IpAddr, MacAddr, Vector, Json, Uuid)
  - Value enum for typed values with full serialization
  - Row struct for tuples of values
  - LEB128 varint encoding for variable-length data
  - Type metadata (fixed_size, is_indexable, is_orderable)

### 4.2 Table Definition ✅
- [x] 4.2.1 Implement `src/storage/schema/table.rs`:
  - TableDef struct (name, columns, primary_key, indexes, constraints, version, timestamps)
  - ColumnDef struct (name, data_type, nullable, default, vector_dim, metadata)
  - IndexDef struct (name, columns, index_type, unique)
  - IndexType enum (BTree, Hash, IvfFlat, Hnsw)
  - Constraint struct with ConstraintType enum (PrimaryKey, Unique, ForeignKey, Check, NotNull)
  - Full binary serialization with "RTBL" magic header

### 4.3 Schema Registry ✅
- [x] 4.3.1 Implement `src/storage/schema/registry.rs`:
  - SchemaRegistry with table storage and versioning
  - create_table(def), drop_table(name)
  - add_column, drop_column, create_index, drop_index
  - rename_table for schema evolution
  - Migration tracking with MigrationOp enum
  - Full binary serialization with "RSCH" magic header

**Phase 4 Tests: 33 passing** ✅

## 5. Phase 5: Vector Support ✅ COMPLETED

### 5.1 Vector Types ✅
- [x] 5.1.1 Implement `src/storage/vector/types.rs`:
  - DenseVector (fixed dimensions, packed f32 storage)
  - SparseVector (indices + values for sparse data)
  - SearchResult with Ord for BinaryHeap usage
  - Serialization/deserialization for persistence

### 5.2 Dense Vector Storage ✅
- [x] 5.2.1 Implement `src/storage/vector/dense.rs`:
  - DenseVectorStorage struct with packed float32
  - ID-to-offset HashMap for O(1) lookup
  - Batch operations (add_batch, iter)
  - Binary serialization

### 5.3 Distance Metrics ✅
- [x] 5.3.1 Implement `src/storage/vector/distance.rs`:
  - L2 distance (Euclidean) and L2 squared
  - Cosine distance and cosine similarity
  - Dot product (inner product)
  - Manhattan distance (L1)
- [x] 5.3.2 Add SIMD-like optimizations (4-element loop unrolling)

### 5.4 Flat Index (Exact Search) ✅
- [x] 5.4.1 Implement `src/storage/vector/flat_index.rs`:
  - Brute-force k-NN search with BinaryHeap
  - Range search (threshold-based)
  - Batch queries
  - Serialization/deserialization

### 5.5 IVF Index (Approximate Search) ✅
- [x] 5.5.1 Implement `src/storage/vector/ivf_index.rs`:
  - K-means++ clustering for centroids
  - Inverted lists per cluster
  - n_probes parameter for accuracy/speed tradeoff
  - train(vectors, max_iterations) for centroid initialization
  - search(query, k, n_probes) -> Vec<SearchResult>
  - Serialization/deserialization

**Phase 5 Tests: 67 passing** ✅

## 6. Phase 6: Query Engine

### 6.1 Query Executor
- [ ] 6.1.1 Implement `src/storage/query/executor.rs`:
  - Execute query plans
  - Fetch results from B-tree
  - Apply filters, sorting, limits

### 6.2 Filter Predicates
- [ ] 6.2.1 Implement `src/storage/query/filter.rs`:
  - Filter enum (Eq, Lt, Gt, Le, Ge, Between, Like, In, And, Or, Not)
  - Filter evaluation on rows
  - Index pushdown optimization

### 6.3 Sorting
- [ ] 6.3.1 Implement `src/storage/query/sort.rs`:
  - OrderBy struct (columns, directions)
  - In-memory sorting
  - External sorting for large result sets

### 6.4 Similarity Search
- [ ] 6.4.1 Implement `src/storage/query/similarity.rs`:
  - NearestNeighbors filter integration
  - Join with vector tables
  - Result ranking by distance

### 6.5 Query Builder API
- [ ] 6.5.1 Enhance `src/storage/query.rs`:
  - SelectQuery builder pattern
  - Fluent API for filters, ordering, limits
  - Type-safe column references

## 7. Phase 7: Migration & Integration

### 7.1 Segment Migration
- [ ] 7.1.1 Implement `src/storage/segments/migration.rs`:
  - Read old .rdb segment format
  - Convert to new schema/tables
  - Preserve all existing data
- [ ] 7.1.2 Add migration progress tracking

### 7.2 Database API
- [ ] 7.2.1 Implement `src/storage/reddb/database.rs`:
  - Database::open(path) -> Result<Database>
  - Database::open_encrypted(path, key) -> Result<Database>
  - High-level CRUD operations
  - Connection pooling (internal)

### 7.3 CLI Integration
- [ ] 7.3.1 Update `src/cli/commands/` for new database:
  - Update database query commands
  - Add encryption key input options
  - Update export/import commands
- [ ] 7.3.2 Add `rb database` subcommands:
  - `rb database open` - Open/create database
  - `rb database migrate` - Migrate old format
  - `rb database query` - Execute queries
  - `rb database vector-search` - Similarity search

### 7.4 Testing
- [ ] 7.4.1 Add unit tests for each component
- [ ] 7.4.2 Add integration tests:
  - CRUD operations
  - Transaction rollback/recovery
  - Encryption/decryption
  - Vector search accuracy
- [ ] 7.4.3 Add benchmark tests:
  - Insert throughput
  - Query latency
  - Vector search performance

---

## Progress Summary

| Phase | Description | Status | Tests |
|-------|-------------|--------|-------|
| 1 | Core Storage Engine | ✅ Complete | 61 |
| 2 | Durability (WAL/Tx) | ✅ Complete | 12 |
| 3 | Security (Encryption) | ✅ Complete | 11 |
| 4 | Schema System | ✅ Complete | 33 |
| 5 | Vector Support | ✅ Complete | 67 |
| 6 | Query Engine | ⏳ Pending | - |
| 7 | Migration & Integration | ⏳ Pending | - |

**Total Tests Passing: 184**
