## ADDED Requirements

### Requirement: Page-Based Storage Engine
The system SHALL provide a page-based storage engine with 4KB aligned pages for efficient disk I/O and memory management.

#### Scenario: Create new database file
- **WHEN** user opens a non-existent database path
- **THEN** the system creates a new database file with header page
- **AND** initializes page 0 with magic bytes, version, and metadata

#### Scenario: Read page from disk
- **WHEN** a page is requested that is not in cache
- **THEN** the system reads 4096 bytes from the correct offset
- **AND** verifies the page checksum
- **AND** returns the page data

#### Scenario: Write page to disk
- **WHEN** a modified page is flushed
- **THEN** the system calculates the page checksum
- **AND** writes 4096 bytes to the correct offset
- **AND** ensures durability via fsync

### Requirement: SIEVE Page Cache
The system SHALL implement a SIEVE-based page cache for efficient page eviction with better hit rates than LRU.

#### Scenario: Cache hit
- **WHEN** a cached page is accessed
- **THEN** the system returns the page immediately
- **AND** marks the cache entry as visited

#### Scenario: Cache miss with available space
- **WHEN** a page is not in cache and cache has space
- **THEN** the system reads the page from disk
- **AND** inserts it into the cache

#### Scenario: Cache eviction
- **WHEN** cache is full and a new page needs insertion
- **THEN** the system sweeps from the eviction hand
- **AND** skips entries with visited=true (clearing the flag)
- **AND** evicts the first entry with visited=false

### Requirement: B-tree Indexing
The system SHALL provide B-tree indexing for O(log n) key lookups, insertions, and range queries.

#### Scenario: Insert key-value pair
- **WHEN** a new key-value pair is inserted
- **THEN** the system traverses the B-tree to find the correct leaf
- **AND** inserts the entry maintaining sorted order
- **AND** splits the node if it exceeds capacity

#### Scenario: Lookup by key
- **WHEN** a key is queried
- **THEN** the system traverses interior nodes using key comparisons
- **AND** returns the value from the leaf node if found
- **AND** returns None if the key does not exist

#### Scenario: Range query
- **WHEN** a range query is executed with start and end keys
- **THEN** the system returns a cursor positioned at the start
- **AND** the cursor iterates through all keys in the range in sorted order

### Requirement: Write-Ahead Log (WAL)
The system SHALL implement a write-ahead log for durability and crash recovery with force-on-commit semantics.

#### Scenario: Transaction commit
- **WHEN** a transaction is committed
- **THEN** all WAL records are written to disk
- **AND** fsync is called to ensure durability
- **AND** the transaction is marked as committed

#### Scenario: Crash recovery
- **WHEN** the database is opened after a crash
- **THEN** the system reads the WAL from the beginning
- **AND** replays committed transactions
- **AND** rolls back uncommitted transactions

#### Scenario: Checkpoint
- **WHEN** the WAL reaches the checkpoint threshold
- **THEN** dirty pages are flushed to the main database file
- **AND** the WAL is truncated
- **AND** checkpoint LSN is recorded

### Requirement: ACID Transactions
The system SHALL provide ACID transactions with commit and rollback support.

#### Scenario: Successful commit
- **WHEN** a transaction executes operations and commits
- **THEN** all changes are persisted atomically
- **AND** the changes are visible to subsequent transactions

#### Scenario: Rollback
- **WHEN** a transaction is rolled back
- **THEN** all changes made by the transaction are undone
- **AND** the database state returns to before the transaction

#### Scenario: Isolation
- **WHEN** multiple transactions run concurrently
- **THEN** each transaction sees a consistent view of the database
- **AND** changes from uncommitted transactions are not visible

### Requirement: Per-Page Encryption
The system SHALL support per-page AES-256-GCM encryption with unique nonces per page write.

#### Scenario: Write encrypted page
- **WHEN** a page is written to an encrypted database
- **THEN** the system derives a unique nonce from page_id and write_counter
- **AND** encrypts the page data with AES-256-GCM
- **AND** appends the authentication tag

#### Scenario: Read encrypted page
- **WHEN** a page is read from an encrypted database
- **THEN** the system verifies the authentication tag
- **AND** decrypts the page data
- **AND** returns an error if verification fails

#### Scenario: Key derivation from passphrase
- **WHEN** a database is opened with a passphrase
- **THEN** the system derives the encryption key using Argon2id
- **AND** uses the stored salt from the database header
- **AND** verifies the key against stored verification data

### Requirement: Secure Key Management
The system SHALL provide secure key management with volatile zeroing and multiple input methods.

#### Scenario: Key zeroing on drop
- **WHEN** a SecureKey is dropped
- **THEN** the key bytes are overwritten with zeros using volatile writes
- **AND** a memory fence ensures the writes are not optimized away

#### Scenario: Key from passphrase
- **WHEN** KeySource::Passphrase is provided
- **THEN** the system derives the key using Argon2id with RFC 9106 parameters
- **AND** uses BLAKE2b for the internal compression function

#### Scenario: Key from hex string
- **WHEN** KeySource::HexKey is provided
- **THEN** the system parses the 64-character hex string
- **AND** validates it represents exactly 32 bytes

#### Scenario: Key from environment variable
- **WHEN** KeySource::EnvVar is provided
- **THEN** the system reads the key from the specified environment variable
- **AND** supports both hex format and base64 encoding

### Requirement: Schema System
The system SHALL provide a type-safe schema system with table definitions and column types.

#### Scenario: Create table
- **WHEN** a table definition is provided
- **THEN** the system validates column types and constraints
- **AND** stores the schema in the schema registry
- **AND** creates the underlying B-tree for the table

#### Scenario: Type validation
- **WHEN** a value is inserted into a column
- **THEN** the system validates the value matches the column type
- **AND** returns an error for type mismatches

#### Scenario: Primary key enforcement
- **WHEN** a row is inserted with a duplicate primary key
- **THEN** the system returns a constraint violation error
- **AND** does not modify the existing row

### Requirement: Vector Storage
The system SHALL provide optimized storage for dense vectors with float32 precision.

#### Scenario: Store dense vector
- **WHEN** a dense vector is inserted
- **THEN** the system stores it in packed float32 format
- **AND** maps the vector ID to storage offset

#### Scenario: Retrieve vector
- **WHEN** a vector ID is queried
- **THEN** the system retrieves the packed data
- **AND** returns the vector as a slice of f32 values

### Requirement: Vector Distance Metrics
The system SHALL provide distance metric calculations for vector similarity search.

#### Scenario: Cosine distance
- **WHEN** cosine distance is calculated between two vectors
- **THEN** the system computes 1 - (dot(a,b) / (||a|| * ||b||))
- **AND** returns 0.0 for identical normalized vectors
- **AND** returns 2.0 for opposite vectors

#### Scenario: L2 (Euclidean) distance
- **WHEN** L2 distance is calculated between two vectors
- **THEN** the system computes sqrt(sum((a[i] - b[i])^2))
- **AND** returns 0.0 for identical vectors

#### Scenario: Dot product
- **WHEN** dot product is calculated between two vectors
- **THEN** the system computes sum(a[i] * b[i])
- **AND** uses loop unrolling for performance

### Requirement: IVF Vector Index
The system SHALL provide an IVF (Inverted File) index for approximate nearest neighbor search.

#### Scenario: Build IVF index
- **WHEN** vectors are added to an IVF-indexed table
- **THEN** the system assigns each vector to the nearest centroid
- **AND** stores the vector in the corresponding inverted list

#### Scenario: IVF search
- **WHEN** a similarity search is executed
- **THEN** the system finds the n_probes nearest centroids to the query
- **AND** searches vectors in those clusters
- **AND** returns the top-k overall results

#### Scenario: Train centroids
- **WHEN** the IVF index is trained on a vector set
- **THEN** the system runs k-means clustering
- **AND** stores the centroids for future searches

### Requirement: Query Engine
The system SHALL provide a query engine with filter predicates, sorting, and limits.

#### Scenario: Filter by equality
- **WHEN** a query includes Filter::Eq(column, value)
- **THEN** only rows where column equals value are returned

#### Scenario: Range filter
- **WHEN** a query includes Filter::Between(column, low, high)
- **THEN** only rows where low <= column <= high are returned

#### Scenario: Sorting
- **WHEN** a query includes OrderBy(column, direction)
- **THEN** results are sorted by the specified column
- **AND** direction can be Ascending or Descending

#### Scenario: Limit
- **WHEN** a query includes limit(n)
- **THEN** at most n rows are returned

### Requirement: Segment Migration
The system SHALL support migration from the legacy segment-based storage format.

#### Scenario: Migrate ports segment
- **WHEN** migration is run on a legacy .rdb file with ports data
- **THEN** port scan results are converted to the new schema
- **AND** data integrity is verified with checksums

#### Scenario: Migrate all segments
- **WHEN** full migration is executed
- **THEN** all 7 segment types (Ports, Subdomains, WHOIS, TLS, DNS, HTTP, Hosts) are migrated
- **AND** a migration report shows success/failure counts

#### Scenario: Verify migration
- **WHEN** migration completes
- **THEN** the old and new databases have equivalent data
- **AND** queries return identical results

### Requirement: Database File Format
The system SHALL use a well-defined binary file format with magic bytes, versioning, and checksums.

#### Scenario: Create database with magic bytes
- **WHEN** a new database is created
- **THEN** the file starts with magic bytes "RDDB" (0x52 0x44 0x44 0x42)
- **AND** version field is 0x00010000 (v1.0)
- **AND** page size is stored as 4096

#### Scenario: Detect corrupted database
- **WHEN** a database file is opened with invalid magic bytes
- **THEN** the system returns error "Invalid database format"
- **AND** does not attempt to read further

#### Scenario: Version compatibility check
- **WHEN** a database with version > supported is opened
- **THEN** the system returns error "Database version not supported"
- **AND** suggests upgrading redblue

### Requirement: Overflow Pages
The system SHALL support overflow pages for values larger than the inline threshold.

#### Scenario: Store large value
- **WHEN** a value exceeds 1KB (inline threshold)
- **THEN** the system allocates overflow pages
- **AND** stores the first 1KB inline
- **AND** chains remaining data through overflow pages

#### Scenario: Read large value
- **WHEN** a value with overflow pages is read
- **THEN** the system follows the overflow chain
- **AND** reconstructs the complete value
- **AND** returns it as a contiguous byte slice

#### Scenario: Delete large value
- **WHEN** a row with overflow pages is deleted
- **THEN** all overflow pages are returned to the freelist
- **AND** the leaf cell is removed

### Requirement: Freelist Management
The system SHALL maintain a freelist of available pages for reuse.

#### Scenario: Allocate from freelist
- **WHEN** a new page is needed and freelist is not empty
- **THEN** the system removes a page from the freelist head
- **AND** returns that page for use
- **AND** updates the freelist head pointer

#### Scenario: Return page to freelist
- **WHEN** a page is freed
- **THEN** the system adds it to the freelist head
- **AND** marks the page as type Free
- **AND** clears sensitive data from the page

#### Scenario: Extend database file
- **WHEN** a new page is needed and freelist is empty
- **THEN** the system extends the database file by one page
- **AND** updates the page count in the header

### Requirement: CRC32 Checksums
The system SHALL compute CRC32 checksums for all pages to detect corruption.

#### Scenario: Write page with checksum
- **WHEN** a page is written to disk
- **THEN** the system computes CRC32 of the page content
- **AND** stores the checksum in the page header
- **AND** writes the complete page atomically

#### Scenario: Verify checksum on read
- **WHEN** a page is read from disk
- **THEN** the system computes CRC32 of the read data
- **AND** compares with the stored checksum
- **AND** returns error "Page corruption detected" if mismatch

### Requirement: BLAKE2b Hash Function
The system SHALL implement BLAKE2b hash function per RFC 7693 for Argon2id support.

#### Scenario: Compute BLAKE2b-256
- **WHEN** BLAKE2b-256 is computed on input data
- **THEN** the output is exactly 32 bytes
- **AND** matches RFC 7693 test vectors

#### Scenario: Compute BLAKE2b-512
- **WHEN** BLAKE2b-512 is computed on input data
- **THEN** the output is exactly 64 bytes
- **AND** matches RFC 7693 test vectors

#### Scenario: Keyed BLAKE2b
- **WHEN** BLAKE2b is initialized with a key
- **THEN** the key is mixed into the initial state
- **AND** output differs from unkeyed hash

### Requirement: Argon2id Password Hashing
The system SHALL implement Argon2id per RFC 9106 for password-based key derivation.

#### Scenario: Derive key with default parameters
- **WHEN** Argon2id is called with memory=64MB, time=3, parallelism=4
- **THEN** the derivation takes 500-1000ms
- **AND** produces a 32-byte key
- **AND** matches RFC 9106 test vectors

#### Scenario: Hybrid mode behavior
- **WHEN** Argon2id processes the first pass
- **THEN** the first half uses data-independent addressing (Argon2i)
- **AND** the second half uses data-dependent addressing (Argon2d)

#### Scenario: Memory-hard property
- **WHEN** memory cost is reduced by 50%
- **THEN** the key derivation is NOT 50% faster
- **AND** security is significantly reduced

### Requirement: Secondary Indexes
The system SHALL support secondary B-tree indexes on non-primary columns.

#### Scenario: Create secondary index
- **WHEN** an index is defined on a column
- **THEN** the system creates a separate B-tree
- **AND** keys are the indexed column values
- **AND** values are primary key references

#### Scenario: Unique index constraint
- **WHEN** a unique index exists and a duplicate is inserted
- **THEN** the system returns error "Unique constraint violation"
- **AND** the insert is rolled back

#### Scenario: Index maintenance on insert
- **WHEN** a row is inserted
- **THEN** all secondary indexes are updated
- **AND** index entries point to the new row

#### Scenario: Index maintenance on delete
- **WHEN** a row is deleted
- **THEN** all secondary index entries for that row are removed

### Requirement: Sparse Vector Storage
The system SHALL support sparse vectors with index-value pairs.

#### Scenario: Store sparse vector
- **WHEN** a sparse vector is inserted
- **THEN** the system stores only non-zero indices and values
- **AND** preserves the total dimension count

#### Scenario: Sparse distance calculation
- **WHEN** distance is calculated between sparse vectors
- **THEN** only overlapping indices contribute to the computation
- **AND** missing indices are treated as zero

### Requirement: K-means Clustering for IVF
The system SHALL implement k-means clustering for IVF index training.

#### Scenario: Train IVF centroids
- **WHEN** train() is called with vectors and nlist parameter
- **THEN** the system runs k-means for max 100 iterations
- **AND** produces nlist centroids
- **AND** convergence is detected when centroids move < epsilon

#### Scenario: Assign vectors to clusters
- **WHEN** vectors are added to a trained IVF index
- **THEN** each vector is assigned to its nearest centroid
- **AND** stored in the corresponding inverted list

### Requirement: Concurrent Read Access
The system SHALL support multiple concurrent readers with a single writer.

#### Scenario: Multiple readers
- **WHEN** multiple threads read concurrently
- **THEN** all readers see a consistent snapshot
- **AND** no reader blocks another reader

#### Scenario: Writer blocks readers
- **WHEN** a write transaction is active
- **THEN** readers see the state before the transaction
- **AND** readers are not blocked unless accessing modified pages

#### Scenario: Deadlock prevention
- **WHEN** multiple transactions attempt conflicting access
- **THEN** the system uses lock ordering to prevent deadlocks
- **AND** no transaction waits indefinitely

### Requirement: Database Compaction
The system SHALL support compacting the database to reclaim space.

#### Scenario: Vacuum command
- **WHEN** vacuum is executed
- **THEN** the system rewrites all live pages contiguously
- **AND** frees unused pages at the end
- **AND** truncates the file to remove free space

#### Scenario: Incremental vacuum
- **WHEN** incremental vacuum is executed with page count N
- **THEN** at most N free pages are reclaimed
- **AND** the operation completes quickly

### Requirement: WAL Checksum Chain
The system SHALL maintain a checksum chain in WAL frames for integrity.

#### Scenario: Compute frame checksum
- **WHEN** a WAL frame is written
- **THEN** the checksum includes the previous frame's checksum
- **AND** forms a chain that detects missing frames

#### Scenario: Detect truncated WAL
- **WHEN** WAL is read during recovery
- **AND** checksum chain is broken
- **THEN** recovery stops at the last valid frame
- **AND** later frames are ignored

### Requirement: Hot Backup
The system SHALL support creating backups while the database is in use.

#### Scenario: Start backup
- **WHEN** backup is initiated
- **THEN** the system copies pages while transactions continue
- **AND** uses WAL to capture concurrent changes

#### Scenario: Complete backup
- **WHEN** backup completes
- **THEN** the backup file is a consistent snapshot
- **AND** includes all committed transactions at backup start time
