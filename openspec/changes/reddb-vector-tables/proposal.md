# RedDB Vector Tables - Implementation Proposal

## Overview

Extension to the RedDB embedded database for redblue, adding **vector-optimized tables** with native support for embeddings, similarity search, and table-vector relationships.

**Key Goals:**
- Store high-dimensional vectors efficiently (IP fingerprints, behavior embeddings, domain vectors)
- Fast nearest-neighbor queries (find similar hosts, behaviors, patterns)
- Easy relationships between regular tables and vectors (1-to-1, 1-to-many)
- Pure Rust implementation (zero external dependencies)

---

## Use Cases for Security Intelligence

### 1. Network Behavior Fingerprinting
```rust
// Store behavior vectors for each host
let host_behavior = vec![
    0.92,  // port scan frequency
    0.15,  // connection duration avg
    0.78,  // packet size variance
    0.45,  // time-of-day activity
    // ... 128 dimensions for behavior profile
];
db.insert_vector("hosts_behavior", host_id, host_behavior)?;

// Find hosts with similar behavior (potential lateral movement)
let similar = db.query_similar("hosts_behavior", suspicious_host_id, 10)?;
```

### 2. Domain Reputation Embedding
```rust
// Domain features as vectors
let domain_vec = vec![
    0.88,  // age score (normalized)
    0.12,  // alexa rank (normalized)
    0.95,  // entropy of subdomain
    0.67,  // TLS certificate score
    // ... features for domain classification
];

// Find domains similar to known-bad domains
let phishing_like = db.query_by_vector("domains_vec", known_phishing_vec, 50)?;
```

### 3. TLS Certificate Clustering
```rust
// Certificate fingerprint vectors
let cert_embedding = extract_cert_features(certificate);
db.insert_vector("cert_embeddings", cert_id, cert_embedding)?;

// Cluster certificates by issuer patterns
let same_issuer_pattern = db.query_similar("cert_embeddings", cert_id, 100)?;
```

---

## Architecture

### Vector Table Types

```
┌─────────────────────────────────────────────────────────────────────┐
│                        RedDB Vector Layer                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐ │
│  │   VectorTable   │  │   VectorIndex   │  │  VectorRelation     │ │
│  │                 │  │                 │  │                     │ │
│  │ - Float32Dense  │  │ - Flat (brute)  │  │ - host_id → vec_id  │ │
│  │ - Float64Dense  │  │ - IVF (approx)  │  │ - domain → vec_id[] │ │
│  │ - Float32Sparse │  │ - HNSW (graph)  │  │ - cert → vec_id     │ │
│  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘ │
│           │                    │                      │            │
│           └────────────────────┴──────────────────────┘            │
│                                │                                   │
│                    ┌───────────▼───────────┐                       │
│                    │    VectorStorage      │                       │
│                    │                       │                       │
│                    │ - Contiguous f32/f64  │                       │
│                    │ - Sparse CSR format   │                       │
│                    │ - SIMD distance ops   │                       │
│                    └───────────────────────┘                       │
└─────────────────────────────────────────────────────────────────────┘
```

### File Format

```
.rdb file structure (extended):
┌────────────────────────────────────────┐
│         RedDB Header (256 bytes)       │
├────────────────────────────────────────┤
│         B-tree Pages (regular data)    │
├────────────────────────────────────────┤
│         Vector Segment Header          │ ◄── NEW
│         - num_tables: u32              │
│         - index_type: u8               │
│         - dimensions: u32              │
├────────────────────────────────────────┤
│         Vector Data Pages              │ ◄── NEW
│         - Contiguous float arrays      │
│         - Row: [row_id: u64][f32 × N]  │
├────────────────────────────────────────┤
│         Vector Index Pages             │ ◄── NEW
│         - IVF centroids or HNSW graph  │
├────────────────────────────────────────┤
│         WAL (Write-Ahead Log)          │
└────────────────────────────────────────┘
```

---

## Vector Types

### 1. Float32Dense
Optimized for typical ML embeddings (128-1024 dimensions).

```rust
pub struct DenseVector<T> {
    pub dims: usize,
    pub data: Vec<T>,  // Contiguous f32 or f64
}

// Storage: dims * sizeof(T) bytes
// Example: 128 dims × 4 bytes = 512 bytes per vector
```

### 2. Float32Sparse
For high-dimensional sparse data (TF-IDF, one-hot encodings).

```rust
pub struct SparseVector {
    pub dims: usize,      // Total dimensionality
    pub indices: Vec<u32>, // Non-zero indices
    pub values: Vec<f32>,  // Non-zero values
}

// Storage: (nnz × 4) + (nnz × 4) = 8 bytes per non-zero
// Example: 10000 dims, 50 non-zero = 400 bytes (vs 40KB dense)
```

### 3. BinaryVector
Ultra-compact for hashing-based similarity (SimHash, MinHash).

```rust
pub struct BinaryVector {
    pub bits: Vec<u64>,  // Packed bits
}

// Storage: ceil(dims / 64) × 8 bytes
// Example: 256 bits = 32 bytes
// Distance: Hamming (popcount XOR)
```

---

## Distance Metrics

All implemented from scratch in pure Rust with optional SIMD:

### Cosine Similarity
```rust
pub fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    let (mut dot, mut norm_a, mut norm_b) = (0.0, 0.0, 0.0);
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 1.0; // Max distance for zero vectors
    }
    1.0 - dot / (norm_a.sqrt() * norm_b.sqrt())
}
```

### Euclidean (L2) Distance
```rust
pub fn l2_distance(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f32>()
        .sqrt()
}
```

### Dot Product
```rust
pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}
```

### Hamming Distance (for BinaryVector)
```rust
pub fn hamming_distance(a: &[u64], b: &[u64]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}
```

---

## Vector Index Strategies

### 1. Flat Index (Exact Search)
Best for small datasets (<10K vectors) or when precision is critical.

```rust
pub struct FlatIndex {
    vectors: Vec<Vec<f32>>,
    ids: Vec<u64>,
    dims: usize,
}

impl FlatIndex {
    pub fn search(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        let mut distances: Vec<_> = self.vectors.iter()
            .zip(self.ids.iter())
            .map(|(v, id)| (*id, cosine_distance(query, v)))
            .collect();
        distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        distances.truncate(k);
        distances
    }
}
```

**Complexity:** O(N × D) per query

### 2. IVF Index (Inverted File)
Good balance of speed/accuracy for medium datasets (10K-1M vectors).

```rust
pub struct IVFIndex {
    centroids: Vec<Vec<f32>>,      // K cluster centroids
    inverted_lists: Vec<Vec<u64>>, // IDs per cluster
    vectors: Vec<Vec<f32>>,        // All vectors
    nprobe: usize,                 // Clusters to search
}

impl IVFIndex {
    pub fn train(&mut self, vectors: &[Vec<f32>], k: usize) {
        // K-means clustering
        self.centroids = kmeans(vectors, k, 20); // 20 iterations

        // Assign vectors to clusters
        for (id, vec) in vectors.iter().enumerate() {
            let cluster = self.nearest_centroid(vec);
            self.inverted_lists[cluster].push(id as u64);
        }
    }

    pub fn search(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        // Find nprobe nearest clusters
        let clusters = self.nearest_centroids(query, self.nprobe);

        // Search only those clusters
        let candidates: Vec<_> = clusters.iter()
            .flat_map(|c| &self.inverted_lists[*c])
            .collect();

        // Exact search on candidates
        // ...
    }
}
```

**Complexity:** O(K + (N/K) × nprobe × D) per query

### 3. HNSW Index (Hierarchical Navigable Small World)
Best for large datasets (1M+ vectors) with high recall requirements.

```rust
pub struct HNSWIndex {
    layers: Vec<HNSWLayer>,
    max_layer: usize,
    ef_construction: usize, // Build-time beam width
    ef_search: usize,       // Search-time beam width
    m: usize,               // Max connections per node
}

pub struct HNSWLayer {
    // Adjacency list per node
    neighbors: Vec<Vec<u32>>,
}

impl HNSWIndex {
    pub fn insert(&mut self, id: u64, vector: &[f32]) {
        // Random layer assignment (exponential decay)
        let layer = self.random_layer();

        // Insert at each layer from top to assigned layer
        for l in (0..=layer).rev() {
            // Find ef_construction nearest neighbors
            // Connect with M nearest
        }
    }

    pub fn search(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        // Start from top layer
        let mut entry_point = self.layers[self.max_layer].entry_point;

        // Descend through layers
        for l in (0..self.max_layer).rev() {
            entry_point = self.greedy_search_layer(query, entry_point, 1, l);
        }

        // Final search at layer 0 with ef_search candidates
        self.greedy_search_layer(query, entry_point, self.ef_search, 0)
    }
}
```

**Complexity:** O(log N × D) per query

---

## Table-Vector Relationships

### Schema Definition

```rust
// Define tables with vector relationships
let schema = Schema::new()
    // Regular table
    .table("hosts")
        .column("id", Type::U64, Primary)
        .column("ip", Type::String, Indexed)
        .column("hostname", Type::String, None)
        .column("last_seen", Type::Timestamp, None)

    // Vector table linked to hosts
    .vector_table("host_embeddings")
        .dimensions(128)
        .dtype(VectorType::Float32Dense)
        .index(IndexType::HNSW { m: 16, ef: 64 })
        .relates_to("hosts", RelationType::OneToOne) // 1 host = 1 vector

    // Multiple vectors per domain (version history)
    .table("domains")
        .column("id", Type::U64, Primary)
        .column("name", Type::String, Indexed)

    .vector_table("domain_snapshots")
        .dimensions(256)
        .dtype(VectorType::Float32Dense)
        .index(IndexType::IVF { nlist: 100, nprobe: 10 })
        .relates_to("domains", RelationType::OneToMany) // N snapshots per domain

    .build();
```

### Relationship Types

#### OneToOne
```
hosts (id=1) ────────────► host_embeddings (vec_id=1)
hosts (id=2) ────────────► host_embeddings (vec_id=2)
```

```rust
// Insert with automatic linking
db.insert("hosts", &host_data)?;
let host_id = db.last_insert_id();
db.insert_vector("host_embeddings", host_id, embedding)?;

// Query: get vector for host
let vec = db.get_vector_for("host_embeddings", host_id)?;

// Query: find host by similar vector
let similar = db.similar_in("host_embeddings", query_vec, 10)?;
for (host_id, distance) in similar {
    let host = db.get("hosts", host_id)?;
    println!("{}: {:?} (dist: {:.4})", host_id, host, distance);
}
```

#### OneToMany
```
domains (id=1) ────┬────► domain_snapshots (vec_id=1, timestamp=T1)
                   ├────► domain_snapshots (vec_id=2, timestamp=T2)
                   └────► domain_snapshots (vec_id=3, timestamp=T3)
```

```rust
// Add multiple snapshots for a domain
db.insert_vector_with_meta(
    "domain_snapshots",
    domain_id,
    embedding,
    &[("timestamp", now()), ("version", "1.2.3")]
)?;

// Get all vectors for a domain
let history = db.get_vectors_for("domain_snapshots", domain_id)?;

// Time-travel query: vector at specific time
let past_vec = db.get_vector_at(
    "domain_snapshots",
    domain_id,
    timestamp("2024-01-01")
)?;
```

#### ManyToMany (via Junction)
```
hosts ◄────► host_domain_vecs ────► domains
                   │
                   ▼
            domain_host_embeddings (combined features)
```

```rust
// Create junction
.vector_table("host_domain_embeddings")
    .dimensions(384)  // Combined features
    .relates_to("hosts", RelationType::ManyToMany)
    .relates_to("domains", RelationType::ManyToMany)
```

---

## API Design

### Core Vector Operations

```rust
pub trait VectorStorage {
    // Insert/Update
    fn insert_vector(&mut self, table: &str, id: u64, vector: Vec<f32>) -> Result<()>;
    fn update_vector(&mut self, table: &str, id: u64, vector: Vec<f32>) -> Result<()>;
    fn delete_vector(&mut self, table: &str, id: u64) -> Result<()>;

    // Retrieval
    fn get_vector(&self, table: &str, id: u64) -> Result<Option<Vec<f32>>>;
    fn get_vectors(&self, table: &str, ids: &[u64]) -> Result<Vec<(u64, Vec<f32>)>>;

    // Similarity Search
    fn search_similar(
        &self,
        table: &str,
        query: &[f32],
        k: usize,
        filter: Option<Filter>,
    ) -> Result<Vec<(u64, f32)>>;

    // Relationship queries
    fn get_vector_for(&self, table: &str, related_id: u64) -> Result<Option<Vec<f32>>>;
    fn search_similar_with_data<T>(
        &self,
        vec_table: &str,
        data_table: &str,
        query: &[f32],
        k: usize,
    ) -> Result<Vec<(T, f32)>>;
}
```

### Query Builder

```rust
// Fluent query API
let results = db.query("hosts")
    .join_vectors("host_embeddings")
    .where_similar("host_embeddings", suspicious_vector, 0.8) // cosine >= 0.8
    .and_where("last_seen", ">", yesterday)
    .order_by_similarity()
    .limit(50)
    .fetch::<Host>()?;
```

### Bulk Operations

```rust
// Batch insert (much faster)
let vectors: Vec<(u64, Vec<f32>)> = hosts.iter()
    .map(|h| (h.id, compute_embedding(h)))
    .collect();

db.batch_insert_vectors("host_embeddings", &vectors)?;

// Rebuild index after bulk insert
db.rebuild_index("host_embeddings")?;
```

---

## Storage Layout

### Dense Vector Page (4KB)

```
┌─────────────────────────────────────────────────────────────┐
│                   Vector Page Header (64 bytes)             │
├─────────────────────────────────────────────────────────────┤
│ page_type: u8      │ Vector page marker (0xFE)              │
│ flags: u8          │ Compressed, normalized, etc.           │
│ dims: u32          │ Vector dimensionality                  │
│ count: u32         │ Number of vectors in page              │
│ next_page: u32     │ Overflow page (0 = none)               │
│ checksum: u32      │ CRC32 of data                          │
│ reserved: [u8; 44] │ Future use                             │
├─────────────────────────────────────────────────────────────┤
│                   Vector Data                               │
│                                                             │
│ [row_id: u64][f32 × dims]                                   │
│ [row_id: u64][f32 × dims]                                   │
│ [row_id: u64][f32 × dims]                                   │
│ ...                                                         │
│                                                             │
│ Example (128 dims):                                         │
│ Row size = 8 + (128 × 4) = 520 bytes                        │
│ Vectors per page = (4096 - 64) / 520 = 7 vectors            │
└─────────────────────────────────────────────────────────────┘
```

### Sparse Vector Page

```
┌─────────────────────────────────────────────────────────────┐
│                   Sparse Page Header (64 bytes)             │
├─────────────────────────────────────────────────────────────┤
│ page_type: u8      │ Sparse page marker (0xFD)              │
│ dims: u32          │ Total dimensionality                   │
│ count: u32         │ Number of vectors                      │
│ offset_table: u16  │ Offset to index table                  │
├─────────────────────────────────────────────────────────────┤
│                   Offset Table                              │
│ [(row_id: u64, offset: u16, nnz: u16)] × count              │
├─────────────────────────────────────────────────────────────┤
│                   Sparse Data (CSR format)                  │
│                                                             │
│ Vector 0: [idx: u32][val: f32] × nnz                        │
│ Vector 1: [idx: u32][val: f32] × nnz                        │
│ ...                                                         │
└─────────────────────────────────────────────────────────────┘
```

### HNSW Index Page

```
┌─────────────────────────────────────────────────────────────┐
│                   HNSW Page Header                          │
├─────────────────────────────────────────────────────────────┤
│ layer: u8          │ Graph layer (0 = bottom)               │
│ m: u8              │ Max neighbors per node                 │
│ node_count: u32    │ Nodes in this page                     │
├─────────────────────────────────────────────────────────────┤
│                   Adjacency Lists                           │
│                                                             │
│ Node 0: [neighbor_id: u32] × degree                         │
│ Node 1: [neighbor_id: u32] × degree                         │
│ ...                                                         │
│                                                             │
│ (degrees stored in separate array or varint-encoded)        │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation Plan

### Phase 1: Vector Foundation (3-4 days)
- [ ] `src/storage/vector/types.rs` - DenseVector, SparseVector, BinaryVector
- [ ] `src/storage/vector/distance.rs` - Cosine, L2, Dot, Hamming
- [ ] `src/storage/vector/serialize.rs` - Binary encoding/decoding
- [ ] Unit tests for all distance metrics

### Phase 2: Flat Storage (2-3 days)
- [ ] `src/storage/vector/flat.rs` - FlatIndex implementation
- [ ] `src/storage/vector/page.rs` - Vector page format
- [ ] Integration with existing Page/Pager system
- [ ] CRUD operations on vectors

### Phase 3: Relationships (2-3 days)
- [ ] `src/storage/vector/relation.rs` - OneToOne, OneToMany
- [ ] Schema extensions for vector tables
- [ ] Join queries (table + vector)
- [ ] Foreign key enforcement

### Phase 4: Advanced Indexes (4-5 days)
- [ ] `src/storage/vector/ivf.rs` - IVF index with k-means
- [ ] `src/storage/vector/hnsw.rs` - HNSW graph index
- [ ] Index rebuild and maintenance
- [ ] Automatic index selection

### Phase 5: Optimization (2-3 days)
- [ ] SIMD acceleration for distance ops
- [ ] Batch operations
- [ ] Memory-mapped vector storage
- [ ] Compression (PQ, scalar quantization)

---

## Module Structure

```
src/storage/
├── mod.rs              # Storage module root
├── page.rs             # Page types (extended)
├── pager.rs            # Page manager (extended)
├── btree.rs            # B-tree for regular data
├── wal.rs              # Write-ahead log
├── vector/             # NEW: Vector subsystem
│   ├── mod.rs          # Vector module exports
│   ├── types.rs        # DenseVector, SparseVector, BinaryVector
│   ├── distance.rs     # Cosine, L2, Dot, Hamming
│   ├── serialize.rs    # Binary format
│   ├── page.rs         # Vector page layout
│   ├── flat.rs         # FlatIndex
│   ├── ivf.rs          # IVF index
│   ├── hnsw.rs         # HNSW index
│   ├── relation.rs     # Table-vector relationships
│   └── query.rs        # Similarity search queries
└── schema.rs           # Schema with vector table support
```

---

## Estimated Effort

| Phase | Component | LOC | Days |
|-------|-----------|-----|------|
| 1 | Vector types + distance | ~500 | 3-4 |
| 2 | Flat storage + pages | ~600 | 2-3 |
| 3 | Relationships | ~400 | 2-3 |
| 4 | IVF + HNSW indexes | ~1200 | 4-5 |
| 5 | Optimization | ~500 | 2-3 |
| **Total** | **Vector subsystem** | **~3200** | **14-18** |

Combined with base RedDB (~8400 LOC, ~22 days):
- **Total RedDB + Vectors: ~11,600 LOC, ~36-40 days**

---

## Security Intelligence Examples

### 1. Host Behavior Anomaly Detection

```rust
// Train on known-good hosts
for host in baseline_hosts {
    let embedding = extract_behavior_features(&host);
    db.insert_vector("host_embeddings", host.id, embedding)?;
}

// Detect anomalies
for host in monitored_hosts {
    let embedding = extract_behavior_features(&host);
    let neighbors = db.search_similar("host_embeddings", &embedding, 5)?;

    let avg_distance = neighbors.iter().map(|(_, d)| d).sum::<f32>() / 5.0;
    if avg_distance > ANOMALY_THRESHOLD {
        alert!("Anomalous behavior detected: {} (dist: {:.3})", host.ip, avg_distance);
    }
}
```

### 2. Phishing Domain Detection

```rust
// Store embeddings of known phishing domains
for domain in phishing_db {
    let features = domain_features(&domain); // NLP + structural
    db.insert_vector("phishing_embeddings", domain.id, features)?;
}

// Check new domains
fn is_phishing_like(domain: &str) -> f32 {
    let features = domain_features(domain);
    let similar = db.search_similar("phishing_embeddings", &features, 1)?;
    similar.first().map(|(_, d)| 1.0 - d).unwrap_or(0.0) // Similarity score
}
```

### 3. TLS Certificate Clustering

```rust
// Cluster certificates by issuer patterns
let certs_with_embeddings = certificates.iter()
    .map(|c| (c.id, cert_embedding(c)))
    .collect::<Vec<_>>();

db.batch_insert_vectors("cert_embeddings", &certs_with_embeddings)?;

// Find all certs similar to a suspicious one
let cluster = db.search_similar("cert_embeddings", &suspicious_cert_embedding, 100)?;
println!("Found {} certs with similar patterns", cluster.len());
```

---

## Success Criteria

1. **Performance**
   - Insert: 10K vectors/second (128-dim, f32)
   - Search: <10ms for 100K vectors (flat), <1ms (HNSW)
   - Memory: <500MB for 1M 128-dim vectors

2. **Accuracy**
   - Flat: 100% recall (exact)
   - IVF: >95% recall@10
   - HNSW: >98% recall@10

3. **Usability**
   - Simple relationship syntax
   - Join queries in single statement
   - Automatic index selection

4. **Compatibility**
   - Same .rdb file format (extended)
   - Backward compatible with non-vector databases
   - Works with existing WAL

---

## References

- Turso/libSQL vector implementation (analyzed above)
- FAISS: Facebook AI Similarity Search
- Annoy: Spotify's approximate nearest neighbors
- HNSW paper: "Efficient and robust approximate nearest neighbor search"
- SQLite FTS5 for hybrid search patterns
