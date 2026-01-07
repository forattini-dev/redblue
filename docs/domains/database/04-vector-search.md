# Vector Search

RedDB implements approximate nearest neighbor (ANN) search from scratch, inspired by Milvus, Chroma, and Pinecone.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Vector Search Pipeline                      │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   Embedding  │───▶│   Indexing   │───▶│    Retrieval     │  │
│  │   (Text →    │    │   (HNSW/     │    │   (k-NN Search)  │  │
│  │    Vector)   │    │    IVF/PQ)   │    │                  │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│                                                                  │
│  Supported Dimensions: 128, 256, 384, 512, 768, 1024, 1536     │
│  Distance Metrics: L2 (Euclidean), Cosine, Inner Product        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Index Types

### Comparison

| Index | Search Time | Memory | Build Time | Accuracy | Best For |
|-------|-------------|--------|------------|----------|----------|
| **Flat** | O(n) | Low | None | 100% | < 10k vectors |
| **HNSW** | O(log n) | High | Medium | 95-99% | Real-time search |
| **IVF** | O(√n) | Medium | Fast | 90-95% | Large datasets |
| **PQ** | O(n) | Very Low | Slow | 80-90% | Billions of vectors |
| **IVF+PQ** | O(√n) | Very Low | Slow | 85-95% | Memory-constrained |

---

## HNSW (Hierarchical Navigable Small World)

The primary index for real-time semantic search.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HNSW Structure                            │
│                                                                  │
│  Layer 3:  [N₁]─────────────────────────────────────[N₈]        │
│             │                                         │          │
│  Layer 2:  [N₁]─────[N₄]─────────────[N₇]────────[N₈]          │
│             │        │                │            │            │
│  Layer 1:  [N₁]──[N₂]──[N₄]──[N₅]──[N₆]──[N₇]──[N₈]          │
│             │   /  │ \   │    │     │    │     │              │
│  Layer 0:  [N₁][N₂][N₃][N₄][N₅][N₆][N₇][N₈][N₉][N₁₀]...      │
│                                                                  │
│  Entry point: N₁ (highest layer)                                │
│  Each node has M connections per layer                          │
└─────────────────────────────────────────────────────────────────┘
```

### Parameters

| Parameter | Description | Typical Value |
|-----------|-------------|---------------|
| `M` | Max connections per node per layer | 16-64 |
| `ef_construction` | Beam width during build | 100-400 |
| `ef_search` | Beam width during search | 50-200 |
| `m_l` | Level multiplier | 1/ln(M) |

### How It Works

```
Search Algorithm:
1. Start at entry point (highest layer)
2. Greedy search: move to closest neighbor
3. When stuck, descend to next layer
4. At layer 0, collect ef_search nearest candidates
5. Return top-k from candidates

Insert Algorithm:
1. Generate random level L with exponential distribution
2. Search from top to layer L+1 (greedy)
3. From L down to 0: find M nearest neighbors
4. Create bidirectional links to M neighbors
5. Prune connections if exceeding M_max
```

### Usage

```rust
use redblue::storage::engine::{VectorStore, HnswConfig, DistanceMetric};

// Create HNSW index
let config = HnswConfig {
    dimension: 384,
    m: 16,
    ef_construction: 200,
    ef_search: 50,
    metric: DistanceMetric::Cosine,
};

let mut store = VectorStore::new(config);

// Insert vectors
store.insert("CVE-2021-44228", embedding_log4j)?;
store.insert("CVE-2023-1234", embedding_rce)?;

// Search
let query = embed("remote code execution vulnerability");
let results = store.search(&query, 10)?;

for (id, distance) in results {
    println!("{}: distance = {:.4}", id, distance);
}
```

### Performance Tuning

```
Trade-offs:

Higher M (connections):
  ✅ Better recall
  ❌ More memory
  ❌ Slower insert

Higher ef_construction:
  ✅ Better index quality
  ❌ Slower build time
  ✅ Same search speed

Higher ef_search:
  ✅ Better recall
  ❌ Slower search
  ✅ Same memory
```

---

## IVF (Inverted File Index)

Partitions vectors into clusters for faster search.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         IVF Structure                            │
│                                                                  │
│  Training Phase (K-Means):                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Input vectors → K-Means → K centroids                  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Index Structure:                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │Centroid 1│  │Centroid 2│  │Centroid 3│  │Centroid K│        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │               │
│  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐        │
│  │ Cluster  │  │ Cluster  │  │ Cluster  │  │ Cluster  │        │
│  │[v₁,v₂,v₃]│  │[v₄,v₅]   │  │[v₆,v₇,v₈]│  │[v₉,v₁₀] │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│                                                                  │
│  Search: Query → Find nprobe nearest centroids → Search those  │
└─────────────────────────────────────────────────────────────────┘
```

### Parameters

| Parameter | Description | Typical Value |
|-----------|-------------|---------------|
| `n_clusters` | Number of centroids (K) | √n to 4√n |
| `n_probe` | Clusters to search | 1-20% of K |
| `n_iter` | K-Means iterations | 20-50 |

### Usage

```rust
use redblue::storage::engine::{IvfIndex, IvfConfig};

let config = IvfConfig {
    dimension: 384,
    n_clusters: 256,
    n_probe: 16,
    metric: DistanceMetric::L2,
};

let mut index = IvfIndex::new(config);

// Must train on sample data first
let training_data: Vec<&[f32]> = vectors.iter().collect();
index.train(&training_data)?;

// Then insert
for (id, vec) in vectors {
    index.insert(id, vec)?;
}

// Search
let results = index.search(&query, 10)?;
```

### When to Use IVF

```
✅ Good for:
  - 100k - 10M vectors
  - Memory-constrained environments
  - Batch processing

❌ Not ideal for:
  - Real-time updates (requires re-clustering)
  - Very small datasets (overhead not worth it)
  - Highest accuracy requirements
```

---

## Product Quantization (PQ)

Compresses vectors for memory-efficient search.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Product Quantization                          │
│                                                                  │
│  Original Vector (384 dims, 1536 bytes):                        │
│  [f32, f32, f32, ..., f32, f32, f32]                           │
│   └── 384 × 4 bytes = 1536 bytes ──┘                           │
│                                                                  │
│  Split into M subspaces:                                        │
│  ┌────────┐ ┌────────┐ ┌────────┐     ┌────────┐               │
│  │ Sub 1  │ │ Sub 2  │ │ Sub 3  │ ... │ Sub M  │               │
│  │48 dims │ │48 dims │ │48 dims │     │48 dims │               │
│  └───┬────┘ └───┬────┘ └───┬────┘     └───┬────┘               │
│      │          │          │              │                      │
│  Quantize each subspace to nearest centroid (256 centroids):    │
│      ▼          ▼          ▼              ▼                      │
│  ┌──────┐  ┌──────┐  ┌──────┐       ┌──────┐                   │
│  │ ID:42│  │ID:128│  │ ID:7 │  ...  │ID:255│                   │
│  │ u8   │  │ u8   │  │ u8   │       │ u8   │                   │
│  └──────┘  └──────┘  └──────┘       └──────┘                   │
│                                                                  │
│  Compressed Vector (M bytes = 8 bytes):                         │
│  [42, 128, 7, ..., 255]                                        │
│                                                                  │
│  Compression ratio: 1536 / 8 = 192x !                           │
└─────────────────────────────────────────────────────────────────┘
```

### Parameters

| Parameter | Description | Typical Value |
|-----------|-------------|---------------|
| `m` | Number of subspaces | 8-64 |
| `n_bits` | Bits per subspace | 8 (256 centroids) |
| `training_size` | Vectors for codebook | 10k-100k |

### Distance Computation

```
Asymmetric Distance Computation (ADC):
- Precompute: query_subvector to all centroids (M × 256 table)
- Search: sum lookup distances for each compressed vector
- Time: O(n × M) lookups instead of O(n × D) multiplies
```

```rust
use redblue::storage::engine::{PQIndex, PQConfig};

let config = PQConfig {
    dimension: 384,
    m: 48,          // 48 subspaces
    n_bits: 8,      // 256 centroids per subspace
};

let mut pq = PQIndex::new(config);

// Train codebook
pq.train(&training_vectors)?;

// Encode and store
for (id, vec) in vectors {
    pq.insert(id, vec)?;
}

// Memory: 1M vectors × 48 bytes = 48 MB (vs 1.5 GB uncompressed)
```

---

## Hybrid Search

Combines dense (vector) and sparse (keyword) retrieval.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Hybrid Search                              │
│                                                                  │
│  Query: "Log4j remote code execution vulnerability"             │
│                                                                  │
│  ┌─────────────────────┐      ┌─────────────────────┐           │
│  │    Dense Search     │      │   Sparse Search     │           │
│  │                     │      │                     │           │
│  │  Embedding Model    │      │    BM25 / TF-IDF    │           │
│  │       ↓             │      │         ↓           │           │
│  │  HNSW k-NN Search   │      │  Inverted Index     │           │
│  │       ↓             │      │         ↓           │           │
│  │  [CVE-1, CVE-2, ...]│      │  [CVE-3, CVE-1, ...]│           │
│  └──────────┬──────────┘      └──────────┬──────────┘           │
│             │                            │                       │
│             └──────────┬─────────────────┘                       │
│                        ▼                                         │
│              ┌─────────────────┐                                │
│              │  Fusion Layer   │                                │
│              │                 │                                │
│              │  • RRF (1/r+k)  │                                │
│              │  • DBSF (norm)  │                                │
│              │  • Weighted Sum │                                │
│              └────────┬────────┘                                │
│                       ▼                                          │
│              [CVE-1, CVE-3, CVE-2, ...]                         │
└─────────────────────────────────────────────────────────────────┘
```

### Fusion Methods

#### Reciprocal Rank Fusion (RRF)

```
RRF(d) = Σ 1 / (k + rank_i(d))

Where:
- k = constant (typically 60)
- rank_i(d) = rank of document d in result list i
```

#### Distribution-Based Score Fusion (DBSF)

```
DBSF normalizes scores to [0,1] range:

score_norm = (score - min) / (max - min)

Then combines:
final = α × dense_norm + (1-α) × sparse_norm
```

### Usage

```rust
use redblue::storage::engine::{HybridSearch, FusionMethod};

let hybrid = HybridSearch::new(
    vector_store,
    bm25_index,
    FusionMethod::RRF { k: 60 },
);

let results = hybrid.search(
    "log4j remote code execution",
    10,     // top-k
    0.7,    // dense weight
)?;

for (id, score) in results {
    println!("{}: hybrid_score = {:.4}", id, score);
}
```

### Sparse Index (BM25)

```
BM25(D, Q) = Σ IDF(qi) × (f(qi,D) × (k1+1)) / (f(qi,D) + k1 × (1 - b + b × |D|/avgdl))

Parameters:
- k1 = 1.2 (term frequency saturation)
- b = 0.75 (length normalization)
```

```rust
use redblue::storage::engine::BM25Index;

let mut bm25 = BM25Index::new();

// Index documents
bm25.add("CVE-2021-44228", "Apache Log4j2 RCE vulnerability");
bm25.add("CVE-2023-1234", "Remote code execution in web server");

// Search
let results = bm25.search("log4j vulnerability", 10);
```

---

## Distance Metrics

### L2 (Euclidean)

```
d(a, b) = √Σ(aᵢ - bᵢ)²

Best for: General purpose, when magnitude matters
```

### Cosine Similarity

```
cos(a, b) = (a · b) / (‖a‖ × ‖b‖)
distance = 1 - cos(a, b)

Best for: Text embeddings (direction matters, not magnitude)
```

### Inner Product

```
IP(a, b) = Σ aᵢ × bᵢ
distance = -IP(a, b)  (for maximum similarity)

Best for: Recommendation, normalized embeddings
```

### Choosing a Metric

| Use Case | Recommended Metric |
|----------|-------------------|
| Text similarity | Cosine |
| Image similarity | L2 |
| Recommendations | Inner Product |
| Anomaly detection | L2 |
| General | Cosine (normalized) or L2 |

---

## Metadata Filtering

Combine vector search with metadata filters.

```rust
use redblue::storage::engine::{MetadataFilter, FilterOp};

let filter = MetadataFilter::new()
    .and("cvss", FilterOp::Gte(7.0))
    .and("published_year", FilterOp::Eq(2023))
    .and("vendor", FilterOp::In(vec!["Apache", "Microsoft"]));

let results = store.search_with_filter(&query, 10, filter)?;
```

### Filter Execution Strategies

```
Pre-filtering:
  1. Apply metadata filter first
  2. Vector search only on filtered subset
  ✅ Exact filter semantics
  ❌ May miss good candidates

Post-filtering:
  1. Vector search returns k × N candidates
  2. Apply filter to reduce to k
  ✅ Better recall
  ❌ May return < k results

In-filter (recommended):
  1. Interleave filtering during HNSW traversal
  2. Skip non-matching nodes
  ✅ Balance of both
```

---

## Quantization Strategies

### Scalar Quantization

```
float32 → uint8

scale = (max - min) / 255
quantized = round((value - min) / scale)

Memory: 4x reduction
Accuracy: ~1-2% loss
```

### Binary Quantization

```
float32 → bit

quantized = value > 0 ? 1 : 0

Memory: 32x reduction
Accuracy: ~5-10% loss (rerank with float for accuracy)
```

### Two-Phase Search

```
1. Coarse search with quantized vectors
2. Rerank top candidates with full-precision vectors

Example:
- Phase 1: Binary search, retrieve 1000 candidates
- Phase 2: Full precision rerank, return top 10
```

---

## Tiered Search (Binary + int8)

The most memory-efficient approach for large-scale similarity search, especially on resource-constrained systems.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Tiered Search Pipeline                        │
│                                                                  │
│  Query Vector (fp32)                                            │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Stage 1: BINARY SEARCH                                  │    │
│  │  • Quantize query to 1-bit per dimension                 │    │
│  │  • Hamming distance (XOR + popcount = 1 CPU instruction) │    │
│  │  • Returns k × 4 candidates                              │    │
│  │  • Memory: 32x less than fp32                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│         │                                                        │
│         ▼  (40 candidates for k=10)                             │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Stage 2: INT8 RESCORE                                   │    │
│  │  • SIMD dot product (AVX2/SSE4)                          │    │
│  │  • Asymmetric: fp32 query × int8 candidates              │    │
│  │  • Returns final k results                               │    │
│  │  • Restores ~99% of fp32 accuracy                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│         │                                                        │
│         ▼  (10 results)                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Stage 3: FP32 RESCORE (optional)                        │    │
│  │  • Full precision for final ranking                      │    │
│  │  • Only when TieredSearchConfig::precise() is used       │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Memory Comparison

| Representation | Bits/dim | 1M × 1024 dims | Compression |
|----------------|----------|----------------|-------------|
| fp32 | 32 | 4 GB | 1x |
| int8 | 8 | 1 GB | 4x |
| binary | 1 | 128 MB | 32x |
| **tiered (bin+i8)** | - | **1.1 GB** | **~4x** |

### Usage

```rust
use redblue::storage::engine::{TieredIndex, TieredSearchConfig};

// Create index
let mut index = TieredIndex::new(768);

// Add embeddings
for embedding in embeddings {
    index.add(&embedding);
}

// Search (uses binary → int8 pipeline)
let results = index.search(&query, 10);

// High-precision search (binary → int8 → fp32)
let results = index.search_with_config(
    &query,
    10,
    &TieredSearchConfig::precise()
);
```

### Memory-Constrained Systems

For edge devices, Raspberry Pi, or containers with limited RAM:

```rust
// Define memory budget
let mut index = TieredIndex::memory_constrained(
    768,                      // dimensions
    TieredIndex::MB(256)      // max 256 MB
);

// Add until full
while let Some(emb) = get_embedding() {
    if !index.add(&emb) {
        break;  // Memory limit reached
    }
}

// Monitor usage
println!("Utilization: {:.1}%",
    index.memory_utilization().unwrap() * 100.0);
println!("Remaining: {:?} vectors",
    index.remaining_capacity());
```

### Capacity by RAM Budget

| RAM Budget | Dimension | Max Vectors (bin+i8) |
|------------|-----------|---------------------|
| 256 MB | 768 | ~290,000 |
| 512 MB | 768 | ~580,000 |
| 1 GB | 1024 | ~930,000 |
| 2 GB | 1024 | ~1,800,000 |

### Search Configurations

```rust
// Fast: fewer candidates, no fp32 rescore
TieredSearchConfig::fast()      // rescore_multiplier = 2

// Balanced (default)
TieredSearchConfig::default()   // rescore_multiplier = 4

// Quality: more candidates + fp32 rescore
TieredSearchConfig::quality()   // rescore_multiplier = 8, use_fp32 = true

// Maximum precision
TieredSearchConfig::precise()   // rescore_multiplier = 10, use_fp32 = true
```

### When to Use Tiered Search

```
✅ Best for:
  • Memory-constrained environments (edge, IoT, small containers)
  • Large datasets (100K+ vectors)
  • 95-99% recall is acceptable
  • Batch processing workloads

❌ Not ideal for:
  • Sub-millisecond latency requirements (use HNSW)
  • 100% exact recall required
  • Very small datasets (brute force is fine)
```

---

## Performance Benchmarks

| Dataset | Index | QPS | Recall@10 | Memory |
|---------|-------|-----|-----------|--------|
| 1M×384 | Flat | 50 | 100% | 1.5 GB |
| 1M×384 | HNSW | 5,000 | 98% | 2.5 GB |
| 1M×384 | IVF | 2,000 | 92% | 1.6 GB |
| 1M×384 | PQ | 3,000 | 85% | 50 MB |
| 1M×384 | IVF+PQ | 4,000 | 88% | 60 MB |

---

## See Also

- [Storage Modalities](/domains/database/01-storage.md) - Vector store architecture
- [Query Languages](/domains/database/02-query-languages.md) - Vector SQL extensions
- [Security Queries](/domains/database/06-security-queries.md) - CVE similarity search
