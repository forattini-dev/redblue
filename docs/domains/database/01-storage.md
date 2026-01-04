# Storage Modalities

RedDB implements three distinct storage engines, each optimized for different data patterns.

## Tables (Relational Storage)

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      B-Tree Index                        │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
│  │ Root    │──│ Branch  │──│ Branch  │──│ Branch  │    │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘    │
│       │            │            │            │          │
│  ┌────▼────┐  ┌────▼────┐  ┌────▼────┐  ┌────▼────┐    │
│  │ Leaf    │  │ Leaf    │  │ Leaf    │  │ Leaf    │    │
│  │ (Data)  │  │ (Data)  │  │ (Data)  │  │ (Data)  │    │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘    │
├─────────────────────────────────────────────────────────┤
│                    Page Storage                          │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐          │
│  │Page 0│ │Page 1│ │Page 2│ │Page 3│ │Page N│          │
│  │ 4KB  │ │ 4KB  │ │ 4KB  │ │ 4KB  │ │ 4KB  │          │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘          │
└─────────────────────────────────────────────────────────┘
```

### Features

| Feature | Description |
|---------|-------------|
| **B-Tree Index** | Self-balancing tree for O(log n) lookups |
| **Page-Aligned** | 4KB pages for efficient disk I/O |
| **WAL** | Write-ahead logging for durability |
| **MVCC** | Multi-version concurrency control |
| **Cursors** | Forward/backward iteration |
| **Range Scans** | Efficient range queries |

### Schema Definition

```rust
use redblue::storage::schema::{Schema, Column, DataType};

let hosts_schema = Schema::new("hosts")
    .column(Column::new("id", DataType::Uuid).primary_key())
    .column(Column::new("hostname", DataType::Text).not_null())
    .column(Column::new("ip", DataType::Text).indexed())
    .column(Column::new("os", DataType::Text))
    .column(Column::new("criticality", DataType::Float))
    .column(Column::new("last_seen", DataType::Timestamp));
```

### Query Examples

```sql
-- Basic CRUD
INSERT INTO hosts (hostname, ip, os) VALUES ('web01', '10.0.0.1', 'Linux');
SELECT * FROM hosts WHERE criticality > 8.0 ORDER BY last_seen DESC;
UPDATE hosts SET os = 'Ubuntu 22.04' WHERE hostname = 'web01';
DELETE FROM hosts WHERE last_seen < '2024-01-01';

-- Aggregations
SELECT os, COUNT(*), AVG(criticality) FROM hosts GROUP BY os;

-- Window Functions
SELECT hostname, criticality,
       RANK() OVER (ORDER BY criticality DESC) as risk_rank
FROM hosts;

-- JOINs
SELECT h.hostname, s.port, s.service
FROM hosts h
JOIN services s ON h.id = s.host_id
WHERE s.port IN (22, 80, 443);
```

---

## Graphs (Property Graph Storage)

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Graph Store                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │                 Node Storage                     │    │
│  │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐        │    │
│  │  │Node 1│  │Node 2│  │Node 3│  │Node N│        │    │
│  │  │Props │  │Props │  │Props │  │Props │        │    │
│  │  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘        │    │
│  └─────┼────────┼────────┼────────┼───────────────┘    │
│        │        │        │        │                     │
│  ┌─────▼────────▼────────▼────────▼───────────────┐    │
│  │              Adjacency Lists                    │    │
│  │  Node 1: [(Edge1, Node2), (Edge2, Node3)]      │    │
│  │  Node 2: [(Edge3, Node1), (Edge4, Node4)]      │    │
│  │  Node 3: [(Edge5, Node2)]                      │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Edge Type Index                    │    │
│  │  CONNECTS_TO: [Edge1, Edge3, Edge5]            │    │
│  │  AUTH_ACCESS: [Edge2, Edge4]                   │    │
│  │  AFFECTED_BY: [Edge6, Edge7]                   │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Node Types

| Type | Description | Properties |
|------|-------------|------------|
| `Host` | Network host | hostname, ip, os, criticality |
| `Service` | Running service | port, protocol, version |
| `User` | User account | username, privileges |
| `Vulnerability` | CVE/vuln | cve_id, cvss, exploitable |
| `Credential` | Auth creds | type, hash, cleartext |
| `Certificate` | TLS cert | subject, issuer, expiry |

### Edge Types

| Type | Description | Weight |
|------|-------------|--------|
| `HAS_SERVICE` | Host → Service | - |
| `CONNECTS_TO` | Host → Host | Latency |
| `AUTH_ACCESS` | Credential → Host | Trust level |
| `AFFECTED_BY` | Host → Vulnerability | CVSS |
| `HAS_USER` | Host → User | - |
| `USES_TECH` | Service → Technology | - |

### Graph Operations

```rust
use redblue::storage::engine::{GraphStore, GraphNodeType, GraphEdgeType};

// Add nodes
let host1 = graph.add_node("host1", GraphNodeType::Host, props![
    "hostname" => "web01",
    "ip" => "10.0.0.1"
]);

let host2 = graph.add_node("host2", GraphNodeType::Host, props![
    "hostname" => "db01",
    "ip" => "10.0.0.2"
]);

// Add edges
graph.add_edge(host1, host2, GraphEdgeType::ConnectsTo, 1.0);

// Traverse
for (edge_type, neighbor, weight) in graph.outgoing_edges("host1") {
    println!("{:?} -> {} (weight: {})", edge_type, neighbor, weight);
}
```

---

## Vectors (Embedding Storage)

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Vector Store                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │                 HNSW Index                       │    │
│  │                                                  │    │
│  │  Layer 2:  [N1]─────────────────────[N5]        │    │
│  │              │                        │          │    │
│  │  Layer 1:  [N1]──[N3]──────[N4]──[N5]          │    │
│  │              │     │         │     │            │    │
│  │  Layer 0:  [N1][N2][N3][N4][N5][N6][N7]...     │    │
│  │                                                  │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │              IVF Index (Clustering)              │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐         │    │
│  │  │Cluster 1│  │Cluster 2│  │Cluster K│         │    │
│  │  │ [v1,v2] │  │ [v3,v4] │  │ [vN-1,vN]│        │    │
│  │  └─────────┘  └─────────┘  └─────────┘         │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │         Product Quantization (Compression)       │    │
│  │  Original: [f32 × 384] = 1536 bytes             │    │
│  │  Encoded:  [u8 × 48]   = 48 bytes (32x smaller) │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Index Types

| Index | Search Time | Memory | Build Time | Use Case |
|-------|-------------|--------|------------|----------|
| **HNSW** | O(log n) | High | Medium | Real-time search |
| **IVF** | O(√n) | Low | Fast | Large datasets |
| **PQ** | O(n) | Very Low | Slow | Billions of vectors |
| **Flat** | O(n) | High | None | Exact search |

### Vector Operations

```rust
use redblue::storage::engine::{VectorStore, HnswConfig};

// Create store
let mut store = VectorStore::new(HnswConfig {
    dimension: 384,
    m: 16,                  // Connections per node
    ef_construction: 200,   // Build-time beam width
    ef_search: 50,          // Search-time beam width
});

// Add vectors
let cve_embedding = embed("CVE-2021-44228 Log4j RCE");
store.insert("CVE-2021-44228", cve_embedding);

// Search
let query = embed("log4j remote code execution vulnerability");
let results = store.search(&query, 10);  // Top 10 similar

for (id, distance) in results {
    println!("{}: {:.4}", id, distance);
}
```

### Distance Metrics

| Metric | Formula | Use Case |
|--------|---------|----------|
| **L2 (Euclidean)** | √Σ(aᵢ - bᵢ)² | General purpose |
| **Cosine** | 1 - (a·b)/(‖a‖‖b‖) | Text embeddings |
| **Inner Product** | -a·b | Normalized vectors |

---

## Unified Index

The **Unified Index** connects all three storage modalities:

```
┌─────────────────────────────────────────────────────────┐
│                   Unified Index                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Entity ID → Storage References                  │    │
│  │                                                  │    │
│  │  "CVE-2021-44228" → {                           │    │
│  │    table: ("vulnerabilities", row_123),         │    │
│  │    graph: (node_456),                           │    │
│  │    vector: (vector_789)                         │    │
│  │  }                                               │    │
│  │                                                  │    │
│  │  "host:web01" → {                               │    │
│  │    table: ("hosts", row_001),                   │    │
│  │    graph: (node_001),                           │    │
│  │    vector: None                                 │    │
│  │  }                                               │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

This enables queries like:

```sql
-- Start with vector similarity, join to graph, filter by table
SELECT h.hostname, v.cve_id
FROM hosts h
JOIN vulnerabilities v ON h.id = v.host_id
WHERE VECTOR_SIMILAR(v.embedding, $query, 10)
  AND attack_path_exists(h.id, 'database_server', 3)
```

## Storage Segments

Data is organized into typed segments for efficient serialization:

| Segment | Content | Format |
|---------|---------|--------|
| `ports` | Port scan results | Binary (24 bytes/record) |
| `dns` | DNS records | Variable length |
| `http` | HTTP responses | Compressed |
| `tls` | Certificates | DER + metadata |
| `hosts` | Host inventory | Structured |
| `graph` | Graph relationships | Adjacency encoded |
| `vectors` | Embeddings | Float32 arrays |
| `intelligence` | Threat intel | JSON + vectors |

## See Also

- [Query Languages](/domains/database/02-query-languages.md) - How to query each modality
- [Graph Algorithms](/domains/database/03-graph-algorithms.md) - Built-in graph analytics
- [Vector Search](/domains/database/04-vector-search.md) - Semantic search details
