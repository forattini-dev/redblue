# RedDB: Unified Storage Engine

## Overview

RedDB is a **multi-modal storage engine** that unifies three storage paradigms into a single queryable system:

- **Relational Tables** - Traditional row-based storage with B-Tree indices
- **Property Graphs** - Nodes and edges with adjacency-list storage
- **Vector Embeddings** - High-dimensional vectors with ANN indices

This unified approach eliminates the need for multiple databases (PostgreSQL + Neo4j + Milvus) and expensive ETL pipelines between them.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Query Layer                                  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────────┐  │
│  │   SQL   │ │ Gremlin │ │ Cypher  │ │ SPARQL  │ │Natural Language│  │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └───────┬───────┘  │
│       └───────────┴───────────┴───────────┴───────────────┘          │
│                              │                                        │
│                    ┌─────────▼─────────┐                             │
│                    │  Multi-Mode Parser │                             │
│                    │  (Auto-Detection)  │                             │
│                    └─────────┬─────────┘                             │
├──────────────────────────────┼───────────────────────────────────────┤
│                    ┌─────────▼─────────┐                             │
│                    │  Query Optimizer   │                             │
│                    │  (Cost-Based)      │                             │
│                    └─────────┬─────────┘                             │
│                              │                                        │
│  ┌───────────────────────────┼───────────────────────────────────┐   │
│  │                   Execution Layer                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐    │   │
│  │  │Security     │  │Multi-Mode   │  │RAG Engine           │    │   │
│  │  │Queries      │  │Executor     │  │(Retrieval-Augmented)│    │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘    │   │
│  └───────────────────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────────────────┤
│                         Cache Layer                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │Result Cache │  │Materialized │  │ Plan Cache  │  │Aggregation │  │
│  │(LFU+LRU)    │  │Views        │  │ (LRU+TTL)   │  │Cache       │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘  │
├──────────────────────────────────────────────────────────────────────┤
│                     SIEVE Page Cache (O(1))                          │
├──────────────────────────────────────────────────────────────────────┤
│                       Storage Layer                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │    Tables       │  │     Graphs      │  │      Vectors        │  │
│  │  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────────┐  │  │
│  │  │ B-Tree    │  │  │  │ Adjacency │  │  │  │ HNSW Index    │  │  │
│  │  │ Index     │  │  │  │ Lists     │  │  │  │ (ANN Search)  │  │  │
│  │  └───────────┘  │  │  └───────────┘  │  │  └───────────────┘  │  │
│  │  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────────┐  │  │
│  │  │ WAL       │  │  │  │ Algorithms│  │  │  │ IVF Index     │  │  │
│  │  │ (Durabil.)│  │  │  │ (PageRank)│  │  │  │ (Clustering)  │  │  │
│  │  └───────────┘  │  │  └───────────┘  │  │  └───────────────┘  │  │
│  │                 │  │                 │  │  ┌───────────────┐  │  │
│  │                 │  │                 │  │  │ PQ Compress   │  │  │
│  │                 │  │                 │  │  │ (32-64x)      │  │  │
│  │                 │  │                 │  │  └───────────────┘  │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
├──────────────────────────────────────────────────────────────────────┤
│               Page-Based Storage (4KB Aligned)                        │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Encrypted Pager (Optional AES-256-GCM)  │  Free List Manager  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

## Design Principles

### 1. Unified Cross-Modal Queries

The key differentiator is **joining across storage modalities** in a single query:

```sql
-- Find hosts vulnerable to similar CVEs with attack paths under 3 hops
SELECT h.hostname, v.cve_id, sim.score
FROM hosts h
JOIN vulnerabilities v ON h.id = v.host_id
JOIN cve_embeddings e ON v.cve_id = e.cve_id
WHERE h.criticality > 8
  AND VECTOR_SIMILARITY(e.embedding, $query) > 0.85
  AND EXISTS (
    SELECT 1 FROM attack_paths(h.id) p WHERE p.hops <= 3
  )
```

### 2. Security-First Design

Every feature is designed with penetration testing in mind:

- **Attack path queries** - Find routes through the network
- **Blast radius analysis** - Impact of compromise
- **Credential chain tracking** - Lateral movement paths
- **CVE similarity search** - Related vulnerability discovery

### 3. Enterprise-Grade Performance

Inspired by production databases:

| Feature | Inspiration | Implementation |
|---------|-------------|----------------|
| Page Cache | Turso/SQLite | SIEVE algorithm (O(1)) |
| Query Planning | PostgreSQL | Cost-based optimizer |
| Graph Algorithms | Neo4j | PageRank, Betweenness, Louvain |
| Vector Search | Milvus/Chroma | HNSW + IVF + PQ |
| SPARQL | Apache Jena | Full BGP pattern matching |

### 4. Zero External Dependencies

All storage engines are implemented from scratch in Rust:

- No SQLite, LevelDB, or RocksDB
- No external graph libraries
- No FAISS or Annoy for vectors
- Just Rust standard library

## Comparison with Other Databases

| Feature | PostgreSQL | Neo4j | Milvus | **RedDB** |
|---------|------------|-------|--------|-----------|
| Tables | ✅ | ❌ | ❌ | ✅ |
| Graphs | ❌ (extensions) | ✅ | ❌ | ✅ |
| Vectors | ❌ (pgvector) | ❌ | ✅ | ✅ |
| Cross-Modal Joins | ❌ | ❌ | ❌ | ✅ |
| Security Queries | ❌ | Partial | ❌ | ✅ |
| Single Binary | ❌ | ❌ | ❌ | ✅ |
| Zero Dependencies | ❌ | ❌ | ❌ | ✅ |

## Use Cases

### Penetration Testing
- Store scan results (hosts, ports, services)
- Build attack graphs from discovered relationships
- Find shortest attack paths to critical assets
- Track credential chains for lateral movement

### Vulnerability Management
- Import CVE data with embeddings
- Find similar vulnerabilities by vector search
- Map affected hosts via graph relationships
- Calculate risk scores with PageRank

### Threat Intelligence
- Store indicators of compromise (IOCs)
- Link threats via graph relationships
- Semantic search across threat reports
- Pattern matching with SPARQL/Gremlin

### Asset Management
- Inventory hosts, services, certificates
- Model dependencies as graphs
- Detect configuration drift
- Calculate blast radius for changes

## Next Steps

- [Storage Modalities](/domains/database/01-storage.md) - Tables, Graphs, Vectors
- [Query Languages](/domains/database/02-query-languages.md) - SQL, Gremlin, Cypher, SPARQL
- [Graph Algorithms](/domains/database/03-graph-algorithms.md) - PageRank, Centrality, Pathfinding
- [Vector Search](/domains/database/04-vector-search.md) - HNSW, IVF, PQ, Hybrid
- [Caching](/domains/database/05-caching.md) - SIEVE, Result Cache, Aggregations
- [Security Queries](/domains/database/06-security-queries.md) - Attack Paths, Blast Radius
