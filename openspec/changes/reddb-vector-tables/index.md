# RedDB - Embedded Database for redblue

## Overview

A purpose-built embedded database engine for redblue security intelligence storage, implemented from scratch in pure Rust with **zero external dependencies**.

## Proposals

### 1. [Base RedDB Engine](../reddb-base/proposal.md)
Core database functionality:
- Page-based storage (4KB pages)
- B-tree indexing for fast lookups
- Write-Ahead Logging (WAL) for durability
- Type-safe schema system
- Query engine

**Estimate:** ~8,400 LOC, ~22 days

### 2. [Vector Tables Extension](./proposal.md)
Vector-optimized storage for ML/security embeddings:
- Dense/Sparse/Binary vector types
- Distance metrics (Cosine, L2, Dot, Hamming)
- Index strategies (Flat, IVF, HNSW)
- Table-vector relationships (OneToOne, OneToMany, ManyToMany)
- Similarity search queries

**Estimate:** ~3,200 LOC, ~14-18 days

## Combined Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           RedDB                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────┐  ┌─────────────────────────────────┐ │
│  │     Query Engine         │  │      Vector Engine              │ │
│  │                          │  │                                 │ │
│  │  - Schema validation     │  │  - Similarity search            │ │
│  │  - B-tree traversal      │  │  - Index maintenance            │ │
│  │  - Join execution        │◄─►  - Distance calculations        │ │
│  │  - Filter evaluation     │  │  - Relationship resolution      │ │
│  └──────────┬───────────────┘  └────────────┬────────────────────┘ │
│             │                               │                      │
│             └───────────────┬───────────────┘                      │
│                             │                                      │
│                   ┌─────────▼─────────┐                            │
│                   │      Pager        │                            │
│                   │                   │                            │
│                   │  - Page cache     │                            │
│                   │  - Read/Write     │                            │
│                   │  - Checksums      │                            │
│                   └─────────┬─────────┘                            │
│                             │                                      │
│      ┌──────────────────────┼──────────────────────┐               │
│      │                      │                      │               │
│  ┌───▼───┐            ┌─────▼─────┐         ┌──────▼──────┐        │
│  │ B-tree │            │  Vector   │         │    WAL      │        │
│  │ Pages  │            │  Pages    │         │  (Append)   │        │
│  └───┬────┘            └─────┬─────┘         └──────┬──────┘        │
│      │                       │                      │               │
│      └───────────────────────┴──────────────────────┘               │
│                              │                                      │
│                    ┌─────────▼─────────┐                            │
│                    │   .rdb File       │                            │
│                    │                   │                            │
│                    │ [Header]          │                            │
│                    │ [B-tree Pages]    │                            │
│                    │ [Vector Pages]    │                            │
│                    │ [Index Pages]     │                            │
│                    │ [WAL Segment]     │                            │
│                    └───────────────────┘                            │
└─────────────────────────────────────────────────────────────────────┘
```

## Use Case Example

```rust
// Complete security intelligence workflow
use reddb::prelude::*;

fn main() -> Result<()> {
    let db = RedDB::open("scan-results.rdb")?;

    // Define schema with vector relationships
    let schema = Schema::new()
        .table("hosts")
            .column("id", Type::U64, Primary)
            .column("ip", Type::String, Indexed)
            .column("hostname", Type::String, None)
            .column("open_ports", Type::Array(Type::U16), None)
            .column("last_scan", Type::Timestamp, Indexed)

        .vector_table("host_behaviors")
            .dimensions(128)
            .dtype(VectorType::Float32Dense)
            .index(IndexType::HNSW { m: 16, ef: 64 })
            .relates_to("hosts", RelationType::OneToOne)

        .table("domains")
            .column("id", Type::U64, Primary)
            .column("name", Type::String, Indexed)
            .column("registrar", Type::String, None)

        .vector_table("domain_embeddings")
            .dimensions(256)
            .dtype(VectorType::Float32Dense)
            .index(IndexType::IVF { nlist: 100, nprobe: 10 })
            .relates_to("domains", RelationType::OneToMany)

        .build();

    db.create_tables(&schema)?;

    // Insert host with behavior vector
    let host_id = db.insert("hosts", &json!({
        "ip": "192.168.1.100",
        "hostname": "web-server",
        "open_ports": [22, 80, 443],
        "last_scan": now()
    }))?;

    let behavior = extract_behavior_features(&host_data);
    db.insert_vector("host_behaviors", host_id, behavior)?;

    // Find hosts with similar behavior patterns
    let suspicious_behavior = get_suspicious_behavior();
    let similar_hosts = db.query("hosts")
        .join_vectors("host_behaviors")
        .where_similar("host_behaviors", &suspicious_behavior, 0.8)
        .order_by_similarity()
        .limit(10)
        .fetch::<Host>()?;

    for (host, distance) in similar_hosts {
        println!("Suspicious: {} ({}) - similarity: {:.3}",
            host.hostname, host.ip, 1.0 - distance);
    }

    Ok(())
}
```

## Implementation Timeline

| Week | Phase | Deliverables |
|------|-------|-------------|
| 1-2 | Core Storage | Page format, Pager, basic I/O |
| 3-4 | B-tree Engine | Insert, search, delete, iteration |
| 5-6 | WAL + Durability | Crash recovery, checkpoints |
| 7-8 | Vector Foundation | Types, distance ops, flat index |
| 9-10 | Vector Indexes | IVF, HNSW implementation |
| 11-12 | Relationships | OneToOne, OneToMany, joins |
| 13-14 | Query Engine | Builder pattern, filters, sorting |
| 15-16 | Optimization | SIMD, batch ops, compression |

## Total Effort

| Component | Lines of Code | Days |
|-----------|---------------|------|
| Base RedDB | ~8,400 | 22 |
| Vector Tables | ~3,200 | 14-18 |
| **Total** | **~11,600** | **36-40** |

## File Structure

```
src/storage/
├── mod.rs
├── page.rs           # Page types and layout
├── pager.rs          # Page management
├── btree.rs          # B-tree implementation
├── wal.rs            # Write-ahead log
├── schema.rs         # Type-safe schema
├── query.rs          # Query builder
├── vector/
│   ├── mod.rs
│   ├── types.rs      # Dense, Sparse, Binary vectors
│   ├── distance.rs   # Cosine, L2, Dot, Hamming
│   ├── flat.rs       # Flat (exact) index
│   ├── ivf.rs        # IVF (approximate) index
│   ├── hnsw.rs       # HNSW (graph) index
│   ├── relation.rs   # Table-vector relationships
│   └── query.rs      # Similarity search
└── format.rs         # .rdb file format
```

## Next Steps

1. **Review proposals** - Ensure architecture meets redblue's needs
2. **Prioritize features** - Decide which vector indexes are essential
3. **Begin implementation** - Start with Phase 1 (Page + Pager)
4. **Iterate** - Build incrementally with tests at each phase
