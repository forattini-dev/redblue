# Caching

RedDB implements a multi-layer caching architecture inspired by Turso, Neo4j, and Milvus.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Caching Architecture                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Query Layer                           │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │    │
│  │  │Result Cache │  │Materialized │  │   Plan Cache    │  │    │
│  │  │(LFU + LRU)  │  │   Views     │  │   (LRU+TTL)     │  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                Aggregation Layer                         │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │  Precomputed: COUNT(*), SUM, AVG, MIN, MAX      │    │    │
│  │  │  Cardinality: Distinct values (HyperLogLog)     │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Page Cache Layer                       │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │           SIEVE Cache (O(1) eviction)           │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                     Storage Layer                        │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │    │
│  │  │  Page 0  │ │  Page 1  │ │  Page 2  │ │  Page N  │   │    │
│  │  │  4KB     │ │  4KB     │ │  4KB     │ │  4KB     │   │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## SIEVE Page Cache

SIEVE is a simple yet high-performance cache eviction algorithm with O(1) operations.

### Algorithm

```
┌─────────────────────────────────────────────────────────────────┐
│                    SIEVE Eviction Algorithm                      │
│                                                                  │
│  State:                                                         │
│  - Circular buffer of cache entries                             │
│  - "Hand" pointer for eviction scanning                         │
│  - Visited bit per entry                                        │
│                                                                  │
│  On Access (hit):                                               │
│    Set visited = true                                           │
│                                                                  │
│  On Insert (miss, cache full):                                  │
│    While hand→visited == true:                                  │
│      hand→visited = false                                       │
│      hand = hand.next()                                         │
│    Evict hand entry                                             │
│    Insert new entry at hand position                            │
│    hand = hand.next()                                           │
│                                                                  │
│  Why it works:                                                  │
│  - Frequently accessed pages get visited=true quickly           │
│  - Cold pages accumulate visited=false                          │
│  - Hand naturally finds cold pages to evict                     │
└─────────────────────────────────────────────────────────────────┘
```

### Comparison with Other Algorithms

| Algorithm | Hit on Access | Eviction | Memory Overhead | Performance |
|-----------|---------------|----------|-----------------|-------------|
| **LRU** | O(1) | O(1) | 2 pointers/entry | Good |
| **LFU** | O(log n) | O(log n) | Counter/entry | Variable |
| **CLOCK** | O(1) | O(n) worst | 1 bit/entry | Good |
| **SIEVE** | O(1) | O(1) amortized | 1 bit/entry | Excellent |

### Implementation

```rust
use redblue::storage::cache::{PageCache, CacheConfig, PageId};

let config = CacheConfig {
    max_pages: 10_000,      // 40 MB for 4KB pages
    page_size: 4096,
};

let mut cache = PageCache::new(config);

// Read page (auto-caches)
let page = cache.get_or_load(PageId(42), || {
    // Load from disk
    storage.read_page(42)
})?;

// Write page (marks dirty)
cache.put(PageId(42), new_data, true)?;

// Flush dirty pages
cache.flush()?;

// Statistics
let stats = cache.stats();
println!("Hit rate: {:.2}%", stats.hit_rate() * 100.0);
println!("Pages cached: {}", stats.cached_pages);
println!("Evictions: {}", stats.evictions);
```

### Configuration Tuning

```
Memory = max_pages × page_size

Example configurations:
- Development: 1,000 pages × 4KB = 4 MB
- Production: 100,000 pages × 4KB = 400 MB
- High-memory: 1,000,000 pages × 4KB = 4 GB

Rule of thumb:
- Allocate 10-25% of available RAM to page cache
- Monitor hit rate; < 90% may indicate undersized cache
```

---

## Result Cache

Caches complete query results with dependency-based invalidation.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Result Cache                               │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Cache Key: hash(query_text + parameters)                 │  │
│  │                                                           │  │
│  │  Entry:                                                   │  │
│  │  ┌─────────────────────────────────────────────────────┐ │  │
│  │  │  query: "SELECT * FROM hosts WHERE crit > 8"       │ │  │
│  │  │  result: [Row{...}, Row{...}, Row{...}]            │ │  │
│  │  │  created_at: 2024-01-15T10:30:00Z                  │ │  │
│  │  │  ttl: 5 minutes                                     │ │  │
│  │  │  dependencies: ["hosts"]                            │ │  │
│  │  │  hit_count: 42                                      │ │  │
│  │  │  memory_size: 1.2 KB                                │ │  │
│  │  └─────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Dependency Index:                                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  "hosts" → [cache_key_1, cache_key_5, cache_key_12]      │  │
│  │  "vulns" → [cache_key_2, cache_key_3]                    │  │
│  │  "hosts,vulns" → [cache_key_7]  (JOIN query)             │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Invalidation Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **TTL** | Expire after fixed time | Volatile data |
| **Dependency** | Invalidate on table change | Consistency-critical |
| **Sliding** | Reset TTL on each hit | Frequently accessed |
| **LRU** | Evict least recently used | Memory pressure |
| **LFU** | Evict least frequently used | Long-running queries |

### Usage

```rust
use redblue::storage::cache::{ResultCache, CachePolicy, CacheKey};

let mut cache = ResultCache::new(100 * 1024 * 1024); // 100 MB

// Define cache policy
let policy = CachePolicy {
    ttl: Duration::from_secs(300),      // 5 minutes
    dependencies: vec!["hosts"],         // Invalidate on hosts change
    priority: 5,                         // Higher = harder to evict
    sliding: true,                       // Reset TTL on hit
};

// Cache a result
let key = CacheKey::from_query("SELECT * FROM hosts WHERE crit > 8", &[]);
cache.put(key.clone(), query_result, policy);

// Get from cache
if let Some(result) = cache.get(&key) {
    return Ok(result);
}

// Invalidate on data change
cache.invalidate_table("hosts");  // All hosts-related queries gone
```

### Hybrid Eviction (LFU + LRU)

```
Eviction Score = (1 / frequency) × (now - last_access) × (1 / priority)

- Low frequency → higher eviction score
- Old access → higher eviction score
- Low priority → higher eviction score

Evict entries with highest scores first.
```

---

## Materialized Views

Precomputed query results that auto-refresh.

### Refresh Policies

| Policy | Trigger | Latency | Consistency |
|--------|---------|---------|-------------|
| **Manual** | Explicit call | User-controlled | Eventually |
| **OnChange** | Table mutation | Synchronous | Strong |
| **Periodic** | Timer | Background | Eventually |
| **AfterWrites** | N write ops | Batched | Eventually |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Materialized View                             │
│                                                                  │
│  Definition:                                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  name: "critical_hosts_summary"                           │  │
│  │  query: SELECT os, COUNT(*) as cnt, AVG(crit)            │  │
│  │         FROM hosts WHERE crit > 8 GROUP BY os            │  │
│  │  refresh: OnChange                                        │  │
│  │  dependencies: ["hosts"]                                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Materialized Data:                                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  ┌────────────┬───────┬──────────┐                       │  │
│  │  │ os         │ cnt   │ avg_crit │                       │  │
│  │  ├────────────┼───────┼──────────┤                       │  │
│  │  │ Linux      │ 42    │ 8.7      │                       │  │
│  │  │ Windows    │ 18    │ 9.1      │                       │  │
│  │  │ FreeBSD    │ 3     │ 8.2      │                       │  │
│  │  └────────────┴───────┴──────────┘                       │  │
│  │                                                           │  │
│  │  last_refresh: 2024-01-15T10:35:00Z                      │  │
│  │  refresh_count: 127                                       │  │
│  │  avg_refresh_time: 45ms                                   │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Usage

```rust
use redblue::storage::cache::{MaterializedViewCache, MaterializedViewDef, RefreshPolicy};

let mut views = MaterializedViewCache::new();

// Define view
let view_def = MaterializedViewDef {
    name: "critical_hosts_summary".to_string(),
    query: "SELECT os, COUNT(*) FROM hosts WHERE crit > 8 GROUP BY os".to_string(),
    dependencies: vec!["hosts".to_string()],
    refresh: RefreshPolicy::OnChange,
};

views.register(view_def)?;

// Query view (instant, uses materialized data)
let result = views.query("critical_hosts_summary")?;

// Manual refresh
views.refresh("critical_hosts_summary")?;

// On table change (automatic if OnChange policy)
views.on_table_change("hosts")?;
```

---

## Aggregation Cache

Precomputed aggregations for O(1) query responses.

### Tracked Aggregations

| Aggregation | Update Cost | Query Cost | Accuracy |
|-------------|-------------|------------|----------|
| **COUNT** | O(1) | O(1) | Exact |
| **SUM** | O(1) | O(1) | Exact |
| **AVG** | O(1) | O(1) | Exact |
| **MIN/MAX** | O(1) insert, O(n) delete | O(1) | Exact |
| **VARIANCE** | O(1) | O(1) | Exact |
| **DISTINCT** | O(1) | O(1) | Approximate (HLL) |

### Incremental Updates

```
┌─────────────────────────────────────────────────────────────────┐
│                   Incremental Aggregation                        │
│                                                                  │
│  On INSERT (value = 10.0):                                      │
│    sum += 10.0                                                  │
│    count += 1                                                   │
│    sum_sq += 100.0                                              │
│    min = min(min, 10.0)                                         │
│    max = max(max, 10.0)                                         │
│                                                                  │
│  On DELETE (value = 10.0):                                      │
│    sum -= 10.0                                                  │
│    count -= 1                                                   │
│    sum_sq -= 100.0                                              │
│    min/max → INVALIDATE (need full scan)                        │
│                                                                  │
│  Derived:                                                       │
│    avg = sum / count                                            │
│    variance = sum_sq/count - avg²                               │
│    stddev = √variance                                           │
└─────────────────────────────────────────────────────────────────┘
```

### Usage

```rust
use redblue::storage::cache::{AggregationCache, AggValue};
use std::collections::HashMap;

let mut agg_cache = AggregationCache::new();

// Register table for tracking
agg_cache.register_table("hosts", &["criticality", "status"]);

// On insert
let mut values = HashMap::new();
values.insert("criticality".to_string(), AggValue::Number(8.5));
values.insert("status".to_string(), AggValue::String("active".to_string()));
agg_cache.on_insert("hosts", &values);

// O(1) aggregation queries
let count = agg_cache.count("hosts");                    // Some(42)
let avg = agg_cache.avg("hosts", "criticality");         // Some(7.3)
let sum = agg_cache.sum("hosts", "criticality");         // Some(306.6)
let distinct = agg_cache.distinct_count("hosts", "status"); // Some(3)
```

### Cardinality Estimation (HyperLogLog)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cardinality Estimation                        │
│                                                                  │
│  Problem: COUNT(DISTINCT column) requires O(n) memory           │
│                                                                  │
│  Solution: HyperLogLog-style probabilistic counting             │
│                                                                  │
│  Exact Mode (< threshold values):                               │
│    Store actual hash values in HashSet                          │
│    Exact count, switches to approximate when full               │
│                                                                  │
│  Approximate Mode (≥ threshold values):                         │
│    Use probabilistic counting                                   │
│    Error: ~2% for large cardinalities                           │
│    Memory: O(1) regardless of cardinality                       │
│                                                                  │
│  Example:                                                       │
│    10,000 distinct IPs → exact (under threshold)               │
│    1,000,000 distinct IPs → approximate (over threshold)       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Plan Cache

Caches parsed and optimized query plans.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Plan Cache                                │
│                                                                  │
│  Query: SELECT * FROM hosts WHERE ip = ?                        │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  1. Normalize query (replace literals with ?)             │  │
│  │  2. Hash normalized query                                 │  │
│  │  3. Check cache                                           │  │
│  │     Hit → Use cached plan                                 │  │
│  │     Miss → Parse → Optimize → Cache                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Cached Plan:                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  normalized: "SELECT * FROM hosts WHERE ip = ?"          │  │
│  │  plan: IndexScan(hosts, ip_idx) → Project(*)             │  │
│  │  statistics: {hosts.rows: 10000, hosts.ip_distinct: 9500}│  │
│  │  compiled_at: 2024-01-15T10:00:00Z                       │  │
│  │  invalidate_on: ["hosts.ip_idx", "hosts.schema"]         │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Invalidation Triggers

| Event | Invalidation |
|-------|--------------|
| Table DROP/ALTER | All plans using table |
| Index CREATE/DROP | Plans using that index |
| Statistics update | Plans with outdated stats |
| Schema change | All cached plans |

---

## Cache Statistics

```rust
// Page cache stats
let page_stats = page_cache.stats();
println!("Page Cache:");
println!("  Hits: {} ({:.1}%)", page_stats.hits, page_stats.hit_rate() * 100.0);
println!("  Misses: {}", page_stats.misses);
println!("  Evictions: {}", page_stats.evictions);
println!("  Memory: {} MB", page_stats.memory_used / 1_000_000);

// Result cache stats
let result_stats = result_cache.stats();
println!("Result Cache:");
println!("  Entries: {}", result_stats.entries);
println!("  Memory: {} MB", result_stats.memory_used / 1_000_000);
println!("  Hit rate: {:.1}%", result_stats.hit_rate * 100.0);

// Aggregation cache stats
let agg_stats = agg_cache.stats();
println!("Aggregation Cache:");
println!("  Tables tracked: {}", agg_stats.tables);
println!("  Total rows: {}", agg_stats.total_rows);
println!("  Columns tracked: {}", agg_stats.tracked_columns);
```

---

## Best Practices

### Memory Allocation

```
Total available memory: 16 GB

Recommended allocation:
  Page Cache:        4 GB (25%)
  Result Cache:    512 MB (3%)
  Materialized Views: 256 MB (2%)
  Aggregation Cache:  64 MB (0.5%)
  Working memory:   11 GB (remaining)
```

### Cache Warming

```rust
// Warm page cache with frequently accessed tables
let tables = ["hosts", "services", "vulnerabilities"];
for table in tables {
    db.prefetch_table(table)?;
}

// Warm result cache with common queries
let common_queries = [
    "SELECT COUNT(*) FROM hosts",
    "SELECT os, COUNT(*) FROM hosts GROUP BY os",
];
for query in common_queries {
    let _ = db.execute(query);  // Result gets cached
}

// Refresh materialized views
db.refresh_all_views()?;
```

### Monitoring

```sql
-- Check cache hit rates
SELECT * FROM sys.cache_stats;

-- Find cache-inefficient queries
SELECT query, hit_rate, miss_count
FROM sys.query_stats
WHERE hit_rate < 0.5
ORDER BY miss_count DESC
LIMIT 10;

-- Memory usage by cache
SELECT cache_name, memory_mb, entry_count
FROM sys.cache_memory
ORDER BY memory_mb DESC;
```

---

## See Also

- [Storage Modalities](/domains/database/01-storage.md) - Page-based storage
- [Query Languages](/domains/database/02-query-languages.md) - Query optimization
- [Security Queries](/domains/database/06-security-queries.md) - Cached security queries
