# Graph Algorithms

RedDB implements graph algorithms from scratch, inspired by Neo4j GDS and Apache TinkerPop.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Graph Algorithm Suite                         │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐ │
│  │  Centrality    │  │  Path Finding  │  │  Community         │ │
│  │                │  │                │  │  Detection         │ │
│  │  • PageRank    │  │  • Dijkstra    │  │  • Louvain         │ │
│  │  • Betweenness │  │  • BFS         │  │  • Label Prop      │ │
│  │  • Closeness   │  │  • DFS         │  │  • Connected       │ │
│  │  • Degree      │  │  • All Paths   │  │    Components      │ │
│  │  • Eigenvector │  │  • K-Shortest  │  │  • Triangle Count  │ │
│  └────────────────┘  └────────────────┘  └────────────────────┘ │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐ │
│  │  Similarity    │  │  Link          │  │  Security          │ │
│  │                │  │  Prediction    │  │  Specific          │ │
│  │  • Jaccard     │  │  • Common      │  │  • Attack Paths    │ │
│  │  • Cosine      │  │    Neighbors   │  │  • Lateral Move    │ │
│  │  • Overlap     │  │  • Adamic-Adar │  │  • Blast Radius    │ │
│  │  • Euclidean   │  │  • Preferential│  │  • Choke Points    │ │
│  └────────────────┘  └────────────────┘  └────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Centrality Algorithms

### PageRank

Identifies the most important nodes based on incoming links. In security context, finds critical assets that many other systems depend on.

**Algorithm:**

```
PR(A) = (1-d)/N + d × Σ(PR(Ti)/C(Ti))

Where:
- d = damping factor (typically 0.85)
- N = total nodes
- Ti = nodes linking to A
- C(Ti) = outbound links from Ti
```

**Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                      PageRank Iteration                      │
│                                                              │
│  Iteration 0:  [1/N, 1/N, 1/N, 1/N, 1/N]  (uniform)        │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  For each node:                                      │    │
│  │    new_rank = (1-d)/N + d × Σ(neighbor_rank/degree) │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Iteration 1:  [0.12, 0.25, 0.18, 0.30, 0.15]              │
│  Iteration 2:  [0.11, 0.28, 0.16, 0.32, 0.13]              │
│  ...                                                         │
│  Converged:    [0.10, 0.29, 0.15, 0.33, 0.13]              │
│                                                              │
│  Convergence: |new - old| < epsilon (1e-6)                  │
└─────────────────────────────────────────────────────────────┘
```

**Usage:**

```rust
use redblue::storage::engine::PageRank;

let pagerank = PageRank::new(0.85, 100, 1e-6);
let scores = pagerank.compute(&graph);

// Top 10 critical assets
let critical = scores.into_iter()
    .sorted_by(|a, b| b.1.partial_cmp(&a.1).unwrap())
    .take(10)
    .collect::<Vec<_>>();
```

**Security Use Case:**

```sql
-- Find critical infrastructure (high PageRank)
SELECT hostname, pagerank_score
FROM hosts
WHERE pagerank_score > 0.1
ORDER BY pagerank_score DESC;
```

---

### Betweenness Centrality

Identifies nodes that act as bridges between other nodes. In security, these are **choke points** - compromising them affects many attack paths.

**Algorithm:**

```
BC(v) = Σ (σst(v) / σst)

Where:
- σst = shortest paths from s to t
- σst(v) = shortest paths from s to t through v
```

**Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                 Betweenness Centrality                       │
│                                                              │
│  For each source node s:                                    │
│    1. BFS from s → shortest path counts                     │
│    2. Backtrack → accumulate path dependencies              │
│                                                              │
│  Example Graph:                                             │
│       A ──── B ──── D                                       │
│        \    / \    /                                        │
│         \  /   \  /                                         │
│          C      E                                           │
│                                                              │
│  Betweenness Scores:                                        │
│    A: 0.0  (endpoint)                                       │
│    B: 6.0  (bridge between clusters)                        │
│    C: 0.0  (no paths through)                               │
│    D: 0.0  (endpoint)                                       │
│    E: 2.0  (some paths through)                             │
└─────────────────────────────────────────────────────────────┘
```

**Usage:**

```rust
use redblue::storage::engine::BetweennessCentrality;

// Compute betweenness (normalized)
let scores = BetweennessCentrality::compute(&graph, true);

// Find choke points
for (node, score) in scores.iter().take(5) {
    println!("Choke point: {} (betweenness: {:.4})", node, score);
}
```

**Security Use Case:**

```cypher
-- Find network choke points
MATCH (h:Host)
WITH h, algo.betweenness(h) as bc
WHERE bc > 0.1
RETURN h.hostname, bc
ORDER BY bc DESC
LIMIT 10
```

---

### Degree Centrality

Simplest centrality measure - counts connections. High in-degree means many depend on it; high out-degree means it depends on many.

```
In-Degree:  DC_in(v) = |{u : (u,v) ∈ E}|
Out-Degree: DC_out(v) = |{u : (v,u) ∈ E}|
Total:      DC(v) = DC_in(v) + DC_out(v)
```

**Usage:**

```rust
// Get degree centrality
for node in graph.nodes() {
    let in_deg = graph.in_degree(&node);
    let out_deg = graph.out_degree(&node);
    println!("{}: in={}, out={}", node, in_deg, out_deg);
}
```

---

### Closeness Centrality

Measures how close a node is to all other nodes. Useful for finding assets that can reach (or be reached by) others quickly.

```
CC(v) = (N-1) / Σ d(v,u)

Where d(v,u) is shortest path distance from v to u
```

**Usage:**

```rust
use redblue::storage::engine::ClosenessCentrality;

let scores = ClosenessCentrality::compute(&graph);

// Find most "central" hosts (can reach others quickly)
for (node, closeness) in scores.iter().take(10) {
    println!("{}: closeness = {:.4}", node, closeness);
}
```

---

## Path Finding Algorithms

### Dijkstra's Algorithm

Finds shortest weighted paths. In security, weights can represent latency, difficulty of exploitation, or required privileges.

**Algorithm:**

```
┌─────────────────────────────────────────────────────────────┐
│                    Dijkstra's Algorithm                      │
│                                                              │
│  1. Initialize: dist[source] = 0, dist[others] = ∞         │
│  2. Priority queue ordered by distance                       │
│  3. While queue not empty:                                   │
│     - Pop minimum distance node u                            │
│     - For each neighbor v:                                   │
│       - If dist[u] + weight(u,v) < dist[v]:                 │
│         - Update dist[v]                                     │
│         - Update predecessor[v] = u                          │
│  4. Reconstruct path from predecessor map                    │
│                                                              │
│  Time: O((V + E) log V) with binary heap                    │
└─────────────────────────────────────────────────────────────┘
```

**Usage:**

```rust
use redblue::storage::engine::Dijkstra;

let dijkstra = Dijkstra::new();
let path = dijkstra.shortest_path(&graph, "host:entry", "host:target");

match path {
    Some((cost, nodes)) => {
        println!("Path cost: {}", cost);
        println!("Path: {}", nodes.join(" -> "));
    }
    None => println!("No path exists"),
}
```

**Security Use Case:**

```sql
-- Find shortest attack path (by exploitation difficulty)
SELECT * FROM shortest_path(
    'host:attacker',
    'host:crown_jewel',
    'difficulty'  -- weight column
);
```

---

### Breadth-First Search (BFS)

Explores nodes level by level. Finds shortest unweighted paths.

```
┌─────────────────────────────────────────────────────────────┐
│                          BFS                                 │
│                                                              │
│  Level 0:  [A]                                              │
│  Level 1:  [B, C]                                           │
│  Level 2:  [D, E, F]                                        │
│  Level 3:  [G, H]                                           │
│                                                              │
│       A ──┬── B ──── D ──── G                               │
│           │                  │                               │
│           └── C ──┬── E     H                               │
│                   └── F                                      │
└─────────────────────────────────────────────────────────────┘
```

**Usage:**

```rust
use redblue::storage::engine::BFS;

// Find all nodes within N hops
let reachable = BFS::reachable_within(&graph, "host:entry", 3);
println!("Hosts within 3 hops: {:?}", reachable);

// Get hop distance to all nodes
let distances = BFS::distances(&graph, "host:entry");
for (node, dist) in distances {
    println!("{} is {} hops away", node, dist);
}
```

---

### Depth-First Search (DFS)

Explores as deep as possible before backtracking. Useful for finding cycles and connected components.

```rust
use redblue::storage::engine::DFS;

// Find all paths (may be exponential!)
let all_paths = DFS::all_paths(&graph, "host:a", "host:z", 10);

// Detect cycles
let cycles = DFS::find_cycles(&graph);
```

---

### All Shortest Paths

Finds all paths with minimum length between two nodes.

```rust
// Find all shortest attack paths (not just one)
let paths = graph.all_shortest_paths("entry", "target");

for path in paths {
    println!("Alternative: {}", path.join(" -> "));
}
```

---

### K-Shortest Paths

Finds the k shortest paths, including non-optimal ones.

```rust
use redblue::storage::engine::YenKSP;

// Find 5 shortest paths
let paths = YenKSP::compute(&graph, "source", "target", 5);

for (i, (cost, path)) in paths.iter().enumerate() {
    println!("Path {}: cost={}, nodes={}", i+1, cost, path.join("->"));
}
```

---

## Community Detection

### Louvain Algorithm

Detects communities by optimizing modularity. In security, finds network segments or organizational boundaries.

**Algorithm:**

```
┌─────────────────────────────────────────────────────────────┐
│                    Louvain Algorithm                         │
│                                                              │
│  Phase 1: Local Optimization                                │
│    - Each node starts in its own community                  │
│    - Move nodes to neighbor's community if modularity ↑     │
│    - Repeat until no improvement                            │
│                                                              │
│  Phase 2: Aggregation                                       │
│    - Merge nodes in same community into super-node          │
│    - Edges between communities become weighted              │
│                                                              │
│  Repeat Phase 1 + 2 until convergence                       │
│                                                              │
│  Modularity: Q = (1/2m) Σ [Aij - (ki*kj/2m)] δ(ci,cj)      │
└─────────────────────────────────────────────────────────────┘
```

**Usage:**

```rust
use redblue::storage::engine::Louvain;

let communities = Louvain::detect(&graph);

// Group hosts by community
for (community_id, members) in communities {
    println!("Community {}: {} hosts", community_id, members.len());
    for host in members.iter().take(5) {
        println!("  - {}", host);
    }
}
```

**Security Use Case:**

```sql
-- Find network segments for lateral movement analysis
SELECT community_id, COUNT(*) as size,
       GROUP_CONCAT(hostname) as hosts
FROM louvain_communities
GROUP BY community_id
ORDER BY size DESC;
```

---

### Connected Components

Finds disconnected subgraphs.

```rust
// Find strongly connected components (directed)
let sccs = graph.strongly_connected_components();

// Find weakly connected components (undirected)
let wccs = graph.weakly_connected_components();

println!("Found {} isolated network segments", wccs.len());
```

---

### Triangle Counting

Counts triangles (3-cliques) for clustering coefficient.

```
Clustering Coefficient: C(v) = 2T(v) / (k(v) * (k(v)-1))

Where:
- T(v) = triangles containing v
- k(v) = degree of v
```

```rust
let triangles = graph.triangle_count();
let clustering = graph.clustering_coefficient();

println!("Triangles: {}", triangles);
println!("Avg clustering: {:.4}", clustering);
```

---

## Similarity Algorithms

### Jaccard Similarity

Measures overlap between node neighborhoods.

```
J(A,B) = |N(A) ∩ N(B)| / |N(A) ∪ N(B)|
```

```rust
let similarity = graph.jaccard_similarity("host:a", "host:b");
println!("Jaccard similarity: {:.4}", similarity);
```

### Cosine Similarity

Based on shared neighbors as vectors.

```rust
let similarity = graph.cosine_similarity("host:a", "host:b");
```

### Overlap Coefficient

```
Overlap(A,B) = |N(A) ∩ N(B)| / min(|N(A)|, |N(B)|)
```

---

## Security-Specific Algorithms

### Attack Path Analysis

Finds all viable attack paths between entry point and target.

```rust
use redblue::storage::query::AttackPathQuery;

let query = AttackPathQuery {
    from: "host:entry".to_string(),
    to: "host:crown_jewel".to_string(),
    max_hops: 5,
    via_edge_types: vec!["CONNECTS_TO", "AUTH_ACCESS"],
    min_severity: Some(7.0),
};

let paths = security.attack_paths(query)?;

for path in paths {
    println!("Path: {} hops, max severity: {}",
             path.hops, path.max_severity);
    for step in path.steps {
        println!("  {} --[{}]--> {}",
                 step.from, step.edge_type, step.to);
    }
}
```

### Lateral Movement Simulation

Simulates attacker movement through the network.

```rust
use redblue::storage::query::LateralMovementQuery;

let query = LateralMovementQuery {
    from: "host:compromised".to_string(),
    max_depth: 5,
    admin_only: true,  // Only follow admin credential edges
};

let result = security.lateral_movement(query)?;

println!("Reachable hosts: {}", result.reachable.len());
for host in result.reachable {
    println!("  {} (depth: {})", host.hostname, host.depth);
}
```

### Blast Radius Calculation

Calculates impact of a compromised asset.

```rust
use redblue::storage::query::BlastRadiusQuery;

let query = BlastRadiusQuery {
    compromised: "host:webserver".to_string(),
    depth: 3,
    transitive: true,
};

let radius = security.blast_radius(query)?;

println!("Direct impact: {} hosts", radius.direct.len());
println!("Transitive impact: {} hosts", radius.transitive.len());
println!("Critical assets affected: {}", radius.critical_count);
```

---

## Performance Characteristics

| Algorithm | Time Complexity | Space Complexity | Parallelizable |
|-----------|-----------------|------------------|----------------|
| PageRank | O(V + E) per iter | O(V) | ✅ |
| Betweenness | O(V × E) | O(V + E) | ✅ |
| Dijkstra | O((V + E) log V) | O(V) | ❌ |
| BFS | O(V + E) | O(V) | ❌ |
| Louvain | O(V log V) | O(V + E) | Partial |
| SCC | O(V + E) | O(V) | ❌ |

---

## See Also

- [Storage Modalities](/domains/database/01-storage.md) - Graph storage architecture
- [Query Languages](/domains/database/02-query-languages.md) - Gremlin/Cypher queries
- [Security Queries](/domains/database/06-security-queries.md) - Security-specific algorithms
