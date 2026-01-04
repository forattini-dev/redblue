# Query Languages

RedDB supports multiple query languages, each optimized for different data modalities and use cases.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Query Layer                                 │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐ │
│  │   SQL   │ │ Gremlin │ │ Cypher  │ │ SPARQL  │ │ Natural   │ │
│  │         │ │         │ │         │ │         │ │ Language  │ │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └─────┬─────┘ │
│       │          │          │          │             │         │
│       └──────────┴──────────┴──────────┴─────────────┘         │
│                              │                                   │
│                    ┌─────────▼─────────┐                        │
│                    │   Multi-Mode      │                        │
│                    │   Parser          │                        │
│                    │   (Auto-Detect)   │                        │
│                    └─────────┬─────────┘                        │
│                              │                                   │
│                    ┌─────────▼─────────┐                        │
│                    │   Query Planner   │                        │
│                    │   (Cost-Based)    │                        │
│                    └─────────┬─────────┘                        │
│                              │                                   │
│           ┌──────────────────┼──────────────────┐               │
│           ▼                  ▼                  ▼               │
│     ┌──────────┐      ┌──────────┐       ┌──────────┐          │
│     │  Table   │      │  Graph   │       │  Vector  │          │
│     │ Executor │      │ Executor │       │ Executor │          │
│     └──────────┘      └──────────┘       └──────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## Language Selection Guide

| Language | Best For | Data Mode | Complexity |
|----------|----------|-----------|------------|
| **SQL** | Structured data, aggregations, joins | Tables | Low-Medium |
| **Gremlin** | Graph traversals, path queries | Graphs | Medium |
| **Cypher** | Pattern matching, relationships | Graphs | Medium |
| **SPARQL** | RDF triples, ontology queries | Graphs | High |
| **Natural** | Semantic search, AI-assisted | Vectors | Low |

---

## SQL (Tables)

SQL is the primary query language for relational data in tables.

### Supported Features

| Feature | Status | Example |
|---------|--------|---------|
| SELECT | ✅ | `SELECT * FROM hosts` |
| INSERT | ✅ | `INSERT INTO hosts (...)` |
| UPDATE | ✅ | `UPDATE hosts SET ...` |
| DELETE | ✅ | `DELETE FROM hosts WHERE ...` |
| JOIN | ✅ | `... JOIN services ON ...` |
| GROUP BY | ✅ | `... GROUP BY os` |
| ORDER BY | ✅ | `... ORDER BY criticality DESC` |
| LIMIT/OFFSET | ✅ | `... LIMIT 10 OFFSET 20` |
| Subqueries | ✅ | `SELECT * FROM (SELECT ...)` |
| CTEs | ✅ | `WITH cte AS (...) SELECT ...` |
| Window Functions | ✅ | `RANK() OVER (...)` |
| Aggregates | ✅ | `COUNT, SUM, AVG, MIN, MAX` |

### Query Examples

```sql
-- Basic SELECT with filters
SELECT hostname, ip, os, criticality
FROM hosts
WHERE criticality > 7.0
  AND os LIKE '%Linux%'
ORDER BY criticality DESC
LIMIT 10;

-- JOIN across tables
SELECT h.hostname, s.port, s.protocol, s.version
FROM hosts h
JOIN services s ON h.id = s.host_id
WHERE s.port IN (22, 80, 443, 3389)
ORDER BY h.hostname, s.port;

-- Aggregations
SELECT os,
       COUNT(*) as host_count,
       AVG(criticality) as avg_crit,
       MAX(criticality) as max_crit
FROM hosts
GROUP BY os
HAVING COUNT(*) > 5
ORDER BY avg_crit DESC;

-- Window functions for ranking
SELECT hostname,
       criticality,
       RANK() OVER (ORDER BY criticality DESC) as risk_rank,
       NTILE(4) OVER (ORDER BY criticality DESC) as quartile
FROM hosts;

-- CTE for complex queries
WITH critical_hosts AS (
    SELECT id, hostname
    FROM hosts
    WHERE criticality > 8.0
),
vuln_count AS (
    SELECT host_id, COUNT(*) as vuln_cnt
    FROM vulnerabilities
    GROUP BY host_id
)
SELECT ch.hostname, vc.vuln_cnt
FROM critical_hosts ch
JOIN vuln_count vc ON ch.id = vc.host_id
ORDER BY vc.vuln_cnt DESC;
```

### Vector Extensions

SQL is extended with vector functions for hybrid queries:

```sql
-- Find similar CVEs using vector search
SELECT cve_id, description, cvss,
       VECTOR_DISTANCE(embedding, $query) as similarity
FROM vulnerabilities
WHERE VECTOR_SIMILAR(embedding, $query, 10)
  AND cvss >= 7.0
ORDER BY similarity;

-- Combine vector search with graph traversal
SELECT h.hostname, v.cve_id
FROM hosts h
JOIN vulnerabilities v ON h.id = v.host_id
WHERE VECTOR_SIMILAR(v.embedding, $query, 10)
  AND EXISTS (
    SELECT 1 FROM attack_paths(h.id) p WHERE p.hops <= 3
  );
```

---

## Gremlin (Graphs)

Gremlin is Apache TinkerPop's graph traversal language, ideal for navigating relationships.

### Traversal Steps

| Step | Description | Example |
|------|-------------|---------|
| `V()` | All vertices | `g.V()` |
| `E()` | All edges | `g.E()` |
| `out()` | Outgoing edges | `g.V('host1').out()` |
| `in()` | Incoming edges | `g.V('host1').in()` |
| `both()` | Both directions | `g.V('host1').both()` |
| `outE()` | Outgoing edge objects | `g.V('host1').outE()` |
| `inV()` | Incoming vertex | `g.E().inV()` |
| `has()` | Filter by property | `g.V().has('type', 'host')` |
| `values()` | Get property values | `g.V().values('hostname')` |
| `count()` | Count results | `g.V().count()` |
| `path()` | Get traversal path | `g.V('host1').repeat(out()).path()` |
| `repeat()` | Repeat traversal | `g.V().repeat(out()).times(3)` |
| `until()` | Repeat until condition | `g.V().repeat(out()).until(has('critical'))` |

### Query Examples

```groovy
// Find all hosts
g.V().hasLabel('host')

// Get neighbors of a specific host
g.V('host:web01').out().values('hostname')

// Find services running on critical hosts
g.V().has('host', 'criticality', gt(8.0))
     .out('HAS_SERVICE')
     .values('port', 'protocol')

// Find attack paths (3 hops max)
g.V('host:attacker')
 .repeat(out('CONNECTS_TO', 'AUTH_ACCESS'))
 .times(3)
 .path()
 .by('hostname')

// Find all hosts reachable via specific credential
g.V('cred:admin_key')
 .out('AUTH_ACCESS')
 .emit()
 .repeat(out('CONNECTS_TO'))
 .times(5)
 .dedup()
 .values('hostname')

// Calculate degree centrality
g.V().hasLabel('host')
     .project('hostname', 'degree')
     .by('hostname')
     .by(both().count())
     .order()
     .by(select('degree'), desc)
     .limit(10)

// Find shortest path between two hosts
g.V('host:entry')
 .repeat(out().simplePath())
 .until(hasId('host:target'))
 .path()
 .limit(1)
```

### Security-Specific Traversals

```groovy
// Lateral movement paths
g.V('host:compromised')
 .repeat(
   outE('AUTH_ACCESS').has('admin', true)
   .inV()
 )
 .emit()
 .times(5)
 .path()
 .by('hostname')

// Blast radius from compromised host
g.V('host:compromised')
 .emit()
 .repeat(out())
 .times(3)
 .dedup()
 .groupCount()
 .by(label)

// Find credential chains
g.V('cred:stolen')
 .repeat(
   out('AUTH_ACCESS')
   .out('HAS_CREDENTIAL')
 )
 .emit()
 .times(4)
 .path()
```

---

## Cypher (Graphs)

Cypher is Neo4j's declarative graph query language, focused on pattern matching.

### Pattern Syntax

```
(n)             -- Node
(n:Host)        -- Node with label
(n:Host {ip: '10.0.0.1'})  -- Node with properties
-[r]->          -- Directed relationship
-[r:CONNECTS_TO]->  -- Typed relationship
-[r:CONNECTS_TO*1..3]->  -- Variable length (1-3 hops)
```

### Query Examples

```cypher
// Find all hosts
MATCH (h:Host)
RETURN h.hostname, h.ip, h.criticality

// Find hosts connected to a specific host
MATCH (h:Host {hostname: 'web01'})-[:CONNECTS_TO]->(neighbor)
RETURN neighbor.hostname

// Find services on critical hosts
MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
WHERE h.criticality > 8.0
RETURN h.hostname, s.port, s.protocol
ORDER BY h.criticality DESC

// Find attack paths (max 3 hops)
MATCH path = (entry:Host {hostname: 'entry-point'})
             -[:CONNECTS_TO|AUTH_ACCESS*1..3]->
             (target:Host {hostname: 'database'})
RETURN path

// Find shortest path
MATCH (start:Host {hostname: 'attacker'}),
      (end:Host {hostname: 'crown-jewel'}),
      path = shortestPath((start)-[*..10]->(end))
RETURN path

// Find all paths with credential usage
MATCH path = (start:Host)-[:AUTH_ACCESS*1..5]->(end:Host)
WHERE end.criticality > 9.0
RETURN path, length(path) as hops
ORDER BY hops

// Lateral movement analysis
MATCH (compromised:Host {compromised: true})
MATCH path = (compromised)-[:AUTH_ACCESS*1..4]->(target:Host)
WHERE target.criticality > 7.0
RETURN DISTINCT target.hostname,
       min(length(path)) as min_hops

// Aggregate analysis
MATCH (h:Host)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN h.hostname,
       count(v) as vuln_count,
       max(v.cvss) as max_cvss
ORDER BY vuln_count DESC
LIMIT 10

// Pattern matching for specific topology
MATCH (web:Host)-[:CONNECTS_TO]->(app:Host)-[:CONNECTS_TO]->(db:Host)
WHERE web.tier = 'dmz'
  AND app.tier = 'application'
  AND db.tier = 'database'
RETURN web.hostname, app.hostname, db.hostname
```

### Security Patterns

```cypher
// Find privilege escalation paths
MATCH path = (user:User {privilege: 'low'})
             -[:HAS_ACCESS]->(:Host)
             -[:AUTH_ACCESS*1..3]->
             (target:Host)
             <-[:HAS_ACCESS]-(admin:User {privilege: 'admin'})
RETURN path

// Identify choke points (high betweenness)
MATCH (h:Host)
WITH h, size((h)<--()) as in_degree, size((h)-->()) as out_degree
WHERE in_degree > 3 AND out_degree > 3
RETURN h.hostname, in_degree, out_degree
ORDER BY in_degree + out_degree DESC

// Find isolated network segments
MATCH (h:Host)
WHERE NOT (h)-[:CONNECTS_TO]->()
  AND NOT (h)<-[:CONNECTS_TO]-()
RETURN h.hostname, h.ip
```

---

## SPARQL (RDF/Semantic)

SPARQL queries RDF-style triples, useful for ontology-based security data.

### Triple Pattern

```
?subject ?predicate ?object .
```

### Query Examples

```sparql
# Find all hosts
PREFIX sec: <http://security.example.org/>
SELECT ?hostname ?ip
WHERE {
  ?host a sec:Host .
  ?host sec:hostname ?hostname .
  ?host sec:ip ?ip .
}

# Find vulnerabilities affecting Linux hosts
PREFIX sec: <http://security.example.org/>
SELECT ?hostname ?cve ?cvss
WHERE {
  ?host a sec:Host .
  ?host sec:hostname ?hostname .
  ?host sec:os ?os .
  FILTER(CONTAINS(?os, "Linux"))

  ?host sec:affectedBy ?vuln .
  ?vuln sec:cveId ?cve .
  ?vuln sec:cvss ?cvss .
  FILTER(?cvss >= 7.0)
}
ORDER BY DESC(?cvss)

# Find network paths (property paths)
PREFIX sec: <http://security.example.org/>
SELECT ?start ?end (COUNT(?mid) as ?hops)
WHERE {
  ?start sec:hostname "entry-point" .
  ?start sec:connectsTo+ ?mid .
  ?mid sec:connectsTo* ?end .
  ?end sec:hostname "target" .
}
GROUP BY ?start ?end

# CONSTRUCT new triples
PREFIX sec: <http://security.example.org/>
CONSTRUCT {
  ?host sec:riskLevel "CRITICAL" .
}
WHERE {
  ?host a sec:Host .
  ?host sec:criticality ?crit .
  FILTER(?crit > 9.0)
}

# ASK if path exists
PREFIX sec: <http://security.example.org/>
ASK {
  ?attacker sec:hostname "attacker" .
  ?attacker sec:connectsTo+ ?target .
  ?target sec:hostname "crown-jewel" .
}

# Federated query (external SPARQL endpoint)
PREFIX sec: <http://security.example.org/>
PREFIX nvd: <http://nvd.nist.gov/>
SELECT ?cve ?description
WHERE {
  ?vuln sec:cveId ?cve .
  SERVICE <http://nvd.nist.gov/sparql> {
    ?nvdEntry nvd:id ?cve .
    ?nvdEntry nvd:description ?description .
  }
}
```

### Property Paths

| Syntax | Meaning |
|--------|---------|
| `p+` | One or more |
| `p*` | Zero or more |
| `p?` | Zero or one |
| `p{n}` | Exactly n |
| `p{n,m}` | Between n and m |
| `p1/p2` | Sequence |
| `p1|p2` | Alternative |
| `^p` | Inverse |

---

## Natural Language

Natural language queries use vector embeddings to understand intent.

### How It Works

```
┌──────────────────────────────────────────────────────────┐
│                   Natural Language Query                  │
│  "Find all hosts vulnerable to remote code execution"    │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│                   Embedding Model                         │
│  [0.12, -0.34, 0.56, ..., 0.78]  (384 dimensions)       │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│                   Vector Search (HNSW)                    │
│  Find k-nearest neighbors in vulnerability embeddings    │
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│                   Results + Metadata                      │
│  CVE-2021-44228 (Log4j), CVE-2023-1234 (RCE)...        │
└──────────────────────────────────────────────────────────┘
```

### Query Examples

```
// Semantic search for vulnerabilities
"remote code execution in web servers"
"privilege escalation on Windows"
"SQL injection affecting databases"

// Asset discovery
"critical production servers"
"hosts in the DMZ with expired certificates"
"services running outdated software"

// Threat intelligence
"similar attacks to SolarWinds"
"APT groups targeting healthcare"
"ransomware indicators of compromise"
```

### Hybrid Mode

Combine natural language with structured filters:

```
// Vector search + SQL filter
natural: "remote code execution vulnerability"
filter: cvss >= 8.0 AND published_after >= '2023-01-01'

// Semantic + Graph
natural: "lateral movement techniques"
graph: MATCH (h:Host)-[:AUTH_ACCESS*1..3]->(target)
       WHERE target.criticality > 8
```

---

## Cross-Modal Queries

The true power of RedDB is joining across all modalities:

```sql
-- Start with vector similarity, join to graph, filter by table
SELECT h.hostname, v.cve_id, sim.score
FROM hosts h
JOIN vulnerabilities v ON h.id = v.host_id
WHERE VECTOR_SIMILAR(v.embedding, $semantic_query, 10)
  AND h.criticality > 8.0
  AND EXISTS (
    SELECT 1 FROM attack_paths(h.id, 'crown_jewel', 3)
  )
ORDER BY sim.score DESC, h.criticality DESC;
```

```cypher
-- Cypher with vector similarity
MATCH (h:Host)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE vector.similar(v.embedding, $query, 10)
  AND h.criticality > 8.0
MATCH path = shortestPath((h)-[*..3]->(target:Host {name: 'crown-jewel'}))
RETURN h, v, path
```

---

## Query Optimization

### Cost-Based Optimizer

```
┌─────────────────────────────────────────────────────────┐
│                  Query Optimizer                         │
│                                                         │
│  Input: SELECT * FROM hosts WHERE criticality > 8      │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  1. Parse → AST                                  │   │
│  │  2. Analyze → Statistics Lookup                  │   │
│  │     - Table cardinality: 10,000 rows            │   │
│  │     - Index on criticality: yes                 │   │
│  │     - Selectivity estimate: 5%                  │   │
│  │  3. Generate Plans                               │   │
│  │     Plan A: Full table scan     Cost: 10,000    │   │
│  │     Plan B: Index scan + fetch  Cost: 500       │   │
│  │  4. Select Best: Plan B                         │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Output: IndexScan(criticality > 8) → Fetch            │
└─────────────────────────────────────────────────────────┘
```

### Index Usage

| Query Pattern | Optimal Index |
|---------------|---------------|
| `WHERE col = value` | B-Tree (exact) |
| `WHERE col > value` | B-Tree (range) |
| `WHERE col LIKE 'prefix%'` | B-Tree (prefix) |
| `WHERE VECTOR_SIMILAR(...)` | HNSW (approximate) |
| `MATCH (a)-[*1..3]->(b)` | Adjacency List |

---

## See Also

- [Storage Modalities](/domains/database/01-storage.md) - Data structures for each modality
- [Graph Algorithms](/domains/database/03-graph-algorithms.md) - PageRank, Betweenness, Dijkstra
- [Vector Search](/domains/database/04-vector-search.md) - HNSW, IVF, Hybrid
- [Security Queries](/domains/database/06-security-queries.md) - Attack paths, blast radius
