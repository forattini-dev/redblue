# Security Queries

RedDB provides specialized query templates for penetration testing and security intelligence.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                  Security Intelligence Layer                     │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐ │
│  │  Attack Path   │  │   Lateral      │  │   Blast Radius     │ │
│  │  Analysis      │  │   Movement     │  │   Calculation      │ │
│  │                │  │                │  │                    │ │
│  │  Entry → ...   │  │  Credential    │  │  Impact of         │ │
│  │  ... → Target  │  │  Chain Hopping │  │  Compromise        │ │
│  └────────────────┘  └────────────────┘  └────────────────────┘ │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐ │
│  │  Choke Point   │  │  Critical      │  │   CVE Similarity   │ │
│  │  Detection     │  │  Assets        │  │   Search           │ │
│  │                │  │                │  │                    │ │
│  │  Betweenness   │  │  PageRank +    │  │  Semantic          │ │
│  │  Centrality    │  │  Criticality   │  │  Matching          │ │
│  └────────────────┘  └────────────────┘  └────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Attack Path Analysis

Find all viable paths from an entry point to a target asset.

### Concept

```
┌─────────────────────────────────────────────────────────────────┐
│                      Attack Path                                 │
│                                                                  │
│  Entry Point          Intermediate Hops          Target         │
│  (Compromised)                                   (Crown Jewel)  │
│                                                                  │
│  [Attacker]  ─────┬──▶ [Web Server] ──▶ [App Server] ──▶ [DB]  │
│              SSH  │          │                │                 │
│                   │          │ RCE            │ SQL             │
│                   │          ▼                ▼                 │
│                   └──▶ [Jump Box] ──────▶ [File Server]        │
│                         Auth Access                             │
│                                                                  │
│  Each path has:                                                 │
│  - Hop count                                                    │
│  - Edge types (exploitation methods)                            │
│  - Cumulative severity/difficulty                               │
│  - Required credentials                                         │
└─────────────────────────────────────────────────────────────────┘
```

### Query Structure

```rust
use redblue::storage::query::{AttackPathQuery, SecurityQueries};

let query = AttackPathQuery {
    from: "host:attacker".to_string(),
    to: "host:crown_jewel".to_string(),
    max_hops: 5,
    via_edge_types: vec![
        "CONNECTS_TO".to_string(),
        "AUTH_ACCESS".to_string(),
        "EXPLOITS".to_string(),
    ],
    min_severity: Some(7.0),  // Only high-severity paths
};

let paths = security.attack_paths(query)?;

for path in paths {
    println!("Path ({} hops, severity: {})", path.hops, path.max_severity);
    for step in &path.steps {
        println!("  {} --[{}]--> {}",
            step.from, step.edge_type, step.to);
    }
}
```

### SQL Equivalent

```sql
-- Find attack paths using recursive CTE
WITH RECURSIVE attack_paths AS (
    -- Base case: start from entry point
    SELECT
        h.id as current_id,
        h.hostname as current_host,
        ARRAY[h.id] as path,
        0 as hops,
        0.0 as max_severity
    FROM hosts h
    WHERE h.hostname = 'attacker'

    UNION ALL

    -- Recursive case: follow edges
    SELECT
        next.id,
        next.hostname,
        ap.path || next.id,
        ap.hops + 1,
        GREATEST(ap.max_severity, e.severity)
    FROM attack_paths ap
    JOIN edges e ON e.from_id = ap.current_id
    JOIN hosts next ON e.to_id = next.id
    WHERE ap.hops < 5
      AND NOT next.id = ANY(ap.path)  -- Prevent cycles
      AND e.type IN ('CONNECTS_TO', 'AUTH_ACCESS', 'EXPLOITS')
)
SELECT *
FROM attack_paths
WHERE current_host = 'crown_jewel'
ORDER BY hops, max_severity DESC;
```

### Cypher Equivalent

```cypher
MATCH path = (entry:Host {hostname: 'attacker'})
             -[:CONNECTS_TO|AUTH_ACCESS|EXPLOITS*1..5]->
             (target:Host {hostname: 'crown_jewel'})
WITH path, relationships(path) as rels,
     length(path) as hops
RETURN path,
       hops,
       reduce(s = 0.0, r IN rels | CASE WHEN r.severity > s THEN r.severity ELSE s END) as max_severity
ORDER BY hops, max_severity DESC
```

---

## Lateral Movement Simulation

Simulate attacker movement through the network using compromised credentials.

### Concept

```
┌─────────────────────────────────────────────────────────────────┐
│                    Lateral Movement                              │
│                                                                  │
│  [Compromised Host]                                             │
│         │                                                        │
│         │ Steal credentials                                      │
│         ▼                                                        │
│  ┌─────────────────┐                                            │
│  │ Domain Admin    │───────▶ [DC] ───────▶ [All Domain Hosts]  │
│  │ Credential      │                                            │
│  └─────────────────┘                                            │
│         │                                                        │
│  ┌─────────────────┐                                            │
│  │ SSH Key         │───────▶ [Server A] ──▶ [Server B]         │
│  └─────────────────┘                                            │
│         │                                                        │
│  ┌─────────────────┐                                            │
│  │ Service Account │───────▶ [Database] ──▶ [Backup]           │
│  └─────────────────┘                                            │
│                                                                  │
│  Result: Graph of reachable hosts by depth                      │
└─────────────────────────────────────────────────────────────────┘
```

### Query Structure

```rust
use redblue::storage::query::{LateralMovementQuery, SecurityQueries};

let query = LateralMovementQuery {
    from: "host:compromised".to_string(),
    max_depth: 5,
    admin_only: false,  // Include all credential types
};

let result = security.lateral_movement(query)?;

println!("Reachable hosts: {}", result.reachable.len());
for host in &result.reachable {
    println!("  {} (depth: {}, via: {})",
        host.hostname, host.depth, host.via_credential);
}

println!("\nCredential chains:");
for chain in &result.credential_chains {
    println!("  {}", chain.credentials.join(" -> "));
}
```

### Output Structure

```rust
pub struct LateralMovementResult {
    /// Hosts reachable from starting point
    pub reachable: Vec<ReachableHost>,
    /// Credential chains discovered
    pub credential_chains: Vec<CredentialChain>,
    /// Total hosts at each depth
    pub depth_histogram: HashMap<usize, usize>,
}

pub struct ReachableHost {
    pub hostname: String,
    pub depth: usize,
    pub via_credential: String,
    pub admin_access: bool,
    pub criticality: f64,
}

pub struct CredentialChain {
    pub credentials: Vec<String>,
    pub reaches: Vec<String>,
}
```

---

## Blast Radius Calculation

Calculate the impact of a compromised asset.

### Concept

```
┌─────────────────────────────────────────────────────────────────┐
│                       Blast Radius                               │
│                                                                  │
│                    [Compromised Asset]                          │
│                           │                                      │
│           ┌───────────────┼───────────────┐                     │
│           ▼               ▼               ▼                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Direct    │  │   Direct    │  │   Direct    │  Depth 1   │
│  │   Impact    │  │   Impact    │  │   Impact    │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Transitive  │  │ Transitive  │  │ Transitive  │  Depth 2   │
│  │   Impact    │  │   Impact    │  │   Impact    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│  Metrics:                                                       │
│  - Direct impact count                                          │
│  - Transitive impact count                                      │
│  - Critical assets affected                                     │
│  - Total risk score                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Query Structure

```rust
use redblue::storage::query::{BlastRadiusQuery, SecurityQueries};

let query = BlastRadiusQuery {
    compromised: "host:web_server".to_string(),
    depth: 3,           // How many hops to consider
    transitive: true,   // Include indirect dependencies
};

let radius = security.blast_radius(query)?;

println!("Blast Radius Analysis for web_server:");
println!("  Direct impact: {} hosts", radius.direct.len());
println!("  Transitive impact: {} hosts", radius.transitive.len());
println!("  Critical assets affected: {}", radius.critical_count);
println!("  Total risk score: {:.2}", radius.total_risk);

println!("\nAffected critical assets:");
for asset in radius.critical_assets() {
    println!("  - {} (criticality: {})", asset.hostname, asset.criticality);
}
```

### Output Structure

```rust
pub struct BlastRadiusResult {
    /// Directly connected hosts
    pub direct: Vec<String>,
    /// Transitively reachable hosts (includes direct)
    pub transitive: Vec<String>,
    /// Count of hosts with criticality > 8
    pub critical_count: usize,
    /// Sum of criticality scores of affected hosts
    pub total_risk: f64,
    /// Depth-to-hosts mapping
    pub by_depth: HashMap<usize, Vec<String>>,
}
```

---

## Choke Point Detection

Identify network nodes that control access to many other nodes.

### Concept

```
┌─────────────────────────────────────────────────────────────────┐
│                      Choke Points                                │
│                                                                  │
│  DMZ ─────┬──────▶ [Firewall] ◀──────┬───── Internal           │
│           │            │              │                          │
│  Web ─────┘            │              └───── Database           │
│                        │                                         │
│                        ▼                                         │
│                 ┌─────────────┐                                 │
│                 │  Jump Box   │  ◀── High Betweenness!         │
│                 │  (Choke)    │                                 │
│                 └──────┬──────┘                                 │
│                        │                                         │
│           ┌────────────┼────────────┐                           │
│           ▼            ▼            ▼                           │
│       [Server A]  [Server B]  [Server C]                       │
│                                                                  │
│  Choke points = nodes with high betweenness centrality          │
│  Securing these limits attacker movement significantly          │
└─────────────────────────────────────────────────────────────────┘
```

### Query Structure

```rust
let choke_points = security.choke_points(10)?;  // Top 10

println!("Network Choke Points:");
for (hostname, betweenness) in choke_points {
    println!("  {} - betweenness: {:.4}", hostname, betweenness);
    println!("    Recommendation: Increase monitoring, harden access");
}
```

### SQL with Graph Function

```sql
-- Find choke points using betweenness centrality
SELECT
    h.hostname,
    graph.betweenness(h.id) as betweenness,
    COUNT(DISTINCT in_edge.from_id) as in_connections,
    COUNT(DISTINCT out_edge.to_id) as out_connections
FROM hosts h
LEFT JOIN edges in_edge ON in_edge.to_id = h.id
LEFT JOIN edges out_edge ON out_edge.from_id = h.id
GROUP BY h.id, h.hostname
HAVING graph.betweenness(h.id) > 0.1
ORDER BY betweenness DESC
LIMIT 10;
```

---

## Critical Asset Identification

Find the most important assets using PageRank-style analysis.

### Concept

```
┌─────────────────────────────────────────────────────────────────┐
│                    Critical Asset Scoring                        │
│                                                                  │
│  Score = α × PageRank + β × Criticality + γ × Vuln_Count       │
│                                                                  │
│  High PageRank: Many systems depend on this asset              │
│  High Criticality: Business-critical (manually tagged)         │
│  High Vuln_Count: Attack surface consideration                  │
│                                                                  │
│  Example Results:                                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Rank │ Hostname      │ PageRank │ Crit │ Score        │   │
│  ├─────────────────────────────────────────────────────────┤   │
│  │  1   │ dc01          │   0.35   │ 10.0 │ 12.85        │   │
│  │  2   │ database01    │   0.28   │  9.5 │ 11.23        │   │
│  │  3   │ file_server   │   0.22   │  8.0 │  9.42        │   │
│  │  4   │ jump_box      │   0.31   │  6.0 │  8.71        │   │
│  │  5   │ web_proxy     │   0.19   │  7.5 │  8.14        │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Query Structure

```rust
let critical_assets = security.critical_assets(10)?;  // Top 10

println!("Critical Assets (PageRank + Criticality):");
for (hostname, score) in critical_assets {
    println!("  {} - composite score: {:.2}", hostname, score);
}
```

### SQL Equivalent

```sql
-- Find critical assets using PageRank
SELECT
    h.hostname,
    h.criticality,
    graph.pagerank(h.id) as pagerank,
    COUNT(v.id) as vuln_count,
    (0.4 * graph.pagerank(h.id) * 10 +
     0.4 * h.criticality +
     0.2 * LOG(1 + COUNT(v.id))) as composite_score
FROM hosts h
LEFT JOIN vulnerabilities v ON v.host_id = h.id
GROUP BY h.id, h.hostname, h.criticality
ORDER BY composite_score DESC
LIMIT 10;
```

---

## CVE Similarity Search

Find vulnerabilities similar to a known CVE using semantic search.

### Concept

```
┌─────────────────────────────────────────────────────────────────┐
│                   CVE Similarity Search                          │
│                                                                  │
│  Query: "CVE-2021-44228"  (Log4j RCE)                          │
│                                                                  │
│  1. Embed CVE description                                       │
│  2. Vector search for similar embeddings                        │
│  3. Rank by semantic similarity + CVSS                          │
│                                                                  │
│  Results:                                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ CVE             │ Similarity │ CVSS │ Description       │   │
│  ├─────────────────────────────────────────────────────────┤   │
│  │ CVE-2021-45046  │    0.94    │ 9.0  │ Log4j follow-up  │   │
│  │ CVE-2022-22965  │    0.87    │ 9.8  │ Spring4Shell     │   │
│  │ CVE-2021-26084  │    0.82    │ 9.8  │ Confluence RCE   │   │
│  │ CVE-2020-1472   │    0.76    │ 10.0 │ Zerologon        │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Query Structure

```rust
// Search for CVEs similar to Log4j
let query_embedding = embed("Apache Log4j2 JNDI injection RCE vulnerability");

let similar = security.similar_cves(query_embedding, 10)?;

for cve in similar {
    println!("{}: similarity={:.2}, cvss={:.1}",
        cve.cve_id, cve.similarity, cve.cvss);
    println!("  {}", cve.description);
}
```

### SQL with Vector Extension

```sql
-- Find CVEs similar to Log4j
SELECT
    v.cve_id,
    v.cvss,
    v.description,
    VECTOR_DISTANCE(v.embedding, $query_embedding) as distance
FROM vulnerabilities v
WHERE VECTOR_SIMILAR(v.embedding, $query_embedding, 20)
  AND v.cvss >= 7.0
ORDER BY distance
LIMIT 10;
```

---

## Privilege Escalation Paths

Find paths from low-privilege users to admin access.

### Concept

```
┌─────────────────────────────────────────────────────────────────┐
│                 Privilege Escalation Path                        │
│                                                                  │
│  [Low-Priv User] ──▶ [Workstation] ──▶ [Vuln Service]          │
│                            │                │                    │
│                            │                ▼                    │
│                            │         [Local Admin]              │
│                            │                │                    │
│                            │                ▼                    │
│                            └────────▶ [Domain Admin]            │
│                                             │                    │
│                                             ▼                    │
│                                      [Domain Controller]        │
│                                                                  │
│  Each step involves:                                            │
│  - Exploitation of vulnerability                                │
│  - Credential theft                                             │
│  - Privilege escalation technique                               │
└─────────────────────────────────────────────────────────────────┘
```

### Query Structure

```rust
use redblue::storage::query::PrivEscQuery;

let query = PrivEscQuery {
    from_user: "jsmith".to_string(),
    from_privilege: "user".to_string(),
    target_privilege: "domain_admin".to_string(),
    max_hops: 6,
};

let paths = security.privilege_escalation_paths(query)?;

for path in paths {
    println!("PrivEsc Path ({} steps):", path.steps.len());
    for step in &path.steps {
        println!("  {} ({}) --[{}]--> {} ({})",
            step.from_host, step.from_priv,
            step.technique,
            step.to_host, step.to_priv);
    }
}
```

---

## Cross-Modal Security Queries

Combine all modalities for comprehensive analysis.

### Example: Complete Threat Assessment

```sql
-- Cross-modal threat assessment query
WITH
-- 1. Find hosts with critical vulnerabilities (TABLE)
critical_vulns AS (
    SELECT h.id, h.hostname, v.cve_id, v.cvss
    FROM hosts h
    JOIN vulnerabilities v ON h.id = v.host_id
    WHERE v.cvss >= 9.0
),

-- 2. Find similar vulnerabilities (VECTOR)
similar_threats AS (
    SELECT cv.hostname, cv.cve_id,
           s.similar_cve, s.similarity
    FROM critical_vulns cv
    CROSS JOIN LATERAL (
        SELECT cve_id as similar_cve,
               VECTOR_DISTANCE(embedding, cv.embedding) as similarity
        FROM vulnerabilities
        WHERE VECTOR_SIMILAR(embedding, cv.embedding, 5)
          AND cve_id != cv.cve_id
    ) s
),

-- 3. Calculate blast radius (GRAPH)
impact AS (
    SELECT cv.hostname,
           graph.blast_radius(cv.id, 3) as affected_hosts,
           graph.pagerank(cv.id) as importance
    FROM critical_vulns cv
)

-- 4. Combine for final report
SELECT
    cv.hostname,
    cv.cve_id,
    cv.cvss,
    st.similar_cve,
    st.similarity,
    i.affected_hosts,
    i.importance,
    (cv.cvss * 0.4 + i.importance * 30 + i.affected_hosts * 0.1) as risk_score
FROM critical_vulns cv
LEFT JOIN similar_threats st ON cv.hostname = st.hostname
LEFT JOIN impact i ON cv.hostname = i.hostname
ORDER BY risk_score DESC
LIMIT 20;
```

---

## Security Query Templates

### Pre-built Templates

| Template | Description | Parameters |
|----------|-------------|------------|
| `attack_surface` | All internet-facing assets with vulns | none |
| `crown_jewels` | Most critical assets by composite score | top_k |
| `weak_links` | Assets with high risk, low protection | threshold |
| `stale_access` | Credentials not used in N days | days |
| `pivot_points` | High betweenness hosts with vulns | top_k |
| `compliance_gap` | Assets failing policy checks | policy_id |

### Using Templates

```rust
// Load and execute a template
let result = security.execute_template("attack_surface", HashMap::new())?;

// With parameters
let mut params = HashMap::new();
params.insert("top_k", "10");
let result = security.execute_template("crown_jewels", params)?;
```

---

## See Also

- [Graph Algorithms](/domains/database/03-graph-algorithms.md) - PageRank, Betweenness
- [Vector Search](/domains/database/04-vector-search.md) - Semantic CVE search
- [Query Languages](/domains/database/02-query-languages.md) - SQL, Cypher, Gremlin
- [Caching](/domains/database/05-caching.md) - Caching security queries
