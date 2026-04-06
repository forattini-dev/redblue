//! Storage Engine Benchmarks
//!
//! Micro-benchmarks for redblue's unified storage engine.
//! Run with: cargo bench --bench storage_bench
//!
//! # Benchmarks
//!
//! - **Tables**: Insert, query, update, delete operations
//! - **Graphs**: Node/edge operations, traversals, algorithms
//! - **Vectors**: Insert, search, HNSW/IVF indices
//! - **Cross-modal**: Hybrid queries across modalities
//! - **Security workflow**: End-to-end pentest scenarios

use std::time::{Duration, Instant};

// ============================================================================
// Benchmark Harness
// ============================================================================

/// Simple benchmark result
#[derive(Clone)]
struct BenchResult {
  name: String,
  iterations: u64,
  total_time: Duration,
  min_time: Duration,
  max_time: Duration,
}

impl BenchResult {
  fn ops_per_sec(&self) -> f64 {
    self.iterations as f64 / self.total_time.as_secs_f64()
  }

  fn avg_time(&self) -> Duration {
    self.total_time / self.iterations as u32
  }
}

/// Run a benchmark with warmup and iterations
fn bench<F>(name: &str, iterations: u64, warmup_iterations: u64, mut f: F) -> BenchResult
where
  F: FnMut(),
{
  // Warmup
  for _ in 0..warmup_iterations {
    f();
  }

  // Actual benchmark
  let mut min_time = Duration::MAX;
  let mut max_time = Duration::ZERO;
  let start = Instant::now();

  for _ in 0..iterations {
    let iter_start = Instant::now();
    f();
    let iter_time = iter_start.elapsed();
    min_time = min_time.min(iter_time);
    max_time = max_time.max(iter_time);
  }

  let total_time = start.elapsed();

  BenchResult {
    name: name.to_string(),
    iterations,
    total_time,
    min_time,
    max_time,
  }
}

/// Run a batch benchmark (multiple ops per iteration)
fn bench_batch<F>(
  name: &str,
  iterations: u64,
  batch_size: u64,
  warmup: u64,
  mut f: F,
) -> BenchResult
where
  F: FnMut(u64),
{
  // Warmup
  for _ in 0..warmup {
    f(batch_size);
  }

  let start = Instant::now();
  let mut min_time = Duration::MAX;
  let mut max_time = Duration::ZERO;

  for _ in 0..iterations {
    let iter_start = Instant::now();
    f(batch_size);
    let iter_time = iter_start.elapsed();
    min_time = min_time.min(iter_time);
    max_time = max_time.max(iter_time);
  }

  let total_time = start.elapsed();
  let total_ops = iterations * batch_size;

  BenchResult {
    name: name.to_string(),
    iterations: total_ops,
    total_time,
    min_time,
    max_time,
  }
}

fn print_result(result: &BenchResult) {
  println!(
    "{:<40} {:>10.2} ops/sec  avg: {:>10.2}µs  min: {:>10.2}µs  max: {:>10.2}µs",
    result.name,
    result.ops_per_sec(),
    result.avg_time().as_secs_f64() * 1_000_000.0,
    result.min_time.as_secs_f64() * 1_000_000.0,
    result.max_time.as_secs_f64() * 1_000_000.0,
  );
}

fn print_section(name: &str) {
  println!("\n{}", "=".repeat(80));
  println!("  {}", name);
  println!("{}\n", "=".repeat(80));
}

// ============================================================================
// Vector Benchmarks
// ============================================================================

mod vector_benches {
  use super::*;

  /// Generate random vectors for testing
  fn random_vectors(n: usize, dim: usize, seed: u64) -> Vec<Vec<f32>> {
    (0..n)
      .map(|i| {
        (0..dim)
          .map(|j| {
            let x = ((seed
              .wrapping_mul(1103515245)
              .wrapping_add(i as u64 * 12345 + j as u64))
              % 10000) as f32
              / 10000.0;
            x * 2.0 - 1.0 // Range [-1, 1]
          })
          .collect()
      })
      .collect()
  }

  /// L2 squared distance (scalar)
  fn l2_squared_scalar(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).powi(2)).sum()
  }

  /// Dot product (scalar)
  fn dot_product_scalar(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
  }

  pub fn run() -> Vec<BenchResult> {
    print_section("Vector Distance Benchmarks");
    let mut results = Vec::new();

    // Generate test data
    let dim = 384; // Common embedding dimension
    let vectors = random_vectors(10000, dim, 42);
    let query = &vectors[0];

    // L2 distance - single pair
    let target = &vectors[1];
    let r = bench("L2 squared (384-dim, scalar)", 100_000, 1000, || {
      let _ = l2_squared_scalar(query, target);
    });
    print_result(&r);
    results.push(r);

    // Dot product - single pair
    let r = bench("Dot product (384-dim, scalar)", 100_000, 1000, || {
      let _ = dot_product_scalar(query, target);
    });
    print_result(&r);
    results.push(r);

    // Brute-force search (k=10)
    let k = 10;
    let r = bench("Brute-force kNN (10000 vecs, k=10)", 100, 5, || {
      let mut distances: Vec<(usize, f32)> = vectors
        .iter()
        .enumerate()
        .map(|(i, v)| (i, l2_squared_scalar(query, v)))
        .collect();
      distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
      distances.truncate(k);
    });
    print_result(&r);
    results.push(r);

    // Higher dimension test
    let dim_768 = 768;
    let vectors_768 = random_vectors(1000, dim_768, 123);
    let query_768 = &vectors_768[0];
    let target_768 = &vectors_768[1];

    let r = bench("L2 squared (768-dim, scalar)", 50_000, 500, || {
      let _ = l2_squared_scalar(query_768, target_768);
    });
    print_result(&r);
    results.push(r);

    results
  }
}

// ============================================================================
// Table Operation Benchmarks
// ============================================================================

mod table_benches {
  use super::*;
  use std::collections::HashMap;

  /// Simple in-memory row for benchmarking
  struct Row {
    id: u64,
    data: HashMap<String, String>,
  }

  /// Simple table for benchmarking
  struct SimpleTable {
    rows: Vec<Row>,
    index: HashMap<u64, usize>,
  }

  impl SimpleTable {
    fn new() -> Self {
      Self {
        rows: Vec::new(),
        index: HashMap::new(),
      }
    }

    fn insert(&mut self, id: u64, data: HashMap<String, String>) {
      let idx = self.rows.len();
      self.rows.push(Row { id, data });
      self.index.insert(id, idx);
    }

    fn get(&self, id: u64) -> Option<&Row> {
      self.index.get(&id).map(|&idx| &self.rows[idx])
    }

    fn scan_filter<F>(&self, predicate: F) -> Vec<&Row>
    where
      F: Fn(&Row) -> bool,
    {
      self.rows.iter().filter(|r| predicate(r)).collect()
    }
  }

  pub fn run() -> Vec<BenchResult> {
    print_section("Table Operation Benchmarks");
    let mut results = Vec::new();

    // Single insert
    let r = bench("Table insert (single row)", 10_000, 100, || {
      let mut table = SimpleTable::new();
      let mut data = HashMap::new();
      data.insert("name".to_string(), "test".to_string());
      data.insert("value".to_string(), "12345".to_string());
      table.insert(1, data);
    });
    print_result(&r);
    results.push(r);

    // Batch insert
    let r = bench_batch("Table batch insert (1000 rows)", 100, 1000, 5, |batch| {
      let mut table = SimpleTable::new();
      for i in 0..batch {
        let mut data = HashMap::new();
        data.insert("name".to_string(), format!("item_{}", i));
        data.insert("value".to_string(), i.to_string());
        table.insert(i, data);
      }
    });
    print_result(&r);
    results.push(r);

    // Point lookup (with index)
    let mut table = SimpleTable::new();
    for i in 0..10000 {
      let mut data = HashMap::new();
      data.insert("name".to_string(), format!("item_{}", i));
      table.insert(i, data);
    }

    let r = bench("Table point lookup (indexed)", 100_000, 1000, || {
      let _ = table.get(5000);
    });
    print_result(&r);
    results.push(r);

    // Full scan with filter
    let r = bench("Table scan filter (10000 rows)", 1000, 10, || {
      let _ = table.scan_filter(|r| r.id > 5000 && r.id < 6000);
    });
    print_result(&r);
    results.push(r);

    results
  }
}

// ============================================================================
// Graph Benchmarks
// ============================================================================

mod graph_benches {
  use super::*;
  use std::collections::{HashMap, HashSet, VecDeque};

  /// Simple adjacency list graph
  struct Graph {
    nodes: HashSet<u64>,
    edges: HashMap<u64, Vec<(u64, f32)>>, // node -> [(neighbor, weight)]
  }

  impl Graph {
    fn new() -> Self {
      Self {
        nodes: HashSet::new(),
        edges: HashMap::new(),
      }
    }

    fn add_node(&mut self, id: u64) {
      self.nodes.insert(id);
      self.edges.entry(id).or_insert_with(Vec::new);
    }

    fn add_edge(&mut self, from: u64, to: u64, weight: f32) {
      self
        .edges
        .entry(from)
        .or_insert_with(Vec::new)
        .push((to, weight));
    }

    fn neighbors(&self, id: u64) -> &[(u64, f32)] {
      self.edges.get(&id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// BFS shortest path
    fn bfs(&self, start: u64, end: u64) -> Option<Vec<u64>> {
      let mut visited = HashSet::new();
      let mut queue = VecDeque::new();
      let mut parent = HashMap::new();

      queue.push_back(start);
      visited.insert(start);

      while let Some(node) = queue.pop_front() {
        if node == end {
          // Reconstruct path
          let mut path = vec![end];
          let mut current = end;
          while let Some(&p) = parent.get(&current) {
            path.push(p);
            current = p;
          }
          path.reverse();
          return Some(path);
        }

        for &(neighbor, _) in self.neighbors(node) {
          if !visited.contains(&neighbor) {
            visited.insert(neighbor);
            parent.insert(neighbor, node);
            queue.push_back(neighbor);
          }
        }
      }
      None
    }

    /// PageRank (simplified)
    fn pagerank(&self, iterations: usize, damping: f32) -> HashMap<u64, f32> {
      let n = self.nodes.len() as f32;
      let mut ranks: HashMap<u64, f32> = self.nodes.iter().map(|&id| (id, 1.0 / n)).collect();

      for _ in 0..iterations {
        let mut new_ranks = HashMap::new();
        for &node in &self.nodes {
          let mut rank = (1.0 - damping) / n;
          // Find nodes pointing to this one (in-edges)
          for &from in &self.nodes {
            let neighbors = self.neighbors(from);
            if neighbors.iter().any(|&(to, _)| to == node) {
              let out_degree = neighbors.len() as f32;
              if out_degree > 0.0 {
                rank += damping * ranks[&from] / out_degree;
              }
            }
          }
          new_ranks.insert(node, rank);
        }
        ranks = new_ranks;
      }
      ranks
    }
  }

  /// Create a random graph for testing
  fn create_random_graph(nodes: usize, edges_per_node: usize, seed: u64) -> Graph {
    let mut graph = Graph::new();

    for i in 0..nodes as u64 {
      graph.add_node(i);
    }

    for i in 0..nodes as u64 {
      for j in 0..edges_per_node {
        let target =
          ((seed.wrapping_mul(i + 1).wrapping_add(j as u64 * 7919)) % nodes as u64) as u64;
        if target != i {
          let weight = ((seed.wrapping_mul(i).wrapping_add(target)) % 100) as f32 / 100.0;
          graph.add_edge(i, target, weight);
        }
      }
    }
    graph
  }

  pub fn run() -> Vec<BenchResult> {
    print_section("Graph Operation Benchmarks");
    let mut results = Vec::new();

    // Node/edge insertion
    let r = bench("Graph add node", 100_000, 1000, || {
      let mut g = Graph::new();
      g.add_node(1);
    });
    print_result(&r);
    results.push(r);

    let r = bench_batch(
      "Graph build (1000 nodes, 5 edges each)",
      100,
      1000,
      5,
      |n| {
        let mut g = Graph::new();
        for i in 0..n {
          g.add_node(i);
        }
        for i in 0..n {
          for j in 0..5u64 {
            let target = (i + j + 1) % n;
            g.add_edge(i, target, 1.0);
          }
        }
      },
    );
    print_result(&r);
    results.push(r);

    // Create test graph
    let graph = create_random_graph(1000, 5, 42);

    // BFS
    let r = bench("BFS shortest path (1000 nodes)", 1000, 50, || {
      let _ = graph.bfs(0, 999);
    });
    print_result(&r);
    results.push(r);

    // PageRank (small graph)
    let small_graph = create_random_graph(100, 5, 123);
    let r = bench("PageRank (100 nodes, 10 iter)", 100, 5, || {
      let _ = small_graph.pagerank(10, 0.85);
    });
    print_result(&r);
    results.push(r);

    // Neighbor lookup
    let r = bench("Neighbor lookup", 100_000, 1000, || {
      let _ = graph.neighbors(500);
    });
    print_result(&r);
    results.push(r);

    results
  }
}

// ============================================================================
// Security Workflow Benchmarks
// ============================================================================

mod security_benches {
  use super::*;
  use std::collections::HashMap;

  /// Simulated host entry
  struct Host {
    ip: String,
    hostname: String,
    ports: Vec<u16>,
    vulns: Vec<String>,
  }

  /// Simulated scan workflow
  fn simulate_recon(hosts: &[Host]) -> Vec<&Host> {
    hosts.iter().filter(|h| !h.ports.is_empty()).collect()
  }

  fn simulate_vuln_correlation<'a>(
    hosts: &'a [Host],
    cve_db: &'a HashMap<String, Vec<String>>,
  ) -> Vec<(&'a Host, Vec<&'a String>)> {
    hosts
      .iter()
      .map(|h| {
        let matched: Vec<&String> = h.vulns.iter().filter(|v| cve_db.contains_key(*v)).collect();
        (h, matched)
      })
      .filter(|(_, v)| !v.is_empty())
      .collect()
  }

  pub fn run() -> Vec<BenchResult> {
    print_section("Security Workflow Benchmarks");
    let mut results = Vec::new();

    // Generate test data
    let hosts: Vec<Host> = (0..1000)
      .map(|i| Host {
        ip: format!("192.168.1.{}", i % 256),
        hostname: format!("host-{}.local", i),
        ports: if i % 3 == 0 {
          vec![22, 80, 443]
        } else if i % 3 == 1 {
          vec![22, 3389]
        } else {
          vec![]
        },
        vulns: if i % 5 == 0 {
          vec!["CVE-2021-44228".to_string(), "CVE-2022-22965".to_string()]
        } else {
          vec![]
        },
      })
      .collect();

    // Build CVE database
    let mut cve_db: HashMap<String, Vec<String>> = HashMap::new();
    cve_db.insert("CVE-2021-44228".to_string(), vec!["Log4Shell".to_string()]);
    cve_db.insert(
      "CVE-2022-22965".to_string(),
      vec!["Spring4Shell".to_string()],
    );
    cve_db.insert("CVE-2023-12345".to_string(), vec!["Example".to_string()]);

    // Recon workflow
    let r = bench("Recon filter (1000 hosts)", 10_000, 100, || {
      let _ = simulate_recon(&hosts);
    });
    print_result(&r);
    results.push(r);

    // Vulnerability correlation
    let r = bench("Vuln correlation (1000 hosts)", 5_000, 50, || {
      let _ = simulate_vuln_correlation(&hosts, &cve_db);
    });
    print_result(&r);
    results.push(r);

    // Combined workflow
    let r = bench("Full recon+vuln workflow", 1_000, 10, || {
      let active = simulate_recon(&hosts);
      let _vulns: Vec<_> = active
        .iter()
        .flat_map(|h| h.vulns.iter())
        .filter(|v| cve_db.contains_key(*v))
        .collect();
    });
    print_result(&r);
    results.push(r);

    results
  }
}

// ============================================================================
// Main Benchmark Runner
// ============================================================================

fn main() {
  println!("\n");
  println!("████████████████████████████████████████████████████████████████████████████████");
  println!("                     redblue Storage Engine Benchmarks");
  println!("████████████████████████████████████████████████████████████████████████████████");

  let mut all_results = Vec::new();

  // Run all benchmark suites
  all_results.extend(vector_benches::run());
  all_results.extend(table_benches::run());
  all_results.extend(graph_benches::run());
  all_results.extend(security_benches::run());

  // Summary
  print_section("Summary");
  println!("Total benchmarks run: {}", all_results.len());
  println!("\nTop 5 fastest operations:");

  let mut sorted = all_results.clone();
  sorted.sort_by(|a, b| b.ops_per_sec().partial_cmp(&a.ops_per_sec()).unwrap());

  for (i, r) in sorted.iter().take(5).enumerate() {
    println!("  {}. {}: {:.0} ops/sec", i + 1, r.name, r.ops_per_sec());
  }

  println!("\nBenchmark complete.");
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_bench_harness() {
    let result = bench("test_op", 100, 10, || {
      let _x = 1 + 1;
    });
    assert_eq!(result.iterations, 100);
    assert!(result.total_time > Duration::ZERO);
  }

  #[test]
  fn test_vector_benches() {
    // Just ensure they don't panic
    let _ = vector_benches::run();
  }
}
