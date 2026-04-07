//! Graph Algorithm Commands
//!
//! Graph analysis algorithms for attack path and network intelligence:
//! - PageRank: Identify influential nodes
//! - Connected Components: Find network segments
//! - Betweenness Centrality: Identify choke points
//! - Label Propagation: Detect communities
//! - Cycle Detection: Find circular dependencies
//! - Path Finding: Attack path discovery

use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::serde_json::Value;
use crate::storage::engine::{
  BetweennessCentrality, ConnectedComponents, CycleDetector, GraphStore, LabelPropagation, PageRank,
};

/// PageRank analysis command
pub fn cmd_pagerank(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let alpha: f64 = ctx
    .flags
    .get("alpha")
    .and_then(|s| s.parse().ok())
    .unwrap_or(0.85);
  let limit: usize = ctx
    .flags
    .get("limit")
    .and_then(|s| s.parse().ok())
    .unwrap_or(20);

  Output::info(&format!("Running PageRank (α={:.2})...", alpha));

  let pr = PageRank::new().alpha(alpha);
  let result = pr.run(graph);

  if result.scores.is_empty() {
    Output::warning("Graph is empty - no nodes to analyze");
    return Ok(());
  }

  // Sort by score descending
  let mut ranked: Vec<_> = result.scores.iter().collect();
  ranked.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

  if format == "json" {
    let payload = pagerank_payload(&result, &ranked, limit);
    render::render_machine_output(ctx, "rb intel graph pagerank", &payload)?;
  } else {
    Output::header("PageRank Results");
    println!(
      "Converged: {} ({} iterations)",
      if result.converged { "yes" } else { "no" },
      result.iterations
    );
    println!();
    println!("{:<5} {:<40} {:>12}", "Rank", "Node", "Score");
    println!("{}", "-".repeat(60));

    for (i, (node_id, score)) in ranked.iter().take(limit).enumerate() {
      println!("{:<5} {:<40} {:>12.6}", i + 1, node_id, score);
    }

    if ranked.len() > limit {
      println!("\n... and {} more nodes", ranked.len() - limit);
    }
  }

  Output::success(&format!("Analyzed {} nodes", result.scores.len()));
  Ok(())
}

/// Connected components analysis command
pub fn cmd_components(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let min_size: usize = ctx
    .flags
    .get("min-size")
    .and_then(|s| s.parse().ok())
    .unwrap_or(2);

  Output::info("Finding connected components...");

  let result = ConnectedComponents::find(graph);

  if result.components.is_empty() {
    Output::warning("Graph is empty - no components found");
    return Ok(());
  }

  // Filter by min size
  let filtered: Vec<_> = result
    .components
    .iter()
    .filter(|c| c.size >= min_size)
    .collect();

  // Count isolated nodes (components of size 1)
  let isolated = result.components.iter().filter(|c| c.size == 1).count();

  if format == "json" {
    let payload = components_payload(&result, &filtered, min_size, isolated);
    render::render_machine_output(ctx, "rb intel graph components", &payload)?;
  } else {
    Output::header("Connected Components");
    println!(
      "Total: {} components, {} isolated nodes",
      result.count, isolated
    );
    println!();

    for (i, comp) in filtered.iter().enumerate() {
      println!("Component {} ({} nodes):", i + 1, comp.size);
      for node in comp.nodes.iter().take(10) {
        println!("  • {}", node);
      }
      if comp.size > 10 {
        println!("  ... and {} more", comp.size - 10);
      }
      println!();
    }
  }

  Output::success(&format!(
    "Found {} components with {} or more nodes",
    filtered.len(),
    min_size
  ));
  Ok(())
}

/// Betweenness centrality analysis command
pub fn cmd_centrality(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let normalize = ctx.flags.contains_key("normalize");
  let limit: usize = ctx
    .flags
    .get("limit")
    .and_then(|s| s.parse().ok())
    .unwrap_or(20);

  Output::info("Calculating betweenness centrality...");

  let result = BetweennessCentrality::compute(graph, normalize);

  if result.scores.is_empty() {
    Output::warning("Graph is empty - no nodes to analyze");
    return Ok(());
  }

  // Sort by score descending
  let mut ranked: Vec<_> = result.scores.iter().collect();
  ranked.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

  if format == "json" {
    let payload = centrality_payload(&result, &ranked, limit, normalize);
    render::render_machine_output(ctx, "rb intel graph centrality", &payload)?;
  } else {
    Output::header("Betweenness Centrality (Choke Points)");
    println!("Nodes that control the most shortest paths:");
    println!();
    println!("{:<5} {:<40} {:>15}", "Rank", "Node", "Centrality");
    println!("{}", "-".repeat(65));

    let max_score = ranked.first().map(|(_, s)| **s).unwrap_or(1.0);
    for (i, (node_id, score)) in ranked.iter().take(limit).enumerate() {
      let indicator = if **score > max_score * 0.8 {
        "🔴 CRITICAL"
      } else if **score > max_score * 0.5 {
        "🟡 HIGH"
      } else {
        ""
      };
      println!("{:<5} {:<40} {:>12.6} {}", i + 1, node_id, score, indicator);
    }
  }

  Output::success(&format!("Analyzed {} nodes", result.scores.len()));
  Ok(())
}

/// Community detection command (Label Propagation)
pub fn cmd_communities(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let max_iterations: usize = ctx
    .flags
    .get("iterations")
    .and_then(|s| s.parse().ok())
    .unwrap_or(100);

  Output::info(&format!(
    "Detecting communities (max {} iterations)...",
    max_iterations
  ));

  let lp = LabelPropagation::new().max_iterations(max_iterations);
  let result = lp.run(graph);

  if result.communities.is_empty() {
    Output::warning("Graph is empty - no communities found");
    return Ok(());
  }

  let community_count = result.communities.len();

  if format == "json" {
    let payload = communities_payload(&result);
    render::render_machine_output(ctx, "rb intel graph communities", &payload)?;
  } else {
    Output::header("Community Detection Results");
    println!("Converged in {} iterations", result.iterations);
    println!("Found {} communities", community_count);
    println!();

    for comm in result.communities.iter().take(10) {
      println!("Community '{}' ({} members):", comm.label, comm.size);
      for member in comm.nodes.iter().take(5) {
        println!("  • {}", member);
      }
      if comm.size > 5 {
        println!("  ... and {} more", comm.size - 5);
      }
      println!();
    }

    if community_count > 10 {
      println!("... and {} more communities", community_count - 10);
    }
  }

  Output::success(&format!("Detected {} communities", community_count));
  Ok(())
}

/// Cycle detection command
pub fn cmd_cycles(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let max_length: usize = ctx
    .flags
    .get("max-length")
    .and_then(|s| s.parse().ok())
    .unwrap_or(10);
  let limit: usize = ctx
    .flags
    .get("limit")
    .and_then(|s| s.parse().ok())
    .unwrap_or(50);

  Output::info(&format!("Detecting cycles (max length {})...", max_length));

  let detector = CycleDetector::new()
    .max_length(max_length)
    .max_cycles(limit);
  let result = detector.find(graph);

  if result.cycles.is_empty() {
    Output::success("No cycles detected in the graph");
    return Ok(());
  }

  let cycle_count = result.cycles.len();

  if format == "json" {
    let payload = cycles_payload(&result, max_length, limit);
    render::render_machine_output(ctx, "rb intel graph cycles", &payload)?;
  } else {
    Output::header("Cycle Detection Results");
    println!("Found {} cycles", cycle_count);
    if result.limit_reached {
      println!("(truncated at {} cycles)", limit);
    }
    println!();

    for (i, cycle) in result.cycles.iter().enumerate() {
      let path = cycle.nodes.join(" → ");
      println!("Cycle {}: {}", i + 1, path);
    }
  }

  if cycle_count > 0 {
    Output::warning(&format!(
      "Detected {} cycles - may indicate circular dependencies",
      cycle_count
    ));
  }
  Ok(())
}

/// Path finding command
pub fn cmd_paths(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let args = &ctx.args;
  if args.len() < 2 {
    Output::error("Usage: rb intel graph paths <from> <to>");
    return Err("Missing source or target node".to_string());
  }

  let from = &args[0];
  let to = &args[1];
  let max_depth: usize = ctx
    .flags
    .get("max-depth")
    .and_then(|s| s.parse().ok())
    .unwrap_or(5);

  Output::info(&format!(
    "Finding paths from '{}' to '{}' (max depth {})...",
    from, to, max_depth
  ));

  // Use BFS to find paths
  let paths = find_paths(graph, from, to, max_depth);

  if paths.is_empty() {
    Output::warning(&format!("No paths found from '{}' to '{}'", from, to));
    return Ok(());
  }

  if format == "json" {
    let payload = paths_payload(from, to, max_depth, &paths);
    render::render_machine_output(ctx, "rb intel graph paths", &payload)?;
  } else {
    Output::header(&format!("Paths from '{}' to '{}'", from, to));
    println!();

    for (i, path) in paths.iter().enumerate() {
      let path_str = path.join(" → ");
      println!("Path {} ({} hops): {}", i + 1, path.len() - 1, path_str);
    }
  }

  Output::success(&format!("Found {} paths", paths.len()));
  Ok(())
}

/// Find paths between two nodes using BFS
pub fn find_paths(graph: &GraphStore, from: &str, to: &str, max_depth: usize) -> Vec<Vec<String>> {
  let mut paths = Vec::new();
  let mut queue = std::collections::VecDeque::new();
  queue.push_back(vec![from.to_string()]);

  while let Some(path) = queue.pop_front() {
    if path.len() > max_depth + 1 {
      continue;
    }

    let current = path.last().unwrap();

    if current == to {
      paths.push(path);
      continue;
    }

    // Get outgoing edges
    for (_, neighbor, _) in graph.outgoing_edges(current) {
      if !path.contains(&neighbor) {
        let mut new_path = path.clone();
        new_path.push(neighbor);
        queue.push_back(new_path);
      }
    }
  }

  // Sort by length
  paths.sort_by(|a, b| a.len().cmp(&b.len()));
  paths.truncate(10); // Limit to 10 paths
  paths
}

fn pagerank_payload(
  result: &crate::storage::engine::PageRankResult,
  ranked: &[(&String, &f64)],
  limit: usize,
) -> Value {
  let scores: Vec<_> = ranked
    .iter()
    .take(limit)
    .enumerate()
    .map(|(index, (node, score))| {
      json!({
        "rank": index + 1,
        "node": (*node).clone(),
        "score": **score
      })
    })
    .collect();

  json!({
    "converged": result.converged,
    "iterations": result.iterations,
    "node_count": result.scores.len(),
    "limit": limit,
    "scores": scores
  })
}

fn components_payload(
  result: &crate::storage::engine::ComponentsResult,
  filtered: &[&crate::storage::engine::Component],
  min_size: usize,
  isolated: usize,
) -> Value {
  let components: Vec<_> = filtered
    .iter()
    .enumerate()
    .map(|(index, component)| {
      json!({
        "id": index + 1,
        "size": component.size,
        "nodes": component.nodes.clone()
      })
    })
    .collect();

  json!({
    "component_count": result.count,
    "isolated_nodes": isolated,
    "min_size": min_size,
    "components": components
  })
}

fn centrality_payload(
  result: &crate::storage::engine::BetweennessResult,
  ranked: &[(&String, &f64)],
  limit: usize,
  normalize: bool,
) -> Value {
  let scores: Vec<_> = ranked
    .iter()
    .take(limit)
    .enumerate()
    .map(|(index, (node, score))| {
      json!({
        "rank": index + 1,
        "node": (*node).clone(),
        "centrality": **score
      })
    })
    .collect();

  json!({
    "normalized": normalize,
    "node_count": result.scores.len(),
    "limit": limit,
    "scores": scores
  })
}

fn communities_payload(result: &crate::storage::engine::CommunitiesResult) -> Value {
  let communities: Vec<_> = result
    .communities
    .iter()
    .map(|community| {
      json!({
        "label": community.label.clone(),
        "size": community.size,
        "members": community.nodes.clone()
      })
    })
    .collect();

  json!({
    "iterations": result.iterations,
    "community_count": result.communities.len(),
    "communities": communities
  })
}

fn cycles_payload(
  result: &crate::storage::engine::CyclesResult,
  max_length: usize,
  limit: usize,
) -> Value {
  let cycles: Vec<_> = result
    .cycles
    .iter()
    .enumerate()
    .map(|(index, cycle)| {
      json!({
        "id": index + 1,
        "length": cycle.length,
        "nodes": cycle.nodes.clone()
      })
    })
    .collect();

  json!({
    "cycle_count": result.cycles.len(),
    "max_length": max_length,
    "limit": limit,
    "limit_reached": result.limit_reached,
    "cycles": cycles
  })
}

fn paths_payload(from: &str, to: &str, max_depth: usize, paths: &[Vec<String>]) -> Value {
  let values: Vec<_> = paths
    .iter()
    .enumerate()
    .map(|(index, path)| {
      json!({
        "id": index + 1,
        "hops": path.len().saturating_sub(1),
        "nodes": path.clone()
      })
    })
    .collect();

  json!({
    "from": from,
    "to": to,
    "max_depth": max_depth,
    "path_count": paths.len(),
    "paths": values
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_find_paths_empty_graph() {
    let graph = GraphStore::new();
    let paths = find_paths(&graph, "a", "b", 5);
    assert!(paths.is_empty());
  }

  #[test]
  fn test_find_paths_direct() {
    let graph = GraphStore::new();
    use crate::storage::engine::{GraphEdgeType, GraphNodeType};

    let _ = graph.add_node("a", "A", GraphNodeType::Host);
    let _ = graph.add_node("b", "B", GraphNodeType::Host);
    let _ = graph.add_edge("a", "b", GraphEdgeType::ConnectsTo, 1.0);

    let paths = find_paths(&graph, "a", "b", 5);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec!["a", "b"]);
  }

  #[test]
  fn test_paths_payload_includes_hops() {
    let payload = paths_payload(
      "a",
      "c",
      5,
      &[vec!["a".to_string(), "b".to_string(), "c".to_string()]],
    );
    assert_eq!(payload["from"], "a");
    assert_eq!(payload["to"], "c");
    assert_eq!(payload["path_count"], 1);
    assert_eq!(payload["paths"][0]["hops"], 2);
  }
}
