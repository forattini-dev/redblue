impl TuiApp {
  fn execute_graph_stats(&mut self) -> Result<(), String> {
    let graph = self.graph.read().map_err(|e| e.to_string())?;

    let node_count = graph.node_count();
    let edge_count = graph.edge_count();

    self
      .scan_activity
      .push("═══ Graph Statistics ═══".to_string());
    self.scan_activity.push(format!("  Nodes: {}", node_count));
    self.scan_activity.push(format!("  Edges: {}", edge_count));

    if node_count > 0 {
      // Count by type
      let hosts = graph.nodes_of_type(GraphNodeType::Host).len();
      let services = graph.nodes_of_type(GraphNodeType::Service).len();
      let vulns = graph.nodes_of_type(GraphNodeType::Vulnerability).len();
      let creds = graph.nodes_of_type(GraphNodeType::Credential).len();
      let users = graph.nodes_of_type(GraphNodeType::User).len();

      self.scan_activity.push("  By type:".to_string());
      if hosts > 0 {
        self.scan_activity.push(format!("    Hosts: {}", hosts));
      }
      if services > 0 {
        self
          .scan_activity
          .push(format!("    Services: {}", services));
      }
      if vulns > 0 {
        self
          .scan_activity
          .push(format!("    Vulnerabilities: {}", vulns));
      }
      if creds > 0 {
        self
          .scan_activity
          .push(format!("    Credentials: {}", creds));
      }
      if users > 0 {
        self.scan_activity.push(format!("    Users: {}", users));
      }
    }

    if let Some(ref node) = self.graph_current_node {
      self
        .scan_activity
        .push(format!("  Current context: {}", node));
    }

    Ok(())
  }

  /// List all nodes in the graph
  fn execute_graph_nodes(&mut self) -> Result<(), String> {
    let graph = self.graph.read().map_err(|e| e.to_string())?;

    let nodes: Vec<_> = graph.iter_nodes().collect();

    if nodes.is_empty() {
      self
        .scan_activity
        .push("Graph is empty. Run scans to populate.".to_string());
      return Ok(());
    }

    self
      .scan_activity
      .push(format!("═══ Graph Nodes ({}) ═══", nodes.len()));

    // Group by type
    let mut by_type: HashMap<String, Vec<&StoredNode>> = HashMap::new();
    for node in &nodes {
      let type_name = format!("{:?}", node.node_type);
      by_type.entry(type_name).or_default().push(node);
    }

    for (type_name, type_nodes) in by_type {
      self
        .scan_activity
        .push(format!("  {} ({}):", type_name, type_nodes.len()));
      for node in type_nodes.iter().take(10) {
        let marker = if Some(&node.id) == self.graph_current_node.as_ref() {
          "→"
        } else {
          " "
        };
        self
          .scan_activity
          .push(format!("  {} {} - {}", marker, node.id, node.label));
      }
      if type_nodes.len() > 10 {
        self
          .scan_activity
          .push(format!("    ... and {} more", type_nodes.len() - 10));
      }
    }

    self.graph_data = nodes
      .iter()
      .map(|n| TableRow {
        module: n.id.clone(),
        status: format!("{:?}", n.node_type),
        data: n.label.clone(),
        timestamp: 0,
      })
      .collect();

    Ok(())
  }

  /// Select a node as the current context
  fn execute_graph_select_node(&mut self, node_id: &str) -> Result<(), String> {
    let graph = self.graph.read().map_err(|e| e.to_string())?;

    // Check if node exists
    if let Some(node) = graph.get_node(node_id) {
      self.graph_current_node = Some(node_id.to_string());
      self
        .scan_activity
        .push(format!("Selected node: {} ({})", node.id, node.label));
      self
        .scan_activity
        .push(format!("  Type: {:?}", node.node_type));

      // Show edges
      let out_edges = graph.outgoing_edges(node_id);
      let in_edges = graph.incoming_edges(node_id);

      // Calculate neighbors (unique targets from outgoing + sources from incoming)
      let mut neighbor_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
      for (_, target, _) in &out_edges {
        neighbor_ids.insert(target.clone());
      }
      for (_, source, _) in &in_edges {
        neighbor_ids.insert(source.clone());
      }

      if !neighbor_ids.is_empty() {
        self
          .scan_activity
          .push(format!("  Neighbors: {}", neighbor_ids.len()));
      }

      if !out_edges.is_empty() {
        self
          .scan_activity
          .push(format!("  Outgoing edges: {}", out_edges.len()));
      }

      if !in_edges.is_empty() {
        self
          .scan_activity
          .push(format!("  Incoming edges: {}", in_edges.len()));
      }
    } else {
      // Try partial match
      let matches: Vec<_> = graph
        .iter_nodes()
        .filter(|n| {
          n.id.contains(node_id) || n.label.to_lowercase().contains(&node_id.to_lowercase())
        })
        .take(5)
        .collect();

      if matches.is_empty() {
        return Err(format!("Node '{}' not found in graph", node_id));
      } else if matches.len() == 1 {
        let node = &matches[0];
        self.graph_current_node = Some(node.id.clone());
        self
          .scan_activity
          .push(format!("Selected node: {} ({})", node.id, node.label));
      } else {
        self.scan_activity.push("Multiple matches:".to_string());
        for node in matches {
          self
            .scan_activity
            .push(format!("  {} - {}", node.id, node.label));
        }
        return Err("Specify a more precise node ID".to_string());
      }
    }

    Ok(())
  }

  /// Show neighbors of a node
  fn execute_graph_neighbors(&mut self, node_id: &str) -> Result<(), String> {
    let graph = self.graph.read().map_err(|e| e.to_string())?;

    if graph.get_node(node_id).is_none() {
      return Err(format!("Node '{}' not found", node_id));
    }

    // Get neighbors via edges
    let out_edges = graph.outgoing_edges(node_id);
    let in_edges = graph.incoming_edges(node_id);

    let neighbor_count = out_edges.len() + in_edges.len();
    self.scan_activity.push(format!(
      "═══ Neighbors of {} ({}) ═══",
      node_id, neighbor_count
    ));

    if out_edges.is_empty() && in_edges.is_empty() {
      self.scan_activity.push("  No neighbors".to_string());
      return Ok(());
    }

    // Show outgoing edges
    for (edge_type, target_id, weight) in out_edges.iter().take(15) {
      if let Some(neighbor) = graph.get_node(target_id) {
        self.scan_activity.push(format!(
          "  --[{:?} {:.2}]--> {} ({:?})",
          edge_type, weight, neighbor.label, neighbor.node_type
        ));
      }
    }

    // Show incoming edges
    for (edge_type, source_id, weight) in in_edges.iter().take(5) {
      if let Some(neighbor) = graph.get_node(source_id) {
        self.scan_activity.push(format!(
          "  <--[{:?} {:.2}]-- {} ({:?})",
          edge_type, weight, neighbor.label, neighbor.node_type
        ));
      }
    }

    if neighbor_count > 20 {
      self
        .scan_activity
        .push(format!("  ... and {} more", neighbor_count - 20));
    }

    Ok(())
  }

  /// Show what can be reached from current node (BFS traversal)
  fn execute_graph_reach(&mut self, node_id: &str) -> Result<(), String> {
    let graph = self.graph.read().map_err(|e| e.to_string())?;

    if graph.get_node(node_id).is_none() {
      return Err(format!("Node '{}' not found", node_id));
    }

    // BFS to find all reachable nodes
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    let mut by_depth: HashMap<usize, Vec<String>> = HashMap::new();

    queue.push_back((node_id.to_string(), 0usize));
    visited.insert(node_id.to_string());

    let max_depth = 5;

    while let Some((current, depth)) = queue.pop_front() {
      if depth > max_depth {
        continue;
      }

      by_depth.entry(depth).or_default().push(current.clone());

      // Get neighbors via outgoing edges (forward traversal)
      for (_, target, _) in graph.outgoing_edges(&current) {
        if !visited.contains(&target) {
          visited.insert(target.clone());
          queue.push_back((target, depth + 1));
        }
      }
    }

    self
      .scan_activity
      .push(format!("═══ Reachable from {} ═══", node_id));
    self
      .scan_activity
      .push(format!("  Total reachable: {} nodes", visited.len() - 1));

    for depth in 1..=max_depth {
      if let Some(nodes) = by_depth.get(&depth) {
        self
          .scan_activity
          .push(format!("  Hop {}: {} nodes", depth, nodes.len()));
        for id in nodes.iter().take(5) {
          if let Some(node) = graph.get_node(id) {
            self
              .scan_activity
              .push(format!("    {} ({:?})", node.label, node.node_type));
          }
        }
        if nodes.len() > 5 {
          self
            .scan_activity
            .push(format!("    ... and {} more", nodes.len() - 5));
        }
      }
    }

    Ok(())
  }

  /// Find paths between two nodes
  fn execute_graph_paths(&mut self, from: &str, to: &str) -> Result<(), String> {
    let graph = self.graph.read().map_err(|e| e.to_string())?;

    if graph.get_node(from).is_none() {
      return Err(format!("Source node '{}' not found", from));
    }
    if graph.get_node(to).is_none() {
      return Err(format!("Target node '{}' not found", to));
    }

    // BFS to find shortest path
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    let mut parent: HashMap<String, String> = HashMap::new();

    queue.push_back(from.to_string());
    visited.insert(from.to_string());

    let mut found = false;

    while let Some(current) = queue.pop_front() {
      if current == to {
        found = true;
        break;
      }

      // Get neighbors via outgoing edges
      for (_, target, _) in graph.outgoing_edges(&current) {
        if !visited.contains(&target) {
          visited.insert(target.clone());
          parent.insert(target.clone(), current.clone());
          queue.push_back(target);
        }
      }
    }

    if !found {
      self
        .scan_activity
        .push(format!("No path found from {} to {}", from, to));
      return Ok(());
    }

    // Reconstruct path
    let mut path = vec![to.to_string()];
    let mut current = to.to_string();
    while let Some(p) = parent.get(&current) {
      path.push(p.clone());
      current = p.clone();
    }
    path.reverse();

    self
      .scan_activity
      .push(format!("═══ Path: {} → {} ═══", from, to));
    self
      .scan_activity
      .push(format!("  Length: {} hops", path.len() - 1));

    for (i, node_id) in path.iter().enumerate() {
      if let Some(node) = graph.get_node(node_id) {
        let prefix = if i == 0 {
          "Start"
        } else if i == path.len() - 1 {
          "End"
        } else {
          "    "
        };
        self.scan_activity.push(format!(
          "  {} {} ({:?})",
          prefix, node.label, node.node_type
        ));
      }
    }

    self.graph_path_results = vec![path];

    Ok(())
  }

  /// Calculate PageRank for graph nodes
  fn execute_graph_pagerank(&mut self) -> Result<(), String> {
    let graph = self.graph.read().map_err(|e| e.to_string())?;

    if graph.node_count() == 0 {
      return Err("Graph is empty".to_string());
    }

    let pagerank = PageRank::new();
    let result = pagerank.run(&graph);

    self
      .scan_activity
      .push("═══ PageRank (Top Influential Nodes) ═══".to_string());

    let top = result.top(10);
    for (rank, (node_id, score)) in top.iter().enumerate() {
      if let Some(node) = graph.get_node(node_id) {
        self.scan_activity.push(format!(
          "  {}. {} ({:.4}) - {:?}",
          rank + 1,
          node.label,
          score,
          node.node_type
        ));
      }
    }

    Ok(())
  }

  /// Find connected components
  fn execute_graph_components(&mut self) -> Result<(), String> {
    let graph = self.graph.read().map_err(|e| e.to_string())?;

    if graph.node_count() == 0 {
      return Err("Graph is empty".to_string());
    }

    let result = ConnectedComponents::find(&graph);

    self
      .scan_activity
      .push(format!("═══ Connected Components ({}) ═══", result.count));

    for comp in result.components.iter().take(10) {
      self
        .scan_activity
        .push(format!("  Component {}: {} nodes", comp.id, comp.size));

      // Show sample nodes from this component
      for node_id in comp.nodes.iter().take(3) {
        if let Some(node) = graph.get_node(node_id) {
          self
            .scan_activity
            .push(format!("    - {} ({:?})", node.label, node.node_type));
        }
      }
    }

    if result.components.len() > 10 {
      self.scan_activity.push(format!(
        "  ... and {} more components",
        result.components.len() - 10
      ));
    }

    Ok(())
  }

  /// Get a reference to the graph store
  pub fn graph_store(&self) -> Arc<RwLock<GraphStore>> {
    Arc::clone(&self.graph)
  }
}

#[cfg(test)]
mod tests {
  use super::TuiApp;
  use crate::storage::records::{PortScanRecord, PortStatus};
  use std::net::{IpAddr, Ipv4Addr};

  fn port_scan(ip: [u8; 4], port: u16, status: PortStatus, ts: u32) -> PortScanRecord {
    PortScanRecord {
      ip: IpAddr::V4(Ipv4Addr::from(ip)),
      port,
      status,
      service_id: 0,
      timestamp: ts,
    }
  }

  #[test]
  fn build_network_rows_groups_by_host() {
    let scans = vec![
      port_scan([10, 0, 0, 1], 22, PortStatus::Open, 100),
      port_scan([10, 0, 0, 1], 80, PortStatus::Open, 105),
      port_scan([10, 0, 0, 1], 443, PortStatus::Filtered, 110),
      port_scan([10, 0, 0, 2], 8080, PortStatus::Closed, 200),
    ];

    let rows = TuiApp::build_network_rows(&scans);
    assert_eq!(rows.len(), 2);

    let host1 = rows
      .iter()
      .find(|row| row.module == "10.0.0.1")
      .expect("missing host 10.0.0.1");

    assert_eq!(host1.status, "Online");
    assert!(host1.data.contains("open 22,80"), "{}", host1.data);
    assert!(host1.data.contains("filtered 443"), "{}", host1.data);
    assert_eq!(host1.timestamp, 110);

    let host2 = rows
      .iter()
      .find(|row| row.module == "10.0.0.2")
      .expect("missing host 10.0.0.2");
    assert_eq!(host2.status, "Closed");
    assert!(host2.data.contains("closed 1"), "{}", host2.data);
    assert_eq!(host2.timestamp, 200);
  }

  #[test]
  fn format_port_sample_limits_length() {
    let small = vec![21u16, 22, 23];
    assert_eq!(TuiApp::format_port_sample(&small), "21,22,23");

    let large = vec![1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(TuiApp::format_port_sample(&large), "1,2,3,4,5,6(+2)");
  }
}

/// Truncate string to max length
fn truncate(s: &str, max_len: usize) -> String {
  if s.len() <= max_len {
    s.to_string()
  } else {
    format!("{}...", &s[..max_len - 3])
  }
}

/// Helper trait for session file
trait SessionFileExt {
  fn load_metadata_from_path(
    path: &str,
  ) -> Result<crate::storage::session::SessionMetadata, String>;
}

impl SessionFileExt for crate::storage::session::SessionFile {
  fn load_metadata_from_path(
    path: &str,
  ) -> Result<crate::storage::session::SessionMetadata, String> {
    let content =
      std::fs::read_to_string(path).map_err(|e| format!("Failed to read session: {}", e))?;
    Self::parse_metadata(&content)
  }
}

/// Drop implementation to ensure terminal cleanup even on panic
impl Drop for TuiApp {
  fn drop(&mut self) {
    // CRITICAL: Always restore terminal state when TUI is dropped
    // This ensures cleanup happens even if there's a panic or early exit
    let _ = self.exit_alternate_screen();
    let _ = self.disable_raw_mode();

    // Extra safety: print a newline to ensure clean exit
    println!();
  }
}

/// Start fullscreen TUI
pub fn start_tui(target: String) -> Result<(), String> {
  let mut app = TuiApp::new(target)?;
  app.run()
}
