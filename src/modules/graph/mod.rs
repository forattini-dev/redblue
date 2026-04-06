//! ShadowGraph Module - Attack path analysis and strategic insights.
//!
//! This module implements a directed graph for analyzing attack paths derived from loot entries.
//! It uses algorithms inspired by genetics-ai.js for efficient traversal and path finding.
//!
//! # Features
//! - Automatic graph building from loot entries
//! - Dijkstra's shortest path algorithm
//! - DFS-based cycle detection and DAG validation
//! - Topological sorting for efficient traversal
//! - Layer-based batch processing
//! - Strategic insights generation (unused credentials, high-value targets, attack paths)
//! - Mermaid diagram export

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};

use crate::storage::segments::actions::{
  ActionOutcome, ActionRecord, ActionType, Target as ActionTarget,
};
use crate::storage::segments::graph::{
  EdgeRef, EdgeType, GraphEdge, GraphNode, GraphSegment, NodeType,
};
use crate::storage::segments::loot::{LootCategory, LootEntry, LootSegment};

// ==================== Insight Types ====================

/// Priority level for insights
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
  Critical = 0,
  High = 1,
  Medium = 2,
  Low = 3,
  Info = 4,
}

impl Priority {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Critical => "critical",
      Self::High => "high",
      Self::Medium => "medium",
      Self::Low => "low",
      Self::Info => "info",
    }
  }
}

/// Type of strategic insight
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsightType {
  /// Credentials that provide access but target not fully exploited
  UnusedCredentials,
  /// Host with many services and/or vulnerabilities
  HighValueTarget,
  /// Multi-hop path from credential to target
  AttackPath,
  /// Host A -> Cred -> Host B pivot opportunity
  PivotOpportunity,
  /// Service discovered but not tested
  UnexploredService,
}

/// A strategic insight derived from graph analysis
#[derive(Debug, Clone)]
pub struct Insight {
  pub insight_type: InsightType,
  pub message: String,
  pub priority: Priority,
  pub related_nodes: Vec<String>,
}

// ==================== Graph Statistics ====================

/// Statistics about the graph structure
#[derive(Debug, Clone, Default)]
pub struct GraphStats {
  pub total_nodes: usize,
  pub nodes_by_type: HashMap<NodeType, usize>,
  pub total_edges: usize,
  pub edges_by_type: HashMap<EdgeType, usize>,
  pub connected_components: usize,
  pub max_depth: usize,
  pub is_dag: bool,
  pub cycle_count: usize,
}

// ==================== DAG Validation ====================

/// Result of DAG validation
#[derive(Debug, Clone)]
pub struct DagValidation {
  pub is_dag: bool,
  /// Edges that cause cycles (from_id, to_id)
  pub cycles: Vec<(String, String)>,
}

// ==================== Graph Layer ====================

/// A layer of nodes at the same depth for batch processing
#[derive(Debug, Clone)]
pub struct GraphLayer {
  pub depth: usize,
  pub node_ids: Vec<String>,
}

// ==================== Path Finding State ====================

/// State for Dijkstra's algorithm
#[derive(Clone, Eq, PartialEq)]
struct DijkstraState {
  cost: u64, // Fixed-point (multiply by 1000 for 3 decimal precision)
  node_id: String,
}

impl Ord for DijkstraState {
  fn cmp(&self, other: &Self) -> Ordering {
    other
      .cost
      .cmp(&self.cost) // Reversed for min-heap
      .then_with(|| self.node_id.cmp(&other.node_id))
  }
}

impl PartialOrd for DijkstraState {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

// ==================== Shadow Graph ====================

/// The ShadowGraph for attack path analysis.
///
/// This struct wraps a GraphSegment and provides high-level analysis capabilities.
pub struct ShadowGraph {
  segment: GraphSegment,
  generation: u64, // Current traversal generation (for caching)
}

impl ShadowGraph {
  /// Create a new empty shadow graph
  pub fn new() -> Self {
    Self {
      segment: GraphSegment::new(),
      generation: 0,
    }
  }

  /// Create from an existing graph segment
  pub fn from_segment(segment: GraphSegment) -> Self {
    Self {
      segment,
      generation: 0,
    }
  }

  /// Get the underlying segment (for persistence)
  pub fn into_segment(self) -> GraphSegment {
    self.segment
  }

  /// Get a reference to the segment
  pub fn segment(&self) -> &GraphSegment {
    &self.segment
  }

  /// Get a mutable reference to the segment
  pub fn segment_mut(&mut self) -> &mut GraphSegment {
    &mut self.segment
  }

  /// Increment generation for cache invalidation
  fn next_generation(&mut self) -> u64 {
    self.generation += 1;
    self.generation
  }

  // ==================== Graph Building ====================

  /// Rebuild graph from loot entries
  pub fn rebuild_from_loot(&mut self, loot: &mut LootSegment) {
    self.segment = GraphSegment::new();

    for entry in loot.all() {
      self.add_loot_entry(&entry);
    }

    // Calculate depths after building
    self.calculate_depths();
  }

  /// Add a single loot entry to the graph
  pub fn add_loot_entry(&mut self, entry: &LootEntry) {
    match entry.category {
      LootCategory::Credential => self.add_credential_loot(entry),
      LootCategory::Vulnerability => self.add_vulnerability_loot(entry),
      LootCategory::Service => self.add_service_loot(entry),
      LootCategory::Endpoint => self.add_endpoint_loot(entry),
      LootCategory::Technology => self.add_technology_loot(entry),
      LootCategory::Finding => self.add_finding_loot(entry),
      _ => {}
    }
  }

  fn add_credential_loot(&mut self, entry: &LootEntry) {
    let cred_id = format!("cred:{}", entry.key);
    let username = entry.metadata.username.as_deref().unwrap_or("unknown");
    let node = GraphNode::credential(&entry.key, username);
    self.segment.add_node(node);

    // If target is specified, add AUTH_ACCESS edge
    if let Some(ip) = entry.target {
      let host_id = format!("host:{}", ip);
      self.ensure_host_node(&ip.to_string());
      self
        .segment
        .add_edge(GraphEdge::new(&cred_id, &host_id, EdgeType::AuthAccess));
    }

    // If source is specified, add CONTAINS edge (cred was found on this host)
    if let Some(ip) = entry.source {
      let host_id = format!("host:{}", ip);
      self.ensure_host_node(&ip.to_string());
      self
        .segment
        .add_edge(GraphEdge::new(&host_id, &cred_id, EdgeType::Contains));
    }
  }

  fn add_vulnerability_loot(&mut self, entry: &LootEntry) {
    let vuln_id = if let Some(cve) = &entry.metadata.cve {
      format!("vuln:{}", cve)
    } else {
      format!("vuln:{}", entry.key)
    };

    let label = entry.metadata.cve.as_deref().unwrap_or(&entry.key);
    let node = GraphNode::vulnerability(label);
    self.segment.add_node(node);

    // If target is specified, add AFFECTED_BY edge
    if let Some(ip) = entry.target {
      let host_id = format!("host:{}", ip);
      self.ensure_host_node(&ip.to_string());
      self
        .segment
        .add_edge(GraphEdge::new(&host_id, &vuln_id, EdgeType::AffectedBy));
    }
  }

  fn add_service_loot(&mut self, entry: &LootEntry) {
    for service in &entry.metadata.services {
      if let Some(ip) = entry.target {
        let host_id = format!("host:{}", ip);
        self.ensure_host_node(&ip.to_string());

        let service_id = format!("service:{}:{}:{}", ip, service.port, service.name);
        let mut node = GraphNode::service(&ip.to_string(), service.port, &service.name);
        if let Some(version) = &service.version {
          node.label = format!("{}:{} ({} {})", ip, service.port, service.name, version);
        }
        self.segment.add_node(node);
        self
          .segment
          .add_edge(GraphEdge::new(&host_id, &service_id, EdgeType::HasService));
      }
    }
  }

  fn add_endpoint_loot(&mut self, entry: &LootEntry) {
    for endpoint in &entry.metadata.endpoints {
      if let Some(ip) = entry.target {
        let host_id = format!("host:{}", ip);
        self.ensure_host_node(&ip.to_string());

        let endpoint_id = format!("endpoint:{}:{}", ip, endpoint.path);
        let node = GraphNode::new(
          &endpoint_id,
          NodeType::Endpoint,
          format!("{} {}", endpoint.method, endpoint.path),
        );
        self.segment.add_node(node);
        self.segment.add_edge(GraphEdge::new(
          &host_id,
          &endpoint_id,
          EdgeType::HasEndpoint,
        ));
      }
    }
  }

  fn add_technology_loot(&mut self, entry: &LootEntry) {
    for tech in &entry.metadata.technologies {
      if let Some(ip) = entry.target {
        let host_id = format!("host:{}", ip);
        self.ensure_host_node(&ip.to_string());

        let tech_id = format!("tech:{}:{}", ip, tech.name);
        let label = if let Some(version) = &tech.version {
          format!("{} {}", tech.name, version)
        } else {
          tech.name.clone()
        };
        let node = GraphNode::new(&tech_id, NodeType::Technology, label);
        self.segment.add_node(node);
        self
          .segment
          .add_edge(GraphEdge::new(&host_id, &tech_id, EdgeType::UsesTech));
      }
    }
  }

  fn add_finding_loot(&mut self, entry: &LootEntry) {
    // Extract any IPs mentioned in the content using regex-like patterns
    if let Some(ip) = entry.target {
      self.ensure_host_node(&ip.to_string());
    }
    if let Some(ip) = entry.source {
      self.ensure_host_node(&ip.to_string());
    }
  }

  // ==================== Action Integration ====================

  /// Rebuild graph from action records
  ///
  /// This method creates graph nodes and edges from action records,
  /// capturing the relationships between targets and actions performed.
  pub fn rebuild_from_actions(&mut self, actions: &[ActionRecord]) {
    for action in actions {
      self.add_action_record(action);
    }
    self.calculate_depths();
  }

  /// Add an action record to the graph
  ///
  /// Creates nodes for targets and edges representing:
  /// - Action relationships (SCANNED, EXPLOITED, etc.)
  /// - Service discovery
  /// - Attack progression
  pub fn add_action_record(&mut self, action: &ActionRecord) {
    // Ensure target node exists
    let target_id = self.ensure_action_target_node(&action.target);

    // Add action-type-specific relationships
    match action.action_type {
      ActionType::Scan | ActionType::Enumerate => {
        // Scan/enum actions discover information about target
        if matches!(action.outcome, ActionOutcome::Success) {
          // Mark node as discovered (metadata flag: 0x01 = discovered)
          if let Some(node) = self.segment.get_node_mut(&target_id) {
            if !node.metadata.contains(&0x01) {
              node.metadata.push(0x01);
            }
          }
        }
      }
      ActionType::Fingerprint => {
        // Fingerprinting identifies services/technologies
        if let ActionTarget::Service(ip, port, service) = &action.target {
          let host_id = format!("host:{}", ip);
          self.ensure_host_node(&ip.to_string());

          let service_id = format!("service:{}:{}:{}", ip, port, service);
          let node = GraphNode::service(&ip.to_string(), *port, service);
          self.segment.add_node(node);
          self
            .segment
            .add_edge(GraphEdge::new(&host_id, &service_id, EdgeType::HasService));
        }
      }
      ActionType::Audit => {
        // Audit actions may find vulnerabilities
        if matches!(action.outcome, ActionOutcome::Success) {
          // Could create vulnerability nodes here if payload contains vuln data
        }
      }
      ActionType::Exploit => {
        // Successful exploits create attack paths
        match &action.outcome {
          ActionOutcome::Success => {
            // Create "compromised" relationship (metadata flag: 0x02 = compromised)
            if let Some(node) = self.segment.get_node_mut(&target_id) {
              if !node.metadata.contains(&0x02) {
                node.metadata.push(0x02);
              }
            }

            // If source info available, add lateral movement edge
            if let crate::storage::ActionSource::Playbook { id, step } = &action.source {
              // Track attack chain via playbook execution
              let chain_id = format!("chain:{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3]);
              if self.segment.get_node(&chain_id).is_none() {
                let node = GraphNode::new(
                  &chain_id,
                  NodeType::AttackChain,
                  format!("Attack Chain {:02x}...", id[0]),
                );
                self.segment.add_node(node);
              }
              // Add edge from chain to target
              self.segment.add_edge(
                GraphEdge::new(&chain_id, &target_id, EdgeType::AttackPath)
                  .with_weight(*step as f32),
              );
            }
          }
          ActionOutcome::Partial { .. } => {
            // Partial exploitation - mark as vulnerable but not fully compromised
            // (metadata flag: 0x03 = vulnerable)
            if let Some(node) = self.segment.get_node_mut(&target_id) {
              if !node.metadata.contains(&0x03) {
                node.metadata.push(0x03);
              }
            }
          }
          _ => {}
        }
      }
      _ => {}
    }
  }

  /// Ensure an action target has a corresponding graph node
  fn ensure_action_target_node(&mut self, target: &ActionTarget) -> String {
    match target {
      ActionTarget::Host(ip) => {
        let id = format!("host:{}", ip);
        self.ensure_host_node(&ip.to_string());
        id
      }
      ActionTarget::Network(ip, prefix) => {
        let id = format!("network:{}/{}", ip, prefix);
        if self.segment.get_node(&id).is_none() {
          let node = GraphNode::new(&id, NodeType::Network, format!("{}/{}", ip, prefix));
          self.segment.add_node(node);
        }
        id
      }
      ActionTarget::Domain(domain) => {
        let id = format!("domain:{}", domain);
        if self.segment.get_node(&id).is_none() {
          let node = GraphNode::new(&id, NodeType::Domain, domain.clone());
          self.segment.add_node(node);
        }
        id
      }
      ActionTarget::Url(url) => {
        let id = format!("url:{}", url);
        if self.segment.get_node(&id).is_none() {
          let node = GraphNode::new(&id, NodeType::Endpoint, url.clone());
          self.segment.add_node(node);
        }
        id
      }
      ActionTarget::Port(ip, port) => {
        let host_id = format!("host:{}", ip);
        self.ensure_host_node(&ip.to_string());

        let port_id = format!("port:{}:{}", ip, port);
        if self.segment.get_node(&port_id).is_none() {
          let node = GraphNode::new(&port_id, NodeType::Service, format!("Port {}", port));
          self.segment.add_node(node);
          self
            .segment
            .add_edge(GraphEdge::new(&host_id, &port_id, EdgeType::HasService));
        }
        port_id
      }
      ActionTarget::Service(ip, port, service) => {
        let host_id = format!("host:{}", ip);
        self.ensure_host_node(&ip.to_string());

        let service_id = format!("service:{}:{}:{}", ip, port, service);
        if self.segment.get_node(&service_id).is_none() {
          let node = GraphNode::service(&ip.to_string(), *port, service);
          self.segment.add_node(node);
          self
            .segment
            .add_edge(GraphEdge::new(&host_id, &service_id, EdgeType::HasService));
        }
        service_id
      }
    }
  }

  fn ensure_host_node(&mut self, ip: &str) {
    let host_id = format!("host:{}", ip);
    if self.segment.get_node(&host_id).is_none() {
      self.segment.add_node(GraphNode::host(ip));
    }
  }

  // ==================== Graph Queries ====================

  /// Add a node to the graph
  pub fn add_node(&mut self, node: GraphNode) {
    self.segment.add_node(node);
  }

  /// Add an edge to the graph
  pub fn add_edge(&mut self, edge: GraphEdge) {
    self.segment.add_edge(edge);
  }

  /// Get a node by ID
  pub fn get_node(&self, id: &str) -> Option<&GraphNode> {
    self.segment.get_node(id)
  }

  /// Get all nodes of a specific type
  pub fn nodes_of_type(&self, node_type: NodeType) -> Vec<&GraphNode> {
    self.segment.nodes_of_type(node_type)
  }

  /// Get outgoing edges of a specific type from a node
  pub fn outgoing_edges(&self, node_id: &str, edge_type: EdgeType) -> Vec<&EdgeRef> {
    self
      .segment
      .get_node(node_id)
      .map(|n| {
        n.out_edges
          .iter()
          .filter(|e| e.edge_type == edge_type)
          .collect()
      })
      .unwrap_or_default()
  }

  /// Get incoming edges of a specific type to a node
  pub fn incoming_edges(&self, node_id: &str, edge_type: EdgeType) -> Vec<&EdgeRef> {
    self
      .segment
      .get_node(node_id)
      .map(|n| {
        n.in_edges
          .iter()
          .filter(|e| e.edge_type == edge_type)
          .collect()
      })
      .unwrap_or_default()
  }

  // ==================== DAG Validation (from genetics-ai) ====================

  /// Validate that the graph is a DAG using DFS
  pub fn validate_dag(&self) -> DagValidation {
    let mut visited = HashSet::new();
    let mut rec_stack = HashSet::new();
    let mut cycles = Vec::new();

    for node in self.segment.all_nodes() {
      if !visited.contains(&node.id) {
        self.detect_cycle_dfs(&node.id, &mut visited, &mut rec_stack, &mut cycles);
      }
    }

    DagValidation {
      is_dag: cycles.is_empty(),
      cycles,
    }
  }

  fn detect_cycle_dfs(
    &self,
    node_id: &str,
    visited: &mut HashSet<String>,
    rec_stack: &mut HashSet<String>,
    cycles: &mut Vec<(String, String)>,
  ) {
    visited.insert(node_id.to_string());
    rec_stack.insert(node_id.to_string());

    if let Some(node) = self.segment.get_node(node_id) {
      for edge in &node.out_edges {
        if !visited.contains(&edge.target_id) {
          self.detect_cycle_dfs(&edge.target_id, visited, rec_stack, cycles);
        } else if rec_stack.contains(&edge.target_id) {
          cycles.push((node_id.to_string(), edge.target_id.clone()));
        }
      }
    }

    rec_stack.remove(node_id);
  }

  /// Auto-fix cycles by removing edges (from genetics-ai Brain.fixCycles)
  pub fn fix_cycles(&mut self) -> usize {
    let validation = self.validate_dag();
    let mut removed = 0;

    for (from_id, to_id) in validation.cycles {
      if let Some(node) = self.segment.get_node_mut(&from_id) {
        node.out_edges.retain(|e| e.target_id != to_id);
        removed += 1;
      }
      if let Some(node) = self.segment.get_node_mut(&to_id) {
        node.in_edges.retain(|e| e.target_id != from_id);
      }
    }

    removed
  }

  // ==================== Topological Sort (from genetics-ai) ====================

  /// Calculate depths for all nodes (for topological ordering)
  fn calculate_depths(&mut self) {
    // Find root nodes (no incoming edges)
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut in_degree: HashMap<String, usize> = HashMap::new();

    for node in self.segment.all_nodes() {
      in_degree.insert(node.id.clone(), node.in_edges.len());
      if node.in_edges.is_empty() {
        queue.push_back(node.id.clone());
      }
    }

    // BFS to assign depths
    let mut current_depth = 0;
    while !queue.is_empty() {
      let level_size = queue.len();
      for _ in 0..level_size {
        if let Some(node_id) = queue.pop_front() {
          if let Some(node) = self.segment.get_node_mut(&node_id) {
            node.depth = current_depth;

            for edge in node.out_edges.clone() {
              if let Some(degree) = in_degree.get_mut(&edge.target_id) {
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                  queue.push_back(edge.target_id.clone());
                }
              }
            }
          }
        }
      }
      current_depth += 1;
    }
  }

  /// Get topological order of nodes by depth (from genetics-ai Brain.defineTickOrder)
  pub fn topological_order(&self) -> Vec<&GraphNode> {
    let mut nodes: Vec<&GraphNode> = self.segment.all_nodes();
    nodes.sort_by_key(|n| n.depth);
    nodes
  }

  /// Build layers by depth for batch processing (from genetics-ai Brain.buildLayers)
  pub fn build_layers(&self) -> Vec<GraphLayer> {
    let mut layers_map: HashMap<usize, Vec<String>> = HashMap::new();
    let mut max_depth = 0;

    for node in self.segment.all_nodes() {
      layers_map
        .entry(node.depth)
        .or_insert_with(Vec::new)
        .push(node.id.clone());
      if node.depth > max_depth {
        max_depth = node.depth;
      }
    }

    let mut layers = Vec::with_capacity(max_depth + 1);
    for depth in 0..=max_depth {
      if let Some(node_ids) = layers_map.remove(&depth) {
        layers.push(GraphLayer { depth, node_ids });
      }
    }

    layers
  }

  // ==================== Tree Traversal (from genetics-ai Vertex.inputsTree) ====================

  /// Get all predecessors (inputs tree) with depth
  pub fn inputs_tree(&self, node_id: &str, max_depth: usize) -> Vec<(String, usize)> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();
    self.inputs_tree_dfs(node_id, 0, max_depth, &mut visited, &mut result);
    result
  }

  fn inputs_tree_dfs(
    &self,
    node_id: &str,
    current_depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
    result: &mut Vec<(String, usize)>,
  ) {
    if current_depth > max_depth || visited.contains(node_id) {
      return;
    }

    visited.insert(node_id.to_string());
    result.push((node_id.to_string(), current_depth));

    if let Some(node) = self.segment.get_node(node_id) {
      for edge in &node.in_edges {
        self.inputs_tree_dfs(
          &edge.target_id,
          current_depth + 1,
          max_depth,
          visited,
          result,
        );
      }
    }
  }

  // ==================== Path Finding ====================

  /// Find shortest path using Dijkstra's algorithm
  pub fn shortest_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
    let mut dist: HashMap<String, u64> = HashMap::new();
    let mut prev: HashMap<String, String> = HashMap::new();
    let mut heap = BinaryHeap::new();

    dist.insert(from.to_string(), 0);
    heap.push(DijkstraState {
      cost: 0,
      node_id: from.to_string(),
    });

    while let Some(DijkstraState { cost, node_id }) = heap.pop() {
      if node_id == to {
        // Reconstruct path
        let mut path = vec![to.to_string()];
        let mut current = to.to_string();
        while let Some(p) = prev.get(&current) {
          path.push(p.clone());
          current = p.clone();
        }
        path.reverse();
        return Some(path);
      }

      if let Some(&d) = dist.get(&node_id) {
        if cost > d {
          continue;
        }
      }

      if let Some(node) = self.segment.get_node(&node_id) {
        for edge in &node.out_edges {
          let weight = (edge.weight * 1000.0) as u64;
          let next_cost = cost + weight;

          let current_dist = dist.get(&edge.target_id).copied().unwrap_or(u64::MAX);
          if next_cost < current_dist {
            dist.insert(edge.target_id.clone(), next_cost);
            prev.insert(edge.target_id.clone(), node_id.clone());
            heap.push(DijkstraState {
              cost: next_cost,
              node_id: edge.target_id.clone(),
            });
          }
        }
      }
    }

    None
  }

  /// Find all paths up to max_depth (for attack path discovery)
  pub fn find_all_paths(&self, from: &str, to: &str, max_depth: usize) -> Vec<Vec<String>> {
    let mut all_paths = Vec::new();
    let mut current_path = vec![from.to_string()];
    let mut visited = HashSet::new();
    visited.insert(from.to_string());

    self.find_paths_dfs(
      from,
      to,
      max_depth,
      &mut visited,
      &mut current_path,
      &mut all_paths,
    );

    all_paths
  }

  fn find_paths_dfs(
    &self,
    current: &str,
    target: &str,
    max_depth: usize,
    visited: &mut HashSet<String>,
    current_path: &mut Vec<String>,
    all_paths: &mut Vec<Vec<String>>,
  ) {
    if current == target {
      all_paths.push(current_path.clone());
      return;
    }

    if current_path.len() > max_depth {
      return;
    }

    if let Some(node) = self.segment.get_node(current) {
      for edge in &node.out_edges {
        if !visited.contains(&edge.target_id) {
          visited.insert(edge.target_id.clone());
          current_path.push(edge.target_id.clone());

          self.find_paths_dfs(
            &edge.target_id,
            target,
            max_depth,
            visited,
            current_path,
            all_paths,
          );

          current_path.pop();
          visited.remove(&edge.target_id);
        }
      }
    }
  }

  // ==================== Strategic Insights ====================

  /// Generate strategic insights from graph analysis
  pub fn get_insights(&self) -> Vec<Insight> {
    let mut insights = Vec::new();

    // 1. Find unused credentials (creds with access but host not fully scanned)
    insights.extend(self.find_unused_credentials());

    // 2. Find high-value targets
    insights.extend(self.find_high_value_targets());

    // 3. Find attack paths
    insights.extend(self.find_attack_paths());

    // 4. Find pivot opportunities
    insights.extend(self.find_pivot_opportunities());

    // Sort by priority
    insights.sort_by(|a, b| a.priority.cmp(&b.priority));

    insights
  }

  fn find_unused_credentials(&self) -> Vec<Insight> {
    let mut insights = Vec::new();

    for node in self.nodes_of_type(NodeType::Credential) {
      let access_targets: Vec<String> = node
        .out_edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::AuthAccess)
        .map(|e| e.target_id.clone())
        .collect();

      if !access_targets.is_empty() {
        // Check if targets have been fully scanned (have vulnerabilities or services)
        let mut unscanned = Vec::new();
        for target_id in &access_targets {
          if let Some(target) = self.segment.get_node(target_id) {
            let has_vulns = target
              .out_edges
              .iter()
              .any(|e| e.edge_type == EdgeType::AffectedBy);
            let service_count = target
              .out_edges
              .iter()
              .filter(|e| e.edge_type == EdgeType::HasService)
              .count();
            if !has_vulns && service_count < 2 {
              unscanned.push(target_id.clone());
            }
          }
        }

        if !unscanned.is_empty() {
          insights.push(Insight {
            insight_type: InsightType::UnusedCredentials,
            message: format!(
              "Credentials '{}' provide access to {} hosts that need more scanning",
              node.label,
              unscanned.len()
            ),
            priority: Priority::High,
            related_nodes: vec![node.id.clone()].into_iter().chain(unscanned).collect(),
          });
        }
      }
    }

    insights
  }

  fn find_high_value_targets(&self) -> Vec<Insight> {
    let mut insights = Vec::new();

    for node in self.nodes_of_type(NodeType::Host) {
      let service_count = node
        .out_edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::HasService)
        .count();
      let vuln_count = node
        .out_edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::AffectedBy)
        .count();
      let cred_count = node
        .out_edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::Contains)
        .count();

      if vuln_count > 0 || service_count >= 3 || cred_count > 0 {
        let priority = if vuln_count > 0 {
          Priority::Critical
        } else if cred_count > 0 {
          Priority::High
        } else {
          Priority::Medium
        };

        insights.push(Insight {
          insight_type: InsightType::HighValueTarget,
          message: format!(
            "High-value target '{}': {} services, {} vulnerabilities, {} credentials found",
            node.label, service_count, vuln_count, cred_count
          ),
          priority,
          related_nodes: vec![node.id.clone()],
        });
      }
    }

    insights
  }

  fn find_attack_paths(&self) -> Vec<Insight> {
    let mut insights = Vec::new();

    // Find paths from credentials to hosts with vulnerabilities
    let creds = self.nodes_of_type(NodeType::Credential);
    let hosts_with_vulns: Vec<String> = self
      .nodes_of_type(NodeType::Host)
      .iter()
      .filter(|h| {
        h.out_edges
          .iter()
          .any(|e| e.edge_type == EdgeType::AffectedBy)
      })
      .map(|h| h.id.clone())
      .collect();

    for cred in creds {
      for target in &hosts_with_vulns {
        // Skip if credential directly accesses this host
        if cred.out_edges.iter().any(|e| &e.target_id == target) {
          continue;
        }

        // Look for multi-hop paths
        let paths = self.find_all_paths(&cred.id, target, 4);
        for path in paths {
          if path.len() > 2 {
            insights.push(Insight {
              insight_type: InsightType::AttackPath,
              message: format!("Attack path found: {} → {}", path.join(" → "), ""),
              priority: Priority::High,
              related_nodes: path,
            });
          }
        }
      }
    }

    insights
  }

  fn find_pivot_opportunities(&self) -> Vec<Insight> {
    let mut insights = Vec::new();

    // Look for Host A -> Contains(Cred) -> AuthAccess(Host B) patterns
    for host in self.nodes_of_type(NodeType::Host) {
      let contained_creds: Vec<&EdgeRef> = host
        .out_edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::Contains)
        .collect();

      for cred_edge in contained_creds {
        if let Some(cred) = self.segment.get_node(&cred_edge.target_id) {
          let accessible_hosts: Vec<String> = cred
            .out_edges
            .iter()
            .filter(|e| e.edge_type == EdgeType::AuthAccess)
            .filter(|e| e.target_id != host.id) // Not the same host
            .map(|e| e.target_id.clone())
            .collect();

          for target_id in accessible_hosts {
            insights.push(Insight {
              insight_type: InsightType::PivotOpportunity,
              message: format!(
                "Pivot opportunity: {} → {} (via {}) → {}",
                host.label, cred.label, cred.label, target_id
              ),
              priority: Priority::High,
              related_nodes: vec![host.id.clone(), cred.id.clone(), target_id],
            });
          }
        }
      }
    }

    insights
  }

  // ==================== Statistics ====================

  /// Get graph statistics
  pub fn stats(&self) -> GraphStats {
    let mut nodes_by_type: HashMap<NodeType, usize> = HashMap::new();
    let edges_by_type = self.segment.count_edges_by_type();
    let mut max_depth = 0;

    for node in self.segment.all_nodes() {
      *nodes_by_type.entry(node.node_type).or_insert(0) += 1;
      if node.depth > max_depth {
        max_depth = node.depth;
      }
    }

    let validation = self.validate_dag();
    let connected_components = self.count_connected_components();

    GraphStats {
      total_nodes: self.segment.node_count(),
      nodes_by_type,
      total_edges: self.segment.edge_count(),
      edges_by_type,
      connected_components,
      max_depth,
      is_dag: validation.is_dag,
      cycle_count: validation.cycles.len(),
    }
  }

  fn count_connected_components(&self) -> usize {
    let mut visited = HashSet::new();
    let mut components = 0;

    for node in self.segment.all_nodes() {
      if !visited.contains(&node.id) {
        self.dfs_component(&node.id, &mut visited);
        components += 1;
      }
    }

    components
  }

  fn dfs_component(&self, node_id: &str, visited: &mut HashSet<String>) {
    visited.insert(node_id.to_string());

    if let Some(node) = self.segment.get_node(node_id) {
      // Visit outgoing edges
      for edge in &node.out_edges {
        if !visited.contains(&edge.target_id) {
          self.dfs_component(&edge.target_id, visited);
        }
      }
      // Visit incoming edges (for undirected component finding)
      for edge in &node.in_edges {
        if !visited.contains(&edge.target_id) {
          self.dfs_component(&edge.target_id, visited);
        }
      }
    }
  }

  // ==================== Mermaid Export ====================

  /// Export graph as Mermaid flowchart diagram
  pub fn to_mermaid(&self) -> String {
    let mut lines = vec!["flowchart LR".to_string()];

    // Add node definitions with styling
    for node in self.segment.all_nodes() {
      let (shape_start, shape_end) = match node.node_type {
        NodeType::Host => ("((", "))"),          // Circle
        NodeType::Service => ("[/", "/]"),       // Parallelogram
        NodeType::Credential => ("[[", "]]"),    // Rectangle with double border
        NodeType::Vulnerability => ("{{", "}}"), // Hexagon
        NodeType::Endpoint => ("([", "])"),      // Stadium
        NodeType::Technology => ("[", "]"),      // Rectangle
        NodeType::Network => ("((", "))"),       // Circle (like Host)
        NodeType::Domain => ("[", "]"),          // Rectangle (like Technology)
        NodeType::AttackChain => (">", "]"),     // Flag shape
      };

      let safe_label = node.label.replace("\"", "'").replace("\n", " ");
      let safe_id = node
        .id
        .replace(":", "_")
        .replace(".", "_")
        .replace("/", "_");
      lines.push(format!(
        "    {}{}\"{}\"{}",
        safe_id, shape_start, safe_label, shape_end
      ));
    }

    lines.push(String::new()); // Blank line

    // Add edges
    for node in self.segment.all_nodes() {
      let safe_source = node
        .id
        .replace(":", "_")
        .replace(".", "_")
        .replace("/", "_");
      for edge in &node.out_edges {
        let safe_target = edge
          .target_id
          .replace(":", "_")
          .replace(".", "_")
          .replace("/", "_");
        let edge_label = match edge.edge_type {
          EdgeType::HasService => "has_service",
          EdgeType::HasEndpoint => "has_endpoint",
          EdgeType::UsesTech => "uses",
          EdgeType::AuthAccess => "auth_access",
          EdgeType::AffectedBy => "affected_by",
          EdgeType::Contains => "contains",
          EdgeType::ConnectsTo => "connects_to",
          EdgeType::RelatedTo => "related",
          EdgeType::AttackPath => "attack_path",
        };
        lines.push(format!(
          "    {} -->|{}| {}",
          safe_source, edge_label, safe_target
        ));
      }
    }

    // Add styling
    lines.push(String::new());
    lines.push("    %% Styling".to_string());
    lines.push("    classDef host fill:#4CAF50,stroke:#333,color:#fff".to_string());
    lines.push("    classDef service fill:#2196F3,stroke:#333,color:#fff".to_string());
    lines.push("    classDef cred fill:#FF9800,stroke:#333,color:#fff".to_string());
    lines.push("    classDef vuln fill:#f44336,stroke:#333,color:#fff".to_string());
    lines.push("    classDef endpoint fill:#9C27B0,stroke:#333,color:#fff".to_string());
    lines.push("    classDef tech fill:#607D8B,stroke:#333,color:#fff".to_string());

    // Apply styles to nodes by type
    let mut hosts = Vec::new();
    let mut services = Vec::new();
    let mut creds = Vec::new();
    let mut vulns = Vec::new();
    let mut endpoints = Vec::new();
    let mut techs = Vec::new();

    for node in self.segment.all_nodes() {
      let safe_id = node
        .id
        .replace(":", "_")
        .replace(".", "_")
        .replace("/", "_");
      match node.node_type {
        NodeType::Host | NodeType::Network => hosts.push(safe_id),
        NodeType::Service => services.push(safe_id),
        NodeType::Credential => creds.push(safe_id),
        NodeType::Vulnerability => vulns.push(safe_id),
        NodeType::Endpoint => endpoints.push(safe_id),
        NodeType::Technology | NodeType::Domain => techs.push(safe_id),
        NodeType::AttackChain => vulns.push(safe_id), // Style like vulns for visibility
      }
    }

    if !hosts.is_empty() {
      lines.push(format!("    class {} host", hosts.join(",")));
    }
    if !services.is_empty() {
      lines.push(format!("    class {} service", services.join(",")));
    }
    if !creds.is_empty() {
      lines.push(format!("    class {} cred", creds.join(",")));
    }
    if !vulns.is_empty() {
      lines.push(format!("    class {} vuln", vulns.join(",")));
    }
    if !endpoints.is_empty() {
      lines.push(format!("    class {} endpoint", endpoints.join(",")));
    }
    if !techs.is_empty() {
      lines.push(format!("    class {} tech", techs.join(",")));
    }

    lines.join("\n")
  }

  /// Export a summary of the graph
  pub fn export_summary(&self) -> String {
    let stats = self.stats();
    let mut lines = Vec::new();

    lines.push("=== Shadow Graph Summary ===".to_string());
    lines.push(format!("Total Nodes: {}", stats.total_nodes));
    lines.push(format!("Total Edges: {}", stats.total_edges));
    lines.push(format!(
      "Connected Components: {}",
      stats.connected_components
    ));
    lines.push(format!("Max Depth: {}", stats.max_depth));
    lines.push(format!("Is DAG: {}", stats.is_dag));

    if !stats.is_dag {
      lines.push(format!("Cycle Count: {}", stats.cycle_count));
    }

    lines.push(String::new());
    lines.push("Nodes by Type:".to_string());
    for (node_type, count) in &stats.nodes_by_type {
      lines.push(format!("  {:?}: {}", node_type, count));
    }

    lines.push(String::new());
    lines.push("Edges by Type:".to_string());
    for (edge_type, count) in &stats.edges_by_type {
      lines.push(format!("  {:?}: {}", edge_type, count));
    }

    lines.join("\n")
  }

  // ==================== Serialization ====================

  /// Serialize graph to bytes for persistence
  pub fn to_bytes(&mut self) -> Vec<u8> {
    self.segment.serialize()
  }

  /// Deserialize graph from bytes
  pub fn from_bytes(
    bytes: &[u8],
  ) -> Result<Self, crate::storage::primitives::encoding::DecodeError> {
    let segment = GraphSegment::deserialize(bytes)?;
    Ok(Self::from_segment(segment))
  }
}

impl Default for ShadowGraph {
  fn default() -> Self {
    Self::new()
  }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_shortest_path() {
    let mut graph = ShadowGraph::new();

    graph.add_node(GraphNode::host("192.168.1.1"));
    graph.add_node(GraphNode::host("192.168.1.2"));
    graph.add_node(GraphNode::host("192.168.1.3"));

    graph.add_edge(GraphEdge::new(
      "host:192.168.1.1",
      "host:192.168.1.2",
      EdgeType::ConnectsTo,
    ));
    graph.add_edge(GraphEdge::new(
      "host:192.168.1.2",
      "host:192.168.1.3",
      EdgeType::ConnectsTo,
    ));

    let path = graph.shortest_path("host:192.168.1.1", "host:192.168.1.3");
    assert!(path.is_some());
    let path = path.unwrap();
    assert_eq!(path.len(), 3);
    assert_eq!(path[0], "host:192.168.1.1");
    assert_eq!(path[2], "host:192.168.1.3");
  }

  #[test]
  fn test_dag_validation() {
    let mut graph = ShadowGraph::new();

    graph.add_node(GraphNode::new("a", NodeType::Host, "A"));
    graph.add_node(GraphNode::new("b", NodeType::Host, "B"));
    graph.add_node(GraphNode::new("c", NodeType::Host, "C"));

    graph.add_edge(GraphEdge::new("a", "b", EdgeType::ConnectsTo));
    graph.add_edge(GraphEdge::new("b", "c", EdgeType::ConnectsTo));

    let validation = graph.validate_dag();
    assert!(validation.is_dag);
    assert!(validation.cycles.is_empty());

    // Add a cycle
    graph.add_edge(GraphEdge::new("c", "a", EdgeType::ConnectsTo));

    let validation = graph.validate_dag();
    assert!(!validation.is_dag);
    assert!(!validation.cycles.is_empty());
  }

  #[test]
  fn test_fix_cycles() {
    let mut graph = ShadowGraph::new();

    graph.add_node(GraphNode::new("a", NodeType::Host, "A"));
    graph.add_node(GraphNode::new("b", NodeType::Host, "B"));

    graph.add_edge(GraphEdge::new("a", "b", EdgeType::ConnectsTo));
    graph.add_edge(GraphEdge::new("b", "a", EdgeType::ConnectsTo));

    assert!(!graph.validate_dag().is_dag);

    let removed = graph.fix_cycles();
    assert!(removed > 0);
    assert!(graph.validate_dag().is_dag);
  }

  #[test]
  fn test_topological_order() {
    let mut graph = ShadowGraph::new();

    let mut node_a = GraphNode::new("a", NodeType::Host, "A");
    node_a.depth = 0;
    let mut node_b = GraphNode::new("b", NodeType::Host, "B");
    node_b.depth = 1;
    let mut node_c = GraphNode::new("c", NodeType::Host, "C");
    node_c.depth = 2;

    graph.add_node(node_c);
    graph.add_node(node_a);
    graph.add_node(node_b);

    let order = graph.topological_order();
    assert_eq!(order[0].id, "a");
    assert_eq!(order[1].id, "b");
    assert_eq!(order[2].id, "c");
  }

  #[test]
  fn test_build_layers() {
    let mut graph = ShadowGraph::new();

    let mut node_a = GraphNode::new("a", NodeType::Host, "A");
    node_a.depth = 0;
    let mut node_b = GraphNode::new("b", NodeType::Host, "B");
    node_b.depth = 0;
    let mut node_c = GraphNode::new("c", NodeType::Host, "C");
    node_c.depth = 1;

    graph.add_node(node_a);
    graph.add_node(node_b);
    graph.add_node(node_c);

    let layers = graph.build_layers();
    assert_eq!(layers.len(), 2);
    assert_eq!(layers[0].depth, 0);
    assert_eq!(layers[0].node_ids.len(), 2);
    assert_eq!(layers[1].depth, 1);
    assert_eq!(layers[1].node_ids.len(), 1);
  }

  #[test]
  fn test_insights_unused_credentials() {
    let mut graph = ShadowGraph::new();

    graph.add_node(GraphNode::credential("admin_creds", "admin"));
    graph.add_node(GraphNode::host("192.168.1.1"));

    graph.add_edge(GraphEdge::new(
      "cred:admin_creds",
      "host:192.168.1.1",
      EdgeType::AuthAccess,
    ));

    let insights = graph.get_insights();
    let unused_cred_insights: Vec<_> = insights
      .iter()
      .filter(|i| i.insight_type == InsightType::UnusedCredentials)
      .collect();

    assert!(!unused_cred_insights.is_empty());
  }

  #[test]
  fn test_mermaid_export() {
    let mut graph = ShadowGraph::new();

    graph.add_node(GraphNode::host("192.168.1.1"));
    graph.add_node(GraphNode::credential("admin", "admin"));

    graph.add_edge(GraphEdge::new(
      "cred:admin",
      "host:192.168.1.1",
      EdgeType::AuthAccess,
    ));

    let mermaid = graph.to_mermaid();
    assert!(mermaid.contains("flowchart LR"));
    assert!(mermaid.contains("auth_access"));
  }

  #[test]
  fn test_find_all_paths() {
    let mut graph = ShadowGraph::new();

    graph.add_node(GraphNode::new("a", NodeType::Host, "A"));
    graph.add_node(GraphNode::new("b", NodeType::Host, "B"));
    graph.add_node(GraphNode::new("c", NodeType::Host, "C"));
    graph.add_node(GraphNode::new("d", NodeType::Host, "D"));

    // Multiple paths from A to D
    graph.add_edge(GraphEdge::new("a", "b", EdgeType::ConnectsTo));
    graph.add_edge(GraphEdge::new("b", "d", EdgeType::ConnectsTo));
    graph.add_edge(GraphEdge::new("a", "c", EdgeType::ConnectsTo));
    graph.add_edge(GraphEdge::new("c", "d", EdgeType::ConnectsTo));

    let paths = graph.find_all_paths("a", "d", 5);
    assert_eq!(paths.len(), 2);
  }

  #[test]
  fn test_stats() {
    let mut graph = ShadowGraph::new();

    graph.add_node(GraphNode::host("192.168.1.1"));
    graph.add_node(GraphNode::host("192.168.1.2"));
    graph.add_node(GraphNode::credential("admin", "admin"));

    graph.add_edge(GraphEdge::new(
      "host:192.168.1.1",
      "host:192.168.1.2",
      EdgeType::ConnectsTo,
    ));

    let stats = graph.stats();
    assert_eq!(stats.total_nodes, 3);
    assert_eq!(stats.total_edges, 1);
    assert_eq!(*stats.nodes_by_type.get(&NodeType::Host).unwrap_or(&0), 2);
  }
}
