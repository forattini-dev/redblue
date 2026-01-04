//! Force-Directed Graph Layout Algorithm
//!
//! Physics-based graph layout using:
//! - Repulsion (Coulomb's law): nodes push each other away
//! - Attraction (Hooke's law): connected nodes pull together
//! - Gravity: nodes are pulled toward center to prevent drift
//!
//! Optional Barnes-Hut optimization for O(N log N) repulsion on large graphs.

use std::collections::HashMap;

/// 2D position for a node
#[derive(Debug, Clone, Copy, Default)]
pub struct Position {
    pub x: f64,
    pub y: f64,
}

impl Position {
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }

    /// Distance to another position
    pub fn distance(&self, other: &Position) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        (dx * dx + dy * dy).sqrt()
    }

    /// Unit vector from self to other
    pub fn direction_to(&self, other: &Position) -> (f64, f64) {
        let dx = other.x - self.x;
        let dy = other.y - self.y;
        let d = (dx * dx + dy * dy).sqrt();
        if d < 1e-10 {
            (0.0, 0.0)
        } else {
            (dx / d, dy / d)
        }
    }
}

/// 2D velocity vector
#[derive(Debug, Clone, Copy, Default)]
struct Velocity {
    vx: f64,
    vy: f64,
}

/// Node with physics state
#[derive(Debug, Clone)]
struct PhysicsNode {
    position: Position,
    velocity: Velocity,
    fixed: bool,
}

/// Edge in the layout graph
#[derive(Debug, Clone)]
pub struct LayoutEdge {
    pub from: String,
    pub to: String,
    pub weight: f64,
}

/// Configuration for the force-directed layout
#[derive(Debug, Clone)]
pub struct LayoutConfig {
    /// Number of simulation iterations
    pub iterations: usize,
    /// Repulsion strength (Coulomb constant)
    pub repulsion: f64,
    /// Attraction strength (spring constant)
    pub attraction: f64,
    /// Gravity strength (pull toward center)
    pub gravity: f64,
    /// Velocity damping factor (0.0-1.0)
    pub damping: f64,
    /// Minimum distance between nodes to avoid division by zero
    pub min_distance: f64,
    /// Initial spread radius for random placement
    pub initial_radius: f64,
    /// Use Barnes-Hut optimization for large graphs
    pub barnes_hut: bool,
    /// Barnes-Hut theta parameter (accuracy vs speed tradeoff)
    pub theta: f64,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            iterations: 500,
            repulsion: 5000.0,
            attraction: 0.1,
            gravity: 0.05,
            damping: 0.85,
            min_distance: 1.0,
            initial_radius: 100.0,
            barnes_hut: false,
            theta: 0.5,
        }
    }
}

impl LayoutConfig {
    /// Quick layout with fewer iterations
    pub fn fast() -> Self {
        Self {
            iterations: 100,
            ..Default::default()
        }
    }

    /// High-quality layout with more iterations
    pub fn quality() -> Self {
        Self {
            iterations: 1000,
            damping: 0.9,
            ..Default::default()
        }
    }

    /// Optimized for large graphs using Barnes-Hut
    pub fn large_graph() -> Self {
        Self {
            iterations: 300,
            barnes_hut: true,
            theta: 0.8,
            ..Default::default()
        }
    }
}

/// Maximum depth for quadtree to prevent stack overflow
const MAX_QUADTREE_DEPTH: usize = 32;

/// Quadtree node for Barnes-Hut optimization
#[derive(Debug)]
struct QuadTreeNode {
    /// Bounding box
    x_min: f64,
    y_min: f64,
    x_max: f64,
    y_max: f64,
    /// Center of mass
    center_x: f64,
    center_y: f64,
    /// Total mass (number of nodes)
    mass: usize,
    /// Node positions if this is a leaf (for colocated nodes at max depth)
    leaf_nodes: Vec<(String, f64, f64)>,
    /// Children: NW, NE, SW, SE
    children: Option<Box<[Option<QuadTreeNode>; 4]>>,
}

impl QuadTreeNode {
    fn new(x_min: f64, y_min: f64, x_max: f64, y_max: f64) -> Self {
        Self {
            x_min,
            y_min,
            x_max,
            y_max,
            center_x: 0.0,
            center_y: 0.0,
            mass: 0,
            leaf_nodes: Vec::new(),
            children: None,
        }
    }

    fn width(&self) -> f64 {
        self.x_max - self.x_min
    }

    fn insert(&mut self, id: &str, x: f64, y: f64, depth: usize) {
        // Update center of mass
        let new_mass = self.mass + 1;
        self.center_x = (self.center_x * self.mass as f64 + x) / new_mass as f64;
        self.center_y = (self.center_y * self.mass as f64 + y) / new_mass as f64;
        self.mass = new_mass;

        // At max depth, just store in leaf
        if depth >= MAX_QUADTREE_DEPTH {
            self.leaf_nodes.push((id.to_string(), x, y));
            return;
        }

        if self.children.is_none() && self.leaf_nodes.is_empty() {
            // Empty leaf - store the node
            self.leaf_nodes.push((id.to_string(), x, y));
            return;
        }

        if self.children.is_none() {
            // Leaf with one node - need to subdivide
            self.subdivide();
            // Re-insert existing nodes
            let existing = std::mem::take(&mut self.leaf_nodes);
            for (eid, ex, ey) in existing {
                self.insert_into_child(&eid, ex, ey, depth + 1);
            }
        }

        // Insert into appropriate child
        self.insert_into_child(id, x, y, depth + 1);
    }

    fn subdivide(&mut self) {
        let mid_x = (self.x_min + self.x_max) / 2.0;
        let mid_y = (self.y_min + self.y_max) / 2.0;

        self.children = Some(Box::new([
            Some(QuadTreeNode::new(self.x_min, self.y_min, mid_x, mid_y)), // NW
            Some(QuadTreeNode::new(mid_x, self.y_min, self.x_max, mid_y)), // NE
            Some(QuadTreeNode::new(self.x_min, mid_y, mid_x, self.y_max)), // SW
            Some(QuadTreeNode::new(mid_x, mid_y, self.x_max, self.y_max)), // SE
        ]));
    }

    fn insert_into_child(&mut self, id: &str, x: f64, y: f64, depth: usize) {
        if let Some(children) = &mut self.children {
            let mid_x = (self.x_min + self.x_max) / 2.0;
            let mid_y = (self.y_min + self.y_max) / 2.0;

            let index = if x < mid_x {
                if y < mid_y {
                    0
                } else {
                    2
                }
            } else if y < mid_y {
                1
            } else {
                3
            };

            if let Some(child) = &mut children[index] {
                child.insert(id, x, y, depth);
            }
        }
    }

    /// Calculate repulsion force from this quadtree node
    fn calculate_force(
        &self,
        x: f64,
        y: f64,
        theta: f64,
        repulsion: f64,
        min_dist: f64,
    ) -> (f64, f64) {
        if self.mass == 0 {
            return (0.0, 0.0);
        }

        let dx = x - self.center_x;
        let dy = y - self.center_y;
        let d = (dx * dx + dy * dy).sqrt().max(min_dist);

        // If this is a leaf or far enough away, treat as single body
        if self.children.is_none() || (self.width() / d) < theta {
            // Coulomb repulsion: F = k * m1 * m2 / d^2
            let force = repulsion * self.mass as f64 / (d * d);
            return (force * dx / d, force * dy / d);
        }

        // Otherwise, recurse into children
        let mut fx = 0.0;
        let mut fy = 0.0;
        if let Some(children) = &self.children {
            for child in children.iter().flatten() {
                let (cfx, cfy) = child.calculate_force(x, y, theta, repulsion, min_dist);
                fx += cfx;
                fy += cfy;
            }
        }

        (fx, fy)
    }
}

/// Force-directed graph layout engine
pub struct ForceLayout {
    config: LayoutConfig,
    nodes: HashMap<String, PhysicsNode>,
    edges: Vec<LayoutEdge>,
    node_counter: usize,
}

impl ForceLayout {
    /// Create a new force layout with default configuration
    pub fn new() -> Self {
        Self {
            config: LayoutConfig::default(),
            nodes: HashMap::new(),
            edges: Vec::new(),
            node_counter: 0,
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: LayoutConfig) -> Self {
        Self {
            config,
            nodes: HashMap::new(),
            edges: Vec::new(),
            node_counter: 0,
        }
    }

    /// Add a node to the layout
    pub fn add_node(&mut self, id: &str) {
        if !self.nodes.contains_key(id) {
            // Use counter for consistent spacing + hash for additional variation
            let counter = self.node_counter;
            self.node_counter += 1;

            // Spread nodes in a spiral pattern based on counter
            let hash = id
                .bytes()
                .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
            let base_angle = counter as f64 * 2.399; // Golden angle for even distribution
            let hash_offset = (hash % 1000) as f64 / 1000.0 * 0.5; // Small random offset
            let angle = base_angle + hash_offset;

            // Radius increases with counter for spiral
            let base_radius = 20.0 + (counter as f64).sqrt() * 15.0;
            let radius = base_radius.min(self.config.initial_radius);

            self.nodes.insert(
                id.to_string(),
                PhysicsNode {
                    position: Position::new(radius * angle.cos(), radius * angle.sin()),
                    velocity: Velocity::default(),
                    fixed: false,
                },
            );
        }
    }

    /// Add a node with a fixed position
    pub fn add_fixed_node(&mut self, id: &str, x: f64, y: f64) {
        self.nodes.insert(
            id.to_string(),
            PhysicsNode {
                position: Position::new(x, y),
                velocity: Velocity::default(),
                fixed: true,
            },
        );
    }

    /// Add an edge between nodes
    pub fn add_edge(&mut self, from: &str, to: &str, weight: f64) {
        // Ensure nodes exist
        self.add_node(from);
        self.add_node(to);

        self.edges.push(LayoutEdge {
            from: from.to_string(),
            to: to.to_string(),
            weight,
        });
    }

    /// Run the layout simulation
    pub fn run(&mut self) -> HashMap<String, Position> {
        for _ in 0..self.config.iterations {
            self.step();
        }

        self.positions()
    }

    /// Run a single simulation step
    pub fn step(&mut self) {
        if self.nodes.is_empty() {
            return;
        }

        // Calculate forces
        let forces = if self.config.barnes_hut && self.nodes.len() > 100 {
            self.calculate_forces_barnes_hut()
        } else {
            self.calculate_forces_naive()
        };

        // Apply forces and update positions
        for (id, node) in &mut self.nodes {
            if node.fixed {
                continue;
            }

            if let Some((fx, fy)) = forces.get(id) {
                // Update velocity with damping
                node.velocity.vx = (node.velocity.vx + fx) * self.config.damping;
                node.velocity.vy = (node.velocity.vy + fy) * self.config.damping;

                // Update position
                node.position.x += node.velocity.vx;
                node.position.y += node.velocity.vy;
            }
        }
    }

    /// Calculate forces using naive O(N^2) algorithm
    fn calculate_forces_naive(&self) -> HashMap<String, (f64, f64)> {
        let mut forces: HashMap<String, (f64, f64)> = HashMap::new();

        let node_ids: Vec<_> = self.nodes.keys().cloned().collect();

        // Initialize forces
        for id in &node_ids {
            forces.insert(id.clone(), (0.0, 0.0));
        }

        // Repulsion between all pairs of nodes
        for i in 0..node_ids.len() {
            for j in (i + 1)..node_ids.len() {
                let id1 = &node_ids[i];
                let id2 = &node_ids[j];

                let pos1 = self.nodes[id1].position;
                let pos2 = self.nodes[id2].position;

                let dx = pos1.x - pos2.x;
                let dy = pos1.y - pos2.y;
                let d = (dx * dx + dy * dy).sqrt().max(self.config.min_distance);

                // Coulomb repulsion: F = k / d^2
                let force = self.config.repulsion / (d * d);
                let fx = force * dx / d;
                let fy = force * dy / d;

                if let Some(f) = forces.get_mut(id1) {
                    f.0 += fx;
                    f.1 += fy;
                }
                if let Some(f) = forces.get_mut(id2) {
                    f.0 -= fx;
                    f.1 -= fy;
                }
            }
        }

        // Attraction along edges (Hooke's law)
        for edge in &self.edges {
            let pos1 = self.nodes[&edge.from].position;
            let pos2 = self.nodes[&edge.to].position;

            let dx = pos2.x - pos1.x;
            let dy = pos2.y - pos1.y;
            let d = (dx * dx + dy * dy).sqrt().max(self.config.min_distance);

            // Spring force: F = k * d
            let force = self.config.attraction * d * edge.weight;
            let fx = force * dx / d;
            let fy = force * dy / d;

            if let Some(f) = forces.get_mut(&edge.from) {
                f.0 += fx;
                f.1 += fy;
            }
            if let Some(f) = forces.get_mut(&edge.to) {
                f.0 -= fx;
                f.1 -= fy;
            }
        }

        // Gravity toward center
        for (id, node) in &self.nodes {
            if let Some(f) = forces.get_mut(id) {
                f.0 -= node.position.x * self.config.gravity;
                f.1 -= node.position.y * self.config.gravity;
            }
        }

        forces
    }

    /// Calculate forces using Barnes-Hut O(N log N) algorithm
    fn calculate_forces_barnes_hut(&self) -> HashMap<String, (f64, f64)> {
        // Build quadtree
        let (mut x_min, mut y_min, mut x_max, mut y_max) = (f64::MAX, f64::MAX, f64::MIN, f64::MIN);
        for node in self.nodes.values() {
            x_min = x_min.min(node.position.x);
            y_min = y_min.min(node.position.y);
            x_max = x_max.max(node.position.x);
            y_max = y_max.max(node.position.y);
        }

        // Add padding
        let padding = 10.0;
        x_min -= padding;
        y_min -= padding;
        x_max += padding;
        y_max += padding;

        let mut root = QuadTreeNode::new(x_min, y_min, x_max, y_max);
        for (id, node) in &self.nodes {
            root.insert(id, node.position.x, node.position.y, 0);
        }

        // Calculate forces
        let mut forces: HashMap<String, (f64, f64)> = HashMap::new();

        for (id, node) in &self.nodes {
            let (fx, fy) = root.calculate_force(
                node.position.x,
                node.position.y,
                self.config.theta,
                self.config.repulsion,
                self.config.min_distance,
            );
            forces.insert(id.clone(), (fx, fy));
        }

        // Add attraction and gravity (same as naive)
        for edge in &self.edges {
            let pos1 = self.nodes[&edge.from].position;
            let pos2 = self.nodes[&edge.to].position;

            let dx = pos2.x - pos1.x;
            let dy = pos2.y - pos1.y;
            let d = (dx * dx + dy * dy).sqrt().max(self.config.min_distance);

            let force = self.config.attraction * d * edge.weight;
            let fx = force * dx / d;
            let fy = force * dy / d;

            if let Some(f) = forces.get_mut(&edge.from) {
                f.0 += fx;
                f.1 += fy;
            }
            if let Some(f) = forces.get_mut(&edge.to) {
                f.0 -= fx;
                f.1 -= fy;
            }
        }

        for (id, node) in &self.nodes {
            if let Some(f) = forces.get_mut(id) {
                f.0 -= node.position.x * self.config.gravity;
                f.1 -= node.position.y * self.config.gravity;
            }
        }

        forces
    }

    /// Get current positions of all nodes
    pub fn positions(&self) -> HashMap<String, Position> {
        self.nodes
            .iter()
            .map(|(id, node)| (id.clone(), node.position))
            .collect()
    }

    /// Get bounding box of the layout
    pub fn bounds(&self) -> (f64, f64, f64, f64) {
        if self.nodes.is_empty() {
            return (0.0, 0.0, 0.0, 0.0);
        }

        let mut x_min = f64::MAX;
        let mut y_min = f64::MAX;
        let mut x_max = f64::MIN;
        let mut y_max = f64::MIN;

        for node in self.nodes.values() {
            x_min = x_min.min(node.position.x);
            y_min = y_min.min(node.position.y);
            x_max = x_max.max(node.position.x);
            y_max = y_max.max(node.position.y);
        }

        (x_min, y_min, x_max, y_max)
    }

    /// Normalize positions to fit within a given width and height
    pub fn normalize(&mut self, width: f64, height: f64, padding: f64) {
        let (x_min, y_min, x_max, y_max) = self.bounds();

        let x_range = (x_max - x_min).max(1.0);
        let y_range = (y_max - y_min).max(1.0);

        let usable_width = width - 2.0 * padding;
        let usable_height = height - 2.0 * padding;

        let scale = (usable_width / x_range).min(usable_height / y_range);

        for node in self.nodes.values_mut() {
            node.position.x = padding + (node.position.x - x_min) * scale;
            node.position.y = padding + (node.position.y - y_min) * scale;
        }
    }
}

impl Default for ForceLayout {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_distance() {
        let p1 = Position::new(0.0, 0.0);
        let p2 = Position::new(3.0, 4.0);
        assert!((p1.distance(&p2) - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_position_direction() {
        let p1 = Position::new(0.0, 0.0);
        let p2 = Position::new(1.0, 0.0);
        let (dx, dy) = p1.direction_to(&p2);
        assert!((dx - 1.0).abs() < 1e-10);
        assert!(dy.abs() < 1e-10);
    }

    #[test]
    fn test_empty_layout() {
        let mut layout = ForceLayout::new();
        let positions = layout.run();
        assert!(positions.is_empty());
    }

    #[test]
    fn test_single_node() {
        let mut layout = ForceLayout::new();
        layout.add_node("A");
        let positions = layout.run();
        assert_eq!(positions.len(), 1);
        assert!(positions.contains_key("A"));
    }

    #[test]
    fn test_two_connected_nodes() {
        let mut layout = ForceLayout::with_config(LayoutConfig {
            iterations: 100,
            ..Default::default()
        });
        layout.add_edge("A", "B", 1.0);
        let positions = layout.run();

        assert_eq!(positions.len(), 2);

        // Nodes should be at some distance from each other
        let pa = positions.get("A").unwrap();
        let pb = positions.get("B").unwrap();
        let dist = pa.distance(pb);

        // After simulation, nodes should have moved from initial positions
        assert!(dist > 0.0);
    }

    #[test]
    fn test_fixed_node() {
        let mut layout = ForceLayout::new();
        layout.add_fixed_node("center", 0.0, 0.0);
        layout.add_edge("center", "A", 1.0);
        let positions = layout.run();

        // Fixed node should remain at origin
        let center = positions.get("center").unwrap();
        assert!((center.x).abs() < 1e-10);
        assert!((center.y).abs() < 1e-10);
    }

    #[test]
    fn test_triangle() {
        let mut layout = ForceLayout::with_config(LayoutConfig {
            iterations: 200,
            ..Default::default()
        });
        layout.add_edge("A", "B", 1.0);
        layout.add_edge("B", "C", 1.0);
        layout.add_edge("C", "A", 1.0);
        let positions = layout.run();

        assert_eq!(positions.len(), 3);

        // All nodes should be roughly equidistant
        let pa = positions.get("A").unwrap();
        let pb = positions.get("B").unwrap();
        let pc = positions.get("C").unwrap();

        let dab = pa.distance(pb);
        let dbc = pb.distance(pc);
        let dca = pc.distance(pa);

        // Distances should be similar (within 50%)
        let avg = (dab + dbc + dca) / 3.0;
        assert!((dab - avg).abs() / avg < 0.5);
        assert!((dbc - avg).abs() / avg < 0.5);
        assert!((dca - avg).abs() / avg < 0.5);
    }

    #[test]
    fn test_normalize() {
        let mut layout = ForceLayout::new();
        layout.add_edge("A", "B", 1.0);
        layout.add_edge("B", "C", 1.0);
        layout.run();
        layout.normalize(800.0, 600.0, 50.0);

        let positions = layout.positions();
        for pos in positions.values() {
            assert!(pos.x >= 50.0 && pos.x <= 750.0);
            assert!(pos.y >= 50.0 && pos.y <= 550.0);
        }
    }

    #[test]
    fn test_barnes_hut_config() {
        let config = LayoutConfig::large_graph();
        assert!(config.barnes_hut);
        assert_eq!(config.theta, 0.8);
    }

    #[test]
    fn test_many_nodes() {
        let mut layout = ForceLayout::with_config(LayoutConfig {
            iterations: 50,
            barnes_hut: true,
            theta: 0.5,
            ..Default::default()
        });

        // Create a star graph with 100 nodes
        for i in 0..100 {
            layout.add_edge("center", &format!("node_{}", i), 1.0);
        }

        let positions = layout.run();
        assert_eq!(positions.len(), 101); // center + 100 nodes
    }
}
