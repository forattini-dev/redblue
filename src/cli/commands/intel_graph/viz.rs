//! Graph Visualization Commands
//!
//! Visualization for graph intelligence:
//! - SVG rendering with force-directed layout
//! - ASCII tree visualization with highlighting
//! - Path and vulnerability highlighting

use super::helpers::truncate_str;
use crate::cli::{output::Output, CliContext};
use crate::modules::viz::{
    EdgeStyle, ForceLayout, LayoutConfig, NodeStyle, PathHighlight, RenderEdge, RenderNode,
    SvgConfig, SvgRenderer,
};
use crate::storage::engine::{GraphEdgeType, GraphNodeType, GraphStore};
use std::collections::{HashMap, HashSet};

/// Graph visualization command
pub fn cmd_viz(ctx: &CliContext, graph: &GraphStore) -> Result<(), String> {
    let limit: usize = ctx
        .flags
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    let nodes: Vec<_> = graph.iter_nodes().take(limit).collect();
    let edges = graph.iter_all_edges();

    if nodes.is_empty() {
        Output::warning("Graph is empty - nothing to visualize");
        return Ok(());
    }

    // Parse flags
    let path_spec = ctx.flags.get("path");
    let highlight_vulns = ctx.flags.contains_key("vulns");
    let svg_output = ctx.flags.get("svg");

    // Find path if specified (format: "FROM node1 TO node2")
    let mut path_highlights: Vec<PathHighlight> = Vec::new();

    if let Some(path_str) = path_spec {
        // Parse "FROM x TO y" or "x TO y" format
        let parts: Vec<&str> = path_str.split_whitespace().collect();
        let (from_id, to_id) = if parts.len() >= 4
            && parts[0].eq_ignore_ascii_case("FROM")
            && parts[2].eq_ignore_ascii_case("TO")
        {
            (parts[1].to_string(), parts[3].to_string())
        } else if parts.len() >= 3 && parts[1].eq_ignore_ascii_case("TO") {
            (parts[0].to_string(), parts[2].to_string())
        } else {
            return Err(format!(
                "Invalid path format: '{}'. Use: FROM node1 TO node2",
                path_str
            ));
        };

        // BFS to find path
        if let Some(path) = find_path_bfs(graph, &from_id, &to_id) {
            Output::success(&format!(
                "Found path with {} hops: {} → {}",
                path.len() - 1,
                from_id,
                to_id
            ));
            path_highlights.push(PathHighlight::attack_path(path));
        } else {
            Output::warning(&format!("No path found from '{}' to '{}'", from_id, to_id));
        }
    }

    // Highlight vulnerability nodes and edges if requested
    let mut vuln_nodes: HashSet<String> = HashSet::new();
    if highlight_vulns {
        for node in &nodes {
            if matches!(node.node_type, GraphNodeType::Vulnerability) {
                vuln_nodes.insert(node.id.clone());
            }
        }
        if !vuln_nodes.is_empty() {
            Output::info(&format!(
                "Highlighting {} vulnerability nodes",
                vuln_nodes.len()
            ));
        }
    }

    // SVG output mode
    if let Some(svg_file) = svg_output {
        Output::info("Generating SVG visualization...");

        // Build force-directed layout
        let mut layout = ForceLayout::with_config(LayoutConfig {
            iterations: 300,
            ..LayoutConfig::default()
        });

        // Add nodes and edges to layout
        for node in &nodes {
            layout.add_node(&node.id);
        }
        for edge in &edges {
            layout.add_edge(&edge.source_id, &edge.target_id, 1.0);
        }

        // Run layout
        let _positions = layout.run();

        // Normalize to fit canvas
        let mut layout_mut = layout;
        layout_mut.normalize(1200.0, 800.0, 60.0);
        let positions = layout_mut.positions();

        // Build render nodes
        let render_nodes: Vec<RenderNode> = nodes
            .iter()
            .map(|n| {
                let node_type = match n.node_type {
                    GraphNodeType::Host => "host",
                    GraphNodeType::Service => "service",
                    GraphNodeType::Credential => "credential",
                    GraphNodeType::Vulnerability => "vulnerability",
                    GraphNodeType::Technology => "technology",
                    GraphNodeType::Domain => "domain",
                    GraphNodeType::Endpoint => "endpoint",
                    GraphNodeType::User => "user",
                    GraphNodeType::Certificate => "certificate",
                };

                // Highlight vuln nodes with special style
                let style = if highlight_vulns && vuln_nodes.contains(&n.id) {
                    let mut s = NodeStyle::vulnerability();
                    s.stroke_width = 4.0;
                    s
                } else {
                    match n.node_type {
                        GraphNodeType::Host => NodeStyle::host(),
                        GraphNodeType::Service => NodeStyle::service(),
                        GraphNodeType::Credential => NodeStyle::credential(),
                        GraphNodeType::Vulnerability => NodeStyle::vulnerability(),
                        GraphNodeType::Technology => NodeStyle::technology(),
                        GraphNodeType::Domain => NodeStyle::domain(),
                        _ => NodeStyle::default(),
                    }
                };

                RenderNode {
                    id: n.id.clone(),
                    label: n.label.clone(),
                    node_type: node_type.to_string(),
                    style,
                }
            })
            .collect();

        // Build render edges
        let render_edges: Vec<RenderEdge> = edges
            .iter()
            .map(|e| {
                let edge_type = match e.edge_type {
                    GraphEdgeType::AuthAccess => "auth",
                    GraphEdgeType::AffectedBy => "vuln", // AffectedBy = vulnerability relationship
                    GraphEdgeType::ConnectsTo => "connects",
                    GraphEdgeType::HasService => "has_service",
                    _ => "default",
                };

                // Highlight vuln edges (AffectedBy edges indicate vulnerabilities)
                let style = if highlight_vulns && matches!(e.edge_type, GraphEdgeType::AffectedBy) {
                    let mut s = EdgeStyle::vuln();
                    s.stroke_width = 3.5;
                    s
                } else {
                    match e.edge_type {
                        GraphEdgeType::AuthAccess => EdgeStyle::auth(),
                        GraphEdgeType::AffectedBy => EdgeStyle::vuln(),
                        GraphEdgeType::ConnectsTo => EdgeStyle::connects(),
                        GraphEdgeType::HasService => EdgeStyle::has_service(),
                        _ => EdgeStyle::default(),
                    }
                };

                RenderEdge {
                    from: e.source_id.clone(),
                    to: e.target_id.clone(),
                    label: String::new(),
                    edge_type: edge_type.to_string(),
                    style,
                }
            })
            .collect();

        // Render SVG
        let renderer = SvgRenderer::with_config(SvgConfig {
            width: 1200,
            height: 800,
            show_labels: true,
            show_legend: true,
            ..SvgConfig::default()
        });

        let svg = renderer.render(&positions, &render_nodes, &render_edges, &path_highlights);

        // Write to file
        std::fs::write(svg_file, &svg).map_err(|e| format!("Failed to write SVG: {}", e))?;

        Output::success(&format!("SVG written to: {}", svg_file));
        println!("  Nodes: {}", nodes.len());
        println!("  Edges: {}", edges.len());
        if !path_highlights.is_empty() {
            println!("  Paths highlighted: {}", path_highlights.len());
        }
        if highlight_vulns {
            println!("  Vulnerabilities highlighted: {}", vuln_nodes.len());
        }

        return Ok(());
    }

    // ASCII output mode (default)
    Output::header("Graph Visualization");
    println!();

    // Build adjacency for display
    let mut adjacency: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for edge in &edges {
        adjacency
            .entry(edge.source_id.clone())
            .or_default()
            .push((edge.target_id.clone(), format!("{:?}", edge.edge_type)));
    }

    // Find root nodes (nodes with no incoming edges)
    let mut has_incoming: HashSet<String> = HashSet::new();
    for edge in &edges {
        has_incoming.insert(edge.target_id.clone());
    }

    let roots: Vec<_> = nodes
        .iter()
        .filter(|n| !has_incoming.contains(&n.id))
        .collect();

    // If no roots, pick first node
    let start_nodes: Vec<_> = if roots.is_empty() {
        nodes.iter().take(3).collect()
    } else {
        roots.into_iter().take(5).collect()
    };

    // Collect path node IDs for highlighting in ASCII
    let path_node_ids: HashSet<String> = path_highlights
        .iter()
        .flat_map(|p| p.nodes.iter().cloned())
        .collect();

    // ASCII tree visualization with highlighting
    let mut visited: HashSet<String> = HashSet::new();

    for root in start_nodes {
        print_tree_node_highlighted(
            root,
            &adjacency,
            &mut visited,
            "",
            true,
            0,
            4,
            &path_node_ids,
            &vuln_nodes,
        );
    }

    // Show legend
    println!();
    println!("┌─ Legend ────────────────────────────────────────┐");
    println!("│ ● Node     ─────► Edge (connection)             │");
    if !path_node_ids.is_empty() {
        println!("│ \x1b[33m★ Path\x1b[0m    Nodes in highlighted attack path      │");
    }
    if highlight_vulns {
        println!("│ \x1b[31m◆ Vuln\x1b[0m    Vulnerability nodes                    │");
    }
    println!("└─────────────────────────────────────────────────┘");
    println!();

    // Stats
    let shown = visited.len();
    let total = graph.iter_nodes().count();
    if shown < total {
        println!(
            "Showing {} of {} nodes (use --limit to show more)",
            shown, total
        );
    }

    // SVG hint
    println!();
    Output::info("Use --svg output.svg for graphical SVG output");

    Ok(())
}

/// BFS path finding between two nodes
pub fn find_path_bfs(graph: &GraphStore, from: &str, to: &str) -> Option<Vec<String>> {
    use std::collections::{HashMap, HashSet, VecDeque};

    // Build adjacency from edges
    let edges = graph.iter_all_edges();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
    for edge in edges {
        adjacency
            .entry(edge.source_id.clone())
            .or_default()
            .push(edge.target_id.clone());
    }

    // BFS
    let mut queue = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut parent: HashMap<String, String> = HashMap::new();

    queue.push_back(from.to_string());
    visited.insert(from.to_string());

    while let Some(current) = queue.pop_front() {
        if current == to {
            // Reconstruct path
            let mut path = vec![current.clone()];
            let mut node = &current;
            while let Some(p) = parent.get(node) {
                path.push(p.clone());
                node = p;
            }
            path.reverse();
            return Some(path);
        }

        if let Some(neighbors) = adjacency.get(&current) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    visited.insert(neighbor.clone());
                    parent.insert(neighbor.clone(), current.clone());
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    None
}

/// Get icon for node type
pub fn get_node_type_icon(node_type: &GraphNodeType) -> &'static str {
    match node_type {
        GraphNodeType::Host => "🖥️",
        GraphNodeType::Service => "⚙️",
        GraphNodeType::Vulnerability => "⚠️",
        GraphNodeType::Credential => "🔑",
        GraphNodeType::User => "👤",
        GraphNodeType::Endpoint => "🔗",
        GraphNodeType::Technology => "🛠️",
        GraphNodeType::Domain => "🌐",
        GraphNodeType::Certificate => "📜",
    }
}

/// Print tree node with path/vuln highlighting
pub fn print_tree_node_highlighted(
    node: &crate::storage::engine::StoredNode,
    adjacency: &HashMap<String, Vec<(String, String)>>,
    visited: &mut HashSet<String>,
    prefix: &str,
    is_last: bool,
    depth: usize,
    max_depth: usize,
    path_nodes: &HashSet<String>,
    vuln_nodes: &HashSet<String>,
) {
    if depth > max_depth || visited.contains(&node.id) {
        return;
    }
    visited.insert(node.id.clone());

    let connector = if depth == 0 {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };
    let icon = get_node_type_icon(&node.node_type);

    // Apply highlighting
    let (start_color, end_color) = if path_nodes.contains(&node.id) {
        ("\x1b[33m★ ", "\x1b[0m") // Yellow star for path
    } else if vuln_nodes.contains(&node.id) {
        ("\x1b[31m◆ ", "\x1b[0m") // Red diamond for vuln
    } else {
        ("", "")
    };

    println!(
        "{}{}{}{} {} ({}){}",
        prefix, connector, start_color, icon, node.label, node.id, end_color
    );

    if let Some(children) = adjacency.get(&node.id) {
        let new_prefix = if depth == 0 {
            String::new()
        } else {
            format!("{}{}", prefix, if is_last { "    " } else { "│   " })
        };

        let child_count = children.len();
        for (i, (child_id, edge_type)) in children.iter().enumerate() {
            // Find child node
            // For now, create a minimal node for display
            let child_node = crate::storage::engine::StoredNode {
                id: child_id.clone(),
                label: child_id.clone(),
                node_type: GraphNodeType::Host, // Default, could be improved
                flags: 0,
                out_edge_count: 0,
                in_edge_count: 0,
                page_id: 0,
                slot: 0,
                table_ref: None,
                vector_ref: None,
            };

            let is_last_child = i == child_count - 1;

            // Print edge
            let edge_prefix = format!("{}{}", new_prefix, if is_last_child { "└" } else { "├" });
            let edge_color = if edge_type.contains("Vuln") {
                "\x1b[31m"
            } else {
                ""
            };
            println!(
                "{}{}──[{}]──►{}",
                edge_prefix,
                edge_color,
                edge_type,
                if edge_color.is_empty() { "" } else { "\x1b[0m" }
            );

            print_tree_node_highlighted(
                &child_node,
                adjacency,
                visited,
                &new_prefix,
                is_last_child,
                depth + 1,
                max_depth,
                path_nodes,
                vuln_nodes,
            );
        }
    }
}

/// Print tree node (simple version without highlighting)
pub fn print_tree_node(
    node: &crate::storage::engine::StoredNode,
    adjacency: &HashMap<String, Vec<(String, String)>>,
    visited: &mut HashSet<String>,
    prefix: &str,
    is_last: bool,
    depth: usize,
    max_depth: usize,
) {
    if depth > max_depth || visited.contains(&node.id) {
        return;
    }
    visited.insert(node.id.clone());

    // Node type icon
    let icon = match format!("{:?}", node.node_type).as_str() {
        "Host" => "🖥",
        "Service" => "⚙",
        "Credential" => "🔑",
        "User" => "👤",
        "Vulnerability" => "⚠",
        "Technology" => "🔧",
        "Endpoint" => "🌐",
        "Domain" => "🏠",
        "Certificate" => "📜",
        _ => "●",
    };

    let connector = if is_last { "└── " } else { "├── " };
    let label = truncate_str(&node.label, 30);

    println!("{}{}{} {} ({})", prefix, connector, icon, label, node.id);

    if let Some(children) = adjacency.get(&node.id) {
        let child_prefix = if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        };

        for (i, (_child_id, edge_type)) in children.iter().enumerate() {
            let is_child_last = i == children.len() - 1;

            // Print edge indicator
            let edge_connector = if is_child_last { "└" } else { "├" };
            println!(
                "{}{}──[{}]──►",
                child_prefix,
                edge_connector,
                truncate_str(edge_type, 15)
            );
        }
    }
}
