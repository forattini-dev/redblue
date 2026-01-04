//! SVG Graph Renderer
//!
//! Renders graphs as SVG with support for:
//! - Node styling by type
//! - Edge styling by type
//! - Path highlighting for attack paths
//! - Labels and tooltips

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use super::{LayoutEdge, Position};

/// Color in hex format (e.g., "#FF5733")
pub type Color = String;

/// Node visual style
#[derive(Debug, Clone)]
pub struct NodeStyle {
    /// Fill color
    pub fill: Color,
    /// Stroke color
    pub stroke: Color,
    /// Stroke width
    pub stroke_width: f64,
    /// Node radius
    pub radius: f64,
    /// Label color
    pub label_color: Color,
    /// Font size
    pub font_size: f64,
}

impl Default for NodeStyle {
    fn default() -> Self {
        Self {
            fill: "#4a90d9".to_string(),
            stroke: "#2c5282".to_string(),
            stroke_width: 2.0,
            radius: 20.0,
            label_color: "#1a1a1a".to_string(),
            font_size: 12.0,
        }
    }
}

impl NodeStyle {
    /// Style for host nodes
    pub fn host() -> Self {
        Self {
            fill: "#48bb78".to_string(),
            stroke: "#276749".to_string(),
            radius: 25.0,
            ..Default::default()
        }
    }

    /// Style for service nodes
    pub fn service() -> Self {
        Self {
            fill: "#4299e1".to_string(),
            stroke: "#2b6cb0".to_string(),
            radius: 18.0,
            ..Default::default()
        }
    }

    /// Style for credential nodes
    pub fn credential() -> Self {
        Self {
            fill: "#ed8936".to_string(),
            stroke: "#c05621".to_string(),
            radius: 20.0,
            ..Default::default()
        }
    }

    /// Style for vulnerability nodes
    pub fn vulnerability() -> Self {
        Self {
            fill: "#fc8181".to_string(),
            stroke: "#c53030".to_string(),
            radius: 22.0,
            ..Default::default()
        }
    }

    /// Style for technology nodes
    pub fn technology() -> Self {
        Self {
            fill: "#9f7aea".to_string(),
            stroke: "#6b46c1".to_string(),
            radius: 16.0,
            ..Default::default()
        }
    }

    /// Style for domain nodes
    pub fn domain() -> Self {
        Self {
            fill: "#667eea".to_string(),
            stroke: "#4c51bf".to_string(),
            radius: 22.0,
            ..Default::default()
        }
    }
}

/// Edge visual style
#[derive(Debug, Clone)]
pub struct EdgeStyle {
    /// Line color
    pub stroke: Color,
    /// Line width
    pub stroke_width: f64,
    /// Dash pattern (empty for solid)
    pub dash_array: String,
    /// Arrow head size
    pub arrow_size: f64,
    /// Show arrow
    pub show_arrow: bool,
}

impl Default for EdgeStyle {
    fn default() -> Self {
        Self {
            stroke: "#718096".to_string(),
            stroke_width: 1.5,
            dash_array: String::new(),
            arrow_size: 8.0,
            show_arrow: true,
        }
    }
}

impl EdgeStyle {
    /// Style for authentication edges
    pub fn auth() -> Self {
        Self {
            stroke: "#48bb78".to_string(),
            stroke_width: 2.0,
            ..Default::default()
        }
    }

    /// Style for vulnerability edges
    pub fn vuln() -> Self {
        Self {
            stroke: "#fc8181".to_string(),
            stroke_width: 2.5,
            ..Default::default()
        }
    }

    /// Style for connection edges
    pub fn connects() -> Self {
        Self {
            stroke: "#4299e1".to_string(),
            stroke_width: 1.5,
            dash_array: "5,5".to_string(),
            ..Default::default()
        }
    }

    /// Style for service edges
    pub fn has_service() -> Self {
        Self {
            stroke: "#9f7aea".to_string(),
            stroke_width: 1.5,
            ..Default::default()
        }
    }

    /// Style for highlighted path
    pub fn highlight() -> Self {
        Self {
            stroke: "#f6e05e".to_string(),
            stroke_width: 4.0,
            ..Default::default()
        }
    }
}

/// Path to highlight in the visualization
#[derive(Debug, Clone)]
pub struct PathHighlight {
    /// Ordered list of node IDs in the path
    pub nodes: Vec<String>,
    /// Color for the path
    pub color: Color,
    /// Path label
    pub label: String,
}

impl PathHighlight {
    pub fn new(nodes: Vec<String>, color: &str, label: &str) -> Self {
        Self {
            nodes,
            color: color.to_string(),
            label: label.to_string(),
        }
    }

    /// Attack path (red)
    pub fn attack_path(nodes: Vec<String>) -> Self {
        Self {
            nodes,
            color: "#e53e3e".to_string(),
            label: "Attack Path".to_string(),
        }
    }

    /// Credential path (orange)
    pub fn credential_path(nodes: Vec<String>) -> Self {
        Self {
            nodes,
            color: "#ed8936".to_string(),
            label: "Credential Chain".to_string(),
        }
    }

    /// Pivot path (purple)
    pub fn pivot_path(nodes: Vec<String>) -> Self {
        Self {
            nodes,
            color: "#9f7aea".to_string(),
            label: "Pivot Path".to_string(),
        }
    }
}

/// SVG renderer configuration
#[derive(Debug, Clone)]
pub struct SvgConfig {
    /// Canvas width
    pub width: u32,
    /// Canvas height
    pub height: u32,
    /// Background color (None for transparent)
    pub background: Option<Color>,
    /// Padding from edges
    pub padding: f64,
    /// Show node labels
    pub show_labels: bool,
    /// Show edge labels
    pub show_edge_labels: bool,
    /// Show legend
    pub show_legend: bool,
    /// Font family
    pub font_family: String,
}

impl Default for SvgConfig {
    fn default() -> Self {
        Self {
            width: 1200,
            height: 800,
            background: Some("#ffffff".to_string()),
            padding: 50.0,
            show_labels: true,
            show_edge_labels: false,
            show_legend: true,
            font_family: "Arial, sans-serif".to_string(),
        }
    }
}

/// Graph node for rendering
#[derive(Debug, Clone)]
pub struct RenderNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub style: NodeStyle,
}

/// Graph edge for rendering
#[derive(Debug, Clone)]
pub struct RenderEdge {
    pub from: String,
    pub to: String,
    pub label: String,
    pub edge_type: String,
    pub style: EdgeStyle,
}

/// SVG graph renderer
pub struct SvgRenderer {
    config: SvgConfig,
    node_styles: HashMap<String, NodeStyle>,
    edge_styles: HashMap<String, EdgeStyle>,
}

impl SvgRenderer {
    /// Create a new SVG renderer with given dimensions
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            config: SvgConfig {
                width,
                height,
                ..Default::default()
            },
            node_styles: HashMap::new(),
            edge_styles: HashMap::new(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: SvgConfig) -> Self {
        Self {
            config,
            node_styles: HashMap::new(),
            edge_styles: HashMap::new(),
        }
    }

    /// Set style for a node type
    pub fn set_node_style(&mut self, node_type: &str, style: NodeStyle) {
        self.node_styles.insert(node_type.to_string(), style);
    }

    /// Set style for an edge type
    pub fn set_edge_style(&mut self, edge_type: &str, style: EdgeStyle) {
        self.edge_styles.insert(edge_type.to_string(), style);
    }

    /// Get node style for type
    fn get_node_style(&self, node_type: &str) -> NodeStyle {
        if let Some(style) = self.node_styles.get(node_type) {
            return style.clone();
        }

        // Default styles based on common types
        match node_type.to_lowercase().as_str() {
            "host" => NodeStyle::host(),
            "service" => NodeStyle::service(),
            "credential" => NodeStyle::credential(),
            "vulnerability" | "vuln" => NodeStyle::vulnerability(),
            "technology" | "tech" => NodeStyle::technology(),
            "domain" => NodeStyle::domain(),
            _ => NodeStyle::default(),
        }
    }

    /// Get edge style for type
    fn get_edge_style(&self, edge_type: &str) -> EdgeStyle {
        if let Some(style) = self.edge_styles.get(edge_type) {
            return style.clone();
        }

        match edge_type.to_lowercase().as_str() {
            "auth" | "auth_access" | "authenticated" => EdgeStyle::auth(),
            "vuln" | "has_vuln" | "vulnerability" => EdgeStyle::vuln(),
            "connects" | "connects_to" => EdgeStyle::connects(),
            "has_service" | "service" => EdgeStyle::has_service(),
            _ => EdgeStyle::default(),
        }
    }

    /// Render a graph to SVG
    pub fn render(
        &self,
        positions: &HashMap<String, Position>,
        nodes: &[RenderNode],
        edges: &[RenderEdge],
        highlights: &[PathHighlight],
    ) -> String {
        let mut svg = String::with_capacity(8192);

        // SVG header
        writeln!(
            svg,
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">"#,
            self.config.width, self.config.height, self.config.width, self.config.height
        )
        .unwrap();

        // Style definitions
        writeln!(svg, "<defs>").unwrap();
        self.write_arrow_markers(&mut svg);
        writeln!(svg, "</defs>").unwrap();

        // Background
        if let Some(bg) = &self.config.background {
            writeln!(svg, r#"<rect width="100%" height="100%" fill="{}"/>"#, bg).unwrap();
        }

        // Build set of highlighted edges for path highlighting
        let highlighted_edges = self.build_highlighted_edges(highlights);

        // Render edges first (behind nodes)
        writeln!(svg, r#"<g class="edges">"#).unwrap();
        for edge in edges {
            self.render_edge(&mut svg, edge, positions, &highlighted_edges);
        }
        writeln!(svg, "</g>").unwrap();

        // Render path highlights
        if !highlights.is_empty() {
            writeln!(svg, r#"<g class="highlights">"#).unwrap();
            for highlight in highlights {
                self.render_highlight(&mut svg, highlight, positions);
            }
            writeln!(svg, "</g>").unwrap();
        }

        // Render nodes
        writeln!(svg, r#"<g class="nodes">"#).unwrap();
        for node in nodes {
            self.render_node(&mut svg, node, positions);
        }
        writeln!(svg, "</g>").unwrap();

        // Legend
        if self.config.show_legend {
            self.render_legend(&mut svg, nodes, highlights);
        }

        writeln!(svg, "</svg>").unwrap();
        svg
    }

    /// Render a simple graph with just positions and edges (infers styles)
    pub fn render_simple(
        &self,
        positions: &HashMap<String, Position>,
        edges: &[LayoutEdge],
    ) -> String {
        let nodes: Vec<RenderNode> = positions
            .keys()
            .map(|id| RenderNode {
                id: id.clone(),
                label: id.clone(),
                node_type: "default".to_string(),
                style: NodeStyle::default(),
            })
            .collect();

        let render_edges: Vec<RenderEdge> = edges
            .iter()
            .map(|e| RenderEdge {
                from: e.from.clone(),
                to: e.to.clone(),
                label: String::new(),
                edge_type: "default".to_string(),
                style: EdgeStyle::default(),
            })
            .collect();

        self.render(positions, &nodes, &render_edges, &[])
    }

    fn write_arrow_markers(&self, svg: &mut String) {
        // Default arrow marker
        svg.push_str(r##"<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">"##);
        svg.push('\n');
        svg.push_str(r##"<path d="M 0 0 L 10 5 L 0 10 z" fill="#718096"/>"##);
        svg.push('\n');
        svg.push_str("</marker>\n");

        // Attack path arrow (red)
        svg.push_str(r##"<marker id="arrow-attack" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">"##);
        svg.push('\n');
        svg.push_str(r##"<path d="M 0 0 L 10 5 L 0 10 z" fill="#e53e3e"/>"##);
        svg.push('\n');
        svg.push_str("</marker>\n");

        // Credential path arrow (orange)
        svg.push_str(r##"<marker id="arrow-credential" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">"##);
        svg.push('\n');
        svg.push_str(r##"<path d="M 0 0 L 10 5 L 0 10 z" fill="#ed8936"/>"##);
        svg.push('\n');
        svg.push_str("</marker>\n");

        // Vuln arrow (red)
        svg.push_str(r##"<marker id="arrow-vuln" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">"##);
        svg.push('\n');
        svg.push_str(r##"<path d="M 0 0 L 10 5 L 0 10 z" fill="#fc8181"/>"##);
        svg.push('\n');
        svg.push_str("</marker>\n");

        // Auth arrow (green)
        svg.push_str(r##"<marker id="arrow-auth" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">"##);
        svg.push('\n');
        svg.push_str(r##"<path d="M 0 0 L 10 5 L 0 10 z" fill="#48bb78"/>"##);
        svg.push('\n');
        svg.push_str("</marker>\n");
    }

    fn build_highlighted_edges(&self, highlights: &[PathHighlight]) -> HashSet<(String, String)> {
        let mut set = HashSet::new();
        for highlight in highlights {
            for window in highlight.nodes.windows(2) {
                set.insert((window[0].clone(), window[1].clone()));
            }
        }
        set
    }

    fn render_node(
        &self,
        svg: &mut String,
        node: &RenderNode,
        positions: &HashMap<String, Position>,
    ) {
        let Some(pos) = positions.get(&node.id) else {
            return;
        };

        let style = self.get_node_style(&node.node_type);

        // Node circle
        writeln!(
            svg,
            r#"<circle cx="{:.2}" cy="{:.2}" r="{}" fill="{}" stroke="{}" stroke-width="{}"/>"#,
            pos.x, pos.y, style.radius, style.fill, style.stroke, style.stroke_width
        )
        .unwrap();

        // Label
        if self.config.show_labels {
            let label = self.truncate_label(&node.label, 15);
            writeln!(
                svg,
                r#"<text x="{:.2}" y="{:.2}" text-anchor="middle" font-family="{}" font-size="{}" fill="{}">{}</text>"#,
                pos.x,
                pos.y + style.radius + style.font_size + 2.0,
                self.config.font_family,
                style.font_size,
                style.label_color,
                self.escape_xml(&label)
            )
            .unwrap();
        }
    }

    fn render_edge(
        &self,
        svg: &mut String,
        edge: &RenderEdge,
        positions: &HashMap<String, Position>,
        highlighted: &HashSet<(String, String)>,
    ) {
        let Some(from_pos) = positions.get(&edge.from) else {
            return;
        };
        let Some(to_pos) = positions.get(&edge.to) else {
            return;
        };

        // Skip if this edge is highlighted (will be drawn separately)
        if highlighted.contains(&(edge.from.clone(), edge.to.clone())) {
            return;
        }

        let style = self.get_edge_style(&edge.edge_type);

        // Calculate line endpoints (adjust for node radius)
        let from_style = self.get_node_style("default");
        let to_style = self.get_node_style("default");

        let (x1, y1, x2, y2) =
            self.calculate_edge_endpoints(from_pos, to_pos, from_style.radius, to_style.radius);

        // Edge line
        let marker = if style.show_arrow {
            match edge.edge_type.to_lowercase().as_str() {
                "vuln" | "has_vuln" => r#" marker-end="url(#arrow-vuln)""#,
                "auth" | "auth_access" => r#" marker-end="url(#arrow-auth)""#,
                _ => r#" marker-end="url(#arrow)""#,
            }
        } else {
            ""
        };

        let dash = if style.dash_array.is_empty() {
            String::new()
        } else {
            format!(r#" stroke-dasharray="{}""#, style.dash_array)
        };

        writeln!(
            svg,
            r#"<line x1="{:.2}" y1="{:.2}" x2="{:.2}" y2="{:.2}" stroke="{}" stroke-width="{}"{}{}/>"#,
            x1, y1, x2, y2, style.stroke, style.stroke_width, dash, marker
        )
        .unwrap();

        // Edge label
        if self.config.show_edge_labels && !edge.label.is_empty() {
            let mid_x = (x1 + x2) / 2.0;
            let mid_y = (y1 + y2) / 2.0;
            let edge_label_color = "#718096";
            writeln!(
                svg,
                r#"<text x="{:.2}" y="{:.2}" text-anchor="middle" font-family="{}" font-size="10" fill="{}">{}</text>"#,
                mid_x, mid_y - 5.0, self.config.font_family, edge_label_color, self.escape_xml(&edge.label)
            )
            .unwrap();
        }
    }

    fn render_highlight(
        &self,
        svg: &mut String,
        highlight: &PathHighlight,
        positions: &HashMap<String, Position>,
    ) {
        if highlight.nodes.len() < 2 {
            return;
        }

        // Draw path edges with thick highlighted style
        for window in highlight.nodes.windows(2) {
            let Some(from_pos) = positions.get(&window[0]) else {
                continue;
            };
            let Some(to_pos) = positions.get(&window[1]) else {
                continue;
            };

            let from_style = self.get_node_style("default");
            let to_style = self.get_node_style("default");

            let (x1, y1, x2, y2) =
                self.calculate_edge_endpoints(from_pos, to_pos, from_style.radius, to_style.radius);

            // Draw glow effect (larger, semi-transparent)
            writeln!(
                svg,
                r#"<line x1="{:.2}" y1="{:.2}" x2="{:.2}" y2="{:.2}" stroke="{}" stroke-width="8" opacity="0.3"/>"#,
                x1, y1, x2, y2, highlight.color
            )
            .unwrap();

            // Draw main line
            writeln!(
                svg,
                r#"<line x1="{:.2}" y1="{:.2}" x2="{:.2}" y2="{:.2}" stroke="{}" stroke-width="3" marker-end="url(#arrow-attack)"/>"#,
                x1, y1, x2, y2, highlight.color
            )
            .unwrap();
        }

        // Highlight path nodes with rings
        for node_id in &highlight.nodes {
            if let Some(pos) = positions.get(node_id) {
                let style = self.get_node_style("default");
                writeln!(
                    svg,
                    r#"<circle cx="{:.2}" cy="{:.2}" r="{}" fill="none" stroke="{}" stroke-width="3"/>"#,
                    pos.x, pos.y, style.radius + 4.0, highlight.color
                )
                .unwrap();
            }
        }
    }

    fn render_legend(&self, svg: &mut String, nodes: &[RenderNode], highlights: &[PathHighlight]) {
        let mut y = 30.0;
        let x = self.config.width as f64 - 150.0;

        writeln!(svg, r#"<g class="legend">"#).unwrap();

        // Background
        writeln!(
            svg,
            r#"<rect x="{}" y="10" width="140" height="{}" fill="white" opacity="0.9" rx="5"/>"#,
            x - 10.0,
            30.0 + (self.count_unique_types(nodes) + highlights.len()) as f64 * 25.0
        )
        .unwrap();

        // Node type legend
        let mut seen_types = HashSet::new();
        for node in nodes {
            if seen_types.insert(node.node_type.clone()) {
                let style = self.get_node_style(&node.node_type);
                writeln!(
                    svg,
                    r#"<circle cx="{}" cy="{}" r="8" fill="{}" stroke="{}" stroke-width="1"/>"#,
                    x, y, style.fill, style.stroke
                )
                .unwrap();
                let legend_text_color = "#1a1a1a";
                writeln!(
                    svg,
                    r#"<text x="{}" y="{}" font-family="{}" font-size="11" fill="{}">{}</text>"#,
                    x + 15.0,
                    y + 4.0,
                    self.config.font_family,
                    legend_text_color,
                    self.capitalize(&node.node_type)
                )
                .unwrap();
                y += 25.0;
            }
        }

        // Path highlight legend
        let legend_text_color = "#1a1a1a";
        for highlight in highlights {
            writeln!(
                svg,
                r#"<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="3"/>"#,
                x - 8.0,
                y,
                x + 8.0,
                y,
                highlight.color
            )
            .unwrap();
            writeln!(
                svg,
                r#"<text x="{}" y="{}" font-family="{}" font-size="11" fill="{}">{}</text>"#,
                x + 15.0,
                y + 4.0,
                self.config.font_family,
                legend_text_color,
                highlight.label
            )
            .unwrap();
            y += 25.0;
        }

        writeln!(svg, "</g>").unwrap();
    }

    fn calculate_edge_endpoints(
        &self,
        from: &Position,
        to: &Position,
        from_radius: f64,
        to_radius: f64,
    ) -> (f64, f64, f64, f64) {
        let dx = to.x - from.x;
        let dy = to.y - from.y;
        let d = (dx * dx + dy * dy).sqrt();

        if d < 1e-10 {
            return (from.x, from.y, to.x, to.y);
        }

        let ux = dx / d;
        let uy = dy / d;

        let x1 = from.x + ux * from_radius;
        let y1 = from.y + uy * from_radius;
        let x2 = to.x - ux * (to_radius + 10.0); // Extra space for arrow
        let y2 = to.y - uy * (to_radius + 10.0);

        (x1, y1, x2, y2)
    }

    fn truncate_label(&self, label: &str, max_len: usize) -> String {
        if label.len() <= max_len {
            label.to_string()
        } else {
            format!("{}...", &label[..max_len - 3])
        }
    }

    fn escape_xml(&self, s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    fn capitalize(&self, s: &str) -> String {
        let mut c = s.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        }
    }

    fn count_unique_types(&self, nodes: &[RenderNode]) -> usize {
        let mut types = HashSet::new();
        for node in nodes {
            types.insert(&node.node_type);
        }
        types.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_style_defaults() {
        let style = NodeStyle::default();
        assert_eq!(style.radius, 20.0);
        assert!(!style.fill.is_empty());
    }

    #[test]
    fn test_node_style_host() {
        let style = NodeStyle::host();
        assert!(style.fill.contains("48bb78")); // Green
        assert_eq!(style.radius, 25.0);
    }

    #[test]
    fn test_edge_style_vuln() {
        let style = EdgeStyle::vuln();
        assert!(style.stroke.contains("fc8181")); // Red
        assert_eq!(style.stroke_width, 2.5);
    }

    #[test]
    fn test_path_highlight() {
        let path =
            PathHighlight::attack_path(vec!["A".to_string(), "B".to_string(), "C".to_string()]);
        assert_eq!(path.nodes.len(), 3);
        assert!(path.color.contains("e53e3e")); // Red
    }

    #[test]
    fn test_render_simple() {
        let renderer = SvgRenderer::new(800, 600);

        let mut positions = HashMap::new();
        positions.insert("A".to_string(), Position::new(100.0, 100.0));
        positions.insert("B".to_string(), Position::new(200.0, 200.0));

        let edges = vec![LayoutEdge {
            from: "A".to_string(),
            to: "B".to_string(),
            weight: 1.0,
        }];

        let svg = renderer.render_simple(&positions, &edges);

        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("circle"));
        assert!(svg.contains("line"));
    }

    #[test]
    fn test_render_with_nodes() {
        let renderer = SvgRenderer::new(800, 600);

        let mut positions = HashMap::new();
        positions.insert("host1".to_string(), Position::new(100.0, 100.0));
        positions.insert("vuln1".to_string(), Position::new(200.0, 200.0));

        let nodes = vec![
            RenderNode {
                id: "host1".to_string(),
                label: "192.168.1.1".to_string(),
                node_type: "host".to_string(),
                style: NodeStyle::host(),
            },
            RenderNode {
                id: "vuln1".to_string(),
                label: "CVE-2021-44228".to_string(),
                node_type: "vulnerability".to_string(),
                style: NodeStyle::vulnerability(),
            },
        ];

        let edges = vec![RenderEdge {
            from: "host1".to_string(),
            to: "vuln1".to_string(),
            label: "has_vuln".to_string(),
            edge_type: "vuln".to_string(),
            style: EdgeStyle::vuln(),
        }];

        let svg = renderer.render(&positions, &nodes, &edges, &[]);

        assert!(svg.contains("192.168.1.1"));
        assert!(svg.contains("CVE-2021-44228"));
    }

    #[test]
    fn test_render_with_highlight() {
        let renderer = SvgRenderer::new(800, 600);

        let mut positions = HashMap::new();
        positions.insert("A".to_string(), Position::new(100.0, 100.0));
        positions.insert("B".to_string(), Position::new(200.0, 150.0));
        positions.insert("C".to_string(), Position::new(300.0, 200.0));

        let nodes: Vec<RenderNode> = ["A", "B", "C"]
            .iter()
            .map(|&id| RenderNode {
                id: id.to_string(),
                label: id.to_string(),
                node_type: "host".to_string(),
                style: NodeStyle::host(),
            })
            .collect();

        let edges = vec![
            RenderEdge {
                from: "A".to_string(),
                to: "B".to_string(),
                label: String::new(),
                edge_type: "connects".to_string(),
                style: EdgeStyle::default(),
            },
            RenderEdge {
                from: "B".to_string(),
                to: "C".to_string(),
                label: String::new(),
                edge_type: "connects".to_string(),
                style: EdgeStyle::default(),
            },
        ];

        let highlights = vec![PathHighlight::attack_path(vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
        ])];

        let svg = renderer.render(&positions, &nodes, &edges, &highlights);

        assert!(svg.contains("highlights"));
        assert!(svg.contains("Attack Path"));
    }

    #[test]
    fn test_escape_xml() {
        let renderer = SvgRenderer::new(100, 100);
        let escaped = renderer.escape_xml("<script>alert('xss')</script>");
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
    }
}
