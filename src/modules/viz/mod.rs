//! Graph Visualization Module
//!
//! Provides force-directed layout and multiple output renderers for graph visualization.
//!
//! # Features
//! - Force-directed layout with physics simulation
//! - Barnes-Hut optimization for large graphs
//! - SVG output with node/edge styling
//! - Path highlighting with color coding
//!
//! # Example
//! ```ignore
//! use redblue::modules::viz::{ForceLayout, LayoutConfig, SvgRenderer};
//!
//! let mut layout = ForceLayout::with_config(LayoutConfig::default());
//! layout.add_edge("host_a", "host_b", 1.0);
//! layout.add_edge("host_b", "vuln_1", 0.5);
//! let positions = layout.run();
//!
//! let svg = SvgRenderer::new(800, 600)
//!     .render_graph(&positions, &edges);
//! ```

mod layout;
mod svg;

pub use layout::{ForceLayout, LayoutConfig, LayoutEdge, Position};
pub use svg::{
    EdgeStyle, NodeStyle, PathHighlight, RenderEdge, RenderNode, SvgConfig, SvgRenderer,
};
