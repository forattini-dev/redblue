//! Terminal UI components for real-time visualization
//!
//! Zero external dependencies - all graphics implemented from scratch using:
//! - Braille Unicode patterns (U+2800-U+28FF) for high-resolution plotting
//! - ANSI escape sequences for colors and cursor control
//! - Pure Rust std math for line drawing algorithms
//!
//! # Features
//! - Real-time animated graphs
//! - Multiple chart types (line, bar, scatter)
//! - ASCII tree rendering for hierarchical data
//! - TrueColor support (16 million colors)
//! - High resolution: 2×4 pixels per character via Braille patterns
//!
//! # Use Cases
//! - `rb bench load test` - Real-time load testing dashboard
//! - `rb tls intel scan` - TLS timing breakdown charts
//! - `rb recon domain graph` - Domain/subdomain tree visualization
//! - `rb shell` - Progress indicators and sparklines

pub mod canvas;
pub mod colors;
pub mod graphs;
pub mod scale;
pub mod tree;

pub use canvas::BrailleCanvas;
pub use colors::{rgb, Color, ANSI_RESET};
pub use graphs::{Chart, ColorPlot, Plot, Shape};
pub use scale::Scale;
pub use tree::{NodeType, ReconTreeBuilder, TreeNode, TreeRenderer};
