//! MITRE ATT&CK Intelligence Module
//!
//! Query MITRE ATT&CK framework data including techniques, tactics, threat groups,
//! software, and mitigations.
//!
//! ## Data Source
//!
//! Data is fetched from MITRE's official GitHub repository:
//! `https://github.com/mitre-attack/attack-stix-data`
//!
//! ## Features
//!
//! - **Navigator Layer Export**: Generate ATT&CK Navigator layers (v4.5)
//! - **Finding Correlation**: Map security findings to MITRE techniques
//! - **Coverage Analysis**: Analyze detection coverage and gaps
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use redblue::modules::recon::mitre::{MitreClient, NavigatorLayer, LayerBuilder};
//!
//! let mut client = MitreClient::new();
//!
//! // Get a specific technique
//! if let Ok(Some(tech)) = client.get_technique("T1059") {
//!     println!("{}: {}", tech.id, tech.name);
//! }
//!
//! // Search across all objects
//! let results = client.search("powershell")?;
//!
//! // Create a Navigator layer
//! let layer = LayerBuilder::new("My Assessment")
//!     .description("Techniques observed during assessment")
//!     .score("T1059", 80)
//!     .score_with_comment("T1055", 60, "Process injection detected")
//!     .build();
//!
//! // Export to JSON for Navigator
//! let json = layer.to_json();
//! ```

pub mod client;
pub mod correlation;
pub mod coverage;
pub mod navigator;
pub mod types;

pub use client::MitreClient;
pub use correlation::{CorrelationEngine, CorrelationResult, FindingMatch};
pub use coverage::{CoverageAnalyzer, CoverageReport, GapPriority, TacticCoverage};
pub use navigator::{
    layer_from_group, layer_from_groups, layer_from_tactic, layer_from_techniques, LayerBuilder,
    NavigatorLayer, TechniqueAnnotation,
};
pub use types::*;
