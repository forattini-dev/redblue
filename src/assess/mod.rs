//! Assessment Workflow Module
//!
//! Provides a continuous assessment workflow that integrates:
//! 1. Technology discovery (fingerprinting)
//! 2. Vulnerability correlation (with smart caching)
//! 3. Playbook recommendation (scoring)
//! 4. Interactive execution (with confirmation)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use redblue::assess::{AssessmentEngine, AssessOptions};
//!
//! let mut engine = AssessmentEngine::new("example.com")?;
//! let result = engine.run(AssessOptions::default())?;
//!
//! println!("Technologies: {:?}", result.technologies);
//! println!("Risk Score: {}/100", result.risk_score);
//! println!("Top Playbook: {:?}", result.recommendations.first());
//! ```

pub mod cache;
pub mod engine;
pub mod output;

pub use cache::{CacheManager, CacheStatus};
pub use engine::{AssessOptions, AssessmentEngine, AssessmentResult};
pub use output::AssessmentOutput;
