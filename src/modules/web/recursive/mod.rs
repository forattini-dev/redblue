//! Recursive Content Discovery Module
//!
//! Provides comprehensive recursive web content discovery capabilities:
//! - Link extraction from HTML, JavaScript, and forms
//! - Priority-based URL queue with depth tracking
//! - Scope enforcement and deduplication
//! - Recursive scanning coordination

pub mod extractor;
pub mod queue;
pub mod scanner;

// Re-export key types
pub use extractor::{
  ExtractedLink, ExtractorConfig, LinkExtractor, LinkExtractorBuilder, LinkSource,
};
pub use queue::{
  DiscoverySource, QueueConfig, QueueStats, QueuedUrl, RecursionQueue, RecursionQueueBuilder,
};
pub use scanner::{
  DiscoveredResource, RecursiveScanConfig, RecursiveScanStats, RecursiveScanner,
  RecursiveScannerBuilder, ScanResult, ScannerState,
};
