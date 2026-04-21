use std::collections::HashMap;

use super::super::manager::ManagerStats;

/// Statistics for UnifiedStore
#[derive(Debug, Clone, Default)]
pub struct StoreStats {
  /// Number of collections
  pub collection_count: usize,
  /// Total entities across all collections
  pub total_entities: usize,
  /// Total memory usage in bytes
  pub total_memory_bytes: usize,
  /// Per-collection statistics
  pub collections: HashMap<String, ManagerStats>,
  /// Total cross-references
  pub cross_ref_count: usize,
}

impl StoreStats {
  /// Get average entities per collection
  pub fn avg_entities_per_collection(&self) -> f64 {
    if self.collection_count == 0 {
      0.0
    } else {
      self.total_entities as f64 / self.collection_count as f64
    }
  }

  /// Get memory in MB
  pub fn memory_mb(&self) -> f64 {
    self.total_memory_bytes as f64 / (1024.0 * 1024.0)
  }
}
