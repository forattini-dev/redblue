use super::super::manager::ManagerConfig;

/// Configuration for UnifiedStore
#[derive(Debug, Clone)]
pub struct UnifiedStoreConfig {
  /// Configuration for segment managers
  pub manager_config: ManagerConfig,
  /// Automatically index cross-references on insert
  pub auto_index_refs: bool,
  /// Maximum cross-references per entity
  pub max_cross_refs: usize,
  /// Enable write-ahead logging
  pub enable_wal: bool,
  /// Data directory path
  pub data_dir: Option<std::path::PathBuf>,
}

impl Default for UnifiedStoreConfig {
  fn default() -> Self {
    Self {
      manager_config: ManagerConfig::default(),
      auto_index_refs: true,
      max_cross_refs: 1000,
      enable_wal: false,
      data_dir: None,
    }
  }
}

impl UnifiedStoreConfig {
  /// Create config with data directory
  pub fn with_data_dir(mut self, path: impl Into<std::path::PathBuf>) -> Self {
    self.data_dir = Some(path.into());
    self
  }

  /// Enable WAL
  pub fn with_wal(mut self) -> Self {
    self.enable_wal = true;
    self
  }

  /// Set max cross-references
  pub fn with_max_refs(mut self, max: usize) -> Self {
    self.max_cross_refs = max;
    self
  }
}
