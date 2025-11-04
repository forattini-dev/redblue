use crate::storage::client::{PersistenceManager, QueryManager};
use crate::storage::layout::SegmentKind;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Once, RwLock};

/// Identifies a logical partition in the storage engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PartitionKey {
    Domain(String),
    Target(String),
    Date(u32),
    Custom(String),
}

/// Metadata describing a partition's layout on disk.
#[derive(Debug, Clone)]
pub struct PartitionMetadata {
    pub key: PartitionKey,
    pub label: String,
    pub storage_path: PathBuf,
    pub segments: Vec<SegmentKind>,
}

impl PartitionMetadata {
    pub fn new<K: Into<PartitionKey>, L: Into<String>, P: Into<PathBuf>>(
        key: K,
        label: L,
        storage_path: P,
        segments: Vec<SegmentKind>,
    ) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            storage_path: storage_path.into(),
            segments,
        }
    }
}

#[derive(Default)]
struct PartitionRegistry {
    entries: Vec<PartitionMetadata>,
    index: HashMap<PartitionKey, usize>,
}

impl PartitionRegistry {
    fn new() -> Self {
        Self::default()
    }

    fn upsert(&mut self, meta: PartitionMetadata) {
        if let Some(&idx) = self.index.get(&meta.key) {
            self.entries[idx] = meta;
        } else {
            let idx = self.entries.len();
            self.index.insert(meta.key.clone(), idx);
            self.entries.push(meta);
        }
    }

    fn snapshot(&self) -> Vec<PartitionMetadata> {
        self.entries.clone()
    }

    fn get(&self, key: &PartitionKey) -> Option<PartitionMetadata> {
        self.index
            .get(key)
            .and_then(|&idx| self.entries.get(idx))
            .cloned()
    }
}

/// Central façade that coordinates persistence/query managers and partition metadata.
pub struct StorageService {
    partitions: RwLock<PartitionRegistry>,
}

impl StorageService {
    fn new() -> Self {
        Self {
            partitions: RwLock::new(PartitionRegistry::new()),
        }
    }

    /// Access the global storage service instance.
    pub fn global() -> &'static StorageService {
        static INIT: Once = Once::new();
        static mut INSTANCE: Option<StorageService> = None;

        unsafe {
            INIT.call_once(|| {
                INSTANCE = Some(StorageService::new());
            });
            INSTANCE
                .as_ref()
                .expect("storage service should be initialised")
        }
    }

    /// Register or update a partition. Future persistence operations can use this metadata
    /// to route writes/reads without crawling the directory structure.
    pub fn register_partition(&self, metadata: PartitionMetadata) {
        let mut guard = self.partitions.write().expect("partition lock poisoned");
        guard.upsert(metadata);
    }

    /// Return a cloned snapshot of all known partitions.
    pub fn partitions(&self) -> Vec<PartitionMetadata> {
        let guard = self.partitions.read().expect("partition lock poisoned");
        guard.snapshot()
    }

    /// Look up a partition by key.
    pub fn partition(&self, key: &PartitionKey) -> Option<PartitionMetadata> {
        let guard = self.partitions.read().expect("partition lock poisoned");
        guard.get(key)
    }

    /// Create a persistence manager for a given target.
    pub fn persistence_for_target(
        &self,
        target: &str,
        persist: Option<bool>,
    ) -> Result<PersistenceManager, String> {
        PersistenceManager::new(target, persist)
    }

    /// Open a query manager for the provided .rdb path.
    pub fn open_query_manager<P: Into<PathBuf>>(&self, path: P) -> std::io::Result<QueryManager> {
        QueryManager::open(path.into())
    }
}
