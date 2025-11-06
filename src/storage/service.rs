use crate::storage::client::{PersistenceManager, QueryManager};
use crate::storage::encoding::DecodeError;
use crate::storage::layout::{FileHeader, SectionEntry, SegmentKind};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Once, RwLock};
use std::time::SystemTime;

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
    pub attributes: BTreeMap<String, String>,
    pub last_refreshed: Option<SystemTime>,
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
            attributes: BTreeMap::new(),
            last_refreshed: None,
        }
    }

    pub fn with_attribute<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn with_attributes<I, K, V>(mut self, attrs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (key, value) in attrs.into_iter() {
            self.attributes.insert(key.into(), value.into());
        }
        self
    }

    pub fn with_last_refreshed(mut self, timestamp: SystemTime) -> Self {
        self.last_refreshed = Some(timestamp);
        self
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

    fn upsert(&mut self, mut meta: PartitionMetadata) {
        if let Some(&idx) = self.index.get(&meta.key) {
            let entry = &mut self.entries[idx];
            let mut merged_attributes = entry.attributes.clone();
            if !meta.attributes.is_empty() {
                for (key, value) in meta.attributes.iter() {
                    merged_attributes.insert(key.clone(), value.clone());
                }
                meta.attributes = merged_attributes;
            } else {
                meta.attributes = entry.attributes.clone();
            }

            if meta.last_refreshed.is_none() {
                meta.last_refreshed = entry.last_refreshed;
            }

            *entry = meta;
        } else {
            let idx = self.entries.len();
            self.index.insert(meta.key.clone(), idx);
            self.entries.push(meta);
        }
    }

    fn snapshot(&self) -> Vec<PartitionMetadata> {
        self.entries.clone()
    }

    fn filter<F>(&self, predicate: F) -> Vec<PartitionMetadata>
    where
        F: Fn(&PartitionMetadata) -> bool,
    {
        self.entries
            .iter()
            .filter(|meta| predicate(meta))
            .cloned()
            .collect()
    }

    fn get(&self, key: &PartitionKey) -> Option<PartitionMetadata> {
        self.index
            .get(key)
            .and_then(|&idx| self.entries.get(idx))
            .cloned()
    }

    fn merge_attributes(&mut self, key: &PartitionKey, attributes: Vec<(String, String)>) {
        if attributes.is_empty() {
            return;
        }
        if let Some(&idx) = self.index.get(key) {
            let entry = &mut self.entries[idx];
            for (attr_key, value) in attributes {
                entry.attributes.insert(attr_key, value);
            }
            entry.last_refreshed.get_or_insert(SystemTime::now());
        }
    }
}

/// Central façade that coordinates persistence/query managers and partition metadata.
pub struct StorageService {
    partitions: RwLock<PartitionRegistry>,
}

const DEFAULT_SEGMENTS: &[SegmentKind] = &[
    SegmentKind::Ports,
    SegmentKind::Subdomains,
    SegmentKind::Whois,
    SegmentKind::Tls,
    SegmentKind::Dns,
    SegmentKind::Http,
    SegmentKind::Host,
];

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
    pub fn register_partition(&self, mut metadata: PartitionMetadata) {
        if metadata.last_refreshed.is_none() {
            metadata.last_refreshed = Some(SystemTime::now());
        }
        let mut guard = self.partitions.write().expect("partition lock poisoned");
        guard.upsert(metadata);
    }

    /// Annotate an existing partition with additional attributes.
    pub fn annotate_partition<I>(&self, key: &PartitionKey, attrs: I)
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let attributes: Vec<(String, String)> = attrs.into_iter().collect();
        if attributes.is_empty() {
            return;
        }
        let mut guard = self.partitions.write().expect("partition lock poisoned");
        guard.merge_attributes(key, attributes);
    }

    /// Convenience helper: register the standard per-target partition.
    pub fn ensure_target_partition<P: Into<PathBuf>>(
        &self,
        target: &str,
        path: P,
        segments: Option<Vec<SegmentKind>>,
        attributes: Option<Vec<(String, String)>>,
    ) {
        let segments_vec = segments.unwrap_or_else(|| DEFAULT_SEGMENTS.to_vec());
        let mut metadata = PartitionMetadata::new(
            PartitionKey::Target(target.to_string()),
            format!("target:{}", target),
            path.into(),
            segments_vec,
        )
        .with_attribute("category", "target")
        .with_attribute("target", target);

        if let Some(attrs) = attributes {
            metadata = metadata.with_attributes(attrs);
        }

        self.register_partition(metadata);
    }

    /// Refresh an existing target partition by inspecting the on-disk segments.
    pub fn refresh_target_partition<P: AsRef<Path>>(
        &self,
        target: &str,
        path: P,
    ) -> io::Result<()> {
        self.refresh_partition(
            PartitionKey::Target(target.to_string()),
            format!("target:{}", target),
            path,
        )
    }

    pub fn refresh_partition<P: AsRef<Path>>(
        &self,
        key: PartitionKey,
        label: String,
        path: P,
    ) -> io::Result<()> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(());
        }

        match Self::inspect_segments(path) {
            Ok(segments) => {
                let mut metadata =
                    PartitionMetadata::new(key.clone(), label, path.to_path_buf(), segments);

                if let Some(existing) = self.partition(&key) {
                    let attrs = existing
                        .attributes
                        .iter()
                        .map(|(attr_key, value)| (attr_key.clone(), value.clone()))
                        .collect::<Vec<_>>();
                    metadata = metadata.with_attributes(attrs);
                }

                self.register_partition(metadata);
                Ok(())
            }
            Err(err) => Err(io::Error::new(
                err.kind(),
                format!("{}: {}", path.display(), err),
            )),
        }
    }

    /// Return a cloned snapshot of all known partitions.
    pub fn partitions(&self) -> Vec<PartitionMetadata> {
        let guard = self.partitions.read().expect("partition lock poisoned");
        guard.snapshot()
    }

    /// Return partitions matching a predicate.
    pub fn partitions_filtered<F>(&self, predicate: F) -> Vec<PartitionMetadata>
    where
        F: Fn(&PartitionMetadata) -> bool,
    {
        let guard = self.partitions.read().expect("partition lock poisoned");
        guard.filter(predicate)
    }

    /// Return partitions that contain a given segment.
    pub fn partitions_with_segment(&self, segment: SegmentKind) -> Vec<PartitionMetadata> {
        self.partitions_filtered(|meta| meta.segments.contains(&segment))
    }

    /// Return partitions matching an attribute.
    pub fn partitions_with_attribute(&self, key: &str, value: &str) -> Vec<PartitionMetadata> {
        self.partitions_filtered(|meta| {
            meta.attributes
                .get(key)
                .map(|candidate| candidate == value)
                .unwrap_or(false)
        })
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
        self.persistence_for_target_with(target, persist, None, Vec::<(String, String)>::new())
    }

    /// Create a persistence manager with explicit segments and metadata attributes.
    pub fn persistence_for_target_with<I>(
        &self,
        target: &str,
        persist: Option<bool>,
        segments: Option<Vec<SegmentKind>>,
        attrs: I,
    ) -> Result<PersistenceManager, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let manager = PersistenceManager::new(target, persist)?;
        let attrs_vec: Vec<(String, String)> = attrs.into_iter().collect();
        if let Some(path) = manager.db_path().cloned() {
            self.ensure_target_partition(target, path, segments, Some(attrs_vec));
        }
        Ok(manager)
    }

    /// Helper to build a custom partition key for arbitrary storage paths.
    pub fn key_for_path<P: AsRef<Path>>(path: P) -> PartitionKey {
        PartitionKey::Custom(path.as_ref().display().to_string())
    }

    /// Open a query manager for the provided .rdb path.
    pub fn open_query_manager<P: Into<PathBuf>>(&self, path: P) -> std::io::Result<QueryManager> {
        let path_buf = path.into();
        let key = Self::key_for_path(&path_buf);
        if let Err(err) = self.refresh_partition(
            key.clone(),
            format!("custom:{}", path_buf.display()),
            &path_buf,
        ) {
            // Ignore refresh errors for ad-hoc paths
            let _ = err;
        }
        QueryManager::open(path_buf)
    }

    fn inspect_segments(path: &Path) -> io::Result<Vec<SegmentKind>> {
        let mut file = File::open(path)?;
        let header = FileHeader::read(&mut file).map_err(decode_err_to_io)?;

        if header.section_count == 0 {
            return Ok(vec![]);
        }

        file.seek(SeekFrom::Start(header.directory_offset))?;
        let entry_size = SectionEntry::size_for_version(header.version);
        let mut buf = vec![0u8; header.section_count as usize * entry_size];
        file.read_exact(&mut buf)?;
        let directory = SectionEntry::read_all(&buf, header.section_count as usize, header.version)
            .map_err(decode_err_to_io)?;
        Ok(directory.into_iter().map(|entry| entry.kind).collect())
    }
}

fn decode_err_to_io(err: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.0)
}
