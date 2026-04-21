use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use super::super::entity::{CrossRef, EntityData, EntityId, EntityKind, RefType, UnifiedEntity};
use super::super::manager::SegmentManager;
use super::super::metadata::{Metadata, MetadataFilter};
use super::config::UnifiedStoreConfig;
use super::errors::StoreError;
use super::stats::StoreStats;

/// Unified storage for tables, graphs, and vectors
///
/// UnifiedStore provides a single coherent interface for all data types:
/// - **Tables**: Row-based data with columns
/// - **Graphs**: Nodes and edges with labels
/// - **Vectors**: Embeddings for similarity search
///
/// # Features
///
/// - Multi-collection management
/// - Cross-collection queries
/// - Cross-reference tracking between entities
/// - Automatic ID generation
/// - Segment-based storage with growing/sealed lifecycle
pub struct UnifiedStore {
  /// Store configuration
  pub(crate) config: UnifiedStoreConfig,
  /// File format version for serialization
  pub(super) format_version: AtomicU32,
  /// Global entity ID counter
  pub(super) next_entity_id: AtomicU64,
  /// Collections by name
  pub(super) collections: RwLock<HashMap<String, Arc<SegmentManager>>>,
  /// Forward cross-references: source_id → [(target_id, ref_type, target_collection)]
  pub(super) cross_refs: RwLock<HashMap<EntityId, Vec<(EntityId, RefType, String)>>>,
  /// Reverse cross-references: target_id → [(source_id, ref_type, source_collection)]
  pub(super) reverse_refs: RwLock<HashMap<EntityId, Vec<(EntityId, RefType, String)>>>,
  /// Optional page-based storage via Pager
  pub(super) pager: Option<Arc<crate::storage::engine::Pager>>,
  /// Database file path (for paged mode)
  pub(super) db_path: Option<std::path::PathBuf>,
  /// B-tree indices for O(log n) entity lookups by ID (per collection)
  pub(super) btree_indices: RwLock<HashMap<String, crate::storage::engine::BTree>>,
}

impl UnifiedStore {
  /// Create a new unified store
  pub fn new() -> Self {
    Self::with_config(UnifiedStoreConfig::default())
  }

  /// Get the current storage format version
  pub fn format_version(&self) -> u32 {
    self.format_version.load(Ordering::SeqCst)
  }

  pub(crate) fn set_format_version(&self, version: u32) {
    self.format_version.store(version, Ordering::SeqCst);
  }

  /// Allocate a global entity ID
  pub fn next_entity_id(&self) -> EntityId {
    EntityId::new(self.next_entity_id.fetch_add(1, Ordering::SeqCst))
  }

  pub(crate) fn register_entity_id(&self, id: EntityId) {
    let candidate = id.raw().saturating_add(1);
    let mut current = self.next_entity_id.load(Ordering::SeqCst);
    while candidate > current {
      match self.next_entity_id.compare_exchange(
        current,
        candidate,
        Ordering::SeqCst,
        Ordering::SeqCst,
      ) {
        Ok(_) => break,
        Err(updated) => current = updated,
      }
    }
  }

  /// Create with custom configuration
  pub fn with_config(config: UnifiedStoreConfig) -> Self {
    Self {
      config,
      format_version: AtomicU32::new(super::STORE_VERSION_V2),
      next_entity_id: AtomicU64::new(1),
      collections: RwLock::new(HashMap::new()),
      cross_refs: RwLock::new(HashMap::new()),
      reverse_refs: RwLock::new(HashMap::new()),
      pager: None,
      db_path: None,
      btree_indices: RwLock::new(HashMap::new()),
    }
  }

  /// Check if the store is using page-based persistence
  pub fn is_paged(&self) -> bool {
    self.pager.is_some()
  }

  /// Get the database file path (if using paged mode)
  pub fn db_path(&self) -> Option<&std::path::Path> {
    self.db_path.as_deref()
  }

  /// Create a new collection
  pub fn create_collection(&self, name: impl Into<String>) -> Result<(), StoreError> {
    let name = name.into();
    let mut collections = self.collections.write().unwrap();

    if collections.contains_key(&name) {
      return Err(StoreError::CollectionExists(name));
    }

    let manager = SegmentManager::with_config(&name, self.config.manager_config.clone());
    collections.insert(name, Arc::new(manager));

    Ok(())
  }

  /// Get or create a collection
  pub fn get_or_create_collection(&self, name: impl Into<String>) -> Arc<SegmentManager> {
    let name = name.into();
    let mut collections = self.collections.write().unwrap();

    if let Some(manager) = collections.get(&name) {
      return Arc::clone(manager);
    }

    let manager = Arc::new(SegmentManager::with_config(
      &name,
      self.config.manager_config.clone(),
    ));
    collections.insert(name, Arc::clone(&manager));
    manager
  }

  /// Get a collection
  pub fn get_collection(&self, name: &str) -> Option<Arc<SegmentManager>> {
    self.collections.read().unwrap().get(name).map(Arc::clone)
  }

  /// List all collections
  pub fn list_collections(&self) -> Vec<String> {
    self.collections.read().unwrap().keys().cloned().collect()
  }

  /// Drop a collection
  pub fn drop_collection(&self, name: &str) -> Result<(), StoreError> {
    let mut collections = self.collections.write().unwrap();

    if collections.remove(name).is_none() {
      return Err(StoreError::CollectionNotFound(name.to_string()));
    }

    Ok(())
  }

  /// Insert an entity into a collection
  pub fn insert(&self, collection: &str, entity: UnifiedEntity) -> Result<EntityId, StoreError> {
    let manager = self
      .get_collection(collection)
      .ok_or_else(|| StoreError::CollectionNotFound(collection.to_string()))?;

    let mut entity = entity;
    if entity.id.raw() == 0 {
      entity.id = self.next_entity_id();
    } else {
      self.register_entity_id(entity.id);
    }
    let id = manager.insert(entity)?;
    self.register_entity_id(id);

    if let Some(pager) = &self.pager {
      if let Some(entity) = manager.get(id) {
        let mut btree_indices = self.btree_indices.write().unwrap();
        let btree = btree_indices
          .entry(collection.to_string())
          .or_insert_with(|| crate::storage::engine::BTree::new(Arc::clone(pager)));

        let key = id.raw().to_le_bytes();
        let value = Self::serialize_entity(&entity, self.format_version());
        let _ = btree.insert(&key, &value);
      }
    }

    if self.config.auto_index_refs {
      if let Some(entity) = manager.get(id) {
        self.index_cross_refs(&entity, collection);
      }
    }

    Ok(id)
  }

  /// Insert an entity, creating collection if needed
  pub fn insert_auto(
    &self,
    collection: &str,
    entity: UnifiedEntity,
  ) -> Result<EntityId, StoreError> {
    let manager = self.get_or_create_collection(collection);
    let mut entity = entity;
    if entity.id.raw() == 0 {
      entity.id = self.next_entity_id();
    } else {
      self.register_entity_id(entity.id);
    }
    let id = manager.insert(entity)?;
    self.register_entity_id(id);

    if let Some(pager) = &self.pager {
      if let Some(entity) = manager.get(id) {
        let mut btree_indices = self.btree_indices.write().unwrap();
        let btree = btree_indices
          .entry(collection.to_string())
          .or_insert_with(|| crate::storage::engine::BTree::new(Arc::clone(pager)));

        let key = id.raw().to_le_bytes();
        let value = Self::serialize_entity(&entity, self.format_version());
        let _ = btree.insert(&key, &value);
      }
    }

    if self.config.auto_index_refs {
      if let Some(entity) = manager.get(id) {
        self.index_cross_refs(&entity, collection);
      }
    }

    Ok(id)
  }

  /// Get an entity from a collection
  ///
  /// Uses B-tree index for O(log n) lookup when page-based storage is active.
  /// Falls back to linear scan through SegmentManager otherwise.
  pub fn get(&self, collection: &str, id: EntityId) -> Option<UnifiedEntity> {
    if self.pager.is_some() {
      let btree_indices = self.btree_indices.read().unwrap();
      if let Some(btree) = btree_indices.get(collection) {
        let key = id.raw().to_le_bytes();
        if let Ok(Some(value)) = btree.get(&key) {
          if let Ok(entity) = Self::deserialize_entity(&value, self.format_version()) {
            return Some(entity);
          }
        }
      }
    }

    self.get_collection(collection)?.get(id)
  }

  /// Get an entity from any collection
  pub fn get_any(&self, id: EntityId) -> Option<(String, UnifiedEntity)> {
    let collections = self.collections.read().unwrap();
    for (name, manager) in collections.iter() {
      if let Some(entity) = manager.get(id) {
        return Some((name.clone(), entity));
      }
    }
    None
  }

  /// Delete an entity
  pub fn delete(&self, collection: &str, id: EntityId) -> Result<bool, StoreError> {
    let manager = self
      .get_collection(collection)
      .ok_or_else(|| StoreError::CollectionNotFound(collection.to_string()))?;

    if self.pager.is_some() {
      let btree_indices = self.btree_indices.read().unwrap();
      if let Some(btree) = btree_indices.get(collection) {
        let key = id.raw().to_le_bytes();
        let _ = btree.delete(&key);
      }
    }

    self.unindex_cross_refs(id);

    Ok(manager.delete(id)?)
  }

  /// Set metadata for an entity
  pub fn set_metadata(
    &self,
    collection: &str,
    id: EntityId,
    metadata: Metadata,
  ) -> Result<(), StoreError> {
    let manager = self
      .get_collection(collection)
      .ok_or_else(|| StoreError::CollectionNotFound(collection.to_string()))?;

    Ok(manager.set_metadata(id, metadata)?)
  }

  /// Get metadata for an entity
  pub fn get_metadata(&self, collection: &str, id: EntityId) -> Option<Metadata> {
    self.get_collection(collection)?.get_metadata(id)
  }

  /// Add a cross-reference between entities
  pub fn add_cross_ref(
    &self,
    source_collection: &str,
    source_id: EntityId,
    target_collection: &str,
    target_id: EntityId,
    ref_type: RefType,
    weight: f32,
  ) -> Result<(), StoreError> {
    let source_manager = self
      .get_collection(source_collection)
      .ok_or_else(|| StoreError::CollectionNotFound(source_collection.to_string()))?;

    if source_manager.get(source_id).is_none() {
      return Err(StoreError::EntityNotFound(source_id));
    }

    let target_manager = self
      .get_collection(target_collection)
      .ok_or_else(|| StoreError::CollectionNotFound(target_collection.to_string()))?;

    if target_manager.get(target_id).is_none() {
      return Err(StoreError::EntityNotFound(target_id));
    }

    let current_refs = self
      .cross_refs
      .read()
      .unwrap()
      .get(&source_id)
      .map_or(0, |v| v.len());
    if current_refs >= self.config.max_cross_refs {
      return Err(StoreError::TooManyRefs(source_id));
    }

    {
      let mut forward = self.cross_refs.write().unwrap();
      let refs = forward.entry(source_id).or_default();
      if !refs
        .iter()
        .any(|(id, kind, coll)| *id == target_id && *kind == ref_type && coll == target_collection)
      {
        refs.push((target_id, ref_type, target_collection.to_string()));
      }
    }

    {
      let mut reverse = self.reverse_refs.write().unwrap();
      let refs = reverse.entry(target_id).or_default();
      if !refs
        .iter()
        .any(|(id, kind, coll)| *id == source_id && *kind == ref_type && coll == source_collection)
      {
        refs.push((source_id, ref_type, source_collection.to_string()));
      }
    }

    if let Some(mut entity) = source_manager.get(source_id) {
      if !entity.cross_refs.iter().any(|xref| {
        xref.target == target_id
          && xref.ref_type == ref_type
          && xref.target_collection == target_collection
      }) {
        let cross_ref =
          CrossRef::with_weight(source_id, target_id, target_collection, ref_type, weight);
        entity.add_cross_ref(cross_ref);
        let _ = source_manager.update(entity);
      }
    }

    Ok(())
  }

  /// Get cross-references from an entity
  pub fn get_refs_from(&self, id: EntityId) -> Vec<(EntityId, RefType, String)> {
    self
      .cross_refs
      .read()
      .unwrap()
      .get(&id)
      .cloned()
      .unwrap_or_default()
  }

  /// Get cross-references to an entity
  pub fn get_refs_to(&self, id: EntityId) -> Vec<(EntityId, RefType, String)> {
    self
      .reverse_refs
      .read()
      .unwrap()
      .get(&id)
      .cloned()
      .unwrap_or_default()
  }

  /// Expand cross-references to get related entities
  pub fn expand_refs(
    &self,
    id: EntityId,
    depth: u32,
    ref_types: Option<&[RefType]>,
  ) -> Vec<(UnifiedEntity, u32, RefType)> {
    let mut results = Vec::new();
    let mut visited = HashSet::new();
    visited.insert(id);

    self.expand_refs_recursive(id, depth, ref_types, &mut visited, &mut results, 1);

    results
  }

  fn expand_refs_recursive(
    &self,
    id: EntityId,
    max_depth: u32,
    ref_types: Option<&[RefType]>,
    visited: &mut HashSet<EntityId>,
    results: &mut Vec<(UnifiedEntity, u32, RefType)>,
    current_depth: u32,
  ) {
    if current_depth > max_depth {
      return;
    }

    for (target_id, ref_type, target_collection) in self.get_refs_from(id) {
      if visited.contains(&target_id) {
        continue;
      }

      if let Some(types) = ref_types {
        if !types.contains(&ref_type) {
          continue;
        }
      }

      visited.insert(target_id);

      if let Some(entity) = self.get(&target_collection, target_id) {
        results.push((entity, current_depth, ref_type));

        self.expand_refs_recursive(
          target_id,
          max_depth,
          ref_types,
          visited,
          results,
          current_depth + 1,
        );
      }
    }
  }

  /// Index cross-references from an entity
  pub(crate) fn index_cross_refs(&self, entity: &UnifiedEntity, collection: &str) {
    for cross_ref in &entity.cross_refs {
      if cross_ref.target_collection.is_empty() {
        continue;
      }

      {
        let mut forward = self.cross_refs.write().unwrap();
        let refs = forward.entry(cross_ref.source).or_default();
        if !refs.iter().any(|(id, kind, coll)| {
          *id == cross_ref.target
            && *kind == cross_ref.ref_type
            && coll == &cross_ref.target_collection
        }) {
          refs.push((
            cross_ref.target,
            cross_ref.ref_type,
            cross_ref.target_collection.clone(),
          ));
        }
      }

      {
        let mut reverse = self.reverse_refs.write().unwrap();
        let refs = reverse.entry(cross_ref.target).or_default();
        if !refs.iter().any(|(id, kind, coll)| {
          *id == cross_ref.source && *kind == cross_ref.ref_type && coll == collection
        }) {
          refs.push((cross_ref.source, cross_ref.ref_type, collection.to_string()));
        }
      }
    }
  }

  /// Remove cross-references for an entity
  pub(crate) fn unindex_cross_refs(&self, id: EntityId) {
    self.cross_refs.write().unwrap().remove(&id);

    let mut reverse = self.reverse_refs.write().unwrap();
    for refs in reverse.values_mut() {
      refs.retain(|(source, _, _)| *source != id);
    }
    reverse.remove(&id);
  }

  /// Query across all collections with a filter
  pub fn query_all<F>(&self, filter: F) -> Vec<(String, UnifiedEntity)>
  where
    F: Fn(&UnifiedEntity) -> bool + Clone,
  {
    let mut results = Vec::new();
    let collections = self.collections.read().unwrap();

    for (name, manager) in collections.iter() {
      for entity in manager.query_all(filter.clone()) {
        results.push((name.clone(), entity));
      }
    }

    results
  }

  /// Filter by metadata across all collections
  pub fn filter_metadata_all(
    &self,
    filters: &[(String, MetadataFilter)],
  ) -> Vec<(String, EntityId)> {
    let mut results = Vec::new();
    let collections = self.collections.read().unwrap();

    for (name, manager) in collections.iter() {
      for id in manager.filter_metadata(filters) {
        results.push((name.clone(), id));
      }
    }

    results
  }

  /// Get statistics
  pub fn stats(&self) -> StoreStats {
    let collections = self.collections.read().unwrap();

    let mut stats = StoreStats {
      collection_count: collections.len(),
      ..Default::default()
    };

    for (name, manager) in collections.iter() {
      let manager_stats = manager.stats();
      stats.total_entities += manager_stats.total_entities;
      stats.total_memory_bytes += manager_stats.total_memory_bytes;
      stats.collections.insert(name.clone(), manager_stats);
    }

    stats.cross_ref_count = self
      .cross_refs
      .read()
      .unwrap()
      .values()
      .map(|v| v.len())
      .sum();

    stats
  }

  /// Run maintenance on all collections
  pub fn run_maintenance(&self) -> Result<(), StoreError> {
    let collections = self.collections.read().unwrap();
    for manager in collections.values() {
      manager.run_maintenance()?;
    }
    Ok(())
  }
}

impl Default for UnifiedStore {
  fn default() -> Self {
    Self::new()
  }
}
