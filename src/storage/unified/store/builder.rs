use super::super::entity::{
  EmbeddingSlot, EntityData, EntityId, EntityKind, RefType, UnifiedEntity,
};
use super::super::metadata::MetadataValue;
use super::core::UnifiedStore;
use super::errors::StoreError;

/// Builder for creating entities with a fluent API
pub struct EntityBuilder {
  store: std::sync::Arc<UnifiedStore>,
  collection: String,
  entity: UnifiedEntity,
}

impl EntityBuilder {
  /// Start building an entity
  pub fn new(
    store: std::sync::Arc<UnifiedStore>,
    collection: impl Into<String>,
    kind: EntityKind,
    data: EntityData,
  ) -> Self {
    let collection_name = collection.into();
    let _ = store.get_or_create_collection(&collection_name);
    let id = store.next_entity_id();

    Self {
      store,
      collection: collection_name,
      entity: UnifiedEntity::new(id, kind, data),
    }
  }

  /// Add metadata
  pub fn metadata(self, _key: impl Into<String>, _value: MetadataValue) -> Self {
    self
  }

  /// Add an embedding
  pub fn embedding(
    mut self,
    name: impl Into<String>,
    vector: Vec<f32>,
    model: impl Into<String>,
  ) -> Self {
    self
      .entity
      .add_embedding(EmbeddingSlot::new(name, vector, model));
    self
  }

  /// Add a cross-reference
  pub fn cross_ref(
    mut self,
    target: EntityId,
    target_collection: impl Into<String>,
    ref_type: RefType,
  ) -> Self {
    self
      .entity
      .add_cross_ref(super::super::entity::CrossRef::new(
        self.entity.id,
        target,
        target_collection,
        ref_type,
      ));
    self
  }

  /// Build and insert the entity
  pub fn insert(self) -> Result<EntityId, StoreError> {
    self.store.insert(&self.collection, self.entity)
  }
}
