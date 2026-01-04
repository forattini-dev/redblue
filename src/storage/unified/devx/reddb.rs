//! RedDB - Main Entry Point
//!
//! Unified Database with best-in-class developer experience for Tables, Graphs, and Vectors.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super::{EntityData, EntityId, UnifiedEntity, UnifiedStore};
use super::batch::BatchBuilder;
use super::builders::{EdgeBuilder, NodeBuilder, RowBuilder, VectorBuilder};
use super::helpers::cosine_similarity;
use super::preprocessors::{IndexConfig, Preprocessor};
use super::query::QueryBuilder;
use super::refs::{NodeRef, TableRef, VectorRef};
use super::types::{LinkedEntity, SimilarResult};
use crate::storage::schema::Value;

/// RedDB - Unified Database with Best-in-Class DevX
///
/// Single entry point for Tables, Graphs, and Vectors with full
/// metadata support and cross-referencing.
pub struct RedDB {
    store: Arc<UnifiedStore>,
    /// Preprocessing hooks
    preprocessors: Vec<Box<dyn Preprocessor>>,
    /// Index configuration
    index_config: IndexConfig,
    /// Persistence path
    path: Option<PathBuf>,
}

impl RedDB {
    /// Create a new RedDB instance (in-memory)
    pub fn new() -> Self {
        Self {
            store: Arc::new(UnifiedStore::new()),
            preprocessors: Vec::new(),
            index_config: IndexConfig::default(),
            path: None,
        }
    }

    /// Open or create a RedDB instance with persistence
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let path_buf = path.as_ref().to_path_buf();

        let store = if path_buf.exists() {
            UnifiedStore::load_from_file(&path_buf)?
        } else {
            UnifiedStore::new()
        };

        Ok(Self {
            store: Arc::new(store),
            preprocessors: Vec::new(),
            index_config: IndexConfig::default(),
            path: Some(path_buf),
        })
    }

    /// Create with custom store
    pub fn with_store(store: Arc<UnifiedStore>) -> Self {
        Self {
            store,
            preprocessors: Vec::new(),
            index_config: IndexConfig::default(),
            path: None,
        }
    }

    /// Flush changes to disk (if persistence is enabled)
    pub fn flush(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(path) = &self.path {
            self.store.save_to_file(path)?;
        }
        Ok(())
    }

    /// List all collections in the store
    pub fn collections(&self) -> Vec<String> {
        self.store.list_collections()
    }

    // ========================================================================
    // Builder Methods - Create Entities
    // ========================================================================

    /// Start building a graph node
    ///
    /// # Example
    /// ```ignore
    /// let host = db.node("hosts", "Host")
    ///     .property("ip", "192.168.1.1")
    ///     .save()?;
    /// ```
    pub fn node(&self, collection: impl Into<String>, label: impl Into<String>) -> NodeBuilder {
        NodeBuilder::new(self.store.clone(), collection, label)
    }

    /// Start building a graph edge
    ///
    /// # Example
    /// ```ignore
    /// let edge = db.edge("connections", "CONNECTS_TO")
    ///     .from(host_a)
    ///     .to(host_b)
    ///     .weight(0.95)
    ///     .property("protocol", "TCP")
    ///     .save()?;
    /// ```
    pub fn edge(&self, collection: impl Into<String>, label: impl Into<String>) -> EdgeBuilder {
        EdgeBuilder::new(self.store.clone(), collection, label)
    }

    /// Start building a vector entry
    ///
    /// # Example
    /// ```ignore
    /// let vec = db.vector("embeddings")
    ///     .dense(embedding)
    ///     .content("Original text content")
    ///     .metadata("source", "document.pdf")
    ///     .save()?;
    /// ```
    pub fn vector(&self, collection: impl Into<String>) -> VectorBuilder {
        VectorBuilder::new(self.store.clone(), collection)
    }

    /// Start building a table row
    ///
    /// # Example
    /// ```ignore
    /// let row = db.row("scans", vec![
    ///     ("timestamp", Value::Timestamp(now)),
    ///     ("target", Value::Text("192.168.1.0/24".into())),
    ///     ("findings", Value::Integer(42)),
    /// ]).save()?;
    /// ```
    pub fn row(&self, table: impl Into<String>, columns: Vec<(&str, Value)>) -> RowBuilder {
        RowBuilder::new(self.store.clone(), table, columns)
    }

    // ========================================================================
    // Reference Helpers - For Metadata Linking
    // ========================================================================

    /// Create a reference to a table row
    pub fn table_ref(&self, table: impl Into<String>, row_id: u64) -> TableRef {
        TableRef::new(table, row_id)
    }

    /// Create a reference to a graph node
    pub fn node_ref(&self, collection: impl Into<String>, node_id: EntityId) -> NodeRef {
        NodeRef::new(collection, node_id)
    }

    /// Create a reference to a vector
    pub fn vector_ref(&self, collection: impl Into<String>, vector_id: EntityId) -> VectorRef {
        VectorRef::new(collection, vector_id)
    }

    // ========================================================================
    // Query API
    // ========================================================================

    /// Start building a query
    pub fn query(&self) -> QueryBuilder {
        QueryBuilder::new(self.store.clone())
    }

    /// Quick vector similarity search
    pub fn similar(&self, collection: &str, vector: &[f32], k: usize) -> Vec<SimilarResult> {
        let manager = match self.store.get_collection(collection) {
            Some(m) => m,
            None => return Vec::new(),
        };

        let entities = manager.query_all(|_| true);
        let mut results: Vec<SimilarResult> = entities
            .iter()
            .filter_map(|e| {
                // Check if entity has matching vector data or embeddings
                let score = match &e.data {
                    EntityData::Vector(v) => cosine_similarity(vector, &v.dense),
                    _ => {
                        // Check embeddings
                        e.embeddings
                            .iter()
                            .map(|emb| cosine_similarity(vector, &emb.vector))
                            .fold(0.0f32, f32::max)
                    }
                };
                if score > 0.0 {
                    Some(SimilarResult {
                        entity_id: e.id,
                        score,
                        entity: e.clone(),
                    })
                } else {
                    None
                }
            })
            .collect();

        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(k);
        results
    }

    /// Get entity by ID from any collection
    pub fn get(&self, id: EntityId) -> Option<UnifiedEntity> {
        self.store.get_any(id).map(|(_, e)| e)
    }

    /// Get entity with its collection name
    pub fn get_with_collection(&self, id: EntityId) -> Option<(String, UnifiedEntity)> {
        self.store.get_any(id)
    }

    // ========================================================================
    // Batch Operations - Performance
    // ========================================================================

    /// Start a batch operation for bulk inserts
    pub fn batch(&self) -> BatchBuilder {
        BatchBuilder::new(self.store.clone())
    }

    // ========================================================================
    // Preprocessing
    // ========================================================================

    /// Add a preprocessor hook
    pub fn add_preprocessor(&mut self, preprocessor: Box<dyn Preprocessor>) {
        self.preprocessors.push(preprocessor);
    }

    /// Run preprocessors on an entity
    #[allow(dead_code)]
    fn preprocess(&self, entity: &mut UnifiedEntity) {
        for preprocessor in &self.preprocessors {
            preprocessor.process(entity);
        }
    }

    // ========================================================================
    // Cross-Reference Navigation
    // ========================================================================

    /// Get all entities linked FROM the given entity
    pub fn linked_from(&self, id: EntityId) -> Vec<LinkedEntity> {
        self.store
            .get_refs_from(id)
            .into_iter()
            .filter_map(|(target_id, ref_type, collection)| {
                self.store
                    .get(&collection, target_id)
                    .map(|entity| LinkedEntity {
                        entity,
                        ref_type,
                        collection,
                    })
            })
            .collect()
    }

    /// Get all entities linked TO the given entity
    pub fn linked_to(&self, id: EntityId) -> Vec<LinkedEntity> {
        self.store
            .get_refs_to(id)
            .into_iter()
            .filter_map(|(source_id, ref_type, collection)| {
                self.store
                    .get(&collection, source_id)
                    .map(|entity| LinkedEntity {
                        entity,
                        ref_type,
                        collection,
                    })
            })
            .collect()
    }

    /// Get the underlying store (for advanced operations)
    pub fn store(&self) -> Arc<UnifiedStore> {
        self.store.clone()
    }
}

impl Default for RedDB {
    fn default() -> Self {
        Self::new()
    }
}
