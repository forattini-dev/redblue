//! Vector Storage and Similarity Search
//!
//! This module provides vector storage and similarity search capabilities for RedDB,
//! enabling semantic search, embeddings storage, and k-NN queries.
//!
//! # Components
//!
//! - **types**: Vector type definitions (dense, sparse)
//! - **distance**: Distance metrics (cosine, L2, dot product)
//! - **dense**: Dense vector storage with packed float32
//! - **flat-index**: Exact k-NN search (brute force)
//! - **ivf-index**: Approximate k-NN search (IVF-Flat)
//!
//! # Example
//!
//! ```ignore
//! use redblue::storage::vector::{DenseVector, FlatIndex, Distance};
//!
//! // Create vectors
//! let v1 = DenseVector::new(vec![1.0, 0.0, 0.0]);
//! let v2 = DenseVector::new(vec![0.0, 1.0, 0.0]);
//!
//! // Build index
//! let mut index = FlatIndex::new(3, Distance::Cosine);
//! index.add(0, v1);
//! index.add(1, v2);
//!
//! // Search
//! let query = DenseVector::new(vec![0.9, 0.1, 0.0]);
//! let results = index.search(&query, 2);
//! ```

pub mod types;
pub mod distance;
pub mod dense;
pub mod flat_index;
pub mod ivf_index;

// Re-export common types
pub use types::{DenseVector, SparseVector, VectorId};
pub use distance::{Distance, DistanceMetric};
pub use dense::DenseVectorStorage;
pub use flat_index::FlatIndex;
pub use ivf_index::IvfIndex;
