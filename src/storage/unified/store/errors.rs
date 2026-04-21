use super::super::entity::EntityId;
use super::super::segment::SegmentError;

/// Errors from UnifiedStore operations
#[derive(Debug)]
pub enum StoreError {
  /// Collection already exists
  CollectionExists(String),
  /// Collection not found
  CollectionNotFound(String),
  /// Entity not found
  EntityNotFound(EntityId),
  /// Too many cross-references
  TooManyRefs(EntityId),
  /// Segment error
  Segment(SegmentError),
  /// I/O error
  Io(std::io::Error),
  /// Serialization error
  Serialization(String),
}

impl std::fmt::Display for StoreError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::CollectionExists(name) => write!(f, "Collection already exists: {}", name),
      Self::CollectionNotFound(name) => write!(f, "Collection not found: {}", name),
      Self::EntityNotFound(id) => write!(f, "Entity not found: {}", id),
      Self::TooManyRefs(id) => write!(f, "Too many cross-references for entity: {}", id),
      Self::Segment(e) => write!(f, "Segment error: {:?}", e),
      Self::Io(e) => write!(f, "I/O error: {}", e),
      Self::Serialization(msg) => write!(f, "Serialization error: {}", msg),
    }
  }
}

impl std::error::Error for StoreError {}

impl From<SegmentError> for StoreError {
  fn from(e: SegmentError) -> Self {
    Self::Segment(e)
  }
}

impl From<std::io::Error> for StoreError {
  fn from(e: std::io::Error) -> Self {
    Self::Io(e)
  }
}
