//! Undo/Redo system for hex editing
//!
//! Provides transaction-based undo/redo with:
//! - Minimal diff storage (only changed bytes)
//! - Transaction grouping for atomic operations
//! - Configurable history depth

use super::buffer::{Delta, PagedBuffer};
use std::time::{SystemTime, UNIX_EPOCH};

/// Error types for undo operations
#[derive(Debug)]
pub enum UndoError {
  NothingToUndo,
  NothingToRedo,
  BufferError(super::source::SourceError),
}

impl std::fmt::Display for UndoError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::NothingToUndo => write!(f, "Nothing to undo"),
      Self::NothingToRedo => write!(f, "Nothing to redo"),
      Self::BufferError(e) => write!(f, "Buffer error: {}", e),
    }
  }
}

impl From<super::source::SourceError> for UndoError {
  fn from(err: super::source::SourceError) -> Self {
    UndoError::BufferError(err)
  }
}

pub type UndoResult<T> = Result<T, UndoError>;

/// A single undo entry
#[derive(Clone, Debug)]
pub struct UndoEntry {
  /// Offset of change
  pub offset: u64,

  /// Old bytes (for undo)
  pub old_bytes: Vec<u8>,

  /// New bytes (for redo)
  pub new_bytes: Vec<u8>,

  /// Transaction this belongs to
  pub transaction_id: u32,

  /// Timestamp
  pub timestamp: u64,

  /// Description of the change
  pub description: String,
}

impl UndoEntry {
  fn new(delta: Delta, transaction_id: u32, description: String) -> Self {
    Self {
      offset: delta.offset,
      old_bytes: delta.old_bytes,
      new_bytes: delta.new_bytes,
      transaction_id,
      timestamp: Self::now(),
      description,
    }
  }

  fn now() -> u64 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or(0)
  }
}

/// Undo/redo stack with transaction support
pub struct UndoStack {
  /// Undo entries
  undo_stack: Vec<UndoEntry>,

  /// Redo entries
  redo_stack: Vec<UndoEntry>,

  /// Current transaction ID
  transaction_id: u32,

  /// In transaction mode
  in_transaction: bool,

  /// Current transaction description
  transaction_desc: String,

  /// Maximum undo depth (0 = unlimited)
  max_depth: usize,

  /// Bytes limit for undo history (0 = unlimited)
  max_bytes: usize,

  /// Current bytes used in undo history
  current_bytes: usize,
}

impl UndoStack {
  /// Create a new undo stack
  pub fn new() -> Self {
    Self {
      undo_stack: Vec::new(),
      redo_stack: Vec::new(),
      transaction_id: 0,
      in_transaction: false,
      transaction_desc: String::new(),
      max_depth: 0,
      max_bytes: 0,
      current_bytes: 0,
    }
  }

  /// Create with maximum depth
  pub fn with_max_depth(max_depth: usize) -> Self {
    Self {
      max_depth,
      ..Self::new()
    }
  }

  /// Create with maximum bytes limit
  pub fn with_max_bytes(max_bytes: usize) -> Self {
    Self {
      max_bytes,
      ..Self::new()
    }
  }

  /// Record changes from buffer deltas
  pub fn record_deltas(&mut self, buffer: &mut PagedBuffer, description: &str) {
    let deltas = buffer.take_deltas();

    if !self.in_transaction {
      self.transaction_id += 1;
    }

    let desc = if self.in_transaction && !self.transaction_desc.is_empty() {
      self.transaction_desc.clone()
    } else {
      description.to_string()
    };

    for delta in deltas {
      let entry_bytes = delta.old_bytes.len() + delta.new_bytes.len();
      let entry = UndoEntry::new(delta, self.transaction_id, desc.clone());

      self.undo_stack.push(entry);
      self.current_bytes += entry_bytes;
    }

    // Clear redo on new changes
    self.clear_redo();

    // Trim if necessary
    self.trim();
  }

  /// Record a single modification
  pub fn record(&mut self, offset: u64, old_bytes: Vec<u8>, new_bytes: Vec<u8>, description: &str) {
    if !self.in_transaction {
      self.transaction_id += 1;
    }

    let desc = if self.in_transaction && !self.transaction_desc.is_empty() {
      self.transaction_desc.clone()
    } else {
      description.to_string()
    };

    let entry_bytes = old_bytes.len() + new_bytes.len();
    let entry = UndoEntry {
      offset,
      old_bytes,
      new_bytes,
      transaction_id: self.transaction_id,
      timestamp: UndoEntry::now(),
      description: desc,
    };

    self.undo_stack.push(entry);
    self.current_bytes += entry_bytes;

    self.clear_redo();
    self.trim();
  }

  /// Begin a transaction (groups multiple changes)
  pub fn begin_transaction(&mut self, description: &str) {
    if !self.in_transaction {
      self.transaction_id += 1;
      self.in_transaction = true;
      self.transaction_desc = description.to_string();
    }
  }

  /// End current transaction
  pub fn end_transaction(&mut self) {
    self.in_transaction = false;
    self.transaction_desc.clear();
  }

  /// Undo last change or transaction
  pub fn undo(&mut self, buffer: &mut PagedBuffer) -> UndoResult<String> {
    if self.undo_stack.is_empty() {
      return Err(UndoError::NothingToUndo);
    }

    let current_tx = self.undo_stack.last().unwrap().transaction_id;
    let description = self.undo_stack.last().unwrap().description.clone();

    // Undo all entries in this transaction (in reverse order)
    while let Some(entry) = self.undo_stack.last() {
      if entry.transaction_id != current_tx {
        break;
      }

      let entry = self.undo_stack.pop().unwrap();
      buffer.write_raw(entry.offset, &entry.old_bytes)?;

      let entry_bytes = entry.old_bytes.len() + entry.new_bytes.len();
      self.current_bytes = self.current_bytes.saturating_sub(entry_bytes);

      self.redo_stack.push(entry);
    }

    Ok(description)
  }

  /// Redo last undone change or transaction
  pub fn redo(&mut self, buffer: &mut PagedBuffer) -> UndoResult<String> {
    if self.redo_stack.is_empty() {
      return Err(UndoError::NothingToRedo);
    }

    let current_tx = self.redo_stack.last().unwrap().transaction_id;
    let description = self.redo_stack.last().unwrap().description.clone();

    // Redo all entries in this transaction (in reverse order)
    while let Some(entry) = self.redo_stack.last() {
      if entry.transaction_id != current_tx {
        break;
      }

      let entry = self.redo_stack.pop().unwrap();
      buffer.write_raw(entry.offset, &entry.new_bytes)?;

      let entry_bytes = entry.old_bytes.len() + entry.new_bytes.len();
      self.current_bytes += entry_bytes;

      self.undo_stack.push(entry);
    }

    Ok(description)
  }

  /// Get count of undoable transactions
  pub fn can_undo(&self) -> usize {
    self
      .undo_stack
      .iter()
      .map(|e| e.transaction_id)
      .collect::<std::collections::HashSet<_>>()
      .len()
  }

  /// Get count of redoable transactions
  pub fn can_redo(&self) -> usize {
    self
      .redo_stack
      .iter()
      .map(|e| e.transaction_id)
      .collect::<std::collections::HashSet<_>>()
      .len()
  }

  /// Get description of next undo
  pub fn next_undo_description(&self) -> Option<&str> {
    self.undo_stack.last().map(|e| e.description.as_str())
  }

  /// Get description of next redo
  pub fn next_redo_description(&self) -> Option<&str> {
    self.redo_stack.last().map(|e| e.description.as_str())
  }

  /// Get total bytes used by undo history
  pub fn bytes_used(&self) -> usize {
    self.current_bytes
  }

  /// Get total number of entries
  pub fn entry_count(&self) -> usize {
    self.undo_stack.len()
  }

  /// Clear all undo/redo history
  pub fn clear(&mut self) {
    self.undo_stack.clear();
    self.redo_stack.clear();
    self.current_bytes = 0;
  }

  /// Clear redo history
  fn clear_redo(&mut self) {
    for entry in &self.redo_stack {
      self.current_bytes = self
        .current_bytes
        .saturating_sub(entry.old_bytes.len() + entry.new_bytes.len());
    }
    self.redo_stack.clear();
  }

  /// Trim undo stack if limits exceeded
  fn trim(&mut self) {
    // Trim by depth
    if self.max_depth > 0 && self.can_undo() > self.max_depth {
      // Remove oldest transaction
      if let Some(oldest_tx) = self.undo_stack.first().map(|e| e.transaction_id) {
        while self.undo_stack.first().map(|e| e.transaction_id) == Some(oldest_tx) {
          if let Some(entry) = self.undo_stack.first() {
            self.current_bytes = self
              .current_bytes
              .saturating_sub(entry.old_bytes.len() + entry.new_bytes.len());
          }
          self.undo_stack.remove(0);
        }
      }
    }

    // Trim by bytes
    if self.max_bytes > 0 {
      while self.current_bytes > self.max_bytes && !self.undo_stack.is_empty() {
        if let Some(entry) = self.undo_stack.first() {
          self.current_bytes = self
            .current_bytes
            .saturating_sub(entry.old_bytes.len() + entry.new_bytes.len());
        }
        self.undo_stack.remove(0);
      }
    }
  }
}

impl Default for UndoStack {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::super::source::BufferSource;
  use super::*;

  #[test]
  fn test_basic_undo_redo() {
    let data = vec![0u8; 10];
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);
    let mut undo = UndoStack::new();

    // Make a change
    buffer.write(0, &[0x41, 0x42]).unwrap();
    undo.record_deltas(&mut buffer, "write 1");

    assert_eq!(undo.can_undo(), 1);
    assert_eq!(undo.can_redo(), 0);

    // Verify change
    let read = buffer.read(0, 2).unwrap();
    assert_eq!(read, vec![0x41, 0x42]);

    // Undo
    undo.undo(&mut buffer).unwrap();
    let read = buffer.read(0, 2).unwrap();
    assert_eq!(read, vec![0x00, 0x00]);

    assert_eq!(undo.can_undo(), 0);
    assert_eq!(undo.can_redo(), 1);

    // Redo
    undo.redo(&mut buffer).unwrap();
    let read = buffer.read(0, 2).unwrap();
    assert_eq!(read, vec![0x41, 0x42]);
  }

  #[test]
  fn test_transaction() {
    let data = vec![0u8; 10];
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);
    let mut undo = UndoStack::new();

    // Begin transaction
    undo.begin_transaction("multi-write");

    buffer.write(0, &[0x41]).unwrap();
    undo.record_deltas(&mut buffer, "write 1");

    buffer.write(1, &[0x42]).unwrap();
    undo.record_deltas(&mut buffer, "write 2");

    undo.end_transaction();

    // Should count as one transaction
    assert_eq!(undo.can_undo(), 1);

    // Undo should revert both changes
    undo.undo(&mut buffer).unwrap();
    let read = buffer.read(0, 2).unwrap();
    assert_eq!(read, vec![0x00, 0x00]);
  }

  #[test]
  fn test_max_depth() {
    let data = vec![0u8; 100];
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);
    let mut undo = UndoStack::with_max_depth(3);

    // Make 5 changes
    for i in 0..5 {
      buffer.write(i as u64, &[i as u8]).unwrap();
      undo.record_deltas(&mut buffer, &format!("write {}", i));
    }

    // Should only keep last 3
    assert_eq!(undo.can_undo(), 3);
  }
}
