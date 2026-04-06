//! Paginated buffer with lazy loading and LRU caching
//!
//! Provides efficient handling of large files by loading pages on demand
//! and evicting least-recently-used pages when memory is constrained.

use super::source::{DataSource, SourceError, SourceResult};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Page size (4KB aligned to system page size)
pub const PAGE_SIZE: usize = 4096;

/// Default maximum cached pages (1MB cache)
pub const DEFAULT_MAX_PAGES: usize = 256;

/// A single page of data
#[derive(Clone)]
pub struct Page {
  /// Page index (offset / PAGE_SIZE)
  pub index: usize,

  /// Page data (may be partial for last page)
  pub data: Vec<u8>,

  /// True if page has been modified
  pub dirty: bool,

  /// Last access timestamp (for LRU)
  last_access: u64,
}

impl Page {
  fn new(index: usize, data: Vec<u8>) -> Self {
    Self {
      index,
      data,
      dirty: false,
      last_access: Self::now(),
    }
  }

  fn touch(&mut self) {
    self.last_access = Self::now();
  }

  fn now() -> u64 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map(|d| d.as_micros() as u64)
      .unwrap_or(0)
  }
}

/// Delta tracking for modifications
#[derive(Clone, Debug)]
pub struct Delta {
  /// Absolute offset in source
  pub offset: u64,

  /// Original bytes (for undo)
  pub old_bytes: Vec<u8>,

  /// New bytes (for redo)
  pub new_bytes: Vec<u8>,
}

/// Paginated buffer with lazy loading and delta tracking
pub struct PagedBuffer {
  /// Data source
  source: Box<dyn DataSource>,

  /// Total size in bytes
  size: u64,

  /// Loaded pages (LRU cache)
  pages: HashMap<usize, Page>,

  /// Access order for LRU eviction
  access_order: VecDeque<usize>,

  /// Maximum pages to cache
  max_pages: usize,

  /// Pending deltas for undo tracking
  pending_deltas: Vec<Delta>,
}

impl PagedBuffer {
  /// Create a new paged buffer from a data source
  pub fn new(source: Box<dyn DataSource>) -> Self {
    let size = source.size();
    Self {
      source,
      size,
      pages: HashMap::new(),
      access_order: VecDeque::new(),
      max_pages: DEFAULT_MAX_PAGES,
      pending_deltas: Vec::new(),
    }
  }

  /// Create with custom max pages
  pub fn with_max_pages(source: Box<dyn DataSource>, max_pages: usize) -> Self {
    let size = source.size();
    Self {
      source,
      size,
      pages: HashMap::new(),
      access_order: VecDeque::new(),
      max_pages,
      pending_deltas: Vec::new(),
    }
  }

  /// Get total size
  pub fn size(&self) -> u64 {
    self.size
  }

  /// Check if source is writable
  pub fn is_writable(&self) -> bool {
    self.source.is_writable()
  }

  /// Get source description
  pub fn description(&self) -> String {
    self.source.description()
  }

  /// Read bytes at offset
  pub fn read(&mut self, offset: u64, len: usize) -> SourceResult<Vec<u8>> {
    if offset >= self.size {
      return Ok(Vec::new());
    }

    let actual_len = len.min((self.size - offset) as usize);
    let mut result = Vec::with_capacity(actual_len);

    let mut remaining = actual_len;
    let mut current_offset = offset;

    while remaining > 0 {
      let page_idx = (current_offset / PAGE_SIZE as u64) as usize;
      let page_offset = (current_offset % PAGE_SIZE as u64) as usize;

      let page = self.load_page(page_idx)?;
      let available = page.data.len().saturating_sub(page_offset);
      let to_copy = remaining.min(available);

      if to_copy == 0 {
        break;
      }

      result.extend_from_slice(&page.data[page_offset..page_offset + to_copy]);
      remaining -= to_copy;
      current_offset += to_copy as u64;
    }

    Ok(result)
  }

  /// Write bytes at offset (with delta tracking)
  pub fn write(&mut self, offset: u64, data: &[u8]) -> SourceResult<()> {
    if !self.source.is_writable() {
      return Err(SourceError::ReadOnly);
    }

    // Read old bytes for delta tracking
    let old_bytes = self.read(offset, data.len())?;

    // Extend size if needed
    let new_end = offset + data.len() as u64;
    if new_end > self.size {
      self.size = new_end;
    }

    // Write to pages
    let mut remaining = data.len();
    let mut data_offset = 0;
    let mut current_offset = offset;

    while remaining > 0 {
      let page_idx = (current_offset / PAGE_SIZE as u64) as usize;
      let page_offset = (current_offset % PAGE_SIZE as u64) as usize;

      // Calculate how much to write to this page
      let available = PAGE_SIZE - page_offset;
      let to_write = remaining.min(available);

      // Load or create page
      self.ensure_page(page_idx)?;

      if let Some(page) = self.pages.get_mut(&page_idx) {
        // Extend page if needed
        let needed = page_offset + to_write;
        if page.data.len() < needed {
          page.data.resize(needed, 0);
        }

        page.data[page_offset..page_offset + to_write]
          .copy_from_slice(&data[data_offset..data_offset + to_write]);
        page.dirty = true;
        page.touch();
      }

      remaining -= to_write;
      data_offset += to_write;
      current_offset += to_write as u64;
    }

    // Track delta
    self.pending_deltas.push(Delta {
      offset,
      old_bytes,
      new_bytes: data.to_vec(),
    });

    Ok(())
  }

  /// Write without delta tracking (for undo/redo operations)
  pub fn write_raw(&mut self, offset: u64, data: &[u8]) -> SourceResult<()> {
    if !self.source.is_writable() {
      return Err(SourceError::ReadOnly);
    }

    let new_end = offset + data.len() as u64;
    if new_end > self.size {
      self.size = new_end;
    }

    let mut remaining = data.len();
    let mut data_offset = 0;
    let mut current_offset = offset;

    while remaining > 0 {
      let page_idx = (current_offset / PAGE_SIZE as u64) as usize;
      let page_offset = (current_offset % PAGE_SIZE as u64) as usize;

      let available = PAGE_SIZE - page_offset;
      let to_write = remaining.min(available);

      self.ensure_page(page_idx)?;

      if let Some(page) = self.pages.get_mut(&page_idx) {
        let needed = page_offset + to_write;
        if page.data.len() < needed {
          page.data.resize(needed, 0);
        }

        page.data[page_offset..page_offset + to_write]
          .copy_from_slice(&data[data_offset..data_offset + to_write]);
        page.dirty = true;
        page.touch();
      }

      remaining -= to_write;
      data_offset += to_write;
      current_offset += to_write as u64;
    }

    Ok(())
  }

  /// Take pending deltas (transfers ownership)
  pub fn take_deltas(&mut self) -> Vec<Delta> {
    std::mem::take(&mut self.pending_deltas)
  }

  /// Flush all dirty pages to source
  pub fn flush(&mut self) -> SourceResult<()> {
    let dirty_pages: Vec<usize> = self
      .pages
      .iter()
      .filter(|(_, p)| p.dirty)
      .map(|(idx, _)| *idx)
      .collect();

    for page_idx in dirty_pages {
      if let Some(page) = self.pages.get_mut(&page_idx) {
        let offset = (page_idx * PAGE_SIZE) as u64;
        self.source.write(offset, &page.data)?;
        page.dirty = false;
      }
    }

    self.source.flush()
  }

  /// Check if there are unsaved changes
  pub fn has_changes(&self) -> bool {
    self.pages.values().any(|p| p.dirty)
  }

  /// Get count of dirty pages
  pub fn dirty_count(&self) -> usize {
    self.pages.values().filter(|p| p.dirty).count()
  }

  /// Get count of cached pages
  pub fn cached_count(&self) -> usize {
    self.pages.len()
  }

  /// Load a page (with LRU eviction)
  fn load_page(&mut self, page_idx: usize) -> SourceResult<&Page> {
    if !self.pages.contains_key(&page_idx) {
      // Evict if necessary
      self.maybe_evict();

      // Load page from source
      let offset = (page_idx * PAGE_SIZE) as u64;
      let len = PAGE_SIZE.min((self.source.size() - offset.min(self.source.size())) as usize);

      if len == 0 {
        // Past end of source, create empty page
        let page = Page::new(page_idx, Vec::new());
        self.pages.insert(page_idx, page);
      } else {
        let data = self.source.read(offset, len)?;
        let page = Page::new(page_idx, data);
        self.pages.insert(page_idx, page);
      }

      // Update access order
      self.access_order.push_back(page_idx);
    } else {
      // Update access order
      self.update_access_order(page_idx);
      if let Some(page) = self.pages.get_mut(&page_idx) {
        page.touch();
      }
    }

    Ok(self.pages.get(&page_idx).unwrap())
  }

  /// Ensure page exists (creates if needed)
  fn ensure_page(&mut self, page_idx: usize) -> SourceResult<()> {
    if !self.pages.contains_key(&page_idx) {
      self.maybe_evict();

      let offset = (page_idx * PAGE_SIZE) as u64;
      let len = if offset < self.source.size() {
        PAGE_SIZE.min((self.source.size() - offset) as usize)
      } else {
        0
      };

      let data = if len > 0 {
        self.source.read(offset, len)?
      } else {
        Vec::new()
      };

      let page = Page::new(page_idx, data);
      self.pages.insert(page_idx, page);
      self.access_order.push_back(page_idx);
    }

    Ok(())
  }

  /// Evict LRU page if at capacity
  fn maybe_evict(&mut self) {
    while self.pages.len() >= self.max_pages {
      // Find a clean page to evict (prefer clean over dirty)
      let to_evict = self
        .access_order
        .iter()
        .find(|idx| self.pages.get(*idx).map(|p| !p.dirty).unwrap_or(false))
        .copied();

      if let Some(idx) = to_evict {
        self.pages.remove(&idx);
        self.access_order.retain(|&x| x != idx);
      } else {
        // All pages are dirty, flush and evict oldest
        if let Some(idx) = self.access_order.pop_front() {
          if let Some(page) = self.pages.remove(&idx) {
            if page.dirty {
              let offset = (idx * PAGE_SIZE) as u64;
              let _ = self.source.write(offset, &page.data);
            }
          }
        }
      }
    }
  }

  /// Update access order (move to back)
  fn update_access_order(&mut self, page_idx: usize) {
    self.access_order.retain(|&x| x != page_idx);
    self.access_order.push_back(page_idx);
  }
}

#[cfg(test)]
mod tests {
  use super::super::source::BufferSource;
  use super::*;

  #[test]
  fn test_basic_read_write() {
    let data = vec![0u8; 100];
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);

    // Write some data
    buffer.write(10, &[0x41, 0x42, 0x43]).unwrap();

    // Read it back
    let read = buffer.read(10, 3).unwrap();
    assert_eq!(read, vec![0x41, 0x42, 0x43]);
  }

  #[test]
  fn test_cross_page_read() {
    let data = vec![0x41u8; PAGE_SIZE * 2];
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);

    // Read across page boundary
    let read = buffer.read((PAGE_SIZE - 2) as u64, 4).unwrap();
    assert_eq!(read.len(), 4);
  }

  #[test]
  fn test_delta_tracking() {
    let data = vec![0x00u8; 100];
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);

    buffer.write(0, &[0x41, 0x42]).unwrap();
    buffer.write(10, &[0x43, 0x44]).unwrap();

    let deltas = buffer.take_deltas();
    assert_eq!(deltas.len(), 2);
    assert_eq!(deltas[0].offset, 0);
    assert_eq!(deltas[0].new_bytes, vec![0x41, 0x42]);
    assert_eq!(deltas[1].offset, 10);
  }
}
