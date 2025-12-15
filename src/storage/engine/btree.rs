//! B+ Tree Implementation for Page-Based Storage
//!
//! A B+ tree optimized for disk I/O with the following properties:
//! - All values stored in leaf nodes
//! - Interior nodes only contain keys and child pointers
//! - Leaf nodes form a doubly-linked list for range scans
//! - Each node fits in a single 4KB page
//!
//! # Page Layout
//!
//! Interior Node:
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │ PageHeader (32 bytes)                                      │
//! ├────────────────────────────────────────────────────────────┤
//! │ right_child: u32 - Rightmost child pointer                 │
//! │ cells: [key_len: u16, key: [u8], child: u32]...           │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! Leaf Node:
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │ PageHeader (32 bytes)                                      │
//! ├────────────────────────────────────────────────────────────┤
//! │ prev_leaf: u32 - Previous leaf (0 = none)                  │
//! │ next_leaf: u32 - Next leaf (0 = none)                      │
//! │ cells: [key_len: u16, val_len: u16, key: [u8], val: [u8]] │
//! └────────────────────────────────────────────────────────────┘
//! ```

use std::cmp::Ordering;
use std::sync::{Arc, RwLock};

use super::page::{Page, PageType, HEADER_SIZE, PAGE_SIZE};
use super::pager::{Pager, PagerError};

/// Maximum key size (to ensure at least 2 keys per node)
pub const MAX_KEY_SIZE: usize = 1024;

/// Maximum value size for inline storage
pub const MAX_VALUE_SIZE: usize = 1024;

/// Minimum fill factor before merge (as percentage)
pub const MIN_FILL_FACTOR: usize = 25;

/// Offset of prev_leaf in leaf page
const LEAF_PREV_OFFSET: usize = HEADER_SIZE;

/// Offset of next_leaf in leaf page
const LEAF_NEXT_OFFSET: usize = HEADER_SIZE + 4;

/// Start of cell data in leaf pages
const LEAF_DATA_OFFSET: usize = HEADER_SIZE + 8;

/// Start of cell data in interior pages (right_child is in header)
const INTERIOR_DATA_OFFSET: usize = HEADER_SIZE;

/// B+ Tree error types
#[derive(Debug, Clone)]
pub enum BTreeError {
    /// Key not found
    NotFound,
    /// Key already exists
    DuplicateKey,
    /// Key too large
    KeyTooLarge(usize),
    /// Value too large
    ValueTooLarge(usize),
    /// Tree is corrupted
    Corrupted(String),
    /// Pager error
    Pager(String),
}

impl std::fmt::Display for BTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Key not found"),
            Self::DuplicateKey => write!(f, "Key already exists"),
            Self::KeyTooLarge(size) => {
                write!(f, "Key too large: {} bytes (max {})", size, MAX_KEY_SIZE)
            }
            Self::ValueTooLarge(size) => write!(
                f,
                "Value too large: {} bytes (max {})",
                size, MAX_VALUE_SIZE
            ),
            Self::Corrupted(msg) => write!(f, "B-tree corrupted: {}", msg),
            Self::Pager(msg) => write!(f, "Pager error: {}", msg),
        }
    }
}

impl std::error::Error for BTreeError {}

impl From<PagerError> for BTreeError {
    fn from(e: PagerError) -> Self {
        Self::Pager(e.to_string())
    }
}

impl From<super::page::PageError> for BTreeError {
    fn from(e: super::page::PageError) -> Self {
        Self::Corrupted(e.to_string())
    }
}

/// Result type for B+ tree operations
pub type BTreeResult<T> = Result<T, BTreeError>;

/// B+ Tree cursor for iteration
pub struct BTreeCursor {
    /// Current leaf page ID
    leaf_page_id: u32,
    /// Current position within leaf
    position: usize,
    /// Pager reference
    pager: Arc<Pager>,
}

impl BTreeCursor {
    /// Move to next entry
    pub fn next(&mut self) -> BTreeResult<Option<(Vec<u8>, Vec<u8>)>> {
        if self.leaf_page_id == 0 {
            return Ok(None);
        }

        let page = self.pager.read_page(self.leaf_page_id)?;
        let cell_count = page.cell_count() as usize;

        // Check if we have more cells in current page
        if self.position < cell_count {
            let (key, value) = read_leaf_cell(&page, self.position)?;
            self.position += 1;
            return Ok(Some((key, value)));
        }

        // Move to next leaf
        let next_leaf = read_next_leaf(&page);
        if next_leaf == 0 {
            self.leaf_page_id = 0;
            return Ok(None);
        }

        self.leaf_page_id = next_leaf;
        self.position = 0;

        // Read from new leaf
        let page = self.pager.read_page(self.leaf_page_id)?;
        if page.cell_count() == 0 {
            return Ok(None);
        }

        let (key, value) = read_leaf_cell(&page, 0)?;
        self.position = 1;
        Ok(Some((key, value)))
    }

    /// Peek at current entry without advancing
    pub fn peek(&self) -> BTreeResult<Option<(Vec<u8>, Vec<u8>)>> {
        if self.leaf_page_id == 0 {
            return Ok(None);
        }

        let page = self.pager.read_page(self.leaf_page_id)?;
        let cell_count = page.cell_count() as usize;

        if self.position >= cell_count {
            return Ok(None);
        }

        let (key, value) = read_leaf_cell(&page, self.position)?;
        Ok(Some((key, value)))
    }
}

/// B+ Tree implementation
pub struct BTree {
    /// Pager for page I/O
    pager: Arc<Pager>,
    /// Root page ID (0 = empty tree)
    root_page_id: RwLock<u32>,
}

impl BTree {
    /// Create a new B+ tree using the given pager
    pub fn new(pager: Arc<Pager>) -> Self {
        Self {
            pager,
            root_page_id: RwLock::new(0),
        }
    }

    /// Create a B+ tree with an existing root
    pub fn with_root(pager: Arc<Pager>, root_page_id: u32) -> Self {
        Self {
            pager,
            root_page_id: RwLock::new(root_page_id),
        }
    }

    /// Get the root page ID
    pub fn root_page_id(&self) -> u32 {
        *self.root_page_id.read().unwrap()
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.root_page_id() == 0
    }

    /// Get value for a key
    pub fn get(&self, key: &[u8]) -> BTreeResult<Option<Vec<u8>>> {
        let root_id = self.root_page_id();
        if root_id == 0 {
            return Ok(None);
        }

        // Find the leaf page
        let (leaf_id, _) = self.find_leaf(root_id, key)?;
        let page = self.pager.read_page(leaf_id)?;

        // Search within the leaf
        match search_leaf(&page, key)? {
            SearchResult::Found(pos) => {
                let (_, value) = read_leaf_cell(&page, pos)?;
                Ok(Some(value))
            }
            SearchResult::NotFound(_) => Ok(None),
        }
    }

    /// Insert a key-value pair
    pub fn insert(&self, key: &[u8], value: &[u8]) -> BTreeResult<()> {
        // Validate sizes
        if key.len() > MAX_KEY_SIZE {
            return Err(BTreeError::KeyTooLarge(key.len()));
        }
        if value.len() > MAX_VALUE_SIZE {
            return Err(BTreeError::ValueTooLarge(value.len()));
        }

        let mut root_id = self.root_page_id();

        // Empty tree - create root leaf
        if root_id == 0 {
            let mut page = self.pager.allocate_page(PageType::BTreeLeaf)?;
            write_leaf_cell(&mut page, 0, key, value)?;
            page.set_cell_count(1);
            init_leaf_links(&mut page, 0, 0);
            page.update_checksum();
            let new_root = page.page_id();
            self.pager.write_page(new_root, page)?;
            *self.root_page_id.write().unwrap() = new_root;
            return Ok(());
        }

        // Find the leaf and path to it
        let (leaf_id, path) = self.find_leaf(root_id, key)?;
        let mut page = self.pager.read_page(leaf_id)?;

        // Check for duplicate
        if let SearchResult::Found(_) = search_leaf(&page, key)? {
            return Err(BTreeError::DuplicateKey);
        }

        // Try to insert into leaf
        if can_insert_leaf(&page, key, value) {
            insert_into_leaf(&mut page, key, value)?;
            page.update_checksum();
            let page_id = page.page_id();
            self.pager.write_page(page_id, page)?;
            return Ok(());
        }

        // Need to split the leaf
        let (new_leaf, separator_key) = self.split_leaf(&mut page, key, value)?;
        page.update_checksum();
        let page_id = page.page_id();
        self.pager.write_page(page_id, page.clone())?;

        // Propagate split up the tree
        self.insert_into_parent(path, page.page_id(), &separator_key, new_leaf.page_id())?;

        Ok(())
    }

    /// Delete a key
    pub fn delete(&self, key: &[u8]) -> BTreeResult<bool> {
        let root_id = self.root_page_id();
        if root_id == 0 {
            return Ok(false);
        }

        let (leaf_id, _path) = self.find_leaf(root_id, key)?;
        let mut page = self.pager.read_page(leaf_id)?;

        // Find the key
        match search_leaf(&page, key)? {
            SearchResult::Found(pos) => {
                delete_from_leaf(&mut page, pos)?;
                page.update_checksum();
                let page_id = page.page_id();
                self.pager.write_page(page_id, page.clone())?;

                // Handle empty root
                if page.cell_count() == 0 && page.page_id() == root_id {
                    self.pager.free_page(root_id)?;
                    *self.root_page_id.write().unwrap() = 0;
                }

                // TODO: Implement merge/rebalance for underflow
                Ok(true)
            }
            SearchResult::NotFound(_) => Ok(false),
        }
    }

    /// Create a cursor starting at the first entry
    pub fn cursor_first(&self) -> BTreeResult<BTreeCursor> {
        let root_id = self.root_page_id();
        if root_id == 0 {
            return Ok(BTreeCursor {
                leaf_page_id: 0,
                position: 0,
                pager: self.pager.clone(),
            });
        }

        // Find leftmost leaf
        let first_leaf = self.find_first_leaf(root_id)?;

        Ok(BTreeCursor {
            leaf_page_id: first_leaf,
            position: 0,
            pager: self.pager.clone(),
        })
    }

    /// Create a cursor starting at or after the given key
    pub fn cursor_seek(&self, key: &[u8]) -> BTreeResult<BTreeCursor> {
        let root_id = self.root_page_id();
        if root_id == 0 {
            return Ok(BTreeCursor {
                leaf_page_id: 0,
                position: 0,
                pager: self.pager.clone(),
            });
        }

        let (leaf_id, _) = self.find_leaf(root_id, key)?;
        let page = self.pager.read_page(leaf_id)?;

        let position = match search_leaf(&page, key)? {
            SearchResult::Found(pos) => pos,
            SearchResult::NotFound(pos) => pos,
        };

        Ok(BTreeCursor {
            leaf_page_id: leaf_id,
            position,
            pager: self.pager.clone(),
        })
    }

    /// Range scan from start_key to end_key (inclusive)
    pub fn range(&self, start_key: &[u8], end_key: &[u8]) -> BTreeResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut results = Vec::new();
        let mut cursor = self.cursor_seek(start_key)?;

        while let Some((key, value)) = cursor.next()? {
            if key.as_slice() > end_key {
                break;
            }
            results.push((key, value));
        }

        Ok(results)
    }

    /// Count entries in the tree
    pub fn count(&self) -> BTreeResult<usize> {
        let root_id = self.root_page_id();
        if root_id == 0 {
            return Ok(0);
        }

        let mut count = 0;
        let mut cursor = self.cursor_first()?;
        while cursor.next()?.is_some() {
            count += 1;
        }

        Ok(count)
    }

    // ==================== Internal Methods ====================

    /// Find the leaf page containing the key
    fn find_leaf(&self, page_id: u32, key: &[u8]) -> BTreeResult<(u32, Vec<u32>)> {
        let mut current_id = page_id;
        let mut path = Vec::new();

        loop {
            let page = self.pager.read_page(current_id)?;

            match page.page_type()? {
                PageType::BTreeLeaf => {
                    return Ok((current_id, path));
                }
                PageType::BTreeInterior => {
                    path.push(current_id);
                    current_id = find_child(&page, key)?;
                }
                other => {
                    return Err(BTreeError::Corrupted(format!(
                        "Unexpected page type in B-tree: {:?}",
                        other
                    )));
                }
            }
        }
    }

    /// Find the leftmost leaf page
    fn find_first_leaf(&self, page_id: u32) -> BTreeResult<u32> {
        let mut current_id = page_id;

        loop {
            let page = self.pager.read_page(current_id)?;

            match page.page_type()? {
                PageType::BTreeLeaf => return Ok(current_id),
                PageType::BTreeInterior => {
                    // Go to leftmost child
                    current_id = find_first_child(&page)?;
                }
                _ => {
                    return Err(BTreeError::Corrupted("Invalid page type".into()));
                }
            }
        }
    }

    /// Split a leaf page
    fn split_leaf(
        &self,
        page: &mut Page,
        new_key: &[u8],
        new_value: &[u8],
    ) -> BTreeResult<(Page, Vec<u8>)> {
        // Collect all entries including the new one
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let cell_count = page.cell_count() as usize;

        for i in 0..cell_count {
            entries.push(read_leaf_cell(page, i)?);
        }

        // Insert new entry in sorted position
        let insert_pos = entries.partition_point(|(k, _)| k.as_slice() < new_key);
        entries.insert(insert_pos, (new_key.to_vec(), new_value.to_vec()));

        // Split in half
        let mid = entries.len() / 2;

        // Create new leaf
        let mut new_page = self.pager.allocate_page(PageType::BTreeLeaf)?;

        // Update leaf links
        let old_next = read_next_leaf(page);
        init_leaf_links(&mut new_page, page.page_id(), old_next);
        set_next_leaf(page, new_page.page_id());

        // Write entries to old page
        clear_leaf_cells(page);
        for (i, (k, v)) in entries[..mid].iter().enumerate() {
            write_leaf_cell(page, i, k, v)?;
        }
        page.set_cell_count(mid as u16);

        // Write entries to new page
        for (i, (k, v)) in entries[mid..].iter().enumerate() {
            write_leaf_cell(&mut new_page, i, k, v)?;
        }
        new_page.set_cell_count((entries.len() - mid) as u16);

        // Separator is first key of new leaf
        let separator = entries[mid].0.clone();

        new_page.update_checksum();
        let new_page_id = new_page.page_id();
        self.pager.write_page(new_page_id, new_page.clone())?;

        Ok((new_page, separator))
    }

    /// Insert into parent after split
    fn insert_into_parent(
        &self,
        mut path: Vec<u32>,
        left_child: u32,
        key: &[u8],
        right_child: u32,
    ) -> BTreeResult<()> {
        // If path is empty, need new root
        if path.is_empty() {
            let mut new_root = self.pager.allocate_page(PageType::BTreeInterior)?;

            // Set right_child in header
            new_root.set_right_child(right_child);

            // Write the single key/child cell
            write_interior_cell(&mut new_root, 0, key, left_child)?;
            new_root.set_cell_count(1);

            new_root.update_checksum();
            let new_root_id = new_root.page_id();
            self.pager.write_page(new_root_id, new_root)?;
            *self.root_page_id.write().unwrap() = new_root_id;
            return Ok(());
        }

        // Insert into parent
        let parent_id = path.pop().unwrap();
        let mut parent = self.pager.read_page(parent_id)?;

        // Can we fit?
        if can_insert_interior(&parent, key) {
            insert_into_interior(&mut parent, key, left_child, right_child)?;
            parent.update_checksum();
            self.pager.write_page(parent_id, parent)?;
            return Ok(());
        }

        // Need to split interior node
        let (new_interior, separator) =
            self.split_interior(&mut parent, key, left_child, right_child)?;
        parent.update_checksum();
        self.pager.write_page(parent_id, parent.clone())?;

        // Propagate up
        self.insert_into_parent(path, parent.page_id(), &separator, new_interior.page_id())
    }

    /// Split an interior node
    fn split_interior(
        &self,
        page: &mut Page,
        new_key: &[u8],
        left_child: u32,
        right_child: u32,
    ) -> BTreeResult<(Page, Vec<u8>)> {
        // Collect all entries
        let mut entries: Vec<(Vec<u8>, u32)> = Vec::new();
        let cell_count = page.cell_count() as usize;

        for i in 0..cell_count {
            entries.push(read_interior_cell(page, i)?);
        }

        // Insert new entry
        let insert_pos = entries.partition_point(|(k, _)| k.as_slice() < new_key);

        // Update children around insertion point
        if insert_pos < entries.len() {
            entries[insert_pos].1 = left_child;
        }
        entries.insert(insert_pos, (new_key.to_vec(), left_child));

        // The key at mid goes up, not into either node
        let mid = entries.len() / 2;
        let separator = entries[mid].0.clone();

        // Create new interior node
        let mut new_page = self.pager.allocate_page(PageType::BTreeInterior)?;

        // Left node gets entries before mid
        clear_interior_cells(page);
        for (i, (k, c)) in entries[..mid].iter().enumerate() {
            write_interior_cell(page, i, k, *c)?;
        }
        page.set_cell_count(mid as u16);
        page.set_right_child(entries[mid].1);

        // Right node gets entries after mid
        for (i, (k, c)) in entries[mid + 1..].iter().enumerate() {
            write_interior_cell(&mut new_page, i, k, *c)?;
        }
        new_page.set_cell_count((entries.len() - mid - 1) as u16);
        new_page.set_right_child(right_child);

        new_page.update_checksum();
        let new_page_id = new_page.page_id();
        self.pager.write_page(new_page_id, new_page.clone())?;

        Ok((new_page, separator))
    }
}

// ==================== Search Helpers ====================

enum SearchResult {
    Found(usize),
    NotFound(usize),
}

fn search_leaf(page: &Page, key: &[u8]) -> BTreeResult<SearchResult> {
    let cell_count = page.cell_count() as usize;

    // Binary search
    let mut low = 0;
    let mut high = cell_count;

    while low < high {
        let mid = (low + high) / 2;
        let (cell_key, _) = read_leaf_cell(page, mid)?;

        match cell_key.as_slice().cmp(key) {
            Ordering::Less => low = mid + 1,
            Ordering::Greater => high = mid,
            Ordering::Equal => return Ok(SearchResult::Found(mid)),
        }
    }

    Ok(SearchResult::NotFound(low))
}

fn find_child(page: &Page, key: &[u8]) -> BTreeResult<u32> {
    let cell_count = page.cell_count() as usize;

    // Binary search for the correct child
    for i in 0..cell_count {
        let (cell_key, child) = read_interior_cell(page, i)?;
        if key < cell_key.as_slice() {
            return Ok(child);
        }
    }

    // Key is >= all keys, use right child
    Ok(page.right_child())
}

fn find_first_child(page: &Page) -> BTreeResult<u32> {
    if page.cell_count() == 0 {
        return Ok(page.right_child());
    }
    let (_, child) = read_interior_cell(page, 0)?;
    Ok(child)
}

// ==================== Leaf Page Helpers ====================

fn read_leaf_cell(page: &Page, index: usize) -> BTreeResult<(Vec<u8>, Vec<u8>)> {
    let data = page.as_bytes();
    let cell_count = page.cell_count() as usize;

    if index >= cell_count {
        return Err(BTreeError::Corrupted("Cell index out of range".into()));
    }

    // Find cell offset by scanning from start
    let mut offset = LEAF_DATA_OFFSET;
    for _ in 0..index {
        let key_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let val_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4 + key_len + val_len;
    }

    let key_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let val_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

    let key = data[offset + 4..offset + 4 + key_len].to_vec();
    let value = data[offset + 4 + key_len..offset + 4 + key_len + val_len].to_vec();

    Ok((key, value))
}

fn write_leaf_cell(page: &mut Page, index: usize, key: &[u8], value: &[u8]) -> BTreeResult<()> {
    let data = page.as_bytes_mut();

    // Find cell offset by scanning from start
    let mut offset = LEAF_DATA_OFFSET;
    for _ in 0..index {
        let key_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let val_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4 + key_len + val_len;
    }

    // Write lengths
    data[offset..offset + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    data[offset + 2..offset + 4].copy_from_slice(&(value.len() as u16).to_le_bytes());

    // Write key and value
    data[offset + 4..offset + 4 + key.len()].copy_from_slice(key);
    data[offset + 4 + key.len()..offset + 4 + key.len() + value.len()].copy_from_slice(value);

    Ok(())
}

fn can_insert_leaf(page: &Page, key: &[u8], value: &[u8]) -> bool {
    let data = page.as_bytes();
    let cell_count = page.cell_count() as usize;

    // Calculate current used space
    let mut offset = LEAF_DATA_OFFSET;
    for _ in 0..cell_count {
        let key_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let val_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4 + key_len + val_len;
    }

    // Check if new cell fits
    let needed = 4 + key.len() + value.len();
    offset + needed <= PAGE_SIZE
}

fn insert_into_leaf(page: &mut Page, key: &[u8], value: &[u8]) -> BTreeResult<()> {
    let cell_count = page.cell_count() as usize;

    // Find insertion position
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(cell_count + 1);
    for i in 0..cell_count {
        entries.push(read_leaf_cell(page, i)?);
    }

    let insert_pos = entries.partition_point(|(k, _)| k.as_slice() < key);
    entries.insert(insert_pos, (key.to_vec(), value.to_vec()));

    // Rewrite all cells
    clear_leaf_cells(page);
    for (i, (k, v)) in entries.iter().enumerate() {
        write_leaf_cell(page, i, k, v)?;
    }
    page.set_cell_count(entries.len() as u16);

    Ok(())
}

fn delete_from_leaf(page: &mut Page, index: usize) -> BTreeResult<()> {
    let cell_count = page.cell_count() as usize;

    // Read all cells except the deleted one
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(cell_count - 1);
    for i in 0..cell_count {
        if i != index {
            entries.push(read_leaf_cell(page, i)?);
        }
    }

    // Rewrite cells
    clear_leaf_cells(page);
    for (i, (k, v)) in entries.iter().enumerate() {
        write_leaf_cell(page, i, k, v)?;
    }
    page.set_cell_count(entries.len() as u16);

    Ok(())
}

fn clear_leaf_cells(page: &mut Page) {
    let data = page.as_bytes_mut();
    // Zero out cell data area
    for byte in &mut data[LEAF_DATA_OFFSET..] {
        *byte = 0;
    }
}

fn init_leaf_links(page: &mut Page, prev: u32, next: u32) {
    let data = page.as_bytes_mut();
    data[LEAF_PREV_OFFSET..LEAF_PREV_OFFSET + 4].copy_from_slice(&prev.to_le_bytes());
    data[LEAF_NEXT_OFFSET..LEAF_NEXT_OFFSET + 4].copy_from_slice(&next.to_le_bytes());
}

fn read_next_leaf(page: &Page) -> u32 {
    let data = page.as_bytes();
    u32::from_le_bytes([
        data[LEAF_NEXT_OFFSET],
        data[LEAF_NEXT_OFFSET + 1],
        data[LEAF_NEXT_OFFSET + 2],
        data[LEAF_NEXT_OFFSET + 3],
    ])
}

fn set_next_leaf(page: &mut Page, next: u32) {
    let data = page.as_bytes_mut();
    data[LEAF_NEXT_OFFSET..LEAF_NEXT_OFFSET + 4].copy_from_slice(&next.to_le_bytes());
}

// ==================== Interior Page Helpers ====================

fn read_interior_cell(page: &Page, index: usize) -> BTreeResult<(Vec<u8>, u32)> {
    let data = page.as_bytes();
    let cell_count = page.cell_count() as usize;

    if index >= cell_count {
        return Err(BTreeError::Corrupted("Cell index out of range".into()));
    }

    // Find cell offset by scanning from start
    let mut offset = INTERIOR_DATA_OFFSET;
    for _ in 0..index {
        let key_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + key_len + 4; // key_len + key + child
    }

    let key_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let key = data[offset + 2..offset + 2 + key_len].to_vec();
    let child = u32::from_le_bytes([
        data[offset + 2 + key_len],
        data[offset + 2 + key_len + 1],
        data[offset + 2 + key_len + 2],
        data[offset + 2 + key_len + 3],
    ]);

    Ok((key, child))
}

fn write_interior_cell(page: &mut Page, index: usize, key: &[u8], child: u32) -> BTreeResult<()> {
    let data = page.as_bytes_mut();

    // Find cell offset by scanning from start
    let mut offset = INTERIOR_DATA_OFFSET;
    for _ in 0..index {
        let key_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + key_len + 4;
    }

    // Write key length
    data[offset..offset + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());

    // Write key
    data[offset + 2..offset + 2 + key.len()].copy_from_slice(key);

    // Write child pointer
    data[offset + 2 + key.len()..offset + 2 + key.len() + 4].copy_from_slice(&child.to_le_bytes());

    Ok(())
}

fn can_insert_interior(page: &Page, key: &[u8]) -> bool {
    let data = page.as_bytes();
    let cell_count = page.cell_count() as usize;

    // Calculate current used space
    let mut offset = INTERIOR_DATA_OFFSET;
    for _ in 0..cell_count {
        let key_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + key_len + 4;
    }

    // Check if new cell fits
    let needed = 2 + key.len() + 4;
    offset + needed <= PAGE_SIZE
}

fn insert_into_interior(
    page: &mut Page,
    key: &[u8],
    left_child: u32,
    right_child: u32,
) -> BTreeResult<()> {
    let cell_count = page.cell_count() as usize;

    // Read all cells
    let mut entries: Vec<(Vec<u8>, u32)> = Vec::with_capacity(cell_count + 1);
    for i in 0..cell_count {
        entries.push(read_interior_cell(page, i)?);
    }

    // Find insertion position
    let insert_pos = entries.partition_point(|(k, _)| k.as_slice() < key);

    // Update child pointer for the key we're displacing
    if insert_pos < entries.len() {
        entries[insert_pos].1 = right_child;
    } else {
        // New key is largest, update right_child
        page.set_right_child(right_child);
    }

    // Insert new entry
    entries.insert(insert_pos, (key.to_vec(), left_child));

    // Rewrite all cells
    clear_interior_cells(page);
    for (i, (k, c)) in entries.iter().enumerate() {
        write_interior_cell(page, i, k, *c)?;
    }
    page.set_cell_count(entries.len() as u16);

    Ok(())
}

fn clear_interior_cells(page: &mut Page) {
    let data = page.as_bytes_mut();
    for byte in &mut data[INTERIOR_DATA_OFFSET..] {
        *byte = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_db_path() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("reddb_btree_test_{}_{}.db", std::process::id(), id));
        path
    }

    fn cleanup(path: &PathBuf) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_btree_empty() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        assert!(tree.is_empty());
        assert_eq!(tree.root_page_id(), 0);
        assert_eq!(tree.get(b"key").unwrap(), None);
        assert_eq!(tree.count().unwrap(), 0);

        cleanup(&path);
    }

    #[test]
    fn test_btree_single_insert() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        tree.insert(b"hello", b"world").unwrap();

        assert!(!tree.is_empty());
        assert_eq!(tree.get(b"hello").unwrap(), Some(b"world".to_vec()));
        assert_eq!(tree.get(b"other").unwrap(), None);
        assert_eq!(tree.count().unwrap(), 1);

        cleanup(&path);
    }

    #[test]
    fn test_btree_multiple_inserts() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        tree.insert(b"c", b"3").unwrap();
        tree.insert(b"a", b"1").unwrap();
        tree.insert(b"b", b"2").unwrap();

        assert_eq!(tree.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(tree.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(tree.get(b"c").unwrap(), Some(b"3".to_vec()));
        assert_eq!(tree.count().unwrap(), 3);

        cleanup(&path);
    }

    #[test]
    fn test_btree_duplicate_key() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        tree.insert(b"key", b"value1").unwrap();
        let result = tree.insert(b"key", b"value2");

        assert!(matches!(result, Err(BTreeError::DuplicateKey)));
        assert_eq!(tree.get(b"key").unwrap(), Some(b"value1".to_vec()));

        cleanup(&path);
    }

    #[test]
    fn test_btree_delete() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        tree.insert(b"a", b"1").unwrap();
        tree.insert(b"b", b"2").unwrap();
        tree.insert(b"c", b"3").unwrap();

        assert!(tree.delete(b"b").unwrap());
        assert!(!tree.delete(b"d").unwrap());

        assert_eq!(tree.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(tree.get(b"b").unwrap(), None);
        assert_eq!(tree.get(b"c").unwrap(), Some(b"3".to_vec()));
        assert_eq!(tree.count().unwrap(), 2);

        cleanup(&path);
    }

    #[test]
    fn test_btree_cursor() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        tree.insert(b"c", b"3").unwrap();
        tree.insert(b"a", b"1").unwrap();
        tree.insert(b"b", b"2").unwrap();

        let mut cursor = tree.cursor_first().unwrap();
        let mut results: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        while let Some(entry) = cursor.next().unwrap() {
            results.push(entry);
        }

        assert_eq!(results.len(), 3);
        assert_eq!(results[0], (b"a".to_vec(), b"1".to_vec()));
        assert_eq!(results[1], (b"b".to_vec(), b"2".to_vec()));
        assert_eq!(results[2], (b"c".to_vec(), b"3".to_vec()));

        cleanup(&path);
    }

    #[test]
    fn test_btree_range() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        for i in 0..10u8 {
            let key = format!("key{:02}", i);
            let value = format!("val{:02}", i);
            tree.insert(key.as_bytes(), value.as_bytes()).unwrap();
        }

        let results = tree.range(b"key03", b"key06").unwrap();

        assert_eq!(results.len(), 4);
        assert_eq!(results[0].0, b"key03".to_vec());
        assert_eq!(results[3].0, b"key06".to_vec());

        cleanup(&path);
    }

    #[test]
    fn test_btree_large_keys() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        let key = vec![b'x'; 500];
        let value = vec![b'y'; 500];

        tree.insert(&key, &value).unwrap();
        assert_eq!(tree.get(&key).unwrap(), Some(value));

        cleanup(&path);
    }

    #[test]
    fn test_btree_key_too_large() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        let key = vec![b'x'; MAX_KEY_SIZE + 1];
        let result = tree.insert(&key, b"value");

        assert!(matches!(result, Err(BTreeError::KeyTooLarge(_))));

        cleanup(&path);
    }

    #[test]
    fn test_btree_many_inserts() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        // Insert enough entries to force splits
        for i in 0..100u32 {
            let key = format!("key{:08}", i);
            let value = format!("value{:08}", i);
            tree.insert(key.as_bytes(), value.as_bytes()).unwrap();
        }

        // Verify all entries
        for i in 0..100u32 {
            let key = format!("key{:08}", i);
            let expected = format!("value{:08}", i);
            assert_eq!(
                tree.get(key.as_bytes()).unwrap(),
                Some(expected.into_bytes())
            );
        }

        assert_eq!(tree.count().unwrap(), 100);

        cleanup(&path);
    }

    #[test]
    fn test_btree_sorted_iteration() {
        let path = temp_db_path();
        cleanup(&path);

        let pager = Arc::new(Pager::open_default(&path).unwrap());
        let tree = BTree::new(pager);

        // Insert in random order
        let keys = vec![50, 25, 75, 10, 30, 60, 80, 5, 15, 27, 35, 55, 65, 77, 90];
        for k in &keys {
            let key = format!("{:03}", k);
            tree.insert(key.as_bytes(), key.as_bytes()).unwrap();
        }

        // Should iterate in sorted order
        let mut cursor = tree.cursor_first().unwrap();
        let mut prev: Option<Vec<u8>> = None;

        while let Some((key, _)) = cursor.next().unwrap() {
            if let Some(p) = &prev {
                assert!(p < &key, "Keys not in sorted order");
            }
            prev = Some(key);
        }

        cleanup(&path);
    }
}
