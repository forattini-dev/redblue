//! RedDB Storage Engine
//!
//! A page-based storage engine inspired by SQLite/Turso architecture.
//! Implements 4KB aligned pages for efficient disk I/O with SIEVE caching.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                       Database API                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                       B-Tree Engine                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Page Cache (SIEVE)  │     Pager (I/O)     │   Free List   │
//! ├─────────────────────────────────────────────────────────────┤
//! │                     Page Structure                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   File System / WAL                         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # References
//!
//! - Turso `core/storage/pager.rs` - Page I/O management
//! - Turso `core/storage/page_cache.rs` - SIEVE eviction algorithm
//! - Turso `core/storage/btree.rs` - B-tree page layout

pub mod page;
pub mod pager;
pub mod page_cache;
pub mod freelist;
pub mod crc32;
pub mod btree;
pub mod database;

#[path = "encrypted-pager.rs"]
pub mod encrypted_pager;

pub use page::{Page, PageType, PageHeader, PAGE_SIZE, HEADER_SIZE};
pub use pager::{Pager, PagerConfig};
pub use page_cache::PageCache;
pub use freelist::FreeList;
pub use crc32::crc32;
pub use btree::{BTree, BTreeCursor, BTreeError};
pub use database::{Database, DatabaseConfig, DatabaseError};
pub use encrypted_pager::{EncryptedPager, EncryptedPagerConfig, EncryptedPagerError};
