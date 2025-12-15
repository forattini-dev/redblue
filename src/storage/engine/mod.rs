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

pub mod btree;
pub mod crc32;
pub mod database;
pub mod freelist;
pub mod page;
pub mod page_cache;
pub mod pager;

#[path = "encrypted-pager.rs"]
pub mod encrypted_pager;

pub use btree::{BTree, BTreeCursor, BTreeError};
pub use crc32::crc32;
pub use database::{Database, DatabaseConfig, DatabaseError};
pub use encrypted_pager::{EncryptedPager, EncryptedPagerConfig, EncryptedPagerError};
pub use freelist::FreeList;
pub use page::{Page, PageHeader, PageType, HEADER_SIZE, PAGE_SIZE};
pub use page_cache::PageCache;
pub use pager::{Pager, PagerConfig};
