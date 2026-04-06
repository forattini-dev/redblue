//! Memory inspection and manipulation module
//!
//! Provides Cheat Engine-like functionality for process memory analysis:
//! - Process attachment via ptrace
//! - Memory reading/writing
//! - Value scanning (exact, range, changed/unchanged)
//! - Pattern/AOB (Array of Bytes) scanning
//! - Memory region enumeration
//!
//! # Example
//! ```rust,ignore
//! use redblue::modules::memory::{ProcessMemory, Scanner, ValueType};
//!
//! let mut proc = ProcessMemory::attach(1234)?;
//! let regions = proc.memory_regions()?;
//!
//! let mut scanner = Scanner::new(&proc);
//! let results = scanner.scan_exact(100i32, &regions)?;
//! ```
//!
//! # Security Note
//! This module requires appropriate permissions (CAP_SYS_PTRACE or root).
//! Use only on processes you own or have authorization to inspect.

pub mod maps;
pub mod pattern;
pub mod process;
pub mod scanner;

// Hex editor infrastructure
pub mod buffer;
pub mod search;
pub mod source;
pub mod types;
pub mod undo;
pub mod view;

pub use maps::{parse_maps, MemoryPermissions, MemoryRegion};
pub use pattern::{Pattern, PatternScanner};
pub use process::ProcessMemory;
pub use scanner::{ScanResult, ScanType, Scanner, ValueType};

// Hex editor exports
pub use buffer::{Delta, Page, PagedBuffer, PAGE_SIZE};
pub use search::{
  replace, replace_all, search_simple, search_text, BoyerMooreSearcher, SearchResult,
};
pub use source::{
  BufferSource, DataSource, FileSource, ProcessMemorySource, SourceError, SourceResult,
};
pub use types::{DataInterpreter, DataValue, Endian};
pub use undo::{UndoEntry, UndoError, UndoResult, UndoStack};
pub use view::{parse_hex, to_hex, HexView, OffsetFormat, ViewSettings};
