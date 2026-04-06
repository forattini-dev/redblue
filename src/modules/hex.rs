//! Cross-platform hex editing infrastructure.
//!
//! This module exposes the file/buffer-oriented pieces of the hex editor
//! without pulling in Linux-only process memory inspection code.

#[path = "memory/buffer.rs"]
pub mod buffer;
#[path = "memory/search.rs"]
pub mod search;
#[path = "memory/source.rs"]
pub mod source;
#[path = "memory/types.rs"]
pub mod types;
#[path = "memory/undo.rs"]
pub mod undo;
#[path = "memory/view.rs"]
pub mod view;

pub use buffer::{Delta, Page, PagedBuffer, PAGE_SIZE};
pub use search::{
  replace, replace_all, search_simple, search_text, BoyerMooreSearcher, SearchResult,
};
#[cfg(target_os = "linux")]
pub use source::ProcessMemorySource;
pub use source::{BufferSource, DataSource, FileSource, SourceError, SourceResult};
pub use types::{DataInterpreter, DataValue, Endian};
pub use undo::{UndoEntry, UndoError, UndoResult, UndoStack};
pub use view::{parse_hex, to_hex, HexView, OffsetFormat, ViewSettings};
