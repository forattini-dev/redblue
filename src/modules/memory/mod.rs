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

pub use maps::{parse_maps, MemoryPermissions, MemoryRegion};
pub use pattern::{Pattern, PatternScanner};
pub use process::ProcessMemory;
pub use scanner::{ScanResult, ScanType, Scanner, ValueType};
