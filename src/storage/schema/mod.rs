//! RedDB Schema System
//!
//! This module provides a complete schema system for RedDB including:
//! - Type system with primitive and network-specific types
//! - Table definitions with columns, constraints, and indexes
//! - Schema registry for storing and managing table definitions
//!
//! The schema system is designed to support security-focused data types
//! like IP addresses, MAC addresses, and vectors for similarity search.

pub mod types;
pub mod table;
pub mod registry;

// Re-export common types
pub use types::{DataType, Value, ValueError, Row};
pub use table::{TableDef, ColumnDef, IndexDef, IndexType, Constraint, ConstraintType};
pub use registry::{SchemaRegistry, SchemaError};
