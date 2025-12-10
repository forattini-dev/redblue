//! Query Engine for RedDB
//!
//! Provides query execution, filtering, sorting, and similarity search
//! capabilities for the RedDB storage engine.
//!
//! # Components
//!
//! - **filter**: Filter predicates (Eq, Lt, Gt, Between, Like, etc.)
//! - **sort**: Sorting and ordering operations
//! - **executor**: Query plan execution
//! - **similarity**: Vector similarity search integration
//! - **legacy**: Simple key-value query interface for backward compatibility
//!
//! # Example
//!
//! ```ignore
//! use redblue::storage::query::{Query, Filter, OrderBy, Direction};
//!
//! let query = Query::select("users")
//!     .filter(Filter::eq("status", "active"))
//!     .filter(Filter::gt("age", 18))
//!     .order_by("created_at", Direction::Desc)
//!     .limit(10);
//!
//! let results = executor.execute(&query)?;
//! ```

pub mod filter;
pub mod sort;
pub mod executor;
pub mod similarity;

// Legacy query interface - disabled until engine_legacy is fixed
// pub mod legacy;

// Re-export common types
pub use filter::{Filter, FilterOp, Predicate};
pub use sort::{OrderBy, Direction, SortKey, QueryLimits, NullsOrder};
pub use executor::{QueryExecutor, QueryPlan, QueryResult};
pub use similarity::{SimilarityQuery, SimilarityResult};
