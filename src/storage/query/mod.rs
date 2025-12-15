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

pub mod executor;
pub mod filter;
pub mod similarity;
pub mod sort;

// Legacy query interface - disabled until engine_legacy is fixed
// pub mod legacy;

// Re-export common types
pub use executor::{QueryExecutor, QueryPlan, QueryResult};
pub use filter::{Filter, FilterOp, Predicate};
pub use similarity::{SimilarityQuery, SimilarityResult};
pub use sort::{Direction, NullsOrder, OrderBy, QueryLimits, SortKey};
