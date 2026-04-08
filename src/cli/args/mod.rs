//! Schema-driven CLI argument parser
//!
//! Three-layer architecture ported from cli-args-parser (TypeScript):
//! - **token**: Pure lexer (argv → typed tokens)
//! - **types**: Shared types (FlagSchema, FlagValue, ParsedCommand)
//! - **error**: Structured errors with Levenshtein suggestions
//! - **schema**: Schema-driven flag parsing + type coercion (TODO)
//! - **router**: Command routing domain→resource→verb (TODO)
//! - **help**: Help text generation (TODO)
//! - **complete**: Shell completion generation (TODO)

pub mod error;
pub mod router;
pub mod schema;
pub mod token;
pub mod types;

pub use error::{suggest, ParseError};
pub use router::{RouteResolution, RouteTree};
pub use schema::{SchemaParser, SchemaResult};
pub use token::{tokenize, Token};
pub use types::{CommandPath, FlagSchema, FlagValue, ParsedCommand, ValueType};
