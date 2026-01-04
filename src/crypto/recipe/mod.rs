//! Recipe System
//!
//! Chain multiple encoding/cipher operations together.

mod executor;
mod parser;

pub use executor::RecipeExecutor;
pub use parser::{Operation, Recipe, RecipeParser};
