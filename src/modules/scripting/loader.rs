//! Script loader for redblue scripting engine
//! Loads script definitions from various sources

use super::engine::Script;

/// Load built-in scripts
pub fn load_builtin_scripts() -> Vec<Script> {
    // TODO: Add built-in vulnerability check scripts
    Vec::new()
}

/// Load scripts from a directory
pub fn load_scripts_from_dir(_path: &str) -> Result<Vec<Script>, String> {
    // TODO: Implement script loading from filesystem
    Ok(Vec::new())
}
