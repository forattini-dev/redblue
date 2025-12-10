//! Script runner for redblue scripting engine
//! Executes scripts against targets

use super::engine::{Script, ScriptEngine, ScriptResult};

/// Run a single script against a target
pub fn run_script(script: &Script, target: &str) -> ScriptResult {
    let engine = ScriptEngine::new();
    engine.execute(script, target)
}

/// Run multiple scripts against a target
pub fn run_scripts(scripts: &[Script], target: &str) -> Vec<ScriptResult> {
    let engine = ScriptEngine::new();
    scripts.iter().map(|s| engine.execute(s, target)).collect()
}
