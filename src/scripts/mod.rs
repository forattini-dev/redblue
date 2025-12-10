/// redblue Scripting Engine
///
/// A lightweight, zero-dependency scripting engine for security checks.
///
/// ## Design Philosophy
///
/// Following redblue's core principles, this scripting engine:
/// - Has ZERO external dependencies (no Lua, no WASM runtimes)
/// - Implements everything from scratch using only Rust std
/// - Supports both compiled Rust scripts AND declarative TOML scripts
/// - Uses a simple expression language for conditions
///
/// ## Script Types
///
/// 1. **Compiled Scripts**: Rust modules implementing the `Script` trait
///    - Fast, type-safe, full Rust capabilities
///    - Requires recompilation to add/modify
///    - Best for complex logic and protocol handling
///
/// 2. **TOML Scripts**: Declarative scripts loaded at runtime
///    - No recompilation needed
///    - Pattern matching and simple conditions
///    - Best for signature-based detection
///
/// ## Categories
///
/// Scripts are organized into categories for filtering and safety:
/// - `default`: Safe scripts run by default
/// - `safe`: Non-intrusive, read-only scripts
/// - `vuln`: Vulnerability detection
/// - `discovery`: Service/host discovery
/// - `intrusive`: May cause service disruption (requires flag)
/// - `exploit`: Active exploitation (requires explicit consent)
///
/// ## Usage
///
/// ```rust
/// use crate::scripts::{Script, ScriptContext, ScriptResult};
///
/// // Run a compiled script
/// let script = HttpHeadersScript::new();
/// let ctx = ScriptContext::new("example.com", 80);
/// let result = script.run(&ctx)?;
///
/// // Load and run TOML scripts
/// let loader = ScriptLoader::new();
/// loader.load_dir("scripts/")?;
/// for script in loader.scripts_for_port(80) {
///     let result = script.run(&ctx)?;
/// }
/// ```

pub mod types;
pub mod expr;
pub mod loader;
pub mod engine;
pub mod builtin;

pub use types::*;

use std::time::Instant;

/// The core Script trait
///
/// All scripts (compiled or loaded) implement this trait.
pub trait Script: Send + Sync {
    /// Get script metadata
    fn metadata(&self) -> &ScriptMetadata;

    /// Get script arguments definition
    fn args(&self) -> Vec<ScriptArg> {
        Vec::new()
    }

    /// Check if this script should run for the given context
    ///
    /// Default implementation checks protocol and port matching.
    fn should_run(&self, ctx: &ScriptContext) -> bool {
        let meta = self.metadata();

        // Check protocol match
        if !meta.protocols.is_empty() && !ctx.protocol.is_empty() {
            if !meta.protocols.iter().any(|p| p.eq_ignore_ascii_case(&ctx.protocol)) {
                return false;
            }
        }

        // Check port match
        if !meta.ports.is_empty() && !meta.ports.contains(&ctx.port) {
            return false;
        }

        // Check category safety
        for cat in &meta.categories {
            if cat.requires_consent() && !ctx.allow_intrusive {
                return false;
            }
        }

        true
    }

    /// Run the script
    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String>;

    /// Get script ID
    fn id(&self) -> &str {
        &self.metadata().id
    }

    /// Get script name
    fn name(&self) -> &str {
        &self.metadata().name
    }

    /// Check if script belongs to a category
    fn has_category(&self, cat: ScriptCategory) -> bool {
        self.metadata().categories.contains(&cat)
    }

    /// Check if script is safe
    fn is_safe(&self) -> bool {
        self.metadata().categories.iter().all(|c| c.is_safe())
    }
}

/// Script runner that handles execution timing and error handling
pub struct ScriptRunner;

impl ScriptRunner {
    /// Run a script with timing and error handling
    pub fn run(script: &dyn Script, ctx: &ScriptContext) -> ScriptResult {
        let start = Instant::now();

        // Check if script should run
        if !script.should_run(ctx) {
            let mut result = ScriptResult::new(script.id());
            result.status = ScriptStatus::Skipped;
            result.add_output("Script preconditions not met");
            return result;
        }

        // Run the script
        match script.run(ctx) {
            Ok(mut result) => {
                result.duration = start.elapsed();
                if result.status == ScriptStatus::NotRun {
                    result.status = ScriptStatus::Completed;
                }
                result
            }
            Err(e) => {
                let mut result = ScriptResult::failure(script.id(), &e);
                result.duration = start.elapsed();
                result
            }
        }
    }

    /// Run multiple scripts in sequence
    pub fn run_all(scripts: &[&dyn Script], ctx: &ScriptContext) -> Vec<ScriptResult> {
        scripts
            .iter()
            .map(|script| Self::run(*script, ctx))
            .collect()
    }
}

/// Script filter for selecting scripts to run
#[derive(Debug, Clone, Default)]
pub struct ScriptFilter {
    /// Categories to include
    pub categories: Vec<ScriptCategory>,
    /// Protocols to match
    pub protocols: Vec<String>,
    /// Ports to match
    pub ports: Vec<u16>,
    /// Script IDs to include (exact match)
    pub ids: Vec<String>,
    /// Script name patterns (substring match)
    pub patterns: Vec<String>,
    /// Exclude intrusive scripts
    pub safe_only: bool,
}

impl ScriptFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter for default scripts only
    pub fn default_scripts() -> Self {
        Self {
            categories: vec![ScriptCategory::Default],
            safe_only: true,
            ..Default::default()
        }
    }

    /// Filter for all safe scripts
    pub fn safe_scripts() -> Self {
        Self {
            safe_only: true,
            ..Default::default()
        }
    }

    /// Filter by category
    pub fn with_category(mut self, cat: ScriptCategory) -> Self {
        self.categories.push(cat);
        self
    }

    /// Filter by protocol
    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocols.push(protocol.to_string());
        self
    }

    /// Filter by port
    pub fn with_port(mut self, port: u16) -> Self {
        self.ports.push(port);
        self
    }

    /// Filter by ID
    pub fn with_id(mut self, id: &str) -> Self {
        self.ids.push(id.to_string());
        self
    }

    /// Filter by name pattern
    pub fn with_pattern(mut self, pattern: &str) -> Self {
        self.patterns.push(pattern.to_string());
        self
    }

    /// Check if a script matches this filter
    pub fn matches(&self, script: &dyn Script) -> bool {
        let meta = script.metadata();

        // Check safe_only
        if self.safe_only && !script.is_safe() {
            return false;
        }

        // Check categories
        if !self.categories.is_empty() {
            let has_category = self
                .categories
                .iter()
                .any(|c| meta.categories.contains(c));
            if !has_category {
                return false;
            }
        }

        // Check protocols
        if !self.protocols.is_empty() {
            let has_protocol = self
                .protocols
                .iter()
                .any(|p| meta.protocols.iter().any(|mp| mp.eq_ignore_ascii_case(p)));
            if !has_protocol && !meta.protocols.is_empty() {
                return false;
            }
        }

        // Check ports
        if !self.ports.is_empty() {
            let has_port = self.ports.iter().any(|p| meta.ports.contains(p));
            if !has_port && !meta.ports.is_empty() {
                return false;
            }
        }

        // Check IDs
        if !self.ids.is_empty() && !self.ids.contains(&meta.id) {
            return false;
        }

        // Check patterns
        if !self.patterns.is_empty() {
            let name_lower = meta.name.to_lowercase();
            let id_lower = meta.id.to_lowercase();
            let matches_pattern = self
                .patterns
                .iter()
                .any(|p| name_lower.contains(&p.to_lowercase()) || id_lower.contains(&p.to_lowercase()));
            if !matches_pattern {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestScript {
        meta: ScriptMetadata,
    }

    impl TestScript {
        fn new(id: &str, categories: Vec<ScriptCategory>) -> Self {
            Self {
                meta: ScriptMetadata {
                    id: id.to_string(),
                    name: format!("Test Script {}", id),
                    categories,
                    ..Default::default()
                },
            }
        }
    }

    impl Script for TestScript {
        fn metadata(&self) -> &ScriptMetadata {
            &self.meta
        }

        fn run(&self, _ctx: &ScriptContext) -> Result<ScriptResult, String> {
            Ok(ScriptResult::success(&self.meta.id))
        }
    }

    #[test]
    fn test_script_filter_categories() {
        let script = TestScript::new("test-1", vec![ScriptCategory::Vuln]);
        let filter = ScriptFilter::new().with_category(ScriptCategory::Vuln);
        assert!(filter.matches(&script));

        let filter2 = ScriptFilter::new().with_category(ScriptCategory::Discovery);
        assert!(!filter2.matches(&script));
    }

    #[test]
    fn test_script_filter_safe_only() {
        let safe_script = TestScript::new("safe-1", vec![ScriptCategory::Safe]);
        let intrusive_script = TestScript::new("intrusive-1", vec![ScriptCategory::Intrusive]);

        let filter = ScriptFilter::safe_scripts();
        assert!(filter.matches(&safe_script));
        assert!(!filter.matches(&intrusive_script));
    }

    #[test]
    fn test_script_runner() {
        let script = TestScript::new("test-runner", vec![ScriptCategory::Safe]);
        let ctx = ScriptContext::new("localhost", 80);

        let result = ScriptRunner::run(&script, &ctx);
        assert_eq!(result.status, ScriptStatus::Completed);
        assert!(result.success);
    }
}
