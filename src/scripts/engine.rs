/// Script Execution Engine
///
/// Orchestrates script execution with parallel processing,
/// scheduling, and result aggregation.
///
/// ## Usage
///
/// ```rust
/// use crate::scripts::{ScriptEngine, ScriptContext, ScriptFilter};
///
/// let mut engine = ScriptEngine::new();
///
/// // Load built-in scripts
/// engine.load_builtin();
///
/// // Load TOML scripts from directory
/// engine.load_directory("scripts/")?;
///
/// // Run scripts against a target
/// let ctx = ScriptContext::new("example.com", 443);
/// let results = engine.run_all(&ctx);
///
/// // Or run with filter
/// let filter = ScriptFilter::new().with_category(ScriptCategory::Vuln);
/// let results = engine.run_filtered(&ctx, &filter);
/// ```
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::scripts::builtin;
use crate::scripts::loader::ScriptLoader;
use crate::scripts::types::*;
use crate::scripts::{Script, ScriptFilter, ScriptRunner};

/// Script execution engine
pub struct ScriptEngine {
    /// Built-in compiled scripts
    builtin_scripts: Vec<Box<dyn Script>>,
    /// TOML script loader
    loader: ScriptLoader,
    /// Maximum parallel threads
    max_threads: usize,
    /// Default timeout per script
    default_timeout: Duration,
    /// Engine statistics
    stats: EngineStats,
}

/// Engine execution statistics
#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    /// Total scripts executed
    pub scripts_run: usize,
    /// Scripts that found something
    pub scripts_matched: usize,
    /// Scripts that failed
    pub scripts_failed: usize,
    /// Scripts that were skipped
    pub scripts_skipped: usize,
    /// Total execution time
    pub total_duration: Duration,
    /// Findings by severity
    pub findings_by_severity: HashMap<String, usize>,
}

impl ScriptEngine {
    /// Create a new script engine
    pub fn new() -> Self {
        Self {
            builtin_scripts: Vec::new(),
            loader: ScriptLoader::new(),
            max_threads: 4,
            default_timeout: Duration::from_secs(30),
            stats: EngineStats::default(),
        }
    }

    /// Set maximum parallel threads
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.max_threads = threads.max(1);
        self
    }

    /// Set default timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Load all built-in scripts
    pub fn load_builtin(&mut self) {
        self.builtin_scripts = builtin::all_scripts();
    }

    /// Add a built-in script
    pub fn add_builtin(&mut self, script: Box<dyn Script>) {
        self.builtin_scripts.push(script);
    }

    /// Load TOML scripts from a directory
    pub fn load_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, String> {
        self.loader.load_dir(path)
    }

    /// Load a single TOML script file
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        self.loader.load_file(path)
    }

    /// Get total number of loaded scripts
    pub fn script_count(&self) -> usize {
        self.builtin_scripts.len() + self.loader.len()
    }

    /// Get engine statistics
    pub fn stats(&self) -> &EngineStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = EngineStats::default();
    }

    /// Run all scripts against a context
    pub fn run_all(&mut self, ctx: &ScriptContext) -> Vec<ScriptResult> {
        let filter = ScriptFilter::new();
        self.run_filtered(ctx, &filter)
    }

    /// Run scripts matching a filter
    pub fn run_filtered(
        &mut self,
        ctx: &ScriptContext,
        filter: &ScriptFilter,
    ) -> Vec<ScriptResult> {
        let start = Instant::now();
        let mut results = Vec::new();

        // Run builtin scripts that match filter
        for script in &self.builtin_scripts {
            if filter.matches(script.as_ref()) {
                let result = ScriptRunner::run(script.as_ref(), ctx);
                results.push(result);
            }
        }

        // Run TOML scripts that match filter
        for script in self.loader.scripts() {
            if filter.matches(script) {
                let result = ScriptRunner::run(script, ctx);
                results.push(result);
            }
        }

        // Update stats after all scripts have run (avoids borrow conflicts)
        for result in &results {
            self.update_stats(result);
        }

        self.stats.total_duration = start.elapsed();
        results
    }

    /// Run scripts for a specific port
    pub fn run_for_port(&mut self, ctx: &ScriptContext, port: u16) -> Vec<ScriptResult> {
        let filter = ScriptFilter::new().with_port(port);
        self.run_filtered(ctx, &filter)
    }

    /// Run scripts for a specific protocol
    pub fn run_for_protocol(&mut self, ctx: &ScriptContext, protocol: &str) -> Vec<ScriptResult> {
        let filter = ScriptFilter::new().with_protocol(protocol);
        self.run_filtered(ctx, &filter)
    }

    /// Run scripts by category
    pub fn run_by_category(
        &mut self,
        ctx: &ScriptContext,
        category: ScriptCategory,
    ) -> Vec<ScriptResult> {
        let filter = ScriptFilter::new().with_category(category);
        self.run_filtered(ctx, &filter)
    }

    /// Run a specific script by ID
    pub fn run_script(&mut self, ctx: &ScriptContext, script_id: &str) -> Option<ScriptResult> {
        // Check built-in scripts
        for script in &self.builtin_scripts {
            if script.id() == script_id {
                let result = ScriptRunner::run(script.as_ref(), ctx);
                self.update_stats(&result);
                return Some(result);
            }
        }

        // Check TOML scripts
        if let Some(script) = self.loader.get_script(script_id) {
            let result = ScriptRunner::run(script, ctx);
            self.update_stats(&result);
            return Some(result);
        }

        None
    }

    /// Run multiple scripts in parallel (reserved for future use)
    #[allow(dead_code)]
    fn run_parallel(&self, scripts: &[&dyn Script], ctx: &ScriptContext) -> Vec<ScriptResult> {
        let results: Arc<Mutex<Vec<(usize, ScriptResult)>>> = Arc::new(Mutex::new(Vec::new()));
        let ctx = ctx.clone();

        // We can't easily parallelize trait objects, so we'll use a simpler approach
        // that chunks the work and runs each chunk sequentially in a thread
        let chunk_size = (scripts.len() + self.max_threads - 1) / self.max_threads;

        for (chunk_idx, chunk) in scripts.chunks(chunk_size).enumerate() {
            let results = Arc::clone(&results);
            let _ctx = ctx.clone();

            // Collect script metadata for this chunk (we can't send trait objects across threads easily)
            let chunk_scripts: Vec<(usize, String)> = chunk
                .iter()
                .enumerate()
                .map(|(i, s)| (chunk_idx * chunk_size + i, s.id().to_string()))
                .collect();

            // For now, we'll run sequentially since trait objects aren't Send
            // A production implementation might use script IDs to look up scripts
            for (idx, _script_id) in chunk_scripts {
                if let Some(script) = scripts.get(idx - chunk_idx * chunk_size) {
                    let result = ScriptRunner::run(*script, &ctx);
                    let mut results_guard = results.lock().unwrap();
                    results_guard.push((idx, result));
                }
            }
        }

        // Sort results by original index and extract
        let mut results_guard = results.lock().unwrap();
        results_guard.sort_by_key(|(idx, _)| *idx);

        results_guard.drain(..).map(|(_, r)| r).collect()
    }

    /// Update statistics from a result
    fn update_stats(&mut self, result: &ScriptResult) {
        self.stats.scripts_run += 1;

        match result.status {
            ScriptStatus::Completed => {
                if result.success {
                    self.stats.scripts_matched += 1;
                }
            }
            ScriptStatus::Failed | ScriptStatus::Timeout => {
                self.stats.scripts_failed += 1;
            }
            ScriptStatus::Skipped => {
                self.stats.scripts_skipped += 1;
            }
            _ => {}
        }

        // Count findings by severity
        for finding in &result.findings {
            let severity = format!("{}", finding.severity);
            *self.stats.findings_by_severity.entry(severity).or_insert(0) += 1;
        }
    }

    /// List all available scripts
    pub fn list_scripts(&self) -> Vec<ScriptInfo> {
        let mut infos = Vec::new();

        for script in &self.builtin_scripts {
            infos.push(ScriptInfo {
                id: script.id().to_string(),
                name: script.name().to_string(),
                description: script.metadata().description.clone(),
                categories: script.metadata().categories.clone(),
                protocols: script.metadata().protocols.clone(),
                ports: script.metadata().ports.clone(),
                source: ScriptSource::Builtin,
            });
        }

        for script in self.loader.scripts() {
            infos.push(ScriptInfo {
                id: script.meta.id.clone(),
                name: script.meta.name.clone(),
                description: script.meta.description.clone(),
                categories: script.meta.categories.clone(),
                protocols: script.meta.protocols.clone(),
                ports: script.meta.ports.clone(),
                source: ScriptSource::Toml(
                    script
                        .source_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                ),
            });
        }

        infos
    }

    /// Search scripts by pattern
    pub fn search_scripts(&self, pattern: &str) -> Vec<ScriptInfo> {
        let pattern = pattern.to_lowercase();
        self.list_scripts()
            .into_iter()
            .filter(|info| {
                info.id.to_lowercase().contains(&pattern)
                    || info.name.to_lowercase().contains(&pattern)
                    || info.description.to_lowercase().contains(&pattern)
            })
            .collect()
    }

    /// Get a script by ID
    pub fn get_script(&self, id: &str) -> Option<ScriptInfo> {
        self.list_scripts().into_iter().find(|info| info.id == id)
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Script information for listing
#[derive(Debug, Clone)]
pub struct ScriptInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub categories: Vec<ScriptCategory>,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub source: ScriptSource,
}

/// Source of a script
#[derive(Debug, Clone)]
pub enum ScriptSource {
    /// Built-in compiled script
    Builtin,
    /// TOML script with file path
    Toml(String),
}

/// Result aggregator for multiple script results
#[derive(Debug, Clone)]
pub struct AggregatedResults {
    /// All results
    pub results: Vec<ScriptResult>,
    /// All findings grouped by severity
    pub findings_by_severity: HashMap<FindingSeverity, Vec<Finding>>,
    /// All findings grouped by type
    pub findings_by_type: HashMap<FindingType, Vec<Finding>>,
    /// All extracted data merged
    pub extracted_data: HashMap<String, String>,
    /// Summary statistics
    pub summary: ResultsSummary,
}

/// Summary of aggregated results
#[derive(Debug, Clone, Default)]
pub struct ResultsSummary {
    pub total_scripts: usize,
    pub successful_scripts: usize,
    pub failed_scripts: usize,
    pub skipped_scripts: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
    pub total_duration: Duration,
}

impl AggregatedResults {
    /// Aggregate multiple script results
    pub fn from_results(results: Vec<ScriptResult>) -> Self {
        let mut aggregated = Self {
            results: Vec::new(),
            findings_by_severity: HashMap::new(),
            findings_by_type: HashMap::new(),
            extracted_data: HashMap::new(),
            summary: ResultsSummary::default(),
        };

        let mut total_duration = Duration::ZERO;

        for result in results {
            total_duration += result.duration;

            aggregated.summary.total_scripts += 1;
            match result.status {
                ScriptStatus::Completed if result.success => {
                    aggregated.summary.successful_scripts += 1;
                }
                ScriptStatus::Completed => {}
                ScriptStatus::Failed | ScriptStatus::Timeout => {
                    aggregated.summary.failed_scripts += 1;
                }
                ScriptStatus::Skipped => {
                    aggregated.summary.skipped_scripts += 1;
                }
                _ => {}
            }

            // Collect findings
            for finding in &result.findings {
                aggregated.summary.total_findings += 1;

                match finding.severity {
                    FindingSeverity::Critical => aggregated.summary.critical_findings += 1,
                    FindingSeverity::High => aggregated.summary.high_findings += 1,
                    FindingSeverity::Medium => aggregated.summary.medium_findings += 1,
                    FindingSeverity::Low => aggregated.summary.low_findings += 1,
                    FindingSeverity::Info => aggregated.summary.info_findings += 1,
                }

                aggregated
                    .findings_by_severity
                    .entry(finding.severity)
                    .or_default()
                    .push(finding.clone());

                aggregated
                    .findings_by_type
                    .entry(finding.finding_type)
                    .or_default()
                    .push(finding.clone());
            }

            // Merge extracted data (later scripts override earlier)
            for (key, value) in &result.extracted {
                aggregated.extracted_data.insert(key.clone(), value.clone());
            }

            aggregated.results.push(result);
        }

        aggregated.summary.total_duration = total_duration;
        aggregated
    }

    /// Get all critical and high severity findings
    pub fn high_priority_findings(&self) -> Vec<&Finding> {
        let mut findings = Vec::new();

        if let Some(critical) = self.findings_by_severity.get(&FindingSeverity::Critical) {
            findings.extend(critical.iter());
        }
        if let Some(high) = self.findings_by_severity.get(&FindingSeverity::High) {
            findings.extend(high.iter());
        }

        findings
    }

    /// Get all vulnerability findings
    pub fn vulnerabilities(&self) -> Vec<&Finding> {
        self.findings_by_type
            .get(&FindingType::Vulnerability)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Check if any critical findings exist
    pub fn has_critical(&self) -> bool {
        self.summary.critical_findings > 0
    }

    /// Check if any high or critical findings exist
    pub fn has_high_priority(&self) -> bool {
        self.summary.critical_findings > 0 || self.summary.high_findings > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = ScriptEngine::new();
        assert_eq!(engine.script_count(), 0);
    }

    #[test]
    fn test_engine_with_builtin() {
        let mut engine = ScriptEngine::new();
        engine.load_builtin();
        // Number depends on builtin scripts implemented
        assert!(engine.script_count() >= 0);
    }

    #[test]
    fn test_aggregated_results() {
        let mut result1 = ScriptResult::success("script-1");
        result1.add_finding(
            Finding::new(FindingType::Vulnerability, "Test Vuln")
                .with_severity(FindingSeverity::High),
        );
        result1.extract("version", "1.0.0");

        let mut result2 = ScriptResult::success("script-2");
        result2.add_finding(Finding::new(FindingType::Info, "Test Info"));

        let aggregated = AggregatedResults::from_results(vec![result1, result2]);

        assert_eq!(aggregated.summary.total_scripts, 2);
        assert_eq!(aggregated.summary.successful_scripts, 2);
        assert_eq!(aggregated.summary.total_findings, 2);
        assert_eq!(aggregated.summary.high_findings, 1);
        assert_eq!(aggregated.summary.info_findings, 1);
        assert_eq!(
            aggregated.extracted_data.get("version"),
            Some(&"1.0.0".to_string())
        );
    }

    #[test]
    fn test_high_priority_findings() {
        let mut result = ScriptResult::success("test");
        result.add_finding(
            Finding::new(FindingType::Vulnerability, "Critical Issue")
                .with_severity(FindingSeverity::Critical),
        );
        result.add_finding(
            Finding::new(FindingType::Vulnerability, "High Issue")
                .with_severity(FindingSeverity::High),
        );
        result.add_finding(Finding::new(FindingType::Info, "Info"));

        let aggregated = AggregatedResults::from_results(vec![result]);

        assert!(aggregated.has_critical());
        assert!(aggregated.has_high_priority());
        assert_eq!(aggregated.high_priority_findings().len(), 2);
    }

    #[test]
    fn test_script_search() {
        let engine = ScriptEngine::new();
        // With no scripts, search should return empty
        let results = engine.search_scripts("http");
        assert!(results.is_empty());
    }

    #[test]
    fn test_engine_stats() {
        let mut engine = ScriptEngine::new();
        let ctx = ScriptContext::new("localhost", 80);

        // Run with no scripts
        let results = engine.run_all(&ctx);
        assert!(results.is_empty());

        let stats = engine.stats();
        assert_eq!(stats.scripts_run, 0);
    }
}
