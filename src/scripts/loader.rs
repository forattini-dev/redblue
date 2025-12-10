/// Script Loader - TOML Script Parser
///
/// Loads and parses TOML-defined scripts at runtime.
/// Zero external dependencies - implements TOML parsing from scratch.
///
/// ## TOML Script Format
///
/// ```toml
/// [metadata]
/// id = "http-server-header"
/// name = "HTTP Server Header Detection"
/// author = "redblue"
/// version = "1.0"
/// description = "Detects server software from HTTP headers"
/// categories = ["discovery", "safe"]
/// protocols = ["http", "https"]
/// ports = [80, 443, 8080, 8443]
///
/// [args]
/// path = { description = "URL path to request", default = "/" }
/// timeout = { description = "Request timeout in seconds", default = "10" }
///
/// [[rules]]
/// name = "Apache Detection"
/// condition = 'header.Server contains "Apache"'
/// finding = { type = "version", title = "Apache Web Server" }
/// extract = { server_version = 'header.Server' }
///
/// [[rules]]
/// name = "Nginx Detection"
/// condition = 'header.Server contains "nginx"'
/// finding = { type = "version", title = "Nginx Web Server" }
/// ```

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::scripts::expr::{ExprEvaluator, ExprValue};
use crate::scripts::types::*;
use crate::scripts::Script;

/// A script loaded from a TOML file
#[derive(Debug, Clone)]
pub struct TomlScript {
    /// Script metadata
    pub meta: ScriptMetadata,
    /// Script arguments
    pub arguments: Vec<ScriptArg>,
    /// Detection rules
    pub rules: Vec<ScriptRule>,
    /// Source file path
    pub source_path: Option<PathBuf>,
}

/// A detection rule within a script
#[derive(Debug, Clone)]
pub struct ScriptRule {
    /// Rule name
    pub name: String,
    /// Condition expression
    pub condition: String,
    /// Finding to create if condition matches
    pub finding: Option<RuleFinding>,
    /// Data to extract if condition matches
    pub extract: HashMap<String, String>,
    /// Output message
    pub output: Option<String>,
}

/// Finding definition in a rule
#[derive(Debug, Clone)]
pub struct RuleFinding {
    pub finding_type: FindingType,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub cve: Option<String>,
}

impl TomlScript {
    /// Create an empty script
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata::default(),
            arguments: Vec::new(),
            rules: Vec::new(),
            source_path: None,
        }
    }

    /// Parse a TOML script from string content
    pub fn parse(content: &str) -> Result<Self, String> {
        let mut script = TomlScript::new();
        let toml = TomlParser::parse(content)?;

        // Parse metadata section
        if let Some(meta) = toml.get_table("metadata") {
            script.meta.id = meta.get_string("id").unwrap_or_default();
            script.meta.name = meta.get_string("name").unwrap_or_default();
            script.meta.author = meta.get_string("author").unwrap_or_else(|| "redblue".to_string());
            script.meta.version = meta.get_string("version").unwrap_or_else(|| "1.0".to_string());
            script.meta.description = meta.get_string("description").unwrap_or_default();
            script.meta.license = meta.get_string("license").unwrap_or_else(|| "MIT".to_string());

            // Parse categories
            if let Some(cats) = meta.get_array("categories") {
                script.meta.categories = cats
                    .iter()
                    .filter_map(|v| {
                        if let TomlValue::String(s) = v {
                            ScriptCategory::from_str(s)
                        } else {
                            None
                        }
                    })
                    .collect();
            }

            // Parse protocols
            if let Some(protos) = meta.get_array("protocols") {
                script.meta.protocols = protos
                    .iter()
                    .filter_map(|v| {
                        if let TomlValue::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
            }

            // Parse ports
            if let Some(ports) = meta.get_array("ports") {
                script.meta.ports = ports
                    .iter()
                    .filter_map(|v| {
                        if let TomlValue::Integer(n) = v {
                            Some(*n as u16)
                        } else {
                            None
                        }
                    })
                    .collect();
            }

            // Parse CVEs
            if let Some(cves) = meta.get_array("cves") {
                script.meta.cves = cves
                    .iter()
                    .filter_map(|v| {
                        if let TomlValue::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
            }

            // Parse references
            if let Some(refs) = meta.get_array("references") {
                script.meta.references = refs
                    .iter()
                    .filter_map(|v| {
                        if let TomlValue::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }

        // Parse args section
        if let Some(args) = toml.get_table("args") {
            for (name, value) in args.entries() {
                if let TomlValue::Table(arg_table) = value {
                    let mut arg = ScriptArg::new(
                        name,
                        &arg_table.get_string("description").unwrap_or_default(),
                    );
                    if let Some(default) = arg_table.get_string("default") {
                        arg = arg.with_default(&default);
                    }
                    if arg_table.get_bool("required").unwrap_or(false) {
                        arg = arg.required();
                    }
                    script.arguments.push(arg);
                }
            }
        }

        // Parse rules array
        if let Some(rules) = toml.get_array("rules") {
            for rule_value in rules {
                if let TomlValue::Table(rule_table) = rule_value {
                    let mut rule = ScriptRule {
                        name: rule_table.get_string("name").unwrap_or_default(),
                        condition: rule_table.get_string("condition").unwrap_or_default(),
                        finding: None,
                        extract: HashMap::new(),
                        output: rule_table.get_string("output"),
                    };

                    // Parse finding
                    if let Some(finding_table) = rule_table.get_table("finding") {
                        let finding_type = finding_table
                            .get_string("type")
                            .and_then(|s| parse_finding_type(&s))
                            .unwrap_or(FindingType::Info);

                        let severity = finding_table
                            .get_string("severity")
                            .and_then(|s| parse_severity(&s))
                            .unwrap_or(FindingSeverity::Info);

                        rule.finding = Some(RuleFinding {
                            finding_type,
                            severity,
                            title: finding_table.get_string("title").unwrap_or_default(),
                            description: finding_table.get_string("description"),
                            remediation: finding_table.get_string("remediation"),
                            cve: finding_table.get_string("cve"),
                        });
                    }

                    // Parse extract
                    if let Some(extract_table) = rule_table.get_table("extract") {
                        for (key, value) in extract_table.entries() {
                            if let TomlValue::String(expr) = value {
                                rule.extract.insert(key.clone(), expr.clone());
                            }
                        }
                    }

                    script.rules.push(rule);
                }
            }
        }

        // Validate
        if script.meta.id.is_empty() {
            return Err("Script must have an 'id' in [metadata]".to_string());
        }
        if script.meta.name.is_empty() {
            script.meta.name = script.meta.id.clone();
        }

        Ok(script)
    }

    /// Load a script from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        let mut script = Self::parse(&content)?;
        script.source_path = Some(path.to_path_buf());
        Ok(script)
    }
}

impl Default for TomlScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for TomlScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn args(&self) -> Vec<ScriptArg> {
        self.arguments.clone()
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);
        let mut evaluator = ExprEvaluator::new();

        // Add context data to evaluator
        evaluator.set_var("host", ctx.host.clone());
        evaluator.set_var("port", ctx.port as f64);
        evaluator.set_var("protocol", ctx.protocol.clone());

        // Add context data as variables
        for (key, value) in &ctx.data {
            evaluator.set_var(key, value.clone());
        }

        // Add arguments with defaults
        for arg in &self.arguments {
            let value = ctx
                .get_arg(&arg.name)
                .map(|s| s.to_string())
                .or_else(|| arg.default.clone())
                .unwrap_or_default();
            evaluator.set_var(&arg.name, value);
        }

        // Keep vars for backward compatibility tracking (unused but shows intent)
        let _vars: HashMap<String, ExprValue> = HashMap::new();

        // Evaluate each rule
        for rule in &self.rules {
            // Skip empty conditions (always match)
            let matches = if rule.condition.is_empty() {
                true
            } else {
                match evaluator.eval(&rule.condition) {
                    Ok(ExprValue::Bool(b)) => b,
                    Ok(_) => false,
                    Err(e) => {
                        result.add_output(&format!("Rule '{}' error: {}", rule.name, e));
                        continue;
                    }
                }
            };

            if matches {
                // Add output message
                if let Some(output) = &rule.output {
                    result.add_output(output);
                }

                // Create finding
                if let Some(finding_def) = &rule.finding {
                    let mut finding = Finding::new(finding_def.finding_type, &finding_def.title)
                        .with_severity(finding_def.severity);

                    if let Some(desc) = &finding_def.description {
                        finding = finding.with_description(desc);
                    }
                    if let Some(rem) = &finding_def.remediation {
                        finding = finding.with_remediation(rem);
                    }
                    if let Some(cve) = &finding_def.cve {
                        finding = finding.with_cve(cve);
                    }

                    result.add_finding(finding);
                    result.success = true;
                }

                // Extract data
                for (key, expr) in &rule.extract {
                    match evaluator.eval(expr) {
                        Ok(ExprValue::String(s)) => {
                            result.extract(key, &s);
                        }
                        Ok(ExprValue::Number(n)) => {
                            result.extract(key, &n.to_string());
                        }
                        Ok(ExprValue::Bool(b)) => {
                            result.extract(key, &b.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(result)
    }
}

/// Script loader for loading multiple scripts from directories
pub struct ScriptLoader {
    /// Loaded scripts
    scripts: Vec<TomlScript>,
    /// Script directories
    directories: Vec<PathBuf>,
}

impl ScriptLoader {
    /// Create a new script loader
    pub fn new() -> Self {
        Self {
            scripts: Vec::new(),
            directories: Vec::new(),
        }
    }

    /// Add a directory to search for scripts
    pub fn add_directory<P: AsRef<Path>>(&mut self, path: P) {
        self.directories.push(path.as_ref().to_path_buf());
    }

    /// Load all scripts from a directory
    pub fn load_dir<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, String> {
        let path = path.as_ref();
        if !path.is_dir() {
            return Err(format!("{} is not a directory", path.display()));
        }

        let mut count = 0;
        let entries = fs::read_dir(path)
            .map_err(|e| format!("Failed to read directory {}: {}", path.display(), e))?;

        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.extension().and_then(|s| s.to_str()) == Some("toml") {
                match TomlScript::load(&entry_path) {
                    Ok(script) => {
                        self.scripts.push(script);
                        count += 1;
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load {}: {}", entry_path.display(), e);
                    }
                }
            }
        }

        self.directories.push(path.to_path_buf());
        Ok(count)
    }

    /// Load a single script file
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        let script = TomlScript::load(path)?;
        self.scripts.push(script);
        Ok(())
    }

    /// Get all loaded scripts
    pub fn scripts(&self) -> &[TomlScript] {
        &self.scripts
    }

    /// Get scripts for a specific port
    pub fn scripts_for_port(&self, port: u16) -> Vec<&TomlScript> {
        self.scripts
            .iter()
            .filter(|s| s.meta.ports.is_empty() || s.meta.ports.contains(&port))
            .collect()
    }

    /// Get scripts for a specific protocol
    pub fn scripts_for_protocol(&self, protocol: &str) -> Vec<&TomlScript> {
        self.scripts
            .iter()
            .filter(|s| {
                s.meta.protocols.is_empty()
                    || s.meta.protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol))
            })
            .collect()
    }

    /// Get scripts by category
    pub fn scripts_by_category(&self, category: ScriptCategory) -> Vec<&TomlScript> {
        self.scripts
            .iter()
            .filter(|s| s.meta.categories.contains(&category))
            .collect()
    }

    /// Get a script by ID
    pub fn get_script(&self, id: &str) -> Option<&TomlScript> {
        self.scripts.iter().find(|s| s.meta.id == id)
    }

    /// Get number of loaded scripts
    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    /// Check if no scripts are loaded
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }
}

impl Default for ScriptLoader {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TOML Parser (from scratch)
// =============================================================================

/// Simple TOML value representation
#[derive(Debug, Clone)]
pub enum TomlValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<TomlValue>),
    Table(TomlTable),
}

/// TOML table (key-value pairs)
#[derive(Debug, Clone, Default)]
pub struct TomlTable {
    entries: HashMap<String, TomlValue>,
}

impl TomlTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: String, value: TomlValue) {
        self.entries.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&TomlValue> {
        self.entries.get(key)
    }

    pub fn get_string(&self, key: &str) -> Option<String> {
        match self.get(key) {
            Some(TomlValue::String(s)) => Some(s.clone()),
            _ => None,
        }
    }

    pub fn get_integer(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(TomlValue::Integer(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key) {
            Some(TomlValue::Boolean(b)) => Some(*b),
            _ => None,
        }
    }

    pub fn get_array(&self, key: &str) -> Option<&Vec<TomlValue>> {
        match self.get(key) {
            Some(TomlValue::Array(arr)) => Some(arr),
            _ => None,
        }
    }

    pub fn get_table(&self, key: &str) -> Option<&TomlTable> {
        match self.get(key) {
            Some(TomlValue::Table(t)) => Some(t),
            _ => None,
        }
    }

    pub fn entries(&self) -> impl Iterator<Item = (&String, &TomlValue)> {
        self.entries.iter()
    }
}

/// Simple TOML parser
pub struct TomlParser;

impl TomlParser {
    /// Parse TOML content into a table
    pub fn parse(content: &str) -> Result<TomlTable, String> {
        let mut root = TomlTable::new();
        let mut current_table: Vec<String> = Vec::new();
        let mut array_tables: HashMap<String, Vec<TomlTable>> = HashMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Array of tables [[name]]
            if line.starts_with("[[") && line.ends_with("]]") {
                let table_name = &line[2..line.len() - 2].trim();
                current_table = table_name.split('.').map(|s| s.trim().to_string()).collect();

                // Initialize array if needed
                let key = current_table.join(".");
                array_tables.entry(key).or_default().push(TomlTable::new());
                continue;
            }

            // Table header [name]
            if line.starts_with('[') && line.ends_with(']') {
                let table_name = &line[1..line.len() - 1].trim();
                current_table = table_name.split('.').map(|s| s.trim().to_string()).collect();
                continue;
            }

            // Key-value pair
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let value_str = line[eq_pos + 1..].trim();

                let value = Self::parse_value(value_str)
                    .map_err(|e| format!("Line {}: {}", line_num + 1, e))?;

                // Insert into the appropriate table
                if current_table.is_empty() {
                    root.insert(key.to_string(), value);
                } else {
                    let table_key = current_table.join(".");

                    // Check if this is an array table
                    if let Some(tables) = array_tables.get_mut(&table_key) {
                        if let Some(last) = tables.last_mut() {
                            last.insert(key.to_string(), value);
                        }
                    } else {
                        // Regular table - ensure it exists
                        Self::ensure_table(&mut root, &current_table);
                        if let Some(table) = Self::get_table_mut(&mut root, &current_table) {
                            table.insert(key.to_string(), value);
                        }
                    }
                }
            }
        }

        // Convert array tables to arrays
        for (key, tables) in array_tables {
            let parts: Vec<&str> = key.split('.').collect();
            let array_value = TomlValue::Array(tables.into_iter().map(TomlValue::Table).collect());

            if parts.len() == 1 {
                root.insert(parts[0].to_string(), array_value);
            } else {
                // Nested array table
                let parent_parts = &parts[..parts.len() - 1];
                Self::ensure_table(&mut root, &parent_parts.iter().map(|s| s.to_string()).collect::<Vec<_>>());
                if let Some(parent) = Self::get_table_mut(&mut root, &parent_parts.iter().map(|s| s.to_string()).collect::<Vec<_>>()) {
                    parent.insert(parts.last().unwrap().to_string(), array_value);
                }
            }
        }

        Ok(root)
    }

    fn ensure_table(root: &mut TomlTable, path: &[String]) {
        let mut current = root;
        for part in path {
            if !current.entries.contains_key(part) {
                current.entries.insert(part.clone(), TomlValue::Table(TomlTable::new()));
            }
            if let Some(TomlValue::Table(t)) = current.entries.get_mut(part) {
                current = t;
            } else {
                return;
            }
        }
    }

    fn get_table_mut<'a>(root: &'a mut TomlTable, path: &[String]) -> Option<&'a mut TomlTable> {
        let mut current = root;
        for part in path {
            if let Some(TomlValue::Table(t)) = current.entries.get_mut(part) {
                current = t;
            } else {
                return None;
            }
        }
        Some(current)
    }

    fn parse_value(s: &str) -> Result<TomlValue, String> {
        let s = s.trim();

        // String (quoted)
        if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
            return Ok(TomlValue::String(Self::unescape_string(&s[1..s.len() - 1])));
        }

        // Boolean
        if s == "true" {
            return Ok(TomlValue::Boolean(true));
        }
        if s == "false" {
            return Ok(TomlValue::Boolean(false));
        }

        // Array
        if s.starts_with('[') && s.ends_with(']') {
            return Self::parse_array(&s[1..s.len() - 1]);
        }

        // Inline table
        if s.starts_with('{') && s.ends_with('}') {
            return Self::parse_inline_table(&s[1..s.len() - 1]);
        }

        // Number
        if let Ok(n) = s.parse::<i64>() {
            return Ok(TomlValue::Integer(n));
        }
        if let Ok(n) = s.parse::<f64>() {
            return Ok(TomlValue::Float(n));
        }

        // Unquoted string (not standard TOML, but we'll be lenient)
        Ok(TomlValue::String(s.to_string()))
    }

    fn parse_array(s: &str) -> Result<TomlValue, String> {
        let mut values = Vec::new();
        let mut current = String::new();
        let mut depth = 0;
        let mut in_string = false;
        let mut string_char = '"';

        for c in s.chars() {
            match c {
                '"' | '\'' if !in_string => {
                    in_string = true;
                    string_char = c;
                    current.push(c);
                }
                c if c == string_char && in_string => {
                    in_string = false;
                    current.push(c);
                }
                '[' | '{' if !in_string => {
                    depth += 1;
                    current.push(c);
                }
                ']' | '}' if !in_string => {
                    depth -= 1;
                    current.push(c);
                }
                ',' if depth == 0 && !in_string => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        values.push(Self::parse_value(trimmed)?);
                    }
                    current.clear();
                }
                _ => current.push(c),
            }
        }

        let trimmed = current.trim();
        if !trimmed.is_empty() {
            values.push(Self::parse_value(trimmed)?);
        }

        Ok(TomlValue::Array(values))
    }

    fn parse_inline_table(s: &str) -> Result<TomlValue, String> {
        let mut table = TomlTable::new();
        let mut current = String::new();
        let mut depth = 0;
        let mut in_string = false;
        let mut string_char = '"';

        for c in s.chars() {
            match c {
                '"' | '\'' if !in_string => {
                    in_string = true;
                    string_char = c;
                    current.push(c);
                }
                c if c == string_char && in_string => {
                    in_string = false;
                    current.push(c);
                }
                '[' | '{' if !in_string => {
                    depth += 1;
                    current.push(c);
                }
                ']' | '}' if !in_string => {
                    depth -= 1;
                    current.push(c);
                }
                ',' if depth == 0 && !in_string => {
                    Self::parse_kv_pair(&current, &mut table)?;
                    current.clear();
                }
                _ => current.push(c),
            }
        }

        if !current.trim().is_empty() {
            Self::parse_kv_pair(&current, &mut table)?;
        }

        Ok(TomlValue::Table(table))
    }

    fn parse_kv_pair(s: &str, table: &mut TomlTable) -> Result<(), String> {
        if let Some(eq_pos) = s.find('=') {
            let key = s[..eq_pos].trim();
            let value_str = s[eq_pos + 1..].trim();
            let value = Self::parse_value(value_str)?;
            table.insert(key.to_string(), value);
        }
        Ok(())
    }

    fn unescape_string(s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some('\'') => result.push('\''),
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }

        result
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn parse_finding_type(s: &str) -> Option<FindingType> {
    match s.to_lowercase().as_str() {
        "vulnerability" | "vuln" => Some(FindingType::Vulnerability),
        "discovery" => Some(FindingType::Discovery),
        "misconfiguration" | "misconfig" => Some(FindingType::Misconfiguration),
        "infoleak" | "info_leak" => Some(FindingType::InfoLeak),
        "credential" | "cred" => Some(FindingType::Credential),
        "version" => Some(FindingType::Version),
        "info" => Some(FindingType::Info),
        _ => None,
    }
}

fn parse_severity(s: &str) -> Option<FindingSeverity> {
    match s.to_lowercase().as_str() {
        "critical" => Some(FindingSeverity::Critical),
        "high" => Some(FindingSeverity::High),
        "medium" => Some(FindingSeverity::Medium),
        "low" => Some(FindingSeverity::Low),
        "info" => Some(FindingSeverity::Info),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_toml() {
        let content = r#"
[metadata]
id = "test-script"
name = "Test Script"
categories = ["safe", "discovery"]
ports = [80, 443]

[[rules]]
name = "Test Rule"
condition = 'banner contains "Apache"'
output = "Found Apache"
"#;

        let script = TomlScript::parse(content).unwrap();
        assert_eq!(script.meta.id, "test-script");
        assert_eq!(script.meta.name, "Test Script");
        assert_eq!(script.meta.categories.len(), 2);
        assert_eq!(script.meta.ports, vec![80, 443]);
        assert_eq!(script.rules.len(), 1);
        assert_eq!(script.rules[0].name, "Test Rule");
    }

    #[test]
    fn test_parse_inline_table() {
        let content = r#"
[metadata]
id = "finding-test"
name = "Finding Test"

[[rules]]
name = "Apache Detection"
condition = 'header.Server contains "Apache"'
finding = { type = "version", severity = "info", title = "Apache Detected" }
"#;

        let script = TomlScript::parse(content).unwrap();
        assert_eq!(script.rules.len(), 1);
        let finding = script.rules[0].finding.as_ref().unwrap();
        assert_eq!(finding.finding_type, FindingType::Version);
        assert_eq!(finding.severity, FindingSeverity::Info);
        assert_eq!(finding.title, "Apache Detected");
    }

    #[test]
    fn test_parse_extract() {
        let content = r#"
[metadata]
id = "extract-test"
name = "Extract Test"

[[rules]]
name = "Version Extract"
condition = 'exists($banner)'
[rules.extract]
server = '$header.Server'
version = '$banner'
"#;

        let script = TomlScript::parse(content).unwrap();
        assert_eq!(script.rules[0].extract.get("server"), Some(&"$header.Server".to_string()));
        assert_eq!(script.rules[0].extract.get("version"), Some(&"$banner".to_string()));
    }

    #[test]
    fn test_script_execution() {
        let content = r#"
[metadata]
id = "exec-test"
name = "Execution Test"

[[rules]]
name = "Banner Check"
condition = 'banner contains "SSH"'
finding = { type = "discovery", title = "SSH Service" }
"#;

        let script = TomlScript::parse(content).unwrap();

        let mut ctx = ScriptContext::new("localhost", 22);
        ctx.set_data("banner", "SSH-2.0-OpenSSH_8.4");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].title, "SSH Service");
    }

    #[test]
    fn test_toml_parser_array() {
        let result = TomlParser::parse_value("[1, 2, 3]").unwrap();
        if let TomlValue::Array(arr) = result {
            assert_eq!(arr.len(), 3);
        } else {
            panic!("Expected array");
        }
    }

    #[test]
    fn test_toml_parser_inline_table() {
        let result = TomlParser::parse_value(r#"{ key = "value", num = 42 }"#).unwrap();
        if let TomlValue::Table(t) = result {
            assert_eq!(t.get_string("key"), Some("value".to_string()));
            assert_eq!(t.get_integer("num"), Some(42));
        } else {
            panic!("Expected table");
        }
    }

    #[test]
    fn test_unescape_string() {
        assert_eq!(TomlParser::unescape_string(r#"hello\nworld"#), "hello\nworld");
        assert_eq!(TomlParser::unescape_string(r#"tab\there"#), "tab\there");
        assert_eq!(TomlParser::unescape_string(r#"quote\"here"#), "quote\"here");
    }
}
