//! MCP Logging - Structured logging capability for MCP servers
//!
//! Provides configurable logging levels and structured log messages
//! that can be sent to clients via notifications.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

/// Log severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Notice = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
    Alert = 6,
    Emergency = 7,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Notice => "notice",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Critical => "critical",
            LogLevel::Alert => "alert",
            LogLevel::Emergency => "emergency",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "notice" => Some(LogLevel::Notice),
            "warning" | "warn" => Some(LogLevel::Warning),
            "error" => Some(LogLevel::Error),
            "critical" | "crit" => Some(LogLevel::Critical),
            "alert" => Some(LogLevel::Alert),
            "emergency" | "emerg" => Some(LogLevel::Emergency),
            _ => None,
        }
    }
}

/// A structured log entry
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Log level
    pub level: LogLevel,
    /// Log message
    pub message: String,
    /// Logger name (component/module)
    pub logger: Option<String>,
    /// Additional structured data
    pub data: Option<String>,
    /// Timestamp (Unix epoch seconds)
    pub timestamp: u64,
}

impl LogEntry {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            level,
            message: message.into(),
            logger: None,
            data: None,
            timestamp,
        }
    }

    pub fn with_logger(mut self, logger: impl Into<String>) -> Self {
        self.logger = Some(logger.into());
        self
    }

    pub fn with_data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Convert to JSON for MCP notification
    pub fn to_json(&self) -> String {
        let logger = self
            .logger
            .as_ref()
            .map(|l| format!(r#","logger":"{}""#, l))
            .unwrap_or_default();
        let data = self
            .data
            .as_ref()
            .map(|d| format!(r#","data":{}"#, d))
            .unwrap_or_default();

        format!(
            r#"{{"level":"{}","message":"{}","timestamp":{}{}{}}}"#,
            self.level.as_str(),
            escape_json(&self.message),
            self.timestamp,
            logger,
            data
        )
    }
}

/// MCP Logger - manages log entries and configuration
pub struct McpLogger {
    /// Minimum log level to capture
    min_level: LogLevel,
    /// Log buffer (for client polling)
    buffer: VecDeque<LogEntry>,
    /// Maximum buffer size
    buffer_size: usize,
    /// Whether logging is enabled
    enabled: bool,
    /// Logger name prefix
    name: String,
}

impl McpLogger {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            min_level: LogLevel::Info,
            buffer: VecDeque::new(),
            buffer_size: 1000,
            enabled: true,
            name: name.into(),
        }
    }

    /// Set minimum log level
    pub fn set_level(&mut self, level: LogLevel) {
        self.min_level = level;
    }

    /// Set buffer size
    pub fn set_buffer_size(&mut self, size: usize) {
        self.buffer_size = size;
        while self.buffer.len() > size {
            self.buffer.pop_front();
        }
    }

    /// Enable or disable logging
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Log a message
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        if !self.enabled || level < self.min_level {
            return;
        }

        let entry = LogEntry::new(level, message).with_logger(&self.name);
        self.add_entry(entry);
    }

    /// Log with structured data
    pub fn log_with_data(
        &mut self,
        level: LogLevel,
        message: impl Into<String>,
        data: impl Into<String>,
    ) {
        if !self.enabled || level < self.min_level {
            return;
        }

        let entry = LogEntry::new(level, message)
            .with_logger(&self.name)
            .with_data(data);
        self.add_entry(entry);
    }

    fn add_entry(&mut self, entry: LogEntry) {
        self.buffer.push_back(entry);
        while self.buffer.len() > self.buffer_size {
            self.buffer.pop_front();
        }
    }

    /// Convenience methods
    pub fn debug(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Debug, message);
    }

    pub fn info(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Info, message);
    }

    pub fn notice(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Notice, message);
    }

    pub fn warning(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Warning, message);
    }

    pub fn error(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Error, message);
    }

    pub fn critical(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Critical, message);
    }

    /// Get buffered log entries
    pub fn get_entries(&self) -> &VecDeque<LogEntry> {
        &self.buffer
    }

    /// Get entries since a timestamp
    pub fn get_entries_since(&self, since: u64) -> Vec<&LogEntry> {
        self.buffer.iter().filter(|e| e.timestamp > since).collect()
    }

    /// Get entries at or above a level
    pub fn get_entries_at_level(&self, level: LogLevel) -> Vec<&LogEntry> {
        self.buffer.iter().filter(|e| e.level >= level).collect()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Drain entries (returns and removes)
    pub fn drain(&mut self) -> Vec<LogEntry> {
        self.buffer.drain(..).collect()
    }

    /// Get current configuration as JSON
    pub fn config_json(&self) -> String {
        format!(
            r#"{{"level":"{}","enabled":{},"buffer_size":{},"name":"{}"}}"#,
            self.min_level.as_str(),
            self.enabled,
            self.buffer_size,
            self.name
        )
    }
}

impl Default for McpLogger {
    fn default() -> Self {
        Self::new("redblue")
    }
}

/// Global logging context for MCP server
pub struct LoggingContext {
    /// Main server logger
    pub server: McpLogger,
    /// Scanner operations logger
    pub scanner: McpLogger,
    /// Intel operations logger
    pub intel: McpLogger,
    /// Exploit operations logger (AUTHORIZED USE ONLY)
    pub exploit: McpLogger,
    /// Agent operations logger
    pub agent: McpLogger,
    /// Storage operations logger
    pub storage: McpLogger,
}

impl LoggingContext {
    pub fn new() -> Self {
        Self {
            server: McpLogger::new("redblue.server"),
            scanner: McpLogger::new("redblue.scanner"),
            intel: McpLogger::new("redblue.intel"),
            exploit: McpLogger::new("redblue.exploit"),
            agent: McpLogger::new("redblue.agent"),
            storage: McpLogger::new("redblue.storage"),
        }
    }

    /// Set level for all loggers
    pub fn set_level_all(&mut self, level: LogLevel) {
        self.server.set_level(level);
        self.scanner.set_level(level);
        self.intel.set_level(level);
        self.exploit.set_level(level);
        self.agent.set_level(level);
        self.storage.set_level(level);
    }

    /// Get all recent entries across loggers
    pub fn all_entries_since(&self, since: u64) -> Vec<&LogEntry> {
        let mut entries = Vec::new();
        entries.extend(self.server.get_entries_since(since));
        entries.extend(self.scanner.get_entries_since(since));
        entries.extend(self.intel.get_entries_since(since));
        entries.extend(self.exploit.get_entries_since(since));
        entries.extend(self.agent.get_entries_since(since));
        entries.extend(self.storage.get_entries_since(since));
        entries.sort_by_key(|e| e.timestamp);
        entries
    }

    /// Get all warnings and errors
    pub fn warnings_and_errors(&self) -> Vec<&LogEntry> {
        let mut entries = Vec::new();
        entries.extend(self.server.get_entries_at_level(LogLevel::Warning));
        entries.extend(self.scanner.get_entries_at_level(LogLevel::Warning));
        entries.extend(self.intel.get_entries_at_level(LogLevel::Warning));
        entries.extend(self.exploit.get_entries_at_level(LogLevel::Warning));
        entries.extend(self.agent.get_entries_at_level(LogLevel::Warning));
        entries.extend(self.storage.get_entries_at_level(LogLevel::Warning));
        entries.sort_by_key(|e| e.timestamp);
        entries
    }
}

impl Default for LoggingContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape string for JSON
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Predefined log messages for common operations
pub mod messages {
    use super::*;

    pub fn scan_started(target: &str, scan_type: &str) -> LogEntry {
        LogEntry::new(
            LogLevel::Info,
            format!("Scan started: {} on {}", scan_type, target),
        )
        .with_logger("redblue.scanner")
        .with_data(format!(
            r#"{{"target":"{}","type":"{}"}}"#,
            target, scan_type
        ))
    }

    pub fn scan_completed(target: &str, results: usize, duration_ms: u64) -> LogEntry {
        LogEntry::new(
            LogLevel::Info,
            format!("Scan completed: {} results in {}ms", results, duration_ms),
        )
        .with_logger("redblue.scanner")
        .with_data(format!(
            r#"{{"target":"{}","results":{},"duration_ms":{}}}"#,
            target, results, duration_ms
        ))
    }

    pub fn scan_error(target: &str, error: &str) -> LogEntry {
        LogEntry::new(LogLevel::Error, format!("Scan failed: {}", error))
            .with_logger("redblue.scanner")
            .with_data(format!(r#"{{"target":"{}","error":"{}"}}"#, target, error))
    }

    pub fn vuln_found(cve: &str, severity: &str, target: &str) -> LogEntry {
        LogEntry::new(
            LogLevel::Warning,
            format!("Vulnerability found: {} ({}) on {}", cve, severity, target),
        )
        .with_logger("redblue.intel")
        .with_data(format!(
            r#"{{"cve":"{}","severity":"{}","target":"{}"}}"#,
            cve, severity, target
        ))
    }

    pub fn technique_mapped(technique_id: &str, name: &str) -> LogEntry {
        LogEntry::new(
            LogLevel::Debug,
            format!("Technique mapped: {} - {}", technique_id, name),
        )
        .with_logger("redblue.intel")
    }

    pub fn session_started(session_id: &str, target: &str) -> LogEntry {
        LogEntry::new(
            LogLevel::Notice,
            format!("Session started: {} targeting {}", session_id, target),
        )
        .with_logger("redblue.agent")
    }

    pub fn session_ended(session_id: &str, reason: &str) -> LogEntry {
        LogEntry::new(
            LogLevel::Notice,
            format!("Session ended: {} - {}", session_id, reason),
        )
        .with_logger("redblue.agent")
    }

    pub fn exploit_attempted(target: &str, exploit_name: &str) -> LogEntry {
        LogEntry::new(
            LogLevel::Warning,
            format!(
                "Exploit attempted: {} against {} (AUTHORIZED USE ONLY)",
                exploit_name, target
            ),
        )
        .with_logger("redblue.exploit")
    }

    pub fn storage_operation(op: &str, table: &str, count: usize) -> LogEntry {
        LogEntry::new(
            LogLevel::Debug,
            format!("Storage: {} {} records in {}", op, count, table),
        )
        .with_logger("redblue.storage")
    }

    pub fn rate_limit_hit(endpoint: &str) -> LogEntry {
        LogEntry::new(
            LogLevel::Warning,
            format!("Rate limit hit for endpoint: {}", endpoint),
        )
        .with_logger("redblue.server")
    }

    pub fn auth_failure(reason: &str) -> LogEntry {
        LogEntry::new(
            LogLevel::Warning,
            format!("Authentication failed: {}", reason),
        )
        .with_logger("redblue.server")
    }

    pub fn mcp_request(method: &str, id: i64) -> LogEntry {
        LogEntry::new(
            LogLevel::Debug,
            format!("MCP request: {} (id: {})", method, id),
        )
        .with_logger("redblue.server")
    }

    pub fn mcp_response(id: i64, success: bool) -> LogEntry {
        LogEntry::new(
            LogLevel::Debug,
            format!("MCP response: id={} success={}", id, success),
        )
        .with_logger("redblue.server")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_levels() {
        assert!(LogLevel::Error > LogLevel::Warning);
        assert!(LogLevel::Warning > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);

        assert_eq!(LogLevel::from_str("info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("WARNING"), Some(LogLevel::Warning));
        assert_eq!(LogLevel::from_str("crit"), Some(LogLevel::Critical));
    }

    #[test]
    fn test_logger() {
        let mut logger = McpLogger::new("test");
        logger.set_level(LogLevel::Info);

        logger.debug("should not appear");
        logger.info("should appear");
        logger.error("should appear");

        let entries = logger.get_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].level, LogLevel::Info);
        assert_eq!(entries[1].level, LogLevel::Error);
    }

    #[test]
    fn test_log_entry_json() {
        let entry = LogEntry::new(LogLevel::Info, "Test message")
            .with_logger("test.logger")
            .with_data(r#"{"key":"value"}"#);

        let json = entry.to_json();
        assert!(json.contains(r#""level":"info""#));
        assert!(json.contains(r#""message":"Test message""#));
        assert!(json.contains(r#""logger":"test.logger""#));
    }

    #[test]
    fn test_predefined_messages() {
        let entry = messages::scan_started("example.com", "port");
        assert_eq!(entry.level, LogLevel::Info);
        assert!(entry.message.contains("example.com"));

        let entry = messages::vuln_found("CVE-2024-1234", "HIGH", "10.0.0.1");
        assert_eq!(entry.level, LogLevel::Warning);
        assert!(entry.data.unwrap().contains("CVE-2024-1234"));
    }
}
