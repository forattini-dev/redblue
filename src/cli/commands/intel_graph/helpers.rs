//! Helper Functions for Graph Intelligence
//!
//! Shared utilities: graph loading, string truncation, timestamp generation.

use crate::storage::engine::GraphStore;
use std::path::Path;

/// Load graph from path
pub fn load_graph(path: &str) -> Result<GraphStore, String> {
    // Check if graph file exists
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        // Create empty graph for demo
        return Ok(GraphStore::new());
    }

    if !path_obj.is_file() {
        return Err(format!("Graph path is not a file: {}", path));
    }

    let data = std::fs::read(path).map_err(|e| format!("Failed to read graph file: {}", e))?;
    if data.is_empty() {
        return Ok(GraphStore::new());
    }

    GraphStore::deserialize(&data).map_err(|e| format!("Failed to deserialize graph: {}", e))
}

/// Simple timestamp without external dependencies
pub fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple ISO-like format: days since epoch approximation
    let days = secs / 86400;
    let years = 1970 + (days / 365);
    let day_of_year = days % 365;
    let month = (day_of_year / 30) + 1;
    let day = (day_of_year % 30) + 1;
    format!("{:04}-{:02}-{:02}", years, month.min(12), day.min(31))
}

/// Truncate string to max length with ellipsis
pub fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_str() {
        assert_eq!(truncate_str("hello", 10), "hello");
        assert_eq!(truncate_str("hello world", 8), "hello...");
    }
}
