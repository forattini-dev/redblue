pub mod file;
pub mod network;
pub mod process;
pub mod registry;
pub mod service;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Metadata about an accessor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessorInfo {
    pub name: String,
    pub description: String,
    pub methods: Vec<String>,
}

/// Structured result from an accessor execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessorResult {
    pub success: bool,
    pub data: Option<Value>,
    pub error: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl AccessorResult {
    pub fn success(data: Value) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            metadata: HashMap::new(),
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
            metadata: HashMap::new(),
        }
    }
}

/// Trait for system accessors
pub trait Accessor: Send + Sync {
    /// Get accessor name (e.g., "file", "process")
    fn name(&self) -> &str;

    /// Get metadata about the accessor
    fn info(&self) -> AccessorInfo;

    /// Execute a method on the accessor
    fn execute(&self, method: &str, args: &HashMap<String, String>) -> AccessorResult;
}
