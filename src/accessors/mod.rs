pub mod file;
pub mod network;
pub mod process;
pub mod registry;
pub mod service;

use crate::serde_json::{JsonDecode, JsonEncode, Map, Value};
use std::collections::HashMap;

/// Metadata about an accessor
#[derive(Debug, Clone)]
pub struct AccessorInfo {
    pub name: String,
    pub description: String,
    pub methods: Vec<String>,
}

/// Structured result from an accessor execution
#[derive(Debug, Clone)]
pub struct AccessorResult {
    pub success: bool,
    pub data: Option<Value>,
    pub error: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl JsonEncode for AccessorInfo {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("methods".to_string(), self.methods.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for AccessorInfo {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            name: String::from_json_value(map.get("name").cloned().unwrap_or(Value::Null))?,
            description: String::from_json_value(
                map.get("description").cloned().unwrap_or(Value::Null),
            )?,
            methods: Vec::<String>::from_json_value(
                map.get("methods").cloned().unwrap_or(Value::Null),
            )?,
        })
    }
}

impl JsonEncode for AccessorResult {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("success".to_string(), self.success.to_json_value());
        map.insert("data".to_string(), self.data.to_json_value());
        map.insert("error".to_string(), self.error.to_json_value());
        map.insert("metadata".to_string(), self.metadata.to_json_value());
        Value::Object(map)
    }
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
