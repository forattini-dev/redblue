use super::{Accessor, AccessorInfo, AccessorResult};
use crate::json;
use crate::serde_json::Value;
use std::collections::HashMap;
use std::process::Command;

pub struct RegistryAccessor;

impl RegistryAccessor {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "windows")]
    fn parse_value_line(line: &str) -> Option<Value> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
            return None;
        }

        let mut parts = trimmed.split_whitespace();
        let name = parts.next()?;
        let value_type = parts.next()?;
        let data = parts.collect::<Vec<_>>().join(" ");

        Some(json!({
            "name": name,
            "type": value_type,
            "data": data
        }))
    }

    #[cfg(target_os = "windows")]
    fn read_key(&self, key: &str, value_name: Option<&str>) -> AccessorResult {
        let mut cmd = Command::new("reg");
        cmd.arg("query").arg(key);
        if let Some(v) = value_name {
            if !v.trim().is_empty() {
                cmd.arg("/v").arg(v);
            }
        }

        let output = match cmd.output() {
            Ok(out) => out,
            Err(err) => {
                return AccessorResult::error(&format!(
                    "Failed to execute reg query for key '{}': {}",
                    key, err
                ));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            let reason = if stderr.trim().is_empty() {
                "registry query failed"
            } else {
                stderr.trim()
            };
            return AccessorResult::error(&format!(
                "Registry query failed for '{}': {}",
                key, reason
            ));
        }

        let mut values = Vec::new();
        for line in stdout.lines() {
            if let Some(value) = Self::parse_value_line(line) {
                values.push(value);
            }
        }

        if values.is_empty() {
            return AccessorResult::error(&format!(
                "No values returned for registry key '{}'",
                key
            ));
        }

        let result = if let Some(name) = value_name {
            if values.len() == 1 {
                AccessorResult::success(
                    json!({"key": key, "value": name, "entry": values[0].clone()}),
                )
            } else {
                AccessorResult::success(
                    json!({"key": key, "value": name, "entries": Value::Array(values)}),
                )
            }
        } else {
            AccessorResult::success(json!({"key": key, "entries": Value::Array(values)}))
        };

        let mut result = result;
        result
            .metadata
            .insert("query-mode".to_string(), "reg-query".to_string());
        result
            .metadata
            .insert("entry-count".to_string(), values.len().to_string());
        result
    }

    #[cfg(not(target_os = "windows"))]
    fn read_key(&self, _key: &str, _value_name: Option<&str>) -> AccessorResult {
        AccessorResult::error("Registry access only supported on Windows")
    }
}

impl Accessor for RegistryAccessor {
    fn name(&self) -> &str {
        "registry"
    }

    fn info(&self) -> AccessorInfo {
        AccessorInfo {
            name: "Registry Accessor".to_string(),
            description: "Interact with Windows Registry".to_string(),
            methods: vec!["read".to_string()],
        }
    }

    fn execute(&self, method: &str, args: &HashMap<String, String>) -> AccessorResult {
        match method {
            "read" => {
                if let Some(key) = args.get("key").or(args.get("arg0")) {
                    let value = args.get("value").or(args.get("arg1")).map(|s| s.as_str());
                    self.read_key(key, value)
                } else {
                    AccessorResult::error("Missing 'key' argument")
                }
            }
            _ => AccessorResult::error(&format!("Unknown method: {}", method)),
        }
    }
}
