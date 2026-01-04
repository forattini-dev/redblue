//! Target database management for MCP server

use crate::utils::json::{parse_json, JsonValue};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get the default path for target database
pub fn default_target_db_path() -> PathBuf {
    PathBuf::from("mcp-targets.json")
}

/// Get current Unix timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A tracked target entry
#[derive(Clone)]
pub struct TargetEntry {
    pub name: String,
    pub target: String,
    pub notes: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl TargetEntry {
    /// Convert entry to JSON representation
    pub fn to_json(&self) -> JsonValue {
        let fields = vec![
            ("name".to_string(), JsonValue::String(self.name.clone())),
            ("target".to_string(), JsonValue::String(self.target.clone())),
            (
                "created_at".to_string(),
                JsonValue::Number(self.created_at as f64),
            ),
            (
                "updated_at".to_string(),
                JsonValue::Number(self.updated_at as f64),
            ),
            (
                "notes".to_string(),
                self.notes
                    .as_ref()
                    .map(|n| JsonValue::String(n.clone()))
                    .unwrap_or(JsonValue::Null),
            ),
        ];
        JsonValue::object(fields)
    }
}

/// Database for managing tracked targets
pub struct TargetDatabase {
    path: PathBuf,
    pub targets: Vec<TargetEntry>,
    dirty: bool,
}

impl TargetDatabase {
    /// Load target database from file
    pub fn load(path: PathBuf) -> Self {
        let mut db = TargetDatabase {
            path,
            targets: Vec::new(),
            dirty: false,
        };

        if let Ok(contents) = fs::read_to_string(&db.path) {
            if let Ok(json) = parse_json(&contents) {
                if let Some(array) = json.get("targets").and_then(|value| value.as_array()) {
                    for item in array {
                        if let Some(entry) = TargetDatabase::entry_from_json(item) {
                            db.targets.push(entry);
                        }
                    }
                }
            }
        }

        db
    }

    /// Parse a TargetEntry from JSON
    fn entry_from_json(value: &JsonValue) -> Option<TargetEntry> {
        let name = value.get("name")?.as_str()?;
        let target = value.get("target")?.as_str()?;
        let notes = value
            .get("notes")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let created_at = value
            .get("created_at")
            .and_then(|v| v.as_f64())
            .map(|v| v as u64)
            .unwrap_or_else(current_timestamp);
        let updated_at = value
            .get("updated_at")
            .and_then(|v| v.as_f64())
            .map(|v| v as u64)
            .unwrap_or(created_at);

        Some(TargetEntry {
            name: name.to_string(),
            target: target.to_string(),
            notes,
            created_at,
            updated_at,
        })
    }

    /// Insert or update a target
    pub fn upsert(&mut self, name: &str, target: &str, notes: Option<&str>) -> (bool, TargetEntry) {
        let normalized_notes = notes.map(|n| n.trim()).filter(|s| !s.is_empty());
        let now = current_timestamp();

        for entry in &mut self.targets {
            if entry.name.eq_ignore_ascii_case(name) {
                entry.name = name.to_string();
                entry.target = target.to_string();
                entry.notes = normalized_notes.map(|n| n.to_string());
                entry.updated_at = now;
                self.dirty = true;
                return (false, entry.clone());
            }
        }

        let new_entry = TargetEntry {
            name: name.to_string(),
            target: target.to_string(),
            notes: normalized_notes.map(|n| n.to_string()),
            created_at: now,
            updated_at: now,
        };
        self.targets.push(new_entry.clone());
        self.dirty = true;
        (true, new_entry)
    }

    /// Remove a target by name
    pub fn remove(&mut self, name: &str) -> Option<TargetEntry> {
        let index = self
            .targets
            .iter()
            .position(|entry| entry.name.eq_ignore_ascii_case(name));
        if let Some(idx) = index {
            self.dirty = true;
            Some(self.targets.remove(idx))
        } else {
            None
        }
    }

    /// Persist changes to file
    pub fn persist(&mut self) -> Result<(), String> {
        if !self.dirty {
            return Ok(());
        }

        let records = self
            .targets
            .iter()
            .map(|entry| entry.to_json())
            .collect::<Vec<JsonValue>>();

        let payload = JsonValue::object(vec![("targets".to_string(), JsonValue::array(records))])
            .to_json_string();

        fs::write(&self.path, payload)
            .map_err(|e| format!("failed to write {}: {}", self.path.display(), e))?;
        self.dirty = false;
        Ok(())
    }
}
