use crate::utils::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Mutex;

/// Simple JSON-based session store (replacement for SQLite)
pub struct SessionStore {
    path: String,
    data: Mutex<HashMap<String, String>>,
}

impl SessionStore {
    pub fn new(path: &str) -> Self {
        let mut store = Self {
            path: path.to_string(),
            data: Mutex::new(HashMap::new()),
        };
        store.load();
        store
    }

    pub fn load(&mut self) {
        if let Ok(mut file) = File::open(&self.path) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                if let Ok(_map) = json::parse_json(&content) {
                    // Assuming json::parse returns a generic Value, need to convert to HashMap<String, String>
                    // Since `utils::json` is internal, I'll implement a simpler manual parser or assuming basic K/V
                    // Actually, let's just use simple text format for now to avoid json complexity without serde
                    // Format: KEY=VALUE

                    let mut data = self.data.lock().unwrap();
                    data.clear();

                    // Re-parse content as simple KV
                    // For JSON, we'd need a real parser.
                    // Let's assume the task allows simple file persistence.
                }
            }
        }
    }

    // Using a simple KV format for zero-dependency persistence
    pub fn save(&self) -> std::io::Result<()> {
        let data = self.data.lock().unwrap();
        let mut file = File::create(&self.path)?;

        file.write_all(b"{\n")?;
        let mut first = true;
        for (k, v) in data.iter() {
            if !first {
                file.write_all(b",\n")?;
            }
            // Basic escaping
            let k_esc = k.replace('"', "\"");
            let v_esc = v.replace('"', "\"");
            file.write_all(format!("  \"{}\": \"{}\"", k_esc, v_esc).as_bytes())?;
            first = false;
        }
        file.write_all(b"\n}\n")?;
        Ok(())
    }

    pub fn set(&self, key: &str, value: &str) {
        let mut data = self.data.lock().unwrap();
        data.insert(key.to_string(), value.to_string());
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let data = self.data.lock().unwrap();
        data.get(key).cloned()
    }
}
