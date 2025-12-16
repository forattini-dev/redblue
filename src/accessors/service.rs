use super::{Accessor, AccessorInfo, AccessorResult};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct ServiceAccessor;

impl ServiceAccessor {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "linux")]
    fn list_services(&self) -> AccessorResult {
        let mut services = Vec::new();
        let dirs = [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
        ];

        for dir in dirs {
            let path = Path::new(dir);
            if path.exists() {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().map(|e| e == "service").unwrap_or(false) {
                            let name = path
                                .file_stem()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string();
                            let description = self.parse_description(&path).unwrap_or_default();

                            services.push(json!({
                                "name": name,
                                "path": path.to_string_lossy(),
                                "description": description,
                                "type": "systemd"
                            }));
                        }
                    }
                }
            }
        }

        // Sort by name
        services.sort_by(|a, b| {
            let a_name = a["name"].as_str().unwrap_or("");
            let b_name = b["name"].as_str().unwrap_or("");
            a_name.cmp(b_name)
        });

        // Deduplicate (simple by name)
        services.dedup_by(|a, b| a["name"].as_str() == b["name"].as_str());

        AccessorResult::success(json!(services))
    }

    #[cfg(target_os = "linux")]
    fn parse_description(&self, path: &Path) -> Option<String> {
        use std::io::BufRead;
        if let Ok(file) = fs::File::open(path) {
            let reader = std::io::BufReader::new(file);
            for line in reader.lines().flatten() {
                if line.starts_with("Description=") {
                    return Some(line.trim_start_matches("Description=").to_string());
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    fn list_services(&self) -> AccessorResult {
        AccessorResult::error("Service listing only implemented for Linux currently")
    }
}

impl Accessor for ServiceAccessor {
    fn name(&self) -> &str {
        "service"
    }

    fn info(&self) -> AccessorInfo {
        AccessorInfo {
            name: "Service Accessor".to_string(),
            description: "Interact with system services".to_string(),
            methods: vec!["list".to_string()],
        }
    }

    fn execute(&self, method: &str, _args: &HashMap<String, String>) -> AccessorResult {
        match method {
            "list" => self.list_services(),
            _ => AccessorResult::error(&format!("Unknown method: {}", method)),
        }
    }
}
