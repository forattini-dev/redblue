use super::{Accessor, AccessorInfo, AccessorResult};
use crate::crypto::{md5, sha1, sha256};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

pub struct FileAccessor;

impl FileAccessor {
    pub fn new() -> Self {
        Self
    }

    fn list(&self, path_str: &str) -> AccessorResult {
        let path = Path::new(path_str);
        if !path.exists() {
            return AccessorResult::error(&format!("Path does not exist: {}", path_str));
        }

        if !path.is_dir() {
            return AccessorResult::error(&format!("Path is not a directory: {}", path_str));
        }

        let mut files = Vec::new();
        match fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        let metadata = entry.metadata().ok();

                        let name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        let is_dir = path.is_dir();
                        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                        let modified = metadata
                            .as_ref()
                            .and_then(|m| m.modified().ok())
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        files.push(json!({
                            "name": name,
                            "path": path.to_string_lossy(),
                            "is_dir": is_dir,
                            "size": size,
                            "modified": modified
                        }));
                    }
                }
                AccessorResult::success(Value::Array(files))
            }
            Err(e) => AccessorResult::error(&format!("Failed to list directory: {}", e)),
        }
    }

    fn read(&self, path_str: &str) -> AccessorResult {
        match fs::read_to_string(path_str) {
            Ok(content) => AccessorResult::success(Value::String(content)),
            Err(e) => AccessorResult::error(&format!("Failed to read file: {}", e)),
        }
    }

    fn hash(&self, path_str: &str, algorithm: &str) -> AccessorResult {
        let mut file = match fs::File::open(path_str) {
            Ok(f) => f,
            Err(e) => return AccessorResult::error(&format!("Failed to open file: {}", e)),
        };

        let mut buffer = Vec::new();
        if let Err(e) = file.read_to_end(&mut buffer) {
            return AccessorResult::error(&format!("Failed to read file: {}", e));
        }

        let hash = match algorithm.to_lowercase().as_str() {
            "md5" => {
                let digest = md5::md5(&buffer);
                digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            }
            "sha1" => {
                let digest = sha1::sha1(&buffer);
                digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            }
            "sha256" => {
                let digest = sha256::sha256(&buffer);
                digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            }
            _ => {
                return AccessorResult::error(&format!(
                    "Unknown hash algorithm: {}. Supported: md5, sha1, sha256",
                    algorithm
                ))
            }
        };

        AccessorResult::success(json!({
            "path": path_str,
            "algorithm": algorithm,
            "hash": hash
        }))
    }

    fn search(&self, path_str: &str, pattern: &str) -> AccessorResult {
        let path = Path::new(path_str);
        if !path.exists() {
            return AccessorResult::error(&format!("Path does not exist: {}", path_str));
        }

        let mut matches = Vec::new();
        self.recursive_search(path, pattern, &mut matches);

        AccessorResult::success(Value::Array(matches))
    }

    fn recursive_search(&self, dir: &Path, pattern: &str, matches: &mut Vec<Value>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap_or_default().to_string_lossy();

                if name.contains(pattern) {
                    matches.push(json!({
                        "name": name,
                        "path": path.to_string_lossy(),
                        "is_dir": path.is_dir()
                    }));
                }

                if path.is_dir() {
                    self.recursive_search(&path, pattern, matches);
                }
            }
        }
    }
}

impl Accessor for FileAccessor {
    fn name(&self) -> &str {
        "file"
    }

    fn info(&self) -> AccessorInfo {
        AccessorInfo {
            name: "File Accessor".to_string(),
            description: "Interact with the file system (list, read, hash, search)".to_string(),
            methods: vec![
                "list (path)".to_string(),
                "read (path)".to_string(),
                "hash (path, algorithm)".to_string(),
                "search (path, pattern)".to_string(),
            ],
        }
    }

    fn execute(&self, method: &str, args: &HashMap<String, String>) -> AccessorResult {
        match method {
            "list" => {
                let path = args
                    .get("path")
                    .or(args.get("arg0"))
                    .map(|s| s.as_str())
                    .unwrap_or(".");
                self.list(path)
            }
            "read" => {
                if let Some(path) = args.get("path").or(args.get("arg0")) {
                    self.read(path)
                } else {
                    AccessorResult::error("Missing 'path' argument")
                }
            }
            "hash" => {
                let path = args.get("path").or(args.get("arg0"));
                let algo = args
                    .get("algorithm")
                    .or(args.get("arg1"))
                    .map(|s| s.as_str())
                    .unwrap_or("sha256");

                if let Some(p) = path {
                    self.hash(p, algo)
                } else {
                    AccessorResult::error("Missing 'path' argument")
                }
            }
            "search" => {
                let path = args
                    .get("path")
                    .or(args.get("arg0"))
                    .map(|s| s.as_str())
                    .unwrap_or(".");
                let pattern = args.get("pattern").or(args.get("arg1"));

                if let Some(pat) = pattern {
                    self.search(path, pat)
                } else {
                    AccessorResult::error("Missing 'pattern' argument")
                }
            }
            _ => AccessorResult::error(&format!("Unknown method: {}", method)),
        }
    }
}
