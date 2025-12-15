use super::{Accessor, AccessorInfo, AccessorResult};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    state: String,
    uid: u32,
    cmdline: Vec<String>,
}

pub struct ProcessAccessor;

impl ProcessAccessor {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "linux")]
    fn list_processes(&self) -> AccessorResult {
        let mut processes = Vec::new();
        let proc_dir = Path::new("/proc");

        if !proc_dir.exists() {
            return AccessorResult::error("/proc filesystem not found");
        }

        match fs::read_dir(proc_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Some(file_name) = path.file_name() {
                            let file_name_str = file_name.to_string_lossy();
                            if let Ok(pid) = file_name_str.parse::<u32>() {
                                if let Some(info) = self.get_process_info(pid, &path) {
                                    processes.push(info);
                                }
                            }
                        }
                    }
                }
                AccessorResult::success(json!(processes))
            },
            Err(e) => AccessorResult::error(&format!("Failed to read /proc: {}", e))
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn list_processes(&self) -> AccessorResult {
        AccessorResult::error("Process listing only implemented for Linux currently")
    }

    #[cfg(target_os = "linux")]
    fn get_process_info(&self, pid: u32, path: &Path) -> Option<ProcessInfo> {
        // Read /proc/[pid]/stat for basic info
        // format: pid (comm) state ppid ...
        let stat_path = path.join("stat");
        let stat_content = fs::read_to_string(&stat_path).ok()?;

        // Parse stat (careful with process names containing spaces/parens)
        let parts: Vec<&str> = stat_content.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        // Find the last closing parenthesis to handle names with parens
        let r_paren_idx = stat_content.rfind(')')?;
        let after_paren = &stat_content[r_paren_idx+2..]; // skip ") "
        let stat_fields: Vec<&str> = after_paren.split_whitespace().collect();

        if stat_fields.len() < 2 {
            return None;
        }

        let state = stat_fields[0].to_string();
        let ppid = stat_fields[1].parse::<u32>().unwrap_or(0);

        // Name is between first ( and last )
        let l_paren_idx = stat_content.find('(')?;
        let name = stat_content[l_paren_idx+1..r_paren_idx].to_string();

        // Read cmdline
        let cmdline_path = path.join("cmdline");
        let cmdline_content = fs::read_to_string(cmdline_path).unwrap_or_default();
        let cmdline: Vec<String> = cmdline_content
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        // Read status for UID
        let status_path = path.join("status");
        let uid = if let Ok(status) = fs::read_to_string(status_path) {
            status.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        Some(ProcessInfo {
            pid,
            ppid,
            name,
            state,
            uid,
            cmdline,
        })
    }

    fn build_tree(&self) -> AccessorResult {
        let result = self.list_processes();
        if !result.success {
            return result;
        }

        let processes: Vec<ProcessInfo> = serde_json::from_value(result.data.unwrap()).unwrap_or_default();
        
        // Build map of children
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut roots = Vec::new();
        let mut process_map: HashMap<u32, ProcessInfo> = HashMap::new();

        for p in &processes {
            process_map.insert(p.pid, p.clone());
            if p.ppid == 0 {
                roots.push(p.pid);
            } else {
                children.entry(p.ppid).or_default().push(p.pid);
            }
        }

        // If a process has a PPID that doesn't exist in our list (e.g. we couldn't read it), treat it as a root
        for p in &processes {
            if p.ppid != 0 && !process_map.contains_key(&p.ppid) {
                roots.push(p.pid);
            }
        }

        let tree = self.recursive_build_tree(&roots, &children, &process_map);
        AccessorResult::success(tree)
    }

    fn recursive_build_tree(&self, pids: &[u32], children: &HashMap<u32, Vec<u32>>, info_map: &HashMap<u32, ProcessInfo>) -> Value {
        let mut nodes = Vec::new();
        
        for pid in pids {
            if let Some(info) = info_map.get(pid) {
                let mut node = json!({
                    "pid": info.pid,
                    "name": info.name,
                    "user": info.uid, // Could resolve to username if we had passwd parsing
                });

                if let Some(child_pids) = children.get(pid) {
                    node["children"] = self.recursive_build_tree(child_pids, children, info_map);
                }

                nodes.push(node);
            }
        }
        
        Value::Array(nodes)
    }
}

impl Accessor for ProcessAccessor {
    fn name(&self) -> &str {
        "process"
    }

    fn info(&self) -> AccessorInfo {
        AccessorInfo {
            name: "Process Accessor".to_string(),
            description: "Interact with system processes".to_string(),
            methods: vec![
                "list".to_string(),
                "tree".to_string(),
            ],
        }
    }

    fn execute(&self, method: &str, _args: &HashMap<String, String>) -> AccessorResult {
        match method {
            "list" => self.list_processes(),
            "tree" => self.build_tree(),
            _ => AccessorResult::error(&format!("Unknown method: {}", method)),
        }
    }
}
