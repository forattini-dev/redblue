//! Script loader for redblue scripting engine
//! Loads script definitions from various sources

use super::{definitions, engine::Script, engine::ScriptStep};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

/// Load built-in scripts
pub fn load_builtin_scripts() -> Vec<Script> {
    definitions::get_builtin_scripts()
}

/// Load scripts from a directory
pub fn load_scripts_from_dir(path: &str) -> Result<Vec<Script>, String> {
    let root = Path::new(path);
    if !root.exists() {
        return Err(format!("Scripts path does not exist: {}", path));
    }
    if !root.is_dir() {
        return Err(format!("Scripts path is not a directory: {}", path));
    }

    let mut scripts = Vec::new();
    let mut stack = Vec::new();
    stack.push(root.to_path_buf());

    while let Some(current_dir) = stack.pop() {
        for entry in fs::read_dir(&current_dir).map_err(|e| {
            format!(
                "Failed to read scripts directory '{}': {}",
                current_dir.display(),
                e
            )
        })? {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                stack.push(entry_path);
                continue;
            }

            if !is_script_file(&entry_path) {
                continue;
            }

            if let Some(script) = parse_script_file(&entry_path)? {
                scripts.push(script);
            }
        }
    }

    Ok(scripts)
}

fn is_script_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext, "rbs" | "rbscript" | "script" | "txt"))
        .unwrap_or(false)
}

fn parse_script_file(path: &Path) -> Result<Option<Script>, String> {
    let mut content = String::new();
    fs::File::open(path)
        .map_err(|e| format!("Failed to open script file '{}': {}", path.display(), e))?
        .read_to_string(&mut content)
        .map_err(|e| format!("Failed to read script file '{}': {}", path.display(), e))?;

    let mut id = None;
    let mut name = None;
    let mut category = None;
    let mut description = None;
    let mut steps = Vec::new();

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim();

        match key.as_str() {
            "id" => id = Some(value.to_string()),
            "name" => name = Some(value.to_string()),
            "category" => category = Some(value.to_string()),
            "description" => description = Some(value.to_string()),
            "step" => {
                if let Ok(step) = parse_http_step(value) {
                    steps.push(step);
                } else if !value.is_empty() {
                    return Err(format!(
                        "Invalid script step in '{}': {}",
                        path.display(),
                        value
                    ));
                }
            }
            _ => {}
        }
    }

    if steps.is_empty() {
        return Ok(None);
    }

    let script_id = id.unwrap_or_else(|| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .map_or_else(|| "script".to_string(), |s| s.to_string())
    });

    Ok(Some(Script {
        id: script_id.clone(),
        name: name.unwrap_or(script_id),
        category: category.unwrap_or_else(|| "custom".to_string()),
        description: description.unwrap_or_else(|| "User-defined script".to_string()),
        steps,
    }))
}

fn parse_http_step(value: &str) -> Result<ScriptStep, String> {
    let mut parts = value.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "Missing HTTP method".to_string())?
        .to_uppercase();
    let path = parts
        .next()
        .ok_or_else(|| "Missing HTTP path".to_string())?
        .to_string();

    let mut match_status = None;
    let mut match_body = None;
    let mut body = None;

    for part in parts {
        if let Some(value) = part.strip_prefix("status=") {
            match_status = value.parse::<u16>().ok();
        } else if let Some(value) = part.strip_prefix("status:") {
            match_status = value.parse::<u16>().ok();
        } else if let Some(value) = part.strip_prefix("body=") {
            body = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("body:") {
            body = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("contains=") {
            match_body = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("contains:") {
            match_body = Some(value.to_string());
        }
    }

    Ok(ScriptStep::HttpRequest {
        method,
        path,
        headers: HashMap::new(),
        body,
        match_status,
        match_body,
    })
}
