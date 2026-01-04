//! Documentation search and indexing for MCP server

use crate::mcp::types::DocHit;
use crate::utils::json::JsonValue;
use std::fs;
use std::path::{Path, PathBuf};

/// Truncate text for preview display
pub fn truncate_preview(text: &str) -> String {
    let trimmed = text.trim();
    const MAX_PREVIEW: usize = 160;
    if trimmed.len() <= MAX_PREVIEW {
        trimmed.replace('\n', " ⏎ ")
    } else {
        let mut snippet = trimmed[..MAX_PREVIEW].to_string();
        snippet.push_str(" …");
        snippet.replace('\n', " ⏎ ")
    }
}

/// Build an index of all documentation files
pub fn build_document_index(max_sections: usize) -> Vec<JsonValue> {
    let mut documents = Vec::new();
    for path in all_document_paths() {
        let content = match fs::read_to_string(&path) {
            Ok(data) => data,
            Err(_) => continue,
        };
        let (title, sections) = summarize_markdown(&content, max_sections);
        let section_values = sections
            .into_iter()
            .map(|(level, heading, line)| {
                JsonValue::object(vec![
                    ("level".to_string(), JsonValue::Number(level as f64)),
                    ("title".to_string(), JsonValue::String(heading.clone())),
                    ("line".to_string(), JsonValue::Number(line as f64)),
                    ("slug".to_string(), JsonValue::String(slugify(&heading))),
                ])
            })
            .collect::<Vec<JsonValue>>();

        documents.push(JsonValue::object(vec![
            (
                "path".to_string(),
                JsonValue::String(path.to_string_lossy().to_string()),
            ),
            ("title".to_string(), JsonValue::String(title)),
            ("sections".to_string(), JsonValue::Array(section_values)),
        ]));
    }
    documents
}

/// Summarize markdown content extracting title and section headings
pub fn summarize_markdown(
    content: &str,
    max_sections: usize,
) -> (String, Vec<(usize, String, usize)>) {
    let mut title = String::new();
    let mut sections = Vec::new();

    for (index, line) in content.lines().enumerate() {
        if let Some((level, heading_text)) = parse_heading(line) {
            if title.is_empty() && level == 1 {
                title = heading_text.to_string();
            }
            if sections.len() < max_sections {
                sections.push((level, heading_text.to_string(), index + 1));
            }
        }
    }

    if title.is_empty() {
        title = "Untitled".to_string();
    }

    (title, sections)
}

/// Parse a markdown heading line
pub fn parse_heading(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('#') {
        return None;
    }
    let level = trimmed.bytes().take_while(|&b| b == b'#').count();
    if level > 6 {
        return None;
    }
    let text = trimmed[level..].trim();
    if text.is_empty() {
        return None;
    }
    Some((level, text))
}

/// Convert heading text to URL-friendly slug
pub fn slugify(input: &str) -> String {
    input
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<&str>>()
        .join("-")
}

/// Extract a section from markdown content by heading name
pub fn extract_markdown_section(content: &str, heading_name: &str) -> Option<String> {
    let heading_lower = heading_name.to_lowercase();
    let lines: Vec<&str> = content.lines().collect();
    let mut start_index: Option<usize> = None;
    let mut start_level: usize = 0;

    for (index, line) in lines.iter().enumerate() {
        if let Some((level, heading_text)) = parse_heading(line) {
            if heading_text.to_lowercase() == heading_lower {
                start_index = Some(index);
                start_level = level;
                break;
            }
        }
    }

    let start = start_index?;
    let mut end = lines.len();

    for (index, line) in lines.iter().enumerate().skip(start + 1) {
        if let Some((level, _)) = parse_heading(line) {
            if level <= start_level {
                end = index;
                break;
            }
        }
    }

    let section_lines = &lines[start..end];
    Some(section_lines.join("\n"))
}

/// Resolve a requested doc path to an actual file path
pub fn resolve_doc_path(requested: &str) -> Option<PathBuf> {
    let candidate = PathBuf::from(requested);

    // Reject path traversal attempts
    if candidate
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }

    let normalized = candidate.to_string_lossy().to_string();
    for path in all_document_paths() {
        if path.to_string_lossy() == normalized {
            return Some(path);
        }
    }
    None
}

/// Get all document paths in the project
pub fn all_document_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("README.md"),
        PathBuf::from("AGENTS.md"),
        PathBuf::from("CLAUDE.md"),
    ];
    collect_doc_paths(Path::new("docs"), &mut paths);
    paths
}

/// Search documentation for a query string
pub fn search_documentation(query: &str, max_hits: usize) -> Vec<DocHit> {
    let mut hits = Vec::new();
    let lowercase_query = query.to_lowercase();

    for path in all_document_paths() {
        if hits.len() >= max_hits {
            break;
        }
        if let Some(hit) = search_file_for_query(&path, &lowercase_query, max_hits - hits.len()) {
            hits.extend(hit);
        }
    }

    hits
}

/// Recursively collect documentation file paths
pub fn collect_doc_paths(root: &Path, accumulator: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_doc_paths(&path, accumulator);
        } else if let Some(ext) = path.extension() {
            if ext == "md" || ext == "txt" {
                accumulator.push(path);
            }
        }
    }
}

/// Search a single file for a query
pub fn search_file_for_query(path: &Path, query: &str, remaining: usize) -> Option<Vec<DocHit>> {
    if remaining == 0 {
        return Some(Vec::new());
    }
    let content = fs::read_to_string(path).ok()?;
    let mut hits = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.to_lowercase().contains(query) {
            hits.push(DocHit {
                path: path.to_string_lossy().to_string(),
                line: index + 1,
                snippet: line.trim().to_string(),
            });
            if hits.len() >= remaining {
                break;
            }
        }
    }
    if hits.is_empty() {
        None
    } else {
        Some(hits)
    }
}
