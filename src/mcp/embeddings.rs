//! Embeddings loader for MCP semantic search.
//!
//! This module handles loading pre-computed document embeddings from:
//! 1. Local cache (~/.cache/rb/embeddings-{version}.json)
//! 2. GitHub Release download (fallback)
//!
//! The embeddings are generated at CI build time using the BGE-small model
//! and attached to GitHub releases.

use crate::protocols::http::HttpClient;
use crate::utils::json::parse_json;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// Represents a document with its embedding vector
#[derive(Debug, Clone)]
pub struct EmbeddedDocument {
    pub id: String,
    pub path: String,
    pub title: String,
    pub section: Option<String>,
    pub category: String,
    pub keywords: Vec<String>,
    pub content: String,
    pub vector: Option<Vec<f32>>,
}

/// Embeddings data loaded from JSON
#[derive(Debug)]
pub struct EmbeddingsData {
    pub version: String,
    pub model: Option<String>,
    pub dimensions: Option<usize>,
    pub has_vectors: bool,
    pub documents: Vec<EmbeddedDocument>,
}

/// Configuration for embeddings loader
pub struct EmbeddingsLoaderConfig {
    /// Force download even if cache exists
    pub force_download: bool,
    /// Work offline (don't download)
    pub offline: bool,
    /// GitHub repository (owner/repo)
    pub repository: String,
    /// Version to download
    pub version: String,
}

impl Default for EmbeddingsLoaderConfig {
    fn default() -> Self {
        Self {
            force_download: false,
            offline: false,
            repository: "tetigo/redblue".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Get the cache directory path
fn cache_dir() -> Option<PathBuf> {
    // Try XDG_CACHE_HOME first, then fallback to ~/.cache
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg).join("rb"));
    }

    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home).join(".cache").join("rb"));
    }

    #[cfg(windows)]
    if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
        return Some(PathBuf::from(appdata).join("rb").join("cache"));
    }

    None
}

/// Get the path to cached embeddings file
fn cache_path(version: &str) -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(format!("embeddings-{}.json", version)))
}

/// Load embeddings from local cache
fn load_from_cache(version: &str) -> Option<String> {
    let path = cache_path(version)?;
    if path.exists() {
        fs::read_to_string(&path).ok()
    } else {
        None
    }
}

/// Save embeddings to local cache
fn save_to_cache(version: &str, content: &str) -> Result<(), String> {
    let path = cache_path(version).ok_or("Could not determine cache path")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create cache directory: {}", e))?;
    }

    let mut file =
        fs::File::create(&path).map_err(|e| format!("Failed to create cache file: {}", e))?;

    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write cache file: {}", e))?;

    Ok(())
}

/// Try to load bundled embeddings from src/mcp/data/
fn load_bundled() -> Option<String> {
    // Try relative to current directory (development)
    let paths = [
        PathBuf::from("src/mcp/data/embeddings.json"),
        PathBuf::from("./src/mcp/data/embeddings.json"),
    ];

    for path in &paths {
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                return Some(content);
            }
        }
    }

    None
}

/// Download embeddings from GitHub Release
fn download_from_github(repository: &str, version: &str) -> Result<String, String> {
    let url = format!(
        "https://github.com/{}/releases/download/v{}/embeddings.json",
        repository, version
    );

    let client = HttpClient::new();
    let response = client
        .get(&url)
        .map_err(|e| format!("Failed to download embeddings: {}", e))?;

    if response.status_code != 200 {
        // Try without 'v' prefix
        let url_no_v = format!(
            "https://github.com/{}/releases/download/{}/embeddings.json",
            repository, version
        );

        let response2 = client
            .get(&url_no_v)
            .map_err(|e| format!("Failed to download embeddings: {}", e))?;

        if response2.status_code != 200 {
            return Err(format!(
                "Embeddings not found for version {} (HTTP {})",
                version, response2.status_code
            ));
        }

        return String::from_utf8(response2.body)
            .map_err(|e| format!("Invalid UTF-8 in embeddings response: {}", e));
    }

    String::from_utf8(response.body)
        .map_err(|e| format!("Invalid UTF-8 in embeddings response: {}", e))
}

/// Parse embeddings JSON into structured data
fn parse_embeddings(json_str: &str) -> Result<EmbeddingsData, String> {
    let json = parse_json(json_str).map_err(|e| format!("Failed to parse embeddings JSON: {}", e))?;

    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let model = json.get("model").and_then(|v| v.as_str()).map(String::from);

    let dimensions = json
        .get("dimensions")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize);

    let has_vectors = json
        .get("has_vectors")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let docs_array = json
        .get("documents")
        .and_then(|v| v.as_array())
        .ok_or("Missing 'documents' array in embeddings")?;

    let mut documents = Vec::with_capacity(docs_array.len());

    for doc in docs_array {
        let id = doc
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let path = doc
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let title = doc
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let section = doc.get("section").and_then(|v| v.as_str()).map(String::from);

        let category = doc
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .to_string();

        let keywords = doc
            .get("keywords")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|k| k.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let content = doc
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let vector = doc.get("vector").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|n| n.as_f64().map(|f| f as f32))
                .collect()
        });

        documents.push(EmbeddedDocument {
            id,
            path,
            title,
            section,
            category,
            keywords,
            content,
            vector,
        });
    }

    Ok(EmbeddingsData {
        version,
        model,
        dimensions,
        has_vectors,
        documents,
    })
}

/// Load embeddings with fallback strategy:
/// 1. Local cache
/// 2. Bundled file (development)
/// 3. GitHub Release download
pub fn load_embeddings(config: &EmbeddingsLoaderConfig) -> Result<EmbeddingsData, String> {
    // 1. Try cache first (unless force download)
    if !config.force_download {
        if let Some(cached) = load_from_cache(&config.version) {
            return parse_embeddings(&cached);
        }
    }

    // 2. Try bundled file (development mode)
    if let Some(bundled) = load_bundled() {
        return parse_embeddings(&bundled);
    }

    // 3. Download from GitHub (unless offline)
    if config.offline {
        return Err("Embeddings not found in cache and offline mode is enabled".to_string());
    }

    let content = download_from_github(&config.repository, &config.version)?;

    // Save to cache for next time
    if let Err(e) = save_to_cache(&config.version, &content) {
        eprintln!("Warning: Failed to cache embeddings: {}", e);
    }

    parse_embeddings(&content)
}

/// Check if embeddings are available (cached or bundled)
pub fn embeddings_available(version: &str) -> bool {
    load_from_cache(version).is_some() || load_bundled().is_some()
}

/// Get cache info for diagnostics
pub fn cache_info(version: &str) -> String {
    let cache = cache_path(version);
    let bundled = load_bundled().is_some();

    let mut info = Vec::new();

    if let Some(path) = cache {
        if path.exists() {
            if let Ok(metadata) = fs::metadata(&path) {
                info.push(format!(
                    "Cache: {} ({} bytes)",
                    path.display(),
                    metadata.len()
                ));
            } else {
                info.push(format!("Cache: {} (exists)", path.display()));
            }
        } else {
            info.push(format!("Cache: {} (not found)", path.display()));
        }
    } else {
        info.push("Cache: unavailable (no home directory)".to_string());
    }

    info.push(format!("Bundled: {}", if bundled { "yes" } else { "no" }));

    info.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_dir() {
        let dir = cache_dir();
        assert!(dir.is_some());
    }

    #[test]
    fn test_parse_embeddings_minimal() {
        let json = r#"{
            "version": "1.0",
            "has_vectors": false,
            "documents": [
                {
                    "id": "doc-0",
                    "path": "README.md",
                    "title": "Test",
                    "category": "general",
                    "keywords": ["test"],
                    "content": "Hello world"
                }
            ]
        }"#;

        let result = parse_embeddings(json);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.version, "1.0");
        assert_eq!(data.documents.len(), 1);
        assert_eq!(data.documents[0].title, "Test");
    }
}
