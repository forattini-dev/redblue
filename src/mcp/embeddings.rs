//! Docs index loader for the MCP `rb.search-docs` tool.
//!
//! This module loads a precomputed index of redblue Markdown
//! documentation (title, section, keywords, excerpt). Despite the
//! historical module name, it does **not** contain or use vector
//! embeddings — ranking in `src/mcp/search.rs` is purely Jaccard over
//! keyword tokens. The module keeps the `embeddings` name and the
//! `EmbeddedDocument` / `EmbeddingsData` types only to preserve the
//! JSON schema consumed by external MCP clients.
//!
//! Load order:
//!   1. Local cache (`~/.cache/rb/docs-index-{version}.json` or the
//!      legacy `embeddings-{version}.json`).
//!   2. Bundled file (`src/mcp/data/docs-index.json`, legacy
//!      `embeddings.json`).
//!   3. GitHub release download of `docs-index.json`.

use crate::protocols::http::HttpClient;
use crate::utils::json::parse_json;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// A single indexed documentation chunk.
#[derive(Debug, Clone)]
pub struct EmbeddedDocument {
  pub id: String,
  pub path: String,
  pub title: String,
  pub section: Option<String>,
  pub category: String,
  pub keywords: Vec<String>,
  pub content: String,
}

/// Docs index loaded from JSON.
#[derive(Debug)]
pub struct EmbeddingsData {
  pub version: String,
  pub documents: Vec<EmbeddedDocument>,
}

/// Configuration for the docs index loader.
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
      version: crate::version::current_version().to_string(),
    }
  }
}

fn cache_dir() -> Option<PathBuf> {
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

fn cache_candidates(version: &str) -> Vec<PathBuf> {
  let Some(dir) = cache_dir() else {
    return Vec::new();
  };
  vec![
    dir.join(format!("docs-index-{}.json", version)),
    dir.join(format!("embeddings-{}.json", version)),
  ]
}

fn primary_cache_path(version: &str) -> Option<PathBuf> {
  cache_dir().map(|dir| dir.join(format!("docs-index-{}.json", version)))
}

fn load_from_cache(version: &str) -> Option<String> {
  for path in cache_candidates(version) {
    if path.exists() {
      if let Ok(content) = fs::read_to_string(&path) {
        return Some(content);
      }
    }
  }
  None
}

fn save_to_cache(version: &str, content: &str) -> Result<(), String> {
  let path = primary_cache_path(version).ok_or("Could not determine cache path")?;

  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).map_err(|e| format!("Failed to create cache directory: {}", e))?;
  }

  let mut file =
    fs::File::create(&path).map_err(|e| format!("Failed to create cache file: {}", e))?;

  file
    .write_all(content.as_bytes())
    .map_err(|e| format!("Failed to write cache file: {}", e))?;

  Ok(())
}

fn load_bundled() -> Option<String> {
  let paths = [
    PathBuf::from("src/mcp/data/docs-index.json"),
    PathBuf::from("./src/mcp/data/docs-index.json"),
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

fn download_from_github(repository: &str, version: &str) -> Result<String, String> {
  let client = HttpClient::new();

  for asset in ["docs-index.json", "embeddings.json"] {
    for prefix in ["v", ""] {
      let url = format!(
        "https://github.com/{}/releases/download/{}{}/{}",
        repository, prefix, version, asset
      );
      let response = client
        .get(&url)
        .map_err(|e| format!("Failed to download {}: {}", asset, e))?;

      if response.status_code == 200 {
        return String::from_utf8(response.body)
          .map_err(|e| format!("Invalid UTF-8 in {} response: {}", asset, e));
      }
    }
  }

  Err(format!("Docs index not found for version {}", version))
}

fn parse_embeddings(json_str: &str) -> Result<EmbeddingsData, String> {
  let json = parse_json(json_str).map_err(|e| format!("Failed to parse docs index JSON: {}", e))?;

  let version = json
    .get("version")
    .and_then(|v| v.as_str())
    .unwrap_or("unknown")
    .to_string();

  let docs_array = json
    .get("documents")
    .and_then(|v| v.as_array())
    .ok_or("Missing 'documents' array in docs index")?;

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

    let section = doc
      .get("section")
      .and_then(|v| v.as_str())
      .map(String::from);

    let category = doc
      .get("category")
      .and_then(|v| v.as_str())
      .unwrap_or("general")
      .to_string();

    let keywords = doc
      .get("keywords")
      .and_then(|v| v.as_array())
      .map(|arr| {
        arr
          .iter()
          .filter_map(|k| k.as_str().map(String::from))
          .collect()
      })
      .unwrap_or_default();

    let content = doc
      .get("content")
      .and_then(|v| v.as_str())
      .unwrap_or("")
      .to_string();

    documents.push(EmbeddedDocument {
      id,
      path,
      title,
      section,
      category,
      keywords,
      content,
    });
  }

  Ok(EmbeddingsData { version, documents })
}

/// Load the docs index with fallback chain: cache → bundled → download.
pub fn load_embeddings(config: &EmbeddingsLoaderConfig) -> Result<EmbeddingsData, String> {
  if !config.force_download {
    if let Some(cached) = load_from_cache(&config.version) {
      return parse_embeddings(&cached);
    }
  }

  if let Some(bundled) = load_bundled() {
    return parse_embeddings(&bundled);
  }

  if config.offline {
    return Err("Docs index not found in cache and offline mode is enabled".to_string());
  }

  let content = download_from_github(&config.repository, &config.version)?;

  if let Err(e) = save_to_cache(&config.version, &content) {
    eprintln!("Warning: Failed to cache docs index: {}", e);
  }

  parse_embeddings(&content)
}

/// Check if docs index is available locally (cached or bundled).
pub fn embeddings_available(version: &str) -> bool {
  load_from_cache(version).is_some() || load_bundled().is_some()
}

/// Get cache info for diagnostics.
pub fn cache_info(version: &str) -> String {
  let mut info = Vec::new();

  for path in cache_candidates(version) {
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
    }
  }

  if info.is_empty() {
    info.push("Cache: not found".to_string());
  }

  info.push(format!(
    "Bundled: {}",
    if load_bundled().is_some() {
      "yes"
    } else {
      "no"
    }
  ));

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
