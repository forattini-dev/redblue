use crate::mcp::search::{hybrid_search, SearchConfig, SearchMode};
use crate::mcp::server::McpServer;
use crate::mcp::server::{
  build_document_index, extract_markdown_section, resolve_doc_path, search_documentation,
};
use crate::mcp::types::ToolResult;
use crate::utils::json::JsonValue;

pub fn tool_search_docs(server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let query = args
    .get("query")
    .and_then(|value| value.as_str())
    .ok_or_else(|| "argument 'query' is required".to_string())?;

  if query.trim().is_empty() {
    return Err("query must not be empty".to_string());
  }

  // Try hybrid search with embeddings first
  server.ensure_embeddings_loaded();

  if let Some(ref embeddings) = server.embeddings {
    let config = SearchConfig {
      max_results: 10,
      min_score: 0.1,
      fuzzy_weight: 0.4,
      keyword_weight: 0.6,
      mode: SearchMode::Hybrid,
    };

    let results = hybrid_search(query, &embeddings.documents, &config);

    let json_hits: Vec<JsonValue> = results
      .iter()
      .map(|result| {
        JsonValue::object(vec![
          (
            "path".to_string(),
            JsonValue::String(result.document.path.clone()),
          ),
          (
            "title".to_string(),
            JsonValue::String(result.document.title.clone()),
          ),
          (
            "section".to_string(),
            result
              .document
              .section
              .as_ref()
              .map(|s| JsonValue::String(s.clone()))
              .unwrap_or(JsonValue::Null),
          ),
          ("score".to_string(), JsonValue::Number(result.score as f64)),
          (
            "match_type".to_string(),
            JsonValue::String(format!("{:?}", result.match_type)),
          ),
          (
            "highlights".to_string(),
            JsonValue::array(
              result
                .highlights
                .iter()
                .map(|h| JsonValue::String(h.clone()))
                .collect(),
            ),
          ),
          (
            "category".to_string(),
            JsonValue::String(result.document.category.clone()),
          ),
        ])
      })
      .collect();

    let mut lines = vec![format!(
      "Hybrid search results for '{}' ({} docs indexed):",
      query,
      embeddings.documents.len()
    )];
    if json_hits.is_empty() {
      lines.push("  - No matches found.".to_string());
    } else {
      for result in &results {
        let section_str = result
          .document
          .section
          .as_ref()
          .map(|s| format!(" > {}", s))
          .unwrap_or_default();
        lines.push(format!(
          "  - [{}] {} ({}{}) - score: {:.2}",
          result.document.category,
          result.document.title,
          result.document.path,
          section_str,
          result.score
        ));
        for highlight in result.highlights.iter().take(2) {
          lines.push(format!("      {}", highlight));
        }
      }
    }

    return Ok(ToolResult {
      text: lines.join("\n"),
      data: JsonValue::object(vec![
        ("query".to_string(), JsonValue::String(query.to_string())),
        ("mode".to_string(), JsonValue::String("hybrid".to_string())),
        (
          "indexed_docs".to_string(),
          JsonValue::Number(embeddings.documents.len() as f64),
        ),
        ("hits".to_string(), JsonValue::array(json_hits)),
      ]),
    });
  }

  let hits = search_documentation(query, 10);
  let json_hits = hits
    .into_iter()
    .map(|hit| {
      JsonValue::object(vec![
        ("path".to_string(), JsonValue::String(hit.path)),
        ("line".to_string(), JsonValue::Number(hit.line as f64)),
        ("snippet".to_string(), JsonValue::String(hit.snippet)),
      ])
    })
    .collect::<Vec<JsonValue>>();

  let mut lines = vec![format!("Search results for '{}' (basic mode):", query)];
  if json_hits.is_empty() {
    lines.push("  - No matches found.".to_string());
  } else {
    for hit in &json_hits {
      let path = hit.get("path").and_then(|v| v.as_str()).unwrap_or_default();
      let line = hit
        .get("line")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize)
        .unwrap_or(0);
      let snippet = hit
        .get("snippet")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
      lines.push(format!("  - {}:{} -> {}", path, line, snippet));
    }
  }

  Ok(ToolResult {
    text: lines.join("\n"),
    data: JsonValue::object(vec![
      ("query".to_string(), JsonValue::String(query.to_string())),
      ("mode".to_string(), JsonValue::String("basic".to_string())),
      ("hits".to_string(), JsonValue::array(json_hits)),
    ]),
  })
}

pub fn tool_docs_index(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
  let index = build_document_index(8);
  let mut preview = Vec::new();
  for entry in index.iter().take(3) {
    if let Some(path) = entry.get("path").and_then(|v| v.as_str()) {
      let title = entry
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled");
      preview.push(format!("  - {} ({})", title, path));
    }
  }
  let mut lines = vec![format!("Indexed {} documentation files.", index.len())];
  if preview.is_empty() {
    lines.push("No documents located.".to_string());
  } else {
    lines.push("Sample:".to_string());
    lines.extend(preview);
  }

  Ok(ToolResult {
    text: lines.join("\n"),
    data: JsonValue::object(vec![("documents".to_string(), JsonValue::array(index))]),
  })
}

pub fn tool_docs_get(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let path = args
    .get("path")
    .and_then(|value| value.as_str())
    .ok_or_else(|| "argument 'path' is required".to_string())?;
  let section = args.get("section").and_then(|v| v.as_str());

  let doc_path = resolve_doc_path(path)
    .ok_or_else(|| format!("documentation path '{}' is not recognized", path))?;

  let content = std::fs::read_to_string(&doc_path)
    .map_err(|e| format!("failed to read '{}': {}", doc_path.display(), e))?;

  let output = if let Some(section_name) = section {
    extract_markdown_section(&content, section_name)
      .ok_or_else(|| format!("section '{}' not found in {}", section_name, path))?
  } else {
    content
  };

  let text = if let Some(section_name) = section {
    format!(
      "Returned section '{}' from {} ({} bytes).",
      section_name,
      path,
      output.len()
    )
  } else {
    format!(
      "Returned entire document {} ({} bytes).",
      path,
      output.len()
    )
  };

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("path".to_string(), JsonValue::String(path.to_string())),
      (
        "section".to_string(),
        section
          .map(|s| JsonValue::String(s.to_string()))
          .unwrap_or(JsonValue::Null),
      ),
      ("content".to_string(), JsonValue::String(output)),
    ]),
  })
}
