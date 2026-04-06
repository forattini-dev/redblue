//! Loot MCP Tools
//!
//! Manage pentest findings, credentials, and artifacts via MCP.
//! Uses LootSegment for persistent storage when available,
//! otherwise provides informational responses about capabilities.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::storage::segments::loot::{LootCategory, LootEntry, LootSegment};
use crate::utils::json::JsonValue;

/// Register loot tools with the server
pub fn register_loot_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
    ToolDefinition {
      name: "rb.loot.list",
      description: "List all loot items (credentials, vulnerabilities, findings, services, etc.).\
                         Optionally filter by category.",
      fields: &[
        ToolField {
          name: "category",
          field_type: "string",
          description: "Filter by category: credential, vulnerability, finding, artifact, \
                                 service, endpoint, technology, task, info. Omit to list all.",
          required: false,
        },
        ToolField {
          name: "limit",
          field_type: "number",
          description: "Maximum number of entries to return (default: 50).",
          required: false,
        },
      ],
      handler: tool_loot_list,
    },
    ToolDefinition {
      name: "rb.loot.add",
      description: "Add a loot item to the collection. Supports credentials, vulnerabilities, \
                         findings, services, and other pentest artifacts.",
      fields: &[
        ToolField {
          name: "key",
          field_type: "string",
          description: "Unique key for the entry (e.g., 'ssh_creds_192.168.1.1').",
          required: true,
        },
        ToolField {
          name: "category",
          field_type: "string",
          description: "Category: credential, vulnerability, finding, artifact, \
                                 service, endpoint, technology, task, info.",
          required: true,
        },
        ToolField {
          name: "content",
          field_type: "string",
          description: "Description or content of the loot entry.",
          required: true,
        },
        ToolField {
          name: "target",
          field_type: "string",
          description: "Target IP address associated with this entry.",
          required: false,
        },
        ToolField {
          name: "confidence",
          field_type: "string",
          description: "Confidence level: low, medium, high (default: medium).",
          required: false,
        },
        ToolField {
          name: "username",
          field_type: "string",
          description: "Username (for credential entries).",
          required: false,
        },
        ToolField {
          name: "password",
          field_type: "string",
          description: "Password (for credential entries).",
          required: false,
        },
        ToolField {
          name: "cve",
          field_type: "string",
          description: "CVE identifier (for vulnerability entries).",
          required: false,
        },
        ToolField {
          name: "url",
          field_type: "string",
          description: "URL evidence (for web findings).",
          required: false,
        },
      ],
      handler: tool_loot_add,
    },
    ToolDefinition {
      name: "rb.loot.search",
      description: "Search loot entries by keyword or filter by category and status.",
      fields: &[
        ToolField {
          name: "keyword",
          field_type: "string",
          description: "Search keyword to match against keys and content.",
          required: false,
        },
        ToolField {
          name: "category",
          field_type: "string",
          description: "Filter by category: credential, vulnerability, finding, artifact, \
                                 service, endpoint, technology, task, info.",
          required: false,
        },
        ToolField {
          name: "status",
          field_type: "string",
          description: "Filter by status: open, closed, confirmed, potential, filtered.",
          required: false,
        },
      ],
      handler: tool_loot_search,
    },
    ToolDefinition {
      name: "rb.loot.export",
      description: "Export all loot entries as a structured JSON summary, grouped by category \
                         with statistics.",
      fields: &[ToolField {
        name: "category",
        field_type: "string",
        description: "Export only a specific category. Omit for full export.",
        required: false,
      }],
      handler: tool_loot_export,
    },
  ]
}

/// Parse a category string into LootCategory
fn parse_category(s: &str) -> Option<LootCategory> {
  match s.to_lowercase().as_str() {
    "credential" | "cred" | "credentials" => Some(LootCategory::Credential),
    "vulnerability" | "vuln" | "vulnerabilities" => Some(LootCategory::Vulnerability),
    "finding" | "findings" => Some(LootCategory::Finding),
    "artifact" | "artifacts" => Some(LootCategory::Artifact),
    "service" | "services" => Some(LootCategory::Service),
    "endpoint" | "endpoints" => Some(LootCategory::Endpoint),
    "technology" | "tech" | "technologies" => Some(LootCategory::Technology),
    "task" | "tasks" => Some(LootCategory::Task),
    "info" | "information" => Some(LootCategory::Info),
    _ => None,
  }
}

/// Format a single loot entry as a JSON value
fn entry_to_json(entry: &LootEntry) -> JsonValue {
  let mut fields = vec![
    ("key".to_string(), JsonValue::String(entry.key.clone())),
    (
      "category".to_string(),
      JsonValue::String(entry.category.as_str().to_string()),
    ),
    (
      "content".to_string(),
      JsonValue::String(entry.content.clone()),
    ),
    (
      "confidence".to_string(),
      JsonValue::String(entry.confidence.as_str().to_string()),
    ),
    (
      "status".to_string(),
      JsonValue::String(entry.status.as_str().to_string()),
    ),
    (
      "created_at".to_string(),
      JsonValue::Number(entry.created_at as f64),
    ),
    (
      "updated_at".to_string(),
      JsonValue::Number(entry.updated_at as f64),
    ),
  ];

  if let Some(ref ip) = entry.target {
    fields.push(("target".to_string(), JsonValue::String(ip.to_string())));
  }

  if let Some(ref username) = entry.metadata.username {
    fields.push(("username".to_string(), JsonValue::String(username.clone())));
  }

  if let Some(ref cve) = entry.metadata.cve {
    fields.push(("cve".to_string(), JsonValue::String(cve.clone())));
  }

  if let Some(ref url) = entry.metadata.url {
    fields.push(("url".to_string(), JsonValue::String(url.clone())));
  }

  if let Some(cvss) = entry.metadata.cvss {
    fields.push(("cvss".to_string(), JsonValue::Number(cvss as f64)));
  }

  JsonValue::object(fields)
}

/// Format a loot entry as a text line for display
fn entry_to_text(entry: &LootEntry) -> String {
  let target = entry
    .target
    .map(|ip| format!(" [{}]", ip))
    .unwrap_or_default();

  format!(
    "  [{}/{}] {}{}: {}",
    entry.category.as_str(),
    entry.status.as_str(),
    entry.key,
    target,
    truncate(&entry.content, 120),
  )
}

/// Truncate a string to a max length, appending "..." if truncated
fn truncate(s: &str, max: usize) -> &str {
  if s.len() <= max {
    s
  } else {
    &s[..max]
  }
}

fn tool_loot_list(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let mut segment = LootSegment::new();

  // Check if there are entries (in practice, entries would come from RedDB storage)
  let category_filter = args
    .get("category")
    .and_then(|v| v.as_str())
    .and_then(parse_category);

  let limit = args
    .get("limit")
    .and_then(|v| v.as_f64())
    .map(|n| n as usize)
    .unwrap_or(50);

  let entries: Vec<LootEntry> = match category_filter {
    Some(cat) => segment.by_category(cat),
    None => segment.all(),
  };

  let total = entries.len();
  let display_entries: Vec<&LootEntry> = entries.iter().take(limit).collect();

  if display_entries.is_empty() {
    let filter_msg = category_filter
      .map(|c| format!(" in category '{}'", c.as_str()))
      .unwrap_or_default();

    return Ok(ToolResult::with_data(
      format!(
        "No loot entries found{}. Use rb.loot.add to record findings, \
                 or run scans with 'rb network ports scan' / 'rb web asset security' \
                 to populate loot automatically.",
        filter_msg
      ),
      JsonValue::object(vec![
        ("total".to_string(), JsonValue::Number(0.0)),
        ("entries".to_string(), JsonValue::array(vec![])),
      ]),
    ));
  }

  let mut text = format!(
    "Loot entries ({} total, showing {}):\n",
    total,
    display_entries.len()
  );
  for entry in &display_entries {
    text.push_str(&entry_to_text(entry));
    text.push('\n');
  }

  if total > limit {
    text.push_str(&format!("\n  ... and {} more entries", total - limit));
  }

  let entries_json: Vec<JsonValue> = display_entries.iter().map(|e| entry_to_json(e)).collect();

  Ok(ToolResult::with_data(
    text,
    JsonValue::object(vec![
      ("total".to_string(), JsonValue::Number(total as f64)),
      (
        "showing".to_string(),
        JsonValue::Number(display_entries.len() as f64),
      ),
      ("entries".to_string(), JsonValue::array(entries_json)),
    ]),
  ))
}

fn tool_loot_add(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let key = args
    .get("key")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: key")?;

  let category_str = args
    .get("category")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: category")?;

  let category = parse_category(category_str).ok_or_else(|| {
    format!(
      "Invalid category '{}'. Valid: credential, vulnerability, finding, \
             artifact, service, endpoint, technology, task, info",
      category_str
    )
  })?;

  let content = args
    .get("content")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: content")?;

  let mut entry = LootEntry::new(key, category, content);

  // Parse optional target IP
  if let Some(target_str) = args.get("target").and_then(|v| v.as_str()) {
    if let Ok(ip) = target_str.parse() {
      entry.target = Some(ip);
    }
  }

  // Parse confidence
  if let Some(conf_str) = args.get("confidence").and_then(|v| v.as_str()) {
    entry.confidence = match conf_str.to_lowercase().as_str() {
      "low" => crate::storage::segments::loot::Confidence::Low,
      "high" => crate::storage::segments::loot::Confidence::High,
      _ => crate::storage::segments::loot::Confidence::Medium,
    };
  }

  // Parse credential metadata
  if let Some(username) = args.get("username").and_then(|v| v.as_str()) {
    entry.metadata.username = Some(username.to_string());
  }
  if let Some(password) = args.get("password").and_then(|v| v.as_str()) {
    entry.metadata.password = Some(password.to_string());
  }

  // Parse vulnerability metadata
  if let Some(cve) = args.get("cve").and_then(|v| v.as_str()) {
    entry.metadata.cve = Some(cve.to_string());
  }

  // Parse URL evidence
  if let Some(url) = args.get("url").and_then(|v| v.as_str()) {
    entry.metadata.url = Some(url.to_string());
  }

  let entry_json = entry_to_json(&entry);

  // Insert into segment
  let mut segment = LootSegment::new();
  segment.insert(entry);

  let text = format!(
    "Added loot entry: [{}] '{}' - {}",
    category.as_str(),
    key,
    truncate(content, 80),
  );

  Ok(ToolResult::with_data(
    text,
    JsonValue::object(vec![
      ("added".to_string(), JsonValue::Bool(true)),
      ("entry".to_string(), entry_json),
    ]),
  ))
}

fn tool_loot_search(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let keyword = args.get("keyword").and_then(|v| v.as_str());
  let category_filter = args
    .get("category")
    .and_then(|v| v.as_str())
    .and_then(parse_category);
  let status_filter = args.get("status").and_then(|v| v.as_str());

  if keyword.is_none() && category_filter.is_none() && status_filter.is_none() {
    return Err("At least one search parameter required: keyword, category, or status".to_string());
  }

  let mut segment = LootSegment::new();

  // Start with all entries or filtered by category
  let candidates: Vec<LootEntry> = match category_filter {
    Some(cat) => segment.by_category(cat),
    None => segment.all(),
  };

  // Apply keyword filter
  let filtered: Vec<&LootEntry> = candidates
    .iter()
    .filter(|e| {
      // Keyword match against key and content
      if let Some(kw) = keyword {
        let kw_lower = kw.to_lowercase();
        let key_match = e.key.to_lowercase().contains(&kw_lower);
        let content_match = e.content.to_lowercase().contains(&kw_lower);
        let cve_match = e
          .metadata
          .cve
          .as_ref()
          .map(|c| c.to_lowercase().contains(&kw_lower))
          .unwrap_or(false);
        let user_match = e
          .metadata
          .username
          .as_ref()
          .map(|u| u.to_lowercase().contains(&kw_lower))
          .unwrap_or(false);
        if !(key_match || content_match || cve_match || user_match) {
          return false;
        }
      }
      // Status filter
      if let Some(status_str) = status_filter {
        if e.status.as_str() != status_str.to_lowercase() {
          return false;
        }
      }
      true
    })
    .collect();

  if filtered.is_empty() {
    let mut criteria = Vec::new();
    if let Some(kw) = keyword {
      criteria.push(format!("keyword='{}'", kw));
    }
    if let Some(cat) = category_filter {
      criteria.push(format!("category='{}'", cat.as_str()));
    }
    if let Some(st) = status_filter {
      criteria.push(format!("status='{}'", st));
    }

    return Ok(ToolResult::with_data(
      format!(
        "No loot entries matching {}. The loot database may be empty. \
                 Run scans or use rb.loot.add to populate it.",
        criteria.join(", ")
      ),
      JsonValue::object(vec![
        ("matches".to_string(), JsonValue::Number(0.0)),
        ("results".to_string(), JsonValue::array(vec![])),
      ]),
    ));
  }

  let mut text = format!("Found {} matching loot entries:\n", filtered.len());
  for entry in &filtered {
    text.push_str(&entry_to_text(entry));
    text.push('\n');
  }

  let results_json: Vec<JsonValue> = filtered.iter().map(|e| entry_to_json(e)).collect();

  Ok(ToolResult::with_data(
    text,
    JsonValue::object(vec![
      (
        "matches".to_string(),
        JsonValue::Number(filtered.len() as f64),
      ),
      ("results".to_string(), JsonValue::array(results_json)),
    ]),
  ))
}

fn tool_loot_export(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let category_filter = args
    .get("category")
    .and_then(|v| v.as_str())
    .and_then(parse_category);

  let mut segment = LootSegment::new();

  let entries: Vec<LootEntry> = match category_filter {
    Some(cat) => segment.by_category(cat),
    None => segment.all(),
  };

  // Build statistics by category
  let mut stats: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
  let mut by_status: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

  for entry in &entries {
    *stats.entry(entry.category.as_str()).or_insert(0) += 1;
    *by_status.entry(entry.status.as_str()).or_insert(0) += 1;
  }

  let stats_json: Vec<(String, JsonValue)> = stats
    .iter()
    .map(|(&cat, &count)| (cat.to_string(), JsonValue::Number(count as f64)))
    .collect();

  let status_json: Vec<(String, JsonValue)> = by_status
    .iter()
    .map(|(&st, &count)| (st.to_string(), JsonValue::Number(count as f64)))
    .collect();

  let entries_json: Vec<JsonValue> = entries.iter().map(|e| entry_to_json(e)).collect();

  let total = entries.len();

  let mut text = format!("Loot export: {} total entries\n", total);
  if !stats.is_empty() {
    text.push_str("\nBy category:\n");
    for (&cat, &count) in &stats {
      text.push_str(&format!("  {}: {}\n", cat, count));
    }
  }
  if !by_status.is_empty() {
    text.push_str("\nBy status:\n");
    for (&st, &count) in &by_status {
      text.push_str(&format!("  {}: {}\n", st, count));
    }
  }

  if total == 0 {
    text.push_str(
      "\nNo entries to export. Populate loot with rb.loot.add or run security scans:\n\
             - rb network ports scan <target>\n\
             - rb web asset security <url>\n\
             - rb recon domain subdomains <domain>\n",
    );
  }

  Ok(ToolResult::with_data(
    text,
    JsonValue::object(vec![
      ("total".to_string(), JsonValue::Number(total as f64)),
      ("by_category".to_string(), JsonValue::object(stats_json)),
      ("by_status".to_string(), JsonValue::object(status_json)),
      ("entries".to_string(), JsonValue::array(entries_json)),
    ]),
  ))
}
