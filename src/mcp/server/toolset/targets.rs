use crate::mcp::server::{default_target_db_path, McpServer, TargetDatabase};
use crate::mcp::types::ToolResult;
use crate::utils::json::JsonValue;

pub fn tool_targets_list(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
  let db = TargetDatabase::load(default_target_db_path());
  let entries = db
    .targets
    .iter()
    .map(|entry| entry.to_json())
    .collect::<Vec<JsonValue>>();

  let mut lines = vec![format!("Tracked targets: {}", entries.len())];
  for entry in db.targets.iter().take(5) {
    lines.push(format!("  - {} -> {}", entry.name, entry.target));
  }
  if db.targets.len() > 5 {
    lines.push(format!("  ... and {} more.", db.targets.len() - 5));
  }

  Ok(ToolResult {
    text: lines.join("\n"),
    data: JsonValue::object(vec![("targets".to_string(), JsonValue::array(entries))]),
  })
}

pub fn tool_targets_save(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let name = args
    .get("name")
    .and_then(|value| value.as_str())
    .ok_or_else(|| "argument 'name' is required".to_string())?;
  let target = args
    .get("target")
    .and_then(|value| value.as_str())
    .ok_or_else(|| "argument 'target' is required".to_string())?;
  let notes = args.get("notes").and_then(|value| value.as_str());

  let path = default_target_db_path();
  let mut db = TargetDatabase::load(path.clone());
  let (created, entry) = db.upsert(name, target, notes);
  db.persist()?;

  let action = if created { "Created" } else { "Updated" };
  let text = format!("{} target '{}' -> {}.", action, entry.name, entry.target);

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("created".to_string(), JsonValue::Bool(created)),
      ("target".to_string(), entry.to_json()),
    ]),
  })
}

pub fn tool_targets_remove(
  _server: &mut McpServer,
  args: &JsonValue,
) -> Result<ToolResult, String> {
  let name = args
    .get("name")
    .and_then(|value| value.as_str())
    .ok_or_else(|| "argument 'name' is required".to_string())?;

  let path = default_target_db_path();
  let mut db = TargetDatabase::load(path.clone());
  let removed = db.remove(name);
  if removed.is_none() {
    return Err(format!("target '{}' not found", name));
  }
  db.persist()?;

  let entry = removed.unwrap();
  Ok(ToolResult {
    text: format!("Removed target '{}' -> {}.", entry.name, entry.target),
    data: JsonValue::object(vec![
      ("removed".to_string(), JsonValue::Bool(true)),
      ("target".to_string(), entry.to_json()),
    ]),
  })
}
