use crate::mcp::categories::{CategoryPreset, ToolCategory};
use crate::mcp::server::McpServer;
use crate::mcp::types::ToolResult;
use crate::utils::json::JsonValue;

pub fn tool_config_categories(
  server: &mut McpServer,
  args: &JsonValue,
) -> Result<ToolResult, String> {
  let action = args
    .get("action")
    .and_then(|v| v.as_str())
    .unwrap_or("list");

  let category_name = args.get("category").and_then(|v| v.as_str());

  match action {
    "list" => {
      let status = server.categories.status_summary();
      let mut lines = Vec::new();
      lines.push(format!(
        "Current preset: {}",
        server.categories.current_preset().as_str()
      ));
      lines.push(format!(
        "Enabled tools: {}/44",
        server.categories.enabled_tool_count()
      ));
      lines.push(String::new());
      lines.push("Category Status:".to_string());

      for (cat, enabled, count) in &status {
        let marker = if *enabled { "[x]" } else { "[ ]" };
        lines.push(format!(
          "  {} {:15} ({:2} tools) - {}",
          marker,
          cat.as_str(),
          count,
          cat.description()
        ));
      }

      let categories_json: Vec<JsonValue> = status
        .iter()
        .map(|(cat, enabled, count)| {
          JsonValue::object(vec![
            (
              "name".to_string(),
              JsonValue::String(cat.as_str().to_string()),
            ),
            ("enabled".to_string(), JsonValue::Bool(*enabled)),
            ("tool_count".to_string(), JsonValue::Number(*count as f64)),
            (
              "description".to_string(),
              JsonValue::String(cat.description().to_string()),
            ),
          ])
        })
        .collect();

      Ok(ToolResult {
        text: lines.join("\n"),
        data: JsonValue::object(vec![
          (
            "preset".to_string(),
            JsonValue::String(server.categories.current_preset().as_str().to_string()),
          ),
          (
            "enabled_count".to_string(),
            JsonValue::Number(server.categories.enabled_tool_count() as f64),
          ),
          ("categories".to_string(), JsonValue::Array(categories_json)),
        ]),
      })
    }
    "enable" => {
      let cat_str = category_name.ok_or("Missing category name for enable action")?;
      let category =
        ToolCategory::from_str(cat_str).ok_or_else(|| format!("Unknown category: {}", cat_str))?;

      server.categories.enable(category);
      let text = format!(
        "Enabled category '{}'. Now exposing {} tools.",
        cat_str,
        server.categories.enabled_tool_count()
      );

      Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
          (
            "action".to_string(),
            JsonValue::String("enabled".to_string()),
          ),
          (
            "category".to_string(),
            JsonValue::String(cat_str.to_string()),
          ),
          (
            "enabled_count".to_string(),
            JsonValue::Number(server.categories.enabled_tool_count() as f64),
          ),
        ]),
      })
    }
    "disable" => {
      let cat_str = category_name.ok_or("Missing category name for disable action")?;
      let category =
        ToolCategory::from_str(cat_str).ok_or_else(|| format!("Unknown category: {}", cat_str))?;

      server.categories.disable(category);
      let text = format!(
        "Disabled category '{}'. Now exposing {} tools.",
        cat_str,
        server.categories.enabled_tool_count()
      );

      Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
          (
            "action".to_string(),
            JsonValue::String("disabled".to_string()),
          ),
          (
            "category".to_string(),
            JsonValue::String(cat_str.to_string()),
          ),
          (
            "enabled_count".to_string(),
            JsonValue::Number(server.categories.enabled_tool_count() as f64),
          ),
        ]),
      })
    }
    "toggle" => {
      let cat_str = category_name.ok_or("Missing category name for toggle action")?;
      let category =
        ToolCategory::from_str(cat_str).ok_or_else(|| format!("Unknown category: {}", cat_str))?;

      let now_enabled = server.categories.toggle(category);
      let action_str = if now_enabled { "enabled" } else { "disabled" };
      let text = format!(
        "Toggled category '{}' -> {}. Now exposing {} tools.",
        cat_str,
        action_str,
        server.categories.enabled_tool_count()
      );

      Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
          (
            "action".to_string(),
            JsonValue::String(action_str.to_string()),
          ),
          (
            "category".to_string(),
            JsonValue::String(cat_str.to_string()),
          ),
          ("enabled".to_string(), JsonValue::Bool(now_enabled)),
          (
            "enabled_count".to_string(),
            JsonValue::Number(server.categories.enabled_tool_count() as f64),
          ),
        ]),
      })
    }
    _ => Err(format!(
      "Unknown action: {}. Use list, enable, disable, or toggle.",
      action
    )),
  }
}

pub fn tool_config_preset(server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let preset_name = args.get("preset").and_then(|v| v.as_str());

  if let Some(name) = preset_name {
    let preset = CategoryPreset::from_str(name).ok_or_else(|| {
      format!(
        "Unknown preset: {}. Available: all, core, blue-team, red-team, web-security, minimal",
        name
      )
    })?;

    server.categories.apply_preset(preset);

    let text = format!(
      "Applied preset '{}': {}. Now exposing {} tools.",
      name,
      preset.description(),
      server.categories.enabled_tool_count()
    );

    Ok(ToolResult {
      text,
      data: JsonValue::object(vec![
        ("preset".to_string(), JsonValue::String(name.to_string())),
        (
          "description".to_string(),
          JsonValue::String(preset.description().to_string()),
        ),
        (
          "enabled_count".to_string(),
          JsonValue::Number(server.categories.enabled_tool_count() as f64),
        ),
      ]),
    })
  } else {
    let mut lines = Vec::new();
    lines.push(format!(
      "Current preset: {}",
      server.categories.current_preset().as_str()
    ));
    lines.push(String::new());
    lines.push("Available presets:".to_string());

    for preset in CategoryPreset::all_presets() {
      let marker = if preset == server.categories.current_preset() {
        ">"
      } else {
        " "
      };
      lines.push(format!(
        "{} {:15} - {}",
        marker,
        preset.as_str(),
        preset.description()
      ));
    }

    let presets_json: Vec<JsonValue> = CategoryPreset::all_presets()
      .iter()
      .map(|p| {
        JsonValue::object(vec![
          (
            "name".to_string(),
            JsonValue::String(p.as_str().to_string()),
          ),
          (
            "description".to_string(),
            JsonValue::String(p.description().to_string()),
          ),
          (
            "active".to_string(),
            JsonValue::Bool(*p == server.categories.current_preset()),
          ),
        ])
      })
      .collect();

    Ok(ToolResult {
      text: lines.join("\n"),
      data: JsonValue::object(vec![
        (
          "current".to_string(),
          JsonValue::String(server.categories.current_preset().as_str().to_string()),
        ),
        ("presets".to_string(), JsonValue::Array(presets_json)),
      ]),
    })
  }
}
