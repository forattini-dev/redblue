use crate::mcp::server::McpServer;
use crate::mcp::types::ToolResult;
use crate::modules::web::dom::Document;
use crate::utils::json::JsonValue;

pub fn tool_html_select(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let html = args
    .get("html")
    .and_then(|v| v.as_str())
    .ok_or_else(|| "argument 'html' is required".to_string())?;

  let selector = args
    .get("selector")
    .and_then(|v| v.as_str())
    .ok_or_else(|| "argument 'selector' is required".to_string())?;

  let attr = args.get("attr").and_then(|v| v.as_str());

  let doc = Document::parse(html);
  let elements = doc.select(selector);

  let results: Vec<JsonValue> = elements
    .iter()
    .map(|el| {
      if let Some(attr_name) = attr {
        el.attr(attr_name)
          .map(|v| JsonValue::String(v.to_string()))
          .unwrap_or(JsonValue::Null)
      } else {
        JsonValue::String(el.text())
      }
    })
    .collect();

  let text = format!("Selected {} elements using '{}'", results.len(), selector);

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "selector".to_string(),
        JsonValue::String(selector.to_string()),
      ),
      ("count".to_string(), JsonValue::Number(results.len() as f64)),
      ("results".to_string(), JsonValue::array(results)),
    ]),
  })
}
