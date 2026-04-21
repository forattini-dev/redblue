use crate::mcp::sampling::{SamplingResponse, StopReason};
use crate::mcp::server::McpServer;
use crate::mcp::types::ToolResult;
use crate::utils::json::JsonValue;

pub fn tool_auto_guide(server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let op_id = args
    .get("operation_id")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: operation_id")?;

  let response_str = args
    .get("response")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: response")?;

  let response = SamplingResponse {
    content: response_str.to_string(),
    model: "user-provided".to_string(),
    stop_reason: StopReason::EndTurn,
  };

  server.orchestrator.provide_guidance(op_id, response)?;

  Ok(ToolResult {
    text: format!(
      "Guidance accepted for operation {}.\n\
                 Use rb.auto.step to continue the operation.",
      op_id
    ),
    data: JsonValue::object(vec![
      (
        "status".to_string(),
        JsonValue::String("guidance_accepted".to_string()),
      ),
      (
        "operation_id".to_string(),
        JsonValue::String(op_id.to_string()),
      ),
    ]),
  })
}
