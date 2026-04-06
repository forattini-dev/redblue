//! Evasion MCP Tools
//!
//! Sandbox detection, obfuscation, and anti-debug tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register evasion tools with the server
pub fn register_evasion_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
    ToolDefinition {
      name: "rb.evasion.sandbox",
      description: "Check for sandbox/VM indicators on the current system.",
      fields: &[],
      handler: tool_evasion_sandbox,
    },
    ToolDefinition {
      name: "rb.evasion.obfuscate",
      description: "Obfuscate text or code using various techniques.",
      fields: &[
        ToolField {
          name: "input",
          field_type: "string",
          description: "Text to obfuscate.",
          required: true,
        },
        ToolField {
          name: "technique",
          field_type: "string",
          description: "Technique: base64, hex, xor, reverse.",
          required: false,
        },
      ],
      handler: tool_evasion_obfuscate,
    },
    ToolDefinition {
      name: "rb.evasion.antidebug",
      description: "Check for debugger presence and anti-debug indicators.",
      fields: &[],
      handler: tool_evasion_antidebug,
    },
  ]
}

fn tool_evasion_sandbox(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::evasion::sandbox;

  // Run individual checks and collect results
  let mut checks = Vec::new();

  let vm_files = sandbox::check_vm_files();
  checks.push(("vm_files".to_string(), vm_files));

  let sandbox_procs = sandbox::check_sandbox_processes();
  checks.push(("sandbox_processes".to_string(), sandbox_procs));

  let timing_anomaly = sandbox::check_timing_anomaly();
  checks.push(("timing_anomaly".to_string(), timing_anomaly));

  let low_resources = sandbox::check_low_resources();
  checks.push(("low_resources".to_string(), low_resources));

  let suspicious_user = sandbox::check_suspicious_username();
  checks.push(("suspicious_username".to_string(), suspicious_user));

  let debugger = sandbox::check_debugger();
  checks.push(("debugger".to_string(), debugger));

  // Get overall detection result
  let is_sandbox = sandbox::detect_sandbox();
  let score = sandbox::sandbox_score();
  let detected_count = checks.iter().filter(|(_, detected)| *detected).count();

  let checks_json: Vec<JsonValue> = checks
    .iter()
    .map(|(name, detected)| {
      JsonValue::object(vec![
        ("name".to_string(), JsonValue::String(name.clone())),
        ("detected".to_string(), JsonValue::Bool(*detected)),
      ])
    })
    .collect();

  let text = if is_sandbox {
    format!(
      "SANDBOX LIKELY: {} of {} indicators detected (score: {})",
      detected_count,
      checks.len(),
      score
    )
  } else {
    format!(
      "No sandbox detected: {} of {} indicators (score: {})",
      detected_count,
      checks.len(),
      score
    )
  };

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("is_sandbox".to_string(), JsonValue::Bool(is_sandbox)),
      ("score".to_string(), JsonValue::Number(score as f64)),
      (
        "indicators_detected".to_string(),
        JsonValue::Number(detected_count as f64),
      ),
      (
        "total_checks".to_string(),
        JsonValue::Number(checks.len() as f64),
      ),
      ("checks".to_string(), JsonValue::array(checks_json)),
    ]),
  })
}

fn tool_evasion_obfuscate(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let input = args
    .get("input")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: input")?;

  let technique = args
    .get("technique")
    .and_then(|v| v.as_str())
    .unwrap_or("base64");

  let output = match technique {
    "base64" => {
      use crate::crypto::encode_base64;
      encode_base64(input.as_bytes())
    }
    "hex" => input
      .bytes()
      .map(|b| format!("{:02x}", b))
      .collect::<String>(),
    "xor" => {
      let key = 0x42u8;
      input
        .bytes()
        .map(|b| format!("{:02x}", b ^ key))
        .collect::<String>()
    }
    "reverse" => input.chars().rev().collect(),
    _ => return Err(format!("Unknown technique: {}", technique)),
  };

  let text = format!(
    "Obfuscated with {}: {} -> {} chars",
    technique,
    input.len(),
    output.len()
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "technique".to_string(),
        JsonValue::String(technique.to_string()),
      ),
      (
        "input_length".to_string(),
        JsonValue::Number(input.len() as f64),
      ),
      (
        "output_length".to_string(),
        JsonValue::Number(output.len() as f64),
      ),
      ("output".to_string(), JsonValue::String(output)),
    ]),
  })
}

fn tool_evasion_antidebug(
  _server: &mut McpServer,
  _args: &JsonValue,
) -> Result<ToolResult, String> {
  use crate::modules::evasion::antidebug::AntiDebug;

  // Use default() since new() requires parameters
  let ad = AntiDebug::default();
  let result = ad.check_all();

  // result.checks is Vec<(String, bool)>
  let checks_json: Vec<JsonValue> = result
    .checks
    .iter()
    .map(|(name, detected)| {
      JsonValue::object(vec![
        ("name".to_string(), JsonValue::String(name.clone())),
        ("detected".to_string(), JsonValue::Bool(*detected)),
      ])
    })
    .collect();

  let text = if result.debugger_detected {
    format!(
      "DEBUGGER DETECTED: Score {} - {:?}",
      result.score, result.action
    )
  } else {
    format!("No debugger detected (score: {})", result.score)
  };

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "debugger_detected".to_string(),
        JsonValue::Bool(result.debugger_detected),
      ),
      ("score".to_string(), JsonValue::Number(result.score as f64)),
      ("checks".to_string(), JsonValue::array(checks_json)),
    ]),
  })
}
