//! Password MCP Tools
//!
//! Hash detection, analysis, and password cracking utilities.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register password tools with the server
pub fn register_password_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
    ToolDefinition {
      name: "rb.password.detect",
      description: "Detect hash format from a hash string (MD5, SHA-*, bcrypt, etc.).",
      fields: &[ToolField {
        name: "hash",
        field_type: "string",
        description: "Hash string to analyze.",
        required: true,
      }],
      handler: tool_password_detect,
    },
    ToolDefinition {
      name: "rb.password.analyze",
      description: "Analyze password hash(es) for format, entropy, and crackability.",
      fields: &[ToolField {
        name: "hashes",
        field_type: "array",
        description: "Array of hash strings to analyze.",
        required: true,
      }],
      handler: tool_password_analyze,
    },
  ]
}

fn tool_password_detect(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::password::detect_format;

  let hash = args
    .get("hash")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: hash")?;

  // detect_format returns Option<HashFormat>
  let format = detect_format(hash);

  let (text, data) = if let Some(fmt) = format {
    let text = format!("Detected format: {}", fmt.name());
    let data = JsonValue::object(vec![
      ("hash".to_string(), JsonValue::String(hash.to_string())),
      ("length".to_string(), JsonValue::Number(hash.len() as f64)),
      (
        "format".to_string(),
        JsonValue::String(fmt.name().to_string()),
      ),
      (
        "hashcat_mode".to_string(),
        JsonValue::Number(fmt.hashcat_mode() as f64),
      ),
    ]);
    (text, data)
  } else {
    let text = format!("Unknown hash format: {}", hash);
    let data = JsonValue::object(vec![
      ("hash".to_string(), JsonValue::String(hash.to_string())),
      ("length".to_string(), JsonValue::Number(hash.len() as f64)),
      ("format".to_string(), JsonValue::Null),
    ]);
    (text, data)
  };

  Ok(ToolResult { text, data })
}

fn tool_password_analyze(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::password::detect_format;
  use std::collections::HashSet;

  let hashes: Vec<String> = args
    .get("hashes")
    .and_then(|v| v.as_array())
    .map(|arr| {
      arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
    })
    .ok_or("Missing required field: hashes")?;

  if hashes.is_empty() {
    return Err("No hashes provided".to_string());
  }

  let mut results = Vec::new();

  for hash in &hashes {
    let format = detect_format(hash);

    // Calculate entropy based on character distribution
    let unique_chars: HashSet<char> = hash.chars().collect();
    let charset_size = unique_chars.len();
    let entropy = if charset_size > 1 {
      (hash.len() as f64) * (charset_size as f64).log2()
    } else {
      0.0
    };

    // Determine charset type
    let charset = if hash.chars().all(|c| c.is_ascii_hexdigit()) {
      "hexadecimal"
    } else if hash
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
      "base64"
    } else if hash
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || c == '$' || c == '.')
    {
      "crypt-style"
    } else {
      "mixed"
    };

    // Estimate crackability based on format
    let (format_name, crackability) = if let Some(ref fmt) = format {
      let name = fmt.name();
      let crack = match name {
        "MD5" | "NTLM" => "easy",
        "SHA-1" | "SHA-256" => "moderate",
        "bcrypt" | "md5crypt" | "sha256crypt" | "sha512crypt" => "hard",
        _ => "unknown",
      };
      (name.to_string(), crack)
    } else {
      ("unknown".to_string(), "unknown")
    };

    results.push(JsonValue::object(vec![
      ("hash".to_string(), JsonValue::String(hash.clone())),
      ("length".to_string(), JsonValue::Number(hash.len() as f64)),
      ("format".to_string(), JsonValue::String(format_name)),
      ("entropy".to_string(), JsonValue::Number(entropy)),
      (
        "charset".to_string(),
        JsonValue::String(charset.to_string()),
      ),
      (
        "crackability".to_string(),
        JsonValue::String(crackability.to_string()),
      ),
    ]));
  }

  let text = format!("Analyzed {} hash(es)", hashes.len());

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("count".to_string(), JsonValue::Number(hashes.len() as f64)),
      ("results".to_string(), JsonValue::array(results)),
    ]),
  })
}
