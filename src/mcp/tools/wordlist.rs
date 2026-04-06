//! Wordlist MCP Tools
//!
//! Wordlist mutation and generation tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register wordlist tools with the server
pub fn register_wordlist_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![ToolDefinition {
    name: "rb.wordlist.mutate",
    description: "Apply mutation rules to words (like hashcat rules).",
    fields: &[
      ToolField {
        name: "words",
        field_type: "array",
        description: "Array of words to mutate.",
        required: true,
      },
      ToolField {
        name: "rules",
        field_type: "array",
        description: "Mutation rules to apply (e.g., ['l', 'u', 'c', '$1']).",
        required: false,
      },
    ],
    handler: tool_wordlist_mutate,
  }]
}

fn tool_wordlist_mutate(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::wordlist::rules::RuleEngine;

  let words: Vec<String> = args
    .get("words")
    .and_then(|v| v.as_array())
    .map(|arr| {
      arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
    })
    .ok_or("Missing required field: words")?;

  if words.is_empty() {
    return Err("No words provided".to_string());
  }

  let rule_strs: Vec<String> = args
    .get("rules")
    .and_then(|v| v.as_array())
    .map(|arr| {
      arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
    })
    .unwrap_or_else(|| {
      vec![
        "l".to_string(),
        "u".to_string(),
        "c".to_string(),
        "$1".to_string(),
      ]
    });

  let mut mutated: Vec<String> = Vec::new();
  for word in &words {
    for rule in &rule_strs {
      mutated.push(RuleEngine::apply(word, rule));
    }
  }

  mutated.sort();
  mutated.dedup();

  let mutated_json: Vec<JsonValue> = mutated
    .iter()
    .map(|w| JsonValue::String(w.clone()))
    .collect();

  let text = format!(
    "Generated {} mutations from {} word(s) using {} rule(s)",
    mutated.len(),
    words.len(),
    rule_strs.len()
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "original_count".to_string(),
        JsonValue::Number(words.len() as f64),
      ),
      (
        "mutation_count".to_string(),
        JsonValue::Number(mutated.len() as f64),
      ),
      (
        "rules_applied".to_string(),
        JsonValue::Number(rule_strs.len() as f64),
      ),
      ("words".to_string(), JsonValue::array(mutated_json)),
    ]),
  })
}
