//! Core MCP Tools
//!
//! CLI introspection, documentation, and target management tools.

use crate::cli::commands;
use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;
use std::collections::HashSet;

/// Register core tools with the server
pub fn register_core_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
        ToolDefinition {
            name: "rb.list-domains",
            description: "List available RedBlue CLI domains.",
            fields: &[],
            handler: tool_list_domains,
        },
        ToolDefinition {
            name: "rb.list-resources",
            description: "List resources and verbs for a given RedBlue CLI domain (e.g. network).",
            fields: &[ToolField {
                name: "domain",
                field_type: "string",
                description: "Domain name to inspect (network, dns, web, ...).",
                required: true,
            }],
            handler: tool_list_resources,
        },
        ToolDefinition {
            name: "rb.describe-command",
            description: "Get detailed help for a domain/resource combination.",
            fields: &[
                ToolField {
                    name: "domain",
                    field_type: "string",
                    description: "Domain name to describe.",
                    required: true,
                },
                ToolField {
                    name: "resource",
                    field_type: "string",
                    description: "Resource name inside the domain.",
                    required: true,
                },
            ],
            handler: tool_describe_command,
        },
        ToolDefinition {
            name: "rb.command-run",
            description: "Run an arbitrary RedBlue CLI command. Use rb.list-domains and rb.describe-command to discover available commands.",
            fields: &[
                ToolField {
                    name: "domain",
                    field_type: "string",
                    description: "CLI domain (network, web, recon, ...).",
                    required: true,
                },
                ToolField {
                    name: "resource",
                    field_type: "string",
                    description: "Resource inside the domain (ports, host, ...).",
                    required: true,
                },
                ToolField {
                    name: "verb",
                    field_type: "string",
                    description: "Action verb (scan, lookup, ...).",
                    required: true,
                },
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Primary target (IP, domain, URL, ...).",
                    required: false,
                },
                ToolField {
                    name: "flags",
                    field_type: "object",
                    description: "Additional flags as key-value pairs.",
                    required: false,
                },
            ],
            handler: tool_command_run,
        },
    ]
}

fn tool_list_domains(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
  let mut domains = HashSet::new();
  for command in commands::all_commands() {
    domains.insert(command.domain().to_string());
  }

  let mut sorted_domains: Vec<String> = domains.into_iter().collect();
  sorted_domains.sort();

  let values = sorted_domains
    .into_iter()
    .map(JsonValue::from)
    .collect::<Vec<JsonValue>>();

  let domain_strings: Vec<String> = values
    .iter()
    .filter_map(|value| value.as_str().map(|s| s.to_string()))
    .collect();

  let text = if domain_strings.is_empty() {
    "No RedBlue CLI domains were found.".to_string()
  } else {
    format!(
      "Available domains ({}): {}",
      domain_strings.len(),
      domain_strings.join(", ")
    )
  };

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![("domains".to_string(), JsonValue::array(values))]),
  })
}

fn tool_list_resources(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let domain = args
    .get("domain")
    .and_then(|value| value.as_str())
    .ok_or_else(|| "argument 'domain' is required".to_string())?;

  let mut resources = Vec::new();
  for command in commands::all_commands() {
    if command.domain() != domain {
      continue;
    }

    let mut entry = Vec::new();
    entry.push((
      "resource".to_string(),
      JsonValue::String(command.resource().to_string()),
    ));
    entry.push((
      "description".to_string(),
      JsonValue::String(command.description().to_string()),
    ));

    let routes = command
      .routes()
      .into_iter()
      .map(|route| {
        JsonValue::object(vec![
          (
            "verb".to_string(),
            JsonValue::String(route.verb.to_string()),
          ),
          (
            "summary".to_string(),
            JsonValue::String(route.summary.to_string()),
          ),
          (
            "usage".to_string(),
            JsonValue::String(route.usage.to_string()),
          ),
        ])
      })
      .collect::<Vec<JsonValue>>();

    entry.push(("verbs".to_string(), JsonValue::array(routes)));
    resources.push(JsonValue::Object(entry));
  }

  if resources.is_empty() {
    return Err(format!("no resources found for domain '{}'", domain));
  }

  let mut summary_lines = vec![format!("Resources in '{}':", domain)];
  for element in &resources {
    if let JsonValue::Object(fields) = element {
      let resource_name = fields
        .iter()
        .find(|(key, _)| key == "resource")
        .and_then(|(_, value)| value.as_str())
        .unwrap_or_default();
      let verbs = fields
        .iter()
        .find(|(key, _)| key == "verbs")
        .and_then(|(_, verbs_value)| verbs_value.as_array());
      let mut verb_names = Vec::new();
      if let Some(verbs_list) = verbs {
        for verb in verbs_list {
          if let Some(name) = verb.get("verb").and_then(|v| v.as_str()) {
            verb_names.push(name.to_string());
          }
        }
      }
      if verb_names.is_empty() {
        summary_lines.push(format!("  - {}", resource_name));
      } else {
        summary_lines.push(format!(
          "  - {} -> {}",
          resource_name,
          verb_names.join(", ")
        ));
      }
    }
  }

  Ok(ToolResult {
    text: summary_lines.join("\n"),
    data: JsonValue::object(vec![
      ("domain".to_string(), JsonValue::String(domain.to_string())),
      ("resources".to_string(), JsonValue::array(resources)),
    ]),
  })
}

fn tool_describe_command(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let domain = args
    .get("domain")
    .and_then(|value| value.as_str())
    .ok_or_else(|| "argument 'domain' is required".to_string())?;
  let resource = args
    .get("resource")
    .and_then(|value| value.as_str())
    .ok_or_else(|| "argument 'resource' is required".to_string())?;

  let command = commands::command_for(domain, resource)
    .ok_or_else(|| format!("unknown command '{} {}'", domain, resource))?;

  let mut result = Vec::new();
  result.push(("domain".to_string(), JsonValue::String(domain.to_string())));
  result.push((
    "resource".to_string(),
    JsonValue::String(resource.to_string()),
  ));
  result.push((
    "description".to_string(),
    JsonValue::String(command.description().to_string()),
  ));

  let routes = command
    .routes()
    .into_iter()
    .map(|route| {
      JsonValue::object(vec![
        (
          "verb".to_string(),
          JsonValue::String(route.verb.to_string()),
        ),
        (
          "summary".to_string(),
          JsonValue::String(route.summary.to_string()),
        ),
        (
          "usage".to_string(),
          JsonValue::String(route.usage.to_string()),
        ),
      ])
    })
    .collect::<Vec<JsonValue>>();
  result.push(("verbs".to_string(), JsonValue::array(routes)));

  let flags = command
    .flags()
    .into_iter()
    .map(|flag| {
      JsonValue::object(vec![
        ("name".to_string(), JsonValue::String(flag.long.to_string())),
        (
          "short".to_string(),
          flag
            .short
            .map(|c| JsonValue::String(c.to_string()))
            .unwrap_or(JsonValue::Null),
        ),
        (
          "description".to_string(),
          JsonValue::String(flag.description.to_string()),
        ),
        (
          "default".to_string(),
          flag
            .default
            .clone()
            .map(JsonValue::String)
            .unwrap_or(JsonValue::Null),
        ),
      ])
    })
    .collect::<Vec<JsonValue>>();
  result.push(("flags".to_string(), JsonValue::array(flags)));

  // examples() returns Vec<(&str, &str)> where tuple is (description, command)
  let examples = command
    .examples()
    .into_iter()
    .map(|(desc, cmd)| {
      JsonValue::object(vec![
        ("command".to_string(), JsonValue::String(cmd.to_string())),
        (
          "description".to_string(),
          JsonValue::String(desc.to_string()),
        ),
      ])
    })
    .collect::<Vec<JsonValue>>();
  result.push(("examples".to_string(), JsonValue::array(examples)));

  let summary = format!(
    "Command: rb {} {}\n{}",
    domain,
    resource,
    command.description()
  );

  Ok(ToolResult {
    text: summary,
    data: JsonValue::Object(result),
  })
}

fn tool_command_run(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let domain = args
    .get("domain")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: domain")?;
  let resource = args
    .get("resource")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: resource")?;
  let verb = args
    .get("verb")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: verb")?;
  let target = args.get("target").and_then(|v| v.as_str());

  // Build command args
  let mut cmd_args: Vec<String> = vec![domain.to_string(), resource.to_string(), verb.to_string()];

  if let Some(t) = target {
    cmd_args.push(t.to_string());
  }

  // Add flags
  if let Some(flags) = args.get("flags") {
    if let JsonValue::Object(pairs) = flags {
      for (key, value) in pairs {
        match value {
          JsonValue::Bool(true) => {
            cmd_args.push(format!("--{}", key));
          }
          JsonValue::Bool(false) => {}
          JsonValue::String(s) => {
            cmd_args.push(format!("--{}", key));
            cmd_args.push(s.clone());
          }
          JsonValue::Number(n) => {
            cmd_args.push(format!("--{}", key));
            cmd_args.push(n.to_string());
          }
          _ => {}
        }
      }
    }
  }

  // Execute the command
  let output = std::process::Command::new("rb")
    .args(&cmd_args)
    .output()
    .map_err(|e| format!("Failed to execute rb: {}", e))?;

  let stdout = String::from_utf8_lossy(&output.stdout).to_string();
  let stderr = String::from_utf8_lossy(&output.stderr).to_string();

  let success = output.status.success();
  let text = if success {
    if stdout.is_empty() {
      "Command completed successfully (no output)".to_string()
    } else {
      stdout.clone()
    }
  } else {
    format!("Command failed:\n{}\n{}", stdout, stderr)
  };

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("command".to_string(), JsonValue::String(cmd_args.join(" "))),
      ("success".to_string(), JsonValue::Bool(success)),
      ("stdout".to_string(), JsonValue::String(stdout)),
      ("stderr".to_string(), JsonValue::String(stderr)),
    ]),
  })
}
