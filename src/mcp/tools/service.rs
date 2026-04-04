//! Service Management MCP Tools
//!
//! List, install, and check status of managed persistence mechanisms.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::modules::service::{get_service_manager, ServiceConfig, ServiceStatus, ServiceType};
use crate::utils::json::JsonValue;

/// Register service management tools with the server
pub fn register_service_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.service.list",
            description: "List all managed redblue services and their current status. \
                         Shows installed persistence mechanisms across systemd, launchd, and cron.",
            fields: &[],
            handler: tool_service_list,
        },
        ToolDefinition {
            name: "rb.service.install",
            description: "Install a persistence mechanism for a redblue service. Supports systemd (Linux), \
                         launchd (macOS), and cron as fallback. Services auto-restart on failure by default.",
            fields: &[
                ToolField {
                    name: "type",
                    field_type: "string",
                    description: "Service type to install: 'mitm-proxy', 'http-server', 'dns-server', \
                                 'listener', 'hooks-server', or 'custom'.",
                    required: true,
                },
                ToolField {
                    name: "command",
                    field_type: "string",
                    description: "Command to run (required for 'custom' type). For other types, \
                                 the rb binary command is auto-generated.",
                    required: false,
                },
                ToolField {
                    name: "name",
                    field_type: "string",
                    description: "Custom service name (optional, auto-generated from type if not provided).",
                    required: false,
                },
                ToolField {
                    name: "port",
                    field_type: "number",
                    description: "Port number for the service (required for most types, default varies).",
                    required: false,
                },
                ToolField {
                    name: "auto_start",
                    field_type: "boolean",
                    description: "Start service automatically on boot (default: true).",
                    required: false,
                },
            ],
            handler: tool_service_install,
        },
        ToolDefinition {
            name: "rb.service.status",
            description: "Check the status of a managed redblue service by name. \
                         Returns running/stopped/failed/unknown state and service details.",
            fields: &[
                ToolField {
                    name: "name",
                    field_type: "string",
                    description: "Service name to check (e.g., 'rb-mitm-8080', 'rb-http-3000').",
                    required: true,
                },
            ],
            handler: tool_service_status,
        },
    ]
}

fn tool_service_list(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
    let manager = get_service_manager();

    match manager.list() {
        Ok(services) => {
            if services.is_empty() {
                return Ok(ToolResult::with_data(
                    "No managed redblue services found.",
                    JsonValue::object(vec![
                        ("count".to_string(), JsonValue::Number(0.0)),
                        ("services".to_string(), JsonValue::array(vec![])),
                    ]),
                ));
            }

            let services_json: Vec<JsonValue> = services
                .iter()
                .map(|svc| {
                    JsonValue::object(vec![
                        ("name".to_string(), JsonValue::String(svc.name.clone())),
                        (
                            "status".to_string(),
                            JsonValue::String(svc.status.as_str().to_string()),
                        ),
                        (
                            "description".to_string(),
                            svc.description
                                .as_ref()
                                .map(|d| JsonValue::String(d.clone()))
                                .unwrap_or(JsonValue::Null),
                        ),
                        (
                            "config_path".to_string(),
                            JsonValue::String(svc.config_path.display().to_string()),
                        ),
                        (
                            "installed_at".to_string(),
                            svc.installed_at
                                .as_ref()
                                .map(|t| JsonValue::String(t.clone()))
                                .unwrap_or(JsonValue::Null),
                        ),
                    ])
                })
                .collect();

            let running = services.iter().filter(|s| s.status.is_running()).count();
            let stopped = services
                .iter()
                .filter(|s| matches!(s.status, ServiceStatus::Stopped))
                .count();
            let failed = services
                .iter()
                .filter(|s| matches!(s.status, ServiceStatus::Failed))
                .count();

            let text = format!(
                "Managed redblue services: {} total ({} running, {} stopped, {} failed)",
                services.len(),
                running,
                stopped,
                failed
            );

            Ok(ToolResult::with_data(
                text,
                JsonValue::object(vec![
                    (
                        "count".to_string(),
                        JsonValue::Number(services.len() as f64),
                    ),
                    ("running".to_string(), JsonValue::Number(running as f64)),
                    ("stopped".to_string(), JsonValue::Number(stopped as f64)),
                    ("failed".to_string(), JsonValue::Number(failed as f64)),
                    ("services".to_string(), JsonValue::array(services_json)),
                ]),
            ))
        }
        Err(e) => {
            let text = format!(
                "Failed to list services: {}. \
                 Ensure systemd/launchd is available. CLI alternative: rb service manage list",
                e
            );
            Ok(ToolResult::text(text))
        }
    }
}

fn tool_service_install(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let service_type_str = args
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: type")?;

    let custom_name = args.get("name").and_then(|v| v.as_str());
    let port = args.get("port").and_then(|v| v.as_f64()).map(|p| p as u16);
    let auto_start = args
        .get("auto_start")
        .and_then(|v| match v {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        })
        .unwrap_or(true);

    let service_type = match service_type_str {
        "mitm-proxy" => {
            let p = port.unwrap_or(8080);
            ServiceType::MitmProxy {
                port: p,
                upstream: None,
            }
        }
        "http-server" => {
            let p = port.unwrap_or(3000);
            ServiceType::HttpServer {
                port: p,
                root: std::path::PathBuf::from("."),
            }
        }
        "dns-server" => {
            let p = port.unwrap_or(5353);
            ServiceType::DnsServer {
                port: p,
                upstream: "8.8.8.8".to_string(),
            }
        }
        "listener" => {
            let p = port.unwrap_or(4444);
            ServiceType::Listener {
                port: p,
                protocol: crate::modules::service::ListenerProtocol::Tcp,
            }
        }
        "hooks-server" => {
            let p = port.unwrap_or(9000);
            ServiceType::HooksServer {
                port: p,
                scripts_dir: std::path::PathBuf::from("./scripts"),
            }
        }
        "custom" => {
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or("Missing required field 'command' for custom service type")?;

            ServiceType::Custom {
                command: command.to_string(),
                args: vec![],
            }
        }
        other => {
            return Err(format!(
                "Unknown service type '{}'. Supported: mitm-proxy, http-server, dns-server, \
                 listener, hooks-server, custom",
                other
            ));
        }
    };

    let mut config = ServiceConfig::new(service_type.clone());
    config = config.with_auto_start(auto_start);

    if let Some(name) = custom_name {
        config = config.with_name(name);
    }

    let manager = get_service_manager();

    match manager.install(&config) {
        Ok(installed) => {
            let text = format!(
                "Service '{}' installed successfully at {}. Status: {}",
                installed.name,
                installed.config_path.display(),
                installed.status.as_str()
            );

            Ok(ToolResult::with_data(
                text,
                JsonValue::object(vec![
                    (
                        "name".to_string(),
                        JsonValue::String(installed.name.clone()),
                    ),
                    (
                        "status".to_string(),
                        JsonValue::String(installed.status.as_str().to_string()),
                    ),
                    (
                        "config_path".to_string(),
                        JsonValue::String(installed.config_path.display().to_string()),
                    ),
                    (
                        "description".to_string(),
                        installed
                            .description
                            .map(|d| JsonValue::String(d))
                            .unwrap_or(JsonValue::Null),
                    ),
                    ("auto_start".to_string(), JsonValue::Bool(auto_start)),
                    (
                        "service_type".to_string(),
                        JsonValue::String(service_type_str.to_string()),
                    ),
                ]),
            ))
        }
        Err(e) => {
            let rb_cmd = match service_type_str {
                "mitm-proxy" => format!(
                    "rb service manage install mitm-proxy --port {}",
                    port.unwrap_or(8080)
                ),
                "http-server" => format!(
                    "rb service manage install http-server --port {}",
                    port.unwrap_or(3000)
                ),
                "dns-server" => format!(
                    "rb service manage install dns-server --port {}",
                    port.unwrap_or(5353)
                ),
                "listener" => format!(
                    "rb service manage install listener --port {}",
                    port.unwrap_or(4444)
                ),
                _ => "rb service manage install --help".to_string(),
            };

            let text = format!(
                "Failed to install service: {}. \
                 This may require elevated permissions. Try via CLI:\n  {}",
                e, rb_cmd
            );

            Ok(ToolResult::with_data(
                text,
                JsonValue::object(vec![
                    ("error".to_string(), JsonValue::String(e)),
                    ("cli_command".to_string(), JsonValue::String(rb_cmd)),
                ]),
            ))
        }
    }
}

fn tool_service_status(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: name")?;

    let manager = get_service_manager();

    match manager.status(name) {
        Ok(status) => {
            let status_str = status.as_str();
            let is_running = status.is_running();

            let text = format!("Service '{}': {}", name, status_str);

            Ok(ToolResult::with_data(
                text,
                JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(name.to_string())),
                    (
                        "status".to_string(),
                        JsonValue::String(status_str.to_string()),
                    ),
                    ("is_running".to_string(), JsonValue::Bool(is_running)),
                ]),
            ))
        }
        Err(e) => {
            let text = format!(
                "Failed to check status of '{}': {}. \
                 CLI alternative: rb service manage status {}",
                name, e, name
            );

            Ok(ToolResult::with_data(
                text,
                JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(name.to_string())),
                    ("status".to_string(), JsonValue::String("error".to_string())),
                    ("error".to_string(), JsonValue::String(e)),
                ]),
            ))
        }
    }
}
