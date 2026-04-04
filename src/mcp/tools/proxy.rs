//! Proxy MCP Tools
//!
//! Tools for HTTP/SOCKS5 proxy management, interception listing,
//! and interception rule configuration. Since proxies are long-running
//! services, these tools provide configuration guidance and status
//! information rather than maintaining persistent state within the MCP session.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register proxy tools with the server
pub fn register_proxy_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.proxy.start",
            description: "Generate the configuration and CLI command to start an HTTP CONNECT or SOCKS5 proxy. \
                         Supports optional authentication, ACL rules, and TLS interception. \
                         Returns the command to run and configuration details since the proxy \
                         is a long-running process that persists beyond the MCP session.",
            fields: &[
                ToolField {
                    name: "type",
                    field_type: "string",
                    description: "Proxy type: 'http', 'socks5', or 'mitm' (default: 'socks5').",
                    required: false,
                },
                ToolField {
                    name: "port",
                    field_type: "number",
                    description: "Port to listen on (default: 1080 for SOCKS5, 8080 for HTTP/MITM).",
                    required: false,
                },
                ToolField {
                    name: "bind",
                    field_type: "string",
                    description: "Address to bind to (default: '127.0.0.1'). Use '0.0.0.0' for all interfaces.",
                    required: false,
                },
                ToolField {
                    name: "auth",
                    field_type: "string",
                    description: "Authentication in 'username:password' format. If omitted, no auth required.",
                    required: false,
                },
                ToolField {
                    name: "upstream",
                    field_type: "string",
                    description: "Upstream proxy to chain through (e.g., 'socks5://10.0.0.1:1080').",
                    required: false,
                },
            ],
            handler: tool_proxy_start,
        },
        ToolDefinition {
            name: "rb.proxy.intercept.list",
            description: "Describe how to list intercepted requests from a running proxy instance. \
                         Provides information about the proxy tracking system including connection \
                         statistics, flow data, and intercepted request/response pairs.",
            fields: &[
                ToolField {
                    name: "port",
                    field_type: "number",
                    description: "Port of the running proxy to query (default: 8080).",
                    required: false,
                },
                ToolField {
                    name: "filter",
                    field_type: "string",
                    description: "Filter intercepted traffic: 'all', 'http', 'https', 'websocket' (default: 'all').",
                    required: false,
                },
                ToolField {
                    name: "host",
                    field_type: "string",
                    description: "Filter by target hostname (e.g., 'example.com').",
                    required: false,
                },
            ],
            handler: tool_proxy_intercept_list,
        },
        ToolDefinition {
            name: "rb.proxy.intercept.rules",
            description: "Generate interception rule configurations for the proxy. \
                         Rules control which connections are intercepted, modified, or passed through. \
                         Supports ACL-based filtering by source IP, destination, port, and protocol.",
            fields: &[
                ToolField {
                    name: "action",
                    field_type: "string",
                    description: "Rule action: 'allow', 'deny', 'intercept', 'passthrough', 'list' (default: 'list').",
                    required: false,
                },
                ToolField {
                    name: "source",
                    field_type: "string",
                    description: "Source IP or CIDR to match (e.g., '192.168.1.0/24'). Default: any.",
                    required: false,
                },
                ToolField {
                    name: "destination",
                    field_type: "string",
                    description: "Destination host or IP to match (e.g., 'example.com' or '10.0.0.0/8'). Default: any.",
                    required: false,
                },
                ToolField {
                    name: "port",
                    field_type: "string",
                    description: "Port or port range to match (e.g., '443' or '80,443,8080'). Default: any.",
                    required: false,
                },
                ToolField {
                    name: "protocol",
                    field_type: "string",
                    description: "Protocol to match: 'tcp', 'udp', 'any' (default: 'any').",
                    required: false,
                },
            ],
            handler: tool_proxy_intercept_rules,
        },
    ]
}

fn tool_proxy_start(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let proxy_type = args
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("socks5");

    let default_port = match proxy_type {
        "http" | "mitm" => 8080,
        "socks5" => 1080,
        other => {
            return Err(format!(
                "Unknown proxy type '{}'. Valid: http, socks5, mitm",
                other
            ))
        }
    };

    let port = args
        .get("port")
        .and_then(|v| v.as_f64())
        .map(|n| n as u16)
        .unwrap_or(default_port);

    let bind_addr = args
        .get("bind")
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1");

    let auth = args.get("auth").and_then(|v| v.as_str());
    let upstream = args.get("upstream").and_then(|v| v.as_str());

    // Build the CLI command
    let mut cli_cmd = format!(
        "rb proxy {} start --port {} --bind {}",
        proxy_type, port, bind_addr
    );

    if let Some(auth_str) = auth {
        cli_cmd.push_str(&format!(" --auth '{}'", auth_str));
    }

    if let Some(upstream_str) = upstream {
        cli_cmd.push_str(&format!(" --upstream '{}'", upstream_str));
    }

    // Build configuration summary
    let listen_addr = format!("{}:{}", bind_addr, port);

    let proxy_url = match proxy_type {
        "socks5" => format!("socks5://{}", listen_addr),
        "http" | "mitm" => format!("http://{}", listen_addr),
        _ => listen_addr.clone(),
    };

    // Build curl/browser config examples
    let curl_example = match proxy_type {
        "socks5" => format!("curl --proxy socks5h://{} https://example.com", listen_addr),
        _ => format!("curl --proxy http://{} https://example.com", listen_addr),
    };

    let env_example = match proxy_type {
        "socks5" => format!("export ALL_PROXY=socks5h://{}", listen_addr),
        _ => format!(
            "export HTTP_PROXY=http://{}\nexport HTTPS_PROXY=http://{}",
            listen_addr, listen_addr
        ),
    };

    let mut features = vec![
        format!("Type: {}", proxy_type.to_uppercase()),
        format!("Listen: {}", listen_addr),
    ];

    if auth.is_some() {
        features.push("Authentication: enabled".to_string());
    } else {
        features.push("Authentication: none (open proxy)".to_string());
    }

    if let Some(up) = upstream {
        features.push(format!("Upstream chain: {}", up));
    }

    if proxy_type == "mitm" {
        features.push("TLS interception: enabled (requires CA certificate trust)".to_string());
    }

    if proxy_type == "socks5" {
        features.push("Protocols: TCP CONNECT, UDP ASSOCIATE".to_string());
    }

    let text = format!(
        "Proxy configuration ({}):\n\n{}\n\n\
         Start command:\n  {}\n\n\
         Client usage:\n  {}\n\n\
         Environment variables:\n  {}",
        proxy_type.to_uppercase(),
        features.join("\n"),
        cli_cmd,
        curl_example,
        env_example,
    );

    let mut data_fields = vec![
        (
            "proxy_type".to_string(),
            JsonValue::String(proxy_type.to_string()),
        ),
        ("listen_address".to_string(), JsonValue::String(listen_addr)),
        ("port".to_string(), JsonValue::Number(port as f64)),
        (
            "bind_address".to_string(),
            JsonValue::String(bind_addr.to_string()),
        ),
        ("proxy_url".to_string(), JsonValue::String(proxy_url)),
        ("cli_command".to_string(), JsonValue::String(cli_cmd)),
        ("curl_example".to_string(), JsonValue::String(curl_example)),
        ("auth_enabled".to_string(), JsonValue::Bool(auth.is_some())),
    ];

    if let Some(upstream_str) = upstream {
        data_fields.push((
            "upstream".to_string(),
            JsonValue::String(upstream_str.to_string()),
        ));
    }

    Ok(ToolResult {
        text,
        data: JsonValue::object(data_fields),
    })
}

fn tool_proxy_intercept_list(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let port = args
        .get("port")
        .and_then(|v| v.as_f64())
        .map(|n| n as u16)
        .unwrap_or(8080);

    let filter = args.get("filter").and_then(|v| v.as_str()).unwrap_or("all");

    let host_filter = args.get("host").and_then(|v| v.as_str());

    // Build the CLI commands for interacting with a running proxy
    let list_cmd = format!("rb proxy intercept list --port {}", port);
    let export_cmd = format!("rb proxy intercept export --port {} --format har", port);

    let mut filter_flags = String::new();
    if filter != "all" {
        filter_flags.push_str(&format!(" --filter {}", filter));
    }
    if let Some(host) = host_filter {
        filter_flags.push_str(&format!(" --host {}", host));
    }

    let full_cmd = if filter_flags.is_empty() {
        list_cmd.clone()
    } else {
        format!("{}{}", list_cmd, filter_flags)
    };

    let text = format!(
        "Proxy interception tracking (port {}):\n\n\
         The proxy tracks all connections with flow statistics including:\n\
         - Source/destination addresses and ports\n\
         - Protocol (TCP/UDP) and connection state\n\
         - Bytes sent/received per connection\n\
         - Connection duration and timing\n\
         - Process information (PID, name) when available\n\n\
         Commands:\n\
         - List intercepted traffic:  {}\n\
         - Export as HAR format:      {}\n\n\
         Flow statistics are accumulated in real-time and include:\n\
         - Total/active connection counts\n\
         - Aggregate bytes sent/received\n\
         - TCP vs UDP connection breakdown",
        port, full_cmd, export_cmd,
    );

    let mut data_fields = vec![
        ("port".to_string(), JsonValue::Number(port as f64)),
        ("filter".to_string(), JsonValue::String(filter.to_string())),
        ("list_command".to_string(), JsonValue::String(full_cmd)),
        ("export_command".to_string(), JsonValue::String(export_cmd)),
        (
            "tracked_fields".to_string(),
            JsonValue::array(vec![
                JsonValue::String("connection_id".to_string()),
                JsonValue::String("source_address".to_string()),
                JsonValue::String("destination_address".to_string()),
                JsonValue::String("protocol".to_string()),
                JsonValue::String("state".to_string()),
                JsonValue::String("bytes_sent".to_string()),
                JsonValue::String("bytes_received".to_string()),
                JsonValue::String("duration".to_string()),
                JsonValue::String("process_info".to_string()),
            ]),
        ),
    ];

    if let Some(host) = host_filter {
        data_fields.push((
            "host_filter".to_string(),
            JsonValue::String(host.to_string()),
        ));
    }

    Ok(ToolResult {
        text,
        data: JsonValue::object(data_fields),
    })
}

fn tool_proxy_intercept_rules(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("list");

    let source = args.get("source").and_then(|v| v.as_str());
    let destination = args.get("destination").and_then(|v| v.as_str());
    let port = args.get("port").and_then(|v| v.as_str());
    let protocol = args
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("any");

    match action {
        "list" => {
            let text = "Proxy interception rules (ACL system):\n\n\
                Rules are evaluated in order. First match wins.\n\n\
                Available actions:\n\
                - allow:       Permit the connection (no interception)\n\
                - deny:        Block the connection entirely\n\
                - intercept:   Allow and capture request/response data\n\
                - passthrough: Allow without any inspection (transparent relay)\n\n\
                Default built-in rules:\n\
                1. [deny]        source=any  dest=127.0.0.0/8  port=any  proto=any  (prevent proxy loops)\n\
                2. [intercept]   source=any  dest=any           port=80   proto=tcp  (capture HTTP)\n\
                3. [intercept]   source=any  dest=any           port=443  proto=tcp  (capture HTTPS for MITM)\n\
                4. [passthrough] source=any  dest=any           port=any  proto=any  (default pass)\n\n\
                CLI commands:\n\
                - List rules:     rb proxy rules list\n\
                - Add rule:       rb proxy rules add --action intercept --dest example.com --port 443\n\
                - Remove rule:    rb proxy rules remove <rule-id>\n\
                - Reorder rules:  rb proxy rules move <rule-id> <position>"
                .to_string();

            let default_rules = vec![
                JsonValue::object(vec![
                    ("id".to_string(), JsonValue::Number(1.0)),
                    ("action".to_string(), JsonValue::String("deny".to_string())),
                    ("source".to_string(), JsonValue::String("any".to_string())),
                    (
                        "destination".to_string(),
                        JsonValue::String("127.0.0.0/8".to_string()),
                    ),
                    ("port".to_string(), JsonValue::String("any".to_string())),
                    ("protocol".to_string(), JsonValue::String("any".to_string())),
                    (
                        "description".to_string(),
                        JsonValue::String("Prevent proxy loops".to_string()),
                    ),
                ]),
                JsonValue::object(vec![
                    ("id".to_string(), JsonValue::Number(2.0)),
                    (
                        "action".to_string(),
                        JsonValue::String("intercept".to_string()),
                    ),
                    ("source".to_string(), JsonValue::String("any".to_string())),
                    (
                        "destination".to_string(),
                        JsonValue::String("any".to_string()),
                    ),
                    ("port".to_string(), JsonValue::String("80".to_string())),
                    ("protocol".to_string(), JsonValue::String("tcp".to_string())),
                    (
                        "description".to_string(),
                        JsonValue::String("Capture HTTP traffic".to_string()),
                    ),
                ]),
                JsonValue::object(vec![
                    ("id".to_string(), JsonValue::Number(3.0)),
                    (
                        "action".to_string(),
                        JsonValue::String("intercept".to_string()),
                    ),
                    ("source".to_string(), JsonValue::String("any".to_string())),
                    (
                        "destination".to_string(),
                        JsonValue::String("any".to_string()),
                    ),
                    ("port".to_string(), JsonValue::String("443".to_string())),
                    ("protocol".to_string(), JsonValue::String("tcp".to_string())),
                    (
                        "description".to_string(),
                        JsonValue::String("Capture HTTPS for MITM".to_string()),
                    ),
                ]),
                JsonValue::object(vec![
                    ("id".to_string(), JsonValue::Number(4.0)),
                    (
                        "action".to_string(),
                        JsonValue::String("passthrough".to_string()),
                    ),
                    ("source".to_string(), JsonValue::String("any".to_string())),
                    (
                        "destination".to_string(),
                        JsonValue::String("any".to_string()),
                    ),
                    ("port".to_string(), JsonValue::String("any".to_string())),
                    ("protocol".to_string(), JsonValue::String("any".to_string())),
                    (
                        "description".to_string(),
                        JsonValue::String("Default passthrough".to_string()),
                    ),
                ]),
            ];

            Ok(ToolResult {
                text,
                data: JsonValue::object(vec![
                    ("action".to_string(), JsonValue::String("list".to_string())),
                    ("default_rules".to_string(), JsonValue::array(default_rules)),
                ]),
            })
        }
        "allow" | "deny" | "intercept" | "passthrough" => {
            let source_str = source.unwrap_or("any");
            let dest_str = destination.unwrap_or("any");
            let port_str = port.unwrap_or("any");

            // Build the CLI command for adding this rule
            let mut cli_cmd = format!("rb proxy rules add --action {}", action);

            if source_str != "any" {
                cli_cmd.push_str(&format!(" --source {}", source_str));
            }
            if dest_str != "any" {
                cli_cmd.push_str(&format!(" --dest {}", dest_str));
            }
            if port_str != "any" {
                cli_cmd.push_str(&format!(" --port {}", port_str));
            }
            if protocol != "any" {
                cli_cmd.push_str(&format!(" --proto {}", protocol));
            }

            let text = format!(
                "Interception rule configuration:\n\n\
                 Action:      {}\n\
                 Source:      {}\n\
                 Destination: {}\n\
                 Port:        {}\n\
                 Protocol:    {}\n\n\
                 CLI command to apply:\n  {}",
                action, source_str, dest_str, port_str, protocol, cli_cmd,
            );

            let rule = JsonValue::object(vec![
                ("action".to_string(), JsonValue::String(action.to_string())),
                (
                    "source".to_string(),
                    JsonValue::String(source_str.to_string()),
                ),
                (
                    "destination".to_string(),
                    JsonValue::String(dest_str.to_string()),
                ),
                ("port".to_string(), JsonValue::String(port_str.to_string())),
                (
                    "protocol".to_string(),
                    JsonValue::String(protocol.to_string()),
                ),
            ]);

            Ok(ToolResult {
                text,
                data: JsonValue::object(vec![
                    ("action".to_string(), JsonValue::String(action.to_string())),
                    ("rule".to_string(), rule),
                    ("cli_command".to_string(), JsonValue::String(cli_cmd)),
                ]),
            })
        }
        other => Err(format!(
            "Unknown action '{}'. Valid: allow, deny, intercept, passthrough, list",
            other
        )),
    }
}
