use crate::cli::commands::{Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::mcp::categories::{CategoryConfig, CategoryPreset, ToolCategory};
use crate::mcp::server::McpServer;
use crate::mcp::transport::{start_http_transports, TransportConfig, TransportHandles};
use std::sync::{Arc, Mutex};

pub struct McpCommand;

impl Command for McpCommand {
    fn domain(&self) -> &str {
        "mcp"
    }

    fn resource(&self) -> &str {
        "server"
    }

    fn description(&self) -> &str {
        "Model Context Protocol (MCP) bridge for local RedBlue automation."
    }

    fn routes(&self) -> Vec<Route> {
        vec![Route {
            verb: "start",
            summary: "Start the local MCP server over stdio.",
            usage: "rb mcp server start",
        }]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("http-addr", "Bind address for MCP HTTP/SSE transports")
                .with_arg("ADDR")
                .with_default("127.0.0.1:8787"),
            Flag::new("no-http", "Disable HTTP/SSE transports (stdio only)"),
            Flag::new("no-sse", "Disable Server-Sent Events transport"),
            Flag::new("no-stream", "Disable streamable HTTP transport"),
            Flag::new(
                "categories",
                "Comma-separated list of tool categories to enable (default: all)",
            )
            .with_arg("CATS")
            .with_default("all"),
            Flag::new(
                "preset",
                "Use a category preset: all, core, blue-team, red-team, web-security, minimal",
            )
            .with_arg("PRESET"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![(
            "Start the MCP server and keep it running for clients",
            "rb mcp server start",
        )]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let resource = ctx.resource.as_deref().unwrap_or_default();
        if resource != "server" {
            return Err(format!(
                "Unknown resource '{}'. Use: rb mcp server start",
                resource
            ));
        }

        let verb = ctx.verb.as_deref().unwrap_or_default();
        match verb {
            "start" => {
                let http_addr = ctx
                    .flags
                    .get("http-addr")
                    .cloned()
                    .unwrap_or_else(|| "127.0.0.1:8787".to_string());
                let enable_http = !ctx.flags.contains_key("no-http");
                let enable_sse = !ctx.flags.contains_key("no-sse");
                let enable_stream = !ctx.flags.contains_key("no-stream");

                // Parse category configuration
                let category_config = if let Some(preset_str) = ctx.flags.get("preset") {
                    // Preset takes priority
                    match CategoryPreset::from_str(preset_str) {
                        Some(preset) => {
                            Output::info(&format!(
                                "Using preset: {} ({})",
                                preset.as_str(),
                                preset.description()
                            ));
                            CategoryConfig::from_preset(preset)
                        }
                        None => {
                            Output::error(&format!(
                                "Unknown preset '{}'. Valid presets: all, core, blue-team, red-team, web-security, minimal",
                                preset_str
                            ));
                            return Err(format!("unknown preset: {}", preset_str));
                        }
                    }
                } else if let Some(cats_str) = ctx.flags.get("categories") {
                    if cats_str == "all" {
                        CategoryConfig::new() // All enabled
                    } else {
                        // Parse comma-separated categories
                        let mut config = CategoryConfig::from_preset(CategoryPreset::Minimal);
                        let mut enabled = Vec::new();

                        for cat_str in cats_str.split(',') {
                            let cat_str = cat_str.trim();
                            if let Some(cat) = ToolCategory::from_str(cat_str) {
                                config.enable(cat);
                                enabled.push(cat.as_str());
                            } else {
                                Output::warning(&format!(
                                    "Unknown category '{}', skipping",
                                    cat_str
                                ));
                            }
                        }

                        if enabled.is_empty() {
                            Output::warning("No valid categories specified, using all");
                            CategoryConfig::new()
                        } else {
                            Output::info(&format!("Enabled categories: {}", enabled.join(", ")));
                            config
                        }
                    }
                } else {
                    CategoryConfig::new() // Default: all enabled
                };

                let core = Arc::new(Mutex::new(McpServer::with_categories(category_config)));
                let handles = if enable_http {
                    let config = TransportConfig {
                        http_addr,
                        enable_http: true,
                        enable_sse,
                        enable_stream,
                    };
                    start_http_transports(core.clone(), config)?
                } else {
                    TransportHandles::default()
                };

                Output::info("Starting MCP server (stdio transport). Press Ctrl+C to exit.");

                let result = McpServer::run_stdio(core.clone());
                handles.stop();
                result.map_err(|e| format!("MCP server error: {}", e))
            }
            _ => Err(format!(
                "Unknown verb '{}'. Try `rb mcp server help` for options.",
                verb
            )),
        }
    }
}
