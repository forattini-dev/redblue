//! MCP Server implementation for redblue
//!
//! This module provides the Model Context Protocol server that exposes
//! redblue's security tools to AI agents.

// Submodules
mod docs;
mod encoding;
mod helpers;
mod protocol;
mod targets;

// Re-export commonly used items
pub use docs::{
    all_document_paths, build_document_index, extract_markdown_section, parse_heading,
    resolve_doc_path, search_documentation, slugify, summarize_markdown, truncate_preview,
};
pub use encoding::{base64_decode, base64_encode, hex, url_decode, url_encode};
pub use helpers::{
    detect_provider_for_mcp, map_tech_to_ecosystem, parse_command_arguments, split_command_line,
    vuln_to_json,
};
pub use protocol::{
    build_error_message, build_input_schema, build_result_message, read_payload, write_message,
};
pub use targets::{current_timestamp, default_target_db_path, TargetDatabase, TargetEntry};

use crate::mcp::categories::{CategoryConfig, CategoryPreset, ToolCategory};
use crate::mcp::embeddings::{load_embeddings, EmbeddingsData, EmbeddingsLoaderConfig};
use crate::mcp::orchestrator::Orchestrator;
use crate::mcp::prompts::PromptRegistry;
use crate::mcp::resources::ResourceRegistry;
use crate::mcp::search::{hybrid_search, SearchConfig, SearchMode};
use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::modules::recon::vuln::osv::OsvClient;
use crate::modules::recon::vuln::{
    calculate_risk_score, generate_cpe, KevClient, NvdClient, VulnCollection,
};
use crate::modules::web::crawler::WebCrawler;
use crate::modules::web::dom::Document;
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::protocols::har::Har;
use crate::utils::json::{parse_json, JsonValue};
use std::fs;
use std::io::{self};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Import tool registration functions
use crate::mcp::tools::{
    register_auto_tools, register_binary_tools, register_code_tools, register_core_tools,
    register_crypto_tools, register_dns_tools, register_evasion_tools, register_file_tools,
    register_intel_tools, register_network_tools, register_password_tools, register_recon_tools,
    register_tls_tools, register_vector_tools, register_vuln_tools, register_web_tools,
    register_wordlist_tools,
};

pub struct McpServer {
    tools: Vec<ToolDefinition<Self>>,
    initialized: bool,
    embeddings: Option<EmbeddingsData>,
    embeddings_loaded: bool,
    resources: ResourceRegistry,
    prompts: PromptRegistry,
    categories: CategoryConfig,
    /// Orchestrator for autonomous operations - public for tool module access
    pub orchestrator: Orchestrator,
}

impl McpServer {
    /// Collect tools that remain inline (not yet extracted to modules)
    fn register_inline_tools() -> Vec<ToolDefinition<Self>> {
        vec![
            // Documentation tools
            ToolDefinition {
                name: "rb.search-docs",
                description:
                    "Search the RedBlue documentation for a keyword or phrase (case-insensitive).",
                fields: &[ToolField {
                    name: "query",
                    field_type: "string",
                    description: "Search term to look for inside docs/ and README.md.",
                    required: true,
                }],
                handler: Self::tool_search_docs,
            },
            ToolDefinition {
                name: "rb.docs.index",
                description: "Return a structured index of project documentation.",
                fields: &[],
                handler: Self::tool_docs_index,
            },
            ToolDefinition {
                name: "rb.docs.get",
                description: "Fetch documentation content by path and optional section.",
                fields: &[
                    ToolField {
                        name: "path",
                        field_type: "string",
                        description: "Relative documentation path (e.g. docs/cli-semantics.md).",
                        required: true,
                    },
                    ToolField {
                        name: "section",
                        field_type: "string",
                        description:
                            "Optional heading to extract (exact text match, case-insensitive).",
                        required: false,
                    },
                ],
                handler: Self::tool_docs_get,
            },
            // Target management
            ToolDefinition {
                name: "rb.targets.list",
                description: "List all MCP-tracked targets with metadata.",
                fields: &[],
                handler: Self::tool_targets_list,
            },
            ToolDefinition {
                name: "rb.targets.save",
                description: "Create or update a tracked target entry.",
                fields: &[
                    ToolField {
                        name: "name",
                        field_type: "string",
                        description: "Human-friendly identifier (unique).",
                        required: true,
                    },
                    ToolField {
                        name: "target",
                        field_type: "string",
                        description: "Target expression (host, URL, CIDR, etc.).",
                        required: true,
                    },
                    ToolField {
                        name: "notes",
                        field_type: "string",
                        description: "Optional notes or task context.",
                        required: false,
                    },
                ],
                handler: Self::tool_targets_save,
            },
            ToolDefinition {
                name: "rb.targets.remove",
                description: "Delete a tracked target by name.",
                fields: &[ToolField {
                    name: "name",
                    field_type: "string",
                    description: "Identifier to remove.",
                    required: true,
                }],
                handler: Self::tool_targets_remove,
            },
            // HTML tools
            ToolDefinition {
                name: "rb.html.select",
                description: "Extract elements from HTML using CSS selectors.",
                fields: &[
                    ToolField {
                        name: "html",
                        field_type: "string",
                        description: "HTML content to parse.",
                        required: true,
                    },
                    ToolField {
                        name: "selector",
                        field_type: "string",
                        description: "CSS selector (e.g., 'div.content', 'a[href]').",
                        required: true,
                    },
                ],
                handler: Self::tool_html_select,
            },
            // HAR tools
            ToolDefinition {
                name: "rb.har.record",
                description: "Start recording HTTP traffic to a HAR file.",
                fields: &[
                    ToolField {
                        name: "output",
                        field_type: "string",
                        description: "Output path for HAR file.",
                        required: true,
                    },
                    ToolField {
                        name: "target",
                        field_type: "string",
                        description: "Target URL or host to filter requests.",
                        required: false,
                    },
                ],
                handler: Self::tool_har_record,
            },
            ToolDefinition {
                name: "rb.har.analyze",
                description: "Analyze a HAR file for security issues and statistics.",
                fields: &[ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Path to HAR file.",
                    required: true,
                }],
                handler: Self::tool_har_analyze,
            },
            // Fingerprinting
            ToolDefinition {
                name: "rb.vuln.fingerprint",
                description: "Fingerprint a web application (CMS, framework, server).",
                fields: &[ToolField {
                    name: "url",
                    field_type: "string",
                    description: "Target URL to fingerprint.",
                    required: true,
                }],
                handler: Self::tool_vuln_fingerprint,
            },
            ToolDefinition {
                name: "rb.fingerprint.service",
                description: "Fingerprint a network service from banner/response.",
                fields: &[
                    ToolField {
                        name: "host",
                        field_type: "string",
                        description: "Target host.",
                        required: true,
                    },
                    ToolField {
                        name: "port",
                        field_type: "number",
                        description: "Target port.",
                        required: true,
                    },
                ],
                handler: Self::tool_fingerprint_service,
            },
            // Configuration
            ToolDefinition {
                name: "rb.config.categories",
                description: "View current tool category configuration.",
                fields: &[],
                handler: Self::tool_config_categories,
            },
            ToolDefinition {
                name: "rb.config.preset",
                description: "Apply a tool preset configuration.",
                fields: &[ToolField {
                    name: "preset",
                    field_type: "string",
                    description: "Preset name: full, passive, active, recon.",
                    required: true,
                }],
                handler: Self::tool_config_preset,
            },
            // Auto guide (not in auto module)
            ToolDefinition {
                name: "rb.auto.guide",
                description: "Get AI guidance for next step in autonomous operation.",
                fields: &[
                    ToolField {
                        name: "operation_id",
                        field_type: "string",
                        description: "Operation ID from auto.recon or auto.vulnscan.",
                        required: true,
                    },
                    ToolField {
                        name: "llm_response",
                        field_type: "string",
                        description: "LLM response with suggested action.",
                        required: true,
                    },
                ],
                handler: Self::tool_auto_guide,
            },
        ]
    }

    pub fn new() -> Self {
        // Collect tools from all modules
        let mut tools: Vec<ToolDefinition<Self>> = Vec::new();

        // Core tools (CLI introspection)
        tools.extend(register_core_tools());

        // Network tools
        tools.extend(register_network_tools());

        // DNS tools
        tools.extend(register_dns_tools());

        // TLS tools
        tools.extend(register_tls_tools());

        // Web tools
        tools.extend(register_web_tools());

        // Recon tools
        tools.extend(register_recon_tools());

        // Vulnerability tools
        tools.extend(register_vuln_tools());

        // Intel tools
        tools.extend(register_intel_tools());

        // Evasion tools
        tools.extend(register_evasion_tools());

        // Autonomous tools
        tools.extend(register_auto_tools());

        // Code analysis tools
        tools.extend(register_code_tools());

        // Password tools
        tools.extend(register_password_tools());

        // Wordlist tools
        tools.extend(register_wordlist_tools());

        // Crypto tools
        tools.extend(register_crypto_tools());

        // File tools (compression, hash)
        tools.extend(register_file_tools());

        // Binary tools
        tools.extend(register_binary_tools());

        // Vector search tools (tiered quantization)
        tools.extend(register_vector_tools());

        // Inline tools (not yet extracted to modules)
        tools.extend(Self::register_inline_tools());

        Self {
            tools,
            initialized: false,
            embeddings: None,
            embeddings_loaded: false,
            resources: ResourceRegistry::new(),
            prompts: PromptRegistry::new(),
            categories: CategoryConfig::new(),
            orchestrator: Orchestrator::new(),
        }
    }

    /// Create with specific category configuration
    pub fn with_categories(categories: CategoryConfig) -> Self {
        let mut server = Self::new();
        server.categories = categories;
        server
    }

    /// Set categories after creation
    pub fn set_categories(&mut self, categories: CategoryConfig) {
        self.categories = categories;
    }

    /// Initialize the MCP server (called before main loop)
    /// This eagerly loads embeddings for semantic search
    pub fn init(&mut self) {
        self.ensure_embeddings_loaded();
    }

    /// Load embeddings for hybrid search (lazy initialization)
    fn ensure_embeddings_loaded(&mut self) {
        if self.embeddings_loaded {
            return;
        }
        self.embeddings_loaded = true;

        let config = EmbeddingsLoaderConfig::default();
        match load_embeddings(&config) {
            Ok(data) => {
                eprintln!(
                    "[MCP] Loaded {} documents with embeddings (has_vectors: {})",
                    data.documents.len(),
                    data.has_vectors
                );
                self.embeddings = Some(data);
            }
            Err(e) => {
                eprintln!("[MCP] Warning: Could not load embeddings: {}", e);
                eprintln!("[MCP] Falling back to basic text search");
            }
        }
    }

    pub fn run_stdio(core: Arc<Mutex<McpServer>>) -> Result<(), String> {
        // Eagerly initialize embeddings for semantic search
        {
            let mut guard = core
                .lock()
                .map_err(|_| "MCP server state poisoned".to_string())?;
            guard.init();
        }

        let stdin = io::stdin();
        let mut reader = stdin.lock();
        loop {
            let payload = match read_payload(&mut reader)? {
                Some(p) => p,
                None => break,
            };
            let message = match parse_json(&payload) {
                Ok(value) => value,
                Err(err) => {
                    let response =
                        build_error_message(None, -32700, &format!("invalid JSON: {}", err));
                    write_message(response)?;
                    continue;
                }
            };
            let response = {
                let mut guard = core
                    .lock()
                    .map_err(|_| "MCP server state poisoned".to_string())?;
                guard.process_message(message)
            };
            if let Some(response) = response {
                write_message(response)?;
            }
        }
        Ok(())
    }

    pub fn process_message(&mut self, message: JsonValue) -> Option<JsonValue> {
        self.handle_message(message)
    }

    fn handle_message(&mut self, message: JsonValue) -> Option<JsonValue> {
        let obj = match message {
            JsonValue::Object(entries) => entries,
            _ => {
                return Some(build_error_message(
                    None,
                    -32600,
                    "top-level message must be an object",
                ))
            }
        };

        let mut id: Option<JsonValue> = None;
        let mut method: Option<String> = None;
        let mut params = JsonValue::Null;

        for (key, value) in obj {
            match key.as_str() {
                "id" => {
                    id = Some(value);
                }
                "method" => {
                    if let JsonValue::String(s) = value {
                        method = Some(s);
                    }
                }
                "params" => {
                    params = value;
                }
                _ => {}
            }
        }

        let method_name = match method {
            Some(name) => name,
            None => return Some(build_error_message(id, -32600, "missing method field")),
        };

        let response = match method_name.as_str() {
            "initialize" => match self.handle_initialize(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("initialize failed: {}", err),
                )),
            },
            "tools/list" => match self.handle_list_tools(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("list failed: {}", err),
                )),
            },
            "tools/call" => match self.handle_tool_call(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("tool call failed: {}", err),
                )),
            },
            "resources/list" => match self.handle_list_resources(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("resources list failed: {}", err),
                )),
            },
            "resources/read" => match self.handle_read_resource(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("resource read failed: {}", err),
                )),
            },
            "prompts/list" => match self.handle_list_prompts(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("prompts list failed: {}", err),
                )),
            },
            "prompts/get" => match self.handle_get_prompt(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("prompt get failed: {}", err),
                )),
            },
            "notifications/initialized" => None,
            other => Some(build_error_message(
                id,
                -32601,
                &format!("unsupported method '{}'", other),
            )),
        };

        response
    }

    fn handle_initialize(&mut self, _params: JsonValue) -> Result<JsonValue, String> {
        let capabilities = JsonValue::object(vec![
            (
                "tools".to_string(),
                JsonValue::object(vec![
                    ("list".to_string(), JsonValue::Bool(true)),
                    ("call".to_string(), JsonValue::Bool(true)),
                ]),
            ),
            (
                "resources".to_string(),
                JsonValue::object(vec![
                    ("list".to_string(), JsonValue::Bool(true)),
                    ("read".to_string(), JsonValue::Bool(true)),
                    ("subscribe".to_string(), JsonValue::Bool(false)),
                ]),
            ),
            (
                "prompts".to_string(),
                JsonValue::object(vec![
                    ("list".to_string(), JsonValue::Bool(true)),
                    ("get".to_string(), JsonValue::Bool(true)),
                ]),
            ),
        ]);

        let result = JsonValue::object(vec![
            (
                "protocolVersion".to_string(),
                JsonValue::String("2024-11-05".to_string()),
            ),
            (
                "serverInfo".to_string(),
                JsonValue::object(vec![
                    (
                        "name".to_string(),
                        JsonValue::String("redblue-mcp".to_string()),
                    ),
                    (
                        "version".to_string(),
                        JsonValue::String(env!("CARGO_PKG_VERSION").to_string()),
                    ),
                ]),
            ),
            ("capabilities".to_string(), capabilities),
        ]);

        self.initialized = true;

        Ok(result)
    }

    fn handle_list_tools(&mut self, _params: JsonValue) -> Result<JsonValue, String> {
        if !self.initialized {
            return Err("call initialize before listing tools".to_string());
        }

        let mut tools_json = Vec::new();
        for tool in &self.tools {
            // Filter by enabled categories (config tools are always available)
            if tool.name.starts_with("rb.config.") || self.categories.is_tool_enabled(tool.name) {
                let entry = vec![
                    ("name".to_string(), JsonValue::String(tool.name.to_string())),
                    (
                        "description".to_string(),
                        JsonValue::String(tool.description.to_string()),
                    ),
                    ("inputSchema".to_string(), build_input_schema(tool.fields)),
                ];
                tools_json.push(JsonValue::Object(entry));
            }
        }

        let result = JsonValue::object(vec![
            ("tools".to_string(), JsonValue::array(tools_json)),
            ("nextCursor".to_string(), JsonValue::Null),
        ]);

        Ok(result)
    }

    fn handle_tool_call(&mut self, params: JsonValue) -> Result<JsonValue, String> {
        if !self.initialized {
            return Err("call initialize before invoking tools".to_string());
        }

        let name = params
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "tool invocation missing name".to_string())?;

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(JsonValue::Object(vec![]));

        for tool in &self.tools {
            if tool.name == name {
                // Check if tool is enabled by category (config tools always allowed)
                if !tool.name.starts_with("rb.config.") && !self.categories.is_tool_enabled(name) {
                    let category = ToolCategory::from_tool_name(name);
                    return Err(format!(
                        "tool '{}' is disabled (category '{}' not enabled)",
                        name,
                        category.as_str()
                    ));
                }

                let output = (tool.handler)(self, &arguments)?;
                let content = JsonValue::array(vec![JsonValue::object(vec![
                    ("type".to_string(), JsonValue::String("text".to_string())),
                    ("text".to_string(), JsonValue::String(output.text)),
                ])]);
                let result = JsonValue::object(vec![
                    ("content".to_string(), content),
                    ("data".to_string(), output.data),
                ]);
                return Ok(result);
            }
        }

        Err(format!("unknown tool '{}'", name))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MCP RESOURCES HANDLERS
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_list_resources(&self, _params: JsonValue) -> Result<JsonValue, String> {
        let mut resources_json = Vec::new();

        // Add static resources
        for resource in self.resources.list_resources() {
            resources_json.push(JsonValue::object(vec![
                ("uri".to_string(), JsonValue::String(resource.uri.clone())),
                ("name".to_string(), JsonValue::String(resource.name.clone())),
                (
                    "description".to_string(),
                    JsonValue::String(resource.description.clone()),
                ),
                (
                    "mimeType".to_string(),
                    JsonValue::String(resource.mime_type.clone()),
                ),
            ]));
        }

        // Add resource templates
        let mut templates_json = Vec::new();
        for template in self.resources.list_templates() {
            templates_json.push(JsonValue::object(vec![
                (
                    "uriTemplate".to_string(),
                    JsonValue::String(template.uri_template.clone()),
                ),
                ("name".to_string(), JsonValue::String(template.name.clone())),
                (
                    "description".to_string(),
                    JsonValue::String(template.description.clone()),
                ),
                (
                    "mimeType".to_string(),
                    JsonValue::String(template.mime_type.clone()),
                ),
            ]));
        }

        Ok(JsonValue::object(vec![
            ("resources".to_string(), JsonValue::array(resources_json)),
            (
                "resourceTemplates".to_string(),
                JsonValue::array(templates_json),
            ),
        ]))
    }

    fn handle_read_resource(&self, params: JsonValue) -> Result<JsonValue, String> {
        let uri = params
            .get("uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'uri' parameter".to_string())?;

        let content = self.resources.read_resource(uri)?;

        let mut content_obj = vec![
            ("uri".to_string(), JsonValue::String(content.uri)),
            ("mimeType".to_string(), JsonValue::String(content.mime_type)),
        ];

        if let Some(text) = content.text {
            content_obj.push(("text".to_string(), JsonValue::String(text)));
        }
        if let Some(blob) = content.blob {
            content_obj.push(("blob".to_string(), JsonValue::String(blob)));
        }

        Ok(JsonValue::object(vec![(
            "contents".to_string(),
            JsonValue::array(vec![JsonValue::object(content_obj)]),
        )]))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MCP PROMPTS HANDLERS
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_list_prompts(&self, _params: JsonValue) -> Result<JsonValue, String> {
        let mut prompts_json = Vec::new();

        for prompt in self.prompts.list_prompts() {
            let mut args_json = Vec::new();
            for arg in &prompt.arguments {
                args_json.push(JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(arg.name.clone())),
                    (
                        "description".to_string(),
                        JsonValue::String(arg.description.clone()),
                    ),
                    ("required".to_string(), JsonValue::Bool(arg.required)),
                ]));
            }

            prompts_json.push(JsonValue::object(vec![
                ("name".to_string(), JsonValue::String(prompt.name.clone())),
                (
                    "description".to_string(),
                    JsonValue::String(prompt.description.clone()),
                ),
                ("arguments".to_string(), JsonValue::array(args_json)),
            ]));
        }

        Ok(JsonValue::object(vec![(
            "prompts".to_string(),
            JsonValue::array(prompts_json),
        )]))
    }

    fn handle_get_prompt(&self, params: JsonValue) -> Result<JsonValue, String> {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'name' parameter".to_string())?;

        // Extract arguments from params
        let mut args = std::collections::HashMap::new();
        if let Some(arguments) = params.get("arguments") {
            if let JsonValue::Object(entries) = arguments {
                for (key, value) in entries {
                    if let JsonValue::String(s) = value {
                        args.insert(key.clone(), s.clone());
                    }
                }
            }
        }

        let result = self.prompts.get_prompt(name, &args)?;

        let mut messages_json = Vec::new();
        for msg in result.messages {
            messages_json.push(JsonValue::object(vec![
                ("role".to_string(), JsonValue::String(msg.role)),
                (
                    "content".to_string(),
                    JsonValue::object(vec![
                        ("type".to_string(), JsonValue::String("text".to_string())),
                        ("text".to_string(), JsonValue::String(msg.content)),
                    ]),
                ),
            ]));
        }

        Ok(JsonValue::object(vec![
            (
                "description".to_string(),
                JsonValue::String(result.description),
            ),
            ("messages".to_string(), JsonValue::array(messages_json)),
        ]))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TOOL IMPLEMENTATIONS
    // ═══════════════════════════════════════════════════════════════════════

    fn tool_search_docs(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let query = args
            .get("query")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'query' is required".to_string())?;

        if query.trim().is_empty() {
            return Err("query must not be empty".to_string());
        }

        // Try hybrid search with embeddings first
        self.ensure_embeddings_loaded();

        if let Some(ref embeddings) = self.embeddings {
            // Use hybrid search
            let config = SearchConfig {
                max_results: 10,
                min_score: 0.1,
                fuzzy_weight: 0.4,
                semantic_weight: 0.6,
                mode: SearchMode::Hybrid,
            };

            let results = hybrid_search(query, &embeddings.documents, &config);

            let json_hits: Vec<JsonValue> = results
                .iter()
                .map(|result| {
                    JsonValue::object(vec![
                        (
                            "path".to_string(),
                            JsonValue::String(result.document.path.clone()),
                        ),
                        (
                            "title".to_string(),
                            JsonValue::String(result.document.title.clone()),
                        ),
                        (
                            "section".to_string(),
                            result
                                .document
                                .section
                                .as_ref()
                                .map(|s| JsonValue::String(s.clone()))
                                .unwrap_or(JsonValue::Null),
                        ),
                        ("score".to_string(), JsonValue::Number(result.score as f64)),
                        (
                            "match_type".to_string(),
                            JsonValue::String(format!("{:?}", result.match_type)),
                        ),
                        (
                            "highlights".to_string(),
                            JsonValue::array(
                                result
                                    .highlights
                                    .iter()
                                    .map(|h| JsonValue::String(h.clone()))
                                    .collect(),
                            ),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::String(result.document.category.clone()),
                        ),
                    ])
                })
                .collect();

            let mut lines = vec![format!(
                "Hybrid search results for '{}' ({} docs indexed):",
                query,
                embeddings.documents.len()
            )];
            if json_hits.is_empty() {
                lines.push("  - No matches found.".to_string());
            } else {
                for result in &results {
                    let section_str = result
                        .document
                        .section
                        .as_ref()
                        .map(|s| format!(" > {}", s))
                        .unwrap_or_default();
                    lines.push(format!(
                        "  - [{}] {} ({}{}) - score: {:.2}",
                        result.document.category,
                        result.document.title,
                        result.document.path,
                        section_str,
                        result.score
                    ));
                    for highlight in result.highlights.iter().take(2) {
                        lines.push(format!("      {}", highlight));
                    }
                }
            }

            return Ok(ToolResult {
                text: lines.join("\n"),
                data: JsonValue::object(vec![
                    ("query".to_string(), JsonValue::String(query.to_string())),
                    ("mode".to_string(), JsonValue::String("hybrid".to_string())),
                    (
                        "indexed_docs".to_string(),
                        JsonValue::Number(embeddings.documents.len() as f64),
                    ),
                    ("hits".to_string(), JsonValue::array(json_hits)),
                ]),
            });
        }

        // Fallback to basic text search
        let hits = search_documentation(query, 10);
        let json_hits = hits
            .into_iter()
            .map(|hit| {
                JsonValue::object(vec![
                    ("path".to_string(), JsonValue::String(hit.path)),
                    ("line".to_string(), JsonValue::Number(hit.line as f64)),
                    ("snippet".to_string(), JsonValue::String(hit.snippet)),
                ])
            })
            .collect::<Vec<JsonValue>>();

        let mut lines = vec![format!("Search results for '{}' (basic mode):", query)];
        if json_hits.is_empty() {
            lines.push("  - No matches found.".to_string());
        } else {
            for hit in &json_hits {
                let path = hit.get("path").and_then(|v| v.as_str()).unwrap_or_default();
                let line = hit
                    .get("line")
                    .and_then(|v| v.as_f64())
                    .map(|n| n as usize)
                    .unwrap_or(0);
                let snippet = hit
                    .get("snippet")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                lines.push(format!("  - {}:{} -> {}", path, line, snippet));
            }
        }

        Ok(ToolResult {
            text: lines.join("\n"),
            data: JsonValue::object(vec![
                ("query".to_string(), JsonValue::String(query.to_string())),
                ("mode".to_string(), JsonValue::String("basic".to_string())),
                ("hits".to_string(), JsonValue::array(json_hits)),
            ]),
        })
    }

    fn tool_docs_index(&mut self, _args: &JsonValue) -> Result<ToolResult, String> {
        let index = build_document_index(8);
        let mut preview = Vec::new();
        for entry in index.iter().take(3) {
            if let Some(path) = entry.get("path").and_then(|v| v.as_str()) {
                let title = entry
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Untitled");
                preview.push(format!("  - {} ({})", title, path));
            }
        }
        let mut lines = vec![format!("Indexed {} documentation files.", index.len())];
        if preview.is_empty() {
            lines.push("No documents located.".to_string());
        } else {
            lines.push("Sample:".to_string());
            lines.extend(preview);
        }

        Ok(ToolResult {
            text: lines.join("\n"),
            data: JsonValue::object(vec![("documents".to_string(), JsonValue::array(index))]),
        })
    }

    fn tool_docs_get(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let path = args
            .get("path")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'path' is required".to_string())?;
        let section = args.get("section").and_then(|v| v.as_str());

        let doc_path = resolve_doc_path(path)
            .ok_or_else(|| format!("documentation path '{}' is not recognized", path))?;

        let content = fs::read_to_string(&doc_path)
            .map_err(|e| format!("failed to read '{}': {}", doc_path.display(), e))?;

        let output = if let Some(section_name) = section {
            extract_markdown_section(&content, section_name)
                .ok_or_else(|| format!("section '{}' not found in {}", section_name, path))?
        } else {
            content
        };

        let text = if let Some(section_name) = section {
            format!(
                "Returned section '{}' from {} ({} bytes).",
                section_name,
                path,
                output.len()
            )
        } else {
            format!(
                "Returned entire document {} ({} bytes).",
                path,
                output.len()
            )
        };

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("path".to_string(), JsonValue::String(path.to_string())),
                (
                    "section".to_string(),
                    section
                        .map(|s| JsonValue::String(s.to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                ("content".to_string(), JsonValue::String(output)),
            ]),
        })
    }

    fn tool_targets_list(&mut self, _args: &JsonValue) -> Result<ToolResult, String> {
        let db = TargetDatabase::load(default_target_db_path());
        let entries = db
            .targets
            .iter()
            .map(|entry| entry.to_json())
            .collect::<Vec<JsonValue>>();

        let mut lines = vec![format!("Tracked targets: {}", entries.len())];
        for entry in db.targets.iter().take(5) {
            lines.push(format!("  - {} -> {}", entry.name, entry.target));
        }
        if db.targets.len() > 5 {
            lines.push(format!("  ... and {} more.", db.targets.len() - 5));
        }

        Ok(ToolResult {
            text: lines.join("\n"),
            data: JsonValue::object(vec![("targets".to_string(), JsonValue::array(entries))]),
        })
    }

    fn tool_targets_save(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let name = args
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'name' is required".to_string())?;
        let target = args
            .get("target")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'target' is required".to_string())?;
        let notes = args.get("notes").and_then(|value| value.as_str());

        let path = default_target_db_path();
        let mut db = TargetDatabase::load(path.clone());
        let (created, entry) = db.upsert(name, target, notes);
        db.persist()?;

        let action = if created { "Created" } else { "Updated" };
        let text = format!("{} target '{}' -> {}.", action, entry.name, entry.target);

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("created".to_string(), JsonValue::Bool(created)),
                ("target".to_string(), entry.to_json()),
            ]),
        })
    }

    fn tool_targets_remove(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let name = args
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'name' is required".to_string())?;

        let path = default_target_db_path();
        let mut db = TargetDatabase::load(path.clone());
        let removed = db.remove(name);
        if removed.is_none() {
            return Err(format!("target '{}' not found", name));
        }
        db.persist()?;

        let entry = removed.unwrap();
        Ok(ToolResult {
            text: format!("Removed target '{}' -> {}.", entry.name, entry.target),
            data: JsonValue::object(vec![
                ("removed".to_string(), JsonValue::Bool(true)),
                ("target".to_string(), entry.to_json()),
            ]),
        })
    }

    // ========== Web Scraping Tool Handlers ==========

    fn tool_html_select(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let html = args
            .get("html")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'html' is required".to_string())?;

        let selector = args
            .get("selector")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'selector' is required".to_string())?;

        let attr = args.get("attr").and_then(|v| v.as_str());

        // Parse HTML
        let doc = Document::parse(html);

        // Select elements
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

    fn tool_har_record(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'url' is required".to_string())?;

        let max_depth = args
            .get("max_depth")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize)
            .unwrap_or(2);

        let max_pages = args
            .get("max_pages")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize)
            .unwrap_or(20);

        let mut crawler = WebCrawler::new()
            .with_max_depth(max_depth)
            .with_max_pages(max_pages)
            .with_same_origin(true)
            .with_har_recording(true);

        let result = crawler
            .crawl(url)
            .map_err(|e| format!("crawl failed: {}", e))?;

        // Get HAR data
        let har_json = if let Some(recorder) = crawler.har_recorder() {
            let guard = recorder.lock().unwrap();
            let har = &guard.har;

            let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
            let total_response_size: i64 =
                har.log.entries.iter().map(|e| e.response.body_size).sum();

            JsonValue::object(vec![
                (
                    "version".to_string(),
                    JsonValue::String(har.log.version.clone()),
                ),
                (
                    "entries_count".to_string(),
                    JsonValue::Number(har.log.entries.len() as f64),
                ),
                ("total_time_ms".to_string(), JsonValue::Number(total_time)),
                (
                    "total_response_bytes".to_string(),
                    JsonValue::Number(total_response_size.max(0) as f64),
                ),
                ("har_content".to_string(), JsonValue::String(har.to_json())),
            ])
        } else {
            JsonValue::Null
        };

        let text = format!(
            "Recorded HTTP traffic for {} pages from '{}' (HAR entries: {})",
            result.total_urls,
            url,
            if let Some(entries) = har_json.get("entries_count").and_then(|v| v.as_f64()) {
                entries as usize
            } else {
                0
            }
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(url.to_string())),
                (
                    "pages_crawled".to_string(),
                    JsonValue::Number(result.total_urls as f64),
                ),
                ("har".to_string(), har_json),
            ]),
        })
    }

    fn tool_har_analyze(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'content' is required".to_string())?;

        let har = Har::from_json(content).map_err(|e| format!("failed to parse HAR: {}", e))?;

        let total_entries = har.log.entries.len();
        let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
        let total_request_size: i64 = har.log.entries.iter().map(|e| e.request.body_size).sum();
        let total_response_size: i64 = har.log.entries.iter().map(|e| e.response.body_size).sum();

        // Count status codes
        let mut status_counts: Vec<(u16, usize)> = Vec::new();
        for entry in &har.log.entries {
            let status = entry.response.status;
            if let Some(pos) = status_counts.iter().position(|(s, _)| *s == status) {
                status_counts[pos].1 += 1;
            } else {
                status_counts.push((status, 1));
            }
        }

        let status_json: Vec<JsonValue> = status_counts
            .iter()
            .map(|(status, count)| {
                JsonValue::object(vec![
                    ("status".to_string(), JsonValue::Number(*status as f64)),
                    ("count".to_string(), JsonValue::Number(*count as f64)),
                ])
            })
            .collect();

        // Get slowest requests
        let mut sorted_entries: Vec<_> = har.log.entries.iter().collect();
        sorted_entries.sort_by(|a, b| {
            b.time
                .partial_cmp(&a.time)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let slowest_json: Vec<JsonValue> = sorted_entries
            .iter()
            .take(5)
            .map(|entry| {
                JsonValue::object(vec![
                    (
                        "url".to_string(),
                        JsonValue::String(entry.request.url.clone()),
                    ),
                    ("time_ms".to_string(), JsonValue::Number(entry.time)),
                    (
                        "status".to_string(),
                        JsonValue::Number(entry.response.status as f64),
                    ),
                ])
            })
            .collect();

        let text = format!(
            "HAR Analysis: {} entries, {:.2}ms total time, {} bytes transferred",
            total_entries,
            total_time,
            total_response_size.max(0)
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "version".to_string(),
                    JsonValue::String(har.log.version.clone()),
                ),
                (
                    "creator".to_string(),
                    JsonValue::String(format!(
                        "{} {}",
                        har.log.creator.name, har.log.creator.version
                    )),
                ),
                (
                    "total_entries".to_string(),
                    JsonValue::Number(total_entries as f64),
                ),
                ("total_time_ms".to_string(), JsonValue::Number(total_time)),
                (
                    "total_request_bytes".to_string(),
                    JsonValue::Number(total_request_size.max(0) as f64),
                ),
                (
                    "total_response_bytes".to_string(),
                    JsonValue::Number(total_response_size.max(0) as f64),
                ),
                ("status_codes".to_string(), JsonValue::array(status_json)),
                (
                    "slowest_requests".to_string(),
                    JsonValue::array(slowest_json),
                ),
            ]),
        })
    }

    // ==================== Vulnerability Intelligence Handlers ====================

    fn tool_vuln_fingerprint(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'url' is required".to_string())?;

        let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("nvd");

        // Fingerprint the URL
        let fingerprinter = WebFingerprinter::new();
        let result = fingerprinter.fingerprint(url)?;
        let techs = &result.technologies;

        if techs.is_empty() {
            return Ok(ToolResult {
                text: format!("No technologies detected for '{}'", url),
                data: JsonValue::object(vec![
                    ("url".to_string(), JsonValue::String(url.to_string())),
                    ("technologies".to_string(), JsonValue::array(vec![])),
                    ("vulnerabilities".to_string(), JsonValue::array(vec![])),
                ]),
            });
        }

        let mut collection = VulnCollection::new();
        let mut kev_client = KevClient::new();

        // For each detected technology, search for vulnerabilities
        for tech in techs {
            let cpe = generate_cpe(&tech.name, tech.version.as_deref());

            // Query NVD
            if source == "nvd" || source == "all" {
                if let Some(ref cpe_str) = cpe {
                    let mut nvd_client = NvdClient::new();
                    if let Ok(vulns) = nvd_client.query_by_cpe(cpe_str) {
                        for vuln in vulns {
                            collection.add(vuln);
                        }
                    }
                }
            }

            // Query OSV for packages
            if source == "osv" || source == "all" {
                let osv_client = OsvClient::new();
                let ecosystem = map_tech_to_ecosystem(&tech.name);
                if let Ok(vulns) =
                    osv_client.query_package(&tech.name, tech.version.as_deref(), ecosystem)
                {
                    for vuln in vulns {
                        collection.add(vuln);
                    }
                }
            }
        }

        // Enrich with KEV and calculate risk scores
        for vuln in collection.iter_mut() {
            let _ = kev_client.enrich_vulnerability(vuln);
            vuln.risk_score = Some(calculate_risk_score(vuln));
        }

        let vulns: Vec<_> = collection.into_sorted().into_iter().take(20).collect();

        let techs_json: Vec<JsonValue> = techs
            .iter()
            .map(|t| {
                JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(t.name.clone())),
                    (
                        "version".to_string(),
                        t.version
                            .as_ref()
                            .map(|v| JsonValue::String(v.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "confidence".to_string(),
                        JsonValue::String(format!("{}", t.confidence)),
                    ),
                    (
                        "category".to_string(),
                        JsonValue::String(format!("{:?}", t.category)),
                    ),
                ])
            })
            .collect();

        let vulns_json: Vec<JsonValue> = vulns.iter().map(vuln_to_json).collect();

        let text = format!(
            "Fingerprint of '{}': {} technologies detected, {} vulnerabilities found",
            url,
            techs.len(),
            vulns.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(url.to_string())),
                ("technologies".to_string(), JsonValue::array(techs_json)),
                (
                    "vulnerability_count".to_string(),
                    JsonValue::Number(vulns.len() as f64),
                ),
                ("vulnerabilities".to_string(), JsonValue::array(vulns_json)),
            ]),
        })
    }

    // ========================================================================
    // FINGERPRINT TOOL HANDLERS
    // ========================================================================

    fn tool_fingerprint_service(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: target")?;

        let port = args
            .get("port")
            .and_then(|v| v.as_f64())
            .map(|p| p as u16)
            .ok_or("Missing required field: port")?;

        // Try to grab banner
        let timeout = Duration::from_secs(5);
        let addr = format!("{}:{}", target, port);

        let banner = if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
            if let Ok(mut stream) = std::net::TcpStream::connect_timeout(&socket_addr, timeout) {
                stream.set_read_timeout(Some(timeout)).ok();
                let mut buf = [0u8; 1024];
                // Send a simple probe for HTTP
                if port == 80 || port == 8080 || port == 443 || port == 8443 {
                    use std::io::Write;
                    let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n");
                }
                use std::io::Read;
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        // Guess service from port number (inline simple version)
        let service_guess: Option<String> = match port {
            21 => Some("FTP".to_string()),
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            25 | 587 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            80 | 8080 | 8000 => Some("HTTP".to_string()),
            110 => Some("POP3".to_string()),
            143 => Some("IMAP".to_string()),
            443 | 8443 => Some("HTTPS".to_string()),
            3306 => Some("MySQL".to_string()),
            5432 => Some("PostgreSQL".to_string()),
            6379 => Some("Redis".to_string()),
            27017 => Some("MongoDB".to_string()),
            _ => None,
        };

        // Try to detect service from banner
        let detected_service = banner.as_ref().and_then(|b| {
            let b_lower = b.to_lowercase();
            if b_lower.contains("ssh") {
                Some("SSH")
            } else if b_lower.contains("http") {
                Some("HTTP")
            } else if b_lower.contains("ftp") {
                Some("FTP")
            } else if b_lower.contains("smtp") || b_lower.contains("mail") {
                Some("SMTP")
            } else if b_lower.contains("mysql") {
                Some("MySQL")
            } else if b_lower.contains("postgresql") || b_lower.contains("postgres") {
                Some("PostgreSQL")
            } else if b_lower.contains("redis") {
                Some("Redis")
            } else {
                None
            }
        });

        let text = format!(
            "Service fingerprint for {}:{}: {}",
            target,
            port,
            detected_service
                .or(service_guess.as_deref())
                .unwrap_or("Unknown")
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("target".to_string(), JsonValue::String(target.to_string())),
                ("port".to_string(), JsonValue::Number(port as f64)),
                (
                    "service".to_string(),
                    detected_service
                        .or(service_guess.as_deref())
                        .map(|s| JsonValue::String(s.to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "banner".to_string(),
                    banner
                        .map(|b| JsonValue::String(b.chars().take(200).collect()))
                        .unwrap_or(JsonValue::Null),
                ),
            ]),
        })
    }

    // ========================================================================
    // CATEGORY CONFIGURATION HANDLERS
    // ========================================================================

    fn tool_config_categories(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("list");

        let category_name = args.get("category").and_then(|v| v.as_str());

        match action {
            "list" => {
                // List all categories and their status
                let status = self.categories.status_summary();
                let mut lines = Vec::new();
                lines.push(format!(
                    "Current preset: {}",
                    self.categories.current_preset().as_str()
                ));
                lines.push(format!(
                    "Enabled tools: {}/44",
                    self.categories.enabled_tool_count()
                ));
                lines.push(String::new());
                lines.push("Category Status:".to_string());

                for (cat, enabled, count) in &status {
                    let marker = if *enabled { "[x]" } else { "[ ]" };
                    lines.push(format!(
                        "  {} {:15} ({:2} tools) - {}",
                        marker,
                        cat.as_str(),
                        count,
                        cat.description()
                    ));
                }

                let categories_json: Vec<JsonValue> = status
                    .iter()
                    .map(|(cat, enabled, count)| {
                        JsonValue::object(vec![
                            (
                                "name".to_string(),
                                JsonValue::String(cat.as_str().to_string()),
                            ),
                            ("enabled".to_string(), JsonValue::Bool(*enabled)),
                            ("tool_count".to_string(), JsonValue::Number(*count as f64)),
                            (
                                "description".to_string(),
                                JsonValue::String(cat.description().to_string()),
                            ),
                        ])
                    })
                    .collect();

                Ok(ToolResult {
                    text: lines.join("\n"),
                    data: JsonValue::object(vec![
                        (
                            "preset".to_string(),
                            JsonValue::String(
                                self.categories.current_preset().as_str().to_string(),
                            ),
                        ),
                        (
                            "enabled_count".to_string(),
                            JsonValue::Number(self.categories.enabled_tool_count() as f64),
                        ),
                        ("categories".to_string(), JsonValue::Array(categories_json)),
                    ]),
                })
            }
            "enable" => {
                let cat_str = category_name.ok_or("Missing category name for enable action")?;
                let category = ToolCategory::from_str(cat_str)
                    .ok_or_else(|| format!("Unknown category: {}", cat_str))?;

                self.categories.enable(category);
                let text = format!(
                    "Enabled category '{}'. Now exposing {} tools.",
                    cat_str,
                    self.categories.enabled_tool_count()
                );

                Ok(ToolResult {
                    text,
                    data: JsonValue::object(vec![
                        (
                            "action".to_string(),
                            JsonValue::String("enabled".to_string()),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::String(cat_str.to_string()),
                        ),
                        (
                            "enabled_count".to_string(),
                            JsonValue::Number(self.categories.enabled_tool_count() as f64),
                        ),
                    ]),
                })
            }
            "disable" => {
                let cat_str = category_name.ok_or("Missing category name for disable action")?;
                let category = ToolCategory::from_str(cat_str)
                    .ok_or_else(|| format!("Unknown category: {}", cat_str))?;

                self.categories.disable(category);
                let text = format!(
                    "Disabled category '{}'. Now exposing {} tools.",
                    cat_str,
                    self.categories.enabled_tool_count()
                );

                Ok(ToolResult {
                    text,
                    data: JsonValue::object(vec![
                        (
                            "action".to_string(),
                            JsonValue::String("disabled".to_string()),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::String(cat_str.to_string()),
                        ),
                        (
                            "enabled_count".to_string(),
                            JsonValue::Number(self.categories.enabled_tool_count() as f64),
                        ),
                    ]),
                })
            }
            "toggle" => {
                let cat_str = category_name.ok_or("Missing category name for toggle action")?;
                let category = ToolCategory::from_str(cat_str)
                    .ok_or_else(|| format!("Unknown category: {}", cat_str))?;

                let now_enabled = self.categories.toggle(category);
                let action_str = if now_enabled { "enabled" } else { "disabled" };
                let text = format!(
                    "Toggled category '{}' -> {}. Now exposing {} tools.",
                    cat_str,
                    action_str,
                    self.categories.enabled_tool_count()
                );

                Ok(ToolResult {
                    text,
                    data: JsonValue::object(vec![
                        (
                            "action".to_string(),
                            JsonValue::String(action_str.to_string()),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::String(cat_str.to_string()),
                        ),
                        ("enabled".to_string(), JsonValue::Bool(now_enabled)),
                        (
                            "enabled_count".to_string(),
                            JsonValue::Number(self.categories.enabled_tool_count() as f64),
                        ),
                    ]),
                })
            }
            _ => Err(format!(
                "Unknown action: {}. Use list, enable, disable, or toggle.",
                action
            )),
        }
    }

    fn tool_config_preset(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let preset_name = args.get("preset").and_then(|v| v.as_str());

        if let Some(name) = preset_name {
            let preset = CategoryPreset::from_str(name).ok_or_else(|| {
                format!(
                    "Unknown preset: {}. Available: all, core, blue-team, red-team, web-security, minimal",
                    name
                )
            })?;

            self.categories.apply_preset(preset);

            let text = format!(
                "Applied preset '{}': {}. Now exposing {} tools.",
                name,
                preset.description(),
                self.categories.enabled_tool_count()
            );

            Ok(ToolResult {
                text,
                data: JsonValue::object(vec![
                    ("preset".to_string(), JsonValue::String(name.to_string())),
                    (
                        "description".to_string(),
                        JsonValue::String(preset.description().to_string()),
                    ),
                    (
                        "enabled_count".to_string(),
                        JsonValue::Number(self.categories.enabled_tool_count() as f64),
                    ),
                ]),
            })
        } else {
            // List available presets
            let mut lines = Vec::new();
            lines.push(format!(
                "Current preset: {}",
                self.categories.current_preset().as_str()
            ));
            lines.push(String::new());
            lines.push("Available presets:".to_string());

            for preset in CategoryPreset::all_presets() {
                let marker = if preset == self.categories.current_preset() {
                    ">"
                } else {
                    " "
                };
                lines.push(format!(
                    "{} {:15} - {}",
                    marker,
                    preset.as_str(),
                    preset.description()
                ));
            }

            let presets_json: Vec<JsonValue> = CategoryPreset::all_presets()
                .iter()
                .map(|p| {
                    JsonValue::object(vec![
                        (
                            "name".to_string(),
                            JsonValue::String(p.as_str().to_string()),
                        ),
                        (
                            "description".to_string(),
                            JsonValue::String(p.description().to_string()),
                        ),
                        (
                            "active".to_string(),
                            JsonValue::Bool(*p == self.categories.current_preset()),
                        ),
                    ])
                })
                .collect();

            Ok(ToolResult {
                text: lines.join("\n"),
                data: JsonValue::object(vec![
                    (
                        "current".to_string(),
                        JsonValue::String(self.categories.current_preset().as_str().to_string()),
                    ),
                    ("presets".to_string(), JsonValue::Array(presets_json)),
                ]),
            })
        }
    }

    // ========================================================================
    // AUTONOMOUS OPERATION HANDLERS
    // ========================================================================

    fn tool_auto_guide(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let op_id = args
            .get("operation_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: operation_id")?;

        let response_str = args
            .get("response")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: response")?;

        // Create sampling response from the string
        let response = crate::mcp::sampling::SamplingResponse {
            content: response_str.to_string(),
            model: "user-provided".to_string(),
            stop_reason: crate::mcp::sampling::StopReason::EndTurn,
        };

        self.orchestrator.provide_guidance(op_id, response)?;

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
}
