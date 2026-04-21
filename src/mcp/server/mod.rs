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
mod toolset;

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

use crate::mcp::categories::{CategoryConfig, ToolCategory};
use crate::mcp::embeddings::{load_embeddings, EmbeddingsData, EmbeddingsLoaderConfig};
use crate::mcp::orchestrator::Orchestrator;
use crate::mcp::prompts::PromptRegistry;
use crate::mcp::resources::ResourceRegistry;
use crate::mcp::types::ToolDefinition;
use crate::utils::json::{parse_json, JsonValue};
use std::collections::HashMap;
use std::io::{self};
use std::sync::{Arc, Mutex};

// Import tool registration functions
use crate::mcp::tools::{
  register_agent_tools, register_auth_tools, register_auto_tools, register_binary_tools,
  register_code_tools, register_core_tools, register_crypto_tools, register_database_tools,
  register_dns_tools, register_evasion_tools, register_exploit_tools, register_file_tools,
  register_fuzz_tools, register_intel_tools, register_loot_tools, register_memory_tools,
  register_network_tools, register_password_tools, register_playbook_tools, register_proxy_tools,
  register_recon_tools, register_report_tools, register_service_tools, register_tls_tools,
  register_vector_tools, register_vuln_tools, register_web_tools, register_wordlist_tools,
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

    // Playbook tools (list, show, execute)
    tools.extend(register_playbook_tools());

    // Loot tools (findings, credentials, artifacts)
    tools.extend(register_loot_tools());

    // Report tools (generation, templates, summary)
    tools.extend(register_report_tools());

    // Exploit tools (privesc, lateral movement, payloads, CVE search, suggestions)
    tools.extend(register_exploit_tools());

    // Auth tools (credential testing, password spray, brute force)
    tools.extend(register_auth_tools());

    // Fuzz tools (directory, vhost, parameter fuzzing)
    tools.extend(register_fuzz_tools());

    // Service tools (list, install, status of persistence mechanisms)
    tools.extend(register_service_tools());

    // Agent/C2 tools (info, transports, generate)
    tools.extend(register_agent_tools());

    // Database/RedDB tools (open, query, node, stats)
    tools.extend(register_database_tools());

    // Memory tools (scan, regions, read, pattern)
    tools.extend(register_memory_tools());

    // Proxy tools (start, intercept, rules)
    tools.extend(register_proxy_tools());

    // Inline tools (not yet extracted to modules)
    tools.extend(toolset::register_inline_tools());

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
  /// This eagerly loads the docs index for keyword search
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
          "[MCP] Loaded docs index: {} documents (keyword-based ranking)",
          data.documents.len()
        );
        self.embeddings = Some(data);
      }
      Err(e) => {
        eprintln!("[MCP] Warning: Could not load docs index: {}", e);
        eprintln!("[MCP] Falling back to basic text search");
      }
    }
  }

  pub fn run_stdio(core: Arc<Mutex<McpServer>>) -> Result<(), String> {
    // Eagerly initialize the docs index for keyword search
    {
      let mut guard = core
        .lock()
        .map_err(|_| "MCP server state poisoned".to_string())?;
      guard.init();
    }

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
      let payload = match protocol::read_payload(&mut reader)? {
        Some(p) => p,
        None => break,
      };
      let message = match parse_json(&payload) {
        Ok(value) => value,
        Err(err) => {
          let response =
            protocol::build_error_message(None, -32700, &format!("invalid JSON: {}", err));
          protocol::write_message(response)?;
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
        protocol::write_message(response)?;
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
        return Some(protocol::build_error_message(
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
      None => {
        return Some(protocol::build_error_message(
          id,
          -32600,
          "missing method field",
        ))
      }
    };

    let response = match method_name.as_str() {
      "initialize" => match self.handle_initialize(params) {
        Ok(result) => Some(protocol::build_result_message(id, result)),
        Err(err) => Some(protocol::build_error_message(
          id,
          -32001,
          &format!("initialize failed: {}", err),
        )),
      },
      "tools/list" => match self.handle_list_tools(params) {
        Ok(result) => Some(protocol::build_result_message(id, result)),
        Err(err) => Some(protocol::build_error_message(
          id,
          -32001,
          &format!("list failed: {}", err),
        )),
      },
      "tools/call" => match self.handle_tool_call(params) {
        Ok(result) => Some(protocol::build_result_message(id, result)),
        Err(err) => Some(protocol::build_error_message(
          id,
          -32001,
          &format!("tool call failed: {}", err),
        )),
      },
      "resources/list" => match self.handle_list_resources(params) {
        Ok(result) => Some(protocol::build_result_message(id, result)),
        Err(err) => Some(protocol::build_error_message(
          id,
          -32001,
          &format!("resources list failed: {}", err),
        )),
      },
      "resources/read" => match self.handle_read_resource(params) {
        Ok(result) => Some(protocol::build_result_message(id, result)),
        Err(err) => Some(protocol::build_error_message(
          id,
          -32001,
          &format!("resource read failed: {}", err),
        )),
      },
      "prompts/list" => match self.handle_list_prompts(params) {
        Ok(result) => Some(protocol::build_result_message(id, result)),
        Err(err) => Some(protocol::build_error_message(
          id,
          -32001,
          &format!("prompts list failed: {}", err),
        )),
      },
      "prompts/get" => match self.handle_get_prompt(params) {
        Ok(result) => Some(protocol::build_result_message(id, result)),
        Err(err) => Some(protocol::build_error_message(
          id,
          -32001,
          &format!("prompt get failed: {}", err),
        )),
      },
      "notifications/initialized" => None,
      other => Some(protocol::build_error_message(
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
            JsonValue::String(crate::version::current_version().to_string()),
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
          (
            "inputSchema".to_string(),
            protocol::build_input_schema(tool.fields),
          ),
        ];
        tools_json.push(JsonValue::Object(entry));
      }
    }

    let result = JsonValue::object(vec![
      ("tools".to_string(), JsonValue::Array(tools_json)),
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
      ("resources".to_string(), JsonValue::Array(resources_json)),
      (
        "resourceTemplates".to_string(),
        JsonValue::Array(templates_json),
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
      JsonValue::Array(vec![JsonValue::Object(content_obj)]),
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
        ("arguments".to_string(), JsonValue::Array(args_json)),
      ]));
    }

    Ok(JsonValue::object(vec![(
      "prompts".to_string(),
      JsonValue::Array(prompts_json),
    )]))
  }

  fn handle_get_prompt(&self, params: JsonValue) -> Result<JsonValue, String> {
    let name = params
      .get("name")
      .and_then(|v| v.as_str())
      .ok_or_else(|| "missing 'name' parameter".to_string())?;

    // Extract arguments from params
    let mut args = HashMap::new();
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
      ("messages".to_string(), JsonValue::Array(messages_json)),
    ]))
  }
}
