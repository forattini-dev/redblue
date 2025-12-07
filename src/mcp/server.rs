use crate::cli::commands;
use crate::mcp::embeddings::{load_embeddings, EmbeddingsData, EmbeddingsLoaderConfig};
use crate::mcp::search::{hybrid_search, SearchConfig, SearchMode};
use crate::utils::json::{parse_json, JsonValue};
use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

type ToolHandler = fn(&mut McpServer, &JsonValue) -> Result<ToolResult, String>;

struct ToolField {
    name: &'static str,
    field_type: &'static str,
    description: &'static str,
    required: bool,
}

struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    fields: &'static [ToolField],
    handler: ToolHandler,
}

struct DocHit {
    path: String,
    line: usize,
    snippet: String,
}

struct ToolResult {
    text: String,
    data: JsonValue,
}

pub struct McpServer {
    tools: Vec<ToolDefinition>,
    initialized: bool,
    embeddings: Option<EmbeddingsData>,
    embeddings_loaded: bool,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            tools: vec![
                ToolDefinition {
                    name: "rb.list-domains",
                    description: "List available RedBlue CLI domains.",
                    fields: &[],
                    handler: Self::tool_list_domains,
                },
                ToolDefinition {
                    name: "rb.list-resources",
                    description:
                        "List resources and verbs for a given RedBlue CLI domain (e.g. network).",
                    fields: &[ToolField {
                        name: "domain",
                        field_type: "string",
                        description: "Domain name to inspect (network, dns, web, ...).",
                        required: true,
                    }],
                    handler: Self::tool_list_resources,
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
                    handler: Self::tool_describe_command,
                },
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
                ToolDefinition {
                    name: "rb.command.run",
                    description: "Execute a RedBlue CLI command and capture the output.",
                    fields: &[
                        ToolField {
                            name: "argv",
                            field_type: "array",
                            description: "Explicit argument vector (domain resource verb ...).",
                            required: false,
                        },
                        ToolField {
                            name: "command",
                            field_type: "string",
                            description: "Command string to split into argv when 'argv' is omitted.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_command_run,
                },
            ],
            initialized: false,
            embeddings: None,
            embeddings_loaded: false,
        }
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
        let capabilities = JsonValue::object(vec![(
            "tools".to_string(),
            JsonValue::object(vec![
                ("list".to_string(), JsonValue::Bool(true)),
                ("call".to_string(), JsonValue::Bool(true)),
            ]),
        )]);

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
            let mut entry = Vec::new();
            entry.push(("name".to_string(), JsonValue::String(tool.name.to_string())));
            entry.push((
                "description".to_string(),
                JsonValue::String(tool.description.to_string()),
            ));
            entry.push(("inputSchema".to_string(), build_input_schema(tool.fields)));
            tools_json.push(JsonValue::Object(entry));
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

    fn tool_list_domains(&mut self, _args: &JsonValue) -> Result<ToolResult, String> {
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

    fn tool_list_resources(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
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

    fn tool_describe_command(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
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
                    ("long".to_string(), JsonValue::String(flag.long.to_string())),
                    (
                        "short".to_string(),
                        flag.short
                            .map(|c| JsonValue::String(c.to_string()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "description".to_string(),
                        JsonValue::String(flag.description.to_string()),
                    ),
                    (
                        "default".to_string(),
                        flag.default.map(JsonValue::from).unwrap_or(JsonValue::Null),
                    ),
                ])
            })
            .collect::<Vec<JsonValue>>();
        result.push(("flags".to_string(), JsonValue::array(flags)));

        let mut lines = vec![format!(
            "`rb {} {} <verb>` -- {}",
            domain,
            resource,
            command.description()
        )];
        if let Some(JsonValue::Array(verbs)) = result
            .iter()
            .find(|(key, _)| key == "verbs")
            .map(|(_, value)| value)
        {
            for verb in verbs {
                if let Some(verb_name) = verb.get("verb").and_then(|v| v.as_str()) {
                    let summary = verb.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                    lines.push(format!("  - {} -> {}", verb_name, summary));
                }
            }
        }
        if let Some(JsonValue::Array(flag_items)) = result
            .iter()
            .find(|(key, _)| key == "flags")
            .map(|(_, value)| value)
        {
            if !flag_items.is_empty() {
                lines.push("Supported flags:".to_string());
                for flag in flag_items {
                    if let Some(long) = flag.get("long").and_then(|v| v.as_str()) {
                        let desc = flag
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let short = flag
                            .get("short")
                            .and_then(|v| v.as_str())
                            .map(|s| format!("-{}, ", s))
                            .unwrap_or_default();
                        lines.push(format!("  - {}--{} {}", short, long, desc));
                    }
                }
            }
        }

        Ok(ToolResult {
            text: lines.join("\n"),
            data: JsonValue::Object(result),
        })
    }

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
                        ("path".to_string(), JsonValue::String(result.document.path.clone())),
                        ("title".to_string(), JsonValue::String(result.document.title.clone())),
                        ("section".to_string(), result.document.section.as_ref()
                            .map(|s| JsonValue::String(s.clone()))
                            .unwrap_or(JsonValue::Null)),
                        ("score".to_string(), JsonValue::Number(result.score as f64)),
                        ("match_type".to_string(), JsonValue::String(format!("{:?}", result.match_type))),
                        ("highlights".to_string(), JsonValue::array(
                            result.highlights.iter()
                                .map(|h| JsonValue::String(h.clone()))
                                .collect()
                        )),
                        ("category".to_string(), JsonValue::String(result.document.category.clone())),
                    ])
                })
                .collect();

            let mut lines = vec![format!("Hybrid search results for '{}' ({} docs indexed):", query, embeddings.documents.len())];
            if json_hits.is_empty() {
                lines.push("  - No matches found.".to_string());
            } else {
                for result in &results {
                    let section_str = result.document.section.as_ref()
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
                    ("indexed_docs".to_string(), JsonValue::Number(embeddings.documents.len() as f64)),
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

    fn tool_command_run(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let argv = parse_command_arguments(args)?;
        if argv.is_empty() {
            return Err("command requires at least one argument (domain)".to_string());
        }

        if argv.len() >= 2
            && argv[0].eq_ignore_ascii_case("mcp")
            && argv[1].eq_ignore_ascii_case("server")
        {
            return Err(
                "running 'rb mcp server ...' inside MCP is blocked to avoid recursion".to_string(),
            );
        }

        let exe = std::env::current_exe()
            .map_err(|e| format!("failed to resolve current executable: {}", e))?;

        let output = Command::new(exe)
            .args(&argv)
            .env("RB_MCP_BRIDGE", "1")
            .output()
            .map_err(|e| format!("failed to execute command: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let status = output.status.code().unwrap_or(-1);

        let preview = if stdout.trim().is_empty() {
            if stderr.trim().is_empty() {
                "(no output)".to_string()
            } else {
                format!("stderr: {}", truncate_preview(&stderr))
            }
        } else {
            truncate_preview(&stdout)
        };

        let text = format!(
            "Command exited with status {}. Preview: {}",
            status, preview
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "argv".to_string(),
                    JsonValue::array(
                        argv.iter()
                            .map(|arg| JsonValue::String(arg.clone()))
                            .collect(),
                    ),
                ),
                ("status".to_string(), JsonValue::Number(status as f64)),
                ("stdout".to_string(), JsonValue::String(stdout)),
                ("stderr".to_string(), JsonValue::String(stderr)),
            ]),
        })
    }
}

fn build_input_schema(fields: &[ToolField]) -> JsonValue {
    let mut properties = Vec::new();
    let mut required = Vec::new();

    for field in fields {
        let mut descriptor = Vec::new();
        descriptor.push((
            "type".to_string(),
            JsonValue::String(field.field_type.to_string()),
        ));
        if !field.description.is_empty() {
            descriptor.push((
                "description".to_string(),
                JsonValue::String(field.description.to_string()),
            ));
        }
        properties.push((field.name.to_string(), JsonValue::Object(descriptor)));
        if field.required {
            required.push(JsonValue::String(field.name.to_string()));
        }
    }

    JsonValue::object(vec![
        ("type".to_string(), JsonValue::String("object".to_string())),
        ("properties".to_string(), JsonValue::Object(properties)),
        ("required".to_string(), JsonValue::Array(required)),
        ("additionalProperties".to_string(), JsonValue::Bool(false)),
    ])
}

fn read_payload<R: BufRead>(reader: &mut R) -> Result<Option<String>, String> {
    let mut content_length: Option<usize> = None;
    let mut header = String::new();

    loop {
        header.clear();
        let bytes = reader
            .read_line(&mut header)
            .map_err(|e| format!("failed to read header: {}", e))?;
        if bytes == 0 {
            return Ok(None);
        }

        let trimmed = header.trim_end_matches(|c| c == '\n' || c == '\r');
        if trimmed.is_empty() {
            break;
        }

        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let value = trimmed["Content-Length:".len()..].trim();
            let length = value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length header".to_string())?;
            content_length = Some(length);
        }
    }

    let length = content_length.ok_or_else(|| "missing Content-Length header".to_string())?;
    let mut buffer = vec![0u8; length];
    reader
        .read_exact(&mut buffer)
        .map_err(|e| format!("failed to read payload: {}", e))?;

    let to_consume = match reader.fill_buf() {
        Ok(buf) => {
            if buf.starts_with(b"\r\n") {
                Some(2)
            } else if buf.starts_with(b"\n") {
                Some(1)
            } else {
                None
            }
        }
        Err(_) => None,
    };

    if let Some(count) = to_consume {
        reader.consume(count);
    }

    String::from_utf8(buffer)
        .map(Some)
        .map_err(|_| "payload is not UTF-8".to_string())
}

fn write_message(payload: JsonValue) -> Result<(), String> {
    let body = payload.to_json_string();
    let mut stdout = io::stdout().lock();
    write!(
        &mut stdout,
        "Content-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    )
    .map_err(|e| format!("failed to write response: {}", e))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush stdout: {}", e))
}

fn build_result_message(id: Option<JsonValue>, result: JsonValue) -> JsonValue {
    let mut entries = Vec::new();
    entries.push(("jsonrpc".to_string(), JsonValue::String("2.0".to_string())));
    if let Some(identifier) = id {
        entries.push(("id".to_string(), identifier));
    } else {
        entries.push(("id".to_string(), JsonValue::Null));
    }
    entries.push(("result".to_string(), result));
    JsonValue::Object(entries)
}

fn build_error_message(id: Option<JsonValue>, code: i64, message: &str) -> JsonValue {
    let mut entries = Vec::new();
    entries.push(("jsonrpc".to_string(), JsonValue::String("2.0".to_string())));
    if let Some(identifier) = id {
        entries.push(("id".to_string(), identifier));
    } else {
        entries.push(("id".to_string(), JsonValue::Null));
    }
    let error = JsonValue::object(vec![
        ("code".to_string(), JsonValue::Number(code as f64)),
        (
            "message".to_string(),
            JsonValue::String(message.to_string()),
        ),
    ]);
    entries.push(("error".to_string(), error));
    JsonValue::Object(entries)
}

fn parse_command_arguments(args: &JsonValue) -> Result<Vec<String>, String> {
    if let Some(array) = args.get("argv").and_then(|value| value.as_array()) {
        let mut result = Vec::with_capacity(array.len());
        for value in array {
            let s = value
                .as_str()
                .ok_or_else(|| "argv elements must be strings".to_string())?;
            result.push(s.to_string());
        }
        if !result.is_empty() {
            return Ok(result);
        }
    }

    if let Some(command) = args.get("command").and_then(|value| value.as_str()) {
        let parts = split_command_line(command);
        if !parts.is_empty() {
            return Ok(parts);
        }
        return Err("command string did not yield any arguments".to_string());
    }

    Err("provide either 'argv' (array of strings) or 'command' (string)".to_string())
}

fn split_command_line(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    let mut quote_char = '\0';

    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' => {
                if in_quotes {
                    if ch == quote_char {
                        in_quotes = false;
                    } else {
                        current.push(ch);
                    }
                } else {
                    in_quotes = true;
                    quote_char = ch;
                }
            }
            '\\' => {
                if let Some(next_ch) = chars.next() {
                    current.push(next_ch);
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            c => current.push(c),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

fn truncate_preview(text: &str) -> String {
    let trimmed = text.trim();
    const MAX_PREVIEW: usize = 160;
    if trimmed.len() <= MAX_PREVIEW {
        trimmed.replace('\n', " ⏎ ")
    } else {
        let mut snippet = trimmed[..MAX_PREVIEW].to_string();
        snippet.push_str(" …");
        snippet.replace('\n', " ⏎ ")
    }
}

fn build_document_index(max_sections: usize) -> Vec<JsonValue> {
    let mut documents = Vec::new();
    for path in all_document_paths() {
        let content = match fs::read_to_string(&path) {
            Ok(data) => data,
            Err(_) => continue,
        };
        let (title, sections) = summarize_markdown(&content, max_sections);
        let section_values = sections
            .into_iter()
            .map(|(level, heading, line)| {
                JsonValue::object(vec![
                    ("level".to_string(), JsonValue::Number(level as f64)),
                    ("title".to_string(), JsonValue::String(heading.clone())),
                    ("line".to_string(), JsonValue::Number(line as f64)),
                    ("slug".to_string(), JsonValue::String(slugify(&heading))),
                ])
            })
            .collect::<Vec<JsonValue>>();

        documents.push(JsonValue::object(vec![
            (
                "path".to_string(),
                JsonValue::String(path.to_string_lossy().to_string()),
            ),
            ("title".to_string(), JsonValue::String(title)),
            ("sections".to_string(), JsonValue::array(section_values)),
        ]));
    }
    documents
}

fn summarize_markdown(content: &str, max_sections: usize) -> (String, Vec<(usize, String, usize)>) {
    let mut title = None;
    let mut sections = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        if let Some((level, heading)) = parse_heading(line) {
            if level == 1 && title.is_none() {
                title = Some(heading.to_string());
            }
            if sections.len() < max_sections {
                sections.push((level, heading.to_string(), idx + 1));
            }
        }
    }

    let doc_title = title.unwrap_or_else(|| "Untitled".to_string());
    (doc_title, sections)
}

fn parse_heading(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('#') {
        return None;
    }
    let mut level = 0;
    for ch in trimmed.chars() {
        if ch == '#' {
            level += 1;
        } else {
            break;
        }
    }
    if level == 0 {
        return None;
    }
    let after = trimmed[level..].trim_start();
    if after.is_empty() {
        return None;
    }
    Some((level, after))
}

fn slugify(input: &str) -> String {
    let mut slug = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_whitespace() || ch == '-' {
            if !slug.ends_with('-') {
                slug.push('-');
            }
        }
    }
    slug.trim_matches('-').to_string()
}

fn extract_markdown_section(content: &str, heading_name: &str) -> Option<String> {
    let mut collecting = false;
    let mut target_level = 0usize;
    let mut buffer: Vec<String> = Vec::new();

    for line in content.lines() {
        if let Some((level, heading)) = parse_heading(line) {
            if collecting {
                if level <= target_level {
                    break;
                }
            }
            if heading.eq_ignore_ascii_case(heading_name.trim()) {
                collecting = true;
                target_level = level;
                buffer.push(line.to_string());
                continue;
            }
        }

        if collecting {
            buffer.push(line.to_string());
        }
    }

    if collecting {
        Some(buffer.join("\n"))
    } else {
        None
    }
}

fn resolve_doc_path(requested: &str) -> Option<PathBuf> {
    let candidate = Path::new(requested);
    if candidate.is_absolute() {
        return None;
    }
    if candidate
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }

    let normalized = candidate.to_string_lossy().to_string();
    for path in all_document_paths() {
        if path.to_string_lossy() == normalized {
            return Some(path);
        }
    }
    None
}

fn all_document_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("README.md"),
        PathBuf::from("AGENTS.md"),
        PathBuf::from("CLAUDE.md"),
    ];
    collect_doc_paths(Path::new("docs"), &mut paths);
    paths
}

fn default_target_db_path() -> PathBuf {
    PathBuf::from("mcp-targets.json")
}

#[derive(Clone)]
struct TargetEntry {
    name: String,
    target: String,
    notes: Option<String>,
    created_at: u64,
    updated_at: u64,
}

impl TargetEntry {
    fn to_json(&self) -> JsonValue {
        let mut fields = Vec::new();
        fields.push(("name".to_string(), JsonValue::String(self.name.clone())));
        fields.push(("target".to_string(), JsonValue::String(self.target.clone())));
        fields.push((
            "created_at".to_string(),
            JsonValue::Number(self.created_at as f64),
        ));
        fields.push((
            "updated_at".to_string(),
            JsonValue::Number(self.updated_at as f64),
        ));
        fields.push((
            "notes".to_string(),
            self.notes
                .as_ref()
                .map(|n| JsonValue::String(n.clone()))
                .unwrap_or(JsonValue::Null),
        ));
        JsonValue::object(fields)
    }
}

struct TargetDatabase {
    path: PathBuf,
    targets: Vec<TargetEntry>,
    dirty: bool,
}

impl TargetDatabase {
    fn load(path: PathBuf) -> Self {
        let mut db = TargetDatabase {
            path,
            targets: Vec::new(),
            dirty: false,
        };

        if let Ok(contents) = fs::read_to_string(&db.path) {
            if let Ok(json) = parse_json(&contents) {
                if let Some(array) = json.get("targets").and_then(|value| value.as_array()) {
                    for item in array {
                        if let Some(entry) = TargetDatabase::entry_from_json(item) {
                            db.targets.push(entry);
                        }
                    }
                }
            }
        }

        db
    }

    fn entry_from_json(value: &JsonValue) -> Option<TargetEntry> {
        let name = value.get("name")?.as_str()?;
        let target = value.get("target")?.as_str()?;
        let notes = value
            .get("notes")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let created_at = value
            .get("created_at")
            .and_then(|v| v.as_f64())
            .map(|v| v as u64)
            .unwrap_or_else(current_timestamp);
        let updated_at = value
            .get("updated_at")
            .and_then(|v| v.as_f64())
            .map(|v| v as u64)
            .unwrap_or(created_at);

        Some(TargetEntry {
            name: name.to_string(),
            target: target.to_string(),
            notes,
            created_at,
            updated_at,
        })
    }

    fn upsert(&mut self, name: &str, target: &str, notes: Option<&str>) -> (bool, TargetEntry) {
        let normalized_notes = notes.map(|n| n.trim()).filter(|s| !s.is_empty());
        let now = current_timestamp();

        for entry in &mut self.targets {
            if entry.name.eq_ignore_ascii_case(name) {
                entry.name = name.to_string();
                entry.target = target.to_string();
                entry.notes = normalized_notes.map(|n| n.to_string());
                entry.updated_at = now;
                self.dirty = true;
                return (false, entry.clone());
            }
        }

        let new_entry = TargetEntry {
            name: name.to_string(),
            target: target.to_string(),
            notes: normalized_notes.map(|n| n.to_string()),
            created_at: now,
            updated_at: now,
        };
        self.targets.push(new_entry.clone());
        self.dirty = true;
        (true, new_entry)
    }

    fn remove(&mut self, name: &str) -> Option<TargetEntry> {
        let index = self
            .targets
            .iter()
            .position(|entry| entry.name.eq_ignore_ascii_case(name));
        if let Some(idx) = index {
            self.dirty = true;
            Some(self.targets.remove(idx))
        } else {
            None
        }
    }

    fn persist(&mut self) -> Result<(), String> {
        if !self.dirty {
            return Ok(());
        }

        let records = self
            .targets
            .iter()
            .map(|entry| entry.to_json())
            .collect::<Vec<JsonValue>>();

        let payload = JsonValue::object(vec![("targets".to_string(), JsonValue::array(records))])
            .to_json_string();

        fs::write(&self.path, payload)
            .map_err(|e| format!("failed to write {}: {}", self.path.display(), e))?;
        self.dirty = false;
        Ok(())
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn search_documentation(query: &str, max_hits: usize) -> Vec<DocHit> {
    let mut hits = Vec::new();
    let lowercase_query = query.to_lowercase();

    for path in all_document_paths() {
        if hits.len() >= max_hits {
            break;
        }
        if let Some(hit) = search_file_for_query(&path, &lowercase_query, max_hits - hits.len()) {
            hits.extend(hit);
        }
    }

    hits
}

fn collect_doc_paths(root: &Path, accumulator: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_doc_paths(&path, accumulator);
        } else if let Some(ext) = path.extension() {
            if ext == "md" || ext == "txt" {
                accumulator.push(path);
            }
        }
    }
}

fn search_file_for_query(path: &Path, query: &str, remaining: usize) -> Option<Vec<DocHit>> {
    if remaining == 0 {
        return Some(Vec::new());
    }
    let content = fs::read_to_string(path).ok()?;
    let mut hits = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.to_lowercase().contains(query) {
            hits.push(DocHit {
                path: path.to_string_lossy().to_string(),
                line: index + 1,
                snippet: line.trim().to_string(),
            });
            if hits.len() >= remaining {
                break;
            }
        }
    }
    if hits.is_empty() {
        None
    } else {
        Some(hits)
    }
}
