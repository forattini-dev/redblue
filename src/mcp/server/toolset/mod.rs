mod auto;
mod config;
mod docs;
mod har;
mod html;
mod targets;
mod vuln;

use crate::mcp::server::McpServer;
use crate::mcp::types::{ToolDefinition, ToolField};

pub(super) fn register_inline_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
    // Documentation tools
    ToolDefinition {
      name: "rb.search-docs",
      description: "Search the RedBlue documentation for a keyword or phrase (case-insensitive).",
      fields: &[ToolField {
        name: "query",
        field_type: "string",
        description: "Search term to look for inside docs/ and README.md.",
        required: true,
      }],
      handler: docs::tool_search_docs,
    },
    ToolDefinition {
      name: "rb.docs.index",
      description: "Return a structured index of project documentation.",
      fields: &[],
      handler: docs::tool_docs_index,
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
          description: "Optional heading to extract (exact text match, case-insensitive).",
          required: false,
        },
      ],
      handler: docs::tool_docs_get,
    },
    // Target management
    ToolDefinition {
      name: "rb.targets.list",
      description: "List all MCP-tracked targets with metadata.",
      fields: &[],
      handler: targets::tool_targets_list,
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
      handler: targets::tool_targets_save,
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
      handler: targets::tool_targets_remove,
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
      handler: html::tool_html_select,
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
      handler: har::tool_har_record,
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
      handler: har::tool_har_analyze,
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
      handler: vuln::tool_vuln_fingerprint,
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
      handler: vuln::tool_fingerprint_service,
    },
    // Configuration
    ToolDefinition {
      name: "rb.config.categories",
      description: "View current tool category configuration.",
      fields: &[],
      handler: config::tool_config_categories,
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
      handler: config::tool_config_preset,
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
      handler: auto::tool_auto_guide,
    },
  ]
}
