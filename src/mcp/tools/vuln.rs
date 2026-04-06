//! Vulnerability MCP Tools
//!
//! Vulnerability search, CVE lookup, and exploit database tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register vulnerability tools with the server
pub fn register_vuln_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
    ToolDefinition {
      name: "rb.vuln.search",
      description: "Search for vulnerabilities by product and version.",
      fields: &[
        ToolField {
          name: "product",
          field_type: "string",
          description: "Product name (e.g., nginx, apache, mysql).",
          required: true,
        },
        ToolField {
          name: "version",
          field_type: "string",
          description: "Product version (e.g., 1.18.0).",
          required: false,
        },
      ],
      handler: tool_vuln_search,
    },
    ToolDefinition {
      name: "rb.vuln.cve",
      description: "Get details for a specific CVE.",
      fields: &[ToolField {
        name: "cve_id",
        field_type: "string",
        description: "CVE identifier (e.g., CVE-2021-44228).",
        required: true,
      }],
      handler: tool_vuln_cve,
    },
    ToolDefinition {
      name: "rb.vuln.kev",
      description: "Check CISA Known Exploited Vulnerabilities catalog.",
      fields: &[ToolField {
        name: "cve_id",
        field_type: "string",
        description: "CVE to check (optional, lists recent if omitted).",
        required: false,
      }],
      handler: tool_vuln_kev,
    },
    ToolDefinition {
      name: "rb.vuln.exploit",
      description: "Search Exploit-DB for exploits.",
      fields: &[ToolField {
        name: "query",
        field_type: "string",
        description: "Search query (product, CVE, or keywords).",
        required: true,
      }],
      handler: tool_vuln_exploit,
    },
  ]
}

fn tool_vuln_search(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::recon::vuln::{generate_cpe, NvdClient};

  let product = args
    .get("product")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: product")?;

  let version = args.get("version").and_then(|v| v.as_str());

  let cpe = generate_cpe(product, version)
    .ok_or_else(|| format!("Could not generate CPE for product: {}", product))?;
  let mut client = NvdClient::new();
  let vulns = client
    .query_by_cpe(&cpe)
    .map_err(|e| format!("NVD search failed: {}", e))?;

  let vulns_json: Vec<JsonValue> = vulns
    .iter()
    .take(20)
    .map(|v| {
      JsonValue::object(vec![
        ("cve_id".to_string(), JsonValue::String(v.id.clone())),
        (
          "description".to_string(),
          JsonValue::String(v.description.chars().take(200).collect()),
        ),
        (
          "cvss".to_string(),
          v.cvss_v3
            .map(|s| JsonValue::Number(s as f64))
            .unwrap_or(JsonValue::Null),
        ),
        (
          "severity".to_string(),
          JsonValue::String(format!("{:?}", v.severity)),
        ),
      ])
    })
    .collect();

  let text = format!(
    "Found {} vulnerabilities for {} {}",
    vulns.len(),
    product,
    version.unwrap_or("")
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "product".to_string(),
        JsonValue::String(product.to_string()),
      ),
      (
        "version".to_string(),
        version
          .map(|v| JsonValue::String(v.to_string()))
          .unwrap_or(JsonValue::Null),
      ),
      ("cpe".to_string(), JsonValue::String(cpe)),
      ("count".to_string(), JsonValue::Number(vulns.len() as f64)),
      ("vulnerabilities".to_string(), JsonValue::array(vulns_json)),
    ]),
  })
}

fn tool_vuln_cve(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::recon::vuln::NvdClient;

  let cve_id = args
    .get("cve_id")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: cve_id")?;

  let mut client = NvdClient::new();
  let cve = client
    .query_by_cve(cve_id)
    .map_err(|e| format!("CVE lookup failed: {}", e))?
    .ok_or_else(|| format!("CVE not found: {}", cve_id))?;

  let text = format!(
    "{}: {} (CVSS: {})",
    cve.id,
    cve.description.chars().take(100).collect::<String>(),
    cve
      .cvss_v3
      .map(|s| s.to_string())
      .unwrap_or_else(|| "N/A".to_string())
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("cve_id".to_string(), JsonValue::String(cve.id)),
      (
        "description".to_string(),
        JsonValue::String(cve.description),
      ),
      (
        "cvss".to_string(),
        cve
          .cvss_v3
          .map(|s| JsonValue::Number(s as f64))
          .unwrap_or(JsonValue::Null),
      ),
      (
        "severity".to_string(),
        JsonValue::String(format!("{:?}", cve.severity)),
      ),
      (
        "published".to_string(),
        cve
          .published
          .map(JsonValue::String)
          .unwrap_or(JsonValue::Null),
      ),
      (
        "references".to_string(),
        JsonValue::array(cve.references.into_iter().map(JsonValue::String).collect()),
      ),
    ]),
  })
}

fn tool_vuln_kev(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::recon::vuln::KevClient;

  let cve_id = args.get("cve_id").and_then(|v| v.as_str());

  let mut client = KevClient::new();

  if let Some(cve) = cve_id {
    let is_kev = client
      .is_in_kev(cve)
      .map_err(|e| format!("KEV check failed: {}", e))?;

    let text = if is_kev {
      format!("{} IS in CISA KEV catalog (actively exploited)", cve)
    } else {
      format!("{} is NOT in CISA KEV catalog", cve)
    };

    Ok(ToolResult {
      text,
      data: JsonValue::object(vec![
        ("cve_id".to_string(), JsonValue::String(cve.to_string())),
        ("is_kev".to_string(), JsonValue::Bool(is_kev)),
      ]),
    })
  } else {
    // Get all KEV entries and take the most recent ones
    let kevs = client
      .get_all()
      .map_err(|e| format!("KEV list failed: {}", e))?;

    let kevs_json: Vec<JsonValue> = kevs
      .iter()
      .take(10)
      .map(|k| {
        JsonValue::object(vec![
          ("cve_id".to_string(), JsonValue::String(k.cve_id.clone())),
          (
            "vendor".to_string(),
            JsonValue::String(k.vendor_project.clone()),
          ),
          ("product".to_string(), JsonValue::String(k.product.clone())),
        ])
      })
      .collect();

    let text = format!(
      "Showing {} of {} total KEV entries",
      kevs_json.len(),
      kevs.len()
    );

    Ok(ToolResult {
      text,
      data: JsonValue::object(vec![
        ("count".to_string(), JsonValue::Number(kevs.len() as f64)),
        ("entries".to_string(), JsonValue::array(kevs_json)),
      ]),
    })
  }
}

fn tool_vuln_exploit(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::recon::vuln::ExploitDbClient;

  let query = args
    .get("query")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: query")?;

  let client = ExploitDbClient::new();
  let exploits = client
    .search(query)
    .map_err(|e| format!("Exploit-DB search failed: {}", e))?;

  let exploits_json: Vec<JsonValue> = exploits
    .iter()
    .take(15)
    .map(|e| {
      JsonValue::object(vec![
        ("id".to_string(), JsonValue::String(e.id.clone())),
        ("title".to_string(), JsonValue::String(e.title.clone())),
        (
          "type".to_string(),
          e.exploit_type
            .as_ref()
            .map(|t| JsonValue::String(t.clone()))
            .unwrap_or(JsonValue::Null),
        ),
        (
          "platform".to_string(),
          e.platform
            .as_ref()
            .map(|p| JsonValue::String(p.clone()))
            .unwrap_or(JsonValue::Null),
        ),
      ])
    })
    .collect();

  let text = format!("Found {} exploits for '{}'", exploits.len(), query);

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("query".to_string(), JsonValue::String(query.to_string())),
      (
        "count".to_string(),
        JsonValue::Number(exploits.len() as f64),
      ),
      ("exploits".to_string(), JsonValue::array(exploits_json)),
    ]),
  })
}
