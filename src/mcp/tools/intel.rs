//! Intel MCP Tools
//!
//! MITRE ATT&CK mapping, IOC extraction, and threat intelligence tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register intel tools with the server
pub fn register_intel_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
    ToolDefinition {
      name: "rb.intel.mitre-map",
      description:
        "Map findings to MITRE ATT&CK techniques. Provide CVE, port number, or technology name.",
      fields: &[
        ToolField {
          name: "cve",
          field_type: "string",
          description: "CVE ID to map (e.g., 'CVE-2021-44228').",
          required: false,
        },
        ToolField {
          name: "port",
          field_type: "number",
          description: "Port number to map (e.g., 22, 443, 3389).",
          required: false,
        },
        ToolField {
          name: "technology",
          field_type: "string",
          description: "Technology/service name to map (e.g., 'ssh', 'apache').",
          required: false,
        },
      ],
      handler: tool_intel_mitre_map,
    },
    ToolDefinition {
      name: "rb.intel.mitre-layer",
      description: "Generate MITRE ATT&CK Navigator layer from techniques.",
      fields: &[
        ToolField {
          name: "techniques",
          field_type: "array",
          description: "Array of technique IDs (e.g., ['T1566', 'T1059']).",
          required: true,
        },
        ToolField {
          name: "name",
          field_type: "string",
          description: "Layer name.",
          required: false,
        },
        ToolField {
          name: "target",
          field_type: "string",
          description: "Target description for the layer.",
          required: false,
        },
      ],
      handler: tool_intel_mitre_layer,
    },
    ToolDefinition {
      name: "rb.intel.ioc-extract",
      description: "Extract IOCs (IPs, domains, hashes, URLs) from HTML/text content.",
      fields: &[ToolField {
        name: "text",
        field_type: "string",
        description: "Text or HTML to extract IOCs from.",
        required: true,
      }],
      handler: tool_intel_ioc_extract,
    },
  ]
}

fn tool_intel_mitre_map(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::intel::mapper::TechniqueMapper;

  let mapper = TechniqueMapper::new();
  let mut all_techniques = Vec::new();

  // Map from CVE if provided
  if let Some(cve) = args.get("cve").and_then(|v| v.as_str()) {
    // For CVE mapping we need a description - use CVE ID as minimal input
    let techniques = mapper.map_cve(cve, cve);
    all_techniques.extend(techniques);
  }

  // Map from port if provided
  if let Some(port) = args.get("port").and_then(|v| v.as_f64()) {
    let techniques = mapper.map_port(port as u16);
    all_techniques.extend(techniques);
  }

  // Map from technology/fingerprint if provided
  if let Some(tech) = args.get("technology").and_then(|v| v.as_str()) {
    let techniques = mapper.map_fingerprint(tech);
    all_techniques.extend(techniques);
  }

  if all_techniques.is_empty() {
    return Err("Provide at least one of: cve, port, or technology".to_string());
  }

  let techniques_json: Vec<JsonValue> = all_techniques
    .iter()
    .take(20)
    .map(|t| {
      JsonValue::object(vec![
        ("id".to_string(), JsonValue::String(t.technique_id.clone())),
        ("name".to_string(), JsonValue::String(t.name.clone())),
        ("tactic".to_string(), JsonValue::String(t.tactic.clone())),
        (
          "confidence".to_string(),
          JsonValue::String(format!("{:?}", t.confidence)),
        ),
        ("reason".to_string(), JsonValue::String(t.reason.clone())),
      ])
    })
    .collect();

  let text = format!("Mapped {} MITRE ATT&CK techniques", techniques_json.len());

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "count".to_string(),
        JsonValue::Number(techniques_json.len() as f64),
      ),
      ("techniques".to_string(), JsonValue::array(techniques_json)),
    ]),
  })
}

fn tool_intel_mitre_layer(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::intel::mapper::{Confidence, MappedTechnique, MappingSource};
  use crate::modules::intel::navigator::create_layer_from_techniques;

  let technique_ids: Vec<String> = args
    .get("techniques")
    .and_then(|v| v.as_array())
    .map(|arr| {
      arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
    })
    .ok_or("Missing required field: techniques")?;

  let name = args
    .get("name")
    .and_then(|v| v.as_str())
    .unwrap_or("RedBlue Layer");

  let target = args
    .get("target")
    .and_then(|v| v.as_str())
    .unwrap_or("unknown");

  // Convert technique IDs to MappedTechnique structs
  // Use Fingerprint source as the generic fallback for manually specified techniques
  let mapped_techniques: Vec<MappedTechnique> = technique_ids
    .iter()
    .map(|id| MappedTechnique {
      technique_id: id.clone(),
      name: id.clone(), // Use ID as name since we don't have a lookup
      reason: "Manually specified".to_string(),
      tactic: "Unknown".to_string(),
      confidence: Confidence::High,
      source: MappingSource::Fingerprint,
      original_value: id.clone(),
    })
    .collect();

  let layer = create_layer_from_techniques(&mapped_techniques, name, target);
  let layer_json = layer.to_json();

  let text = format!(
    "Generated MITRE ATT&CK layer '{}' with {} techniques",
    name,
    technique_ids.len()
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("name".to_string(), JsonValue::String(name.to_string())),
      (
        "technique_count".to_string(),
        JsonValue::Number(technique_ids.len() as f64),
      ),
      ("layer".to_string(), JsonValue::String(layer_json)),
    ]),
  })
}

fn tool_intel_ioc_extract(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  use crate::modules::intel::ioc::IocExtractor;

  let text_input = args
    .get("text")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: text")?;

  // Create extractor with text content as target
  let extractor = IocExtractor::new("ioc-extraction");

  // Use extract_from_html which works on text/HTML content
  let iocs = extractor.extract_from_html(text_input);

  // Group IOCs by type for the response
  let mut ips = Vec::new();
  let mut domains = Vec::new();
  let mut urls = Vec::new();
  let mut hashes = Vec::new();
  let mut emails = Vec::new();

  for ioc in &iocs {
    let value = &ioc.value;
    match format!("{}", ioc.ioc_type).as_str() {
      "ipv4" | "ipv6" => ips.push(value.clone()),
      "domain" => domains.push(value.clone()),
      "url" => urls.push(value.clone()),
      "md5" | "sha1" | "sha256" => hashes.push(value.clone()),
      "email" => emails.push(value.clone()),
      _ => {}
    }
  }

  let ips_json: Vec<JsonValue> = ips.iter().map(|ip| JsonValue::String(ip.clone())).collect();
  let domains_json: Vec<JsonValue> = domains
    .iter()
    .map(|d| JsonValue::String(d.clone()))
    .collect();
  let urls_json: Vec<JsonValue> = urls.iter().map(|u| JsonValue::String(u.clone())).collect();
  let hashes_json: Vec<JsonValue> = hashes
    .iter()
    .map(|h| JsonValue::String(h.clone()))
    .collect();
  let emails_json: Vec<JsonValue> = emails
    .iter()
    .map(|e| JsonValue::String(e.clone()))
    .collect();

  let total = iocs.len();
  let text = format!(
    "Extracted {} IOCs: {} IPs, {} domains, {} URLs, {} hashes, {} emails",
    total,
    ips.len(),
    domains.len(),
    urls.len(),
    hashes.len(),
    emails.len()
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("total".to_string(), JsonValue::Number(total as f64)),
      ("ips".to_string(), JsonValue::array(ips_json)),
      ("domains".to_string(), JsonValue::array(domains_json)),
      ("urls".to_string(), JsonValue::array(urls_json)),
      ("hashes".to_string(), JsonValue::array(hashes_json)),
      ("emails".to_string(), JsonValue::array(emails_json)),
    ]),
  })
}
