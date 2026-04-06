//! TLS MCP Tools
//!
//! TLS certificate inspection and security auditing tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register TLS tools with the server
pub fn register_tls_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![ToolDefinition {
    name: "rb.tls.cert",
    description: "Get TLS certificate information for a host.",
    fields: &[
      ToolField {
        name: "host",
        field_type: "string",
        description: "Hostname to inspect (e.g., example.com).",
        required: true,
      },
      ToolField {
        name: "port",
        field_type: "number",
        description: "Port number (default: 443).",
        required: false,
      },
    ],
    handler: tool_tls_cert,
  }]
}

fn tool_tls_cert(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let host = args
    .get("host")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: host")?;

  let port = args
    .get("port")
    .and_then(|v| v.as_f64())
    .map(|n| n as u16)
    .unwrap_or(443);

  // Use our TLS implementation to get certificate info
  use crate::protocols::tls::TlsClient;

  let certs =
    TlsClient::get_certificates(host, port).map_err(|e| format!("TLS connection failed: {}", e))?;

  if certs.is_empty() {
    return Err("No certificates returned from server".to_string());
  }

  // Get the leaf certificate (first one)
  let cert = &certs[0];

  let subject = cert.subject_string();
  let issuer = cert.issuer_string();
  let serial = cert.serial_number_hex();
  let sans = cert.get_subject_alt_names();
  let not_before = cert.validity.not_before.clone();
  let not_after = cert.validity.not_after.clone();

  let text = format!(
    "Certificate for {}:{}\n  Subject: {}\n  Issuer: {}\n  Valid until: {}",
    host, port, subject, issuer, not_after
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("host".to_string(), JsonValue::String(host.to_string())),
      ("port".to_string(), JsonValue::Number(port as f64)),
      ("subject".to_string(), JsonValue::String(subject)),
      ("issuer".to_string(), JsonValue::String(issuer)),
      ("not_before".to_string(), JsonValue::String(not_before)),
      ("not_after".to_string(), JsonValue::String(not_after)),
      ("serial".to_string(), JsonValue::String(serial)),
      (
        "san".to_string(),
        JsonValue::array(sans.into_iter().map(JsonValue::String).collect()),
      ),
      (
        "chain_length".to_string(),
        JsonValue::Number(certs.len() as f64),
      ),
    ]),
  })
}
