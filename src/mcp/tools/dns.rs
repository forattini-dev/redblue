//! DNS MCP Tools
//!
//! DNS lookup and resolution tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::protocols::dns::{DnsClient, DnsRdata, DnsRecordType};
use crate::utils::json::JsonValue;

/// Register DNS tools with the server
pub fn register_dns_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.dns.lookup",
            description: "Perform DNS lookup for a domain with specified record type.",
            fields: &[
                ToolField {
                    name: "domain",
                    field_type: "string",
                    description: "Domain name to lookup.",
                    required: true,
                },
                ToolField {
                    name: "type",
                    field_type: "string",
                    description: "Record type: A, AAAA, MX, NS, TXT, CNAME, SOA (default: A).",
                    required: false,
                },
                ToolField {
                    name: "server",
                    field_type: "string",
                    description: "DNS server to query (default: 8.8.8.8).",
                    required: false,
                },
            ],
            handler: tool_dns_lookup,
        },
        ToolDefinition {
            name: "rb.dns.resolve",
            description: "Resolve a hostname to IP addresses using system resolver.",
            fields: &[ToolField {
                name: "hostname",
                field_type: "string",
                description: "Hostname to resolve.",
                required: true,
            }],
            handler: tool_dns_resolve,
        },
    ]
}

fn tool_dns_lookup(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let domain = args
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: domain")?;

    let record_type = args
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("A")
        .to_uppercase();

    let server = args
        .get("server")
        .and_then(|v| v.as_str())
        .unwrap_or("8.8.8.8");

    let client = DnsClient::new(server);

    let query_type = match record_type.as_str() {
        "A" => DnsRecordType::A,
        "AAAA" => DnsRecordType::AAAA,
        "MX" => DnsRecordType::MX,
        "NS" => DnsRecordType::NS,
        "TXT" => DnsRecordType::TXT,
        "CNAME" => DnsRecordType::CNAME,
        "SOA" => DnsRecordType::SOA,
        _ => return Err(format!("Unsupported record type: {}", record_type)),
    };

    let answers = client.query(domain, query_type)?;

    let records_json: Vec<JsonValue> = answers
        .iter()
        .map(|r| {
            let data_str = match &r.data {
                DnsRdata::A(ip) => ip.clone(),
                DnsRdata::AAAA(ip) => ip.clone(),
                DnsRdata::NS(ns) => ns.clone(),
                DnsRdata::CNAME(name) => name.clone(),
                DnsRdata::PTR(ptr) => ptr.clone(),
                DnsRdata::MX {
                    preference,
                    exchange,
                } => format!("{} {}", preference, exchange),
                DnsRdata::TXT(texts) => texts.join(" "),
                DnsRdata::SOA {
                    mname,
                    rname,
                    serial,
                    ..
                } => format!("{} {} {}", mname, rname, serial),
                DnsRdata::Raw(bytes) => format!("(raw {} bytes)", bytes.len()),
            };
            JsonValue::object(vec![
                ("type".to_string(), JsonValue::String(record_type.clone())),
                ("data".to_string(), JsonValue::String(data_str)),
                ("ttl".to_string(), JsonValue::Number(r.ttl as f64)),
            ])
        })
        .collect();

    let text = format!(
        "DNS lookup for {} ({}): {} record(s) found",
        domain,
        record_type,
        records_json.len()
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("domain".to_string(), JsonValue::String(domain.to_string())),
            ("type".to_string(), JsonValue::String(record_type)),
            ("server".to_string(), JsonValue::String(server.to_string())),
            ("records".to_string(), JsonValue::array(records_json)),
        ]),
    })
}

fn tool_dns_resolve(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let hostname = args
        .get("hostname")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: hostname")?;

    use std::net::ToSocketAddrs;

    let addrs: Vec<String> = format!("{}:0", hostname)
        .to_socket_addrs()
        .map_err(|e| format!("Resolution failed: {}", e))?
        .map(|addr| addr.ip().to_string())
        .collect();

    let text = if addrs.is_empty() {
        format!("No addresses found for {}", hostname)
    } else {
        format!("Resolved {}: {}", hostname, addrs.join(", "))
    };

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "hostname".to_string(),
                JsonValue::String(hostname.to_string()),
            ),
            (
                "addresses".to_string(),
                JsonValue::array(addrs.into_iter().map(JsonValue::String).collect()),
            ),
        ]),
    })
}
