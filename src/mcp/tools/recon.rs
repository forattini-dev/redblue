//! Recon MCP Tools
//!
//! Reconnaissance tools for subdomain enumeration, WHOIS, etc.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register recon tools with the server
pub fn register_recon_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.recon.whois",
            description: "Perform WHOIS lookup for a domain.",
            fields: &[ToolField {
                name: "domain",
                field_type: "string",
                description: "Domain name to lookup.",
                required: true,
            }],
            handler: tool_recon_whois,
        },
        ToolDefinition {
            name: "rb.recon.subdomains",
            description: "Enumerate subdomains for a domain using crt.sh.",
            fields: &[ToolField {
                name: "domain",
                field_type: "string",
                description: "Base domain to enumerate.",
                required: true,
            }],
            handler: tool_recon_subdomains,
        },
        ToolDefinition {
            name: "rb.recon.dnsdumpster",
            description: "Query DNSDumpster for DNS records and subdomains.",
            fields: &[ToolField {
                name: "domain",
                field_type: "string",
                description: "Domain to query.",
                required: true,
            }],
            handler: tool_recon_dnsdumpster,
        },
        ToolDefinition {
            name: "rb.recon.massdns",
            description: "Perform high-speed subdomain bruteforce using MassDNS-style resolution.",
            fields: &[
                ToolField {
                    name: "domain",
                    field_type: "string",
                    description: "Base domain for subdomain bruteforce.",
                    required: true,
                },
                ToolField {
                    name: "wordlist",
                    field_type: "string",
                    description: "Wordlist: 'small', 'medium', 'large'.",
                    required: false,
                },
            ],
            handler: tool_recon_massdns,
        },
    ]
}

fn tool_recon_whois(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::protocols::whois::WhoisClient;

    let domain = args
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: domain")?;

    let client = WhoisClient::new();
    let result = client
        .query(domain)
        .map_err(|e| format!("WHOIS query failed: {}", e))?;

    let text = format!(
        "WHOIS for {}:\n{}",
        domain,
        result.raw.chars().take(1000).collect::<String>()
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("domain".to_string(), JsonValue::String(domain.to_string())),
            (
                "registrar".to_string(),
                result
                    .registrar
                    .map(JsonValue::String)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "creation_date".to_string(),
                result
                    .creation_date
                    .map(JsonValue::String)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "expiration_date".to_string(),
                result
                    .expiration_date
                    .map(JsonValue::String)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "name_servers".to_string(),
                JsonValue::array(
                    result
                        .name_servers
                        .into_iter()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            ("raw".to_string(), JsonValue::String(result.raw)),
        ]),
    })
}

fn tool_recon_subdomains(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::recon::crtsh::CrtShClient;

    let domain = args
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: domain")?;

    // Use crt.sh to find subdomains from certificate transparency logs
    let crtsh = CrtShClient::new();
    let mut subdomains = crtsh
        .query_subdomains(domain)
        .map_err(|e| format!("crt.sh query failed: {}", e))?;

    subdomains.sort();
    subdomains.dedup();

    let text = format!("Found {} subdomains for {}", subdomains.len(), domain);

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("domain".to_string(), JsonValue::String(domain.to_string())),
            (
                "count".to_string(),
                JsonValue::Number(subdomains.len() as f64),
            ),
            (
                "subdomains".to_string(),
                JsonValue::array(subdomains.into_iter().map(JsonValue::String).collect()),
            ),
        ]),
    })
}

fn tool_recon_dnsdumpster(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::recon::dnsdumpster::DnsDumpsterClient;

    let domain = args
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: domain")?;

    let client = DnsDumpsterClient::new();
    let result = client
        .query(domain)
        .map_err(|e| format!("DNSDumpster query failed: {}", e))?;

    // Combine host_records and subdomains for comprehensive results
    let all_records: Vec<_> = result
        .host_records
        .iter()
        .chain(result.subdomains.iter())
        .take(100)
        .collect();

    let hosts_json: Vec<JsonValue> = all_records
        .iter()
        .map(|h| {
            JsonValue::object(vec![
                ("hostname".to_string(), JsonValue::String(h.host.clone())),
                (
                    "ip".to_string(),
                    h.ip.clone()
                        .map(JsonValue::String)
                        .unwrap_or(JsonValue::Null),
                ),
            ])
        })
        .collect();

    let text = format!(
        "DNSDumpster found {} records for {}",
        all_records.len(),
        domain
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("domain".to_string(), JsonValue::String(domain.to_string())),
            (
                "hosts_count".to_string(),
                JsonValue::Number(all_records.len() as f64),
            ),
            ("hosts".to_string(), JsonValue::array(hosts_json)),
        ]),
    })
}

fn tool_recon_massdns(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::recon::massdns::{common_subdomains, MassDnsScanner};

    let domain = args
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: domain")?;

    let wordlist_arg = args
        .get("wordlist")
        .and_then(|v| v.as_str())
        .unwrap_or("small");

    let wordlist: Vec<String> = match wordlist_arg {
        "small" => common_subdomains().into_iter().take(100).collect(),
        "medium" => common_subdomains().into_iter().take(1000).collect(),
        "large" => common_subdomains(),
        _ => common_subdomains().into_iter().take(100).collect(),
    };

    let scanner = MassDnsScanner::new()
        .with_threads(10)
        .with_resolvers(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]);

    let results = scanner
        .bruteforce(domain, &wordlist)
        .map_err(|e| format!("MassDNS bruteforce failed: {}", e))?;

    let found: Vec<JsonValue> = results
        .resolved
        .iter()
        .take(200)
        .map(|r| {
            JsonValue::object(vec![
                (
                    "subdomain".to_string(),
                    JsonValue::String(r.subdomain.clone()),
                ),
                (
                    "ips".to_string(),
                    JsonValue::array(
                        r.ips
                            .iter()
                            .map(|ip| JsonValue::String(ip.to_string()))
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();

    let text = format!(
        "MassDNS found {} live subdomains for {}",
        found.len(),
        domain
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("domain".to_string(), JsonValue::String(domain.to_string())),
            (
                "wordlist_size".to_string(),
                JsonValue::Number(wordlist.len() as f64),
            ),
            (
                "found_count".to_string(),
                JsonValue::Number(found.len() as f64),
            ),
            ("subdomains".to_string(), JsonValue::array(found)),
        ]),
    })
}
