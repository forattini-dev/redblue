//! Web MCP Tools
//!
//! Web crawling, scraping, and HTTP analysis tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register web tools with the server
pub fn register_web_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.web.crawl",
            description: "Crawl a website and discover pages, forms, and resources.",
            fields: &[
                ToolField {
                    name: "url",
                    field_type: "string",
                    description: "Starting URL to crawl.",
                    required: true,
                },
                ToolField {
                    name: "max_depth",
                    field_type: "number",
                    description: "Maximum crawl depth (default: 2).",
                    required: false,
                },
                ToolField {
                    name: "max_pages",
                    field_type: "number",
                    description: "Maximum pages to crawl (default: 100).",
                    required: false,
                },
            ],
            handler: tool_web_crawl,
        },
        ToolDefinition {
            name: "rb.web.scrape",
            description: "Fetch and parse a single web page.",
            fields: &[
                ToolField {
                    name: "url",
                    field_type: "string",
                    description: "URL to fetch.",
                    required: true,
                },
                ToolField {
                    name: "selector",
                    field_type: "string",
                    description: "CSS selector to extract (optional).",
                    required: false,
                },
            ],
            handler: tool_web_scrape,
        },
        ToolDefinition {
            name: "rb.web.links",
            description: "Extract all links from a web page.",
            fields: &[ToolField {
                name: "url",
                field_type: "string",
                description: "URL to extract links from.",
                required: true,
            }],
            handler: tool_web_links,
        },
        ToolDefinition {
            name: "rb.web.tables",
            description: "Extract tables from a web page as structured data.",
            fields: &[ToolField {
                name: "url",
                field_type: "string",
                description: "URL containing tables.",
                required: true,
            }],
            handler: tool_web_tables,
        },
        // SQL Injection tools
        ToolDefinition {
            name: "rb.web.sqli.test",
            description: "Test URL parameters for SQL injection vulnerabilities (sqlmap-style).",
            fields: &[
                ToolField {
                    name: "url",
                    field_type: "string",
                    description: "URL with parameters to test (e.g., http://site.com/page?id=1).",
                    required: true,
                },
                ToolField {
                    name: "param",
                    field_type: "string",
                    description:
                        "Specific parameter to test (optional, tests all if not specified).",
                    required: false,
                },
                ToolField {
                    name: "dbms",
                    field_type: "string",
                    description: "Target DBMS: mysql, postgres, mssql, oracle, sqlite.",
                    required: false,
                },
                ToolField {
                    name: "level",
                    field_type: "string",
                    description: "Scan level: quick, standard, thorough (default: standard).",
                    required: false,
                },
            ],
            handler: tool_sqli_test,
        },
        ToolDefinition {
            name: "rb.web.sqli.payloads",
            description: "List available SQL injection payloads.",
            fields: &[
                ToolField {
                    name: "dbms",
                    field_type: "string",
                    description: "Filter by DBMS: mysql, postgres, mssql, oracle, sqlite.",
                    required: false,
                },
                ToolField {
                    name: "technique",
                    field_type: "string",
                    description: "Filter by technique: error, blind, time, union, stacked.",
                    required: false,
                },
            ],
            handler: tool_sqli_payloads,
        },
        // NoSQL Injection tools
        ToolDefinition {
            name: "rb.web.nosqli.test",
            description: "Test URL parameters for NoSQL injection vulnerabilities.",
            fields: &[
                ToolField {
                    name: "url",
                    field_type: "string",
                    description: "URL with parameters to test.",
                    required: true,
                },
                ToolField {
                    name: "param",
                    field_type: "string",
                    description: "Specific parameter to test.",
                    required: false,
                },
                ToolField {
                    name: "db",
                    field_type: "string",
                    description: "Target database: mongodb, redis, elasticsearch, couchdb.",
                    required: false,
                },
            ],
            handler: tool_nosqli_test,
        },
        // Git Exposed tools
        ToolDefinition {
            name: "rb.web.git.scan",
            description: "Scan for exposed .git directories on web servers.",
            fields: &[
                ToolField {
                    name: "url",
                    field_type: "string",
                    description: "Target URL to scan for exposed .git.",
                    required: true,
                },
                ToolField {
                    name: "scan_secrets",
                    field_type: "boolean",
                    description: "Scan recovered content for secrets (default: false).",
                    required: false,
                },
            ],
            handler: tool_git_scan,
        },
    ]
}

fn tool_web_crawl(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::web::crawler::WebCrawler;

    let url = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: url")?;

    let max_depth = args
        .get("max_depth")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize)
        .unwrap_or(2);

    let max_pages = args
        .get("max_pages")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize)
        .unwrap_or(100);

    let mut crawler = WebCrawler::new()
        .with_max_depth(max_depth)
        .with_max_pages(max_pages);

    let result = crawler
        .crawl(url)
        .map_err(|e| format!("Crawl failed: {}", e))?;

    let pages_json: Vec<JsonValue> = result
        .pages
        .iter()
        .take(50) // Limit output
        .map(|page| {
            JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(page.url.clone())),
                (
                    "title".to_string(),
                    page.meta
                        .title
                        .clone()
                        .map(JsonValue::String)
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "status".to_string(),
                    JsonValue::Number(page.status_code as f64),
                ),
            ])
        })
        .collect();

    let text = format!("Crawled {}: {} pages discovered", url, result.pages.len());

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("start_url".to_string(), JsonValue::String(url.to_string())),
            (
                "pages_crawled".to_string(),
                JsonValue::Number(result.pages.len() as f64),
            ),
            ("pages".to_string(), JsonValue::array(pages_json)),
        ]),
    })
}

fn tool_web_scrape(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::web::dom::Document;
    use crate::protocols::http::HttpClient;

    let url = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: url")?;

    let selector = args.get("selector").and_then(|v| v.as_str());

    let client = HttpClient::new();
    let response = client
        .get(url)
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let body = response.body_as_string();
    let doc = Document::parse(&body);

    let extracted = if let Some(sel) = selector {
        let elements = doc.select(sel);
        elements.text()
    } else {
        doc.title()
            .map(|s| s.to_string())
            .unwrap_or_else(|| body.chars().take(500).collect())
    };

    let text = format!("Scraped {}: {} bytes", url, body.len());

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("url".to_string(), JsonValue::String(url.to_string())),
            (
                "status".to_string(),
                JsonValue::Number(response.status_code as f64),
            ),
            (
                "content_length".to_string(),
                JsonValue::Number(body.len() as f64),
            ),
            ("extracted".to_string(), JsonValue::String(extracted)),
        ]),
    })
}

fn tool_web_links(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::web::dom::Document;
    use crate::modules::web::extractors;
    use crate::protocols::http::HttpClient;

    let url = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: url")?;

    let client = HttpClient::new();
    let response = client
        .get(url)
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let body = response.body_as_string();
    let doc = Document::parse(&body);
    let links = extractors::links(&doc);

    let links_json: Vec<JsonValue> = links
        .iter()
        .take(100)
        .map(|link| {
            JsonValue::object(vec![
                ("href".to_string(), JsonValue::String(link.href.clone())),
                ("text".to_string(), JsonValue::String(link.text.clone())),
                (
                    "rel".to_string(),
                    link.rel
                        .clone()
                        .map(JsonValue::String)
                        .unwrap_or(JsonValue::Null),
                ),
            ])
        })
        .collect();

    let text = format!("Found {} links on {}", links.len(), url);

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("url".to_string(), JsonValue::String(url.to_string())),
            ("count".to_string(), JsonValue::Number(links.len() as f64)),
            ("links".to_string(), JsonValue::array(links_json)),
        ]),
    })
}

fn tool_web_tables(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::web::dom::Document;
    use crate::modules::web::extractors;
    use crate::protocols::http::HttpClient;

    let url = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: url")?;

    let client = HttpClient::new();
    let response = client
        .get(url)
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let body = response.body_as_string();
    let doc = Document::parse(&body);
    let tables = extractors::tables(&doc);

    let tables_json: Vec<JsonValue> = tables
        .iter()
        .take(10)
        .map(|table| {
            let rows: Vec<JsonValue> = table
                .rows
                .iter()
                .take(20)
                .map(|row| {
                    JsonValue::array(row.iter().map(|c| JsonValue::String(c.clone())).collect())
                })
                .collect();
            JsonValue::object(vec![
                (
                    "headers".to_string(),
                    JsonValue::array(
                        table
                            .headers
                            .iter()
                            .map(|h| JsonValue::String(h.clone()))
                            .collect(),
                    ),
                ),
                ("rows".to_string(), JsonValue::array(rows)),
            ])
        })
        .collect();

    let text = format!("Found {} tables on {}", tables.len(), url);

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("url".to_string(), JsonValue::String(url.to_string())),
            ("count".to_string(), JsonValue::Number(tables.len() as f64)),
            ("tables".to_string(), JsonValue::array(tables_json)),
        ]),
    })
}

// =============================================================================
// SQL Injection Tools
// =============================================================================

fn tool_sqli_test(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::web::{
        sqli::techniques::HttpResponse as SqliHttpResponse, Dbms, InjectionPoint, SqliScanConfig,
        SqliScanner,
    };
    use crate::protocols::http::HttpClient;

    let url = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: url")?;

    let level = args
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("standard");

    let mut config = match level {
        "quick" => SqliScanConfig::quick(),
        "thorough" => SqliScanConfig::thorough(),
        _ => SqliScanConfig::default(),
    };

    // Apply DBMS filter
    if let Some(dbms_str) = args.get("dbms").and_then(|v| v.as_str()) {
        let dbms = match dbms_str.to_lowercase().as_str() {
            "mysql" => Dbms::MySQL,
            "postgres" | "postgresql" => Dbms::PostgreSQL,
            "mssql" | "sqlserver" => Dbms::MsSQL,
            "oracle" => Dbms::Oracle,
            "sqlite" => Dbms::SQLite,
            _ => return Err(format!("Unknown DBMS: {}", dbms_str)),
        };
        config = config.for_dbms(dbms);
    }

    // Parse URL parameters
    let params = SqliScanner::parse_url_params(url);
    if params.is_empty() {
        return Err("No parameters found in URL".to_string());
    }

    // Filter to specific param if requested
    let only_param = args.get("param").and_then(|v| v.as_str());

    let scanner = SqliScanner::new(config);
    let client = HttpClient::new();

    let mut results = Vec::new();

    for (param_name, original_value) in &params {
        if let Some(only) = only_param {
            if !param_name.to_lowercase().contains(&only.to_lowercase()) {
                continue;
            }
        }

        let url_clone = url.to_string();
        let param_clone = param_name.clone();
        let client_ref = &client;

        let send_request = |payload: &str| -> SqliHttpResponse {
            let test_url = SqliScanner::build_url_with_param(&url_clone, &param_clone, payload);
            match client_ref.send_with_metrics(&crate::protocols::http::HttpRequest::get(&test_url))
            {
                Ok((response, duration)) => SqliHttpResponse {
                    status_code: response.status_code,
                    body: String::from_utf8_lossy(&response.body).to_string(),
                    headers: response.headers.clone(),
                    response_time_ms: duration.as_millis() as u64,
                },
                Err(_) => SqliHttpResponse {
                    status_code: 0,
                    body: String::new(),
                    headers: std::collections::HashMap::new(),
                    response_time_ms: 0,
                },
            }
        };

        let result = scanner.scan_parameter(
            param_name,
            original_value,
            InjectionPoint::GetParam,
            send_request,
        );

        if result.detection.vulnerable {
            results.push(JsonValue::object(vec![
                (
                    "parameter".to_string(),
                    JsonValue::String(param_name.clone()),
                ),
                ("vulnerable".to_string(), JsonValue::Bool(true)),
                (
                    "technique".to_string(),
                    JsonValue::String(format!("{:?}", result.detection.technique)),
                ),
                (
                    "dbms".to_string(),
                    result
                        .detection
                        .dbms
                        .map(|d| JsonValue::String(format!("{:?}", d)))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "confidence".to_string(),
                    JsonValue::Number(result.detection.confidence as f64),
                ),
                (
                    "payload".to_string(),
                    result
                        .detection
                        .payload
                        .map(JsonValue::String)
                        .unwrap_or(JsonValue::Null),
                ),
            ]));
        }
    }

    let vuln_count = results.len();
    let text = if vuln_count > 0 {
        format!(
            "Found {} SQL injection vulnerabilities in {}",
            vuln_count, url
        )
    } else {
        format!("No SQL injection vulnerabilities found in {}", url)
    };

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("url".to_string(), JsonValue::String(url.to_string())),
            (
                "parameters_tested".to_string(),
                JsonValue::Number(params.len() as f64),
            ),
            (
                "vulnerabilities_found".to_string(),
                JsonValue::Number(vuln_count as f64),
            ),
            ("findings".to_string(), JsonValue::array(results)),
        ]),
    })
}

fn tool_sqli_payloads(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::web::sqli::{payloads_by_dbms, payloads_by_technique, total_payload_count};
    use crate::modules::web::{Dbms, SqliTechnique};

    let total = total_payload_count();

    // Filter by DBMS
    if let Some(dbms_str) = args.get("dbms").and_then(|v| v.as_str()) {
        let dbms = match dbms_str.to_lowercase().as_str() {
            "mysql" => Dbms::MySQL,
            "postgres" | "postgresql" => Dbms::PostgreSQL,
            "mssql" | "sqlserver" => Dbms::MsSQL,
            "oracle" => Dbms::Oracle,
            "sqlite" => Dbms::SQLite,
            _ => return Err(format!("Unknown DBMS: {}", dbms_str)),
        };

        let payloads = payloads_by_dbms(dbms);
        let payload_list: Vec<JsonValue> = payloads
            .iter()
            .take(20)
            .map(|p| {
                JsonValue::object(vec![
                    (
                        "payload".to_string(),
                        JsonValue::String(p.payload.to_string()),
                    ),
                    (
                        "risk".to_string(),
                        JsonValue::String(format!("{:?}", p.risk)),
                    ),
                ])
            })
            .collect();

        return Ok(ToolResult {
            text: format!("{} payloads for {:?}", payloads.len(), dbms),
            data: JsonValue::object(vec![
                ("dbms".to_string(), JsonValue::String(format!("{:?}", dbms))),
                (
                    "count".to_string(),
                    JsonValue::Number(payloads.len() as f64),
                ),
                ("payloads".to_string(), JsonValue::array(payload_list)),
            ]),
        });
    }

    // Filter by technique
    if let Some(tech_str) = args.get("technique").and_then(|v| v.as_str()) {
        let technique = match tech_str.to_lowercase().as_str() {
            "error" => SqliTechnique::ErrorBased,
            "blind" | "boolean" => SqliTechnique::BooleanBlind,
            "time" => SqliTechnique::TimeBlind,
            "union" => SqliTechnique::Union,
            "stacked" => SqliTechnique::Stacked,
            _ => return Err(format!("Unknown technique: {}", tech_str)),
        };

        let payloads = payloads_by_technique(technique);
        let payload_list: Vec<JsonValue> = payloads
            .iter()
            .take(20)
            .map(|p| {
                JsonValue::object(vec![
                    (
                        "payload".to_string(),
                        JsonValue::String(p.payload.to_string()),
                    ),
                    (
                        "dbms".to_string(),
                        JsonValue::String(format!("{:?}", p.dbms)),
                    ),
                ])
            })
            .collect();

        return Ok(ToolResult {
            text: format!("{} payloads for {:?}", payloads.len(), technique),
            data: JsonValue::object(vec![
                (
                    "technique".to_string(),
                    JsonValue::String(format!("{:?}", technique)),
                ),
                (
                    "count".to_string(),
                    JsonValue::Number(payloads.len() as f64),
                ),
                ("payloads".to_string(), JsonValue::array(payload_list)),
            ]),
        });
    }

    // Return summary
    Ok(ToolResult {
        text: format!("{} SQL injection payloads available", total),
        data: JsonValue::object(vec![
            ("total".to_string(), JsonValue::Number(total as f64)),
            (
                "by_dbms".to_string(),
                JsonValue::object(vec![
                    (
                        "mysql".to_string(),
                        JsonValue::Number(payloads_by_dbms(Dbms::MySQL).len() as f64),
                    ),
                    (
                        "postgres".to_string(),
                        JsonValue::Number(payloads_by_dbms(Dbms::PostgreSQL).len() as f64),
                    ),
                    (
                        "mssql".to_string(),
                        JsonValue::Number(payloads_by_dbms(Dbms::MsSQL).len() as f64),
                    ),
                    (
                        "oracle".to_string(),
                        JsonValue::Number(payloads_by_dbms(Dbms::Oracle).len() as f64),
                    ),
                    (
                        "sqlite".to_string(),
                        JsonValue::Number(payloads_by_dbms(Dbms::SQLite).len() as f64),
                    ),
                ]),
            ),
        ]),
    })
}

// =============================================================================
// NoSQL Injection Tools
// =============================================================================

fn tool_nosqli_test(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::web::{
        nosqli::techniques::HttpResponse as NoSqlHttpResponse, NoSqlDb, NoSqlInjectionPoint,
        NoSqlScanConfig, NoSqliScanner,
    };
    use crate::protocols::http::HttpClient;

    let url = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: url")?;

    let mut config = NoSqlScanConfig::default();

    // Apply DB filter
    if let Some(db_str) = args.get("db").and_then(|v| v.as_str()) {
        let db = match db_str.to_lowercase().as_str() {
            "mongodb" | "mongo" => NoSqlDb::MongoDB,
            "redis" => NoSqlDb::Redis,
            "elasticsearch" | "elastic" => NoSqlDb::Elasticsearch,
            "couchdb" | "couch" => NoSqlDb::CouchDB,
            _ => return Err(format!("Unknown database: {}", db_str)),
        };
        config.databases = vec![db];
    }

    // Parse URL parameters
    let params: Vec<(String, String)> = if let Some(query_start) = url.find('?') {
        url[query_start + 1..]
            .split('&')
            .filter_map(|pair| {
                pair.find('=')
                    .map(|eq| (pair[..eq].to_string(), pair[eq + 1..].to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    if params.is_empty() {
        return Err("No parameters found in URL".to_string());
    }

    let only_param = args.get("param").and_then(|v| v.as_str());
    let scanner = NoSqliScanner::new(config);
    let client = HttpClient::new();

    let mut results = Vec::new();

    for (param_name, original_value) in &params {
        if let Some(only) = only_param {
            if !param_name.to_lowercase().contains(&only.to_lowercase()) {
                continue;
            }
        }

        let url_clone = url.to_string();
        let param_clone = param_name.clone();
        let client_ref = &client;

        let send_request = |payload: &str| -> NoSqlHttpResponse {
            let test_url = replace_param(&url_clone, &param_clone, payload);
            match client_ref.send_with_metrics(&crate::protocols::http::HttpRequest::get(&test_url))
            {
                Ok((response, duration)) => NoSqlHttpResponse {
                    status: response.status_code,
                    body: String::from_utf8_lossy(&response.body).to_string(),
                    headers: response.headers.clone(),
                    response_time_ms: duration.as_millis() as u64,
                    content_length: response.body.len(),
                },
                Err(_) => NoSqlHttpResponse {
                    status: 0,
                    body: String::new(),
                    headers: std::collections::HashMap::new(),
                    response_time_ms: 0,
                    content_length: 0,
                },
            }
        };

        let result = scanner.scan_parameter(
            url,
            param_name,
            original_value,
            NoSqlInjectionPoint::GetParam,
            send_request,
        );

        if result.vulnerable {
            results.push(JsonValue::object(vec![
                (
                    "parameter".to_string(),
                    JsonValue::String(param_name.clone()),
                ),
                ("vulnerable".to_string(), JsonValue::Bool(true)),
                (
                    "database".to_string(),
                    result
                        .database
                        .map(|d| JsonValue::String(d.to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "technique".to_string(),
                    result
                        .technique
                        .map(|t| JsonValue::String(t.to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "confidence".to_string(),
                    JsonValue::Number(result.confidence),
                ),
            ]));
        }
    }

    let vuln_count = results.len();
    let text = if vuln_count > 0 {
        format!(
            "Found {} NoSQL injection vulnerabilities in {}",
            vuln_count, url
        )
    } else {
        format!("No NoSQL injection vulnerabilities found in {}", url)
    };

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("url".to_string(), JsonValue::String(url.to_string())),
            (
                "parameters_tested".to_string(),
                JsonValue::Number(params.len() as f64),
            ),
            (
                "vulnerabilities_found".to_string(),
                JsonValue::Number(vuln_count as f64),
            ),
            ("findings".to_string(), JsonValue::array(results)),
        ]),
    })
}

/// Replace a URL parameter value (helper for NoSQLi)
fn replace_param(url: &str, param: &str, value: &str) -> String {
    if let Some(query_start) = url.find('?') {
        let base = &url[..query_start];
        let query = &url[query_start + 1..];

        let new_query: Vec<String> = query
            .split('&')
            .map(|pair| {
                if let Some(eq_pos) = pair.find('=') {
                    let name = &pair[..eq_pos];
                    if name == param {
                        return format!("{}={}", name, url_encode(value));
                    }
                }
                pair.to_string()
            })
            .collect();

        format!("{}?{}", base, new_query.join("&"))
    } else {
        url.to_string()
    }
}

/// URL encode a string
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

// =============================================================================
// Git Exposed Tools
// =============================================================================

fn tool_git_scan(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::web::git_exposed::{GitScanner, ScanConfig};

    let url = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: url")?;

    let scan_secrets = args
        .get("scan_secrets")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut config = ScanConfig::default();
    config.scan_secrets = scan_secrets;

    let scanner = GitScanner::new(config);

    match scanner.scan(url) {
        Ok(result) => {
            let status_str = result.status.as_str();
            let is_vulnerable = result.is_vulnerable();
            let severity = format!("{:?}", result.severity);

            let counts = result.object_counts();
            let objects_json: Vec<JsonValue> = counts
                .iter()
                .map(|(obj_type, count)| {
                    JsonValue::object(vec![
                        (
                            "type".to_string(),
                            JsonValue::String(format!("{:?}", obj_type)),
                        ),
                        ("count".to_string(), JsonValue::Number(*count as f64)),
                    ])
                })
                .collect();

            let secrets_json: Vec<JsonValue> = result
                .secrets
                .iter()
                .take(10)
                .map(|s| {
                    JsonValue::object(vec![
                        ("type".to_string(), JsonValue::String(s.secret_type.clone())),
                        ("path".to_string(), JsonValue::String(s.path.clone())),
                        ("line".to_string(), JsonValue::Number(s.line as f64)),
                    ])
                })
                .collect();

            let text = if is_vulnerable {
                format!(
                    "VULNERABLE: .git directory exposed at {} ({})",
                    url, severity
                )
            } else {
                format!("Not vulnerable: {} at {}", status_str, url)
            };

            Ok(ToolResult {
                text,
                data: JsonValue::object(vec![
                    ("url".to_string(), JsonValue::String(url.to_string())),
                    (
                        "status".to_string(),
                        JsonValue::String(status_str.to_string()),
                    ),
                    ("vulnerable".to_string(), JsonValue::Bool(is_vulnerable)),
                    ("severity".to_string(), JsonValue::String(severity)),
                    ("objects".to_string(), JsonValue::array(objects_json)),
                    (
                        "secrets_found".to_string(),
                        JsonValue::Number(result.secrets.len() as f64),
                    ),
                    ("secrets".to_string(), JsonValue::array(secrets_json)),
                    (
                        "recovery_percent".to_string(),
                        JsonValue::Number(result.recovery_percent as f64),
                    ),
                ]),
            })
        }
        Err(e) => Err(format!("Scan failed: {:?}", e)),
    }
}
