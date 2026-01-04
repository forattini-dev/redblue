/// NoSQL Injection testing command - MongoDB, Redis, Elasticsearch vulnerability testing
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::CliContext;
use crate::modules::web::{
    nosqli::payloads::{
        payloads_by_technique, payloads_for_db, total_payload_count, NoSqlTechnique,
    },
    nosqli::techniques::HttpResponse as NoSqlHttpResponse,
    NoSqlDb, NoSqlInjectionPoint, NoSqlScanConfig, NoSqliScanner,
};
use crate::protocols::http::HttpClient;

pub struct NoSqliCommand;

impl Command for NoSqliCommand {
    fn domain(&self) -> &str {
        "web"
    }

    fn resource(&self) -> &str {
        "nosqli"
    }

    fn description(&self) -> &str {
        "NoSQL injection testing (MongoDB, Redis, Elasticsearch)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "test",
                summary: "Test URL parameters for NoSQL injection",
                usage: "rb web nosqli test <url> [--param <name>]",
            },
            Route {
                verb: "payloads",
                summary: "List available NoSQL injection payloads",
                usage: "rb web nosqli payloads [--db mongodb] [--technique auth-bypass]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("param", "Test only this parameter").with_short('p'),
            Flag::new(
                "db",
                "Target specific DB (mongodb|redis|elasticsearch|couchdb|cassandra)",
            )
            .with_short('d'),
            Flag::new(
                "technique",
                "NoSQLi technique (operator|javascript|auth-bypass|command|query-dsl|blind|error)",
            )
            .with_short('T'),
            Flag::new("level", "Scan level: quick|standard|thorough")
                .with_short('l')
                .with_default("standard"),
            Flag::new("timeout", "Request timeout in seconds").with_default("30"),
            Flag::new("auth-bypass", "Test authentication bypass payloads"),
            Flag::new("cookie", "Cookie header value").with_short('c'),
            Flag::new("header", "Custom header (Name: Value)").with_short('H'),
            Flag::new("json", "Test JSON body instead of URL params"),
            Flag::new("format", "Output format (text|json)")
                .with_short('f')
                .with_default("text"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Test URL for NoSQLi",
                "rb web nosqli test 'http://api.site/users?id=1'",
            ),
            (
                "Test specific parameter",
                "rb web nosqli test 'http://api.site/search?q=test' --param q",
            ),
            (
                "Test with MongoDB payloads only",
                "rb web nosqli test 'http://api.site/login' --db mongodb",
            ),
            (
                "Test authentication bypass",
                "rb web nosqli test 'http://api.site/login' --auth-bypass",
            ),
            (
                "Thorough Redis scan",
                "rb web nosqli test 'http://api.site/cache?key=x' --db redis --level thorough",
            ),
            ("List all payloads", "rb web nosqli payloads"),
            (
                "List MongoDB payloads",
                "rb web nosqli payloads --db mongodb",
            ),
            (
                "List auth bypass payloads",
                "rb web nosqli payloads --technique auth-bypass",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "Missing verb. Use: rb web nosqli <test|payloads>".to_string()
        })?;

        match verb.as_str() {
            "test" => self.test_nosqli(ctx),
            "payloads" => self.list_payloads(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!("Unknown verb '{}'. Use: rb web nosqli help", verb)),
        }
    }
}

impl NoSqliCommand {
    /// Test URL for NoSQL injection vulnerabilities
    fn test_nosqli(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx
            .args
            .first()
            .ok_or("Missing URL. Usage: rb web nosqli test <url>")?;

        // Build scan config
        let level = ctx
            .flags
            .get("level")
            .map(|s| s.as_str())
            .unwrap_or("standard");
        let mut config = match level {
            "quick" => NoSqlScanConfig::quick(),
            "thorough" => NoSqlScanConfig::thorough(),
            _ => NoSqlScanConfig::default(),
        };

        // Apply DB filter
        if let Some(db_str) = ctx.flags.get("db") {
            let db = parse_db(db_str)?;
            config.databases = vec![db];
        }

        // Auth bypass
        if ctx.flags.contains_key("auth-bypass") {
            config.auth_bypass = true;
        }

        // Add headers
        if let Some(header) = ctx.flags.get("header") {
            if let Some(colon_pos) = header.find(':') {
                let name = header[..colon_pos].trim().to_string();
                let value = header[colon_pos + 1..].trim().to_string();
                config.headers.insert(name, value);
            }
        }

        // Add cookie
        if let Some(cookie) = ctx.flags.get("cookie") {
            config.headers.insert("Cookie".to_string(), cookie.clone());
        }

        let db_list: Vec<_> = config.databases.iter().map(|d| d.as_str()).collect();
        println!("\n\x1b[1;36m\u{25b6} NoSQL Injection Test\x1b[0m");
        println!("  Target: {}", url);
        println!("  Level: {}", level);
        println!("  Databases: {}", db_list.join(", "));
        println!();

        // Parse URL parameters
        let params = parse_url_params(url);
        if params.is_empty() {
            return Err("No parameters found in URL. Add ?param=value to the URL.".to_string());
        }

        println!("  Parameters found: {}", params.len());
        for (name, value) in &params {
            println!("    \u{2022} {} = {}", name, value);
        }
        println!();

        // Create scanner
        let scanner = NoSqliScanner::new(config);

        // Create HTTP client for sending requests
        let client = HttpClient::new();

        let mut vulnerabilities_found = 0;
        let mut tested = 0;

        // Filter to specific param if requested
        let only_param = ctx.flags.get("param");

        for (param_name, original_value) in &params {
            // Check only list
            if let Some(only) = only_param {
                if !param_name.to_lowercase().contains(&only.to_lowercase()) {
                    continue;
                }
            }

            tested += 1;
            print!("  Testing parameter '{}' ... ", param_name);

            // Create the send_request closure
            let url_clone = url.to_string();
            let param_clone = param_name.clone();
            let client_ref = &client;

            let send_request = |payload: &str| -> NoSqlHttpResponse {
                let test_url = replace_param(&url_clone, &param_clone, payload);

                match client_ref
                    .send_with_metrics(&crate::protocols::http::HttpRequest::get(&test_url))
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
                vulnerabilities_found += 1;
                println!("\x1b[31mVULNERABLE\x1b[0m");
                if let Some(db) = result.database {
                    println!("    Database: {}", db);
                }
                if let Some(technique) = result.technique {
                    println!("    Technique: {}", technique);
                }
                if let Some(ref payload) = result.payload {
                    println!("    Payload: {}", payload);
                }
                println!("    Confidence: {:.0}%", result.confidence * 100.0);
                if !result.evidence.is_empty() {
                    println!("    Evidence: {}", result.evidence);
                }
            } else {
                println!("\x1b[32mOK\x1b[0m");
            }
        }

        println!();
        println!("\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}");
        if vulnerabilities_found > 0 {
            println!(
                "\x1b[31m\u{26a0} Found {} vulnerable parameter(s) out of {} tested\x1b[0m",
                vulnerabilities_found, tested
            );

            // Emit synergy events for findings
            // Note: Would call NoSqliScanner::emit_synergy_events() here in production
        } else {
            println!(
                "\x1b[32m\u{2713} No NoSQL injection vulnerabilities found ({} parameters tested)\x1b[0m",
                tested
            );
        }
        println!();

        Ok(())
    }

    /// List available payloads
    fn list_payloads(&self, ctx: &CliContext) -> Result<(), String> {
        println!("\n\x1b[1;36m\u{25b6} NoSQL Injection Payloads\x1b[0m");
        println!("  Total: {} payloads\n", total_payload_count());

        // Filter by DB
        if let Some(db_str) = ctx.flags.get("db") {
            let db = parse_db(db_str)?;
            let payloads = payloads_for_db(db);
            println!("  {} payloads: {}", db, payloads.len());
            for (i, p) in payloads.iter().take(20).enumerate() {
                println!("    {}. {} (risk: {:?})", i + 1, p.payload, p.risk);
            }
            if payloads.len() > 20 {
                println!("    ... and {} more", payloads.len() - 20);
            }
            return Ok(());
        }

        // Filter by technique
        if let Some(tech_str) = ctx.flags.get("technique") {
            let technique = parse_technique(tech_str)?;
            let payloads = payloads_by_technique(technique);
            println!("  {:?} payloads: {}", technique, payloads.len());
            for (i, p) in payloads.iter().take(20).enumerate() {
                println!("    {}. {} (db: {:?})", i + 1, p.payload, p.database);
            }
            if payloads.len() > 20 {
                println!("    ... and {} more", payloads.len() - 20);
            }
            return Ok(());
        }

        // Show summary by database
        println!("  By Database:");
        for db in [
            NoSqlDb::MongoDB,
            NoSqlDb::Redis,
            NoSqlDb::Elasticsearch,
            NoSqlDb::CouchDB,
            NoSqlDb::Cassandra,
        ] {
            let count = payloads_for_db(db).len();
            println!("    {}: {} payloads", db, count);
        }

        println!("\n  By Technique:");
        for technique in [
            NoSqlTechnique::OperatorInjection,
            NoSqlTechnique::JavaScriptInjection,
            NoSqlTechnique::AuthBypass,
            NoSqlTechnique::CommandInjection,
            NoSqlTechnique::QueryDslInjection,
            NoSqlTechnique::BlindInjection,
            NoSqlTechnique::ErrorBased,
        ] {
            let count = payloads_by_technique(technique).len();
            println!("    {}: {} payloads", technique, count);
        }

        println!("\n  Use --db or --technique to filter payloads");
        Ok(())
    }
}

fn parse_db(s: &str) -> Result<NoSqlDb, String> {
    match s.to_lowercase().as_str() {
        "mongodb" | "mongo" => Ok(NoSqlDb::MongoDB),
        "redis" => Ok(NoSqlDb::Redis),
        "elasticsearch" | "elastic" | "es" => Ok(NoSqlDb::Elasticsearch),
        "couchdb" | "couch" => Ok(NoSqlDb::CouchDB),
        "cassandra" => Ok(NoSqlDb::Cassandra),
        _ => Err(format!(
            "Unknown database '{}'. Use: mongodb|redis|elasticsearch|couchdb|cassandra",
            s
        )),
    }
}

fn parse_technique(s: &str) -> Result<NoSqlTechnique, String> {
    match s.to_lowercase().as_str() {
        "operator" | "operator-injection" => Ok(NoSqlTechnique::OperatorInjection),
        "javascript" | "js" | "javascript-injection" => Ok(NoSqlTechnique::JavaScriptInjection),
        "auth-bypass" | "auth" | "bypass" => Ok(NoSqlTechnique::AuthBypass),
        "command" | "command-injection" => Ok(NoSqlTechnique::CommandInjection),
        "query-dsl" | "dsl" | "query" => Ok(NoSqlTechnique::QueryDslInjection),
        "blind" | "blind-injection" => Ok(NoSqlTechnique::BlindInjection),
        "error" | "error-based" => Ok(NoSqlTechnique::ErrorBased),
        _ => Err(format!(
            "Unknown technique '{}'. Use: operator|javascript|auth-bypass|command|query-dsl|blind|error",
            s
        )),
    }
}

/// Parse URL query parameters
fn parse_url_params(url: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();

    if let Some(query_start) = url.find('?') {
        let query = &url[query_start + 1..];

        for pair in query.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let name = pair[..eq_pos].to_string();
                let value = pair[eq_pos + 1..].to_string();
                params.push((name, value));
            }
        }
    }

    params
}

/// Replace a URL parameter value
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
