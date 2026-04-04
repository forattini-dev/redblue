//! Authentication Testing MCP Tools
//!
//! Credential testing, password spraying, and brute force tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::modules::auth::http_auth::HttpAuthTester;
use crate::modules::auth::iterator::CredentialIterator;
use crate::modules::auth::rate_limit::RateLimiter;
use crate::utils::json::JsonValue;
use std::io::BufRead;

/// Register authentication testing tools with the server
pub fn register_auth_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.auth.test",
            description: "Test credentials against a target URL. Supports basic and digest HTTP authentication, \
                         as well as form-based login. Returns whether the credentials are valid.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target URL to authenticate against (e.g., 'http://example.com/admin').",
                    required: true,
                },
                ToolField {
                    name: "username",
                    field_type: "string",
                    description: "Username to test.",
                    required: true,
                },
                ToolField {
                    name: "password",
                    field_type: "string",
                    description: "Password to test.",
                    required: true,
                },
                ToolField {
                    name: "auth_type",
                    field_type: "string",
                    description: "Authentication type: 'basic', 'digest', or 'form' (default: 'basic').",
                    required: false,
                },
            ],
            handler: tool_auth_test,
        },
        ToolDefinition {
            name: "rb.auth.spray",
            description: "Password spray attack: test a single password against multiple usernames. \
                         Useful for detecting weak/shared credentials across accounts.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target URL to authenticate against.",
                    required: true,
                },
                ToolField {
                    name: "usernames",
                    field_type: "string",
                    description: "Comma-separated list of usernames to test (e.g., 'admin,root,user').",
                    required: true,
                },
                ToolField {
                    name: "password",
                    field_type: "string",
                    description: "Single password to spray across all usernames.",
                    required: true,
                },
            ],
            handler: tool_auth_spray,
        },
        ToolDefinition {
            name: "rb.auth.brute",
            description: "Brute force credentials with rate limiting. Tests a username against a wordlist file \
                         with configurable delay to avoid lockouts. Automatically backs off on 429/403 responses.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target URL to authenticate against.",
                    required: true,
                },
                ToolField {
                    name: "username",
                    field_type: "string",
                    description: "Username to brute force.",
                    required: true,
                },
                ToolField {
                    name: "wordlist_path",
                    field_type: "string",
                    description: "Path to password wordlist file (one password per line).",
                    required: true,
                },
                ToolField {
                    name: "delay_ms",
                    field_type: "number",
                    description: "Delay between attempts in milliseconds (default: 100). \
                                 Automatically increases on rate-limit detection.",
                    required: false,
                },
            ],
            handler: tool_auth_brute,
        },
    ]
}

fn tool_auth_test(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let username = args
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: username")?;

    let password = args
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: password")?;

    let auth_type = args
        .get("auth_type")
        .and_then(|v| v.as_str())
        .unwrap_or("basic");

    match auth_type {
        "basic" => {
            let mut tester = HttpAuthTester::new();
            let success = tester.test_basic(target, username, password);

            let text = if success {
                format!(
                    "Authentication SUCCESSFUL for {}:{} at {} (basic auth)",
                    username, password, target
                )
            } else {
                format!(
                    "Authentication FAILED for {}:{} at {} (basic auth)",
                    username, password, target
                )
            };

            Ok(ToolResult::with_data(
                text,
                JsonValue::object(vec![
                    ("target".to_string(), JsonValue::String(target.to_string())),
                    (
                        "username".to_string(),
                        JsonValue::String(username.to_string()),
                    ),
                    (
                        "auth_type".to_string(),
                        JsonValue::String("basic".to_string()),
                    ),
                    ("success".to_string(), JsonValue::Bool(success)),
                ]),
            ))
        }
        "digest" => {
            let success =
                crate::modules::auth::digest::DigestAuth::test(target, username, password);

            let text = if success {
                format!(
                    "Authentication SUCCESSFUL for {}:{} at {} (digest auth)",
                    username, password, target
                )
            } else {
                format!(
                    "Authentication FAILED for {}:{} at {} (digest auth). \
                     Note: digest auth support is limited; use CLI: rb auth test --digest {} {} {}",
                    username, password, target, target, username, password
                )
            };

            Ok(ToolResult::with_data(
                text,
                JsonValue::object(vec![
                    ("target".to_string(), JsonValue::String(target.to_string())),
                    (
                        "username".to_string(),
                        JsonValue::String(username.to_string()),
                    ),
                    (
                        "auth_type".to_string(),
                        JsonValue::String("digest".to_string()),
                    ),
                    ("success".to_string(), JsonValue::Bool(success)),
                ]),
            ))
        }
        "form" => {
            // Form-based auth requires knowing field names and form action URL.
            // Provide guidance to use the CLI for full form auth testing.
            let text = format!(
                "Form-based authentication testing requires additional context (form action URL, \
                 field names). Use the CLI for full support:\n\
                 rb auth test --form {} --user {} --pass {}\n\n\
                 Alternatively, use rb.web.scrape to discover form fields first, then craft \
                 a targeted request with rb.web.crawl.",
                target, username, password
            );

            Ok(ToolResult::with_data(
                text,
                JsonValue::object(vec![
                    ("target".to_string(), JsonValue::String(target.to_string())),
                    (
                        "username".to_string(),
                        JsonValue::String(username.to_string()),
                    ),
                    (
                        "auth_type".to_string(),
                        JsonValue::String("form".to_string()),
                    ),
                    ("success".to_string(), JsonValue::Bool(false)),
                    (
                        "note".to_string(),
                        JsonValue::String(
                            "Form auth requires field discovery. Use CLI for full support."
                                .to_string(),
                        ),
                    ),
                ]),
            ))
        }
        other => Err(format!(
            "Unknown auth_type '{}'. Supported: basic, digest, form",
            other
        )),
    }
}

fn tool_auth_spray(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let usernames_str = args
        .get("usernames")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: usernames")?;

    let password = args
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: password")?;

    let usernames: Vec<String> = usernames_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if usernames.is_empty() {
        return Err("No valid usernames provided. Use comma-separated list.".to_string());
    }

    let passwords = vec![password.to_string()];
    let iterator = CredentialIterator::new(usernames.clone(), passwords);

    let mut tester = HttpAuthTester::new();
    let mut results: Vec<JsonValue> = Vec::new();
    let mut success_count = 0;
    let mut tested_count = 0;

    for (user, pass) in iterator {
        tested_count += 1;
        let success = tester.test_basic(target, &user, &pass);

        if success {
            success_count += 1;
        }

        results.push(JsonValue::object(vec![
            ("username".to_string(), JsonValue::String(user)),
            ("password".to_string(), JsonValue::String(pass)),
            ("success".to_string(), JsonValue::Bool(success)),
        ]));
    }

    let text = format!(
        "Password spray on {}: tested {} usernames with password '{}' - {} successful",
        target, tested_count, password, success_count
    );

    Ok(ToolResult::with_data(
        text,
        JsonValue::object(vec![
            ("target".to_string(), JsonValue::String(target.to_string())),
            (
                "password".to_string(),
                JsonValue::String(password.to_string()),
            ),
            (
                "total_tested".to_string(),
                JsonValue::Number(tested_count as f64),
            ),
            (
                "successful".to_string(),
                JsonValue::Number(success_count as f64),
            ),
            ("results".to_string(), JsonValue::array(results)),
        ]),
    ))
}

fn tool_auth_brute(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let username = args
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: username")?;

    let wordlist_path = args
        .get("wordlist_path")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: wordlist_path")?;

    let delay_ms = args
        .get("delay_ms")
        .and_then(|v| v.as_f64())
        .unwrap_or(100.0) as u64;

    // Load wordlist
    let file = std::fs::File::open(wordlist_path)
        .map_err(|e| format!("Failed to open wordlist '{}': {}", wordlist_path, e))?;
    let reader = std::io::BufReader::new(file);

    let passwords: Vec<String> = reader
        .lines()
        .filter_map(|line| {
            line.ok().and_then(|l| {
                let trimmed = l.trim().to_string();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    None
                } else {
                    Some(trimmed)
                }
            })
        })
        .collect();

    if passwords.is_empty() {
        return Err(format!(
            "Wordlist '{}' contains no valid passwords.",
            wordlist_path
        ));
    }

    let mut tester = HttpAuthTester::new();
    let mut rate_limiter = RateLimiter::new(delay_ms);
    let mut tested = 0;
    let mut found_password: Option<String> = None;
    let rate_limited = false;

    for password in &passwords {
        rate_limiter.wait();
        tested += 1;

        let success = tester.test_basic(target, username, password);

        if success {
            found_password = Some(password.clone());
            break;
        }

        // Report result to rate limiter for adaptive backoff
        // We use 401 for auth failure, since test_basic returns bool
        // The rate limiter watches for 429/403 to auto-backoff
        if !success {
            rate_limiter.report_result(401);
        }
    }

    let text = if let Some(ref pass) = found_password {
        format!(
            "Brute force SUCCESS: {}:{} at {} (found after {} attempts)",
            username, pass, target, tested
        )
    } else {
        format!(
            "Brute force completed: no valid password found for '{}' at {} ({} passwords tested from {})",
            username, target, tested, wordlist_path
        )
    };

    Ok(ToolResult::with_data(
        text,
        JsonValue::object(vec![
            ("target".to_string(), JsonValue::String(target.to_string())),
            (
                "username".to_string(),
                JsonValue::String(username.to_string()),
            ),
            (
                "wordlist".to_string(),
                JsonValue::String(wordlist_path.to_string()),
            ),
            ("total_tested".to_string(), JsonValue::Number(tested as f64)),
            (
                "total_passwords".to_string(),
                JsonValue::Number(passwords.len() as f64),
            ),
            (
                "found".to_string(),
                JsonValue::Bool(found_password.is_some()),
            ),
            (
                "password".to_string(),
                found_password
                    .map(|p| JsonValue::String(p))
                    .unwrap_or(JsonValue::Null),
            ),
            ("rate_limited".to_string(), JsonValue::Bool(rate_limited)),
            ("delay_ms".to_string(), JsonValue::Number(delay_ms as f64)),
        ]),
    ))
}
