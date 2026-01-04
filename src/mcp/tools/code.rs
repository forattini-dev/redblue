//! Code MCP Tools
//!
//! Secret scanning and validation, code analysis tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register code analysis tools with the server
pub fn register_code_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.code.secrets",
            description: "Scan files or directories for secrets like API keys, tokens, and credentials.",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "File or directory path to scan.",
                    required: true,
                },
                ToolField {
                    name: "include",
                    field_type: "array",
                    description: "File patterns to include (e.g., ['*.py', '*.js']).",
                    required: false,
                },
                ToolField {
                    name: "exclude",
                    field_type: "array",
                    description: "File patterns to exclude (e.g., ['*.min.js', 'node_modules']).",
                    required: false,
                },
                ToolField {
                    name: "redact",
                    field_type: "boolean",
                    description: "Redact actual secret values in output (default: true).",
                    required: false,
                },
            ],
            handler: tool_code_secrets,
        },
        ToolDefinition {
            name: "rb.secrets.validate",
            description: "Validate a secret (API key, token) against its provider API to check if it's active.",
            fields: &[
                ToolField {
                    name: "secret",
                    field_type: "string",
                    description: "The secret value to validate.",
                    required: true,
                },
                ToolField {
                    name: "provider",
                    field_type: "string",
                    description: "Provider name (github, stripe, openai, etc.). Auto-detected if omitted.",
                    required: false,
                },
            ],
            handler: tool_secrets_validate,
        },
        ToolDefinition {
            name: "rb.secrets.providers",
            description: "List all supported secret validation providers.",
            fields: &[],
            handler: tool_secrets_providers,
        },
    ]
}

fn tool_code_secrets(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::code::secrets::{ScannerConfig, SecretsScanner};

    let path_str = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: path")?;

    let redact = args.get("redact").and_then(|v| v.as_bool()).unwrap_or(true);

    let include_patterns: Vec<String> = args
        .get("include")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let exclude_patterns: Vec<String> = args
        .get("exclude")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "*.min.js".to_string(),
                "*.min.css".to_string(),
            ]
        });

    let config = ScannerConfig {
        include_patterns,
        exclude_patterns,
        ..Default::default()
    };

    let scanner = SecretsScanner::new(config);
    let path = std::path::Path::new(path_str);

    let findings = if path.is_dir() {
        let (findings, _summary) = scanner.scan_directory(path);
        findings
    } else if path.is_file() {
        scanner.scan_file(path)
    } else {
        return Err(format!("Path does not exist: {}", path_str));
    };

    let findings_json: Vec<JsonValue> = findings
        .iter()
        .map(|f| {
            let finding = if redact { f.redacted() } else { f.clone() };
            JsonValue::object(vec![
                (
                    "type".to_string(),
                    JsonValue::String(finding.secret_type.clone()),
                ),
                (
                    "severity".to_string(),
                    JsonValue::String(finding.severity.to_string()),
                ),
                (
                    "file".to_string(),
                    JsonValue::String(finding.file_path.display().to_string()),
                ),
                (
                    "line".to_string(),
                    JsonValue::Number(finding.line_number as f64),
                ),
                (
                    "match".to_string(),
                    JsonValue::String(finding.match_text.clone()),
                ),
                (
                    "confidence".to_string(),
                    JsonValue::Number(finding.confidence),
                ),
            ])
        })
        .collect();

    let text = format!("Found {} secrets in {}", findings.len(), path_str);

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "count".to_string(),
                JsonValue::Number(findings.len() as f64),
            ),
            ("path".to_string(), JsonValue::String(path_str.to_string())),
            ("findings".to_string(), JsonValue::array(findings_json)),
        ]),
    })
}

fn tool_secrets_validate(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::code::secrets::{SecretValidator, ValidationStatus};

    let secret = args
        .get("secret")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: secret")?;

    let provider = args
        .get("provider")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let provider_name = match provider {
        Some(p) => p,
        None => detect_provider(secret)
            .ok_or("Could not auto-detect provider. Please specify --provider.")?,
    };

    let validator = SecretValidator::new();
    let result = validator.validate(secret, &provider_name);

    let status_str = match result.status {
        ValidationStatus::Valid => "valid",
        ValidationStatus::Invalid => "invalid",
        ValidationStatus::RateLimited => "rate_limited",
        ValidationStatus::Error => "error",
        ValidationStatus::Unsupported => "unsupported",
        ValidationStatus::IncompleteParams => "incomplete_params",
    };

    let redacted = if secret.len() > 8 {
        format!("{}...{}", &secret[..4], &secret[secret.len() - 4..])
    } else {
        "****".to_string()
    };

    let text = format!(
        "Secret {} is {} for provider {}",
        redacted,
        status_str.to_uppercase(),
        result.provider
    );

    let info_items: Vec<JsonValue> = result
        .info
        .iter()
        .map(|(k, v)| {
            JsonValue::object(vec![
                ("key".to_string(), JsonValue::String(k.clone())),
                ("value".to_string(), JsonValue::String(v.clone())),
            ])
        })
        .collect();

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("provider".to_string(), JsonValue::String(result.provider)),
            ("is_valid".to_string(), JsonValue::Bool(result.is_valid)),
            (
                "status".to_string(),
                JsonValue::String(status_str.to_string()),
            ),
            ("info".to_string(), JsonValue::array(info_items)),
            (
                "response_time_ms".to_string(),
                JsonValue::Number(result.response_time_ms as f64),
            ),
            (
                "error".to_string(),
                result
                    .error
                    .map(JsonValue::String)
                    .unwrap_or(JsonValue::Null),
            ),
        ]),
    })
}

fn tool_secrets_providers(
    _server: &mut McpServer,
    _args: &JsonValue,
) -> Result<ToolResult, String> {
    use crate::modules::code::secrets::validator::PROVIDERS;

    let providers: Vec<JsonValue> = PROVIDERS
        .iter()
        .map(|p| JsonValue::String(p.name.to_string()))
        .collect();

    let text = format!("{} secret validation providers available", PROVIDERS.len());

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "count".to_string(),
                JsonValue::Number(PROVIDERS.len() as f64),
            ),
            ("providers".to_string(), JsonValue::array(providers)),
        ]),
    })
}

/// Auto-detect provider from secret format
fn detect_provider(secret: &str) -> Option<String> {
    let prefixes = [
        ("ghp_", "github"),
        ("gho_", "github"),
        ("ghs_", "github"),
        ("github_pat_", "github"),
        ("glpat-", "gitlab"),
        ("sk_live_", "stripe"),
        ("sk_test_", "stripe"),
        ("xoxb-", "slack"),
        ("xoxp-", "slack"),
        ("sk-", "openai"),
        ("sk-ant-", "anthropic"),
        ("SG.", "sendgrid"),
        ("npm_", "npm"),
        ("hf_", "huggingface"),
        ("r8_", "replicate"),
        ("AKIA", "aws"),
        ("AIza", "gcp"),
    ];

    for (prefix, provider) in prefixes {
        if secret.starts_with(prefix) {
            return Some(provider.to_string());
        }
    }

    None
}
