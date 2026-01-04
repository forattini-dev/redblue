//! Helper functions for MCP server tool handlers

use crate::modules::recon::vuln::osv::Ecosystem;
use crate::utils::json::JsonValue;

/// Convert a Vulnerability to JSON representation
pub fn vuln_to_json(vuln: &crate::modules::recon::vuln::Vulnerability) -> JsonValue {
    let exploits_json: Vec<JsonValue> = vuln
        .exploits
        .iter()
        .map(|e| {
            JsonValue::object(vec![
                ("source".to_string(), JsonValue::String(e.source.clone())),
                ("url".to_string(), JsonValue::String(e.url.clone())),
                (
                    "title".to_string(),
                    e.title
                        .as_ref()
                        .map(|t| JsonValue::String(t.clone()))
                        .unwrap_or(JsonValue::Null),
                ),
            ])
        })
        .collect();

    JsonValue::object(vec![
        ("id".to_string(), JsonValue::String(vuln.id.clone())),
        ("title".to_string(), JsonValue::String(vuln.title.clone())),
        (
            "description".to_string(),
            JsonValue::String(vuln.description.clone()),
        ),
        (
            "cvss_v3".to_string(),
            vuln.cvss_v3
                .map(|s| JsonValue::Number(s as f64))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "severity".to_string(),
            JsonValue::String(vuln.severity.as_str().to_string()),
        ),
        (
            "risk_score".to_string(),
            vuln.risk_score
                .map(|s| JsonValue::Number(s as f64))
                .unwrap_or(JsonValue::Null),
        ),
        ("cisa_kev".to_string(), JsonValue::Bool(vuln.cisa_kev)),
        (
            "kev_due_date".to_string(),
            vuln.kev_due_date
                .as_ref()
                .map(|d| JsonValue::String(d.clone()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "has_exploit".to_string(),
            JsonValue::Bool(vuln.has_exploit()),
        ),
        ("exploits".to_string(), JsonValue::array(exploits_json)),
        (
            "published".to_string(),
            vuln.published
                .as_ref()
                .map(|p| JsonValue::String(p.clone()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "cwes".to_string(),
            JsonValue::array(
                vuln.cwes
                    .iter()
                    .map(|c| JsonValue::String(c.clone()))
                    .collect(),
            ),
        ),
    ])
}

/// Map technology name to OSV ecosystem
pub fn map_tech_to_ecosystem(tech_name: &str) -> Ecosystem {
    let name_lower = tech_name.to_lowercase();
    if name_lower.contains("node")
        || name_lower.contains("npm")
        || name_lower.contains("express")
        || name_lower.contains("react")
        || name_lower.contains("vue")
        || name_lower.contains("angular")
        || name_lower.contains("jquery")
        || name_lower.contains("lodash")
    {
        Ecosystem::Npm
    } else if name_lower.contains("python")
        || name_lower.contains("django")
        || name_lower.contains("flask")
        || name_lower.contains("fastapi")
    {
        Ecosystem::PyPI
    } else if name_lower.contains("rust") || name_lower.contains("cargo") {
        Ecosystem::Cargo
    } else if name_lower.contains("ruby") || name_lower.contains("rails") {
        Ecosystem::RubyGems
    } else if name_lower.contains("go") || name_lower.contains("golang") {
        Ecosystem::Go
    } else if name_lower.contains("java")
        || name_lower.contains("maven")
        || name_lower.contains("spring")
    {
        Ecosystem::Maven
    } else if name_lower.contains("nuget")
        || name_lower.contains(".net")
        || name_lower.contains("dotnet")
    {
        Ecosystem::NuGet
    } else if name_lower.contains("php")
        || name_lower.contains("composer")
        || name_lower.contains("laravel")
        || name_lower.contains("wordpress")
        || name_lower.contains("drupal")
    {
        Ecosystem::Packagist
    } else {
        Ecosystem::Npm // Default to npm for JS-related technologies
    }
}

/// Parse command arguments from JSON (argv array or command string)
pub fn parse_command_arguments(args: &JsonValue) -> Result<Vec<String>, String> {
    if let Some(array) = args.get("argv").and_then(|value| value.as_array()) {
        let mut result = Vec::with_capacity(array.len());
        for value in array {
            let s = value
                .as_str()
                .ok_or_else(|| "argv elements must be strings".to_string())?;
            result.push(s.to_string());
        }
        if !result.is_empty() {
            return Ok(result);
        }
    }

    if let Some(command) = args.get("command").and_then(|value| value.as_str()) {
        let parts = split_command_line(command);
        if !parts.is_empty() {
            return Ok(parts);
        }
        return Err("command string did not yield any arguments".to_string());
    }

    Err("provide either 'argv' (array of strings) or 'command' (string)".to_string())
}

/// Split a command line string respecting quotes
pub fn split_command_line(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    let mut quote_char = '\0';

    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' => {
                if in_quotes {
                    if ch == quote_char {
                        in_quotes = false;
                    } else {
                        current.push(ch);
                    }
                } else {
                    in_quotes = true;
                    quote_char = ch;
                }
            }
            '\\' => {
                if let Some(next_ch) = chars.next() {
                    current.push(next_ch);
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            c => current.push(c),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

/// Auto-detect provider from secret format
pub fn detect_provider_for_mcp(secret: &str) -> Option<String> {
    // Common prefixes that identify providers
    let prefixes = [
        ("ghp_", "github"),
        ("gho_", "github"),
        ("ghs_", "github"),
        ("ghr_", "github"),
        ("github_pat_", "github"),
        ("glpat-", "gitlab"),
        ("sk_live_", "stripe"),
        ("sk_test_", "stripe"),
        ("rk_live_", "stripe"),
        ("pk_live_", "stripe"),
        ("pk_test_", "stripe"),
        ("xoxb-", "slack"),
        ("xoxp-", "slack"),
        ("xoxa-", "slack"),
        ("xoxr-", "slack"),
        ("sk-", "openai"),
        ("sk-ant-", "anthropic"),
        ("SG.", "sendgrid"),
        ("key-", "mailgun"),
        ("do_", "digitalocean"),
        ("dop_v1_", "digitalocean"),
        ("doo_v1_", "digitalocean"),
        ("npm_", "npm"),
        ("pypi-", "pypi"),
        ("hf_", "huggingface"),
        ("r8_", "replicate"),
        ("sq0", "square"),
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
