//! Fuzzing MCP Tools
//!
//! Directory fuzzing, virtual host fuzzing, and parameter fuzzing tools.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::modules::web::fuzzer::{
  FuzzTarget, FuzzerConfig, HttpMethod, WebFuzzer, WordlistManager,
};
use crate::utils::json::JsonValue;
use std::time::Duration;

/// Register fuzzing tools with the server
pub fn register_fuzz_tools() -> Vec<ToolDefinition<McpServer>> {
  vec![
        ToolDefinition {
            name: "rb.fuzz.dir",
            description: "Directory and file fuzzing. Replace 'FUZZ' in the URL with wordlist entries \
                         to discover hidden paths, files, and directories. Supports status code and \
                         response size filtering.",
            fields: &[
                ToolField {
                    name: "url",
                    field_type: "string",
                    description: "URL with FUZZ placeholder (e.g., 'http://example.com/FUZZ').",
                    required: true,
                },
                ToolField {
                    name: "wordlist",
                    field_type: "string",
                    description: "Path to wordlist file (one entry per line).",
                    required: true,
                },
                ToolField {
                    name: "status_filter",
                    field_type: "string",
                    description: "Comma-separated status codes to include (e.g., '200,301,302,403'). \
                                 Default: all non-404 responses.",
                    required: false,
                },
                ToolField {
                    name: "size_filter",
                    field_type: "string",
                    description: "Filter out responses of this size in bytes (e.g., '0' or '1234'). \
                                 Useful for excluding custom 404 pages.",
                    required: false,
                },
            ],
            handler: tool_fuzz_dir,
        },
        ToolDefinition {
            name: "rb.fuzz.vhost",
            description: "Virtual host fuzzing. Discovers hidden virtual hosts by fuzzing the Host header. \
                         Compares response sizes against baseline to identify unique vhosts.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target IP address or base URL (e.g., 'http://10.10.10.1').",
                    required: true,
                },
                ToolField {
                    name: "domain",
                    field_type: "string",
                    description: "Base domain for vhost generation (e.g., 'example.com'). \
                                 Wordlist entries are prepended as subdomains.",
                    required: true,
                },
                ToolField {
                    name: "wordlist",
                    field_type: "string",
                    description: "Path to subdomain wordlist file.",
                    required: true,
                },
            ],
            handler: tool_fuzz_vhost,
        },
        ToolDefinition {
            name: "rb.fuzz.param",
            description: "Parameter fuzzing. Tests URL query parameters with wordlist values to discover \
                         hidden parameters, injection points, or interesting responses.",
            fields: &[
                ToolField {
                    name: "url",
                    field_type: "string",
                    description: "Base URL to test (e.g., 'http://example.com/page').",
                    required: true,
                },
                ToolField {
                    name: "param_name",
                    field_type: "string",
                    description: "Parameter name to fuzz (e.g., 'id', 'debug', 'admin').",
                    required: true,
                },
                ToolField {
                    name: "wordlist",
                    field_type: "string",
                    description: "Path to wordlist file for parameter values.",
                    required: true,
                },
            ],
            handler: tool_fuzz_param,
        },
    ]
}

/// Load wordlist from file, returning words and count
fn load_wordlist(path: &str) -> Result<Vec<String>, String> {
  let mut wl = WordlistManager::new();
  wl.load_file(path)?;

  if wl.is_empty() {
    return Err(format!(
      "Wordlist '{}' is empty or contains no valid entries.",
      path
    ));
  }

  Ok(wl.words().to_vec())
}

/// Format fuzz results into JSON array
fn results_to_json(results: &[crate::modules::web::fuzzer::FuzzResult]) -> Vec<JsonValue> {
  results
    .iter()
    .map(|r| {
      JsonValue::object(vec![
        ("payload".to_string(), JsonValue::String(r.payload.clone())),
        ("url".to_string(), JsonValue::String(r.url.clone())),
        (
          "status".to_string(),
          JsonValue::Number(r.status_code as f64),
        ),
        ("size".to_string(), JsonValue::Number(r.size as f64)),
        ("words".to_string(), JsonValue::Number(r.words as f64)),
        ("lines".to_string(), JsonValue::Number(r.lines as f64)),
        (
          "duration_ms".to_string(),
          JsonValue::Number(r.duration.as_millis() as f64),
        ),
        (
          "redirect".to_string(),
          r.redirect
            .as_ref()
            .map(|loc| JsonValue::String(loc.clone()))
            .unwrap_or(JsonValue::Null),
        ),
        (
          "content_type".to_string(),
          r.content_type
            .as_ref()
            .map(|ct| JsonValue::String(ct.clone()))
            .unwrap_or(JsonValue::Null),
        ),
      ])
    })
    .collect()
}

fn tool_fuzz_dir(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let url = args
    .get("url")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: url")?;

  let wordlist_path = args
    .get("wordlist")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: wordlist")?;

  let status_filter: Option<Vec<u16>> =
    args.get("status_filter").and_then(|v| v.as_str()).map(|s| {
      s.split(',')
        .filter_map(|code| code.trim().parse::<u16>().ok())
        .collect()
    });

  let size_filter: Option<usize> = args
    .get("size_filter")
    .and_then(|v| v.as_str())
    .and_then(|s| s.trim().parse::<usize>().ok());

  // Ensure URL contains FUZZ placeholder
  let fuzz_url = if url.contains("FUZZ") {
    url.to_string()
  } else {
    // Append FUZZ to path if not present
    let base = url.trim_end_matches('/');
    format!("{}/FUZZ", base)
  };

  let words = load_wordlist(wordlist_path)?;
  let word_count = words.len();

  let config = FuzzerConfig {
    threads: 20,
    timeout: Duration::from_secs(10),
    auto_calibrate: true,
    ..FuzzerConfig::default()
  };

  let target = FuzzTarget {
    url: fuzz_url.clone(),
    method: HttpMethod::GET,
    headers: vec![],
    body: None,
    cookies: None,
  };

  let mut fuzzer = WebFuzzer::new(config);
  let results = fuzzer.fuzz(&target, &words)?;

  // Apply post-filters
  let filtered: Vec<_> = results
    .into_iter()
    .filter(|r| {
      // Apply status filter
      if let Some(ref codes) = status_filter {
        if !codes.contains(&r.status_code) {
          return false;
        }
      } else {
        // Default: exclude 404
        if r.status_code == 404 {
          return false;
        }
      }
      // Apply size filter
      if let Some(exclude_size) = size_filter {
        if r.size == exclude_size {
          return false;
        }
      }
      true
    })
    .collect();

  let stats = fuzzer.stats();
  let results_json = results_to_json(&filtered);

  let text = format!(
    "Directory fuzzing on {}: {} words tested, {} hits found, {} errors (RPS: {:.1})",
    fuzz_url,
    word_count,
    filtered.len(),
    stats.errors,
    stats.rps
  );

  Ok(ToolResult::with_data(
    text,
    JsonValue::object(vec![
      ("url".to_string(), JsonValue::String(fuzz_url)),
      (
        "wordlist".to_string(),
        JsonValue::String(wordlist_path.to_string()),
      ),
      (
        "words_tested".to_string(),
        JsonValue::Number(word_count as f64),
      ),
      ("hits".to_string(), JsonValue::Number(filtered.len() as f64)),
      ("errors".to_string(), JsonValue::Number(stats.errors as f64)),
      ("rps".to_string(), JsonValue::Number(stats.rps)),
      ("results".to_string(), JsonValue::array(results_json)),
    ]),
  ))
}

fn tool_fuzz_vhost(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let target = args
    .get("target")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: target")?;

  let domain = args
    .get("domain")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: domain")?;

  let wordlist_path = args
    .get("wordlist")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: wordlist")?;

  let words = load_wordlist(wordlist_path)?;
  let word_count = words.len();

  // Build vhost wordlist: prepend each word as subdomain to domain
  let vhost_words: Vec<String> = words.iter().map(|w| format!("{}.{}", w, domain)).collect();

  // Normalize target URL
  let base_url = if target.starts_with("http://") || target.starts_with("https://") {
    target.to_string()
  } else {
    format!("http://{}", target)
  };

  // Use FUZZ in the Host header for vhost discovery
  let config = FuzzerConfig {
    threads: 20,
    timeout: Duration::from_secs(10),
    auto_calibrate: true,
    ..FuzzerConfig::default()
  };

  let fuzz_target = FuzzTarget {
    url: base_url.clone(),
    method: HttpMethod::GET,
    headers: vec![("Host".to_string(), "FUZZ".to_string())],
    body: None,
    cookies: None,
  };

  let mut fuzzer = WebFuzzer::new(config);
  let results = fuzzer.fuzz(&fuzz_target, &vhost_words)?;

  // Vhost results are interesting if they differ from baseline (auto-calibration handles this)
  let stats = fuzzer.stats();
  let results_json = results_to_json(&results);

  let text = format!(
    "VHost fuzzing on {} (domain: {}): {} subdomains tested, {} unique vhosts found (RPS: {:.1})",
    target,
    domain,
    word_count,
    results.len(),
    stats.rps
  );

  Ok(ToolResult::with_data(
    text,
    JsonValue::object(vec![
      ("target".to_string(), JsonValue::String(target.to_string())),
      ("domain".to_string(), JsonValue::String(domain.to_string())),
      (
        "wordlist".to_string(),
        JsonValue::String(wordlist_path.to_string()),
      ),
      (
        "words_tested".to_string(),
        JsonValue::Number(word_count as f64),
      ),
      (
        "vhosts_found".to_string(),
        JsonValue::Number(results.len() as f64),
      ),
      ("errors".to_string(), JsonValue::Number(stats.errors as f64)),
      ("rps".to_string(), JsonValue::Number(stats.rps)),
      ("results".to_string(), JsonValue::array(results_json)),
    ]),
  ))
}

fn tool_fuzz_param(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let url = args
    .get("url")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: url")?;

  let param_name = args
    .get("param_name")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: param_name")?;

  let wordlist_path = args
    .get("wordlist")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: wordlist")?;

  let words = load_wordlist(wordlist_path)?;
  let word_count = words.len();

  // Build URL with FUZZ placeholder in query parameter
  let separator = if url.contains('?') { "&" } else { "?" };
  let fuzz_url = format!("{}{}{}=FUZZ", url, separator, param_name);

  let config = FuzzerConfig {
    threads: 20,
    timeout: Duration::from_secs(10),
    auto_calibrate: true,
    ..FuzzerConfig::default()
  };

  let target = FuzzTarget {
    url: fuzz_url.clone(),
    method: HttpMethod::GET,
    headers: vec![],
    body: None,
    cookies: None,
  };

  let mut fuzzer = WebFuzzer::new(config);
  let results = fuzzer.fuzz(&target, &words)?;

  let stats = fuzzer.stats();
  let results_json = results_to_json(&results);

  let text = format!(
        "Parameter fuzzing on {} (param: '{}'): {} values tested, {} interesting responses (RPS: {:.1})",
        url, param_name, word_count, results.len(), stats.rps
    );

  Ok(ToolResult::with_data(
    text,
    JsonValue::object(vec![
      ("url".to_string(), JsonValue::String(url.to_string())),
      (
        "param_name".to_string(),
        JsonValue::String(param_name.to_string()),
      ),
      ("fuzz_url".to_string(), JsonValue::String(fuzz_url)),
      (
        "wordlist".to_string(),
        JsonValue::String(wordlist_path.to_string()),
      ),
      (
        "words_tested".to_string(),
        JsonValue::Number(word_count as f64),
      ),
      ("hits".to_string(), JsonValue::Number(results.len() as f64)),
      ("errors".to_string(), JsonValue::Number(stats.errors as f64)),
      ("rps".to_string(), JsonValue::Number(stats.rps)),
      ("results".to_string(), JsonValue::array(results_json)),
    ]),
  ))
}
