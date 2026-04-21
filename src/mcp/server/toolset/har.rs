use crate::mcp::server::McpServer;
use crate::mcp::types::ToolResult;
use crate::modules::web::crawler::WebCrawler;
use crate::protocols::har::Har;
use crate::utils::json::JsonValue;

pub fn tool_har_record(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let url = args
    .get("url")
    .and_then(|v| v.as_str())
    .ok_or_else(|| "argument 'url' is required".to_string())?;

  let max_depth = args
    .get("max_depth")
    .and_then(|v| v.as_f64())
    .map(|n| n as usize)
    .unwrap_or(2);

  let max_pages = args
    .get("max_pages")
    .and_then(|v| v.as_f64())
    .map(|n| n as usize)
    .unwrap_or(20);

  let mut crawler = WebCrawler::new()
    .with_max_depth(max_depth)
    .with_max_pages(max_pages)
    .with_same_origin(true)
    .with_har_recording(true);

  let result = crawler
    .crawl(url)
    .map_err(|e| format!("crawl failed: {}", e))?;

  let har_json = if let Some(recorder) = crawler.har_recorder() {
    let guard = recorder.lock().unwrap();
    let har = &guard.har;

    let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
    let total_response_size: i64 = har.log.entries.iter().map(|e| e.response.body_size).sum();

    JsonValue::object(vec![
      (
        "version".to_string(),
        JsonValue::String(har.log.version.clone()),
      ),
      (
        "entries_count".to_string(),
        JsonValue::Number(har.log.entries.len() as f64),
      ),
      ("total_time_ms".to_string(), JsonValue::Number(total_time)),
      (
        "total_response_bytes".to_string(),
        JsonValue::Number(total_response_size.max(0) as f64),
      ),
      ("har_content".to_string(), JsonValue::String(har.to_json())),
    ])
  } else {
    JsonValue::Null
  };

  let text = format!(
    "Recorded HTTP traffic for {} pages from '{}' (HAR entries: {})",
    result.total_urls,
    url,
    if let Some(entries) = har_json.get("entries_count").and_then(|v| v.as_f64()) {
      entries as usize
    } else {
      0
    }
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      ("url".to_string(), JsonValue::String(url.to_string())),
      (
        "pages_crawled".to_string(),
        JsonValue::Number(result.total_urls as f64),
      ),
      ("har".to_string(), har_json),
    ]),
  })
}

pub fn tool_har_analyze(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
  let content = args
    .get("content")
    .and_then(|v| v.as_str())
    .ok_or_else(|| "argument 'content' is required".to_string())?;

  let har = Har::from_json(content).map_err(|e| format!("failed to parse HAR: {}", e))?;

  let total_entries = har.log.entries.len();
  let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
  let total_request_size: i64 = har.log.entries.iter().map(|e| e.request.body_size).sum();
  let total_response_size: i64 = har.log.entries.iter().map(|e| e.response.body_size).sum();

  let mut status_counts: Vec<(u16, usize)> = Vec::new();
  for entry in &har.log.entries {
    let status = entry.response.status;
    if let Some(pos) = status_counts.iter().position(|(s, _)| *s == status) {
      status_counts[pos].1 += 1;
    } else {
      status_counts.push((status, 1));
    }
  }

  let status_json: Vec<JsonValue> = status_counts
    .iter()
    .map(|(status, count)| {
      JsonValue::object(vec![
        ("status".to_string(), JsonValue::Number(*status as f64)),
        ("count".to_string(), JsonValue::Number(*count as f64)),
      ])
    })
    .collect();

  let mut sorted_entries: Vec<_> = har.log.entries.iter().collect();
  sorted_entries.sort_by(|a, b| {
    b.time
      .partial_cmp(&a.time)
      .unwrap_or(std::cmp::Ordering::Equal)
  });

  let slowest_json: Vec<JsonValue> = sorted_entries
    .iter()
    .take(5)
    .map(|entry| {
      JsonValue::object(vec![
        (
          "url".to_string(),
          JsonValue::String(entry.request.url.clone()),
        ),
        ("time_ms".to_string(), JsonValue::Number(entry.time)),
        (
          "status".to_string(),
          JsonValue::Number(entry.response.status as f64),
        ),
      ])
    })
    .collect();

  let text = format!(
    "HAR Analysis: {} entries, {:.2}ms total time, {} bytes transferred",
    total_entries,
    total_time,
    total_response_size.max(0)
  );

  Ok(ToolResult {
    text,
    data: JsonValue::object(vec![
      (
        "version".to_string(),
        JsonValue::String(har.log.version.clone()),
      ),
      (
        "creator".to_string(),
        JsonValue::String(format!(
          "{} {}",
          har.log.creator.name, har.log.creator.version
        )),
      ),
      (
        "total_entries".to_string(),
        JsonValue::Number(total_entries as f64),
      ),
      ("total_time_ms".to_string(), JsonValue::Number(total_time)),
      (
        "total_request_bytes".to_string(),
        JsonValue::Number(total_request_size.max(0) as f64),
      ),
      (
        "total_response_bytes".to_string(),
        JsonValue::Number(total_response_size.max(0) as f64),
      ),
      ("status_codes".to_string(), JsonValue::array(status_json)),
      (
        "slowest_requests".to_string(),
        JsonValue::array(slowest_json),
      ),
    ]),
  })
}
