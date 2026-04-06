//! HTTP persistence helpers for web commands

use crate::cli::commands::build_partition_attributes;
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::protocols::http::{HttpRequest, HttpResponse};
#[cfg(not(target_os = "windows"))]
use crate::protocols::http2::Http2Response;
use crate::storage::records::HttpHeadersRecord;
use crate::storage::service::StorageService;

use super::types::{current_timestamp, extract_host};

/// Persist HTTP/1.x request/response to database
pub fn maybe_persist_http(
  ctx: &CliContext,
  url: &str,
  request: &HttpRequest,
  response: &HttpResponse,
) -> Result<(), String> {
  let persist_flag = if ctx.has_flag("persist") {
    Some(true)
  } else if ctx.has_flag("no-persist") {
    Some(false)
  } else {
    None
  };

  let host = request.host().to_string();
  let attributes = build_partition_attributes(
    ctx,
    &host,
    [
      ("operation", ctx.verb.as_deref().unwrap_or("get")),
      ("url", url),
      ("method", request.method.as_str()),
    ],
  );
  let mut pm =
    StorageService::global().persistence_for_target_with(&host, persist_flag, None, attributes)?;

  if pm.is_enabled() {
    let scheme = if request.is_https() { "https" } else { "http" };
    let server_header = response
      .headers
      .iter()
      .find(|(key, _)| key.eq_ignore_ascii_case("server"))
      .map(|(_, value)| value.clone());
    let headers = response
      .headers
      .iter()
      .map(|(k, v)| (k.clone(), v.clone()))
      .collect();

    let record = HttpHeadersRecord {
      host: host.clone(),
      url: url.to_string(),
      method: request.method.clone(),
      scheme: scheme.to_string(),
      http_version: request.version.clone(),
      status_code: response.status_code,
      status_text: response.status_text.clone(),
      server: server_header,
      body_size: response.body.len().min(u32::MAX as usize) as u32,
      headers,
      timestamp: current_timestamp(),
      tls: None,
    };

    pm.add_http_capture(record)?;
    if let Some(path) = pm.commit()? {
      Output::success(&format!("Results saved to {}", path.display()));
    }
  }

  Ok(())
}

/// Persist HTTP/2 request/response to database
#[cfg(not(target_os = "windows"))]
pub fn maybe_persist_http2(
  ctx: &CliContext,
  url: &str,
  method: &str,
  authority: &str,
  response: &Http2Response,
) -> Result<(), String> {
  let persist_flag = if ctx.has_flag("persist") {
    Some(true)
  } else if ctx.has_flag("no-persist") {
    Some(false)
  } else {
    None
  };

  let host = extract_host(url);
  let attributes = build_partition_attributes(
    ctx,
    &host,
    [
      ("operation", ctx.verb.as_deref().unwrap_or("http2")),
      ("url", url),
      ("method", method),
      ("authority", authority),
    ],
  );

  let mut pm =
    StorageService::global().persistence_for_target_with(&host, persist_flag, None, attributes)?;

  if pm.is_enabled() {
    let server_header = response
      .headers
      .iter()
      .find(|h| h.name.eq_ignore_ascii_case("server"))
      .map(|h| h.value.clone());
    let headers: Vec<(String, String)> = response
      .headers
      .iter()
      .map(|h| (h.name.clone(), h.value.clone()))
      .collect();
    // HTTP/2 TLS snapshot not yet implemented
    let tls_snapshot = None;

    let record = HttpHeadersRecord {
      host: host.clone(),
      url: url.to_string(),
      method: method.to_string(),
      scheme: "https".to_string(),
      http_version: "HTTP/2".to_string(),
      status_code: response.status,
      status_text: String::new(),
      server: server_header,
      body_size: response.body.len().min(u32::MAX as usize) as u32,
      headers,
      timestamp: current_timestamp(),
      tls: tls_snapshot,
    };

    pm.add_http_capture(record)?;
    if let Some(path) = pm.commit()? {
      Output::success(&format!("Results saved to {}", path.display()));
    }
  }

  Ok(())
}

#[cfg(target_os = "windows")]
pub fn maybe_persist_http2(
  _ctx: &CliContext,
  _url: &str,
  _method: &str,
  _authority: &str,
  _response: &(),
) -> Result<(), String> {
  Ok(())
}
