//! Core HTTP request operations

use crate::cli::format::OutputFormat;
use crate::cli::output::Output;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::intelligence::banner_analysis::analyze_http_server;
use crate::protocols::http::{HttpClient, HttpRequest};
use crate::protocols::http2::{
    Header, Http2Dispatcher, Http2LoggingMiddleware, Http2Request, Http2Response,
};
use crate::protocols::tls_impersonator::TlsProfile;
use std::fs;
use std::sync::Arc;

use super::persist::{maybe_persist_http, maybe_persist_http2};
use super::types::{
    collect_request_headers, escape_json, guard_plain_http, parse_https_url, BufferingHttp2Handler,
};

/// Execute HTTP GET request
pub fn get(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset get <URL> Example: rb web asset get http://example.com",
    )?;

    Validator::validate_url(url)?;
    guard_plain_http(url, "rb web asset get")?;

    let format = ctx.get_output_format();

    let client = HttpClient::new();
    let mut request = HttpRequest::get(url);
    if let Some(profile_str) = ctx.get_flag("impersonate") {
        if let Some(profile) = TlsProfile::from_str(&profile_str) {
            request = request.with_tls_profile(profile);
        } else {
            Output::warning(&format!("Unknown impersonation profile: {}", profile_str));
            Output::info("Available profiles: chrome, firefox, safari");
        }
    }

    if format == OutputFormat::Human {
        Output::spinner_start("Sending request");
    }

    let response = client
        .send(&request)
        .map_err(|e| format!("Request failed: {}", e))?;

    if format == OutputFormat::Human {
        Output::spinner_done();
    }

    // JSON output
    if format == OutputFormat::Json {
        println!("{{");
        println!("  \"url\": \"{}\",", url);
        println!("  \"status_code\": {},", response.status_code);
        println!("  \"status_text\": \"{}\",", response.status_text);
        println!("  \"body_size\": {},", response.body.len());
        println!("  \"headers\": {{");
        let header_count = response.headers.len();
        for (i, (key, value)) in response.headers.iter().enumerate() {
            let comma = if i < header_count - 1 { "," } else { "" };
            let value_escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            println!("    \"{}\": \"{}\"{}", key, value_escaped, comma);
        }
        println!("  }}");
        println!("}}");
        maybe_persist_http(ctx, url, &request, &response)?;
        return Ok(());
    }

    // YAML output
    if format == OutputFormat::Yaml {
        println!("url: {}", url);
        println!("status_code: {}", response.status_code);
        println!("status_text: {}", response.status_text);
        println!("body_size: {}", response.body.len());
        println!("headers:");
        for (key, value) in &response.headers {
            println!("  {}: \"{}\"", key, value.replace('"', "\\\""));
        }
        maybe_persist_http(ctx, url, &request, &response)?;
        return Ok(());
    }

    // Human output
    Output::header("HTTP GET Request");
    Output::item("URL", url);
    println!();

    Output::subheader("Response");
    Output::item(
        "Status",
        &format!("{} {}", response.status_code, response.status_text),
    );
    Output::item("Body Size", &format!("{} bytes", response.body.len()));
    println!();

    Output::subheader("Headers");
    for (key, value) in &response.headers {
        Output::item(key, value);
    }

    maybe_persist_http(ctx, url, &request, &response)?;

    // HTTP server intelligence gathering
    if ctx.has_flag("intel") {
        println!();
        Output::header("HTTP Server Intelligence");

        if let Some(server_header) = response.headers.get("server") {
            let banner_info = analyze_http_server(server_header);

            if let Some(vendor) = &banner_info.vendor {
                Output::item("Server Software", vendor);
            }

            if let Some(version) = &banner_info.version {
                Output::item("Version", version);
            }

            if !banner_info.os_hints.is_empty() {
                Output::item("Operating System", &banner_info.os_hints.join(", "));
            }

            if banner_info.is_modified {
                Output::warning("⚠ Server header appears to be modified/customized");
            }

            for (key, value) in &banner_info.custom_fields {
                let label = key
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i == 0 {
                            c.to_uppercase().to_string()
                        } else {
                            c.to_string()
                        }
                    })
                    .collect::<String>();
                Output::item(&label, value);
            }

            if banner_info.is_modified {
                Output::item("Raw Server Header", &banner_info.raw_banner);
            }
        } else {
            Output::warning("No Server header found in response");
            Output::info("Server may be hiding version information for security");
        }
    }

    println!();
    if (200..300).contains(&response.status_code) {
        Output::success("Request successful");
    } else if response.status_code >= 400 {
        Output::warning(&format!("Client/Server error: {}", response.status_code));
    }

    Ok(())
}

/// Execute HTTP/2 request
pub fn http2(ctx: &CliContext) -> Result<(), String> {
    let url = ctx
        .target
        .as_ref()
        .ok_or("Missing URL. Usage: rb web asset http2 <https-url>")?;

    Validator::validate_url(url)?;
    let (_host, _port, _authority, _path) = parse_https_url(url)?;

    let method = ctx.get_flag_or("method", "GET").to_uppercase();

    let mut headers = collect_request_headers(ctx)?;

    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("accept"))
    {
        headers.push(("accept".to_string(), "*/*".to_string()));
    }

    let body_bytes = if let Some(body_inline) = ctx.get_flag("body") {
        Some(body_inline.clone().into_bytes())
    } else if let Some(body_path) = ctx.get_flag("body-file") {
        let data = fs::read(&body_path)
            .map_err(|e| format!("Failed to read body file {}: {}", body_path, e))?;
        Some(data)
    } else {
        None
    };

    let _timeout = ctx
        .get_flag("timeout")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15);

    let http2_headers: Vec<Header> = headers
        .iter()
        .map(|(k, v)| Header::new(k.as_str(), v.as_str()))
        .collect();

    let mut request = Http2Request::new(&method, url)?;
    request.headers = http2_headers;
    request.body = body_bytes;

    let dispatcher = Http2Dispatcher::new().with_middleware(Arc::new(Http2LoggingMiddleware));
    let mut collector = BufferingHttp2Handler::default();
    let (head, _) = dispatcher.send_with_handler(request.clone(), &mut collector)?;

    let response = Http2Response {
        status: head.status,
        headers: head.headers,
        body: collector.body,
    };

    maybe_persist_http2(ctx, url, &method, &request.authority, &response)?;

    let format = ctx.get_output_format();
    if format == OutputFormat::Json {
        render_http2_json(url, &method, &request.authority, &response)?;
    } else {
        render_http2_response(url, &method, &response)?;
    }

    Ok(())
}

/// Render HTTP/2 response in human-readable format
fn render_http2_response(url: &str, method: &str, response: &Http2Response) -> Result<(), String> {
    Output::success(&format!("HTTP/2 {} {}", method, url));
    Output::item("Status", &response.status.to_string());

    if !response.headers.is_empty() {
        Output::subheader("Response Headers");
        for header in &response.headers {
            println!("{}: {}", header.name, header.value);
        }
    }

    if !response.body.is_empty() {
        println!();
        println!("{}", String::from_utf8_lossy(&response.body));
        println!();
        Output::info(&format!("Body size: {} bytes", response.body.len()));
    }

    Ok(())
}

/// Render HTTP/2 response as JSON
fn render_http2_json(
    url: &str,
    method: &str,
    authority: &str,
    response: &Http2Response,
) -> Result<(), String> {
    println!("{{");
    println!("  \"request\": {{");
    println!("    \"url\": \"{}\",", escape_json(url));
    println!("    \"method\": \"{}\",", escape_json(method));
    println!("    \"authority\": \"{}\"", escape_json(authority));
    println!("  }},");
    println!("  \"response\": {{");
    println!("    \"status\": {},", response.status);
    println!("    \"headers\": [");
    for (idx, header) in response.headers.iter().enumerate() {
        let comma = if idx + 1 < response.headers.len() {
            ","
        } else {
            ""
        };
        println!(
            "      {{ \"name\": \"{}\", \"value\": \"{}\" }}{}",
            escape_json(&header.name),
            escape_json(&header.value),
            comma
        );
    }
    println!("    ],");
    println!(
        "    \"body_text\": \"{}\",",
        escape_json(&String::from_utf8_lossy(&response.body))
    );
    println!("    \"body_size\": {}", response.body.len());
    println!("  }}");
    println!("}}");

    Ok(())
}

/// Inspect HTTP headers
pub fn headers(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset headers <URL> Example: rb web asset headers http://example.com",
    )?;

    Validator::validate_url(url)?;
    guard_plain_http(url, "rb web asset headers")?;

    let format = ctx.get_output_format();

    let client = HttpClient::new();
    let mut request = HttpRequest::get(url);
    if let Some(profile_str) = ctx.get_flag("impersonate") {
        if let Some(profile) = TlsProfile::from_str(&profile_str) {
            request = request.with_tls_profile(profile);
        } else {
            Output::warning(&format!("Unknown impersonation profile: {}", profile_str));
            Output::info("Available profiles: chrome, firefox, safari");
        }
    }

    if format == OutputFormat::Human {
        Output::spinner_start("Fetching headers");
    }

    let response = client
        .send(&request)
        .map_err(|e| format!("Request failed: {}", e))?;

    if format == OutputFormat::Human {
        Output::spinner_done();
    }

    // JSON output
    if format == OutputFormat::Json {
        println!("{{");
        println!("  \"url\": \"{}\",", url);
        println!("  \"status_code\": {},", response.status_code);
        println!("  \"status_text\": \"{}\",", response.status_text);
        println!("  \"header_count\": {},", response.headers.len());
        println!("  \"headers\": {{");
        let header_count = response.headers.len();
        for (i, (key, value)) in response.headers.iter().enumerate() {
            let comma = if i < header_count - 1 { "," } else { "" };
            let value_escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            println!("    \"{}\": \"{}\"{}", key, value_escaped, comma);
        }
        println!("  }}");
        println!("}}");
        maybe_persist_http(ctx, url, &request, &response)?;
        return Ok(());
    }

    // YAML output
    if format == OutputFormat::Yaml {
        println!("url: {}", url);
        println!("status_code: {}", response.status_code);
        println!("status_text: {}", response.status_text);
        println!("header_count: {}", response.headers.len());
        println!("headers:");
        for (key, value) in &response.headers {
            println!("  {}: \"{}\"", key, value.replace('"', "\\\""));
        }
        maybe_persist_http(ctx, url, &request, &response)?;
        return Ok(());
    }

    // Human output
    Output::header("HTTP Headers Analysis");
    Output::item("URL", url);
    println!();

    Output::subheader(&format!(
        "Status: {} {}",
        response.status_code, response.status_text
    ));
    println!();

    Output::table_header(&["HEADER", "VALUE"]);
    for (key, value) in &response.headers {
        Output::table_row(&[key, value]);
    }

    println!();
    Output::success(&format!("Found {} headers", response.headers.len()));

    maybe_persist_http(ctx, url, &request, &response)?;

    Ok(())
}

/// TLS certificate inspection (currently disabled)
pub fn cert(_ctx: &CliContext) -> Result<(), String> {
    Err(
        "TLS certificate inspection temporarily disabled - use openssl s_client instead"
            .to_string(),
    )
}
