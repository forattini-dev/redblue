//! HAR (HTTP Archive) operations

use crate::cli::output::Output;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::modules::web::crawler::WebCrawler;
use crate::protocols::har::{Har, HarEntry};
use crate::protocols::http::HttpClient;
use std::fs;
use std::time::Duration;

use super::types::extract_host;

/// Crawl website and export to HAR format
pub fn har_export(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset har-export <URL> [--output FILE]\nExample: rb web asset har-export http://example.com --output site.har",
    )?;

  Validator::validate_url(url)?;

  Output::header("HAR Export - HTTP Archive Recorder");
  Output::item("URL", url);

  // Get options
  let max_depth = ctx
    .get_flag("depth")
    .or_else(|| ctx.get_flag("d"))
    .and_then(|s| s.parse::<usize>().ok())
    .unwrap_or(2);

  let max_pages = ctx
    .get_flag("max-pages")
    .or_else(|| ctx.get_flag("m"))
    .and_then(|s| s.parse::<usize>().ok())
    .unwrap_or(50);

  let output_file = ctx
    .get_flag("output")
    .or_else(|| ctx.get_flag("o"))
    .map(|s| s.to_string())
    .unwrap_or_else(|| {
      // Generate filename from URL
      let host = extract_host(url);
      format!("{}.har", host.replace(':', "_"))
    });

  Output::item("Output File", &output_file);
  Output::item("Max Depth", &max_depth.to_string());
  Output::item("Max Pages", &max_pages.to_string());
  println!();

  Output::spinner_start("Crawling and recording HTTP traffic");

  // Create crawler with HAR recording
  let mut crawler = WebCrawler::new()
    .with_max_depth(max_depth)
    .with_max_pages(max_pages)
    .with_same_origin(true)
    .with_har_recording(true);

  // Crawl
  let result = crawler.crawl(url)?;

  Output::spinner_done();

  // Export HAR file
  Output::spinner_start("Exporting HAR file");
  crawler.save_har(&output_file)?;
  Output::spinner_done();

  Output::success(&format!("HAR file exported: {}", output_file));
  println!();

  // Display summary
  println!("\x1b[1m\x1b[36m● Crawl Summary\x1b[0m");
  println!("  Pages crawled: {}", result.total_urls);
  println!("  Links found: {}", result.total_links);
  println!("  Max depth reached: {}", result.max_depth_reached);
  println!();

  // Get HAR stats from recorder
  if let Some(recorder) = crawler.har_recorder() {
    let guard = recorder.lock().unwrap();
    let har = &guard.har;
    println!("\x1b[1m\x1b[35m● HAR Summary\x1b[0m");
    println!("  Total entries: {}", har.log.entries.len());

    // Calculate total size
    let total_request_size: i64 = har.log.entries.iter().map(|e| e.request.body_size).sum();
    let total_response_size: i64 = har.log.entries.iter().map(|e| e.response.body_size).sum();

    println!("  Total request size: {} bytes", total_request_size.max(0));
    println!(
      "  Total response size: {} bytes",
      total_response_size.max(0)
    );

    // Calculate total time
    let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
    println!("  Total time: {:.2}ms", total_time);
  }

  Ok(())
}

/// View and analyze a HAR file
pub fn har_view(ctx: &CliContext) -> Result<(), String> {
  let file_path = ctx.target.as_ref().ok_or(
        "Missing HAR file. Usage: rb web asset har-view <file>\nExample: rb web asset har-view site.har",
    )?;

  Output::header("HAR Viewer - HTTP Archive Analyzer");
  Output::item("File", file_path);
  println!();

  Output::spinner_start("Loading HAR file");

  // Read and parse HAR file
  let content =
    fs::read_to_string(file_path).map_err(|e| format!("Failed to read HAR file: {}", e))?;

  // Manual JSON parsing for HAR structure
  let har = Har::from_json(&content).map_err(|e| format!("Failed to parse HAR: {}", e))?;

  Output::spinner_done();

  // Show options
  let show_entries = ctx.has_flag("entries");
  let show_timings = ctx.has_flag("timings");
  let show_errors = ctx.has_flag("errors");

  // HAR Overview
  println!("\x1b[1m\x1b[36m● HAR Overview\x1b[0m");
  println!("  Version: {}", har.log.version);
  println!(
    "  Creator: {} {}",
    har.log.creator.name, har.log.creator.version
  );
  println!("  Total entries: {}", har.log.entries.len());

  // Calculate statistics
  let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
  let total_request_size: i64 = har.log.entries.iter().map(|e| e.request.body_size).sum();
  let total_response_size: i64 = har.log.entries.iter().map(|e| e.response.body_size).sum();

  println!("  Total time: {:.2}ms", total_time);
  println!("  Total request size: {} bytes", total_request_size.max(0));
  println!(
    "  Total response size: {} bytes",
    total_response_size.max(0)
  );
  println!();

  // Show entries
  if show_entries || (!show_timings && !show_errors) {
    println!("\x1b[1m\x1b[32m● Entries\x1b[0m");
    for (i, entry) in har.log.entries.iter().take(20).enumerate() {
      let status_color = if entry.response.status >= 400 {
        "\x1b[31m" // Red for errors
      } else if entry.response.status >= 300 {
        "\x1b[33m" // Yellow for redirects
      } else {
        "\x1b[32m" // Green for success
      };
      println!(
        "  {:3}. {}{} {}\x1b[0m {} ({:.1}ms)",
        i + 1,
        status_color,
        entry.response.status,
        entry.request.method,
        entry.request.url,
        entry.time
      );
    }
    if har.log.entries.len() > 20 {
      println!(
        "  \x1b[90m... and {} more\x1b[0m",
        har.log.entries.len() - 20
      );
    }
    println!();
  }

  // Show timings
  if show_timings {
    println!("\x1b[1m\x1b[35m● Timing Analysis\x1b[0m");

    // Find slowest entries
    let mut sorted: Vec<_> = har.log.entries.iter().collect();
    sorted.sort_by(|a, b| b.time.partial_cmp(&a.time).unwrap());

    println!("  Slowest requests:");
    for (i, entry) in sorted.iter().take(5).enumerate() {
      println!(
        "    {:3}. {:.2}ms - {} {}",
        i + 1,
        entry.time,
        entry.request.method,
        entry.request.url
      );
    }
    println!();
  }

  // Show errors
  if show_errors {
    println!("\x1b[1m\x1b[31m● Errors (4xx/5xx)\x1b[0m");

    let errors: Vec<_> = har
      .log
      .entries
      .iter()
      .filter(|e| e.response.status >= 400)
      .collect();

    if errors.is_empty() {
      println!("  No errors found");
    } else {
      for (i, entry) in errors.iter().take(10).enumerate() {
        println!(
          "  {:3}. {} {} - {}",
          i + 1,
          entry.response.status,
          entry.response.status_text,
          entry.request.url
        );
      }
      if errors.len() > 10 {
        println!("  \x1b[90m... and {} more\x1b[0m", errors.len() - 10);
      }
    }
    println!();
  }

  // Status code distribution
  let mut status_counts: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
  for entry in &har.log.entries {
    *status_counts.entry(entry.response.status).or_insert(0) += 1;
  }

  println!("\x1b[1m\x1b[33m● Status Codes\x1b[0m");
  let mut codes: Vec<_> = status_counts.iter().collect();
  codes.sort_by_key(|(k, _)| *k);
  for (code, count) in codes {
    let color = if *code >= 400 {
      "\x1b[31m"
    } else if *code >= 300 {
      "\x1b[33m"
    } else {
      "\x1b[32m"
    };
    println!("  {}{}\x1b[0m: {} requests", color, code, count);
  }

  Ok(())
}

/// Replay HTTP requests from HAR file
pub fn har_replay(ctx: &CliContext) -> Result<(), String> {
  let file_path = ctx.target.as_ref().ok_or(
        "Missing HAR file. Usage: rb web asset har-replay <file>\nExample: rb web asset har-replay site.har",
    )?;

  Output::header("HAR Replay - HTTP Request Replay");
  Output::item("File", file_path);
  println!();

  // Parse options
  let sequential = ctx.has_flag("sequential");
  let compare = ctx.has_flag("compare");
  let delay_ms: u64 = ctx
    .get_flag("delay")
    .and_then(|d| d.parse().ok())
    .unwrap_or(0);

  Output::spinner_start("Loading HAR file");

  let content =
    fs::read_to_string(file_path).map_err(|e| format!("Failed to read HAR file: {}", e))?;

  let har = Har::from_json(&content).map_err(|e| format!("Failed to parse HAR: {}", e))?;

  Output::spinner_done();

  let entries = &har.log.entries;
  if entries.is_empty() {
    Output::warning("No entries to replay in HAR file");
    return Ok(());
  }

  Output::info(&format!("Found {} entries to replay", entries.len()));
  if sequential {
    Output::info("Mode: Sequential (one at a time)");
  }
  if compare {
    Output::info("Mode: Compare responses");
  }
  if delay_ms > 0 {
    Output::info(&format!("Delay between requests: {}ms", delay_ms));
  }
  println!();

  let client = HttpClient::new();
  let mut success_count = 0;
  let mut fail_count = 0;
  let mut diff_count = 0;

  for (i, entry) in entries.iter().enumerate() {
    let url = &entry.request.url;
    let method = &entry.request.method;

    print!("  [{}/{}] {} {} ... ", i + 1, entries.len(), method, url);

    // Build request headers
    let mut _headers = Vec::new();
    for header in &entry.request.headers {
      // Skip pseudo-headers and host (will be set automatically)
      if !header.name.starts_with(':') && header.name.to_lowercase() != "host" {
        _headers.push((header.name.clone(), header.value.clone()));
      }
    }

    // Make the request
    let result = match method.to_uppercase().as_str() {
      "GET" => client.get(url),
      "POST" => {
        let body = entry
          .request
          .post_data
          .as_ref()
          .map(|p| p.text.clone())
          .unwrap_or_default();
        client.post(url, body.into_bytes())
      }
      "HEAD" => {
        // HEAD not directly supported, use GET
        client.get(url)
      }
      _ => {
        println!("\x1b[33mSKIPPED\x1b[0m (unsupported method)");
        continue;
      }
    };

    match result {
      Ok(response) => {
        let status = response.status_code;
        let original_status = entry.response.status;

        let status_color = if status >= 400 {
          "\x1b[31m"
        } else if status >= 300 {
          "\x1b[33m"
        } else {
          "\x1b[32m"
        };

        if compare {
          if status == original_status {
            println!("{}OK\x1b[0m (status: {})", status_color, status);
            success_count += 1;
          } else {
            println!(
              "\x1b[33mDIFF\x1b[0m (was: {}, now: {})",
              original_status, status
            );
            diff_count += 1;
          }
        } else {
          println!("{}{}OK\x1b[0m", status_color, status);
          success_count += 1;
        }
      }
      Err(e) => {
        println!("\x1b[31mFAIL\x1b[0m ({})", e);
        fail_count += 1;
      }
    }

    // Delay between requests
    if delay_ms > 0 && i < entries.len() - 1 {
      std::thread::sleep(Duration::from_millis(delay_ms));
    }
  }

  println!();
  println!("\x1b[1m● Summary\x1b[0m");
  println!("  \x1b[32mSuccess: {}\x1b[0m", success_count);
  if diff_count > 0 {
    println!("  \x1b[33mDifferent: {}\x1b[0m", diff_count);
  }
  if fail_count > 0 {
    println!("  \x1b[31mFailed: {}\x1b[0m", fail_count);
  }

  Ok(())
}

/// Convert HAR entries to curl/wget/python/httpie commands
pub fn har_to_curl(ctx: &CliContext) -> Result<(), String> {
  let file_path = ctx.target.as_ref().ok_or(
        "Missing HAR file. Usage: rb web asset har-to-curl <file>\nExample: rb web asset har-to-curl site.har --format curl",
    )?;

  let format = ctx
    .get_flag("format")
    .map(|s| s.to_string())
    .unwrap_or_else(|| "curl".to_string());

  Output::header("HAR to Commands - Export HTTP Requests");
  Output::item("File", file_path);
  Output::item("Format", &format);
  println!();

  Output::spinner_start("Loading HAR file");

  let content =
    fs::read_to_string(file_path).map_err(|e| format!("Failed to read HAR file: {}", e))?;

  let har = Har::from_json(&content).map_err(|e| format!("Failed to parse HAR: {}", e))?;

  Output::spinner_done();

  let entries = &har.log.entries;
  if entries.is_empty() {
    Output::warning("No entries in HAR file");
    return Ok(());
  }

  Output::info(&format!(
    "Converting {} entries to {} format",
    entries.len(),
    format
  ));
  println!();

  for (i, entry) in entries.iter().enumerate() {
    println!("\x1b[1m# Request {}\x1b[0m", i + 1);

    let cmd = match format.as_str() {
      "curl" => entry_to_curl(entry),
      "wget" => entry_to_wget(entry),
      "python" => entry_to_python(entry),
      "httpie" => entry_to_httpie(entry),
      _ => {
        return Err(format!(
          "Unknown format: {}. Use: curl, wget, python, httpie",
          format
        ))
      }
    };

    println!("{}", cmd);
    println!();
  }

  Ok(())
}

fn entry_to_curl(entry: &HarEntry) -> String {
  let mut cmd = format!("curl -X {} '{}'", entry.request.method, entry.request.url);

  // Add headers
  for header in &entry.request.headers {
    if !header.name.starts_with(':') {
      cmd.push_str(&format!(" \\\n  -H '{}: {}'", header.name, header.value));
    }
  }

  // Add body
  if let Some(ref post_data) = entry.request.post_data {
    if !post_data.text.is_empty() {
      let escaped = post_data.text.replace('\'', "'\\''");
      cmd.push_str(&format!(" \\\n  -d '{}'", escaped));
    }
  }

  cmd
}

fn entry_to_wget(entry: &HarEntry) -> String {
  let mut cmd = format!(
    "wget --method={} '{}'",
    entry.request.method, entry.request.url
  );

  // Add headers
  for header in &entry.request.headers {
    if !header.name.starts_with(':') && header.name.to_lowercase() != "host" {
      cmd.push_str(&format!(
        " \\\n  --header='{}: {}'",
        header.name, header.value
      ));
    }
  }

  // Add body
  if let Some(ref post_data) = entry.request.post_data {
    if !post_data.text.is_empty() {
      let escaped = post_data.text.replace('\'', "'\\''");
      cmd.push_str(&format!(" \\\n  --body-data='{}'", escaped));
    }
  }

  cmd.push_str(" \\\n  -O -");
  cmd
}

fn entry_to_python(entry: &HarEntry) -> String {
  let mut code = String::from("import requests\n\n");

  // Build headers dict
  let headers: Vec<String> = entry
    .request
    .headers
    .iter()
    .filter(|h| !h.name.starts_with(':'))
    .map(|h| format!("    '{}': '{}'", h.name, h.value.replace('\'', "\\'")))
    .collect();

  if !headers.is_empty() {
    code.push_str("headers = {\n");
    code.push_str(&headers.join(",\n"));
    code.push_str("\n}\n\n");
  }

  // Build request
  let method = entry.request.method.to_lowercase();
  code.push_str(&format!("response = requests.{}(\n", method));
  code.push_str(&format!("    '{}',\n", entry.request.url));

  if !headers.is_empty() {
    code.push_str("    headers=headers,\n");
  }

  if let Some(ref post_data) = entry.request.post_data {
    if !post_data.text.is_empty() {
      let escaped = post_data.text.replace('\'', "\\'");
      code.push_str(&format!("    data='{}',\n", escaped));
    }
  }

  code.push_str(")\n\n");
  code.push_str("print(response.status_code)\nprint(response.text)");

  code
}

fn entry_to_httpie(entry: &HarEntry) -> String {
  let method = entry.request.method.to_uppercase();
  let mut cmd = format!("http {} '{}'", method, entry.request.url);

  // Add headers
  for header in &entry.request.headers {
    if !header.name.starts_with(':') && header.name.to_lowercase() != "host" {
      cmd.push_str(&format!(" \\\n  '{}:{}'", header.name, header.value));
    }
  }

  // Add body
  if let Some(ref post_data) = entry.request.post_data {
    if !post_data.text.is_empty() {
      // For JSON, httpie uses := for raw JSON
      cmd.push_str(&format!(
        " \\\n  --raw='{}'",
        post_data.text.replace('\'', "\\'")
      ));
    }
  }

  cmd
}
