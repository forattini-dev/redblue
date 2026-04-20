//! Database query operations for stored HTTP data

use crate::cli::commands::annotate_query_partition;
use crate::cli::commands::describe_mode::{
  read_from_json_source, resolve_describe_mode, DescribeMode,
};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::storage::service::StorageService;
use std::collections::HashMap;
use std::path::PathBuf;

/// List all saved HTTP data for a host from database
pub fn list_http(ctx: &CliContext) -> Result<(), String> {
  let host = ctx.target.as_ref().ok_or("Missing target host")?;
  let db_path = get_db_path(ctx, host)?;

  Output::header(&format!("Listing HTTP Data: {}", host));
  Output::info(&format!("Database: {}", db_path.display()));

  let mut query = StorageService::global()
    .open_query_manager(&db_path)
    .map_err(|e| format!("Failed to open database: {}", e))?;

  annotate_query_partition(
    ctx,
    &db_path,
    [("query_dataset", "http"), ("query_operation", "list")],
  );

  let http_records = query
    .list_http_records(host)
    .map_err(|e| format!("Query failed: {}", e))?;

  if http_records.is_empty() {
    Output::warning("No HTTP data found in database");
    Output::info(&format!(
      "Run HTTP request first: rb web asset headers {} --persist",
      host
    ));
    return Ok(());
  }

  Output::success(&format!("Found {} HTTP record(s)", http_records.len()));
  println!();

  for record in &http_records {
    println!("URL: {}", record.url);
    println!("Status: {}", record.status_code);
    println!("Headers: {} found", record.headers.len());
    println!();
  }

  Ok(())
}

/// `rb web asset describe <host>` — consolidated HTTP snapshot.
///
/// Default mode (0.2.13+) is live: runs `headers`, `security`, and
/// `fingerprint` inline and prints a consolidated summary. Pass
/// `--from-db` / `--cache-only` to read from an existing DB (legacy
/// behavior), `--persist` / `--save` to live-collect and write the DB,
/// or `--from-json <path|->` to ingest a pre-collected payload.
pub fn describe_http(ctx: &CliContext) -> Result<(), String> {
  let host = ctx.target.as_ref().ok_or("Missing target host")?;
  let mode = resolve_describe_mode(ctx)?;

  match mode {
    DescribeMode::FromJson(source) => {
      let bytes = read_from_json_source(&source)?;
      Output::header(&format!("HTTP Summary: {} (from {})", host, source));
      let preview: String = String::from_utf8_lossy(&bytes).chars().take(1000).collect();
      println!("{}", preview);
      if bytes.len() > preview.len() {
        println!("... ({} bytes total)", bytes.len());
      }
      Ok(())
    }
    DescribeMode::FromDb => describe_from_db(ctx, host),
    DescribeMode::Live | DescribeMode::LivePersist => describe_live(ctx, host, &mode),
  }
}

fn describe_from_db(ctx: &CliContext, host: &str) -> Result<(), String> {
  let db_path = get_db_path(ctx, host)?;

  Output::header(&format!("HTTP Summary: {} (from DB)", host));
  Output::info(&format!("Database: {}", db_path.display()));

  let mut query = match StorageService::global().open_query_manager(&db_path) {
    Ok(q) => q,
    Err(e) => {
      let msg = e.to_string();
      if crate::storage::is_incompatible_db_error(&msg) {
        Output::warning(&format!(
          "Skipping incompatible DB at {}: {}",
          db_path.display(),
          msg
        ));
        Output::info(&format!(
          "Run `rb web asset describe {}` without --from-db to collect live.",
          host
        ));
        return Err(msg);
      }
      return Err(format!("Failed to open database: {}", msg));
    }
  };

  annotate_query_partition(
    ctx,
    &db_path,
    [("query_dataset", "http"), ("query_operation", "describe")],
  );

  let http_records = query
    .list_http_records(host)
    .map_err(|e| format!("Query failed: {}", e))?;

  if http_records.is_empty() {
    Output::warning("No HTTP data found in database");
    Output::info(&format!(
      "Run HTTP request first: rb web asset headers {} --persist",
      host
    ));
    return Ok(());
  }

  render_http_summary(&http_records);
  Ok(())
}

fn describe_live(ctx: &CliContext, host: &str, mode: &DescribeMode) -> Result<(), String> {
  use crate::cli::commands::web::{fingerprint, http, security};

  let persist_hint = matches!(mode, DescribeMode::LivePersist);

  Output::header(&format!(
    "HTTP Describe (live{}): {}",
    if persist_hint { " + persist" } else { "" },
    host
  ));

  let mut sub_ctx = ctx.clone();
  if !persist_hint {
    // Ensure downstream collectors don't attempt to write DB when user asked
    // for discard-only describe.
    sub_ctx.flags.remove("persist");
    sub_ctx.flags.remove("save");
  }

  println!();
  println!("─── Headers ───");
  if let Err(e) = http::headers(&sub_ctx) {
    Output::warning(&format!("headers: {}", e));
  }

  println!();
  println!("─── Security ───");
  if let Err(e) = security::security(&sub_ctx) {
    Output::warning(&format!("security: {}", e));
  }

  println!();
  println!("─── Fingerprint ───");
  if let Err(e) = fingerprint::fingerprint(&sub_ctx) {
    Output::warning(&format!("fingerprint: {}", e));
  }

  Ok(())
}

fn render_http_summary(http_records: &[crate::storage::records::HttpHeadersRecord]) {
  println!();
  println!("📊 HTTP Data Summary:");
  println!("━━━━━━━━━━━━━━━━━━━━");
  println!("  Total Requests: {}", http_records.len());

  let mut status_counts: HashMap<u16, usize> = HashMap::new();
  for record in http_records {
    *status_counts.entry(record.status_code).or_insert(0) += 1;
  }

  println!("\n  Status Codes:");
  for (status, count) in &status_counts {
    println!("    {}: {} requests", status, count);
  }

  println!("\n  Sample URLs:");
  for (i, record) in http_records.iter().take(5).enumerate() {
    println!("    {}. {} ({})", i + 1, record.url, record.status_code);
  }
  if http_records.len() > 5 {
    println!("    ... and {} more", http_records.len() - 5);
  }
}

/// Get database path - either from flag or auto-detect based on host
pub fn get_db_path(ctx: &CliContext, host: &str) -> Result<PathBuf, String> {
  if let Some(db_path) = ctx.get_flag("db") {
    return Ok(PathBuf::from(db_path));
  }

  let base = host
    .trim_start_matches("www.")
    .trim_start_matches("http://")
    .trim_start_matches("https://")
    .to_lowercase();

  let primary = crate::storage::default_db_path(&base);
  if primary.exists() {
    return Ok(primary);
  }

  // Legacy fallback: CWD copy from pre-0.2.13 scans.
  if let Ok(cwd) = std::env::current_dir() {
    let legacy = cwd.join(format!("{}.rdb", &base));
    if legacy.exists() {
      return Ok(legacy);
    }
  }

  Err(format!(
    "Database not found: {}\nRun HTTP request first: rb web asset headers {} --persist",
    primary.display(),
    host
  ))
}
