//! Database query operations for stored HTTP data

use crate::cli::commands::annotate_query_partition;
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

/// Get detailed HTTP summary from database
pub fn describe_http(ctx: &CliContext) -> Result<(), String> {
  let host = ctx.target.as_ref().ok_or("Missing target host")?;
  let db_path = get_db_path(ctx, host)?;

  Output::header(&format!("HTTP Summary: {}", host));
  Output::info(&format!("Database: {}", db_path.display()));

  let mut query = StorageService::global()
    .open_query_manager(&db_path)
    .map_err(|e| format!("Failed to open database: {}", e))?;

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

  println!();
  println!("📊 HTTP Data Summary:");
  println!("━━━━━━━━━━━━━━━━━━━━");
  println!("  Total Requests: {}", http_records.len());

  let mut status_counts: HashMap<u16, usize> = HashMap::new();
  for record in &http_records {
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

  Ok(())
}

/// Get database path - either from flag or auto-detect based on host
pub fn get_db_path(ctx: &CliContext, host: &str) -> Result<PathBuf, String> {
  if let Some(db_path) = ctx.get_flag("db") {
    return Ok(PathBuf::from(db_path));
  }

  let cwd = std::env::current_dir().map_err(|e| format!("Failed to get CWD: {}", e))?;
  let base = host
    .trim_start_matches("www.")
    .trim_start_matches("http://")
    .trim_start_matches("https://")
    .to_lowercase();
  let candidate = cwd.join(format!("{}.rdb", &base));
  if candidate.exists() {
    return Ok(candidate);
  }

  Err(format!(
    "Database not found: {}\nRun HTTP request first: rb web asset headers {} --persist",
    candidate.display(),
    host
  ))
}
