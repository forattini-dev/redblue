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
  let json_mode = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

  let mut sub_ctx = ctx.clone();
  if !persist_hint {
    sub_ctx.flags.remove("persist");
    sub_ctx.flags.remove("save");
  }

  if json_mode {
    // Aggregate sub-command output into a single JSON envelope by invoking
    // the binary as subprocesses with -o json. Keeps describe parsable by
    // consumers that pipe through runJson.
    let aggregate = run_describe_subcommands_json(
      host,
      &[
        ("headers", &["web", "asset", "headers"]),
        ("security", &["web", "asset", "security"]),
        ("fingerprint", &["web", "asset", "fingerprint"]),
      ],
      &sub_ctx,
    );
    println!("{}", aggregate);
    return Ok(());
  }

  Output::header(&format!(
    "HTTP Describe (live{}): {}",
    if persist_hint { " + persist" } else { "" },
    host
  ));

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

/// Invoke `rb <route> <target> -o json` for each named sub-command and
/// aggregate the parsed outputs into a single JSON object. Lives in
/// describe bundles that need a machine-safe envelope.
pub(crate) fn run_describe_subcommands_json(
  target: &str,
  commands: &[(&str, &[&str])],
  ctx: &CliContext,
) -> String {
  use std::io::Read;
  use std::process::{Command, Stdio};
  use std::sync::{Arc, Mutex};
  use std::time::{Duration, Instant};

  let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("rb"));

  const SAFE_FORWARD_FLAGS: &[&str] = &[
    "timeout",
    "user-agent",
    "headers",
    "method",
    "body",
    "body-file",
    "browser",
    "db",
    "db-password",
  ];
  let mut forwarded: Vec<(String, String)> = Vec::new();
  for (key, value) in &ctx.flags {
    if !SAFE_FORWARD_FLAGS.contains(&key.as_str()) {
      continue;
    }
    forwarded.push((key.clone(), value.clone()));
  }

  // Per-slot timeout. Consumers (SDK runJson / tinyseo wrapper) impose
  // their own outer timeout; without a per-slot cap one stuck subprocess
  // (e.g. a 3-minute fingerprint against a heavy target) would blow the
  // whole envelope. Override with --timeout on the describe call itself.
  let slot_timeout = Duration::from_secs(
    ctx
      .get_flag("timeout")
      .and_then(|s| s.parse::<u64>().ok())
      .unwrap_or(30),
  );

  // Spawn all sub-commands concurrently and collect results.
  let results: Arc<Mutex<Vec<(usize, String, String)>>> = Arc::new(Mutex::new(Vec::new()));
  std::thread::scope(|scope| {
    for (idx, (name, route)) in commands.iter().enumerate() {
      let exe = exe.clone();
      let forwarded = forwarded.clone();
      let results = Arc::clone(&results);
      let name = name.to_string();
      let route = route.to_vec();
      let target = target.to_string();
      scope.spawn(move || {
        let mut cmd = Command::new(&exe);
        cmd.args(route.iter().copied());
        cmd.arg(&target);
        cmd.arg("-o");
        cmd.arg("json");
        for (k, v) in &forwarded {
          cmd.arg(format!("--{}", k));
          if !v.is_empty() {
            cmd.arg(v);
          }
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let payload = match cmd.spawn() {
          Ok(mut child) => {
            let start = Instant::now();
            let mut stdout_data = Vec::new();
            let mut stderr_data = Vec::new();
            let mut timed_out = false;
            // Poll for completion with timeout. If exceeded, kill the child.
            loop {
              match child.try_wait() {
                Ok(Some(status)) => {
                  if let Some(mut s) = child.stdout.take() {
                    let _ = s.read_to_end(&mut stdout_data);
                  }
                  if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_end(&mut stderr_data);
                  }
                  let code = status.code().unwrap_or(-1);
                  let success = status.success();
                  break build_slot_payload(success, code, &stdout_data, &stderr_data, false);
                }
                Ok(None) => {
                  if start.elapsed() >= slot_timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(mut s) = child.stdout.take() {
                      let _ = s.read_to_end(&mut stdout_data);
                    }
                    if let Some(mut s) = child.stderr.take() {
                      let _ = s.read_to_end(&mut stderr_data);
                    }
                    timed_out = true;
                    break build_slot_payload(false, -1, &stdout_data, &stderr_data, true);
                  }
                  std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                  break format!("{{ \"error\": {} }}", json_quote(&e.to_string()));
                }
              }
            }
          }
          Err(e) => format!("{{ \"error\": {} }}", json_quote(&e.to_string())),
        };
        results.lock().unwrap().push((idx, name, payload));
        let _ = ();
      });
    }
  });

  // Collect in declaration order.
  let mut collected = results.lock().unwrap().clone();
  collected.sort_by_key(|(idx, _, _)| *idx);

  let mut out = String::from("{\n");
  out.push_str(&format!("  \"target\": {},\n", json_quote(target)));
  out.push_str("  \"bundle\": {\n");
  for (pos, (_, name, payload)) in collected.iter().enumerate() {
    let comma = if pos + 1 < collected.len() { "," } else { "" };
    out.push_str(&format!("    {}: {}{}\n", json_quote(name), payload, comma));
  }
  out.push_str("  }\n}");
  out
}

fn build_slot_payload(
  success: bool,
  exit_code: i32,
  stdout: &[u8],
  stderr: &[u8],
  timed_out: bool,
) -> String {
  let stdout_s = String::from_utf8_lossy(stdout).trim().to_string();
  let stderr_s = String::from_utf8_lossy(stderr).trim().to_string();
  if success {
    if stdout_s.is_empty() {
      return "null".to_string();
    }
    if stdout_s.starts_with('{') || stdout_s.starts_with('[') {
      return stdout_s;
    }
    return format!("{{ \"raw\": {} }}", json_quote(&stdout_s));
  }
  let message = if timed_out {
    "slot timed out".to_string()
  } else if !stderr_s.is_empty() {
    stderr_s.clone()
  } else {
    stdout_s.clone()
  };
  format!(
    "{{ \"error\": {}, \"timed_out\": {}, \"stdout\": {}, \"stderr\": {}, \"exit_code\": {} }}",
    json_quote(&message),
    timed_out,
    json_quote(&stdout_s),
    json_quote(&stderr_s),
    exit_code
  )
}

fn json_quote(s: &str) -> String {
  let mut out = String::with_capacity(s.len() + 2);
  out.push('"');
  for c in s.chars() {
    match c {
      '"' => out.push_str("\\\""),
      '\\' => out.push_str("\\\\"),
      '\n' => out.push_str("\\n"),
      '\r' => out.push_str("\\r"),
      '\t' => out.push_str("\\t"),
      c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
      c => out.push(c),
    }
  }
  out.push('"');
  out
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
