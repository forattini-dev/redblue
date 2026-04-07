use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::web::fuzzer::{
  FuzzResult, FuzzTarget, FuzzerConfig, HttpMethod, WebFuzzer, FUZZ_KEYWORD,
};
use crate::serde_json::Value;
use crate::wordlists::Loader;
use std::path::Path;

// Helper to convert FuzzResult to JSON payload
fn fuzz_result_to_json(result: &FuzzResult) -> Value {
  let mut payload = json!({
    "payload": result.payload.clone(),
    "url": result.url.clone(),
    "status_code": result.status_code,
    "size": result.size,
    "words": result.words,
    "lines": result.lines,
    "duration_ms": result.duration.as_millis() as u64,
    "filtered": result.filtered
  });

  if let Some(ref redirect) = result.redirect {
    payload["redirect"] = Value::String(redirect.clone());
  }
  if let Some(ref content_type) = result.content_type {
    payload["content_type"] = Value::String(content_type.clone());
  }

  payload
}

// Helper to convert FuzzResult to a CSV row string
fn fuzz_result_to_csv_row(result: &FuzzResult) -> String {
  format!(
    "{},{},{},{},{},{},{},{},\"{}\",\"{}\"",
    result.payload,
    result.url,
    result.status_code,
    result.size,
    result.words,
    result.lines,
    result.duration.as_millis(),
    result.filtered,
    result.redirect.as_deref().unwrap_or(""),
    result.content_type.as_deref().unwrap_or("")
  )
}

pub struct FuzzCommand;

impl Command for FuzzCommand {
  fn domain(&self) -> &str {
    "web"
  }

  fn resource(&self) -> &str {
    "fuzz"
  }

  fn description(&self) -> &str {
    "Fuzz web applications with wordlists"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![Route {
      verb: "run",
      summary: "Start a fuzzing scan",
      usage: "rb web fuzz run <url> -w <wordlist> [--output <format>]",
    }]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("wordlist", "Path to wordlist file").with_short('w'),
      Flag::new("output", "Output format (json, csv, plain)").with_short('o'),
      Flag::new(
        "format",
        "Output format (json, csv, plain) - alias for --output",
      )
      .with_short('f'),
      // Add other fuzzing flags here
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![(
      "Basic directory fuzzing",
      "rb web fuzz run http://example.com/FUZZ -w /path/to/wordlist.txt",
    )]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "run" => self.run(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        Err("Invalid verb".to_string())
      }
    }
  }
}

impl FuzzCommand {
  fn run(&self, ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or("Missing target URL")?;
    let wordlist_path_str = ctx.get_flag("wordlist").ok_or("Missing --wordlist")?;
    // Check both --format and --output flags for consistency
    let output_format = ctx
      .get_flag("format")
      .or_else(|| ctx.get_flag("output"))
      .unwrap_or_else(|| "plain".to_string())
      .to_lowercase();

    let wordlist_path = Path::new(&wordlist_path_str);
    if !wordlist_path.exists() {
      return Err(format!("Wordlist file not found: {}", wordlist_path_str));
    }

    let words = Loader::load_lines(wordlist_path).map_err(|e| e.to_string())?;
    let total_words = words.len() as u64;

    if !url.contains(FUZZ_KEYWORD) {
      if !ctx.wants_machine_output() {
        Output::warning(&format!(
          "URL does not contain the '{}' keyword. Appending it to the end.",
          FUZZ_KEYWORD
        ));
      }
      let new_url = format!("{}/{}", url.trim_end_matches('/'), FUZZ_KEYWORD);
      // This is an error because fuzzing won't work without FUZZ.
      return Err(format!(
        "URL must contain '{}' keyword. Automatically appending it: {}",
        FUZZ_KEYWORD, new_url
      ));
    }

    let config = FuzzerConfig::default(); // Use default config for now
    let target = FuzzTarget {
      url: url.clone(),
      method: HttpMethod::GET, // Default to GET for simplicity
      headers: Vec::new(),
      body: None,
      cookies: None,
    };

    let mut fuzzer = WebFuzzer::new(config);

    if !ctx.wants_machine_output() {
      Output::info("Starting fuzzing...");
    }
    let progress_enabled = !ctx.wants_machine_output() && output_format == "plain";
    let progress_bar = Output::progress_bar("Fuzzing", total_words, progress_enabled);

    let mut all_results = Vec::new();

    for word_chunk in words.chunks(100) {
      // Process in chunks to update progress
      let chunk_vec: Vec<String> = word_chunk.to_vec();
      let chunk_results = fuzzer
        .fuzz(&target, &chunk_vec)
        .map_err(|e| e.to_string())?;
      all_results.extend(chunk_results);
      progress_bar.tick(word_chunk.len() as u64);
    }
    progress_bar.finish(); // Ensure progress bar finishes

    let machine_results: Vec<Value> = all_results.iter().map(fuzz_result_to_json).collect();
    let filtered_count = all_results.iter().filter(|result| result.filtered).count();
    let payload = json!({
      "target": url.clone(),
      "wordlist": wordlist_path_str.clone(),
      "total_candidates": total_words,
      "results_count": all_results.len(),
      "filtered_count": filtered_count,
      "results": machine_results
    });
    if render::render_machine_output(ctx, "rb web fuzz run", &payload)? {
      return Ok(());
    }

    match output_format.as_str() {
      "json" => {
        Output::raw(&payload["results"].to_string_pretty());
      }
      "xml" => {
        Output::error("XML output not implemented due to zero external dependencies constraint. Requires a dedicated XML library.");
      }
      "csv" => {
        // Print CSV header
        Output::raw("Payload,URL,Status,Size,Words,Lines,DurationMs,Filtered,Redirect,ContentType");
        for result in all_results {
          Output::raw(&fuzz_result_to_csv_row(&result));
        }
      }
      "plain" => {
        for result in all_results {
          Output::info(&format!(
            "STATUS: {} SIZE: {} WORDS: {} LINES: {} DURATION: {:?} URL: {}",
            result.status_code,
            result.size,
            result.words,
            result.lines,
            result.duration,
            result.url
          ));
          // Add more details if needed
        }
      }
      _ => {
        Output::error(&format!("Unknown output format: {}", output_format));
      }
    }

    Ok(())
  }
}
