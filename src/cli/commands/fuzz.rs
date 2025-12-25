use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::web::fuzzer::{
    FuzzResult, FuzzTarget, FuzzerConfig, HttpMethod, WebFuzzer, FUZZ_KEYWORD,
};
use crate::utils::json::JsonValue;
use crate::wordlists::Loader;
use std::path::Path;

// Helper to convert FuzzResult to JsonValue
fn fuzz_result_to_json(result: &FuzzResult) -> JsonValue {
    let mut obj_entries = vec![
        (
            "payload".to_string(),
            JsonValue::String(result.payload.clone()),
        ),
        ("url".to_string(), JsonValue::String(result.url.clone())),
        (
            "status_code".to_string(),
            JsonValue::Number(result.status_code as f64),
        ),
        ("size".to_string(), JsonValue::Number(result.size as f64)),
        ("words".to_string(), JsonValue::Number(result.words as f64)),
        ("lines".to_string(), JsonValue::Number(result.lines as f64)),
        (
            "duration_ms".to_string(),
            JsonValue::Number(result.duration.as_millis() as f64),
        ),
        ("filtered".to_string(), JsonValue::Bool(result.filtered)),
    ];
    if let Some(ref redirect) = result.redirect {
        obj_entries.push(("redirect".to_string(), JsonValue::String(redirect.clone())));
    }
    if let Some(ref content_type) = result.content_type {
        obj_entries.push((
            "content_type".to_string(),
            JsonValue::String(content_type.clone()),
        ));
    }
    JsonValue::Object(obj_entries)
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
            Output::warning(&format!(
                "URL does not contain the '{}' keyword. Appending it to the end.",
                FUZZ_KEYWORD
            ));
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

        Output::info("Starting fuzzing...");
        let progress_enabled = output_format == "plain"; // Only show progress for plain output
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

        match output_format.as_str() {
            "json" => {
                let json_results: Vec<JsonValue> =
                    all_results.iter().map(fuzz_result_to_json).collect();
                Output::json(&JsonValue::Array(json_results).to_json_string());
            }
            "xml" => {
                Output::error("XML output not implemented due to zero external dependencies constraint. Requires a dedicated XML library.");
            }
            "csv" => {
                // Print CSV header
                Output::raw(
                    "Payload,URL,Status,Size,Words,Lines,DurationMs,Filtered,Redirect,ContentType",
                );
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
