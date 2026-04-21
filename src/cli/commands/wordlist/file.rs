pub struct WordlistFileCommand;

impl Command for WordlistFileCommand {
  fn domain(&self) -> &str {
    "wordlist"
  }

  fn resource(&self) -> &str {
    "file"
  }

  fn description(&self) -> &str {
    "Operations on local wordlist files"
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
    let machine_output = match verb {
      "info" => crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      _ => self.metadata().machine_output,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(machine_output)
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "info",
        summary: "Show wordlist file statistics and preview",
        usage: "rb wordlist file info <path>",
      },
      Route {
        verb: "filter",
        summary: "Filter wordlist by pattern or length",
        usage: "rb wordlist file filter <path> --pattern <str> --min <n> --max <n>",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output format (text, json, yaml)")
        .with_short('o')
        .with_default("text"),
      Flag::new("pattern", "Filter by pattern (substring)").with_arg("str"),
      Flag::new("min", "Minimum length").with_arg("n"),
      Flag::new("max", "Maximum length").with_arg("n"),
      Flag::new("inverse", "Invert pattern match (grep -v)"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Show stats for a wordlist",
        "rb wordlist file info rockyou.txt",
      ),
      (
        "Filter words containing 'admin'",
        "rb wordlist file filter rockyou.txt --pattern admin",
      ),
      (
        "Filter passwords > 8 chars",
        "rb wordlist file filter rockyou.txt --min 8",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "info" => self.info(ctx),
      "filter" => self.filter(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        Err("Invalid verb".to_string())
      }
    }
  }
}

impl WordlistFileCommand {
  fn info(&self, ctx: &CliContext) -> Result<(), String> {
    let path_str = ctx
      .target
      .as_ref()
      .ok_or("Missing wordlist path.\nUsage: rb wordlist file info <path>")?;
    let path = std::path::Path::new(path_str);

    if !path.exists() {
      let payload = wordlist_file_error_payload(path_str, "File not found");
      render::render_machine_output(ctx, "rb wordlist file info", &payload)?;
      return Err(format!("File not found: {}", path_str));
    }

    use crate::modules::wordlist::analysis::Analyzer;
    use crate::modules::wordlist::loader::Loader;
    use std::io::{BufRead, BufReader};

    let reader = Loader::open(path).map_err(|e| e.to_string())?;
    let buf_reader = BufReader::new(reader);

    let lines: Result<Vec<String>, _> = buf_reader.lines().collect();
    let lines = lines.map_err(|e| e.to_string())?;

    let stats = Analyzer::analyze(&lines);

    let payload = wordlist_file_info_payload(path_str, &stats, &lines);
    if render::render_machine_output(ctx, "rb wordlist file info", &payload)? {
      return Ok(());
    }

    Output::header(&format!("Wordlist Analysis: {}", path_str));

    Output::item("Lines", &stats.line_count.to_string());
    Output::item("Unique", &stats.unique_count.to_string());
    Output::item("Avg Length", &format!("{:.1}", stats.avg_length));
    Output::item("Min Length", &stats.min_length.to_string());
    Output::item("Max Length", &stats.max_length.to_string());
    Output::item("Charset", &stats.charset);

    // Preview
    Output::section("Preview (first 10)");
    for line in lines.iter().take(10) {
      println!("  {}", line);
    }

    Ok(())
  }

  fn filter(&self, ctx: &CliContext) -> Result<(), String> {
    let path_str = ctx
      .target
      .as_ref()
      .ok_or("Missing wordlist path.\nUsage: rb wordlist file filter <path>")?;
    let path = std::path::Path::new(path_str);

    use crate::modules::wordlist::filter::Filter;
    use crate::modules::wordlist::loader::Loader;
    use std::io::{BufRead, BufReader};

    let reader = Loader::open(path).map_err(|e| e.to_string())?;
    let buf_reader = BufReader::new(reader);
    let lines: Result<Vec<String>, _> = buf_reader.lines().collect();
    let mut words = lines.map_err(|e| e.to_string())?;

    // Apply length filter
    let min = ctx.get_flag("min").and_then(|s| s.parse().ok());
    let max = ctx.get_flag("max").and_then(|s| s.parse().ok());

    if min.is_some() || max.is_some() {
      words = Filter::by_length(words, min, max);
    }

    // Apply pattern filter
    if let Some(pattern) = ctx.get_flag("pattern") {
      let inverse = ctx.has_flag("inverse");
      words = Filter::by_pattern(words, &pattern, inverse);
    }

    for w in words {
      println!("{}", w);
    }

    Ok(())
  }
}

/// Intelligent wordlist operations (context resolution, mutation, learning)
pub struct WordlistIntelCommand;

