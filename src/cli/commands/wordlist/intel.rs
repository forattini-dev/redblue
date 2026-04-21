impl Command for WordlistIntelCommand {
  fn domain(&self) -> &str {
    "wordlist"
  }

  fn resource(&self) -> &str {
    "intel"
  }

  fn description(&self) -> &str {
    "Intelligent wordlist operations: context-aware resolution, mutation, and TF-IDF learning"
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
      "resolve" | "learn" | "extract" | "checkpoints" => {
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly)
      }
      _ => self.metadata().machine_output,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(machine_output)
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "resolve",
        summary: "Resolve context-aware wordlist for a scanning context",
        usage: "rb wordlist intel resolve <context> [--size small|medium|large]",
      },
      Route {
        verb: "mutate",
        summary: "Apply mutation rules to wordlist",
        usage: "rb wordlist intel mutate <file> --rules <rule1,rule2>",
      },
      Route {
        verb: "learn",
        summary: "Show learned words from previous scans",
        usage: "rb wordlist intel learn --from-scan <scan_id>",
      },
      Route {
        verb: "extract",
        summary: "Extract words from HTML/JS content using TF-IDF",
        usage: "rb wordlist intel extract <file_or_url>",
      },
      Route {
        verb: "checkpoints",
        summary: "List available scan checkpoints for resume",
        usage: "rb wordlist intel checkpoints",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output format (text, json)")
        .with_short('o')
        .with_default("text"),
      Flag::new("size", "Wordlist size: small, medium, large, or auto")
        .with_short('s')
        .with_default("auto"),
      Flag::new(
        "rules",
        "Mutation rules: leet, case, suffix, prefix, append-numbers",
      )
      .with_short('r'),
      Flag::new("from-scan", "Learn from scan ID"),
      Flag::new("domain", "Filter learned words by domain"),
      Flag::new("top", "Show top N words")
        .with_short('n')
        .with_default("100"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Resolve directory wordlist",
        "rb wordlist intel resolve directories --size medium",
      ),
      (
        "Resolve subdomain wordlist",
        "rb wordlist intel resolve subdomains --size large",
      ),
      (
        "Apply leet mutations",
        "rb wordlist intel mutate passwords.txt --rules leet,case",
      ),
      (
        "Extract words from HTML",
        "rb wordlist intel extract response.html --top 50",
      ),
      ("List scan checkpoints", "rb wordlist intel checkpoints"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "resolve" => self.resolve(ctx),
      "mutate" => self.mutate(ctx),
      "learn" => self.learn(ctx),
      "extract" => self.extract(ctx),
      "checkpoints" => self.checkpoints(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        Err("Invalid verb".to_string())
      }
    }
  }
}

impl WordlistIntelCommand {
  fn resolve(&self, ctx: &CliContext) -> Result<(), String> {
    let context_str = ctx.target.as_ref().ok_or(
            "Missing context.\nUsage: rb wordlist intel resolve <context>\n\nContexts: directories, files, subdomains, parameters, passwords, usernames",
        )?;

    use crate::modules::wordlist::{ContextResolver, WordlistContext, WordlistSize};

    let context = match context_str.to_lowercase().as_str() {
      "directories" | "dirs" | "dir" => WordlistContext::Directories,
      "files" | "file" => WordlistContext::Files,
      "subdomains" | "subdomain" | "sub" => WordlistContext::Subdomains,
      "parameters" | "params" | "param" => WordlistContext::Parameters,
      "passwords" | "password" | "pass" => WordlistContext::Passwords,
      "usernames" | "username" | "user" => WordlistContext::Usernames,
      other => WordlistContext::Custom(other.to_string()),
    };

    let size_str = ctx.get_flag("size").unwrap_or_else(|| "auto".to_string());
    let size = match size_str.to_lowercase().as_str() {
      "small" | "s" => WordlistSize::Small,
      "medium" | "m" => WordlistSize::Medium,
      "large" | "l" => WordlistSize::Large,
      _ => {
        // Auto-detect based on context (use default target for size suggestion)
        ContextResolver::suggest_size("", None)
      }
    };

    let recommendations = ContextResolver::recommended_wordlists(&context);

    let payload = wordlist_resolve_payload(&context, &size, &recommendations);
    if render::render_machine_output(ctx, "rb wordlist intel resolve", &payload)? {
      return Ok(());
    }

    Output::header(&format!("Wordlist Resolution: {:?}", context));
    Output::item("Context", &format!("{:?}", context));
    Output::item("Size", &format!("{:?}", size));

    Output::section("Recommended Wordlists");
    for name in &recommendations {
      println!("  • {}", name);
    }

    // Show extensions for this context
    let extensions = ContextResolver::context_extensions(&context);
    if !extensions.is_empty() {
      Output::section("Common Extensions");
      println!("  {}", extensions.join(", "));
    }

    Ok(())
  }

  fn mutate(&self, ctx: &CliContext) -> Result<(), String> {
    let path_str = ctx
      .target
      .as_ref()
      .ok_or("Missing wordlist path.\nUsage: rb wordlist intel mutate <file> --rules <rules>")?;

    let rules_str = ctx.get_flag("rules").ok_or(
            "Missing rules.\nUsage: rb wordlist intel mutate <file> --rules leet,case\n\nRules: leet, case, suffix, prefix, append-numbers",
        )?;

    use crate::modules::wordlist::loader::Loader;
    use crate::modules::wordlist::mutations::Mutator;
    use std::io::{BufRead, BufReader};

    let path = std::path::Path::new(path_str);
    let reader = Loader::open(path).map_err(|e| e.to_string())?;
    let buf_reader = BufReader::new(reader);
    let lines: Result<Vec<String>, _> = buf_reader.lines().collect();
    let words = lines.map_err(|e| e.to_string())?;

    // Parse rules
    let rules: Vec<&str> = rules_str.split(',').map(|s| s.trim()).collect();

    let mut mutated: std::collections::HashSet<String> = std::collections::HashSet::new();

    for word in &words {
      // Always include original
      mutated.insert(word.clone());

      for rule in &rules {
        let mutations: Vec<String> = match *rule {
          "leet" | "l33t" => vec![Mutator::l33t(word)],
          "case" => Mutator::common_mutations(word),
          "suffix" => {
            let suffixes = ["123", "1", "!", "@", "2024", "2025"];
            suffixes.iter().map(|s| format!("{}{}", word, s)).collect()
          }
          "prefix" => {
            let prefixes = ["the", "my", "admin", "root", "test"];
            prefixes.iter().map(|p| format!("{}{}", p, word)).collect()
          }
          "append-numbers" | "numbers" => Mutator::append_numbers(word, 99),
          _ => vec![],
        };
        mutated.extend(mutations);
      }
    }

    for word in mutated {
      println!("{}", word);
    }

    Ok(())
  }

  fn learn(&self, ctx: &CliContext) -> Result<(), String> {
    let top_n: usize = ctx
      .get_flag("top")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    // Note: This is a placeholder - actual learned words would come from storage
    Output::warning("TF-IDF learning integration requires active scan data");
    Output::info("Learned words are captured during scans with --learn-words flag");

    let payload = wordlist_learn_payload(top_n);
    if render::render_machine_output(ctx, "rb wordlist intel learn", &payload)? {
    } else {
      Output::header("Learned Words");
      println!("\n  No learned words found in storage.");
      println!("\n  To learn words during a scan:");
      println!("    rb web fuzz http://target/FUZZ --learn-words");
      println!("\n  To view learned words after a scan:");
      println!(
        "    rb wordlist intel learn --from-scan <scan_id> --top {}",
        top_n
      );
    }

    Ok(())
  }

  fn extract(&self, ctx: &CliContext) -> Result<(), String> {
    let path_str = ctx.target.as_ref().ok_or(
            "Missing file path.\nUsage: rb wordlist intel extract <file>\nExample: rb wordlist intel extract response.html",
        )?;

    let top_n: usize = ctx
      .get_flag("top")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    // Read file
    let content =
      std::fs::read_to_string(path_str).map_err(|e| format!("Failed to read file: {}", e))?;

    use crate::modules::wordlist::{Document, TfIdfEngine, WordExtractor};

    // Extract words
    let extractor = WordExtractor::with_defaults();
    let result = extractor.extract(&content);

    if result.is_empty() {
      let payload = wordlist_extract_empty_payload();
      if render::render_machine_output(ctx, "rb wordlist intel extract", &payload)? {
      } else {
        Output::warning("No words extracted from content");
      }
      return Ok(());
    }

    // Calculate TF-IDF scores
    let mut engine = TfIdfEngine::with_defaults();
    engine.add_document(Document::new(path_str, result.all_words.clone()));
    let scores = engine.top_words(top_n);

    let payload = wordlist_extract_payload(path_str, result.all_words.len(), &scores);
    if render::render_machine_output(ctx, "rb wordlist intel extract", &payload)? {
      return Ok(());
    }

    Output::header(&format!("Word Extraction: {}", path_str));
    Output::item("Total Extracted", &result.all_words.len().to_string());
    Output::item("Text Words", &result.text_words.len().to_string());
    Output::item("Path Words", &result.path_words.len().to_string());
    Output::item("Form Fields", &result.form_fields.len().to_string());
    Output::item("JS Identifiers", &result.js_identifiers.len().to_string());

    Output::section(&format!(
      "Top {} Words (TF-IDF Scored)",
      top_n.min(scores.len())
    ));
    println!("{:<30} {:>10}", "WORD", "SCORE");
    println!("{}", "━".repeat(45));

    for word in scores.iter().take(top_n) {
      println!("{:<30} {:>10.4}", word.word, word.tfidf);
    }

    Ok(())
  }

  fn checkpoints(&self, ctx: &CliContext) -> Result<(), String> {
    use crate::modules::web::fuzzer::ResumeManager;

    let manager = ResumeManager::with_defaults();
    let checkpoints = manager.list_checkpoints();

    let payload = wordlist_checkpoints_payload(&checkpoints);
    if render::render_machine_output(ctx, "rb wordlist intel checkpoints", &payload)? {
      return Ok(());
    }

    Output::header("Scan Checkpoints");

    if checkpoints.is_empty() {
      Output::info("No checkpoints found");
      println!("\n  Checkpoints are created during scans with --checkpoint flag:");
      println!("    rb web fuzz http://target/FUZZ --checkpoint");
      println!("\n  To resume a scan:");
      println!("    rb web fuzz --resume <scan_id>");
      return Ok(());
    }

    println!(
      "{:<20} {:<40} {:>8} {:>10}",
      "SCAN ID", "TARGET", "PROGRESS", "ELAPSED"
    );
    println!("{}", "━".repeat(85));

    for cp in &checkpoints {
      let target_display = if cp.target_url.len() > 38 {
        format!("{}...", &cp.target_url[..35])
      } else {
        cp.target_url.clone()
      };

      println!(
        "{:<20} {:<40} {:>7.1}% {:>10}",
        &cp.scan_id.as_str()[..16.min(cp.scan_id.as_str().len())],
        target_display,
        cp.progress_percent,
        cp.elapsed_string()
      );
    }

    println!("\n  Total: {} checkpoint(s)", checkpoints.len());
    println!("\n  To resume a scan: rb web fuzz --resume <scan_id>");

    Ok(())
  }
}

