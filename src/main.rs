use redblue::{cli, config, utils::logger};

use cli::{args, commands, output::Output, parser};
use std::env;

fn main() {
  // Load configuration once at startup so downstream modules can access it.
  let _config = config::init();

  let raw_args: Vec<String> = env::args().skip(1).collect();
  let stealth_profile = parse_stealth_flag(&raw_args);

  // --stealth / -S activates heap jitter with the specified profile.
  let _heap_guard = stealth_profile
    .as_ref()
    .map(|profile| force_heap_jitter(profile.as_deref()));

  let args = raw_args;

  if args.is_empty() {
    commands::print_global_help();
    return;
  }

  // Try the new schema-driven parser first.
  // It returns (CliContext, &Command) on success, or ParseError for
  // special commands (help/version/shell) and validation failures.
  match args::parse_and_route(&args) {
    Ok((ctx, command)) => {
      Output::set_machine_mode(ctx.get_output_format() != cli::format::OutputFormat::Human);
      if ctx.has_flag("verbose") || ctx.has_flag("v") {
        logger::enable_verbose();
      }

      if let Err(e) = command.execute(&ctx) {
        Output::error(&e);
        std::process::exit(1);
      }

      // Post-dispatch stealth rehash
      if stealth_profile.is_some() {
        if let Err(e) = redblue::modules::evasion::rehash::rehash() {
          eprintln!("warning: stealth rehash failed: {}", e);
        }
      }

      let _ = maybe_create_rbdb(&ctx);
    }
    Err(args::ParseError::HelpRequested { .. }) => {
      // Re-parse with old parser for help context (help handlers need CliContext)
      let ctx = parser::parse_args(&args).unwrap_or_default();
      if ctx.domain.is_some() {
        handle_help_flag(&ctx);
      } else {
        commands::print_global_help();
      }
    }
    Err(args::ParseError::VersionRequested { .. }) => {
      print_version();
    }
    Err(args::ParseError::Other(ref msg)) if msg == "shell" => {
      let ctx = parser::parse_args(&args).unwrap_or_default();
      handle_shell_command(&ctx);
    }
    Err(args::ParseError::Other(ref msg)) if msg == "commands" => {
      commands::print_all_commands();
    }
    Err(args::ParseError::Other(ref msg)) if msg == "magic_scan" => {
      // Fallback to old dispatch for magic scan (auto-detect target type)
      let ctx = parser::parse_args(&args).unwrap_or_default();
      if let Err(e) = commands::dispatch(&ctx) {
        Output::error(&e);
        std::process::exit(1);
      }
    }
    Err(args::ParseError::MissingResource { domain, available }) => {
      Output::error(&format!("Missing resource for domain '{}'", domain));
      if !available.is_empty() {
        println!("\nAvailable resources:\n  {}", available.join("\n  "));
      }
      std::process::exit(1);
    }
    Err(args::ParseError::MissingVerb { domain, resource, available }) => {
      Output::error(&format!("Missing verb for '{} {}'", domain, resource));
      if !available.is_empty() {
        println!("\nAvailable verbs:\n  {}", available.join("\n  "));
      }
      std::process::exit(1);
    }
    Err(e) => {
      // Fallback: try old parser + dispatch for anything the new parser can't handle yet
      match parser::parse_args(&args) {
        Ok(ctx) => {
          Output::set_machine_mode(ctx.get_output_format() != cli::format::OutputFormat::Human);
          if ctx.has_flag("verbose") || ctx.has_flag("v") {
            logger::enable_verbose();
          }
          if let Err(dispatch_err) = commands::dispatch(&ctx) {
            // Both parsers failed — show the new parser's error (better messages)
            Output::error(&e.to_string());
            std::process::exit(1);
          }
        }
        Err(_) => {
          Output::error(&e.to_string());
          std::process::exit(1);
        }
      }
    }
  }

}

fn handle_help_flag(ctx: &cli::CliContext) {
  if let Some(domain) = ctx.domain.as_deref() {
    if let Some(resource) = ctx.resource.as_deref() {
      if resource == "help" {
        if let Some(target_resource) = ctx.verb.as_deref() {
          if let Some(command) = commands::command_for(domain, target_resource) {
            commands::print_help(command);
            return;
          }

          Output::error(&format!(
            "Unknown resource '{}' in domain '{}'",
            target_resource, domain
          ));
          commands::print_global_help();
          return;
        }

        if let Err(err) = commands::print_domain_overview(domain) {
          Output::error(&err);
          commands::print_global_help();
        }
        return;
      }

      if let Some(command) = commands::command_for(domain, resource) {
        commands::print_help(command);
        return;
      }

      Output::error(&format!(
        "Unknown resource '{}' in domain '{}'",
        resource, domain
      ));
      commands::print_global_help();
      return;
    }

    if let Err(err) = commands::print_domain_overview(domain) {
      Output::error(&err);
      commands::print_global_help();
    }
    return;
  }

  commands::print_global_help();
}

fn handle_help_command(ctx: &cli::CliContext) {
  let Some(domain_token) = ctx.resource.as_deref() else {
    commands::print_global_help();
    return;
  };

  let domain = cli::aliases::resolve_domain_alias(domain_token);
  if cli::schema::find_domain_node(domain, false).is_none() {
    Output::error(&format!(
      "Unknown domain '{}'.{}",
      domain_token,
      suggest_domains_text(domain_token)
    ));
    commands::print_global_help();
    return;
  }

  let Some(resource_token) = ctx.verb.as_deref() else {
    if let Err(err) = commands::print_domain_overview(domain) {
      Output::error(&err);
      commands::print_global_help();
    }
    return;
  };

  let resource = cli::aliases::resolve_resource_alias(resource_token);
  let Some(command) = commands::command_for(domain, resource) else {
    Output::error(&format!(
      "Unknown resource '{}' in domain '{}'.{}",
      resource_token,
      domain,
      suggest_resources_text(domain, resource_token)
    ));
    return;
  };

  let Some(verb_token) = ctx.target.as_deref() else {
    commands::print_help(command);
    return;
  };

  let verb = cli::aliases::resolve_verb_alias(verb_token);
  if let Some(route) = command
    .routes()
    .into_iter()
    .find(|route| route.verb == verb)
  {
    let route_metadata = command.route_metadata(route.verb);
    let flags = command.flags();
    let examples = route_help_examples(command, domain, resource, verb);

    Output::header(&format!("{} {} {}", domain, resource, verb));
    println!("\n\x1b[1mSUMMARY:\x1b[0m");
    println!("  {}", route.summary);
    println!("\n\x1b[1mUSAGE:\x1b[0m");
    println!("  {}", route.usage);
    println!("\n\x1b[1mMACHINE OUTPUT:\x1b[0m");
    println!(
      "  {}",
      cli::schema::machine_output_summary(route_metadata.machine_output)
    );
    if !route_metadata.aliases.is_empty() {
      println!("  aliases: {}", route_metadata.aliases.join(", "));
    }

    if !flags.is_empty() {
      println!("\n\x1b[1mFLAGS:\x1b[0m");
      for flag in flags {
        let mut label = format!("--{}", flag.long);
        if let Some(short) = flag.short {
          label = format!("{}, -{}", label, short);
        }
        if let Some(arg) = flag.arg.as_ref() {
          label = format!("{} <{}>", label, arg);
        }
        if let Some(default) = flag.default.as_ref() {
          println!(
            "  {:<28} {} (default: {})",
            label, flag.description, default
          );
        } else {
          println!("  {:<28} {}", label, flag.description);
        }
      }
    }

    if !examples.is_empty() {
      println!("\n\x1b[1mEXAMPLES:\x1b[0m");
      for (summary, command_line) in examples {
        if summary.is_empty() {
          println!("  {}", command_line);
        } else {
          println!("  {}: {}", summary, command_line);
        }
      }
    }
    return;
  }

  Output::error(&format!(
    "Unknown verb '{}' for '{} {}'.{}",
    verb_token,
    domain,
    resource,
    suggest_routes_text(domain, resource, verb_token)
  ));
}

fn suggest_domains_text(input: &str) -> String {
  let suggestions = cli::schema::suggest_domains(input, 3, false);
  if suggestions.is_empty() {
    String::new()
  } else {
    format!(
      "\n\nDid you mean one of these canonical domains?\n  {}",
      suggestions.join("\n  ")
    )
  }
}

fn suggest_resources_text(domain: &str, resource: &str) -> String {
  let suggestions = cli::schema::suggest_resources(domain, resource, 3);
  if suggestions.is_empty() {
    String::new()
  } else {
    format!(
      "\n\nDid you mean one of these canonical resources?\n  {}",
      suggestions.join("\n  ")
    )
  }
}

fn suggest_routes_text(domain: &str, resource: &str, verb: &str) -> String {
  let suggestions = cli::schema::suggest_route_commands(domain, resource, verb, 3);
  if suggestions.is_empty() {
    String::new()
  } else {
    format!(
      "\n\nDid you mean one of these canonical routes?\n  {}",
      suggestions.join("\n  ")
    )
  }
}

fn route_help_examples(
  command: &dyn commands::Command,
  domain: &str,
  resource: &str,
  verb: &str,
) -> Vec<(String, String)> {
  let route_prefix = format!("rb {} {} {}", domain, resource, verb);
  let mut filtered = Vec::new();
  let mut fallback = Vec::new();

  for (summary, command_line) in command.examples() {
    let summary_text = summary.to_string();
    let command_text = command_line.to_string();
    if command_line.starts_with(&route_prefix) {
      filtered.push((summary_text, command_text));
    } else {
      fallback.push((summary_text, command_text));
    }
  }

  if !filtered.is_empty() {
    return filtered;
  }

  fallback.into_iter().take(3).collect()
}

fn handle_shell_command(ctx: &cli::CliContext) {
  let target = ctx.resource.as_ref().or(ctx.target.as_ref());

  let target = match target {
    Some(t) => t.to_string(),
    None => {
      Output::error("Usage: rb shell <target>");
      Output::info("  rb shell example.com");
      Output::info(&format!(
        "  rb shell example{}",
        redblue::storage::session::SessionFile::EXTENSION
      ));
      Output::info("  rb shell www.tetis.io");
      std::process::exit(1);
    }
  };

  // Launch fullscreen TUI shell
  if let Err(e) = cli::tui::start_tui(target) {
    Output::error(&e);
    std::process::exit(1);
  }
}

fn print_version() {
  println!("RedBlue CLI v{}", redblue::version::current_version());
  println!("Built with Rust from scratch");
}

fn maybe_create_rbdb(ctx: &cli::CliContext) -> Result<(), std::io::Error> {
  use redblue::storage::session::SessionFile;

  let target = match ctx.target.as_deref() {
    Some(t) => t,
    None => return Ok(()),
  };

  let identifier = match extract_target_identifier(target) {
    Some(id) => id,
    None => return Ok(()),
  };

  let session_path = env::current_dir()?.join(format!("{}{}", identifier, SessionFile::EXTENSION));
  if session_path.exists() {
    return Ok(());
  }

  SessionFile::create(target, &ctx.raw)
    .map(|_| ())
    .map_err(std::io::Error::other)
}

fn extract_target_identifier(target: &str) -> Option<String> {
  let trimmed = target.trim();
  if trimmed.is_empty() {
    return None;
  }

  let without_scheme = if let Some(idx) = trimmed.find("://") {
    &trimmed[idx + 3..]
  } else {
    trimmed
  };

  let without_user = without_scheme
    .split('@')
    .next_back()
    .unwrap_or(without_scheme);
  let base = without_user
    .trim_start_matches('/')
    .split(['/', '?', '#'])
    .next()
    .unwrap_or(without_user);
  let host_str = if let Some(rest) = base.strip_prefix('[') {
    if let Some(end) = rest.find(']') {
      &rest[..end]
    } else {
      base
    }
  } else if base.matches(':').count() == 1 {
    if let Some(idx) = base.rfind(':') {
      if base[idx + 1..].chars().all(|ch| ch.is_ascii_digit()) {
        &base[..idx]
      } else {
        base
      }
    } else {
      base
    }
  } else {
    base
  };

  if host_str.is_empty() {
    return None;
  }

  let mut sanitized = String::with_capacity(host_str.len());
  for ch in host_str.chars() {
    let mapped = match ch {
      'a'..='z' | '0'..='9' | '.' | '-' | '_' => ch,
      'A'..='Z' => ch.to_ascii_lowercase(),
      _ => '_',
    };
    sanitized.push(mapped);
  }

  if sanitized.is_empty() {
    None
  } else {
    Some(sanitized)
  }
}

/// Parse --stealth / -S from raw args before full parsing.
/// Returns Some(optional_profile) if stealth is active, None otherwise.
///   -S            → Some(None)         → default profile
///   -S nodejs     → Some(Some("nodejs")) → explicit profile
///   --stealth=browser → Some(Some("browser"))
fn parse_stealth_flag(args: &[String]) -> Option<Option<String>> {
  let known_profiles = ["browser", "nodejs", "node", "system", "random"];

  for (i, arg) in args.iter().enumerate() {
    // --stealth=<profile>
    if let Some(val) = arg.strip_prefix("--stealth=") {
      return Some(Some(val.to_string()));
    }
    // --stealth or --stealth <profile>
    if arg == "--stealth" {
      if let Some(next) = args.get(i + 1) {
        if known_profiles.contains(&next.as_str()) {
          return Some(Some(next.to_string()));
        }
      }
      return Some(None);
    }
    // -S or -S <profile>
    if arg == "-S" {
      if let Some(next) = args.get(i + 1) {
        if known_profiles.contains(&next.as_str()) {
          return Some(Some(next.to_string()));
        }
      }
      return Some(None);
    }
  }
  None
}

/// Force heap jitter activation (used by --stealth flag).
/// Uses the explicit profile, then env var, then defaults to Random.
fn force_heap_jitter(
  profile_name: Option<&str>,
) -> redblue::modules::evasion::heap_jitter::HeapJitter {
  use redblue::modules::evasion::heap_jitter::{HeapJitter, JitterProfile};

  let profile = profile_name
    .and_then(JitterProfile::from_name)
    .or_else(|| {
      env::var("REDBLUE_HEAP_PROFILE")
        .ok()
        .and_then(|name| JitterProfile::from_name(&name))
    })
    .unwrap_or(JitterProfile::Random);

  let mut jitter = HeapJitter::new(profile);
  jitter.activate();
  jitter.spray_decoys(50);
  jitter
}
