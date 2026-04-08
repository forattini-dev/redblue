use redblue::{cli, config, utils::logger};

use cli::{args, commands, output::Output};
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
      // Build a minimal CliContext from positional args for help routing
      let ctx = build_ctx_from_args(&args);
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
      let ctx = build_ctx_from_args(&args);
      handle_shell_command(&ctx);
    }
    Err(args::ParseError::Other(ref msg)) if msg == "commands" => {
      commands::print_all_commands();
    }
    Err(args::ParseError::Other(ref msg)) if msg == "magic_scan" => {
      // Magic scan: build context and dispatch to the scan/magic handler
      let mut ctx = build_ctx_from_args(&args);
      // The target is the first non-flag arg (URL, IP, or domain)
      if ctx.target.is_none() {
        ctx.target = ctx.domain.take();
      }
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
    Err(args::ParseError::MissingVerb {
      domain,
      resource,
      available,
    }) => {
      Output::error(&format!("Missing verb for '{} {}'", domain, resource));
      if !available.is_empty() {
        println!("\nAvailable verbs:\n  {}", available.join("\n  "));
      }
      std::process::exit(1);
    }
    Err(e) => {
      Output::error(&e.to_string());
      std::process::exit(1);
    }
  }
}

/// Build a minimal CliContext by extracting positional args and flags from argv.
/// This replaces the old parser::parse_args for help/shell/magic_scan contexts.
fn build_ctx_from_args(args: &[String]) -> cli::CliContext {
  let mut ctx = cli::CliContext {
    raw: args.to_vec(),
    ..Default::default()
  };

  let mut positionals = Vec::new();
  let mut i = 0;
  while i < args.len() {
    let arg = &args[i];
    if arg == "--" {
      positionals.extend_from_slice(&args[i + 1..]);
      break;
    }
    if let Some(stripped) = arg.strip_prefix("--") {
      if let Some((key, val)) = stripped.split_once('=') {
        ctx.flags.insert(key.to_string(), val.to_string());
      } else {
        let key = stripped.to_string();
        if i + 1 < args.len() && !args[i + 1].starts_with('-') {
          ctx.flags.insert(key, args[i + 1].clone());
          i += 1;
        } else {
          ctx.flags.insert(key, "true".to_string());
        }
      }
    } else if arg.starts_with('-') && arg.len() == 2 {
      let key = arg[1..].to_string();
      ctx.flags.insert(key, "true".to_string());
    } else {
      positionals.push(arg.clone());
    }
    i += 1;
  }

  // Map positionals to domain/resource/verb/target/args
  if let Some(d) = positionals.first() {
    ctx.domain = Some(d.clone());
  }
  if let Some(r) = positionals.get(1) {
    ctx.resource = Some(r.clone());
  }
  if let Some(v) = positionals.get(2) {
    ctx.verb = Some(v.clone());
  }
  if let Some(t) = positionals.get(3) {
    ctx.target = Some(t.clone());
  }
  if positionals.len() > 4 {
    ctx.args = positionals[4..].to_vec();
  }

  ctx
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
