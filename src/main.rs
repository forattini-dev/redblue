use redblue::{cli, config, utils::logger};

use cli::{commands, output::Output, parser};
use std::env;

fn main() {
    // Load configuration once at startup so downstream modules can access it.
    let _config = config::init();

    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        commands::print_global_help();
        return;
    }

    let ctx = match parser::parse_args(&args) {
        Ok(ctx) => ctx,
        Err(e) => {
            Output::error(&e);
            std::process::exit(1);
        }
    };

    // Enable verbose logging if --verbose flag is present
    if ctx.has_flag("verbose") || ctx.has_flag("v") {
        logger::enable_verbose();
    }

    if ctx.has_flag("version") {
        print_version();
        return;
    }

    if ctx.has_flag("h") || ctx.has_flag("help") {
        handle_help_flag(&ctx);
        return;
    }

    if let Some(domain) = ctx.domain_only() {
        match domain {
            "help" => {
                handle_help_command(&ctx);
                return;
            }
            "version" => {
                print_version();
                return;
            }
            "repl" => {
                handle_repl_command(&ctx);
                return;
            }
            _ => {}
        }
    }

    if let Err(e) = commands::dispatch(&ctx) {
        Output::error(&e);
        std::process::exit(1);
    }

    let _ = maybe_create_rbdb(&ctx);
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
    if ctx.resource.is_some() {
        Output::error(
            "Use `rb <domain> help` or `rb <domain> <resource> help` for contextual help.",
        );
        commands::print_global_help();
        return;
    }

    commands::print_global_help();
}

fn handle_repl_command(ctx: &cli::CliContext) {
    let target = ctx.resource.as_ref().or(ctx.target.as_ref());

    let target = match target {
        Some(t) => t.to_string(),
        None => {
            Output::error("Usage: rb repl <target>");
            Output::info("  rb repl example.com");
            Output::info(&format!(
                "  rb repl example{}",
                redblue::storage::session::SessionFile::EXTENSION
            ));
            Output::info("  rb repl www.tetis.io");
            std::process::exit(1);
        }
    };

    // Check if --classic flag is set for old REPL
    let use_tui = !ctx.has_flag("classic");

    if use_tui {
        // Use fullscreen TUI (default)
        if let Err(e) = cli::tui::start_tui(target) {
            Output::error(&e);
            std::process::exit(1);
        }
    } else {
        // Use classic line-based REPL
        if let Err(e) = cli::repl::start_repl(target) {
            Output::error(&e);
            std::process::exit(1);
        }
    }
}

fn print_version() {
    println!("RedBlue CLI v{}", env!("CARGO_PKG_VERSION"));
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

    let session_path =
        env::current_dir()?.join(format!("{}{}", identifier, SessionFile::EXTENSION));
    if session_path.exists() {
        return Ok(());
    }

    SessionFile::create(target, &ctx.raw)
        .map(|_| ())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
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

    let without_user = without_scheme.split('@').last().unwrap_or(without_scheme);
    let base = without_user
        .trim_start_matches('/')
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()
        .unwrap_or(without_user);
    let host_str = if base.starts_with('[') && base.ends_with(']') {
        base.trim_start_matches('[').trim_end_matches(']')
    } else if let Some(idx) = base.rfind(':') {
        if base[idx + 1..].chars().all(|ch| ch.is_ascii_digit()) {
            &base[..idx]
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
