//! Path and parameter enumeration CLI commands
//!
//! Exposes the path-enumerator and param-enumerator modules through the
//! `rb web asset paths` and `rb web asset params` verbs.

use crate::cli::format::OutputFormat;
use crate::cli::output::Output;
use crate::cli::render;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::json;
use crate::modules::web::param_enumerator::{ParamConfig, ParamEnumerator};
use crate::modules::web::path_enumerator::{PathEnumConfig, PathEnumerator, PathSource};

use super::types::guard_plain_http;

// ---------------------------------------------------------------------------
// Path enumeration
// ---------------------------------------------------------------------------

/// Discover paths and directories
pub fn paths(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
    "Missing URL. Usage: rb web asset paths <URL> [--brute]\nExample: rb web asset paths https://example.com",
  )?;

  Validator::validate_url(url)?;
  guard_plain_http(url, "rb web asset paths")?;

  let format = ctx.get_output_format();

  let brute = ctx.has_flag("brute");
  let wordlist = ctx.get_flag("wordlist");
  let recursive = ctx.has_flag("recursive");
  let extensions: Vec<String> = ctx
    .get_flag("extensions")
    .map(|e| e.split(',').map(|s| s.trim().to_string()).collect())
    .unwrap_or_default();
  let threads = ctx
    .get_flag("threads")
    .and_then(|t| t.parse().ok())
    .unwrap_or(10);
  let depth = ctx
    .get_flag("depth")
    .and_then(|d| d.parse().ok())
    .unwrap_or(3);

  let config = PathEnumConfig {
    brute,
    wordlist,
    recursive,
    extensions,
    threads,
    max_depth: depth,
    ..Default::default()
  };

  if format == OutputFormat::Human {
    if brute || config.wordlist.is_some() {
      Output::spinner_start("Enumerating paths (passive + active)");
    } else {
      Output::spinner_start("Enumerating paths (passive only)");
    }
  }

  let enumerator = PathEnumerator::new(config);
  let results = enumerator.enumerate(url);

  if format == OutputFormat::Human {
    Output::spinner_done();
  }

  // Build JSON payload
  let paths_json: Vec<_> = results
    .iter()
    .map(|p| {
      let source_str = match p.source {
        PathSource::Robots => "robots.txt",
        PathSource::Sitemap => "sitemap.xml",
        PathSource::SecurityTxt => "security.txt",
        PathSource::HtmlLink => "html-link",
        PathSource::JsExtract => "js-extract",
        PathSource::Brute => "brute",
      };
      json!({
        "url": p.url,
        "path": p.path,
        "status": p.status,
        "size": p.size,
        "content_type": p.content_type,
        "redirect_to": p.redirect_to.clone(),
        "source": source_str,
        "depth": p.depth
      })
    })
    .collect();
  let payload = json!({
    "url": url,
    "paths_found": results.len(),
    "paths": paths_json
  });

  if render::render_machine_output_with_yaml(ctx, "rb web asset paths", &payload, || {
    println!("url: {}", url);
    println!("paths_found: {}", results.len());
    println!("paths:");
    for p in &results {
      let source_str = match p.source {
        PathSource::Robots => "robots.txt",
        PathSource::Sitemap => "sitemap.xml",
        PathSource::SecurityTxt => "security.txt",
        PathSource::HtmlLink => "html-link",
        PathSource::JsExtract => "js-extract",
        PathSource::Brute => "brute",
      };
      println!("  - path: {}", p.path);
      println!("    status: {}", p.status);
      println!("    size: {}", p.size);
      println!("    source: {}", source_str);
      if let Some(ref redir) = p.redirect_to {
        println!("    redirect_to: {}", redir);
      }
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  Output::header("Path Enumeration");
  Output::item("URL", url);
  Output::item("Paths Found", &results.len().to_string());
  if !brute {
    Output::info("Passive mode only. Use --brute to enable active probing.");
  }
  println!();

  if results.is_empty() {
    Output::warning("No paths discovered");
  } else {
    println!(
      "  {:<6} {:<7} {:<40} {:<14} {}",
      "STATUS", "SIZE", "PATH", "SOURCE", "REDIRECT"
    );
    println!("  {}", "-".repeat(85));

    for p in &results {
      let status_color = match p.status {
        200..=299 => "\x1b[32m",
        300..=399 => "\x1b[33m",
        400..=499 => "\x1b[91m",
        500..=599 => "\x1b[31m",
        _ => "\x1b[0m",
      };
      let source_label = match p.source {
        PathSource::Robots => "robots.txt",
        PathSource::Sitemap => "sitemap",
        PathSource::SecurityTxt => "security.txt",
        PathSource::HtmlLink => "html-link",
        PathSource::JsExtract => "js-extract",
        PathSource::Brute => "brute",
      };
      let redirect = p.redirect_to.as_deref().unwrap_or("");

      let path_display = if p.path.len() > 38 {
        format!("{}...", &p.path[..35])
      } else {
        p.path.clone()
      };

      println!(
        "  {}{:<6}\x1b[0m {:<7} {:<40} {:<14} {}",
        status_color, p.status, p.size, path_display, source_label, redirect
      );
    }
  }

  println!();
  Output::success("Path enumeration completed");

  Ok(())
}

// ---------------------------------------------------------------------------
// Parameter enumeration
// ---------------------------------------------------------------------------

/// Discover hidden parameters
pub fn params(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
    "Missing URL. Usage: rb web asset params <URL> --brute\nExample: rb web asset params https://example.com/page --brute",
  )?;

  Validator::validate_url(url)?;
  guard_plain_http(url, "rb web asset params")?;

  let format = ctx.get_output_format();

  let brute = ctx.has_flag("brute");
  let wordlist = ctx.get_flag("wordlist");
  let method = ctx.get_flag_or("method", "GET").to_uppercase();
  let threads = ctx
    .get_flag("threads")
    .and_then(|t| t.parse().ok())
    .unwrap_or(10);

  if !brute && wordlist.is_none() {
    let payload = json!({
      "url": url,
      "error": "Parameter enumeration requires --brute flag or --wordlist for safety"
    });
    if render::render_machine_output_with_yaml(ctx, "rb web asset params", &payload, || {
      println!("url: {}", url);
      println!("error: Parameter enumeration requires --brute flag or --wordlist for safety");
      Ok(())
    })? {
      return Ok(());
    }

    Output::header("Parameter Discovery");
    Output::item("URL", url);
    println!();
    Output::warning("Parameter enumeration sends many requests to the target.");
    Output::info("Use --brute to confirm active probing, or --wordlist to provide a custom list.");
    return Ok(());
  }

  let config = ParamConfig {
    threads,
    method: method.clone(),
    brute: true, // Already confirmed via the check above
    wordlist,
    ..Default::default()
  };

  if format == OutputFormat::Human {
    Output::spinner_start(&format!("Discovering parameters ({} method)", method));
  }

  let enumerator = ParamEnumerator::new(config);
  let results = enumerator.enumerate(url);

  if format == OutputFormat::Human {
    Output::spinner_done();
  }

  // Build JSON payload
  let params_json: Vec<_> = results
    .iter()
    .map(|p| {
      let diff_str = match &p.diff {
        crate::modules::web::param_enumerator::ParamDiff::StatusChanged { from, to } => {
          format!("status-changed:{}>{}", from, to)
        }
        crate::modules::web::param_enumerator::ParamDiff::SizeChanged { delta, .. } => {
          format!("size-changed:{:+}", delta)
        }
        crate::modules::web::param_enumerator::ParamDiff::Reflected => "reflected".to_string(),
        crate::modules::web::param_enumerator::ParamDiff::HeaderAdded { header } => {
          format!("header-added:{}", header)
        }
        crate::modules::web::param_enumerator::ParamDiff::NoChange => "no-change".to_string(),
      };
      json!({
        "name": p.name,
        "method": p.method,
        "diff": diff_str,
        "response_status": p.response_status,
        "response_size": p.response_size
      })
    })
    .collect();
  let payload = json!({
    "url": url,
    "method": method,
    "params_found": results.len(),
    "params": params_json
  });

  if render::render_machine_output_with_yaml(ctx, "rb web asset params", &payload, || {
    println!("url: {}", url);
    println!("method: {}", method);
    println!("params_found: {}", results.len());
    println!("params:");
    for p in &results {
      println!("  - name: {}", p.name);
      println!("    method: {}", p.method);
      println!("    response_status: {}", p.response_status);
      println!("    response_size: {}", p.response_size);
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  Output::header("Parameter Discovery");
  Output::item("URL", url);
  Output::item("Method", &method);
  Output::item("Parameters Found", &results.len().to_string());
  println!();

  if results.is_empty() {
    Output::warning("No hidden parameters discovered");
  } else {
    println!(
      "  {:<25} {:<8} {:<6} {:<8} DIFF",
      "PARAMETER", "METHOD", "STATUS", "SIZE"
    );
    println!("  {}", "-".repeat(75));

    for p in &results {
      let diff_display = match &p.diff {
        crate::modules::web::param_enumerator::ParamDiff::StatusChanged { from, to } => {
          format!("\x1b[33mstatus {} -> {}\x1b[0m", from, to)
        }
        crate::modules::web::param_enumerator::ParamDiff::SizeChanged { delta, .. } => {
          format!("\x1b[36msize {:+} bytes\x1b[0m", delta)
        }
        crate::modules::web::param_enumerator::ParamDiff::Reflected => {
          "\x1b[31mREFLECTED (potential XSS/SSRF)\x1b[0m".to_string()
        }
        crate::modules::web::param_enumerator::ParamDiff::HeaderAdded { header } => {
          format!("\x1b[33mnew header: {}\x1b[0m", header)
        }
        crate::modules::web::param_enumerator::ParamDiff::NoChange => "no change".to_string(),
      };

      let status_color = match p.response_status {
        200..=299 => "\x1b[32m",
        300..=399 => "\x1b[33m",
        _ => "\x1b[0m",
      };

      println!(
        "  {:<25} {:<8} {}{:<6}\x1b[0m {:<8} {}",
        p.name, p.method, status_color, p.response_status, p.response_size, diff_display
      );
    }
  }

  println!();
  Output::success("Parameter discovery completed");

  Ok(())
}
