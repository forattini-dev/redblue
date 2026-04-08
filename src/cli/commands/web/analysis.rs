//! Security analysis commands: CSP, CORS, cookies, and rule-engine fingerprinting
//!
//! Each function follows the standard CliContext pattern used by other web
//! subcommand modules: extract the target URL, fetch the page, invoke the
//! corresponding module, then render human or machine output.

use crate::cli::format::OutputFormat;
use crate::cli::output::Output;
use crate::cli::render;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::json;
use crate::protocols::http::HttpClient;
use std::collections::HashMap;

use super::types::guard_plain_http;

// ---------------------------------------------------------------------------
// CSP analysis
// ---------------------------------------------------------------------------

/// Analyze Content-Security-Policy header
pub fn csp(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
    "Missing URL. Usage: rb web asset csp <URL>\nExample: rb web asset csp https://example.com",
  )?;

  Validator::validate_url(url)?;
  guard_plain_http(url, "rb web asset csp")?;

  let format = ctx.get_output_format();
  let client = HttpClient::new();

  if format == OutputFormat::Human {
    Output::spinner_start("Analyzing CSP");
  }

  let response = client
    .get(url)
    .map_err(|e| format!("Request failed: {}", e))?;

  if format == OutputFormat::Human {
    Output::spinner_done();
  }

  // Look for Content-Security-Policy header (case-insensitive)
  let csp_header = response
    .headers
    .iter()
    .find(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))
    .map(|(_, v)| v.as_str());

  let Some(csp_value) = csp_header else {
    let payload = json!({
      "url": url,
      "csp": "",
      "grade": "F",
      "message": "No Content-Security-Policy header found"
    });
    if render::render_machine_output_with_yaml(ctx, "rb web asset csp", &payload, || {
      println!("url: {}", url);
      println!("csp: null");
      println!("grade: F");
      println!("message: No Content-Security-Policy header found");
      Ok(())
    })? {
      return Ok(());
    }

    Output::header("CSP Analysis");
    Output::item("URL", url);
    println!();
    Output::warning("No Content-Security-Policy header found");
    println!("  Grade: \x1b[31mF\x1b[0m");
    return Ok(());
  };

  let analysis = crate::modules::web::csp::analyze_csp(csp_value);

  // Build JSON payload
  let directives_json: Vec<_> = analysis
    .directives
    .iter()
    .map(|d| {
      json!({
        "name": d.name.clone(),
        "values": d.values.clone()
      })
    })
    .collect();
  let issues_json: Vec<_> = analysis
    .issues
    .iter()
    .map(|i| {
      json!({
        "severity": format!("{}", i.severity),
        "directive": i.directive.clone(),
        "description": i.description.clone()
      })
    })
    .collect();
  let payload = json!({
    "url": url,
    "grade": format!("{}", analysis.grade),
    "raw_policy": analysis.raw_policy,
    "directives": directives_json,
    "issues": issues_json
  });

  if render::render_machine_output_with_yaml(ctx, "rb web asset csp", &payload, || {
    println!("url: {}", url);
    println!("grade: {}", analysis.grade);
    println!(
      "raw_policy: \"{}\"",
      analysis.raw_policy.replace('"', "\\\"")
    );
    println!("directives:");
    for d in &analysis.directives {
      println!("  - name: {}", d.name);
      println!("    values: [{}]", d.values.join(", "));
    }
    println!("issues:");
    for i in &analysis.issues {
      println!("  - severity: {}", i.severity);
      println!("    directive: {}", i.directive);
      println!(
        "    description: \"{}\"",
        i.description.replace('"', "\\\"")
      );
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  Output::header("CSP Analysis");
  Output::item("URL", url);

  let grade_color = match analysis.grade {
    'A' => "\x1b[32m",
    'B' => "\x1b[92m",
    'C' => "\x1b[33m",
    'D' => "\x1b[33m",
    _ => "\x1b[31m",
  };
  println!("  Grade: {}{}  \x1b[0m", grade_color, analysis.grade);
  println!();

  // Directives
  Output::subheader(&format!("Directives ({})", analysis.directives.len()));
  println!();
  for dir in &analysis.directives {
    println!("  \x1b[36m{}\x1b[0m: {}", dir.name, dir.values.join(" "));
  }

  // Issues
  if !analysis.issues.is_empty() {
    println!();
    Output::subheader(&format!("Issues ({})", analysis.issues.len()));
    println!();
    for issue in &analysis.issues {
      let severity_color = match issue.severity {
        crate::modules::web::csp::CspSeverity::Critical => "\x1b[31m",
        crate::modules::web::csp::CspSeverity::High => "\x1b[91m",
        crate::modules::web::csp::CspSeverity::Medium => "\x1b[33m",
        crate::modules::web::csp::CspSeverity::Low => "\x1b[36m",
        crate::modules::web::csp::CspSeverity::Info => "\x1b[34m",
      };
      let directive_label = if issue.directive.is_empty() {
        String::new()
      } else {
        format!(" ({})", issue.directive)
      };
      println!(
        "  {}{:<8}\x1b[0m{} {}",
        severity_color,
        format!("{}", issue.severity),
        directive_label,
        issue.description
      );
    }
  }

  println!();
  Output::success("CSP analysis completed");

  Ok(())
}

// ---------------------------------------------------------------------------
// CORS analysis
// ---------------------------------------------------------------------------

/// Scan for CORS misconfigurations
pub fn cors(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
    "Missing URL. Usage: rb web asset cors <URL>\nExample: rb web asset cors https://example.com",
  )?;

  Validator::validate_url(url)?;
  guard_plain_http(url, "rb web asset cors")?;

  let format = ctx.get_output_format();

  if format == OutputFormat::Human {
    Output::spinner_start("Scanning CORS configuration");
  }

  let analysis =
    crate::modules::web::cors::scan_cors(url).map_err(|e| format!("CORS scan failed: {}", e))?;

  if format == OutputFormat::Human {
    Output::spinner_done();
  }

  // Build JSON payload
  let policy_str = match &analysis.origin_policy {
    crate::modules::web::cors::OriginPolicy::Wildcard => "wildcard".to_string(),
    crate::modules::web::cors::OriginPolicy::Reflected => "reflected".to_string(),
    crate::modules::web::cors::OriginPolicy::NullAllowed => "null-allowed".to_string(),
    crate::modules::web::cors::OriginPolicy::Specific(origin) => {
      format!("specific:{}", origin)
    }
    crate::modules::web::cors::OriginPolicy::None => "none".to_string(),
  };
  let issues_json: Vec<_> = analysis
    .issues
    .iter()
    .map(|i| {
      json!({
        "severity": format!("{}", i.severity),
        "description": i.description.clone()
      })
    })
    .collect();
  let payload = json!({
    "url": url,
    "origin_policy": policy_str,
    "allows_credentials": analysis.allows_credentials,
    "exposed_headers": analysis.exposed_headers,
    "max_age": analysis.max_age,
    "risk_level": format!("{}", analysis.risk_level),
    "issues": issues_json
  });

  if render::render_machine_output_with_yaml(ctx, "rb web asset cors", &payload, || {
    println!("url: {}", url);
    println!("origin_policy: {}", policy_str);
    println!("allows_credentials: {}", analysis.allows_credentials);
    println!("exposed_headers: [{}]", analysis.exposed_headers.join(", "));
    if let Some(age) = analysis.max_age {
      println!("max_age: {}", age);
    } else {
      println!("max_age: null");
    }
    println!("risk_level: {}", analysis.risk_level);
    println!("issues:");
    for i in &analysis.issues {
      println!("  - severity: {}", i.severity);
      println!(
        "    description: \"{}\"",
        i.description.replace('"', "\\\"")
      );
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  Output::header("CORS Misconfiguration Scan");
  Output::item("URL", url);
  println!();

  // Origin policy
  let policy_display = match &analysis.origin_policy {
    crate::modules::web::cors::OriginPolicy::Wildcard => "\x1b[33mWildcard (*)\x1b[0m".to_string(),
    crate::modules::web::cors::OriginPolicy::Reflected => {
      "\x1b[31mReflected (echoes any Origin)\x1b[0m".to_string()
    }
    crate::modules::web::cors::OriginPolicy::NullAllowed => {
      "\x1b[33mNull origin allowed\x1b[0m".to_string()
    }
    crate::modules::web::cors::OriginPolicy::Specific(origin) => {
      format!("\x1b[32mSpecific: {}\x1b[0m", origin)
    }
    crate::modules::web::cors::OriginPolicy::None => {
      "\x1b[32mNo CORS headers (safe)\x1b[0m".to_string()
    }
  };
  Output::item("Origin Policy", &policy_display);
  Output::item(
    "Allows Credentials",
    if analysis.allows_credentials {
      "\x1b[33mtrue\x1b[0m"
    } else {
      "false"
    },
  );
  if !analysis.exposed_headers.is_empty() {
    Output::item("Exposed Headers", &analysis.exposed_headers.join(", "));
  }
  if let Some(age) = analysis.max_age {
    Output::item("Max-Age", &format!("{}s", age));
  }

  // Risk level
  let risk_color = match analysis.risk_level {
    crate::modules::web::cors::CorsRisk::Critical => "\x1b[31m",
    crate::modules::web::cors::CorsRisk::High => "\x1b[91m",
    crate::modules::web::cors::CorsRisk::Medium => "\x1b[33m",
    crate::modules::web::cors::CorsRisk::Low => "\x1b[36m",
    crate::modules::web::cors::CorsRisk::None => "\x1b[32m",
  };
  println!(
    "\n  Risk Level: {}{}\x1b[0m",
    risk_color, analysis.risk_level
  );

  // Issues
  if !analysis.issues.is_empty() {
    println!();
    Output::subheader("Issues");
    println!();
    for issue in &analysis.issues {
      let severity_color = match issue.severity {
        crate::modules::web::cors::CorsRisk::Critical => "\x1b[31m",
        crate::modules::web::cors::CorsRisk::High => "\x1b[91m",
        crate::modules::web::cors::CorsRisk::Medium => "\x1b[33m",
        crate::modules::web::cors::CorsRisk::Low => "\x1b[36m",
        crate::modules::web::cors::CorsRisk::None => "\x1b[32m",
      };
      println!(
        "  {}{:<10}\x1b[0m {}",
        severity_color,
        format!("{}", issue.severity),
        issue.description
      );
    }
  } else {
    println!();
    Output::success("No CORS misconfigurations detected");
  }

  println!();
  Output::success("CORS scan completed");

  Ok(())
}

// ---------------------------------------------------------------------------
// Cookie analysis
// ---------------------------------------------------------------------------

/// Analyze cookie security flags
pub fn cookies(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
    "Missing URL. Usage: rb web asset cookies <URL>\nExample: rb web asset cookies https://example.com",
  )?;

  Validator::validate_url(url)?;
  guard_plain_http(url, "rb web asset cookies")?;

  let format = ctx.get_output_format();
  let client = HttpClient::new();

  if format == OutputFormat::Human {
    Output::spinner_start("Analyzing cookies");
  }

  let response = client
    .get(url)
    .map_err(|e| format!("Request failed: {}", e))?;

  if format == OutputFormat::Human {
    Output::spinner_done();
  }

  let is_https = url.starts_with("https://");

  // Collect headers as (name, value) pairs for the analyze_cookies API
  let header_pairs: Vec<(String, String)> = response
    .headers
    .iter()
    .map(|(k, v)| (k.clone(), v.clone()))
    .collect();

  let results = crate::modules::web::cookies::analyze_cookies(&header_pairs, is_https);

  if results.is_empty() {
    let payload = json!({
      "url": url,
      "cookies": [],
      "message": "No Set-Cookie headers found"
    });
    if render::render_machine_output_with_yaml(ctx, "rb web asset cookies", &payload, || {
      println!("url: {}", url);
      println!("cookies: []");
      println!("message: No Set-Cookie headers found");
      Ok(())
    })? {
      return Ok(());
    }

    Output::header("Cookie Security Analysis");
    Output::item("URL", url);
    println!();
    Output::warning("No Set-Cookie headers found in response");
    return Ok(());
  }

  // Build JSON payload
  let cookies_json: Vec<_> = results
    .iter()
    .map(|c| {
      let issues_json: Vec<_> = c
        .issues
        .iter()
        .map(|i| {
          json!({
            "severity": format!("{}", i.severity),
            "description": i.description.clone()
          })
        })
        .collect();
      json!({
        "name": c.name,
        "value_preview": c.value_preview,
        "secure": c.flags.secure,
        "http_only": c.flags.http_only,
        "same_site": c.flags.same_site.as_ref().map(|s| match s {
          crate::modules::web::cookies::SameSitePolicy::Strict => "Strict",
          crate::modules::web::cookies::SameSitePolicy::Lax => "Lax",
          crate::modules::web::cookies::SameSitePolicy::None => "None",
        }),
        "domain": c.flags.domain.clone(),
        "path": c.flags.path.clone(),
        "issues": issues_json
      })
    })
    .collect();

  let total_issues: usize = results.iter().map(|c| c.issues.len()).sum();
  let payload = json!({
    "url": url,
    "is_https": is_https,
    "cookie_count": results.len(),
    "total_issues": total_issues,
    "cookies": cookies_json
  });

  if render::render_machine_output_with_yaml(ctx, "rb web asset cookies", &payload, || {
    println!("url: {}", url);
    println!("is_https: {}", is_https);
    println!("cookie_count: {}", results.len());
    println!("total_issues: {}", total_issues);
    println!("cookies:");
    for c in &results {
      println!("  - name: {}", c.name);
      println!("    secure: {}", c.flags.secure);
      println!("    http_only: {}", c.flags.http_only);
      if let Some(ref ss) = c.flags.same_site {
        let label = match ss {
          crate::modules::web::cookies::SameSitePolicy::Strict => "Strict",
          crate::modules::web::cookies::SameSitePolicy::Lax => "Lax",
          crate::modules::web::cookies::SameSitePolicy::None => "None",
        };
        println!("    same_site: {}", label);
      } else {
        println!("    same_site: null");
      }
      println!("    issues:");
      for i in &c.issues {
        println!("      - severity: {}", i.severity);
        println!(
          "        description: \"{}\"",
          i.description.replace('"', "\\\"")
        );
      }
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  Output::header("Cookie Security Analysis");
  Output::item("URL", url);
  Output::item("HTTPS", if is_https { "yes" } else { "no" });
  Output::item("Cookies Found", &results.len().to_string());
  println!();

  for c in &results {
    Output::subheader(&format!("Cookie: {}", c.name));
    println!();

    // Flags summary
    let secure_display = if c.flags.secure {
      "\x1b[32myes\x1b[0m"
    } else {
      "\x1b[31mno\x1b[0m"
    };
    let httponly_display = if c.flags.http_only {
      "\x1b[32myes\x1b[0m"
    } else {
      "\x1b[31mno\x1b[0m"
    };
    let samesite_display = match &c.flags.same_site {
      Some(crate::modules::web::cookies::SameSitePolicy::Strict) => {
        "\x1b[32mStrict\x1b[0m".to_string()
      }
      Some(crate::modules::web::cookies::SameSitePolicy::Lax) => "\x1b[32mLax\x1b[0m".to_string(),
      Some(crate::modules::web::cookies::SameSitePolicy::None) => "\x1b[33mNone\x1b[0m".to_string(),
      None => "\x1b[31mnot set\x1b[0m".to_string(),
    };

    println!(
      "    Secure: {}  HttpOnly: {}  SameSite: {}",
      secure_display, httponly_display, samesite_display
    );
    if let Some(ref domain) = c.flags.domain {
      println!("    Domain: {}", domain);
    }
    if let Some(ref path) = c.flags.path {
      println!("    Path: {}", path);
    }

    // Issues
    if !c.issues.is_empty() {
      println!();
      for issue in &c.issues {
        let severity_color = match issue.severity {
          crate::modules::web::cookies::CookieSeverity::High => "\x1b[31m",
          crate::modules::web::cookies::CookieSeverity::Medium => "\x1b[33m",
          crate::modules::web::cookies::CookieSeverity::Low => "\x1b[36m",
          crate::modules::web::cookies::CookieSeverity::Info => "\x1b[34m",
        };
        println!(
          "    {}{:<8}\x1b[0m {}",
          severity_color,
          format!("{}", issue.severity),
          issue.description
        );
      }
    } else {
      println!();
      println!("    \x1b[32mNo issues found\x1b[0m");
    }
    println!();
  }

  if total_issues == 0 {
    Output::success("All cookies pass security checks");
  } else {
    Output::warning(&format!(
      "{} issue(s) found across {} cookie(s)",
      total_issues,
      results.len()
    ));
  }

  Ok(())
}

// ---------------------------------------------------------------------------
// Rule-engine fingerprinting
// ---------------------------------------------------------------------------

/// Detect technologies using the data-driven rule engine
pub fn fingerprint_rules(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
    "Missing URL. Usage: rb web asset tech <URL>\nExample: rb web asset tech https://example.com",
  )?;

  Validator::validate_url(url)?;
  guard_plain_http(url, "rb web asset tech")?;

  let format = ctx.get_output_format();
  let client = HttpClient::new();

  if format == OutputFormat::Human {
    Output::spinner_start("Detecting technologies");
  }

  let response = client
    .get(url)
    .map_err(|e| format!("Request failed: {}", e))?;

  if format == OutputFormat::Human {
    Output::spinner_done();
  }

  let rules = crate::modules::web::rule_engine::load_rules();
  if rules.is_empty() {
    return Err("Failed to load fingerprint rules database".to_string());
  }

  // Build inputs for the rule engine
  let headers: HashMap<String, String> = response
    .headers
    .iter()
    .map(|(k, v)| (k.clone(), v.clone()))
    .collect();
  let body = response.body_as_string();
  let cookies: Vec<String> = response
    .headers
    .iter()
    .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
    .map(|(_, v)| v.clone())
    .collect();

  let matches = crate::modules::web::rule_engine::match_rules(&rules, &headers, &body, &cookies);

  // Build JSON payload
  let matches_json: Vec<_> = matches
    .iter()
    .map(|m| {
      json!({
        "name": m.name,
        "categories": m.categories,
        "version": m.version.clone(),
        "confidence": m.confidence,
        "matched_by": m.matched_by,
        "website": m.website
      })
    })
    .collect();
  let payload = json!({
    "url": url,
    "rules_loaded": rules.len(),
    "technologies_detected": matches.len(),
    "technologies": matches_json
  });

  if render::render_machine_output_with_yaml(ctx, "rb web asset tech", &payload, || {
    println!("url: {}", url);
    println!("rules_loaded: {}", rules.len());
    println!("technologies_detected: {}", matches.len());
    println!("technologies:");
    for m in &matches {
      println!("  - name: {}", m.name);
      println!("    categories: [{}]", m.categories.join(", "));
      if let Some(ref v) = m.version {
        println!("    version: {}", v);
      } else {
        println!("    version: null");
      }
      println!("    confidence: {}", m.confidence);
      println!("    matched_by: [{}]", m.matched_by.join(", "));
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  Output::header("Technology Detection (Rule Engine)");
  Output::item("URL", url);
  Output::item("Rules Loaded", &rules.len().to_string());
  Output::item("Technologies Found", &matches.len().to_string());
  println!();

  if matches.is_empty() {
    Output::warning("No technologies detected");
  } else {
    println!(
      "  {:<30} {:<20} {:<12} {:<10} MATCHED BY",
      "TECHNOLOGY", "CATEGORIES", "CONFIDENCE", "VERSION"
    );
    println!("  {}", "-".repeat(90));

    for m in &matches {
      let confidence_color = if m.confidence >= 75 {
        "\x1b[32m" // green
      } else if m.confidence >= 50 {
        "\x1b[33m" // yellow
      } else {
        "\x1b[36m" // cyan
      };

      let version = m.version.as_deref().unwrap_or("-");
      let categories = m.categories.join(", ");
      let matched_by = m.matched_by.join(", ");

      println!(
        "  {:<30} {:<20} {}{}%{:<8}\x1b[0m {:<10} {}",
        m.name,
        if categories.len() > 18 {
          format!("{}...", &categories[..15])
        } else {
          categories
        },
        confidence_color,
        m.confidence,
        "",
        version,
        matched_by
      );
    }
  }

  println!();
  Output::success("Technology detection completed");

  Ok(())
}
