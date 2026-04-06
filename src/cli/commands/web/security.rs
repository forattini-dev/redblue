//! Security header analysis

use crate::cli::commands::build_partition_attributes;
use crate::cli::format::OutputFormat;
use crate::cli::output::Output;
use crate::cli::render;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::json;
use crate::protocols::http::HttpClient;
use crate::storage::records::HttpHeadersRecord;
use crate::storage::service::StorageService;

use super::types::{extract_host, guard_plain_http};

/// Audit security-related HTTP headers
pub fn security(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset security <URL> Example: rb web asset security http://example.com",
    )?;

  Validator::validate_url(url)?;
  guard_plain_http(url, "rb web asset security")?;

  let format = ctx.get_output_format();

  let client = HttpClient::new();

  if format == OutputFormat::Human {
    Output::spinner_start("Analyzing security");
  }

  let response = client
    .get(url)
    .map_err(|e| format!("Request failed: {}", e))?;

  if format == OutputFormat::Human {
    Output::spinner_done();
  }

  // Database persistence
  let persist_flag = if ctx.has_flag("persist") {
    Some(true)
  } else if ctx.has_flag("no-persist") {
    Some(false)
  } else {
    None
  };

  let host = extract_host(url);
  let attributes =
    build_partition_attributes(ctx, &host, [("operation", "security"), ("url", url)]);
  let mut pm =
    StorageService::global().persistence_for_target_with(&host, persist_flag, None, attributes)?;

  // Save security audit to database
  if pm.is_enabled() {
    let record = HttpHeadersRecord {
      host: host.clone(),
      url: url.to_string(),
      method: "GET".to_string(),
      scheme: if url.starts_with("https://") {
        "https".to_string()
      } else {
        "http".to_string()
      },
      http_version: "HTTP/1.1".to_string(),
      status_code: response.status_code,
      status_text: response.status_text.clone(),
      server: response.headers.get("server").map(|s| s.to_string()),
      body_size: response.body.len() as u32,
      headers: response
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect(),
      timestamp: 0, // Will be set by PersistenceManager
      tls: None,
    };

    if let Err(e) = pm.add_http_capture(record) {
      eprintln!("Warning: Failed to save security audit to database: {}", e);
    } else if format == OutputFormat::Human {
      Output::success(&format!("✓ Saved to {}.rdb", host));
    }
  }

  let security_headers = vec![
    ("Strict-Transport-Security", "HSTS - Forces HTTPS"),
    ("X-Frame-Options", "Prevents clickjacking"),
    ("X-Content-Type-Options", "Prevents MIME sniffing"),
    ("X-XSS-Protection", "XSS filter"),
    ("Content-Security-Policy", "CSP - Prevents XSS/injection"),
    ("Referrer-Policy", "Controls referrer information"),
    ("Permissions-Policy", "Controls browser features"),
  ];

  let security_headers_json: Vec<_> = security_headers
    .iter()
    .map(|(header, description)| {
      let value = response.headers.get(*header).cloned();
      json!({
          "header": *header,
          "description": *description,
          "present": value.is_some(),
          "value": value
      })
    })
    .collect();
  let payload = json!({
      "url": url,
      "security_headers": security_headers_json
  });
  if render::render_machine_output_with_yaml(ctx, "rb web asset security", &payload, || {
    println!("url: {}", url);
    println!("security_headers:");
    for (header, description) in &security_headers {
      let present = response.headers.get(*header).is_some();
      println!("  - header: {}", header);
      println!("    description: {}", description);
      println!("    present: {}", present);
      if present {
        let value = response.headers.get(*header).unwrap();
        let value_escaped = value.replace('"', "\\\"");
        println!("    value: \"{}\"", value_escaped);
      } else {
        println!("    value: null");
      }
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  Output::header("Security Headers Audit");
  Output::item("URL", url);
  println!();

  Output::subheader("Security Headers");
  println!();

  for (header, description) in security_headers {
    if let Some(value) = response.headers.get(header) {
      Output::success(&format!("{}: {}", header, value));
      println!("  \x1b[2m{}\x1b[0m", description);
    } else {
      Output::error(&format!("{} is missing", header));
      println!("  \x1b[2m{}\x1b[0m", description);
    }
    println!();
  }

  Ok(())
}

/// Grade security headers (A+ to F)
pub fn grade(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
    "Missing URL. Usage: rb web asset grade <URL>\nExample: rb web asset grade https://example.com",
  )?;

  Validator::validate_url(url)?;
  guard_plain_http(url, "rb web asset grade")?;

  let format = ctx.get_output_format();
  let client = HttpClient::new();

  if format == OutputFormat::Human {
    Output::spinner_start("Analyzing security headers");
  }

  let response = client
    .get(url)
    .map_err(|e| format!("Request failed: {}", e))?;

  if format == OutputFormat::Human {
    Output::spinner_done();
  }

  // Security grading system
  let mut score: i32 = 100;
  let mut findings: Vec<(&str, &str, i32, String)> = Vec::new();

  // 1. HSTS Check
  if let Some(hsts) = response.headers.get("Strict-Transport-Security") {
    let max_age = hsts
      .split(';')
      .find_map(|part| {
        let part = part.trim();
        if part.to_lowercase().starts_with("max-age=") {
          part[8..].parse::<u64>().ok()
        } else {
          None
        }
      })
      .unwrap_or(0);

    let one_year = 31536000u64;
    if max_age < one_year {
      score -= 5;
      findings.push((
        "Strict-Transport-Security",
        "WEAK",
        -5,
        format!("max-age={} is less than 1 year (31536000s)", max_age),
      ));
    } else {
      let details = if hsts.to_lowercase().contains("includesubdomains") {
        format!("✓ max-age={}, includeSubDomains", max_age)
      } else {
        format!("✓ max-age={}", max_age)
      };
      findings.push(("Strict-Transport-Security", "PASS", 0, details));
    }
  } else {
    score -= 20;
    findings.push((
      "Strict-Transport-Security",
      "FAIL",
      -20,
      "Missing - enables downgrade attacks".to_string(),
    ));
  }

  // 2. CSP Check
  if let Some(csp) = response.headers.get("Content-Security-Policy") {
    let csp_lower = csp.to_lowercase();
    let mut csp_deductions = 0;
    let mut csp_issues: Vec<String> = Vec::new();

    if csp_lower.contains("'unsafe-inline'") {
      csp_deductions += 10;
      csp_issues.push("unsafe-inline".to_string());
    }
    if csp_lower.contains("'unsafe-eval'") {
      csp_deductions += 10;
      csp_issues.push("unsafe-eval".to_string());
    }
    let dangerous_wildcards = ["script-src *", "default-src *", "object-src *"];
    for pattern in &dangerous_wildcards {
      if csp_lower.contains(pattern) {
        csp_deductions += 5;
        csp_issues.push(format!(
          "wildcard in {}",
          pattern.split(' ').next().unwrap_or("")
        ));
        break;
      }
    }

    score -= csp_deductions;
    if csp_issues.is_empty() {
      findings.push((
        "Content-Security-Policy",
        "PASS",
        0,
        "Present and well-configured".to_string(),
      ));
    } else {
      findings.push((
        "Content-Security-Policy",
        "WARN",
        -csp_deductions,
        format!("Issues: {}", csp_issues.join(", ")),
      ));
    }
  } else {
    score -= 15;
    findings.push((
      "Content-Security-Policy",
      "FAIL",
      -15,
      "Missing - no XSS protection".to_string(),
    ));
  }

  // 3. X-Frame-Options
  if response.headers.get("X-Frame-Options").is_some() {
    findings.push((
      "X-Frame-Options",
      "PASS",
      0,
      "Present - prevents clickjacking".to_string(),
    ));
  } else {
    if let Some(csp) = response.headers.get("Content-Security-Policy") {
      if csp.to_lowercase().contains("frame-ancestors") {
        findings.push((
          "X-Frame-Options",
          "PASS",
          0,
          "Not present, but CSP frame-ancestors is set".to_string(),
        ));
      } else {
        score -= 10;
        findings.push((
          "X-Frame-Options",
          "FAIL",
          -10,
          "Missing - vulnerable to clickjacking".to_string(),
        ));
      }
    } else {
      score -= 10;
      findings.push((
        "X-Frame-Options",
        "FAIL",
        -10,
        "Missing - vulnerable to clickjacking".to_string(),
      ));
    }
  }

  // 4. X-Content-Type-Options
  if response.headers.get("X-Content-Type-Options").is_some() {
    findings.push((
      "X-Content-Type-Options",
      "PASS",
      0,
      "Present - prevents MIME sniffing".to_string(),
    ));
  } else {
    score -= 5;
    findings.push((
      "X-Content-Type-Options",
      "FAIL",
      -5,
      "Missing - MIME sniffing possible".to_string(),
    ));
  }

  // 5. Referrer-Policy
  if let Some(rp) = response.headers.get("Referrer-Policy") {
    findings.push(("Referrer-Policy", "PASS", 0, format!("Set to: {}", rp)));
  } else {
    findings.push((
      "Referrer-Policy",
      "INFO",
      0,
      "Not set (browser defaults apply)".to_string(),
    ));
  }

  // 6. Permissions-Policy
  if response.headers.get("Permissions-Policy").is_some() {
    findings.push((
      "Permissions-Policy",
      "PASS",
      0,
      "Present - restricts browser features".to_string(),
    ));
  } else {
    findings.push((
      "Permissions-Policy",
      "INFO",
      0,
      "Not set (all features enabled)".to_string(),
    ));
  }

  // 7. Cross-Origin headers
  if response.headers.get("Cross-Origin-Opener-Policy").is_some() {
    findings.push((
      "Cross-Origin-Opener-Policy",
      "PASS",
      0,
      "Present".to_string(),
    ));
  }
  if response
    .headers
    .get("Cross-Origin-Embedder-Policy")
    .is_some()
  {
    findings.push((
      "Cross-Origin-Embedder-Policy",
      "PASS",
      0,
      "Present".to_string(),
    ));
  }
  if response
    .headers
    .get("Cross-Origin-Resource-Policy")
    .is_some()
  {
    findings.push((
      "Cross-Origin-Resource-Policy",
      "PASS",
      0,
      "Present".to_string(),
    ));
  }

  // Calculate grade
  let score = score.max(0);
  let grade = match score {
    100 => "A+",
    90..=99 => "A",
    80..=89 => "B",
    70..=79 => "C",
    60..=69 => "D",
    _ => "F",
  };

  let findings_json: Vec<_> = findings
    .iter()
    .map(|(header, status, deduction, details)| {
      json!({
          "header": *header,
          "status": *status,
          "deduction": *deduction,
          "details": details.clone()
      })
    })
    .collect();
  let payload = json!({
      "url": url,
      "score": score,
      "grade": grade,
      "findings": findings_json
  });
  if render::render_machine_output_with_yaml(ctx, "rb web asset grade", &payload, || {
    println!("url: {}", url);
    println!("score: {}", score);
    println!("grade: {}", grade);
    println!("findings:");
    for (header, status, deduction, details) in &findings {
      println!("  - header: {}", header);
      println!("    status: {}", status);
      println!("    deduction: {}", deduction);
      println!("    details: \"{}\"", details);
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  Output::header(&format!("Security Grade: {}", url));
  println!();

  let grade_color = match grade {
    "A+" | "A" => "\x1b[32m",
    "B" => "\x1b[92m",
    "C" => "\x1b[33m",
    "D" => "\x1b[33m",
    _ => "\x1b[31m",
  };
  println!(
    "  {}┌─────────────────────────────────────────┐\x1b[0m",
    grade_color
  );
  println!(
    "  {}│  Grade: {}    Score: {}/100           │\x1b[0m",
    grade_color, grade, score
  );
  println!(
    "  {}└─────────────────────────────────────────┘\x1b[0m",
    grade_color
  );
  println!();

  println!("  {:<35} {:<8} {:<8} DETAILS", "HEADER", "STATUS", "SCORE");
  println!("  {}", "─".repeat(90));

  for (header, status, deduction, details) in &findings {
    let status_display = match *status {
      "PASS" => "\x1b[32m✓ PASS\x1b[0m",
      "WARN" => "\x1b[33m⚠ WARN\x1b[0m",
      "FAIL" => "\x1b[31m✗ FAIL\x1b[0m",
      "INFO" => "\x1b[34mℹ INFO\x1b[0m",
      _ => status,
    };

    let deduction_str = if *deduction < 0 {
      format!("\x1b[31m{}\x1b[0m", deduction)
    } else {
      "0".to_string()
    };

    let details_display = if details.len() > 40 {
      format!("{}...", &details[..37])
    } else {
      details.clone()
    };

    println!(
      "  {:<35} {:<16} {:<8} {}",
      header, status_display, deduction_str, details_display
    );
  }

  println!();

  // Recommendations
  let failed_headers: Vec<_> = findings
    .iter()
    .filter(|(_, s, _, _)| *s == "FAIL")
    .collect();
  if !failed_headers.is_empty() {
    Output::section("Recommendations");
    for (header, _, _, _) in failed_headers {
      match *header {
        "Strict-Transport-Security" => {
          println!("  • Add HSTS header:");
          println!("    \x1b[2mStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\x1b[0m");
        }
        "Content-Security-Policy" => {
          println!("  • Add CSP header:");
          println!(
            "    \x1b[2mContent-Security-Policy: default-src 'self'; script-src 'self'\x1b[0m"
          );
        }
        "X-Frame-Options" => {
          println!("  • Add X-Frame-Options header:");
          println!("    \x1b[2mX-Frame-Options: DENY\x1b[0m");
        }
        "X-Content-Type-Options" => {
          println!("  • Add X-Content-Type-Options header:");
          println!("    \x1b[2mX-Content-Type-Options: nosniff\x1b[0m");
        }
        _ => {}
      }
    }
    println!();
  }

  match grade {
    "A+" => Output::success("Perfect security headers configuration!"),
    "A" => Output::success("Excellent security headers configuration"),
    "B" => Output::success("Good security - minor improvements possible"),
    "C" => Output::warning("Fair security - several improvements needed"),
    "D" => Output::warning("Poor security - action recommended"),
    _ => Output::error("Critical: Major security headers missing"),
  }

  Ok(())
}
