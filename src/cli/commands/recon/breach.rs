//! Breach checking and secrets scanning commands

use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::recon::breach::BreachClient;
use crate::modules::recon::secrets::SecretsScanner;

/// Password or email breach check (HIBP)
pub fn breach(ctx: &CliContext) -> Result<(), String> {
  let target = ctx.target.as_ref().ok_or(
        "Missing password or email.\nUsage: rb recon domain breach <PASSWORD|EMAIL> [--type password|email]",
    )?;

  let check_type = ctx
    .get_flag("type")
    .unwrap_or_else(|| "password".to_string());

  let mut client = BreachClient::new();

  // Add API key if provided (required for email checks)
  if let Some(api_key) = ctx.get_flag("hibp-key") {
    client = client.with_api_key(&api_key);
  }

  match check_type.as_str() {
    "password" => {
      if !ctx.wants_machine_output() {
        Output::spinner_start("Checking password against HIBP breach database");
      }

      let result = client.check_password(target)?;

      if !ctx.wants_machine_output() {
        Output::spinner_done();
      }

      let payload = password_breach_payload(&result);
      if render::render_machine_output(ctx, "rb recon domain breach", &payload)? {
        return Ok(());
      }

      // Human output
      Output::header("Password Breach Check (HIBP)");
      println!();

      if result.pwned {
        Output::error(&format!("Password found in {} breaches!", result.count));
        println!();
        Output::warning("This password has been exposed in data breaches.");
        Output::warning("Do NOT use this password anywhere!");
      } else {
        Output::success("Password NOT found in any known breaches");
        println!();
        Output::info("This password has not been seen in HIBP's database.");
        Output::info("Note: This doesn't guarantee the password is secure.");
      }
    }
    "email" => {
      if ctx.get_flag("hibp-key").is_none() {
        return Err(
          r#"Email breach checks require an HIBP API key.
Get one at: https://haveibeenpwned.com/API/Key ($3.50/month)
Usage: rb recon domain breach user@example.com --type email --hibp-key YOUR_KEY"#
            .to_string(),
        );
      }

      if !target.contains('@') {
        return Err(format!("Invalid email address: {}", target));
      }

      if !ctx.wants_machine_output() {
        Output::spinner_start(&format!("Checking email {} against HIBP", target));
      }

      let result = client.check_email(target)?;

      if !ctx.wants_machine_output() {
        Output::spinner_done();
      }

      let payload = email_breach_payload(&result);
      if render::render_machine_output(ctx, "rb recon domain breach", &payload)? {
        return Ok(());
      }

      // Human output
      Output::header(&format!("Email Breach Check: {}", target));
      println!();

      if result.pwned {
        Output::error(&format!("Email found in {} breaches!", result.breach_count));
        println!();

        Output::subheader("Breaches");
        for breach in &result.breaches {
          let date = &breach.breach_date;
          let count = if breach.pwn_count > 1_000_000 {
            format!("{}M accounts", breach.pwn_count / 1_000_000)
          } else if breach.pwn_count > 1_000 {
            format!("{}K accounts", breach.pwn_count / 1_000)
          } else {
            format!("{} accounts", breach.pwn_count)
          };

          println!(
            "  \x1b[31m●\x1b[0m {} ({}) - {} - {}",
            breach.name, breach.domain, date, count
          );
        }
      } else {
        Output::success("Email NOT found in any known breaches");
        println!();
        Output::info("This email address has not been seen in HIBP's data breaches.");
      }
    }
    _ => {
      return Err(format!(
        "Invalid check type: {}. Use 'password' or 'email'.",
        check_type
      ));
    }
  }

  Ok(())
}

/// Scan a URL for exposed secrets (API keys, tokens, credentials)
pub fn secrets(ctx: &CliContext) -> Result<(), String> {
  let url = ctx.target.as_ref().ok_or(
        "Missing URL.\nUsage: rb recon domain secrets <URL>\nExample: rb recon domain secrets http://example.com/config.js",
    )?;

  // Basic URL validation
  if !url.starts_with("http://") && !url.starts_with("https://") {
    return Err("Invalid URL. Must start with http:// or https://".to_string());
  }

  if !ctx.wants_machine_output() {
    Output::header("Secrets Scanner");
    Output::item("Target URL", url);
    println!();
  }

  let scanner = SecretsScanner::new();

  if !ctx.wants_machine_output() {
    Output::spinner_start(&format!("Scanning {} for exposed secrets", url));
  }
  let results = scanner.scan_url(url)?;
  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  if results.is_empty() {
    let payload = secrets_payload(url, &results);
    if render::render_machine_output(ctx, "rb recon domain secrets", &payload)? {
      return Ok(());
    }
    Output::info("No secrets found.");
    return Ok(());
  }

  // Sort results by severity
  let mut sorted_results = results;
  sorted_results.sort_by(|a, b| b.severity.cmp(&a.severity));

  let payload = secrets_payload(url, &sorted_results);
  if render::render_machine_output(ctx, "rb recon domain secrets", &payload)? {
    return Ok(());
  }

  println!();
  Output::subheader(&format!("Found {} potential secrets", sorted_results.len()));
  println!();

  for result in &sorted_results {
    let severity_color = result.severity.color_code();
    let severity_str = result.severity.as_upper();

    println!(
      "  {}{}● {} [{}]\x1b[0m",
      severity_color, severity_color, result.matched, severity_str
    );
    if let Some(line) = result.line {
      println!("    └─ Line: {}", line);
    }
    println!("    └─ Type: {}", result.secret_type);
    println!();
  }

  Output::success(&format!("Found {} potential secrets", sorted_results.len()));

  Ok(())
}

fn password_breach_payload(
  result: &crate::modules::recon::breach::PasswordCheckResult,
) -> crate::serde_json::Value {
  json!({
    "type": "password",
    "pwned": result.pwned,
    "count": result.count,
  })
}

fn email_breach_payload(
  result: &crate::modules::recon::breach::EmailCheckResult,
) -> crate::serde_json::Value {
  let breaches: Vec<_> = result
    .breaches
    .iter()
    .map(|breach| {
      json!({
        "name": breach.name,
        "domain": breach.domain,
        "breach_date": breach.breach_date,
        "pwn_count": breach.pwn_count,
      })
    })
    .collect();

  json!({
    "type": "email",
    "email": result.email,
    "pwned": result.pwned,
    "breach_count": result.breach_count,
    "breaches": breaches,
  })
}

fn secrets_payload(
  url: &str,
  results: &[crate::modules::recon::secrets::WebSecretFinding],
) -> crate::serde_json::Value {
  let secrets: Vec<_> = results
    .iter()
    .map(|result| {
      json!({
        "matched": result.matched.replace('\n', " "),
        "secret_type": result.secret_type,
        "severity": result.severity.as_str(),
        "line": result.line,
      })
    })
    .collect();

  json!({
    "url": url,
    "total": results.len(),
    "secrets": secrets,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::modules::common::Severity;
  use crate::modules::recon::breach::{EmailCheckResult, PasswordCheckResult};
  use crate::modules::recon::secrets::WebSecretFinding;

  #[test]
  fn password_breach_payload_includes_count() {
    let payload = password_breach_payload(&PasswordCheckResult {
      pwned: true,
      count: 99,
    });

    assert_eq!(payload["type"].as_str(), Some("password"));
    assert_eq!(payload["count"].as_u64(), Some(99));
  }

  #[test]
  fn email_breach_payload_includes_breaches() {
    let payload = email_breach_payload(&EmailCheckResult {
      email: "user@example.com".to_string(),
      pwned: true,
      breach_count: 1,
      breaches: vec![crate::modules::recon::breach::BreachInfo {
        name: "Example".to_string(),
        domain: "example.com".to_string(),
        breach_date: "2024-01-01".to_string(),
        pwn_count: 100,
        data_classes: vec!["Emails".to_string()],
      }],
    });

    assert_eq!(payload["email"].as_str(), Some("user@example.com"));
    assert_eq!(payload["breaches"][0]["name"].as_str(), Some("Example"));
  }

  #[test]
  fn secrets_payload_tracks_total_and_severity() {
    let payload = secrets_payload(
      "https://example.com/config.js",
      &[WebSecretFinding {
        matched: "API_KEY=abc123".to_string(),
        secret_type: "api-key".to_string(),
        severity: Severity::High,
        location: "https://example.com/config.js".to_string(),
        line: Some(12),
        context: None,
        pattern_name: "generic-api-key".to_string(),
      }],
    );

    assert_eq!(payload["total"].as_u64(), Some(1));
    assert_eq!(payload["secrets"][0]["severity"].as_str(), Some("high"));
  }
}
