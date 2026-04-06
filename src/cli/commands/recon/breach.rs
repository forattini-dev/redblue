//! Breach checking and secrets scanning commands

use crate::cli::output::Output;
use crate::cli::CliContext;
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
    let format = ctx.get_output_format();

    let mut client = BreachClient::new();

    // Add API key if provided (required for email checks)
    if let Some(api_key) = ctx.get_flag("hibp-key") {
        client = client.with_api_key(&api_key);
    }

    match check_type.as_str() {
        "password" => {
            if format == crate::cli::format::OutputFormat::Human {
                Output::spinner_start("Checking password against HIBP breach database");
            }

            let result = client.check_password(target)?;

            if format == crate::cli::format::OutputFormat::Human {
                Output::spinner_done();
            }

            // JSON output
            if format == crate::cli::format::OutputFormat::Json {
                Output::json_value(&json!({
                    "type": "password",
                    "pwned": result.pwned,
                    "count": result.count,
                }));
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
                return Err(r#"Email breach checks require an HIBP API key.
Get one at: https://haveibeenpwned.com/API/Key ($3.50/month)
Usage: rb recon domain breach user@example.com --type email --hibp-key YOUR_KEY"#
                    .to_string());
            }

            if !target.contains('@') {
                return Err(format!("Invalid email address: {}", target));
            }

            if format == crate::cli::format::OutputFormat::Human {
                Output::spinner_start(&format!("Checking email {} against HIBP", target));
            }

            let result = client.check_email(target)?;

            if format == crate::cli::format::OutputFormat::Human {
                Output::spinner_done();
            }

            // JSON output
            if format == crate::cli::format::OutputFormat::Json {
                let breaches_json: Vec<_> = result
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
                Output::json_value(&json!({
                    "type": "email",
                    "email": result.email,
                    "pwned": result.pwned,
                    "breach_count": result.breach_count,
                    "breaches": breaches_json,
                }));
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

    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    if !is_json {
        Output::header("Secrets Scanner");
        Output::item("Target URL", url);
        println!();
    }

    let scanner = SecretsScanner::new();

    if !is_json {
        Output::spinner_start(&format!("Scanning {} for exposed secrets", url));
    }
    let results = scanner.scan_url(url)?;
    if !is_json {
        Output::spinner_done();
    }

    if results.is_empty() {
        if is_json {
            Output::json_value(&json!({
                "url": url,
                "total": 0,
                "secrets": [],
            }));
            return Ok(());
        }
        Output::info("No secrets found.");
        return Ok(());
    }

    // Sort results by severity
    let mut sorted_results = results;
    sorted_results.sort_by(|a, b| b.severity.cmp(&a.severity));

    // JSON output
    if is_json {
        let secrets_json: Vec<_> = sorted_results
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
        Output::json_value(&json!({
            "url": url,
            "total": sorted_results.len(),
            "secrets": secrets_json,
        }));
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
