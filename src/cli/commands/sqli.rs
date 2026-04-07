/// SQL Injection testing command - sqlmap-style vulnerability testing
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::CliContext;
use crate::modules::web::{
  sqli::tamper::TAMPER_SCRIPTS,
  sqli::techniques::HttpResponse as SqliHttpResponse,
  sqli::{payloads_by_dbms, payloads_by_technique, total_payload_count},
  Dbms, InjectionPoint, SqliScanConfig, SqliScanner, SqliTechnique,
};
use crate::protocols::http::HttpClient;

pub struct SqliCommand;

impl Command for SqliCommand {
  fn domain(&self) -> &str {
    "web"
  }

  fn resource(&self) -> &str {
    "sqli"
  }

  fn description(&self) -> &str {
    "SQL injection testing (sqlmap-style)"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "test",
        summary: "Test URL parameters for SQL injection",
        usage: "rb web sqli test <url> [--param <name>]",
      },
      Route {
        verb: "payloads",
        summary: "List available SQL injection payloads",
        usage: "rb web sqli payloads [--dbms mysql] [--technique blind]",
      },
      Route {
        verb: "tampers",
        summary: "List available WAF bypass tamper scripts",
        usage: "rb web sqli tampers",
      },
    ]
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(self.metadata().machine_output)
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("param", "Test only this parameter").with_short('p'),
      Flag::new(
        "dbms",
        "Target specific DBMS (mysql|postgres|mssql|oracle|sqlite)",
      )
      .with_short('d'),
      Flag::new(
        "technique",
        "SQLi technique (error|blind|time|union|stacked|inline)",
      )
      .with_short('T'),
      Flag::new("tamper", "Comma-separated tamper scripts to apply").with_short('t'),
      Flag::new("level", "Scan level: quick|standard|thorough")
        .with_short('l')
        .with_default("standard"),
      Flag::new("timeout", "Request timeout in seconds").with_default("10"),
      Flag::new("auth-bypass", "Test authentication bypass payloads"),
      Flag::new("cookie", "Cookie header value").with_short('c'),
      Flag::new("header", "Custom header (Name: Value)").with_short('H'),
      Flag::new("format", "Output format (text|json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Test URL for SQLi",
        "rb web sqli test 'http://vuln.site/page?id=1'",
      ),
      (
        "Test specific parameter",
        "rb web sqli test 'http://vuln.site/page?id=1&name=x' --param id",
      ),
      (
        "Test with MySQL payloads",
        "rb web sqli test 'http://vuln.site/page?id=1' --dbms mysql",
      ),
      (
        "Use tamper scripts for WAF bypass",
        "rb web sqli test 'http://vuln.site/page?id=1' --tamper space2comment,randomcase",
      ),
      (
        "Thorough scan with auth bypass",
        "rb web sqli test 'http://vuln.site/login?user=x' --level thorough --auth-bypass",
      ),
      ("List all payloads", "rb web sqli payloads"),
      ("List MySQL payloads", "rb web sqli payloads --dbms mysql"),
      ("List tamper scripts", "rb web sqli tampers"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "Missing verb. Use: rb web sqli <test|payloads|tampers>".to_string()
    })?;

    match verb.as_str() {
      "test" => self.test_sqli(ctx),
      "payloads" => self.list_payloads(ctx),
      "tampers" => self.list_tampers_cmd(ctx),
      "help" => {
        print_help(self);
        Ok(())
      }
      _ => Err(format!("Unknown verb '{}'. Use: rb web sqli help", verb)),
    }
  }
}

impl SqliCommand {
  /// Test URL for SQL injection vulnerabilities
  fn test_sqli(&self, ctx: &CliContext) -> Result<(), String> {
    let url = ctx
      .args
      .first()
      .ok_or("Missing URL. Usage: rb web sqli test <url>")?;

    // Build scan config
    let level = ctx
      .flags
      .get("level")
      .map(|s| s.as_str())
      .unwrap_or("standard");
    let mut config = match level {
      "quick" => SqliScanConfig::quick(),
      "thorough" => SqliScanConfig::thorough(),
      _ => SqliScanConfig::default(),
    };

    // Apply DBMS filter
    if let Some(dbms_str) = ctx.flags.get("dbms") {
      config = config.for_dbms(parse_dbms(dbms_str)?);
    }

    // Apply tampers
    if let Some(tampers) = ctx.flags.get("tamper") {
      let tamper_list: Vec<String> = tampers.split(',').map(|s| s.trim().to_string()).collect();
      config = config.with_tampers(tamper_list);
    }

    // Auth bypass
    if ctx.flags.contains_key("auth-bypass") {
      config.test_auth_bypass = true;
    }

    // Add headers
    if let Some(header) = ctx.flags.get("header") {
      if let Some(colon_pos) = header.find(':') {
        let name = header[..colon_pos].trim();
        let value = header[colon_pos + 1..].trim();
        config = config.with_header(name, value);
      }
    }

    // Add cookie
    if let Some(cookie) = ctx.flags.get("cookie") {
      config = config.with_header("Cookie", cookie.as_str());
    }

    // Only test specific param
    if let Some(param) = ctx.flags.get("param") {
      config.only_params = vec![param.clone()];
    }

    println!("\n\x1b[1;36m▶ SQL Injection Test\x1b[0m");
    println!("  Target: {}", url);
    println!("  Level: {}", level);
    if !config.tamper_scripts.is_empty() {
      println!("  Tampers: {}", config.tamper_scripts.join(", "));
    }
    println!();

    // Parse URL parameters
    let params = SqliScanner::parse_url_params(url);
    if params.is_empty() {
      return Err("No parameters found in URL. Add ?param=value to the URL.".to_string());
    }

    println!("  Parameters found: {}", params.len());
    for (name, value) in &params {
      println!("    • {} = {}", name, value);
    }
    println!();

    // Create scanner
    let scanner = SqliScanner::new(config.clone());

    // Create HTTP client for sending requests
    let client = HttpClient::new();

    let mut vulnerabilities_found = 0;
    let mut tested = 0;

    for (param_name, original_value) in &params {
      // Check skip list
      if config
        .skip_params
        .iter()
        .any(|p| param_name.to_lowercase().contains(&p.to_lowercase()))
      {
        continue;
      }

      // Check only list
      if !config.only_params.is_empty()
        && !config
          .only_params
          .iter()
          .any(|p| param_name.to_lowercase().contains(&p.to_lowercase()))
      {
        continue;
      }

      tested += 1;
      print!("  Testing parameter '{}' ... ", param_name);

      // Create the send_request closure
      let url_clone = url.to_string();
      let param_clone = param_name.clone();
      let client_ref = &client;

      let send_request = |payload: &str| -> SqliHttpResponse {
        let test_url = SqliScanner::build_url_with_param(&url_clone, &param_clone, payload);

        match client_ref.send_with_metrics(&crate::protocols::http::HttpRequest::get(&test_url)) {
          Ok((response, duration)) => SqliHttpResponse {
            status_code: response.status_code,
            body: String::from_utf8_lossy(&response.body).to_string(),
            headers: response.headers.clone(),
            response_time_ms: duration.as_millis() as u64,
          },
          Err(_) => SqliHttpResponse {
            status_code: 0,
            body: String::new(),
            headers: std::collections::HashMap::new(),
            response_time_ms: 0,
          },
        }
      };

      let result = scanner.scan_parameter(
        param_name,
        original_value,
        InjectionPoint::GetParam,
        send_request,
      );

      if result.detection.vulnerable {
        vulnerabilities_found += 1;
        println!("\x1b[31mVULNERABLE\x1b[0m");
        println!("    Technique: {:?}", result.detection.technique);
        if let Some(dbms) = result.detection.dbms {
          println!("    DBMS: {:?}", dbms);
        }
        if let Some(ref payload) = result.detection.payload {
          println!("    Payload: {}", payload);
        }
        println!("    Confidence: {}%", result.detection.confidence);
      } else {
        println!("\x1b[32mOK\x1b[0m");
      }
    }

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if vulnerabilities_found > 0 {
      println!(
        "\x1b[31m⚠ Found {} vulnerable parameter(s) out of {} tested\x1b[0m",
        vulnerabilities_found, tested
      );
    } else {
      println!(
        "\x1b[32m✓ No SQL injection vulnerabilities found ({} parameters tested)\x1b[0m",
        tested
      );
    }
    println!();

    Ok(())
  }

  /// List available payloads
  fn list_payloads(&self, ctx: &CliContext) -> Result<(), String> {
    println!("\n\x1b[1;36m▶ SQL Injection Payloads\x1b[0m");
    println!("  Total: {} payloads\n", total_payload_count());

    // Filter by DBMS
    if let Some(dbms_str) = ctx.flags.get("dbms") {
      let dbms = parse_dbms(dbms_str)?;
      let payloads = payloads_by_dbms(dbms);
      println!("  {:?} payloads: {}", dbms, payloads.len());
      for (i, p) in payloads.iter().take(20).enumerate() {
        println!("    {}. {} (risk: {:?})", i + 1, p.payload, p.risk);
      }
      if payloads.len() > 20 {
        println!("    ... and {} more", payloads.len() - 20);
      }
      return Ok(());
    }

    // Filter by technique
    if let Some(tech_str) = ctx.flags.get("technique") {
      let technique = parse_technique(tech_str)?;
      let payloads = payloads_by_technique(technique);
      println!("  {:?} payloads: {}", technique, payloads.len());
      for (i, p) in payloads.iter().take(20).enumerate() {
        println!("    {}. {} (dbms: {:?})", i + 1, p.payload, p.dbms);
      }
      if payloads.len() > 20 {
        println!("    ... and {} more", payloads.len() - 20);
      }
      return Ok(());
    }

    // Show summary by technique
    println!("  By Technique:");
    for technique in [
      SqliTechnique::ErrorBased,
      SqliTechnique::BooleanBlind,
      SqliTechnique::TimeBlind,
      SqliTechnique::Union,
      SqliTechnique::Stacked,
      SqliTechnique::InlineComment,
    ] {
      let count = payloads_by_technique(technique).len();
      println!("    {:?}: {} payloads", technique, count);
    }

    println!("\n  By DBMS:");
    for dbms in [
      Dbms::MySQL,
      Dbms::PostgreSQL,
      Dbms::MsSQL,
      Dbms::Oracle,
      Dbms::SQLite,
    ] {
      let count = payloads_by_dbms(dbms).len();
      println!("    {:?}: {} payloads", dbms, count);
    }

    println!("\n  Use --dbms or --technique to filter payloads");
    Ok(())
  }

  /// List tamper scripts
  fn list_tampers_cmd(&self, _ctx: &CliContext) -> Result<(), String> {
    let tampers = TAMPER_SCRIPTS;

    println!("\n\x1b[1;36m▶ WAF Bypass Tamper Scripts\x1b[0m");
    println!("  Total: {} tampers\n", tampers.len());

    for t in tampers {
      println!("  \x1b[33m{}\x1b[0m", t.name);
      println!("    {}", t.description);
      if !t.dbms.is_empty() {
        // let dbms_str: Vec<_> = t.dbms.iter().map(|d| format!("{:?}", d)).collect();
        println!("    DBMS: {}", t.dbms);
      }
      println!();
    }

    println!("  Usage: rb web sqli test <url> --tamper <name1,name2,...>");
    Ok(())
  }
}

fn parse_dbms(s: &str) -> Result<Dbms, String> {
  match s.to_lowercase().as_str() {
    "mysql" => Ok(Dbms::MySQL),
    "postgres" | "postgresql" => Ok(Dbms::PostgreSQL),
    "mssql" | "sqlserver" => Ok(Dbms::MsSQL),
    "oracle" => Ok(Dbms::Oracle),
    "sqlite" => Ok(Dbms::SQLite),
    _ => Err(format!(
      "Unknown DBMS '{}'. Use: mysql|postgres|mssql|oracle|sqlite",
      s
    )),
  }
}

fn parse_technique(s: &str) -> Result<SqliTechnique, String> {
  match s.to_lowercase().as_str() {
    "error" | "error-based" => Ok(SqliTechnique::ErrorBased),
    "blind" | "boolean" | "boolean-blind" => Ok(SqliTechnique::BooleanBlind),
    "time" | "time-blind" => Ok(SqliTechnique::TimeBlind),
    "union" => Ok(SqliTechnique::Union),
    "stacked" => Ok(SqliTechnique::Stacked),
    "inline" => Ok(SqliTechnique::InlineComment),
    _ => Err(format!(
      "Unknown technique '{}'. Use: error|blind|time|union|stacked|inline",
      s
    )),
  }
}
