impl TlsCommand {
  fn list_tls(&self, ctx: &CliContext) -> Result<(), String> {
    let host = ctx.target.as_ref().ok_or(
            "Missing target host.\nUsage: rb tls security list <HOST> [--db <file>]\nExample: rb tls security list google.com",
        )?;

    let db_path = self.get_db_path(ctx, host)?;

    let mut query = StorageService::global()
      .open_query_manager(&db_path)
      .map_err(|e| format!("Failed to open database: {}", e))?;

    annotate_query_partition(
      ctx,
      &db_path,
      [("query_dataset", "tls"), ("query_operation", "list")],
    );

    let mut scans = query
      .list_tls_scans(host)
      .map_err(|e| format!("Query failed: {}", e))?;

    if scans.is_empty() {
      Output::warning(&format!("No TLS scans found for {} in database", host));
      Output::dim(&format!("  Database: {}", db_path.display()));
      return Ok(());
    }

    scans.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Output::header(&format!("TLS Scans for {}", host));
    Output::dim(&format!("Database: {}\n", db_path.display()));

    println!(
      "{:<12}  {:<10}  {:<30}  Certificate",
      "Timestamp", "Version", "Cipher"
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    for scan in &scans {
      let version = scan.negotiated_version.as_deref().unwrap_or("unknown");
      let cipher = scan.negotiated_cipher.as_deref().unwrap_or("n/a");
      let cert_status = if scan.certificate_valid {
        "valid"
      } else {
        "invalid"
      };
      println!(
        "{:<12}  {:<10}  {:<30}  {}",
        Self::format_timestamp(scan.timestamp),
        version,
        cipher,
        cert_status
      );
    }

    println!("\n  Total: {} scan(s)", scans.len());
    Ok(())
  }

  fn get_tls(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security get <HOST>:cert [--db <file>]\nExample: rb tls security get google.com:cert",
        )?;

    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 || parts[1] != "cert" {
      return Err(format!(
        "Invalid target format: {}\nExpected format: <host>:cert\nExample: google.com:cert",
        target
      ));
    }

    let host = parts[0];
    let db_path = self.get_db_path(ctx, host)?;

    let mut query = StorageService::global()
      .open_query_manager(&db_path)
      .map_err(|e| format!("Failed to open database: {}", e))?;

    annotate_query_partition(
      ctx,
      &db_path,
      [("query_dataset", "tls"), ("query_operation", "get")],
    );

    let scan = query
      .latest_tls_scan(host)
      .map_err(|e| format!("Query failed: {}", e))?;

    let Some(scan) = scan else {
      Output::warning(&format!("No TLS data found for {} in database", host));
      Output::dim(&format!("  Database: {}", db_path.display()));
      return Err("TLS scan not found".to_string());
    };

    if scan.certificate_chain.is_empty() {
      Output::warning("TLS scan does not contain certificate chain data");
      return Err("No certificate data available".to_string());
    }

    Output::header(&format!("TLS Certificate Chain for {}", host));
    Output::dim(&format!("Database: {}\n", db_path.display()));

    Output::section("Handshake Telemetry");
    if let Some(ref ja3) = scan.ja3 {
      Output::item("JA3", ja3);
      if let Some(ref raw) = scan.ja3_raw {
        Output::dim(&format!("  Raw: {}", raw));
      }
    } else {
      Output::dim("  JA3: unavailable");
    }

    if let Some(ref ja3s) = scan.ja3s {
      Output::item("JA3S", ja3s);
      if let Some(ref raw) = scan.ja3s_raw {
        Output::dim(&format!("  Raw: {}", raw));
      }
    } else {
      Output::dim("  JA3S: unavailable");
    }

    if !scan.peer_fingerprints.is_empty() {
      Output::subheader("Peer Certificate SHA256");
      for fp in &scan.peer_fingerprints {
        println!("  - {}", fp);
      }
    }

    for (index, cert) in scan.certificate_chain.iter().enumerate() {
      Output::section(&format!("Certificate #{}", index + 1));
      Output::item("Subject", &cert.subject);
      Output::item("Issuer", &cert.issuer);
      Output::item("Serial Number", &cert.serial_number);
      Output::item("Version", &format!("{}", cert.version));
      Output::item("Signature Algorithm", &cert.signature_algorithm);
      Output::item("Public Key Algorithm", &cert.public_key_algorithm);
      Output::item("Valid From", &Self::format_timestamp(cert.not_before));
      Output::item("Valid Until", &Self::format_timestamp(cert.not_after));
      Output::item("Self-Signed", if cert.self_signed { "yes" } else { "no" });

      if !cert.sans.is_empty() {
        println!("  Subject Alternative Names:");
        for san in &cert.sans {
          println!("    • {}", san);
        }
      }

      println!();
    }

    Ok(())
  }

  fn describe_tls(&self, ctx: &CliContext) -> Result<(), String> {
    use crate::cli::commands::describe_mode::{
      read_from_json_source, resolve_describe_mode, DescribeMode,
    };

    let host = ctx.target.as_ref().ok_or(
            "Missing target host.\nUsage: rb tls security describe <HOST> [--from-db | --persist | --from-json -]\nExample: rb tls security describe google.com",
        )?;

    match resolve_describe_mode(ctx)? {
      DescribeMode::FromJson(source) => {
        let bytes = read_from_json_source(&source)?;
        Output::header(&format!("TLS Describe: {} (from {})", host, source));
        let preview: String = String::from_utf8_lossy(&bytes).chars().take(1000).collect();
        println!("{}", preview);
        return Ok(());
      }
      mode @ (DescribeMode::Live | DescribeMode::LivePersist) => {
        let persist_hint = matches!(mode, DescribeMode::LivePersist);
        let json_mode = ctx
          .get_flag("output")
          .map(|v| v.eq_ignore_ascii_case("json"))
          .unwrap_or(false);
        let mut sub_ctx = ctx.clone();
        sub_ctx.verb = Some("audit".to_string());
        if !persist_hint {
          sub_ctx.flags.remove("persist");
          sub_ctx.flags.remove("save");
        }
        if !json_mode {
          Output::header(&format!(
            "TLS Describe (live{}): {}",
            if persist_hint { " + persist" } else { "" },
            host
          ));
        }
        // audit already honors -o json on its own, so delegating preserves the
        // JSON envelope when json_mode is true.
        return self.audit(&sub_ctx);
      }
      DescribeMode::FromDb => {
        // Fall through to existing DB read path below.
      }
    }

    let db_path = self.get_db_path(ctx, host)?;

    let mut query = StorageService::global()
      .open_query_manager(&db_path)
      .map_err(|e| format!("Failed to open database: {}", e))?;

    annotate_query_partition(
      ctx,
      &db_path,
      [("query_dataset", "tls"), ("query_operation", "describe")],
    );

    let scan = query
      .latest_tls_scan(host)
      .map_err(|e| format!("Query failed: {}", e))?;

    let Some(scan) = scan else {
      Output::warning(&format!("No TLS data found for {} in database", host));
      Output::dim(&format!("  Database: {}", db_path.display()));
      return Ok(());
    };

    Output::header(&format!("TLS Security Summary for {}", host));
    Output::dim(&format!("Database: {}\n", db_path.display()));

    Output::section("Negotiated Parameters");
    Output::item(
      "Version",
      scan.negotiated_version.as_deref().unwrap_or("unknown"),
    );
    Output::item("Cipher", scan.negotiated_cipher.as_deref().unwrap_or("n/a"));
    Output::item(
      "Cipher Strength",
      Self::render_cipher_strength(scan.negotiated_cipher_strength),
    );
    Output::item(
      "Certificate Valid",
      if scan.certificate_valid { "yes" } else { "no" },
    );

    if !scan.versions.is_empty() {
      Output::section("Version Support Matrix");
      for version in &scan.versions {
        let status = if version.supported { "✓" } else { "✗" };
        if let Some(error) = &version.error {
          println!("  {} {} ({})", status, version.version, error);
        } else {
          println!("  {} {}", status, version.version);
        }
      }
    }

    if !scan.ciphers.is_empty() {
      Output::section("Supported Ciphers");
      for cipher in &scan.ciphers {
        println!(
          "  {:<32} 0x{:04X} ({})",
          cipher.name,
          cipher.code,
          Self::render_cipher_strength(cipher.strength)
        );
      }
    }

    if !scan.vulnerabilities.is_empty() {
      Output::section("Vulnerabilities");
      for vuln in &scan.vulnerabilities {
        println!("  [{}] {}", Self::render_severity(vuln.severity), vuln.name);
        println!("    {}", vuln.description);
      }
    } else {
      Output::success("No vulnerabilities recorded for this scan");
    }

    Ok(())
  }

  fn get_db_path(&self, ctx: &CliContext, host: &str) -> Result<std::path::PathBuf, String> {
    use std::path::PathBuf;

    if let Some(db_path) = ctx.get_flag("db") {
      return Ok(PathBuf::from(db_path));
    }

    let base = host
      .trim_start_matches("www.")
      .trim_start_matches("http://")
      .trim_start_matches("https://")
      .split(':')
      .next()
      .unwrap_or(host)
      .to_lowercase();

    let primary = crate::storage::default_db_path(&base);
    if primary.exists() {
      return Ok(primary);
    }

    // Legacy fallback: CWD copy from pre-0.2.13.
    if let Ok(cwd) = std::env::current_dir() {
      let legacy = cwd.join(format!("{}.rdb", &base));
      if legacy.exists() {
        return Ok(legacy);
      }
    }

    Err(format!(
      "Database file not found: {}\nRun `rb tls security audit {} --persist` first to collect data",
      primary.display(),
      host
    ))
  }
}
