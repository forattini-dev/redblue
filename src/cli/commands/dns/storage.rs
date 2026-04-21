impl DnsCommand {

  fn describe_records(&self, ctx: &CliContext) -> Result<(), String> {
    use crate::cli::commands::describe_mode::{
      read_from_json_source, resolve_describe_mode, DescribeMode,
    };

    let domain = ctx.target.as_ref().ok_or("Missing target domain")?;

    match resolve_describe_mode(ctx)? {
      DescribeMode::FromJson(source) => {
        let bytes = read_from_json_source(&source)?;
        Output::header(&format!("DNS Describe: {} (from {})", domain, source));
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
        sub_ctx.verb = Some("lookup".to_string());
        if !persist_hint {
          sub_ctx.flags.remove("persist");
          sub_ctx.flags.remove("save");
        }

        if json_mode {
          use crate::cli::commands::web::db::run_describe_subcommands_json;
          let records: Vec<(&str, Vec<&str>)> = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
            .iter()
            .map(|t| (*t, vec!["dns", "record", "lookup"]))
            .collect();
          let refs: Vec<(&str, &[&str])> =
            records.iter().map(|(n, v)| (*n, v.as_slice())).collect();
          // For DNS, each sub-invocation needs `--type <T>` to differ. Since
          // our helper forwards one flag set, we invoke each type inline and
          // aggregate manually.
          let mut out = String::from("{\n");
          out.push_str(&format!("  \"target\": \"{}\",\n", domain));
          out.push_str("  \"records\": {\n");
          for (idx, (name, _)) in refs.iter().enumerate() {
            let mut type_ctx = sub_ctx.clone();
            type_ctx
              .flags
              .insert("type".to_string(), (*name).to_string());
            let payload = capture_dns_lookup_json(&type_ctx, domain, name);
            let comma = if idx + 1 < refs.len() { "," } else { "" };
            out.push_str(&format!("    \"{}\": {}{}\n", name, payload, comma));
          }
          out.push_str("  }\n}");
          println!("{}", out);
          return Ok(());
        }

        Output::header(&format!(
          "DNS Describe (live{}): {}",
          if persist_hint { " + persist" } else { "" },
          domain
        ));
        for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] {
          let mut type_ctx = sub_ctx.clone();
          type_ctx
            .flags
            .insert("type".to_string(), record_type.to_string());
          println!();
          println!("─── {} ───", record_type);
          if let Err(e) = self.lookup(&type_ctx) {
            Output::warning(&format!("{}: {}", record_type, e));
          }
        }
        return Ok(());
      }
      DescribeMode::FromDb => {
        // Fall through to existing DB read path below.
      }
    }

    let db_path = self.get_db_path(ctx, domain)?;

    Output::header(&format!("DNS Description: {}", domain));
    Output::info(&format!("Database: {}", db_path.display()));

    let mut query = StorageService::global()
      .open_query_manager(&db_path)
      .map_err(|e| {
        format!(
          "Unable to open DB at {}: {}. If this file was not produced by `rb ... --persist`, delete it or point --db at a real scan DB.",
          db_path.display(),
          e
        )
      })?;

    annotate_query_partition(
      ctx,
      &db_path,
      [("query_dataset", "dns"), ("query_operation", "describe")],
    );

    let records = query
      .list_dns_records(domain)
      .map_err(|e| format!("Query failed: {}", e))?;

    if records.is_empty() {
      Output::warning("No DNS data found in database");
      Output::info(&format!(
        "Run a DNS lookup first: rb dns record lookup {} --persist",
        domain
      ));
      return Ok(());
    }

    // Count records by type
    let mut type_counts: std::collections::HashMap<String, usize> =
      std::collections::HashMap::new();
    for record in &records {
      let type_str = format!("{:?}", record.record_type);
      *type_counts.entry(type_str).or_insert(0) += 1;
    }

    Output::success(&format!("Total DNS Records: {}", records.len()));
    println!();

    println!("📊 Record Summary:");
    println!("━━━━━━━━━━━━━━━━━━━");
    for (record_type, count) in &type_counts {
      println!("  {} records: {}", record_type, count);
    }
    println!();

    println!("📝 Detailed Records:");
    println!("━━━━━━━━━━━━━━━━━━━");
    for record in &records {
      println!(
        "  {:6} → {} (TTL: {})",
        format!("{:?}", record.record_type),
        record.value,
        record.ttl
      );
    }

    Ok(())
  }

  fn dnssec(&self, ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or(
      "Missing domain.\nUsage: rb dns record dnssec <DOMAIN>\nExample: rb dns record dnssec example.com",
    )?;

    Validator::validate_domain(domain)?;

    let cfg = config::get();
    let server = ctx
      .get_flag("server")
      .unwrap_or_else(|| cfg.network.dns_resolver.clone());

    Output::spinner_start(&format!("Checking DNSSEC for {}", domain));
    let assessment = crate::modules::dns::dnssec::assess_dnssec(domain, &server);
    Output::spinner_done();

    // Build JSON payload for machine output
    let status_str = match &assessment.status {
      DnssecStatus::Secure { .. } => "secure",
      DnssecStatus::Bogus { .. } => "bogus",
      DnssecStatus::Insecure => "insecure",
      DnssecStatus::Indeterminate { .. } => "indeterminate",
    };

    let dnskeys_json: Vec<_> = assessment
      .dnskeys
      .iter()
      .map(|k| {
        json!({
          "role": if k.is_ksk { "KSK" } else { "ZSK" },
          "algorithm": k.algorithm,
          "key_tag": k.key_tag,
          "key_size_bits": k.key_size_bits,
          "flags": k.flags
        })
      })
      .collect();

    let ds_json: Vec<_> = assessment
      .ds_records
      .iter()
      .map(|ds| {
        json!({
          "key_tag": ds.key_tag,
          "algorithm": ds.algorithm,
          "digest_type": ds.digest_type,
          "digest": ds.digest_hex
        })
      })
      .collect();

    let sigs_json: Vec<_> = assessment
      .signatures
      .iter()
      .map(|sig| {
        json!({
          "type_covered": sig.type_covered,
          "algorithm": sig.algorithm,
          "signer": sig.signer,
          "key_tag": sig.key_tag,
          "valid": sig.valid,
          "expiration": sig.expiration,
          "inception": sig.inception
        })
      })
      .collect();

    let payload = json!({
      "domain": domain,
      "server": server,
      "status": status_str,
      "dnskeys": dnskeys_json,
      "ds_records": ds_json,
      "signatures": sigs_json
    });

    if render::render_machine_output_with_yaml(ctx, "rb dns record dnssec", &payload, || {
      println!("domain: {}", domain);
      println!("server: {}", server);
      println!("status: {}", status_str);
      println!("dnskeys:");
      for k in &assessment.dnskeys {
        let role = if k.is_ksk { "KSK" } else { "ZSK" };
        println!("  - role: {}", role);
        println!("    algorithm: {}", k.algorithm);
        println!("    key_tag: {}", k.key_tag);
        println!("    key_size_bits: {}", k.key_size_bits);
      }
      println!("ds_records:");
      for ds in &assessment.ds_records {
        println!("  - key_tag: {}", ds.key_tag);
        println!("    algorithm: {}", ds.algorithm);
        println!("    digest_type: {}", ds.digest_type);
      }
      println!("signatures:");
      for sig in &assessment.signatures {
        println!("  - type_covered: {}", sig.type_covered);
        println!("    signer: {}", sig.signer);
        println!("    key_tag: {}", sig.key_tag);
        println!("    valid: {}", sig.valid);
      }
      Ok(())
    })? {
      return Ok(());
    }

    // Human-readable output
    Output::header(&format!("DNSSEC: {}", domain));

    match &assessment.status {
      DnssecStatus::Secure {
        algorithms,
        key_count,
        has_ksk,
        has_zsk,
      } => {
        Output::success("DNSSEC: Secure (signed and validated)");
        println!("  Keys: {} (KSK: {}, ZSK: {})", key_count, has_ksk, has_zsk);
        println!("  Algorithms: {}", algorithms.join(", "));
      }
      DnssecStatus::Bogus { reason } => {
        Output::error(&format!("DNSSEC: Bogus - {}", reason));
      }
      DnssecStatus::Insecure => {
        Output::warning("DNSSEC: Insecure (not signed)");
        println!("  This domain does not use DNSSEC.");
        println!("  DNS responses could be spoofed.");
      }
      DnssecStatus::Indeterminate { reason } => {
        Output::warning(&format!("DNSSEC: Indeterminate - {}", reason));
      }
    }

    if !assessment.dnskeys.is_empty() {
      println!();
      println!("  DNSKEY records:");
      for key in &assessment.dnskeys {
        let role = if key.is_ksk { "KSK" } else { "ZSK" };
        println!(
          "    {} ({}) - {} bits, tag {}",
          role, key.algorithm, key.key_size_bits, key.key_tag
        );
      }
    }

    if !assessment.ds_records.is_empty() {
      println!();
      println!("  DS records:");
      for ds in &assessment.ds_records {
        println!(
          "    tag {} - {} ({})",
          ds.key_tag, ds.algorithm, ds.digest_type
        );
      }
    }

    if !assessment.signatures.is_empty() {
      println!();
      println!("  Signatures:");
      for sig in &assessment.signatures {
        let status = if sig.valid { "valid" } else { "EXPIRED" };
        println!(
          "    {} signed by {} (tag {}) - {}",
          sig.type_covered, sig.signer, sig.key_tag, status
        );
      }
    }

    Ok(())
  }

  fn get_db_path(&self, ctx: &CliContext, domain: &str) -> Result<std::path::PathBuf, String> {
    if let Some(db_path) = ctx.get_flag("db") {
      return Ok(std::path::PathBuf::from(db_path));
    }

    let primary = crate::storage::default_db_path(domain);
    if primary.exists() {
      return Ok(primary);
    }

    // Legacy fallback: check CWD for users coming from pre-0.2.13 scans.
    let base = domain.trim_start_matches("www.").to_lowercase();
    if let Ok(cwd) = std::env::current_dir() {
      let legacy = cwd.join(format!("{}.rdb", &base));
      if legacy.exists() {
        return Ok(legacy);
      }
    }

    Err(format!(
      "Database not found: {}\nRun a scan first: rb dns record lookup {} --persist",
      primary.display(),
      domain
    ))
  }
}
