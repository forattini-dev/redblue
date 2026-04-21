impl DnsCommand {

  fn email_security(&self, ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb dns record email <DOMAIN>\nExample: rb dns record email example.com",
        )?;

    Validator::validate_domain(domain)?;

    let cfg = config::get();
    let server = ctx
      .get_flag("server")
      .unwrap_or_else(|| cfg.network.dns_resolver.clone());
    let format = ctx.get_output_format();

    let client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_start("Checking email security records");
    }

    // Check SPF record (TXT record at domain)
    let spf_result = client.query(domain, DnsRecordType::TXT);
    let spf_record = spf_result.as_ref().ok().and_then(|answers| {
      answers.iter().find_map(|a| {
        let val = a.display_value();
        if val.to_lowercase().starts_with("v=spf1") {
          Some(val)
        } else {
          None
        }
      })
    });

    // Check DMARC record (TXT record at _dmarc.domain)
    let dmarc_domain = format!("_dmarc.{}", domain);
    let dmarc_result = client.query(&dmarc_domain, DnsRecordType::TXT);
    let dmarc_record = dmarc_result.as_ref().ok().and_then(|answers| {
      answers.iter().find_map(|a| {
        let val = a.display_value();
        if val.to_lowercase().starts_with("v=dmarc1") {
          Some(val)
        } else {
          None
        }
      })
    });

    // Check MX records to get mail servers
    let mx_result = client.query(domain, DnsRecordType::MX);
    let mx_records: Vec<String> = mx_result
      .as_ref()
      .ok()
      .map(|answers| answers.iter().map(|a| a.display_value()).collect())
      .unwrap_or_default();

    // Try common DKIM selectors
    let common_selectors = [
      "default",
      "selector1",
      "selector2",
      "google",
      "k1",
      "mail",
      "dkim",
    ];
    let mut dkim_results: Vec<(String, Option<String>)> = Vec::new();

    for selector in &common_selectors {
      let dkim_domain = format!("{}._domainkey.{}", selector, domain);
      let dkim_result = client.query(&dkim_domain, DnsRecordType::TXT);
      let dkim_record = dkim_result.ok().and_then(|answers| {
        answers.iter().find_map(|a| {
          let val = a.display_value();
          if val.to_lowercase().contains("v=dkim1") || val.contains("k=rsa") {
            Some(val)
          } else {
            None
          }
        })
      });

      if dkim_record.is_some() {
        dkim_results.push((selector.to_string(), dkim_record));
      }
    }

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_done();
    }

    // Calculate security score
    let mut score = 0;
    let mut max_score = 0;

    // SPF scoring
    max_score += 30;
    let spf_score = if let Some(ref spf) = spf_record {
      if spf.contains("-all") {
        30 // Strict SPF
      } else if spf.contains("~all") {
        20 // Soft fail
      } else if spf.contains("?all") {
        10 // Neutral
      } else {
        15 // Has SPF but permissive
      }
    } else {
      0
    };
    score += spf_score;

    // DKIM scoring
    max_score += 30;
    let dkim_score = if !dkim_results.is_empty() { 30 } else { 0 };
    score += dkim_score;

    // DMARC scoring
    max_score += 40;
    let dmarc_score = if let Some(ref dmarc) = dmarc_record {
      if dmarc.contains("p=reject") {
        40 // Strictest policy
      } else if dmarc.contains("p=quarantine") {
        30 // Quarantine policy
      } else if dmarc.contains("p=none") {
        15 // Monitoring only
      } else {
        20 // Has DMARC but unknown policy
      }
    } else {
      0
    };
    score += dmarc_score;

    let grade = match (score * 100) / max_score {
      90..=100 => "A",
      80..=89 => "B",
      70..=79 => "C",
      60..=69 => "D",
      _ => "F",
    };

    let selectors: Vec<_> = dkim_results
      .iter()
      .map(|(selector, record)| {
        let truncated = record.as_ref().map(|value| {
          if value.len() > 80 {
            format!("{}...", &value[..80])
          } else {
            value.clone()
          }
        });
        json!({
            "selector": selector.clone(),
            "record": truncated
        })
      })
      .collect();
    let payload = json!({
      "domain": domain,
      "server": server,
      "score": score,
      "max_score": max_score,
      "grade": grade,
      "spf": json!({
          "present": spf_record.is_some(),
          "record": spf_record.clone(),
          "score": spf_score
      }),
      "dkim": json!({
          "present": !dkim_results.is_empty(),
          "selectors": selectors,
          "score": dkim_score
      }),
      "dmarc": json!({
          "present": dmarc_record.is_some(),
          "record": dmarc_record.clone(),
          "score": dmarc_score
      }),
      "mx": mx_records.clone()
    });
    if render::render_machine_output_with_yaml(ctx, "rb dns record email", &payload, || {
      println!("domain: {}", domain);
      println!("server: {}", server);
      println!("score: {}", score);
      println!("max_score: {}", max_score);
      println!("grade: {}", grade);
      println!("spf:");
      println!("  present: {}", spf_record.is_some());
      if let Some(ref spf) = spf_record {
        println!("  record: \"{}\"", spf);
      } else {
        println!("  record: null");
      }
      println!("  score: {}", spf_score);
      println!("dkim:");
      println!("  present: {}", !dkim_results.is_empty());
      println!("  selectors:");
      for (selector, record) in &dkim_results {
        println!("    - selector: {}", selector);
        if let Some(r) = record {
          let truncated = if r.len() > 80 {
            format!("{}...", &r[..80])
          } else {
            r.clone()
          };
          println!("      record: \"{}\"", truncated);
        } else {
          println!("      record: null");
        }
      }
      println!("  score: {}", dkim_score);
      println!("dmarc:");
      println!("  present: {}", dmarc_record.is_some());
      if let Some(ref dmarc) = dmarc_record {
        println!("  record: \"{}\"", dmarc);
      } else {
        println!("  record: null");
      }
      println!("  score: {}", dmarc_score);
      println!("mx:");
      for mx in &mx_records {
        println!("  - \"{}\"", mx);
      }
      Ok(())
    })? {
      return Ok(());
    }

    // Human output
    Output::header(&format!("Email Security: {}", domain));
    println!();

    // Grade display
    let grade_color = match grade {
      "A" => "\x1b[32m", // Green
      "B" => "\x1b[92m", // Light green
      "C" => "\x1b[33m", // Yellow
      "D" => "\x1b[33m", // Yellow
      "F" => "\x1b[31m", // Red
      _ => "\x1b[0m",
    };
    println!(
      "  Grade: {}{}  {}/{}\x1b[0m",
      grade_color, grade, score, max_score
    );
    println!();

    // SPF Section
    println!("  \x1b[1mSPF (Sender Policy Framework)\x1b[0m");
    println!("  {}", "─".repeat(50));
    if let Some(ref spf) = spf_record {
      println!("  Status: \x1b[32m✓ FOUND\x1b[0m");
      // Truncate if too long
      let display_spf = if spf.len() > 70 {
        format!("{}...", &spf[..67])
      } else {
        spf.clone()
      };
      println!("  Record: {}", display_spf);

      // SPF analysis
      if spf.contains("-all") {
        println!("  Policy: \x1b[32mStrict (-all)\x1b[0m - Reject unauthorized senders");
      } else if spf.contains("~all") {
        println!("  Policy: \x1b[33mSoft fail (~all)\x1b[0m - Mark but don't reject");
      } else if spf.contains("?all") {
        println!("  Policy: \x1b[33mNeutral (?all)\x1b[0m - No policy");
      } else if spf.contains("+all") {
        println!("  Policy: \x1b[31mPermissive (+all)\x1b[0m - DANGEROUS: allows any sender");
      }
    } else {
      println!("  Status: \x1b[31m✗ NOT FOUND\x1b[0m");
      println!("  \x1b[33mRecommend: Add SPF record to prevent email spoofing\x1b[0m");
    }
    println!();

    // DKIM Section
    println!("  \x1b[1mDKIM (DomainKeys Identified Mail)\x1b[0m");
    println!("  {}", "─".repeat(50));
    if !dkim_results.is_empty() {
      println!(
        "  Status: \x1b[32m✓ FOUND\x1b[0m ({} selector(s))",
        dkim_results.len()
      );
      for (selector, record) in &dkim_results {
        println!("  Selector: {}", selector);
        if let Some(r) = record {
          let truncated = if r.len() > 50 {
            format!("{}...", &r[..47])
          } else {
            r.clone()
          };
          println!("    Record: {}", truncated);
        }
      }
    } else {
      println!("  Status: \x1b[33m? NO COMMON SELECTORS FOUND\x1b[0m");
      println!("  Checked: {}", common_selectors.join(", "));
      println!("  \x1b[2mNote: DKIM may use a custom selector\x1b[0m");
    }
    println!();

    // DMARC Section
    println!("  \x1b[1mDMARC (Domain-based Message Authentication)\x1b[0m");
    println!("  {}", "─".repeat(50));
    if let Some(ref dmarc) = dmarc_record {
      println!("  Status: \x1b[32m✓ FOUND\x1b[0m");
      let display_dmarc = if dmarc.len() > 70 {
        format!("{}...", &dmarc[..67])
      } else {
        dmarc.clone()
      };
      println!("  Record: {}", display_dmarc);

      // DMARC policy analysis
      if dmarc.contains("p=reject") {
        println!("  Policy: \x1b[32mReject\x1b[0m - Unauthorized mail is rejected");
      } else if dmarc.contains("p=quarantine") {
        println!("  Policy: \x1b[33mQuarantine\x1b[0m - Unauthorized mail goes to spam");
      } else if dmarc.contains("p=none") {
        println!("  Policy: \x1b[33mNone\x1b[0m - Monitoring only, no enforcement");
      }

      // Check for reporting
      if dmarc.contains("rua=") {
        println!("  Reports: \x1b[32m✓ Aggregate reports enabled\x1b[0m");
      }
      if dmarc.contains("ruf=") {
        println!("  Reports: \x1b[32m✓ Forensic reports enabled\x1b[0m");
      }
    } else {
      println!("  Status: \x1b[31m✗ NOT FOUND\x1b[0m");
      println!("  \x1b[33mRecommend: Add DMARC record for email authentication\x1b[0m");
    }
    println!();

    // MX Section (brief)
    if !mx_records.is_empty() {
      println!("  \x1b[1mMX Records\x1b[0m");
      println!("  {}", "─".repeat(50));
      for mx in &mx_records {
        println!("  {}", mx);
      }
      println!();
    }

    // Summary
    match grade {
      "A" => Output::success("Excellent email security configuration"),
      "B" => Output::success("Good email security configuration"),
      "C" => Output::warning("Fair email security - consider improvements"),
      "D" => Output::warning("Poor email security - action recommended"),
      "F" => Output::error("Critical: Missing essential email security records"),
      _ => {}
    }

    Ok(())
  }

  fn parse_record_type(s: &str) -> Result<DnsRecordType, String> {
    match s.to_uppercase().as_str() {
      "A" => Ok(DnsRecordType::A),
      "AAAA" => Ok(DnsRecordType::AAAA),
      "MX" => Ok(DnsRecordType::MX),
      "NS" => Ok(DnsRecordType::NS),
      "TXT" => Ok(DnsRecordType::TXT),
      "CNAME" => Ok(DnsRecordType::CNAME),
      "SOA" => Ok(DnsRecordType::SOA),
      "PTR" => Ok(DnsRecordType::PTR),
      "SRV" => Ok(DnsRecordType::SRV),
      "TLSA" => Ok(DnsRecordType::TLSA),
      "CAA" => Ok(DnsRecordType::CAA),
      "ANY" => Ok(DnsRecordType::ANY),
      _ => Err(format!(
        "Invalid record type: {}\nSupported types: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, TLSA, CAA, ANY",
        s
      )),
    }
  }

  fn record_type_to_string(record_type: DnsRecordType) -> &'static str {
    match record_type {
      DnsRecordType::A => "A",
      DnsRecordType::AAAA => "AAAA",
      DnsRecordType::MX => "MX",
      DnsRecordType::NS => "NS",
      DnsRecordType::TXT => "TXT",
      DnsRecordType::CNAME => "CNAME",
      DnsRecordType::SOA => "SOA",
      DnsRecordType::PTR => "PTR",
      DnsRecordType::SRV => "SRV",
      DnsRecordType::TLSA => "TLSA",
      DnsRecordType::CAA => "CAA",
      DnsRecordType::DS => "DS",
      DnsRecordType::RRSIG => "RRSIG",
      DnsRecordType::NSEC => "NSEC",
      DnsRecordType::DNSKEY => "DNSKEY",
      DnsRecordType::NSEC3 => "NSEC3",
      DnsRecordType::ANY => "ANY",
    }
  }

  fn build_ptr_name(addr: std::net::IpAddr) -> String {
    match addr {
      std::net::IpAddr::V4(v4) => {
        let octets = v4.octets();
        format!(
          "{}.{}.{}.{}.in-addr.arpa",
          octets[3], octets[2], octets[1], octets[0]
        )
      }
      std::net::IpAddr::V6(v6) => {
        let mut labels = Vec::with_capacity(32);
        for byte in v6.octets().iter().rev() {
          labels.push(format!("{:x}", byte & 0x0F));
          labels.push(format!("{:x}", byte >> 4));
        }
        format!("{}.ip6.arpa", labels.join("."))
      }
    }
  }

  // ===== RESTful Commands - Query Stored Data =====

  fn list_records(&self, ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or("Missing target domain")?;

    let db_path = self.get_db_path(ctx, domain)?;

    Output::header(&format!("Listing DNS Records from Database: {}", domain));
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
      [("query_dataset", "dns"), ("query_operation", "list")],
    );

    let records = query
      .list_dns_records(domain)
      .map_err(|e| format!("Query failed: {}", e))?;

    if records.is_empty() {
      Output::warning("No DNS records found in database");
      Output::info(&format!(
        "Run a DNS lookup first: rb dns record lookup {} --persist",
        domain
      ));
      return Ok(());
    }

    Output::success(&format!("Found {} DNS record(s)", records.len()));
    println!();

    println!("TYPE     VALUE                                          TTL");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    for record in &records {
      let type_str = format!("{:?}", record.record_type);
      println!("{:<8} {:<46} {}", type_str, record.value, record.ttl);
    }

    Ok(())
  }

  fn get_record(&self, ctx: &CliContext) -> Result<(), String> {
    use crate::cli::commands::describe_mode::{
      read_from_json_source, resolve_describe_mode, DescribeMode,
    };

    let target = ctx
      .target
      .as_ref()
      .ok_or("Missing target (format: domain:TYPE)")?;

    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
      return Err(
        "Invalid format. Use: rb dns record get <domain>:<type> (e.g., example.com:A)".to_string(),
      );
    }

    let domain = parts[0];
    let record_type_str = parts[1].to_uppercase();

    let record_type = match record_type_str.as_str() {
      "A" => StorageDnsRecordType::A,
      "AAAA" => StorageDnsRecordType::AAAA,
      "MX" => StorageDnsRecordType::MX,
      "NS" => StorageDnsRecordType::NS,
      "TXT" => StorageDnsRecordType::TXT,
      "CNAME" => StorageDnsRecordType::CNAME,
      _ => {
        return Err(format!(
          "Invalid record type: {}. Valid types: A, AAAA, MX, NS, TXT, CNAME",
          record_type_str
        ))
      }
    };

    match resolve_describe_mode(ctx)? {
      DescribeMode::FromJson(source) => {
        let bytes = read_from_json_source(&source)?;
        Output::header(&format!(
          "DNS Record: {} {} (from {})",
          domain, record_type_str, source
        ));
        let preview: String = String::from_utf8_lossy(&bytes).chars().take(1000).collect();
        println!("{}", preview);
        return Ok(());
      }
      DescribeMode::Live | DescribeMode::LivePersist => {
        // Default (Live) and LivePersist both delegate to the live `lookup`
        // verb. Persist is forwarded through ctx so the storage layer writes
        // when auto_persist allows. Discard-mode strips persist/save.
        let mut sub_ctx = ctx.clone();
        sub_ctx.verb = Some("lookup".to_string());
        sub_ctx
          .flags
          .insert("type".to_string(), record_type_str.clone());
        if matches!(resolve_describe_mode(ctx)?, DescribeMode::Live) {
          sub_ctx.flags.remove("persist");
          sub_ctx.flags.remove("save");
        }
        // Rewrite the target to just the domain (strip the :type suffix).
        sub_ctx.target = Some(domain.to_string());
        return self.lookup(&sub_ctx);
      }
      DescribeMode::FromDb => {
        // Fall through to existing DB read path below.
      }
    }

    let db_path = self.get_db_path(ctx, domain)?;

    Output::header(&format!(
      "Querying DNS Record: {} {}",
      domain, record_type_str
    ));

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
      [
        ("query_dataset", "dns"),
        ("query_operation", "get"),
        ("query_key", record_type_str.as_str()),
      ],
    );

    let all_records = query
      .list_dns_records(domain)
      .map_err(|e| format!("Query failed: {}", e))?;

    let matching_records: Vec<_> = all_records
      .iter()
      .filter(|r| std::mem::discriminant(&r.record_type) == std::mem::discriminant(&record_type))
      .collect();

    if matching_records.is_empty() {
      Output::warning(&format!("No {} records found in database", record_type_str));
      Output::info(&format!(
        "Run a DNS lookup first: rb dns record lookup {} --type {} --persist",
        domain, record_type_str
      ));
      return Ok(());
    }

    Output::success(&format!(
      "Found {} {} record(s)",
      matching_records.len(),
      record_type_str
    ));
    println!();

  for record in matching_records {
    Output::item("Domain", &record.domain);
    Output::item("Type", &format!("{:?}", record.record_type));
    Output::item("Value", &record.value);
    Output::item("TTL", &record.ttl.to_string());
    println!();
  }

  Ok(())
  }

}
