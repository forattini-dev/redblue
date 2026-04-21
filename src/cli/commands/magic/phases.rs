impl MagicScan {
  fn discover_paths(&self) -> Result<PhaseResult, String> {
    let url = self.target_url();
    let config = PathEnumConfig {
      brute: true, // Phase 3 is aggressive — enable brute force
      ..Default::default()
    };
    let enumerator = PathEnumerator::new(config);
    let results = enumerator.enumerate(&url);

    let summary = format!("{} paths discovered", results.len());
    let details = results
      .iter()
      .map(|p| format!("[{}] {} ({}B, {:?})", p.status, p.path, p.size, p.source))
      .collect();

    Ok(PhaseResult::new(summary, details))
  }

  fn print_details(details: &[String]) {
    for detail in details.iter().take(8) {
      Output::item("", detail);
    }
    if details.len() > 8 {
      Output::item("", &format!("... and {} more", details.len() - 8));
    }
  }

  /// Phase 2: Stealth active scanning (minimal contact)
  ///
  /// All enabled tasks run in parallel — each is independent and makes at most
  /// a few requests that look like normal browser traffic.
  fn run_stealth_phase(&self) -> Result<(), String> {
    self.session.append_section("Phase 2: Stealth Scanning")?;
    Output::phase("Phase 2: Stealth Scanning");
    println!("  ℹ  Minimal contact - looks like normal traffic\n");

    // Build the task list: (label, session_key, task_fn)
    let mut tasks: Vec<(
      &str,
      &str,
      Box<dyn Fn() -> Result<PhaseResult, String> + Send + Sync>,
    )> = Vec::new();

    if self.preset.has_module(&Module::TlsCert) {
      tasks.push((
        "TLS Certificate Check",
        "tls_cert",
        Box::new(|| self.inspect_tls_certificate()),
      ));
    }
    if self.preset.has_module(&Module::HttpHeaders) {
      tasks.push((
        "HTTP Headers Analysis",
        "http_headers",
        Box::new(|| self.analyze_http_headers()),
      ));
    }
    if self.preset.has_module(&Module::DnsEnumeration) {
      tasks.push((
        "Subdomain Enumeration (stealth)",
        "dns_enum",
        Box::new(|| self.enumerate_subdomains()),
      ));
    }
    if self.preset.has_module(&Module::PortScanCommon) {
      tasks.push((
        "Port Scan (common ports only)",
        "port_scan",
        Box::new(|| self.port_scan_common()),
      ));
    }
    if self.preset.has_module(&Module::CspAnalysis) {
      tasks.push((
        "Content-Security-Policy",
        "csp",
        Box::new(|| self.check_csp()),
      ));
    }
    if self.preset.has_module(&Module::CorsCheck) {
      tasks.push(("CORS Configuration", "cors", Box::new(|| self.check_cors())));
    }
    if self.preset.has_module(&Module::CookieAnalysis) {
      tasks.push((
        "Cookie Security",
        "cookies",
        Box::new(|| self.check_cookies()),
      ));
    }
    if self.preset.has_module(&Module::TechFingerprint) {
      tasks.push((
        "Technology Fingerprint",
        "tech_fingerprint",
        Box::new(|| self.check_technologies()),
      ));
    }
    if self.preset.has_module(&Module::DnssecCheck) {
      tasks.push((
        "DNSSEC Validation",
        "dnssec",
        Box::new(|| self.check_dnssec()),
      ));
    }
    if self.preset.has_module(&Module::EmailSecurity) {
      tasks.push((
        "Email Security (SPF/DKIM/DMARC)",
        "email_security",
        Box::new(|| self.check_email_security()),
      ));
    }

    // Run all tasks in parallel, collect results in order
    let results: std::sync::Mutex<Vec<(usize, Result<PhaseResult, String>)>> =
      std::sync::Mutex::new(Vec::new());

    std::thread::scope(|s| {
      for (idx, (_label, _key, task_fn)) in tasks.iter().enumerate() {
        let results = &results;
        s.spawn(move || {
          let result = task_fn();
          results.lock().unwrap().push((idx, result));
        });
      }
    });

    let mut collected = results.into_inner().unwrap();
    collected.sort_by_key(|(idx, _)| *idx);

    // Print results sequentially (preserves output order)
    for (idx, result) in collected {
      let (label, key, _) = &tasks[idx];
      Output::task_start(label);
      match result {
        Ok(outcome) => {
          Output::task_done(&outcome.summary);
          Self::print_details(&outcome.details);
          let _ = self
            .session
            .append_result("stealth", key, "success", &outcome.summary);
        }
        Err(err) => {
          Output::task_done("failed");
          Output::warning(&format!("    {}", err));
          let _ = self.session.append_result("stealth", key, "error", &err);
        }
      }
    }

    println!();
    Ok(())
  }

  /// Phase 3: Aggressive scanning (full speed)
  fn run_aggressive_phase(&self) -> Result<(), String> {
    self
      .session
      .append_section("Phase 3: Aggressive Scanning")?;
    Output::phase("Phase 3: Aggressive Scanning");
    println!("  ⚠  Full-speed scanning - may trigger alerts\n");

    // Full port scan
    if self.preset.has_module(&Module::PortScanFull) {
      Output::task_start("Full Port Scan (1-65535)");
      match self.port_scan_full() {
        Ok(outcome) => {
          Output::task_done(&outcome.summary);
          Self::print_details(&outcome.details);
          self.session.append_result(
            "aggressive",
            "port_scan_full",
            "success",
            &outcome.summary,
          )?;
        }
        Err(err) => {
          Output::task_done("failed");
          Output::warning(&format!("    {}", err));
          self
            .session
            .append_result("aggressive", "port_scan_full", "error", &err)?;
        }
      }
    }

    // Directory fuzzing
    if self.preset.has_module(&Module::DirFuzzing) {
      Output::task_start("Directory Fuzzing");
      let message = "Skipped (directory fuzzing module not yet implemented in core)".to_string();
      Output::task_done("skipped");
      Output::warning(&format!("    {}", message));
      self
        .session
        .append_result("aggressive", "dir_fuzz", "skipped", &message)?;
    }

    // Vulnerability scanning
    if self.preset.has_module(&Module::VulnScanning) {
      Output::task_start("Vulnerability Scanning");
      let message = "Skipped (web vulnerability scanner scheduled in roadmap)".to_string();
      Output::task_done("skipped");
      Output::warning(&format!("    {}", message));
      self
        .session
        .append_result("aggressive", "vuln_scan", "skipped", &message)?;
    }

    // Web crawling
    if self.preset.has_module(&Module::WebCrawling) {
      Output::task_start("Web Crawling");
      let message = "Skipped (web crawler subsystem pending implementation)".to_string();
      Output::task_done("skipped");
      Output::warning(&format!("    {}", message));
      self
        .session
        .append_result("aggressive", "web_crawl", "skipped", &message)?;
    }

    // Path Discovery (passive + active brute force)
    if self.preset.has_module(&Module::PathDiscovery) {
      Output::task_start("Path Discovery (brute force)");
      match self.discover_paths() {
        Ok(outcome) => {
          Output::task_done(&outcome.summary);
          Self::print_details(&outcome.details);
          self.session.append_result(
            "aggressive",
            "path_discovery",
            "success",
            &outcome.summary,
          )?;
        }
        Err(err) => {
          Output::task_done("failed");
          Output::warning(&format!("    {}", err));
          self
            .session
            .append_result("aggressive", "path_discovery", "error", &err)?;
        }
      }
    }

    println!();
    Ok(())
  }
}

/// Execute magic scan from CLI
pub fn execute(ctx: &CliContext) -> Result<(), String> {
  // When magic scan is triggered, the URL/domain is in ctx.domain
  // (because it's the first positional argument)
  let target = ctx
    .domain
    .as_ref()
    .or(ctx.target.as_ref())
    .ok_or("No target specified")?;

  // Get preset from --preset flag
  let preset_str = ctx.get_flag("preset");
  let preset_flag = preset_str.as_deref();

  let scan = MagicScan::new(target.to_string(), &ctx.raw, preset_flag)?;
  scan.run()
}

#[cfg(test)]
mod tests {
  use super::*;
  #[cfg(not(target_os = "windows"))]
  use boring::asn1::Asn1Time;
  #[cfg(not(target_os = "windows"))]
  use boring::bn::BigNum;
  #[cfg(not(target_os = "windows"))]
  use boring::hash::MessageDigest;
  #[cfg(not(target_os = "windows"))]
  use boring::pkey::PKey;
  #[cfg(not(target_os = "windows"))]
  use boring::rsa::Rsa;
  #[cfg(not(target_os = "windows"))]
  use boring::x509::extension::SubjectAlternativeName;
  #[cfg(not(target_os = "windows"))]
  use boring::x509::X509NameBuilder;

  #[cfg(not(target_os = "windows"))]
  fn make_test_localhost_cert() -> X509 {
    let rsa = Rsa::generate(2048).expect("test rsa generation");
    let pkey = PKey::from_rsa(rsa).expect("test pkey generation");

    let mut name_builder = X509NameBuilder::new().expect("test name builder");
    name_builder
      .append_entry_by_nid(Nid::COMMONNAME, "localhost")
      .expect("test common name");
    let name = name_builder.build();

    let mut builder = X509::builder().expect("test x509 builder");
    builder.set_version(2).expect("test x509 version");

    let serial = BigNum::from_u32(1)
      .expect("test serial")
      .to_asn1_integer()
      .expect("test serial asn1");
    builder
      .set_serial_number(&serial)
      .expect("test serial number");
    builder.set_subject_name(&name).expect("test subject name");
    builder.set_issuer_name(&name).expect("test issuer name");
    builder.set_pubkey(&pkey).expect("test public key");

    let not_before = Asn1Time::days_from_now(0).expect("test not before");
    let not_after = Asn1Time::days_from_now(30).expect("test not after");
    builder
      .set_not_before(&not_before)
      .expect("test set not before");
    builder
      .set_not_after(&not_after)
      .expect("test set not after");

    let ctx = builder.x509v3_context(None, None);
    let san = SubjectAlternativeName::new()
      .dns("localhost")
      .build(&ctx)
      .expect("test san");
    builder.append_extension(&san).expect("test append san");

    builder
      .sign(&pkey, MessageDigest::sha256())
      .expect("test sign cert");
    builder.build()
  }

  #[test]
  fn test_magic_scan_creation() {
    let args: Vec<String> = vec![];
    let scan = MagicScan::new("example.com".to_string(), &args, None);
    assert!(scan.is_ok());
    let scan = scan.unwrap();
    assert_eq!(scan.target, "example.com");
    assert_eq!(scan.preset.name, "stealth"); // Default
  }

  #[cfg(not(target_os = "windows"))]
  #[test]
  fn test_magic_tls_verify_host_mismatch() {
    let cert = make_test_localhost_cert();
    let now = std::time::SystemTime::now();

    let ok = MagicScan::verify_tls_certificate("localhost", &cert, now);
    assert!(ok.is_ok());

    let err = MagicScan::verify_tls_certificate("example.com", &cert, now);
    assert!(err.is_err());
  }
}
