/// TLS/SSL security testing command
use crate::cli::commands::{
  annotate_query_partition, build_partition_attributes, print_help, Command, Flag, Route,
};
use crate::cli::{output::Output, render, validator::Validator, CliContext};
use crate::json;
use crate::modules::common::Severity;
use crate::modules::tls::auditor::{CipherStrength, TlsAuditResult, TlsAuditor};
use crate::modules::tls::mozilla_profiles::{
  ComplianceSeverity, MozillaComplianceChecker, MozillaProfile,
};
use crate::modules::tls::session_resumption::{ResumptionSeverity, SessionResumptionTester};
use crate::protocols::tls_cert::CertificateInfo;
use crate::protocols::x509::parse_x509_time;
use crate::storage::client::ActionRecorder;
use crate::storage::records::{
  TlsCertRecord, TlsCipherRecord, TlsCipherStrength, TlsScanRecord, TlsSeverity, TlsVersionRecord,
  TlsVulnerabilityRecord,
};
use crate::storage::segments::convert::TlsAuditResults;
use crate::storage::service::StorageService;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TlsCommand;

impl Command for TlsCommand {
  fn domain(&self) -> &str {
    "tls"
  }

  fn resource(&self) -> &str {
    "security"
  }

  fn description(&self) -> &str {
    "TLS/SSL security testing and cipher enumeration"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
      .with_aliases(crate::cli::aliases::resource_aliases_for(self.resource()))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_preferred_flag("output", "json")
          .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let aliases = crate::cli::aliases::verb_aliases_for(verb);
    match verb {
      "audit" => crate::cli::schema::RouteMetadata::new()
        .with_aliases(aliases)
        .with_machine_output(
          crate::cli::schema::MachineOutputMetadata::new()
            .with_preferred_flag("output", "json")
            .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
            .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
            .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
        ),
      _ => crate::cli::schema::RouteMetadata::new()
        .with_aliases(aliases)
        .with_machine_output(self.metadata().machine_output),
    }
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "audit",
        summary: "Full TLS security audit (sslyze replacement)",
        usage: "rb tls security audit <host[:port]> [--timeout SEC]",
      },
      Route {
        verb: "ciphers",
        summary: "Enumerate supported cipher suites (sslscan replacement)",
        usage: "rb tls security ciphers <host[:port]>",
      },
      Route {
        verb: "vuln",
        summary: "Check for known TLS vulnerabilities",
        usage: "rb tls security vuln <host[:port]>",
      },
      Route {
        verb: "resume",
        summary: "Test session resumption (Session ID, Tickets, TLS 1.3 PSK)",
        usage: "rb tls security resume <host[:port]>",
      },
      Route {
        verb: "mozilla",
        summary: "Check Mozilla TLS compliance (Modern/Intermediate/Old profiles)",
        usage: "rb tls security mozilla <host[:port]> [--profile modern|intermediate|old]",
      },
      // RESTful verbs - query stored data
      Route {
        verb: "list",
        summary: "List all stored TLS scans for a host",
        usage: "rb tls security list <host> [--db <file>]",
      },
      Route {
        verb: "get",
        summary: "Show stored TLS certificate chain for a host",
        usage: "rb tls security get <host>:cert [--db <file>]",
      },
      Route {
        verb: "describe",
        summary: "Summarize stored TLS findings for a host",
        usage: "rb tls security describe <host> [--db <file>]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("timeout", "Connection timeout in seconds").with_default("10"),
      Flag::new("port", "Target port").with_default("443"),
      Flag::new("persist", "Save results to binary database (.rdb file)"),
      Flag::new("no-persist", "Don't save results (overrides config)"),
      Flag::new(
        "from-db",
        "describe/get: read from an existing DB instead of collecting live",
      ),
      Flag::new("cache-only", "Alias for --from-db"),
      Flag::new(
        "from-json",
        "describe/get: ingest a pre-collected payload (path or '-' for stdin)",
      ),
      Flag::new("output", "Output format (text|json)")
        .with_short('o')
        .with_default("text"),
      Flag::new(
        "db",
        "Database file path for RESTful queries (default: auto-detect)",
      )
      .with_short('d'),
      Flag::new(
        "profile",
        "Mozilla compliance profile (modern|intermediate|old)",
      )
      .with_short('p')
      .with_default("intermediate"),
      // Global action flags for unified intelligence layer
      Flag::new("trace", "Enable detailed attempt tracing"),
      Flag::new("no-store", "Disable automatic action storage"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Full TLS audit", "rb tls security audit google.com"),
      (
        "Audit with custom port",
        "rb tls security audit example.com:8443",
      ),
      (
        "Cipher enumeration only",
        "rb tls security ciphers google.com",
      ),
      (
        "Vulnerability scan",
        "rb tls security vuln example.com --timeout 15",
      ),
      (
        "Session resumption test",
        "rb tls security resume google.com",
      ),
      (
        "Mozilla Modern compliance",
        "rb tls security mozilla example.com --profile modern",
      ),
      (
        "Mozilla Intermediate check",
        "rb tls security mozilla example.com",
      ),
      ("List stored TLS scans", "rb tls security list example.com"),
      (
        "Show TLS summary from database",
        "rb tls security describe example.com",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      // Action verbs
      "audit" => self.audit(ctx),
      "ciphers" => self.ciphers(ctx),
      "vuln" => self.vuln(ctx),
      "resume" => self.resume(ctx),
      "mozilla" => self.mozilla(ctx),
      "list" => self.list_tls(ctx),
      "get" => self.get_tls(ctx),
      "describe" => self.describe_tls(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        println!(
          "{}",
          Validator::suggest_command(
            verb,
            &["audit", "ciphers", "vuln", "resume", "mozilla", "list", "get", "describe"]
          )
        );
        Err("Invalid verb".to_string())
      }
    }
  }
}

impl TlsCommand {
  fn audit(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security audit <HOST[:PORT]>\nExample: rb tls security audit google.com",
        )?;

    let (host, port) = Self::parse_host_port(target, 443)?;
    let timeout = ctx
      .flags
      .get("timeout")
      .and_then(|v| v.parse::<u64>().ok())
      .unwrap_or(10);

    let format = ctx.get_output_format();
    if format == crate::cli::format::OutputFormat::Human {
      Output::header(&format!("TLS Security Audit: {}:{}", host, port));
    }
    let auditor = TlsAuditor::new().with_timeout(std::time::Duration::from_secs(timeout));

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_start("Running TLS audit");
    }
    let result = auditor
      .audit(&host, port)
      .map_err(|e| format!("TLS audit failed: {}", e))?;
    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_done();
    }

    let payload = self.audit_json_payload(&host, port, &result);
    if render::render_machine_output(ctx, "rb tls security audit", &payload)? {
      self.save_if_enabled(ctx, &host, &result)?;
      return Ok(());
    }

    // Display TLS versions
    Output::section("Supported TLS Versions");
    for version in &result.supported_versions {
      if version.supported {
        match version.version.as_str() {
          "TLS 1.0" | "SSLv3" | "SSLv2" => Output::error(&format!(
            "  {} ENABLED (deprecated and insecure — disable immediately)",
            version.version
          )),
          "TLS 1.1" => Output::warning(&format!(
            "  {} ENABLED (legacy protocol — schedule removal)",
            version.version
          )),
          _ => Output::success(&format!("  {}", version.version)),
        }
      } else if let Some(ref err) = version.error {
        Output::dim(&format!("  ✗ {} ({})", version.version, err));
      }
    }

    // Display cipher suites
    if !result.supported_ciphers.is_empty() {
      Output::section(&format!(
        "Supported Cipher Suites ({})",
        result.supported_ciphers.len()
      ));
      for cipher in &result.supported_ciphers {
        let color = match cipher.strength {
          CipherStrength::Secure => "\x1b[32m", // Green - modern ciphers
          CipherStrength::Weak => "\x1b[33m",   // Yellow - deprecated
          CipherStrength::Insecure => "\x1b[31m", // Red - broken
          CipherStrength::NullCipher => "\x1b[35m", // Magenta - no encryption!
        };
        println!(
          "  {}● {:?} - {} (0x{:04X})\x1b[0m",
          color, cipher.strength, cipher.name, cipher.code
        );
      }
    }

    // Display vulnerabilities
    if !result.vulnerabilities.is_empty() {
      Output::section(&format!(
        "Vulnerabilities Found ({})",
        result.vulnerabilities.len()
      ));
      for vuln in &result.vulnerabilities {
        let color = match vuln.severity {
          Severity::Critical => "\x1b[35m", // Magenta
          Severity::High => "\x1b[31m",     // Red
          Severity::Medium => "\x1b[33m",   // Yellow
          Severity::Low => "\x1b[36m",      // Cyan
          Severity::Info => "\x1b[37m",     // White
        };
        println!("  {}{} [{}]\x1b[0m", color, vuln.name, vuln.severity);
        println!("    {}", vuln.description);
      }
    } else {
      Output::success("\nNo known vulnerabilities detected");
    }

    // Certificate validation
    Output::section("Certificate Validation");
    if result.certificate_valid {
      Output::success("  ✓ Certificate chain is valid");
    } else {
      Output::error("  ✗ Certificate validation failed");
    }

    if !result.certificate_chain.is_empty() {
      Output::dim(&format!(
        "  Chain length: {} certificate(s)",
        result.certificate_chain.len()
      ));
    }

    Output::section("Handshake Fingerprints");
    if let Some(ref ja3) = result.ja3 {
      Output::item("JA3", ja3);
      if let Some(ref raw) = result.ja3_raw {
        Output::dim(&format!("  Raw: {}", raw));
      }
    } else {
      Output::dim("  JA3: unavailable");
    }

    if let Some(ref ja3s) = result.ja3s {
      Output::item("JA3S", ja3s);
      if let Some(ref raw) = result.ja3s_raw {
        Output::dim(&format!("  Raw: {}", raw));
      }
    } else {
      Output::dim("  JA3S: unavailable");
    }

    if !result.peer_fingerprints.is_empty() {
      Output::subheader("Peer Certificate SHA256");
      for fp in &result.peer_fingerprints {
        println!("  - {}", fp);
      }
    }

    // Legacy persistence
    self.save_if_enabled(ctx, &host, &result)?;

    // Auto-persist to unified intelligence layer
    let action_config = ctx.get_action_config();
    if action_config.should_store() {
      let mut recorder = ActionRecorder::new("tls-security-audit", action_config)?;

      // Get the strongest cipher version
      let version = result
        .supported_versions
        .iter()
        .filter(|v| v.supported)
        .map(|v| v.version.clone())
        .next()
        .unwrap_or_else(|| "unknown".to_string());

      // Get the first supported cipher
      let cipher = result
        .supported_ciphers
        .first()
        .map(|c| c.name.clone())
        .unwrap_or_else(|| "unknown".to_string());

      // Extract certificate info
      let (cert_subject, cert_issuer, expires_at) = result
        .certificate_chain
        .first()
        .map(|c| {
          // Parse valid_until string to timestamp if possible
          let expires = parse_x509_time(&c.valid_until)
            .and_then(|st| st.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
          (Some(c.subject.clone()), Some(c.issuer.clone()), expires)
        })
        .unwrap_or((None, None, None));

      // Collect vulnerability names
      let issues: Vec<String> = result
        .vulnerabilities
        .iter()
        .map(|v| v.name.clone())
        .collect();

      let tls_result = TlsAuditResults {
        host: host.to_string(),
        port,
        version,
        cipher,
        certificate_subject: cert_subject,
        certificate_issuer: cert_issuer,
        expires_at,
        issues,
        error: None,
      };
      recorder.record(tls_result)?;

      let count = recorder.commit()?;
      if count > 0 && format == crate::cli::format::OutputFormat::Human {
        Output::info(&format!("Action recorded ({} entries)", count));
      }
    }

    Ok(())
  }

  fn ciphers(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security ciphers <HOST[:PORT]>\nExample: rb tls security ciphers google.com",
        )?;

    let (host, port) = Self::parse_host_port(target, 443)?;
    let timeout = ctx
      .flags
      .get("timeout")
      .and_then(|v| v.parse::<u64>().ok())
      .unwrap_or(10);

    Output::header(&format!("TLS Cipher Enumeration: {}:{}", host, port));

    let auditor = TlsAuditor::new().with_timeout(std::time::Duration::from_secs(timeout));

    Output::spinner_start("Enumerating cipher suites");
    let result = auditor
      .audit(&host, port)
      .map_err(|e| format!("Cipher enumeration failed: {}", e))?;
    Output::spinner_done();

    if result.supported_ciphers.is_empty() {
      Output::warning("No cipher suites detected");
      return Ok(());
    }

    // Group by strength
    let mut secure = Vec::new();
    let mut weak = Vec::new();
    let mut insecure = Vec::new();

    for cipher in &result.supported_ciphers {
      match cipher.strength {
        CipherStrength::Secure => secure.push(cipher),
        CipherStrength::Weak => weak.push(cipher),
        CipherStrength::Insecure | CipherStrength::NullCipher => insecure.push(cipher),
      }
    }

    Output::section(&format!(
      "Cipher Suites Summary (Total: {})",
      result.supported_ciphers.len()
    ));
    println!(
            "  \x1b[32m● Secure:\x1b[0m    {}\n  \x1b[33m● Weak:\x1b[0m      {}\n  \x1b[31m● Insecure:\x1b[0m  {}",
            secure.len(),
            weak.len(),
            insecure.len()
        );

    if !secure.is_empty() {
      Output::section("Secure Ciphers");
      for cipher in secure {
        println!("  \x1b[32m✓\x1b[0m {} (0x{:04X})", cipher.name, cipher.code);
      }
    }

    if !weak.is_empty() {
      Output::section("Weak Ciphers (Deprecated)");
      for cipher in weak {
        println!("  \x1b[33m●\x1b[0m {} (0x{:04X})", cipher.name, cipher.code);
      }
    }

    if !insecure.is_empty() {
      Output::section("Insecure Ciphers (AVOID!)");
      for cipher in insecure {
        println!("  \x1b[31m✗\x1b[0m {} (0x{:04X})", cipher.name, cipher.code);
      }
    }

    self.save_if_enabled(ctx, &host, &result)?;

    Ok(())
  }

  fn vuln(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security vuln <HOST[:PORT]>\nExample: rb tls security vuln example.com",
        )?;

    let (host, port) = Self::parse_host_port(target, 443)?;
    let timeout = ctx
      .flags
      .get("timeout")
      .and_then(|v| v.parse::<u64>().ok())
      .unwrap_or(10);

    Output::header(&format!("TLS Vulnerability Scan: {}:{}", host, port));

    let auditor = TlsAuditor::new().with_timeout(std::time::Duration::from_secs(timeout));

    Output::spinner_start("Scanning for TLS vulnerabilities");
    let result = auditor
      .audit(&host, port)
      .map_err(|e| format!("Vulnerability scan failed: {}", e))?;
    Output::spinner_done();

    if result.vulnerabilities.is_empty() {
      Output::success("\n✓ No known TLS vulnerabilities detected");
      Output::dim("  The TLS configuration appears secure");
      return Ok(());
    }

    // Group by severity
    let mut critical = Vec::new();
    let mut high = Vec::new();
    let mut medium = Vec::new();
    let mut low = Vec::new();
    let mut info = Vec::new();

    for vuln in &result.vulnerabilities {
      match vuln.severity {
        Severity::Critical => critical.push(vuln),
        Severity::High => high.push(vuln),
        Severity::Medium => medium.push(vuln),
        Severity::Low => low.push(vuln),
        Severity::Info => info.push(vuln),
      }
    }

    Output::section(&format!(
      "Vulnerabilities Summary (Total: {})",
      result.vulnerabilities.len()
    ));
    println!(
            "  \x1b[35m● Critical:\x1b[0m {}\n  \x1b[31m● High:\x1b[0m     {}\n  \x1b[33m● Medium:\x1b[0m   {}\n  \x1b[36m● Low:\x1b[0m      {}",
            critical.len(),
            high.len(),
            medium.len(),
            low.len()
        );

    if !critical.is_empty() {
      Output::section("CRITICAL Vulnerabilities");
      for vuln in critical {
        println!("  \x1b[35m✗ {}\x1b[0m", vuln.name);
        println!("    {}", vuln.description);
      }
    }

    if !high.is_empty() {
      Output::section("HIGH Severity Vulnerabilities");
      for vuln in high {
        println!("  \x1b[31m✗ {}\x1b[0m", vuln.name);
        println!("    {}", vuln.description);
      }
    }

    if !medium.is_empty() {
      Output::section("MEDIUM Severity Vulnerabilities");
      for vuln in medium {
        println!("  \x1b[33m● {}\x1b[0m", vuln.name);
        println!("    {}", vuln.description);
      }
    }

    if !low.is_empty() {
      Output::section("LOW Severity Vulnerabilities");
      for vuln in low {
        println!("  \x1b[36m○ {}\x1b[0m", vuln.name);
        println!("    {}", vuln.description);
      }
    }

    self.save_if_enabled(ctx, &host, &result)?;

    Ok(())
  }

  fn resume(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security resume <HOST[:PORT]>\nExample: rb tls security resume google.com",
        )?;

    let (host, port) = Self::parse_host_port(target, 443)?;
    let timeout = ctx
      .flags
      .get("timeout")
      .and_then(|v| v.parse::<u64>().ok())
      .unwrap_or(10);

    Output::header(&format!("TLS Session Resumption Test: {}:{}", host, port));

    let tester = SessionResumptionTester::with_timeout(std::time::Duration::from_secs(timeout));

    Output::spinner_start("Testing session resumption capabilities");
    let result = tester.test(&host, port);
    Output::spinner_done();

    // Session ID Resumption
    Output::section("Session ID Resumption (TLS 1.2 Classic)");
    if result.session_id_supported {
      Output::success("  Supported - Server reuses session IDs");
    } else if let Some(ref err) = result.session_id_error {
      Output::warning(&format!("  Not supported: {}", err));
    } else {
      Output::dim("  Not supported");
    }

    // Session Ticket Resumption (RFC 5077)
    Output::section("Session Tickets (RFC 5077)");
    if result.session_ticket_supported {
      Output::success("  Supported - Server issues session tickets");
      if let Some(lifetime) = result.session_ticket_lifetime {
        let hours = lifetime / 3600;
        let minutes = (lifetime % 3600) / 60;
        Output::item(
          "  Ticket Lifetime",
          &format!("{}h {}m ({} seconds)", hours, minutes, lifetime),
        );
      }
    } else if let Some(ref err) = result.session_ticket_error {
      Output::warning(&format!("  Not supported: {}", err));
    } else {
      Output::dim("  Not supported");
    }

    // TLS 1.3 PSK Resumption
    Output::section("TLS 1.3 Resumption (PSK)");
    if result.tls13_psk_supported {
      Output::success("  Supported - TLS 1.3 PSK-based resumption available");
      if result.tls13_early_data_supported {
        Output::warning("  0-RTT Early Data: Enabled (potential replay attack risk)");
      } else {
        Output::success("  0-RTT Early Data: Disabled (secure default)");
      }
    } else {
      Output::dim("  Not available (TLS 1.3 may not be supported)");
    }

    // Security Issues
    if !result.issues.is_empty() {
      Output::section(&format!("Security Issues ({})", result.issues.len()));
      for issue in &result.issues {
        let color = match issue.severity {
          ResumptionSeverity::High => "\x1b[31m",
          ResumptionSeverity::Medium => "\x1b[33m",
          ResumptionSeverity::Low => "\x1b[36m",
          ResumptionSeverity::Info => "\x1b[37m",
        };
        println!("  {}[{:?}] {}\x1b[0m", color, issue.severity, issue.title);
        println!("    {}", issue.description);
      }
    } else {
      Output::success("\nNo session resumption security issues detected");
    }

    // Summary
    Output::section("Summary");
    let resumption_count = [
      result.session_id_supported,
      result.session_ticket_supported,
      result.tls13_psk_supported,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    if resumption_count == 0 {
      Output::warning("  No session resumption methods supported");
      Output::dim("  This may impact TLS connection performance");
    } else {
      Output::success(&format!(
        "  {} resumption method(s) available",
        resumption_count
      ));
    }

    Ok(())
  }

  fn mozilla(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb tls security mozilla <HOST[:PORT]> [--profile modern|intermediate|old]\nExample: rb tls security mozilla google.com --profile modern",
        )?;

    let (host, port) = Self::parse_host_port(target, 443)?;
    let timeout = ctx
      .flags
      .get("timeout")
      .and_then(|v| v.parse::<u64>().ok())
      .unwrap_or(10);

    let profile_str = ctx
      .flags
      .get("profile")
      .map(|s| s.as_str())
      .unwrap_or("intermediate");
    let profile = match profile_str.to_lowercase().as_str() {
      "modern" => MozillaProfile::Modern,
      "intermediate" => MozillaProfile::Intermediate,
      "old" | "legacy" => MozillaProfile::Old,
      _ => {
        return Err(format!(
          "Invalid profile: {}\nValid profiles: modern, intermediate, old",
          profile_str
        ));
      }
    };

    Output::header(&format!(
      "Mozilla {} Profile Compliance: {}:{}",
      match profile {
        MozillaProfile::Modern => "Modern",
        MozillaProfile::Intermediate => "Intermediate",
        MozillaProfile::Old => "Old",
      },
      host,
      port
    ));

    // First, run TLS audit to get version and cipher info
    let auditor = TlsAuditor::new().with_timeout(std::time::Duration::from_secs(timeout));

    Output::spinner_start("Auditing TLS configuration");
    let audit_result = auditor
      .audit(&host, port)
      .map_err(|e| format!("TLS audit failed: {}", e))?;
    Output::spinner_done();

    // Extract versions and ciphers for compliance check
    let supported_versions: Vec<String> = audit_result
      .supported_versions
      .iter()
      .filter(|v| v.supported)
      .map(|v| v.version.clone())
      .collect();

    let supported_ciphers: Vec<(u16, String)> = audit_result
      .supported_ciphers
      .iter()
      .map(|c| (c.code, c.name.clone()))
      .collect();

    // Run Mozilla compliance check
    let checker = MozillaComplianceChecker::new(profile.clone());
    let result = checker.check(&supported_versions, &supported_ciphers, None);

    // Display compliance result
    Output::section("Compliance Status");
    if result.compliant {
      Output::success(&format!("  COMPLIANT - Score: {}/100", result.score));
    } else {
      Output::error(&format!("  NON-COMPLIANT - Score: {}/100", result.score));
    }

    // Display profile requirements
    Output::section("Profile Requirements");
    match profile {
      MozillaProfile::Modern => {
        Output::item("  Min TLS Version", "TLS 1.3");
        Output::item("  Cipher Suites", "TLS 1.3 AEAD ciphers only");
        Output::item("  Target Audience", "Modern clients (2019+)");
      }
      MozillaProfile::Intermediate => {
        Output::item("  Min TLS Version", "TLS 1.2");
        Output::item("  Cipher Suites", "AEAD + secure CBC ciphers");
        Output::item("  Target Audience", "General purpose servers");
      }
      MozillaProfile::Old => {
        Output::item("  Min TLS Version", "TLS 1.0");
        Output::item("  Cipher Suites", "Legacy compatibility");
        Output::item("  Target Audience", "Legacy clients (use with caution)");
      }
    }

    // Detected TLS configuration
    Output::section("Detected Configuration");
    Output::item("  TLS Versions", &supported_versions.join(", "));
    Output::item(
      "  Cipher Suites",
      &format!("{} supported", supported_ciphers.len()),
    );

    // Compliance issues
    if !result.issues.is_empty() {
      Output::section(&format!("Compliance Issues ({})", result.issues.len()));
      for issue in &result.issues {
        let color = match issue.severity {
          ComplianceSeverity::Critical => "\x1b[35m",
          ComplianceSeverity::Warning => "\x1b[33m",
          ComplianceSeverity::Info => "\x1b[37m",
        };
        println!("  {}[{:?}] {}\x1b[0m", color, issue.severity, issue.title);
        println!("    {}", issue.description);
      }
    }

    // Recommendations
    if !result.recommendations.is_empty() {
      Output::section("Recommendations");
      for rec in &result.recommendations {
        println!("  - {}", rec);
      }
    }

    // Other profile suggestions
    if !result.compliant {
      Output::section("Alternative Profiles");
      match profile {
        MozillaProfile::Modern => {
          Output::dim("  Consider testing with --profile intermediate for broader compatibility");
        }
        MozillaProfile::Intermediate => {
          Output::dim("  Try --profile modern for higher security (if client support allows)");
          Output::dim("  Or --profile old if you must support legacy clients");
        }
        MozillaProfile::Old => {
          Output::dim("  Consider upgrading to --profile intermediate when possible");
        }
      }
    }

    Ok(())
  }

  fn parse_host_port(target: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(colon_pos) = target.rfind(':') {
      let host = target[..colon_pos].to_string();
      let port_str = &target[colon_pos + 1..];
      let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("Invalid port: {}", port_str))?;
      Ok((host, port))
    } else {
      Ok((target.to_string(), default_port))
    }
  }

  fn save_if_enabled(
    &self,
    ctx: &CliContext,
    host: &str,
    result: &crate::modules::tls::auditor::TlsAuditResult,
  ) -> Result<(), String> {
    let persist_flag = if ctx.has_flag("persist") {
      Some(true)
    } else if ctx.has_flag("no-persist") {
      Some(false)
    } else {
      None
    };

    let verb = ctx.verb.as_deref().unwrap_or("audit");
    let attributes = build_partition_attributes(ctx, host, [("operation", verb)]);
    let mut pm =
      StorageService::global().persistence_for_target_with(host, persist_flag, None, attributes)?;

    if pm.is_enabled() {
      let record = self.build_tls_scan_record(host, result);
      pm.add_tls_scan(record)?;
      if let Some(path) = pm.commit()? {
        Output::success(&format!("TLS results saved to {}", path.display()));
      }
    }

    Ok(())
  }

  fn audit_json_payload(
    &self,
    host: &str,
    port: u16,
    result: &TlsAuditResult,
  ) -> crate::serde_json::Value {
    let versions: Vec<_> = result
      .supported_versions
      .iter()
      .map(|version| {
        json!({
            "version": version.version.clone(),
            "supported": version.supported,
            "error": version.error.clone()
        })
      })
      .collect();
    let ciphers: Vec<_> = result
      .supported_ciphers
      .iter()
      .map(|cipher| {
        let strength = match cipher.strength {
          CipherStrength::Secure => "secure",
          CipherStrength::Weak => "weak",
          CipherStrength::Insecure => "insecure",
          CipherStrength::NullCipher => "null",
        };
        json!({
            "name": cipher.name.clone(),
            "code": cipher.code,
            "strength": strength
        })
      })
      .collect();
    let vulnerabilities: Vec<_> = result
      .vulnerabilities
      .iter()
      .map(|vuln| {
        json!({
            "name": vuln.name.clone(),
            "severity": vuln.severity.to_string(),
            "description": vuln.description.clone()
        })
      })
      .collect();
    let certificate_chain: Vec<_> = result
      .certificate_chain
      .iter()
      .map(|cert| {
        json!({
            "subject": cert.subject.clone(),
            "issuer": cert.issuer.clone(),
            "serial_number": cert.serial_number.clone(),
            "signature_algorithm": cert.signature_algorithm.clone(),
            "public_key_algorithm": cert.public_key_algorithm.clone(),
            "version": cert.version,
            "valid_from": cert.valid_from.clone(),
            "valid_until": cert.valid_until.clone(),
            "self_signed": cert.is_self_signed,
            "sans": cert.san.clone()
        })
      })
      .collect();

    json!({
        "target": json!({
            "host": host,
            "port": port
        }),
        "handshake": json!({
            "negotiated_version": result.negotiated_version.clone(),
            "negotiated_cipher": result.negotiated_cipher.clone(),
            "negotiated_cipher_code": result.negotiated_cipher_code,
            "ja3": result.ja3.clone(),
            "ja3_raw": result.ja3_raw.clone(),
            "ja3s": result.ja3s.clone(),
            "ja3s_raw": result.ja3s_raw.clone(),
            "certificate_valid": result.certificate_valid,
            "peer_fingerprints": result.peer_fingerprints.clone(),
            "certificate_chain_pem": result.certificate_chain_pem.clone()
        }),
        "versions": versions,
        "ciphers": ciphers,
        "vulnerabilities": vulnerabilities,
        "certificate_chain": certificate_chain
    })
  }

  fn build_tls_scan_record(
    &self,
    host: &str,
    result: &crate::modules::tls::auditor::TlsAuditResult,
  ) -> TlsScanRecord {
    let timestamp = Self::current_timestamp();

    let versions = result
      .supported_versions
      .iter()
      .map(|version| TlsVersionRecord {
        version: version.version.clone(),
        supported: version.supported,
        error: version.error.clone(),
      })
      .collect();

    let ciphers = result
      .supported_ciphers
      .iter()
      .map(|cipher| TlsCipherRecord {
        name: cipher.name.clone(),
        code: cipher.code,
        strength: Self::convert_cipher_strength(&cipher.strength),
      })
      .collect();

    let vulnerabilities = result
      .vulnerabilities
      .iter()
      .map(|vuln| TlsVulnerabilityRecord {
        name: vuln.name.clone(),
        severity: Self::convert_severity(&vuln.severity),
        description: vuln.description.clone(),
      })
      .collect();

    let certificate_chain = result
      .certificate_chain
      .iter()
      .map(|cert| self.convert_certificate(host, cert, timestamp))
      .collect();

    TlsScanRecord {
      host: host.to_string(),
      port: result.port,
      timestamp,
      negotiated_version: result.negotiated_version.clone(),
      negotiated_cipher: result.negotiated_cipher.clone(),
      negotiated_cipher_code: result.negotiated_cipher_code,
      negotiated_cipher_strength: result
        .negotiated_cipher_strength
        .as_ref()
        .map(Self::convert_cipher_strength)
        .unwrap_or(TlsCipherStrength::Medium),
      certificate_valid: result.certificate_valid,
      versions,
      ciphers,
      vulnerabilities,
      certificate_chain,
      ja3: result.ja3.clone(),
      ja3s: result.ja3s.clone(),
      ja3_raw: result.ja3_raw.clone(),
      ja3s_raw: result.ja3s_raw.clone(),
      peer_fingerprints: result.peer_fingerprints.clone(),
      certificate_chain_pem: result.certificate_chain_pem.clone(),
    }
  }

  fn convert_certificate(
    &self,
    host: &str,
    cert: &CertificateInfo,
    timestamp: u32,
  ) -> TlsCertRecord {
    TlsCertRecord {
      domain: host.to_string(),
      issuer: cert.issuer.clone(),
      subject: cert.subject.clone(),
      serial_number: cert.serial_number.clone(),
      signature_algorithm: cert.signature_algorithm.clone(),
      public_key_algorithm: cert.public_key_algorithm.clone(),
      version: cert.version,
      not_before: Self::x509_timestamp(&cert.valid_from),
      not_after: Self::x509_timestamp(&cert.valid_until),
      sans: cert.san.clone(),
      self_signed: cert.is_self_signed,
      timestamp,
    }
  }

  fn convert_cipher_strength(strength: &CipherStrength) -> TlsCipherStrength {
    match strength {
      CipherStrength::Secure => TlsCipherStrength::Strong,
      CipherStrength::Weak => TlsCipherStrength::Medium,
      CipherStrength::Insecure | CipherStrength::NullCipher => TlsCipherStrength::Weak,
    }
  }

  fn convert_severity(severity: &Severity) -> TlsSeverity {
    match severity {
      Severity::Info => TlsSeverity::Low, // Info maps to Low for TLS context
      Severity::Low => TlsSeverity::Low,
      Severity::Medium => TlsSeverity::Medium,
      Severity::High => TlsSeverity::High,
      Severity::Critical => TlsSeverity::Critical,
    }
  }

  fn x509_timestamp(value: &str) -> u32 {
    parse_x509_time(value)
      .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
      .map(|duration| duration.as_secs() as u32)
      .unwrap_or(0)
  }

  fn current_timestamp() -> u32 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_else(|_| std::time::Duration::from_secs(0))
      .as_secs() as u32
  }

  fn format_timestamp(epoch: u32) -> String {
    if epoch == 0 {
      "unknown".to_string()
    } else {
      format!("{}", epoch)
    }
  }

  fn render_cipher_strength(strength: TlsCipherStrength) -> &'static str {
    match strength {
      TlsCipherStrength::Weak => "WEAK",
      TlsCipherStrength::Medium => "MEDIUM",
      TlsCipherStrength::Strong => "STRONG",
    }
  }

  fn render_severity(severity: TlsSeverity) -> &'static str {
    match severity {
      TlsSeverity::Low => "LOW",
      TlsSeverity::Medium => "MEDIUM",
      TlsSeverity::High => "HIGH",
      TlsSeverity::Critical => "CRITICAL",
    }
  }

  // ============================================================================
  // RESTful Commands - Query stored TLS data from .rdb files
  // ============================================================================
}
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
