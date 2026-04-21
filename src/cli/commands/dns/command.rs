/// DNS/record command - DNS reconnaissance and enumeration
use crate::cli::commands::{
  annotate_query_partition, build_partition_attributes, print_help, Command, Flag, Route,
};
use crate::cli::{output::Output, render, validator::Validator, CliContext};
use crate::config;
use crate::intelligence::banner_analysis::analyze_dns_version;
use crate::json;
use crate::modules::dns::dnssec::DnssecStatus;
use crate::protocols::dns::{DnsClient, DnsRecordType};
use crate::protocols::doh::{DohClient, PropagationStatus, DOH_PROVIDERS};
use crate::storage::client::ActionRecorder;
use crate::storage::records::DnsRecordType as StorageDnsRecordType;
use crate::storage::segments::convert::DnsResults;
use crate::storage::service::StorageService;
use crate::wordlists::WordlistManager;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct DnsCommand;

impl Command for DnsCommand {
  fn domain(&self) -> &str {
    "dns"
  }

  fn resource(&self) -> &str {
    "record"
  }

  fn description(&self) -> &str {
    "DNS reconnaissance and enumeration"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
      .with_aliases(crate::cli::aliases::resource_aliases_for(self.resource()))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let aliases = crate::cli::aliases::verb_aliases_for(verb);
    match verb {
      "lookup" | "all" | "propagation" | "email" | "dnssec" => {
        crate::cli::schema::RouteMetadata::new()
          .with_aliases(aliases)
          .with_machine_output(
            crate::cli::schema::MachineOutputMetadata::new()
              .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
              .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
              .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
          )
      }
      _ => crate::cli::schema::RouteMetadata::new()
        .with_aliases(aliases)
        .with_machine_output(self.metadata().machine_output),
    }
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      // Action verbs - execute DNS queries
      Route {
        verb: "lookup",
        summary: "Query DNS records for a domain",
        usage: "rb dns record lookup <domain> [--type A]",
      },
      Route {
        verb: "all",
        summary: "Query all DNS record types in parallel (A, AAAA, CNAME, MX, NS, TXT, SOA)",
        usage: "rb dns record all <domain>",
      },
      Route {
        verb: "resolve",
        summary: "Resolve a domain name to IP addresses",
        usage: "rb dns record resolve <domain>",
      },
      Route {
        verb: "reverse",
        summary: "Perform a reverse DNS lookup on an IP",
        usage: "rb dns record reverse <ip>",
      },
      Route {
        verb: "bruteforce",
        summary: "Enumerate subdomains using wordlists",
        usage: "rb dns record bruteforce <domain> --wordlist WORDS",
      },
      Route {
        verb: "propagation",
        summary: "Check DNS propagation across multiple providers",
        usage: "rb dns record propagation <domain> [--type A]",
      },
      Route {
        verb: "email",
        summary: "Check email security records (SPF, DKIM, DMARC)",
        usage: "rb dns record email <domain>",
      },
      Route {
        verb: "dnssec",
        summary: "Check DNSSEC validation status",
        usage: "rb dns record dnssec <domain>",
      },
      // RESTful verbs - query stored data
      Route {
        verb: "list",
        summary: "List all DNS records for a domain from database",
        usage: "rb dns record list <domain> [--db <file>]",
      },
      Route {
        verb: "get",
        summary: "Get specific DNS record type from database",
        usage: "rb dns record get <domain>:<type> [--db <file>]",
      },
      Route {
        verb: "describe",
        summary: "Get detailed DNS information from database",
        usage: "rb dns record describe <domain> [--db <file>]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("type", "Record type (A|AAAA|MX|NS|TXT|CNAME|SOA|PTR|ANY)")
        .with_short('t')
        .with_default("A"),
      Flag::new("server", "DNS server to use")
        .with_short('s')
        .with_default("8.8.8.8"),
      Flag::new("wordlist", "Wordlist for brute force").with_short('w'),
      Flag::new("threads", "Number of threads").with_default("50"),
      Flag::new("save", "Force save to database (overrides config)"),
      Flag::new("no-save", "Disable auto-save for this command"),
      Flag::new("persist", "Alias for --save"),
      Flag::new(
        "from-db",
        "describe/get: read from an existing DB instead of collecting live",
      ),
      Flag::new("cache-only", "Alias for --from-db"),
      Flag::new(
        "from-json",
        "describe/get: ingest a pre-collected payload (path or '-' for stdin)",
      ),
      Flag::new(
        "db-password",
        "Database encryption password (overrides keyring)",
      ),
      Flag::new(
        "intel",
        "Perform DNS server fingerprinting using VERSION.BIND query",
      ),
      Flag::new(
        "db",
        "Database file path for RESTful queries (default: auto-detect)",
      )
      .with_short('d'),
      // Global action flags for unified intelligence layer
      Flag::new("trace", "Enable detailed attempt tracing"),
      Flag::new("no-store", "Disable automatic action storage"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Lookup A records",
        "rb dns record lookup google.com --type A",
      ),
      (
        "Lookup and save to encrypted database",
        "rb dns record lookup example.com --save",
      ),
      (
        "Get all record types at once",
        "rb dns record all google.com",
      ),
      (
        "Lookup MX records",
        "rb dns record lookup example.com --type MX",
      ),
      (
        "Use different DNS server",
        "rb dns record lookup example.com --server 1.1.1.1",
      ),
      ("Quick IP resolution", "rb dns record resolve github.com"),
      (
        "Subdomain brute force",
        "rb dns record bruteforce example.com --wordlist common",
      ),
      (
        "DNS server fingerprinting",
        "rb dns record lookup example.com --intel",
      ),
      (
        "Check DNS propagation",
        "rb dns record propagation example.com --type A",
      ),
      ("Check email security", "rb dns record email example.com"),
      (
        "Check DNSSEC validation status",
        "rb dns record dnssec example.com",
      ),
      // RESTful examples
      (
        "List all saved DNS records",
        "rb dns record list google.com",
      ),
      (
        "Get specific record type from database",
        "rb dns record get google.com:A",
      ),
      ("Describe all DNS data", "rb dns record describe google.com"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      // Action verbs
      "lookup" => self.lookup(ctx),
      "all" => self.lookup_all(ctx),
      "resolve" => self.resolve(ctx),
      "reverse" => self.reverse(ctx),
      "bruteforce" => self.bruteforce(ctx),
      "propagation" => self.propagation(ctx),
      "email" => self.email_security(ctx),
      "dnssec" => self.dnssec(ctx),
      // RESTful verbs
      "list" => self.list_records(ctx),
      "get" => self.get_record(ctx),
      "describe" => self.describe_records(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        println!(
          "{}",
          Validator::suggest_command(
            verb,
            &[
              "lookup",
              "all",
              "resolve",
              "reverse",
              "bruteforce",
              "propagation",
              "email",
              "dnssec",
              "list",
              "get",
              "describe"
            ]
          )
        );
        Err("Invalid verb".to_string())
      }
    }
  }

}

/// Subprocess-invoke `rb dns record lookup <domain> --type <T> -o json` and
/// return the raw stdout (or a serialized error envelope) so describe bundles
/// can aggregate per-type payloads into a single JSON document.
fn capture_dns_lookup_json(ctx: &CliContext, domain: &str, record_type: &str) -> String {
  use std::process::Command;
  let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("rb"));
  let mut cmd = Command::new(&exe);
  cmd.args([
    "dns",
    "record",
    "lookup",
    domain,
    "--type",
    record_type,
    "-o",
    "json",
  ]);
  if let Some(server) = ctx.get_flag("server") {
    cmd.args(["--server", &server]);
  }
  match cmd.output() {
    Ok(o) if o.status.success() => {
      let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
      if stdout.is_empty() {
        "null".to_string()
      } else if stdout.starts_with('{') || stdout.starts_with('[') {
        stdout
      } else {
        format!("{{\"raw\":{}}}", json_escape(&stdout))
      }
    }
    Ok(o) => {
      let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
      format!(
        "{{\"error\":{},\"exit_code\":{}}}",
        json_escape(&stderr),
        o.status.code().unwrap_or(-1)
      )
    }
    Err(e) => format!("{{\"error\":{}}}", json_escape(&e.to_string())),
  }
}

fn json_escape(s: &str) -> String {
  let mut out = String::with_capacity(s.len() + 2);
  out.push('"');
  for c in s.chars() {
    match c {
      '"' => out.push_str("\\\""),
      '\\' => out.push_str("\\\\"),
      '\n' => out.push_str("\\n"),
      '\r' => out.push_str("\\r"),
      '\t' => out.push_str("\\t"),
      c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
      c => out.push(c),
    }
  }
  out.push('"');
  out
}

impl DnsCommand {
  fn lookup(&self, ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb dns record lookup <DOMAIN>\nExample: rb dns record lookup example.com",
        )?;

    Validator::validate_domain(domain)?;

    // Clone domain for persistence
    let domain_owned = domain.to_string();

    let record_type_str = ctx.get_flag_or("type", "A");
    let record_type = Self::parse_record_type(&record_type_str)?;

    let cfg = config::get();
    let server = ctx
      .get_flag("server")
      .unwrap_or_else(|| cfg.network.dns_resolver.clone());
    let format = ctx.get_output_format();

    let client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_start("Querying DNS");
    }

    let answers = client
      .query(domain, record_type)
      .map_err(|e| format!("DNS query failed: {}", e))?;

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_done();
    }

    // Database persistence using unified PersistenceConfig
    let persistence_config = ctx.get_persistence_config();
    let storage = StorageService::global();
    let attributes = build_partition_attributes(
      ctx,
      &domain_owned,
      [
        ("operation", "lookup"),
        ("record_type", record_type_str.as_str()),
        ("resolver", server.as_str()),
      ],
    );
    let mut pm = storage.persistence_with_config(&domain_owned, persistence_config, attributes)?;

    // Save DNS records to database
    if pm.is_enabled() {
      for answer in &answers {
        let value = answer.display_value();
        if let Err(e) = pm.add_dns_record(domain, answer.record_type, answer.ttl, &value) {
          eprintln!("Warning: Failed to save DNS record to database: {}", e);
        }
      }
    }

    let records: Vec<_> = answers
      .iter()
      .map(|answer| {
        json!({
            "type": answer.type_string(),
            "value": answer.display_value(),
            "ttl": answer.ttl
        })
      })
      .collect();
    let payload = json!({
        "domain": domain,
        "record_type": record_type_str,
        "server": server,
        "count": answers.len(),
        "records": records
    });

    if render::render_machine_output_with_yaml(ctx, "rb dns record lookup", &payload, || {
      println!("domain: {}", domain);
      println!("record_type: {}", record_type_str);
      println!("server: {}", server);
      println!("count: {}", answers.len());
      println!("records:");
      for answer in &answers {
        println!("  - type: {}", answer.type_string());
        println!("    value: \"{}\"", answer.display_value());
        println!("    ttl: {}", answer.ttl);
      }
      Ok(())
    })? {
      pm.commit()?;
      return Ok(());
    }

    // Human output
    if answers.is_empty() {
      Output::warning("No records found");

      // Commit database even if no results
      if let Some(db_path) = pm.commit()? {
        Output::success(&format!("Database saved to {}", db_path.display()));
      }
      return Ok(());
    }

    Output::header(&format!(
      "DNS: {} ({}) @ {}",
      domain, record_type_str, server
    ));
    Output::summary_line(&[("Records", &answers.len().to_string())]);

    for answer in &answers {
      let record_type = answer.type_string();
      let value = answer.display_value();
      let ttl_str = format!("{}s", answer.ttl);

      println!("  {} {} \x1b[2m{}\x1b[0m", record_type, value, ttl_str);
    }

    // DNS server intelligence gathering
    if ctx.has_flag("intel") {
      println!();
      Output::header("DNS Server Intelligence");

      // Query VERSION.BIND using TXT record
      // This is a special query supported by most DNS servers to reveal version info
      Output::spinner_start("Fingerprinting DNS server");

      // Re-use existing client configuration
      let cfg = config::get();
      let intel_client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

      // VERSION.BIND is queried as a TXT record
      // Domain: "version.bind" or "version.server"
      match intel_client.query("version.bind", DnsRecordType::TXT) {
        Ok(txt_records) => {
          Output::spinner_done();

          if !txt_records.is_empty() {
            // Extract TXT data from DNS answers and concatenate
            let mut txt_strings = Vec::new();
            for answer in &txt_records {
              if let crate::protocols::dns::DnsRdata::TXT(strings) = &answer.data {
                txt_strings.extend(strings.clone());
              }
            }
            let version_response = txt_strings.join(" ");

            // Analyze the version string
            let banner_info = analyze_dns_version(&version_response);

            // Display vendor
            if let Some(vendor) = &banner_info.vendor {
              Output::item("Vendor", vendor);
            }

            // Display version
            if let Some(version) = &banner_info.version {
              Output::item("Version", version);
            }

            // Display OS hints
            if !banner_info.os_hints.is_empty() {
              Output::item("Operating System", &banner_info.os_hints.join(", "));
            }

            // Display if banner was modified
            if banner_info.is_modified {
              Output::warning("⚠ Banner appears to be modified/customized");
            }

            // Display custom fields (e.g., build info)
            for (key, value) in &banner_info.custom_fields {
              let label = key
                .chars()
                .enumerate()
                .map(|(i, c)| {
                  if i == 0 {
                    c.to_uppercase().to_string()
                  } else {
                    c.to_string()
                  }
                })
                .collect::<String>();
              Output::item(&label, value);
            }

            // Display raw banner if modified
            if banner_info.is_modified {
              Output::item("Raw Response", &banner_info.raw_banner);
            }
          } else {
            Output::warning("Server responded but returned no version information");
          }
        }
        Err(e) => {
          Output::spinner_done();
          Output::warning(&format!("Could not fingerprint DNS server: {}", e));
          Output::info("Some DNS servers hide version information for security");
        }
      }
    }

    // Commit database
    if let Some(db_path) = pm.commit()? {
      println!();
      Output::success(&format!("✓ Results saved to {}", db_path.display()));
    }

    // Auto-persist to unified intelligence layer
    let action_config = ctx.get_action_config();
    if action_config.should_store() && !answers.is_empty() {
      let mut recorder = ActionRecorder::new("dns-record-lookup", action_config)?;

      // Collect all records into single DnsResults
      let records: Vec<String> = answers.iter().map(|a| a.display_value()).collect();
      let ttl = answers.first().map(|a| a.ttl);

      let dns_result = DnsResults {
        domain: domain.to_string(),
        record_type: record_type_str.clone(),
        records,
        ttl,
        error: None,
      };
      recorder.record(dns_result)?;

      let count = recorder.commit()?;
      if count > 0 && format == crate::cli::format::OutputFormat::Human {
        Output::info(&format!("Action recorded ({} entries)", count));
      }
    }

  Ok(())
  }

  fn lookup_all(&self, ctx: &CliContext) -> Result<(), String> {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let domain = ctx.target.as_ref().ok_or(
      "Missing domain.\nUsage: rb dns record all <DOMAIN>\nExample: rb dns record all google.com",
    )?;

    Validator::validate_domain(domain)?;

    let cfg = config::get();
    let server = ctx
      .get_flag("server")
      .unwrap_or_else(|| cfg.network.dns_resolver.clone());
    let format = ctx.get_output_format();

    // All record types to query
    let record_types = vec![
      DnsRecordType::A,
      DnsRecordType::AAAA,
      DnsRecordType::CNAME,
      DnsRecordType::MX,
      DnsRecordType::NS,
      DnsRecordType::TXT,
      DnsRecordType::SOA,
    ];
    let total_types = record_types.len();

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_start(&format!(
        "Querying {} record types in parallel",
        total_types
      ));
    }

    // Parallel queries
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for record_type in record_types.iter().copied() {
      let domain = domain.clone();
      let server = server.clone();
      let results = Arc::clone(&results);
      let timeout = cfg.network.dns_timeout_ms;

      let handle = thread::spawn(move || {
        let client = DnsClient::new(&server).with_timeout(timeout);

        if let Ok(answers) = client.query(&domain, record_type) {
          if !answers.is_empty() {
            let mut results = results.lock().unwrap();
            results.push((record_type, answers));
          }
        }
      });

      handles.push(handle);
    }

    // Wait for all threads
    let mut completed = 0usize;
    for handle in handles {
      let _ = handle.join();
      completed += 1;
      if format == crate::cli::format::OutputFormat::Human {
        Output::spinner_status(&format!(
          "Fetched {}/{} record types",
          completed, total_types
        ));
      }
    }

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_done();
    }

    // Collect results
    let all_results = match Arc::try_unwrap(results) {
      Ok(mutex) => mutex.into_inner().unwrap(),
      Err(arc) => arc.lock().unwrap().clone(),
    };

    let record_types: Vec<_> = all_results
      .iter()
      .map(|(record_type, answers)| {
        let records: Vec<_> = answers
          .iter()
          .map(|answer| {
            json!({
                "value": answer.display_value(),
                "ttl": answer.ttl
            })
          })
          .collect();
        json!({
            "type": Self::record_type_to_string(*record_type),
            "count": answers.len(),
            "records": records
        })
      })
      .collect();
    let total_records: usize = all_results.iter().map(|(_, answers)| answers.len()).sum();
    let payload = json!({
      "domain": domain,
      "server": server,
      "record_type_count": all_results.len(),
      "total_records": total_records,
      "record_types": record_types
    });
    if render::render_machine_output_with_yaml(ctx, "rb dns record all", &payload, || {
      println!("domain: {}", domain);
      println!("server: {}", server);
      println!("record_type_count: {}", all_results.len());
      println!("total_records: {}", total_records);
      println!("record_types:");

      for (record_type, answers) in &all_results {
        println!("  - type: {}", Self::record_type_to_string(*record_type));
        println!("    count: {}", answers.len());
        println!("    records:");
        for answer in answers {
          println!("      - value: \"{}\"", answer.display_value());
          println!("        ttl: {}", answer.ttl);
        }
      }
      Ok(())
    })? {
      return Ok(());
    }

    if all_results.is_empty() {
      Output::warning("No DNS records found");
      return Ok(());
    }

    // Human output
    Output::header(&format!("DNS: {} (ALL TYPES) @ {}", domain, server));

    Output::summary_line(&[
      ("Record Types", &all_results.len().to_string()),
      ("Total Records", &total_records.to_string()),
    ]);
    println!();

    // Group by record type
    for (record_type, answers) in &all_results {
      let type_str = Self::record_type_to_string(*record_type);
      println!("  \x1b[1m{}\x1b[0m ({} records)", type_str, answers.len());

      for answer in answers {
        let value = answer.display_value();
        let ttl_str = format!("{}s", answer.ttl);
        println!("    {} \x1b[2m{}\x1b[0m", value, ttl_str);
      }
      println!();
    }

    Ok(())
  }

  fn resolve(&self, ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb dns record resolve <DOMAIN>\nExample: rb dns record resolve github.com",
        )?;

    Validator::validate_domain(domain)?;

    let cfg = config::get();
    let server = ctx
      .get_flag("server")
      .unwrap_or_else(|| cfg.network.dns_resolver.clone());
    let client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

    Output::spinner_start(&format!("Resolving {}", domain));
    let answers = client
      .query(domain, DnsRecordType::A)
      .map_err(|e| format!("Resolution failed: {}", e))?;
    Output::spinner_done();

    let mut found = false;
    for answer in answers {
      if let Some(ip) = answer.as_ip() {
        Output::success(&format!("{} → {}", domain, ip));
        found = true;
      }
    }

    if !found {
      Output::error(&format!("{} does not resolve to any IP", domain));
    }

    Ok(())
  }

  fn reverse(&self, ctx: &CliContext) -> Result<(), String> {
    let ip = ctx.target.as_ref().ok_or(
            "Missing IP address.\nUsage: rb dns record reverse <IP>\nExample: rb dns record reverse 8.8.8.8",
        )?;

    let ip_addr = Validator::validate_ip(ip)?;
    let ptr_name = Self::build_ptr_name(ip_addr);

    let cfg = config::get();
    let server = ctx
      .get_flag("server")
      .unwrap_or_else(|| cfg.network.dns_resolver.clone());
    let client = DnsClient::new(&server).with_timeout(cfg.network.dns_timeout_ms);

    Output::spinner_start(&format!("Querying PTR for {}", ip));
    let answers = client
      .query(&ptr_name, DnsRecordType::PTR)
      .map_err(|e| format!("Reverse lookup failed: {}", e))?;
    Output::spinner_done();

    if answers.is_empty() {
      Output::warning("No PTR records found");
      return Ok(());
    }

    Output::subheader(&format!("PTR records for {}:", ip));
    println!();
    Output::table_header(&["HOST", "TTL"]);
    for answer in answers {
      let value = answer.display_value();
      let ttl = answer.ttl.to_string();
      Output::table_row(&[value.as_str(), ttl.as_str()]);
    }

    println!();
    Output::success("Reverse lookup completed");

    Ok(())
  }

  fn bruteforce(&self, ctx: &CliContext) -> Result<(), String> {
    let domain = ctx
      .target
      .as_ref()
      .ok_or("Missing domain.\nUsage: rb dns record bruteforce <DOMAIN> --wordlist WORDS")?;

    Validator::validate_domain(domain)?;

    // Get wordlist
    let default_wordlist = "subdomains-top100".to_string();
    let wordlist_name = ctx.get_flag("wordlist").unwrap_or(default_wordlist);

    let wordlist_manager = WordlistManager::new()?;
    let wordlist = wordlist_manager.get(&wordlist_name)?;

    Output::header(&format!("Subdomain Brute Force: {}", domain));
    Output::item("Wordlist", &wordlist_name);
    Output::item("Entries", &wordlist.len().to_string());
    println!();

    // DNS server
    let default_server = "8.8.8.8".to_string();
    let dns_server = ctx.get_flag("server").unwrap_or(default_server);

    // Thread count
    let thread_count = ctx
      .get_flag("threads")
      .and_then(|t| t.parse::<usize>().ok())
      .unwrap_or(50);

    Output::spinner_start(&format!(
      "Scanning {} subdomains with {} threads",
      wordlist.len(),
      thread_count
    ));

    // Shared results container
    let found_subdomains = Arc::new(Mutex::new(Vec::new()));
    let wordlist = Arc::new(wordlist);

    // Create work queue
    let work_index = Arc::new(Mutex::new(0));

    // Spawn worker threads
    let mut handles = vec![];
    for _ in 0..thread_count {
      let wordlist_clone = Arc::clone(&wordlist);
      let found_clone = Arc::clone(&found_subdomains);
      let work_clone = Arc::clone(&work_index);
      let domain_clone = domain.to_string();
      let dns_server_clone = dns_server.clone();

      let handle = thread::spawn(move || {
        let client = DnsClient::new(&dns_server_clone);

        loop {
          // Get next work item
          let index = {
            let mut idx = work_clone.lock().unwrap();
            if *idx >= wordlist_clone.len() {
              break;
            }
            let current = *idx;
            *idx += 1;
            current
          };

          let subdomain_part = &wordlist_clone[index];
          let full_subdomain = format!("{}.{}", subdomain_part, domain_clone);

          // Try to resolve
          if let Ok(response) = client.query(&full_subdomain, DnsRecordType::A) {
            if !response.is_empty() {
              // Extract IPs
              let ips: Vec<String> = response
                .iter()
                .filter_map(|answer| answer.as_ip())
                .collect();

              if !ips.is_empty() {
                found_clone.lock().unwrap().push((full_subdomain, ips));
              }
            }
          }
        }
      });

      handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
      let _ = handle.join();
    }

    Output::spinner_done();

    // Display results
    let results = found_subdomains.lock().unwrap();

    if results.is_empty() {
      Output::warning("No subdomains found");
      return Ok(());
    }

    Output::section(&format!("Found {} subdomains", results.len()));
    println!();

    for (subdomain, ips) in results.iter() {
      Output::success(subdomain);
      for ip in ips {
        Output::dim(&format!("  → {}", ip));
      }
    }

    // Database persistence using unified PersistenceConfig
    let persistence_config = ctx.get_persistence_config();
    let attributes = build_partition_attributes(
      ctx,
      domain,
      [
        ("operation", "bruteforce"),
        ("wordlist", wordlist_name.as_str()),
      ],
    );
    let mut pm =
      StorageService::global().persistence_with_config(domain, persistence_config, attributes)?;

    if pm.is_enabled() {
      for (subdomain, ips) in results.iter() {
        let ip_addrs: Vec<IpAddr> = ips
          .iter()
          .filter_map(|ip_str| ip_str.parse::<IpAddr>().ok())
          .collect();

        if let Err(e) = pm.add_subdomain(domain, subdomain, 0, &ip_addrs) {
          eprintln!("Warning: Failed to save subdomain to database: {}", e);
        }
      }

      Output::success(&format!(
        "✓ Saved {} subdomains to {}.rdb",
        results.len(),
        domain
      ));
    }

    println!();
    Output::success(&format!(
      "Scan complete: {}/{} found",
      results.len(),
      wordlist.len()
    ));

    Ok(())
  }

  fn propagation(&self, ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or(
            "Missing domain.\nUsage: rb dns record propagation <DOMAIN>\nExample: rb dns record propagation example.com",
        )?;

    Validator::validate_domain(domain)?;

    let record_type_str = ctx.get_flag_or("type", "A");
    let record_type = Self::parse_record_type(&record_type_str)?;
    let format = ctx.get_output_format();

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_start(&format!(
        "Checking DNS propagation across {} providers",
        DOH_PROVIDERS.len()
      ));
    }

    let client = DohClient::new();
    let result = client.check_propagation(domain, record_type);

    if format == crate::cli::format::OutputFormat::Human {
      Output::spinner_done();
    }

    let providers: Vec<_> = result
      .results
      .iter()
      .map(|provider_result| {
        let status = match provider_result.status {
          PropagationStatus::Success => "success",
          PropagationStatus::NoRecords => "no_records",
          PropagationStatus::Error => "error",
        };
        json!({
            "provider": provider_result.provider.clone(),
            "status": status,
            "values": provider_result.values.clone(),
            "ttl": provider_result.ttl
        })
      })
      .collect();
    let payload = json!({
      "domain": domain,
      "record_type": record_type_str,
      "is_propagated": result.is_propagated,
      "consensus_values": result.consensus_values.clone(),
      "provider_count": result.results.len(),
      "providers": providers
    });
    if render::render_machine_output_with_yaml(ctx, "rb dns record propagation", &payload, || {
      println!("domain: {}", domain);
      println!("record_type: {}", record_type_str);
      println!("is_propagated: {}", result.is_propagated);
      println!("provider_count: {}", result.results.len());
      println!("consensus_values:");
      for value in &result.consensus_values {
        println!("  - \"{}\"", value);
      }
      println!("providers:");
      for pr in &result.results {
        let status_str = match pr.status {
          PropagationStatus::Success => "success",
          PropagationStatus::NoRecords => "no_records",
          PropagationStatus::Error => "error",
        };
        println!("  - provider: {}", pr.provider);
        println!("    status: {}", status_str);
        println!("    values:");
        for v in &pr.values {
          println!("      - \"{}\"", v);
        }
        if let Some(ttl) = pr.ttl {
          println!("    ttl: {}", ttl);
        } else {
          println!("    ttl: null");
        }
      }
      Ok(())
    })? {
      return Ok(());
    }

    // Human output
    Output::header(&format!(
      "DNS Propagation: {} ({})",
      domain, record_type_str
    ));

    // Status summary
    let success_count = result
      .results
      .iter()
      .filter(|r| r.status == PropagationStatus::Success)
      .count();
    let total_count = result.results.len();

    Output::summary_line(&[
      ("Providers", &total_count.to_string()),
      ("Responding", &success_count.to_string()),
      (
        "Status",
        if result.is_propagated {
          "Propagated"
        } else {
          "Propagating"
        },
      ),
    ]);
    println!();

    // Provider results table
    println!(
      "  {:<12} {:<12} {:<40} TTL",
      "PROVIDER", "STATUS", "VALUE(S)"
    );
    println!("  {}", "─".repeat(76));

    for pr in &result.results {
      let status_display = match pr.status {
        PropagationStatus::Success => "\x1b[32m✓ OK\x1b[0m",
        PropagationStatus::NoRecords => "\x1b[33m- EMPTY\x1b[0m",
        PropagationStatus::Error => "\x1b[31m✗ ERROR\x1b[0m",
      };

      let values_str = if pr.values.is_empty() {
        "-".to_string()
      } else {
        pr.values.join(", ")
      };

      let ttl_str = pr
        .ttl
        .map(|t| format!("{}s", t))
        .unwrap_or_else(|| "-".to_string());

      // Truncate values if too long
      let values_display = if values_str.len() > 38 {
        format!("{}...", &values_str[..35])
      } else {
        values_str
      };

      println!(
        "  {:<12} {:<20} {:<40} {}",
        pr.provider, status_display, values_display, ttl_str
      );
    }

    println!();

    // Consensus values
    if !result.consensus_values.is_empty() {
      Output::section("Consensus Values");
      for value in &result.consensus_values {
        println!("  \x1b[1m{}\x1b[0m", value);
      }
      println!();
    }

    // Final status
    if result.is_propagated {
      Output::success("DNS propagation complete - all providers agree");
    } else {
      Output::warning("DNS propagation in progress - values may differ across providers");
    }

    Ok(())
  }
}
