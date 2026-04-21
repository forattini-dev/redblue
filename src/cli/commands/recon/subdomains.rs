//! Subdomain enumeration commands

use super::map_subdomain_source;
use crate::cli::commands::build_partition_attributes;
use crate::cli::output::Output;
use crate::cli::render;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::modules::recon::dnsdumpster::DnsDumpsterClient;
use crate::modules::recon::massdns::{common_subdomains, MassDnsScanner};
use crate::modules::recon::subdomain::{
  load_wordlist_from_file, EnumerationSource, SubdomainEnumerator, SubdomainResult,
};
use crate::serde_json::Value;
use crate::storage::service::StorageService;
use crate::utils::json::JsonValue;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

pub fn subdomains(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx
    .target
    .as_ref()
    .ok_or("Missing domain.\nUsage: rb recon domain subdomains <DOMAIN>")?;

  Validator::validate_domain(domain)?;

  let format = ctx.get_output_format();

  // Create enumerator
  let mut enumerator = SubdomainEnumerator::new(domain);

  // Apply flags
  if let Some(threads_str) = ctx.get_flag("threads") {
    let threads: usize = threads_str
      .parse()
      .map_err(|_| format!("Invalid threads value: {}", threads_str))?;
    enumerator = enumerator.with_threads(threads);
  }

  if let Some(wordlist_path) = ctx.get_flag("wordlist") {
    let wordlist = load_wordlist_from_file(&wordlist_path)?;
    enumerator = enumerator.with_wordlist(wordlist);
  }

  // Wildcard policy: default = filter (reject hits inside the wildcard pool).
  // Opt out with --include-wildcards (returns every hit, each marked with
  // wildcard_suspect: true/false). Legacy --filter-wildcards flag is kept as
  // an explicit opt-in alias that forces filtering on.
  let include_wildcards = ctx.has_flag("include-wildcards");
  let legacy_filter_request = ctx.has_flag("filter-wildcards");
  let filter_wildcards = legacy_filter_request || !include_wildcards;
  enumerator = enumerator.with_wildcard_filtering(filter_wildcards);

  let passive_only = ctx.has_flag("passive");

  // Run enumeration
  let results = if passive_only {
    enumerator.enumerate_ct_logs()?
  } else {
    enumerator.enumerate_all()?
  };

  let validate_dns = ctx.has_flag("resolve") || ctx.has_flag("validate");
  if validate_dns {
    eprintln!("🔎 Validating discovered subdomains via live DNS (A/AAAA)...");
  }

  let (confirmed_results, candidate_results) = if validate_dns {
    let confirmed = enumerator.validate_results(results.clone());
    partition_confirmed_candidates(&results, &confirmed)
  } else {
    split_results_by_resolution(&results)
  };

  let display_results = if validate_dns {
    confirmed_results.clone()
  } else {
    results.clone()
  };

  // Wildcard metadata for the payload. `detect_wildcard_ips` ran inside the
  // enumeration step; we now publish the pool + how many hits sat inside it.
  let wildcard_pool = enumerator.wildcard_pool();
  let wildcard_detected = !wildcard_pool.is_empty();
  let wildcard_rejected_count = results
    .iter()
    .filter(|r| enumerator.is_wildcard_hit(r))
    .count();
  let verification_method = if passive_only {
    "passive"
  } else if validate_dns {
    "dns-brute+resolve"
  } else {
    "dns-brute"
  };

  let persisted_to = persist_subdomain_results(
    ctx,
    domain,
    &display_results,
    if passive_only { "passive" } else { "hybrid" },
    validate_dns,
  )?;

  let payload = build_subdomains_payload(
    domain,
    &display_results,
    &confirmed_results,
    &candidate_results,
    passive_only,
    validate_dns,
    persisted_to.as_deref(),
    wildcard_detected,
    &wildcard_pool,
    wildcard_rejected_count,
    filter_wildcards,
    verification_method,
    &enumerator,
  );
  if render::render_machine_output_with_yaml(ctx, "rb recon domain subdomains", &payload, || {
    println!("domain: {}", domain);
    println!("count: {}", display_results.len());
    println!("total: {}", display_results.len());
    println!("confirmed_count: {}", confirmed_results.len());
    println!("candidate_count: {}", candidate_results.len());
    println!("validated: {}", validate_dns);
    println!("subdomains:");
    for result in &display_results {
      println!("  - subdomain: {}", result.subdomain);
      println!("    ips:");
      for ip in &result.ips {
        println!("      - {}", ip);
      }
      if !result.cname_chain.is_empty() {
        println!("    cname_chain:");
        for cname in &result.cname_chain {
          println!("      - {}", cname);
        }
      }
      println!("    source: {}", result.source);
    }
    Ok(())
  })? {
    return Ok(());
  }

  // Human output
  if display_results.is_empty() {
    if validate_dns && !candidate_results.is_empty() {
      Output::warning("No confirmed subdomains found after DNS validation");
      Output::item(
        "Unresolved Candidates",
        &candidate_results.len().to_string(),
      );
    } else {
      Output::warning("No subdomains found");
    }
    return Ok(());
  }

  Output::header("Subdomain Enumeration");
  Output::item("Target Domain", domain);
  Output::item("Mode", if passive_only { "passive" } else { "hybrid" });
  if validate_dns {
    Output::item("DNS Validation", "enabled (A/AAAA only)");
  }
  println!();

  println!();
  Output::subheader(&format!(
    "{} ({})",
    if validate_dns {
      "Confirmed Subdomains"
    } else {
      "Discovered Subdomains"
    },
    display_results.len()
  ));
  println!();

  // Print table header
  println!(
    "  {:<40} {:<20} {:<10}",
    "SUBDOMAIN", "IP ADDRESSES", "SOURCE"
  );
  println!("  {}", "─".repeat(75));

  for result in &display_results {
    let ips = if result.ips.is_empty() {
      "N/A".to_string()
    } else if result.ips.len() == 1 {
      result.ips[0].clone()
    } else {
      format!("{} (+{})", result.ips[0], result.ips.len() - 1)
    };

    println!(
      "  {:<40} {:<20} {:<10}",
      result.subdomain,
      ips,
      result.source.to_string()
    );

    // Show CNAME chain if present
    if !result.cname_chain.is_empty() {
      println!("    └─ CNAME: {}", result.cname_chain.join(" → "));
    }
  }

  println!();
  if validate_dns {
    Output::success(&format!(
      "Confirmed {} subdomains; filtered {} unresolved candidates",
      display_results.len(),
      candidate_results.len()
    ));
  } else {
    Output::success(&format!(
      "Found {} unique subdomains",
      display_results.len()
    ));
  }

  if let Some(db_path) = persisted_to {
    Output::success(&format!("Results saved to {}", db_path));
  }

  Ok(())
}

fn persist_subdomain_results(
  ctx: &CliContext,
  domain: &str,
  results: &[SubdomainResult],
  mode: &str,
  validate_dns: bool,
) -> Result<Option<String>, String> {
  let persist_flag = if ctx.has_flag("persist") {
    Some(true)
  } else if ctx.has_flag("no-persist") {
    Some(false)
  } else {
    None
  };

  let attributes = build_partition_attributes(
    ctx,
    domain,
    [
      ("operation", "subdomains"),
      ("mode", mode),
      ("validated", if validate_dns { "true" } else { "false" }),
    ],
  );
  let mut pm =
    StorageService::global().persistence_for_target_with(domain, persist_flag, None, attributes)?;
  if !pm.is_enabled() {
    return Ok(None);
  }

  for result in results {
    let source = map_subdomain_source(&result.source.to_string());
    let ips: Vec<IpAddr> = result
      .ips
      .iter()
      .filter_map(|ip| ip.parse::<IpAddr>().ok())
      .collect();

    pm.add_subdomain(domain, &result.subdomain, source as u8, &ips)?;
  }

  Ok(pm.commit()?.map(|path| path.display().to_string()))
}

fn split_results_by_resolution(
  results: &[SubdomainResult],
) -> (Vec<SubdomainResult>, Vec<SubdomainResult>) {
  let mut confirmed = Vec::new();
  let mut candidates = Vec::new();

  for result in results {
    if result.ips.is_empty() {
      candidates.push(result.clone());
    } else {
      confirmed.push(result.clone());
    }
  }

  (confirmed, candidates)
}

fn partition_confirmed_candidates(
  all_results: &[SubdomainResult],
  confirmed_results: &[SubdomainResult],
) -> (Vec<SubdomainResult>, Vec<SubdomainResult>) {
  let confirmed_names: HashSet<&str> = confirmed_results
    .iter()
    .map(|result| result.subdomain.as_str())
    .collect();

  let mut candidates = Vec::new();
  for result in all_results {
    if !confirmed_names.contains(result.subdomain.as_str()) {
      candidates.push(result.clone());
    }
  }

  (confirmed_results.to_vec(), candidates)
}

#[allow(clippy::too_many_arguments)]
fn build_subdomains_payload(
  domain: &str,
  display_results: &[SubdomainResult],
  confirmed_results: &[SubdomainResult],
  candidate_results: &[SubdomainResult],
  passive_only: bool,
  validate_dns: bool,
  persisted_to: Option<&str>,
  wildcard_detected: bool,
  wildcard_pool: &[String],
  wildcard_rejected_count: usize,
  wildcard_filter_active: bool,
  verification_method: &str,
  enumerator: &SubdomainEnumerator,
) -> Value {
  let json = JsonValue::object(vec![
    ("schema_version".to_string(), JsonValue::Number(2.0)),
    ("domain".to_string(), JsonValue::String(domain.to_string())),
    (
      "mode".to_string(),
      JsonValue::String(if passive_only { "passive" } else { "hybrid" }.to_string()),
    ),
    ("validated".to_string(), JsonValue::Bool(validate_dns)),
    (
      "verification_method".to_string(),
      JsonValue::String(verification_method.to_string()),
    ),
    (
      "wildcard_detected".to_string(),
      JsonValue::Bool(wildcard_detected),
    ),
    (
      "wildcard_pool".to_string(),
      JsonValue::array(
        wildcard_pool
          .iter()
          .map(|ip| JsonValue::String(ip.clone()))
          .collect(),
      ),
    ),
    (
      "wildcard_rejected_count".to_string(),
      JsonValue::Number(wildcard_rejected_count as f64),
    ),
    (
      "wildcard_filter_active".to_string(),
      JsonValue::Bool(wildcard_filter_active),
    ),
    (
      "total".to_string(),
      JsonValue::Number(display_results.len() as f64),
    ),
    (
      "count".to_string(),
      JsonValue::Number(display_results.len() as f64),
    ),
    (
      "confirmed_total".to_string(),
      JsonValue::Number(confirmed_results.len() as f64),
    ),
    (
      "candidate_total".to_string(),
      JsonValue::Number(candidate_results.len() as f64),
    ),
    (
      "subdomains".to_string(),
      JsonValue::array(subdomain_names(display_results)),
    ),
    (
      "confirmed".to_string(),
      JsonValue::array(subdomain_names(confirmed_results)),
    ),
    (
      "candidates".to_string(),
      JsonValue::array(subdomain_names(candidate_results)),
    ),
    (
      "entries".to_string(),
      JsonValue::array(subdomain_entries_with_wildcard(display_results, enumerator)),
    ),
    (
      "confirmed_entries".to_string(),
      JsonValue::array(subdomain_entries_with_wildcard(
        confirmed_results,
        enumerator,
      )),
    ),
    (
      "candidate_entries".to_string(),
      JsonValue::array(subdomain_entries_with_wildcard(
        candidate_results,
        enumerator,
      )),
    ),
    (
      "persisted_to".to_string(),
      persisted_to
        .map(|path| JsonValue::String(path.to_string()))
        .unwrap_or(JsonValue::Null),
    ),
  ]);

  Value::from(json)
}

fn subdomain_entries_with_wildcard(
  results: &[SubdomainResult],
  enumerator: &SubdomainEnumerator,
) -> Vec<JsonValue> {
  results
    .iter()
    .map(|r| {
      let mut entry = subdomain_entry_fields(r);
      entry.push((
        "wildcard_suspect".to_string(),
        JsonValue::Bool(enumerator.is_wildcard_hit(r)),
      ));
      JsonValue::object(entry)
    })
    .collect()
}

fn subdomain_names(results: &[SubdomainResult]) -> Vec<JsonValue> {
  results
    .iter()
    .map(|result| JsonValue::String(result.subdomain.clone()))
    .collect()
}

fn subdomain_entry_fields(result: &SubdomainResult) -> Vec<(String, JsonValue)> {
  vec![
    (
      "subdomain".to_string(),
      JsonValue::String(result.subdomain.clone()),
    ),
    (
      "ips".to_string(),
      JsonValue::array(
        result
          .ips
          .iter()
          .map(|ip| JsonValue::String(ip.clone()))
          .collect(),
      ),
    ),
    (
      "cname_chain".to_string(),
      JsonValue::array(
        result
          .cname_chain
          .iter()
          .map(|cname| JsonValue::String(cname.clone()))
          .collect(),
      ),
    ),
    (
      "source".to_string(),
      JsonValue::String(render_source_label(&result.source)),
    ),
    (
      "resolved".to_string(),
      JsonValue::Bool(!result.ips.is_empty()),
    ),
  ]
}

#[allow(dead_code)]
fn subdomain_entries(results: &[SubdomainResult]) -> Vec<JsonValue> {
  results
    .iter()
    .map(|r| JsonValue::object(subdomain_entry_fields(r)))
    .collect()
}

fn render_source_label(source: &EnumerationSource) -> String {
  source.to_string()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_result(name: &str, ips: &[&str], source: EnumerationSource) -> SubdomainResult {
    SubdomainResult {
      subdomain: name.to_string(),
      ips: ips.iter().map(|ip| (*ip).to_string()).collect(),
      cname_chain: Vec::new(),
      source,
    }
  }

  #[test]
  fn test_split_results_by_resolution() {
    let results = vec![
      sample_result(
        "api.example.com",
        &["1.1.1.1"],
        EnumerationSource::CertificateTransparency,
      ),
      sample_result("stale.example.com", &[], EnumerationSource::HackerTarget),
    ];

    let (confirmed, candidates) = split_results_by_resolution(&results);
    assert_eq!(confirmed.len(), 1);
    assert_eq!(candidates.len(), 1);
    assert_eq!(confirmed[0].subdomain, "api.example.com");
    assert_eq!(candidates[0].subdomain, "stale.example.com");
  }

  #[test]
  fn test_render_subdomains_json_contains_machine_friendly_lists() {
    let display = vec![sample_result(
      "api.example.com",
      &["1.1.1.1"],
      EnumerationSource::CertificateTransparency,
    )];
    let confirmed = display.clone();
    let candidates = vec![sample_result(
      "old.example.com",
      &[],
      EnumerationSource::HackerTarget,
    )];

    let enumerator = SubdomainEnumerator::new("example.com");
    let rendered = build_subdomains_payload(
      "example.com",
      &display,
      &confirmed,
      &candidates,
      false,
      true,
      Some("/tmp/example.rdb"),
      false,
      &[],
      0,
      true,
      "dns-brute+resolve",
      &enumerator,
    )
    .to_string_pretty();
    let parsed = crate::serde_json::from_str::<Value>(&rendered).unwrap();

    assert_eq!(parsed["schema_version"].as_i64(), Some(2));
    assert_eq!(parsed["domain"].as_str(), Some("example.com"));
    assert_eq!(parsed["validated"].as_bool(), Some(true));
    assert_eq!(
      parsed["verification_method"].as_str(),
      Some("dns-brute+resolve")
    );
    assert_eq!(parsed["wildcard_detected"].as_bool(), Some(false));
    assert_eq!(parsed["wildcard_pool"].as_array().unwrap().len(), 0);
    assert_eq!(parsed["wildcard_rejected_count"].as_i64(), Some(0));
    assert_eq!(parsed["wildcard_filter_active"].as_bool(), Some(true));
    assert_eq!(parsed["total"].as_i64(), Some(1));
    assert_eq!(parsed["confirmed_total"].as_i64(), Some(1));
    assert_eq!(parsed["candidate_total"].as_i64(), Some(1));

    let subdomains = parsed["subdomains"].as_array().unwrap();
    assert_eq!(subdomains.len(), 1);
    assert_eq!(subdomains[0].as_str(), Some("api.example.com"));

    let candidates_json = parsed["candidates"].as_array().unwrap();
    assert_eq!(candidates_json.len(), 1);
    assert_eq!(candidates_json[0].as_str(), Some("old.example.com"));

    let entries = parsed["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resolved"].as_bool(), Some(true));
    assert_eq!(entries[0]["wildcard_suspect"].as_bool(), Some(false));
  }
}

pub fn dnsdumpster(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain dnsdumpster <DOMAIN>\nExample: rb recon domain dnsdumpster example.com",
    )?;

  Validator::validate_domain(domain)?;

  Output::header(&format!("DNSDumpster Lookup: {}", domain));
  println!();

  let client = DnsDumpsterClient::new();

  Output::spinner_start(&format!("Querying DNSDumpster for {}", domain));
  let results = client.query(domain)?;
  Output::spinner_done();

  if results.dns_records.is_empty() && results.host_records.is_empty() {
    Output::info("No DNS records found.");
    return Ok(());
  }

  println!();
  Output::subheader(&format!(
    "DNS Records ({})",
    results.dns_records.len() + results.host_records.len()
  ));
  println!();

  for record in &results.dns_records {
    println!("  \x1b[1m{}: {}\x1b[0m", record.record_type, record.value);
  }
  for record in &results.host_records {
    println!(
      "  \x1b[1mHost: {}\x1b[0m ({})",
      record.host,
      record.ip.as_deref().unwrap_or("N/A")
    );
  }

  Output::success(&format!(
    "Found {} DNS records",
    results.dns_records.len() + results.host_records.len()
  ));

  Ok(())
}

pub fn massdns(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain massdns <DOMAIN> [--wordlist <file>] [--threads N]\nExample: rb recon domain massdns example.com",
    )?;

  Validator::validate_domain(domain)?;

  let wordlist_path = ctx.get_flag("wordlist");
  let threads: usize = ctx
    .get_flag("threads")
    .unwrap_or_else(|| "10".to_string())
    .parse()
    .unwrap_or(10);
  let resolvers: Vec<String> = ctx
    .get_flag("resolvers")
    .unwrap_or_else(|| "8.8.8.8,1.1.1.1,9.9.9.9".to_string())
    .split(',')
    .map(|s| s.to_string())
    .collect();
  let timeout_ms: u64 = ctx
    .get_flag("timeout-ms")
    .unwrap_or_else(|| "2000".to_string())
    .parse()
    .unwrap_or(2000);
  let delay: u64 = ctx
    .get_flag("delay")
    .unwrap_or_else(|| "10".to_string())
    .parse()
    .unwrap_or(10);

  Output::header(&format!("MassDNS Subdomain Enumeration: {}", domain));
  Output::item("Threads", &threads.to_string());
  Output::item("Resolvers", &resolvers.join(", "));
  Output::item("Timeout (ms)", &timeout_ms.to_string());
  Output::item("Delay (ms)", &delay.to_string());
  if let Some(path) = &wordlist_path {
    Output::item("Wordlist", path);
  } else {
    Output::item("Wordlist", "Default (common subdomains)");
  }
  println!();

  let scanner = MassDnsScanner::new()
    .with_threads(threads)
    .with_resolvers(resolvers)
    .with_timeout(Duration::from_millis(timeout_ms))
    .with_delay(Duration::from_millis(delay));

  let wordlist: Vec<String>;
  if let Some(path) = wordlist_path {
    wordlist = load_wordlist_from_file(&path)?;
  } else {
    wordlist = common_subdomains();
  }

  Output::spinner_start("Starting MassDNS scan...");
  let results = scanner.bruteforce(domain, &wordlist)?;
  Output::spinner_done();

  if results.resolved.is_empty() {
    Output::info("No subdomains found.");
    return Ok(());
  }

  println!();
  Output::subheader(&format!("Found {} Subdomains", results.resolved.len()));
  println!();

  for result in &results.resolved {
    let ips = result.ips.join(", ");
    println!("  \x1b[32m●\x1b[0m {} ({})", result.subdomain, ips);
  }

  Output::success(&format!("Found {} subdomains", results.resolved.len()));

  Ok(())
}
