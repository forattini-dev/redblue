//! Virtual host discovery CLI command

use crate::cli::output::Output;
use crate::cli::render;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::json;
use crate::modules::web::vhost_enumerator::{VhostConfig, VhostEnumerator};
use crate::protocols::dns::{DnsClient, DnsRecordType};

/// Resolve a domain name to its first A-record IP address.
fn resolve_to_ip(domain: &str) -> Result<String, String> {
  let client = DnsClient::new("8.8.8.8");
  let answers = client
    .query(domain, DnsRecordType::A)
    .map_err(|e| format!("Failed to resolve {}: {}", domain, e))?;

  for answer in &answers {
    if let Some(ip) = answer.as_ip() {
      return Ok(ip.to_string());
    }
  }

  Err(format!(
    "Could not resolve {} to an IP address. Provide a resolvable domain or use an IP directly.",
    domain
  ))
}

pub fn vhosts(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx
    .target
    .as_ref()
    .ok_or("Missing domain.\nUsage: rb recon domain vhosts <DOMAIN> [--brute]\nExample: rb recon domain vhosts example.com --brute")?;

  Validator::validate_domain(domain)?;

  let brute = ctx.has_flag("brute");
  let wordlist = ctx.get_flag("wordlist");
  let threads: usize = ctx
    .get_flag("threads")
    .unwrap_or_else(|| "10".to_string())
    .parse()
    .unwrap_or(10);

  if !brute && wordlist.is_none() {
    return Err(
      "VHost discovery requires --brute or --wordlist flag.\n\
       Usage: rb recon domain vhosts <domain> --brute\n\
       Usage: rb recon domain vhosts <domain> --wordlist <file>"
        .into(),
    );
  }

  Output::header(&format!("VHost Discovery: {}", domain));
  println!();

  // Resolve domain to IP
  Output::spinner_start(&format!("Resolving {} to IP", domain));
  let ip = resolve_to_ip(domain)?;
  Output::spinner_done();
  Output::item("Target IP", &ip);

  let config = VhostConfig {
    brute,
    wordlist,
    base_domain: domain.to_string(),
    threads,
    ..Default::default()
  };

  Output::spinner_start("Enumerating virtual hosts");
  let enumerator = VhostEnumerator::new(config);
  let results = enumerator.enumerate(&ip);
  Output::spinner_done();

  // Build JSON payload for machine output
  let vhosts_json: Vec<_> = results
    .iter()
    .map(|v| {
      json!({
        "hostname": v.hostname,
        "status": v.status,
        "size": v.size,
        "title": v.title.as_deref().unwrap_or(""),
        "differs_from_default": v.differs_from_default
      })
    })
    .collect();

  let payload = json!({
    "domain": domain,
    "ip": ip,
    "count": results.len(),
    "vhosts": vhosts_json
  });

  if render::render_machine_output(ctx, "rb recon domain vhosts", &payload)? {
    return Ok(());
  }

  // Human-readable output
  if results.is_empty() {
    Output::warning("No additional virtual hosts discovered.");
    println!("  The server may not host other vhosts, or responses are identical to the default.");
    return Ok(());
  }

  Output::success(&format!("Found {} virtual host(s)", results.len()));
  println!();

  for vhost in &results {
    let title_str = vhost
      .title
      .as_deref()
      .map(|t| format!(" - \"{}\"", t))
      .unwrap_or_default();
    println!(
      "  \x1b[1;32m{}\x1b[0m [{}] ({} bytes){}",
      vhost.hostname, vhost.status, vhost.size, title_str
    );
  }

  Ok(())
}
