//! Username OSINT, email intelligence, and ASN lookup

use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::recon::asn::{AsnClient, AsnInfo};
use crate::modules::recon::osint::{EmailIntel, EmailResult, OsintConfig as EmailOsintConfig};

pub fn osint(ctx: &CliContext) -> Result<(), String> {
  let target = ctx
    .target
    .as_ref()
    .ok_or("Missing username.\nUsage: rb recon domain osint <USERNAME>")?;

  if target.is_empty() {
    return Err("Username cannot be empty".to_string());
  }

  let payload = osint_placeholder_payload(target);
  if render::render_machine_output(ctx, "rb recon domain osint", &payload)? {
    return Ok(());
  }

  Output::warning("OSINT helpers not yet implemented");
  println!("\nComing soon!");
  Ok(())
}

pub fn email(ctx: &CliContext) -> Result<(), String> {
  let target = ctx
    .target
    .as_ref()
    .ok_or("Missing email address.\nUsage: rb recon domain email <EMAIL>")?;

  if !target.contains('@') {
    return Err(format!("Invalid email address: {}", target));
  }

  let config = EmailOsintConfig::default();
  let intel = EmailIntel::new(config);

  // Validate email format
  if !intel.is_valid_format(target) {
    return Err(format!("Invalid email format: {}", target));
  }

  if !ctx.wants_machine_output() {
    Output::header(&format!("Email Intelligence: {}", target));
    Output::spinner_start(&format!("Investigating {}", target));
  }

  let result = intel.investigate(target);

  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = email_payload(&result);
  if render::render_machine_output(ctx, "rb recon domain email", &payload)? {
    return Ok(());
  }

  // Human output
  println!();
  Output::item("Email", &result.email);
  Output::item("Valid", if result.valid { "Yes" } else { "No" });

  if let Some(provider) = &result.provider {
    Output::item("Provider", provider);
  }

  // Check if disposable
  if intel.is_disposable(target) {
    Output::warning("This appears to be a disposable email address");
  }

  // Services found
  if !result.services.is_empty() {
    println!();
    Output::subheader(&format!("Registered Services ({})", result.services.len()));
    for service in &result.services {
      println!("  \x1b[32m✓\x1b[0m {}", service);
    }
  }

  // Social profiles linked
  if !result.social_profiles.is_empty() {
    println!();
    Output::subheader(&format!(
      "Social Profiles ({})",
      result.social_profiles.len()
    ));
    for profile in &result.social_profiles {
      let url = profile.url.as_deref().unwrap_or("N/A");
      println!(
        "  \x1b[32m✓\x1b[0m {} - \x1b[36m{}\x1b[0m",
        profile.platform, url
      );
    }
  }

  // Summary
  println!();
  let total = result.services.len() + result.social_profiles.len();
  if total > 0 {
    Output::success(&format!(
      "Found {} service(s) and {} profile(s)",
      result.services.len(),
      result.social_profiles.len()
    ));
  } else {
    Output::info("No service registrations or profiles found");
  }

  // Extract username and suggest related search
  if let Some(username) = intel.extract_username(target) {
    println!();
    Output::info(&format!(
      "Tip: Try 'rb recon identity username {}' for broader search",
      username
    ));
  }

  Ok(())
}

/// ASN lookup for IP address or hostname
pub fn asn(ctx: &CliContext) -> Result<(), String> {
  let target = ctx.target.as_ref().ok_or(
        "Missing IP address or hostname.\nUsage: rb recon domain asn <IP|HOSTNAME>\nExample: rb recon domain asn 8.8.8.8",
    )?;

  let client = AsnClient::new();

  if !ctx.wants_machine_output() {
    Output::spinner_start(&format!("Looking up ASN for {}", target));
  }

  // Check if it's an IP or hostname
  let is_ip = target.parse::<std::net::IpAddr>().is_ok();

  let results = if is_ip {
    vec![client.lookup_ip(target)?]
  } else {
    client.lookup_host(target)?
  };

  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = asn_payload(target, &results);
  if render::render_machine_output(ctx, "rb recon domain asn", &payload)? {
    return Ok(());
  }

  // Human output
  Output::header(&format!("ASN Lookup: {}", target));
  println!();

  for info in &results {
    if !info.announced {
      Output::warning(&format!("IP {} is not announced (not routed)", info.ip));
      continue;
    }

    println!("  {:<15} {}", "IP:", info.ip);
    if let Some(asn) = info.asn {
      println!("  {:<15} AS{}", "ASN:", asn);
    }
    if let Some(ref org) = info.organization {
      println!("  {:<15} {}", "Organization:", org);
    }
    if let Some(ref country) = info.country {
      println!("  {:<15} {}", "Country:", country);
    }
    if let Some(ref cidr) = info.cidr {
      println!("  {:<15} {}", "Network:", cidr);
    }
    println!();
  }

  Output::success("ASN lookup completed");
  Ok(())
}

fn email_payload(result: &EmailResult) -> crate::serde_json::Value {
  let social_profiles: Vec<_> = result
    .social_profiles
    .iter()
    .map(|profile| {
      json!({
        "platform": profile.platform.clone(),
        "url": profile.url.clone()
      })
    })
    .collect();

  json!({
    "email": result.email,
    "valid": result.valid,
    "provider": result.provider,
    "services": result.services,
    "social_profiles": social_profiles
  })
}

fn osint_placeholder_payload(target: &str) -> crate::serde_json::Value {
  json!({
    "target": target,
    "status": "not_implemented",
    "message": "OSINT helpers not yet implemented",
  })
}

fn asn_payload(query: &str, results: &[AsnInfo]) -> crate::serde_json::Value {
  let payload: Vec<_> = results
    .iter()
    .map(|info| {
      json!({
        "ip": info.ip.to_string(),
        "announced": info.announced,
        "asn": info.asn,
        "organization": info.organization.clone(),
        "country": info.country.clone(),
        "cidr": info.cidr.clone()
      })
    })
    .collect();

  json!({
    "query": query,
    "results": payload
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn email_payload_includes_profiles() {
    let payload = email_payload(&EmailResult {
      email: "user@example.com".to_string(),
      valid: true,
      provider: Some("gmail".to_string()),
      breaches: vec![],
      pastes: vec![],
      services: vec!["github".to_string()],
      social_profiles: vec![],
    });

    assert_eq!(payload["email"].as_str(), Some("user@example.com"));
    assert_eq!(
      payload["services"].as_array().unwrap()[0].as_str(),
      Some("github")
    );
  }

  #[test]
  fn osint_placeholder_payload_marks_not_implemented() {
    let payload = osint_placeholder_payload("johndoe");

    assert_eq!(payload["target"].as_str(), Some("johndoe"));
    assert_eq!(payload["status"].as_str(), Some("not_implemented"));
  }

  #[test]
  fn asn_payload_includes_query_and_asn() {
    let payload = asn_payload(
      "8.8.8.8",
      &[AsnInfo {
        ip: "8.8.8.8".to_string(),
        announced: true,
        asn: Some(15169),
        asn_string: Some("AS15169".to_string()),
        country: Some("US".to_string()),
        organization: Some("GOOGLE".to_string()),
        asn_name: Some("GOOGLE".to_string()),
        first_ip: Some("8.8.8.0".to_string()),
        last_ip: Some("8.8.8.255".to_string()),
        cidr: Some("8.8.8.0/24".to_string()),
      }],
    );

    assert_eq!(payload["query"].as_str(), Some("8.8.8.8"));
    assert_eq!(
      payload["results"].as_array().unwrap()[0]["asn"].as_i64(),
      Some(15169)
    );
  }
}
