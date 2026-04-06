//! OSINT data harvesting commands

use crate::cli::output::Output;
use crate::cli::render;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::json;
use crate::modules::recon::harvester::Harvester;
use crate::modules::recon::urlharvest::UrlHarvester;
use std::collections::HashMap;

pub fn harvest(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain harvest <DOMAIN>\nExample: rb recon domain harvest example.com",
    )?;

  Validator::validate_domain(domain)?;

  let format = ctx.get_output_format();
  let is_human = format == crate::cli::format::OutputFormat::Human;

  if is_human {
    Output::header("OSINT Data Harvesting (theHarvester)");
    Output::item("Target Domain", domain);
    println!();
  }

  let harvester = Harvester::new();

  if is_human {
    Output::spinner_start(&format!("Harvesting OSINT data for {}", domain));
  }
  let result = harvester.harvest(domain)?;
  if is_human {
    Output::spinner_done();
  }

  let total = result.emails.len() + result.subdomains.len() + result.ips.len() + result.urls.len();
  let payload = json!({
      "domain": domain,
      "total_items": total,
      "emails": result.emails.clone(),
      "subdomains": result.subdomains.clone(),
      "ips": result.ips.clone(),
      "urls": result.urls.clone(),
  });
  if render::render_machine_output(ctx, "rb recon domain harvest", &payload)? {
    return Ok(());
  }

  // Display emails
  if !result.emails.is_empty() {
    println!();
    Output::subheader(&format!("Email Addresses ({})", result.emails.len()));
    println!();
    for email in &result.emails {
      println!("  \x1b[36m✉\x1b[0m  {}", email);
    }
  }

  // Display subdomains
  if !result.subdomains.is_empty() {
    println!();
    Output::subheader(&format!("Subdomains ({})", result.subdomains.len()));
    println!();
    for subdomain in &result.subdomains {
      println!("  \x1b[32m●\x1b[0m  {}", subdomain);
    }
  }

  // Display IPs
  if !result.ips.is_empty() {
    println!();
    Output::subheader(&format!("IP Addresses ({})", result.ips.len()));
    println!();
    for ip in &result.ips {
      println!("  \x1b[33m◆\x1b[0m  {}", ip);
    }
  }

  // Display URLs
  if !result.urls.is_empty() {
    println!();
    Output::subheader(&format!("URLs ({})", result.urls.len()));
    println!();
    for url in &result.urls {
      println!("  \x1b[35m→\x1b[0m  {}", url);
    }
  }

  println!();
  Output::success(&format!("Harvested {} total items", total));

  Ok(())
}

pub fn urls(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain urls <DOMAIN>\nExample: rb recon domain urls example.com",
    )?;

  Validator::validate_domain(domain)?;

  let format = ctx.get_output_format();
  let is_human = format == crate::cli::format::OutputFormat::Human;

  if is_human {
    Output::header("URL Harvester (waybackurls/gau)");
    Output::item("Target Domain", domain);
    println!();
  }

  let harvester = UrlHarvester::new();

  if is_human {
    Output::spinner_start(&format!("Harvesting historical URLs for {}", domain));
  }
  let mut urls = harvester.harvest(domain)?;
  if is_human {
    Output::spinner_done();
  }

  // Apply filters
  let include_pattern = ctx.get_flag("include").or_else(|| ctx.get_flag("i"));
  let exclude_pattern = ctx.get_flag("exclude").or_else(|| ctx.get_flag("e"));

  if include_pattern.is_some() || exclude_pattern.is_some() {
    urls = harvester.filter_urls(urls, include_pattern.as_deref(), exclude_pattern.as_deref());
  }

  // Filter by extensions if specified
  if let Some(extensions_str) = ctx.get_flag("extensions") {
    let extensions: Vec<&str> = extensions_str.split(',').map(|s| s.trim()).collect();
    urls = harvester.filter_by_extension(urls, &extensions);
  }

  if urls.is_empty() {
    let empty_payload = json!({
        "domain": domain,
        "total": 0,
        "urls": [],
    });
    if render::render_machine_output(ctx, "rb recon domain urls", &empty_payload)? {
      return Ok(());
    }
    Output::warning("No URLs found");
    return Ok(());
  }

  // Group by source
  let mut by_source: HashMap<String, Vec<&crate::modules::recon::urlharvest::HarvestedUrl>> =
    HashMap::new();

  for url in &urls {
    by_source
      .entry(url.source.clone())
      .or_insert_with(Vec::new)
      .push(url);
  }

  let urls_json: Vec<_> = urls
    .iter()
    .map(|url_obj| {
      json!({
          "url": url_obj.url,
          "source": url_obj.source,
          "timestamp": url_obj.timestamp,
      })
    })
    .collect();
  let payload = json!({
      "domain": domain,
      "total": urls.len(),
      "urls": urls_json,
  });
  if render::render_machine_output(ctx, "rb recon domain urls", &payload)? {
    return Ok(());
  }

  // Display results
  println!();
  Output::subheader(&format!("Discovered URLs ({})", urls.len()));
  println!();

  // Sort sources alphabetically
  let mut sources: Vec<_> = by_source.keys().collect();
  sources.sort();

  for source in &sources {
    let source_urls = by_source.get(*source).unwrap();
    println!("\x1b[1m\x1b[36m{}\x1b[0m ({})", source, source_urls.len());

    // Show first 100 URLs per source
    let display_count = source_urls.len().min(100);
    for url_obj in source_urls.iter().take(display_count) {
      if let Some(ref timestamp) = url_obj.timestamp {
        println!("  \x1b[2m{}\x1b[0m  {}", timestamp, url_obj.url);
      } else {
        println!("  {}", url_obj.url);
      }
    }

    if source_urls.len() > 100 {
      println!(
        "  \x1b[2m... and {} more URLs\x1b[0m",
        source_urls.len() - 100
      );
    }

    println!();
  }

  // Summary by source
  println!("\x1b[1mSummary by Source:\x1b[0m");
  for source in &sources {
    let count = by_source.get(*source).unwrap().len();
    println!("  {}: {}", source, count);
  }

  println!();
  Output::success(&format!("Found {} unique URLs", urls.len()));

  Ok(())
}
