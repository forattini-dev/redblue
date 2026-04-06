//! Social media mapping and Google dorks commands

use crate::cli::output::Output;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::modules::recon::dorks::DorksSearcher;
use crate::modules::recon::social::SocialMapper;

/// Google dorks search for domain intel
pub fn dorks(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain dorks <DOMAIN>\nExample: rb recon domain dorks example.com",
    )?;

  Validator::validate_domain(domain)?;

  Output::header(&format!("Google Dorks Search: {}", domain));
  println!();

  let searcher = DorksSearcher::new();

  Output::spinner_start(&format!("Searching Google for {} ...", domain));
  let results = searcher.search(domain);
  Output::spinner_done();

  if results.summary.total_results == 0 {
    Output::info("No results found.");
    return Ok(());
  }

  println!();
  Output::subheader(&format!(
    "Found {} potential leaks/intel:",
    results.summary.total_results
  ));
  println!();

  // Display results by category
  if !results.categories.github.is_empty() {
    println!("\x1b[1;36mGitHub:\x1b[0m");
    for dork_result in &results.categories.github {
      for url in &dork_result.urls {
        println!("  \x1b[36m→\x1b[0m {}", url);
      }
    }
    println!();
  }
  if !results.categories.pastebin.is_empty() {
    println!("\x1b[1;36mPastebin:\x1b[0m");
    for dork_result in &results.categories.pastebin {
      for url in &dork_result.urls {
        println!("  \x1b[36m→\x1b[0m {}", url);
      }
    }
    println!();
  }
  if !results.categories.linkedin.is_empty() {
    println!("\x1b[1;36mLinkedIn:\x1b[0m");
    for dork_result in &results.categories.linkedin {
      for url in &dork_result.urls {
        println!("  \x1b[36m→\x1b[0m {}", url);
      }
    }
    println!();
  }
  if !results.categories.documents.is_empty() {
    println!("\x1b[1;36mDocuments:\x1b[0m");
    for dork_result in &results.categories.documents {
      for url in &dork_result.urls {
        println!("  \x1b[36m→\x1b[0m {}", url);
      }
    }
    println!();
  }
  if !results.categories.subdomains.is_empty() {
    println!("\x1b[1;36mSubdomains:\x1b[0m");
    for url in &results.categories.subdomains {
      println!("  \x1b[36m→\x1b[0m {}", url);
    }
    println!();
  }
  if !results.categories.login_pages.is_empty() {
    println!("\x1b[1;36mLogin Pages:\x1b[0m");
    for dork_result in &results.categories.login_pages {
      for url in &dork_result.urls {
        println!("  \x1b[36m→\x1b[0m {}", url);
      }
    }
    println!();
  }
  if !results.categories.configs.is_empty() {
    println!("\x1b[1;36mConfig Files:\x1b[0m");
    for dork_result in &results.categories.configs {
      for url in &dork_result.urls {
        println!("  \x1b[36m→\x1b[0m {}", url);
      }
    }
    println!();
  }
  if !results.categories.errors.is_empty() {
    println!("\x1b[1;36mError Pages:\x1b[0m");
    for dork_result in &results.categories.errors {
      for url in &dork_result.urls {
        println!("  \x1b[36m→\x1b[0m {}", url);
      }
    }
    println!();
  }

  Output::success(&format!(
    "Found {} potential leaks/intel",
    results.summary.total_results
  ));

  Ok(())
}

/// Social media profile mapping for a domain
pub fn social(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain social <DOMAIN>\nExample: rb recon domain social example.com",
    )?;

  Validator::validate_domain(domain)?;

  Output::header(&format!("Social Media Mapping: {}", domain));
  println!();

  let mapper = SocialMapper::new();

  Output::spinner_start(&format!("Mapping social media for {}", domain));
  let results = mapper.map(domain);
  Output::spinner_done();

  if results.profiles.is_empty() {
    Output::info("No social media profiles found.");
    return Ok(());
  }

  println!();
  Output::subheader(&format!(
    "Found {} social media profiles:",
    results.profiles.len()
  ));
  println!();

  for profile in results.profiles.values() {
    if profile.found {
      println!(
        "  \x1b[36m{}\x1b[0m - \x1b[1m{}\x1b[0m",
        profile.platform, profile.url
      );
    }
  }

  Output::success(&format!(
    "Found {} social media profiles",
    results.profiles.len()
  ));

  Ok(())
}
