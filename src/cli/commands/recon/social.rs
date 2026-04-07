//! Social media mapping and Google dorks commands

use crate::cli::validator::Validator;
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::recon::dorks::DorksSearcher;
use crate::modules::recon::dorks::{DorkResult, DorksSearchResult};
use crate::modules::recon::social::{SocialMapper, SocialMappingResult, SocialProfile};

/// Google dorks search for domain intel
pub fn dorks(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain dorks <DOMAIN>\nExample: rb recon domain dorks example.com",
    )?;

  Validator::validate_domain(domain)?;

  if !ctx.wants_machine_output() {
    Output::header(&format!("Google Dorks Search: {}", domain));
    println!();
  }

  let searcher = DorksSearcher::new();

  if !ctx.wants_machine_output() {
    Output::spinner_start(&format!("Searching Google for {} ...", domain));
  }
  let results = searcher.search(domain);
  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = dorks_payload(&results);
  if render::render_machine_output(ctx, "rb recon domain dorks", &payload)? {
    return Ok(());
  }

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

  if !ctx.wants_machine_output() {
    Output::header(&format!("Social Media Mapping: {}", domain));
    println!();
  }

  let mapper = SocialMapper::new();

  if !ctx.wants_machine_output() {
    Output::spinner_start(&format!("Mapping social media for {}", domain));
  }
  let results = mapper.map(domain);
  if !ctx.wants_machine_output() {
    Output::spinner_done();
  }

  let payload = social_payload(&results);
  if render::render_machine_output(ctx, "rb recon domain social", &payload)? {
    return Ok(());
  }

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

fn dork_result_payload(result: &DorkResult) -> crate::serde_json::Value {
  json!({
    "query": result.query,
    "category": result.category,
    "urls": result.urls,
  })
}

fn dorks_payload(results: &DorksSearchResult) -> crate::serde_json::Value {
  let summary = json!({
    "total_results": results.summary.total_results,
    "github_count": results.summary.github_count,
    "pastebin_count": results.summary.pastebin_count,
    "linkedin_count": results.summary.linkedin_count,
    "documents_count": results.summary.documents_count,
    "subdomains_count": results.summary.subdomains_count,
    "login_pages_count": results.summary.login_pages_count,
    "configs_count": results.summary.configs_count,
    "errors_count": results.summary.errors_count,
  });
  let categories = json!({
    "github": results.categories.github.iter().map(dork_result_payload).collect::<Vec<_>>(),
    "pastebin": results.categories.pastebin.iter().map(dork_result_payload).collect::<Vec<_>>(),
    "linkedin": results.categories.linkedin.iter().map(dork_result_payload).collect::<Vec<_>>(),
    "documents": results.categories.documents.iter().map(dork_result_payload).collect::<Vec<_>>(),
    "subdomains": results.categories.subdomains,
    "login_pages": results.categories.login_pages.iter().map(dork_result_payload).collect::<Vec<_>>(),
    "configs": results.categories.configs.iter().map(dork_result_payload).collect::<Vec<_>>(),
    "errors": results.categories.errors.iter().map(dork_result_payload).collect::<Vec<_>>(),
  });

  json!({
    "domain": results.domain,
    "company_name": results.company_name,
    "summary": summary,
    "categories": categories
  })
}

fn social_profile_payload(profile: &SocialProfile) -> crate::serde_json::Value {
  json!({
    "platform": profile.platform,
    "url": profile.url,
    "found": profile.found,
    "username": profile.username,
    "followers": profile.followers,
    "bio": profile.bio,
    "verified": profile.verified,
    "location": profile.location,
    "activity": profile.activity,
  })
}

fn social_payload(results: &SocialMappingResult) -> crate::serde_json::Value {
  let mut profiles: Vec<_> = results
    .profiles
    .values()
    .map(social_profile_payload)
    .collect();
  profiles.sort_by(|a, b| {
    let a_platform = a["platform"].as_str().unwrap_or("");
    let b_platform = b["platform"].as_str().unwrap_or("");
    a_platform.cmp(b_platform)
  });

  json!({
    "domain": results.domain,
    "company_name": results.company_name,
    "found_count": results.found_count,
    "total_checked": results.total_checked,
    "profiles": profiles,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::modules::recon::dorks::{DorkCategories, DorksSummary};
  use std::collections::HashMap;

  #[test]
  fn dorks_payload_includes_summary_and_categories() {
    let payload = dorks_payload(&DorksSearchResult {
      domain: "example.com".to_string(),
      company_name: "Example".to_string(),
      categories: DorkCategories {
        github: vec![DorkResult {
          query: "site:github.com \"example.com\"".to_string(),
          category: "github".to_string(),
          urls: vec!["https://github.com/example".to_string()],
        }],
        ..DorkCategories::default()
      },
      summary: DorksSummary {
        total_results: 1,
        github_count: 1,
        ..DorksSummary::default()
      },
    });

    assert_eq!(payload["summary"]["total_results"].as_u64(), Some(1));
    assert_eq!(
      payload["categories"]["github"][0]["urls"][0].as_str(),
      Some("https://github.com/example")
    );
  }

  #[test]
  fn social_payload_includes_sorted_profiles() {
    let mut profiles = HashMap::new();
    profiles.insert(
      "twitter".to_string(),
      SocialProfile {
        platform: "twitter".to_string(),
        url: "https://x.com/example".to_string(),
        found: true,
        username: Some("example".to_string()),
        followers: None,
        bio: None,
        verified: Some(true),
        location: None,
        activity: None,
      },
    );

    let payload = social_payload(&SocialMappingResult {
      domain: "example.com".to_string(),
      company_name: "Example".to_string(),
      profiles,
      found_count: 1,
      total_checked: 10,
    });

    assert_eq!(payload["found_count"].as_u64(), Some(1));
    assert_eq!(payload["profiles"][0]["platform"].as_str(), Some("twitter"));
  }
}
