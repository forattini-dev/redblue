/// Identity OSINT command - Username and email reconnaissance
///
/// Consolidates person/identity OSINT:
/// - Username enumeration (sherlock/maigret-style)
/// - Email intelligence (holehe-style)
/// - Breach checking
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::recon::breach::BreachClient;
use crate::modules::recon::osint::{
  platforms::get_all_platforms, EmailIntel, EmailResult, EnumerationSummary, OsintConfig,
  PlatformCategory, ProfileResult, UsernameEnumerator,
};
use crate::serde_json::Value;
use std::time::Duration;

pub struct ReconIdentityCommand;

impl Command for ReconIdentityCommand {
  fn domain(&self) -> &str {
    "recon"
  }

  fn resource(&self) -> &str {
    "identity"
  }

  fn description(&self) -> &str {
    "Person/identity OSINT - username enumeration, email intelligence, breach checks"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "username",
        summary: "Search username across 1000+ platforms (sherlock/maigret-style)",
        usage: "rb recon identity username <username> [--category social|coding|gaming]",
      },
      Route {
        verb: "email",
        summary: "Email intelligence - provider detection, service registrations (holehe-style)",
        usage: "rb recon identity email <email>",
      },
      Route {
        verb: "breach",
        summary: "Check if email/password appears in data breaches (HIBP)",
        usage: "rb recon identity breach <email|password> [--type email|password]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      // Username flags
      Flag::new(
        "category",
        "Filter by category (social, coding, gaming, professional, etc.)",
      )
      .with_short('c'),
      Flag::new("platforms", "Specific platforms to check (comma-separated)").with_short('p'),
      Flag::new("threads", "Number of concurrent threads").with_default("50"),
      Flag::new("timeout", "Timeout per request in ms").with_default("10000"),
      Flag::new("max-sites", "Maximum sites to check (0 = unlimited)").with_default("0"),
      // Breach flags
      Flag::new("type", "Breach check type: email or password")
        .with_short('t')
        .with_default("password"),
      Flag::new("hibp-key", "HIBP API key for email breach checks"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      // Username examples
      (
        "Search username across all platforms",
        "rb recon identity username johndoe",
      ),
      (
        "Search social sites only",
        "rb recon identity username johndoe --category social",
      ),
      (
        "Search coding sites only",
        "rb recon identity username johndoe --category coding",
      ),
      (
        "Search gaming sites only",
        "rb recon identity username johndoe --category gaming",
      ),
      (
        "Limit number of sites",
        "rb recon identity username johndoe --max-sites 100",
      ),
      (
        "Check specific platforms",
        "rb recon identity username johndoe --platforms github,twitter",
      ),
      // Email examples
      (
        "Email intelligence",
        "rb recon identity email user@example.com",
      ),
      // Breach examples
      (
        "Check password breach",
        "rb recon identity breach password123",
      ),
      (
        "Check email breach",
        "rb recon identity breach user@example.com --type email --hibp-key KEY",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "username" => self.username_search(ctx),
      "email" => self.email_intel(ctx),
      "breach" => self.breach_check(ctx),
      _ => {
        print_help(self);
        Err(format!(
          "Unknown verb '{}'. Valid: username, email, breach",
          verb
        ))
      }
    }
  }
}

impl ReconIdentityCommand {
  fn username_search(&self, ctx: &CliContext) -> Result<(), String> {
    let username = ctx.target.as_ref().ok_or(
            "Missing username.\nUsage: rb recon identity username <username>\nExample: rb recon identity username johndoe",
        )?;
    let category_filter = ctx.get_flag("category");
    let platforms_filter = ctx.get_flag("platforms");
    let threads: usize = ctx
      .get_flag("threads")
      .and_then(|s| s.parse().ok())
      .unwrap_or(50);
    let timeout: u64 = ctx
      .get_flag("timeout")
      .and_then(|s| s.parse().ok())
      .unwrap_or(10000);
    let max_sites: usize = ctx
      .get_flag("max-sites")
      .and_then(|s| s.parse().ok())
      .unwrap_or(0);

    // If specific platforms requested, use check mode
    if let Some(platforms_str) = platforms_filter {
      return self.username_check(ctx, username, &platforms_str);
    }

    // Build category list
    let categories = if let Some(cat) = &category_filter {
      Self::parse_category(cat)
    } else {
      vec![
        PlatformCategory::Social,
        PlatformCategory::Development,
        PlatformCategory::Gaming,
        PlatformCategory::Business,
        PlatformCategory::Creative,
        PlatformCategory::Photography,
        PlatformCategory::Video,
        PlatformCategory::Music,
        PlatformCategory::News,
        PlatformCategory::Forum,
        PlatformCategory::Dating,
        PlatformCategory::Finance,
        PlatformCategory::Crypto,
        PlatformCategory::Shopping,
        PlatformCategory::Adult,
        PlatformCategory::Other,
      ]
    };

    // Build config
    let config = OsintConfig {
            timeout: Duration::from_millis(timeout),
            threads,
            delay: Duration::from_millis(50),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            categories: categories.clone(),
            skip_platforms: Vec::new(),
            extract_metadata: false,
            follow_redirects: true,
        };

    // Get total platforms for this category set
    let all_platforms = get_all_platforms();
    let mut platform_count = all_platforms
      .iter()
      .filter(|p| categories.contains(&p.category))
      .count();

    // Apply max_sites limit
    if max_sites > 0 && max_sites < platform_count {
      platform_count = max_sites;
    }

    if !ctx.wants_machine_output() {
      Output::header(&format!("Username Search: {}", username));

      if let Some(cat) = &category_filter {
        Output::item("Category Filter", cat);
      }
      Output::item("Platforms", &format!("{}", platform_count));
      Output::item("Threads", &format!("{}", threads));

      Output::spinner_start(&format!(
        "Searching {} across {} platforms",
        username, platform_count
      ));
    }

    let enumerator = UsernameEnumerator::new(config);
    let result = enumerator.enumerate(username);

    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }

    let payload = Self::username_enumeration_payload(username, category_filter.as_deref(), &result);
    if render::render_machine_output(ctx, "rb recon identity username", &payload)? {
      return Ok(());
    }

    // Display results
    println!();
    Output::item("Username", username);
    Output::item("Platforms Checked", &format!("{}", result.total_checked));
    Output::item("Profiles Found", &format!("{}", result.found_count));
    Output::item("Errors", &format!("{}", result.error_count));
    Output::item(
      "Duration",
      &format!("{:.2}s", result.duration.as_secs_f64()),
    );
    println!();

    if result.found_count == 0 {
      Output::warning("No profiles found for this username");
      return Ok(());
    }

    // Display by category
    let mut sorted_categories: Vec<_> = result.by_category.iter().collect();
    sorted_categories.sort_by_key(|(cat, _)| format!("{:?}", cat));

    for (category, profiles) in sorted_categories {
      let found: Vec<_> = profiles.iter().filter(|p| p.exists).collect();
      if found.is_empty() {
        continue;
      }

      Output::subheader(&format!("{:?} ({})", category, found.len()));
      for profile in found {
        let url = profile.url.as_deref().unwrap_or("N/A");
        println!(
          "  \x1b[32m✓\x1b[0m {} - \x1b[36m{}\x1b[0m",
          profile.platform, url
        );
      }
      println!();
    }

    Output::success(&format!(
      "Found {} profiles in {:.2}s",
      result.found_count,
      result.duration.as_secs_f64()
    ));

    Ok(())
  }

  fn username_check(
    &self,
    ctx: &CliContext,
    username: &str,
    platforms_str: &str,
  ) -> Result<(), String> {
    let platform_names: Vec<&str> = platforms_str.split(',').map(|s| s.trim()).collect();

    if !ctx.wants_machine_output() {
      Output::header(&format!("Username Check: {}", username));
      Output::item("Platforms", &platform_names.join(", "));

      Output::spinner_start(&format!(
        "Checking {} on {} platforms",
        username,
        platform_names.len()
      ));
    }

    // Filter platforms by name from the full list
    let all_platforms = get_all_platforms();
    let filtered: Vec<_> = all_platforms
      .into_iter()
      .filter(|p| {
        platform_names.iter().any(|name| {
          p.name.eq_ignore_ascii_case(name) || p.name.to_lowercase().contains(&name.to_lowercase())
        })
      })
      .collect();

    // Build config for quick check
    let config = OsintConfig {
      timeout: Duration::from_secs(10),
      threads: filtered.len().min(20),
      delay: Duration::from_millis(0),
      user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
      categories: vec![
        PlatformCategory::Social,
        PlatformCategory::Development,
        PlatformCategory::Gaming,
        PlatformCategory::Business,
        PlatformCategory::Creative,
        PlatformCategory::Photography,
        PlatformCategory::Video,
        PlatformCategory::Music,
        PlatformCategory::News,
        PlatformCategory::Forum,
        PlatformCategory::Dating,
        PlatformCategory::Finance,
        PlatformCategory::Crypto,
        PlatformCategory::Shopping,
        PlatformCategory::Adult,
        PlatformCategory::Other,
      ],
      skip_platforms: Vec::new(),
      extract_metadata: false,
      follow_redirects: true,
    };

    let enumerator = UsernameEnumerator::new(config);
    let result = enumerator.enumerate(username);

    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }

    let mut filtered_profiles = Vec::new();
    let mut found_count = 0;
    for profiles in result.by_category.values() {
      for profile in profiles {
        if !platform_names.iter().any(|name| {
          profile.platform.eq_ignore_ascii_case(name)
            || profile
              .platform
              .to_lowercase()
              .contains(&name.to_lowercase())
        }) {
          continue;
        }

        if profile.exists {
          found_count += 1;
        }
        filtered_profiles.push(profile);
      }
    }
    filtered_profiles.sort_by(|a, b| a.platform.cmp(&b.platform));

    let payload =
      Self::username_check_payload(username, &platform_names, &filtered_profiles, found_count);
    if render::render_machine_output(ctx, "rb recon identity username", &payload)? {
      return Ok(());
    }

    // Display results
    println!();
    Output::subheader("Results");

    for profile in filtered_profiles {
      if profile.exists {
        let url = profile.url.as_deref().unwrap_or("N/A");
        println!(
          "  \x1b[32m✓\x1b[0m {} - \x1b[36m{}\x1b[0m",
          profile.platform, url
        );
      } else if profile.error.is_some() {
        println!(
          "  \x1b[33m?\x1b[0m {} - error: {}",
          profile.platform,
          profile.error.as_ref().unwrap()
        );
      } else {
        println!("  \x1b[31m✗\x1b[0m {} - not found", profile.platform);
      }
    }

    println!();
    Output::success(&format!(
      "Found {}/{} profiles",
      found_count,
      platform_names.len()
    ));

    Ok(())
  }

  fn parse_category(cat: &str) -> Vec<PlatformCategory> {
    match cat.to_lowercase().as_str() {
      "social" => vec![PlatformCategory::Social],
      "coding" | "development" | "dev" => vec![PlatformCategory::Development],
      "gaming" | "games" => vec![PlatformCategory::Gaming],
      "business" | "professional" => vec![PlatformCategory::Business],
      "creative" | "art" => vec![PlatformCategory::Creative],
      "photo" | "photography" => vec![PlatformCategory::Photography],
      "video" => vec![PlatformCategory::Video],
      "music" => vec![PlatformCategory::Music],
      "news" => vec![PlatformCategory::News],
      "forum" => vec![PlatformCategory::Forum],
      "dating" => vec![PlatformCategory::Dating],
      "finance" => vec![PlatformCategory::Finance],
      "crypto" => vec![PlatformCategory::Crypto],
      "shopping" => vec![PlatformCategory::Shopping],
      _ => vec![PlatformCategory::Other],
    }
  }

  fn username_enumeration_payload(
    username: &str,
    category_filter: Option<&str>,
    result: &EnumerationSummary,
  ) -> Value {
    let mut found: Vec<_> = result
      .by_category
      .values()
      .flat_map(|profiles| profiles.iter())
      .filter(|profile| profile.exists)
      .collect();
    found.sort_by(|a, b| a.platform.cmp(&b.platform));
    let profiles: Vec<_> = found.into_iter().map(profile_result_to_json).collect();

    json!({
      "username": username,
      "category_filter": category_filter,
      "total_checked": result.total_checked,
      "found_count": result.found_count,
      "error_count": result.error_count,
      "duration_ms": result.duration.as_millis() as u64,
      "profiles": profiles
    })
  }

  fn username_check_payload(
    username: &str,
    platform_names: &[&str],
    filtered_profiles: &[&ProfileResult],
    found_count: usize,
  ) -> Value {
    let profiles: Vec<_> = filtered_profiles
      .iter()
      .map(|profile| {
        let status = if profile.exists {
          "found"
        } else if profile.error.is_some() {
          "error"
        } else {
          "not_found"
        };
        let mut value = profile_result_to_json(profile);
        if let Some(obj) = value.as_object().cloned() {
          let mut map = obj;
          map.insert("status".to_string(), json!(status));
          value = Value::Object(map);
        }
        value
      })
      .collect();

    json!({
      "username": username,
      "requested_platforms": platform_names.iter().map(|name| name.to_string()).collect::<Vec<_>>(),
      "checked_profiles": filtered_profiles.len(),
      "found_count": found_count,
      "profiles": profiles
    })
  }

  fn email_intel_payload(email: &str, result: &EmailResult) -> Value {
    let social_profiles: Vec<_> = result
      .social_profiles
      .iter()
      .map(profile_result_to_json)
      .collect();
    let breaches: Vec<_> = result.breaches.iter().map(email_breach_to_json).collect();

    json!({
      "email": email,
      "provider": result.provider.clone(),
      "valid": result.valid,
      "services": result.services.clone(),
      "social_profiles": social_profiles,
      "breaches": breaches
    })
  }

  fn email_breach_payload(
    target: &str,
    result: &crate::modules::recon::breach::EmailCheckResult,
  ) -> Value {
    let breaches: Vec<_> = result.breaches.iter().map(hibp_breach_to_json).collect();

    json!({
      "type": "email",
      "target_masked": format!("{}****", &target[..target.len().min(4)]),
      "pwned": result.pwned,
      "breach_count": result.breach_count,
      "breaches": breaches
    })
  }

  fn password_breach_payload(result: &crate::modules::recon::breach::PasswordCheckResult) -> Value {
    json!({
      "type": "password",
      "pwned": result.pwned,
      "count": result.count
    })
  }

  fn email_intel(&self, ctx: &CliContext) -> Result<(), String> {
    let email = ctx.target.as_ref().ok_or(
            "Missing email.\nUsage: rb recon identity email <email>\nExample: rb recon identity email user@example.com",
        )?;

    // Validate email format
    if !email.contains('@') || !email.contains('.') {
      return Err(format!("Invalid email format: {}", email));
    }

    if !ctx.wants_machine_output() {
      Output::header(&format!("Email Intelligence: {}", email));
      Output::spinner_start(&format!("Investigating {}", email));
    }

    let config = crate::modules::recon::osint::OsintConfig {
      timeout: Duration::from_secs(10),
      threads: 20,
      delay: Duration::from_millis(100),
      user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
      categories: vec![],
      skip_platforms: vec![],
      extract_metadata: true,
      follow_redirects: true,
    };

    let intel = EmailIntel::new(config);
    let result = intel.investigate(email);

    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }

    let payload = Self::email_intel_payload(email, &result);
    if render::render_machine_output(ctx, "rb recon identity email", &payload)? {
      return Ok(());
    }

    // Display results
    println!();
    Output::item("Email", email);
    Output::item(
      "Provider",
      &result
        .provider
        .clone()
        .unwrap_or_else(|| "Unknown".to_string()),
    );
    Output::item("Valid", if result.valid { "Yes" } else { "No" });
    println!();

    if !result.services.is_empty() {
      Output::subheader(&format!("Registered Services ({})", result.services.len()));
      for service in &result.services {
        println!("  \x1b[32m✓\x1b[0m {}", service);
      }
      println!();
    }

    if !result.social_profiles.is_empty() {
      Output::subheader(&format!(
        "Social Profiles ({})",
        result.social_profiles.len()
      ));
      for profile in &result.social_profiles {
        println!(
          "  • {} - \x1b[36m{}\x1b[0m",
          profile.platform,
          profile.url.as_deref().unwrap_or("N/A")
        );
      }
      println!();
    }

    if !result.breaches.is_empty() {
      Output::subheader(&format!("Breaches ({})", result.breaches.len()));
      for breach in result.breaches.iter().take(10) {
        println!("  \x1b[31m!\x1b[0m {}", breach.name);
      }
      println!();
    }

    Output::success(&format!(
      "Found {} services, {} profiles",
      result.services.len(),
      result.social_profiles.len()
    ));

    Ok(())
  }

  fn breach_check(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb recon identity breach <email|password>\nExample: rb recon identity breach password123",
        )?;

    let check_type = ctx
      .get_flag("type")
      .unwrap_or_else(|| "password".to_string());
    let hibp_key = ctx.get_flag("hibp-key");

    if !ctx.wants_machine_output() {
      Output::header("Breach Check (HIBP)");
      Output::item("Target", &format!("{}****", &target[..target.len().min(4)]));
      Output::item("Type", &check_type);
      Output::spinner_start("Checking breach databases");
    }

    let mut client = BreachClient::new();
    if let Some(key) = hibp_key {
      client.set_api_key(&key);
    }

    match check_type.as_str() {
      "email" => {
        let result = client.check_email(target);
        if !ctx.wants_machine_output() {
          Output::spinner_done();
        }
        let result = result?;

        let payload = Self::email_breach_payload(target, &result);
        if render::render_machine_output(ctx, "rb recon identity breach", &payload)? {
          return Ok(());
        }

        if result.pwned {
          Output::warning(&format!("PWNED! Found in {} breaches", result.breach_count));

          if !result.breaches.is_empty() {
            println!();
            Output::subheader("Breaches");
            for breach in result.breaches.iter().take(10) {
              println!(
                "  • {} - {} ({} accounts)",
                breach.name, breach.breach_date, breach.pwn_count
              );
            }
            if result.breaches.len() > 10 {
              Output::dim(&format!("  ... and {} more", result.breaches.len() - 10));
            }
          }
        } else {
          Output::success("Not found in known breaches");
        }
      }
      _ => {
        let result = client.check_password(target);
        if !ctx.wants_machine_output() {
          Output::spinner_done();
        }
        let result = result?;

        let payload = Self::password_breach_payload(&result);
        if render::render_machine_output(ctx, "rb recon identity breach", &payload)? {
          return Ok(());
        }

        if result.pwned {
          Output::warning(&format!(
            "PWNED! Password found {} times in breaches",
            result.count
          ));
        } else {
          Output::success("Password not found in known breaches");
        }
      }
    }

    Ok(())
  }
}

fn profile_result_to_json(
  profile: &crate::modules::recon::osint::ProfileResult,
) -> crate::serde_json::Value {
  let metadata = json!({
      "display_name": profile.metadata.display_name.clone(),
      "bio": profile.metadata.bio.clone(),
      "avatar_url": profile.metadata.avatar_url.clone(),
      "followers": profile.metadata.followers,
      "following": profile.metadata.following,
      "post_count": profile.metadata.post_count,
      "created_at": profile.metadata.created_at.clone(),
      "last_active": profile.metadata.last_active.clone(),
      "location": profile.metadata.location.clone(),
      "website": profile.metadata.website.clone(),
      "email": profile.metadata.email.clone(),
      "verified": profile.metadata.verified
  });

  json!({
      "platform": profile.platform.clone(),
      "category": format!("{:?}", profile.category),
      "exists": profile.exists,
      "url": profile.url.clone(),
      "duration_ms": profile.duration.as_millis() as u64,
      "error": profile.error.clone(),
      "metadata": metadata
  })
}

fn email_breach_to_json(
  breach: &crate::modules::recon::osint::BreachInfo,
) -> crate::serde_json::Value {
  json!({
      "name": breach.name.clone(),
      "date": breach.date.clone(),
      "accounts": breach.accounts,
      "data_types": breach.data_types.clone(),
      "description": breach.description.clone(),
      "verified": breach.verified,
      "sensitive": breach.sensitive
  })
}

fn hibp_breach_to_json(
  breach: &crate::modules::recon::breach::BreachInfo,
) -> crate::serde_json::Value {
  json!({
      "name": breach.name.clone(),
      "domain": breach.domain.clone(),
      "breach_date": breach.breach_date.clone(),
      "pwn_count": breach.pwn_count,
      "data_classes": breach.data_classes.clone()
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::modules::recon::breach::{EmailCheckResult, PasswordCheckResult};
  use crate::modules::recon::osint::{BreachInfo, ProfileMetadata};

  #[test]
  fn username_check_payload_includes_status() {
    let profile = ProfileResult {
      platform: "GitHub".to_string(),
      category: PlatformCategory::Development,
      exists: true,
      url: Some("https://github.com/johndoe".to_string()),
      metadata: ProfileMetadata::default(),
      duration: Duration::from_millis(42),
      error: None,
    };

    let payload =
      ReconIdentityCommand::username_check_payload("johndoe", &["github"], &[&profile], 1);

    assert_eq!(payload["found_count"].as_u64(), Some(1));
    assert_eq!(payload["profiles"][0]["status"].as_str(), Some("found"));
  }

  #[test]
  fn email_breach_payload_masks_target() {
    let payload = ReconIdentityCommand::email_breach_payload(
      "user@example.com",
      &EmailCheckResult {
        email: "user@example.com".to_string(),
        pwned: true,
        breach_count: 1,
        breaches: vec![crate::modules::recon::breach::BreachInfo {
          name: "Example".to_string(),
          domain: "example.com".to_string(),
          breach_date: "2024-01-01".to_string(),
          pwn_count: 10,
          data_classes: vec!["Emails".to_string()],
        }],
      },
    );

    assert_eq!(payload["type"].as_str(), Some("email"));
    assert_eq!(payload["target_masked"].as_str(), Some("user****"));
  }

  #[test]
  fn email_intel_payload_includes_services_and_breaches() {
    let payload = ReconIdentityCommand::email_intel_payload(
      "user@example.com",
      &EmailResult {
        email: "user@example.com".to_string(),
        valid: true,
        provider: Some("gmail".to_string()),
        breaches: vec![BreachInfo {
          name: "Example".to_string(),
          date: Some("2024-01-01".to_string()),
          accounts: Some(10),
          data_types: vec!["Emails".to_string()],
          description: Some("Example breach".to_string()),
          verified: true,
          sensitive: false,
        }],
        pastes: vec![],
        services: vec!["github".to_string()],
        social_profiles: vec![],
      },
    );

    assert_eq!(payload["services"][0].as_str(), Some("github"));
    assert_eq!(payload["breaches"][0]["name"].as_str(), Some("Example"));
  }

  #[test]
  fn password_breach_payload_includes_count() {
    let payload = ReconIdentityCommand::password_breach_payload(&PasswordCheckResult {
      pwned: true,
      count: 123,
    });

    assert_eq!(payload["type"].as_str(), Some("password"));
    assert_eq!(payload["count"].as_u64(), Some(123));
  }
}
