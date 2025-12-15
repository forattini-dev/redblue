/// Identity OSINT command - Username and email reconnaissance
///
/// Consolidates person/identity OSINT:
/// - Username enumeration (sherlock/maigret-style)
/// - Email intelligence (holehe-style)
/// - Breach checking
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::recon::osint::{
    UsernameEnumerator, OsintConfig, PlatformCategory,
    platforms::get_all_platforms,
    EmailIntel,
};
use crate::modules::recon::breach::BreachClient;
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
            Flag::new("category", "Filter by category (social, coding, gaming, professional, etc.)")
                .with_short('c'),
            Flag::new("platforms", "Specific platforms to check (comma-separated)")
                .with_short('p'),
            Flag::new("threads", "Number of concurrent threads")
                .with_default("50"),
            Flag::new("timeout", "Timeout per request in ms")
                .with_default("10000"),
            Flag::new("max-sites", "Maximum sites to check (0 = unlimited)")
                .with_default("0"),
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
            ("Search username across all platforms", "rb recon identity username johndoe"),
            ("Search social sites only", "rb recon identity username johndoe --category social"),
            ("Search coding sites only", "rb recon identity username johndoe --category coding"),
            ("Search gaming sites only", "rb recon identity username johndoe --category gaming"),
            ("Limit number of sites", "rb recon identity username johndoe --max-sites 100"),
            ("Check specific platforms", "rb recon identity username johndoe --platforms github,twitter"),
            // Email examples
            ("Email intelligence", "rb recon identity email user@example.com"),
            // Breach examples
            ("Check password breach", "rb recon identity breach password123"),
            ("Check email breach", "rb recon identity breach user@example.com --type email --hibp-key KEY"),
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
                Err(format!("Unknown verb '{}'. Valid: username, email, breach", verb))
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
        let mut platform_count = all_platforms.iter()
            .filter(|p| categories.contains(&p.category))
            .count();

        // Apply max_sites limit
        if max_sites > 0 && max_sites < platform_count {
            platform_count = max_sites;
        }

        Output::header(&format!("Username Search: {}", username));

        if let Some(cat) = &category_filter {
            Output::item("Category Filter", cat);
        }
        Output::item("Platforms", &format!("{}", platform_count));
        Output::item("Threads", &format!("{}", threads));

        Output::spinner_start(&format!("Searching {} across {} platforms", username, platform_count));

        let enumerator = UsernameEnumerator::new(config);
        let result = enumerator.enumerate(username);

        Output::spinner_done();

        // Check for JSON output
        let format = ctx.get_output_format();
        if format == crate::cli::format::OutputFormat::Json {
            let found: Vec<_> = result.by_category.values()
                .flat_map(|v| v.iter())
                .filter(|r| r.exists)
                .collect();
            println!("{{");
            println!("  \"username\": \"{}\",", username);
            println!("  \"total_checked\": {},", result.total_checked);
            println!("  \"found_count\": {},", result.found_count);
            println!("  \"error_count\": {},", result.error_count);
            println!("  \"duration_ms\": {},", result.duration.as_millis());
            println!("  \"profiles\": [");
            for (i, profile) in found.iter().enumerate() {
                println!("    {{");
                println!("      \"platform\": \"{}\",", profile.platform);
                println!("      \"category\": \"{:?}\",", profile.category);
                println!("      \"url\": \"{}\"", profile.url.as_ref().unwrap_or(&String::new()));
                if i < found.len() - 1 {
                    println!("    }},");
                } else {
                    println!("    }}");
                }
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // Display results
        println!();
        Output::item("Username", username);
        Output::item("Platforms Checked", &format!("{}", result.total_checked));
        Output::item("Profiles Found", &format!("{}", result.found_count));
        Output::item("Errors", &format!("{}", result.error_count));
        Output::item("Duration", &format!("{:.2}s", result.duration.as_secs_f64()));
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
                let url = profile.url.as_ref().map(|s| s.as_str()).unwrap_or("N/A");
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

    fn username_check(&self, ctx: &CliContext, username: &str, platforms_str: &str) -> Result<(), String> {
        let platform_names: Vec<&str> = platforms_str.split(',').map(|s| s.trim()).collect();

        Output::header(&format!("Username Check: {}", username));
        Output::item("Platforms", &platform_names.join(", "));

        Output::spinner_start(&format!("Checking {} on {} platforms", username, platform_names.len()));

        // Filter platforms by name from the full list
        let all_platforms = get_all_platforms();
        let filtered: Vec<_> = all_platforms.into_iter()
            .filter(|p| platform_names.iter().any(|name|
                p.name.eq_ignore_ascii_case(name) ||
                p.name.to_lowercase().contains(&name.to_lowercase())
            ))
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

        Output::spinner_done();

        // Display results
        println!();
        Output::subheader("Results");

        let mut found_count = 0;
        for profiles in result.by_category.values() {
            for profile in profiles {
                if !platform_names.iter().any(|name|
                    profile.platform.eq_ignore_ascii_case(name) ||
                    profile.platform.to_lowercase().contains(&name.to_lowercase())
                ) {
                    continue;
                }

                if profile.exists {
                    found_count += 1;
                    let url = profile.url.as_ref().map(|s| s.as_str()).unwrap_or("N/A");
                    println!("  \x1b[32m✓\x1b[0m {} - \x1b[36m{}\x1b[0m", profile.platform, url);
                } else if profile.error.is_some() {
                    println!("  \x1b[33m?\x1b[0m {} - error: {}", profile.platform, profile.error.as_ref().unwrap());
                } else {
                    println!("  \x1b[31m✗\x1b[0m {} - not found", profile.platform);
                }
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

    fn email_intel(&self, ctx: &CliContext) -> Result<(), String> {
        let email = ctx.target.as_ref().ok_or(
            "Missing email.\nUsage: rb recon identity email <email>\nExample: rb recon identity email user@example.com",
        )?;

        // Validate email format
        if !email.contains('@') || !email.contains('.') {
            return Err(format!("Invalid email format: {}", email));
        }

        Output::header(&format!("Email Intelligence: {}", email));
        Output::spinner_start(&format!("Investigating {}", email));

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

        Output::spinner_done();

        // Display results
        println!();
        Output::item("Email", email);
        Output::item("Provider", &result.provider.clone().unwrap_or_else(|| "Unknown".to_string()));
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
            Output::subheader(&format!("Social Profiles ({})", result.social_profiles.len()));
            for profile in &result.social_profiles {
                println!("  • {} - \x1b[36m{}\x1b[0m", profile.platform, profile.url.as_deref().unwrap_or("N/A"));
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

        let check_type = ctx.get_flag("type").unwrap_or_else(|| "password".to_string());
        let hibp_key = ctx.get_flag("hibp-key");

        Output::header("Breach Check (HIBP)");
        Output::item("Target", &format!("{}****", &target[..target.len().min(4)]));
        Output::item("Type", &check_type);

        Output::spinner_start("Checking breach databases");

        let mut client = BreachClient::new();
        if let Some(key) = hibp_key {
            client.set_api_key(&key);
        }

        Output::spinner_done();

        match check_type.as_str() {
            "email" => {
                let result = client.check_email(target)?;
                if result.pwned {
                    Output::warning(&format!(
                        "PWNED! Found in {} breaches",
                        result.breach_count
                    ));

                    if !result.breaches.is_empty() {
                        println!();
                        Output::subheader("Breaches");
                        for breach in result.breaches.iter().take(10) {
                            println!("  • {} - {} ({} accounts)", breach.name, breach.breach_date, breach.pwn_count);
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
                let result = client.check_password(target)?;
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
