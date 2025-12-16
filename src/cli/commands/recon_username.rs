/// Username OSINT command - Search username across 1000+ platforms
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::recon::osint::{
    platforms::get_all_platforms, OsintConfig, PlatformCategory, UsernameEnumerator,
};
use std::time::Duration;

pub struct ReconUsernameCommand;

impl Command for ReconUsernameCommand {
    fn domain(&self) -> &str {
        "recon"
    }

    fn resource(&self) -> &str {
        "username"
    }

    fn description(&self) -> &str {
        "Search username across 1000+ platforms (sherlock/maigret-style)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "search",
                summary: "Search username across platforms",
                usage: "rb recon username search <username> [--category social|coding|gaming]",
            },
            Route {
                verb: "check",
                summary: "Quick check on specific platforms",
                usage: "rb recon username check <username> --platforms github,twitter,linkedin",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new(
                "category",
                "Filter by category (social, coding, gaming, professional, etc.)",
            )
            .with_short('c'),
            Flag::new("platforms", "Specific platforms to check (comma-separated)").with_short('p'),
            Flag::new("threads", "Number of concurrent threads").with_default("20"),
            Flag::new("timeout", "Timeout per request in ms").with_default("5000"),
            Flag::new("max-sites", "Maximum sites to check").with_default("100"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Search all platforms", "rb recon username search johndoe"),
            (
                "Search social sites only",
                "rb recon username search johndoe --category social",
            ),
            (
                "Search coding sites only",
                "rb recon username search johndoe --category coding",
            ),
            (
                "Search gaming sites only",
                "rb recon username search johndoe --category gaming",
            ),
            (
                "Limit number of sites",
                "rb recon username search johndoe --max-sites 50",
            ),
            (
                "Quick check specific platforms",
                "rb recon username check johndoe --platforms github,twitter",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        // Handle bare command: `rb recon username johndoe` -> treat as search
        let verb = ctx.verb.as_deref();

        match verb {
            Some("search") => self.search(ctx),
            Some("check") => self.check(ctx),
            None => {
                // If no verb but there's a target, treat as search
                if ctx.target.is_some() {
                    self.search(ctx)
                } else {
                    print_help(self);
                    Err("No username provided".to_string())
                }
            }
            Some(unknown) => {
                // Maybe the "verb" is actually the username (bare usage)
                // `rb recon username johndoe` -> verb="johndoe", target=None
                // In this case, treat verb as the username
                self.search_with_username(ctx, unknown)
            }
        }
    }
}

impl ReconUsernameCommand {
    fn search(&self, ctx: &CliContext) -> Result<(), String> {
        let username = ctx.target.as_ref().ok_or(
            "Missing username.\nUsage: rb recon username search <username>\nExample: rb recon username search johndoe",
        )?;

        self.search_with_username(ctx, username)
    }

    fn search_with_username(&self, ctx: &CliContext, username: &str) -> Result<(), String> {
        let category_filter = ctx.get_flag("category");
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
            .unwrap_or(0); // 0 = no limit

        // Build category list
        let categories = if let Some(cat) = &category_filter {
            Self::parse_category(cat)
        } else {
            // All categories by default
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

        let enumerator = UsernameEnumerator::new(config);
        let result = enumerator.enumerate(username);

        Output::spinner_done();

        // Check for JSON output
        let format = ctx.get_output_format();
        if format == crate::cli::format::OutputFormat::Json {
            let found: Vec<_> = result
                .by_category
                .values()
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
                println!(
                    "      \"url\": \"{}\"",
                    profile.url.as_ref().unwrap_or(&String::new())
                );
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

    fn check(&self, ctx: &CliContext) -> Result<(), String> {
        let username = ctx.target.as_ref().ok_or(
            "Missing username.\nUsage: rb recon username check <username> --platforms github,twitter",
        )?;

        let platforms_str = ctx.get_flag("platforms").ok_or(
            "Missing --platforms flag.\nUsage: rb recon username check <username> --platforms github,twitter,linkedin",
        )?;

        let platform_names: Vec<&str> = platforms_str.split(',').map(|s| s.trim()).collect();

        Output::header(&format!("Username Check: {}", username));
        Output::item("Platforms", &platform_names.join(", "));

        Output::spinner_start(&format!(
            "Checking {} on {} platforms",
            username,
            platform_names.len()
        ));

        // Filter platforms by name from the full list
        let all_platforms = get_all_platforms();
        let filtered: Vec<_> = all_platforms
            .into_iter()
            .filter(|p| {
                platform_names.iter().any(|name| {
                    p.name.eq_ignore_ascii_case(name)
                        || p.name.to_lowercase().contains(&name.to_lowercase())
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

        Output::spinner_done();

        // Display results
        println!();
        Output::subheader("Results");

        let mut found_count = 0;
        for profiles in result.by_category.values() {
            for profile in profiles {
                // Only show if it matches one of the requested platforms
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
        }

        println!();
        Output::success(&format!(
            "Found {}/{} profiles",
            found_count,
            platform_names.len()
        ));

        Ok(())
    }
}
