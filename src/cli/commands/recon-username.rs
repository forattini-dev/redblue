/// Username OSINT command - Search username across platforms
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::recon::username::UsernameSearcher;

pub struct ReconUsernameCommand;

impl Command for ReconUsernameCommand {
    fn domain(&self) -> &str {
        "recon"
    }

    fn resource(&self) -> &str {
        "username"
    }

    fn description(&self) -> &str {
        "Search username across 100+ platforms (WhatsMyName-style)"
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
            Flag::new("category", "Filter by category (social, coding, gaming, professional, etc.)")
                .with_short('c'),
            Flag::new("platforms", "Specific platforms to check (comma-separated)")
                .with_short('p'),
            Flag::new("threads", "Number of concurrent threads")
                .with_default("20"),
            Flag::new("timeout", "Timeout per request in ms")
                .with_default("5000"),
            Flag::new("max-sites", "Maximum sites to check")
                .with_default("100"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Search all platforms", "rb recon username search johndoe"),
            ("Search social sites only", "rb recon username search johndoe --category social"),
            ("Search coding sites only", "rb recon username search johndoe --category coding"),
            ("Search gaming sites only", "rb recon username search johndoe --category gaming"),
            ("Limit number of sites", "rb recon username search johndoe --max-sites 50"),
            ("Quick check specific platforms", "rb recon username check johndoe --platforms github,twitter"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        // Handle bare command: `rb recon username johndoe` -> treat as search
        let verb = ctx.verb.as_ref().map(|s| s.as_str());

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
        let category = ctx.get_flag("category");
        let threads: usize = ctx
            .get_flag("threads")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);
        let timeout: u64 = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5000);
        let max_sites: usize = ctx
            .get_flag("max-sites")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        Output::header(&format!("Username Search: {}", username));

        if let Some(cat) = &category {
            Output::item("Category Filter", cat);
        }

        Output::spinner_start(&format!("Searching {} across platforms", username));

        let searcher = UsernameSearcher::new()
            .with_threads(threads)
            .with_timeout(timeout)
            .with_max_sites(max_sites);

        let result = if let Some(cat) = category {
            searcher.search_categories(username, &[cat.as_str()])
        } else {
            searcher.search(username)
        };

        Output::spinner_done();

        // Check for JSON output
        let format = ctx.get_output_format();
        if format == crate::cli::format::OutputFormat::Json {
            let found: Vec<_> = result.results.iter().filter(|r| r.found).collect();
            println!("{{");
            println!("  \"username\": \"{}\",", result.username);
            println!("  \"total_sites\": {},", result.total_sites);
            println!("  \"found_count\": {},", result.found_count);
            println!("  \"profiles\": [");
            for (i, profile) in found.iter().enumerate() {
                println!("    {{");
                println!("      \"platform\": \"{}\",", profile.site_name);
                println!("      \"category\": \"{}\",", profile.category);
                println!("      \"url\": \"{}\"", profile.url);
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
        Output::item("Username", &result.username);
        Output::item("Sites Checked", &format!("{}", result.total_sites));
        Output::item("Profiles Found", &format!("{}", result.found_count));
        println!();

        if result.found_count == 0 {
            Output::warning("No profiles found for this username");
            return Ok(());
        }

        // Group by category
        let mut categories: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
        for profile in result.results.iter().filter(|r| r.found) {
            categories
                .entry(profile.category.clone())
                .or_default()
                .push(profile);
        }

        for (category, profiles) in &categories {
            Output::subheader(&format!("{} ({})", Self::capitalize(category), profiles.len()));
            for profile in profiles {
                println!(
                    "  \x1b[32m✓\x1b[0m {} - \x1b[36m{}\x1b[0m",
                    profile.site_name, profile.url
                );
            }
            println!();
        }

        Output::success(&format!(
            "Found {} profiles across {} categories",
            result.found_count,
            categories.len()
        ));

        Ok(())
    }

    fn check(&self, ctx: &CliContext) -> Result<(), String> {
        let username = ctx.target.as_ref().ok_or(
            "Missing username.\nUsage: rb recon username check <username> --platforms github,twitter",
        )?;

        let platforms_str = ctx.get_flag("platforms").ok_or(
            "Missing --platforms flag.\nUsage: rb recon username check <username> --platforms github,twitter,linkedin",
        )?;

        let platforms: Vec<&str> = platforms_str.split(',').map(|s| s.trim()).collect();

        Output::header(&format!("Username Check: {}", username));
        Output::item("Platforms", &platforms.join(", "));

        Output::spinner_start(&format!("Checking {} on {} platforms", username, platforms.len()));

        // Use the check_platform function for quick checks
        let mut found_count = 0;
        let mut results = Vec::new();

        for platform in &platforms {
            if let Some(profile) = crate::modules::recon::social::check_platform(platform, username) {
                results.push((platform.to_string(), profile.found, profile.url));
                if profile.found {
                    found_count += 1;
                }
            }
        }

        Output::spinner_done();

        println!();
        Output::subheader("Results");
        for (platform, found, url) in &results {
            if *found {
                println!("  \x1b[32m✓\x1b[0m {} - \x1b[36m{}\x1b[0m", platform, url);
            } else {
                println!("  \x1b[31m✗\x1b[0m {} - not found", platform);
            }
        }

        println!();
        Output::success(&format!(
            "Found {}/{} profiles",
            found_count,
            platforms.len()
        ));

        Ok(())
    }

    fn capitalize(s: &str) -> String {
        let mut chars = s.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }
}
