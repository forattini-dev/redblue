use crate::cli::commands::{Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::collection::browser_creds::BrowserCollector;

pub struct CollectCommand;

impl Command for CollectCommand {
    fn domain(&self) -> &str {
        "collect"
    }

    fn resource(&self) -> &str {
        "browser"
    }

    fn description(&self) -> &str {
        "Data collection from local system (browsers, secrets, etc)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "chrome",
                summary: "Collect Chrome/Chromium credentials",
                usage: "rb collect browser chrome",
            },
            Route {
                verb: "firefox",
                summary: "Collect Firefox credentials",
                usage: "rb collect browser firefox",
            },
            Route {
                verb: "all",
                summary: "Collect all browser credentials",
                usage: "rb collect browser all",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![Flag::new("output", "Output format (text, json, yaml)")
            .with_short('o')
            .with_default("text")]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Collect Chrome passwords", "rb collect browser chrome"),
            ("Collect all browser data", "rb collect browser all"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        let verb = ctx.verb.as_deref().ok_or("Missing verb")?;
        let collector = BrowserCollector::new();

        let creds = match verb {
            "chrome" => collector.collect_chrome().unwrap_or_default(),
            "firefox" => collector.collect_firefox().unwrap_or_default(),
            "all" => collector.collect(),
            _ => return Err(format!("Unknown browser type: {}", verb)),
        };

        if is_json {
            println!("{{");
            println!("  \"browser\": \"{}\",", verb);
            println!("  \"total\": {},", creds.len());
            println!("  \"credentials\": [");
            for (i, cred) in creds.iter().enumerate() {
                let comma = if i < creds.len() - 1 { "," } else { "" };
                let pwd = cred.password.as_deref().unwrap_or("");
                println!("    {{");
                println!(
                    "      \"browser\": \"{}\",",
                    cred.browser.replace('"', "\\\"")
                );
                println!("      \"url\": \"{}\",", cred.url.replace('"', "\\\""));
                println!(
                    "      \"username\": \"{}\",",
                    cred.username.replace('"', "\\\"")
                );
                println!("      \"password\": \"{}\"", pwd.replace('"', "\\\""));
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        if creds.is_empty() {
            Output::info("No credentials found.");
            return Ok(());
        }

        Output::success(&format!("Found {} credentials", creds.len()));
        println!();
        println!(
            "{:<15} {:<30} {:<30} {:<20}",
            "BROWSER", "URL", "USERNAME", "PASSWORD"
        );
        println!("{}", "-".repeat(100));

        for cred in creds {
            let pwd = cred.password.as_deref().unwrap_or("[EMPTY]");
            println!(
                "{:<15} {:<30} {:<30} {:<20}",
                cred.browser,
                cred.url.chars().take(28).collect::<String>(),
                cred.username.chars().take(28).collect::<String>(),
                pwd.chars().take(20).collect::<String>()
            );
        }

        Ok(())
    }
}

// Extension methods for BrowserCollector to access private methods if needed,
// or I can modify BrowserCollector to be more public.
// Note: BrowserCollector::collect_chrome/firefox are private in the file I read.
// I need to make them public in src/modules/collection/browser_creds.rs
