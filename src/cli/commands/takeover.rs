use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::cloud::takeover::{Confidence, TakeoverChecker, TakeoverResult};

pub struct TakeoverCommand;

impl Command for TakeoverCommand {
    fn domain(&self) -> &str {
        "cloud"
    }

    fn resource(&self) -> &str {
        "asset"
    }

    fn description(&self) -> &str {
        "Subdomain takeover detection (CNAME hijacking)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "takeover",
                summary: "Check single domain for takeover vulnerability",
                usage: "rb cloud asset takeover <domain>",
            },
            Route {
                verb: "takeover-scan",
                summary: "Scan multiple subdomains for takeover",
                usage: "rb cloud asset takeover-scan --wordlist subdomains.txt",
            },
            Route {
                verb: "services",
                summary: "List vulnerable service fingerprints",
                usage: "rb cloud asset services",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("wordlist", "File containing list of domains to check")
                .with_short('w')
                .with_arg("FILE"),
            Flag::new("confidence", "Minimum confidence level (high|medium|low)")
                .with_short('c')
                .with_arg("LEVEL"),
            Flag::new("format", "Output format (text, json)")
                .with_short('f')
                .with_default("text"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Check single domain",
                "rb cloud asset takeover subdomain.example.com",
            ),
            (
                "Scan from wordlist",
                "rb cloud asset takeover-scan --wordlist subs.txt",
            ),
            ("List services", "rb cloud asset services"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "takeover" => self.check_single(ctx),
            "takeover-scan" => self.scan_bulk(ctx),
            "services" => self.list_services(ctx),
            _ => {
                print_help(self);
                Err(format!("Invalid verb: {}", verb))
            }
        }
    }
}

impl TakeoverCommand {
    /// Check a single domain for takeover vulnerability
    fn check_single(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";
        let domain = ctx.target.as_ref().ok_or(
            "Missing domain. Usage: rb cloud asset takeover <domain> Example: rb cloud asset takeover subdomain.example.com"
        )?;

        let checker = TakeoverChecker::new();

        if !is_json {
            Output::header("Subdomain Takeover Checker");
            Output::item("Domain", domain);
            println!();
            Output::spinner_start(&format!("Checking {}", domain));
        }

        let result = checker.check(domain)?;

        if !is_json {
            Output::spinner_done();
        }

        if is_json {
            self.print_result_json(&result);
            return Ok(());
        }

        self.display_result(&result);

        Ok(())
    }

    /// Print single result as JSON
    fn print_result_json(&self, result: &TakeoverResult) {
        let confidence_str = match result.confidence {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
            Confidence::None => "none",
        };
        println!("{{");
        println!("  \"domain\": \"{}\",", result.domain.replace('"', "\\\""));
        println!("  \"vulnerable\": {},", result.vulnerable);
        println!("  \"confidence\": \"{}\",", confidence_str);
        if let Some(ref cname) = result.cname {
            println!("  \"cname\": \"{}\",", cname.replace('"', "\\\""));
        } else {
            println!("  \"cname\": null,");
        }
        if let Some(ref service) = result.service {
            println!("  \"service\": \"{}\",", service.replace('"', "\\\""));
        } else {
            println!("  \"service\": null,");
        }
        println!("  \"message\": \"{}\"", result.message.replace('"', "\\\""));
        println!("}}");
    }

    /// Scan multiple domains from a wordlist
    fn scan_bulk(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";
        let wordlist_path = ctx
            .get_flag("wordlist")
            .ok_or("Missing wordlist. Usage: rb cloud asset takeover-scan --wordlist subs.txt")?;

        // Read wordlist
        use std::fs;
        let wordlist_content = fs::read_to_string(&wordlist_path)
            .map_err(|e| format!("Failed to read wordlist: {}", e))?;

        let domains: Vec<String> = wordlist_content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect();

        let checker = TakeoverChecker::new();

        if !is_json {
            Output::header("Bulk Subdomain Takeover Scan");
            Output::item("Wordlist", &wordlist_path);
            Output::item("Total domains", &domains.len().to_string());
            println!();
            Output::spinner_start(&format!("Scanning {} domains", domains.len()));
        }

        let results = checker.check_bulk(&domains);

        if !is_json {
            Output::spinner_done();
        }

        if is_json {
            self.print_bulk_results_json(&results, ctx);
            return Ok(());
        }

        self.display_bulk_results(&results, ctx);

        Ok(())
    }

    /// Print bulk results as JSON
    fn print_bulk_results_json(&self, results: &[TakeoverResult], ctx: &CliContext) {
        let stats = TakeoverChecker::get_stats(results);

        // Filter by confidence level if specified
        let min_confidence = ctx
            .get_flag("confidence")
            .unwrap_or_else(|| "low".to_string());

        let filtered: Vec<_> = results
            .iter()
            .filter(|r| r.vulnerable)
            .filter(|r| match min_confidence.as_str() {
                "high" => r.confidence == Confidence::High,
                "medium" => r.confidence == Confidence::High || r.confidence == Confidence::Medium,
                _ => true,
            })
            .collect();

        println!("{{");
        println!("  \"total\": {},", stats.get("total").unwrap_or(&0));
        println!(
            "  \"vulnerable\": {},",
            stats.get("vulnerable").unwrap_or(&0)
        );
        println!(
            "  \"high_confidence\": {},",
            stats.get("high_confidence").unwrap_or(&0)
        );
        println!(
            "  \"medium_confidence\": {},",
            stats.get("medium_confidence").unwrap_or(&0)
        );
        println!(
            "  \"low_confidence\": {},",
            stats.get("low_confidence").unwrap_or(&0)
        );
        println!("  \"min_confidence_filter\": \"{}\",", min_confidence);
        println!("  \"results\": [");
        for (i, result) in filtered.iter().enumerate() {
            let confidence_str = match result.confidence {
                Confidence::High => "high",
                Confidence::Medium => "medium",
                Confidence::Low => "low",
                Confidence::None => "none",
            };
            let comma = if i < filtered.len() - 1 { "," } else { "" };
            println!("    {{");
            println!(
                "      \"domain\": \"{}\",",
                result.domain.replace('"', "\\\"")
            );
            println!("      \"vulnerable\": {},", result.vulnerable);
            println!("      \"confidence\": \"{}\",", confidence_str);
            if let Some(ref cname) = result.cname {
                println!("      \"cname\": \"{}\",", cname.replace('"', "\\\""));
            } else {
                println!("      \"cname\": null,");
            }
            if let Some(ref service) = result.service {
                println!("      \"service\": \"{}\",", service.replace('"', "\\\""));
            } else {
                println!("      \"service\": null,");
            }
            println!(
                "      \"message\": \"{}\"",
                result.message.replace('"', "\\\"")
            );
            println!("    }}{}", comma);
        }
        println!("  ]");
        println!("}}");
    }

    /// List all supported vulnerable services
    fn list_services(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let checker = TakeoverChecker::new();
        let services = checker.list_services();

        if is_json {
            println!("{{");
            println!("  \"total\": {},", services.len());
            println!("  \"services\": [");
            for (i, service) in services.iter().enumerate() {
                let comma = if i < services.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", service.replace('"', "\\\""), comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        Output::header("Supported Vulnerable Services");
        println!();

        Output::subheader(&format!("Total Services: {}", services.len()));
        println!();

        for (i, service) in services.iter().enumerate() {
            println!("  {}. {}", i + 1, Output::colorize(service, "cyan"));
        }

        println!();
        Output::info("These services are checked for subdomain takeover vulnerabilities");

        Ok(())
    }

    /// Display a single takeover result
    fn display_result(&self, result: &TakeoverResult) {
        println!();

        if let Some(cname) = &result.cname {
            Output::item("CNAME", cname);
        }

        match result.confidence {
            Confidence::High => {
                Output::warning("⚠️  VULNERABLE - High Confidence");
                Output::warning(&format!(
                    "   Service: {}",
                    result.service.as_deref().unwrap_or("Unknown")
                ));
                Output::warning(&format!("   {}", result.message));
                println!();
                Output::warning("🚨 ACTION REQUIRED:");
                Output::warning("   1. Verify the vulnerability manually");
                Output::warning("   2. Remove the CNAME record OR claim the service");
                Output::warning("   3. Monitor for unauthorized changes");
            }
            Confidence::Medium => {
                Output::warning("⚠️  POTENTIALLY VULNERABLE - Medium Confidence");
                Output::warning(&format!(
                    "   Service: {}",
                    result.service.as_deref().unwrap_or("Unknown")
                ));
                Output::warning(&format!("   {}", result.message));
                println!();
                Output::info("Recommendation: Verify manually by checking HTTP response");
            }
            Confidence::Low => {
                Output::warning("⚠️  DEAD DNS - Low Confidence");
                Output::warning(&format!("   {}", result.message));
                println!();
                Output::info("Recommendation: Check if the CNAME target exists");
            }
            Confidence::None => {
                Output::success("✓ Not vulnerable");
                Output::item("Status", &result.message);
            }
        }
    }

    /// Display bulk scan results
    fn display_bulk_results(&self, results: &[TakeoverResult], ctx: &CliContext) {
        println!();

        // Get statistics
        let stats = TakeoverChecker::get_stats(results);

        Output::subheader("Scan Summary");
        Output::item(
            "Total domains",
            &stats.get("total").unwrap_or(&0).to_string(),
        );
        Output::item(
            "Vulnerable",
            &stats.get("vulnerable").unwrap_or(&0).to_string(),
        );
        Output::item(
            "High confidence",
            &stats.get("high_confidence").unwrap_or(&0).to_string(),
        );
        Output::item(
            "Medium confidence",
            &stats.get("medium_confidence").unwrap_or(&0).to_string(),
        );
        Output::item(
            "Low confidence",
            &stats.get("low_confidence").unwrap_or(&0).to_string(),
        );

        // Filter by confidence level if specified
        let min_confidence = ctx
            .get_flag("confidence")
            .unwrap_or_else(|| "low".to_string());

        let filtered: Vec<_> = results
            .iter()
            .filter(|r| r.vulnerable)
            .filter(|r| match min_confidence.as_str() {
                "high" => r.confidence == Confidence::High,
                "medium" => r.confidence == Confidence::High || r.confidence == Confidence::Medium,
                _ => true, // "low" or any other value shows all
            })
            .collect();

        if !filtered.is_empty() {
            println!();
            Output::warning(&format!("⚠️  {} VULNERABLE DOMAINS FOUND:", filtered.len()));
            println!();

            for result in filtered {
                let confidence_str = match result.confidence {
                    Confidence::High => "🔴 HIGH",
                    Confidence::Medium => "🟡 MEDIUM",
                    Confidence::Low => "🟢 LOW",
                    Confidence::None => "NONE",
                };

                println!(
                    "  {} | {} | {}",
                    Output::colorize(&result.domain, "blue"),
                    confidence_str,
                    result.service.as_deref().unwrap_or("Unknown")
                );

                if let Some(cname) = &result.cname {
                    println!("    CNAME: {}", cname);
                }
                println!("    {}", result.message);
                println!();
            }

            Output::warning("🚨 SECURITY ALERT: Subdomain takeover vulnerabilities detected!");
            Output::warning("   Review each finding and take appropriate action");
        } else {
            println!();
            Output::success("✓ No vulnerabilities found at specified confidence level");
        }
    }
}
