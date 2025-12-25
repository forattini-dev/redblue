/// Port Health Check CLI Command
///
/// Re-scans stored ports to detect state changes over time.
/// Commands: check, diff, watch
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::network::health::{
    PortCheckResult, PortDiff, PortHealthChecker, PortWatcher, WatchConfig,
};
use std::time::Duration;

pub struct HealthCommand;

impl Command for HealthCommand {
    fn domain(&self) -> &str {
        "network"
    }

    fn resource(&self) -> &str {
        "health"
    }

    fn description(&self) -> &str {
        "Port health monitoring - re-scan ports to detect state changes"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "check",
                summary: "Check health of specific ports on a target",
                usage: "rb network health check <target> [--ports 22,80,443] [--timeout 1000]",
            },
            Route {
                verb: "diff",
                summary: "Compare current port states with previous scan from database",
                usage: "rb network health diff <target> [--db <file>]",
            },
            Route {
                verb: "watch",
                summary: "Continuously monitor ports and alert on changes",
                usage: "rb network health watch <target> [--ports 22,80,443] [--interval 60]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("output", "Output format (text, json, yaml)")
                .with_short('o')
                .with_default("text"),
            Flag::new("ports", "Comma-separated list of ports to check")
                .with_short('p')
                .with_default("22,80,443,8080,8443"),
            Flag::new("timeout", "Connection timeout in milliseconds")
                .with_short('t')
                .with_default("1000"),
            Flag::new("threads", "Number of concurrent threads")
                .with_short('T')
                .with_default("50"),
            Flag::new("interval", "Watch interval in seconds")
                .with_short('i')
                .with_default("60"),
            Flag::new("count", "Number of watch iterations (0 = infinite)")
                .with_short('c')
                .with_default("0"),
            Flag::new("db", "Database file to compare against"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Check common ports", "rb network health check 192.168.1.1"),
            (
                "Check specific ports",
                "rb network health check example.com --ports 22,80,443,8080",
            ),
            (
                "Fast check with short timeout",
                "rb network health check 10.0.0.1 --timeout 500",
            ),
            (
                "Check ports as JSON",
                "rb network health check 192.168.1.1 --output=json",
            ),
            (
                "Watch ports continuously",
                "rb network health watch 192.168.1.1 --interval 30",
            ),
            (
                "Watch with limited iterations",
                "rb network health watch server.local --count 10",
            ),
            (
                "Watch with JSON output",
                "rb network health watch 192.168.1.1 --output=json --count 5",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "check" => self.check(ctx),
            "diff" => self.diff(ctx),
            "watch" => self.watch(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(verb, &["check", "diff", "watch"])
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl HealthCommand {
    /// Parse ports from comma-separated string
    fn parse_ports(ports_str: &str) -> Vec<u16> {
        ports_str
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    }

    /// Check health of specific ports
    fn check(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network health check <HOST> [--ports 22,80,443]\nExample: rb network health check 192.168.1.1",
        )?;

        Validator::validate_host(target)?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        let ports_str = ctx
            .flags
            .get("ports")
            .map(|s| s.as_str())
            .unwrap_or("22,80,443,8080,8443");
        let ports = Self::parse_ports(ports_str);

        if ports.is_empty() {
            return Err("No valid ports specified".to_string());
        }

        let timeout_ms = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1000);

        let threads = ctx
            .flags
            .get("threads")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(50);

        if !is_json {
            Output::header(&format!("Port Health Check: {}", target));
            Output::info(&format!(
                "Checking {} ports (timeout: {}ms, threads: {})",
                ports.len(),
                timeout_ms,
                threads
            ));
            println!();
        }

        let checker = PortHealthChecker::new()
            .with_timeout(Duration::from_millis(timeout_ms))
            .with_threads(threads);

        if !is_json {
            Output::spinner_start("Scanning ports");
        }
        let results = checker.check_ports(target, &ports);
        if !is_json {
            Output::spinner_done();
        }

        // Display results
        if is_json {
            self.display_check_results_json(target, &results, timeout_ms, threads);
        } else {
            self.display_check_results(&results);
        }

        Ok(())
    }

    /// Display check results
    fn display_check_results(&self, results: &[PortCheckResult]) {
        let open_count = results.iter().filter(|r| r.is_open).count();
        let closed_count = results.len() - open_count;

        Output::section("Port Status");
        println!(
            "  Open:   {} | Closed: {}",
            Output::colorize(&open_count.to_string(), "green"),
            Output::colorize(&closed_count.to_string(), "red")
        );
        println!();

        // Open ports
        if open_count > 0 {
            Output::section("Open Ports");
            for result in results.iter().filter(|r| r.is_open) {
                let service = result.service.as_deref().unwrap_or("-");
                println!(
                    "  {} {} {} ({}ms)",
                    Output::colorize("OPEN", "green"),
                    Output::colorize(&result.port.to_string(), "cyan"),
                    service,
                    result.response_time_ms
                );
            }
            println!();
        }

        // Closed ports (summary)
        if closed_count > 0 {
            Output::section("Closed Ports");
            let closed_ports: Vec<String> = results
                .iter()
                .filter(|r| !r.is_open)
                .map(|r| r.port.to_string())
                .collect();
            println!("  {}", closed_ports.join(", "));
            println!();
        }
    }

    /// Display check results as JSON
    fn display_check_results_json(
        &self,
        target: &str,
        results: &[PortCheckResult],
        timeout_ms: u64,
        threads: usize,
    ) {
        let open_count = results.iter().filter(|r| r.is_open).count();
        let closed_count = results.len() - open_count;

        println!("{{");
        println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
        println!("  \"timeout_ms\": {},", timeout_ms);
        println!("  \"threads\": {},", threads);
        println!("  \"total_ports\": {},", results.len());
        println!("  \"open_count\": {},", open_count);
        println!("  \"closed_count\": {},", closed_count);
        println!("  \"open_ports\": [");

        let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();
        for (i, result) in open_ports.iter().enumerate() {
            let comma = if i < open_ports.len() - 1 { "," } else { "" };
            let service = result
                .service
                .as_ref()
                .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                .unwrap_or_else(|| "null".to_string());
            println!(
                "    {{\"port\": {}, \"service\": {}, \"response_time_ms\": {}}}{}",
                result.port, service, result.response_time_ms, comma
            );
        }

        println!("  ],");
        println!("  \"closed_ports\": [");

        let closed_ports: Vec<_> = results.iter().filter(|r| !r.is_open).collect();
        for (i, result) in closed_ports.iter().enumerate() {
            let comma = if i < closed_ports.len() - 1 { "," } else { "" };
            println!("    {}{}", result.port, comma);
        }

        println!("  ]");
        println!("}}");
    }

    /// Compare current scan with previous scan from database
    fn diff(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network health diff <HOST> [--db <file>]\nExample: rb network health diff 192.168.1.1",
        )?;

        Validator::validate_host(target)?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        if is_json {
            println!("{{");
            println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
            println!("  \"status\": \"not_implemented\",");
            println!("  \"message\": \"Database integration not yet implemented\",");
            println!("  \"suggestions\": [");
            println!("    \"Use 'rb network health check' to scan ports first\",");
            println!("    \"Use 'rb network health watch' for continuous monitoring\"");
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // For now, show a placeholder until we integrate with storage
        Output::header(&format!("Port Health Diff: {}", target));
        Output::warning("Database integration not yet implemented");
        Output::info("Use 'rb network health check' to scan ports first");
        Output::info("Then use 'rb network health watch' for continuous monitoring");

        Ok(())
    }

    /// Watch ports continuously
    fn watch(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network health watch <HOST> [--interval 60]\nExample: rb network health watch 192.168.1.1",
        )?;

        Validator::validate_host(target)?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        let ports_str = ctx
            .flags
            .get("ports")
            .map(|s| s.as_str())
            .unwrap_or("22,80,443,8080,8443");
        let ports = Self::parse_ports(ports_str);

        if ports.is_empty() {
            return Err("No valid ports specified".to_string());
        }

        let timeout_ms = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1000);

        let threads = ctx
            .flags
            .get("threads")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(50);

        let interval_secs = ctx
            .flags
            .get("interval")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);

        let max_count = ctx
            .flags
            .get("count")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        let max_iterations = if max_count == 0 {
            None
        } else {
            Some(max_count)
        };

        if is_json {
            // For JSON mode, output as a JSON array of iterations
            println!("{{");
            println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
            println!("  \"interval_secs\": {},", interval_secs);
            println!("  \"timeout_ms\": {},", timeout_ms);
            println!("  \"ports_monitored\": {},", ports.len());
            if let Some(max) = max_iterations {
                println!("  \"max_iterations\": {},", max);
            } else {
                println!("  \"max_iterations\": null,");
            }
            println!("  \"iterations\": [");
        } else {
            Output::header(&format!("Port Health Watch: {}", target));
            Output::info(&format!(
                "Monitoring {} ports every {}s (timeout: {}ms)",
                ports.len(),
                interval_secs,
                timeout_ms
            ));
            if let Some(max) = max_iterations {
                Output::info(&format!("Will run {} iterations", max));
            } else {
                Output::info("Press Ctrl+C to stop");
            }
            println!();
        }

        let checker = PortHealthChecker::new()
            .with_timeout(Duration::from_millis(timeout_ms))
            .with_threads(threads);

        let config = WatchConfig {
            interval: Duration::from_secs(interval_secs),
            max_iterations,
            alert_on_change: true,
        };

        let watcher = PortWatcher::new(checker, config);

        // Track iteration count for JSON comma handling
        let iteration_count = std::cell::Cell::new(0u32);
        let max_iter_for_comma = max_iterations;

        watcher.watch(target, &ports, |results, diff, iteration| {
            iteration_count.set(iteration);
            if is_json {
                self.display_watch_iteration_json(results, diff, iteration, max_iter_for_comma);
            } else {
                self.display_watch_iteration(results, diff, iteration);
            }
        });

        if is_json {
            println!("  ]");
            println!("}}");
        } else {
            Output::success("Watch complete");
        }
        Ok(())
    }

    /// Display watch iteration results
    fn display_watch_iteration(
        &self,
        results: &[PortCheckResult],
        diff: &PortDiff,
        iteration: u32,
    ) {
        let open_count = results.iter().filter(|r| r.is_open).count();
        let timestamp = chrono_lite_timestamp();

        // Always show iteration header
        println!(
            "[{}] Iteration {} - {} open, {} closed",
            Output::colorize(&timestamp, "dim"),
            iteration,
            Output::colorize(&open_count.to_string(), "green"),
            Output::colorize(&(results.len() - open_count).to_string(), "red")
        );

        // Show changes if any
        if diff.has_changes() {
            Output::warning(&format!("{} changes detected!", diff.total_changes()));

            // Newly opened ports
            for result in &diff.now_open {
                println!(
                    "  {} Port {} {} (was closed)",
                    Output::colorize("+", "green"),
                    Output::colorize(&result.port.to_string(), "cyan"),
                    result.service.as_deref().unwrap_or("-")
                );
            }

            // Newly closed ports
            for result in &diff.now_closed {
                println!(
                    "  {} Port {} {} (was open)",
                    Output::colorize("-", "red"),
                    Output::colorize(&result.port.to_string(), "cyan"),
                    result.service.as_deref().unwrap_or("-")
                );
            }

            // New ports
            for result in &diff.new_ports {
                println!(
                    "  {} Port {} {} (new)",
                    Output::colorize("*", "yellow"),
                    Output::colorize(&result.port.to_string(), "cyan"),
                    result.service.as_deref().unwrap_or("-")
                );
            }
        }

        println!();
    }

    /// Display watch iteration results as JSON
    fn display_watch_iteration_json(
        &self,
        results: &[PortCheckResult],
        diff: &PortDiff,
        iteration: u32,
        max_iterations: Option<u32>,
    ) {
        let open_count = results.iter().filter(|r| r.is_open).count();
        let closed_count = results.len() - open_count;
        let timestamp = chrono_lite_timestamp();

        // Determine if we need a comma after this iteration
        let needs_comma = match max_iterations {
            Some(max) => iteration < max,
            None => true, // In infinite mode, always add comma (streaming)
        };
        let comma = if needs_comma { "," } else { "" };

        println!("    {{");
        println!("      \"iteration\": {},", iteration);
        println!("      \"timestamp\": \"{}\",", timestamp);
        println!("      \"open_count\": {},", open_count);
        println!("      \"closed_count\": {},", closed_count);
        println!("      \"has_changes\": {},", diff.has_changes());
        println!("      \"total_changes\": {},", diff.total_changes());

        // Open ports
        println!("      \"open_ports\": [");
        let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();
        for (i, result) in open_ports.iter().enumerate() {
            let port_comma = if i < open_ports.len() - 1 { "," } else { "" };
            let service = result
                .service
                .as_ref()
                .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                .unwrap_or_else(|| "null".to_string());
            println!(
                "        {{\"port\": {}, \"service\": {}, \"response_time_ms\": {}}}{}",
                result.port, service, result.response_time_ms, port_comma
            );
        }
        println!("      ],");

        // Changes
        println!("      \"changes\": {{");

        // Now open
        println!("        \"now_open\": [");
        for (i, result) in diff.now_open.iter().enumerate() {
            let change_comma = if i < diff.now_open.len() - 1 { "," } else { "" };
            let service = result
                .service
                .as_ref()
                .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                .unwrap_or_else(|| "null".to_string());
            println!(
                "          {{\"port\": {}, \"service\": {}}}{}",
                result.port, service, change_comma
            );
        }
        println!("        ],");

        // Now closed
        println!("        \"now_closed\": [");
        for (i, result) in diff.now_closed.iter().enumerate() {
            let change_comma = if i < diff.now_closed.len() - 1 {
                ","
            } else {
                ""
            };
            let service = result
                .service
                .as_ref()
                .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                .unwrap_or_else(|| "null".to_string());
            println!(
                "          {{\"port\": {}, \"service\": {}}}{}",
                result.port, service, change_comma
            );
        }
        println!("        ],");

        // New ports
        println!("        \"new_ports\": [");
        for (i, result) in diff.new_ports.iter().enumerate() {
            let change_comma = if i < diff.new_ports.len() - 1 {
                ","
            } else {
                ""
            };
            let service = result
                .service
                .as_ref()
                .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                .unwrap_or_else(|| "null".to_string());
            println!(
                "          {{\"port\": {}, \"service\": {}}}{}",
                result.port, service, change_comma
            );
        }
        println!("        ]");

        println!("      }}");
        println!("    }}{}", comma);
    }
}

/// Simple timestamp without external dependencies
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Simple HH:MM:SS format
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;

    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}
