/// Network/trace command - Traceroute and MTR functionality
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::network::traceroute::{Mtr, Traceroute};

pub struct TraceCommand;

impl Command for TraceCommand {
    fn domain(&self) -> &str {
        "network"
    }

    fn resource(&self) -> &str {
        "trace"
    }

    fn description(&self) -> &str {
        "Network path tracing and latency analysis"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "run",
                summary: "Perform a traceroute to a target",
                usage: "rb network trace run <target> [--max-hops N] [--timeout MS]",
            },
            Route {
                verb: "mtr",
                summary: "Perform continuous MTR-style monitoring",
                usage: "rb network trace mtr <target> [--iterations N]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("output", "Output format (text, json, yaml)")
                .with_short('o')
                .with_default("text"),
            Flag::new("max-hops", "Maximum number of hops")
                .with_short('m')
                .with_default("30"),
            Flag::new("timeout", "Timeout in milliseconds")
                .with_short('t')
                .with_default("2000"),
            Flag::new("no-dns", "Skip reverse DNS lookup").with_short('n'),
            Flag::new("iterations", "Number of iterations for MTR")
                .with_short('i')
                .with_default("10"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Basic traceroute", "rb network trace run 8.8.8.8"),
            (
                "Traceroute with custom max hops",
                "rb network trace run google.com --max-hops 20",
            ),
            (
                "Fast traceroute without DNS",
                "rb network trace run 1.1.1.1 --no-dns --timeout 1000",
            ),
            (
                "Traceroute as JSON",
                "rb network trace run 8.8.8.8 --output=json",
            ),
            ("MTR monitoring", "rb network trace mtr 8.8.8.8"),
            (
                "MTR with custom iterations",
                "rb network trace mtr google.com --iterations 20",
            ),
            ("MTR as JSON", "rb network trace mtr 8.8.8.8 --output=json"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "run" => self.run_trace(ctx),
            "mtr" => self.run_mtr(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!("{}", Validator::suggest_command(verb, &["run", "mtr"]));
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl TraceCommand {
    fn run_trace(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network trace run <TARGET>\nExample: rb network trace run 8.8.8.8",
        )?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        // Parse flags
        let max_hops = ctx
            .get_flag_or("max-hops", "30")
            .parse::<u8>()
            .map_err(|_| "Invalid max-hops value")?;

        let timeout_ms = ctx
            .get_flag_or("timeout", "2000")
            .parse::<u64>()
            .map_err(|_| "Invalid timeout value")?;

        let dns_resolve = !ctx.has_flag("no-dns");

        if !is_json {
            Output::header("Traceroute");
            Output::item("Target", target);
            Output::item("Max Hops", &max_hops.to_string());
            Output::item("Timeout", &format!("{}ms", timeout_ms));
            Output::item("DNS Resolve", if dns_resolve { "Yes" } else { "No" });
            println!();
        }

        // Create traceroute instance
        let traceroute = Traceroute::new(target)
            .with_max_hops(max_hops)
            .with_timeout(timeout_ms)
            .with_dns_resolve(dns_resolve);

        // Run traceroute
        if !is_json {
            Output::spinner_start(&format!("Tracing route to {}", target));
        }
        let hops = traceroute.run()?;
        if !is_json {
            Output::spinner_done();
        }

        // JSON output
        if is_json {
            println!("{{");
            println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
            println!("  \"config\": {{");
            println!("    \"max_hops\": {},", max_hops);
            println!("    \"timeout_ms\": {},", timeout_ms);
            println!("    \"dns_resolve\": {}", dns_resolve);
            println!("  }},");
            println!("  \"total_hops\": {},", hops.len());
            println!("  \"hops\": [");

            for (i, hop) in hops.iter().enumerate() {
                let comma = if i < hops.len() - 1 { "," } else { "" };
                let hostname = hop
                    .hostname
                    .as_ref()
                    .map(|h| format!("\"{}\"", h.replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string());
                let ip = hop
                    .ip
                    .map(|addr| format!("\"{}\"", addr))
                    .unwrap_or_else(|| "null".to_string());
                let latency = hop
                    .latency_ms
                    .map(|ms| format!("{:.3}", ms))
                    .unwrap_or_else(|| "null".to_string());

                println!(
                    "    {{\"ttl\": {}, \"hostname\": {}, \"ip\": {}, \"latency_ms\": {}}}{}",
                    hop.ttl, hostname, ip, latency, comma
                );
            }

            println!("  ]");
            println!("}}");
            return Ok(());
        }

        if hops.is_empty() {
            Output::warning("No hops found");
            return Ok(());
        }

        // Display results
        println!();
        Output::subheader(&format!("Route to {} ({} hops)", target, hops.len()));
        println!();

        // Print table header
        println!(
            "  {:<4} {:<40} {:<20} {:<10}",
            "HOP", "HOSTNAME", "IP ADDRESS", "LATENCY"
        );
        println!("  {}", "─".repeat(80));

        for hop in &hops {
            let hostname = hop.hostname.as_deref().unwrap_or("*");

            let ip = if let Some(addr) = hop.ip {
                addr.to_string()
            } else {
                "*".to_string()
            };

            let latency = if let Some(ms) = hop.latency_ms {
                format!("{:.2} ms", ms)
            } else {
                "*".to_string()
            };

            println!(
                "  {:<4} {:<40} {:<20} {:<10}",
                hop.ttl, hostname, ip, latency
            );
        }

        println!();
        Output::success("Traceroute completed");

        Ok(())
    }

    fn run_mtr(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network trace mtr <TARGET>\nExample: rb network trace mtr 8.8.8.8",
        )?;

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        // Parse flags
        let max_hops = ctx
            .get_flag_or("max-hops", "30")
            .parse::<u8>()
            .map_err(|_| "Invalid max-hops value")?;

        let timeout_ms = ctx
            .get_flag_or("timeout", "2000")
            .parse::<u64>()
            .map_err(|_| "Invalid timeout value")?;

        let iterations = ctx
            .get_flag_or("iterations", "10")
            .parse::<usize>()
            .map_err(|_| "Invalid iterations value")?;

        let dns_resolve = !ctx.has_flag("no-dns");

        if !is_json {
            Output::header("MTR - Network Path Monitor");
            Output::item("Target", target);
            Output::item("Max Hops", &max_hops.to_string());
            Output::item("Iterations", &iterations.to_string());
            Output::item("Timeout", &format!("{}ms", timeout_ms));
            Output::item("DNS Resolve", if dns_resolve { "Yes" } else { "No" });
            println!();
        }

        // Create MTR instance
        let mtr = Mtr::new(target).with_iterations(iterations);

        // Run MTR
        if !is_json {
            Output::spinner_start(&format!(
                "Running MTR to {} ({} iterations)",
                target, iterations
            ));
        }
        let stats = mtr.run()?;
        if !is_json {
            Output::spinner_done();
        }

        // JSON output
        if is_json {
            println!("{{");
            println!("  \"target\": \"{}\",", target.replace('"', "\\\""));
            println!("  \"config\": {{");
            println!("    \"max_hops\": {},", max_hops);
            println!("    \"timeout_ms\": {},", timeout_ms);
            println!("    \"iterations\": {},", iterations);
            println!("    \"dns_resolve\": {}", dns_resolve);
            println!("  }},");
            println!("  \"total_hops\": {},", stats.len());
            println!("  \"hops\": [");

            for (i, hop_stat) in stats.iter().enumerate() {
                let comma = if i < stats.len() - 1 { "," } else { "" };
                let hostname = hop_stat
                    .hostname
                    .as_ref()
                    .map(|h| format!("\"{}\"", h.replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string());
                let ip = hop_stat
                    .ip
                    .map(|addr| format!("\"{}\"", addr))
                    .unwrap_or_else(|| "null".to_string());

                println!("    {{");
                println!("      \"ttl\": {},", hop_stat.ttl);
                println!("      \"hostname\": {},", hostname);
                println!("      \"ip\": {},", ip);
                println!("      \"sent\": {},", hop_stat.sent);
                println!("      \"received\": {},", hop_stat.received);
                println!("      \"loss_percent\": {:.2},", hop_stat.loss_percent());
                println!("      \"min_latency_ms\": {:.3},", hop_stat.min_latency());
                println!("      \"avg_latency_ms\": {:.3},", hop_stat.avg_latency());
                println!("      \"max_latency_ms\": {:.3}", hop_stat.max_latency());
                println!("    }}{}", comma);
            }

            println!("  ]");
            println!("}}");
            return Ok(());
        }

        if stats.is_empty() {
            Output::warning("No statistics collected");
            return Ok(());
        }

        // Display results
        println!();
        Output::subheader(&format!(
            "MTR Statistics for {} ({} hops)",
            target,
            stats.len()
        ));
        println!();

        // Print table header
        println!(
            "  {:<4} {:<25} {:<16} {:<6} {:<8} {:<8} {:<8} {:<8}",
            "HOP", "HOSTNAME", "IP", "LOSS%", "SENT", "RECV", "AVG", "BEST/WORST"
        );
        println!("  {}", "─".repeat(100));

        for hop_stat in &stats {
            let hostname = hop_stat
                .hostname
                .as_ref()
                .map(|h| {
                    if h.len() > 23 {
                        format!("{}...", &h[..20])
                    } else {
                        h.clone()
                    }
                })
                .unwrap_or_else(|| "*".to_string());

            let ip = if let Some(addr) = hop_stat.ip {
                addr.to_string()
            } else {
                "*".to_string()
            };

            let loss = format!("{:.1}%", hop_stat.loss_percent());

            let avg = if hop_stat.received > 0 {
                format!("{:.2}", hop_stat.avg_latency())
            } else {
                "*".to_string()
            };

            let best_worst = if hop_stat.received > 0 {
                format!(
                    "{:.2}/{:.2}",
                    hop_stat.min_latency(),
                    hop_stat.max_latency()
                )
            } else {
                "*".to_string()
            };

            println!(
                "  {:<4} {:<25} {:<16} {:<6} {:<8} {:<8} {:<8} {:<8}",
                hop_stat.ttl, hostname, ip, loss, hop_stat.sent, hop_stat.received, avg, best_worst
            );
        }

        println!();
        Output::success("MTR monitoring completed");

        Ok(())
    }
}
