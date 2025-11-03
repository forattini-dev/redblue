/// Benchmark/load testing command - Performance and stress testing
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::benchmark::load_generator::{LoadConfig, LoadGenerator, LoadTestResults};
use std::time::Duration;

pub struct BenchCommand;

impl Command for BenchCommand {
    fn domain(&self) -> &str {
        "bench"
    }

    fn resource(&self) -> &str {
        "load"
    }

    fn description(&self) -> &str {
        "HTTP load testing and performance benchmarking"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "run",
                summary: "Run load test against target URL",
                usage: "rb bench load run <url> [--users 100] [--duration 60s]",
            },
            Route {
                verb: "stress",
                summary: "Stress test with maximum load",
                usage: "rb bench load stress <url> --users 1000",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("users", "Number of concurrent users")
                .with_short('u')
                .with_default("100"),
            Flag::new("duration", "Test duration in seconds")
                .with_short('d')
                .with_default("60"),
            Flag::new("requests", "Total requests per user").with_short('r'),
            Flag::new("think-time", "Delay between requests in ms")
                .with_short('t')
                .with_default("100"),
            Flag::new("timeout", "Request timeout in seconds").with_default("30"),
            Flag::new("keep-alive", "Use HTTP keep-alive (connection pooling)")
                .with_short('k')
                .with_default("true"),
            Flag::new("max-idle", "Max idle connections per host").with_default("50"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Basic load test", "rb bench load run https://example.com"),
            (
                "1000 concurrent users for 2 minutes",
                "rb bench load run https://api.example.com --users 1000 --duration 120",
            ),
            (
                "Fixed request count",
                "rb bench load run https://example.com --users 50 --requests 1000",
            ),
            (
                "Stress test with high load",
                "rb bench load stress https://example.com --users 5000",
            ),
            (
                "Realistic user simulation",
                "rb bench load run https://shop.example.com --users 500 --think-time 2000",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "run" => self.run_load_test(ctx),
            "stress" => self.run_stress_test(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                print_help(self);
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl BenchCommand {
    fn run_load_test(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb bench load run <URL>\nExample: rb bench load run https://example.com"
        )?;

        // Validate URL format
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!(
                "Invalid URL: {}\nURL must start with http:// or https://",
                url
            ));
        }

        // Parse flags
        let users = ctx
            .get_flag("users")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(100);

        let duration_secs = ctx
            .get_flag("duration")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);

        let requests = ctx
            .get_flag("requests")
            .and_then(|s| s.parse::<usize>().ok());

        let think_time_ms = ctx
            .get_flag("think-time")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(100);

        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30);

        let keep_alive = ctx
            .get_flag("keep-alive")
            .map(|s| s != "false")
            .unwrap_or(true);

        let max_idle = ctx
            .get_flag("max-idle")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50);

        // Build config
        let mut config = LoadConfig::new(url.clone())
            .with_users(users)
            .with_think_time(Duration::from_millis(think_time_ms))
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_connection_pool(keep_alive)
            .with_max_idle_per_host(max_idle);

        if let Some(req_count) = requests {
            config = config.with_requests(req_count);
        } else {
            config = config.with_duration(Duration::from_secs(duration_secs));
        }

        // Display config
        Output::header("HTTP Load Test");
        Output::item("Target", url);
        Output::item("Concurrent Users", &users.to_string());
        if let Some(req) = requests {
            Output::item("Requests/User", &req.to_string());
        } else {
            Output::item("Duration", &format!("{}s", duration_secs));
        }
        Output::item("Think Time", &format!("{}ms", think_time_ms));
        println!();

        // Run load test
        Output::spinner_start(&format!("Running load test with {} users", users));
        let generator = LoadGenerator::new(config);
        let results = generator.run()?;
        Output::spinner_done();

        // Display results
        self.display_results(&results);

        Ok(())
    }

    fn run_stress_test(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb bench load stress <URL>\nExample: rb bench load stress https://example.com"
        )?;

        // Validate URL
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!(
                "Invalid URL: {}\nURL must start with http:// or https://",
                url
            ));
        }

        let users = ctx
            .get_flag("users")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1000);

        // Stress test = no think time, aggressive requests
        let config = LoadConfig::new(url.clone())
            .with_users(users)
            .with_duration(Duration::from_secs(60))
            .with_think_time(Duration::ZERO) // No delay
            .with_timeout(Duration::from_secs(10));

        Output::header("HTTP Stress Test");
        Output::warning("⚠️  AGGRESSIVE LOAD - USE ONLY ON AUTHORIZED TARGETS");
        Output::item("Target", url);
        Output::item("Concurrent Users", &users.to_string());
        Output::item("Think Time", "0ms (aggressive)");
        println!();

        Output::spinner_start(&format!("Stress testing with {} users", users));
        let generator = LoadGenerator::new(config);
        let results = generator.run()?;
        Output::spinner_done();

        self.display_results(&results);

        Ok(())
    }

    fn display_results(&self, results: &LoadTestResults) {
        println!();
        Output::subheader("LOAD TEST RESULTS");
        println!();

        // Summary
        Output::item("Total Requests", &results.total_requests.to_string());
        Output::item(
            "Successful",
            &format!(
                "{} ({:.1}%)",
                results.successful_requests, results.success_rate
            ),
        );
        Output::item("Failed", &results.failed_requests.to_string());
        Output::item(
            "Test Duration",
            &format!("{:.2}s", results.test_duration.as_secs_f64()),
        );
        Output::item(
            "Requests/sec",
            &format!("{:.2}", results.requests_per_second),
        );
        println!();

        // Latency
        Output::subheader("Latency Distribution");
        Output::item(
            "p50 (median)",
            &format!("{:.2}ms", results.latency.p50.as_secs_f64() * 1000.0),
        );
        Output::item(
            "p95",
            &format!("{:.2}ms", results.latency.p95.as_secs_f64() * 1000.0),
        );
        Output::item(
            "p99",
            &format!("{:.2}ms", results.latency.p99.as_secs_f64() * 1000.0),
        );
        Output::item(
            "min",
            &format!("{:.2}ms", results.latency.min.as_secs_f64() * 1000.0),
        );
        Output::item(
            "max",
            &format!("{:.2}ms", results.latency.max.as_secs_f64() * 1000.0),
        );
        Output::item(
            "avg",
            &format!("{:.2}ms", results.latency.avg.as_secs_f64() * 1000.0),
        );
        println!();

        // Status codes
        if results.successful_requests > 0 {
            Output::subheader("Status Codes");
            if results.status_2xx > 0 {
                Output::item("2xx (Success)", &results.status_2xx.to_string());
            }
            if results.status_3xx > 0 {
                Output::item("3xx (Redirect)", &results.status_3xx.to_string());
            }
            if results.status_4xx > 0 {
                Output::item("4xx (Client Error)", &results.status_4xx.to_string());
            }
            if results.status_5xx > 0 {
                Output::item("5xx (Server Error)", &results.status_5xx.to_string());
            }
            println!();
        }

        // Throughput
        Output::subheader("Throughput");
        Output::item(
            "Total Data",
            &format!("{:.2} MB", results.total_bytes as f64 / 1_000_000.0),
        );
        Output::item(
            "Throughput",
            &format!("{:.2} Mbps", results.throughput_mbps),
        );
        println!();

        // Errors (first 10)
        if !results.errors.is_empty() {
            Output::warning(&format!("⚠️  {} ERRORS DETECTED:", results.errors.len()));
            for (i, error) in results.errors.iter().take(10).enumerate() {
                println!("  {}. {}", i + 1, error);
            }
            if results.errors.len() > 10 {
                println!("  ... and {} more errors", results.errors.len() - 10);
            }
            println!();
        }

        // Performance rating
        if results.success_rate > 99.0 && results.latency.p95.as_millis() < 500 {
            Output::success("✓ Excellent performance!");
        } else if results.success_rate > 95.0 && results.latency.p95.as_millis() < 1000 {
            Output::success("✓ Good performance");
        } else if results.success_rate > 90.0 {
            Output::warning("⚠  Acceptable performance - consider optimization");
        } else {
            Output::error("✗ Poor performance - check server capacity");
        }
    }
}
