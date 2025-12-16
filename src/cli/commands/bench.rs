//! Benchmark/load testing command - Performance and stress testing

#![allow(clippy::needless_range_loop)]

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::benchmark::load_generator::{
    LiveSnapshot, LoadConfig, LoadGenerator, LoadMode, LoadTestResults, ProtocolPreference,
};
use std::collections::VecDeque;
use std::f64;
use std::fs;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, str::FromStr};

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
            Flag::new("protocol", "HTTP protocol to use (auto, http1, http2)"),
            Flag::new("method", "HTTP method to use (default GET)"),
            Flag::new("body", "Inline request body payload (string)"),
            Flag::new("body-file", "File containing request body payload"),
            Flag::new("keep-alive", "Use HTTP keep-alive (connection pooling)")
                .with_short('k')
                .with_default("true"),
            Flag::new("max-idle", "Max idle connections per host").with_default("50"),
            // Mode flags
            Flag::new(
                "mode",
                "Testing mode: throughput, connections, realistic, stress",
            )
            .with_short('m')
            .with_default("realistic"),
            Flag::new(
                "new-user-ratio",
                "Ratio of new users in realistic mode (0.0-1.0)",
            )
            .with_default("0.3"),
            Flag::new(
                "session-length",
                "Requests per session before reconnect (realistic mode)",
            ),
            Flag::new(
                "think-variance",
                "Think time variance multiplier (realistic mode)",
            )
            .with_default("0.0"),
            Flag::new("ramp-up", "Gradual ramp-up duration in seconds"),
            Flag::new("warmup", "Warmup requests to skip from statistics").with_default("0"),
            Flag::new("rate-limit", "Target RPS limit (0 = unlimited)").with_default("0"),
            // HTTP/2 pool flags
            Flag::new(
                "shared-http2-pool",
                "Share HTTP/2 connections across workers",
            )
            .with_default("true"),
            Flag::new("http2-connections", "Max HTTP/2 connections per origin").with_default("6"),
            Flag::new("live", "Show real-time dashboard with graphs").with_short('l'),
            Flag::new("live-interval", "Seconds between live dashboard updates")
                .with_default("1.0"),
            Flag::new(
                "live-history",
                "History window (seconds) retained in live dashboard",
            )
            .with_default("60"),
            Flag::new("live-height", "Rows used for live graphs (min 4, max 16)").with_default("8"),
            Flag::new(
                "color",
                "Color output mode for live dashboard (always, auto, never)",
            ),
            Flag::new(
                "live-rps-color",
                "Color for RPS graph (hex or name: purple, teal, coral, mint, gold)",
            ),
            Flag::new(
                "live-latency-color",
                "Color for latency graph (hex or name: purple, teal, coral, mint, gold)",
            ),
            Flag::new(
                "live-cpu-color",
                "Color for CPU sparkline (hex or name: purple, teal, coral, mint, gold)",
            ),
            Flag::new(
                "live-ram-color",
                "Color for RAM sparkline (hex or name: purple, teal, coral, mint, gold)",
            ),
            Flag::new(
                "no-live",
                "Disable the live dashboard and use final summary only",
            ),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Basic load test (realistic mode)",
                "rb bench load run https://example.com",
            ),
            (
                "Maximum throughput test",
                "rb bench load run https://example.com --mode throughput --users 500",
            ),
            (
                "Connection stress test",
                "rb bench load run https://example.com --mode connections --users 500",
            ),
            (
                "Max stress test",
                "rb bench load run https://example.com --mode stress --users 5000",
            ),
            (
                "Real-time dashboard with graphs",
                "rb bench load run https://example.com --live",
            ),
            (
                "1000 concurrent users for 2 minutes",
                "rb bench load run https://api.example.com --users 1000 --duration 120",
            ),
            (
                "With warmup and rate limiting",
                "rb bench load run https://example.com --warmup 100 --rate-limit 1000",
            ),
            (
                "Disable shared HTTP/2 pool",
                "rb bench load run https://example.com --shared-http2-pool false",
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

        let (method, body_payload) = parse_method_and_body(ctx)?;
        let body_size = body_payload.as_ref().map(|b| b.len()).unwrap_or(0);

        let protocol = match ctx.get_flag("protocol") {
            Some(flag) => ProtocolPreference::from_str(&flag)?,
            None => ProtocolPreference::Auto,
        };

        let keep_alive = ctx
            .get_flag("keep-alive")
            .map(|s| s != "false")
            .unwrap_or(true);

        let max_idle = ctx
            .get_flag("max-idle")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50);

        // Parse mode flags
        let mode = match ctx.get_flag("mode") {
            Some(flag) => LoadMode::from_str(&flag)?,
            None => LoadMode::Realistic,
        };

        let new_user_ratio = ctx
            .get_flag("new-user-ratio")
            .and_then(|s| s.parse::<f64>().ok())
            .map(|r| r.clamp(0.0, 1.0))
            .unwrap_or(0.3);

        let session_length = ctx
            .get_flag("session-length")
            .and_then(|s| s.parse::<usize>().ok());

        let think_variance = ctx
            .get_flag("think-variance")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);

        let ramp_up = ctx
            .get_flag("ramp-up")
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs);

        let warmup = ctx
            .get_flag("warmup")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let rate_limit = ctx
            .get_flag("rate-limit")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let shared_http2_pool = ctx
            .get_flag("shared-http2-pool")
            .map(|s| s != "false")
            .unwrap_or(true);

        let http2_connections = ctx
            .get_flag("http2-connections")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(6);

        // Build config - apply mode FIRST, then explicit overrides
        let mut config = LoadConfig::new(url.clone())
            .with_mode(mode) // Apply mode defaults first
            .with_users(users)
            .with_think_time(Duration::from_millis(think_time_ms))
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_connection_pool(keep_alive)
            .with_max_idle_per_host(max_idle)
            .with_protocol(protocol)
            .with_method(method.clone())
            .with_body(body_payload)
            .with_new_user_ratio(new_user_ratio)
            .with_session_length(session_length)
            .with_think_time_variance(think_variance)
            .with_ramp_up(ramp_up)
            .with_warmup(warmup)
            .with_rate_limit(rate_limit)
            .with_shared_http2_pool(shared_http2_pool)
            .with_http2_max_connections(http2_connections);

        if let Some(req_count) = requests {
            config = config.with_requests(req_count);
        } else {
            config = config.with_duration(Duration::from_secs(duration_secs));
        }

        // Display config
        Output::header("HTTP Load Test");
        Output::item("Target", url);
        Output::item(
            "Mode",
            &format!("{} ({})", mode.label(), mode.description()),
        );
        Output::item("Concurrent Users", &users.to_string());
        if let Some(req) = requests {
            Output::item("Requests/User", &req.to_string());
        } else {
            Output::item("Duration", &format!("{}s", duration_secs));
        }
        Output::item("Think Time", &format!("{}ms", think_time_ms));
        Output::item("Protocol", protocol.label());
        Output::item("Method", &method);
        let body_display = if body_size > 0 {
            format!("{} bytes", body_size)
        } else {
            "none".to_string()
        };
        Output::item("Body", &body_display);
        Output::item(
            "Connection Pool",
            &format!(
                "HTTP/1={}, HTTP/2 shared={}",
                if keep_alive { "on" } else { "off" },
                if shared_http2_pool { "on" } else { "off" }
            ),
        );
        println!();

        let live_flag_value = ctx
            .get_flag("live")
            .or_else(|| ctx.get_flag("l"))
            .map(|value| {
                let v = value.to_ascii_lowercase();
                v != "false" && v != "0" && v != "no"
            });

        let live_enabled = if ctx.has_flag("no-live") {
            false
        } else {
            live_flag_value.unwrap_or(true)
        };

        let live_interval_secs = ctx
            .get_flag("live-interval")
            .and_then(|s| s.parse::<f64>().ok())
            .map(|v| v.max(0.2))
            .unwrap_or(1.0);

        let live_history_secs = ctx
            .get_flag("live-history")
            .and_then(|s| s.parse::<f64>().ok())
            .map(|v| v.max(live_interval_secs * 2.0))
            .unwrap_or(60.0)
            .min(3600.0);

        let live_height = ctx
            .get_flag("live-height")
            .and_then(|s| s.parse::<usize>().ok())
            .map(|v| v.clamp(4, 16))
            .unwrap_or(8);

        let live_capacity = ((live_history_secs / live_interval_secs).ceil() as usize).max(10);
        let observer_interval = Duration::from_secs_f64(live_interval_secs);
        let color_mode = ColorMode::from_context(ctx)?;
        let color_theme = ColorTheme::from_flags(
            ctx.get_flag("live-rps-color").as_ref(),
            ctx.get_flag("live-latency-color").as_ref(),
            ctx.get_flag("live-cpu-color").as_ref(),
            ctx.get_flag("live-ram-color").as_ref(),
            color_mode,
        )?;

        let generator = LoadGenerator::new(config);
        let results = if live_enabled {
            Output::section("Live Load Dashboard");
            let dashboard = Arc::new(Mutex::new(LiveDashboard::new(
                live_capacity,
                observer_interval,
                live_height,
                color_theme,
                protocol.label().to_string(),
                method.clone(),
            )));
            let observer_dashboard = Arc::clone(&dashboard);
            let observer = Arc::new(move |snapshot: LiveSnapshot| {
                if let Ok(mut dash) = observer_dashboard.lock() {
                    dash.update(&snapshot);
                    dash.render(&snapshot);
                }
            });
            let result = generator.run_with_observer(observer_interval, observer)?;
            if let Ok(mut dash) = dashboard.lock() {
                dash.finish();
            }
            println!();
            result
        } else {
            Output::spinner_start(&format!("Running load test with {} users", users));
            let result = generator.run()?;
            Output::spinner_done();
            result
        };

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

        let (method, body_payload) = parse_method_and_body(ctx)?;
        let body_size = body_payload.as_ref().map(|b| b.len()).unwrap_or(0);

        let protocol = match ctx.get_flag("protocol") {
            Some(flag) => ProtocolPreference::from_str(&flag)?,
            None => ProtocolPreference::Auto,
        };

        // Stress test = no think time, aggressive requests
        let config = LoadConfig::new(url.clone())
            .with_users(users)
            .with_duration(Duration::from_secs(60))
            .with_think_time(Duration::ZERO) // No delay
            .with_timeout(Duration::from_secs(10))
            .with_protocol(protocol)
            .with_method(method.clone())
            .with_body(body_payload);

        Output::header("HTTP Stress Test");
        Output::warning("⚠️  AGGRESSIVE LOAD - USE ONLY ON AUTHORIZED TARGETS");
        Output::item("Target", url);
        Output::item("Concurrent Users", &users.to_string());
        Output::item("Think Time", "0ms (aggressive)");
        Output::item("Protocol", protocol.label());
        Output::item("Method", &method);
        let body_display = if body_size > 0 {
            format!("{} bytes", body_size)
        } else {
            "none".to_string()
        };
        Output::item("Body", &body_display);
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
        Output::item("Protocol", &results.protocol.display_label());
        Output::item("Method", &results.config.method);
        let body_summary = results
            .config
            .body
            .as_ref()
            .map(|b| format!("{} bytes", b.len()))
            .unwrap_or_else(|| "none".to_string());
        Output::item("Body", &body_summary);
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

        Output::subheader("TTFB Distribution");
        Output::item(
            "p50 (median)",
            &format!("{:.2}ms", results.ttfb.p50.as_secs_f64() * 1000.0),
        );
        Output::item(
            "p95",
            &format!("{:.2}ms", results.ttfb.p95.as_secs_f64() * 1000.0),
        );
        Output::item(
            "p99",
            &format!("{:.2}ms", results.ttfb.p99.as_secs_f64() * 1000.0),
        );
        Output::item(
            "min",
            &format!("{:.2}ms", results.ttfb.min.as_secs_f64() * 1000.0),
        );
        Output::item(
            "max",
            &format!("{:.2}ms", results.ttfb.max.as_secs_f64() * 1000.0),
        );
        Output::item(
            "avg",
            &format!("{:.2}ms", results.ttfb.avg.as_secs_f64() * 1000.0),
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

fn parse_method_and_body(ctx: &CliContext) -> Result<(String, Option<Vec<u8>>), String> {
    let method_raw = ctx.get_flag("method").unwrap_or_else(|| "GET".to_string());
    let method_trimmed = method_raw.trim();
    if method_trimmed.is_empty() {
        return Err("HTTP method cannot be empty".to_string());
    }
    if method_trimmed.chars().any(|c| c.is_whitespace()) {
        return Err("HTTP method must not contain whitespace characters".to_string());
    }
    let method = method_trimmed.to_ascii_uppercase();

    let body_inline = ctx.get_flag("body");
    let body_file = ctx.get_flag("body-file");
    if body_inline.is_some() && body_file.is_some() {
        return Err("Specify either --body or --body-file, not both.".to_string());
    }

    let body = if let Some(path) = body_file {
        let data =
            fs::read(&path).map_err(|e| format!("Failed to read body file '{}': {}", path, e))?;
        Some(data)
    } else if let Some(inline) = body_inline {
        Some(inline.into_bytes())
    } else {
        None
    };

    Ok((method, body))
}

const LIVE_GRAPH_WIDTH: usize = 60;
const SPARK_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

struct LiveDashboard {
    capacity: usize,
    rps_history: VecDeque<f64>,
    latency_history: VecDeque<f64>,
    cpu_history: VecDeque<f64>,
    mem_history: VecDeque<f64>,
    last_render_lines: usize,
    cursor_hidden: bool,
    sample_interval: f64,
    graph_height: usize,
    stats: SystemStats,
    colors: ColorTheme,
    protocol_label: String,
    method_label: String,
}

impl LiveDashboard {
    fn new(
        capacity: usize,
        interval: Duration,
        graph_height: usize,
        colors: ColorTheme,
        protocol_label: String,
        method_label: String,
    ) -> Self {
        Self {
            capacity,
            rps_history: VecDeque::with_capacity(capacity),
            latency_history: VecDeque::with_capacity(capacity),
            cpu_history: VecDeque::with_capacity(capacity),
            mem_history: VecDeque::with_capacity(capacity),
            last_render_lines: 0,
            cursor_hidden: false,
            sample_interval: interval.as_secs_f64().max(f64::EPSILON),
            graph_height: graph_height.max(4),
            stats: SystemStats::new(),
            colors,
            protocol_label,
            method_label,
        }
    }

    fn update(&mut self, snapshot: &LiveSnapshot) {
        self.stats.refresh();
        Self::push_sample(
            &mut self.rps_history,
            self.capacity,
            snapshot.requests_per_second,
        );
        Self::push_sample(
            &mut self.latency_history,
            self.capacity,
            snapshot.p95.as_secs_f64() * 1000.0,
        );
        if let Some(cpu) = self.stats.cpu_percent_value() {
            Self::push_sample(&mut self.cpu_history, self.capacity, cpu);
        }
        if let Some(mem) = self.stats.mem_percent_value() {
            Self::push_sample(&mut self.mem_history, self.capacity, mem);
        }
    }

    fn render(&mut self, snapshot: &LiveSnapshot) {
        let lines = self.build_lines(snapshot);
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        if !self.cursor_hidden {
            let _ = write!(handle, "\x1b[?25l");
            self.cursor_hidden = true;
        }
        if self.last_render_lines > 0 {
            let _ = write!(handle, "\x1b[{}F", self.last_render_lines);
        }
        for line in &lines {
            let _ = write!(handle, "\x1b[2K\r{}\n", line);
        }
        self.last_render_lines = lines.len();
        if self.last_render_lines == 0 {
            self.last_render_lines = 1;
            let _ = write!(handle, "\n");
        }
        let _ = handle.flush();
    }

    fn finish(&mut self) {
        if !self.cursor_hidden {
            return;
        }
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        if self.last_render_lines > 0 {
            let _ = write!(handle, "\x1b[{}E", self.last_render_lines);
        }
        let _ = write!(handle, "\x1b[?25h");
        let _ = handle.flush();
        self.cursor_hidden = false;
        self.last_render_lines = 0;
    }

    fn push_sample(queue: &mut VecDeque<f64>, capacity: usize, value: f64) {
        if queue.len() == capacity {
            queue.pop_front();
        }
        queue.push_back(value);
    }

    fn build_lines(&self, snapshot: &LiveSnapshot) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(self.colors.wrap_summary(&format!(
            "t={:>5.1}s  total={}  ok={}  err={}  rps={:>6.1}  p95={:>6.0}ms  ttfb={:>6.0}ms  succ={:>5.1}%  proto={}  method={}",
            snapshot.elapsed.as_secs_f64(),
            snapshot.total_requests,
            snapshot.successful_requests,
            snapshot.failed_requests,
            snapshot.requests_per_second,
            snapshot.p95.as_secs_f64() * 1000.0,
            snapshot.ttfb_p95.as_secs_f64() * 1000.0,
            snapshot.success_rate,
            self.protocol_label,
            self.method_label
        )));
        let cpu_spark = render_sparkline(&self.cpu_history, LIVE_GRAPH_WIDTH);
        lines.push(self.colors.wrap_cpu_line(&format!(
            " CPU    {}  {:>6}",
            cpu_spark,
            self.stats.cpu_compact_display()
        )));
        let ram_spark = render_sparkline(&self.mem_history, LIVE_GRAPH_WIDTH);
        lines.push(self.colors.wrap_ram_line(&format!(
            " RAM    {}  {:>6} {}",
            ram_spark,
            self.stats.mem_compact_display(),
            self.stats.mem_detail_display()
        )));
        lines.push(String::new());

        let rps_values: Vec<f64> = self.rps_history.iter().copied().collect();
        for line in render_graph(
            " RPS",
            &rps_values,
            "req/s",
            self.sample_interval,
            self.graph_height,
        ) {
            lines.push(self.colors.wrap_rps(&line));
        }
        lines.push(String::new());

        let latency_values: Vec<f64> = self.latency_history.iter().copied().collect();
        for line in render_graph(
            " Latency",
            &latency_values,
            "ms",
            self.sample_interval,
            self.graph_height,
        ) {
            lines.push(self.colors.wrap_latency(&line));
        }
        lines
    }
}

fn render_graph(
    label: &str,
    values: &[f64],
    unit: &str,
    sample_interval: f64,
    graph_height: usize,
) -> Vec<String> {
    if values.is_empty() {
        return vec![format!("{:<10} (awaiting samples)", label)];
    }

    let width = LIVE_GRAPH_WIDTH;
    let height = graph_height.max(4);
    let display_len = values.len().min(width);
    let start = values.len() - display_len;
    let slice = &values[start..];
    let max_value = slice
        .iter()
        .cloned()
        .fold(0.0_f64, f64::max)
        .max(f64::EPSILON);
    let avg = slice.iter().sum::<f64>() / display_len as f64;
    let current = *slice.last().unwrap_or(&0.0);
    let span_seconds = sample_interval * (display_len.saturating_sub(1) as f64);

    let axis_max = if max_value <= f64::EPSILON {
        1.0
    } else {
        let magnitude = 10_f64.powf((max_value.log10()).floor());
        let scaled = max_value / magnitude;
        let factor = if scaled <= 1.0 {
            1.0
        } else if scaled <= 2.0 {
            2.0
        } else if scaled <= 5.0 {
            5.0
        } else {
            10.0
        };
        factor * magnitude
    };

    let mut lines = Vec::new();
    lines.push(format!(
        "{:<10} cur {:>8.1}  avg {:>8.1}  max {:>8.1} {}",
        label, current, avg, max_value, unit
    ));

    let mut grid = vec![vec![' '; width]; height];
    let offset = width - display_len;
    for idx in 0..display_len {
        let value = slice[idx];
        let normalized = normalize_value(value, axis_max);
        let col = offset + idx;
        draw_column(&mut grid, col, normalized);
    }

    for row in 0..height {
        let label_value = if row == 0 {
            Some(axis_max)
        } else if row == height / 2 {
            Some(axis_max * 0.5)
        } else if row == height - 1 {
            Some(0.0)
        } else {
            None
        };

        let label_text = label_value
            .map(format_axis_value)
            .unwrap_or_else(|| "      ".to_string());

        let mut line = String::with_capacity(width + 12);
        line.push_str(&label_text);
        line.push_str(" │");
        for col in 0..width {
            line.push(grid[row][col]);
        }
        line.push('│');
        lines.push(line);
    }

    let mut baseline = String::with_capacity(width + 12);
    baseline.push_str("      ");
    baseline.push_str(" └");
    baseline.push_str(&"─".repeat(width));
    baseline.push('┘');
    lines.push(baseline);
    let axis_span_label = if span_seconds >= 100.0 {
        format!("{:.0}s", span_seconds)
    } else if span_seconds >= 10.0 {
        format!("{:.1}s", span_seconds)
    } else {
        format!("{:.2}s", span_seconds)
    };
    let pad = width
        .saturating_sub(axis_span_label.len().saturating_add(2))
        .saturating_add(1);
    lines.push(format!("      0s{}{}", " ".repeat(pad), axis_span_label));
    lines
}

fn format_axis_value(value: f64) -> String {
    if value >= 1000.0 {
        format!("{:>6.0}", value)
    } else if value >= 10.0 {
        format!("{:>6.1}", value)
    } else if value >= 1.0 {
        format!("{:>6.2}", value)
    } else if value > 0.0 {
        format!("{:>6.3}", value)
    } else {
        "     0".to_string()
    }
}

fn normalize_value(value: f64, axis_max: f64) -> f64 {
    if axis_max <= f64::EPSILON {
        0.0
    } else {
        (value / axis_max).clamp(0.0, 1.0)
    }
}

fn draw_column(grid: &mut Vec<Vec<char>>, col: usize, value: f64) {
    let height = grid.len();
    if height == 0 {
        return;
    }

    for row in 0..height {
        grid[row][col] = ' ';
    }

    let clamped = value.clamp(0.0, 1.0);
    let total_units = clamped * height as f64;
    let mut full_rows = total_units.floor() as isize;
    if full_rows as usize > height {
        full_rows = height as isize;
    }
    let mut remainder = total_units - full_rows as f64;
    if clamped >= 0.999_999 {
        remainder = 1.0;
    }

    for i in 0..full_rows.max(0) {
        let row = height as isize - 1 - i;
        if row < 0 {
            break;
        }
        grid[row as usize][col] = '█';
    }

    if (remainder > f64::EPSILON) && (full_rows as usize) < height {
        let row = height as isize - 1 - full_rows;
        if row >= 0 {
            let idx = (remainder * (SPARK_CHARS.len() as f64 - 1.0)).round() as usize;
            let ch = SPARK_CHARS[idx.min(SPARK_CHARS.len() - 1)];
            if grid[row as usize][col] == ' ' {
                grid[row as usize][col] = ch;
            }
        }
    }
}

fn render_sparkline(history: &VecDeque<f64>, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    const EMPTY_CHAR: char = '·';
    if history.is_empty() {
        return EMPTY_CHAR.to_string().repeat(width);
    }

    let len = history.len();
    let start = len.saturating_sub(width);
    let slice: Vec<f64> = history.iter().skip(start).copied().collect();

    let min = slice.iter().cloned().fold(f64::INFINITY, f64::min).min(0.0);
    let max = slice
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max)
        .max(0.0);
    let range = (max - min).max(f64::EPSILON);

    let padding = width.saturating_sub(slice.len());
    let mut spark = String::with_capacity(width);
    if padding > 0 {
        spark.push_str(&EMPTY_CHAR.to_string().repeat(padding));
    }

    for value in slice {
        let normalized = ((value - min) / range).clamp(0.0, 1.0);
        let idx = (normalized * (SPARK_CHARS.len() as f64 - 1.0)).round() as usize;
        spark.push(SPARK_CHARS[idx.min(SPARK_CHARS.len() - 1)]);
    }

    spark
}

const ANSI_RESET: &str = "\x1b[0m";

#[derive(Clone)]
struct AnsiColor {
    prefix: String,
}

impl AnsiColor {
    fn plain() -> Self {
        Self {
            prefix: String::new(),
        }
    }

    fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        Self {
            prefix: format!("\x1b[38;2;{};{};{}m", r, g, b),
        }
    }

    fn wrap(&self, text: &str) -> String {
        if self.prefix.is_empty() {
            text.to_string()
        } else {
            format!("{}{}{}", self.prefix, text, ANSI_RESET)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ColorMode {
    Always,
    Auto,
    Never,
}

impl FromStr for ColorMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "" => Ok(Self::Always),
            "always" | "true" | "yes" | "1" => Ok(Self::Always),
            "auto" | "tty" => Ok(Self::Auto),
            "never" | "false" | "no" | "0" => Ok(Self::Never),
            other => Err(format!(
                "Invalid color mode '{}'. Use always, auto, or never.",
                other
            )),
        }
    }
}

impl ColorMode {
    fn from_context(ctx: &CliContext) -> Result<Self, String> {
        if ctx.has_flag("no-color") {
            return Ok(Self::Never);
        }

        if let Some(flag) = ctx.get_flag("color") {
            return ColorMode::from_str(&flag);
        }

        if env::var("CLICOLOR_FORCE")
            .map(|v| !v.trim().is_empty() && v.trim() != "0")
            .unwrap_or(false)
        {
            return Ok(Self::Always);
        }

        if env::var_os("NO_COLOR").is_some() {
            return Ok(Self::Never);
        }

        if env::var("CLICOLOR")
            .map(|v| v.trim() == "0")
            .unwrap_or(false)
        {
            return Ok(Self::Never);
        }

        Ok(Self::Always)
    }

    fn should_color(self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                if env::var_os("NO_COLOR").is_some() {
                    return false;
                }
                // Check if stdout is a terminal
                #[cfg(not(target_os = "windows"))]
                {
                    unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
                }
                #[cfg(target_os = "windows")]
                {
                    // On Windows, check via GetStdHandle
                    use std::os::windows::io::AsRawHandle;
                    let handle = std::io::stdout().as_raw_handle();
                    unsafe {
                        #[link(name = "kernel32")]
                        extern "system" {
                            fn GetConsoleMode(handle: *mut std::ffi::c_void, mode: *mut u32)
                                -> i32;
                        }
                        let mut mode = 0;
                        GetConsoleMode(handle as *mut _, &mut mode) != 0
                    }
                }
            }
        }
    }
}

struct ColorTheme {
    rps: AnsiColor,
    latency: AnsiColor,
    cpu: AnsiColor,
    ram: AnsiColor,
    summary: AnsiColor,
}

impl ColorTheme {
    fn default() -> Self {
        Self {
            rps: AnsiColor::from_rgb(179, 136, 255),     // brand purple
            latency: AnsiColor::from_rgb(128, 222, 234), // pastel cyan
            cpu: AnsiColor::from_rgb(255, 171, 145),     // warm coral
            ram: AnsiColor::from_rgb(200, 230, 201),     // mint green
            summary: AnsiColor::from_rgb(171, 71, 188),  // accent purple
        }
    }

    fn monochrome() -> Self {
        let base = AnsiColor::plain();
        Self {
            rps: base.clone(),
            latency: base.clone(),
            cpu: base.clone(),
            ram: base.clone(),
            summary: base,
        }
    }

    fn from_flags(
        rps: Option<&String>,
        latency: Option<&String>,
        cpu: Option<&String>,
        ram: Option<&String>,
        mode: ColorMode,
    ) -> Result<Self, String> {
        if !mode.should_color() {
            return Ok(Self::monochrome());
        }
        let defaults = Self::default();
        Ok(Self {
            rps: parse_color_flag(rps, &defaults.rps)?,
            latency: parse_color_flag(latency, &defaults.latency)?,
            cpu: parse_color_flag(cpu, &defaults.cpu)?,
            ram: parse_color_flag(ram, &defaults.ram)?,
            summary: defaults.summary.clone(),
        })
    }

    fn wrap_rps(&self, text: &str) -> String {
        self.rps.wrap(text)
    }

    fn wrap_latency(&self, text: &str) -> String {
        self.latency.wrap(text)
    }

    fn wrap_cpu(&self, text: &str) -> String {
        self.cpu.wrap(text)
    }

    fn wrap_ram(&self, text: &str) -> String {
        self.ram.wrap(text)
    }

    fn wrap_summary(&self, text: &str) -> String {
        self.summary.wrap(text)
    }

    fn wrap_cpu_line(&self, text: &str) -> String {
        self.cpu.wrap(text)
    }

    fn wrap_ram_line(&self, text: &str) -> String {
        self.ram.wrap(text)
    }
}

fn parse_color_flag(flag: Option<&String>, default: &AnsiColor) -> Result<AnsiColor, String> {
    match flag {
        Some(value) if !value.trim().is_empty() => parse_color_value(value),
        _ => Ok(default.clone()),
    }
}

fn parse_color_value(value: &str) -> Result<AnsiColor, String> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    let rgb = match lower.as_str() {
        "purple" => (179, 136, 255),
        "teal" => (100, 216, 203),
        "coral" => (255, 171, 145),
        "mint" => (165, 214, 167),
        "gold" => (255, 224, 130),
        "royal" => (121, 134, 203),
        _ => {
            let hex = lower.trim_start_matches('#');
            if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "Invalid color value '{}'. Use hex like #RRGGBB or names: purple, teal, coral, mint, gold, royal.",
                    trimmed
                ));
            }
            let r = u8::from_str_radix(&hex[0..2], 16).map_err(|_| {
                format!(
                    "Invalid color value '{}'. Unable to parse red channel.",
                    trimmed
                )
            })?;
            let g = u8::from_str_radix(&hex[2..4], 16).map_err(|_| {
                format!(
                    "Invalid color value '{}'. Unable to parse green channel.",
                    trimmed
                )
            })?;
            let b = u8::from_str_radix(&hex[4..6], 16).map_err(|_| {
                format!(
                    "Invalid color value '{}'. Unable to parse blue channel.",
                    trimmed
                )
            })?;
            (r, g, b)
        }
    };
    Ok(AnsiColor::from_rgb(rgb.0, rgb.1, rgb.2))
}

struct SystemStats {
    prev_total: Option<u64>,
    prev_idle: Option<u64>,
    cpu_percent: Option<f64>,
    mem_total_kib: Option<u64>,
    mem_used_kib: Option<u64>,
    mem_percent: Option<f64>,
}

impl SystemStats {
    fn new() -> Self {
        Self {
            prev_total: None,
            prev_idle: None,
            cpu_percent: None,
            mem_total_kib: None,
            mem_used_kib: None,
            mem_percent: None,
        }
    }

    fn refresh(&mut self) {
        self.update_cpu();
        self.update_mem();
    }

    fn update_cpu(&mut self) {
        if let Ok(contents) = fs::read_to_string("/proc/stat") {
            if let Some(line) = contents.lines().next() {
                let mut parts = line.split_whitespace();
                let _ = parts.next(); // skip "cpu"
                let mut values = Vec::new();
                for part in parts {
                    if let Ok(val) = part.parse::<u64>() {
                        values.push(val);
                    }
                }
                if values.len() >= 4 {
                    let idle = values[3] + values.get(4).copied().unwrap_or(0);
                    let total: u64 = values.iter().sum();
                    if let (Some(prev_total), Some(prev_idle)) = (self.prev_total, self.prev_idle) {
                        let total_diff = total.saturating_sub(prev_total);
                        if total_diff > 0 {
                            let idle_diff = idle.saturating_sub(prev_idle);
                            let used = total_diff.saturating_sub(idle_diff);
                            self.cpu_percent = Some((used as f64 / total_diff as f64) * 100.0);
                        }
                    }
                    self.prev_total = Some(total);
                    self.prev_idle = Some(idle);
                }
            }
        }
    }

    fn update_mem(&mut self) {
        self.mem_percent = None;
        if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
            let mut total = None;
            let mut available = None;
            for line in contents.lines() {
                if line.starts_with("MemTotal:") {
                    total = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok());
                } else if line.starts_with("MemAvailable:") {
                    available = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok());
                }
                if total.is_some() && available.is_some() {
                    break;
                }
            }
            if let (Some(total_kib), Some(avail_kib)) = (total, available) {
                self.mem_total_kib = Some(total_kib);
                self.mem_used_kib = Some(total_kib.saturating_sub(avail_kib));
                if total_kib > 0 {
                    let percent = ((total_kib - avail_kib) as f64 / total_kib as f64) * 100.0;
                    self.mem_percent = Some(percent);
                }
            }
        }
    }

    fn cpu_percent_value(&self) -> Option<f64> {
        self.cpu_percent
    }

    fn cpu_compact_display(&self) -> String {
        if let Some(percent) = self.cpu_percent {
            format!("{:>5.1}%", percent)
        } else {
            "  n/a".to_string()
        }
    }

    fn mem_percent_value(&self) -> Option<f64> {
        self.mem_percent
    }

    fn mem_compact_display(&self) -> String {
        if let Some(percent) = self.mem_percent {
            format!("{:>5.1}%", percent)
        } else {
            "  n/a".to_string()
        }
    }

    fn mem_detail_display(&self) -> String {
        match (self.mem_used_kib, self.mem_total_kib) {
            (Some(used), Some(total)) if total > 0 => {
                let used_gb = used as f64 / (1024.0 * 1024.0);
                let total_gb = total as f64 / (1024.0 * 1024.0);
                format!("({:.1}/{:.1}G)", used_gb, total_gb)
            }
            _ => String::from("(n/a)"),
        }
    }
}
