// Benchmark/load testing command - Performance and stress testing

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

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(self.metadata().machine_output)
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
        "Testing mode: throughput, connections, realistic, stress, slowloris",
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
      Flag::new(
        "slowloris-interval",
        "Seconds between keep-alive headers in slowloris mode",
      )
      .with_default("10"),
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
      Flag::new("live-interval", "Seconds between live dashboard updates").with_default("1.0"),
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
        "Slowloris attack (hold connections open)",
        "rb bench load run https://example.com --mode slowloris --users 500",
      ),
      (
        "Slowloris with custom interval",
        "rb bench load run https://example.com --mode slowloris --users 200 --slowloris-interval 5",
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

    let slowloris_interval_secs = ctx
      .get_flag("slowloris-interval")
      .and_then(|s| s.parse::<u64>().ok())
      .unwrap_or(10);

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
      .with_http2_max_connections(http2_connections)
      .with_slowloris_interval(Duration::from_secs(slowloris_interval_secs));

    if let Some(req_count) = requests {
      config = config.with_requests(req_count);
    } else {
      config = config.with_duration(Duration::from_secs(duration_secs));
    }

    // Display config
    if mode == LoadMode::Slowloris {
      Output::header("HTTP Slowloris Attack");
      Output::warning("SLOW HTTP DoS - USE ONLY ON AUTHORIZED TARGETS");
    } else {
      Output::header("HTTP Load Test");
    }
    Output::item("Target", url);
    Output::item(
      "Mode",
      &format!("{} ({})", mode.label(), mode.description()),
    );
    Output::item("Concurrent Users", &users.to_string());
    if mode == LoadMode::Slowloris {
      Output::item("Header Interval", &format!("{}s", slowloris_interval_secs));
      Output::item(
        "Initial Headers",
        &config.slowloris_initial_headers.to_string(),
      );
    }
    if let Some(req) = requests {
      Output::item("Requests/User", &req.to_string());
    } else {
      Output::item("Duration", &format!("{}s", duration_secs));
    }
    if mode != LoadMode::Slowloris {
      Output::item("Think Time", &format!("{}ms", think_time_ms));
    }
    Output::item("Protocol", protocol.label());
    if mode != LoadMode::Slowloris {
      Output::item("Method", &method);
      let body_display = if body_size > 0 {
        format!("{} bytes", body_size)
      } else {
        "none".to_string()
      };
      Output::item("Body", &body_display);
    }
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

}
