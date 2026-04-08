/// Port Health Check CLI Command
///
/// Re-scans stored ports to detect state changes over time.
/// Commands: check, diff, watch
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, validator::Validator, CliContext};
use crate::json;
use crate::modules::network::health::{
  PortCheckResult, PortDiff, PortHealthChecker, PortWatcher, WatchConfig,
};
use crate::serde_json::Value;
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

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let machine_output = match verb {
      "check" | "diff" => crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      "watch" => crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      _ => self.metadata().machine_output,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(machine_output)
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

    if !ctx.wants_machine_output() {
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

    if !ctx.wants_machine_output() {
      Output::spinner_start("Scanning ports");
    }
    let results = checker.check_ports(target, &ports);
    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }

    let payload = Self::check_payload(target, &results, timeout_ms, threads);
    if render::render_machine_output(ctx, "rb network health check", &payload)? {
      return Ok(());
    }

    self.display_check_results(&results);

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

  fn check_payload(
    target: &str,
    results: &[PortCheckResult],
    timeout_ms: u64,
    threads: usize,
  ) -> Value {
    let open_count = results.iter().filter(|r| r.is_open).count();
    let closed_count = results.len() - open_count;
    let open_ports: Vec<_> = results
      .iter()
      .filter(|r| r.is_open)
      .map(|result| {
        json!({
            "port": result.port,
            "service": result.service,
            "response_time_ms": result.response_time_ms
        })
      })
      .collect();
    let closed_ports: Vec<_> = results
      .iter()
      .filter(|r| !r.is_open)
      .map(|result| result.port)
      .collect();

    json!({
      "target": target,
      "timeout_ms": timeout_ms,
      "threads": threads,
      "total_ports": results.len(),
      "open_count": open_count,
      "closed_count": closed_count,
      "open_ports": open_ports,
      "closed_ports": closed_ports
    })
  }

  /// Compare current scan with previous scan from database
  fn diff(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network health diff <HOST> [--db <file>]\nExample: rb network health diff 192.168.1.1",
        )?;

    Validator::validate_host(target)?;
    let payload = Self::diff_payload(target);
    if render::render_machine_output(ctx, "rb network health diff", &payload)? {
      return Ok(());
    }

    // For now, show a placeholder until we integrate with storage
    Output::header(&format!("Port Health Diff: {}", target));
    Output::warning("Database integration not yet implemented");
    Output::info("Use 'rb network health check' to scan ports first");
    Output::info("Then use 'rb network health watch' for continuous monitoring");

    Ok(())
  }

  fn diff_payload(target: &str) -> Value {
    json!({
      "target": target,
      "status": "not_implemented",
      "message": "Database integration not yet implemented",
      "suggestions": vec![
        "Use 'rb network health check' to scan ports first",
        "Use 'rb network health watch' for continuous monitoring"
      ]
    })
  }

  /// Watch ports continuously
  fn watch(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
            "Missing target.\nUsage: rb network health watch <HOST> [--interval 60]\nExample: rb network health watch 192.168.1.1",
        )?;

    Validator::validate_host(target)?;

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

    if ctx.wants_machine_output() {
      if max_iterations.is_none() {
        return Err(
          "Machine output for `rb network health watch` requires `--count` to avoid an infinite stream."
            .to_string(),
        );
      }
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

    if ctx.wants_machine_output() {
      let mut iterations: Vec<Value> = Vec::new();
      watcher.watch(target, &ports, |results, diff, iteration| {
        iterations.push(Self::watch_iteration_payload(results, diff, iteration));
      });

      let payload = Self::watch_payload(
        target,
        interval_secs,
        timeout_ms,
        ports.len(),
        max_iterations,
        &iterations,
      );
      if render::render_machine_output(ctx, "rb network health watch", &payload)? {
        return Ok(());
      }
    } else {
      watcher.watch(target, &ports, |results, diff, iteration| {
        self.display_watch_iteration(results, diff, iteration);
      });
      Output::success("Watch complete");
    }
    Ok(())
  }

  /// Display watch iteration results
  fn display_watch_iteration(&self, results: &[PortCheckResult], diff: &PortDiff, iteration: u32) {
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

  fn watch_iteration_payload(
    results: &[PortCheckResult],
    diff: &PortDiff,
    iteration: u32,
  ) -> Value {
    let open_count = results.iter().filter(|r| r.is_open).count();
    let closed_count = results.len() - open_count;
    let timestamp = chrono_lite_timestamp();

    let open_ports: Vec<_> = results
      .iter()
      .filter(|r| r.is_open)
      .map(|result| {
        json!({
            "port": result.port,
            "service": result.service,
            "response_time_ms": result.response_time_ms
        })
      })
      .collect();
    let now_open: Vec<_> = diff
      .now_open
      .iter()
      .map(|result| json!({"port": result.port, "service": result.service}))
      .collect();
    let now_closed: Vec<_> = diff
      .now_closed
      .iter()
      .map(|result| json!({"port": result.port, "service": result.service}))
      .collect();
    let new_ports: Vec<_> = diff
      .new_ports
      .iter()
      .map(|result| json!({"port": result.port, "service": result.service}))
      .collect();
    json!({
      "iteration": iteration,
      "timestamp": timestamp,
      "open_count": open_count,
      "closed_count": closed_count,
      "has_changes": diff.has_changes(),
      "total_changes": diff.total_changes(),
      "open_ports": open_ports,
      "changes": json!({
          "now_open": now_open,
          "now_closed": now_closed,
          "new_ports": new_ports
      })
    })
  }

  fn watch_payload(
    target: &str,
    interval_secs: u64,
    timeout_ms: u64,
    ports_monitored: usize,
    max_iterations: Option<u32>,
    iterations: &[Value],
  ) -> Value {
    let total_changes = iterations
      .iter()
      .filter_map(|item| item.get("total_changes").and_then(Value::as_i64))
      .sum::<i64>();
    let last_open_count = iterations
      .last()
      .and_then(|item| item.get("open_count"))
      .and_then(Value::as_i64)
      .unwrap_or(0);
    let last_closed_count = iterations
      .last()
      .and_then(|item| item.get("closed_count"))
      .and_then(Value::as_i64)
      .unwrap_or(0);

    json!({
      "target": target,
      "interval_secs": interval_secs,
      "timeout_ms": timeout_ms,
      "ports_monitored": ports_monitored,
      "max_iterations": max_iterations,
      "iterations_count": iterations.len(),
      "total_changes": total_changes,
      "last_open_count": last_open_count,
      "last_closed_count": last_closed_count,
      "iterations": iterations.to_vec()
    })
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::storage::records::PortStateChange;

  #[test]
  fn check_payload_counts_open_and_closed_ports() {
    let results = vec![
      PortCheckResult {
        host: "example.com".to_string(),
        ip: None,
        port: 22,
        is_open: true,
        response_time_ms: 12,
        change: PortStateChange::New,
        service: Some("ssh".to_string()),
      },
      PortCheckResult {
        host: "example.com".to_string(),
        ip: None,
        port: 80,
        is_open: false,
        response_time_ms: 0,
        change: PortStateChange::New,
        service: None,
      },
    ];

    let payload = HealthCommand::check_payload("example.com", &results, 1000, 50);
    let object = payload.as_object().expect("payload should be an object");

    assert_eq!(
      object.get("target").and_then(Value::as_str),
      Some("example.com")
    );
    assert_eq!(object.get("open_count").and_then(Value::as_i64), Some(1));
    assert_eq!(object.get("closed_count").and_then(Value::as_i64), Some(1));
  }

  #[test]
  fn diff_payload_marks_not_implemented() {
    let payload = HealthCommand::diff_payload("example.com");
    let object = payload.as_object().expect("payload should be an object");

    assert_eq!(
      object.get("target").and_then(Value::as_str),
      Some("example.com")
    );
    assert_eq!(
      object.get("status").and_then(Value::as_str),
      Some("not_implemented")
    );
  }
}
