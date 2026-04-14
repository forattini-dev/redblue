//! `rb system stress` — resource stress testing (cpu, mem, io, all).
//!
//! AUTHORIZED USE ONLY. Designed for resilience auditing of systems you own
//! or have written permission to test. Hard timeout ceiling enforced.

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::stress::{
  clamp_timeout, cpu, io, limits, mem, num_cpus_fallback, CpuMethod, StressConfig, StressStats,
  MAX_TIMEOUT_SECS,
};
use crate::serde_json::Value;
use std::time::Duration;

pub struct SystemStressCommand;

impl Command for SystemStressCommand {
  fn domain(&self) -> &str {
    "system"
  }

  fn resource(&self) -> &str {
    "stress"
  }

  fn description(&self) -> &str {
    "Stress test local CPU, memory, and disk I/O — resilience auditing"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(self.metadata().machine_output)
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "cpu",
        summary: "Saturate CPU cores with compute-bound workers",
        usage: "rb system stress cpu [--workers N] [--timeout 30s] [--method sha256|matrix|prime]",
      },
      Route {
        verb: "mem",
        summary: "Allocate and touch pages to pressure RAM",
        usage: "rb system stress mem [--bytes 2G | --pct 50] [--workers N] [--timeout 30s]",
      },
      Route {
        verb: "io",
        summary: "Write/fsync/read/unlink loops against a scratch directory",
        usage: "rb system stress io [--workers N] [--bytes 100M] [--path /tmp] [--no-fsync] [--timeout 30s]",
      },
      Route {
        verb: "all",
        summary: "Run cpu + mem + io stressors in parallel",
        usage: "rb system stress all [--timeout 30s] [--cpu-workers N] [--mem 2G] [--io-workers N]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("workers", "Number of worker threads (default: CPU count)")
        .with_short('w')
        .with_arg("N"),
      Flag::new("timeout", "Test duration (e.g. 30s, 1m, 5m; max 10m)")
        .with_short('t')
        .with_default("30s"),
      Flag::new("bytes", "Allocation/IO size (e.g. 1G, 512M)")
        .with_short('b')
        .with_arg("SIZE"),
      Flag::new("pct", "Memory budget as percent of MemAvailable").with_arg("N"),
      Flag::new("method", "CPU work method: sha256, matrix, prime").with_default("sha256"),
      Flag::new("path", "Scratch directory for IO stress").with_default("/tmp"),
      Flag::new("no-fsync", "Skip fsync between write/read cycles (IO)"),
      Flag::new(
        "max-mem-pct",
        "Hard cap on memory alloc as percent of MemAvailable",
      )
      .with_default("80"),
      Flag::new("cpu-workers", "Worker count for CPU stressor in 'all' mode").with_arg("N"),
      Flag::new("io-workers", "Worker count for IO stressor in 'all' mode").with_arg("N"),
      Flag::new("mem", "Memory budget for 'all' mode (e.g. 2G)").with_arg("SIZE"),
      Flag::new("dry-run", "Print plan without running"),
      Flag::new("output", "Output format (text, json)")
        .with_short('o')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Saturate all cores for 30s", "rb system stress cpu -t 30s"),
      (
        "CPU stress with 8 workers, 1m",
        "rb system stress cpu -w 8 -t 1m",
      ),
      (
        "Allocate 2 GiB of RAM for 30s",
        "rb system stress mem -b 2G -t 30s",
      ),
      (
        "Pressure 50% of available memory",
        "rb system stress mem --pct 50 -t 30s",
      ),
      (
        "Write/fsync loop in /tmp for 20s",
        "rb system stress io -w 2 -t 20s",
      ),
      (
        "IO stress under custom path, no fsync",
        "rb system stress io --path /var/tmp --no-fsync -t 10s",
      ),
      ("Run all three in parallel", "rb system stress all -t 30s"),
      (
        "Combined stress with explicit budgets",
        "rb system stress all -t 30s --cpu-workers 4 --mem 2G --io-workers 2",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = match ctx.verb.as_deref() {
      Some(v) => v,
      None => {
        print_help(self);
        return Err("Missing verb. Use 'cpu', 'mem', 'io', or 'all'.".into());
      }
    };

    match verb {
      "help" => {
        print_help(self);
        Ok(())
      }
      "cpu" => run_cpu(self, ctx),
      "mem" => run_mem(self, ctx),
      "io" => run_io(self, ctx),
      "all" => run_all(self, ctx),
      _ => {
        print_help(self);
        Err(format!(
          "Unknown verb '{}'. Use cpu, mem, io, or all.",
          verb
        ))
      }
    }
  }
}

fn run_cpu(cmd: &SystemStressCommand, ctx: &CliContext) -> Result<(), String> {
  let cfg = parse_cpu_config(ctx)?;
  if dry_run(ctx) {
    return emit_plan(cmd, ctx, "cpu", &cfg);
  }
  print_human_preamble(ctx, "cpu", &cfg);
  let stats = cpu::run(&cfg);
  emit_stats(cmd, ctx, "cpu", &stats)
}

fn run_mem(cmd: &SystemStressCommand, ctx: &CliContext) -> Result<(), String> {
  let cfg = parse_mem_config(ctx)?;
  if dry_run(ctx) {
    return emit_plan(cmd, ctx, "mem", &cfg);
  }
  print_human_preamble(ctx, "mem", &cfg);
  let stats = mem::run(&cfg);
  emit_stats(cmd, ctx, "mem", &stats)
}

fn run_io(cmd: &SystemStressCommand, ctx: &CliContext) -> Result<(), String> {
  let cfg = parse_io_config(ctx)?;
  if dry_run(ctx) {
    return emit_plan(cmd, ctx, "io", &cfg);
  }
  print_human_preamble(ctx, "io", &cfg);
  let stats = io::run(&cfg);
  emit_stats(cmd, ctx, "io", &stats)
}

fn run_all(cmd: &SystemStressCommand, ctx: &CliContext) -> Result<(), String> {
  let timeout = parse_timeout(ctx)?;
  let max_mem_pct = parse_max_mem_pct(ctx)?;

  let cpu_cfg = StressConfig {
    workers: flag_usize(ctx, "cpu-workers").unwrap_or_else(num_cpus_fallback),
    timeout,
    method: parse_method(ctx)?,
    ..StressConfig::default()
  };

  let mem_bytes = match ctx.flags.get("mem").map(|s| s.as_str()) {
    Some(s) if !s.is_empty() => Some(limits::parse_bytes(s)?),
    _ => None,
  };
  let mem_cfg = StressConfig {
    workers: 2,
    timeout,
    bytes: mem_bytes,
    mem_pct: flag_u8(ctx, "pct"),
    max_mem_pct,
    ..StressConfig::default()
  };

  let io_cfg = StressConfig {
    workers: flag_usize(ctx, "io-workers").unwrap_or(2),
    timeout,
    bytes: Some(100 * 1024 * 1024),
    path: Some(
      ctx
        .flags
        .get("path")
        .cloned()
        .unwrap_or_else(|| "/tmp".into()),
    ),
    fsync: !flag_bool(ctx, "no-fsync"),
    ..StressConfig::default()
  };

  if dry_run(ctx) {
    let payload = json!({
      "mode": "all",
      "timeout_secs": timeout.as_secs(),
      "cpu": plan_json(&cpu_cfg),
      "mem": plan_json(&mem_cfg),
      "io":  plan_json(&io_cfg),
    });
    if render::render_machine_output(ctx, "rb system stress all", &payload)? {
      return Ok(());
    }
    Output::header("Stress plan: all");
    Output::item("Timeout", &format!("{}s", timeout.as_secs()));
    Output::item("CPU workers", &cpu_cfg.workers.to_string());
    Output::item("Mem workers", &mem_cfg.workers.to_string());
    Output::item("IO workers", &io_cfg.workers.to_string());
    return Ok(());
  }

  print_human_preamble(ctx, "all", &cpu_cfg);

  let cpu_handle = std::thread::Builder::new()
    .name("rb-stress-all-cpu".into())
    .spawn(move || cpu::run(&cpu_cfg))
    .map_err(|e| format!("spawn cpu thread: {}", e))?;
  let mem_handle = std::thread::Builder::new()
    .name("rb-stress-all-mem".into())
    .spawn(move || mem::run(&mem_cfg))
    .map_err(|e| format!("spawn mem thread: {}", e))?;
  let io_handle = std::thread::Builder::new()
    .name("rb-stress-all-io".into())
    .spawn(move || io::run(&io_cfg))
    .map_err(|e| format!("spawn io thread: {}", e))?;

  let cpu_stats = cpu_handle.join().map_err(|_| "cpu worker panicked")?;
  let mem_stats = mem_handle.join().map_err(|_| "mem worker panicked")?;
  let io_stats = io_handle.join().map_err(|_| "io worker panicked")?;

  let payload = json!({
    "mode": "all",
    "cpu": stats_to_json(&cpu_stats),
    "mem": stats_to_json(&mem_stats),
    "io":  stats_to_json(&io_stats),
  });
  if render::render_machine_output(ctx, "rb system stress all", &payload)? {
    return Ok(());
  }

  print_stats_human(&cpu_stats);
  println!();
  print_stats_human(&mem_stats);
  println!();
  print_stats_human(&io_stats);
  Ok(())
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

fn parse_cpu_config(ctx: &CliContext) -> Result<StressConfig, String> {
  Ok(StressConfig {
    workers: flag_usize(ctx, "workers").unwrap_or_else(num_cpus_fallback),
    timeout: parse_timeout(ctx)?,
    method: parse_method(ctx)?,
    ..StressConfig::default()
  })
}

fn parse_mem_config(ctx: &CliContext) -> Result<StressConfig, String> {
  let bytes = match ctx.flags.get("bytes").map(|s| s.as_str()) {
    Some(s) if !s.is_empty() => Some(limits::parse_bytes(s)?),
    _ => None,
  };
  Ok(StressConfig {
    workers: flag_usize(ctx, "workers").unwrap_or(2),
    timeout: parse_timeout(ctx)?,
    bytes,
    mem_pct: flag_u8(ctx, "pct"),
    max_mem_pct: parse_max_mem_pct(ctx)?,
    ..StressConfig::default()
  })
}

fn parse_io_config(ctx: &CliContext) -> Result<StressConfig, String> {
  let bytes = match ctx.flags.get("bytes").map(|s| s.as_str()) {
    Some(s) if !s.is_empty() => Some(limits::parse_bytes(s)?),
    _ => Some(100 * 1024 * 1024),
  };
  Ok(StressConfig {
    workers: flag_usize(ctx, "workers").unwrap_or(2),
    timeout: parse_timeout(ctx)?,
    bytes,
    path: Some(
      ctx
        .flags
        .get("path")
        .cloned()
        .unwrap_or_else(|| "/tmp".into()),
    ),
    fsync: !flag_bool(ctx, "no-fsync"),
    ..StressConfig::default()
  })
}

fn parse_timeout(ctx: &CliContext) -> Result<Duration, String> {
  let raw = ctx
    .flags
    .get("timeout")
    .cloned()
    .unwrap_or_else(|| "30s".into());
  let secs = limits::parse_duration_secs(&raw)?;
  if secs > MAX_TIMEOUT_SECS {
    return Err(format!(
      "timeout {}s exceeds safety ceiling of {}s",
      secs, MAX_TIMEOUT_SECS
    ));
  }
  Ok(clamp_timeout(Duration::from_secs(secs)))
}

fn parse_method(ctx: &CliContext) -> Result<CpuMethod, String> {
  let raw = ctx
    .flags
    .get("method")
    .cloned()
    .unwrap_or_else(|| "sha256".into());
  CpuMethod::parse(&raw).ok_or_else(|| format!("unknown method '{}'", raw))
}

fn parse_max_mem_pct(ctx: &CliContext) -> Result<u8, String> {
  let v = ctx
    .flags
    .get("max-mem-pct")
    .and_then(|s| s.parse::<u8>().ok())
    .unwrap_or(80);
  if v == 0 || v > 100 {
    return Err("--max-mem-pct must be in 1..=100".into());
  }
  Ok(v)
}

fn flag_usize(ctx: &CliContext, key: &str) -> Option<usize> {
  ctx.flags.get(key).and_then(|s| s.parse().ok())
}

fn flag_u8(ctx: &CliContext, key: &str) -> Option<u8> {
  ctx.flags.get(key).and_then(|s| s.parse().ok())
}

fn dry_run(ctx: &CliContext) -> bool {
  flag_bool(ctx, "dry-run")
}

fn flag_bool(ctx: &CliContext, key: &str) -> bool {
  ctx.flags.get(key).map(|v| v == "true").unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn print_human_preamble(ctx: &CliContext, kind: &str, cfg: &StressConfig) {
  use crate::cli::format::OutputFormat;
  if ctx.get_output_format() != OutputFormat::Human {
    return;
  }
  Output::header(&format!("Stress {}", kind));
  Output::item("Workers", &cfg.workers.to_string());
  Output::item("Timeout", &format!("{}s", cfg.timeout.as_secs()));
  if kind == "mem" {
    if let Some(b) = cfg.bytes {
      Output::item("Budget", &limits::format_bytes(b));
    } else if let Some(p) = cfg.mem_pct {
      Output::item("Budget", &format!("{}% of MemAvailable", p));
    } else {
      Output::item("Budget", "25% of MemAvailable (default)");
    }
    Output::item("Safety cap", &format!("{}% MemAvailable", cfg.max_mem_pct));
  }
  if kind == "io" {
    if let Some(p) = &cfg.path {
      Output::item("Path", p);
    }
    Output::item("fsync", if cfg.fsync { "on" } else { "off" });
  }
  if kind == "cpu" {
    Output::item("Method", cfg.method.name());
  }
  println!();
  Output::info("Running... (Ctrl+C to abort)");
}

fn emit_plan(
  _cmd: &SystemStressCommand,
  ctx: &CliContext,
  kind: &str,
  cfg: &StressConfig,
) -> Result<(), String> {
  let payload = json!({
    "mode": kind,
    "plan": plan_json(cfg),
  });
  if render::render_machine_output(ctx, &format!("rb system stress {}", kind), &payload)? {
    return Ok(());
  }
  Output::header(&format!("Stress plan: {}", kind));
  Output::item("Workers", &cfg.workers.to_string());
  Output::item("Timeout", &format!("{}s", cfg.timeout.as_secs()));
  if let Some(b) = cfg.bytes {
    Output::item("Bytes", &limits::format_bytes(b));
  }
  if let Some(p) = cfg.mem_pct {
    Output::item("Pct", &format!("{}%", p));
  }
  if kind == "cpu" {
    Output::item("Method", cfg.method.name());
  }
  if kind == "io" {
    if let Some(p) = &cfg.path {
      Output::item("Path", p);
    }
    Output::item("fsync", if cfg.fsync { "on" } else { "off" });
  }
  Output::info("Dry run — no work performed.");
  Ok(())
}

fn emit_stats(
  _cmd: &SystemStressCommand,
  ctx: &CliContext,
  kind: &str,
  stats: &StressStats,
) -> Result<(), String> {
  let payload = stats_to_json(stats);
  if render::render_machine_output(ctx, &format!("rb system stress {}", kind), &payload)? {
    return Ok(());
  }
  print_stats_human(stats);
  Ok(())
}

fn print_stats_human(stats: &StressStats) {
  Output::section(&format!("Stress {} — results", stats.kind));
  Output::item("Workers", &stats.workers.to_string());
  Output::item(
    "Elapsed",
    &format!("{:.2}s", stats.elapsed_ms as f64 / 1000.0),
  );
  Output::item("Total ops", &limits::format_ops(stats.total_ops));
  Output::item(
    "Ops/sec",
    &format!("{} /s", limits::format_ops(stats.ops_per_sec as u64)),
  );
  if stats.bytes_touched > 0 {
    Output::item("Bytes touched", &limits::format_bytes(stats.bytes_touched));
    Output::item(
      "Bytes/sec",
      &format!("{}/s", limits::format_bytes(stats.bytes_per_sec as u64)),
    );
  }
  if stats.peak_rss_kb > 0 {
    Output::item("Peak RSS", &limits::format_bytes(stats.peak_rss_kb * 1024));
  }
  if let Some((one, five, fifteen)) = stats.load_avg {
    Output::item(
      "Load avg",
      &format!("{:.2} {:.2} {:.2}", one, five, fifteen),
    );
  }
  if !stats.per_worker_ops.is_empty() && stats.per_worker_ops.len() <= 16 {
    let per: Vec<String> = stats
      .per_worker_ops
      .iter()
      .map(|v| limits::format_ops(*v))
      .collect();
    Output::item("Per-worker", &per.join(", "));
  }
  if let Some(note) = &stats.note {
    Output::item("Note", note);
  }
}

fn stats_to_json(stats: &StressStats) -> Value {
  json!({
    "kind": stats.kind,
    "workers": stats.workers,
    "elapsed_ms": stats.elapsed_ms,
    "total_ops": stats.total_ops,
    "ops_per_sec": stats.ops_per_sec,
    "bytes_touched": stats.bytes_touched,
    "bytes_per_sec": stats.bytes_per_sec,
    "per_worker_ops": stats.per_worker_ops.clone(),
    "peak_rss_kb": stats.peak_rss_kb,
    "load_avg": stats.load_avg.map(|(a, b, c)| json!([a, b, c])),
    "note": stats.note.clone(),
  })
}

fn plan_json(cfg: &StressConfig) -> Value {
  json!({
    "workers": cfg.workers,
    "timeout_secs": cfg.timeout.as_secs(),
    "bytes": cfg.bytes,
    "mem_pct": cfg.mem_pct,
    "path": cfg.path,
    "fsync": cfg.fsync,
    "method": cfg.method.name(),
    "max_mem_pct": cfg.max_mem_pct,
  })
}
