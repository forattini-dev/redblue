//! Network port scanning commands
//!
//! Layout:
//!   * basic    — TCP connect scans (ports, range, subnet)
//!   * advanced — raw-socket scans (syn/udp/stealth/mass)
//!   * helpers  — payload builders + parsers shared across classes

/// Network/ports command - Port scanning and network discovery
use crate::cli::commands::{build_partition_attributes, print_help, Command, Flag, Route};
use crate::cli::{
  format::OutputFormat,
  output::{Output, ProgressBar},
  render,
  validator::Validator,
  CliContext,
};
use crate::config;
use crate::intelligence::{
  banner_analysis, os_probes, os_signatures, service_detection, timing_analysis,
};
use crate::json;
use crate::modules::network::highspeed::{
  DeduplicationCache, RandomScanIterator, ScanRange, SynCookie, TokenBucket,
};
use crate::modules::network::scanner::{
  AdvancedScanner, PortScanResult, PortScanner, ScanType, TimingTemplate,
};
use crate::serde_json::Value;
use crate::storage::service::StorageService;
use std::collections::HashMap;
use std::sync::Arc;

mod advanced;
mod basic;
mod helpers;

pub struct ScanCommand;

impl Command for ScanCommand {
  fn domain(&self) -> &str {
    "network"
  }

  fn resource(&self) -> &str {
    "ports"
  }

  fn description(&self) -> &str {
    "Port scanning and network discovery"
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
      "scan" | "range" | "syn-scan" | "udp-scan" | "stealth" => {
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly)
      }
      _ => self.metadata().machine_output,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(machine_output)
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "scan",
        summary: "Scan a host using predefined port presets",
        usage: "rb network ports scan <host> [--preset common]",
      },
      Route {
        verb: "range",
        summary: "Scan an arbitrary port range on a host",
        usage: "rb network ports range <host> <start> <end>",
      },
      Route {
        verb: "syn-scan",
        summary: "TCP SYN scan (half-open, requires root/CAP_NET_RAW)",
        usage: "rb network ports syn-scan <host> [--preset common]",
      },
      Route {
        verb: "udp-scan",
        summary: "UDP scan with ICMP unreachable detection",
        usage: "rb network ports udp-scan <host> [--preset common]",
      },
      Route {
        verb: "stealth",
        summary: "Stealth scan (FIN/NULL/XMAS, requires root)",
        usage: "rb network ports stealth <host> --type fin|null|xmas",
      },
      Route {
        verb: "subnet",
        summary: "Discover and scan all hosts in a subnet (CIDR notation)",
        usage: "rb network ports subnet <cidr> [--preset common]",
      },
      Route {
        verb: "mass-scan",
        summary: "High-speed masscan-style scan with BlackRock IP randomization",
        usage: "rb network ports mass-scan <cidr> [--rate 1000] [--ports 1-1000]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    let cfg = config::get();
    let threads_default = cfg.network.threads.to_string();
    let timeout_default = cfg.network.timeout_ms.to_string();

    vec![
      Flag::new("threads", "Number of concurrent threads")
        .with_short('t')
        .with_default(&threads_default),
      Flag::new("timeout", "Timeout in milliseconds").with_default(&timeout_default),
      Flag::new("preset", "Use port preset (common|full|web)").with_short('p'),
      Flag::new(
        "fast",
        "Fast mode (masscan-style): 1000 threads, 300ms timeout",
      )
      .with_short('f'),
      Flag::new("output", "Output format (text|json)")
        .with_short('o')
        .with_default("text"),
      Flag::new("save", "Force save to database (overrides config)"),
      Flag::new("no-save", "Disable auto-save for this command"),
      Flag::new("db", "Custom database file path").with_short('d'),
      Flag::new(
        "db-password",
        "Database encryption password (overrides keyring)",
      ),
      Flag::new(
        "intel",
        "Gather intelligence on discovered services (timing, banners, OS hints)",
      )
      .with_short('i'),
      Flag::new("type", "Stealth scan type (fin|null|xmas) for stealth verb"),
      Flag::new(
        "timing",
        "Timing template: T0=paranoid, T1=sneaky, T2=polite, T3=normal, T4=aggressive, T5=insane",
      )
      .with_short('T'),
      Flag::new(
        "os-detect",
        "Enable OS fingerprinting (TCP/IP stack analysis, requires open port)",
      )
      .with_short('O'),
      // High-speed scanning flags
      Flag::new("rate", "Packets per second for mass-scan (default: 1000)").with_short('r'),
      Flag::new(
        "ports",
        "Port specification for mass-scan (e.g., 1-1000,8080,8443)",
      ),
      Flag::new("resume", "Resume mass-scan from index"),
      Flag::new(
        "shard",
        "Distributed shard: N/M (e.g., 1/4 for first of 4 shards)",
      ),
      Flag::new("seed", "Random seed for reproducible IP ordering"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Scan common ports",
        "rb network ports scan 192.168.1.1 --preset common",
      ),
      (
        "Scan and save to encrypted database",
        "rb network ports scan 192.168.1.1 --preset common --save",
      ),
      (
        "Fast scan (masscan-style)",
        "rb network ports scan 10.0.0.1 --fast",
      ),
      (
        "Fast scan with more threads",
        "rb network ports scan 10.0.0.1 --threads 500",
      ),
      (
        "Scan specific range",
        "rb network ports range 192.168.1.1 80 443",
      ),
      (
        "Full port scan (slow)",
        "rb network ports range 192.168.1.1 1 65535 --timeout 500",
      ),
      (
        "Fast full scan (masscan-style)",
        "rb network ports range 192.168.1.1 1 65535 --fast",
      ),
      (
        "JSON output",
        "rb network ports scan 127.0.0.1 --preset common -o json",
      ),
      (
        "Intelligence gathering",
        "rb network ports scan 192.168.1.1 --preset common --intel",
      ),
      (
        "Subnet discovery and scan",
        "rb network ports subnet 192.168.1.0/24 --preset common",
      ),
      (
        "Subnet scan with persistence",
        "rb network ports subnet 10.0.0.0/24 --preset common --save",
      ),
      (
        "SYN scan (requires root)",
        "rb network ports syn-scan 192.168.1.1 --preset common",
      ),
      ("UDP scan", "rb network ports udp-scan 192.168.1.1"),
      (
        "FIN stealth scan",
        "rb network ports stealth 192.168.1.1 --type fin",
      ),
      (
        "XMAS stealth scan",
        "rb network ports stealth 192.168.1.1 --type xmas",
      ),
      (
        "Paranoid timing (IDS evasion)",
        "rb network ports syn-scan 192.168.1.1 --timing T0",
      ),
      (
        "Aggressive timing (fast scan)",
        "rb network ports syn-scan 192.168.1.1 --timing T4",
      ),
      (
        "Insane timing (maximum speed)",
        "rb network ports syn-scan 192.168.1.1 --timing T5 --preset full",
      ),
      (
        "OS fingerprinting",
        "rb network ports scan 192.168.1.1 --preset common --os-detect",
      ),
      (
        "Full scan with OS detection",
        "rb network ports scan 192.168.1.1 -O --intel",
      ),
      (
        "Mass scan subnet (BlackRock randomization)",
        "rb network ports mass-scan 192.168.1.0/24 --rate 1000 --ports 1-1000",
      ),
      (
        "Mass scan with resume capability",
        "rb network ports mass-scan 10.0.0.0/8 --rate 10000 --resume 1000000",
      ),
      (
        "Distributed shard scan (1st of 4 workers)",
        "rb network ports mass-scan 10.0.0.0/8 --shard 1/4",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "scan" => self.scan_ports(ctx),
      "range" => self.scan_range(ctx),
      "syn-scan" => self.advanced_scan(ctx, ScanType::Syn),
      "udp-scan" => self.advanced_scan(ctx, ScanType::Udp),
      "stealth" => self.stealth_scan(ctx),
      "subnet" => self.scan_subnet(ctx),
      "mass-scan" => self.mass_scan(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        println!(
          "{}",
          Validator::suggest_command(
            verb,
            &["scan", "range", "syn-scan", "udp-scan", "stealth", "subnet"]
          )
        );
        Err("Invalid verb".to_string())
      }
    }
  }
}
