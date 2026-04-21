//! IOC (Indicators of Compromise) Intelligence Command
//!
//! Extract, manage, and export IOCs from scan data:
//! - Extract IOCs from port scans, DNS, TLS, HTTP
//! - Export to STIX, JSON, or CSV formats
//! - Search and filter IOCs
//! - Link to MITRE ATT&CK techniques

use super::operations;
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::CliContext;

pub struct IntelIocCommand;

impl Command for IntelIocCommand {
  fn domain(&self) -> &str {
    "intelligence" // Short alias: "intel"
  }

  fn resource(&self) -> &str {
    "ioc"
  }

  fn description(&self) -> &str {
    "Extract and manage Indicators of Compromise (IOCs)"
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
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "extract",
        summary: "Extract IOCs from provided data",
        usage: "rb intel ioc extract [target=domain] [ip=...] [ports=...] [dns=...]",
      },
      Route {
        verb: "export",
        summary: "Export IOCs to STIX, JSON, or CSV format",
        usage: "rb intel ioc export [format=json|csv|stix] [output=file]",
      },
      Route {
        verb: "types",
        summary: "Show supported IOC types",
        usage: "rb intel ioc types",
      },
      Route {
        verb: "demo",
        summary: "Demonstrate IOC extraction with sample data",
        usage: "rb intel ioc demo [target]",
      },
      Route {
        verb: "import",
        summary: "Import IOCs from external file (JSON, CSV, STIX)",
        usage: "rb intel ioc import <file> [format=auto|json|csv|stix]",
      },
      Route {
        verb: "search",
        summary: "Search IOCs by value, type, or tag",
        usage: "rb intel ioc search <query> [type=...] [tag=...]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output format (text, json, yaml)")
        .with_short('o')
        .with_default("text"),
      Flag::new("target", "Target domain or host for IOC context").with_short('t'),
      Flag::new("ip", "IP address from scan results"),
      Flag::new("ports", "Comma-separated open ports").with_short('p'),
      Flag::new("dns", "Domain to extract DNS IOCs from"),
      Flag::new(
        "export-format",
        "Export format for 'export' verb (json, csv, stix)",
      )
      .with_short('f')
      .with_default("json"),
      Flag::new("file", "Output file path for 'export' verb"),
      Flag::new(
        "confidence",
        "Filter by minimum confidence (low, medium, high)",
      )
      .with_short('c'),
      Flag::new("type", "Filter by IOC type (ipv4, domain, email, etc.)"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Extract from port scan",
        "rb intel ioc extract target=example.com ip=93.184.216.34 ports=22,80,443",
      ),
      (
        "Extract as JSON",
        "rb intel ioc extract target=example.com ip=93.184.216.34 ports=22,80,443 --output=json",
      ),
      ("Run demo extraction", "rb intel ioc demo example.com"),
      (
        "Export to JSON file",
        "rb intel ioc export --export-format=json --file=iocs.json",
      ),
      (
        "Export to CSV file",
        "rb intel ioc export --export-format=csv --file=iocs.csv",
      ),
      (
        "Export to STIX file",
        "rb intel ioc export --export-format=stix --file=iocs.stix.json",
      ),
      ("Show IOC types", "rb intel ioc types"),
      ("Show IOC types as JSON", "rb intel ioc types --output=json"),
      ("Import from JSON file", "rb intel ioc import iocs.json"),
      (
        "Import from STIX bundle",
        "rb intel ioc import threat-intel.stix.json --export-format=stix",
      ),
      (
        "Import from CSV",
        "rb intel ioc import indicators.csv --export-format=csv",
      ),
      ("Search by IP", "rb intel ioc search 192.168.1.1"),
      ("Search by type", "rb intel ioc search 192.168.1 type=ipv4"),
      (
        "Search as JSON",
        "rb intel ioc search 192.168.1 --output=json",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "extract" => self.extract_iocs(ctx),
      "export" => self.export_iocs(ctx),
      "types" => self.show_types(ctx),
      "demo" => self.run_demo(ctx),
      "import" => self.import_iocs(ctx),
      "search" => self.search_iocs(ctx),
      _ => {
        print_help(self);
        Err(format!("Unknown verb: {}", verb))
      }
    }
  }
}

impl IntelIocCommand {
  pub(super) fn extract_iocs(&self, ctx: &CliContext) -> Result<(), String> {
    operations::extract_iocs(self, ctx)
  }

  pub(super) fn export_iocs(&self, ctx: &CliContext) -> Result<(), String> {
    operations::export_iocs(self, ctx)
  }

  pub(super) fn show_types(&self, ctx: &CliContext) -> Result<(), String> {
    operations::show_types(self, ctx)
  }

  pub(super) fn run_demo(&self, ctx: &CliContext) -> Result<(), String> {
    operations::run_demo(self, ctx)
  }

  pub(super) fn import_iocs(&self, ctx: &CliContext) -> Result<(), String> {
    operations::import_iocs(self, ctx)
  }

  pub(super) fn search_iocs(&self, ctx: &CliContext) -> Result<(), String> {
    operations::search_iocs(self, ctx)
  }
}
