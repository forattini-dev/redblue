/// Git Exposed Scanner - Detect and dump exposed .git directories
///
/// Security testing tool for authorized penetration testing.
/// Detects exposed .git directories and downloads repository content.
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::CliContext;
use crate::modules::web::git_exposed::{GitObjectType, GitScanner, ScanConfig, ScanResult};

pub struct GitExposedCommand;

impl Command for GitExposedCommand {
  fn domain(&self) -> &str {
    "web"
  }

  fn resource(&self) -> &str {
    "git"
  }

  fn description(&self) -> &str {
    "Exposed .git directory scanner (git-scanner style)"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "scan",
        summary: "Scan for exposed .git directory",
        usage: "rb web git scan <url>",
      },
      Route {
        verb: "dump",
        summary: "Dump exposed git objects to directory",
        usage: "rb web git dump <url> --output <dir>",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output directory for dumped objects").with_short('o'),
      Flag::new("timeout", "Request timeout in seconds")
        .with_short('t')
        .with_default("30"),
      Flag::new("max-objects", "Maximum objects to download").with_default("10000"),
      Flag::new("scan-secrets", "Scan for secrets in recovered content"),
      Flag::new("scan-history", "Scan git history for secrets"),
      Flag::new("no-packs", "Skip pack file download"),
      Flag::new("verbose", "Verbose output").with_short('v'),
      Flag::new("format", "Output format (text|json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Scan for exposed .git", "rb web git scan http://target.com"),
      (
        "Dump exposed repository",
        "rb web git dump http://target.com --output ./git-dump",
      ),
      (
        "Scan with secret detection",
        "rb web git scan http://target.com --scan-secrets",
      ),
      (
        "Full scan with history",
        "rb web git scan http://target.com --scan-secrets --scan-history",
      ),
      (
        "Quick scan (skip packs)",
        "rb web git scan http://target.com --no-packs",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "Missing verb. Use: rb web git <scan|dump>".to_string()
    })?;

    match verb.as_str() {
      "scan" => self.scan_git(ctx),
      "dump" => self.dump_git(ctx),
      "help" => {
        print_help(self);
        Ok(())
      }
      _ => Err(format!("Unknown verb '{}'. Use: rb web git help", verb)),
    }
  }
}

impl GitExposedCommand {
  /// Build scanner configuration from context
  fn build_config(&self, ctx: &CliContext) -> ScanConfig {
    let mut config = ScanConfig::default();

    if let Some(timeout) = ctx.flags.get("timeout") {
      config.timeout = timeout.parse().unwrap_or(30);
    }

    if let Some(max) = ctx.flags.get("max-objects") {
      config.max_objects = max.parse().unwrap_or(10000);
    }

    if ctx.flags.contains_key("scan-secrets") {
      config.scan_secrets = true;
    }

    if ctx.flags.contains_key("scan-history") {
      config.scan_history = true;
    }

    if ctx.flags.contains_key("no-packs") {
      config.download_packs = false;
    }

    if ctx.flags.contains_key("verbose") {
      config.verbose = true;
    }

    config
  }

  /// Scan for exposed .git directory
  fn scan_git(&self, ctx: &CliContext) -> Result<(), String> {
    let url = ctx
      .args
      .first()
      .ok_or("Missing URL. Usage: rb web git scan <url>")?;

    let config = self.build_config(ctx);

    println!("\n\x1b[1;36m\u{25b6} Git Exposure Scan\x1b[0m");
    println!("  Target: {}", url);
    if config.scan_secrets {
      println!("  Secret scanning: enabled");
    }
    if config.scan_history {
      println!("  History scanning: enabled");
    }
    println!();

    let scanner = GitScanner::new(config);

    match scanner.scan(url) {
      Ok(result) => {
        self.print_result(&result);
        Ok(())
      }
      Err(e) => Err(format!("Scan failed: {:?}", e)),
    }
  }

  /// Dump exposed git objects
  fn dump_git(&self, ctx: &CliContext) -> Result<(), String> {
    let url = ctx
      .args
      .first()
      .ok_or("Missing URL. Usage: rb web git dump <url> --output <dir>")?;

    let output = ctx
      .flags
      .get("output")
      .ok_or("Missing --output directory")?;

    let config = self.build_config(ctx);

    println!("\n\x1b[1;36m\u{25b6} Git Object Dump\x1b[0m");
    println!("  Target: {}", url);
    println!("  Output: {}", output);
    println!();

    let scanner = GitScanner::new(config);

    // First scan
    print!("  Scanning for exposed .git... ");
    let result = scanner
      .scan(url)
      .map_err(|e| format!("Scan failed: {:?}", e))?;

    if !result.is_vulnerable() {
      println!("\x1b[32mNot exposed\x1b[0m");
      println!("\n  Status: {:?}", result.status);
      return Ok(());
    }

    println!("\x1b[31mEXPOSED\x1b[0m");
    println!();

    // Dump objects
    print!("  Dumping objects... ");
    match scanner.dump_to_dir(&result, output) {
      Ok(count) => {
        println!("\x1b[32mDone\x1b[0m");
        println!("\n  Objects written: {}", count);
        println!("  Output directory: {}", output);
      }
      Err(e) => {
        println!("\x1b[31mFailed\x1b[0m");
        return Err(format!("Dump failed: {:?}", e));
      }
    }

    // Print summary
    self.print_result(&result);

    Ok(())
  }

  /// Print scan result
  fn print_result(&self, result: &ScanResult) {
    let status_color = match result.severity {
      crate::modules::common::Severity::Critical => "\x1b[1;31m", // Bold red
      crate::modules::common::Severity::High => "\x1b[31m",       // Red
      crate::modules::common::Severity::Medium => "\x1b[33m",     // Yellow
      _ => "\x1b[32m",                                            // Green
    };

    println!("\n\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}");
    println!(
      "  Status: {}{}  ({:?})\x1b[0m",
      status_color,
      result.status.as_str().to_uppercase(),
      result.severity
    );

    if result.is_vulnerable() {
      println!("\x1b[31m  \u{26a0} .git directory is EXPOSED!\x1b[0m");
    } else {
      println!("\x1b[32m  \u{2713} .git directory is protected\x1b[0m");
    }

    // Object counts
    let counts = result.object_counts();
    if !counts.is_empty() {
      println!("\n  Objects discovered:");
      for (obj_type, count) in &counts {
        let type_name = match obj_type {
          GitObjectType::Commit => "Commits",
          GitObjectType::Tree => "Trees",
          GitObjectType::Blob => "Blobs",
          GitObjectType::Tag => "Tags",
          GitObjectType::Unknown => "Unknown",
        };
        println!("    {} {}", count, type_name);
      }
    }

    // Secrets found
    if !result.secrets.is_empty() {
      println!(
        "\n  \x1b[31mSecrets detected: {}\x1b[0m",
        result.secrets.len()
      );
      for (i, secret) in result.secrets.iter().take(10).enumerate() {
        println!(
          "    {}. [{}] {} in {}",
          i + 1,
          secret.secret_type,
          truncate(&secret.match_content, 40),
          secret.path
        );
      }
      if result.secrets.len() > 10 {
        println!("    ... and {} more", result.secrets.len() - 10);
      }
    }

    println!();
  }
}

/// Truncate string with ellipsis
fn truncate(s: &str, max_len: usize) -> String {
  if s.len() <= max_len {
    s.to_string()
  } else {
    format!(
      "{}\
...",
      &s[..max_len - 3]
    )
  }
}
