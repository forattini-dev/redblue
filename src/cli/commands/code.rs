use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::crypto::uuid::Uuid;
use crate::json;
use crate::modules::code::secrets::{SecretValidator, ValidationStatus};
use crate::modules::collection::secrets::git_scanner::GitScanner;
use crate::modules::collection::secrets::{SecretFinding, SecretScanner};
use std::fs;
use std::process::Command as ProcessCommand;

pub struct CodeCommand;

impl Command for CodeCommand {
  fn domain(&self) -> &str {
    "code"
  }

  fn resource(&self) -> &str {
    "secrets"
  }

  fn description(&self) -> &str {
    "Scan code for secrets, API keys, and credentials (Gitleaks replacement)"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "scan",
        summary: "Scan directory or file for secrets",
        usage: "rb code secrets scan <path|url>",
      },
      Route {
        verb: "validate",
        summary: "Validate a secret against its provider API",
        usage: "rb code secrets validate <secret> --provider <name>",
      },
      Route {
        verb: "providers",
        summary: "List supported secret validation providers",
        usage: "rb code secrets providers",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("min-entropy", "Minimum entropy threshold for detection").with_default("3.5"),
      Flag::new("max-file-size", "Maximum file size in MB to scan").with_default("10"),
      Flag::new("output", "Output format: text or json")
        .with_short('o')
        .with_default("text"),
      Flag::new("history", "Scan git history (full log) for remote repos").with_default("true"),
      Flag::new(
        "validate",
        "Validate detected secrets against provider APIs",
      )
      .with_short('V'),
      Flag::new("provider", "Provider name for secret validation").with_short('p'),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Scan current directory for secrets",
        "rb code secrets scan .",
      ),
      (
        "Scan remote git repository",
        "rb code secrets scan https://github.com/owner/repo.git",
      ),
      (
        "Scan and validate secrets",
        "rb code secrets scan . --validate",
      ),
      (
        "Validate a GitHub token",
        "rb code secrets validate ghp_xxxx --provider github",
      ),
      (
        "Validate with auto-detection",
        "rb code secrets validate sk_live_xxxx",
      ),
      ("List supported providers", "rb code secrets providers"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided. Use 'scan', 'validate', or 'providers'.".to_string()
    })?;

    match verb.as_str() {
      "scan" => self.scan(ctx),
      "validate" => self.validate(ctx),
      "providers" => self.list_providers(),
      _ => {
        print_help(self);
        Err(format!(
          "Unknown verb '{}'. Valid: scan, validate, providers",
          verb
        ))
      }
    }
  }
}

impl CodeCommand {
  fn scan(&self, ctx: &CliContext) -> Result<(), String> {
    let target = ctx
      .target
      .as_ref()
      .ok_or_else(|| "Missing target path. Syntax: rb code secrets scan <path>".to_string())?;

    Output::header("Secret Scanner (Gitleaks)");
    Output::item("Target", target);

    // Get output format
    let output_format = ctx
      .flags
      .get("output")
      .or_else(|| ctx.flags.get("o"))
      .map(|s| s.as_str())
      .unwrap_or("text");

    // Check if target is a URL
    let is_url =
      target.starts_with("http://") || target.starts_with("https://") || target.starts_with("git@");

    let findings = if is_url {
      self.scan_remote_repo(target, ctx)?
    } else {
      // Local scan
      Output::spinner_start(&format!("Scanning {} for secrets", target));
      let scanner = SecretScanner::new();
      let res = scanner.scan_directory(target)?;
      Output::spinner_done();
      res
    };

    // Display results based on output format
    match output_format {
      "json" => self.display_json(&findings)?,
      _ => self.display_text(&findings, target)?,
    }

    Ok(())
  }

  fn scan_remote_repo(&self, url: &str, _ctx: &CliContext) -> Result<Vec<SecretFinding>, String> {
    let temp_dir = std::env::temp_dir().join(format!("redblue-scan-{}", Uuid::new_v4()));
    let temp_path = temp_dir.to_string_lossy().to_string();

    Output::info(&format!("Cloning {} to temporary directory...", url));

    let status = ProcessCommand::new("git")
      .arg("clone")
      .arg(url)
      .arg(&temp_path)
      .status()
      .map_err(|e| format!("Failed to execute git clone: {}", e))?;

    if !status.success() {
      return Err("Git clone failed".to_string());
    }

    Output::success("Repository cloned successfully");
    Output::spinner_start("Scanning git history for secrets...");

    let git_scanner = GitScanner::new();
    // Use scan_history for remote repos to catch secrets in commits
    let findings = git_scanner.scan_history(&temp_path);

    Output::spinner_done();

    // Cleanup
    if let Err(e) = fs::remove_dir_all(&temp_path) {
      Output::error(&format!(
        "Failed to clean up temporary directory {}: {}",
        temp_path, e
      ));
    } else {
      Output::info("Temporary directory cleaned up");
    }

    findings
  }

  fn display_text(&self, findings: &[SecretFinding], target: &str) -> Result<(), String> {
    if findings.is_empty() {
      Output::success(&format!("No secrets found in {}", target));
      return Ok(());
    }

    Output::warning(&format!("Found {} potential secret(s)", findings.len()));
    println!();

    // Group findings by file
    let mut by_file: std::collections::HashMap<String, Vec<&SecretFinding>> =
      std::collections::HashMap::new();

    for finding in findings {
      by_file
        .entry(finding.file.clone())
        .or_insert_with(Vec::new)
        .push(finding);
    }

    // Sort files alphabetically
    let mut files: Vec<_> = by_file.keys().collect();
    files.sort();

    for file_path in files {
      let file_findings = by_file.get(file_path).unwrap();

      // Display file header
      println!("\x1b[1m\x1b[34m{}\x1b[0m", file_path);

      for finding in file_findings {
        // Display finding details
        println!(
          "  \x1b[33m{}\x1b[0m ({})",
          finding.description, finding.rule_id
        );
        println!(
          "    Line {}, Column {}",
          finding
            .line
            .map(|l| l.to_string())
            .unwrap_or_else(|| "?".to_string()),
          finding.column
        );

        // Display entropy if available
        if let Some(entropy) = finding.entropy {
          println!("    Entropy: \x1b[36m{:.2}\x1b[0m", entropy);
        }

        // Display the secret (masked)
        let masked_secret = self.mask_secret(&finding.secret);
        println!("    Secret: \x1b[31m{}\x1b[0m", masked_secret);

        // Display line content (trimmed)
        let trimmed_line = finding.line_content.trim();
        if !trimmed_line.is_empty() && trimmed_line.len() < 120 {
          println!("    Context: \x1b[2m{}\x1b[0m", trimmed_line);
        }

        println!();
      }
    }

    // Display summary
    println!("\x1b[1mSummary:\x1b[0m");
    println!("  Total findings: \x1b[31m{}\x1b[0m", findings.len());
    println!("  Files affected: \x1b[33m{}\x1b[0m", by_file.len());

    // Display breakdown by rule
    let mut by_rule: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for finding in findings {
      *by_rule.entry(finding.description.clone()).or_insert(0) += 1;
    }

    println!("\n\x1b[1mBy Type:\x1b[0m");
    let mut rule_counts: Vec<_> = by_rule.iter().collect();
    rule_counts.sort_by(|a, b| b.1.cmp(a.1));
    for (rule, count) in rule_counts {
      println!("  {}: {}", rule, count);
    }

    Ok(())
  }

  fn display_json(&self, findings: &[SecretFinding]) -> Result<(), String> {
    let findings_json: Vec<_> = findings
      .iter()
      .map(|finding| {
        json!({
            "file": finding.file.clone(),
            "line": finding.line,
            "column": finding.column,
            "rule_id": finding.rule_id.clone(),
            "description": finding.description.clone(),
            "secret": self.mask_secret(&finding.secret),
            "entropy": finding.entropy,
            "line_content": finding.line_content.clone()
        })
      })
      .collect();
    Output::json_value(&json!({
        "findings": findings_json,
        "total": findings.len()
    }));

    Ok(())
  }

  /// Mask secret for display (show first 4 and last 4 chars)
  fn mask_secret(&self, secret: &str) -> String {
    if secret.len() <= 12 {
      return "*".repeat(secret.len());
    }

    let start = &secret[..4];
    let end = &secret[secret.len() - 4..];
    format!("{}...{}", start, end)
  }

  /// Escape JSON string
  fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
      .replace('"', "\\\"")
      .replace('\n', "\\n")
      .replace('\r', "\\r")
      .replace('\t', "\\t")
  }

  /// Validate a secret against its provider API
  fn validate(&self, ctx: &CliContext) -> Result<(), String> {
    let secret = ctx.target.as_ref().ok_or_else(|| {
      "Missing secret. Syntax: rb code secrets validate <secret> --provider <name>".to_string()
    })?;

    Output::header("Secret Validator");

    let validator = SecretValidator::new();

    // Get provider from flags or try auto-detection
    let provider = ctx.flags.get("provider").or_else(|| ctx.flags.get("p"));

    let result = if let Some(provider_name) = provider {
      Output::item("Provider", provider_name);
      Output::item("Secret", &self.mask_secret(secret));
      Output::spinner_start("Validating secret...");
      validator.validate(secret, provider_name)
    } else {
      // Try to auto-detect provider from secret pattern
      Output::item("Secret", &self.mask_secret(secret));
      Output::info("No provider specified, attempting auto-detection...");
      Output::spinner_start("Validating secret...");

      // Try to detect provider from secret prefix
      let detected_provider = self.detect_provider_from_secret(secret);
      if let Some(provider_name) = detected_provider {
        Output::item("Detected provider", provider_name);
        validator.validate(secret, provider_name)
      } else {
        Output::spinner_done();
        return Err("Could not auto-detect provider. Please specify --provider <name>".to_string());
      }
    };

    Output::spinner_done();

    // Display result
    match result.status {
      ValidationStatus::Valid => {
        Output::success(&format!(
          "Secret is VALID for provider: {}",
          result.provider
        ));

        // Show additional info if available
        if !result.info.is_empty() {
          println!("\n\x1b[1mAccount Info:\x1b[0m");
          for (key, value) in &result.info {
            println!("  {}: \x1b[36m{}\x1b[0m", key, value);
          }
        }

        println!(
          "\n\x1b[33m⚠ WARNING: This secret is active and should be rotated immediately!\x1b[0m"
        );
      }
      ValidationStatus::Invalid => {
        Output::info(&format!(
          "Secret is INVALID for provider: {}",
          result.provider
        ));
        println!("  The secret appears to be expired, revoked, or incorrect.");
      }
      ValidationStatus::RateLimited => {
        Output::warning(&format!("Rate limited by provider: {}", result.provider));
        println!("  Try again later or reduce validation frequency.");
      }
      ValidationStatus::Error => {
        Output::error(&format!(
          "Validation error: {}",
          result.error.unwrap_or_default()
        ));
      }
      ValidationStatus::Unsupported => {
        Output::error(&format!("Provider '{}' is not supported", result.provider));
        println!("  Run 'rb code secrets providers' to see supported providers.");
      }
      ValidationStatus::IncompleteParams => {
        Output::error("Additional parameters required for this provider");
      }
    }

    println!("\n  Response time: {}ms", result.response_time_ms);

    Ok(())
  }

  /// List all supported secret validation providers
  fn list_providers(&self) -> Result<(), String> {
    Output::header("Supported Secret Providers");

    let validator = SecretValidator::new();
    let mut providers: Vec<&str> = validator.supported_providers();
    providers.sort();

    println!("\n\x1b[1m{} providers available:\x1b[0m\n", providers.len());

    // Group by category
    let categories = [
      (
        "Cloud",
        vec![
          "aws",
          "gcp",
          "azure",
          "digitalocean",
          "heroku",
          "vercel",
          "netlify",
          "linode",
          "vultr",
        ],
      ),
      (
        "Code",
        vec![
          "github",
          "gitlab",
          "bitbucket",
          "circleci",
          "travisci",
          "buildkite",
          "npm",
          "pypi",
        ],
      ),
      (
        "Communication",
        vec![
          "slack", "discord", "telegram", "twilio", "sendgrid", "mailgun", "postmark",
        ],
      ),
      ("Payment", vec!["stripe", "paypal", "square", "coinbase"]),
      (
        "AI/ML",
        vec!["openai", "anthropic", "replicate", "huggingface"],
      ),
      (
        "Monitoring",
        vec!["datadog", "sentry", "pagerduty", "newrelic"],
      ),
      (
        "SaaS",
        vec![
          "hubspot", "zendesk", "asana", "notion", "linear", "airtable",
        ],
      ),
      (
        "Security",
        vec!["shodan", "virustotal", "securitytrails", "censys"],
      ),
    ];

    for (category, expected) in &categories {
      let found: Vec<&&str> = providers.iter().filter(|p| expected.contains(*p)).collect();

      if !found.is_empty() {
        println!("\x1b[1;34m{}:\x1b[0m", category);
        for provider in found {
          println!("  • {}", provider);
        }
        println!();
      }
    }

    // Show any remaining uncategorized
    let categorized: Vec<&str> = categories
      .iter()
      .flat_map(|(_, providers)| providers.iter().copied())
      .collect();
    let other: Vec<&&str> = providers
      .iter()
      .filter(|p| !categorized.contains(*p))
      .collect();

    if !other.is_empty() {
      println!("\x1b[1;34mOther:\x1b[0m");
      for provider in other {
        println!("  • {}", provider);
      }
      println!();
    }

    println!("\x1b[2mUsage: rb code secrets validate <secret> --provider <name>\x1b[0m");

    Ok(())
  }

  /// Try to detect provider from secret pattern
  fn detect_provider_from_secret(&self, secret: &str) -> Option<&'static str> {
    // GitHub tokens
    if secret.starts_with("ghp_")
      || secret.starts_with("gho_")
      || secret.starts_with("ghu_")
      || secret.starts_with("ghs_")
    {
      return Some("github");
    }

    // Stripe keys
    if secret.starts_with("sk_live_")
      || secret.starts_with("sk_test_")
      || secret.starts_with("pk_live_")
      || secret.starts_with("pk_test_")
    {
      return Some("stripe");
    }

    // Slack tokens
    if secret.starts_with("xoxb-")
      || secret.starts_with("xoxp-")
      || secret.starts_with("xoxa-")
      || secret.starts_with("xoxs-")
    {
      return Some("slack");
    }

    // OpenAI
    if secret.starts_with("sk-") && secret.len() > 40 {
      return Some("openai");
    }

    // Discord
    if secret.len() == 59 && secret.contains('.') {
      return Some("discord");
    }

    // Telegram Bot
    if secret.contains(':')
      && secret
        .split(':')
        .next()
        .map(|s| s.parse::<u64>().is_ok())
        .unwrap_or(false)
    {
      return Some("telegram");
    }

    // Anthropic
    if secret.starts_with("sk-ant-") {
      return Some("anthropic");
    }

    // GitLab
    if secret.starts_with("glpat-") {
      return Some("gitlab");
    }

    // npm
    if secret.starts_with("npm_") {
      return Some("npm");
    }

    // Shodan
    if secret.len() == 32 && secret.chars().all(|c| c.is_ascii_alphanumeric()) {
      // Could be Shodan or many others - don't auto-detect
      return None;
    }

    None
  }
}
