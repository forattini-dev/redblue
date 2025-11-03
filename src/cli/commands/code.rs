use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::collection::secrets::{SecretFinding, SecretScanner};

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
        vec![Route {
            verb: "scan",
            summary: "Scan directory or file for secrets",
            usage: "rb code secrets scan <path>",
        }]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("min-entropy", "Minimum entropy threshold for detection").with_default("3.5"),
            Flag::new("max-file-size", "Maximum file size in MB to scan").with_default("10"),
            Flag::new("output", "Output format: text or json")
                .with_short('o')
                .with_default("text"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Scan current directory for secrets",
                "rb code secrets scan .",
            ),
            (
                "Scan specific directory",
                "rb code secrets scan /path/to/repo",
            ),
            (
                "Scan with JSON output",
                "rb code secrets scan . --output json",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided. Use 'scan'.".to_string()
        })?;

        match verb.as_str() {
            "scan" => self.scan(ctx),
            _ => {
                print_help(self);
                Err(format!("Unknown verb '{}'. Valid: scan", verb))
            }
        }
    }
}

impl CodeCommand {
    fn scan(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or_else(|| {
            "Missing target path. Syntax: rb code secrets scan <path>".to_string()
        })?;

        Output::header("Secret Scanner (Gitleaks)");
        Output::item("Target", target);

        // Get output format
        let output_format = ctx
            .flags
            .get("output")
            .or_else(|| ctx.flags.get("o"))
            .map(|s| s.as_str())
            .unwrap_or("text");

        Output::spinner_start(&format!("Scanning {} for secrets", target));

        // Create scanner
        let scanner = SecretScanner::new();

        // Scan the directory
        let findings = scanner.scan_directory(target)?;

        Output::spinner_done();

        // Display results based on output format
        match output_format {
            "json" => self.display_json(&findings)?,
            _ => self.display_text(&findings, target)?,
        }

        Ok(())
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
                println!("    Line {}, Column {}", finding.line, finding.column);

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
        let mut by_rule: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
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
        println!("{{");
        println!("  \"findings\": [");

        for (i, finding) in findings.iter().enumerate() {
            let comma = if i < findings.len() - 1 { "," } else { "" };

            println!("    {{");
            println!("      \"file\": \"{}\",", Self::escape_json(&finding.file));
            println!("      \"line\": {},", finding.line);
            println!("      \"column\": {},", finding.column);
            println!(
                "      \"rule_id\": \"{}\",",
                Self::escape_json(&finding.rule_id)
            );
            println!(
                "      \"description\": \"{}\",",
                Self::escape_json(&finding.description)
            );
            println!(
                "      \"secret\": \"{}\",",
                Self::escape_json(&self.mask_secret(&finding.secret))
            );

            if let Some(entropy) = finding.entropy {
                println!("      \"entropy\": {:.2},", entropy);
            } else {
                println!("      \"entropy\": null,");
            }

            println!(
                "      \"line_content\": \"{}\"",
                Self::escape_json(&finding.line_content)
            );
            println!("    }}{}", comma);
        }

        println!("  ],");
        println!("  \"total\": {}", findings.len());
        println!("}}");

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
}
