/// Dependencies command - Scan dependencies for vulnerabilities
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::collection::dependencies::{DependencyScanner, VulnSeverity};

pub struct DepsCommand;

impl Command for DepsCommand {
    fn domain(&self) -> &str {
        "code"
    }

    fn resource(&self) -> &str {
        "dependencies"
    }

    fn description(&self) -> &str {
        "Scan dependencies for known vulnerabilities (Snyk/npm audit replacement)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![Route {
            verb: "scan",
            summary: "Scan project dependencies for vulnerabilities",
            usage: "rb code dependencies scan <path>",
        }]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![Flag::new("output", "Output format: text or json")
            .with_short('o')
            .with_default("text")]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Scan current directory", "rb code dependencies scan ."),
            (
                "Scan specific project",
                "rb code dependencies scan /path/to/project",
            ),
            (
                "Scan with JSON output",
                "rb code dependencies scan . --output json",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "scan" => self.scan(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                print_help(self);
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl DepsCommand {
    fn scan(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx
            .target
            .as_ref()
            .ok_or("Missing target path.\nUsage: rb code dependencies scan <PATH>\nExample: rb code dependencies scan .")?;

        let format = ctx.get_output_format();

        Output::header("Dependency Scanner (Snyk)");
        Output::item("Target", target);
        println!();

        Output::spinner_start(&format!("Scanning {} for dependency files", target));
        let scanner = DependencyScanner::new();
        let result = scanner.scan_directory(target)?;
        Output::spinner_done();

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            self.output_json(&result);
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            self.output_yaml(&result);
            return Ok(());
        }

        // Human-readable output
        if result.files_scanned.is_empty() {
            Output::warning("No dependency files found");
            return Ok(());
        }

        Output::success(&format!(
            "Found {} dependency files",
            result.files_scanned.len()
        ));
        println!();

        // Show files scanned
        Output::subheader("Dependency Files Scanned:");
        for file in &result.files_scanned {
            println!("  ✓ {}", Output::colorize(file, "cyan"));
        }
        println!();

        // Summary
        Output::subheader(&format!(
            "Summary: {} total dependencies, {} vulnerable",
            result.total_dependencies, result.vulnerable_dependencies
        ));
        println!();

        if result.vulnerabilities.is_empty() {
            Output::success("✓ No known vulnerabilities found!");
            return Ok(());
        }

        // Show vulnerabilities
        Output::warning(&format!(
            "⚠️  Found {} vulnerable dependencies",
            result.vulnerabilities.len()
        ));
        println!();

        // Group by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();

        for vuln in &result.vulnerabilities {
            match vuln.severity {
                VulnSeverity::Critical => critical.push(vuln),
                VulnSeverity::High => high.push(vuln),
                VulnSeverity::Medium => medium.push(vuln),
                VulnSeverity::Low => low.push(vuln),
            }
        }

        // Display vulnerabilities by severity
        if !critical.is_empty() {
            self.display_vulnerabilities("CRITICAL", &critical, "red");
        }
        if !high.is_empty() {
            self.display_vulnerabilities("HIGH", &high, "red");
        }
        if !medium.is_empty() {
            self.display_vulnerabilities("MEDIUM", &medium, "yellow");
        }
        if !low.is_empty() {
            self.display_vulnerabilities("LOW", &low, "blue");
        }

        println!();
        Output::warning("⚠️  Run 'npm audit fix' or update packages to resolve vulnerabilities");

        Ok(())
    }

    fn display_vulnerabilities(
        &self,
        severity: &str,
        vulns: &[&crate::modules::collection::dependencies::Vulnerability],
        color: &str,
    ) {
        println!("\n{} Severity:", Output::colorize(severity, color));

        for vuln in vulns {
            println!(
                "  • {} ({})",
                Output::colorize(&vuln.package_name, "cyan"),
                vuln.affected_version
            );

            if let Some(cve) = &vuln.cve_id {
                println!("    CVE: {}", Output::colorize(cve, "blue"));
            }

            println!("    {}", vuln.title);

            if let Some(fixed) = &vuln.fixed_version {
                println!("    Fix: Upgrade to {}", Output::colorize(fixed, "green"));
            }

            println!();
        }
    }

    fn output_json(&self, result: &crate::modules::collection::dependencies::DependencyScanResult) {
        println!("{{");
        println!("  \"total_dependencies\": {},", result.total_dependencies);
        println!(
            "  \"vulnerable_dependencies\": {},",
            result.vulnerable_dependencies
        );
        println!("  \"files_scanned\": [");

        for (i, file) in result.files_scanned.iter().enumerate() {
            let comma = if i < result.files_scanned.len() - 1 {
                ","
            } else {
                ""
            };
            println!(
                "    \"{}\"{}",
                file.replace('\\', "\\\\").replace('"', "\\\""),
                comma
            );
        }

        println!("  ],");
        println!("  \"vulnerabilities\": [");

        for (i, vuln) in result.vulnerabilities.iter().enumerate() {
            let comma = if i < result.vulnerabilities.len() - 1 {
                ","
            } else {
                ""
            };
            println!("    {{");
            println!("      \"package\": \"{}\",", vuln.package_name);
            println!("      \"affected_version\": \"{}\",", vuln.affected_version);
            println!("      \"severity\": \"{}\",", vuln.severity.as_str());

            if let Some(cve) = &vuln.cve_id {
                println!("      \"cve_id\": \"{}\",", cve);
            } else {
                println!("      \"cve_id\": null,");
            }

            println!("      \"title\": \"{}\",", vuln.title.replace('"', "\\\""));

            if let Some(fixed) = &vuln.fixed_version {
                println!("      \"fixed_version\": \"{}\"", fixed);
            } else {
                println!("      \"fixed_version\": null");
            }

            println!("    }}{}", comma);
        }

        println!("  ]");
        println!("}}");
    }

    fn output_yaml(&self, result: &crate::modules::collection::dependencies::DependencyScanResult) {
        println!("total_dependencies: {}", result.total_dependencies);
        println!(
            "vulnerable_dependencies: {}",
            result.vulnerable_dependencies
        );
        println!("files_scanned:");

        for file in &result.files_scanned {
            println!("  - \"{}\"", file.replace('"', "\\\""));
        }

        println!("vulnerabilities:");

        for vuln in &result.vulnerabilities {
            println!("  - package: {}", vuln.package_name);
            println!("    affected_version: {}", vuln.affected_version);
            println!("    severity: {}", vuln.severity.as_str());

            if let Some(cve) = &vuln.cve_id {
                println!("    cve_id: {}", cve);
            } else {
                println!("    cve_id: null");
            }

            println!("    title: \"{}\"", vuln.title.replace('"', "\\\""));

            if let Some(fixed) = &vuln.fixed_version {
                println!("    fixed_version: {}", fixed);
            } else {
                println!("    fixed_version: null");
            }
        }
    }
}
