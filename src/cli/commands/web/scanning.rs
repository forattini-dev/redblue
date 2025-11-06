use crate::cli::{format::OutputFormat, output::Output, validator::Validator, CliContext};
use crate::modules::web::scanner_strategy::{ScanStrategy, UnifiedScanResult, UnifiedWebScanner};
use crate::modules::web::strategies::django::{DjangoScanResult, DjangoSeverity};
use crate::modules::web::strategies::drupal::{
    DrupalScanResult, VulnSeverity as DrupalVulnSeverity,
};
use crate::modules::web::strategies::laravel::{
    FindingSeverity as LaravelSeverity, LaravelScanResult,
};
use crate::modules::web::strategies::wordpress::{VulnSeverity, WPScanResult};
use crate::modules::web::vuln_scanner::{self, Severity, WebScanner};
use std::sync::Arc;

fn guard_plain_http(url: &str, command: &str) -> Result<(), String> {
    if url.to_ascii_lowercase().starts_with("https://") {
        let host_hint = url
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(url);
        return Err(format!(
            "{cmd} currently supports only http:// targets while native TLS transport is under development. \
Use `rb web asset cert {host}` or `rb web asset tls-audit {host}` for HTTPS analysis.",
            cmd = command,
            host = host_hint
        ));
    }
    Ok(())
}

const GENERIC_SCAN_PHASES: u64 = 10;
const CMS_SCAN_PHASES: u64 = 6;

fn scan_step_budget(strategy: ScanStrategy) -> u64 {
    match strategy {
        ScanStrategy::WordPress
        | ScanStrategy::Drupal
        | ScanStrategy::Joomla
        | ScanStrategy::Strapi
        | ScanStrategy::Ghost
        | ScanStrategy::Directus
        | ScanStrategy::Laravel
        | ScanStrategy::Django => CMS_SCAN_PHASES,
        ScanStrategy::Generic => GENERIC_SCAN_PHASES,
        ScanStrategy::AutoDetect => GENERIC_SCAN_PHASES,
    }
}

pub fn run_scan(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL.\nUsage: rb web asset scan <URL> [--strategy auto|wordpress|drupal|joomla|generic]\nExample: rb web asset scan http://example.com --strategy auto",
    )?;

    Validator::validate_url(url)?;
    // HTTPS is supported via the in-tree TLS 1.2 client
    // guard_plain_http(url, "rb web asset scan")?;  // REMOVED - HTTPS works!

    let strategy_str = ctx.get_flag_or("strategy", "auto");
    let strategy = ScanStrategy::from_str(&strategy_str)?;

    Output::header("Web Scan");
    Output::item("Target", url);

    let strategy_display = match strategy {
        ScanStrategy::AutoDetect => "Auto-Detect (fingerprint first)",
        ScanStrategy::WordPress => "WordPress (forced)",
        ScanStrategy::Drupal => "Drupal (forced)",
        ScanStrategy::Joomla => "Joomla (forced)",
        ScanStrategy::Strapi => "Strapi (forced)",
        ScanStrategy::Ghost => "Ghost (forced)",
        ScanStrategy::Directus => "Directus (forced)",
        ScanStrategy::Laravel => "Laravel (forced)",
        ScanStrategy::Django => "Django (forced)",
        ScanStrategy::Generic => "Generic (forced)",
    };
    Output::item("Strategy", strategy_display);
    println!();

    let format = ctx.get_output_format();
    let detection_steps: u64 = if matches!(strategy, ScanStrategy::AutoDetect) {
        1
    } else {
        0
    };
    let short_target = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let initial_total = 1 + detection_steps + scan_step_budget(strategy);

    let progress = if format == OutputFormat::Human {
        Some(Arc::new(Output::progress_bar(
            format!("scan {}", short_target),
            initial_total,
            true,
        )))
    } else {
        None
    };

    if let Some(p) = &progress {
        p.tick(1);
    }

    let unified_scanner = UnifiedWebScanner::new();
    let mut effective_strategy = strategy;

    if matches!(strategy, ScanStrategy::AutoDetect) {
        effective_strategy = unified_scanner.detect_strategy_for(url)?;
        if let Some(p) = &progress {
            p.tick(1);
            let adjusted_total = 1 + detection_steps + scan_step_budget(effective_strategy);
            p.set_total(adjusted_total);
        }
        Output::item(
            "Detected",
            match effective_strategy {
                ScanStrategy::WordPress => "WordPress",
                ScanStrategy::Drupal => "Drupal",
                ScanStrategy::Joomla => "Joomla",
                ScanStrategy::Strapi => "Strapi",
                ScanStrategy::Ghost => "Ghost",
                ScanStrategy::Directus => "Directus",
                ScanStrategy::Laravel => "Laravel",
                ScanStrategy::Django => "Django",
                ScanStrategy::Generic | ScanStrategy::AutoDetect => "Generic",
            },
        );
    } else if let Some(p) = &progress {
        let adjusted_total = 1 + detection_steps + scan_step_budget(effective_strategy);
        p.set_total(adjusted_total);
    }

    let progress_for_scan = progress
        .as_ref()
        .map(|p| Arc::clone(p) as Arc<dyn crate::modules::network::scanner::ScanProgress>);

    let result = unified_scanner.scan_with_strategy_with_progress(
        url,
        effective_strategy,
        progress_for_scan,
    )?;

    if let Some(p) = &progress {
        p.finish();
    }

    println!();

    match result {
        UnifiedScanResult::WordPress(wp_result) => display_wordpress_results(&wp_result),
        UnifiedScanResult::Drupal(drupal_result) => {
            display_drupal_results(&drupal_result)?;
            Output::success("Drupal scan completed");
            Ok(())
        }
        UnifiedScanResult::Joomla(joomla_result) => {
            display_joomla_results(&joomla_result)?;
            Output::success("Joomla scan completed");
            Ok(())
        }
        UnifiedScanResult::Strapi(strapi_result) => {
            Output::info(&format!("Strapi version: {:?}", strapi_result.version));
            Output::success("Strapi scan completed");
            Ok(())
        }
        UnifiedScanResult::Ghost(ghost_result) => {
            Output::info(&format!("Ghost version: {:?}", ghost_result.version));
            Output::success("Ghost scan completed");
            Ok(())
        }
        UnifiedScanResult::Directus(directus_result) => {
            Output::info(&format!("Directus version: {:?}", directus_result.version));
            Output::success("Directus scan completed");
            Ok(())
        }
        UnifiedScanResult::Laravel(laravel_result) => {
            display_laravel_scan_results(&laravel_result)?;
            Output::success("Laravel scan completed");
            Ok(())
        }
        UnifiedScanResult::Django(django_result) => {
            display_django_scan_results(&django_result)?;
            Output::success("Django scan completed");
            Ok(())
        }
        UnifiedScanResult::Generic(vuln_result) => {
            display_generic_vuln_results(&vuln_result)?;
            Output::success("Scan completed");
            Ok(())
        }
        UnifiedScanResult::NotDetected(vuln_result) => {
            Output::info("No specific CMS detected - running generic vulnerability scan");
            println!();
            display_generic_vuln_results(&vuln_result)?;
            Output::success("Scan completed");
            Ok(())
        }
    }
}

pub fn run_active_scan(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL.\nUsage: rb web asset vuln-scan <URL>\nExample: rb web asset vuln-scan http://example.com",
    )?;

    Validator::validate_url(url)?;
    guard_plain_http(url, "rb web asset vuln-scan")?;

    Output::header("Active Vuln Scan");
    Output::item("Target", url);
    Output::warning("This performs ACTIVE testing - only use on authorized targets!");
    println!();

    let format = ctx.get_output_format();
    let total_steps = 1 + 5 + 5; // setup + passive checks + active checks
    let short_target = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let progress = if format == OutputFormat::Human {
        Some(Arc::new(Output::progress_bar(
            format!("vuln {}", short_target),
            total_steps,
            true,
        )))
    } else {
        None
    };

    if let Some(p) = &progress {
        p.tick(1);
    }

    let scanner = WebScanner::new();
    let progress_for_scan = progress.as_ref().map(|p| {
        let cloned = Arc::clone(p) as Arc<dyn crate::modules::network::scanner::ScanProgress>;
        cloned
    });

    let result = scanner.scan_active_with_progress(url, progress_for_scan)?;

    if let Some(p) = &progress {
        p.finish();
    }

    println!();

    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for finding in &result.findings {
        match finding.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    if result.findings.is_empty() {
        Output::success("No vulnerabilities detected!");
    } else {
        Output::subheader(&format!("Found {} Vulnerabilities", result.findings.len()));
        println!();

        println!("  Summary:");
        if critical > 0 {
            println!(
                "    \x1b[31m● CRITICAL: {} (Immediate attention required!)\x1b[0m",
                critical
            );
        }
        if high > 0 {
            println!(
                "    \x1b[31m● HIGH:     {} (High risk - fix ASAP)\x1b[0m",
                high
            );
        }
        if medium > 0 {
            println!(
                "    \x1b[33m● MEDIUM:   {} (Should be fixed)\x1b[0m",
                medium
            );
        }
        if low > 0 {
            println!("    \x1b[36m● LOW:      {} (Low priority)\x1b[0m", low);
        }
        if info > 0 {
            println!("    \x1b[2m● INFO:     {} (Informational)\x1b[0m", info);
        }
        println!();

        Output::subheader("Detailed Findings");
        println!();

        for (i, finding) in result.findings.iter().enumerate() {
            let severity_color = match finding.severity {
                Severity::Critical => "\x1b[31m",
                Severity::High => "\x1b[31m",
                Severity::Medium => "\x1b[33m",
                Severity::Low => "\x1b[36m",
                Severity::Info => "\x1b[2m",
            };

            println!(
                "  {}[{}] {} - {}\x1b[0m",
                severity_color,
                finding.severity,
                i + 1,
                finding.title
            );
            println!("      Path: {}", finding.path);
            println!("      Description: {}", finding.description);
            if let Some(evidence) = &finding.evidence {
                println!("      Evidence: {}", evidence);
            }
            println!();
        }
    }

    println!();
    Output::subheader("Scan Statistics");
    println!(
        "  Duration: {:.2}s",
        result.scan_duration_ms as f64 / 1000.0
    );
    println!("  Total Findings: {}", result.findings.len());
    println!("  Tests Performed: XSS, SQLi, Path Traversal, SSRF, Command Injection");

    println!();
    if result.findings.is_empty() {
        Output::success("Active vulnerability scan completed - No issues found!");
    } else if critical > 0 || high > 0 {
        Output::error("CRITICAL or HIGH severity vulnerabilities detected!");
    } else {
        Output::success("Active vulnerability scan completed");
    }

    Ok(())
}

fn display_wordpress_results(result: &WPScanResult) -> Result<(), String> {
    Output::subheader("WordPress Detected");
    println!();

    if let Some(ref version) = result.version {
        Output::item("Version", version);
    }

    if !result.plugins.is_empty() {
        println!();
        Output::info(&format!("Found {} plugins", result.plugins.len()));
        for plugin in result.plugins.iter().take(5) {
            let version = plugin
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("Unknown");
            println!("  \x1b[36m●\x1b[0m  {} ({})", plugin.name, version);
        }
        if result.plugins.len() > 5 {
            println!("  ... and {} more", result.plugins.len() - 5);
        }
    }

    if !result.themes.is_empty() {
        println!();
        Output::info(&format!("Found {} themes", result.themes.len()));
        for theme in &result.themes {
            let version = theme
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("Unknown");
            println!("  \x1b[35m●\x1b[0m  {} ({})", theme.name, version);
        }
    }

    if !result.users.is_empty() {
        println!();
        Output::warning(&format!("Enumerated {} users", result.users.len()));
        for user in result.users.iter().take(5) {
            println!("  \x1b[33m●\x1b[0m  {}", user);
        }
        if result.users.len() > 5 {
            println!("  ... and {} more", result.users.len() - 5);
        }
    }

    if !result.vulnerabilities.is_empty() {
        println!();
        Output::error(&format!(
            "Found {} vulnerabilities",
            result.vulnerabilities.len()
        ));
        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                VulnSeverity::Critical => "\x1b[31m",
                VulnSeverity::High => "\x1b[31m",
                VulnSeverity::Medium => "\x1b[33m",
                VulnSeverity::Low => "\x1b[36m",
                VulnSeverity::Info => "\x1b[2m",
            };
            println!(
                "  {}[{}]\x1b[0m {}",
                severity_color, vuln.severity, vuln.title
            );
        }
    }

    Ok(())
}

fn display_laravel_scan_results(result: &LaravelScanResult) -> Result<(), String> {
    Output::subheader("Laravel Application");
    if let Some(version) = &result.version_hint {
        Output::item("Version hint", version);
    }

    println!();

    if !result.vulnerabilities.is_empty() {
        Output::error(&format!(
            "Detected {} Laravel-specific misconfigurations",
            result.vulnerabilities.len()
        ));
        for finding in &result.vulnerabilities {
            let (label, color) = match finding.severity {
                LaravelSeverity::Critical => ("CRITICAL", "\x1b[31m"),
                LaravelSeverity::High => ("HIGH", "\x1b[31m"),
                LaravelSeverity::Medium => ("MEDIUM", "\x1b[33m"),
                LaravelSeverity::Low => ("LOW", "\x1b[36m"),
                LaravelSeverity::Info => ("INFO", "\x1b[2m"),
            };
            println!("  {}[{}]\x1b[0m {}", color, label, finding.title);
            println!("      {}", finding.description);
            if let Some(evidence) = &finding.evidence {
                println!("      Evidence: {}", evidence);
            }
            println!("      Fix: {}", finding.remediation);
            println!();
        }
    } else {
        Output::success("No high-impact Laravel issues observed");
    }

    println!();
    Output::subheader("Signals");
    let mut signals = Vec::new();
    if result.debug_signals {
        signals.push("Debug tooling exposed");
    }
    if result.env_exposed {
        signals.push(".env accessible");
    }
    if result.horizon_exposed {
        signals.push("Horizon metrics open");
    }
    if result.telescope_exposed {
        signals.push("Telescope dashboard open");
    }
    if result.storage_logs_exposed {
        signals.push("storage/logs exposed");
    }
    if result.ignition_health_endpoint {
        signals.push("Ignition health-check live");
    }

    if signals.is_empty() {
        Output::info("No dangerous Laravel signals detected");
    } else {
        for signal in signals {
            println!("  • {}", signal);
        }
    }

    if !result.interesting_endpoints.is_empty() {
        println!();
        Output::subheader("Interesting Endpoints");
        for endpoint in &result.interesting_endpoints {
            println!("  • {}", endpoint);
        }
    }

    Ok(())
}

fn display_django_scan_results(result: &DjangoScanResult) -> Result<(), String> {
    Output::subheader("Django Application");
    if let Some(version) = &result.version_hint {
        Output::item("Version hint", version);
    }

    println!();

    if !result.findings.is_empty() {
        Output::error(&format!(
            "Detected {} Django-specific misconfigurations",
            result.findings.len()
        ));
        for finding in &result.findings {
            let (label, color) = match finding.severity {
                DjangoSeverity::Critical => ("CRITICAL", "\x1b[31m"),
                DjangoSeverity::High => ("HIGH", "\x1b[31m"),
                DjangoSeverity::Medium => ("MEDIUM", "\x1b[33m"),
                DjangoSeverity::Low => ("LOW", "\x1b[36m"),
                DjangoSeverity::Info => ("INFO", "\x1b[2m"),
            };
            println!("  {}[{}]\x1b[0m {}", color, label, finding.title);
            println!("      {}", finding.description);
            if let Some(evidence) = &finding.evidence {
                println!("      Evidence: {}", evidence);
            }
            println!("      Fix: {}", finding.remediation);
            println!();
        }
    } else {
        Output::success("No high-impact Django issues observed");
    }

    println!();
    Output::subheader("Signals");
    let mut signals = Vec::new();
    if result.admin_login_exposed {
        signals.push("Admin login reachable at /admin/");
    }
    if result.debug_toolbar_exposed {
        signals.push("Debug toolbar exposed");
    }
    if result.env_exposed {
        signals.push(".env accessible");
    }
    if result.sqlite_database_exposed {
        signals.push("SQLite database downloadable");
    }
    if result.settings_exposed {
        signals.push("settings.py exposed");
    }

    if signals.is_empty() {
        Output::info("No dangerous Django signals detected");
    } else {
        for signal in signals {
            println!("  • {}", signal);
        }
    }

    if !result.interesting_endpoints.is_empty() {
        println!();
        Output::subheader("Interesting Endpoints");
        for endpoint in &result.interesting_endpoints {
            println!("  • {}", endpoint);
        }
    }

    Ok(())
}

fn display_generic_vuln_results(result: &vuln_scanner::ScanResult) -> Result<(), String> {
    if result.findings.is_empty() {
        Output::success("No vulnerabilities detected");
        return Ok(());
    }

    let critical = result
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .count();
    let high = result
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();

    Output::subheader(&format!("Found {} vulnerabilities", result.findings.len()));
    println!();

    if critical > 0 {
        println!("  \x1b[31m● CRITICAL: {}\x1b[0m", critical);
    }
    if high > 0 {
        println!("  \x1b[31m● HIGH:     {}\x1b[0m", high);
    }

    println!();
    println!("  Top findings:");
    for (i, finding) in result.findings.iter().take(5).enumerate() {
        let severity_color = match finding.severity {
            Severity::Critical => "\x1b[31m",
            Severity::High => "\x1b[31m",
            Severity::Medium => "\x1b[33m",
            Severity::Low => "\x1b[36m",
            Severity::Info => "\x1b[2m",
        };
        println!(
            "  {}{}. [{}]\x1b[0m {}",
            severity_color,
            i + 1,
            finding.severity,
            finding.title
        );
    }

    if result.findings.len() > 5 {
        println!(
            "\n  Use 'rb web asset vuln-scan {}' for full details",
            result.url
        );
    }

    println!();

    Ok(())
}

fn display_drupal_results(result: &DrupalScanResult) -> Result<(), String> {
    if !result.is_drupal {
        Output::warning("Not a Drupal site");
        return Ok(());
    }

    Output::subheader("Drupal Detected");
    println!();

    if let Some(ref version) = result.version {
        Output::item("Version", version);
    }

    if !result.modules.is_empty() {
        println!();
        Output::info(&format!("Found {} modules", result.modules.len()));
        for module in result.modules.iter().take(10) {
            let version = module
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("Unknown");
            println!("  \x1b[36m●\x1b[0m  {} ({})", module.name, version);
        }
        if result.modules.len() > 10 {
            println!("  ... and {} more", result.modules.len() - 10);
        }
    }

    if !result.themes.is_empty() {
        println!();
        Output::info(&format!("Found {} themes", result.themes.len()));
        for theme in &result.themes {
            let version = theme
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("Unknown");
            println!("  \x1b[35m●\x1b[0m  {} ({})", theme.name, version);
        }
    }

    if !result.users.is_empty() {
        println!();
        Output::warning(&format!("Enumerated {} users", result.users.len()));
        for user in result.users.iter().take(5) {
            println!("  \x1b[33m●\x1b[0m  {}", user);
        }
        if result.users.len() > 5 {
            println!("  ... and {} more", result.users.len() - 5);
        }
    }

    if !result.config_exposure.is_empty() {
        println!();
        Output::error(&format!(
            "Found {} exposed configuration files",
            result.config_exposure.len()
        ));
        for config in &result.config_exposure {
            println!("  \x1b[31m●\x1b[0m  {} - {}", config.path, config.risk);
        }
    }

    if !result.vulnerabilities.is_empty() {
        println!();
        Output::error(&format!(
            "Found {} known vulnerabilities",
            result.vulnerabilities.len()
        ));
        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                DrupalVulnSeverity::Critical => "\x1b[31m",
                DrupalVulnSeverity::High => "\x1b[31m",
                DrupalVulnSeverity::Medium => "\x1b[33m",
                DrupalVulnSeverity::Low => "\x1b[36m",
            };
            print!(
                "  {}[{}]\x1b[0m {}",
                severity_color, vuln.severity, vuln.title
            );
            if let Some(ref cve) = vuln.cve {
                print!(" ({})", cve);
            }
            println!();
            println!("      {}", vuln.description);
            println!("      Affected: {}", vuln.affected_versions);
        }
    }

    Ok(())
}

fn display_joomla_results(
    result: &crate::modules::web::strategies::joomla::JoomlaScanResult,
) -> Result<(), String> {
    use crate::modules::web::strategies::joomla::VulnSeverity as JoomlaVulnSeverity;

    if !result.is_joomla {
        Output::warning("Not a Joomla site");
        return Ok(());
    }

    Output::subheader("Joomla Detected");
    println!();

    if let Some(ref version) = result.version {
        Output::item("Version", version);
    }

    if !result.extensions.is_empty() {
        println!();
        Output::info(&format!("Found {} extensions", result.extensions.len()));
        for ext in result.extensions.iter().take(10) {
            let version = ext
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("Unknown");
            println!(
                "  \x1b[36m●\x1b[0m  [{:9}] {} ({})",
                ext.ext_type, ext.name, version
            );
        }
        if result.extensions.len() > 10 {
            println!("  ... and {} more", result.extensions.len() - 10);
        }
    }

    if !result.templates.is_empty() {
        println!();
        Output::info(&format!("Found {} templates", result.templates.len()));
        for template in &result.templates {
            let version = template
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("Unknown");
            println!("  \x1b[35m●\x1b[0m  {} ({})", template.name, version);
        }
    }

    if !result.users.is_empty() {
        println!();
        Output::warning(&format!("Enumerated {} users", result.users.len()));
        for user in result.users.iter().take(5) {
            println!("  \x1b[33m●\x1b[0m  {}", user);
        }
        if result.users.len() > 5 {
            println!("  ... and {} more", result.users.len() - 5);
        }
    }

    if !result.config_exposure.is_empty() {
        println!();
        Output::error(&format!(
            "Found {} exposed configuration files",
            result.config_exposure.len()
        ));
        for config in &result.config_exposure {
            println!("  \x1b[31m●\x1b[0m  {} - {}", config.path, config.risk);
        }
    }

    if !result.vulnerabilities.is_empty() {
        println!();
        Output::error(&format!(
            "Found {} known vulnerabilities",
            result.vulnerabilities.len()
        ));
        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                JoomlaVulnSeverity::Critical => "\x1b[31m",
                JoomlaVulnSeverity::High => "\x1b[31m",
                JoomlaVulnSeverity::Medium => "\x1b[33m",
                JoomlaVulnSeverity::Low => "\x1b[36m",
            };
            print!(
                "  {}[{}]\x1b[0m {}",
                severity_color, vuln.severity, vuln.title
            );
            if let Some(ref cve) = vuln.cve {
                print!(" ({})", cve);
            }
            println!();
            println!("      {}", vuln.description);
            println!("      Affected: {}", vuln.affected_versions);
        }
    }

    Ok(())
}
