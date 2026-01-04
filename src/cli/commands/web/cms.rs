//! CMS scanning operations (WordPress, Drupal, Joomla)

use crate::cli::output::Output;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::modules::web::scanner_strategy::{ScanStrategy, UnifiedScanResult, UnifiedWebScanner};
use std::time::Duration;

use super::types::guard_plain_http;

/// WordPress security scanner
pub fn wpscan(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset wpscan <URL> Example: rb web asset wpscan http://example.com",
    )?;

    Validator::validate_url(url)?;
    guard_plain_http(url, "rb web asset wpscan")?;

    Output::header("WordPress Security Scanner");
    Output::item("Target", url);
    println!();

    Output::spinner_start("Scanning WordPress installation");

    use crate::modules::web::strategies::wordpress::WPScanner;
    let scanner = WPScanner::new();
    let result = scanner.scan(url)?;

    Output::spinner_done();
    println!();

    if !result.is_wordpress {
        Output::info("Not a WordPress site");
        return Ok(());
    }

    Output::success("✓ WordPress Detected");

    if let Some(version) = &result.version {
        Output::item("Version", version);
    } else {
        Output::item("Version", "Unknown");
    }
    println!();

    // Display plugins
    if !result.plugins.is_empty() {
        Output::subheader(&format!("Plugins Found: {}", result.plugins.len()));
        for plugin in &result.plugins {
            let version_str = plugin.version.as_deref().unwrap_or("unknown");
            println!(
                "  • {} ({})",
                Output::colorize(&plugin.name, "cyan"),
                version_str
            );
            println!("    Path: {}", plugin.path);
        }
        println!();
    }

    // Display themes
    if !result.themes.is_empty() {
        Output::subheader(&format!("Themes Found: {}", result.themes.len()));
        for theme in &result.themes {
            let version_str = theme.version.as_deref().unwrap_or("unknown");
            println!(
                "  • {} ({})",
                Output::colorize(&theme.name, "cyan"),
                version_str
            );
            println!("    Path: {}", theme.path);
        }
        println!();
    }

    // Display users
    if !result.users.is_empty() {
        Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
        for user in &result.users {
            println!("  • {}", Output::colorize(user, "yellow"));
        }
        println!();
    }

    // Display vulnerabilities
    if !result.vulnerabilities.is_empty() {
        Output::warning(&format!(
            "⚠️  {} VULNERABILITIES FOUND:",
            result.vulnerabilities.len()
        ));
        println!();

        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                crate::modules::web::strategies::wordpress::VulnSeverity::Critical => "red",
                crate::modules::web::strategies::wordpress::VulnSeverity::High => "red",
                crate::modules::web::strategies::wordpress::VulnSeverity::Medium => "yellow",
                crate::modules::web::strategies::wordpress::VulnSeverity::Low => "blue",
                crate::modules::web::strategies::wordpress::VulnSeverity::Info => "cyan",
            };

            println!(
                "  {} | {}",
                Output::colorize(&vuln.severity.to_string(), severity_color),
                Output::colorize(&vuln.title, "white")
            );
            println!("    {}", vuln.description);
            if let Some(path) = &vuln.path {
                println!("    Path: {}", path);
            }
            println!();
        }

        Output::warning("🚨 SECURITY ALERT: WordPress vulnerabilities detected!");
        Output::warning("   Review findings and apply security patches");
    } else {
        Output::success("✓ No known vulnerabilities detected");
    }

    Ok(())
}

/// Drupal security scanner
pub fn drupal_scan(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset drupal-scan <URL> Example: rb web asset drupal-scan http://example.com",
    )?;

    Validator::validate_url(url)?;
    guard_plain_http(url, "rb web asset drupal-scan")?;

    Output::header("Drupal Security Scanner");
    Output::item("Target", url);
    println!();

    Output::spinner_start("Scanning Drupal installation");

    use crate::modules::web::strategies::drupal::DrupalScanner;
    let scanner = DrupalScanner::new();
    let result = scanner.scan(url)?;

    Output::spinner_done();
    println!();

    if !result.is_drupal {
        Output::info("Not a Drupal site");
        return Ok(());
    }

    Output::success("✓ Drupal Detected");

    if let Some(version) = &result.version {
        Output::item("Version", version);
    } else {
        Output::item("Version", "Unknown");
    }
    println!();

    // Display modules
    if !result.modules.is_empty() {
        Output::subheader(&format!("Modules Found: {}", result.modules.len()));
        for module in &result.modules {
            let version_str = module.version.as_deref().unwrap_or("unknown");
            println!(
                "  • {} ({})",
                Output::colorize(&module.name, "cyan"),
                version_str
            );
            println!("    Path: {}", module.path);
        }
        println!();
    }

    // Display themes
    if !result.themes.is_empty() {
        Output::subheader(&format!("Themes Found: {}", result.themes.len()));
        for theme in &result.themes {
            let version_str = theme.version.as_deref().unwrap_or("unknown");
            println!(
                "  • {} ({})",
                Output::colorize(&theme.name, "cyan"),
                version_str
            );
            println!("    Path: {}", theme.path);
        }
        println!();
    }

    // Display users
    if !result.users.is_empty() {
        Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
        for user in &result.users {
            println!("  • {}", Output::colorize(user, "yellow"));
        }
        println!();
    }

    // Display config exposure
    if !result.config_exposure.is_empty() {
        Output::warning(&format!(
            "⚠️  {} CONFIGURATION FILES EXPOSED:",
            result.config_exposure.len()
        ));
        println!();
        for config in &result.config_exposure {
            println!(
                "  • {} [{}] - Risk: {}",
                Output::colorize(&config.path, "red"),
                config.status,
                config.risk
            );
        }
        println!();
    }

    // Display vulnerabilities
    if !result.vulnerabilities.is_empty() {
        Output::warning(&format!(
            "⚠️  {} VULNERABILITIES FOUND:",
            result.vulnerabilities.len()
        ));
        println!();

        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                crate::modules::web::strategies::drupal::VulnSeverity::Critical => "red",
                crate::modules::web::strategies::drupal::VulnSeverity::High => "red",
                crate::modules::web::strategies::drupal::VulnSeverity::Medium => "yellow",
                crate::modules::web::strategies::drupal::VulnSeverity::Low => "blue",
            };

            println!(
                "  {} | {}",
                Output::colorize(&vuln.severity.to_string(), severity_color),
                Output::colorize(&vuln.title, "white")
            );
            println!("    {}", vuln.description);
            println!("    Affected: {}", vuln.affected_versions);
            if let Some(cve) = &vuln.cve {
                println!("    CVE: {}", cve);
            }
            println!();
        }

        Output::warning("🚨 SECURITY ALERT: Drupal vulnerabilities detected!");
        Output::warning("   Review findings and apply security patches");
    } else {
        Output::success("✓ No known vulnerabilities detected");
    }

    Ok(())
}

/// Joomla security scanner
pub fn joomla_scan(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset joomla-scan <URL> Example: rb web asset joomla-scan http://example.com",
    )?;

    Validator::validate_url(url)?;
    guard_plain_http(url, "rb web asset joomla-scan")?;

    Output::header("Joomla Security Scanner");
    Output::item("Target", url);
    println!();

    Output::spinner_start("Scanning Joomla installation");

    use crate::modules::web::strategies::joomla::JoomlaScanner;
    let scanner = JoomlaScanner::new();
    let result = scanner.scan(url)?;

    Output::spinner_done();
    println!();

    if !result.is_joomla {
        Output::info("Not a Joomla site");
        return Ok(());
    }

    Output::success("✓ Joomla Detected");

    if let Some(version) = &result.version {
        Output::item("Version", version);
    } else {
        Output::item("Version", "Unknown");
    }
    println!();

    // Display extensions
    if !result.extensions.is_empty() {
        Output::subheader(&format!("Extensions Found: {}", result.extensions.len()));
        for ext in &result.extensions {
            let version_str = ext.version.as_deref().unwrap_or("unknown");
            println!(
                "  • {} ({}) - {}",
                Output::colorize(&ext.name, "cyan"),
                version_str,
                ext.ext_type
            );
            println!("    Path: {}", ext.path);
        }
        println!();
    }

    // Display templates
    if !result.templates.is_empty() {
        Output::subheader(&format!("Templates Found: {}", result.templates.len()));
        for template in &result.templates {
            let version_str = template.version.as_deref().unwrap_or("unknown");
            println!(
                "  • {} ({})",
                Output::colorize(&template.name, "cyan"),
                version_str
            );
            println!("    Path: {}", template.path);
        }
        println!();
    }

    // Display users
    if !result.users.is_empty() {
        Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
        for user in &result.users {
            println!("  • {}", Output::colorize(user, "yellow"));
        }
        println!();
    }

    // Display config exposure
    if !result.config_exposure.is_empty() {
        Output::warning(&format!(
            "⚠️  {} CONFIGURATION FILES EXPOSED:",
            result.config_exposure.len()
        ));
        println!();
        for config in &result.config_exposure {
            println!(
                "  • {} [{}] - Risk: {}",
                Output::colorize(&config.path, "red"),
                config.status,
                config.risk
            );
        }
        println!();
    }

    // Display vulnerabilities
    if !result.vulnerabilities.is_empty() {
        Output::warning(&format!(
            "⚠️  {} VULNERABILITIES FOUND:",
            result.vulnerabilities.len()
        ));
        println!();

        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                crate::modules::web::strategies::joomla::VulnSeverity::Critical => "red",
                crate::modules::web::strategies::joomla::VulnSeverity::High => "red",
                crate::modules::web::strategies::joomla::VulnSeverity::Medium => "yellow",
                crate::modules::web::strategies::joomla::VulnSeverity::Low => "blue",
            };

            println!(
                "  {} | {}",
                Output::colorize(&vuln.severity.to_string(), severity_color),
                Output::colorize(&vuln.title, "white")
            );
            println!("    {}", vuln.description);
            println!("    Affected: {}", vuln.affected_versions);
            if let Some(cve) = &vuln.cve {
                println!("    CVE: {}", cve);
            }
            println!();
        }

        Output::warning("🚨 SECURITY ALERT: Joomla vulnerabilities detected!");
        Output::warning("   Review findings and apply security patches");
    } else {
        Output::success("✓ No known vulnerabilities detected");
    }

    Ok(())
}

/// Unified CMS scanner with auto-detection
pub fn cms_scan(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL.\nUsage: rb web asset cms-scan <URL> [--strategy auto|wordpress|drupal|joomla]\nExample: rb web asset cms-scan http://example.com --strategy auto",
    )?;

    Validator::validate_url(url)?;

    let strategy_str = ctx
        .flags
        .get("strategy")
        .map(|s| s.as_str())
        .unwrap_or("auto");

    let strategy = ScanStrategy::from_str(strategy_str)?;

    Output::header(&format!("Unified CMS Scanner: {}", url));

    if strategy == ScanStrategy::AutoDetect {
        Output::info("🔍 Auto-detecting CMS/framework...");
    } else {
        Output::info(&format!("🎯 Using strategy: {:?}", strategy));
    }

    let scanner = UnifiedWebScanner::new();

    Output::spinner_start("Scanning");
    let result = scanner
        .scan(url, strategy)
        .map_err(|e| format!("Scan failed: {}", e))?;
    Output::spinner_done();

    // Display results based on detected CMS
    match result {
        UnifiedScanResult::WordPress(wp_result) => {
            let version_str = wp_result
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("unknown");
            Output::success(&format!("✓ Detected: WordPress {}", version_str));
            display_wp_results(&wp_result)?;
        }
        UnifiedScanResult::Drupal(drupal_result) => {
            let version_str = drupal_result
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("unknown");
            Output::success(&format!("✓ Detected: Drupal {}", version_str));
            display_drupal_results(&drupal_result)?;
        }
        UnifiedScanResult::Joomla(joomla_result) => {
            let version_str = joomla_result
                .version
                .as_ref()
                .map(|v| v.as_str())
                .unwrap_or("unknown");
            Output::success(&format!("✓ Detected: Joomla {}", version_str));
            display_joomla_results(&joomla_result)?;
        }
        UnifiedScanResult::Strapi(_) => {
            Output::success("✓ Detected: Strapi");
            Output::info("Strapi-specific scanner results (coming soon)");
        }
        UnifiedScanResult::Ghost(_) => {
            Output::success("✓ Detected: Ghost");
            Output::info("Ghost-specific scanner results (coming soon)");
        }
        UnifiedScanResult::Directus(_) => {
            Output::success("✓ Detected: Directus");
            Output::info("Directus-specific scanner results (coming soon)");
        }
        UnifiedScanResult::Laravel(laravel_result) => {
            let version = laravel_result
                .version_hint
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            Output::success(&format!("✓ Detected: Laravel {}", version));
            display_laravel_results(&laravel_result)?;
        }
        UnifiedScanResult::Django(django_result) => {
            let version = django_result
                .version_hint
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            Output::success(&format!("✓ Detected: Django {}", version));
            display_django_results(&django_result)?;
        }
        UnifiedScanResult::Generic(vuln_result) => {
            Output::warning("⚠️  No specific CMS detected, running generic scan");
            Output::info(&format!(
                "Found {} potential issues",
                vuln_result.findings.len()
            ));
        }
        UnifiedScanResult::NotDetected(_) => {
            Output::warning("⚠️  Could not detect CMS type");
            Output::info("Try specifying --strategy manually (wordpress, drupal, joomla, etc.)");
        }
    }

    Ok(())
}

/// Advanced CMS security testing
pub fn cms_advanced(ctx: &CliContext) -> Result<(), String> {
    use crate::modules::web::cms::{CmsScanConfig, CmsScanner, CmsType, VulnSeverity};

    let url = ctx.target.as_ref().ok_or(
        "Missing URL.\nUsage: rb web asset cms <URL> [--aggressive] [--waf-evasion]\nExample: rb web asset cms http://example.com",
    )?;

    Validator::validate_url(url)?;

    // Build config from flags
    let aggressive = ctx.flags.contains_key("aggressive");
    let waf_evasion = ctx.flags.contains_key("waf-evasion");
    let timeout = ctx
        .flags
        .get("timeout")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10);
    let threads = ctx
        .flags
        .get("threads")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10);

    // Parse enumerate flag
    let enumerate_str = ctx
        .flags
        .get("enumerate")
        .map(|s| s.as_str())
        .unwrap_or("plugins,themes,users");
    let enumerate_plugins = enumerate_str.contains("plugins") || enumerate_str.contains("all");
    let enumerate_themes = enumerate_str.contains("themes") || enumerate_str.contains("all");
    let enumerate_users = enumerate_str.contains("users") || enumerate_str.contains("all");

    let config = CmsScanConfig {
        target: url.clone(),
        timeout: Duration::from_secs(timeout),
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        threads,
        aggressive,
        enumerate_plugins,
        enumerate_themes,
        enumerate_users,
        wordlist: ctx.flags.get("wordlist").cloned(),
        max_enum_items: 1000,
        waf_evasion,
        rate_limit: ctx
            .flags
            .get("rate-limit")
            .and_then(|v| v.parse::<f64>().ok()),
        random_delay: None,
        follow_redirects: true,
        headers: Vec::new(),
        proxy: ctx.flags.get("proxy").cloned(),
        api_token: ctx.flags.get("api-token").cloned(),
    };

    Output::header(&format!("Advanced CMS Security Scanner: {}", url));
    Output::info(&format!(
        "Mode: {}",
        if aggressive { "Aggressive" } else { "Passive" }
    ));
    if waf_evasion {
        Output::info("WAF Evasion: Enabled");
    }
    Output::info(&format!("Enumerate: {}", enumerate_str));
    println!();

    Output::spinner_start("Detecting CMS and scanning...");

    let scanner = CmsScanner::new(config);
    let result = scanner.scan();

    Output::spinner_done();
    println!();

    // Display CMS detection result
    match result.cms_type {
        CmsType::Unknown => {
            Output::warning("No CMS detected");
            return Ok(());
        }
        cms_type => {
            let cms_name = format!("{:?}", cms_type);
            let version = result.version.as_deref().unwrap_or("unknown");
            Output::success(&format!("Detected: {} {}", cms_name, version));
            Output::item("Confidence", &format!("{}%", result.confidence));
            Output::item("Detection Methods", &result.detection_methods.join(", "));
        }
    }
    println!();

    // Display risk score
    let risk_color = match result.risk_score {
        0..=20 => "green",
        21..=50 => "yellow",
        51..=75 => "red",
        _ => "red",
    };
    Output::section("Risk Assessment");
    println!(
        "  Risk Score: {} ({})",
        Output::colorize(&result.risk_score.to_string(), risk_color),
        Output::colorize(result.risk_rating(), risk_color)
    );

    // Display vulnerability counts
    let (critical, high, medium, low, info) = result.vuln_counts();
    if critical + high + medium + low + info > 0 {
        println!("  Vulnerabilities:");
        if critical > 0 {
            println!("    \x1b[31mCritical: {}\x1b[0m", critical);
        }
        if high > 0 {
            println!("    \x1b[91mHigh: {}\x1b[0m", high);
        }
        if medium > 0 {
            println!("    \x1b[33mMedium: {}\x1b[0m", medium);
        }
        if low > 0 {
            println!("    \x1b[94mLow: {}\x1b[0m", low);
        }
        if info > 0 {
            println!("    \x1b[36mInfo: {}\x1b[0m", info);
        }
    }
    println!();

    // Display plugins
    if !result.plugins.is_empty() {
        Output::section(&format!("Plugins Found: {}", result.plugins.len()));
        for plugin in result.plugins.iter().take(20) {
            let version = plugin.version.as_deref().unwrap_or("unknown");
            let vuln_marker = if plugin.vulnerable {
                " \x1b[31m[VULNERABLE]\x1b[0m"
            } else {
                ""
            };
            println!(
                "  • {} ({}){}",
                Output::colorize(&plugin.name, "cyan"),
                version,
                vuln_marker
            );
        }
        if result.plugins.len() > 20 {
            Output::dim(&format!("  ... and {} more", result.plugins.len() - 20));
        }
        println!();
    }

    // Display themes
    if !result.themes.is_empty() {
        Output::section(&format!("Themes Found: {}", result.themes.len()));
        for theme in result.themes.iter().take(10) {
            let version = theme.version.as_deref().unwrap_or("unknown");
            let vuln_marker = if theme.vulnerable {
                " \x1b[31m[VULNERABLE]\x1b[0m"
            } else {
                ""
            };
            println!(
                "  • {} ({}){}",
                Output::colorize(&theme.name, "cyan"),
                version,
                vuln_marker
            );
        }
        if result.themes.len() > 10 {
            Output::dim(&format!("  ... and {} more", result.themes.len() - 10));
        }
        println!();
    }

    // Display users
    if !result.users.is_empty() {
        Output::section(&format!("Users Enumerated: {}", result.users.len()));
        for user in result.users.iter().take(20) {
            let id_str = user
                .id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!(
                "  • {} (ID: {})",
                Output::colorize(&user.username, "yellow"),
                id_str
            );
            if let Some(ref display) = user.display_name {
                println!("    Display: {}", display);
            }
        }
        if result.users.len() > 20 {
            Output::dim(&format!("  ... and {} more", result.users.len() - 20));
        }
        println!();
    }

    // Display vulnerabilities
    if !result.vulnerabilities.is_empty() {
        Output::section(&format!(
            "Vulnerabilities: {}",
            result.vulnerabilities.len()
        ));
        for vuln in result.vulnerabilities.iter().take(15) {
            let severity_color = match vuln.severity {
                VulnSeverity::Critical => "\x1b[31m",
                VulnSeverity::High => "\x1b[91m",
                VulnSeverity::Medium => "\x1b[33m",
                VulnSeverity::Low => "\x1b[94m",
                VulnSeverity::Info => "\x1b[36m",
            };
            println!(
                "  {}[{:?}]\x1b[0m {}",
                severity_color, vuln.severity, vuln.title
            );
            if !vuln.id.is_empty() {
                println!("         ID: {}", vuln.id);
            }
            if !vuln.references.is_empty() {
                println!("         Ref: {}", vuln.references[0]);
            }
        }
        if result.vulnerabilities.len() > 15 {
            Output::dim(&format!(
                "  ... and {} more",
                result.vulnerabilities.len() - 15
            ));
        }
        println!();
    }

    // Display interesting findings
    if !result.interesting_findings.is_empty() {
        Output::section(&format!(
            "Interesting Findings: {}",
            result.interesting_findings.len()
        ));
        for finding in result.interesting_findings.iter().take(10) {
            println!("  [{:?}] {}", finding.finding_type, finding.description);
            if let Some(ref url) = finding.url {
                println!("        URL: {}", url);
            }
        }
        if result.interesting_findings.len() > 10 {
            Output::dim(&format!(
                "  ... and {} more",
                result.interesting_findings.len() - 10
            ));
        }
    }

    Ok(())
}

// Helper display functions

fn display_wp_results(
    result: &crate::modules::web::strategies::wordpress::WPScanResult,
) -> Result<(), String> {
    use crate::modules::web::strategies::wordpress::VulnSeverity;

    if !result.plugins.is_empty() {
        Output::subheader(&format!("Plugins Detected: {}", result.plugins.len()));
        for plugin in &result.plugins {
            println!("  • {}", Output::colorize(&plugin.name, "cyan"));
        }
        println!();
    }

    if !result.themes.is_empty() {
        Output::subheader(&format!("Themes Detected: {}", result.themes.len()));
        for theme in &result.themes {
            println!("  • {}", Output::colorize(&theme.name, "blue"));
        }
        println!();
    }

    if !result.users.is_empty() {
        Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
        for user in &result.users {
            println!("  • {}", Output::colorize(user, "yellow"));
        }
        println!();
    }

    if !result.vulnerabilities.is_empty() {
        Output::subheader(&format!(
            "🔴 VULNERABILITIES: {}",
            result.vulnerabilities.len()
        ));
        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                VulnSeverity::Critical => "red",
                VulnSeverity::High => "red",
                VulnSeverity::Medium => "yellow",
                VulnSeverity::Low => "cyan",
                VulnSeverity::Info => "white",
            };
            println!(
                "  {} {}",
                Output::colorize(&format!("[{:?}]", vuln.severity), severity_color),
                vuln.title
            );
        }
        Output::warning("🚨 SECURITY ALERT: WordPress vulnerabilities detected!");
    } else {
        Output::success("✓ No known vulnerabilities detected");
    }

    Ok(())
}

fn display_drupal_results(
    result: &crate::modules::web::strategies::drupal::DrupalScanResult,
) -> Result<(), String> {
    use crate::modules::web::strategies::drupal::VulnSeverity;

    if !result.modules.is_empty() {
        Output::subheader(&format!("Modules Detected: {}", result.modules.len()));
        for module in &result.modules {
            println!("  • {}", Output::colorize(&module.name, "cyan"));
        }
        println!();
    }

    if !result.themes.is_empty() {
        Output::subheader(&format!("Themes Detected: {}", result.themes.len()));
        for theme in &result.themes {
            println!("  • {}", Output::colorize(&theme.name, "blue"));
        }
        println!();
    }

    if !result.vulnerabilities.is_empty() {
        Output::subheader(&format!(
            "🔴 VULNERABILITIES: {}",
            result.vulnerabilities.len()
        ));
        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                VulnSeverity::Critical => "red",
                VulnSeverity::High => "red",
                VulnSeverity::Medium => "yellow",
                VulnSeverity::Low => "cyan",
            };
            println!(
                "  {} {}",
                Output::colorize(&format!("[{:?}]", vuln.severity), severity_color),
                vuln.title
            );
        }
        Output::warning("🚨 SECURITY ALERT: Drupal vulnerabilities detected!");
    } else {
        Output::success("✓ No known vulnerabilities detected");
    }

    Ok(())
}

fn display_joomla_results(
    result: &crate::modules::web::strategies::joomla::JoomlaScanResult,
) -> Result<(), String> {
    use crate::modules::web::strategies::joomla::VulnSeverity;

    if !result.extensions.is_empty() {
        Output::subheader(&format!("Extensions Detected: {}", result.extensions.len()));
        for ext in &result.extensions {
            println!(
                "  • {} ({:?})",
                Output::colorize(&ext.name, "cyan"),
                ext.ext_type
            );
        }
        println!();
    }

    if !result.users.is_empty() {
        Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
        for user in &result.users {
            println!("  • {}", Output::colorize(user, "yellow"));
        }
        println!();
    }

    if !result.vulnerabilities.is_empty() {
        Output::subheader(&format!(
            "🔴 VULNERABILITIES: {}",
            result.vulnerabilities.len()
        ));
        for vuln in &result.vulnerabilities {
            let severity_color = match vuln.severity {
                VulnSeverity::Critical => "red",
                VulnSeverity::High => "red",
                VulnSeverity::Medium => "yellow",
                VulnSeverity::Low => "cyan",
            };
            println!(
                "  {} {}",
                Output::colorize(&format!("[{:?}]", vuln.severity), severity_color),
                vuln.title
            );
        }
        Output::warning("🚨 SECURITY ALERT: Joomla vulnerabilities detected!");
    } else {
        Output::success("✓ No known vulnerabilities detected");
    }

    Ok(())
}

fn display_laravel_results(
    result: &crate::modules::web::strategies::laravel::LaravelScanResult,
) -> Result<(), String> {
    use crate::modules::web::strategies::laravel::FindingSeverity;

    if !result.vulnerabilities.is_empty() {
        Output::subheader(&format!(
            "Laravel Findings: {}",
            result.vulnerabilities.len()
        ));
        for finding in &result.vulnerabilities {
            let (label, color) = match finding.severity {
                FindingSeverity::Critical => ("CRITICAL", "red"),
                FindingSeverity::High => ("HIGH", "red"),
                FindingSeverity::Medium => ("MEDIUM", "yellow"),
                FindingSeverity::Low => ("LOW", "cyan"),
                FindingSeverity::Info => ("INFO", "blue"),
            };

            println!("  [{}] {}", Output::colorize(label, color), finding.title);
            println!("      {}", finding.description);
            if let Some(evidence) = &finding.evidence {
                println!("      Evidence: {}", evidence);
            }
            println!("      Fix: {}", finding.remediation);
            println!();
        }
    } else {
        Output::info("No high-impact Laravel misconfigurations uncovered");
    }

    Output::subheader("Signals");
    if result.debug_signals {
        Output::warning("• Debug tooling detected (Debugbar/Ignition)");
    } else {
        Output::info("• Debug tooling was not observed");
    }
    if result.env_exposed {
        Output::error("• .env file exposed to unauthenticated users");
    }
    if result.horizon_exposed {
        Output::warning("• Horizon metrics API reachable");
    }
    if result.telescope_exposed {
        Output::warning("• Telescope dashboard reachable");
    }
    if result.storage_logs_exposed {
        Output::warning("• Application logs readable via the web root");
    }
    if result.ignition_health_endpoint {
        Output::warning("• Ignition health-check endpoint enabled");
    }

    if !result.interesting_endpoints.is_empty() {
        Output::subheader("Interesting Endpoints");
        for endpoint in &result.interesting_endpoints {
            println!("  • {}", endpoint);
        }
    }

    Ok(())
}

fn display_django_results(
    result: &crate::modules::web::strategies::django::DjangoScanResult,
) -> Result<(), String> {
    use crate::modules::web::strategies::django::DjangoSeverity;

    if !result.findings.is_empty() {
        Output::subheader(&format!("Django Findings: {}", result.findings.len()));
        for finding in &result.findings {
            let (label, color) = match finding.severity {
                DjangoSeverity::Critical => ("CRITICAL", "red"),
                DjangoSeverity::High => ("HIGH", "red"),
                DjangoSeverity::Medium => ("MEDIUM", "yellow"),
                DjangoSeverity::Low => ("LOW", "cyan"),
                DjangoSeverity::Info => ("INFO", "blue"),
            };

            println!("  [{}] {}", Output::colorize(label, color), finding.title);
            println!("      {}", finding.description);
            if let Some(evidence) = &finding.evidence {
                println!("      Evidence: {}", evidence);
            }
            println!("      Fix: {}", finding.remediation);
            println!();
        }
    } else {
        Output::info("No high-impact Django misconfigurations uncovered");
    }

    Output::subheader("Signals");
    if result.admin_login_exposed {
        Output::warning("• Admin login available at /admin/");
    }
    if result.debug_toolbar_exposed {
        Output::warning("• Debug toolbar exposed (__debug__)");
    }
    if result.env_exposed {
        Output::error("• Environment secrets accessible via .env");
    }
    if result.sqlite_database_exposed {
        Output::error("• SQLite database downloadable via HTTP");
    }
    if result.settings_exposed {
        Output::warning("• settings.py reachable through the web server");
    }

    if !result.interesting_endpoints.is_empty() {
        Output::subheader("Interesting Endpoints");
        for endpoint in &result.interesting_endpoints {
            println!("  • {}", endpoint);
        }
    }

    Ok(())
}
