//! Web technology fingerprinting

use crate::cli::output::Output;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::modules::web::fingerprinter::WebFingerprinter;

use super::types::guard_plain_http;

/// Fingerprint web technologies (whatweb-style)
pub fn fingerprint(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset fingerprint <URL> Example: rb web asset fingerprint http://example.com",
    )?;

    Validator::validate_url(url)?;
    guard_plain_http(url, "rb web asset fingerprint")?;

    Output::header("Web Technology Fingerprinting");
    Output::item("URL", url);
    println!();

    let fingerprinter = WebFingerprinter::new();

    Output::spinner_start("Analyzing technologies");
    let result = fingerprinter.fingerprint(url)?;
    Output::spinner_done();

    // Display main findings
    println!();
    Output::subheader("Key Findings");
    println!();

    if let Some(ref cms) = result.cms {
        Output::item("CMS", cms);
    }

    if let Some(ref server) = result.web_server {
        Output::item("Web Server", server);
    }

    if let Some(ref lang) = result.programming_language {
        Output::item("Language", lang);
    }

    if !result.frameworks.is_empty() {
        Output::item("Frameworks", &result.frameworks.join(", "));
    }

    // Display all detected technologies
    if !result.technologies.is_empty() {
        println!();
        Output::subheader(&format!(
            "All Technologies ({} detected)",
            result.technologies.len()
        ));
        println!();

        println!(
            "  {:<30} {:<15} {:<12} VERSION",
            "TECHNOLOGY", "CATEGORY", "CONFIDENCE"
        );
        println!("  {}", "─".repeat(75));

        for tech in &result.technologies {
            let category = match tech.category {
                crate::modules::web::fingerprinter::TechCategory::CMS => "CMS",
                crate::modules::web::fingerprinter::TechCategory::Framework => "Framework",
                crate::modules::web::fingerprinter::TechCategory::WebServer => "Web Server",
                crate::modules::web::fingerprinter::TechCategory::Language => "Language",
                crate::modules::web::fingerprinter::TechCategory::Library => "Library",
                crate::modules::web::fingerprinter::TechCategory::CDN => "CDN",
                crate::modules::web::fingerprinter::TechCategory::Analytics => "Analytics",
                crate::modules::web::fingerprinter::TechCategory::Database => "Database",
                crate::modules::web::fingerprinter::TechCategory::Other => "Other",
            };

            let confidence_color = match tech.confidence {
                crate::modules::web::fingerprinter::Confidence::High => "\x1b[32m", // Green
                crate::modules::web::fingerprinter::Confidence::Medium => "\x1b[33m", // Yellow
                crate::modules::web::fingerprinter::Confidence::Low => "\x1b[36m",  // Cyan
            };

            let version = tech.version.as_deref().unwrap_or("-");

            println!(
                "  {:<30} {:<15} {}{:<12}\x1b[0m {}",
                tech.name, category, confidence_color, tech.confidence, version
            );
        }
    } else {
        println!();
        Output::warning("No technologies detected");
    }

    println!();
    Output::success("Fingerprinting completed");

    Ok(())
}
