//! Vulnerability scanning for web targets

use super::map_to_osv_ecosystem;
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::recon::vuln::{NvdClient, OsvClient, Vulnerability};
use crate::modules::web::fingerprinter::WebFingerprinter;

/// Generate CPE identifier for a technology
fn generate_cpe(name: &str, version: Option<&str>) -> Option<String> {
    let name_lower = name.to_lowercase();
    let version_str = version.unwrap_or("*");

    // Map common technology names to CPE vendor:product format
    let (vendor, product) = match name_lower.as_str() {
        "nginx" => ("nginx", "nginx"),
        "apache" | "apache httpd" => ("apache", "http_server"),
        "php" => ("php", "php"),
        "python" => ("python", "python"),
        "node.js" | "nodejs" => ("nodejs", "node.js"),
        "jquery" => ("jquery", "jquery"),
        "wordpress" => ("wordpress", "wordpress"),
        "drupal" => ("drupal", "drupal"),
        "joomla" => ("joomla", "joomla"),
        "react" => ("facebook", "react"),
        "angular" => ("google", "angular"),
        "vue.js" | "vue" => ("vuejs", "vue.js"),
        "express" => ("expressjs", "express"),
        "django" => ("djangoproject", "django"),
        "flask" => ("palletsprojects", "flask"),
        "spring" => ("vmware", "spring_framework"),
        "tomcat" => ("apache", "tomcat"),
        "iis" => ("microsoft", "iis"),
        "openssl" => ("openssl", "openssl"),
        _ => return None,
    };

    Some(format!(
        "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
        vendor, product, version_str
    ))
}

/// Vulnerability scan based on web fingerprinting
pub fn vuln(ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
        "Missing URL.\nUsage: rb recon domain vuln <URL> [--source nvd|osv|all] [--limit N]\nExample: rb recon domain vuln http://example.com",
    )?;

    // Basic URL validation
    if !target.starts_with("http://") && !target.starts_with("https://") {
        return Err("Invalid URL. Must start with http:// or https://".to_string());
    }

    let source = ctx.get_flag("source").unwrap_or_else(|| "nvd".to_string());
    let limit: usize = ctx
        .get_flag("limit")
        .unwrap_or_else(|| "20".to_string())
        .parse()
        .unwrap_or(20);

    Output::header(&format!("Vulnerability Scan: {}", target));
    Output::item("Source", &source);
    Output::item("Limit", &limit.to_string());
    println!();

    let fingerprinter = WebFingerprinter::new();
    let mut nvd_client = NvdClient::new();
    let osv_client = OsvClient::new();

    // Get API keys from flags if provided
    if let Some(api_key) = ctx.get_flag("api-key") {
        nvd_client = nvd_client.with_api_key(&api_key);
    }

    Output::spinner_start("Fingerprinting target...");
    let fingerprint_result = fingerprinter.fingerprint(target)?;
    Output::spinner_done();

    if fingerprint_result.technologies.is_empty() {
        Output::warning("No technologies detected on target.");
        return Ok(());
    }

    println!();
    Output::subheader(&format!(
        "Detected Technologies ({})",
        fingerprint_result.technologies.len()
    ));
    for tech in &fingerprint_result.technologies {
        let conf = match tech.confidence {
            crate::modules::web::fingerprinter::Confidence::High => "High",
            crate::modules::web::fingerprinter::Confidence::Medium => "Medium",
            crate::modules::web::fingerprinter::Confidence::Low => "Low",
        };
        println!("  • {} (Confidence: {})", tech.name, conf);
    }
    println!();

    let mut all_vulns: Vec<Vulnerability> = Vec::new();

    // Scan NVD if requested
    if source == "nvd" || source == "all" {
        Output::spinner_start("Querying NVD for vulnerabilities...");
        for tech in &fingerprint_result.technologies {
            if let Some(cpe) = generate_cpe(&tech.name, tech.version.as_deref()) {
                match nvd_client.query_by_cpe(&cpe) {
                    Ok(mut vulns) => {
                        all_vulns.append(&mut vulns);
                    }
                    Err(e) => {
                        eprintln!("Warning: NVD query failed for {}: {}", cpe, e);
                    }
                }
            }
        }
        Output::spinner_done();
    }

    // Scan OSV if requested
    if source == "osv" || source == "all" {
        Output::spinner_start("Querying OSV for vulnerabilities...");
        for tech in &fingerprint_result.technologies {
            if let Some(ecosystem) = map_to_osv_ecosystem(&tech.name) {
                match osv_client.query_package(&tech.name, tech.version.as_deref(), ecosystem) {
                    Ok(mut vulns) => {
                        all_vulns.append(&mut vulns);
                    }
                    Err(e) => {
                        eprintln!("Warning: OSV query failed for tech {}: {}", tech.name, e);
                    }
                }
            }
        }
        Output::spinner_done();
    }

    // Deduplicate and sort vulnerabilities
    all_vulns.sort_by(|a, b| a.id.cmp(&b.id));
    all_vulns.dedup_by(|a, b| a.id == b.id);
    all_vulns.sort_by(|a, b| {
        let cvss_a = a.cvss_v3.or(a.cvss_v2).unwrap_or(0.0);
        let cvss_b = b.cvss_v3.or(b.cvss_v2).unwrap_or(0.0);
        cvss_b
            .partial_cmp(&cvss_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if all_vulns.is_empty() {
        Output::info("No known vulnerabilities found for detected technologies.");
        return Ok(());
    }

    println!();
    Output::subheader(&format!(
        "Found {} Vulnerabilities (Top {})",
        all_vulns.len(),
        limit
    ));
    println!();

    for vuln in all_vulns.iter().take(limit) {
        let cvss_score = vuln.cvss_v3.or(vuln.cvss_v2).unwrap_or(0.0);
        let severity = match cvss_score {
            s if s >= 9.0 => "CRITICAL",
            s if s >= 7.0 => "HIGH",
            s if s >= 4.0 => "MEDIUM",
            _ => "LOW",
        };
        let severity_color = match severity {
            "CRITICAL" => "\x1b[1;31m",
            "HIGH" => "\x1b[31m",
            "MEDIUM" => "\x1b[33m",
            _ => "\x1b[36m",
        };

        println!(
            "  {}{}● {} (CVSS {:.1})\x1b[0m",
            severity_color, severity_color, vuln.id, cvss_score
        );
        println!(
            "    └─ {}",
            vuln.description.chars().take(100).collect::<String>()
        );
        println!();
    }

    if all_vulns.len() > limit {
        println!(
            "  ... and {} more vulnerabilities found.\n",
            all_vulns.len() - limit
        );
    }

    Output::success(&format!("Found {} vulnerabilities", all_vulns.len()));

    Ok(())
}
