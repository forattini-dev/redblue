//! Username OSINT, email intelligence, and ASN lookup

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::recon::asn::AsnClient;
use crate::modules::recon::osint::{EmailIntel, OsintConfig as EmailOsintConfig};

pub fn osint(ctx: &CliContext) -> Result<(), String> {
    let target = ctx
        .target
        .as_ref()
        .ok_or("Missing username.\nUsage: rb recon domain osint <USERNAME>")?;

    if target.is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    Output::warning("OSINT helpers not yet implemented");
    println!("\nComing soon!");
    Ok(())
}

pub fn email(ctx: &CliContext) -> Result<(), String> {
    let target = ctx
        .target
        .as_ref()
        .ok_or("Missing email address.\nUsage: rb recon domain email <EMAIL>")?;

    if !target.contains('@') {
        return Err(format!("Invalid email address: {}", target));
    }

    Output::header(&format!("Email Intelligence: {}", target));

    let config = EmailOsintConfig::default();
    let intel = EmailIntel::new(config);

    let format = ctx.get_output_format();

    // Validate email format
    if !intel.is_valid_format(target) {
        return Err(format!("Invalid email format: {}", target));
    }

    Output::spinner_start(&format!("Investigating {}", target));

    let result = intel.investigate(target);

    Output::spinner_done();

    // JSON output
    if format == crate::cli::format::OutputFormat::Json {
        println!("{{");
        println!("  \"email\": \"{}\",", result.email);
        println!("  \"valid\": {},", result.valid);
        if let Some(ref provider) = result.provider {
            println!("  \"provider\": \"{}\",", provider);
        }
        println!("  \"services\": [");
        for (i, service) in result.services.iter().enumerate() {
            let comma = if i < result.services.len() - 1 {
                ","
            } else {
                ""
            };
            println!("    \"{}\"{}", service, comma);
        }
        println!("  ],");
        println!("  \"social_profiles\": [");
        for (i, profile) in result.social_profiles.iter().enumerate() {
            let url = profile.url.as_deref().unwrap_or("");
            let comma = if i < result.social_profiles.len() - 1 {
                ","
            } else {
                ""
            };
            println!(
                "    {{ \"platform\": \"{}\", \"url\": \"{}\" }}{}",
                profile.platform, url, comma
            );
        }
        println!("  ]");
        println!("}}");
        return Ok(());
    }

    // Human output
    println!();
    Output::item("Email", &result.email);
    Output::item("Valid", if result.valid { "Yes" } else { "No" });

    if let Some(provider) = &result.provider {
        Output::item("Provider", provider);
    }

    // Check if disposable
    if intel.is_disposable(target) {
        Output::warning("This appears to be a disposable email address");
    }

    // Services found
    if !result.services.is_empty() {
        println!();
        Output::subheader(&format!("Registered Services ({})", result.services.len()));
        for service in &result.services {
            println!("  \x1b[32m✓\x1b[0m {}", service);
        }
    }

    // Social profiles linked
    if !result.social_profiles.is_empty() {
        println!();
        Output::subheader(&format!(
            "Social Profiles ({})",
            result.social_profiles.len()
        ));
        for profile in &result.social_profiles {
            let url = profile.url.as_deref().unwrap_or("N/A");
            println!(
                "  \x1b[32m✓\x1b[0m {} - \x1b[36m{}\x1b[0m",
                profile.platform, url
            );
        }
    }

    // Summary
    println!();
    let total = result.services.len() + result.social_profiles.len();
    if total > 0 {
        Output::success(&format!(
            "Found {} service(s) and {} profile(s)",
            result.services.len(),
            result.social_profiles.len()
        ));
    } else {
        Output::info("No service registrations or profiles found");
    }

    // Extract username and suggest related search
    if let Some(username) = intel.extract_username(target) {
        println!();
        Output::info(&format!(
            "Tip: Try 'rb recon identity username {}' for broader search",
            username
        ));
    }

    Ok(())
}

/// ASN lookup for IP address or hostname
pub fn asn(ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
        "Missing IP address or hostname.\nUsage: rb recon domain asn <IP|HOSTNAME>\nExample: rb recon domain asn 8.8.8.8",
    )?;

    let format = ctx.get_output_format();
    let client = AsnClient::new();

    if format == crate::cli::format::OutputFormat::Human {
        Output::spinner_start(&format!("Looking up ASN for {}", target));
    }

    // Check if it's an IP or hostname
    let is_ip = target.parse::<std::net::IpAddr>().is_ok();

    let results = if is_ip {
        vec![client.lookup_ip(target)?]
    } else {
        client.lookup_host(target)?
    };

    if format == crate::cli::format::OutputFormat::Human {
        Output::spinner_done();
    }

    // JSON output
    if format == crate::cli::format::OutputFormat::Json {
        println!("{{");
        println!("  \"query\": \"{}\",", target);
        println!("  \"results\": [");
        for (i, info) in results.iter().enumerate() {
            let comma = if i < results.len() - 1 { "," } else { "" };
            println!("    {{");
            println!("      \"ip\": \"{}\",", info.ip);
            println!("      \"announced\": {},", info.announced);
            if let Some(asn) = info.asn {
                println!("      \"asn\": {},", asn);
            }
            if let Some(ref org) = info.organization {
                println!("      \"organization\": \"{}\",", org);
            }
            if let Some(ref country) = info.country {
                println!("      \"country\": \"{}\",", country);
            }
            if let Some(ref cidr) = info.cidr {
                println!("      \"cidr\": \"{}\"", cidr);
            }
            println!("    }}{}", comma);
        }
        println!("  ]");
        println!("}}");
        return Ok(());
    }

    // Human output
    Output::header(&format!("ASN Lookup: {}", target));
    println!();

    for info in &results {
        if !info.announced {
            Output::warning(&format!("IP {} is not announced (not routed)", info.ip));
            continue;
        }

        println!("  {:<15} {}", "IP:", info.ip);
        if let Some(asn) = info.asn {
            println!("  {:<15} AS{}", "ASN:", asn);
        }
        if let Some(ref org) = info.organization {
            println!("  {:<15} {}", "Organization:", org);
        }
        if let Some(ref country) = info.country {
            println!("  {:<15} {}", "Country:", country);
        }
        if let Some(ref cidr) = info.cidr {
            println!("  {:<15} {}", "Network:", cidr);
        }
        println!();
    }

    Output::success("ASN lookup completed");
    Ok(())
}
