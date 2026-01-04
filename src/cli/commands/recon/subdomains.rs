//! Subdomain enumeration commands

use super::map_subdomain_source;
use crate::cli::commands::build_partition_attributes;
use crate::cli::output::Output;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::modules::recon::dnsdumpster::DnsDumpsterClient;
use crate::modules::recon::massdns::{common_subdomains, MassDnsScanner};
use crate::modules::recon::subdomain::{load_wordlist_from_file, SubdomainEnumerator};
use crate::storage::service::StorageService;
use std::net::IpAddr;
use std::time::Duration;

pub fn subdomains(ctx: &CliContext) -> Result<(), String> {
    let domain = ctx
        .target
        .as_ref()
        .ok_or("Missing domain.\nUsage: rb recon domain subdomains <DOMAIN>")?;

    Validator::validate_domain(domain)?;

    let format = ctx.get_output_format();

    // Create enumerator
    let mut enumerator = SubdomainEnumerator::new(domain);

    // Apply flags
    if let Some(threads_str) = ctx.get_flag("threads") {
        let threads: usize = threads_str
            .parse()
            .map_err(|_| format!("Invalid threads value: {}", threads_str))?;
        enumerator = enumerator.with_threads(threads);
    }

    if let Some(wordlist_path) = ctx.get_flag("wordlist") {
        let wordlist = load_wordlist_from_file(&wordlist_path)?;
        enumerator = enumerator.with_wordlist(wordlist);
    }

    // Apply wildcard filtering flag
    let filter_wildcards = ctx.has_flag("filter-wildcards");
    enumerator = enumerator.with_wildcard_filtering(filter_wildcards);

    let passive_only = ctx.has_flag("passive");

    // Run enumeration
    let results = if passive_only {
        enumerator.enumerate_ct_logs()?
    } else {
        enumerator.enumerate_all()?
    };

    // JSON output
    if format == crate::cli::format::OutputFormat::Json {
        println!("{{");
        println!("  \"domain\": \"{}\",", domain);
        println!("  \"count\": {},", results.len());
        println!("  \"subdomains\": [");
        for (i, result) in results.iter().enumerate() {
            let comma = if i < results.len() - 1 { "," } else { "" };
            println!("    {{");
            println!("      \"subdomain\": \"{}\",", result.subdomain);
            println!("      \"ips\": [");
            for (j, ip) in result.ips.iter().enumerate() {
                let ip_comma = if j < result.ips.len() - 1 { "," } else { "" };
                println!("        \"{}\"{}", ip, ip_comma);
            }
            println!("      ],");
            println!("      \"cname_chain\": [");
            for (j, cname) in result.cname_chain.iter().enumerate() {
                let cname_comma = if j < result.cname_chain.len() - 1 {
                    ","
                } else {
                    ""
                };
                println!("        \"{}\"{}", cname, cname_comma);
            }
            println!("      ],");
            println!("      \"source\": \"{}\"", result.source);
            println!("    }}{}", comma);
        }
        println!("  ]");
        println!("}}");
        return Ok(());
    }

    // YAML output
    if format == crate::cli::format::OutputFormat::Yaml {
        println!("domain: {}", domain);
        println!("count: {}", results.len());
        println!("subdomains:");
        for result in &results {
            println!("  - subdomain: {}", result.subdomain);
            println!("    ips:");
            for ip in &result.ips {
                println!("      - {}", ip);
            }
            if !result.cname_chain.is_empty() {
                println!("    cname_chain:");
                for cname in &result.cname_chain {
                    println!("      - {}", cname);
                }
            }
            println!("    source: {}", result.source);
        }
        return Ok(());
    }

    // Human output
    if results.is_empty() {
        Output::warning("No subdomains found");
        return Ok(());
    }

    Output::header("Subdomain Enumeration");
    Output::item("Target Domain", domain);
    println!();

    println!();
    Output::subheader(&format!("Discovered Subdomains ({})", results.len()));
    println!();

    // Print table header
    println!(
        "  {:<40} {:<20} {:<10}",
        "SUBDOMAIN", "IP ADDRESSES", "SOURCE"
    );
    println!("  {}", "─".repeat(75));

    for result in &results {
        let ips = if result.ips.is_empty() {
            "N/A".to_string()
        } else if result.ips.len() == 1 {
            result.ips[0].clone()
        } else {
            format!("{} (+{})", result.ips[0], result.ips.len() - 1)
        };

        println!(
            "  {:<40} {:<20} {:<10}",
            result.subdomain,
            ips,
            result.source.to_string()
        );

        // Show CNAME chain if present
        if !result.cname_chain.is_empty() {
            println!("    └─ CNAME: {}", result.cname_chain.join(" → "));
        }
    }

    println!();
    Output::success(&format!("Found {} unique subdomains", results.len()));

    // Persistence
    let persist_flag = if ctx.has_flag("persist") {
        Some(true)
    } else if ctx.has_flag("no-persist") {
        Some(false)
    } else {
        None
    };

    let mode_value = if passive_only { "passive" } else { "hybrid" };
    let attributes = build_partition_attributes(
        ctx,
        domain,
        [("operation", "subdomains"), ("mode", mode_value)],
    );
    let mut pm = StorageService::global().persistence_for_target_with(
        domain,
        persist_flag,
        None,
        attributes,
    )?;
    if pm.is_enabled() {
        for result in &results {
            let source = map_subdomain_source(&result.source.to_string());
            let ips: Vec<IpAddr> = result
                .ips
                .iter()
                .filter_map(|ip| ip.parse::<IpAddr>().ok())
                .collect();

            pm.add_subdomain(domain, &result.subdomain, source as u8, &ips)?;
        }

        if let Some(db_path) = pm.commit()? {
            Output::success(&format!("Results saved to {}", db_path.display()));
        }
    }

    Ok(())
}

pub fn dnsdumpster(ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain dnsdumpster <DOMAIN>\nExample: rb recon domain dnsdumpster example.com",
    )?;

    Validator::validate_domain(domain)?;

    Output::header(&format!("DNSDumpster Lookup: {}", domain));
    println!();

    let client = DnsDumpsterClient::new();

    Output::spinner_start(&format!("Querying DNSDumpster for {}", domain));
    let results = client.query(domain)?;
    Output::spinner_done();

    if results.dns_records.is_empty() && results.host_records.is_empty() {
        Output::info("No DNS records found.");
        return Ok(());
    }

    println!();
    Output::subheader(&format!(
        "DNS Records ({})",
        results.dns_records.len() + results.host_records.len()
    ));
    println!();

    for record in &results.dns_records {
        println!("  \x1b[1m{}: {}\x1b[0m", record.record_type, record.value);
    }
    for record in &results.host_records {
        println!(
            "  \x1b[1mHost: {}\x1b[0m ({})",
            record.host,
            record.ip.as_deref().unwrap_or("N/A")
        );
    }

    Output::success(&format!(
        "Found {} DNS records",
        results.dns_records.len() + results.host_records.len()
    ));

    Ok(())
}

pub fn massdns(ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain massdns <DOMAIN> [--wordlist <file>] [--threads N]\nExample: rb recon domain massdns example.com",
    )?;

    Validator::validate_domain(domain)?;

    let wordlist_path = ctx.get_flag("wordlist");
    let threads: usize = ctx
        .get_flag("threads")
        .unwrap_or_else(|| "10".to_string())
        .parse()
        .unwrap_or(10);
    let resolvers: Vec<String> = ctx
        .get_flag("resolvers")
        .unwrap_or_else(|| "8.8.8.8,1.1.1.1,9.9.9.9".to_string())
        .split(',')
        .map(|s| s.to_string())
        .collect();
    let timeout_ms: u64 = ctx
        .get_flag("timeout-ms")
        .unwrap_or_else(|| "2000".to_string())
        .parse()
        .unwrap_or(2000);
    let delay: u64 = ctx
        .get_flag("delay")
        .unwrap_or_else(|| "10".to_string())
        .parse()
        .unwrap_or(10);

    Output::header(&format!("MassDNS Subdomain Enumeration: {}", domain));
    Output::item("Threads", &threads.to_string());
    Output::item("Resolvers", &resolvers.join(", "));
    Output::item("Timeout (ms)", &timeout_ms.to_string());
    Output::item("Delay (ms)", &delay.to_string());
    if let Some(path) = &wordlist_path {
        Output::item("Wordlist", path);
    } else {
        Output::item("Wordlist", "Default (common subdomains)");
    }
    println!();

    let scanner = MassDnsScanner::new()
        .with_threads(threads)
        .with_resolvers(resolvers)
        .with_timeout(Duration::from_millis(timeout_ms))
        .with_delay(Duration::from_millis(delay));

    let wordlist: Vec<String>;
    if let Some(path) = wordlist_path {
        wordlist = load_wordlist_from_file(&path)?;
    } else {
        wordlist = common_subdomains();
    }

    Output::spinner_start("Starting MassDNS scan...");
    let results = scanner.bruteforce(domain, &wordlist)?;
    Output::spinner_done();

    if results.resolved.is_empty() {
        Output::info("No subdomains found.");
        return Ok(());
    }

    println!();
    Output::subheader(&format!("Found {} Subdomains", results.resolved.len()));
    println!();

    for result in &results.resolved {
        let ips = result.ips.join(", ");
        println!("  \x1b[32m●\x1b[0m {} ({})", result.subdomain, ips);
    }

    Output::success(&format!("Found {} subdomains", results.resolved.len()));

    Ok(())
}
