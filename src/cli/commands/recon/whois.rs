//! WHOIS and RDAP lookups

use super::parse_whois_timestamp;
use crate::cli::commands::build_partition_attributes;
use crate::cli::output::Output;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::protocols::rdap::{RdapClient, RdapDomainResponse, RdapIpResponse};
use crate::protocols::whois::WhoisClient;
use crate::storage::service::StorageService;

pub fn whois(ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.target.as_ref().ok_or(
        "Missing domain.\nUsage: rb recon domain whois <DOMAIN>\nExample: rb recon domain whois example.com",
    )?;

    Validator::validate_domain(domain)?;

    let domain_owned = domain.to_string();
    let format = ctx.get_output_format();
    let client = WhoisClient::new();

    if format == crate::cli::format::OutputFormat::Human {
        Output::spinner_start(&format!("Querying WHOIS for {}", domain));
    }

    let result = client.query(domain)?;

    if format == crate::cli::format::OutputFormat::Human {
        Output::spinner_done();
    }

    // Database persistence
    let persist_flag = if ctx.has_flag("persist") {
        Some(true)
    } else if ctx.has_flag("no-persist") {
        Some(false)
    } else {
        None
    };

    let registrar_attr = result.registrar.as_deref().unwrap_or("unknown");
    let attributes = build_partition_attributes(
        ctx,
        &domain_owned,
        [("operation", "whois"), ("registrar", registrar_attr)],
    );
    let mut pm = StorageService::global().persistence_for_target_with(
        &domain_owned,
        persist_flag,
        None,
        attributes,
    )?;

    // Save WHOIS data to database
    if pm.is_enabled() {
        let registrar = result
            .registrar
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        let created = parse_whois_timestamp(result.creation_date.as_deref()).unwrap_or(0);
        let expires = parse_whois_timestamp(result.expiration_date.as_deref()).unwrap_or(0);
        let nameservers = result.name_servers.clone();

        if let Err(e) = pm.add_whois(domain, &registrar, created, expires, &nameservers) {
            eprintln!("Warning: Failed to save WHOIS data to database: {}", e);
        }
    }

    // JSON output
    if format == crate::cli::format::OutputFormat::Json {
        println!("{{");
        println!("  \"domain\": \"{}\",", domain);
        if let Some(ref registrar) = result.registrar {
            println!("  \"registrar\": \"{}\",", registrar);
        }
        if let Some(ref org) = result.registrant_org {
            println!("  \"registrant_org\": \"{}\",", org);
        }
        if let Some(ref country) = result.registrant_country {
            println!("  \"registrant_country\": \"{}\",", country);
        }
        if let Some(ref created) = result.creation_date {
            println!("  \"creation_date\": \"{}\",", created);
        }
        if let Some(ref updated) = result.updated_date {
            println!("  \"updated_date\": \"{}\",", updated);
        }
        if let Some(ref expires) = result.expiration_date {
            println!("  \"expiration_date\": \"{}\",", expires);
        }
        println!("  \"name_servers\": [");
        for (i, ns) in result.name_servers.iter().enumerate() {
            let comma = if i < result.name_servers.len() - 1 {
                ","
            } else {
                ""
            };
            println!("    \"{}\"{}", ns, comma);
        }
        println!("  ],");
        println!("  \"status\": [");
        for (i, status) in result.status.iter().enumerate() {
            let comma = if i < result.status.len() - 1 { "," } else { "" };
            println!("    \"{}\"{}", status, comma);
        }
        println!("  ]");
        println!("}}");

        pm.commit()?;
        return Ok(());
    }

    // YAML output
    if format == crate::cli::format::OutputFormat::Yaml {
        println!("domain: {}", domain);
        if let Some(ref registrar) = result.registrar {
            println!("registrar: {}", registrar);
        }
        if let Some(ref org) = result.registrant_org {
            println!("registrant_org: {}", org);
        }
        if let Some(ref country) = result.registrant_country {
            println!("country: {}", country);
        }
        if let Some(ref created) = result.creation_date {
            println!("creation_date: {}", created);
        }
        if let Some(ref updated) = result.updated_date {
            println!("updated_date: {}", updated);
        }
        if let Some(ref expires) = result.expiration_date {
            println!("expiration_date: {}", expires);
        }
        println!("name_servers:");
        for ns in &result.name_servers {
            println!("  - {}", ns);
        }
        println!("status:");
        for status in &result.status {
            println!("  - {}", status);
        }

        pm.commit()?;
        return Ok(());
    }

    Output::header(&format!("WHOIS: {}", domain));

    // Compact summary line
    let mut summary_items = vec![];
    if let Some(ref registrar) = result.registrar {
        summary_items.push(("Registrar", registrar.as_str()));
    }
    if let Some(ref org) = result.registrant_org {
        summary_items.push(("Org", org.as_str()));
    }
    if let Some(ref country) = result.registrant_country {
        summary_items.push(("Country", country.as_str()));
    }

    if !summary_items.is_empty() {
        Output::summary_line(&summary_items);
    }

    // Compact dates on one line
    let mut date_items = vec![];
    if let Some(ref created) = result.creation_date {
        date_items.push(("Created", created.as_str()));
    }
    if let Some(ref expires) = result.expiration_date {
        date_items.push(("Expires", expires.as_str()));
    }

    if !date_items.is_empty() {
        Output::summary_line(&date_items);
    }

    if !result.name_servers.is_empty() {
        Output::subheader(&format!("Nameservers ({})", result.name_servers.len()));
        for ns in &result.name_servers {
            println!("  {}", ns);
        }
    }

    if !result.status.is_empty() {
        Output::subheader(&format!("Status ({})", result.status.len()));
        for (i, status) in result.status.iter().enumerate() {
            if i < 3 {
                println!("  {}", status);
            } else if i == 3 {
                println!("  ... and {} more", result.status.len() - 3);
                break;
            }
        }
    }

    if ctx.has_flag("raw") {
        println!();
        Output::subheader("Raw WHOIS Response");
        println!();
        println!("{}", result.raw);
    }

    // Commit database
    if let Some(db_path) = pm.commit()? {
        println!();
        Output::success(&format!("✓ Results saved to {}", db_path.display()));
    } else {
        println!();
        Output::success("WHOIS lookup completed");
    }

    Ok(())
}

/// RDAP lookup - modern WHOIS alternative (RFC 7480-7484)
pub fn rdap(ctx: &CliContext) -> Result<(), String> {
    let target = ctx.target.as_ref().ok_or(
        "Missing target.\nUsage: rb recon domain rdap <DOMAIN|IP>\nExample: rb recon domain rdap example.com"
            .to_string(),
    )?;

    let format = ctx.get_output_format();
    let mut client = RdapClient::new();

    // Detect if target is IP or domain
    let is_ip = target.parse::<std::net::IpAddr>().is_ok();

    if format == crate::cli::format::OutputFormat::Human {
        Output::spinner_start(&format!(
            "Querying RDAP for {} ({})",
            target,
            if is_ip { "IP" } else { "domain" }
        ));
    }

    if is_ip {
        // IP lookup
        let result: RdapIpResponse = client.query_ip(target)?;

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"type\": \"ip\",");
            println!("  \"query\": \"{}\",", target);
            println!("  \"handle\": \"{}\",", result.handle);
            println!("  \"start_address\": \"{}\",", result.start_address);
            println!("  \"end_address\": \"{}\",", result.end_address);
            println!("  \"ip_version\": \"{}\",", result.ip_version);
            if let Some(ref name) = result.name {
                println!("  \"name\": \"{}\",", name);
            }
            if let Some(ref country) = result.country {
                println!("  \"country\": \"{}\",", country);
            }
            println!("  \"status\": [");
            for (i, status) in result.status.iter().enumerate() {
                let comma = if i < result.status.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", status, comma);
            }
            println!("  ],");
            println!("  \"events\": [");
            for (i, event) in result.events.iter().enumerate() {
                let comma = if i < result.events.len() - 1 { "," } else { "" };
                println!(
                    "    {{ \"action\": \"{}\", \"date\": \"{}\" }}{}",
                    event.action, event.date, comma
                );
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("type: ip");
            println!("query: {}", target);
            println!("handle: {}", result.handle);
            println!("start_address: {}", result.start_address);
            println!("end_address: {}", result.end_address);
            println!("ip_version: {}", result.ip_version);
            if let Some(ref name) = result.name {
                println!("name: {}", name);
            }
            if let Some(ref country) = result.country {
                println!("country: {}", country);
            }
            println!("status:");
            for status in &result.status {
                println!("  - {}", status);
            }
            println!("events:");
            for event in &result.events {
                println!("  - action: {}", event.action);
                println!("    date: {}", event.date);
            }
            return Ok(());
        }

        // Human output
        Output::header(&format!("RDAP: {} (IP)", target));

        // Summary line
        let range_str = format!("{} - {}", result.start_address, result.end_address);
        let mut summary: Vec<(&str, &str)> = vec![];
        summary.push(("Handle", result.handle.as_str()));
        summary.push(("Range", &range_str));
        if let Some(ref name) = result.name {
            summary.push(("Name", name.as_str()));
        }
        if let Some(ref country) = result.country {
            summary.push(("Country", country.as_str()));
        }
        Output::summary_line(&summary);

        if !result.status.is_empty() {
            Output::subheader("Status");
            for status in &result.status {
                println!("  {}", status);
            }
        }

        if !result.events.is_empty() {
            Output::subheader("Events");
            for event in &result.events {
                println!("  {} - {}", event.action, event.date);
            }
        }

        if !result.entities.is_empty() {
            Output::subheader("Entities");
            for entity in &result.entities {
                let name = entity
                    .name
                    .as_deref()
                    .or(entity.organization.as_deref())
                    .unwrap_or("Unknown");
                let roles = entity.roles.join(", ");
                println!("  {} ({})", name, roles);
            }
        }

        if ctx.has_flag("raw") {
            println!();
            Output::subheader("Raw RDAP Response");
            println!("{}", result.raw_json);
        }
    } else {
        // Domain lookup
        Validator::validate_domain(target)?;
        let result: RdapDomainResponse = client.query_domain(target)?;

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"type\": \"domain\",");
            println!("  \"domain\": \"{}\",", result.domain);
            if let Some(ref registrar) = result.registrar {
                println!("  \"registrar\": \"{}\",", registrar);
            }
            println!("  \"status\": [");
            for (i, status) in result.status.iter().enumerate() {
                let comma = if i < result.status.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", status, comma);
            }
            println!("  ],");
            println!("  \"nameservers\": [");
            for (i, ns) in result.nameservers.iter().enumerate() {
                let comma = if i < result.nameservers.len() - 1 {
                    ","
                } else {
                    ""
                };
                println!("    \"{}\"{}", ns, comma);
            }
            println!("  ],");
            println!("  \"events\": [");
            for (i, event) in result.events.iter().enumerate() {
                let comma = if i < result.events.len() - 1 { "," } else { "" };
                println!(
                    "    {{ \"action\": \"{}\", \"date\": \"{}\" }}{}",
                    event.action, event.date, comma
                );
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("type: domain");
            println!("query: {}", target);
            println!("name: {}", result.domain);
            if let Some(ref registrar) = result.registrar {
                println!("country: {}", registrar);
            }
            println!("status:");
            for status in &result.status {
                println!("  - {}", status);
            }
            println!("nameservers:");
            for ns in &result.nameservers {
                println!("  - {}", ns);
            }
            println!("events:");
            for event in &result.events {
                println!("  - action: {}", event.action);
                println!("    date: {}", event.date);
            }
            return Ok(());
        }

        // Human output
        Output::header(&format!("RDAP: {}", result.domain));

        if let Some(ref registrar) = result.registrar {
            Output::item("Registrar", registrar);
        }

        if !result.status.is_empty() {
            Output::subheader(&format!("Status ({})", result.status.len()));
            for (i, status) in result.status.iter().enumerate() {
                if i < 5 {
                    println!("  {}", status);
                } else if i == 5 {
                    println!("  ... and {} more", result.status.len() - 5);
                    break;
                }
            }
        }

        if !result.nameservers.is_empty() {
            Output::subheader(&format!("Nameservers ({})", result.nameservers.len()));
            for ns in &result.nameservers {
                println!("  {}", ns);
            }
        }

        if !result.events.is_empty() {
            Output::subheader("Events");
            for event in &result.events {
                let action_display = match event.action.as_str() {
                    "registration" => "Registered",
                    "expiration" => "Expires",
                    "last changed" => "Updated",
                    "last update of RDAP database" => "RDAP Updated",
                    other => other,
                };
                let date_display = if event.date.len() > 10 {
                    &event.date[..10]
                } else {
                    &event.date
                };
                println!("  {} : {}", action_display, date_display);
            }
        }

        if let Some(ref registrant) = result.registrant {
            Output::subheader("Registrant");
            if let Some(ref name) = registrant.name {
                println!("  Name: {}", name);
            }
            if let Some(ref org) = registrant.organization {
                println!("  Organization: {}", org);
            }
        }

        if ctx.has_flag("raw") {
            println!();
            Output::subheader("Raw RDAP Response");
            println!("{}", result.raw_json);
        }
    }

    println!();
    Output::success("RDAP lookup completed");
    Ok(())
}
