//! Entity-Centric Intelligence Commands
//!
//! Intelligence queries centered on specific entity types:
//! - Host: What do we know about this host?
//! - Credential: Where can this credential access?
//! - User: Where does this user exist?
//! - Service: Who runs this service?
//! - Vulnerability: What is affected?
//! - Technology: Who uses this technology?
//! - Network: Segments and gateways
//! - Domain: DNS and subdomains
//! - Certificate: Certificates and their usage

use super::helpers::truncate_str;
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::serde_json::Value;
use crate::storage::engine::{ConnectedComponents, GraphEdgeType, GraphNodeType, GraphStore};

/// Host-centric intelligence command
pub fn cmd_intel_host(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let target = ctx
    .target
    .clone()
    .or_else(|| ctx.args.first().cloned())
    .ok_or_else(|| "No host specified. Usage: rb intel graph host <ip>".to_string())?;

  Output::info(&format!("Analyzing host: {}", target));

  // Find host node (try exact match, then partial)
  let host_node = graph.iter_nodes().find(|n| {
    matches!(n.node_type, GraphNodeType::Host)
      && (n.id.contains(&target) || n.label.contains(&target))
  });

  let host = match host_node {
    Some(h) => h,
    None => {
      let hosts: Vec<_> = graph
        .iter_nodes()
        .filter(|n| matches!(n.node_type, GraphNodeType::Host))
        .take(10)
        .collect();
      if format == "json" {
        let payload = not_found_payload("host", &target, &hosts);
        render::render_machine_output(ctx, "rb intel graph host", &payload)?;
      } else {
        Output::warning(&format!("Host '{}' not found in graph", target));
        if !hosts.is_empty() {
          println!("\nAvailable hosts:");
          for h in &hosts {
            println!("  • {} ({})", h.label, h.id);
          }
        }
      }
      return Ok(());
    }
  };

  // Get related nodes via edges
  let services: Vec<_> = graph
    .outgoing_edges(&host.id)
    .iter()
    .filter(|(et, _, _)| matches!(et, GraphEdgeType::HasService))
    .filter_map(|(_, target, _)| graph.get_node(target))
    .collect();

  let vulns: Vec<_> = graph
    .outgoing_edges(&host.id)
    .iter()
    .filter(|(et, _, _)| matches!(et, GraphEdgeType::AffectedBy))
    .filter_map(|(_, target, _)| graph.get_node(target))
    .collect();

  let users: Vec<_> = graph
    .outgoing_edges(&host.id)
    .iter()
    .filter(|(et, _, _)| matches!(et, GraphEdgeType::HasUser))
    .filter_map(|(_, target, _)| graph.get_node(target))
    .collect();

  let techs: Vec<_> = graph
    .outgoing_edges(&host.id)
    .iter()
    .filter(|(et, _, _)| matches!(et, GraphEdgeType::UsesTech))
    .filter_map(|(_, target, _)| graph.get_node(target))
    .collect();

  // Incoming connections
  let connected_from: Vec<_> = graph
    .incoming_edges(&host.id)
    .iter()
    .filter(|(et, _, _)| matches!(et, GraphEdgeType::ConnectsTo))
    .filter_map(|(_, source, _)| graph.get_node(source))
    .collect();

  if format == "json" {
    let payload = host_payload(&host, &services, &vulns, &users, &techs, &connected_from);
    render::render_machine_output(ctx, "rb intel graph host", &payload)?;
  } else {
    Output::header(&format!("Host Intelligence: {}", host.label));
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  HOST: {:<53} │", truncate_str(&host.label, 53));
    println!("│  ID:   {:<53} │", truncate_str(&host.id, 53));
    println!("├─────────────────────────────────────────────────────────────┤");

    // Services
    if !services.is_empty() {
      println!(
        "│  SERVICES ({})                                               │",
        services.len()
      );
      for svc in services.iter().take(5) {
        println!("│    ⚙ {:<55} │", truncate_str(&svc.label, 55));
      }
      if services.len() > 5 {
        println!(
          "│    ... and {} more                                          │",
          services.len() - 5
        );
      }
    }

    // Vulnerabilities
    if !vulns.is_empty() {
      println!(
        "│  VULNERABILITIES ({})                                        │",
        vulns.len()
      );
      for vuln in vulns.iter().take(5) {
        println!("│    ⚠ {:<55} │", truncate_str(&vuln.label, 55));
      }
    }

    // Users
    if !users.is_empty() {
      println!(
        "│  USERS ({})                                                  │",
        users.len()
      );
      for user in users.iter().take(5) {
        println!("│    👤 {:<54} │", truncate_str(&user.label, 54));
      }
    }

    // Technologies
    if !techs.is_empty() {
      println!(
        "│  TECHNOLOGIES ({})                                           │",
        techs.len()
      );
      for tech in techs.iter().take(5) {
        println!("│    🔧 {:<54} │", truncate_str(&tech.label, 54));
      }
    }

    // Connected from
    if !connected_from.is_empty() {
      println!(
        "│  CONNECTED FROM ({})                                         │",
        connected_from.len()
      );
      for src in connected_from.iter().take(3) {
        println!("│    ← {:<55} │", truncate_str(&src.label, 55));
      }
    }

    println!("└─────────────────────────────────────────────────────────────┘");
  }

  Ok(())
}

/// Credential-centric intelligence command
pub fn cmd_intel_credential(
  ctx: &CliContext,
  graph: &GraphStore,
  format: &str,
) -> Result<(), String> {
  let target = ctx
    .target
    .clone()
    .or_else(|| ctx.args.first().cloned())
    .ok_or_else(|| {
      "No credential specified. Usage: rb intel graph credential <name>".to_string()
    })?;

  Output::info(&format!("Analyzing credential: {}", target));

  // Find credential node
  let cred_node = graph.iter_nodes().find(|n| {
    matches!(n.node_type, GraphNodeType::Credential)
      && (n.id.contains(&target) || n.label.to_lowercase().contains(&target.to_lowercase()))
  });

  let cred = match cred_node {
    Some(c) => c,
    None => {
      let creds: Vec<_> = graph
        .iter_nodes()
        .filter(|n| matches!(n.node_type, GraphNodeType::Credential))
        .take(10)
        .collect();
      if format == "json" {
        let payload = not_found_payload("credential", &target, &creds);
        render::render_machine_output(ctx, "rb intel graph credential", &payload)?;
      } else {
        Output::warning(&format!("Credential '{}' not found", target));
        if !creds.is_empty() {
          println!("\nAvailable credentials:");
          for c in &creds {
            println!("  • {} ({})", c.label, c.id);
          }
        }
      }
      return Ok(());
    }
  };

  // Find hosts this credential can access (AuthAccess edges)
  let reachable_hosts: Vec<_> = graph
    .outgoing_edges(&cred.id)
    .iter()
    .filter(|(et, _, _)| matches!(et, GraphEdgeType::AuthAccess))
    .filter_map(|(_, target, _)| graph.get_node(target))
    .collect();

  // Find where this credential was found
  let found_on: Vec<_> = graph
    .incoming_edges(&cred.id)
    .iter()
    .filter_map(|(_, source, _)| graph.get_node(source))
    .filter(|n| matches!(n.node_type, GraphNodeType::Host))
    .collect();

  if format == "json" {
    let payload = credential_payload(&cred, &reachable_hosts, &found_on);
    render::render_machine_output(ctx, "rb intel graph credential", &payload)?;
  } else {
    Output::header(&format!("Credential Intelligence: {}", cred.label));
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  CREDENTIAL: {:<47} │", truncate_str(&cred.label, 47));
    println!(
      "│  REACH: {} hosts can be accessed                            │",
      reachable_hosts.len()
    );
    println!("├─────────────────────────────────────────────────────────────┤");

    if !reachable_hosts.is_empty() {
      println!("│  CAN ACCESS:                                                │");
      for host in reachable_hosts.iter().take(10) {
        println!("│    → {:<55} │", truncate_str(&host.label, 55));
      }
    }

    if !found_on.is_empty() {
      println!("│  FOUND ON:                                                  │");
      for host in found_on.iter().take(5) {
        println!("│    • {:<55} │", truncate_str(&host.label, 55));
      }
    }

    println!("└─────────────────────────────────────────────────────────────┘");
  }

  Ok(())
}

/// User-centric intelligence command
pub fn cmd_intel_user(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let target = ctx
    .target
    .clone()
    .or_else(|| ctx.args.first().cloned())
    .ok_or_else(|| "No user specified. Usage: rb intel graph user <username>".to_string())?;

  Output::info(&format!("Analyzing user: {}", target));

  // Find user nodes (type User or search in Credentials)
  let user_nodes: Vec<_> = graph
    .iter_nodes()
    .filter(|n| {
      (matches!(n.node_type, GraphNodeType::User)
        || matches!(n.node_type, GraphNodeType::Credential))
        && n.label.to_lowercase().contains(&target.to_lowercase())
    })
    .collect();

  if user_nodes.is_empty() {
    if format == "json" {
      let payload = json!({
        "entity": "user",
        "target": target,
        "status": "not_found",
        "matches": []
      });
      render::render_machine_output(ctx, "rb intel graph user", &payload)?;
    } else {
      Output::warning(&format!("User '{}' not found", target));
    }
    return Ok(());
  }

  // Find hosts where this user exists
  let mut hosts_with_user: std::collections::HashSet<String> = std::collections::HashSet::new();
  for user in &user_nodes {
    for (_, source, _) in graph.incoming_edges(&user.id) {
      if let Some(node) = graph.get_node(&source) {
        if matches!(node.node_type, GraphNodeType::Host) {
          hosts_with_user.insert(source);
        }
      }
    }
  }

  if format == "json" {
    let payload = user_payload(&target, &user_nodes, &hosts_with_user);
    render::render_machine_output(ctx, "rb intel graph user", &payload)?;
  } else {
    Output::header(&format!("User Intelligence: {}", target));
    println!();

    println!("Found on {} hosts:", hosts_with_user.len());
    for host_id in hosts_with_user.iter().take(20) {
      if let Some(host) = graph.get_node(host_id) {
        println!("  • {}", host.label);
      }
    }
  }

  Ok(())
}

/// Service-centric intelligence command
pub fn cmd_intel_service(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let target = ctx
    .target
    .clone()
    .or_else(|| ctx.args.first().cloned())
    .ok_or_else(|| "No service specified. Usage: rb intel graph service <name>".to_string())?;

  Output::info(&format!("Analyzing service: {}", target));

  // Find all service nodes matching the name
  let service_nodes: Vec<_> = graph
    .iter_nodes()
    .filter(|n| {
      matches!(n.node_type, GraphNodeType::Service)
        && n.label.to_lowercase().contains(&target.to_lowercase())
    })
    .collect();

  if service_nodes.is_empty() {
    let services: Vec<_> = graph
      .iter_nodes()
      .filter(|n| matches!(n.node_type, GraphNodeType::Service))
      .take(10)
      .collect();
    if format == "json" {
      let payload = not_found_payload("service", &target, &services);
      render::render_machine_output(ctx, "rb intel graph service", &payload)?;
    } else {
      Output::warning(&format!("Service '{}' not found", target));
      if !services.is_empty() {
        println!("\nAvailable services:");
        for s in &services {
          println!("  • {}", s.label);
        }
      }
    }
    return Ok(());
  }

  // Find hosts running this service
  let mut hosts: Vec<_> = Vec::new();
  for svc in &service_nodes {
    for (_, source, _) in graph.incoming_edges(&svc.id) {
      if let Some(node) = graph.get_node(&source) {
        if matches!(node.node_type, GraphNodeType::Host) {
          hosts.push(node);
        }
      }
    }
  }

  // Find vulnerabilities affecting this service
  let mut vulns: Vec<_> = Vec::new();
  for svc in &service_nodes {
    for (et, target, _) in graph.outgoing_edges(&svc.id) {
      if matches!(et, GraphEdgeType::AffectedBy) {
        if let Some(node) = graph.get_node(&target) {
          vulns.push(node);
        }
      }
    }
  }

  if format == "json" {
    let payload = service_payload(&target, &service_nodes, &hosts, &vulns);
    render::render_machine_output(ctx, "rb intel graph service", &payload)?;
  } else {
    Output::header(&format!("Service Intelligence: {}", target));
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  SERVICE: {:<50} │", truncate_str(&target, 50));
    println!("│  INSTANCES: {:<48} │", service_nodes.len());
    println!("├─────────────────────────────────────────────────────────────┤");

    if !hosts.is_empty() {
      println!(
        "│  HOSTS RUNNING THIS SERVICE ({})                           │",
        hosts.len()
      );
      for host in hosts.iter().take(10) {
        println!("│    🖥 {:<54} │", truncate_str(&host.label, 54));
      }
    }

    if !vulns.is_empty() {
      println!(
        "│  KNOWN VULNERABILITIES ({})                                │",
        vulns.len()
      );
      for vuln in vulns.iter().take(5) {
        println!("│    ⚠ {:<55} │", truncate_str(&vuln.label, 55));
      }
    }

    println!("└─────────────────────────────────────────────────────────────┘");
  }

  Ok(())
}

/// Vulnerability-centric intelligence command
pub fn cmd_intel_vuln(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let target = ctx.target.clone().or_else(|| ctx.args.first().cloned());

  let show_critical = ctx.flags.contains_key("critical");

  if target.is_none() && !show_critical {
    return Err("No CVE specified. Usage: rb intel graph vuln <cve> or --critical".to_string());
  }

  // Get all vulnerabilities
  let all_vulns: Vec<_> = graph
    .iter_nodes()
    .filter(|n| matches!(n.node_type, GraphNodeType::Vulnerability))
    .collect();

  if show_critical {
    // Sort by number of affected hosts
    let mut vuln_hosts: Vec<(&crate::storage::engine::StoredNode, usize)> = all_vulns
      .iter()
      .map(|v| {
        let affected = graph
          .incoming_edges(&v.id)
          .iter()
          .filter(|(et, _, _)| matches!(et, GraphEdgeType::AffectedBy))
          .count();
        (v, affected)
      })
      .collect();
    vuln_hosts.sort_by(|a, b| b.1.cmp(&a.1));
    if format == "json" {
      let payload = critical_vulns_payload(&vuln_hosts);
      render::render_machine_output(ctx, "rb intel graph vuln", &payload)?;
    } else {
      Output::header("Critical Vulnerabilities");
      println!();
      println!("{:<40} {:>10}", "Vulnerability", "Affected");
      println!("{}", "-".repeat(52));
      for (vuln, count) in vuln_hosts.iter().take(20) {
        println!("{:<40} {:>10}", truncate_str(&vuln.label, 40), count);
      }
    }
    return Ok(());
  }

  let target = target.unwrap();
  Output::info(&format!("Analyzing vulnerability: {}", target));

  // Find the vulnerability
  let vuln_node = graph.iter_nodes().find(|n| {
    matches!(n.node_type, GraphNodeType::Vulnerability)
      && (n.id.contains(&target) || n.label.to_lowercase().contains(&target.to_lowercase()))
  });

  let vuln = match vuln_node {
    Some(v) => v,
    None => {
      if format == "json" {
        let payload = json!({
          "entity": "vulnerability",
          "target": target,
          "status": "not_found"
        });
        render::render_machine_output(ctx, "rb intel graph vuln", &payload)?;
      } else {
        Output::warning(&format!("Vulnerability '{}' not found", target));
      }
      return Ok(());
    }
  };

  // Find affected hosts/services
  let affected: Vec<_> = graph
    .incoming_edges(&vuln.id)
    .iter()
    .filter(|(et, _, _)| matches!(et, GraphEdgeType::AffectedBy))
    .filter_map(|(_, source, _)| graph.get_node(source))
    .collect();

  if format == "json" {
    let payload = vuln_payload(&vuln, &affected);
    render::render_machine_output(ctx, "rb intel graph vuln", &payload)?;
  } else {
    Output::header(&format!("Vulnerability Intelligence: {}", vuln.label));
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  VULN: {:<53} │", truncate_str(&vuln.label, 53));
    println!(
      "│  AFFECTED: {} hosts/services                                │",
      affected.len()
    );
    println!("├─────────────────────────────────────────────────────────────┤");

    if !affected.is_empty() {
      println!("│  AFFECTED ASSETS:                                           │");
      for asset in affected.iter().take(15) {
        let icon = match asset.node_type {
          GraphNodeType::Host => "🖥",
          GraphNodeType::Service => "⚙",
          _ => "•",
        };
        println!("│    {} {:<54} │", icon, truncate_str(&asset.label, 54));
      }
    }

    println!("└─────────────────────────────────────────────────────────────┘");
  }

  Ok(())
}

/// Technology-centric intelligence command
pub fn cmd_intel_tech(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let target = ctx
    .target
    .clone()
    .or_else(|| ctx.args.first().cloned())
    .ok_or_else(|| "No technology specified. Usage: rb intel graph tech <name>".to_string())?;

  Output::info(&format!("Analyzing technology: {}", target));

  // Find technology nodes
  let tech_nodes: Vec<_> = graph
    .iter_nodes()
    .filter(|n| {
      matches!(n.node_type, GraphNodeType::Technology)
        && n.label.to_lowercase().contains(&target.to_lowercase())
    })
    .collect();

  if tech_nodes.is_empty() {
    let techs: Vec<_> = graph
      .iter_nodes()
      .filter(|n| matches!(n.node_type, GraphNodeType::Technology))
      .take(10)
      .collect();
    if format == "json" {
      let payload = not_found_payload("technology", &target, &techs);
      render::render_machine_output(ctx, "rb intel graph tech", &payload)?;
    } else {
      Output::warning(&format!("Technology '{}' not found", target));
      if !techs.is_empty() {
        println!("\nAvailable technologies:");
        for t in &techs {
          println!("  • {}", t.label);
        }
      }
    }
    return Ok(());
  }

  // Find hosts using this technology
  let mut hosts: Vec<_> = Vec::new();
  for tech in &tech_nodes {
    for (_, source, _) in graph.incoming_edges(&tech.id) {
      if let Some(node) = graph.get_node(&source) {
        if matches!(node.node_type, GraphNodeType::Host) {
          hosts.push(node);
        }
      }
    }
  }

  if format == "json" {
    let payload = tech_payload(&target, &tech_nodes, &hosts);
    render::render_machine_output(ctx, "rb intel graph tech", &payload)?;
  } else {
    Output::header(&format!("Technology Intelligence: {}", target));
    println!();

    println!("Versions found: {}", tech_nodes.len());
    for tech in tech_nodes.iter().take(5) {
      println!("  • {}", tech.label);
    }

    println!("\nUsed by {} hosts:", hosts.len());
    for host in hosts.iter().take(15) {
      println!("  🖥 {}", host.label);
    }
  }

  Ok(())
}

/// Network topology intelligence command
pub fn cmd_intel_network(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  Output::info("Analyzing network topology...");

  // Get all hosts
  let hosts: Vec<_> = graph
    .iter_nodes()
    .filter(|n| matches!(n.node_type, GraphNodeType::Host))
    .collect();

  // Build connectivity map
  let mut connections: std::collections::HashMap<String, Vec<String>> =
    std::collections::HashMap::new();

  for host in &hosts {
    let connected: Vec<String> = graph
      .outgoing_edges(&host.id)
      .iter()
      .filter(|(et, _, _)| matches!(et, GraphEdgeType::ConnectsTo))
      .map(|(_, target, _)| target.clone())
      .collect();
    connections.insert(host.id.clone(), connected);
  }

  // Find gateway nodes (high connectivity)
  let mut gateways: Vec<(&crate::storage::engine::StoredNode, usize)> = hosts
    .iter()
    .map(|h| {
      let out_count = connections.get(&h.id).map(|v| v.len()).unwrap_or(0);
      let in_count = graph
        .incoming_edges(&h.id)
        .iter()
        .filter(|(et, _, _)| matches!(et, GraphEdgeType::ConnectsTo))
        .count();
      (h, out_count + in_count)
    })
    .filter(|(_, count)| *count > 2)
    .collect();
  gateways.sort_by(|a, b| b.1.cmp(&a.1));

  // Detect segments using connected components
  let components = ConnectedComponents::find(graph);

  if format == "json" {
    let payload = network_payload(&hosts, &components, &gateways);
    render::render_machine_output(ctx, "rb intel graph network", &payload)?;
  } else {
    Output::header("Network Topology Intelligence");
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  NETWORK OVERVIEW                                           │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│  Total Hosts: {:<46} │", hosts.len());
    println!("│  Network Segments: {:<41} │", components.count);
    println!("│  Potential Gateways: {:<39} │", gateways.len());
    println!("└─────────────────────────────────────────────────────────────┘");

    if !gateways.is_empty() {
      println!("\nGateway Nodes (high connectivity):");
      for (gw, count) in gateways.iter().take(10) {
        println!("  🌐 {} ({} connections)", gw.label, count);
      }
    }

    println!("\nSegments:");
    for (i, comp) in components.components.iter().take(5).enumerate() {
      let hosts_in_segment: Vec<_> = comp
        .nodes
        .iter()
        .filter_map(|id| graph.get_node(id))
        .filter(|n| matches!(n.node_type, GraphNodeType::Host))
        .take(3)
        .collect();
      let host_names: Vec<_> = hosts_in_segment.iter().map(|h| h.label.as_str()).collect();
      println!(
        "  Segment {}: {} nodes ({}{})",
        i + 1,
        comp.size,
        host_names.join(", "),
        if comp.size > 3 { "..." } else { "" }
      );
    }
  }

  Ok(())
}

/// Domain-centric intelligence command
pub fn cmd_intel_domain(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let target = ctx
    .target
    .clone()
    .or_else(|| ctx.args.first().cloned())
    .ok_or_else(|| "No domain specified. Usage: rb intel graph domain <name>".to_string())?;

  Output::info(&format!("Analyzing domain: {}", target));

  // Find domain nodes
  let domain_nodes: Vec<_> = graph
    .iter_nodes()
    .filter(|n| {
      matches!(n.node_type, GraphNodeType::Domain)
        && n.label.to_lowercase().contains(&target.to_lowercase())
    })
    .collect();

  // Also find hosts that might be subdomains
  let subdomain_hosts: Vec<_> = graph
    .iter_nodes()
    .filter(|n| {
      matches!(n.node_type, GraphNodeType::Host)
        && n.label.to_lowercase().ends_with(&target.to_lowercase())
    })
    .collect();

  if format == "json" {
    let payload = domain_payload(&target, &domain_nodes, &subdomain_hosts);
    render::render_machine_output(ctx, "rb intel graph domain", &payload)?;
  } else {
    Output::header(&format!("Domain Intelligence: {}", target));
    println!();

    if domain_nodes.is_empty() && subdomain_hosts.is_empty() {
      println!("No domain records found for '{}'", target);
    } else {
      println!("Found {} domain records", domain_nodes.len());
      println!("Found {} related hosts/subdomains", subdomain_hosts.len());

      if !subdomain_hosts.is_empty() {
        println!("\nRelated hosts:");
        for host in subdomain_hosts.iter().take(20) {
          println!("  • {}", host.label);
        }
      }
    }
  }

  Ok(())
}

/// Certificate-centric intelligence command
pub fn cmd_intel_cert(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
  let target = ctx.target.clone().or_else(|| ctx.args.first().cloned());

  let show_expiring = ctx.flags.contains_key("expiring");

  // Get all certificate nodes
  let all_certs: Vec<_> = graph
    .iter_nodes()
    .filter(|n| matches!(n.node_type, GraphNodeType::Certificate))
    .collect();

  if target.is_none() && !show_expiring {
    if format == "json" {
      let payload = cert_overview_payload(graph, &all_certs);
      render::render_machine_output(ctx, "rb intel graph cert", &payload)?;
    } else {
      Output::header("Certificate Overview");
      println!();
      println!("Total certificates: {}", all_certs.len());
      println!();

      for cert in all_certs.iter().take(20) {
        let hosts: Vec<_> = graph
          .incoming_edges(&cert.id)
          .iter()
          .filter_map(|(_, source, _)| graph.get_node(source))
          .filter(|n| matches!(n.node_type, GraphNodeType::Host))
          .collect();
        println!("  📜 {} ({} hosts)", cert.label, hosts.len());
      }
    }
    return Ok(());
  }

  if show_expiring {
    // This would require date parsing from cert labels/properties
    // For now, just list all certs
    if format == "json" {
      let payload = json!({
        "entity": "certificate",
        "mode": "expiring",
        "status": "not_implemented",
        "message": "Expiring certificate detection requires certificate metadata"
      });
      render::render_machine_output(ctx, "rb intel graph cert", &payload)?;
    } else {
      Output::warning("Expiring certificate detection requires certificate metadata");
    }
    return Ok(());
  }

  let target = target.unwrap();
  Output::info(&format!("Analyzing certificate: {}", target));

  // Find certificate
  let cert_node = graph.iter_nodes().find(|n| {
    matches!(n.node_type, GraphNodeType::Certificate)
      && n.label.to_lowercase().contains(&target.to_lowercase())
  });

  let cert = match cert_node {
    Some(c) => c,
    None => {
      if format == "json" {
        let payload = json!({
          "entity": "certificate",
          "target": target,
          "status": "not_found"
        });
        render::render_machine_output(ctx, "rb intel graph cert", &payload)?;
      } else {
        Output::warning(&format!("Certificate '{}' not found", target));
      }
      return Ok(());
    }
  };

  // Find hosts using this certificate
  let hosts: Vec<_> = graph
    .incoming_edges(&cert.id)
    .iter()
    .filter(|(et, _, _)| matches!(et, GraphEdgeType::HasCert))
    .filter_map(|(_, source, _)| graph.get_node(source))
    .collect();

  if format == "json" {
    let payload = cert_payload(&cert, &hosts);
    render::render_machine_output(ctx, "rb intel graph cert", &payload)?;
  } else {
    Output::header(&format!("Certificate Intelligence: {}", cert.label));
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  CERTIFICATE: {:<46} │", truncate_str(&cert.label, 46));
    println!(
      "│  USED BY: {} hosts                                          │",
      hosts.len()
    );
    println!("└─────────────────────────────────────────────────────────────┘");

    if !hosts.is_empty() {
      println!("\nHosts using this certificate:");
      for host in hosts.iter().take(15) {
        println!("  🖥 {}", host.label);
      }
    }
  }

  Ok(())
}

fn node_ref_payload(node: &crate::storage::engine::StoredNode) -> Value {
  json!({
    "id": node.id.clone(),
    "label": node.label.clone(),
    "type": format!("{:?}", node.node_type)
  })
}

fn node_refs_payload(nodes: &[crate::storage::engine::StoredNode]) -> Vec<Value> {
  nodes.iter().map(|node| node_ref_payload(node)).collect()
}

fn not_found_payload(
  entity: &str,
  target: &str,
  available: &[crate::storage::engine::StoredNode],
) -> Value {
  json!({
    "entity": entity,
    "target": target,
    "status": "not_found",
    "available": node_refs_payload(available)
  })
}

fn host_payload(
  host: &crate::storage::engine::StoredNode,
  services: &[crate::storage::engine::StoredNode],
  vulns: &[crate::storage::engine::StoredNode],
  users: &[crate::storage::engine::StoredNode],
  techs: &[crate::storage::engine::StoredNode],
  connected_from: &[crate::storage::engine::StoredNode],
) -> Value {
  json!({
    "entity": "host",
    "host": node_ref_payload(host),
    "counts": json!({
      "services": services.len(),
      "vulnerabilities": vulns.len(),
      "users": users.len(),
      "technologies": techs.len(),
      "connected_from": connected_from.len()
    }),
    "services": node_refs_payload(services),
    "vulnerabilities": node_refs_payload(vulns),
    "users": node_refs_payload(users),
    "technologies": node_refs_payload(techs),
    "connected_from": node_refs_payload(connected_from)
  })
}

fn credential_payload(
  credential: &crate::storage::engine::StoredNode,
  reachable_hosts: &[crate::storage::engine::StoredNode],
  found_on: &[crate::storage::engine::StoredNode],
) -> Value {
  json!({
    "entity": "credential",
    "credential": node_ref_payload(credential),
    "reach": reachable_hosts.len(),
    "found_on_count": found_on.len(),
    "reachable_hosts": node_refs_payload(reachable_hosts),
    "found_on": node_refs_payload(found_on)
  })
}

fn user_payload(
  target: &str,
  user_nodes: &[crate::storage::engine::StoredNode],
  hosts_with_user: &std::collections::HashSet<String>,
) -> Value {
  let mut hosts: Vec<_> = hosts_with_user.iter().cloned().collect();
  hosts.sort();
  json!({
    "entity": "user",
    "target": target,
    "matches": node_refs_payload(user_nodes),
    "hosts_count": hosts.len(),
    "hosts": hosts
  })
}

fn service_payload(
  target: &str,
  service_nodes: &[crate::storage::engine::StoredNode],
  hosts: &[crate::storage::engine::StoredNode],
  vulns: &[crate::storage::engine::StoredNode],
) -> Value {
  json!({
    "entity": "service",
    "target": target,
    "instances": service_nodes.len(),
    "services": node_refs_payload(service_nodes),
    "hosts": node_refs_payload(hosts),
    "vulnerabilities": node_refs_payload(vulns)
  })
}

fn critical_vulns_payload(vuln_hosts: &[(&crate::storage::engine::StoredNode, usize)]) -> Value {
  let vulnerabilities: Vec<_> = vuln_hosts
    .iter()
    .take(20)
    .enumerate()
    .map(|(index, (vuln, affected))| {
      json!({
        "rank": index + 1,
        "vulnerability": node_ref_payload(vuln),
        "affected": *affected
      })
    })
    .collect();
  json!({
    "entity": "vulnerability",
    "mode": "critical",
    "count": vuln_hosts.len(),
    "vulnerabilities": vulnerabilities
  })
}

fn vuln_payload(
  vuln: &crate::storage::engine::StoredNode,
  affected: &[crate::storage::engine::StoredNode],
) -> Value {
  json!({
    "entity": "vulnerability",
    "vulnerability": node_ref_payload(vuln),
    "affected_count": affected.len(),
    "affected": node_refs_payload(affected)
  })
}

fn tech_payload(
  target: &str,
  tech_nodes: &[crate::storage::engine::StoredNode],
  hosts: &[crate::storage::engine::StoredNode],
) -> Value {
  json!({
    "entity": "technology",
    "target": target,
    "versions": tech_nodes.len(),
    "technology_nodes": node_refs_payload(tech_nodes),
    "hosts": node_refs_payload(hosts)
  })
}

fn network_payload(
  hosts: &[crate::storage::engine::StoredNode],
  components: &crate::storage::engine::ComponentsResult,
  gateways: &[(&crate::storage::engine::StoredNode, usize)],
) -> Value {
  let gateway_nodes: Vec<_> = gateways
    .iter()
    .map(|(node, count)| {
      json!({
        "node": node_ref_payload(node),
        "connections": *count
      })
    })
    .collect();
  let segments: Vec<_> = components
    .components
    .iter()
    .map(|component| {
      json!({
        "id": component.id.clone(),
        "size": component.size,
        "nodes": component.nodes.clone()
      })
    })
    .collect();
  json!({
    "entity": "network",
    "host_count": hosts.len(),
    "segments": components.count,
    "gateways": gateways.len(),
    "gateway_nodes": gateway_nodes,
    "components": segments
  })
}

fn domain_payload(
  target: &str,
  domain_nodes: &[crate::storage::engine::StoredNode],
  subdomain_hosts: &[crate::storage::engine::StoredNode],
) -> Value {
  json!({
    "entity": "domain",
    "target": target,
    "records": domain_nodes.len(),
    "subdomains": subdomain_hosts.len(),
    "domain_nodes": node_refs_payload(domain_nodes),
    "related_hosts": node_refs_payload(subdomain_hosts)
  })
}

fn cert_overview_payload(
  graph: &GraphStore,
  certs: &[crate::storage::engine::StoredNode],
) -> Value {
  let certificates: Vec<_> = certs
    .iter()
    .take(20)
    .map(|cert| {
      let hosts: Vec<_> = graph
        .incoming_edges(&cert.id)
        .iter()
        .filter_map(|(_, source, _)| graph.get_node(source))
        .filter(|n| matches!(n.node_type, GraphNodeType::Host))
        .collect();
      json!({
        "certificate": node_ref_payload(cert),
        "hosts": hosts.len(),
        "host_nodes": node_refs_payload(&hosts)
      })
    })
    .collect();
  json!({
    "entity": "certificate",
    "mode": "overview",
    "total": certs.len(),
    "certificates": certificates
  })
}

fn cert_payload(
  cert: &crate::storage::engine::StoredNode,
  hosts: &[crate::storage::engine::StoredNode],
) -> Value {
  json!({
    "entity": "certificate",
    "certificate": node_ref_payload(cert),
    "hosts": hosts.len(),
    "host_nodes": node_refs_payload(hosts)
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_user_payload_sorts_hosts() {
    let hosts =
      std::collections::HashSet::from(["b.example.com".to_string(), "a.example.com".to_string()]);
    let payload = user_payload("alice", &[], &hosts);
    assert_eq!(payload["hosts_count"], 2);
    assert_eq!(payload["hosts"][0], "a.example.com");
    assert_eq!(payload["hosts"][1], "b.example.com");
  }

  #[test]
  fn test_domain_payload_counts_related_assets() {
    let domain = crate::storage::engine::StoredNode {
      id: "domain:example.com".to_string(),
      label: "example.com".to_string(),
      node_type: GraphNodeType::Domain,
      properties: std::collections::HashMap::new(),
      created_at: 0,
      updated_at: 0,
    };
    let host = crate::storage::engine::StoredNode {
      id: "host:app.example.com".to_string(),
      label: "app.example.com".to_string(),
      node_type: GraphNodeType::Host,
      properties: std::collections::HashMap::new(),
      created_at: 0,
      updated_at: 0,
    };

    let payload = domain_payload("example.com", &[domain], &[host]);
    assert_eq!(payload["records"], 1);
    assert_eq!(payload["subdomains"], 1);
    assert_eq!(payload["related_hosts"][0]["label"], "app.example.com");
  }
}
