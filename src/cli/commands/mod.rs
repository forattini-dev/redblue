pub mod access; // ✅ Remote access - reverse shells & listeners
pub mod agent; // ✅ C2 Agent - server and client
pub mod assess; // ✅ Assessment workflow - fingerprint → vuln → playbook
pub mod attack; // ✅ Attack workflow - plan, run, playbooks
pub mod auth_test; // ✅ Credential testing
#[cfg(not(target_os = "windows"))]
pub mod bench;
pub mod binary; // ✅ Binary analysis - ELF/PE parsing, checksec, ROP gadgets
pub mod cloud;
pub mod code;
pub mod collection; // ✅ Browser credentials collection
pub mod config; // ✅ Configuration management - database passwords, settings
pub mod crypto; // ✅ File encryption vault - AES-256-GCM
pub mod database; // ✅ Database operations - engine, vector search
pub mod deps;
pub mod dns; // ✅ DNS with RESTful verbs (list, get, describe)
pub mod dns_server; // ✅ DNS server with hijacking for MITM
pub mod docs; // ✅ Documentation search and indexing
pub mod evasion; // ✅ AV/EDR evasion - sandbox detection, obfuscation, network jitter
pub mod exploit; // ⚠️ Exploitation framework - privesc, lateral, persist, replicate
pub mod exploit_browser; // ✅ RBB Browser Exploitation
pub mod exploit_phish; // ✅ Phishing toolkit - email delivery & credential harvesting
pub mod file; // ✅ File operations - compression, decompression, hash verification
pub mod fuzz;
pub mod git_exposed; // ✅ Exposed .git directory scanner
pub mod health; // ✅ Port health monitoring (check, diff, watch)
pub mod hex; // ✅ Hex editor - view, edit, search, replace, inspect binary files
pub mod http_server; // ✅ HTTP server for file serving and payload hosting
pub mod init; // ✅ Config init command
pub mod intel; // ✅ Intelligence domain - vuln, mitre, ioc, taxii
pub mod intel_graph; // ✅ Graph intelligence - pagerank, centrality, communities
pub mod intel_ioc; // ✅ IOC extraction and management - rb intel ioc
pub mod intel_mitre; // ✅ MITRE ATT&CK intelligence - rb intel mitre
pub mod intel_taxii;
pub mod loot; // ✅ Loot management - credentials, vulns, findings, attack graph
pub mod magic;
pub mod mcp;
#[cfg(target_os = "linux")]
pub mod memory; // ✅ Process memory inspection (Cheat Engine-style)
#[cfg(not(target_os = "windows"))]
pub mod mitm; // ✅ MITM attack orchestrator - DNS hijacking + TLS interception (requires TLS)
pub mod nc; // ⚠️ Netcat - AUTHORIZED USE ONLY
pub mod network;
pub mod nosqli; // ✅ NoSQL injection testing - MongoDB, Redis, Elasticsearch
pub mod password; // ✅ Password hash cracking - dictionary, mask, hybrid
pub mod ping; // ICMP ping
pub mod playbook; // ✅ Playbook management - pentest methodologies
pub mod proxy; // ✅ MITM TLS proxy - AUTHORIZED USE ONLY
pub mod recon;
pub mod recon_identity; // ✅ Identity OSINT - rb recon identity username/email/breach
pub mod report; // ✅ Report generation - pentest reports from loot and graph
pub mod scan;
pub mod screenshot;
pub mod sdk; // Internal SDK bridge metadata (hidden)
pub mod search; // ✅ Global search across all stored data
pub mod service; // ✅ Service manager - systemd, launchd, Windows Tasks
pub mod sqli; // ✅ SQL injection testing - sqlmap-style
pub mod system; // ✅ Local host inventory and environment inference
pub mod takeover;
pub mod tls; // TLS security testing - audit, ciphers, vuln
pub mod tls_intel; // ✅ TLS intelligence gathering
pub mod trace; // ✅ TAXII 2.1 client - rb intel taxii
               // pub mod vuln; // REMOVED - use intel vuln
pub mod web; // ✅ Re-enabled with TLS routes!
pub mod wordlist; // ✅ Wordlist management

use crate::cli::{output::Output, CliContext};
use crate::storage::service::StorageService;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

struct CommandRegistry {
  commands: Vec<Box<dyn Command>>,
  domain_index: HashMap<String, Vec<usize>>,
  resource_index: HashMap<String, HashMap<String, usize>>,
}

static COMMAND_REGISTRY: OnceLock<CommandRegistry> = OnceLock::new();

impl CommandRegistry {
  fn new() -> Self {
    let commands: Vec<Box<dyn Command>> = vec![
      Box::new(access::AccessCommand), // ✅ Remote access - rb access shell create
      Box::new(loot::LootEntryCommand), // ✅ Loot entry management
      Box::new(loot::LootGraphCommand), // ✅ Attack graph analysis
      Box::new(playbook::PlaybookCommand), // ✅ Playbook methodologies
      Box::new(report::ReportCommand), // ✅ Report generation
      Box::new(agent::AgentCommand),   // ✅ C2 Agent
      Box::new(assess::AssessCommand), // ✅ Assessment workflow
      Box::new(attack::AttackCommand), // ✅ Attack workflow - plan, run, playbooks
      Box::new(auth_test::AuthTestCommand), // ✅ Credential testing
      Box::new(scan::ScanCommand),
      Box::new(network::NetworkCommand), // ✅ Host ping & discovery
      Box::new(health::HealthCommand),   // ✅ Port health monitoring (check, diff, watch)
      // Box::new(ping::PingCommand),  // Temporarily disabled
      Box::new(trace::TraceCommand),
      Box::new(dns::DnsCommand), // ✅ DNS with RESTful verbs (list, get, describe)
      Box::new(web::WebCommand), // ✅ Re-enabled with TLS cert & audit!
      Box::new(sqli::SqliCommand), // ✅ SQL injection testing - sqlmap-style
      Box::new(nosqli::NoSqliCommand), // ✅ NoSQL injection testing
      Box::new(git_exposed::GitExposedCommand), // ✅ Exposed .git scanner
      Box::new(tls::TlsCommand), // TLS security testing
      Box::new(tls_intel::TlsIntelCommand), // ✅ TLS intelligence gathering
      Box::new(recon::ReconCommand),
      Box::new(recon_identity::ReconIdentityCommand), // ✅ rb recon identity username/email/breach
      Box::new(exploit::ExploitCommand), // ⚠️ Exploitation - privesc, lateral, persist, replicate
      Box::new(nc::NetcatCommand),       // ⚠️ Netcat - AUTHORIZED USE ONLY
      Box::new(code::CodeCommand),
      Box::new(collection::CollectCommand), // ✅ Browser collection
      Box::new(fuzz::FuzzCommand),          // ✅ Web fuzzing engine
      Box::new(file::FileCommand),          // ✅ File operations - zip/unzip/hash
      Box::new(crypto::CryptoHashCommand),  // ✅ Hash utilities - rb crypto hash verify
      Box::new(crypto::CryptoCommand),      // ✅ File encryption vault
      Box::new(crypto::CryptoCodecCommand), // ✅ Encoding/decoding (Base64, Hex, etc.)
      Box::new(crypto::CryptoCipherCommand), // ✅ Classical ciphers (Caesar, ROT13, etc.)
      Box::new(crypto::CryptoAnalyzeCommand), // ✅ Analysis (hash ID, frequency, auto-detect)
      Box::new(crypto::CryptoRecipeCommand), // ✅ CyberChef-style recipe chains
      Box::new(crypto::CryptoCyclicCommand), // ✅ De Bruijn patterns for exploit dev
      Box::new(password::PasswordCommand),  // ✅ Password hash cracking
      Box::new(binary::BinaryCommand),      // ✅ Binary analysis - ELF/PE parsing, checksec, ROP
      Box::new(hex::HexCommand),            // ✅ Hex editor - view, edit, search, replace
      Box::new(deps::DepsCommand),
      Box::new(cloud::CloudCommand),
      Box::new(takeover::TakeoverCommand),
      #[cfg(not(target_os = "windows"))]
      Box::new(bench::BenchCommand),
      Box::new(screenshot::ScreenshotCommand), // ✅ Screenshot capture
      Box::new(wordlist::WordlistCommand),     // ✅ Wordlist management
      Box::new(wordlist::WordlistFileCommand), // ✅ Wordlist file operations
      Box::new(mcp::McpCommand),               // ✅ Local MCP server bridge
      Box::new(docs::DocsCommand),             // ✅ Documentation search
      Box::new(intel::IntelCommand),           // ✅ Intelligence domain - rb intel vuln *
      Box::new(intel_graph::IntelGraphCommand), // ✅ Graph intelligence - rb intel graph *
      Box::new(intel_mitre::IntelMitreCommand), // ✅ MITRE ATT&CK intelligence - rb intel mitre *
      Box::new(intel_ioc::IntelIocCommand),    // ✅ IOC extraction - rb intel ioc *
      Box::new(intel_taxii::IntelTaxiiCommand), // ✅ TAXII 2.1 client - rb intel taxii *
      Box::new(proxy::HttpProxyCommand),       // ✅ HTTP CONNECT proxy
      Box::new(proxy::Socks5ProxyCommand),     // ✅ SOCKS5 proxy (RFC 1928)
      #[cfg(not(target_os = "windows"))]
      Box::new(proxy::TransparentProxyCommand), // ✅ Transparent proxy (iptables/nftables)
      Box::new(proxy::ProxyDataCommand),       // ✅ Query stored proxy history and traffic data
      Box::new(dns_server::DnsServerCommand),  // ✅ DNS server with hijacking for MITM
      #[cfg(not(target_os = "windows"))]
      Box::new(mitm::MitmCommand), // ✅ MITM attack orchestrator
      Box::new(exploit_browser::BrowserExploitCommand), // ✅ RBB Browser Exploitation
      Box::new(exploit_phish::PhishCommand),   // ✅ Phishing toolkit
      Box::new(http_server::HttpServerCommand), // ✅ HTTP server for file serving
      Box::new(service::ServiceCommand),       // ✅ Service manager - persistence
      Box::new(system::SystemCommand),         // ✅ Local host inventory
      Box::new(evasion::EvasionSandboxCommand), // ✅ Sandbox/VM detection
      Box::new(evasion::EvasionObfuscateCommand), // ✅ String obfuscation
      Box::new(evasion::EvasionNetworkCommand), // ✅ Network evasion (jitter)
      Box::new(evasion::EvasionConfigCommand), // ✅ Evasion config presets
      Box::new(evasion::EvasionBuildCommand),  // ✅ Build-time binary mutation
      Box::new(evasion::EvasionAntidebugCommand), // ✅ Anti-debugging detection
      Box::new(evasion::EvasionMemoryCommand), // ✅ Memory encryption
      Box::new(evasion::EvasionApihashCommand), // ✅ API hashing
      Box::new(evasion::EvasionControlflowCommand), // ✅ Control flow obfuscation
      Box::new(evasion::EvasionInjectCommand), // ✅ Process injection & shellcode
      Box::new(evasion::EvasionAmsiCommand),   // ✅ AMSI bypass (Windows)
      Box::new(evasion::EvasionStringsCommand), // ✅ String encryption
      Box::new(evasion::EvasionTracksCommand), // ✅ Track covering (history clearing)
      Box::new(init::InitCommand),             // ✅ Config init
      Box::new(config::ConfigDatabaseCommand), // ✅ Database password management
      Box::new(search::SearchCommand),         // ✅ Global search across all stored data
      Box::new(sdk::SdkBridgeCommand),         // Internal SDK bridge metadata
      #[cfg(target_os = "linux")]
      Box::new(memory::MemoryCommand), // ✅ Process memory inspection
                                               // Box::new(monitor::MonitorCommand),  // Temporarily disabled
    ];

    let mut commands = commands;
    commands.extend(database::commands()); // ✅ Database - engine, vector search

    let mut domain_index: HashMap<String, Vec<usize>> = HashMap::new();
    let mut resource_index: HashMap<String, HashMap<String, usize>> = HashMap::new();

    for (idx, command) in commands.iter().enumerate() {
      domain_index
        .entry(command.domain().to_string())
        .or_default()
        .push(idx);

      resource_index
        .entry(command.domain().to_string())
        .or_default()
        .insert(command.resource().to_string(), idx);
    }

    Self {
      commands,
      domain_index,
      resource_index,
    }
  }

  fn commands(&self) -> &[Box<dyn Command>] {
    &self.commands
  }

  fn domain_indices(&self, domain: &str) -> Option<&Vec<usize>> {
    self.domain_index.get(domain)
  }

  fn command(&self, index: usize) -> &dyn Command {
    self.commands[index].as_ref()
  }

  fn find(&self, domain: &str, resource: &str) -> Option<&dyn Command> {
    self
      .resource_index
      .get(domain)
      .and_then(|resources| resources.get(resource))
      .map(|&idx| self.command(idx))
  }
}

fn command_registry() -> &'static CommandRegistry {
  COMMAND_REGISTRY.get_or_init(CommandRegistry::new)
}

pub fn all_commands() -> &'static [Box<dyn Command>] {
  command_registry().commands()
}

pub fn command_for(domain: &str, resource: &str) -> Option<&'static dyn Command> {
  command_registry().find(domain, resource)
}

pub fn resources_for_domain(domain: &str) -> Vec<String> {
  let registry = command_registry();
  registry
    .domain_indices(domain)
    .map(|indices| {
      indices
        .iter()
        .filter_map(|&idx| {
          let command = registry.command(idx);
          if command.hidden() {
            None
          } else {
            Some(command.resource().to_string())
          }
        })
        .collect()
    })
    .unwrap_or_default()
}

pub fn build_partition_attributes<I, K, V>(
  ctx: &CliContext,
  target: &str,
  extra: I,
) -> Vec<(String, String)>
where
  I: IntoIterator<Item = (K, V)>,
  K: Into<String>,
  V: Into<String>,
{
  let mut attributes = Vec::with_capacity(6);

  if let Some(domain) = ctx.domain.as_deref() {
    attributes.push(("domain".to_string(), domain.to_string()));
  }

  if let Some(resource) = ctx.resource.as_deref() {
    attributes.push(("resource".to_string(), resource.to_string()));
  }

  if let Some(verb) = ctx.verb.as_deref() {
    attributes.push(("verb".to_string(), verb.to_string()));
  }

  attributes.push(("target".to_string(), target.to_string()));

  let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_else(|_| std::time::Duration::from_secs(0))
    .as_secs();
  attributes.push(("run_ts".to_string(), timestamp.to_string()));

  for (key, value) in extra.into_iter() {
    attributes.push((key.into(), value.into()));
  }

  attributes
}

pub fn annotate_query_partition<I, K, V>(ctx: &CliContext, path: &Path, extra: I)
where
  I: IntoIterator<Item = (K, V)>,
  K: Into<String>,
  V: Into<String>,
{
  let mut attributes = Vec::with_capacity(6);

  if let Some(domain) = ctx.domain.as_deref() {
    attributes.push(("query_domain".to_string(), domain.to_string()));
  }

  if let Some(resource) = ctx.resource.as_deref() {
    attributes.push(("query_resource".to_string(), resource.to_string()));
  }

  if let Some(verb) = ctx.verb.as_deref() {
    attributes.push(("query_verb".to_string(), verb.to_string()));
  }

  if let Some(target) = ctx.target.as_deref() {
    attributes.push(("query_target".to_string(), target.to_string()));
  }

  if !ctx.raw.is_empty() {
    attributes.push(("query_command".to_string(), ctx.raw.join(" ")));
  }

  for (key, value) in extra.into_iter() {
    attributes.push((key.into(), value.into()));
  }

  let service = StorageService::global();
  let key = StorageService::key_for_path(path);
  service.annotate_partition(&key, attributes);
}

pub trait Command: Send + Sync {
  fn domain(&self) -> &str;
  fn resource(&self) -> &str;
  fn description(&self) -> &str;
  fn routes(&self) -> Vec<Route>;
  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
  }
  fn hidden(&self) -> bool {
    false
  }
  fn route_metadata(&self, _verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(_verb))
      .with_machine_output(self.metadata().machine_output)
  }
  fn flags(&self) -> Vec<Flag> {
    vec![]
  }
  fn examples(&self) -> Vec<(&str, &str)>;
  fn execute(&self, ctx: &CliContext) -> Result<(), String>;
}

#[derive(Clone)]
pub struct Flag {
  pub short: Option<char>,
  pub long: String,
  pub description: String,
  pub default: Option<String>,
  pub arg: Option<String>,
}

impl Flag {
  pub fn new(long: &str, desc: &str) -> Self {
    Self {
      short: None,
      long: long.to_string(),
      description: desc.to_string(),
      default: None,
      arg: None,
    }
  }

  pub fn with_short(mut self, short: char) -> Self {
    self.short = Some(short);
    self
  }

  pub fn with_default(mut self, default: &str) -> Self {
    self.default = Some(default.to_string());
    self
  }

  pub fn with_arg(mut self, arg: &str) -> Self {
    self.arg = Some(arg.to_string());
    self
  }
}

#[derive(Clone)]
pub struct Route {
  pub verb: &'static str,
  pub summary: &'static str,
  pub usage: &'static str,
}

pub fn print_domain_overview(domain: &str) -> Result<(), String> {
  let Some(domain_node) = crate::cli::schema::find_domain_node(domain, false) else {
    let suggestions = crate::cli::schema::suggest_domains(domain, 3, false);
    let suggestion_text = if suggestions.is_empty() {
      String::new()
    } else {
      format!(
        "\n\nDid you mean one of these canonical domains?\n  {}",
        suggestions.join("\n  ")
      )
    };
    return Err(format!("Unknown domain '{}'.{}", domain, suggestion_text));
  };

  Output::header(&format!("Domain: {}", domain_node.name));
  println!("\nCanonical grammar:");
  println!("  {}", crate::cli::schema::CANONICAL_GRAMMAR);
  if !domain_node.aliases.is_empty() {
    println!("\nAliases:");
    println!("  {}", domain_node.aliases.join(", "));
  }

  println!("\nResources:");
  for resource in domain_node.resources {
    println!("  • {:<18} {}", resource.name, resource.description);
    if !resource.aliases.is_empty() {
      println!("    aliases: {}", resource.aliases.join(", "));
    }
    let verbs = resource
      .verbs
      .iter()
      .map(|verb| verb.name.as_str())
      .collect::<Vec<_>>();
    if !verbs.is_empty() {
      println!("    verbs: {}", verbs.join(", "));
    }
  }

  println!("\nUse: rb {} <resource> help", domain_node.name);
  println!("     rb {} <resource> --help", domain_node.name);
  Ok(())
}

fn canonical_resource_suggestion_text(domain: &str, resource: &str) -> String {
  let suggestions = crate::cli::schema::suggest_resources(domain, resource, 3);
  if suggestions.is_empty() {
    String::new()
  } else {
    format!(
      "\n\nDid you mean one of these canonical resources?\n  {}",
      suggestions.join("\n  ")
    )
  }
}

fn canonical_route_suggestion_text(domain: &str, resource: &str, verb: &str) -> String {
  let suggestions = crate::cli::schema::suggest_route_commands(domain, resource, verb, 3);
  if suggestions.is_empty() {
    String::new()
  } else {
    format!(
      "\n\nDid you mean one of these canonical routes?\n  {}",
      suggestions.join("\n  ")
    )
  }
}

fn canonical_command_for(domain: &str, resource: &str, verb: &str) -> String {
  format!("rb {} {} {}", domain, resource, verb)
}

fn translate_compat_route(
  domain: &str,
  resource: Option<String>,
  verb: Option<String>,
) -> (Option<String>, Option<String>, Option<String>) {
  let (Some(resource_token), Some(verb_token)) = (resource.clone(), verb.clone()) else {
    return (resource, verb, None);
  };

  if crate::cli::schema::route_exists(domain, &resource_token, &verb_token) {
    return (resource, verb, None);
  }

  // Legacy translation stays intentionally narrow:
  // only swap when the first token is not already a known canonical resource.
  if crate::cli::schema::resource_exists(domain, &resource_token) {
    return (resource, verb, None);
  }

  if crate::cli::schema::route_exists(domain, &verb_token, &resource_token) {
    let canonical = canonical_command_for(domain, &verb_token, &resource_token);
    return (Some(verb_token), Some(resource_token), Some(canonical));
  }

  (resource, verb, None)
}

pub fn dispatch(ctx: &CliContext) -> Result<(), String> {
  let domain = ctx
    .domain
    .as_deref()
    .ok_or_else(|| "Missing domain. Syntax: rb <domain> <resource> <verb> [target]".to_string())?;

  // Compact command aliases — defined in aliases.rs (single source of truth)
  // rb ebr → rb evasion build rehash
  if ctx.resource.is_none() {
    if let Some((d, r, v)) = crate::cli::aliases::resolve_compact_alias(domain) {
      let mut alias_ctx = ctx.clone();
      alias_ctx.domain = Some(d.to_string());
      alias_ctx.resource = Some(r.to_string());
      alias_ctx.verb = Some(v.to_string());
      return dispatch(&alias_ctx);
    }
  }

  // Magic scan detection: if domain looks like a URL/domain, trigger magic scan
  // Do this BEFORE alias resolution to avoid false positives
  if is_magic_scan_target(domain) && ctx.resource.is_none() {
    return magic::execute(ctx);
  }

  // Resolve aliases to canonical names
  let (resolved_domain, resolved_resource, resolved_verb) =
    crate::cli::schema::resolve_command_tokens(
      domain,
      ctx.resource.as_deref(),
      ctx.verb.as_deref(),
    );

  let (resolved_resource, resolved_verb, compat_canonical) =
    translate_compat_route(&resolved_domain, resolved_resource, resolved_verb);

  // Create new context with resolved names
  let mut resolved_ctx = ctx.clone();
  resolved_ctx.domain = Some(resolved_domain.clone());
  resolved_ctx.resource = resolved_resource.clone();
  resolved_ctx.verb = resolved_verb.clone();
  if let Some(canonical) = compat_canonical.as_deref() {
    if !resolved_ctx.wants_machine_output() {
      Output::warning(&format!(
        "Compatibility command order detected. Canonical form: {}",
        canonical
      ));
    }
  }

  // Use resolved names for the rest of dispatch
  let domain = resolved_domain.as_str();
  let registry = command_registry();

  // Netcat special case: standalone command like `rb nc listen 4444`
  // Only trigger if we have a resource (which will contain the verb)
  if domain == "nc" && resolved_ctx.resource.is_some() {
    if let Some(command) = registry.commands().iter().find(|cmd| cmd.domain() == "nc") {
      return command.execute(&resolved_ctx);
    }
  }

  if resolved_ctx.resource.as_deref() == Some("help") {
    if let Some(target_resource) = resolved_ctx.verb.as_deref() {
      if let Some(command) = registry.find(domain, target_resource) {
        print_help(command);
        return Ok(());
      }

      return Err(format!(
        "Unknown resource '{}' in domain '{}'.{}",
        target_resource,
        domain,
        canonical_resource_suggestion_text(domain, target_resource)
      ));
    }

    print_domain_overview(domain)?;
    return Ok(());
  }

  let resource = resolved_ctx.resource.as_deref().ok_or_else(|| {
    let summaries = crate::cli::schema::domain_resource_summaries(domain);

    let resources_list = if !summaries.is_empty() {
      let lines = summaries
        .iter()
        .map(|summary| format!("  • {:<18} {}", summary.resource, summary.description))
        .collect::<Vec<_>>()
        .join("\n");
      format!("\n\nAvailable resources for '{}':\n{}", domain, lines)
    } else {
      String::new()
    };

    format!(
      "Missing resource for domain '{}'.\n\nCanonical grammar:\n  {}\n\nSyntax: rb {} <resource> <verb> [target]{}",
      domain,
      crate::cli::schema::CANONICAL_GRAMMAR,
      domain,
      resources_list
    )
  })?;

  if resolved_ctx.verb.as_deref() == Some("help") {
    if let Some(command) = registry.find(domain, resource) {
      print_help(command);
      return Ok(());
    }

    return Err(format!(
      "Unknown resource '{}' in domain '{}'.{}",
      resource,
      domain,
      canonical_resource_suggestion_text(domain, resource)
    ));
  }

  let Some(command) = registry.find(domain, resource) else {
    let route_suggestion_text = resolved_ctx
      .verb
      .as_deref()
      .map(|verb| canonical_route_suggestion_text(domain, resource, verb))
      .unwrap_or_default();

    return Err(format!(
      "Unknown resource '{}' in domain '{}'.{}{}",
      resource,
      domain,
      canonical_resource_suggestion_text(domain, resource),
      route_suggestion_text
    ));
  };

  let verb = resolved_ctx.verb.as_deref().ok_or_else(|| {
    // Get available verbs for this resource
    let verbs: Vec<String> = command
      .routes()
      .iter()
      .map(|route| route.verb.to_string())
      .collect();

    let verbs_list = if !verbs.is_empty() {
      format!(
        "\n\nAvailable verbs for '{} {}':\n  {}",
        domain,
        resource,
        verbs.join(", ")
      )
    } else {
      String::new()
    };

    format!(
      "Missing verb for {} {}.\n\nCanonical syntax:\n  rb {} {} <verb> [target]\n{}",
      domain, resource, domain, resource, verbs_list
    )
  })?;

  if !command.routes().iter().any(|route| route.verb == verb) {
    let verbs = command
      .routes()
      .iter()
      .map(|route| route.verb.to_string())
      .collect::<Vec<_>>();
    let verbs_list = if verbs.is_empty() {
      String::new()
    } else {
      format!(
        "\n\nAvailable verbs for '{} {}':\n  {}",
        domain,
        resource,
        verbs.join(", ")
      )
    };

    return Err(format!(
      "Unknown verb '{}' for '{} {}'.{}{}\n\nUse `rb {} {} help` to inspect available verbs.",
      verb,
      domain,
      resource,
      canonical_route_suggestion_text(domain, resource, verb),
      verbs_list,
      domain,
      resource
    ));
  }

  command.execute(&resolved_ctx)
}

pub fn print_help(cmd: &dyn Command) {
  let metadata = cmd.metadata();

  Output::header(&format!(
    "{} {} - {}",
    cmd.domain(),
    cmd.resource(),
    cmd.description()
  ));

  println!("\n\x1b[1mUSAGE:\x1b[0m");
  println!("  {}", crate::cli::schema::CANONICAL_GRAMMAR);
  println!(
    "  rb {} {} <verb> [target] [FLAGS]",
    cmd.domain(),
    cmd.resource()
  );

  println!("\n\x1b[1mCOMMAND CONTRACT:\x1b[0m");
  println!("  canonical-order      {}", metadata.canonical_order);
  println!(
    "  machine-output       {}",
    crate::cli::schema::machine_output_summary(metadata.machine_output)
  );
  let domain_aliases = crate::cli::aliases::domain_aliases_for(cmd.domain());
  if !domain_aliases.is_empty() {
    println!("  domain-aliases       {}", domain_aliases.join(", "));
  }
  let resource_aliases = crate::cli::aliases::resource_aliases_for(cmd.resource());
  if !resource_aliases.is_empty() {
    println!("  resource-aliases     {}", resource_aliases.join(", "));
  }
  if !metadata.aliases.is_empty() {
    println!("  aliases              {}", metadata.aliases.join(", "));
  }

  let routes = cmd.routes();
  if !routes.is_empty() {
    println!("\n\x1b[1mVERBS:\x1b[0m");
    for route in &routes {
      let route_metadata = cmd.route_metadata(route.verb);
      println!("  {:<12} {}", route.verb, route.summary);
      println!(
        "               {}",
        crate::cli::schema::machine_output_summary(route_metadata.machine_output)
      );
      if !route_metadata.aliases.is_empty() {
        println!(
          "               aliases: {}",
          route_metadata.aliases.join(", ")
        );
      }
    }

    println!("\n\x1b[1mROUTE EXAMPLES:\x1b[0m");
    for route in &routes {
      println!("  {}", route.usage);
    }
  }

  let flags = cmd.flags();
  if !flags.is_empty() {
    println!("\n\x1b[1mFLAGS:\x1b[0m");
    for flag in flags {
      let short = flag.short.map(|c| format!("-{}, ", c)).unwrap_or_default();
      let default = flag
        .default
        .as_ref()
        .map(|d| format!(" (default: {})", d))
        .unwrap_or_default();
      println!(
        "  {}--{:<20} {}{}",
        short, flag.long, flag.description, default
      );
    }
  }

  let examples = cmd.examples();
  if !examples.is_empty() {
    println!("\n\x1b[1mEXAMPLES:\x1b[0m");
    for (desc, example) in examples {
      println!("  \x1b[2m# {}\x1b[0m", desc);
      println!("  \x1b[36m{}\x1b[0m\n", example);
    }
  }
}

/// Check if the input looks like a target for magic scan (URL, domain, or IP)
fn is_magic_scan_target(input: &str) -> bool {
  // Check for URL schemes
  if input.starts_with("http://") || input.starts_with("https://") {
    return true;
  }

  // Check for domain patterns (contains dots and no spaces)
  if input.contains('.') && !input.contains(' ') {
    // Simple check: if it's not a known CLI domain
    let known_domains = [
      "access",
      "agent",    // C2 Agent
      "assess",   // Assessment workflow
      "attack",   // ✅ Attack workflow - plan, run, playbooks (includes lab)
      "binary",   // ✅ Binary analysis - ELF/PE parsing, checksec, ROP gadgets
      "loot",     // ✅ Loot management - credentials, vulns, attack graph
      "playbook", // ✅ Playbook methodologies
      "report",   // ✅ Report generation
      "network",
      "dns",
      "web",
      "tls",
      "recon",
      "intelligence", // ✅ Intelligence domain - vuln, mitre, ioc, taxii (alias: intel)
      "exploit",
      "nc",   // netcat standalone command
      "file", // ✅ File operations - zip/unzip/hash
      "code",
      "cloud",
      "collection",
      "bench",
      "service", // service manager
      "evasion", // AV/EDR evasion
      "ebr",     // compact alias: evasion build rehash
      "config",  // configuration management
      "search",  // global search across databases
      "help",
      "version",
      "shell",
    ];
    if known_domains.contains(&input) {
      return false;
    }
    return true;
  }

  // Check for IP address patterns
  let parts: Vec<&str> = input.split('.').collect();
  if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
    return true;
  }

  false
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::CliContext;

  #[test]
  fn dispatch_unknown_verb_suggests_canonical_route() {
    let ctx = CliContext {
      domain: Some("tls".to_string()),
      resource: Some("security".to_string()),
      verb: Some("audti".to_string()),
      ..CliContext::default()
    };

    let error = dispatch(&ctx).expect_err("dispatch should fail for unknown verb");
    assert!(error.contains("Unknown verb 'audti'"));
    assert!(error.contains("rb tls security audit"));
  }

  #[test]
  fn dispatch_unknown_resource_can_suggest_canonical_route() {
    let ctx = CliContext {
      domain: Some("tls".to_string()),
      resource: Some("securit".to_string()),
      verb: Some("audit".to_string()),
      ..CliContext::default()
    };

    let error = dispatch(&ctx).expect_err("dispatch should fail for unknown resource");
    assert!(error.contains("Unknown resource 'securit'"));
    assert!(error.contains("rb tls security audit"));
  }

  #[test]
  fn translate_compat_route_swaps_legacy_order_when_canonical_exists() {
    let (resource, verb, canonical) = translate_compat_route(
      "network",
      Some("scan".to_string()),
      Some("ports".to_string()),
    );

    assert_eq!(resource.as_deref(), Some("ports"));
    assert_eq!(verb.as_deref(), Some("scan"));
    assert_eq!(canonical.as_deref(), Some("rb network ports scan"));
  }

  #[test]
  fn translate_compat_route_keeps_canonical_order_intact() {
    let (resource, verb, canonical) = translate_compat_route(
      "tls",
      Some("security".to_string()),
      Some("audit".to_string()),
    );

    assert_eq!(resource.as_deref(), Some("security"));
    assert_eq!(verb.as_deref(), Some("audit"));
    assert!(canonical.is_none());
  }

  #[test]
  fn translate_compat_route_does_not_swap_when_resource_is_already_canonical() {
    let (resource, verb, canonical) =
      translate_compat_route("web", Some("fuzz".to_string()), Some("asset".to_string()));

    assert_eq!(resource.as_deref(), Some("fuzz"));
    assert_eq!(verb.as_deref(), Some("asset"));
    assert!(canonical.is_none());
  }
}

pub fn print_global_help() {
  let title = "\x1b[1m\x1b[36m";
  let bold = "\x1b[1m";
  let dim = "\x1b[2m";
  let reset = "\x1b[0m";
  let domain_lines = crate::cli::schema::domain_tree(false)
    .into_iter()
    .map(|domain| {
      let aliases = if domain.aliases.is_empty() {
        String::new()
      } else {
        format!(" {dim}[aliases: {}]{reset}", domain.aliases.join(", "))
      };
      format!(
        "  {:<10} {}{}",
        domain.name,
        crate::cli::schema::domain_summary(&domain.name),
        aliases
      )
    })
    .collect::<Vec<_>>()
    .join("\n");

  println!(
        "
{title}RedBlue CLI{reset} - Modern security testing interface

{bold}USAGE:{reset}
  rb <domain> <resource> <verb> [target] [FLAGS]

{bold}DOMAINS:{reset}
{domain_lines}

{bold}EXAMPLES:{reset}
  {dim}# Initialize config file{reset}
  rb config init create

  {dim}# Scan common ports{reset}
  rb network ports scan 192.168.1.1 --preset common

  {dim}# DNS lookup{reset}
  rb dns record lookup google.com --type MX

  {dim}# Web security audit{reset}
  rb web asset security http://intranet.local

  {dim}# WHOIS{reset}
  rb recon domain whois example.com

  {dim}# Vulnerability intelligence{reset}
  rb intel vuln search nginx 1.18.0
  rb intel vuln cve CVE-2021-44228

  {dim}# MITRE ATT&CK mapping{reset}
  rb intel mitre map ports=22,80,443 tech=wordpress
  rb intel mitre export output=layer.json ports=22,80,443

{dim}NOTE:{reset} HTTPS endpoints are supported via TLS tooling (`rb web asset cert|tls-audit`). HTTP routes expect explicit `http://` targets.

{bold}MAGIC SCAN:{reset}
  rb <url>                 Run intelligent multi-phase scan (magic mode)
  rb <domain>              Auto-detect and scan target
  rb <ip>                  Scan IP address with smart presets

{bold}SHELL (Interactive Mode):{reset}
  rb shell <target>        Enter fullscreen TUI for exploring scans
  rb shell <file>{session_ext}     Open existing session file

{bold}GLOBAL COMMANDS:{reset}
  rb help                  Show global overview
  rb commands              List all available commands
  rb <domain> help         List resources inside a domain
  rb help <d> <r> <v>      Show contextual route help
  rb version               Show version information

{bold}GLOBAL OUTPUT:{reset}
  rb ... --json            Force JSON output globally
  rb ... -j                Short alias for --json
  rb ... --output json     Explicit output format selection
  rb ... --format yaml     Alias for --output

{bold}EVASION:{reset}
  rb ... --stealth, -S     Full evasion: heap jitter + rehash after execution
  rb ebr                   Manual binary rehash

For detailed documentation: Check docs/cli-semantics.md and QUICKSTART.md
",
        title = title,
        bold = bold,
        dim = dim,
        domain_lines = domain_lines,
        session_ext = crate::storage::session::SessionFile::EXTENSION,
        reset = reset
    );
}

pub fn print_all_commands() {
  let bold = "\x1b[1m";
  let dim = "\x1b[2m";
  let cyan = "\x1b[36m";
  let yellow = "\x1b[33m";
  let reset = "\x1b[0m";

  println!("{bold}{cyan}redblue CLI - All Commands{reset}\n");
  println!("Usage: {}\n", crate::cli::schema::CANONICAL_GRAMMAR);

  let domains = crate::cli::schema::domain_tree(false);
  let total_commands = crate::cli::schema::total_route_count(false);

  for domain in &domains {
    let alias_text = if domain.aliases.is_empty() {
      String::new()
    } else {
      format!(" {dim}[aliases: {}]{reset}", domain.aliases.join(", "))
    };
    println!(
      "{bold}{yellow}{}{reset} {dim}# {}{}{reset}",
      domain.name,
      crate::cli::schema::domain_summary(&domain.name),
      alias_text
    );

    for resource in &domain.resources {
      let resource_aliases = if resource.aliases.is_empty() {
        String::new()
      } else {
        format!(" {dim}[aliases: {}]{reset}", resource.aliases.join(", "))
      };
      println!(
        "  {dim}└─{reset} {} {dim}{}{}{reset}",
        resource.name, resource.description, resource_aliases
      );
      for verb in &resource.verbs {
        let verb_aliases = if verb.aliases.is_empty() {
          String::new()
        } else {
          format!(" {dim}[aliases: {}]{reset}", verb.aliases.join(", "))
        };
        println!(
          "      {dim}•{reset} {:<16} {dim}{}{} {reset}",
          verb.name, verb.summary, verb_aliases
        );
      }
    }
    println!();
  }

  println!("{dim}────────────────────────────────────────{reset}");
  println!(
    "{bold}Total:{reset} ~{} commands across {} domains",
    total_commands,
    domains.len()
  );
  println!("\n{dim}Quick access:{reset}");
  println!("  rb help                  Global help");
  println!("  rb <domain> help         Domain help");
  println!("  rb commands              This list");
  println!("  rb shell <target>        Interactive TUI");
}
