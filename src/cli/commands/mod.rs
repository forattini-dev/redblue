pub mod access; // ✅ Remote access - reverse shells & listeners
pub mod agent; // ✅ C2 Agent - server and client
pub mod assess; // ✅ Assessment workflow - fingerprint → vuln → playbook
pub mod attack; // ✅ Attack workflow - plan, run, playbooks
pub mod auth_test; // ✅ Credential testing
pub mod bench;
pub mod cloud;
pub mod code;
pub mod collection; // ✅ Browser credentials collection
pub mod config; // ✅ Configuration management - database passwords, settings
pub mod crypto; // ✅ File encryption vault - AES-256-GCM
pub mod evasion; // ✅ AV/EDR evasion - sandbox detection, obfuscation, network jitter
pub mod search; // ✅ Global search across all stored data
pub mod service; // ✅ Service manager - systemd, launchd, Windows Tasks
                 // pub mod database; // Database operations - TODO: APIs changed, needs update
pub mod deps;
pub mod dns; // ✅ DNS with RESTful verbs (list, get, describe)
pub mod dns_server; // ✅ DNS server with hijacking for MITM
pub mod docs; // ✅ Documentation search and indexing
pub mod exploit; // ⚠️ Exploitation framework - privesc, lateral, persist, replicate
pub mod fuzz;
pub mod health; // ✅ Port health monitoring (check, diff, watch)
pub mod http_server; // ✅ HTTP server for file serving and payload hosting
pub mod init; // ✅ Config init command
pub mod magic;
pub mod mcp;
#[cfg(not(target_os = "windows"))]
pub mod mitm; // ✅ MITM attack orchestrator - DNS hijacking + TLS interception (requires TLS)
              // pub mod monitor; // Network monitoring - TODO: monitor.rs doesn't exist
pub mod exploit_browser; // ✅ RBB Browser Exploitation
pub mod intel; // ✅ Intelligence domain - vuln, mitre, ioc, taxii
pub mod intel_ioc; // ✅ IOC extraction and management - rb intel ioc
pub mod intel_mitre; // ✅ MITRE ATT&CK intelligence - rb intel mitre
pub mod intel_taxii;
pub mod nc; // ⚠️ Netcat - AUTHORIZED USE ONLY
pub mod network;
pub mod ping; // ICMP ping
pub mod proxy; // ✅ MITM TLS proxy - AUTHORIZED USE ONLY
pub mod recon;
pub mod recon_identity; // ✅ Identity OSINT - rb recon identity username/email/breach
pub mod recon_username; // ✅ Username OSINT - rb recon username <username> (legacy alias)
pub mod scan;
pub mod screenshot;
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
            Box::new(tls::TlsCommand), // TLS security testing
            Box::new(tls_intel::TlsIntelCommand), // ✅ TLS intelligence gathering
            Box::new(recon::ReconCommand),
            Box::new(recon_username::ReconUsernameCommand), // ✅ rb recon username <username> (legacy)
            Box::new(recon_identity::ReconIdentityCommand), // ✅ rb recon identity username/email/breach
            Box::new(exploit::ExploitCommand), // ⚠️ Exploitation - privesc, lateral, persist, replicate
            Box::new(nc::NetcatCommand),       // ⚠️ Netcat - AUTHORIZED USE ONLY
            Box::new(code::CodeCommand),
            Box::new(collection::CollectCommand), // ✅ Browser collection
            Box::new(fuzz::FuzzCommand),          // ✅ Web fuzzing engine
            Box::new(crypto::CryptoCommand),      // ✅ File encryption vault
            Box::new(deps::DepsCommand),
            Box::new(cloud::CloudCommand),
            Box::new(takeover::TakeoverCommand),
            Box::new(bench::BenchCommand),
            Box::new(screenshot::ScreenshotCommand), // ✅ Screenshot capture
            Box::new(wordlist::WordlistCommand),     // ✅ Wordlist management
            Box::new(wordlist::WordlistFileCommand), // ✅ Wordlist file operations
            Box::new(mcp::McpCommand),               // ✅ Local MCP server bridge
            Box::new(docs::DocsCommand),             // ✅ Documentation search
            Box::new(intel::IntelCommand),           // ✅ Intelligence domain - rb intel vuln *
            Box::new(intel_mitre::IntelMitreCommand), // ✅ MITRE ATT&CK intelligence - rb intel mitre *
            Box::new(intel_ioc::IntelIocCommand),     // ✅ IOC extraction - rb intel ioc *
            Box::new(intel_taxii::IntelTaxiiCommand), // ✅ TAXII 2.1 client - rb intel taxii *
            Box::new(proxy::HttpProxyCommand),        // ✅ HTTP CONNECT proxy
            Box::new(proxy::Socks5ProxyCommand),      // ✅ SOCKS5 proxy (RFC 1928)
            #[cfg(not(target_os = "windows"))]
            Box::new(proxy::TransparentProxyCommand), // ✅ Transparent proxy (iptables/nftables)
            Box::new(proxy::ProxyDataCommand), // ✅ Query stored proxy history and traffic data
            Box::new(dns_server::DnsServerCommand), // ✅ DNS server with hijacking for MITM
            #[cfg(not(target_os = "windows"))]
            Box::new(mitm::MitmCommand), // ✅ MITM attack orchestrator
            Box::new(exploit_browser::BrowserExploitCommand), // ✅ RBB Browser Exploitation
            Box::new(http_server::HttpServerCommand), // ✅ HTTP server for file serving
            Box::new(service::ServiceCommand), // ✅ Service manager - persistence
            Box::new(evasion::EvasionSandboxCommand), // ✅ Sandbox/VM detection
            Box::new(evasion::EvasionObfuscateCommand), // ✅ String obfuscation
            Box::new(evasion::EvasionNetworkCommand), // ✅ Network evasion (jitter)
            Box::new(evasion::EvasionConfigCommand), // ✅ Evasion config presets
            Box::new(evasion::EvasionBuildCommand), // ✅ Build-time binary mutation
            Box::new(evasion::EvasionAntidebugCommand), // ✅ Anti-debugging detection
            Box::new(evasion::EvasionMemoryCommand), // ✅ Memory encryption
            Box::new(evasion::EvasionApihashCommand), // ✅ API hashing
            Box::new(evasion::EvasionControlflowCommand), // ✅ Control flow obfuscation
            Box::new(evasion::EvasionInjectCommand), // ✅ Process injection & shellcode
            Box::new(evasion::EvasionAmsiCommand), // ✅ AMSI bypass (Windows)
            Box::new(evasion::EvasionStringsCommand), // ✅ String encryption
            Box::new(evasion::EvasionTracksCommand), // ✅ Track covering (history clearing)
            Box::new(init::InitCommand),       // ✅ Config init
            Box::new(config::ConfigDatabaseCommand), // ✅ Database password management
            Box::new(search::SearchCommand),   // ✅ Global search across all stored data
                                               // Box::new(monitor::MonitorCommand),  // Temporarily disabled
        ];

        // commands.extend(database::commands()); // Temporarily disabled

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
        self.resource_index
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
                .map(|&idx| registry.command(idx).resource().to_string())
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
}

impl Flag {
    pub fn new(long: &str, desc: &str) -> Self {
        Self {
            short: None,
            long: long.to_string(),
            description: desc.to_string(),
            default: None,
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

    pub fn with_arg(self, _arg: &str) -> Self {
        // Argument metadata (for documentation only)
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
    let registry = command_registry();
    let indices = registry
        .domain_indices(domain)
        .ok_or_else(|| format!("Unknown domain '{}'", domain))?;

    Output::header(&format!("Domain: {}", domain));
    println!("\nResources:");
    for &idx in indices {
        let command = registry.command(idx);
        println!("  • {}", command.resource());
    }
    println!("\nUse: rb {} <resource> help", domain);
    println!("     rb {} <resource> --help", domain);
    Ok(())
}

pub fn dispatch(ctx: &CliContext) -> Result<(), String> {
    use crate::cli::aliases::AliasResolver;

    let domain = ctx.domain.as_deref().ok_or_else(|| {
        "Missing domain. Syntax: rb <domain> <resource> <verb> [target]".to_string()
    })?;

    // Magic scan detection: if domain looks like a URL/domain, trigger magic scan
    // Do this BEFORE alias resolution to avoid false positives
    if is_magic_scan_target(domain) && ctx.resource.is_none() {
        return magic::execute(ctx);
    }

    // Resolve aliases to canonical names
    let resolver = AliasResolver::new();
    let (resolved_domain, resolved_resource, resolved_verb) =
        resolver.resolve_all(domain, ctx.resource.as_deref(), ctx.verb.as_deref());

    // Create new context with resolved names
    let mut resolved_ctx = ctx.clone();
    resolved_ctx.domain = Some(resolved_domain.clone());
    resolved_ctx.resource = resolved_resource.clone();
    resolved_ctx.verb = resolved_verb.clone();

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
                "Unknown resource '{}' in domain '{}'",
                target_resource, domain
            ));
        }

        print_domain_overview(domain)?;
        return Ok(());
    }

    let resource = resolved_ctx.resource.as_deref().ok_or_else(|| {
        // Get available resources for this domain
        let resources: Vec<String> = registry
            .domain_indices(domain)
            .map(|indices| {
                indices
                    .iter()
                    .map(|&idx| registry.command(idx).resource().to_string())
                    .collect()
            })
            .unwrap_or_default();

        let resources_list = if !resources.is_empty() {
            format!(
                "\n\nAvailable resources for '{}':\n  {}",
                domain,
                resources.join(", ")
            )
        } else {
            String::new()
        };

        format!(
            "Missing resource for domain '{}'.\n\nSyntax: rb {} <resource> <verb> [target]{}",
            domain, domain, resources_list
        )
    })?;

    if resolved_ctx.verb.as_deref() == Some("help") {
        if let Some(command) = registry.find(domain, resource) {
            print_help(command);
            return Ok(());
        }

        return Err(format!(
            "Unknown resource '{}' in domain '{}'",
            resource, domain
        ));
    }

    let verb = resolved_ctx.verb.as_deref().ok_or_else(|| {
        // Get available verbs for this resource
        let verbs: Vec<String> = registry
            .find(domain, resource)
            .map(|command| {
                command
                    .routes()
                    .iter()
                    .map(|r| r.verb.to_string())
                    .collect()
            })
            .unwrap_or_default();

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
            "Missing verb for {} {}.\n\nSyntax: rb {} {} <verb> [target]{}",
            domain, resource, domain, resource, verbs_list
        )
    })?;

    if let Some(command) = registry.find(domain, resource) {
        return command.execute(&resolved_ctx);
    }

    Err(format!(
        "Unknown route: {} {} {}\nUse `rb {} help` to inspect available resources.",
        domain, resource, verb, domain
    ))
}

pub fn print_help(cmd: &dyn Command) {
    Output::header(&format!(
        "{} {} - {}",
        cmd.domain(),
        cmd.resource(),
        cmd.description()
    ));

    println!("\n\x1b[1mUSAGE:\x1b[0m");
    println!(
        "  rb {} {} <verb> [target] [FLAGS]",
        cmd.domain(),
        cmd.resource()
    );

    let routes = cmd.routes();
    if !routes.is_empty() {
        println!("\n\x1b[1mVERBS:\x1b[0m");
        for route in &routes {
            println!("  {:<12} {}", route.verb, route.summary);
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
            "agent",  // C2 Agent
            "assess", // Assessment workflow
            "attack", // ✅ Attack workflow - plan, run, playbooks (includes lab)
            "network",
            "dns",
            "web",
            "tls",
            "recon",
            "intelligence", // ✅ Intelligence domain - vuln, mitre, ioc, taxii (alias: intel)
            "exploit",
            "nc", // netcat standalone command
            "code",
            "cloud",
            "collection",
            "bench",
            "service", // service manager
            "evasion", // AV/EDR evasion
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

pub fn print_global_help() {
    let title = "\x1b[1m\x1b[36m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    println!(
        "
{title}RedBlue CLI{reset} - Modern security testing interface

{bold}USAGE:{reset}
  rb <domain> <resource> <verb> [target] [FLAGS]

{bold}DOMAINS:{reset}
  access     ⚠️  Remote access - reverse shells & listeners (AUTHORIZED USE ONLY)
  exploit    ⚠️  Exploitation - privesc, lateral movement, persistence, replication (AUTHORIZED USE ONLY)
  mitm       ⚠️  Man-in-the-Middle attacks - DNS hijacking + TLS interception (AUTHORIZED USE ONLY)
  evasion    ⚠️  AV/EDR evasion - sandbox detection, obfuscation, anti-debug (AUTHORIZED USE ONLY)
  network    Hosts, ports, and low-level telemetry
  dns        Records, zones, and resolvers
  web        Web assets and HTTP audits
  tls        TLS/SSL security testing and cipher enumeration
  recon      Asset intelligence and WHOIS insights
  intel      Threat intelligence - vulnerabilities, MITRE ATT&CK, IOCs, TAXII feeds
  proxy      HTTP CONNECT and SOCKS5 proxy servers
  service    Service manager - install persistent services (systemd, launchd, Windows)
  code       Code security (secrets, dependencies)
  cloud      Cloud storage security (S3, Azure, GCS)
  bench      Load testing and performance benchmarking
  search     Search across all stored reconnaissance data
  mcp        Local Model Context Protocol bridge for tooling agents

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
  rb version               Show version information

For detailed documentation: Check docs/cli-semantics.md and QUICKSTART.md
",
        title = title,
        bold = bold,
        dim = dim,
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
    println!("Usage: rb <domain> <resource> <verb> [target] [flags]\n");

    let registry = command_registry();
    let commands = registry.commands();

    // Group commands by domain
    let mut domains: HashMap<String, Vec<&dyn Command>> = HashMap::new();
    for cmd in commands.iter() {
        domains
            .entry(cmd.domain().to_string())
            .or_default()
            .push(cmd.as_ref());
    }

    // Sort domains alphabetically
    let mut domain_names: Vec<_> = domains.keys().collect();
    domain_names.sort();

    let mut total_commands = 0;

    for domain_name in domain_names {
        let cmds = &domains[domain_name];
        println!("{bold}{yellow}{}{reset}", domain_name);

        for cmd in cmds {
            let routes = cmd.routes();
            if routes.is_empty() {
                println!("  {dim}└─{reset} {}", cmd.resource());
                total_commands += 1;
            } else {
                println!("  {dim}└─{reset} {}", cmd.resource());
                for route in &routes {
                    println!(
                        "      {dim}•{reset} {:<16} {dim}{}{reset}",
                        route.verb, route.summary
                    );
                    total_commands += 1;
                }
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
