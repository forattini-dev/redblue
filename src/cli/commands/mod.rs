pub mod bench;
pub mod cloud;
pub mod code;
pub mod database;
pub mod deps;
pub mod dns; // ✅ DNS with RESTful verbs (list, get, describe)
pub mod exploit; // ⚠️ Exploitation framework - AUTHORIZED USE ONLY
// pub mod init; // ✅ Config init command - TEMPORARILY DISABLED (missing function)
pub mod magic;
// pub mod monitor;  // Temporarily disabled - compilation errors
pub mod nc; // ⚠️ Netcat - AUTHORIZED USE ONLY
pub mod network;
// pub mod ping;     // Temporarily disabled - compilation errors
pub mod recon;
pub mod scan;
pub mod screenshot;
pub mod takeover;
pub mod tls;
pub mod trace;
pub mod web; // ✅ Re-enabled with TLS routes!

use crate::cli::{output::Output, CliContext};

pub trait Command {
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
    let domain_commands: Vec<_> = all_commands()
        .into_iter()
        .filter(|cmd| cmd.domain() == domain)
        .collect();

    if domain_commands.is_empty() {
        return Err(format!("Unknown domain '{}'", domain));
    }

    Output::header(&format!("Domain: {}", domain));
    println!("\nResources:");
    for command in &domain_commands {
        println!("  • {}", command.resource());
    }
    println!("\nUse: rb {} <resource> help", domain);
    println!("     rb {} <resource> --help", domain);
    Ok(())
}

pub fn all_commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(scan::ScanCommand),
        Box::new(network::NetworkCommand), // ✅ Host ping & discovery
        // Box::new(ping::PingCommand),  // Temporarily disabled
        Box::new(trace::TraceCommand),
        Box::new(dns::DnsCommand), // ✅ DNS with RESTful verbs (list, get, describe)
        Box::new(web::WebCommand), // ✅ Re-enabled with TLS cert & audit!
        Box::new(tls::TlsCommand), // ✅ TLS security testing
        Box::new(recon::ReconCommand),
        Box::new(exploit::ExploitCommand), // ⚠️ Exploitation framework
        Box::new(nc::NetcatCommand),       // ⚠️ Netcat - AUTHORIZED USE ONLY
        Box::new(code::CodeCommand),
        Box::new(deps::DepsCommand),
        Box::new(cloud::CloudCommand),
        Box::new(takeover::TakeoverCommand),
        Box::new(bench::BenchCommand),
        Box::new(screenshot::ScreenshotCommand), // ✅ Screenshot capture
        Box::new(database::DatabaseCommand),
        // Box::new(init::InitCommand), // ✅ Config init - TEMPORARILY DISABLED
        // Box::new(monitor::MonitorCommand),  // Temporarily disabled
    ]
}

pub fn dispatch(ctx: &CliContext) -> Result<(), String> {
    let domain = ctx.domain.as_deref().ok_or_else(|| {
        "Missing domain. Syntax: rb <domain> <resource> <verb> [target]".to_string()
    })?;

    // Magic scan detection: if domain looks like a URL/domain, trigger magic scan
    if is_magic_scan_target(domain) && ctx.resource.is_none() {
        return magic::execute(ctx);
    }

    // Netcat special case: standalone command like `rb nc listen 4444`
    // Only trigger if we have a resource (which will contain the verb)
    if domain == "nc" && ctx.resource.is_some() {
        if let Some(command) = all_commands().into_iter().find(|cmd| cmd.domain() == "nc") {
            return command.execute(ctx);
        }
    }

    if ctx.resource.as_deref() == Some("help") {
        if let Some(target_resource) = ctx.verb.as_deref() {
            if let Some(command) = all_commands()
                .into_iter()
                .find(|cmd| cmd.domain() == domain && cmd.resource() == target_resource)
            {
                print_help(&*command);
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

    let resource = ctx.resource.as_deref().ok_or_else(|| {
        // Get available resources for this domain
        let resources: Vec<String> = all_commands()
            .into_iter()
            .filter(|cmd| cmd.domain() == domain)
            .map(|cmd| cmd.resource().to_string())
            .collect();

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

    if ctx.verb.as_deref() == Some("help") {
        if let Some(command) = all_commands()
            .into_iter()
            .find(|cmd| cmd.domain() == domain && cmd.resource() == resource)
        {
            print_help(&*command);
            return Ok(());
        }

        return Err(format!(
            "Unknown resource '{}' in domain '{}'",
            resource, domain
        ));
    }

    let verb = ctx.verb.as_deref().ok_or_else(|| {
        // Get available verbs for this resource
        let verbs: Vec<String> = all_commands()
            .into_iter()
            .find(|cmd| cmd.domain() == domain && cmd.resource() == resource)
            .map(|cmd| cmd.routes().iter().map(|r| r.verb.to_string()).collect())
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

    if let Some(command) = all_commands()
        .into_iter()
        .find(|cmd| cmd.domain() == domain && cmd.resource() == resource)
    {
        return command.execute(ctx);
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

    println!("\n{}USAGE:{}", "\x1b[1m", "\x1b[0m");
    println!(
        "  rb {} {} <verb> [target] [FLAGS]",
        cmd.domain(),
        cmd.resource()
    );

    let routes = cmd.routes();
    if !routes.is_empty() {
        println!("\n{}VERBS:{}", "\x1b[1m", "\x1b[0m");
        for route in &routes {
            println!("  {:<12} {}", route.verb, route.summary);
        }

        println!("\n{}ROUTE EXAMPLES:{}", "\x1b[1m", "\x1b[0m");
        for route in &routes {
            println!("  {}", route.usage);
        }
    }

    let flags = cmd.flags();
    if !flags.is_empty() {
        println!("\n{}FLAGS:{}", "\x1b[1m", "\x1b[0m");
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
        println!("\n{}EXAMPLES:{}", "\x1b[1m", "\x1b[0m");
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
            "network",
            "dns",
            "web",
            "tls",
            "recon",
            "exploit",
            "nc", // netcat standalone command
            "code",
            "cloud",
            "collection",
            "bench",
            "help",
            "version",
            "repl",
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
  network    Hosts, ports, and low-level telemetry
  dns        Records, zones, and resolvers
  web        Web assets and HTTP audits
  tls        TLS/SSL security testing and cipher enumeration
  recon      Asset intelligence and WHOIS insights
  exploit    ⚠️  Exploitation framework (AUTHORIZED USE ONLY)
  code       Code security (secrets, dependencies)
  cloud      Cloud storage security (S3, Azure, GCS)
  bench      Load testing and performance benchmarking
  config     Configuration management
  database   Database operations and queries
  monitor    Protocol monitoring (TCP, UDP, ICMP)

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

{dim}NOTE:{reset} HTTPS endpoints are supported via TLS tooling (`rb web asset cert|tls-audit`). HTTP routes expect explicit `http://` targets.

{bold}MAGIC SCAN:{reset}
  rb <url>                 Run intelligent multi-phase scan (magic mode)
  rb <domain>              Auto-detect and scan target
  rb <ip>                  Scan IP address with smart presets

{bold}REPL (Interactive Mode):{reset}
  rb repl <target>         Enter interactive REPL for exploring scans
  rb repl <file>.rdb      Open existing session file

{bold}GLOBAL COMMANDS:{reset}
  rb help                  Show global overview
  rb <domain> help         List resources inside a domain
  rb version               Show version information

For detailed documentation: Check docs/CLI_SEMANTICS.md and QUICKSTART.md
",
        title = title,
        bold = bold,
        dim = dim,
        reset = reset
    );
}
