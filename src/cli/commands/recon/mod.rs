//! Recon CLI commands - Information gathering and OSINT

mod breach;
mod harvest;
mod osint;
mod query;
mod social;
mod subdomains;
mod vuln;
mod whois;
mod workflow;

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::recon::vuln::osv::Ecosystem;
use crate::storage::records::SubdomainSource;

pub struct ReconCommand;

impl Command for ReconCommand {
  fn domain(&self) -> &str {
    "recon"
  }

  fn resource(&self) -> &str {
    "domain"
  }

  fn description(&self) -> &str {
    "Information gathering and baseline OSINT"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
      .with_aliases(crate::cli::aliases::resource_aliases_for(self.resource()))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let aliases = crate::cli::aliases::verb_aliases_for(verb);
    match verb {
      "subdomains" | "whois" | "harvest" | "urls" => crate::cli::schema::RouteMetadata::new()
        .with_aliases(aliases)
        .with_machine_output(
          crate::cli::schema::MachineOutputMetadata::new()
            .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
            .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
            .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
        ),
      _ => crate::cli::schema::RouteMetadata::new()
        .with_aliases(aliases)
        .with_machine_output(self.metadata().machine_output),
    }
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      // === FULL RECON WORKFLOW ===
      Route {
        verb: "full",
        summary: "Complete reconnaissance workflow (ports, dns, fingerprint, vulns)",
        usage: "rb recon domain full <target>",
      },
      Route {
        verb: "show",
        summary: "Show consolidated findings for a target",
        usage: "rb recon domain show <target>",
      },
      // === Individual Recon Commands ===
      Route {
        verb: "whois",
        summary: "Query WHOIS information for a domain",
        usage: "rb recon domain whois <domain>",
      },
      Route {
        verb: "rdap",
        summary: "Query RDAP (modern WHOIS) for domain or IP",
        usage: "rb recon domain rdap <domain|ip>",
      },
      Route {
        verb: "subdomains",
        summary: "Enumerate subdomains via CT logs and DNS bruteforce",
        usage:
          "rb recon domain subdomains <domain> [--passive] [--threads N] [--resolve|--validate]",
      },
      Route {
        verb: "harvest",
        summary: "OSINT data harvesting - emails, subdomains, URLs (theHarvester)",
        usage: "rb recon domain harvest <domain>",
      },
      Route {
        verb: "urls",
        summary: "Harvest historical URLs from Wayback, URLScan, etc (waybackurls/gau)",
        usage: "rb recon domain urls <domain> [--include PATTERN] [--exclude PATTERN]",
      },
      Route {
        verb: "osint",
        summary: "Run username OSINT helpers (coming soon)",
        usage: "rb recon domain osint <username>",
      },
      Route {
        verb: "email",
        summary: "Email intelligence - provider detection, service registrations (holehe-style)",
        usage: "rb recon domain email <email>",
      },
      Route {
        verb: "asn",
        summary: "ASN lookup for IP address (iptoasn.com)",
        usage: "rb recon domain asn <IP>",
      },
      Route {
        verb: "breach",
        summary: "Check if password/email appears in data breaches (HIBP)",
        usage: "rb recon domain breach <password|email> [--type password|email]",
      },
      Route {
        verb: "secrets",
        summary: "Scan URL for exposed secrets and credentials",
        usage: "rb recon domain secrets <URL>",
      },
      Route {
        verb: "dorks",
        summary: "Google/DuckDuckGo dork search for leaks and intel",
        usage: "rb recon domain dorks <domain>",
      },
      Route {
        verb: "social",
        summary: "Map social media presence for a company/brand",
        usage: "rb recon domain social <domain>",
      },
      Route {
        verb: "vuln",
        summary: "Fingerprint target and find vulnerabilities for detected technologies",
        usage: "rb recon domain vuln <url> [--source nvd|osv|all] [--limit N]",
      },
      Route {
        verb: "dnsdumpster",
        summary: "Query DNSDumpster for DNS intelligence (MX, TXT, DNS hosts, subdomains)",
        usage: "rb recon domain dnsdumpster <domain>",
      },
      Route {
        verb: "massdns",
        summary: "High-performance DNS bruteforce subdomain enumeration",
        usage: "rb recon domain massdns <domain> [--wordlist <file>] [--threads N]",
      },
      // RESTful verbs - query stored data
      Route {
        verb: "list",
        summary: "List all subdomains for a domain from database",
        usage: "rb recon domain list <domain> [--db <file>]",
      },
      Route {
        verb: "get",
        summary: "Get specific subdomain info from database",
        usage: "rb recon domain get <subdomain> [--db <file>]",
      },
      Route {
        verb: "describe",
        summary: "Get detailed OSINT data from database",
        usage: "rb recon domain describe <domain> [--db <file>]",
      },
      Route {
        verb: "graph",
        summary: "Visualize domain/subdomain tree from database",
        usage: "rb recon domain graph <domain> [--db <file>] [--depth N]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("recursive", "Recursive enumeration").with_short('r'),
      Flag::new("wordlist", "Custom wordlist path").with_short('w'),
      Flag::new("threads", "Number of threads for DNS bruteforce").with_default("10"),
      Flag::new("passive", "Passive enumeration only (CT logs)").with_short('p'),
      Flag::new("raw", "Show raw WHOIS response"),
      Flag::new("include", "Include URLs matching pattern").with_short('i'),
      Flag::new("exclude", "Exclude URLs matching pattern").with_short('e'),
      Flag::new(
        "extensions",
        "Filter by extensions (comma-separated: js,php,asp)",
      ),
      Flag::new("persist", "Save results to binary database (.rdb file)"),
      Flag::new("no-persist", "Don't save results (overrides config)"),
      Flag::new(
        "source",
        "Vulnerability source for vuln command (nvd, osv, all)",
      )
      .with_short('s')
      .with_default("nvd"),
      Flag::new("limit", "Maximum vulnerabilities to show").with_default("20"),
      Flag::new("api-key", "NVD API key for higher rate limits"),
      Flag::new("hibp-key", "HIBP API key for email breach checks"),
      Flag::new("type", "Breach check type: password or email")
        .with_short('t')
        .with_default("password"),
      Flag::new(
        "db",
        "Database file path for RESTful queries (default: auto-detect)",
      )
      .with_short('d'),
      // MassDNS flags
      Flag::new("resolvers", "Comma-separated DNS resolvers for massdns")
        .with_default("8.8.8.8,1.1.1.1,9.9.9.9"),
      Flag::new(
        "timeout-ms",
        "DNS query timeout in milliseconds for massdns",
      )
      .with_default("2000"),
      Flag::new("delay", "Delay between queries in ms for rate limiting").with_default("10"),
      Flag::new(
        "filter-wildcards",
        "Enable wildcard detection and filtering (for subdomains command)",
      ),
      Flag::new(
        "resolve",
        "Re-resolve discovered subdomains and keep only those with live A/AAAA answers",
      ),
      Flag::new(
        "validate",
        "Alias for --resolve; filters output to confirmed DNS-resolving subdomains",
      ),
      Flag::new("depth", "Maximum tree depth for graph command").with_default("5"),
      Flag::new("no-color", "Disable colored output in graph"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("WHOIS lookup", "rb recon domain whois example.com"),
      ("RDAP domain lookup", "rb recon domain rdap example.com"),
      ("RDAP IP lookup", "rb recon domain rdap 8.8.8.8"),
      (
        "Subdomain enumeration (all methods)",
        "rb recon domain subdomains example.com",
      ),
      (
        "Passive enumeration only",
        "rb recon domain subdomains example.com --passive",
      ),
      (
        "Only confirmed DNS-resolving subdomains",
        "rb recon domain subdomains example.com --resolve -o json",
      ),
      (
        "Custom wordlist and threads",
        "rb recon domain subdomains example.com --wordlist my-list.txt --threads 20",
      ),
      (
        "OSINT harvesting (theHarvester-style)",
        "rb recon domain harvest example.com",
      ),
      (
        "Get historical URLs (waybackurls/gau)",
        "rb recon domain urls example.com",
      ),
      (
        "Filter URLs by pattern",
        "rb recon domain urls example.com --include /api/ --exclude .png",
      ),
      (
        "Filter by file extension",
        "rb recon domain urls example.com --extensions js,php,asp",
      ),
      ("ASN lookup for IP", "rb recon domain asn 8.8.8.8"),
      ("ASN lookup for hostname", "rb recon domain asn google.com"),
      (
        "Check password breach (HIBP)",
        "rb recon domain breach password123",
      ),
      (
        "Check email breach (requires API key)",
        "rb recon domain breach user@example.com --type email --hibp-key YOUR_KEY",
      ),
      (
        "Scan URL for exposed secrets",
        "rb recon domain secrets http://example.com/config.js",
      ),
      (
        "Search username across platforms",
        "rb recon identity username johndoe",
      ),
      (
        "Google dorks search for domain",
        "rb recon domain dorks example.com",
      ),
      (
        "Map social media presence",
        "rb recon domain social example.com",
      ),
      (
        "Fingerprint target and find vulnerabilities",
        "rb recon domain vuln http://example.com",
      ),
      (
        "Vuln scan with OSV source",
        "rb recon domain vuln http://example.com --source osv",
      ),
      (
        "Query DNSDumpster for DNS intel",
        "rb recon domain dnsdumpster example.com",
      ),
      (
        "Mass DNS bruteforce with defaults",
        "rb recon domain massdns example.com",
      ),
      (
        "MassDNS with custom wordlist",
        "rb recon domain massdns example.com --wordlist subdomains.txt --threads 50",
      ),
      (
        "MassDNS with custom resolvers",
        "rb recon domain massdns example.com --resolvers 8.8.8.8,1.1.1.1",
      ),
      (
        "List all saved subdomains",
        "rb recon domain list example.com",
      ),
      (
        "Get specific subdomain info",
        "rb recon domain get api.example.com",
      ),
      (
        "Describe all recon data",
        "rb recon domain describe example.com",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      // Full workflow
      "full" => workflow::full_recon(ctx),
      "show" => workflow::show_findings(ctx),
      // Action verbs
      "whois" => whois::whois(ctx),
      "rdap" => whois::rdap(ctx),
      "subdomains" => subdomains::subdomains(ctx),
      "harvest" => harvest::harvest(ctx),
      "urls" => harvest::urls(ctx),
      "osint" => osint::osint(ctx),
      "email" => osint::email(ctx),
      "asn" => osint::asn(ctx),
      "breach" => breach::breach(ctx),
      "secrets" => breach::secrets(ctx),
      "dorks" => social::dorks(ctx),
      "social" => social::social(ctx),
      "vuln" => vuln::vuln(ctx),
      "dnsdumpster" => subdomains::dnsdumpster(ctx),
      "massdns" => subdomains::massdns(ctx),
      // RESTful verbs
      "list" => query::list_subdomains(ctx),
      "get" => query::get_subdomain(ctx),
      "describe" => query::describe_domain(ctx),
      "graph" => query::graph(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        println!(
          "{}",
          Validator::suggest_command(
            verb,
            &[
              "full",
              "show",
              "whois",
              "rdap",
              "subdomains",
              "harvest",
              "urls",
              "osint",
              "email",
              "asn",
              "breach",
              "secrets",
              "dorks",
              "social",
              "vuln",
              "dnsdumpster",
              "massdns",
              "list",
              "get",
              "describe",
              "graph"
            ]
          )
        );
        Err("Invalid verb".to_string())
      }
    }
  }
}

// Helper function to parse WHOIS timestamps (simplified)
pub(crate) fn parse_whois_timestamp(date_str: Option<&str>) -> Option<u32> {
  date_str.and_then(|s| {
    // Attempt to parse common formats like YYYY-MM-DD
    if s.len() >= 10 {
      let parsed = crate::utils::timing::parse_ymd_to_timestamp(&s[..10])?;
      return Some(parsed as u32);
    }
    None
  })
}

// Helper function to map subdomain source strings to enum values
pub(crate) fn map_subdomain_source(source: &str) -> SubdomainSource {
  match source {
    "DnsBruteforce" => SubdomainSource::DnsBruteforce,
    "CertTransparency" => SubdomainSource::CertTransparency,
    "SearchEngine" => SubdomainSource::SearchEngine,
    "WebCrawl" => SubdomainSource::WebCrawl,
    _ => SubdomainSource::SearchEngine,
  }
}

// Helper function to map technology names to OSV ecosystems
pub(crate) fn map_to_osv_ecosystem(tech_name: &str) -> Option<Ecosystem> {
  match tech_name.to_lowercase().as_str() {
    "npm" | "nodejs" => Some(Ecosystem::Npm),
    "python" | "pypi" => Some(Ecosystem::PyPI),
    "rust" | "cargo" => Some(Ecosystem::Cargo),
    "go" => Some(Ecosystem::Go),
    "java" | "maven" => Some(Ecosystem::Maven),
    "nuget" => Some(Ecosystem::NuGet),
    "php" | "packagist" => Some(Ecosystem::Packagist),
    "ruby" | "rubygems" => Some(Ecosystem::RubyGems),
    "dart" | "pub" => Some(Ecosystem::Pub),
    "elixir" | "hex" => Some(Ecosystem::Hex),
    "cpp" | "conancenter" => Some(Ecosystem::ConanCenter),
    _ => None,
  }
}
