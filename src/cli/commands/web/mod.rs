//! Web/asset command - Web application testing and analysis
//!
//! This module provides comprehensive web application testing capabilities,
//! including HTTP requests, security header analysis, CMS scanning, web scraping,
//! HAR recording, and database persistence.

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};

mod analysis;
mod cms;
mod db;
mod enumerators;
mod fingerprint;
mod har;
mod http;
mod persist;
mod scanning;
mod scrape;
mod security;
mod types;

pub struct WebCommand;

impl Command for WebCommand {
  fn domain(&self) -> &str {
    "web"
  }

  fn resource(&self) -> &str {
    "asset"
  }

  fn description(&self) -> &str {
    "Web application testing and analysis"
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
      "get" | "http2" | "headers" | "security" | "grade" | "csp" | "cors" | "cookies" | "tech"
      | "paths" | "params" => crate::cli::schema::RouteMetadata::new()
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
            Route {
                verb: "get",
                summary: "Execute a raw HTTP GET request",
                usage: "rb web asset get <url>",
            },
            Route {
                verb: "http2",
                summary: "Execute an HTTP/2 request over TLS",
                usage: "rb web asset http2 <https-url> [--method VERB] [--body STRING | --body-file PATH] [--headers \"k:v;...\"] [--timeout SECONDS]",
            },
            Route {
                verb: "headers",
                summary: "Inspect HTTP response headers",
                usage: "rb web asset headers <url>",
            },
            Route {
                verb: "security",
                summary: "Audit security-related HTTP headers",
                usage: "rb web asset security <url>",
            },
            Route {
                verb: "grade",
                summary: "Grade security headers (A+ to F) with detailed scoring",
                usage: "rb web asset grade <url>",
            },
            Route {
                verb: "cert",
                summary: "Inspect TLS certificate metadata",
                usage: "rb web asset cert <host[:port]>",
            },
            Route {
                verb: "fuzz",
                summary: "Run directory fuzzing against the target",
                usage: "rb web asset fuzz <url> --wordlist WORDS",
            },
            Route {
                verb: "fingerprint",
                summary: "Identify web technologies (whatweb-style)",
                usage: "rb web asset fingerprint <url>",
            },
            Route {
                verb: "scan",
                summary: "Vulnerability scan (nikto-style)",
                usage: "rb web asset scan <url>",
            },
            Route {
                verb: "vuln-scan",
                summary: "Active vulnerability scanner (OWASP ZAP-style)",
                usage: "rb web asset vuln-scan <url>",
            },
            Route {
                verb: "wpscan",
                summary: "WordPress security scanner",
                usage: "rb web asset wpscan <url>",
            },
            Route {
                verb: "drupal-scan",
                summary: "Drupal security scanner (droopescan replacement)",
                usage: "rb web asset drupal-scan <url>",
            },
            Route {
                verb: "joomla-scan",
                summary: "Joomla security scanner",
                usage: "rb web asset joomla-scan <url>",
            },
            Route {
                verb: "cms-scan",
                summary: "Unified CMS scanner with auto-detection (smart scan)",
                usage: "rb web asset cms-scan <url> [--strategy auto|wordpress|drupal|joomla]",
            },
            Route {
                verb: "cms",
                summary: "Advanced CMS security testing (wpscan/droopescan replacement)",
                usage: "rb web asset cms <url> [--aggressive] [--waf-evasion] [--enumerate plugins,themes,users]",
            },
            Route {
                verb: "linkfinder",
                summary: "Extract endpoints from JavaScript files",
                usage: "rb web asset linkfinder <js-url> [--type api|s3|all]",
            },
            Route {
                verb: "crawl",
                summary: "Crawl website discovering pages, links, forms, assets",
                usage: "rb web asset crawl <url> [--depth N] [--max-pages N] [--har FILE]",
            },
            Route {
                verb: "scrape",
                summary: "Extract data using CSS selectors",
                usage: "rb web asset scrape <url> --select SELECTOR [--attr NAME] [--format json|text]",
            },
            Route {
                verb: "links",
                summary: "Extract all links from a page",
                usage: "rb web asset links <url> [--type internal|external|all]",
            },
            Route {
                verb: "images",
                summary: "Extract all images from a page",
                usage: "rb web asset images <url>",
            },
            Route {
                verb: "meta",
                summary: "Extract meta tags and OpenGraph data",
                usage: "rb web asset meta <url>",
            },
            Route {
                verb: "forms",
                summary: "Extract all forms and inputs from a page",
                usage: "rb web asset forms <url>",
            },
            Route {
                verb: "tables",
                summary: "Extract tables as structured data",
                usage: "rb web asset tables <url> [--select SELECTOR]",
            },
            // HAR verbs
            Route {
                verb: "har-export",
                summary: "Crawl website and export to HAR format",
                usage: "rb web asset har-export <url> [--output FILE] [--depth N] [--max-pages N]",
            },
            Route {
                verb: "har-view",
                summary: "View and analyze a HAR file",
                usage: "rb web asset har-view <file> [--entries] [--timings] [--errors]",
            },
            Route {
                verb: "har-replay",
                summary: "Replay HTTP requests from a HAR file",
                usage: "rb web asset har-replay <file> [--sequential] [--compare] [--delay MS]",
            },
            Route {
                verb: "har-to-curl",
                summary: "Convert HAR entries to curl/wget/python commands",
                usage: "rb web asset har-to-curl <file> [--format curl|wget|python|httpie]",
            },
            // RESTful verbs - query stored data
            Route {
                verb: "list",
                summary: "List all saved HTTP data for a host from database",
                usage: "rb web asset list <host> [--db <file>]",
            },
            Route {
                verb: "describe",
                summary: "Get detailed HTTP summary from database",
                usage: "rb web asset describe <host> [--db <file>]",
            },
            // Security analysis verbs
            Route {
                verb: "csp",
                summary: "Analyze Content-Security-Policy header",
                usage: "rb web asset csp <url>",
            },
            Route {
                verb: "cors",
                summary: "Scan for CORS misconfigurations",
                usage: "rb web asset cors <url>",
            },
            Route {
                verb: "cookies",
                summary: "Analyze cookie security flags",
                usage: "rb web asset cookies <url>",
            },
            Route {
                verb: "tech",
                summary: "Detect technologies using rule engine",
                usage: "rb web asset tech <url>",
            },
            // Enumeration verbs
            Route {
                verb: "paths",
                summary: "Discover paths and directories",
                usage: "rb web asset paths <url> [--brute]",
            },
            Route {
                verb: "params",
                summary: "Discover hidden parameters",
                usage: "rb web asset params <url> [--brute]",
            },
        ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("timeout", "Request timeout in seconds")
        .with_short('t')
        .with_default("10"),
      Flag::new("user-agent", "Custom User-Agent header").with_short('u'),
      Flag::new(
        "impersonate",
        "Impersonate a browser profile (chrome, firefox, safari)",
      )
      .with_short('I'),
      Flag::new("follow", "Follow redirects").with_short('f'),
      Flag::new("wordlist", "Wordlist for fuzzing").with_short('w'),
      Flag::new("threads", "Number of concurrent threads for fuzzing").with_default("50"),
      Flag::new("filter", "Filter out status codes (comma-separated)").with_default("404"),
      Flag::new("match", "Only show status codes (comma-separated)"),
      Flag::new("common", "Use built-in common wordlist"),
      Flag::new(
        "type",
        "Filter linkfinder results by type (api, s3, websocket, graphql, all)",
      ),
      Flag::new(
        "recursive",
        "Enable recursive directory fuzzing (feroxbuster-style)",
      )
      .with_short('r'),
      Flag::new("depth", "Maximum recursion depth for fuzzing").with_default("3"),
      Flag::new(
        "strategy",
        "Scanning strategy: auto (default), wordpress, drupal, joomla, generic",
      )
      .with_short('s')
      .with_default("auto"),
      Flag::new(
        "intel",
        "Perform HTTP server fingerprinting and intelligence gathering",
      ),
      Flag::new("persist", "Save results to binary database (.rdb file)"),
      Flag::new("no-persist", "Don't save results (overrides config)"),
      Flag::new(
        "from-db",
        "describe/get: read from an existing DB instead of collecting live",
      ),
      Flag::new("cache-only", "Alias for --from-db"),
      Flag::new(
        "from-json",
        "describe/get: ingest a pre-collected payload (path or '-' for stdin)",
      ),
      Flag::new(
        "db",
        "Database file path for RESTful queries (default: auto-detect)",
      )
      .with_short('d'),
      // Scraping flags
      Flag::new("select", "CSS selector for element selection").with_short('S'),
      Flag::new("attr", "Extract specific attribute (use with --select)").with_short('a'),
      Flag::new("format", "Output format (text, json)").with_default("text"),
      Flag::new("link-type", "Filter link type: internal, external, all").with_default("all"),
      Flag::new("har", "Export HAR file for crawl command"),
      Flag::new("max-pages", "Maximum pages to crawl").with_short('m'),
      Flag::new("external", "Include external links when crawling"),
      // HTTP/2 flags
      Flag::new("method", "HTTP method (GET, POST, PUT, DELETE, etc)").with_default("GET"),
      Flag::new("body", "Request body for POST/PUT requests"),
      Flag::new("body-file", "Read request body from file"),
      Flag::new(
        "headers",
        "Additional headers (format: \"key:value;key2:value2\")",
      ),
      // HAR flags
      Flag::new("output", "Output file path"),
      Flag::new("entries", "Show individual HAR entries"),
      Flag::new("timings", "Show timing breakdown"),
      Flag::new("errors", "Show only errors"),
      Flag::new("sequential", "Replay requests sequentially"),
      Flag::new("compare", "Compare responses with original"),
      Flag::new("delay", "Delay between replayed requests (ms)"),
      // CMS flags
      Flag::new("aggressive", "Enable aggressive scanning mode"),
      Flag::new("waf-evasion", "Enable WAF evasion techniques"),
      Flag::new("enumerate", "What to enumerate (plugins,themes,users)"),
      // Enumeration flags
      Flag::new(
        "brute",
        "Enable active brute force (required for path/param enumeration)",
      ),
      Flag::new("extensions", "File extensions to try (comma-separated)").with_arg("EXTS"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Simple GET request", "rb web asset get http://example.com"),
      (
        "HTTP server fingerprinting",
        "rb web asset get http://example.com --intel",
      ),
      ("Analyze headers", "rb web asset headers http://example.com"),
      ("Security audit", "rb web asset security http://example.com"),
      ("TLS certificate check", "rb web asset cert example.com:443"),
      (
        "Directory fuzzing (basic)",
        "rb web asset fuzz http://example.com --common",
      ),
      (
        "Recursive fuzzing (feroxbuster-style)",
        "rb web asset fuzz http://example.com --common --recursive --depth 4",
      ),
      (
        "Auto-detect scan (smart)",
        "rb web asset scan http://example.com",
      ),
      (
        "Force WordPress scan",
        "rb web asset scan http://example.com --strategy wordpress",
      ),
      (
        "Extract links from page",
        "rb web asset links http://example.com",
      ),
      (
        "Crawl and export HAR",
        "rb web asset har-export http://example.com --output site.har",
      ),
      ("Analyze CSP header", "rb web asset csp https://example.com"),
      (
        "Scan for CORS misconfiguration",
        "rb web asset cors https://example.com",
      ),
      (
        "Analyze cookie security",
        "rb web asset cookies https://example.com",
      ),
      (
        "Detect technologies (rule engine)",
        "rb web asset tech https://example.com",
      ),
      (
        "Discover paths (passive)",
        "rb web asset paths https://example.com",
      ),
      (
        "Discover paths (active brute-force)",
        "rb web asset paths https://example.com --brute",
      ),
      (
        "Discover hidden parameters",
        "rb web asset params https://example.com/page --brute",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      // Core HTTP operations
      "get" => http::get(ctx),
      "headers" => http::headers(ctx),
      "http2" => http::http2(ctx),
      "cert" => http::cert(ctx),

      // Security analysis
      "security" => security::security(ctx),
      "grade" => security::grade(ctx),

      // Fingerprinting
      "fingerprint" => fingerprint::fingerprint(ctx),

      // Scanning (delegated to scanning submodule)
      "scan" => scanning::run_scan(ctx),
      "vuln-scan" => scanning::run_active_scan(ctx),

      // CMS scanning
      "wpscan" => cms::wpscan(ctx),
      "drupal-scan" => cms::drupal_scan(ctx),
      "joomla-scan" => cms::joomla_scan(ctx),
      "cms-scan" => cms::cms_scan(ctx),
      "cms" => cms::cms_advanced(ctx),

      // Scraping and extraction
      "linkfinder" => scrape::linkfinder(ctx),
      "crawl" => scrape::crawl(ctx),
      "scrape" => scrape::scrape(ctx),
      "links" => scrape::links(ctx),
      "images" => scrape::images(ctx),
      "meta" => scrape::meta(ctx),
      "forms" => scrape::forms(ctx),
      "tables" => scrape::tables(ctx),

      // HAR operations
      "har-export" => har::har_export(ctx),
      "har-view" => har::har_view(ctx),
      "har-replay" => har::har_replay(ctx),
      "har-to-curl" => har::har_to_curl(ctx),

      // Database queries
      "list" => db::list_http(ctx),
      "describe" => db::describe_http(ctx),

      // Security analysis
      "csp" => analysis::csp(ctx),
      "cors" => analysis::cors(ctx),
      "cookies" => analysis::cookies(ctx),
      "tech" => analysis::fingerprint_rules(ctx),

      // Enumeration
      "paths" => enumerators::paths(ctx),
      "params" => enumerators::params(ctx),

      // Fuzzing redirect
      "fuzz" => Err("Use 'rb web fuzz' command instead (dedicated fuzzing module)".to_string()),

      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        println!(
          "{}",
          Validator::suggest_command(
            verb,
            &[
              "get",
              "headers",
              "security",
              "grade",
              "http2",
              "cert",
              "fuzz",
              "fingerprint",
              "scan",
              "vuln-scan",
              "wpscan",
              "drupal-scan",
              "joomla-scan",
              "cms-scan",
              "cms",
              "linkfinder",
              "crawl",
              "scrape",
              "links",
              "images",
              "meta",
              "forms",
              "tables",
              "har-export",
              "har-view",
              "har-replay",
              "har-to-curl",
              "list",
              "describe",
              "csp",
              "cors",
              "cookies",
              "tech",
              "paths",
              "params"
            ]
          )
        );
        Err("Invalid verb".to_string())
      }
    }
  }
}
