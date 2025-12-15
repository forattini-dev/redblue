/// Web/asset command - Web application testing
use crate::cli::commands::{
    annotate_query_partition, build_partition_attributes, print_help, Command, Flag, Route,
};
use crate::cli::{format::OutputFormat, output::Output, validator::Validator, CliContext};
use crate::intelligence::banner_analysis::analyze_http_server;
use crate::modules::web::crawler::WebCrawler;
use crate::modules::web::dom::Document;
use crate::modules::web::extractors;
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::modules::web::linkfinder::{EndpointType, LinkFinder};
use crate::modules::web::scanner_strategy::{ScanStrategy, UnifiedScanResult, UnifiedWebScanner};
use crate::protocols::har::{Har, HarRecorder};
use crate::protocols::http::{HttpClient, HttpRequest, HttpResponse};
use crate::protocols::http2::{
    Header, Http2Dispatcher, Http2LoggingMiddleware, Http2Request, Http2Response,
    Http2ResponseHandler,
};
use crate::protocols::tls_impersonator::TlsProfile;
use crate::storage::records::{HttpHeadersRecord, HttpTlsSnapshot};
use crate::storage::service::StorageService;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod scanning;

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
            // Route {
            //     verb: "tls-audit",
            //     summary: "Comprehensive TLS security audit (sslyze-style)",
            //     usage: "rb web asset tls-audit <host[:port]>",
            // },
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
                "db",
                "Database file path for RESTful queries (default: auto-detect)",
            )
            .with_short('d'),
            // New scraping flags
            Flag::new("select", "CSS selector for element selection").with_short('S'),
            Flag::new("attr", "Extract specific attribute (use with --select)").with_short('a'),
            Flag::new("format", "Output format (text, json)").with_default("text"),
            Flag::new("link-type", "Filter link type: internal, external, all").with_default("all"),
            Flag::new("har", "Export HAR file for crawl command"),
            Flag::new("max-pages", "Maximum pages to crawl").with_short('m'),
            Flag::new("external", "Include external links when crawling"),
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
            ("TLS security audit", "rb web asset tls-audit example.com"),
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
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "get" => self.get(ctx),
            "headers" => self.headers(ctx),
            "security" => self.security(ctx),
            "grade" => self.grade(ctx),
            "http2" => self.http2(ctx),
            "cert" => self.cert(ctx),
            // "tls-audit" => self.tls_audit(ctx), // TODO: Enable when TlsAuditor compiles
            "fuzz" => {
                Err("Use 'rb web fuzz' command instead (dedicated fuzzing module)".to_string())
            }
            "fingerprint" => self.fingerprint(ctx),
            "scan" => self.scan(ctx),
            "vuln-scan" => self.vuln_scan(ctx),
            "wpscan" => self.wpscan(ctx),
            "drupal-scan" => self.drupal_scan(ctx),
            "joomla-scan" => self.joomla_scan(ctx),
            "cms-scan" => self.cms_scan(ctx),
            "cms" => self.cms_advanced(ctx),
            "linkfinder" => self.linkfinder(ctx),
            "crawl" => self.crawl(ctx),
            // Scraping verbs
            "scrape" => self.scrape(ctx),
            "links" => self.links(ctx),
            "images" => self.images(ctx),
            "meta" => self.meta(ctx),
            "forms" => self.forms(ctx),
            "tables" => self.tables(ctx),
            // HAR verbs
            "har-export" => self.har_export(ctx),
            "har-view" => self.har_view(ctx),
            "har-replay" => self.har_replay(ctx),
            "har-to-curl" => self.har_to_curl(ctx),
            // RESTful verbs
            "list" => self.list_http(ctx),
            "describe" => self.describe_http(ctx),
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
                            "list",
                            "describe"
                        ]
                    )
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

// TODO: Disabled until TLS is fixed
// fn render_certificate_summary(label: &str, cert: &CertificateInfo) {
//     // Simple status based on string dates
//     let status = "Check dates manually".to_string();
//
//     let san_display = if cert.san.is_empty() {
//         "-".to_string()
//     } else {
//         cert.san.join(", ")
//     };
//
//     Output::subheader(label);
//     Output::item("Subject", &cert.subject);
//     Output::item("Issuer", &cert.issuer);
//     Output::item("Valid From", &cert.valid_from);
//     Output::item("Valid Until", &cert.valid_until);
//     Output::item("Serial", &cert.serial_number);
//     Output::item("Signature", &cert.signature_algorithm);
//     Output::item("Public Key", &cert.public_key_algorithm);
//     Output::item("SANs", san_display.as_str());
//     Output::item("Status", status.as_str());
//
//     // TODO: Add certificate validation when TLS implementation is complete
//     // if expired {
//     //     Output::warning("Certificate is expired");
//     // } else if not_yet_valid {
//     //     Output::warning("Certificate validity period has not started");
//     // }
// }

impl WebCommand {
    /// Extract host from URL for database naming
    fn extract_host(url: &str) -> String {
        // Parse URL to get host
        if let Some(host_start) = url.find("://") {
            let after_protocol = &url[host_start + 3..];
            if let Some(path_start) = after_protocol.find('/') {
                after_protocol[..path_start].to_string()
            } else {
                after_protocol.to_string()
            }
        } else {
            url.to_string()
        }
    }

    fn current_timestamp() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs() as u32
    }

    fn guard_plain_http(_url: &str, _command: &str) -> Result<(), String> {
        // HTTPS supported via native TLS 1.2 client
        Ok(())
    }

    fn parse_https_url(url: &str) -> Result<(String, u16, String, String), String> {
        let lower = url.to_ascii_lowercase();
        if !lower.starts_with("https://") {
            return Err("HTTP/2 client requires an https:// URL".to_string());
        }

        let without_scheme = &url[8..];
        let (authority_raw, path_part) = match without_scheme.find('/') {
            Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
            None => (without_scheme, "/"),
        };

        if authority_raw.is_empty() {
            return Err("Missing host in URL".to_string());
        }

        let (host, port, authority) = if authority_raw.starts_with('[') {
            let end = authority_raw
                .find(']')
                .ok_or_else(|| "Invalid IPv6 host notation".to_string())?;
            let host_part = authority_raw[1..end].to_string();
            let authority = if end + 1 < authority_raw.len() {
                authority_raw.to_string()
            } else {
                format!("[{}]", host_part)
            };

            if end + 1 < authority_raw.len() && authority_raw.as_bytes()[end + 1] == b':' {
                let port_str = &authority_raw[end + 2..];
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid port: {}", port_str))?;
                (host_part, port, authority)
            } else {
                (host_part, 443, authority)
            }
        } else if let Some(idx) = authority_raw.rfind(':') {
            if authority_raw[idx + 1..].contains(':') {
                (authority_raw.to_string(), 443, authority_raw.to_string())
            } else {
                let host_part = authority_raw[..idx].to_string();
                let port_str = &authority_raw[idx + 1..];
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid port: {}", port_str))?;
                (host_part.clone(), port, format!("{}:{}", host_part, port))
            }
        } else {
            (authority_raw.to_string(), 443, authority_raw.to_string())
        };

        Ok((host, port, authority, path_part.to_string()))
    }

    fn collect_request_headers(ctx: &CliContext) -> Result<Vec<(String, String)>, String> {
        let mut headers: Vec<(String, String)> = Vec::new();

        if let Some(header_value) = ctx.get_flag("header") {
            if let Some((name, value)) = header_value.split_once(':') {
                headers.push((name.trim().to_lowercase(), value.trim().to_string()));
            } else {
                return Err("Header format must be 'Name: Value'".to_string());
            }
        }

        if let Some(headers_list) = ctx.get_flag("headers") {
            for entry in headers_list
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if let Some((name, value)) = entry.split_once(':') {
                    headers.push((name.trim().to_lowercase(), value.trim().to_string()));
                } else {
                    return Err(format!("Invalid header entry: {}", entry));
                }
            }
        }

        Ok(headers)
    }

    fn get(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset get <URL> Example: rb web asset get http://example.com"
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset get")?;

        let format = ctx.get_output_format();

        let client = HttpClient::new();
        let mut request = HttpRequest::get(url);
        if let Some(profile_str) = ctx.get_flag("impersonate") {
            if let Some(profile) = TlsProfile::from_str(&profile_str) {
                request = request.with_tls_profile(profile);
            } else {
                Output::warning(&format!("Unknown impersonation profile: {}", profile_str));
                Output::info("Available profiles: chrome, firefox, safari");
            }
        }

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start("Sending request");
        }

        let response = client
            .send(&request)
            .map_err(|e| format!("Request failed: {}", e))?;

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"url\": \"{}\",", url);
            println!("  \"status_code\": {},", response.status_code);
            println!("  \"status_text\": \"{}\",", response.status_text);
            println!("  \"body_size\": {},", response.body.len());
            println!("  \"headers\": {{");
            let header_count = response.headers.len();
            for (i, (key, value)) in response.headers.iter().enumerate() {
                let comma = if i < header_count - 1 { "," } else { "" };
                let value_escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
                println!("    \"{}\": \"{}\"{}", key, value_escaped, comma);
            }
            println!("  }}");
            println!("}}");
            self.maybe_persist_http(ctx, url, &request, &response)?;
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("url: {}", url);
            println!("status_code: {}", response.status_code);
            println!("status_text: {}", response.status_text);
            println!("body_size: {}", response.body.len());
            println!("headers:");
            for (key, value) in &response.headers {
                println!("  {}: \"{}\"", key, value.replace('"', "\\\""));
            }
            self.maybe_persist_http(ctx, url, &request, &response)?;
            return Ok(());
        }

        // Human output
        Output::header("HTTP GET Request");
        Output::item("URL", url);
        println!();

        Output::subheader("Response");
        Output::item(
            "Status",
            &format!("{} {}", response.status_code, response.status_text),
        );
        Output::item("Body Size", &format!("{} bytes", response.body.len()));
        println!();

        Output::subheader("Headers");
        for (key, value) in &response.headers {
            Output::item(key, value);
        }

        self.maybe_persist_http(ctx, url, &request, &response)?;

        // HTTP server intelligence gathering
        if ctx.has_flag("intel") {
            println!();
            Output::header("HTTP Server Intelligence");

            // Extract Server header
            if let Some(server_header) = response.headers.get("server") {
                let banner_info = analyze_http_server(server_header);

                // Display vendor
                if let Some(vendor) = &banner_info.vendor {
                    Output::item("Server Software", vendor);
                }

                // Display version
                if let Some(version) = &banner_info.version {
                    Output::item("Version", version);
                }

                // Display OS hints
                if !banner_info.os_hints.is_empty() {
                    Output::item("Operating System", &banner_info.os_hints.join(", "));
                }

                // Display if banner was modified
                if banner_info.is_modified {
                    Output::warning("⚠ Server header appears to be modified/customized");
                }

                // Display custom fields (e.g., build info, modules)
                for (key, value) in &banner_info.custom_fields {
                    let label = key
                        .chars()
                        .enumerate()
                        .map(|(i, c)| {
                            if i == 0 {
                                c.to_uppercase().to_string()
                            } else {
                                c.to_string()
                            }
                        })
                        .collect::<String>();
                    Output::item(&label, value);
                }

                // Display raw banner if modified
                if banner_info.is_modified {
                    Output::item("Raw Server Header", &banner_info.raw_banner);
                }
            } else {
                Output::warning("No Server header found in response");
                Output::info("Server may be hiding version information for security");
            }
        }

        println!();
        if (200..300).contains(&response.status_code) {
            Output::success("Request successful");
        } else if response.status_code >= 400 {
            Output::warning(&format!("Client/Server error: {}", response.status_code));
        }

        Ok(())
    }

    fn http2(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx
            .target
            .as_ref()
            .ok_or("Missing URL. Usage: rb web asset http2 <https-url>")?;

        Validator::validate_url(url)?;
        let (_host, _port, authority, _path) = Self::parse_https_url(url)?;

        let method = ctx.get_flag_or("method", "GET").to_uppercase();

        let mut headers = Self::collect_request_headers(ctx)?;

        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("accept"))
        {
            headers.push(("accept".to_string(), "*/*".to_string()));
        }

        let body_bytes = if let Some(body_inline) = ctx.get_flag("body") {
            Some(body_inline.clone().into_bytes())
        } else if let Some(body_path) = ctx.get_flag("body-file") {
            let data = fs::read(&body_path)
                .map_err(|e| format!("Failed to read body file {}: {}", body_path, e))?;
            Some(data)
        } else {
            None
        };

        let _timeout = ctx
            .get_flag("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(15);

        let http2_headers: Vec<Header> = headers
            .iter()
            .map(|(k, v)| Header::new(k.as_str(), v.as_str()))
            .collect();

        let mut request = Http2Request::new(&method, url)?;
        request.headers = http2_headers;
        request.body = body_bytes;

        let dispatcher = Http2Dispatcher::new().with_middleware(Arc::new(Http2LoggingMiddleware));
        let mut collector = BufferingHttp2Handler::default();
        let (head, _) = dispatcher.send_with_handler(request.clone(), &mut collector)?;

        let response = Http2Response {
            status: head.status,
            headers: head.headers,
            body: collector.body,
        };

        self.maybe_persist_http2(ctx, url, &method, &request.authority, &response)?;

        let format = ctx.get_output_format();
        if format == OutputFormat::Json {
            self.render_http2_json(url, &method, &request.authority, &response)?;
        } else {
            self.render_http2_response(url, &method, &response)?;
        }

        Ok(())
    }

    fn render_http2_response(
        &self,
        url: &str,
        method: &str,
        response: &Http2Response,
    ) -> Result<(), String> {
        Output::success(&format!("HTTP/2 {} {}", method, url));
        Output::item("Status", &response.status.to_string());

        if !response.headers.is_empty() {
            Output::subheader("Response Headers");
            for header in &response.headers {
                println!("{}: {}", header.name, header.value);
            }
        }

        if !response.body.is_empty() {
            println!();
            println!("{}", String::from_utf8_lossy(&response.body));
            println!();
            Output::info(&format!("Body size: {} bytes", response.body.len()));
        }

        Ok(())
    }

    fn render_http2_json(
        &self,
        url: &str,
        method: &str,
        authority: &str,
        response: &Http2Response,
    ) -> Result<(), String> {
        println!("{{");
        println!("  \"request\": {{");
        println!("    \"url\": \"{}\",", escape_json(url));
        println!("    \"method\": \"{}\",", escape_json(method));
        println!("    \"authority\": \"{}\"", escape_json(authority));
        println!("  }},");
        println!("  \"response\": {{");
        println!("    \"status\": {},", response.status);
        println!("    \"headers\": [");
        for (idx, header) in response.headers.iter().enumerate() {
            let comma = if idx + 1 < response.headers.len() {
                ","
            } else {
                ""
            };
            println!(
                "      {{ \"name\": \"{}\", \"value\": \"{}\" }}{}",
                escape_json(&header.name),
                escape_json(&header.value),
                comma
            );
        }
        println!("    ],");
        println!(
            "    \"body_text\": \"{}\",",
            escape_json(&String::from_utf8_lossy(&response.body))
        );
        println!("    \"body_size\": {}", response.body.len());
        println!("  }}");

        println!("}}");

        Ok(())
    }

    fn headers(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset headers <URL> Example: rb web asset headers http://example.com",
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset headers")?;

        let format = ctx.get_output_format();

        let client = HttpClient::new();
        let mut request = HttpRequest::get(url);
        if let Some(profile_str) = ctx.get_flag("impersonate") {
            if let Some(profile) = TlsProfile::from_str(&profile_str) {
                request = request.with_tls_profile(profile);
            } else {
                Output::warning(&format!("Unknown impersonation profile: {}", profile_str));
                Output::info("Available profiles: chrome, firefox, safari");
            }
        }

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start("Fetching headers");
        }

        let response = client
            .send(&request)
            .map_err(|e| format!("Request failed: {}", e))?;

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_done();
        }

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"url\": \"{}\",", url);
            println!("  \"status_code\": {},", response.status_code);
            println!("  \"status_text\": \"{}\",", response.status_text);
            println!("  \"header_count\": {},", response.headers.len());
            println!("  \"headers\": {{");
            let header_count = response.headers.len();
            for (i, (key, value)) in response.headers.iter().enumerate() {
                let comma = if i < header_count - 1 { "," } else { "" };
                let value_escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
                println!("    \"{}\": \"{}\"{}", key, value_escaped, comma);
            }
            println!("  }}");
            println!("}}");
            self.maybe_persist_http(ctx, url, &request, &response)?;
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("url: {}", url);
            println!("status_code: {}", response.status_code);
            println!("status_text: {}", response.status_text);
            println!("header_count: {}", response.headers.len());
            println!("headers:");
            for (key, value) in &response.headers {
                println!("  {}: \"{}\"", key, value.replace('"', "\\\""));
            }
            self.maybe_persist_http(ctx, url, &request, &response)?;
            return Ok(());
        }

        // Human output
        Output::header("HTTP Headers Analysis");
        Output::item("URL", url);
        println!();

        Output::subheader(&format!(
            "Status: {} {}",
            response.status_code, response.status_text
        ));
        println!();

        Output::table_header(&["HEADER", "VALUE"]);
        for (key, value) in &response.headers {
            Output::table_row(&[key, value]);
        }

        println!();
        Output::success(&format!("Found {} headers", response.headers.len()));

        self.maybe_persist_http(ctx, url, &request, &response)?;

        Ok(())
    }

    fn security(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset security <URL> Example: rb web asset security http://example.com",
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset security")?;

        let format = ctx.get_output_format();

        let client = HttpClient::new();

        if format == crate::cli::format::OutputFormat::Human {
            Output::spinner_start("Analyzing security");
        }

        let response = client
            .get(url)
            .map_err(|e| format!("Request failed: {}", e))?;

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

        let host = Self::extract_host(url);
        let attributes =
            build_partition_attributes(ctx, &host, [("operation", "security"), ("url", url)]);
        let mut pm = StorageService::global().persistence_for_target_with(
            &host,
            persist_flag,
            None,
            attributes,
        )?;

        // Save security audit to database
        if pm.is_enabled() {
            let record = HttpHeadersRecord {
                host: host.clone(),
                url: url.to_string(),
                method: "GET".to_string(),
                scheme: if url.starts_with("https://") {
                    "https".to_string()
                } else {
                    "http".to_string()
                },
                http_version: "HTTP/1.1".to_string(),
                status_code: response.status_code,
                status_text: response.status_text.clone(),
                server: response.headers.get("server").map(|s| s.to_string()),
                body_size: response.body.len() as u32,
                headers: response
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                timestamp: 0, // Will be set by PersistenceManager
                tls: None,
            };

            if let Err(e) = pm.add_http_capture(record) {
                eprintln!("Warning: Failed to save security audit to database: {}", e);
            } else if format == crate::cli::format::OutputFormat::Human {
                Output::success(&format!("✓ Saved to {}.rdb", host));
            }
        }

        let security_headers = vec![
            ("Strict-Transport-Security", "HSTS - Forces HTTPS"),
            ("X-Frame-Options", "Prevents clickjacking"),
            ("X-Content-Type-Options", "Prevents MIME sniffing"),
            ("X-XSS-Protection", "XSS filter"),
            ("Content-Security-Policy", "CSP - Prevents XSS/injection"),
            ("Referrer-Policy", "Controls referrer information"),
            ("Permissions-Policy", "Controls browser features"),
        ];

        // JSON output
        if format == crate::cli::format::OutputFormat::Json {
            println!("{{");
            println!("  \"url\": \"{}\",", url);
            println!("  \"security_headers\": [");
            for (i, (header, description)) in security_headers.iter().enumerate() {
                let comma = if i < security_headers.len() - 1 {
                    ","
                } else {
                    ""
                };
                let present = response.headers.get(*header).is_some();
                println!("    {{");
                println!("      \"header\": \"{}\",", header);
                println!("      \"description\": \"{}\",", description);
                println!("      \"present\": {},", present);
                if present {
                    let value = response.headers.get(*header).unwrap();
                    let value_escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
                    println!("      \"value\": \"{}\"", value_escaped);
                } else {
                    println!("      \"value\": null");
                }
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            // Already persisted above
            return Ok(());
        }

        // YAML output
        if format == crate::cli::format::OutputFormat::Yaml {
            println!("url: {}", url);
            println!("security_headers:");
            for (header, description) in security_headers.iter() {
                let present = response.headers.get(*header).is_some();
                println!("  - header: {}", header);
                println!("    description: {}", description);
                println!("    present: {}", present);
                if present {
                    let value = response.headers.get(*header).unwrap();
                    let value_escaped = value.replace('"', "\\\"");
                    println!("    value: \"{}\"", value_escaped);
                } else {
                    println!("    value: null");
                }
            }
            // Already persisted above
            return Ok(());
        }

        // Human output
        Output::header("Security Headers Audit");
        Output::item("URL", url);
        println!();

        Output::subheader("Security Headers");
        println!();

        for (header, description) in security_headers {
            if let Some(value) = response.headers.get(header) {
                Output::success(&format!("{}: {}", header, value));
                println!("  \x1b[2m{}\x1b[0m", description);
            } else {
                Output::error(&format!("{} is missing", header));
                println!("  \x1b[2m{}\x1b[0m", description);
            }
            println!();
        }

        // Already persisted above

        Ok(())
    }

    fn grade(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset grade <URL>\nExample: rb web asset grade https://example.com",
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset grade")?;

        let format = ctx.get_output_format();
        let client = HttpClient::new();

        if format == OutputFormat::Human {
            Output::spinner_start("Analyzing security headers");
        }

        let response = client
            .get(url)
            .map_err(|e| format!("Request failed: {}", e))?;

        if format == OutputFormat::Human {
            Output::spinner_done();
        }

        // Security grading system based on design.md
        // Base Score: 100, with deductions for missing/weak headers
        let mut score: i32 = 100;
        let mut findings: Vec<(&str, &str, i32, String)> = Vec::new(); // (header, status, deduction, details)

        // 1. HSTS Check (-20 if missing, -5 if max-age < 1 year)
        if let Some(hsts) = response.headers.get("Strict-Transport-Security") {
            // Check max-age
            let max_age = hsts
                .split(';')
                .find_map(|part| {
                    let part = part.trim();
                    if part.to_lowercase().starts_with("max-age=") {
                        part[8..].parse::<u64>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            let one_year = 31536000u64; // seconds
            if max_age < one_year {
                score -= 5;
                findings.push((
                    "Strict-Transport-Security",
                    "WEAK",
                    -5,
                    format!("max-age={} is less than 1 year (31536000s)", max_age),
                ));
            } else {
                let details = if hsts.to_lowercase().contains("includesubdomains") {
                    format!("✓ max-age={}, includeSubDomains", max_age)
                } else {
                    format!("✓ max-age={}", max_age)
                };
                findings.push(("Strict-Transport-Security", "PASS", 0, details));
            }
        } else {
            score -= 20;
            findings.push((
                "Strict-Transport-Security",
                "FAIL",
                -20,
                "Missing - enables downgrade attacks".to_string(),
            ));
        }

        // 2. CSP Check (-15 if missing, -10 for unsafe-inline, -10 for unsafe-eval, -5 for *)
        if let Some(csp) = response.headers.get("Content-Security-Policy") {
            let csp_lower = csp.to_lowercase();
            let mut csp_deductions = 0;
            let mut csp_issues: Vec<String> = Vec::new();

            if csp_lower.contains("'unsafe-inline'") {
                csp_deductions += 10;
                csp_issues.push("unsafe-inline".to_string());
            }
            if csp_lower.contains("'unsafe-eval'") {
                csp_deductions += 10;
                csp_issues.push("unsafe-eval".to_string());
            }
            // Check for wildcard in dangerous directives
            let dangerous_wildcards = ["script-src *", "default-src *", "object-src *"];
            for pattern in &dangerous_wildcards {
                if csp_lower.contains(pattern) {
                    csp_deductions += 5;
                    csp_issues.push(format!(
                        "wildcard in {}",
                        pattern.split(' ').next().unwrap_or("")
                    ));
                    break; // Only count once
                }
            }

            score -= csp_deductions;
            if csp_issues.is_empty() {
                findings.push((
                    "Content-Security-Policy",
                    "PASS",
                    0,
                    "Present and well-configured".to_string(),
                ));
            } else {
                findings.push((
                    "Content-Security-Policy",
                    "WARN",
                    -csp_deductions,
                    format!("Issues: {}", csp_issues.join(", ")),
                ));
            }
        } else {
            score -= 15;
            findings.push((
                "Content-Security-Policy",
                "FAIL",
                -15,
                "Missing - no XSS protection".to_string(),
            ));
        }

        // 3. X-Frame-Options (-10 if missing)
        if response.headers.get("X-Frame-Options").is_some() {
            findings.push((
                "X-Frame-Options",
                "PASS",
                0,
                "Present - prevents clickjacking".to_string(),
            ));
        } else {
            // Check if CSP has frame-ancestors (modern replacement)
            if let Some(csp) = response.headers.get("Content-Security-Policy") {
                if csp.to_lowercase().contains("frame-ancestors") {
                    findings.push((
                        "X-Frame-Options",
                        "PASS",
                        0,
                        "Not present, but CSP frame-ancestors is set".to_string(),
                    ));
                } else {
                    score -= 10;
                    findings.push((
                        "X-Frame-Options",
                        "FAIL",
                        -10,
                        "Missing - vulnerable to clickjacking".to_string(),
                    ));
                }
            } else {
                score -= 10;
                findings.push((
                    "X-Frame-Options",
                    "FAIL",
                    -10,
                    "Missing - vulnerable to clickjacking".to_string(),
                ));
            }
        }

        // 4. X-Content-Type-Options (-5 if missing)
        if response.headers.get("X-Content-Type-Options").is_some() {
            findings.push((
                "X-Content-Type-Options",
                "PASS",
                0,
                "Present - prevents MIME sniffing".to_string(),
            ));
        } else {
            score -= 5;
            findings.push((
                "X-Content-Type-Options",
                "FAIL",
                -5,
                "Missing - MIME sniffing possible".to_string(),
            ));
        }

        // 5. Referrer-Policy (informational, no deduction)
        if let Some(rp) = response.headers.get("Referrer-Policy") {
            findings.push(("Referrer-Policy", "PASS", 0, format!("Set to: {}", rp)));
        } else {
            findings.push((
                "Referrer-Policy",
                "INFO",
                0,
                "Not set (browser defaults apply)".to_string(),
            ));
        }

        // 6. Permissions-Policy (informational, no deduction)
        if response.headers.get("Permissions-Policy").is_some() {
            findings.push((
                "Permissions-Policy",
                "PASS",
                0,
                "Present - restricts browser features".to_string(),
            ));
        } else {
            findings.push((
                "Permissions-Policy",
                "INFO",
                0,
                "Not set (all features enabled)".to_string(),
            ));
        }

        // 7. Cross-Origin headers (informational)
        if response.headers.get("Cross-Origin-Opener-Policy").is_some() {
            findings.push((
                "Cross-Origin-Opener-Policy",
                "PASS",
                0,
                "Present".to_string(),
            ));
        }
        if response
            .headers
            .get("Cross-Origin-Embedder-Policy")
            .is_some()
        {
            findings.push((
                "Cross-Origin-Embedder-Policy",
                "PASS",
                0,
                "Present".to_string(),
            ));
        }
        if response
            .headers
            .get("Cross-Origin-Resource-Policy")
            .is_some()
        {
            findings.push((
                "Cross-Origin-Resource-Policy",
                "PASS",
                0,
                "Present".to_string(),
            ));
        }

        // Calculate grade
        let score = score.max(0); // Don't go below 0
        let grade = match score {
            100 => "A+",
            90..=99 => "A",
            80..=89 => "B",
            70..=79 => "C",
            60..=69 => "D",
            _ => "F",
        };

        // JSON output
        if format == OutputFormat::Json {
            println!("{{");
            println!("  \"url\": \"{}\",", url);
            println!("  \"score\": {},", score);
            println!("  \"grade\": \"{}\",", grade);
            println!("  \"findings\": [");
            for (i, (header, status, deduction, details)) in findings.iter().enumerate() {
                let comma = if i < findings.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"header\": \"{}\",", header);
                println!("      \"status\": \"{}\",", status);
                println!("      \"deduction\": {},", deduction);
                println!("      \"details\": \"{}\"", details.replace('"', "\\\""));
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
            return Ok(());
        }

        // YAML output
        if format == OutputFormat::Yaml {
            println!("url: {}", url);
            println!("score: {}", score);
            println!("grade: {}", grade);
            println!("findings:");
            for (header, status, deduction, details) in &findings {
                println!("  - header: {}", header);
                println!("    status: {}", status);
                println!("    deduction: {}", deduction);
                println!("    details: \"{}\"", details);
            }
            return Ok(());
        }

        // Human output
        Output::header(&format!("Security Grade: {}", url));
        println!();

        // Large grade display
        let grade_color = match grade {
            "A+" | "A" => "\x1b[32m", // Green
            "B" => "\x1b[92m",        // Light green
            "C" => "\x1b[33m",        // Yellow
            "D" => "\x1b[33m",        // Yellow
            _ => "\x1b[31m",          // Red
        };
        println!(
            "  {}┌─────────────────────────────────────────┐\x1b[0m",
            grade_color
        );
        println!(
            "  {}│  Grade: {}    Score: {}/100           │\x1b[0m",
            grade_color, grade, score
        );
        println!(
            "  {}└─────────────────────────────────────────┘\x1b[0m",
            grade_color
        );
        println!();

        // Findings table
        println!(
            "  {:<35} {:<8} {:<8} {}",
            "HEADER", "STATUS", "SCORE", "DETAILS"
        );
        println!("  {}", "─".repeat(90));

        for (header, status, deduction, details) in &findings {
            let status_display = match *status {
                "PASS" => "\x1b[32m✓ PASS\x1b[0m",
                "WARN" => "\x1b[33m⚠ WARN\x1b[0m",
                "FAIL" => "\x1b[31m✗ FAIL\x1b[0m",
                "INFO" => "\x1b[34mℹ INFO\x1b[0m",
                _ => status,
            };

            let deduction_str = if *deduction < 0 {
                format!("\x1b[31m{}\x1b[0m", deduction)
            } else {
                "0".to_string()
            };

            // Truncate details if too long
            let details_display = if details.len() > 40 {
                format!("{}...", &details[..37])
            } else {
                details.clone()
            };

            println!(
                "  {:<35} {:<16} {:<8} {}",
                header, status_display, deduction_str, details_display
            );
        }

        println!();

        // Recommendations
        let failed_headers: Vec<_> = findings
            .iter()
            .filter(|(_, s, _, _)| *s == "FAIL")
            .collect();
        if !failed_headers.is_empty() {
            Output::section("Recommendations");
            for (header, _, _, _) in failed_headers {
                match *header {
                    "Strict-Transport-Security" => {
                        println!("  • Add HSTS header:");
                        println!("    \x1b[2mStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\x1b[0m");
                    }
                    "Content-Security-Policy" => {
                        println!("  • Add CSP header:");
                        println!("    \x1b[2mContent-Security-Policy: default-src 'self'; script-src 'self'\x1b[0m");
                    }
                    "X-Frame-Options" => {
                        println!("  • Add X-Frame-Options header:");
                        println!("    \x1b[2mX-Frame-Options: DENY\x1b[0m");
                    }
                    "X-Content-Type-Options" => {
                        println!("  • Add X-Content-Type-Options header:");
                        println!("    \x1b[2mX-Content-Type-Options: nosniff\x1b[0m");
                    }
                    _ => {}
                }
            }
            println!();
        }

        // Summary
        match grade {
            "A+" => Output::success("Perfect security headers configuration!"),
            "A" => Output::success("Excellent security headers configuration"),
            "B" => Output::success("Good security - minor improvements possible"),
            "C" => Output::warning("Fair security - several improvements needed"),
            "D" => Output::warning("Poor security - action recommended"),
            _ => Output::error("Critical: Major security headers missing"),
        }

        Ok(())
    }

    fn maybe_persist_http(
        &self,
        ctx: &CliContext,
        url: &str,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<(), String> {
        let persist_flag = if ctx.has_flag("persist") {
            Some(true)
        } else if ctx.has_flag("no-persist") {
            Some(false)
        } else {
            None
        };

        let host = request.host().to_string();
        let attributes = build_partition_attributes(
            ctx,
            &host,
            [
                ("operation", ctx.verb.as_deref().unwrap_or("get")),
                ("url", url),
                ("method", request.method.as_str()),
            ],
        );
        let mut pm = StorageService::global().persistence_for_target_with(
            &host,
            persist_flag,
            None,
            attributes,
        )?;

        if pm.is_enabled() {
            let scheme = if request.is_https() { "https" } else { "http" };
            let server_header = response
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("server"))
                .map(|(_, value)| value.clone());
            let headers = response
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            let record = HttpHeadersRecord {
                host: host.clone(),
                url: url.to_string(),
                method: request.method.clone(),
                scheme: scheme.to_string(),
                http_version: request.version.clone(),
                status_code: response.status_code,
                status_text: response.status_text.clone(),
                server: server_header,
                body_size: response.body.len().min(u32::MAX as usize) as u32,
                headers,
                timestamp: Self::current_timestamp(),
                tls: None,
            };

            pm.add_http_capture(record)?;
            if let Some(path) = pm.commit()? {
                Output::success(&format!("Results saved to {}", path.display()));
            }
        }

        Ok(())
    }

    fn maybe_persist_http2(
        &self,
        ctx: &CliContext,
        url: &str,
        method: &str,
        authority: &str,
        response: &Http2Response,
    ) -> Result<(), String> {
        let persist_flag = if ctx.has_flag("persist") {
            Some(true)
        } else if ctx.has_flag("no-persist") {
            Some(false)
        } else {
            None
        };

        let host = Self::extract_host(url);
        let attributes = build_partition_attributes(
            ctx,
            &host,
            [
                ("operation", ctx.verb.as_deref().unwrap_or("http2")),
                ("url", url),
                ("method", method),
                ("authority", authority),
            ],
        );

        let mut pm = StorageService::global().persistence_for_target_with(
            &host,
            persist_flag,
            None,
            attributes,
        )?;

        if pm.is_enabled() {
            let server_header = response
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("server"))
                .map(|h| h.value.clone());
            let headers: Vec<(String, String)> = response
                .headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect();
            // HTTP/2 TLS snapshot not yet implemented
            let tls_snapshot = None;

            let record = HttpHeadersRecord {
                host: host.clone(),
                url: url.to_string(),
                method: method.to_string(),
                scheme: "https".to_string(),
                http_version: "HTTP/2".to_string(),
                status_code: response.status,
                status_text: String::new(),
                server: server_header,
                body_size: response.body.len().min(u32::MAX as usize) as u32,
                headers,
                timestamp: Self::current_timestamp(),
                tls: tls_snapshot,
            };

            pm.add_http_capture(record)?;
            if let Some(path) = pm.commit()? {
                Output::success(&format!("Results saved to {}", path.display()));
            }
        }

        Ok(())
    }

    fn cert(&self, _ctx: &CliContext) -> Result<(), String> {
        Err(
            "TLS certificate inspection temporarily disabled - use openssl s_client instead"
                .to_string(),
        )
    }

    fn fingerprint(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset fingerprint <URL> Example: rb web asset fingerprint http://example.com",
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset fingerprint")?;

        Output::header("Web Technology Fingerprinting");
        Output::item("URL", url);
        println!();

        let fingerprinter = WebFingerprinter::new();

        Output::spinner_start("Analyzing technologies");
        let result = fingerprinter.fingerprint(url)?;
        Output::spinner_done();

        // Display main findings
        println!();
        Output::subheader("Key Findings");
        println!();

        if let Some(ref cms) = result.cms {
            Output::item("CMS", cms);
        }

        if let Some(ref server) = result.web_server {
            Output::item("Web Server", server);
        }

        if let Some(ref lang) = result.programming_language {
            Output::item("Language", lang);
        }

        if !result.frameworks.is_empty() {
            Output::item("Frameworks", &result.frameworks.join(", "));
        }

        // Display all detected technologies
        if !result.technologies.is_empty() {
            println!();
            Output::subheader(&format!(
                "All Technologies ({} detected)",
                result.technologies.len()
            ));
            println!();

            println!(
                "  {:<30} {:<15} {:<12} {}",
                "TECHNOLOGY", "CATEGORY", "CONFIDENCE", "VERSION"
            );
            println!("  {}", "─".repeat(75));

            for tech in &result.technologies {
                let category = match tech.category {
                    crate::modules::web::fingerprinter::TechCategory::CMS => "CMS",
                    crate::modules::web::fingerprinter::TechCategory::Framework => "Framework",
                    crate::modules::web::fingerprinter::TechCategory::WebServer => "Web Server",
                    crate::modules::web::fingerprinter::TechCategory::Language => "Language",
                    crate::modules::web::fingerprinter::TechCategory::Library => "Library",
                    crate::modules::web::fingerprinter::TechCategory::CDN => "CDN",
                    crate::modules::web::fingerprinter::TechCategory::Analytics => "Analytics",
                    crate::modules::web::fingerprinter::TechCategory::Database => "Database",
                    crate::modules::web::fingerprinter::TechCategory::Other => "Other",
                };

                let confidence_color = match tech.confidence {
                    crate::modules::web::fingerprinter::Confidence::High => "\x1b[32m", // Green
                    crate::modules::web::fingerprinter::Confidence::Medium => "\x1b[33m", // Yellow
                    crate::modules::web::fingerprinter::Confidence::Low => "\x1b[36m",  // Cyan
                };

                let version = tech.version.as_ref().map(|v| v.as_str()).unwrap_or("-");

                println!(
                    "  {:<30} {:<15} {}{:<12}\x1b[0m {}",
                    tech.name, category, confidence_color, tech.confidence, version
                );
            }
        } else {
            println!();
            Output::warning("No technologies detected");
        }

        println!();
        Output::success("Fingerprinting completed");

        Ok(())
    }

    fn scan(&self, ctx: &CliContext) -> Result<(), String> {
        scanning::run_scan(ctx)
    }

    fn vuln_scan(&self, ctx: &CliContext) -> Result<(), String> {
        scanning::run_active_scan(ctx)
    }

    fn wpscan(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset wpscan <URL> Example: rb web asset wpscan http://example.com",
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset wpscan")?;

        Output::header("WordPress Security Scanner");
        Output::item("Target", url);
        println!();

        Output::spinner_start("Scanning WordPress installation");

        // Create scanner and run scan
        use crate::modules::web::strategies::wordpress::WPScanner;
        let scanner = WPScanner::new();
        let result = scanner.scan(url)?;

        Output::spinner_done();
        println!();

        // Display results
        if !result.is_wordpress {
            Output::info("Not a WordPress site");
            return Ok(());
        }

        Output::success("✓ WordPress Detected");

        if let Some(version) = &result.version {
            Output::item("Version", version);
        } else {
            Output::item("Version", "Unknown");
        }
        println!();

        // Display plugins
        if !result.plugins.is_empty() {
            Output::subheader(&format!("Plugins Found: {}", result.plugins.len()));
            for plugin in &result.plugins {
                let version_str = plugin.version.as_deref().unwrap_or("unknown");
                println!(
                    "  • {} ({})",
                    Output::colorize(&plugin.name, "cyan"),
                    version_str
                );
                println!("    Path: {}", plugin.path);
            }
            println!();
        }

        // Display themes
        if !result.themes.is_empty() {
            Output::subheader(&format!("Themes Found: {}", result.themes.len()));
            for theme in &result.themes {
                let version_str = theme.version.as_deref().unwrap_or("unknown");
                println!(
                    "  • {} ({})",
                    Output::colorize(&theme.name, "cyan"),
                    version_str
                );
                println!("    Path: {}", theme.path);
            }
            println!();
        }

        // Display users
        if !result.users.is_empty() {
            Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
            for user in &result.users {
                println!("  • {}", Output::colorize(user, "yellow"));
            }
            println!();
        }

        // Display vulnerabilities
        if !result.vulnerabilities.is_empty() {
            Output::warning(&format!(
                "⚠️  {} VULNERABILITIES FOUND:",
                result.vulnerabilities.len()
            ));
            println!();

            for vuln in &result.vulnerabilities {
                let severity_color = match vuln.severity {
                    crate::modules::web::strategies::wordpress::VulnSeverity::Critical => "red",
                    crate::modules::web::strategies::wordpress::VulnSeverity::High => "red",
                    crate::modules::web::strategies::wordpress::VulnSeverity::Medium => "yellow",
                    crate::modules::web::strategies::wordpress::VulnSeverity::Low => "blue",
                    crate::modules::web::strategies::wordpress::VulnSeverity::Info => "cyan",
                };

                println!(
                    "  {} | {}",
                    Output::colorize(&vuln.severity.to_string(), severity_color),
                    Output::colorize(&vuln.title, "white")
                );
                println!("    {}", vuln.description);
                if let Some(path) = &vuln.path {
                    println!("    Path: {}", path);
                }
                println!();
            }

            Output::warning("🚨 SECURITY ALERT: WordPress vulnerabilities detected!");
            Output::warning("   Review findings and apply security patches");
        } else {
            Output::success("✓ No known vulnerabilities detected");
        }

        Ok(())
    }

    fn drupal_scan(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset drupal-scan <URL> Example: rb web asset drupal-scan http://example.com",
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset drupal-scan")?;

        Output::header("Drupal Security Scanner");
        Output::item("Target", url);
        println!();

        Output::spinner_start("Scanning Drupal installation");

        // Create scanner and run scan
        use crate::modules::web::strategies::drupal::DrupalScanner;
        let scanner = DrupalScanner::new();
        let result = scanner.scan(url)?;

        Output::spinner_done();
        println!();

        // Display results
        if !result.is_drupal {
            Output::info("Not a Drupal site");
            return Ok(());
        }

        Output::success("✓ Drupal Detected");

        if let Some(version) = &result.version {
            Output::item("Version", version);
        } else {
            Output::item("Version", "Unknown");
        }
        println!();

        // Display modules
        if !result.modules.is_empty() {
            Output::subheader(&format!("Modules Found: {}", result.modules.len()));
            for module in &result.modules {
                let version_str = module.version.as_deref().unwrap_or("unknown");
                println!(
                    "  • {} ({})",
                    Output::colorize(&module.name, "cyan"),
                    version_str
                );
                println!("    Path: {}", module.path);
            }
            println!();
        }

        // Display themes
        if !result.themes.is_empty() {
            Output::subheader(&format!("Themes Found: {}", result.themes.len()));
            for theme in &result.themes {
                let version_str = theme.version.as_deref().unwrap_or("unknown");
                println!(
                    "  • {} ({})",
                    Output::colorize(&theme.name, "cyan"),
                    version_str
                );
                println!("    Path: {}", theme.path);
            }
            println!();
        }

        // Display users
        if !result.users.is_empty() {
            Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
            for user in &result.users {
                println!("  • {}", Output::colorize(user, "yellow"));
            }
            println!();
        }

        // Display config exposure
        if !result.config_exposure.is_empty() {
            Output::warning(&format!(
                "⚠️  {} CONFIGURATION FILES EXPOSED:",
                result.config_exposure.len()
            ));
            println!();
            for config in &result.config_exposure {
                println!(
                    "  • {} [{}] - Risk: {}",
                    Output::colorize(&config.path, "red"),
                    config.status,
                    config.risk
                );
            }
            println!();
        }

        // Display vulnerabilities
        if !result.vulnerabilities.is_empty() {
            Output::warning(&format!(
                "⚠️  {} VULNERABILITIES FOUND:",
                result.vulnerabilities.len()
            ));
            println!();

            for vuln in &result.vulnerabilities {
                let severity_color = match vuln.severity {
                    crate::modules::web::strategies::drupal::VulnSeverity::Critical => "red",
                    crate::modules::web::strategies::drupal::VulnSeverity::High => "red",
                    crate::modules::web::strategies::drupal::VulnSeverity::Medium => "yellow",
                    crate::modules::web::strategies::drupal::VulnSeverity::Low => "blue",
                };

                println!(
                    "  {} | {}",
                    Output::colorize(&vuln.severity.to_string(), severity_color),
                    Output::colorize(&vuln.title, "white")
                );
                println!("    {}", vuln.description);
                println!("    Affected: {}", vuln.affected_versions);
                if let Some(cve) = &vuln.cve {
                    println!("    CVE: {}", cve);
                }
                println!();
            }

            Output::warning("🚨 SECURITY ALERT: Drupal vulnerabilities detected!");
            Output::warning("   Review findings and apply security patches");
        } else {
            Output::success("✓ No known vulnerabilities detected");
        }

        Ok(())
    }

    fn joomla_scan(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset joomla-scan <URL> Example: rb web asset joomla-scan http://example.com",
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset joomla-scan")?;

        Output::header("Joomla Security Scanner");
        Output::item("Target", url);
        println!();

        Output::spinner_start("Scanning Joomla installation");

        // Create scanner and run scan
        use crate::modules::web::strategies::joomla::JoomlaScanner;
        let scanner = JoomlaScanner::new();
        let result = scanner.scan(url)?;

        Output::spinner_done();
        println!();

        // Display results
        if !result.is_joomla {
            Output::info("Not a Joomla site");
            return Ok(());
        }

        Output::success("✓ Joomla Detected");

        if let Some(version) = &result.version {
            Output::item("Version", version);
        } else {
            Output::item("Version", "Unknown");
        }
        println!();

        // Display extensions
        if !result.extensions.is_empty() {
            Output::subheader(&format!("Extensions Found: {}", result.extensions.len()));
            for ext in &result.extensions {
                let version_str = ext.version.as_deref().unwrap_or("unknown");
                println!(
                    "  • {} ({}) - {}",
                    Output::colorize(&ext.name, "cyan"),
                    version_str,
                    ext.ext_type
                );
                println!("    Path: {}", ext.path);
            }
            println!();
        }

        // Display templates
        if !result.templates.is_empty() {
            Output::subheader(&format!("Templates Found: {}", result.templates.len()));
            for template in &result.templates {
                let version_str = template.version.as_deref().unwrap_or("unknown");
                println!(
                    "  • {} ({})",
                    Output::colorize(&template.name, "cyan"),
                    version_str
                );
                println!("    Path: {}", template.path);
            }
            println!();
        }

        // Display users
        if !result.users.is_empty() {
            Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
            for user in &result.users {
                println!("  • {}", Output::colorize(user, "yellow"));
            }
            println!();
        }

        // Display config exposure
        if !result.config_exposure.is_empty() {
            Output::warning(&format!(
                "⚠️  {} CONFIGURATION FILES EXPOSED:",
                result.config_exposure.len()
            ));
            println!();
            for config in &result.config_exposure {
                println!(
                    "  • {} [{}] - Risk: {}",
                    Output::colorize(&config.path, "red"),
                    config.status,
                    config.risk
                );
            }
            println!();
        }

        // Display vulnerabilities
        if !result.vulnerabilities.is_empty() {
            Output::warning(&format!(
                "⚠️  {} VULNERABILITIES FOUND:",
                result.vulnerabilities.len()
            ));
            println!();

            for vuln in &result.vulnerabilities {
                let severity_color = match vuln.severity {
                    crate::modules::web::strategies::joomla::VulnSeverity::Critical => "red",
                    crate::modules::web::strategies::joomla::VulnSeverity::High => "red",
                    crate::modules::web::strategies::joomla::VulnSeverity::Medium => "yellow",
                    crate::modules::web::strategies::joomla::VulnSeverity::Low => "blue",
                };

                println!(
                    "  {} | {}",
                    Output::colorize(&vuln.severity.to_string(), severity_color),
                    Output::colorize(&vuln.title, "white")
                );
                println!("    {}", vuln.description);
                println!("    Affected: {}", vuln.affected_versions);
                if let Some(cve) = &vuln.cve {
                    println!("    CVE: {}", cve);
                }
                println!();
            }

            Output::warning("🚨 SECURITY ALERT: Joomla vulnerabilities detected!");
            Output::warning("   Review findings and apply security patches");
        } else {
            Output::success("✓ No known vulnerabilities detected");
        }

        Ok(())
    }

    fn cms_scan(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb web asset cms-scan <URL> [--strategy auto|wordpress|drupal|joomla]\nExample: rb web asset cms-scan http://example.com --strategy auto",
        )?;

        Validator::validate_url(url)?;

        let strategy_str = ctx
            .flags
            .get("strategy")
            .map(|s| s.as_str())
            .unwrap_or("auto");

        let strategy = ScanStrategy::from_str(strategy_str)?;

        Output::header(&format!("Unified CMS Scanner: {}", url));

        if strategy == ScanStrategy::AutoDetect {
            Output::info("🔍 Auto-detecting CMS/framework...");
        } else {
            Output::info(&format!("🎯 Using strategy: {:?}", strategy));
        }

        let scanner = UnifiedWebScanner::new();

        Output::spinner_start("Scanning");
        let result = scanner
            .scan(url, strategy)
            .map_err(|e| format!("Scan failed: {}", e))?;
        Output::spinner_done();

        // Display results based on detected CMS
        match result {
            UnifiedScanResult::WordPress(wp_result) => {
                let version_str = wp_result
                    .version
                    .as_ref()
                    .map(|v| v.as_str())
                    .unwrap_or("unknown");
                Output::success(&format!("✓ Detected: WordPress {}", version_str));
                self.display_wp_results(&wp_result)?;
            }
            UnifiedScanResult::Drupal(drupal_result) => {
                let version_str = drupal_result
                    .version
                    .as_ref()
                    .map(|v| v.as_str())
                    .unwrap_or("unknown");
                Output::success(&format!("✓ Detected: Drupal {}", version_str));
                self.display_drupal_results(&drupal_result)?;
            }
            UnifiedScanResult::Joomla(joomla_result) => {
                let version_str = joomla_result
                    .version
                    .as_ref()
                    .map(|v| v.as_str())
                    .unwrap_or("unknown");
                Output::success(&format!("✓ Detected: Joomla {}", version_str));
                self.display_joomla_results(&joomla_result)?;
            }
            UnifiedScanResult::Strapi(_) => {
                Output::success("✓ Detected: Strapi");
                Output::info("Strapi-specific scanner results (coming soon)");
            }
            UnifiedScanResult::Ghost(_) => {
                Output::success("✓ Detected: Ghost");
                Output::info("Ghost-specific scanner results (coming soon)");
            }
            UnifiedScanResult::Directus(_) => {
                Output::success("✓ Detected: Directus");
                Output::info("Directus-specific scanner results (coming soon)");
            }
            UnifiedScanResult::Laravel(laravel_result) => {
                let version = laravel_result
                    .version_hint
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                Output::success(&format!("✓ Detected: Laravel {}", version));
                self.display_laravel_results(&laravel_result)?;
            }
            UnifiedScanResult::Django(django_result) => {
                let version = django_result
                    .version_hint
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                Output::success(&format!("✓ Detected: Django {}", version));
                self.display_django_results(&django_result)?;
            }
            UnifiedScanResult::Generic(vuln_result) => {
                Output::warning("⚠️  No specific CMS detected, running generic scan");
                Output::info(&format!(
                    "Found {} potential issues",
                    vuln_result.findings.len()
                ));
            }
            UnifiedScanResult::NotDetected(_) => {
                Output::warning("⚠️  Could not detect CMS type");
                Output::info(
                    "Try specifying --strategy manually (wordpress, drupal, joomla, etc.)",
                );
            }
        }

        Ok(())
    }

    // Helper methods to display CMS-specific results
    fn display_wp_results(
        &self,
        result: &crate::modules::web::strategies::wordpress::WPScanResult,
    ) -> Result<(), String> {
        use crate::modules::web::strategies::wordpress::VulnSeverity;

        // Display plugins
        if !result.plugins.is_empty() {
            Output::subheader(&format!("Plugins Detected: {}", result.plugins.len()));
            for plugin in &result.plugins {
                println!("  • {}", Output::colorize(&plugin.name, "cyan"));
            }
            println!();
        }

        // Display themes
        if !result.themes.is_empty() {
            Output::subheader(&format!("Themes Detected: {}", result.themes.len()));
            for theme in &result.themes {
                println!("  • {}", Output::colorize(&theme.name, "blue"));
            }
            println!();
        }

        // Display users
        if !result.users.is_empty() {
            Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
            for user in &result.users {
                println!("  • {}", Output::colorize(user, "yellow"));
            }
            println!();
        }

        // Display vulnerabilities
        if !result.vulnerabilities.is_empty() {
            Output::subheader(&format!(
                "🔴 VULNERABILITIES: {}",
                result.vulnerabilities.len()
            ));
            for vuln in &result.vulnerabilities {
                let severity_color = match vuln.severity {
                    VulnSeverity::Critical => "red",
                    VulnSeverity::High => "red",
                    VulnSeverity::Medium => "yellow",
                    VulnSeverity::Low => "cyan",
                    VulnSeverity::Info => "white",
                };
                println!(
                    "  {} {}",
                    Output::colorize(&format!("[{:?}]", vuln.severity), severity_color),
                    vuln.title
                );
            }
            Output::warning("🚨 SECURITY ALERT: WordPress vulnerabilities detected!");
        } else {
            Output::success("✓ No known vulnerabilities detected");
        }

        Ok(())
    }

    fn display_laravel_results(
        &self,
        result: &crate::modules::web::strategies::laravel::LaravelScanResult,
    ) -> Result<(), String> {
        use crate::modules::web::strategies::laravel::FindingSeverity;

        if !result.vulnerabilities.is_empty() {
            Output::subheader(&format!(
                "Laravel Findings: {}",
                result.vulnerabilities.len()
            ));
            for finding in &result.vulnerabilities {
                let (label, color) = match finding.severity {
                    FindingSeverity::Critical => ("CRITICAL", "red"),
                    FindingSeverity::High => ("HIGH", "red"),
                    FindingSeverity::Medium => ("MEDIUM", "yellow"),
                    FindingSeverity::Low => ("LOW", "cyan"),
                    FindingSeverity::Info => ("INFO", "blue"),
                };

                println!("  [{}] {}", Output::colorize(label, color), finding.title);
                println!("      {}", finding.description);
                if let Some(evidence) = &finding.evidence {
                    println!("      Evidence: {}", evidence);
                }
                println!("      Fix: {}", finding.remediation);
                println!();
            }
        } else {
            Output::info("No high-impact Laravel misconfigurations uncovered");
        }

        Output::subheader("Signals");
        if result.debug_signals {
            Output::warning("• Debug tooling detected (Debugbar/Ignition)");
        } else {
            Output::info("• Debug tooling was not observed");
        }
        if result.env_exposed {
            Output::error("• .env file exposed to unauthenticated users");
        }
        if result.horizon_exposed {
            Output::warning("• Horizon metrics API reachable");
        }
        if result.telescope_exposed {
            Output::warning("• Telescope dashboard reachable");
        }
        if result.storage_logs_exposed {
            Output::warning("• Application logs readable via the web root");
        }
        if result.ignition_health_endpoint {
            Output::warning("• Ignition health-check endpoint enabled");
        }

        if !result.interesting_endpoints.is_empty() {
            Output::subheader("Interesting Endpoints");
            for endpoint in &result.interesting_endpoints {
                println!("  • {}", endpoint);
            }
        }

        Ok(())
    }

    fn display_django_results(
        &self,
        result: &crate::modules::web::strategies::django::DjangoScanResult,
    ) -> Result<(), String> {
        use crate::modules::web::strategies::django::DjangoSeverity;

        if !result.findings.is_empty() {
            Output::subheader(&format!("Django Findings: {}", result.findings.len()));
            for finding in &result.findings {
                let (label, color) = match finding.severity {
                    DjangoSeverity::Critical => ("CRITICAL", "red"),
                    DjangoSeverity::High => ("HIGH", "red"),
                    DjangoSeverity::Medium => ("MEDIUM", "yellow"),
                    DjangoSeverity::Low => ("LOW", "cyan"),
                    DjangoSeverity::Info => ("INFO", "blue"),
                };

                println!("  [{}] {}", Output::colorize(label, color), finding.title);
                println!("      {}", finding.description);
                if let Some(evidence) = &finding.evidence {
                    println!("      Evidence: {}", evidence);
                }
                println!("      Fix: {}", finding.remediation);
                println!();
            }
        } else {
            Output::info("No high-impact Django misconfigurations uncovered");
        }

        Output::subheader("Signals");
        if result.admin_login_exposed {
            Output::warning("• Admin login available at /admin/");
        }
        if result.debug_toolbar_exposed {
            Output::warning("• Debug toolbar exposed (__debug__)");
        }
        if result.env_exposed {
            Output::error("• Environment secrets accessible via .env");
        }
        if result.sqlite_database_exposed {
            Output::error("• SQLite database downloadable via HTTP");
        }
        if result.settings_exposed {
            Output::warning("• settings.py reachable through the web server");
        }

        if !result.interesting_endpoints.is_empty() {
            Output::subheader("Interesting Endpoints");
            for endpoint in &result.interesting_endpoints {
                println!("  • {}", endpoint);
            }
        }

        Ok(())
    }

    fn display_drupal_results(
        &self,
        result: &crate::modules::web::strategies::drupal::DrupalScanResult,
    ) -> Result<(), String> {
        use crate::modules::web::strategies::drupal::VulnSeverity;

        // Display modules
        if !result.modules.is_empty() {
            Output::subheader(&format!("Modules Detected: {}", result.modules.len()));
            for module in &result.modules {
                println!("  • {}", Output::colorize(&module.name, "cyan"));
            }
            println!();
        }

        // Display themes
        if !result.themes.is_empty() {
            Output::subheader(&format!("Themes Detected: {}", result.themes.len()));
            for theme in &result.themes {
                println!("  • {}", Output::colorize(&theme.name, "blue"));
            }
            println!();
        }

        // Display vulnerabilities
        if !result.vulnerabilities.is_empty() {
            Output::subheader(&format!(
                "🔴 VULNERABILITIES: {}",
                result.vulnerabilities.len()
            ));
            for vuln in &result.vulnerabilities {
                let severity_color = match vuln.severity {
                    VulnSeverity::Critical => "red",
                    VulnSeverity::High => "red",
                    VulnSeverity::Medium => "yellow",
                    VulnSeverity::Low => "cyan",
                };
                println!(
                    "  {} {}",
                    Output::colorize(&format!("[{:?}]", vuln.severity), severity_color),
                    vuln.title
                );
            }
            Output::warning("🚨 SECURITY ALERT: Drupal vulnerabilities detected!");
        } else {
            Output::success("✓ No known vulnerabilities detected");
        }

        Ok(())
    }

    fn display_joomla_results(
        &self,
        result: &crate::modules::web::strategies::joomla::JoomlaScanResult,
    ) -> Result<(), String> {
        use crate::modules::web::strategies::joomla::VulnSeverity;

        // Display extensions
        if !result.extensions.is_empty() {
            Output::subheader(&format!("Extensions Detected: {}", result.extensions.len()));
            for ext in &result.extensions {
                println!(
                    "  • {} ({:?})",
                    Output::colorize(&ext.name, "cyan"),
                    ext.ext_type
                );
            }
            println!();
        }

        // Display users
        if !result.users.is_empty() {
            Output::subheader(&format!("Users Enumerated: {}", result.users.len()));
            for user in &result.users {
                println!("  • {}", Output::colorize(user, "yellow"));
            }
            println!();
        }

        // Display vulnerabilities
        if !result.vulnerabilities.is_empty() {
            Output::subheader(&format!(
                "🔴 VULNERABILITIES: {}",
                result.vulnerabilities.len()
            ));
            for vuln in &result.vulnerabilities {
                let severity_color = match vuln.severity {
                    VulnSeverity::Critical => "red",
                    VulnSeverity::High => "red",
                    VulnSeverity::Medium => "yellow",
                    VulnSeverity::Low => "cyan",
                };
                println!(
                    "  {} {}",
                    Output::colorize(&format!("[{:?}]", vuln.severity), severity_color),
                    vuln.title
                );
            }
            Output::warning("🚨 SECURITY ALERT: Joomla vulnerabilities detected!");
        } else {
            Output::success("✓ No known vulnerabilities detected");
        }

        Ok(())
    }

    fn crawl(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset crawl <URL> [--depth N] [--max-pages N] Example: rb web asset crawl http://example.com",
        )?;

        Validator::validate_url(url)?;

        Output::header("Web Crawler - Site Mapping");
        Output::item("Target", url);

        // Parse options
        let max_depth = ctx
            .get_flag("depth")
            .or_else(|| ctx.get_flag("d"))
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(3);

        let max_pages = ctx
            .get_flag("max-pages")
            .or_else(|| ctx.get_flag("m"))
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(100);

        let same_origin = !ctx.has_flag("external");

        Output::item("Max Depth", &max_depth.to_string());
        Output::item("Max Pages", &max_pages.to_string());
        Output::item("Same Origin", if same_origin { "Yes" } else { "No" });
        println!();

        Output::spinner_start("Crawling website");

        // Create crawler
        let mut crawler = WebCrawler::new()
            .with_max_depth(max_depth)
            .with_max_pages(max_pages)
            .with_same_origin(same_origin);

        // Crawl
        let result = crawler.crawl(url)?;

        Output::spinner_done();

        // Display results
        Output::success(&format!(
            "Crawled {} pages (depth: {})",
            result.total_urls, result.max_depth_reached
        ));
        println!();

        // Group pages by depth
        let mut by_depth: std::collections::HashMap<usize, Vec<&str>> =
            std::collections::HashMap::new();

        for page in &result.pages {
            by_depth
                .entry(page.depth)
                .or_insert_with(Vec::new)
                .push(&page.url);
        }

        // Display pages by depth
        for depth in 0..=result.max_depth_reached {
            if let Some(urls) = by_depth.get(&depth) {
                println!(
                    "\x1b[1m\x1b[36m● Depth {}\x1b[0m ({} pages)",
                    depth,
                    urls.len()
                );

                // Show first 5 URLs per depth
                for (i, url) in urls.iter().take(5).enumerate() {
                    println!("  {}. {}", i + 1, url);
                }

                if urls.len() > 5 {
                    println!("  \x1b[90m... and {} more\x1b[0m", urls.len() - 5);
                }

                println!();
            }
        }

        // Display forms found
        let total_forms: usize = result.pages.iter().map(|p| p.forms.len()).sum();
        if total_forms > 0 {
            println!(
                "\x1b[1m\x1b[33m● Forms Found\x1b[0m ({} total)",
                total_forms
            );

            let mut form_count = 0;
            for page in &result.pages {
                for form in &page.forms {
                    if form_count >= 5 {
                        break;
                    }
                    println!(
                        "  {} {} (inputs: {:?})",
                        form.method, form.action, form.inputs
                    );
                    form_count += 1;
                }
                if form_count >= 5 {
                    break;
                }
            }

            if total_forms > 5 {
                println!("  \x1b[90m... and {} more\x1b[0m", total_forms - 5);
            }

            println!();
        }

        // Display assets summary
        let total_js: usize = result
            .pages
            .iter()
            .map(|p| {
                p.assets
                    .iter()
                    .filter(|a| a.asset_type == crate::modules::web::crawler::AssetType::JavaScript)
                    .count()
            })
            .sum();

        let total_css: usize = result
            .pages
            .iter()
            .map(|p| {
                p.assets
                    .iter()
                    .filter(|a| a.asset_type == crate::modules::web::crawler::AssetType::CSS)
                    .count()
            })
            .sum();

        let total_images: usize = result
            .pages
            .iter()
            .map(|p| {
                p.assets
                    .iter()
                    .filter(|a| a.asset_type == crate::modules::web::crawler::AssetType::Image)
                    .count()
            })
            .sum();

        if total_js + total_css + total_images > 0 {
            println!("\x1b[1m\x1b[35m● Assets Discovered\x1b[0m");
            println!("  JavaScript: {}", total_js);
            println!("  CSS: {}", total_css);
            println!("  Images: {}", total_images);
            println!();
        }

        // Statistics
        println!("\x1b[1mStatistics:\x1b[0m");
        println!("  Pages crawled: {}", result.total_urls);
        println!("  Total links found: {}", result.total_links);
        println!("  Max depth reached: {}", result.max_depth_reached);
        println!("  Forms discovered: {}", total_forms);
        println!("  Assets found: {}", total_js + total_css + total_images);

        Ok(())
    }

    fn linkfinder(&self, ctx: &CliContext) -> Result<(), String> {
        let js_url = ctx.target.as_ref().ok_or(
            "Missing JavaScript URL. Usage: rb web asset linkfinder <js-url> [--type api|s3|websocket|graphql|all] Example: rb web asset linkfinder https://example.com/app.js",
        )?;

        Validator::validate_url(js_url)?;

        Output::header("LinkFinder - JS Endpoint Extractor");
        Output::item("Target", js_url);

        let filter_type = ctx.get_flag("type").or_else(|| ctx.get_flag("t"));
        if let Some(ref t) = filter_type {
            Output::item("Filter Type", t);
        }
        println!();

        Output::spinner_start("Extracting endpoints from JavaScript");

        let finder = LinkFinder::new();
        let endpoints = finder.extract_from_url(js_url)?;

        Output::spinner_done();

        if endpoints.is_empty() {
            Output::warning("No endpoints found in JavaScript file");
            return Ok(());
        }

        // Apply type filter if specified
        let filtered_endpoints = if let Some(ref type_filter) = filter_type {
            match type_filter.to_lowercase().as_str() {
                "api" => LinkFinder::filter_by_type(endpoints, EndpointType::ApiEndpoint),
                "s3" => LinkFinder::filter_by_type(endpoints, EndpointType::S3Bucket),
                "websocket" | "ws" => {
                    LinkFinder::filter_by_type(endpoints, EndpointType::WebSocket)
                }
                "graphql" | "gql" => LinkFinder::filter_by_type(endpoints, EndpointType::GraphQL),
                "cloud" => LinkFinder::filter_by_type(endpoints, EndpointType::CloudStorage),
                "relative" => LinkFinder::filter_by_type(endpoints, EndpointType::RelativePath),
                "absolute" | "url" => {
                    LinkFinder::filter_by_type(endpoints, EndpointType::AbsoluteUrl)
                }
                "all" => endpoints,
                _ => {
                    return Err(format!(
                        "Invalid type '{}'. Valid types: api, s3, websocket, graphql, cloud, relative, absolute, all",
                        type_filter
                    ));
                }
            }
        } else {
            endpoints
        };

        if filtered_endpoints.is_empty() {
            let filter_str = filter_type.as_ref().map(|s| s.as_str()).unwrap_or("all");
            Output::warning(&format!(
                "No endpoints found matching filter '{}'",
                filter_str
            ));
            return Ok(());
        }

        // Group by endpoint type
        let mut by_type: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();

        for endpoint in &filtered_endpoints {
            let type_name = match endpoint.endpoint_type {
                EndpointType::RelativePath => "Relative Paths",
                EndpointType::AbsoluteUrl => "Absolute URLs",
                EndpointType::ApiEndpoint => "API Endpoints",
                EndpointType::S3Bucket => "S3 Buckets",
                EndpointType::CloudStorage => "Cloud Storage",
                EndpointType::WebSocket => "WebSockets",
                EndpointType::GraphQL => "GraphQL",
            };
            by_type
                .entry(type_name.to_string())
                .or_insert_with(Vec::new)
                .push(endpoint.url.clone());
        }

        // Display results grouped by type
        Output::success(&format!("Found {} endpoints", filtered_endpoints.len()));
        println!();

        for (type_name, urls) in by_type.iter() {
            // Color based on type
            let color = match type_name.as_str() {
                "API Endpoints" => "\x1b[36m",  // Cyan
                "S3 Buckets" => "\x1b[33m",     // Yellow
                "Cloud Storage" => "\x1b[33m",  // Yellow
                "WebSockets" => "\x1b[35m",     // Magenta
                "GraphQL" => "\x1b[36m",        // Cyan
                "Relative Paths" => "\x1b[32m", // Green
                "Absolute URLs" => "\x1b[34m",  // Blue
                _ => "\x1b[0m",                 // Default
            };

            println!("{}● {}\x1b[0m ({} found)", color, type_name, urls.len());

            // Show first 10 URLs per type
            for (i, url) in urls.iter().take(10).enumerate() {
                println!("  {}. {}", i + 1, url);
            }

            if urls.len() > 10 {
                println!("  \x1b[90m... and {} more\x1b[0m", urls.len() - 10);
            }
            println!();
        }

        // Show statistics
        println!("\x1b[1mStatistics:\x1b[0m");
        println!("  Total endpoints: {}", filtered_endpoints.len());
        println!("  Unique types: {}", by_type.len());

        Ok(())
    }

    // ===== Scraping Commands - DOM-based Data Extraction =====

    fn scrape(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset scrape <URL> --select SELECTOR [--attr NAME]\nExample: rb web asset scrape http://example.com --select \"h1\" --attr class",
        )?;

        let selector = ctx.get_flag("select").or_else(|| ctx.get_flag("S")).ok_or(
            "Missing selector. Use --select or -S to specify a CSS selector\nExample: rb web asset scrape http://example.com --select \"div.content p\"",
        )?;

        Validator::validate_url(url)?;

        Output::header("Web Scraper - CSS Selector Extraction");
        Output::item("URL", url);
        Output::item("Selector", &selector);

        let attr = ctx.get_flag("attr").or_else(|| ctx.get_flag("a"));
        if let Some(ref a) = attr {
            Output::item("Attribute", a);
        }

        let format_str = ctx.get_flag("format");
        let format = format_str.as_deref().unwrap_or("text");
        println!();

        Output::spinner_start("Fetching page and extracting data");

        // Fetch HTML
        let client = HttpClient::new();
        let response = client.get(url)?;
        let html = String::from_utf8_lossy(&response.body);

        // Parse DOM
        let doc = Document::parse(&html);

        // Select elements
        let elements = doc.select(&selector);

        Output::spinner_done();

        if elements.is_empty() {
            Output::warning(&format!("No elements match selector: {}", selector));
            return Ok(());
        }

        Output::success(&format!("Found {} matching elements", elements.len()));
        println!();

        if format == "json" {
            // JSON output
            println!("[");
            for (i, elem) in elements.iter().enumerate() {
                let value = if let Some(ref attr_name) = attr {
                    elem.attr(attr_name).cloned().unwrap_or_default()
                } else {
                    elem.text()
                };
                let escaped = escape_json(&value);
                if i < elements.len() - 1 {
                    println!("  \"{}\",", escaped);
                } else {
                    println!("  \"{}\"", escaped);
                }
            }
            println!("]");
        } else {
            // Text output
            for (i, elem) in elements.iter().enumerate() {
                let value = if let Some(ref attr_name) = attr {
                    elem.attr(attr_name).cloned().unwrap_or_default()
                } else {
                    elem.text()
                };
                println!("{:3}. {}", i + 1, value);
            }
        }

        Ok(())
    }

    fn links(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset links <URL> [--link-type internal|external|all]\nExample: rb web asset links http://example.com",
        )?;

        Validator::validate_url(url)?;

        Output::header("Link Extractor");
        Output::item("URL", url);

        let link_type_str = ctx.get_flag("link-type").or_else(|| ctx.get_flag("type"));
        let link_type = link_type_str.as_deref().unwrap_or("all");

        Output::item("Filter", &link_type);
        println!();

        Output::spinner_start("Extracting links from page");

        // Fetch HTML
        let client = HttpClient::new();
        let response = client.get(url)?;
        let html = String::from_utf8_lossy(&response.body);

        // Parse and extract links
        let doc = Document::parse(&html);
        let extracted_links = extractors::links(&doc);

        Output::spinner_done();

        // Get base domain for filtering
        let base_domain = Self::extract_host(url);

        let mut internal_links: Vec<&str> = Vec::new();
        let mut external_links: Vec<&str> = Vec::new();

        for link in &extracted_links {
            if link.url.contains(&base_domain)
                || link.href.starts_with('/')
                || link.href.starts_with('#')
            {
                internal_links.push(&link.url);
            } else if link.href.starts_with("http") {
                external_links.push(&link.url);
            } else {
                internal_links.push(&link.url); // Relative links are internal
            }
        }

        let show_internal = link_type == "all" || link_type == "internal";
        let show_external = link_type == "all" || link_type == "external";

        if show_internal && !internal_links.is_empty() {
            println!(
                "\x1b[1m\x1b[32m● Internal Links\x1b[0m ({} found)",
                internal_links.len()
            );
            for (i, link) in internal_links.iter().take(20).enumerate() {
                println!("  {:3}. {}", i + 1, link);
            }
            if internal_links.len() > 20 {
                println!(
                    "  \x1b[90m... and {} more\x1b[0m",
                    internal_links.len() - 20
                );
            }
            println!();
        }

        if show_external && !external_links.is_empty() {
            println!(
                "\x1b[1m\x1b[33m● External Links\x1b[0m ({} found)",
                external_links.len()
            );
            for (i, link) in external_links.iter().take(20).enumerate() {
                println!("  {:3}. {}", i + 1, link);
            }
            if external_links.len() > 20 {
                println!(
                    "  \x1b[90m... and {} more\x1b[0m",
                    external_links.len() - 20
                );
            }
            println!();
        }

        // Statistics
        println!("\x1b[1mStatistics:\x1b[0m");
        println!("  Internal: {}", internal_links.len());
        println!("  External: {}", external_links.len());
        println!("  Total: {}", extracted_links.len());

        Ok(())
    }

    fn images(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset images <URL>\nExample: rb web asset images http://example.com",
        )?;

        Validator::validate_url(url)?;

        Output::header("Image Extractor");
        Output::item("URL", url);
        println!();

        Output::spinner_start("Extracting images from page");

        // Fetch HTML
        let client = HttpClient::new();
        let response = client.get(url)?;
        let html = String::from_utf8_lossy(&response.body);

        // Parse and extract images
        let doc = Document::parse(&html);
        let images = extractors::images(&doc);

        Output::spinner_done();

        if images.is_empty() {
            Output::warning("No images found on page");
            return Ok(());
        }

        Output::success(&format!("Found {} images", images.len()));
        println!();

        // Display images grouped by type
        let mut with_alt: Vec<&extractors::ExtractedImage> = Vec::new();
        let mut without_alt: Vec<&extractors::ExtractedImage> = Vec::new();

        for img in &images {
            if img.alt.is_some() {
                with_alt.push(img);
            } else {
                without_alt.push(img);
            }
        }

        // Images with alt text (accessible)
        if !with_alt.is_empty() {
            println!(
                "\x1b[1m\x1b[32m● Images with Alt Text\x1b[0m ({} images)",
                with_alt.len()
            );
            for (i, img) in with_alt.iter().take(10).enumerate() {
                println!("  {:3}. {}", i + 1, img.url);
                if let Some(ref alt) = img.alt {
                    println!("       Alt: {}", alt);
                }
            }
            if with_alt.len() > 10 {
                println!("  \x1b[90m... and {} more\x1b[0m", with_alt.len() - 10);
            }
            println!();
        }

        // Images without alt text (accessibility issue)
        if !without_alt.is_empty() {
            println!(
                "\x1b[1m\x1b[33m● Images Without Alt Text\x1b[0m ({} images - accessibility issue)",
                without_alt.len()
            );
            for (i, img) in without_alt.iter().take(10).enumerate() {
                println!("  {:3}. {}", i + 1, img.url);
            }
            if without_alt.len() > 10 {
                println!("  \x1b[90m... and {} more\x1b[0m", without_alt.len() - 10);
            }
            println!();
        }

        // Statistics
        println!("\x1b[1mStatistics:\x1b[0m");
        println!("  Total images: {}", images.len());
        println!(
            "  With alt text: {} ({:.0}%)",
            with_alt.len(),
            (with_alt.len() as f64 / images.len() as f64) * 100.0
        );
        println!(
            "  Without alt text: {} ({:.0}%)",
            without_alt.len(),
            (without_alt.len() as f64 / images.len() as f64) * 100.0
        );

        Ok(())
    }

    fn meta(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset meta <URL>\nExample: rb web asset meta http://example.com",
        )?;

        Validator::validate_url(url)?;

        Output::header("Meta Tag & OpenGraph Extractor");
        Output::item("URL", url);
        println!();

        Output::spinner_start("Extracting meta information");

        // Fetch HTML
        let client = HttpClient::new();
        let response = client.get(url)?;
        let html = String::from_utf8_lossy(&response.body);

        // Parse DOM
        let doc = Document::parse(&html);

        // Extract meta information
        let meta_data = extractors::meta(&doc);

        // Extract OpenGraph data
        let og_data = extractors::open_graph(&doc);

        Output::spinner_done();

        // Display title
        println!("\x1b[1m\x1b[36m● Page Title\x1b[0m");
        println!("  {}", meta_data.title.as_deref().unwrap_or("(no title)"));
        println!();

        // Display standard meta tags
        println!("\x1b[1m\x1b[32m● Meta Tags\x1b[0m");
        if let Some(ref desc) = meta_data.description {
            println!("  \x1b[1mdescription\x1b[0m: {}", desc);
        }
        if !meta_data.keywords.is_empty() {
            println!(
                "  \x1b[1mkeywords\x1b[0m: {}",
                meta_data.keywords.join(", ")
            );
        }
        if let Some(ref author) = meta_data.author {
            println!("  \x1b[1mauthor\x1b[0m: {}", author);
        }
        if let Some(ref canonical) = meta_data.canonical {
            println!("  \x1b[1mcanonical\x1b[0m: {}", canonical);
        }
        if let Some(ref robots) = meta_data.robots {
            println!("  \x1b[1mrobots\x1b[0m: {}", robots);
        }
        if let Some(ref viewport) = meta_data.viewport {
            println!("  \x1b[1mviewport\x1b[0m: {}", viewport);
        }
        if let Some(ref charset) = meta_data.charset {
            println!("  \x1b[1mcharset\x1b[0m: {}", charset);
        }
        if let Some(ref lang) = meta_data.language {
            println!("  \x1b[1mlanguage\x1b[0m: {}", lang);
        }
        // Display other meta tags
        for (key, value) in &meta_data.other {
            println!("  \x1b[1m{}\x1b[0m: {}", key, value);
        }
        println!();

        // Display OpenGraph data
        let has_og = og_data.title.is_some()
            || og_data.description.is_some()
            || og_data.image.is_some()
            || og_data.url.is_some()
            || og_data.og_type.is_some();

        if has_og {
            println!("\x1b[1m\x1b[35m● OpenGraph Data\x1b[0m");
            if let Some(ref t) = og_data.title {
                println!("  \x1b[1mog:title\x1b[0m: {}", t);
            }
            if let Some(ref d) = og_data.description {
                println!("  \x1b[1mog:description\x1b[0m: {}", d);
            }
            if let Some(ref i) = og_data.image {
                println!("  \x1b[1mog:image\x1b[0m: {}", i);
            }
            if let Some(ref u) = og_data.url {
                println!("  \x1b[1mog:url\x1b[0m: {}", u);
            }
            if let Some(ref ot) = og_data.og_type {
                println!("  \x1b[1mog:type\x1b[0m: {}", ot);
            }
            if let Some(ref s) = og_data.site_name {
                println!("  \x1b[1mog:site_name\x1b[0m: {}", s);
            }
            println!();
        }

        // Statistics
        println!("\x1b[1mStatistics:\x1b[0m");
        let meta_count = meta_data.other.len()
            + if meta_data.description.is_some() {
                1
            } else {
                0
            };
        println!("  Meta tags: {}", meta_count);
        println!(
            "  OpenGraph: {}",
            if has_og { "Present" } else { "Not found" }
        );
        println!(
            "  SEO-ready: {}",
            if meta_data.title.is_some() && meta_data.description.is_some() {
                "Yes"
            } else {
                "Needs improvement"
            }
        );

        Ok(())
    }

    fn forms(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset forms <URL>\nExample: rb web asset forms http://example.com/login",
        )?;

        Validator::validate_url(url)?;

        Output::header("Form Extractor");
        Output::item("URL", url);
        println!();

        Output::spinner_start("Extracting forms from page");

        // Fetch HTML
        let client = HttpClient::new();
        let response = client.get(url)?;
        let html = String::from_utf8_lossy(&response.body);

        // Parse and extract forms
        let doc = Document::parse(&html);
        let forms = extractors::forms(&doc);

        Output::spinner_done();

        if forms.is_empty() {
            Output::warning("No forms found on page");
            return Ok(());
        }

        Output::success(&format!("Found {} forms", forms.len()));
        println!();

        for (i, form) in forms.iter().enumerate() {
            let action = if form.action.is_empty() {
                "(current page)"
            } else {
                &form.action
            };

            println!(
                "\x1b[1m\x1b[36m● Form #{}\x1b[0m [{} {}]",
                i + 1,
                form.method,
                action
            );

            if let Some(ref id) = form.id {
                println!("  ID: {}", id);
            }
            if let Some(ref name) = form.name {
                println!("  Name: {}", name);
            }

            // Display fields
            if !form.fields.is_empty() {
                println!("  \x1b[1mFields:\x1b[0m");
                for field in &form.fields {
                    let name = field.name.as_deref().unwrap_or("(unnamed)");
                    let required = if field.required { " *" } else { "" };

                    print!("    - [{}] {}{}", field.field_type, name, required);

                    if let Some(ref placeholder) = field.placeholder {
                        print!(" (placeholder: {})", placeholder);
                    }
                    if let Some(ref value) = field.value {
                        if !value.is_empty() {
                            print!(" = \"{}\"", value);
                        }
                    }
                    println!();
                }
            }

            println!();
        }

        // Security analysis
        println!("\x1b[1m\x1b[33m● Security Notes\x1b[0m");

        let has_password = forms
            .iter()
            .any(|f| f.fields.iter().any(|field| field.field_type == "password"));
        let uses_post = forms.iter().any(|f| f.method == "POST");

        if has_password && !url.starts_with("https://") {
            Output::warning("Password field found on non-HTTPS page!");
        }
        if has_password && !uses_post {
            Output::warning("Password form using GET method (credentials in URL)!");
        }
        if !has_password {
            println!("  No password fields detected");
        } else {
            println!("  Password fields present - ensure HTTPS and POST method");
        }

        Ok(())
    }

    fn tables(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset tables <URL> [--select SELECTOR]\nExample: rb web asset tables http://example.com/data",
        )?;

        Validator::validate_url(url)?;

        Output::header("Table Extractor");
        Output::item("URL", url);

        let selector = ctx.get_flag("select").or_else(|| ctx.get_flag("S"));
        if let Some(ref sel) = selector {
            Output::item("Selector", sel);
        }
        println!();

        Output::spinner_start("Extracting tables from page");

        // Fetch HTML
        let client = HttpClient::new();
        let response = client.get(url)?;
        let html = String::from_utf8_lossy(&response.body);

        // Parse and extract tables
        let doc = Document::parse(&html);
        let tables = extractors::tables(&doc);

        Output::spinner_done();

        if tables.is_empty() {
            Output::warning("No tables found on page");
            return Ok(());
        }

        Output::success(&format!("Found {} tables", tables.len()));
        println!();

        for (i, table) in tables.iter().enumerate() {
            println!(
                "\x1b[1m\x1b[36m● Table #{}\x1b[0m ({} rows × {} cols)",
                i + 1,
                table.rows.len(),
                table
                    .headers
                    .len()
                    .max(table.rows.first().map(|r| r.len()).unwrap_or(0))
            );

            // Display headers if present
            if !table.headers.is_empty() {
                print!("  \x1b[1m");
                for (j, header) in table.headers.iter().enumerate() {
                    if j > 0 {
                        print!(" | ");
                    }
                    print!("{}", header);
                }
                println!("\x1b[0m");
                println!("  {}", "-".repeat(60));
            }

            // Display first few rows
            for (row_idx, row) in table.rows.iter().take(5).enumerate() {
                print!("  ");
                for (col_idx, cell) in row.iter().enumerate() {
                    if col_idx > 0 {
                        print!(" | ");
                    }
                    // Truncate long cells
                    if cell.len() > 20 {
                        print!("{}...", &cell[..17]);
                    } else {
                        print!("{}", cell);
                    }
                }
                println!();

                if row_idx == 4 && table.rows.len() > 5 {
                    println!(
                        "  \x1b[90m... and {} more rows\x1b[0m",
                        table.rows.len() - 5
                    );
                }
            }

            println!();
        }

        // Statistics
        println!("\x1b[1mStatistics:\x1b[0m");
        println!("  Total tables: {}", tables.len());
        let total_rows: usize = tables.iter().map(|t| t.rows.len()).sum();
        println!("  Total rows: {}", total_rows);
        let with_headers = tables.iter().filter(|t| !t.headers.is_empty()).count();
        println!("  Tables with headers: {}", with_headers);

        Ok(())
    }

    // ===== HAR Commands - HTTP Archive Recording =====

    fn har_export(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset har-export <URL> [--output FILE]\nExample: rb web asset har-export http://example.com --output site.har",
        )?;

        Validator::validate_url(url)?;

        Output::header("HAR Export - HTTP Archive Recorder");
        Output::item("URL", url);

        // Get options
        let max_depth = ctx
            .get_flag("depth")
            .or_else(|| ctx.get_flag("d"))
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(2);

        let max_pages = ctx
            .get_flag("max-pages")
            .or_else(|| ctx.get_flag("m"))
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50);

        let output_file = ctx
            .get_flag("output")
            .or_else(|| ctx.get_flag("o"))
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // Generate filename from URL
                let host = Self::extract_host(url);
                format!("{}.har", host.replace(':', "_"))
            });

        Output::item("Output File", &output_file);
        Output::item("Max Depth", &max_depth.to_string());
        Output::item("Max Pages", &max_pages.to_string());
        println!();

        Output::spinner_start("Crawling and recording HTTP traffic");

        // Create crawler with HAR recording
        let mut crawler = WebCrawler::new()
            .with_max_depth(max_depth)
            .with_max_pages(max_pages)
            .with_same_origin(true)
            .with_har_recording(true);

        // Crawl
        let result = crawler.crawl(url)?;

        Output::spinner_done();

        // Export HAR file
        Output::spinner_start("Exporting HAR file");
        crawler.save_har(&output_file)?;
        Output::spinner_done();

        Output::success(&format!("HAR file exported: {}", output_file));
        println!();

        // Display summary
        println!("\x1b[1m\x1b[36m● Crawl Summary\x1b[0m");
        println!("  Pages crawled: {}", result.total_urls);
        println!("  Links found: {}", result.total_links);
        println!("  Max depth reached: {}", result.max_depth_reached);
        println!();

        // Get HAR stats from recorder
        if let Some(recorder) = crawler.har_recorder() {
            let guard = recorder.lock().unwrap();
            let har = &guard.har;
            println!("\x1b[1m\x1b[35m● HAR Summary\x1b[0m");
            println!("  Total entries: {}", har.log.entries.len());

            // Calculate total size
            let total_request_size: i64 = har.log.entries.iter().map(|e| e.request.body_size).sum();
            let total_response_size: i64 =
                har.log.entries.iter().map(|e| e.response.body_size).sum();

            println!("  Total request size: {} bytes", total_request_size.max(0));
            println!(
                "  Total response size: {} bytes",
                total_response_size.max(0)
            );

            // Calculate total time
            let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
            println!("  Total time: {:.2}ms", total_time);
        }

        Ok(())
    }

    fn har_view(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing HAR file. Usage: rb web asset har-view <file>\nExample: rb web asset har-view site.har",
        )?;

        Output::header("HAR Viewer - HTTP Archive Analyzer");
        Output::item("File", file_path);
        println!();

        Output::spinner_start("Loading HAR file");

        // Read and parse HAR file
        let content =
            fs::read_to_string(file_path).map_err(|e| format!("Failed to read HAR file: {}", e))?;

        // Manual JSON parsing for HAR structure
        let har = Har::from_json(&content).map_err(|e| format!("Failed to parse HAR: {}", e))?;

        Output::spinner_done();

        // Show options
        let show_entries = ctx.has_flag("entries");
        let show_timings = ctx.has_flag("timings");
        let show_errors = ctx.has_flag("errors");

        // HAR Overview
        println!("\x1b[1m\x1b[36m● HAR Overview\x1b[0m");
        println!("  Version: {}", har.log.version);
        println!(
            "  Creator: {} {}",
            har.log.creator.name, har.log.creator.version
        );
        println!("  Total entries: {}", har.log.entries.len());

        // Calculate statistics
        let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
        let total_request_size: i64 = har.log.entries.iter().map(|e| e.request.body_size).sum();
        let total_response_size: i64 = har.log.entries.iter().map(|e| e.response.body_size).sum();

        println!("  Total time: {:.2}ms", total_time);
        println!("  Total request size: {} bytes", total_request_size.max(0));
        println!(
            "  Total response size: {} bytes",
            total_response_size.max(0)
        );
        println!();

        // Show entries
        if show_entries || (!show_timings && !show_errors) {
            println!("\x1b[1m\x1b[32m● Entries\x1b[0m");
            for (i, entry) in har.log.entries.iter().take(20).enumerate() {
                let status_color = if entry.response.status >= 400 {
                    "\x1b[31m" // Red for errors
                } else if entry.response.status >= 300 {
                    "\x1b[33m" // Yellow for redirects
                } else {
                    "\x1b[32m" // Green for success
                };
                println!(
                    "  {:3}. {}{} {}\x1b[0m {} ({:.1}ms)",
                    i + 1,
                    status_color,
                    entry.response.status,
                    entry.request.method,
                    entry.request.url,
                    entry.time
                );
            }
            if har.log.entries.len() > 20 {
                println!(
                    "  \x1b[90m... and {} more\x1b[0m",
                    har.log.entries.len() - 20
                );
            }
            println!();
        }

        // Show timings
        if show_timings {
            println!("\x1b[1m\x1b[35m● Timing Analysis\x1b[0m");

            // Find slowest entries
            let mut sorted: Vec<_> = har.log.entries.iter().collect();
            sorted.sort_by(|a, b| b.time.partial_cmp(&a.time).unwrap());

            println!("  Slowest requests:");
            for (i, entry) in sorted.iter().take(5).enumerate() {
                println!(
                    "    {:3}. {:.2}ms - {} {}",
                    i + 1,
                    entry.time,
                    entry.request.method,
                    entry.request.url
                );
            }
            println!();
        }

        // Show errors
        if show_errors {
            println!("\x1b[1m\x1b[31m● Errors (4xx/5xx)\x1b[0m");

            let errors: Vec<_> = har
                .log
                .entries
                .iter()
                .filter(|e| e.response.status >= 400)
                .collect();

            if errors.is_empty() {
                println!("  No errors found");
            } else {
                for (i, entry) in errors.iter().take(10).enumerate() {
                    println!(
                        "  {:3}. {} {} - {}",
                        i + 1,
                        entry.response.status,
                        entry.response.status_text,
                        entry.request.url
                    );
                }
                if errors.len() > 10 {
                    println!("  \x1b[90m... and {} more\x1b[0m", errors.len() - 10);
                }
            }
            println!();
        }

        // Status code distribution
        let mut status_counts: std::collections::HashMap<u16, usize> =
            std::collections::HashMap::new();
        for entry in &har.log.entries {
            *status_counts.entry(entry.response.status).or_insert(0) += 1;
        }

        println!("\x1b[1m\x1b[33m● Status Codes\x1b[0m");
        let mut codes: Vec<_> = status_counts.iter().collect();
        codes.sort_by_key(|(k, _)| *k);
        for (code, count) in codes {
            let color = if *code >= 400 {
                "\x1b[31m"
            } else if *code >= 300 {
                "\x1b[33m"
            } else {
                "\x1b[32m"
            };
            println!("  {}{}\x1b[0m: {} requests", color, code, count);
        }

        Ok(())
    }

    /// Replay HTTP requests from HAR file
    fn har_replay(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing HAR file. Usage: rb web asset har-replay <file>\nExample: rb web asset har-replay site.har",
        )?;

        Output::header("HAR Replay - HTTP Request Replay");
        Output::item("File", file_path);
        println!();

        // Parse options
        let sequential = ctx.has_flag("sequential");
        let compare = ctx.has_flag("compare");
        let delay_ms: u64 = ctx
            .get_flag("delay")
            .and_then(|d| d.parse().ok())
            .unwrap_or(0);

        Output::spinner_start("Loading HAR file");

        let content =
            fs::read_to_string(file_path).map_err(|e| format!("Failed to read HAR file: {}", e))?;

        let har = Har::from_json(&content).map_err(|e| format!("Failed to parse HAR: {}", e))?;

        Output::spinner_done();

        let entries = &har.log.entries;
        if entries.is_empty() {
            Output::warning("No entries to replay in HAR file");
            return Ok(());
        }

        Output::info(&format!("Found {} entries to replay", entries.len()));
        if sequential {
            Output::info("Mode: Sequential (one at a time)");
        }
        if compare {
            Output::info("Mode: Compare responses");
        }
        if delay_ms > 0 {
            Output::info(&format!("Delay between requests: {}ms", delay_ms));
        }
        println!();

        let client = HttpClient::new();
        let mut success_count = 0;
        let mut fail_count = 0;
        let mut diff_count = 0;

        for (i, entry) in entries.iter().enumerate() {
            let url = &entry.request.url;
            let method = &entry.request.method;

            print!("  [{}/{}] {} {} ... ", i + 1, entries.len(), method, url);

            // Build request headers
            let mut headers = Vec::new();
            for header in &entry.request.headers {
                // Skip pseudo-headers and host (will be set automatically)
                if !header.name.starts_with(':') && header.name.to_lowercase() != "host" {
                    headers.push((header.name.clone(), header.value.clone()));
                }
            }

            // Make the request
            let result = match method.to_uppercase().as_str() {
                "GET" => client.get(url),
                "POST" => {
                    let body = entry
                        .request
                        .post_data
                        .as_ref()
                        .map(|p| p.text.clone())
                        .unwrap_or_default();
                    client.post(url, body.into_bytes())
                }
                "HEAD" => {
                    // HEAD not directly supported, use GET
                    client.get(url)
                }
                _ => {
                    println!("\x1b[33mSKIPPED\x1b[0m (unsupported method)");
                    continue;
                }
            };

            match result {
                Ok(response) => {
                    let status = response.status_code;
                    let original_status = entry.response.status;

                    let status_color = if status >= 400 {
                        "\x1b[31m"
                    } else if status >= 300 {
                        "\x1b[33m"
                    } else {
                        "\x1b[32m"
                    };

                    if compare {
                        if status == original_status {
                            println!("{}{}OK\x1b[0m (status: {})", status_color, "", status);
                            success_count += 1;
                        } else {
                            println!(
                                "\x1b[33mDIFF\x1b[0m (was: {}, now: {})",
                                original_status, status
                            );
                            diff_count += 1;
                        }
                    } else {
                        println!("{}{}OK\x1b[0m", status_color, status);
                        success_count += 1;
                    }
                }
                Err(e) => {
                    println!("\x1b[31mFAIL\x1b[0m ({})", e);
                    fail_count += 1;
                }
            }

            // Delay between requests
            if delay_ms > 0 && i < entries.len() - 1 {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
        }

        println!();
        println!("\x1b[1m● Summary\x1b[0m");
        println!("  \x1b[32mSuccess: {}\x1b[0m", success_count);
        if diff_count > 0 {
            println!("  \x1b[33mDifferent: {}\x1b[0m", diff_count);
        }
        if fail_count > 0 {
            println!("  \x1b[31mFailed: {}\x1b[0m", fail_count);
        }

        Ok(())
    }

    /// Convert HAR entries to curl/wget/python/httpie commands
    fn har_to_curl(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx.target.as_ref().ok_or(
            "Missing HAR file. Usage: rb web asset har-to-curl <file>\nExample: rb web asset har-to-curl site.har --format curl",
        )?;

        let format = ctx
            .get_flag("format")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "curl".to_string());

        Output::header("HAR to Commands - Export HTTP Requests");
        Output::item("File", file_path);
        Output::item("Format", &format);
        println!();

        Output::spinner_start("Loading HAR file");

        let content =
            fs::read_to_string(file_path).map_err(|e| format!("Failed to read HAR file: {}", e))?;

        let har = Har::from_json(&content).map_err(|e| format!("Failed to parse HAR: {}", e))?;

        Output::spinner_done();

        let entries = &har.log.entries;
        if entries.is_empty() {
            Output::warning("No entries in HAR file");
            return Ok(());
        }

        Output::info(&format!(
            "Converting {} entries to {} format",
            entries.len(),
            format
        ));
        println!();

        for (i, entry) in entries.iter().enumerate() {
            println!("\x1b[1m# Request {}\x1b[0m", i + 1);

            let cmd = match format.as_str() {
                "curl" => self.entry_to_curl(entry),
                "wget" => self.entry_to_wget(entry),
                "python" => self.entry_to_python(entry),
                "httpie" => self.entry_to_httpie(entry),
                _ => {
                    return Err(format!(
                        "Unknown format: {}. Use: curl, wget, python, httpie",
                        format
                    ))
                }
            };

            println!("{}", cmd);
            println!();
        }

        Ok(())
    }

    fn entry_to_curl(&self, entry: &crate::protocols::har::HarEntry) -> String {
        let mut cmd = format!("curl -X {} '{}'", entry.request.method, entry.request.url);

        // Add headers
        for header in &entry.request.headers {
            if !header.name.starts_with(':') {
                cmd.push_str(&format!(" \\\n  -H '{}: {}'", header.name, header.value));
            }
        }

        // Add body
        if let Some(ref post_data) = entry.request.post_data {
            if !post_data.text.is_empty() {
                let escaped = post_data.text.replace('\'', "'\\''");
                cmd.push_str(&format!(" \\\n  -d '{}'", escaped));
            }
        }

        cmd
    }

    fn entry_to_wget(&self, entry: &crate::protocols::har::HarEntry) -> String {
        let mut cmd = format!(
            "wget --method={} '{}'",
            entry.request.method, entry.request.url
        );

        // Add headers
        for header in &entry.request.headers {
            if !header.name.starts_with(':') && header.name.to_lowercase() != "host" {
                cmd.push_str(&format!(
                    " \\\n  --header='{}: {}'",
                    header.name, header.value
                ));
            }
        }

        // Add body
        if let Some(ref post_data) = entry.request.post_data {
            if !post_data.text.is_empty() {
                let escaped = post_data.text.replace('\'', "'\\''");
                cmd.push_str(&format!(" \\\n  --body-data='{}'", escaped));
            }
        }

        cmd.push_str(" \\\n  -O -");
        cmd
    }

    fn entry_to_python(&self, entry: &crate::protocols::har::HarEntry) -> String {
        let mut code = String::from("import requests\n\n");

        // Build headers dict
        let headers: Vec<String> = entry
            .request
            .headers
            .iter()
            .filter(|h| !h.name.starts_with(':'))
            .map(|h| format!("    '{}': '{}'", h.name, h.value.replace('\'', "\\'")))
            .collect();

        if !headers.is_empty() {
            code.push_str("headers = {\n");
            code.push_str(&headers.join(",\n"));
            code.push_str("\n}\n\n");
        }

        // Build request
        let method = entry.request.method.to_lowercase();
        code.push_str(&format!("response = requests.{}(\n", method));
        code.push_str(&format!("    '{}',\n", entry.request.url));

        if !headers.is_empty() {
            code.push_str("    headers=headers,\n");
        }

        if let Some(ref post_data) = entry.request.post_data {
            if !post_data.text.is_empty() {
                let escaped = post_data.text.replace('\'', "\\'");
                code.push_str(&format!("    data='{}',\n", escaped));
            }
        }

        code.push_str(")\n\n");
        code.push_str("print(response.status_code)\nprint(response.text)");

        code
    }

    fn entry_to_httpie(&self, entry: &crate::protocols::har::HarEntry) -> String {
        let method = entry.request.method.to_uppercase();
        let mut cmd = format!("http {} '{}'", method, entry.request.url);

        // Add headers
        for header in &entry.request.headers {
            if !header.name.starts_with(':') && header.name.to_lowercase() != "host" {
                cmd.push_str(&format!(" \\\n  '{}:{}'", header.name, header.value));
            }
        }

        // Add body
        if let Some(ref post_data) = entry.request.post_data {
            if !post_data.text.is_empty() {
                // For JSON, httpie uses := for raw JSON
                if post_data.mime_type.contains("json") {
                    cmd.push_str(&format!(
                        " \\\n  --raw='{}'",
                        post_data.text.replace('\'', "\\'")
                    ));
                } else {
                    cmd.push_str(&format!(
                        " \\\n  --raw='{}'",
                        post_data.text.replace('\'', "\\'")
                    ));
                }
            }
        }

        cmd
    }

    // ===== RESTful Commands - Query Stored Data =====

    fn list_http(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or("Missing target host")?;
        let db_path = self.get_db_path(ctx, host)?;

        Output::header(&format!("Listing HTTP Data: {}", host));
        Output::info(&format!("Database: {}", db_path.display()));

        let mut query = StorageService::global()
            .open_query_manager(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        annotate_query_partition(
            ctx,
            &db_path,
            [("query_dataset", "http"), ("query_operation", "list")],
        );

        let http_records = query
            .list_http_records(host)
            .map_err(|e| format!("Query failed: {}", e))?;

        if http_records.is_empty() {
            Output::warning("No HTTP data found in database");
            Output::info(&format!(
                "Run HTTP request first: rb web asset headers {} --persist",
                host
            ));
            return Ok(());
        }

        Output::success(&format!("Found {} HTTP record(s)", http_records.len()));
        println!();

        for record in &http_records {
            println!("URL: {}", record.url);
            println!("Status: {}", record.status_code);
            println!("Headers: {} found", record.headers.len());
            println!();
        }

        Ok(())
    }

    fn describe_http(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or("Missing target host")?;
        let db_path = self.get_db_path(ctx, host)?;

        Output::header(&format!("HTTP Summary: {}", host));
        Output::info(&format!("Database: {}", db_path.display()));

        let mut query = StorageService::global()
            .open_query_manager(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        annotate_query_partition(
            ctx,
            &db_path,
            [("query_dataset", "http"), ("query_operation", "describe")],
        );

        let http_records = query
            .list_http_records(host)
            .map_err(|e| format!("Query failed: {}", e))?;

        if http_records.is_empty() {
            Output::warning("No HTTP data found in database");
            Output::info(&format!(
                "Run HTTP request first: rb web asset headers {} --persist",
                host
            ));
            return Ok(());
        }

        println!();
        println!("📊 HTTP Data Summary:");
        println!("━━━━━━━━━━━━━━━━━━━━");
        println!("  Total Requests: {}", http_records.len());

        let mut status_counts: std::collections::HashMap<u16, usize> =
            std::collections::HashMap::new();
        for record in &http_records {
            *status_counts.entry(record.status_code).or_insert(0) += 1;
        }

        println!("\n  Status Codes:");
        for (status, count) in &status_counts {
            println!("    {}: {} requests", status, count);
        }

        println!("\n  Sample URLs:");
        for (i, record) in http_records.iter().take(5).enumerate() {
            println!("    {}. {} ({})", i + 1, record.url, record.status_code);
        }
        if http_records.len() > 5 {
            println!("    ... and {} more", http_records.len() - 5);
        }

        Ok(())
    }

    fn get_db_path(&self, ctx: &CliContext, host: &str) -> Result<std::path::PathBuf, String> {
        if let Some(db_path) = ctx.get_flag("db") {
            return Ok(std::path::PathBuf::from(db_path));
        }

        let cwd = std::env::current_dir().map_err(|e| format!("Failed to get CWD: {}", e))?;
        let base = host
            .trim_start_matches("www.")
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .to_lowercase();
        let candidate = cwd.join(format!("{}.rdb", &base));
        if candidate.exists() {
            return Ok(candidate);
        }

        Err(format!(
            "Database not found: {}\nRun HTTP request first: rb web asset headers {} --persist",
            candidate.display(),
            host
        ))
    }

    /// Advanced CMS security testing using the comprehensive cms module
    fn cms_advanced(&self, ctx: &CliContext) -> Result<(), String> {
        use crate::modules::web::cms::{CmsScanConfig, CmsScanner, CmsType, VulnSeverity};
        use std::time::Duration;

        let url = ctx.target.as_ref().ok_or(
            "Missing URL.\nUsage: rb web asset cms <URL> [--aggressive] [--waf-evasion]\nExample: rb web asset cms http://example.com",
        )?;

        Validator::validate_url(url)?;

        // Build config from flags
        let aggressive = ctx.flags.contains_key("aggressive");
        let waf_evasion = ctx.flags.contains_key("waf-evasion");
        let timeout = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10);
        let threads = ctx
            .flags
            .get("threads")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10);

        // Parse enumerate flag
        let enumerate_str = ctx
            .flags
            .get("enumerate")
            .map(|s| s.as_str())
            .unwrap_or("plugins,themes,users");
        let enumerate_plugins = enumerate_str.contains("plugins") || enumerate_str.contains("all");
        let enumerate_themes = enumerate_str.contains("themes") || enumerate_str.contains("all");
        let enumerate_users = enumerate_str.contains("users") || enumerate_str.contains("all");

        let config = CmsScanConfig {
            target: url.clone(),
            timeout: Duration::from_secs(timeout),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            threads,
            aggressive,
            enumerate_plugins,
            enumerate_themes,
            enumerate_users,
            wordlist: ctx.flags.get("wordlist").map(|s| s.clone()),
            max_enum_items: 1000,
            waf_evasion,
            rate_limit: ctx
                .flags
                .get("rate-limit")
                .and_then(|v| v.parse::<f64>().ok()),
            random_delay: None,
            follow_redirects: true,
            headers: Vec::new(),
            proxy: ctx.flags.get("proxy").map(|s| s.clone()),
            api_token: ctx.flags.get("api-token").map(|s| s.clone()),
        };

        Output::header(&format!("Advanced CMS Security Scanner: {}", url));
        Output::info(&format!(
            "Mode: {}",
            if aggressive { "Aggressive" } else { "Passive" }
        ));
        if waf_evasion {
            Output::info("WAF Evasion: Enabled");
        }
        Output::info(&format!("Enumerate: {}", enumerate_str));
        println!();

        Output::spinner_start("Detecting CMS and scanning...");

        let scanner = CmsScanner::new(config);
        let result = scanner.scan();

        Output::spinner_done();
        println!();

        // Display CMS detection result
        match result.cms_type {
            CmsType::Unknown => {
                Output::warning("No CMS detected");
                return Ok(());
            }
            cms_type => {
                let cms_name = format!("{:?}", cms_type);
                let version = result.version.as_deref().unwrap_or("unknown");
                Output::success(&format!("Detected: {} {}", cms_name, version));
                Output::item("Confidence", &format!("{}%", result.confidence));
                Output::item("Detection Methods", &result.detection_methods.join(", "));
            }
        }
        println!();

        // Display risk score
        let risk_color = match result.risk_score {
            0..=20 => "green",
            21..=50 => "yellow",
            51..=75 => "red",
            _ => "red",
        };
        Output::section("Risk Assessment");
        println!(
            "  Risk Score: {} ({})",
            Output::colorize(&result.risk_score.to_string(), risk_color),
            Output::colorize(result.risk_rating(), risk_color)
        );

        // Display vulnerability counts
        let (critical, high, medium, low, info) = result.vuln_counts();
        if critical + high + medium + low + info > 0 {
            println!("  Vulnerabilities:");
            if critical > 0 {
                println!("    \x1b[31mCritical: {}\x1b[0m", critical);
            }
            if high > 0 {
                println!("    \x1b[91mHigh: {}\x1b[0m", high);
            }
            if medium > 0 {
                println!("    \x1b[33mMedium: {}\x1b[0m", medium);
            }
            if low > 0 {
                println!("    \x1b[94mLow: {}\x1b[0m", low);
            }
            if info > 0 {
                println!("    \x1b[36mInfo: {}\x1b[0m", info);
            }
        }
        println!();

        // Display plugins
        if !result.plugins.is_empty() {
            Output::section(&format!("Plugins Found: {}", result.plugins.len()));
            for plugin in result.plugins.iter().take(20) {
                let version = plugin.version.as_deref().unwrap_or("unknown");
                let vuln_marker = if plugin.vulnerable {
                    " \x1b[31m[VULNERABLE]\x1b[0m"
                } else {
                    ""
                };
                println!(
                    "  • {} ({}){}",
                    Output::colorize(&plugin.name, "cyan"),
                    version,
                    vuln_marker
                );
            }
            if result.plugins.len() > 20 {
                Output::dim(&format!("  ... and {} more", result.plugins.len() - 20));
            }
            println!();
        }

        // Display themes
        if !result.themes.is_empty() {
            Output::section(&format!("Themes Found: {}", result.themes.len()));
            for theme in result.themes.iter().take(10) {
                let version = theme.version.as_deref().unwrap_or("unknown");
                let vuln_marker = if theme.vulnerable {
                    " \x1b[31m[VULNERABLE]\x1b[0m"
                } else {
                    ""
                };
                println!(
                    "  • {} ({}){}",
                    Output::colorize(&theme.name, "cyan"),
                    version,
                    vuln_marker
                );
            }
            if result.themes.len() > 10 {
                Output::dim(&format!("  ... and {} more", result.themes.len() - 10));
            }
            println!();
        }

        // Display users
        if !result.users.is_empty() {
            Output::section(&format!("Users Enumerated: {}", result.users.len()));
            for user in result.users.iter().take(20) {
                let id_str = user
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "?".to_string());
                println!(
                    "  • {} (ID: {})",
                    Output::colorize(&user.username, "yellow"),
                    id_str
                );
                if let Some(ref display) = user.display_name {
                    println!("    Display: {}", display);
                }
            }
            if result.users.len() > 20 {
                Output::dim(&format!("  ... and {} more", result.users.len() - 20));
            }
            println!();
        }

        // Display vulnerabilities
        if !result.vulnerabilities.is_empty() {
            Output::section(&format!(
                "Vulnerabilities: {}",
                result.vulnerabilities.len()
            ));
            for vuln in result.vulnerabilities.iter().take(15) {
                let severity_color = match vuln.severity {
                    VulnSeverity::Critical => "\x1b[31m",
                    VulnSeverity::High => "\x1b[91m",
                    VulnSeverity::Medium => "\x1b[33m",
                    VulnSeverity::Low => "\x1b[94m",
                    VulnSeverity::Info => "\x1b[36m",
                };
                println!(
                    "  {}[{:?}]\x1b[0m {}",
                    severity_color, vuln.severity, vuln.title
                );
                if !vuln.id.is_empty() {
                    println!("         ID: {}", vuln.id);
                }
                if !vuln.references.is_empty() {
                    println!("         Ref: {}", vuln.references[0]);
                }
            }
            if result.vulnerabilities.len() > 15 {
                Output::dim(&format!(
                    "  ... and {} more",
                    result.vulnerabilities.len() - 15
                ));
            }
            println!();
        }

        // Display interesting findings
        if !result.interesting_findings.is_empty() {
            Output::section(&format!(
                "Interesting Findings: {}",
                result.interesting_findings.len()
            ));
            for finding in result.interesting_findings.iter().take(10) {
                println!("  [{:?}] {}", finding.finding_type, finding.description);
                if let Some(ref url) = finding.url {
                    println!("        URL: {}", url);
                }
            }
            if result.interesting_findings.len() > 10 {
                Output::dim(&format!(
                    "  ... and {} more",
                    result.interesting_findings.len() - 10
                ));
            }
        }

        Ok(())
    }
}

#[derive(Default)]
struct BufferingHttp2Handler {
    body: Vec<u8>,
}

impl Http2ResponseHandler for BufferingHttp2Handler {
    fn on_data(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.body.extend_from_slice(chunk);
        Ok(())
    }
}

fn escape_json(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}
