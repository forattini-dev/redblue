/// Web/asset command - Web application testing
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::intelligence::banner_analysis::analyze_http_server;
// use crate::modules::tls::auditor::TlsAuditor; // TODO: Enable when auditor module compiles
use crate::modules::web::crawler::WebCrawler;
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::modules::web::fuzzer::{DirectoryFuzzer, Wordlists};
use crate::modules::web::linkfinder::{EndpointType, LinkFinder};
use crate::modules::web::scanner_strategy::{ScanStrategy, UnifiedScanResult, UnifiedWebScanner};
use crate::protocols::http::{HttpClient, HttpRequest, HttpResponse};
use crate::storage::client::{PersistenceManager, QueryManager};
// use crate::protocols::tls_cert::TlsClient; // Use modules::network::tls instead
use crate::storage::schema::HttpHeadersRecord;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
                verb: "linkfinder",
                summary: "Extract endpoints from JavaScript files",
                usage: "rb web asset linkfinder <js-url> [--type api|s3|all]",
            },
            Route {
                verb: "crawl",
                summary: "Launch a lightweight crawler (coming soon)",
                usage: "rb web asset crawl <url>",
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
            "cert" => self.cert(ctx),
            // "tls-audit" => self.tls_audit(ctx), // TODO: Enable when TlsAuditor compiles
            "fuzz" => self.fuzz(ctx),
            "fingerprint" => self.fingerprint(ctx),
            "scan" => self.scan(ctx),
            "vuln-scan" => self.vuln_scan(ctx),
            "wpscan" => self.wpscan(ctx),
            "drupal-scan" => self.drupal_scan(ctx),
            "joomla-scan" => self.joomla_scan(ctx),
            "cms-scan" => self.cms_scan(ctx),
            "linkfinder" => self.linkfinder(ctx),
            "crawl" => self.crawl(ctx),
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
                            // "cert", // TODO: Disabled until TLS is fixed
                            // "tls-audit", // TODO: Disabled until TLS is fixed
                            "fuzz",
                            "fingerprint",
                            "scan",
                            "vuln-scan",
                            "wpscan",
                            "drupal-scan",
                            "joomla-scan",
                            "linkfinder",
                            "crawl"
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

    fn get(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset get <URL> Example: rb web asset get http://example.com"
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset get")?;

        let format = ctx.get_output_format();

        let client = HttpClient::new();
        let request = HttpRequest::get(url);

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

    fn headers(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or(
            "Missing URL. Usage: rb web asset headers <URL> Example: rb web asset headers http://example.com",
        )?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset headers")?;

        let format = ctx.get_output_format();

        let client = HttpClient::new();
        let request = HttpRequest::get(url);

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
        let mut pm = PersistenceManager::new(&host, persist_flag)?;

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
        let mut pm = PersistenceManager::new(&host, persist_flag)?;

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

    #[allow(dead_code)]
    fn fuzz(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx
        .target
        .as_ref()
        .ok_or("Missing URL. Usage: rb web asset fuzz <URL> --wordlist WORDS Example: rb web asset fuzz http://example.com --common")?;

        Validator::validate_url(url)?;
        Self::guard_plain_http(url, "rb web asset fuzz")?;

        let recursive = ctx.has_flag("recursive");
        let header = if recursive {
            "Directory Fuzzing (feroxbuster-style - RECURSIVE)"
        } else {
            "Directory Fuzzing (ffuf-style)"
        };

        Output::header(header);
        Output::item("Target", url);
        println!();

        // Determine wordlist source
        let wordlist_path = if ctx.has_flag("common") {
            // Use built-in common wordlist via WordlistManager
            let wl_manager = crate::wordlists::WordlistManager::new()?;
            let words = wl_manager.get("directories-common")?;
            Output::item("Wordlist", "directories-common (embedded)");
            Output::item("Words", &words.len().to_string());

            // Convert Vec<String> to Vec<&str>
            let words_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
            Wordlists::create_temp_wordlist(&words_refs)?
        } else if let Some(wordlist_name) = ctx.get_flag("wordlist") {
            // Try to resolve via WordlistManager (supports embedded, project, cached, or file paths)
            let wl_manager = crate::wordlists::WordlistManager::new()?;
            match wl_manager.get(&wordlist_name) {
                Ok(words) => {
                    Output::item("Wordlist", &wordlist_name);
                    Output::item("Words", &words.len().to_string());
                    // Convert Vec<String> to Vec<&str>
                    let words_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
                    Wordlists::create_temp_wordlist(&words_refs)?
                }
                Err(_) => {
                    // Fallback: treat as file path directly
                    Output::item("Wordlist", &wordlist_name);
                    wordlist_name.to_string()
                }
            }
        } else {
            return Err(
                "No wordlist specified. Use --wordlist <NAME|FILE> or --common".to_string(),
            );
        };

        // Parse configuration
        let threads = ctx
            .get_flag_or("threads", "50")
            .parse::<usize>()
            .map_err(|_| "Invalid threads value")?;

        let filter_codes = if let Some(filter_str) = ctx.get_flag("filter") {
            filter_str
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect()
        } else {
            vec![404]
        };

        let match_codes = if let Some(match_str) = ctx.get_flag("match") {
            match_str
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect()
        } else {
            Vec::new()
        };

        Output::item("Threads", &threads.to_string());
        if recursive {
            let depth = ctx
                .get_flag_or("depth", "3")
                .parse::<usize>()
                .map_err(|_| "Invalid depth value")?;
            Output::item("Mode", &format!("Recursive (max depth: {})", depth));
        } else {
            Output::item("Mode", "Single-level");
        }
        if !filter_codes.is_empty() {
            Output::item(
                "Filter",
                &format!(
                    "{}",
                    filter_codes
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        if !match_codes.is_empty() {
            Output::item(
                "Match",
                &format!(
                    "{}",
                    match_codes
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        println!();

        // Create fuzzer
        let mut fuzzer = DirectoryFuzzer::new(url, &wordlist_path)
            .with_threads(threads)
            .with_filter_status(filter_codes)
            .with_match_status(match_codes);

        // Enable recursive mode if requested
        if recursive {
            let depth = ctx
                .get_flag_or("depth", "3")
                .parse::<usize>()
                .map_err(|_| "Invalid depth value")?;
            fuzzer = fuzzer.with_recursive(depth);
        }

        let format = ctx.get_output_format();
        let total_words_estimate = if let Ok(words) = fuzzer.preview_wordlist_count() {
            words as u64
        } else {
            0
        };

        let progress_label = format!("Fuzzing {}", url);
        let progress =
            if format == crate::cli::format::OutputFormat::Human && total_words_estimate > 0 {
                Some(Arc::new(Output::progress_bar(
                    progress_label,
                    total_words_estimate,
                    true,
                )))
            } else {
                None
            };

        if let Some(p) = &progress {
            fuzzer = fuzzer.with_progress(Arc::clone(p) as Arc<_>);
        }

        let (results, stats) = fuzzer.fuzz()?;

        if let Some(progress_bar) = progress {
            progress_bar.finish();
        }

        // Display results
        if results.is_empty() {
            println!();
            Output::warning("No directories/files found");
        } else {
            println!();
            Output::subheader(&format!("Found {} Paths", results.len()));
            println!();

            println!(
                "  {:<6} {:<60} {:<10} {}",
                "STATUS", "PATH", "SIZE", "INTERESTING"
            );
            println!("  {}", "─".repeat(90));

            for result in &results {
                let status_color = if (200..300).contains(&result.status_code) {
                    "\x1b[32m" // Green
                } else if (300..400).contains(&result.status_code) {
                    "\x1b[33m" // Yellow
                } else if result.status_code == 401 || result.status_code == 403 {
                    "\x1b[31m" // Red
                } else {
                    "\x1b[36m" // Cyan
                };

                let interesting = if result.interesting { "✓" } else { "" };

                println!(
                    "  {}{:<6}\x1b[0m {:<60} {:<10} {}",
                    status_color, result.status_code, result.path, result.size, interesting
                );
            }
        }

        // Display statistics
        println!();
        Output::subheader("Statistics");
        println!("  Total Requests: {}", stats.total_requests);
        println!("  Found:          {}", stats.found);
        println!("  Errors:         {}", stats.errors);
        println!(
            "  Duration:       {:.2}s",
            stats.duration_ms as f64 / 1000.0
        );
        println!(
            "  Requests/sec:   {:.0}",
            stats.total_requests as f64 / (stats.duration_ms as f64 / 1000.0)
        );

        println!();
        Output::success("Fuzzing completed");

        Ok(())
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

    // ===== RESTful Commands - Query Stored Data =====

    fn list_http(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or("Missing target host")?;
        let db_path = self.get_db_path(ctx, host)?;

        Output::header(&format!("Listing HTTP Data: {}", host));
        Output::info(&format!("Database: {}", db_path.display()));

        let mut query =
            QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

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

        let mut query =
            QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

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
}
