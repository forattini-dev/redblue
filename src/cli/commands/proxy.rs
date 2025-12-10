//! Proxy commands - HTTP CONNECT, SOCKS5, and Transparent proxies
//!
//! High-performance proxy servers for tunneling and traffic routing.

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::proxy::http::{HttpProxy, HttpProxyConfig};
use crate::modules::proxy::socks5::{Socks5Config, Socks5Server};
use crate::modules::proxy::transparent::{TransparentConfig, TransparentMode, TransparentProxy};
use crate::modules::proxy::transparent::{generate_iptables_rules, generate_nftables_rules};
use crate::modules::proxy::ProxyContext;
use crate::storage::QueryManager;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// HTTP CONNECT Proxy Command
// ============================================================================

pub struct HttpProxyCommand;

impl Command for HttpProxyCommand {
    fn domain(&self) -> &str {
        "proxy"
    }

    fn resource(&self) -> &str {
        "http"
    }

    fn description(&self) -> &str {
        "HTTP CONNECT proxy for tunneling TCP connections"
    }

    fn routes(&self) -> Vec<Route> {
        vec![Route {
            verb: "start",
            summary: "Start the HTTP CONNECT proxy server",
            usage: "rb proxy http start [--port PORT] [--bind ADDR]",
        }]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("port", "Listen port for the proxy")
                .with_short('p')
                .with_default("8080"),
            Flag::new("bind", "Bind address")
                .with_short('b')
                .with_default("127.0.0.1"),
            Flag::new("timeout", "Connection timeout in seconds")
                .with_short('t')
                .with_default("30"),
            Flag::new("auth", "Enable authentication (user:pass)").with_short('a'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Start HTTP proxy on default port", "rb proxy http start"),
            ("Start on custom port", "rb proxy http start --port 3128"),
            (
                "Bind to all interfaces",
                "rb proxy http start --bind 0.0.0.0 --port 8080",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "start" => self.start_proxy(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!("{}", Validator::suggest_command(verb, &["start"]));
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl HttpProxyCommand {
    fn start_proxy(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("HTTP CONNECT Proxy");
        println!();

        let bind = ctx.get_flag_or("bind", "127.0.0.1");
        let port: u16 = ctx
            .get_flag_or("port", "8080")
            .parse()
            .map_err(|_| "Invalid port number")?;

        let timeout: u64 = ctx
            .get_flag_or("timeout", "30")
            .parse()
            .map_err(|_| "Invalid timeout value")?;

        let listen_addr: SocketAddr = format!("{}:{}", bind, port)
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        Output::item("Listen Address", &listen_addr.to_string());
        Output::item("Timeout", &format!("{}s", timeout));
        println!();

        Output::info("To use this proxy:");
        println!("  curl -x http://{}:{} https://example.com", bind, port);
        println!("  export http_proxy=http://{}:{}", bind, port);
        println!("  export https_proxy=http://{}:{}", bind, port);
        println!();

        Output::success(&format!("Starting HTTP proxy on {}...", listen_addr));
        println!();

        let mut config = HttpProxyConfig::default();
        config.listen_addr = listen_addr;
        config.timeout = Duration::from_secs(timeout);

        let proxy_ctx = Arc::new(ProxyContext::default());
        let proxy = HttpProxy::with_config(config, proxy_ctx);
        proxy.run().map_err(|e| format!("Proxy error: {}", e))
    }
}

// ============================================================================
// SOCKS5 Proxy Command
// ============================================================================

pub struct Socks5ProxyCommand;

impl Command for Socks5ProxyCommand {
    fn domain(&self) -> &str {
        "proxy"
    }

    fn resource(&self) -> &str {
        "socks5"
    }

    fn description(&self) -> &str {
        "SOCKS5 proxy server (RFC 1928)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![Route {
            verb: "start",
            summary: "Start the SOCKS5 proxy server",
            usage: "rb proxy socks5 start [--port PORT] [--bind ADDR]",
        }]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("port", "Listen port for the proxy")
                .with_short('p')
                .with_default("1080"),
            Flag::new("bind", "Bind address")
                .with_short('b')
                .with_default("127.0.0.1"),
            Flag::new("timeout", "Connection timeout in seconds")
                .with_short('t')
                .with_default("30"),
            Flag::new("no-udp", "Disable UDP associate"),
            Flag::new("auth", "Enable authentication (user:pass)").with_short('a'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Start SOCKS5 proxy on default port", "rb proxy socks5 start"),
            ("Start on custom port", "rb proxy socks5 start --port 9050"),
            (
                "Bind to all interfaces",
                "rb proxy socks5 start --bind 0.0.0.0 --port 1080",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "start" => self.start_proxy(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!("{}", Validator::suggest_command(verb, &["start"]));
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl Socks5ProxyCommand {
    fn start_proxy(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("SOCKS5 Proxy");
        println!();

        let bind = ctx.get_flag_or("bind", "127.0.0.1");
        let port: u16 = ctx
            .get_flag_or("port", "1080")
            .parse()
            .map_err(|_| "Invalid port number")?;

        let timeout: u64 = ctx
            .get_flag_or("timeout", "30")
            .parse()
            .map_err(|_| "Invalid timeout value")?;

        let allow_udp = !ctx.has_flag("no-udp");

        let listen_addr: SocketAddr = format!("{}:{}", bind, port)
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        Output::item("Listen Address", &listen_addr.to_string());
        Output::item("Timeout", &format!("{}s", timeout));
        Output::item(
            "UDP Associate",
            if allow_udp { "Enabled" } else { "Disabled" },
        );
        println!();

        Output::info("To use this proxy:");
        println!("  curl --socks5 {}:{} https://example.com", bind, port);
        println!("  ssh -D {} user@remote  # Creates SOCKS5 tunnel", port);
        println!("  proxychains -q your_command  # With proxychains config");
        println!();

        Output::success(&format!("Starting SOCKS5 proxy on {}...", listen_addr));
        println!();

        let mut config = Socks5Config::default();
        config.listen_addr = listen_addr;
        config.timeout = Duration::from_secs(timeout);
        config.allow_udp = allow_udp;

        let proxy_ctx = Arc::new(ProxyContext::default());
        let proxy = Socks5Server::with_config(config, proxy_ctx);
        proxy.run().map_err(|e| format!("Proxy error: {}", e))
    }
}

// ============================================================================
// Transparent Proxy Command
// ============================================================================

pub struct TransparentProxyCommand;

impl Command for TransparentProxyCommand {
    fn domain(&self) -> &str {
        "proxy"
    }

    fn resource(&self) -> &str {
        "transparent"
    }

    fn description(&self) -> &str {
        "Transparent proxy using iptables/nftables (Linux only)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "start",
                summary: "Start the transparent proxy server",
                usage: "rb proxy transparent start [--port PORT] [--mode MODE]",
            },
            Route {
                verb: "iptables",
                summary: "Generate iptables rules for transparent proxy",
                usage: "rb proxy transparent iptables [--port PORT] [--mode MODE]",
            },
            Route {
                verb: "nftables",
                summary: "Generate nftables rules for transparent proxy",
                usage: "rb proxy transparent nftables [--port PORT] [--mode MODE]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("port", "Listen port for the proxy")
                .with_short('p')
                .with_default("8080"),
            Flag::new("bind", "Bind address")
                .with_short('b')
                .with_default("0.0.0.0"),
            Flag::new("timeout", "Connection timeout in seconds")
                .with_short('t')
                .with_default("30"),
            Flag::new("mode", "Proxy mode: redirect (NAT) or tproxy")
                .with_short('m')
                .with_default("redirect"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Generate iptables rules",
                "rb proxy transparent iptables --port 8080",
            ),
            (
                "Start transparent proxy",
                "rb proxy transparent start --port 8080",
            ),
            (
                "Use TPROXY mode (preserves source IP)",
                "rb proxy transparent start --mode tproxy --port 8080",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "start" => self.start_proxy(ctx),
            "iptables" => self.show_iptables(ctx),
            "nftables" => self.show_nftables(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(verb, &["start", "iptables", "nftables"])
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl TransparentProxyCommand {
    fn parse_mode(&self, mode_str: &str) -> Result<TransparentMode, String> {
        match mode_str.to_lowercase().as_str() {
            "redirect" | "nat" => Ok(TransparentMode::Redirect),
            "tproxy" | "transparent" => Ok(TransparentMode::TProxy),
            _ => Err(format!(
                "Invalid mode '{}'. Use 'redirect' (NAT) or 'tproxy'",
                mode_str
            )),
        }
    }

    fn start_proxy(&self, ctx: &CliContext) -> Result<(), String> {
        Output::header("Transparent Proxy");
        println!();

        let bind = ctx.get_flag_or("bind", "0.0.0.0");
        let port: u16 = ctx
            .get_flag_or("port", "8080")
            .parse()
            .map_err(|_| "Invalid port number")?;

        let timeout: u64 = ctx
            .get_flag_or("timeout", "30")
            .parse()
            .map_err(|_| "Invalid timeout value")?;

        let mode = self.parse_mode(&ctx.get_flag_or("mode", "redirect"))?;

        let listen_addr: SocketAddr = format!("{}:{}", bind, port)
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        let mode_name = match mode {
            TransparentMode::Redirect => "NAT Redirect (SO_ORIGINAL_DST)",
            TransparentMode::TProxy => "TPROXY (IP_TRANSPARENT)",
        };

        Output::item("Listen Address", &listen_addr.to_string());
        Output::item("Mode", mode_name);
        Output::item("Timeout", &format!("{}s", timeout));
        println!();

        #[cfg(not(target_os = "linux"))]
        {
            Output::error("Transparent proxy is only supported on Linux");
            return Err("Platform not supported".to_string());
        }

        #[cfg(target_os = "linux")]
        {
            Output::warning("Transparent proxy requires iptables/nftables rules.");
            Output::info("Run the following to set up iptables:");
            println!();
            for rule in generate_iptables_rules(port, mode) {
                if rule.starts_with('#') {
                    println!("  \x1b[90m{}\x1b[0m", rule);
                } else if !rule.is_empty() {
                    println!("  \x1b[33m{}\x1b[0m", rule);
                } else {
                    println!();
                }
            }
            println!();

            if mode == TransparentMode::TProxy {
                Output::warning("TPROXY mode requires CAP_NET_ADMIN capability");
                Output::info("Run with: sudo setcap cap_net_admin+ep ./rb");
            }

            Output::success(&format!(
                "Starting transparent proxy on {}...",
                listen_addr
            ));
            println!();

            let config = TransparentConfig::new(listen_addr)
                .with_mode(mode)
                .with_timeout(Duration::from_secs(timeout));

            let proxy = TransparentProxy::new(config);
            proxy.run().map_err(|e| format!("Proxy error: {}", e))
        }
    }

    fn show_iptables(&self, ctx: &CliContext) -> Result<(), String> {
        let port: u16 = ctx
            .get_flag_or("port", "8080")
            .parse()
            .map_err(|_| "Invalid port number")?;

        let mode = self.parse_mode(&ctx.get_flag_or("mode", "redirect"))?;

        Output::header("iptables Rules for Transparent Proxy");
        println!();

        for rule in generate_iptables_rules(port, mode) {
            if rule.starts_with('#') {
                println!("\x1b[90m{}\x1b[0m", rule);
            } else if rule.is_empty() {
                println!();
            } else {
                println!("\x1b[33m{}\x1b[0m", rule);
            }
        }

        Ok(())
    }

    fn show_nftables(&self, ctx: &CliContext) -> Result<(), String> {
        let port: u16 = ctx
            .get_flag_or("port", "8080")
            .parse()
            .map_err(|_| "Invalid port number")?;

        let mode = self.parse_mode(&ctx.get_flag_or("mode", "redirect"))?;

        Output::header("nftables Rules for Transparent Proxy");
        println!();

        for rule in generate_nftables_rules(port, mode) {
            if rule.starts_with('#') {
                println!("\x1b[90m{}\x1b[0m", rule);
            } else if rule.is_empty() {
                println!();
            } else {
                println!("\x1b[33m{}\x1b[0m", rule);
            }
        }

        Ok(())
    }
}

// ============================================================================
// Proxy Data Command (History/Analytics)
// ============================================================================

pub struct ProxyDataCommand;

impl Command for ProxyDataCommand {
    fn domain(&self) -> &str {
        "proxy"
    }

    fn resource(&self) -> &str {
        "data"
    }

    fn description(&self) -> &str {
        "Query stored proxy connection history and traffic data"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "list",
                summary: "List all proxy connections from stored data",
                usage: "rb proxy data list [--db FILE]",
            },
            Route {
                verb: "requests",
                summary: "List HTTP requests from proxy sessions",
                usage: "rb proxy data requests [--db FILE] [--host HOST]",
            },
            Route {
                verb: "responses",
                summary: "List HTTP responses from proxy sessions",
                usage: "rb proxy data responses [--db FILE] [--status CODE]",
            },
            Route {
                verb: "show",
                summary: "Show details for a specific connection",
                usage: "rb proxy data show <connection_id> [--db FILE]",
            },
            Route {
                verb: "stats",
                summary: "Show proxy data statistics",
                usage: "rb proxy data stats [--db FILE]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("db", "Database file to query").with_short('d'),
            Flag::new("host", "Filter by destination host").with_short('h'),
            Flag::new("status", "Filter by HTTP status code").with_short('s'),
            Flag::new("limit", "Maximum number of results")
                .with_short('l')
                .with_default("50"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("List all proxy connections", "rb proxy data list"),
            ("List connections from specific database", "rb proxy data list --db target.rdb"),
            ("Show requests to a specific host", "rb proxy data requests --host api.example.com"),
            ("Show connection details", "rb proxy data show 12345"),
            ("Show proxy statistics", "rb proxy data stats"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "list" => self.list_connections(ctx),
            "requests" => self.list_requests(ctx),
            "responses" => self.list_responses(ctx),
            "show" => self.show_connection(ctx),
            "stats" => self.show_stats(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(verb, &["list", "requests", "responses", "show", "stats"])
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl ProxyDataCommand {
    fn resolve_db_path(&self, ctx: &CliContext) -> Result<String, String> {
        if let Some(db) = ctx.get_flag("db") {
            return Ok(db.clone());
        }

        // Look for .rdb files in current directory
        let entries = std::fs::read_dir(".")
            .map_err(|e| format!("Failed to read current directory: {}", e))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "rdb" {
                    if let Some(p) = path.to_str() {
                        return Ok(p.to_string());
                    }
                }
            }
        }

        Err("No database file specified. Use --db <file> or run from a directory with .rdb files".to_string())
    }

    fn list_connections(&self, ctx: &CliContext) -> Result<(), String> {
        let db_path = self.resolve_db_path(ctx)?;
        let limit: usize = ctx
            .get_flag_or("limit", "50")
            .parse()
            .map_err(|_| "Invalid limit")?;

        Output::header("Proxy Connections");
        Output::item("Database", &db_path);
        println!();

        let qm = QueryManager::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        let connections = qm.list_proxy_connections()
            .map_err(|e| format!("Failed to list connections: {}", e))?;

        if connections.is_empty() {
            Output::info("No proxy connections found in database");
            return Ok(());
        }

        // Table header
        println!("{:<12} {:<20} {:<8} {:<30} {:<10} {:<10}",
            "CONN_ID", "SOURCE", "PROTO", "DESTINATION", "TX BYTES", "RX BYTES");
        println!("{}", "─".repeat(90));

        for conn in connections.iter().take(limit) {
            let proto = match conn.protocol {
                0 => "TCP",
                1 => "UDP",
                2 => "TLS",
                _ => "?",
            };
            let src = format!("{}:{}", conn.src_ip, conn.src_port);
            let dst = format!("{}:{}", conn.dst_host, conn.dst_port);

            println!("{:<12} {:<20} {:<8} {:<30} {:<10} {:<10}",
                conn.connection_id,
                src,
                proto,
                dst,
                format_bytes(conn.bytes_sent),
                format_bytes(conn.bytes_received),
            );
        }

        println!();
        if connections.len() > limit {
            Output::info(&format!("Showing {} of {} connections (use --limit to show more)", limit, connections.len()));
        } else {
            Output::info(&format!("Found {} connection(s)", connections.len()));
        }

        Ok(())
    }

    fn list_requests(&self, ctx: &CliContext) -> Result<(), String> {
        let db_path = self.resolve_db_path(ctx)?;
        let limit: usize = ctx
            .get_flag_or("limit", "50")
            .parse()
            .map_err(|_| "Invalid limit")?;
        let host_filter = ctx.get_flag("host");

        Output::header("Proxy HTTP Requests");
        Output::item("Database", &db_path);
        if let Some(h) = &host_filter {
            Output::item("Host Filter", h);
        }
        println!();

        let qm = QueryManager::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        let requests = qm.list_proxy_requests()
            .map_err(|e| format!("Failed to list requests: {}", e))?;

        // Filter by host if specified
        let filtered: Vec<_> = if let Some(host) = host_filter {
            requests.into_iter()
                .filter(|r| r.host.contains(&host))
                .collect()
        } else {
            requests
        };

        if filtered.is_empty() {
            Output::info("No proxy requests found");
            return Ok(());
        }

        // Table header
        println!("{:<12} {:<8} {:<40} {:<30}",
            "CONN_ID", "METHOD", "PATH", "HOST");
        println!("{}", "─".repeat(90));

        for req in filtered.iter().take(limit) {
            let path = if req.path.len() > 38 {
                format!("{}...", &req.path[..35])
            } else {
                req.path.clone()
            };

            println!("{:<12} {:<8} {:<40} {:<30}",
                req.connection_id,
                req.method,
                path,
                req.host,
            );
        }

        println!();
        if filtered.len() > limit {
            Output::info(&format!("Showing {} of {} requests", limit, filtered.len()));
        } else {
            Output::info(&format!("Found {} request(s)", filtered.len()));
        }

        Ok(())
    }

    fn list_responses(&self, ctx: &CliContext) -> Result<(), String> {
        let db_path = self.resolve_db_path(ctx)?;
        let limit: usize = ctx
            .get_flag_or("limit", "50")
            .parse()
            .map_err(|_| "Invalid limit")?;
        let status_filter: Option<u16> = ctx.get_flag("status")
            .and_then(|s| s.parse().ok());

        Output::header("Proxy HTTP Responses");
        Output::item("Database", &db_path);
        if let Some(s) = status_filter {
            Output::item("Status Filter", &s.to_string());
        }
        println!();

        let qm = QueryManager::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        let responses = qm.list_proxy_responses()
            .map_err(|e| format!("Failed to list responses: {}", e))?;

        // Filter by status if specified
        let filtered: Vec<_> = if let Some(status) = status_filter {
            responses.into_iter()
                .filter(|r| r.status_code == status)
                .collect()
        } else {
            responses
        };

        if filtered.is_empty() {
            Output::info("No proxy responses found");
            return Ok(());
        }

        // Table header
        println!("{:<12} {:<8} {:<20} {:<30} {:<15}",
            "CONN_ID", "STATUS", "STATUS_TEXT", "CONTENT_TYPE", "BODY_SIZE");
        println!("{}", "─".repeat(85));

        for resp in filtered.iter().take(limit) {
            let content_type = resp.content_type.as_deref().unwrap_or("-");
            let content_type_short = if content_type.len() > 28 {
                format!("{}...", &content_type[..25])
            } else {
                content_type.to_string()
            };

            let status_color = if resp.status_code >= 200 && resp.status_code < 300 {
                "\x1b[32m" // Green
            } else if resp.status_code >= 400 {
                "\x1b[31m" // Red
            } else if resp.status_code >= 300 {
                "\x1b[33m" // Yellow
            } else {
                ""
            };

            println!("{:<12} {}{:<8}\x1b[0m {:<20} {:<30} {:<15}",
                resp.connection_id,
                status_color,
                resp.status_code,
                resp.status_text,
                content_type_short,
                format_bytes(resp.body.len() as u64),
            );
        }

        println!();
        if filtered.len() > limit {
            Output::info(&format!("Showing {} of {} responses", limit, filtered.len()));
        } else {
            Output::info(&format!("Found {} response(s)", filtered.len()));
        }

        Ok(())
    }

    fn show_connection(&self, ctx: &CliContext) -> Result<(), String> {
        let db_path = self.resolve_db_path(ctx)?;
        let conn_id: u64 = ctx.target.as_ref()
            .ok_or("Missing connection ID")?
            .parse()
            .map_err(|_| "Invalid connection ID")?;

        let qm = QueryManager::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        let conn = qm.get_proxy_connection(conn_id)
            .map_err(|e| format!("Failed to get connection: {}", e))?
            .ok_or_else(|| format!("Connection {} not found", conn_id))?;

        Output::header(&format!("Proxy Connection #{}", conn_id));
        println!();

        let proto = match conn.protocol {
            0 => "TCP",
            1 => "UDP",
            2 => "TLS",
            _ => "Unknown",
        };

        Output::item("Source", &format!("{}:{}", conn.src_ip, conn.src_port));
        Output::item("Destination", &format!("{}:{}", conn.dst_host, conn.dst_port));
        Output::item("Protocol", proto);
        Output::item("TLS Intercepted", if conn.tls_intercepted { "Yes" } else { "No" });
        Output::item("Started", &format_timestamp(conn.started_at));
        Output::item("Ended", &format_timestamp(conn.ended_at));
        Output::item("Bytes Sent", &format_bytes(conn.bytes_sent));
        Output::item("Bytes Received", &format_bytes(conn.bytes_received));
        Output::item("Duration", &format!("{} seconds", conn.ended_at.saturating_sub(conn.started_at)));

        // Show requests for this connection
        let requests = qm.list_proxy_requests()
            .map_err(|e| format!("Failed to list requests: {}", e))?;
        let conn_requests: Vec<_> = requests.iter()
            .filter(|r| r.connection_id == conn_id)
            .collect();

        if !conn_requests.is_empty() {
            println!();
            Output::subheader(&format!("HTTP Requests ({})", conn_requests.len()));
            for req in conn_requests {
                println!("  [{:>3}] {} {} {}",
                    req.request_seq, req.method, req.path, req.http_version);
            }
        }

        // Show responses for this connection
        let responses = qm.list_proxy_responses()
            .map_err(|e| format!("Failed to list responses: {}", e))?;
        let conn_responses: Vec<_> = responses.iter()
            .filter(|r| r.connection_id == conn_id)
            .collect();

        if !conn_responses.is_empty() {
            println!();
            Output::subheader(&format!("HTTP Responses ({})", conn_responses.len()));
            for resp in conn_responses {
                println!("  [{:>3}] {} {} ({} bytes)",
                    resp.request_seq, resp.status_code, resp.status_text, resp.body.len());
            }
        }

        Ok(())
    }

    fn show_stats(&self, ctx: &CliContext) -> Result<(), String> {
        let db_path = self.resolve_db_path(ctx)?;

        let qm = QueryManager::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        Output::header("Proxy Data Statistics");
        Output::item("Database", &db_path);
        println!();

        let connections = qm.list_proxy_connections()
            .map_err(|e| format!("Failed to list connections: {}", e))?;
        let requests = qm.list_proxy_requests()
            .map_err(|e| format!("Failed to list requests: {}", e))?;
        let responses = qm.list_proxy_responses()
            .map_err(|e| format!("Failed to list responses: {}", e))?;

        // Connection stats
        let total_bytes_sent: u64 = connections.iter().map(|c| c.bytes_sent).sum();
        let total_bytes_recv: u64 = connections.iter().map(|c| c.bytes_received).sum();
        let tls_count = connections.iter().filter(|c| c.tls_intercepted).count();

        println!("SEGMENT                   COUNT");
        println!("────────────────────────────────");
        println!("{:<24} {:>6}", "Connections", connections.len());
        println!("{:<24} {:>6}", "  └ TLS Intercepted", tls_count);
        println!("{:<24} {:>6}", "HTTP Requests", requests.len());
        println!("{:<24} {:>6}", "HTTP Responses", responses.len());
        println!("────────────────────────────────");
        println!("{:<24} {:>6}", "Total Bytes Sent", format_bytes(total_bytes_sent));
        println!("{:<24} {:>6}", "Total Bytes Received", format_bytes(total_bytes_recv));

        // Top hosts
        if !requests.is_empty() {
            println!();
            Output::subheader("Top Hosts");

            let mut host_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
            for req in &requests {
                *host_counts.entry(&req.host).or_insert(0) += 1;
            }
            let mut sorted: Vec<_> = host_counts.into_iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));

            for (host, count) in sorted.iter().take(10) {
                println!("  {:<40} {:>6}", host, count);
            }
        }

        // Status code distribution
        if !responses.is_empty() {
            println!();
            Output::subheader("Status Code Distribution");

            let mut status_counts: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
            for resp in &responses {
                *status_counts.entry(resp.status_code).or_insert(0) += 1;
            }
            let mut sorted: Vec<_> = status_counts.into_iter().collect();
            sorted.sort_by_key(|(code, _)| *code);

            for (code, count) in sorted {
                let color = if code >= 200 && code < 300 {
                    "\x1b[32m"
                } else if code >= 400 {
                    "\x1b[31m"
                } else if code >= 300 {
                    "\x1b[33m"
                } else {
                    ""
                };
                println!("  {}{:<6}\x1b[0m {:>6}", color, code, count);
            }
        }

        Ok(())
    }
}

// Helper functions
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.2} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

fn format_timestamp(ts: u32) -> String {
    if ts == 0 {
        return "-".to_string();
    }
    // Simple timestamp formatting (Unix epoch)
    use std::time::{Duration as StdDuration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + StdDuration::from_secs(ts as u64);
    format!("{:?}", dt)
}
