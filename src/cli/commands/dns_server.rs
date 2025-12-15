/// DNS Server command - DNS server with hijacking capabilities
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, validator::Validator, CliContext};
use crate::modules::dns::server::{DnsRule, DnsServer, DnsServerConfig};
use std::net::IpAddr;

pub struct DnsServerCommand;

impl Command for DnsServerCommand {
    fn domain(&self) -> &str {
        "dns"
    }

    fn resource(&self) -> &str {
        "server"
    }

    fn description(&self) -> &str {
        "DNS server with hijacking capabilities for MITM attacks"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "start",
                summary: "Start the DNS server",
                usage: "rb dns server start [--bind 0.0.0.0:53]",
            },
            Route {
                verb: "hijack",
                summary: "Start server with hijacking rules",
                usage: "rb dns server hijack --target *.example.com --ip 10.0.0.1",
            },
            Route {
                verb: "block",
                summary: "Start server blocking specific domains",
                usage: "rb dns server block --pattern *.ads.com",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("bind", "Bind address (IP:port)")
                .with_short('b')
                .with_default("0.0.0.0:53"),
            Flag::new("upstream", "Upstream DNS server")
                .with_short('u')
                .with_default("8.8.8.8"),
            Flag::new("upstream-fallback", "Fallback upstream DNS server").with_default("1.1.1.1"),
            Flag::new(
                "target",
                "Domain pattern to hijack (supports *.example.com)",
            )
            .with_short('t'),
            Flag::new("ip", "IP address to return for hijacked domains"),
            Flag::new("pattern", "Domain pattern to block (supports wildcards)").with_short('p'),
            Flag::new("no-cache", "Disable DNS response caching"),
            Flag::new("no-tcp", "Disable TCP DNS server"),
            Flag::new("log", "Enable query logging").with_short('l'),
            Flag::new(
                "rules",
                "Load rules from file (one per line: pattern,action,value)",
            ),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Start basic DNS server", "rb dns server start"),
            (
                "Start with custom upstream",
                "rb dns server start --upstream 1.1.1.1",
            ),
            (
                "Hijack a domain",
                "rb dns server hijack --target *.target.com --ip 10.0.0.1",
            ),
            (
                "Block ad domains",
                "rb dns server block --pattern *.ads.com",
            ),
            ("Start with logging", "rb dns server start --log"),
            (
                "Custom bind address",
                "rb dns server start --bind 127.0.0.1:5353",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "start" => self.start_server(ctx),
            "hijack" => self.start_hijack(ctx),
            "block" => self.start_block(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                println!(
                    "{}",
                    Validator::suggest_command(verb, &["start", "hijack", "block"])
                );
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl DnsServerCommand {
    fn build_config(&self, ctx: &CliContext) -> Result<DnsServerConfig, String> {
        let bind_str = ctx.get_flag_or("bind", "0.0.0.0:53");
        let bind_addr = bind_str
            .parse()
            .map_err(|e| format!("Invalid bind address '{}': {}", bind_str, e))?;

        let upstream = ctx.get_flag_or("upstream", "8.8.8.8");
        let upstream_fallback = ctx.get_flag("upstream-fallback");

        let enable_cache = !ctx.has_flag("no-cache");
        let enable_tcp = !ctx.has_flag("no-tcp");
        let log_queries = ctx.has_flag("log");

        Ok(DnsServerConfig {
            bind_udp: bind_addr,
            bind_tcp: bind_addr,
            upstream: upstream.to_string(),
            upstream_secondary: upstream_fallback,
            enable_cache,
            enable_tcp,
            log_queries,
            ..Default::default()
        })
    }

    fn start_server(&self, ctx: &CliContext) -> Result<(), String> {
        let config = self.build_config(ctx)?;

        Output::header("DNS Server");
        Output::item("Bind Address", &config.bind_udp.to_string());
        Output::item("Upstream", &config.upstream);
        if let Some(ref fallback) = config.upstream_secondary {
            Output::item("Fallback", fallback);
        }
        Output::item(
            "Cache",
            if config.enable_cache {
                "enabled"
            } else {
                "disabled"
            },
        );
        Output::item(
            "TCP",
            if config.enable_tcp {
                "enabled"
            } else {
                "disabled"
            },
        );
        Output::item(
            "Logging",
            if config.log_queries {
                "enabled"
            } else {
                "disabled"
            },
        );
        println!();

        // Load rules from file if specified
        let mut server = DnsServer::new(config);

        if let Some(rules_file) = ctx.get_flag("rules") {
            let rules = self.load_rules_from_file(&rules_file)?;
            server.add_rules(rules);
            Output::success(&format!(
                "Loaded {} rules from {}",
                server.stats().queries_received,
                rules_file
            ));
        }

        Output::info("Starting DNS server... Press Ctrl+C to stop");
        println!();

        // Run server
        server.run()
    }

    fn start_hijack(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.get_flag("target").ok_or(
            "Missing --target flag.\nUsage: rb dns server hijack --target *.example.com --ip 10.0.0.1",
        )?;

        let ip_str = ctx.get_flag("ip").ok_or(
            "Missing --ip flag.\nUsage: rb dns server hijack --target *.example.com --ip 10.0.0.1",
        )?;

        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| format!("Invalid IP address '{}': {}", ip_str, e))?;

        let config = self.build_config(ctx)?;

        Output::header("DNS Hijacking Server");
        Output::item("Target Pattern", &target);
        Output::item("Hijack IP", &ip.to_string());
        Output::item("Bind Address", &config.bind_udp.to_string());
        Output::item("Upstream", &config.upstream);
        println!();

        let mut server = DnsServer::new(config);

        // Add hijack rule based on IP type
        let rule = match ip {
            IpAddr::V4(_) => DnsRule::override_a(&target, &ip_str),
            IpAddr::V6(_) => DnsRule::override_aaaa(&target, &ip_str),
        };
        server.add_rule(rule);

        Output::warning("DNS hijacking is enabled for authorized testing only!");
        Output::info("Starting DNS server... Press Ctrl+C to stop");
        println!();

        server.run()
    }

    fn start_block(&self, ctx: &CliContext) -> Result<(), String> {
        let pattern = ctx
            .get_flag("pattern")
            .ok_or("Missing --pattern flag.\nUsage: rb dns server block --pattern *.ads.com")?;

        let config = self.build_config(ctx)?;

        Output::header("DNS Blocking Server");
        Output::item("Block Pattern", &pattern);
        Output::item("Bind Address", &config.bind_udp.to_string());
        Output::item("Upstream", &config.upstream);
        println!();

        let mut server = DnsServer::new(config);

        // Add block rule
        server.add_rule(DnsRule::block(&pattern));

        Output::info("Starting DNS server with blocking... Press Ctrl+C to stop");
        println!();

        server.run()
    }

    fn load_rules_from_file(&self, path: &str) -> Result<Vec<DnsRule>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read rules file '{}': {}", path, e))?;

        let mut rules = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if parts.len() < 2 {
                Output::warning(&format!(
                    "Line {}: Invalid rule format, expected: pattern,action[,value]",
                    line_num + 1
                ));
                continue;
            }

            let pattern = parts[0];
            let action = parts[1].to_lowercase();
            let value = parts.get(2).copied();

            let rule = match action.as_str() {
                "block" => DnsRule::block(pattern),
                "allow" => DnsRule::allow(pattern),
                "override" | "hijack" => {
                    let ip = value.ok_or_else(|| {
                        format!("Line {}: 'override' action requires IP value", line_num + 1)
                    })?;
                    let ip_addr: IpAddr = ip.parse().map_err(|e| {
                        format!("Line {}: Invalid IP '{}': {}", line_num + 1, ip, e)
                    })?;
                    match ip_addr {
                        IpAddr::V4(_) => DnsRule::override_a(pattern, ip),
                        IpAddr::V6(_) => DnsRule::override_aaaa(pattern, ip),
                    }
                }
                "redirect" => {
                    let target = value.ok_or_else(|| {
                        format!(
                            "Line {}: 'redirect' action requires target domain",
                            line_num + 1
                        )
                    })?;
                    DnsRule::redirect(pattern, target)
                }
                "forward" => {
                    let upstream = value.ok_or_else(|| {
                        format!(
                            "Line {}: 'forward' action requires upstream server",
                            line_num + 1
                        )
                    })?;
                    DnsRule::forward(pattern, upstream)
                }
                _ => {
                    Output::warning(&format!(
                        "Line {}: Unknown action '{}', skipping",
                        line_num + 1,
                        action
                    ));
                    continue;
                }
            };

            rules.push(rule);
        }

        Ok(rules)
    }
}
