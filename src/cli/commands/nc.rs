/// Netcat (nc) - Network Swiss Army Knife
///
/// Complete netcat replacement for penetration testing and network operations.
/// Used in 100% of CTF competitions and penetration tests.
///
/// ⚠️ AUTHORIZED USE ONLY - For penetration testing, CTFs, and educational purposes.
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::CliContext;
use crate::modules::network::broker::{Broker, BrokerConfig};
use crate::modules::network::netcat::{Netcat, NetcatConfig, Protocol};
use crate::modules::network::relay::{EndpointType, Relay, RelayConfig};
use std::time::Duration;

pub struct NetcatCommand;

impl Command for NetcatCommand {
    fn domain(&self) -> &str {
        "nc"
    }

    fn resource(&self) -> &str {
        "" // Standalone command
    }

    fn description(&self) -> &str {
        "Netcat - Network Swiss Army Knife for TCP/UDP communication"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "listen",
                summary: "Listen for incoming connections (server mode)",
                usage: "rb nc listen <port> [FLAGS]",
            },
            Route {
                verb: "connect",
                summary: "Connect to remote host (client mode)",
                usage: "rb nc connect <host> <port> [FLAGS]",
            },
            Route {
                verb: "scan",
                summary: "Port scanning (zero I/O mode)",
                usage: "rb nc scan <host> <port>",
            },
            Route {
                verb: "relay",
                summary: "Port forwarding / relay (socat-style)",
                usage: "rb nc relay <source> <destination> [FLAGS]",
            },
            Route {
                verb: "broker",
                summary: "Multi-client chat server (ncat --broker)",
                usage: "rb nc broker <port> [FLAGS]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("udp", "Use UDP instead of TCP")
                .with_short('u')
                .with_default("false"),
            Flag::new("verbose", "Verbose output")
                .with_short('v')
                .with_default("false"),
            Flag::new("timeout", "Connection timeout in seconds")
                .with_short('t')
                .with_default("10"),
            Flag::new("hex", "Hex dump mode")
                .with_short('x')
                .with_default("false"),
            Flag::new("fork", "Fork mode - handle multiple simultaneous connections (relay only)")
                .with_short('f')
                .with_default("false"),
            Flag::new("chat-log", "Log all chat messages to file (broker only)")
                .with_default(""),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            // Listener examples
            (
                "Listen on port 4444 (reverse shell listener)",
                "rb nc listen 4444",
            ),
            (
                "Listen on port 443 with verbose output",
                "rb nc listen 443 --verbose",
            ),
            ("UDP listener on port 53", "rb nc listen 53 --udp"),
            // Client examples
            ("Connect to HTTP server", "rb nc connect example.com 80"),
            (
                "Connect with verbose output",
                "rb nc connect 192.168.1.1 22 --verbose",
            ),
            ("UDP client", "rb nc connect 8.8.8.8 53 --udp"),
            // Port scanning
            ("Check if port is open", "rb nc scan example.com 443"),
            (
                "Scan with custom timeout",
                "rb nc scan 192.168.1.1 22 --timeout 2",
            ),
            // Real-world use cases
            ("🎯 Reverse shell listener", "rb nc listen 4444"),
            ("🎯 Banner grab SSH", "rb nc connect target.com 22"),
            ("🎯 Test connectivity", "rb nc scan internal.server 3306"),
            // Relay examples
            ("Port forward 8080 -> 80", "rb nc relay tcp:8080 tcp:internal:80"),
            ("UDP to TCP relay", "rb nc relay udp:53 tcp:dns-server:53"),
            (
                "Multiple connections (fork mode)",
                "rb nc relay tcp:8080 tcp:backend:80 --fork",
            ),
            // Broker examples
            ("Chat server", "rb nc broker 4444"),
            (
                "Chat with logging",
                "rb nc broker 4444 --chat-log chat.txt --verbose",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        // Netcat follows NEW parser pattern: rb nc <verb> <args>
        // With "listen"/"connect" in RESTFUL_VERBS, parser does:
        //   rb nc listen 4444           → domain=nc, verb=listen, resource=4444
        //   rb nc scan host port        → domain=nc, verb=scan, resource=host, target=port
        //   rb nc connect host port     → domain=nc, verb=connect, resource=host, target=port
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "Missing verb. Use 'listen', 'connect', or 'scan'".to_string()
        })?;

        match verb.as_str() {
            "listen" | "l" => self.listen(ctx),
            "connect" | "c" => self.connect(ctx),
            "scan" | "s" => self.scan(ctx),
            "relay" | "r" => self.relay(ctx),
            "broker" | "b" => self.broker(ctx),
            "help" | "--help" | "-h" => {
                print_help(self);
                Ok(())
            }
            _ => {
                print_help(self);
                Err(format!(
                    "Unknown verb '{}'. Use 'listen', 'connect', 'scan', 'relay', or 'broker'",
                    verb
                ))
            }
        }
    }
}

impl NetcatCommand {
    /// Listen mode (server)
    fn listen(&self, ctx: &CliContext) -> Result<(), String> {
        // NEW pattern: rb nc listen 4444 → domain=nc, verb=listen, resource=4444
        let port_str = ctx
            .resource
            .as_ref()
            .ok_or("Missing port number. Usage: rb nc listen <port>")?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port number: {}", port_str))?;

        // Parse flags
        let udp = ctx.has_flag("udp");
        let verbose = ctx.has_flag("verbose");
        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);

        // Build configuration
        let mut config = NetcatConfig::server(port)
            .with_verbose(verbose)
            .with_timeout(Duration::from_secs(timeout_secs));

        if udp {
            config = config.with_protocol(Protocol::Udp);
        }

        // Create and run netcat
        let nc = Netcat::new(config);
        nc.run()
    }

    /// Connect mode (client)
    fn connect(&self, ctx: &CliContext) -> Result<(), String> {
        // NEW pattern: rb nc connect example.com 80 → domain=nc, verb=connect, resource=example.com, target=80
        let host = ctx
            .resource
            .as_ref()
            .ok_or("Missing host. Usage: rb nc connect <host> <port>")?;
        let port_str = ctx
            .target
            .as_ref()
            .ok_or("Missing port. Usage: rb nc connect <host> <port>")?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port number: {}", port_str))?;

        // Parse flags
        let udp = ctx.has_flag("udp");
        let verbose = ctx.has_flag("verbose");
        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);

        // Build configuration
        let mut config = NetcatConfig::client(host, port)
            .with_verbose(verbose)
            .with_timeout(Duration::from_secs(timeout_secs));

        if udp {
            config = config.with_protocol(Protocol::Udp);
        }

        // Create and run netcat
        let nc = Netcat::new(config);
        nc.run()
    }

    /// Scan mode (zero I/O)
    fn scan(&self, ctx: &CliContext) -> Result<(), String> {
        // NEW pattern: rb nc scan example.com 443 → domain=nc, verb=scan, resource=example.com, target=443
        let host = ctx
            .resource
            .as_ref()
            .ok_or("Missing host. Usage: rb nc scan <host> <port>")?;
        let port_str = ctx
            .target
            .as_ref()
            .ok_or("Missing port. Usage: rb nc scan <host> <port>")?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port number: {}", port_str))?;

        // Parse flags
        let verbose = ctx.has_flag("verbose");
        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2);

        // Build configuration with zero I/O mode
        let config = NetcatConfig::client(host, port)
            .with_verbose(verbose)
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_zero_io(true);

        // Create and run netcat
        let nc = Netcat::new(config);
        nc.run()
    }

    /// Relay mode (port forwarding)
    fn relay(&self, ctx: &CliContext) -> Result<(), String> {
        // NEW pattern: rb nc relay tcp:8080 tcp:internal:80
        // resource = "tcp:8080", target = "tcp:internal:80"
        let source_str = ctx
            .resource
            .as_ref()
            .ok_or("Missing source endpoint. Usage: rb nc relay <source> <destination>")?;
        let dest_str = ctx
            .target
            .as_ref()
            .ok_or("Missing destination endpoint. Usage: rb nc relay <source> <destination>")?;

        // Parse endpoints
        let source = Self::parse_endpoint(source_str)?;
        let destination = Self::parse_endpoint(dest_str)?;

        // Parse flags
        let verbose = ctx.has_flag("verbose");
        let fork = ctx.has_flag("fork");
        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);

        // Build configuration
        let config = RelayConfig::new(source, destination)
            .with_verbose(verbose)
            .with_fork(fork)
            .with_timeout(Duration::from_secs(timeout_secs));

        // Create and run relay
        let relay = Relay::new(config);
        relay.run()
    }

    /// Parse endpoint string (tcp:8080, udp:host:port, etc.)
    fn parse_endpoint(s: &str) -> Result<EndpointType, String> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() < 2 {
            return Err(format!(
                "Invalid endpoint format: {}. Expected tcp:port or tcp:host:port",
                s
            ));
        }

        let protocol = parts[0].to_lowercase();

        match protocol.as_str() {
            "tcp" => {
                if parts.len() == 2 {
                    // tcp:8080 - listen mode
                    let port: u16 = parts[1]
                        .parse()
                        .map_err(|_| format!("Invalid port number: {}", parts[1]))?;
                    Ok(EndpointType::TcpListen(port))
                } else if parts.len() == 3 {
                    // tcp:host:port - connect mode
                    let host = parts[1].to_string();
                    let port: u16 = parts[2]
                        .parse()
                        .map_err(|_| format!("Invalid port number: {}", parts[2]))?;
                    Ok(EndpointType::TcpConnect(host, port))
                } else {
                    Err(format!("Invalid TCP endpoint format: {}", s))
                }
            }
            "udp" => {
                if parts.len() == 2 {
                    // udp:53 - listen mode
                    let port: u16 = parts[1]
                        .parse()
                        .map_err(|_| format!("Invalid port number: {}", parts[1]))?;
                    Ok(EndpointType::UdpListen(port))
                } else if parts.len() == 3 {
                    // udp:host:port - connect mode
                    let host = parts[1].to_string();
                    let port: u16 = parts[2]
                        .parse()
                        .map_err(|_| format!("Invalid port number: {}", parts[2]))?;
                    Ok(EndpointType::UdpConnect(host, port))
                } else {
                    Err(format!("Invalid UDP endpoint format: {}", s))
                }
            }
            _ => Err(format!(
                "Unknown protocol: {}. Use 'tcp' or 'udp'",
                protocol
            )),
        }
    }

    /// Broker mode (multi-client chat server)
    fn broker(&self, ctx: &CliContext) -> Result<(), String> {
        // NEW pattern: rb nc broker 4444 → domain=nc, verb=broker, resource=4444
        let port_str = ctx
            .resource
            .as_ref()
            .ok_or("Missing port number. Usage: rb nc broker <port>")?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port number: {}", port_str))?;

        // Parse flags
        let verbose = ctx.has_flag("verbose");
        let chat_log = ctx.get_flag("chat-log").filter(|s| !s.is_empty()).cloned();

        // Build configuration
        let config = BrokerConfig::new(port)
            .with_verbose(verbose)
            .with_log_file(chat_log);

        // Create and run broker
        let broker = Broker::new(config);
        broker.run()
    }
}
