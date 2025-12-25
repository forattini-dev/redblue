/// Netcat (nc) - Network Swiss Army Knife
///
/// Complete netcat replacement for penetration testing and network operations.
/// Used in 100% of CTF competitions and penetration tests.
///
/// ⚠️ AUTHORIZED USE ONLY - For penetration testing, CTFs, and educational purposes.
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::CliContext;
use crate::modules::network::broker::{Broker, BrokerConfig};
use crate::modules::network::netcat::{IpVersion, Netcat, NetcatConfig, Protocol};
use crate::modules::network::relay::{EndpointType, Relay, RelayConfig};
use crate::modules::network::unix_socket::{
    UnixSocketConfig, UnixSocketManager, UnixSocketMode, UnixSocketType,
};
use std::path::PathBuf;
use std::time::Duration;

pub struct NetcatCommand;

impl Command for NetcatCommand {
    fn domain(&self) -> &str {
        "network"
    }

    fn resource(&self) -> &str {
        "nc"
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
            Flag::new("output", "Output format (text, json, yaml)")
                .with_short('o')
                .with_default("text"),
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
            Flag::new(
                "keep-open",
                "Keep listening, accept multiple connections (server only)",
            )
            .with_short('k')
            .with_default("false"),
            Flag::new("source-port", "Bind to specific source port (client only)")
                .with_short('p')
                .with_default(""),
            Flag::new("exec", "Execute command on connection (e.g., /bin/bash)")
                .with_short('e')
                .with_default(""),
            Flag::new(
                "fork",
                "Fork mode - handle multiple simultaneous connections (relay only)",
            )
            .with_short('f')
            .with_default("false"),
            Flag::new("chat-log", "Log all chat messages to file (broker only)").with_default(""),
            Flag::new("ipv4", "Force IPv4 only")
                .with_short('4')
                .with_default("false"),
            Flag::new("ipv6", "Force IPv6 only")
                .with_short('6')
                .with_default("false"),
            Flag::new("encrypt", "Cryptcat mode - Twofish encryption (password)")
                .with_short('c')
                .with_default(""),
            Flag::new("delay", "Delay between lines in milliseconds")
                .with_short('i')
                .with_default(""),
            Flag::new(
                "line-delay",
                "Apply delay only after newlines (requires --delay)",
            )
            .with_default("false"),
            Flag::new(
                "wait",
                "Idle timeout in seconds (connection closes after inactivity)",
            )
            .with_short('w')
            .with_default(""),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            // Listener examples
            (
                "Listen on port 4444 (reverse shell listener)",
                "rb network nc listen 4444",
            ),
            (
                "Listen on port 443 with verbose output",
                "rb network nc listen 443 --verbose",
            ),
            ("UDP listener on port 53", "rb network nc listen 53 --udp"),
            // Client examples
            (
                "Connect to HTTP server",
                "rb network nc connect example.com 80",
            ),
            (
                "Connect with verbose output",
                "rb network nc connect 192.168.1.1 22 --verbose",
            ),
            ("UDP client", "rb network nc connect 8.8.8.8 53 --udp"),
            // Unix sockets
            (
                "Unix socket listener",
                "rb network nc listen unix:/tmp/my.sock",
            ),
            (
                "Unix socket client",
                "rb network nc connect unix:/var/run/docker.sock",
            ),
            // Port scanning
            (
                "Check if port is open",
                "rb network nc scan example.com 443",
            ),
            (
                "Scan with custom timeout",
                "rb network nc scan 192.168.1.1 22 --timeout 2",
            ),
            (
                "Port scan as JSON",
                "rb network nc scan example.com 443 --output=json",
            ),
            // Real-world use cases
            ("🎯 Reverse shell listener", "rb network nc listen 4444"),
            ("🎯 Banner grab SSH", "rb network nc connect target.com 22"),
            (
                "🎯 Test connectivity",
                "rb network nc scan internal.server 3306",
            ),
            (
                "🎯 Talk to Docker daemon",
                "rb network nc connect unix:/var/run/docker.sock",
            ),
            // Relay examples
            (
                "Port forward 8080 -> 80",
                "rb network nc relay tcp:8080 tcp:internal:80",
            ),
            (
                "UDP to TCP relay",
                "rb network nc relay udp:53 tcp:dns-server:53",
            ),
            (
                "Multiple connections (fork mode)",
                "rb network nc relay tcp:8080 tcp:backend:80 --fork",
            ),
            // Broker examples
            ("Chat server", "rb network nc broker 4444"),
            (
                "Chat with logging",
                "rb network nc broker 4444 --chat-log chat.txt --verbose",
            ),
            // Cryptcat (encryption) examples
            (
                "🔐 Encrypted listener (Cryptcat)",
                "rb network nc listen 4444 --encrypt mypassword",
            ),
            (
                "🔐 Encrypted client (Cryptcat)",
                "rb network nc connect target.com 4444 --encrypt mypassword",
            ),
            // Delay and timeout examples
            (
                "Slow connection (100ms delay per write)",
                "rb network nc connect example.com 80 --delay 100",
            ),
            (
                "Delay only after newlines",
                "rb network nc connect example.com 80 --delay 100 --line-delay",
            ),
            (
                "Connection with 5s idle timeout",
                "rb network nc connect example.com 80 --wait 5",
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
        // NEW pattern: rb network nc listen 4444 → domain=network, verb=listen, resource=4444
        // Unix socket: rb network nc listen unix:/path/to/socket
        let resource = ctx
            .resource
            .as_ref()
            .ok_or("Missing port or socket path. Usage: rb network nc listen <port|unix:path>")?;

        // Check if this is a Unix socket
        if resource.starts_with("unix:") {
            return self.listen_unix(ctx, resource);
        }

        // Otherwise, it's a TCP/UDP port
        let port: u16 = resource
            .parse()
            .map_err(|_| format!("Invalid port number: {}", resource))?;

        // Parse flags
        let udp = ctx.has_flag("udp");
        let verbose = ctx.has_flag("verbose");
        let keep_open = ctx.has_flag("keep-open");
        let exec_cmd = ctx.get_flag("exec");
        let ip_version = self.parse_ip_version(ctx)?;
        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);
        let encrypt_password = ctx.get_flag("encrypt");
        let delay_ms = ctx.get_flag("delay").and_then(|s| s.parse::<u64>().ok());
        let line_delay = ctx.has_flag("line-delay");
        let idle_timeout_secs = ctx.get_flag("wait").and_then(|s| s.parse::<u64>().ok());

        // Build configuration
        let mut config = NetcatConfig::server(port)
            .with_verbose(verbose)
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_keep_open(keep_open)
            .with_ip_version(ip_version);

        if udp {
            config = config.with_protocol(Protocol::Udp);
        }

        if let Some(cmd) = exec_cmd {
            config = config.with_exec(cmd.to_string());
        }

        if let Some(password) = encrypt_password {
            config = config.with_encryption(password.to_string());
        }

        if let Some(delay) = delay_ms {
            config = config.with_delay(delay).with_per_line_delay(line_delay);
        }

        if let Some(idle_secs) = idle_timeout_secs {
            config = config.with_idle_timeout(Duration::from_secs(idle_secs));
        }

        // Create and run netcat
        let nc = Netcat::new(config);
        nc.run()
    }

    /// Connect mode (client)
    fn connect(&self, ctx: &CliContext) -> Result<(), String> {
        // NEW pattern: rb network nc connect example.com 80 → domain=network, verb=connect, resource=example.com, target=80
        // Unix socket: rb network nc connect unix:/path/to/socket
        let host = ctx.resource.as_ref().ok_or(
            "Missing host or socket path. Usage: rb network nc connect <host> <port|unix:path>",
        )?;

        // Check if this is a Unix socket
        if host.starts_with("unix:") {
            return self.connect_unix(ctx, host);
        }

        // Otherwise, it's TCP/UDP connection
        let port_str = ctx
            .target
            .as_ref()
            .ok_or("Missing port. Usage: rb network nc connect <host> <port>")?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port number: {}", port_str))?;

        // Parse flags
        let udp = ctx.has_flag("udp");
        let verbose = ctx.has_flag("verbose");
        let source_port = ctx
            .get_flag("source-port")
            .and_then(|s| s.parse::<u16>().ok());
        let exec_cmd = ctx.get_flag("exec");
        let ip_version = self.parse_ip_version(ctx)?;
        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);
        let encrypt_password = ctx.get_flag("encrypt");
        let delay_ms = ctx.get_flag("delay").and_then(|s| s.parse::<u64>().ok());
        let line_delay = ctx.has_flag("line-delay");
        let idle_timeout_secs = ctx.get_flag("wait").and_then(|s| s.parse::<u64>().ok());

        // Build configuration
        let mut config = NetcatConfig::client(host, port)
            .with_verbose(verbose)
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_ip_version(ip_version);

        if udp {
            config = config.with_protocol(Protocol::Udp);
        }

        if let Some(sport) = source_port {
            config = config.with_source_port(sport);
        }

        if let Some(cmd) = exec_cmd {
            config = config.with_exec(cmd.to_string());
        }

        if let Some(password) = encrypt_password {
            config = config.with_encryption(password.to_string());
        }

        if let Some(delay) = delay_ms {
            config = config.with_delay(delay).with_per_line_delay(line_delay);
        }

        if let Some(idle_secs) = idle_timeout_secs {
            config = config.with_idle_timeout(Duration::from_secs(idle_secs));
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

        let format = ctx.get_output_format();
        let is_json = format == crate::cli::format::OutputFormat::Json;

        // For JSON output, do a direct connection test and output result
        if is_json {
            use std::net::{TcpStream, ToSocketAddrs};
            let timeout = Duration::from_secs(timeout_secs);
            let start = std::time::Instant::now();

            // Resolve host
            let addr_str = format!("{}:{}", host, port);
            let addrs: Vec<_> = match addr_str.to_socket_addrs() {
                Ok(a) => a.collect(),
                Err(e) => {
                    println!("{{");
                    println!("  \"host\": \"{}\",", host.replace('"', "\\\""));
                    println!("  \"port\": {},", port);
                    println!("  \"status\": \"error\",");
                    println!(
                        "  \"error\": \"DNS resolution failed: {}\"",
                        e.to_string().replace('"', "\\\"")
                    );
                    println!("}}");
                    return Ok(());
                }
            };

            if addrs.is_empty() {
                println!("{{");
                println!("  \"host\": \"{}\",", host.replace('"', "\\\""));
                println!("  \"port\": {},", port);
                println!("  \"status\": \"error\",");
                println!("  \"error\": \"No addresses found\"");
                println!("}}");
                return Ok(());
            }

            // Try to connect
            let result = TcpStream::connect_timeout(&addrs[0], timeout);
            let elapsed_ms = start.elapsed().as_millis();

            println!("{{");
            println!("  \"host\": \"{}\",", host.replace('"', "\\\""));
            println!("  \"port\": {},", port);
            println!("  \"ip\": \"{}\",", addrs[0].ip());
            println!("  \"timeout_secs\": {},", timeout_secs);
            println!("  \"response_time_ms\": {},", elapsed_ms);

            match result {
                Ok(_) => {
                    println!("  \"status\": \"open\"");
                }
                Err(e) => {
                    let status = if e.kind() == std::io::ErrorKind::TimedOut {
                        "filtered"
                    } else {
                        "closed"
                    };
                    println!("  \"status\": \"{}\",", status);
                    println!("  \"error\": \"{}\"", e.to_string().replace('"', "\\\""));
                }
            }
            println!("}}");
            return Ok(());
        }

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

    /// Parse IP version preference from flags
    fn parse_ip_version(&self, ctx: &CliContext) -> Result<IpVersion, String> {
        let ipv4 = ctx.has_flag("ipv4");
        let ipv6 = ctx.has_flag("ipv6");

        if ipv4 && ipv6 {
            return Err("Cannot specify both --ipv4 and --ipv6".to_string());
        }

        Ok(if ipv4 {
            IpVersion::V4Only
        } else if ipv6 {
            IpVersion::V6Only
        } else {
            IpVersion::Any
        })
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
        let chat_log = ctx.get_flag("chat-log").filter(|s| !s.is_empty());

        // Build configuration
        let config = BrokerConfig::new(port)
            .with_verbose(verbose)
            .with_log_file(chat_log);

        // Create and run broker
        let broker = Broker::new(config);
        broker.run()
    }

    /// Unix socket listen mode
    #[cfg(unix)]
    fn listen_unix(&self, ctx: &CliContext, resource: &str) -> Result<(), String> {
        // Extract path from "unix:/path/to/socket"
        let path = resource
            .strip_prefix("unix:")
            .ok_or("Invalid unix socket format. Use unix:/path/to/socket")?;

        let verbose = ctx.has_flag("verbose");
        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);

        let config = UnixSocketConfig::new(
            UnixSocketType::Stream,
            UnixSocketMode::Listen(PathBuf::from(path)),
        )
        .with_verbose(verbose)
        .with_timeout(Duration::from_secs(timeout_secs));

        let manager = UnixSocketManager::new(config);
        manager.run()
    }

    /// Unix socket connect mode
    #[cfg(unix)]
    fn connect_unix(&self, ctx: &CliContext, host: &str) -> Result<(), String> {
        // Extract path from "unix:/path/to/socket"
        let path = host
            .strip_prefix("unix:")
            .ok_or("Invalid unix socket format. Use unix:/path/to/socket")?;

        let verbose = ctx.has_flag("verbose");
        let timeout_secs = ctx
            .get_flag("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);

        let config = UnixSocketConfig::new(
            UnixSocketType::Stream,
            UnixSocketMode::Connect(PathBuf::from(path)),
        )
        .with_verbose(verbose)
        .with_timeout(Duration::from_secs(timeout_secs));

        let manager = UnixSocketManager::new(config);
        manager.run()
    }

    #[cfg(not(unix))]
    fn listen_unix(&self, _ctx: &CliContext, _resource: &str) -> Result<(), String> {
        Err("Unix domain sockets are only supported on Unix systems".to_string())
    }

    #[cfg(not(unix))]
    fn connect_unix(&self, _ctx: &CliContext, _host: &str) -> Result<(), String> {
        Err("Unix domain sockets are only supported on Unix systems".to_string())
    }
}
