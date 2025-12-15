use crate::agent::client::{AgentClient, AgentConfig};
use crate::agent::server::{AgentServer, AgentServerConfig};
use crate::cli::commands::{Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use std::net::SocketAddr;
use std::time::Duration;

pub struct AgentCommand;

impl Command for AgentCommand {
    fn domain(&self) -> &str {
        "agent"
    }

    fn resource(&self) -> &str {
        "c2"
    }

    fn description(&self) -> &str {
        "Agent C2 operations (server and client)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "server",
                summary: "Start the C2 server",
                usage: "rb agent c2 server [--host <host>] [--port <port>]",
            },
            Route {
                verb: "connect",
                summary: "Connect as an agent to a C2 server",
                usage: "rb agent c2 connect <url> [--interval <seconds>]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("host", "Bind host address").with_default("0.0.0.0"),
            Flag::new("port", "Bind port").with_default("4444"),
            Flag::new("interval", "Beacon interval in seconds").with_default("60"),
            Flag::new("jitter", "Jitter percentage (0.0-1.0)").with_default("0.1"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Start C2 server on default port (4444)",
                "rb agent c2 server",
            ),
            (
                "Connect to C2 server",
                "rb agent c2 connect http://127.0.0.1:4444",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("help");

        match verb {
            "server" => self.start_server(ctx),
            "connect" => self.start_agent(ctx),
            _ => {
                crate::cli::commands::print_help(self);
                Ok(())
            }
        }
    }
}

impl AgentCommand {
    fn start_server(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.get_flag_or("host", "0.0.0.0");
        let port = ctx.get_flag_or("port", "4444");
        let addr_str = format!("{}:{}", host, port);

        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("Invalid address {}: {}", addr_str, e))?;

        Output::header("Starting C2 Server");
        Output::item("Address", &addr_str);

        let config = AgentServerConfig {
            bind_addr: addr,
            use_tls: false,
            cert_path: None,
            key_path: None,
            db_path: Some("redblue.rdb".to_string()),
        };

        let mut server = AgentServer::new(config);
        server.start(None)?;

        // Keep main thread alive
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn start_agent(&self, ctx: &CliContext) -> Result<(), String> {
        let url = ctx.target.as_ref().ok_or("Missing C2 server URL")?;
        let interval_secs = ctx
            .get_flag_or("interval", "60")
            .parse::<u64>()
            .unwrap_or(60);
        let jitter = ctx
            .get_flag_or("jitter", "0.1")
            .parse::<f32>()
            .unwrap_or(0.1);

        Output::header("Starting Agent");
        Output::item("C2 Server", url);
        Output::item("Interval", &format!("{}s", interval_secs));

        let config = AgentConfig {
            server_url: url.clone(),
            interval: Duration::from_secs(interval_secs),
            jitter,
        };

        let mut agent = AgentClient::new(config);
        agent.start()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_command_parsing() {
        let cmd = AgentCommand;

        // Test flags
        let flags = cmd.flags();
        assert!(flags.iter().any(|f| f.long == "host"));
        assert!(flags.iter().any(|f| f.long == "port"));
        assert!(flags.iter().any(|f| f.long == "interval"));

        // Test routes
        let routes = cmd.routes();
        assert!(routes.iter().any(|r| r.verb == "server"));
        assert!(routes.iter().any(|r| r.verb == "connect"));
    }
}
