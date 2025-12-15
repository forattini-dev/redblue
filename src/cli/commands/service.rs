//! Service Manager CLI Command
//!
//! Install redblue services to persist across reboots.
//!
//! # Usage
//! ```bash
//! rb service manage install mitm-proxy --port 8080
//! rb service manage list
//! rb service manage status rb-mitm-8080
//! rb service manage uninstall rb-mitm-8080
//! ```

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::service::{
    get_service_manager, ListenerProtocol, ServiceConfig, ServiceManager, ServiceStatus,
    ServiceType,
};
use std::path::PathBuf;

use super::{print_help, Command, Flag, Route};

pub struct ServiceCommand;

impl Command for ServiceCommand {
    fn domain(&self) -> &str {
        "service"
    }

    fn resource(&self) -> &str {
        "manage"
    }

    fn description(&self) -> &str {
        "Install and manage persistent redblue services"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "install",
                summary: "Install a service for persistence",
                usage: "rb service manage install <type> --port <port> [--name <name>]",
            },
            Route {
                verb: "uninstall",
                summary: "Remove an installed service",
                usage: "rb service manage uninstall <name>",
            },
            Route {
                verb: "start",
                summary: "Start a service",
                usage: "rb service manage start <name>",
            },
            Route {
                verb: "stop",
                summary: "Stop a running service",
                usage: "rb service manage stop <name>",
            },
            Route {
                verb: "restart",
                summary: "Restart a service",
                usage: "rb service manage restart <name>",
            },
            Route {
                verb: "status",
                summary: "Show service status",
                usage: "rb service manage status [name]",
            },
            Route {
                verb: "list",
                summary: "List all installed redblue services",
                usage: "rb service manage list",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("port", "Port number for the service")
                .with_short('p')
                .with_arg("PORT"),
            Flag::new("name", "Custom service name")
                .with_short('n')
                .with_arg("NAME"),
            Flag::new("upstream", "Upstream server (for proxy/dns)").with_arg("HOST:PORT"),
            Flag::new("root", "Root directory (for http server)").with_arg("PATH"),
            Flag::new("no-autostart", "Don't start service on boot"),
            Flag::new("no-restart", "Don't restart on failure"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Install MITM proxy on port 8080",
                "rb service manage install mitm-proxy --port 8080",
            ),
            (
                "Install TCP listener on port 4444",
                "rb service manage install listener --port 4444",
            ),
            (
                "Install HTTP server",
                "rb service manage install http-server --port 8000 --root /var/www",
            ),
            (
                "Install DNS server",
                "rb service manage install dns-server --port 5353 --upstream 8.8.8.8",
            ),
            ("List all services", "rb service manage list"),
            (
                "Check service status",
                "rb service manage status rb-mitm-8080",
            ),
            (
                "Uninstall a service",
                "rb service manage uninstall rb-mitm-8080",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().ok_or_else(|| {
            print_help(self);
            "No verb specified".to_string()
        })?;

        match verb {
            "install" => self.install(ctx),
            "uninstall" => self.uninstall(ctx),
            "start" => self.start(ctx),
            "stop" => self.stop(ctx),
            "restart" => self.restart(ctx),
            "status" => self.status(ctx),
            "list" => self.list(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use 'rb service manage help'.",
                verb
            )),
        }
    }
}

impl ServiceCommand {
    fn install(&self, ctx: &CliContext) -> Result<(), String> {
        let service_type_name = ctx.target.as_deref().ok_or_else(|| {
            "Missing service type. Available: mitm-proxy, http-server, dns-server, listener"
                .to_string()
        })?;

        let port: u16 = ctx
            .flags
            .get("port")
            .ok_or("--port is required")?
            .parse()
            .map_err(|_| "Invalid port number")?;

        // Build service type
        let service_type = match service_type_name {
            "mitm-proxy" | "mitm" => {
                let upstream = ctx.flags.get("upstream").cloned();
                ServiceType::MitmProxy { port, upstream }
            }
            "http-server" | "http" => {
                let root = ctx
                    .flags
                    .get("root")
                    .map(|r| PathBuf::from(r))
                    .unwrap_or_else(|| PathBuf::from("."));
                ServiceType::HttpServer { port, root }
            }
            "dns-server" | "dns" => {
                let upstream = ctx
                    .flags
                    .get("upstream")
                    .cloned()
                    .unwrap_or_else(|| "8.8.8.8".to_string());
                ServiceType::DnsServer { port, upstream }
            }
            "listener" => {
                let protocol = match ctx.flags.get("protocol").map(|s| s.as_str()) {
                    Some("udp") => ListenerProtocol::Udp,
                    Some("http") => ListenerProtocol::Http,
                    Some("https") => ListenerProtocol::Https,
                    _ => ListenerProtocol::Tcp,
                };
                ServiceType::Listener { port, protocol }
            }
            "hooks-server" | "hooks" => {
                let scripts_dir = ctx
                    .flags
                    .get("scripts")
                    .map(|s| PathBuf::from(s))
                    .unwrap_or_else(|| PathBuf::from("./hooks"));
                ServiceType::HooksServer { port, scripts_dir }
            }
            _ => {
                return Err(format!(
                    "Unknown service type '{}'. Available: mitm-proxy, http-server, dns-server, listener, hooks-server",
                    service_type_name
                ));
            }
        };

        // Build config
        let mut config = ServiceConfig::new(service_type);

        if let Some(name) = ctx.flags.get("name") {
            config = config.with_name(name);
        }

        if ctx.flags.contains_key("no-autostart") {
            config = config.with_auto_start(false);
        }

        if ctx.flags.contains_key("no-restart") {
            config = config.with_restart(false);
        }

        Output::header("Service Installation");
        Output::item("Type", service_type_name);
        Output::item("Name", &config.name);
        Output::item("Port", &port.to_string());
        Output::item("Auto-start", if config.auto_start { "yes" } else { "no" });

        Output::spinner_start("Installing service");

        let manager = get_service_manager();
        let installed = manager.install(&config)?;

        Output::spinner_done();

        Output::success(&format!(
            "Service '{}' installed successfully",
            installed.name
        ));
        Output::item("Config", &installed.config_path.display().to_string());
        println!();
        println!("To start the service:");
        println!("  rb service manage start {}", installed.name);

        Ok(())
    }

    fn uninstall(&self, ctx: &CliContext) -> Result<(), String> {
        let name = ctx.target.as_deref().ok_or("Missing service name")?;

        Output::header("Service Removal");
        Output::item("Name", name);

        Output::spinner_start("Removing service");

        let manager = get_service_manager();
        manager.uninstall(name)?;

        Output::spinner_done();
        Output::success(&format!("Service '{}' removed successfully", name));

        Ok(())
    }

    fn start(&self, ctx: &CliContext) -> Result<(), String> {
        let name = ctx.target.as_deref().ok_or("Missing service name")?;

        Output::item("Starting", name);

        let manager = get_service_manager();
        manager.start(name)?;

        Output::success(&format!("Service '{}' started", name));
        Ok(())
    }

    fn stop(&self, ctx: &CliContext) -> Result<(), String> {
        let name = ctx.target.as_deref().ok_or("Missing service name")?;

        Output::item("Stopping", name);

        let manager = get_service_manager();
        manager.stop(name)?;

        Output::success(&format!("Service '{}' stopped", name));
        Ok(())
    }

    fn restart(&self, ctx: &CliContext) -> Result<(), String> {
        let name = ctx.target.as_deref().ok_or("Missing service name")?;

        Output::item("Restarting", name);

        let manager = get_service_manager();
        manager.restart(name)?;

        Output::success(&format!("Service '{}' restarted", name));
        Ok(())
    }

    fn status(&self, ctx: &CliContext) -> Result<(), String> {
        let manager = get_service_manager();

        if let Some(name) = ctx.target.as_deref() {
            // Status for specific service
            let status = manager.status(name)?;
            Output::header(&format!("Service: {}", name));

            let (color, icon) = match status {
                ServiceStatus::Running => ("\x1b[32m", "●"),  // green
                ServiceStatus::Stopped => ("\x1b[33m", "○"),  // yellow
                ServiceStatus::Failed => ("\x1b[31m", "✗"),   // red
                ServiceStatus::Unknown => ("\x1b[90m", "?"),  // gray
                ServiceStatus::NotFound => ("\x1b[31m", "✗"), // red
            };

            println!("{}{} {}\x1b[0m", color, icon, status.as_str());
        } else {
            // Status for all services
            self.list(ctx)?;
        }

        Ok(())
    }

    fn list(&self, ctx: &CliContext) -> Result<(), String> {
        let manager = get_service_manager();
        let services = manager.list()?;

        Output::header("Installed redblue Services");

        if services.is_empty() {
            println!("\n  No services installed.");
            println!("\n  Install with: rb service manage install <type> --port <port>");
            return Ok(());
        }

        println!();
        println!("  {:<25} {:<12} {}", "NAME", "STATUS", "DESCRIPTION");
        println!("  {}", "-".repeat(70));

        for service in &services {
            let (color, icon) = match service.status {
                ServiceStatus::Running => ("\x1b[32m", "●"),
                ServiceStatus::Stopped => ("\x1b[33m", "○"),
                ServiceStatus::Failed => ("\x1b[31m", "✗"),
                ServiceStatus::Unknown => ("\x1b[90m", "?"),
                ServiceStatus::NotFound => ("\x1b[31m", "✗"),
            };

            let desc = service
                .description
                .as_deref()
                .unwrap_or("-")
                .chars()
                .take(35)
                .collect::<String>();

            println!(
                "  {:<25} {}{} {:<10}\x1b[0m {}",
                service.name,
                color,
                icon,
                service.status.as_str(),
                desc
            );
        }

        println!();
        println!("  Total: {} service(s)", services.len());

        Ok(())
    }
}
