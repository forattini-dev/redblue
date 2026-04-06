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

use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::service::{
  get_service_manager, ListenerProtocol, ServiceConfig, ServiceStatus, ServiceType,
};
use crate::serde_json::Value;
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

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let machine_output = match verb {
      "install" | "uninstall" | "start" | "stop" | "restart" | "status" | "list" => {
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly)
      }
      _ => self.metadata().machine_output,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(machine_output)
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
      Flag::new("output", "Output format (text, json, yaml)")
        .with_short('o')
        .with_default("text"),
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
        "List services as JSON",
        "rb service manage list --output=json",
      ),
      (
        "Check service status",
        "rb service manage status rb-mitm-8080",
      ),
      (
        "Check status as JSON",
        "rb service manage status rb-mitm-8080 --output=json",
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
      "Missing service type. Available: mitm-proxy, http-server, dns-server, listener".to_string()
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
          .map(PathBuf::from)
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
          .map(PathBuf::from)
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

    if !ctx.wants_machine_output() {
      Output::header("Service Installation");
      Output::item("Type", service_type_name);
      Output::item("Name", &config.name);
      Output::item("Port", &port.to_string());
      Output::item("Auto-start", if config.auto_start { "yes" } else { "no" });
      Output::spinner_start("Installing service");
    }

    let manager = get_service_manager();
    let installed = manager.install(&config)?;

    let payload = Self::install_payload(
      &installed.name,
      service_type_name,
      port,
      config.auto_start,
      &installed.config_path,
    );
    if render::render_machine_output(ctx, "rb service manage install", &payload)? {
      return Ok(());
    }

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

    if !ctx.wants_machine_output() {
      Output::header("Service Removal");
      Output::item("Name", name);
      Output::spinner_start("Removing service");
    }

    let manager = get_service_manager();
    manager.uninstall(name)?;

    let payload = Self::action_payload("uninstall", name);
    if render::render_machine_output(ctx, "rb service manage uninstall", &payload)? {
      return Ok(());
    }

    Output::spinner_done();
    Output::success(&format!("Service '{}' removed successfully", name));

    Ok(())
  }

  fn start(&self, ctx: &CliContext) -> Result<(), String> {
    let name = ctx.target.as_deref().ok_or("Missing service name")?;

    if !ctx.wants_machine_output() {
      Output::item("Starting", name);
    }

    let manager = get_service_manager();
    manager.start(name)?;

    let payload = Self::action_payload("start", name);
    if render::render_machine_output(ctx, "rb service manage start", &payload)? {
      return Ok(());
    }

    Output::success(&format!("Service '{}' started", name));
    Ok(())
  }

  fn stop(&self, ctx: &CliContext) -> Result<(), String> {
    let name = ctx.target.as_deref().ok_or("Missing service name")?;

    if !ctx.wants_machine_output() {
      Output::item("Stopping", name);
    }

    let manager = get_service_manager();
    manager.stop(name)?;

    let payload = Self::action_payload("stop", name);
    if render::render_machine_output(ctx, "rb service manage stop", &payload)? {
      return Ok(());
    }

    Output::success(&format!("Service '{}' stopped", name));
    Ok(())
  }

  fn restart(&self, ctx: &CliContext) -> Result<(), String> {
    let name = ctx.target.as_deref().ok_or("Missing service name")?;

    if !ctx.wants_machine_output() {
      Output::item("Restarting", name);
    }

    let manager = get_service_manager();
    manager.restart(name)?;

    let payload = Self::action_payload("restart", name);
    if render::render_machine_output(ctx, "rb service manage restart", &payload)? {
      return Ok(());
    }

    Output::success(&format!("Service '{}' restarted", name));
    Ok(())
  }

  fn status(&self, ctx: &CliContext) -> Result<(), String> {
    let manager = get_service_manager();

    if let Some(name) = ctx.target.as_deref() {
      // Status for specific service
      let status = manager.status(name)?;

      let payload = Self::status_payload(name, &status);
      if render::render_machine_output(ctx, "rb service manage status", &payload)? {
        return Ok(());
      }

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

    let payload = Self::list_payload(&services);
    if render::render_machine_output(ctx, "rb service manage list", &payload)? {
      return Ok(());
    }

    Output::header("Installed redblue Services");

    if services.is_empty() {
      println!("\n  No services installed.");
      println!("\n  Install with: rb service manage install <type> --port <port>");
      return Ok(());
    }

    println!();
    println!("  {:<25} {:<12} DESCRIPTION", "NAME", "STATUS");
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

  fn action_payload(action: &str, name: &str) -> Value {
    json!({
      "action": action,
      "success": true,
      "name": name
    })
  }

  fn status_payload(name: &str, status: &ServiceStatus) -> Value {
    json!({
      "name": name,
      "status": status.as_str()
    })
  }

  fn list_payload(services: &[crate::modules::service::InstalledService]) -> Value {
    let payload: Vec<_> = services
      .iter()
      .map(|service| {
        json!({
          "name": service.name,
          "status": service.status.as_str(),
          "description": service.description
        })
      })
      .collect();

    json!({
      "total": services.len(),
      "services": payload
    })
  }

  fn install_payload(
    name: &str,
    service_type_name: &str,
    port: u16,
    auto_start: bool,
    config_path: &PathBuf,
  ) -> Value {
    json!({
      "action": "install",
      "success": true,
      "service": json!({
        "name": name,
        "type": service_type_name,
        "port": port,
        "auto_start": auto_start,
        "config_path": config_path.display().to_string()
      })
    })
  }
}
