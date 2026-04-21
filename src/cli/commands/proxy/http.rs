// Proxy commands - HTTP CONNECT, SOCKS5, and Transparent proxies
//
// High-performance proxy servers for tunneling and traffic routing.

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, validator::Validator, CliContext};
use crate::json;
use crate::modules::proxy::http::{HttpProxy, HttpProxyConfig};
use crate::modules::proxy::socks5::{Socks5Config, Socks5Server};
#[cfg(not(target_os = "windows"))]
use crate::modules::proxy::transparent::{generate_iptables_rules, generate_nftables_rules};
#[cfg(not(target_os = "windows"))]
use crate::modules::proxy::transparent::{TransparentConfig, TransparentMode, TransparentProxy};
use crate::modules::proxy::ProxyContext;
use crate::serde_json::Value;
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

