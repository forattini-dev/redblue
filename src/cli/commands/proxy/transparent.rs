pub struct TransparentProxyCommand;

#[cfg(not(target_os = "windows"))]
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

#[cfg(not(target_os = "windows"))]
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

      Output::success(&format!("Starting transparent proxy on {}...", listen_addr));
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

