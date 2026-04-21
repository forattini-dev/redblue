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
      (
        "Start SOCKS5 proxy on default port",
        "rb proxy socks5 start",
      ),
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
// Transparent Proxy Command (Unix only - requires iptables/nftables)
// ============================================================================

