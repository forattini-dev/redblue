pub struct ProxyDataCommand;

impl Command for ProxyDataCommand {
  fn domain(&self) -> &str {
    "proxy"
  }

  fn resource(&self) -> &str {
    "data"
  }

  fn description(&self) -> &str {
    "Query stored proxy connection history and traffic data"
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
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "list",
        summary: "List all proxy connections from stored data",
        usage: "rb proxy data list [--db FILE]",
      },
      Route {
        verb: "requests",
        summary: "List HTTP requests from proxy sessions",
        usage: "rb proxy data requests [--db FILE] [--host HOST]",
      },
      Route {
        verb: "responses",
        summary: "List HTTP responses from proxy sessions",
        usage: "rb proxy data responses [--db FILE] [--status CODE]",
      },
      Route {
        verb: "show",
        summary: "Show details for a specific connection",
        usage: "rb proxy data show <connection_id> [--db FILE]",
      },
      Route {
        verb: "stats",
        summary: "Show proxy data statistics",
        usage: "rb proxy data stats [--db FILE]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("db", "Database file to query").with_short('d'),
      Flag::new("host", "Filter by destination host").with_short('h'),
      Flag::new("status", "Filter by HTTP status code").with_short('s'),
      Flag::new("limit", "Maximum number of results")
        .with_short('l')
        .with_default("50"),
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("List all proxy connections", "rb proxy data list"),
      (
        "List connections from specific database",
        "rb proxy data list --db target.rdb",
      ),
      (
        "Show requests to a specific host",
        "rb proxy data requests --host api.example.com",
      ),
      ("Show connection details", "rb proxy data show 12345"),
      ("Show proxy statistics", "rb proxy data stats"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "list" => self.list_connections(ctx),
      "requests" => self.list_requests(ctx),
      "responses" => self.list_responses(ctx),
      "show" => self.show_connection(ctx),
      "stats" => self.show_stats(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        println!(
          "{}",
          Validator::suggest_command(verb, &["list", "requests", "responses", "show", "stats"])
        );
        Err("Invalid verb".to_string())
      }
    }
  }
}

impl ProxyDataCommand {
  fn resolve_db_path(&self, ctx: &CliContext) -> Result<String, String> {
    if let Some(db) = ctx.get_flag("db") {
      return Ok(db.clone());
    }

    // Look for .rdb files in current directory
    let entries =
      std::fs::read_dir(".").map_err(|e| format!("Failed to read current directory: {}", e))?;

    for entry in entries.flatten() {
      let path = entry.path();
      if let Some(ext) = path.extension() {
        if ext == "rdb" {
          if let Some(p) = path.to_str() {
            return Ok(p.to_string());
          }
        }
      }
    }

    Err(
      "No database file specified. Use --db <file> or run from a directory with .rdb files"
        .to_string(),
    )
  }

  fn list_connections(&self, ctx: &CliContext) -> Result<(), String> {
    let db_path = self.resolve_db_path(ctx)?;
    let limit: usize = ctx
      .get_flag_or("limit", "50")
      .parse()
      .map_err(|_| "Invalid limit")?;

    let qm = QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

    let connections = qm
      .list_proxy_connections()
      .map_err(|e| format!("Failed to list connections: {}", e))?;

    let payload = proxy_connections_payload(&db_path, limit, &connections);
    if render::render_machine_output(ctx, "rb proxy data list", &payload)? {
      return Ok(());
    }

    Output::header("Proxy Connections");
    Output::item("Database", &db_path);
    println!();

    if connections.is_empty() {
      Output::info("No proxy connections found in database");
      return Ok(());
    }

    // Table header
    println!(
      "{:<12} {:<20} {:<8} {:<30} {:<10} {:<10}",
      "CONN_ID", "SOURCE", "PROTO", "DESTINATION", "TX BYTES", "RX BYTES"
    );
    println!("{}", "─".repeat(90));

    for conn in connections.iter().take(limit) {
      let proto = match conn.protocol {
        0 => "TCP",
        1 => "UDP",
        2 => "TLS",
        _ => "?",
      };
      let src = format!("{}:{}", conn.src_ip, conn.src_port);
      let dst = format!("{}:{}", conn.dst_host, conn.dst_port);

      println!(
        "{:<12} {:<20} {:<8} {:<30} {:<10} {:<10}",
        conn.connection_id,
        src,
        proto,
        dst,
        format_bytes(conn.bytes_sent),
        format_bytes(conn.bytes_received),
      );
    }

    println!();
    if connections.len() > limit {
      Output::info(&format!(
        "Showing {} of {} connections (use --limit to show more)",
        limit,
        connections.len()
      ));
    } else {
      Output::info(&format!("Found {} connection(s)", connections.len()));
    }

    Ok(())
  }

  fn list_requests(&self, ctx: &CliContext) -> Result<(), String> {
    let db_path = self.resolve_db_path(ctx)?;
    let limit: usize = ctx
      .get_flag_or("limit", "50")
      .parse()
      .map_err(|_| "Invalid limit")?;
    let host_filter = ctx.get_flag("host");

    let qm = QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

    let requests = qm
      .list_proxy_requests()
      .map_err(|e| format!("Failed to list requests: {}", e))?;

    // Filter by host if specified
    let filtered: Vec<_> = if let Some(ref host) = host_filter {
      requests
        .into_iter()
        .filter(|r| r.host.contains(host))
        .collect()
    } else {
      requests
    };

    let payload = proxy_requests_payload(&db_path, host_filter.clone(), limit, &filtered);
    if render::render_machine_output(ctx, "rb proxy data requests", &payload)? {
      return Ok(());
    }

    Output::header("Proxy HTTP Requests");
    Output::item("Database", &db_path);
    if let Some(h) = &host_filter {
      Output::item("Host Filter", h);
    }
    println!();

    if filtered.is_empty() {
      Output::info("No proxy requests found");
      return Ok(());
    }

    // Table header
    println!(
      "{:<12} {:<8} {:<40} {:<30}",
      "CONN_ID", "METHOD", "PATH", "HOST"
    );
    println!("{}", "─".repeat(90));

    for req in filtered.iter().take(limit) {
      let path = if req.path.len() > 38 {
        format!("{}...", &req.path[..35])
      } else {
        req.path.clone()
      };

      println!(
        "{:<12} {:<8} {:<40} {:<30}",
        req.connection_id, req.method, path, req.host,
      );
    }

    println!();
    if filtered.len() > limit {
      Output::info(&format!("Showing {} of {} requests", limit, filtered.len()));
    } else {
      Output::info(&format!("Found {} request(s)", filtered.len()));
    }

    Ok(())
  }

  fn list_responses(&self, ctx: &CliContext) -> Result<(), String> {
    let db_path = self.resolve_db_path(ctx)?;
    let limit: usize = ctx
      .get_flag_or("limit", "50")
      .parse()
      .map_err(|_| "Invalid limit")?;
    let status_filter: Option<u16> = ctx.get_flag("status").and_then(|s| s.parse().ok());

    let qm = QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

    let responses = qm
      .list_proxy_responses()
      .map_err(|e| format!("Failed to list responses: {}", e))?;

    // Filter by status if specified
    let filtered: Vec<_> = if let Some(status) = status_filter {
      responses
        .into_iter()
        .filter(|r| r.status_code == status)
        .collect()
    } else {
      responses
    };

    let payload = proxy_responses_payload(&db_path, status_filter, limit, &filtered);
    if render::render_machine_output(ctx, "rb proxy data responses", &payload)? {
      return Ok(());
    }

    Output::header("Proxy HTTP Responses");
    Output::item("Database", &db_path);
    if let Some(s) = status_filter {
      Output::item("Status Filter", &s.to_string());
    }
    println!();

    if filtered.is_empty() {
      Output::info("No proxy responses found");
      return Ok(());
    }

    // Table header
    println!(
      "{:<12} {:<8} {:<20} {:<30} {:<15}",
      "CONN_ID", "STATUS", "STATUS_TEXT", "CONTENT_TYPE", "BODY_SIZE"
    );
    println!("{}", "─".repeat(85));

    for resp in filtered.iter().take(limit) {
      let content_type = resp.content_type.as_deref().unwrap_or("-");
      let content_type_short = if content_type.len() > 28 {
        format!("{}...", &content_type[..25])
      } else {
        content_type.to_string()
      };

      let status_color = if resp.status_code >= 200 && resp.status_code < 300 {
        "\x1b[32m" // Green
      } else if resp.status_code >= 400 {
        "\x1b[31m" // Red
      } else if resp.status_code >= 300 {
        "\x1b[33m" // Yellow
      } else {
        ""
      };

      println!(
        "{:<12} {}{:<8}\x1b[0m {:<20} {:<30} {:<15}",
        resp.connection_id,
        status_color,
        resp.status_code,
        resp.status_text,
        content_type_short,
        format_bytes(resp.body.len() as u64),
      );
    }

    println!();
    if filtered.len() > limit {
      Output::info(&format!(
        "Showing {} of {} responses",
        limit,
        filtered.len()
      ));
    } else {
      Output::info(&format!("Found {} response(s)", filtered.len()));
    }

    Ok(())
  }

  fn show_connection(&self, ctx: &CliContext) -> Result<(), String> {
    let db_path = self.resolve_db_path(ctx)?;
    let conn_id: u64 = ctx
      .target
      .as_ref()
      .ok_or("Missing connection ID")?
      .parse()
      .map_err(|_| "Invalid connection ID")?;

    let qm = QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

    let conn = qm
      .get_proxy_connection(conn_id)
      .map_err(|e| format!("Failed to get connection: {}", e))?
      .ok_or_else(|| format!("Connection {} not found", conn_id))?;

    // Get requests and responses for this connection
    let requests = qm
      .list_proxy_requests()
      .map_err(|e| format!("Failed to list requests: {}", e))?;
    let conn_requests: Vec<_> = requests
      .iter()
      .filter(|r| r.connection_id == conn_id)
      .collect();

    let responses = qm
      .list_proxy_responses()
      .map_err(|e| format!("Failed to list responses: {}", e))?;
    let conn_responses: Vec<_> = responses
      .iter()
      .filter(|r| r.connection_id == conn_id)
      .collect();

    let payload = proxy_show_payload(&conn, &conn_requests, &conn_responses);
    if render::render_machine_output(ctx, "rb proxy data show", &payload)? {
      return Ok(());
    }

    Output::header(&format!("Proxy Connection #{}", conn_id));
    println!();

    let proto = match conn.protocol {
      0 => "TCP",
      1 => "UDP",
      2 => "TLS",
      _ => "Unknown",
    };

    Output::item("Source", &format!("{}:{}", conn.src_ip, conn.src_port));
    Output::item(
      "Destination",
      &format!("{}:{}", conn.dst_host, conn.dst_port),
    );
    Output::item("Protocol", proto);
    Output::item(
      "TLS Intercepted",
      if conn.tls_intercepted { "Yes" } else { "No" },
    );
    Output::item("Started", &format_timestamp(conn.started_at));
    Output::item("Ended", &format_timestamp(conn.ended_at));
    Output::item("Bytes Sent", &format_bytes(conn.bytes_sent));
    Output::item("Bytes Received", &format_bytes(conn.bytes_received));
    Output::item(
      "Duration",
      &format!("{} seconds", conn.ended_at.saturating_sub(conn.started_at)),
    );

    if !conn_requests.is_empty() {
      println!();
      Output::subheader(&format!("HTTP Requests ({})", conn_requests.len()));
      for req in conn_requests {
        println!(
          "  [{:>3}] {} {} {}",
          req.request_seq, req.method, req.path, req.http_version
        );
      }
    }

    if !conn_responses.is_empty() {
      println!();
      Output::subheader(&format!("HTTP Responses ({})", conn_responses.len()));
      for resp in conn_responses {
        println!(
          "  [{:>3}] {} {} ({} bytes)",
          resp.request_seq,
          resp.status_code,
          resp.status_text,
          resp.body.len()
        );
      }
    }

    Ok(())
  }

  fn show_stats(&self, ctx: &CliContext) -> Result<(), String> {
    let db_path = self.resolve_db_path(ctx)?;

    let qm = QueryManager::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

    let connections = qm
      .list_proxy_connections()
      .map_err(|e| format!("Failed to list connections: {}", e))?;
    let requests = qm
      .list_proxy_requests()
      .map_err(|e| format!("Failed to list requests: {}", e))?;
    let responses = qm
      .list_proxy_responses()
      .map_err(|e| format!("Failed to list responses: {}", e))?;

    // Connection stats
    let total_bytes_sent: u64 = connections.iter().map(|c| c.bytes_sent).sum();
    let total_bytes_recv: u64 = connections.iter().map(|c| c.bytes_received).sum();
    let tls_count = connections.iter().filter(|c| c.tls_intercepted).count();

    // Host counts
    let mut host_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for req in &requests {
      *host_counts.entry(&req.host).or_insert(0) += 1;
    }
    let mut sorted_hosts: Vec<_> = host_counts.into_iter().collect();
    sorted_hosts.sort_by(|a, b| b.1.cmp(&a.1));

    // Status code counts
    let mut status_counts: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
    for resp in &responses {
      *status_counts.entry(resp.status_code).or_insert(0) += 1;
    }
    let mut sorted_status: Vec<_> = status_counts.into_iter().collect();
    sorted_status.sort_by_key(|(code, _)| *code);

    let payload = proxy_stats_payload(
      &db_path,
      tls_count,
      requests.len(),
      responses.len(),
      total_bytes_sent,
      total_bytes_recv,
      &sorted_hosts,
      &sorted_status,
      connections.len(),
    );
    if render::render_machine_output(ctx, "rb proxy data stats", &payload)? {
      return Ok(());
    }

    Output::header("Proxy Data Statistics");
    Output::item("Database", &db_path);
    println!();

    println!("SEGMENT                   COUNT");
    println!("────────────────────────────────");
    println!("{:<24} {:>6}", "Connections", connections.len());
    println!("{:<24} {:>6}", "  └ TLS Intercepted", tls_count);
    println!("{:<24} {:>6}", "HTTP Requests", requests.len());
    println!("{:<24} {:>6}", "HTTP Responses", responses.len());
    println!("────────────────────────────────");
    println!(
      "{:<24} {:>6}",
      "Total Bytes Sent",
      format_bytes(total_bytes_sent)
    );
    println!(
      "{:<24} {:>6}",
      "Total Bytes Received",
      format_bytes(total_bytes_recv)
    );

    // Top hosts
    if !requests.is_empty() {
      println!();
      Output::subheader("Top Hosts");

      for (host, count) in sorted_hosts.iter().take(10) {
        println!("  {:<40} {:>6}", host, count);
      }
    }

    // Status code distribution
    if !responses.is_empty() {
      println!();
      Output::subheader("Status Code Distribution");

      for (code, count) in sorted_status {
        let color = if (200..300).contains(&code) {
          "\x1b[32m"
        } else if code >= 400 {
          "\x1b[31m"
        } else if (300..400).contains(&code) {
          "\x1b[33m"
        } else {
          ""
        };
        println!("  {}{:<6}\x1b[0m {:>6}", color, code, count);
      }
    }

    Ok(())
  }
}

fn proxy_connections_payload(
  database: &str,
  limit: usize,
  connections: &[crate::storage::ProxyConnectionRecord],
) -> Value {
  let connections_json: Vec<Value> = connections
    .iter()
    .take(limit)
    .map(proxy_connection_to_json)
    .collect();
  json!({
    "database": database,
    "total": connections.len(),
    "limit": limit,
    "connections": connections_json
  })
}

fn proxy_requests_payload(
  database: &str,
  host_filter: Option<String>,
  limit: usize,
  requests: &[crate::storage::ProxyHttpRequestRecord],
) -> Value {
  let requests_json: Vec<Value> = requests
    .iter()
    .take(limit)
    .map(proxy_request_to_json)
    .collect();
  json!({
    "database": database,
    "host_filter": host_filter,
    "total": requests.len(),
    "limit": limit,
    "requests": requests_json
  })
}

fn proxy_responses_payload(
  database: &str,
  status_filter: Option<u16>,
  limit: usize,
  responses: &[crate::storage::ProxyHttpResponseRecord],
) -> Value {
  let responses_json: Vec<Value> = responses
    .iter()
    .take(limit)
    .map(proxy_response_to_json)
    .collect();
  json!({
    "database": database,
    "status_filter": status_filter,
    "total": responses.len(),
    "limit": limit,
    "responses": responses_json
  })
}

fn proxy_show_payload(
  conn: &crate::storage::ProxyConnectionRecord,
  requests: &[&crate::storage::ProxyHttpRequestRecord],
  responses: &[&crate::storage::ProxyHttpResponseRecord],
) -> Value {
  let requests_json: Vec<Value> = requests
    .iter()
    .map(|req| proxy_request_to_json(req))
    .collect();
  let responses_json: Vec<Value> = responses
    .iter()
    .map(|resp| proxy_response_to_json(resp))
    .collect();
  let mut conn_json = proxy_connection_to_json(conn);
  if let Some(obj) = conn_json.as_object().cloned() {
    let mut map = obj;
    map.insert(
      "duration_seconds".to_string(),
      json!(conn.ended_at.saturating_sub(conn.started_at)),
    );
    map.insert("requests".to_string(), json!(requests_json));
    map.insert("responses".to_string(), json!(responses_json));
    conn_json = Value::Object(map);
  }
  conn_json
}

fn proxy_stats_payload(
  database: &str,
  tls_intercepted: usize,
  http_requests: usize,
  http_responses: usize,
  total_bytes_sent: u64,
  total_bytes_received: u64,
  sorted_hosts: &[(&str, usize)],
  sorted_status: &[(u16, usize)],
  connections: usize,
) -> Value {
  let top_hosts: Vec<Value> = sorted_hosts
    .iter()
    .take(10)
    .map(|(host, count)| json!({ "host": host.to_string(), "count": *count }))
    .collect();
  let status_distribution: Vec<Value> = sorted_status
    .iter()
    .map(|(code, count)| json!({ "status_code": *code, "count": *count }))
    .collect();
  json!({
    "database": database,
    "connections": connections,
    "tls_intercepted": tls_intercepted,
    "http_requests": http_requests,
    "http_responses": http_responses,
    "total_bytes_sent": total_bytes_sent,
    "total_bytes_received": total_bytes_received,
    "top_hosts": top_hosts,
    "status_distribution": status_distribution
  })
}

fn protocol_name(protocol: u8) -> &'static str {
  match protocol {
    0 => "TCP",
    1 => "UDP",
    2 => "TLS",
    _ => "UNKNOWN",
  }
}

fn proxy_connection_to_json(
  conn: &crate::storage::ProxyConnectionRecord,
) -> crate::serde_json::Value {
  json!({
      "connection_id": conn.connection_id,
      "src_ip": conn.src_ip.to_string(),
      "src_port": conn.src_port,
      "dst_host": conn.dst_host.clone(),
      "dst_port": conn.dst_port,
      "protocol": protocol_name(conn.protocol),
      "bytes_sent": conn.bytes_sent,
      "bytes_received": conn.bytes_received,
      "tls_intercepted": conn.tls_intercepted,
      "started_at": conn.started_at,
      "ended_at": conn.ended_at
  })
}

fn proxy_request_to_json(req: &crate::storage::ProxyHttpRequestRecord) -> crate::serde_json::Value {
  json!({
      "connection_id": req.connection_id,
      "request_seq": req.request_seq,
      "method": req.method.clone(),
      "path": req.path.clone(),
      "host": req.host.clone(),
      "http_version": req.http_version.clone()
  })
}

fn proxy_response_to_json(
  resp: &crate::storage::ProxyHttpResponseRecord,
) -> crate::serde_json::Value {
  json!({
      "connection_id": resp.connection_id,
      "request_seq": resp.request_seq,
      "status_code": resp.status_code,
      "status_text": resp.status_text.clone(),
      "content_type": resp.content_type.clone(),
      "body_size": resp.body.len()
  })
}

// Helper functions
fn format_bytes(bytes: u64) -> String {
  if bytes >= 1_000_000_000 {
    format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
  } else if bytes >= 1_000_000 {
    format!("{:.2} MB", bytes as f64 / 1_000_000.0)
  } else if bytes >= 1_000 {
    format!("{:.2} KB", bytes as f64 / 1_000.0)
  } else {
    format!("{} B", bytes)
  }
}

fn format_timestamp(ts: u32) -> String {
  if ts == 0 {
    return "-".to_string();
  }
  // Simple timestamp formatting (Unix epoch)
  use std::time::{Duration as StdDuration, UNIX_EPOCH};
  let dt = UNIX_EPOCH + StdDuration::from_secs(ts as u64);
  format!("{:?}", dt)
}
