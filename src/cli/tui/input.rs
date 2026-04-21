impl TuiApp {
  fn handle_enter_action(&mut self) -> Result<(), String> {
    match self.mode {
      ViewMode::Network => {
        // Enter on a network device = switch to Ports view for that IP
        if !self.network_data.is_empty() && self.selected_row < self.network_data.len() {
          let device_ip = self.network_data[self.selected_row].module.clone();
          self
            .scan_activity
            .push(format!("Starting port scan on {}...", device_ip));
          self.change_target(&device_ip)?;
          self.mode = ViewMode::Ports;
          self.scroll_offset = 0;
          self.selected_row = 0;
          self.execute_port_scan()?;
        }
      }
      ViewMode::Ports | ViewMode::Subdomains => {
        let row = self.current_rows().get(self.selected_row).cloned();
        if let Some(row) = row {
          self.push_row_details(&row);
        }
      }
      ViewMode::Vuln | ViewMode::Mitre | ViewMode::IOC => {
        let row = self.current_rows().get(self.selected_row).cloned();
        if let Some(row) = row {
          self.push_row_details(&row);
        }
      }
      _ => {}
    }
    Ok(())
  }

  /// Scroll down
  fn scroll_down(&mut self) {
    let rows = self.current_rows();
    if rows.is_empty() {
      return;
    }

    if self.selected_row < rows.len() - 1 {
      self.selected_row += 1;

      let visible_rows = (self.size.rows - 5) as usize;
      if self.selected_row >= self.scroll_offset + visible_rows {
        self.scroll_offset += 1;
      }
    }
  }

  /// Scroll up
  fn scroll_up(&mut self) {
    if self.selected_row > 0 {
      self.selected_row -= 1;

      if self.selected_row < self.scroll_offset {
        self.scroll_offset = self.selected_row;
      }
    }
  }

  /// Scroll page down (half page)
  fn scroll_page_down(&mut self) {
    let rows = self.current_rows();
    if rows.is_empty() {
      return;
    }

    let visible_rows = (self.size.rows - 5) as usize;
    let page_jump = visible_rows / 2; // Half page

    let new_row = (self.selected_row + page_jump).min(rows.len().saturating_sub(1));
    self.selected_row = new_row;

    // Adjust scroll offset to keep selection visible
    if self.selected_row >= self.scroll_offset + visible_rows {
      self.scroll_offset = self.selected_row.saturating_sub(visible_rows - 1);
    }
  }

  /// Scroll page up (half page)
  fn scroll_page_up(&mut self) {
    let visible_rows = (self.size.rows - 5) as usize;
    let page_jump = visible_rows / 2; // Half page

    self.selected_row = self.selected_row.saturating_sub(page_jump);

    // Adjust scroll offset to keep selection visible
    if self.selected_row < self.scroll_offset {
      self.scroll_offset = self.selected_row;
    }
  }

  /// Scroll to top (Home)
  fn scroll_to_top(&mut self) {
    self.selected_row = 0;
    self.scroll_offset = 0;
  }

  /// Scroll to bottom (End)
  fn scroll_to_bottom(&mut self) {
    let rows = self.current_rows();
    if rows.is_empty() {
      return;
    }

    self.selected_row = rows.len().saturating_sub(1);

    let visible_rows = (self.size.rows - 5) as usize;
    if self.selected_row >= visible_rows {
      self.scroll_offset = self.selected_row.saturating_sub(visible_rows - 1);
    }
  }

  /// Execute command
  fn execute_command(&mut self, cmd: &str) -> Result<(), String> {
    // Expand variables in command before processing
    let expanded_cmd = self.expand_variables(cmd);
    let parts: Vec<&str> = expanded_cmd.trim().split_whitespace().collect();

    if parts.is_empty() {
      return Ok(());
    }

    match parts[0] {
      // Session variable commands
      "set" => {
        // set VAR=value or set VAR value
        if parts.len() < 2 {
          return Err("Usage: set VAR=value or set VAR value".to_string());
        }

        // Check for VAR=value format
        let rest = expanded_cmd.trim_start_matches("set").trim();
        if let Some(eq_pos) = rest.find('=') {
          let name = rest[..eq_pos].trim();
          let value = rest[eq_pos + 1..].trim();
          if name.is_empty() {
            return Err("Variable name cannot be empty".to_string());
          }
          self.set_variable(name, value);
        } else if parts.len() >= 3 {
          // set VAR value format
          let name = parts[1];
          let value = parts[2..].join(" ");
          self.set_variable(name, &value);
        } else {
          return Err("Usage: set VAR=value or set VAR value".to_string());
        }
        return Ok(());
      }
      "get" => {
        if parts.len() < 2 {
          return Err("Usage: get VAR".to_string());
        }
        let name = parts[1].trim_start_matches('$');
        if let Some(value) = self.get_variable(name) {
          self.scan_activity.push(format!("${} = {}", name, value));
        } else {
          self.scan_activity.push(format!("${} is not set", name));
        }
        return Ok(());
      }
      "unset" => {
        if parts.len() < 2 {
          return Err("Usage: unset VAR".to_string());
        }
        let name = parts[1].trim_start_matches('$');
        if !self.unset_variable(name) {
          self.scan_activity.push(format!("${} was not set", name));
        }
        return Ok(());
      }
      "vars" | "env" => {
        // Clone variables to avoid borrow checker issues
        let vars: Vec<(String, String)> = self
          .session_variables
          .iter()
          .map(|(k, v)| (k.clone(), v.clone()))
          .collect();
        if vars.is_empty() {
          self
            .scan_activity
            .push("No session variables set".to_string());
        } else {
          self
            .scan_activity
            .push(format!("Session variables ({}):", vars.len()));
          for (name, value) in vars {
            self.scan_activity.push(format!("  ${} = {}", name, value));
          }
        }
        return Ok(());
      }
      "add" => {
        if parts.len() < 2 {
          return Err("Usage: add <ip> [status]".to_string());
        }

        if self.mode != ViewMode::Network {
          return Err("Use `add` in network mode only".to_string());
        }

        let host = parts[1].trim().to_string();
        let status = if parts.len() >= 3 {
          parts[2..].join(" ")
        } else {
          "Manual".to_string()
        };

        self.add_network_host(host, status)?;
      }
      "run" => {
        if parts.len() < 2 {
          return Err("Usage: run <preset|playbook>".to_string());
        }

        // If starts with "playbook", treat as playbook run
        if parts[1].starts_with("playbook:") {
          let playbook = parts[1].trim_start_matches("playbook:");
          self
            .scan_activity
            .push(format!("Running playbook: {}...", playbook));
          self.run_external_command(&[
            "playbook".to_string(),
            "run".to_string(),
            playbook.to_string(),
            self.target.clone(),
          ])?;
        } else {
          // Default to scan preset
          self.run_scan(parts[1])?;
        }
      }
      "ports" => {
        self.switch_view(ViewMode::Ports)?;
        return Ok(());
      }
      "vulns" | "vulnerabilities" => {
        self.switch_view(ViewMode::Vuln)?;
        return Ok(());
      }
      "mitre" | "attack" => {
        self.switch_view(ViewMode::Mitre)?;
        return Ok(());
      }
      "ioc" | "iocs" => {
        self.switch_view(ViewMode::IOC)?;
        return Ok(());
      }
      "check" => {
        self
          .scan_activity
          .push("Checking port health...".to_string());
        self.run_external_command(&[
          "network".to_string(),
          "health".to_string(),
          "check".to_string(),
          self.target.clone(),
        ])?;
        return Ok(());
      }
      "watch" => {
        self
          .scan_activity
          .push("Starting port watch...".to_string());
        self.run_external_command(&[
          "network".to_string(),
          "health".to_string(),
          "watch".to_string(),
          self.target.clone(),
        ])?;
        return Ok(());
      }
      "plan" => {
        self
          .scan_activity
          .push("Generating attack plan...".to_string());
        self.run_external_command(&[
          "exploit".to_string(),
          "payload".to_string(),
          "plan".to_string(),
          self.target.clone(),
        ])?;
        return Ok(());
      }
      "exec" => {
        if parts.len() < 2 {
          return Err("Usage: exec <command> [args...]".to_string());
        }
        // Reconstruct arguments properly handling quotes?
        // For now simple split is enough for basic commands
        let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
        self
          .scan_activity
          .push(format!("Executing: rb {}", args.join(" ")));
        self.run_external_command(&args)?;
      }
      "reload" => {
        self.load_session()?;
      }
      "quit" | "q" | "exit" => {
        self.running = false;
      }
      // Simplified commands that use target context automatically
      "scan" => {
        if parts.len() < 2 {
          return Err("Usage: scan <ports|subdomains|network>".to_string());
        }
        match parts[1] {
          "ports" => {
            self
              .scan_activity
              .push(format!("Command: Scanning ports on {}", self.target));
            self.execute_port_scan()?;
          }
          "subdomains" => {
            self
              .scan_activity
              .push(format!("Command: Scanning subdomains for {}", self.target));
            self.execute_subdomain_scan()?;
          }
          "network" => {
            self
              .scan_activity
              .push(format!("Command: Scanning network for {}", self.target));
            self.execute_network_scan()?;
          }
          _ => {
            return Err(format!("Unknown scan type: {}", parts[1]));
          }
        }
      }
      "recon" => {
        if parts.len() < 3 {
          return Err("Usage: recon domain <subdomains|whois>".to_string());
        }
        if parts[1] == "domain" {
          match parts[2] {
            "subdomains" => {
              self
                .scan_activity
                .push(format!("Command: Subdomain recon for {}", self.target));
              self.execute_subdomain_scan()?;
            }
            "whois" => {
              self
                .scan_activity
                .push(format!("Command: WHOIS lookup for {}", self.target));
              self.execute_whois_lookup()?;
            }
            _ => {
              return Err(format!("Unknown recon command: {}", parts[2]));
            }
          }
        } else {
          return Err("Usage: recon domain <subdomains|whois>".to_string());
        }
      }
      // ========== Scraping Commands ==========
      "scrap" => {
        if parts.len() < 2 {
          return Err("Usage: scrap <url>".to_string());
        }
        let url = parts[1..].join(" ");
        self.execute_scrap(&url)?;
      }
      "$" => {
        // CSS selector query
        if parts.len() < 2 {
          return Err("Usage: $ <selector>".to_string());
        }
        let selector = expanded_cmd.trim_start_matches('$').trim();
        self.execute_selector_query(selector)?;
      }
      "$text" => {
        self.execute_selector_text()?;
      }
      "$attr" => {
        if parts.len() < 2 {
          return Err("Usage: $attr <attribute-name>".to_string());
        }
        self.execute_selector_attr(parts[1])?;
      }
      "$html" => {
        self.execute_selector_html()?;
      }
      "$links" => {
        self.execute_extract_links()?;
      }
      "$images" => {
        self.execute_extract_images()?;
      }
      "$forms" => {
        self.execute_extract_forms()?;
      }
      "$meta" => {
        self.execute_extract_meta()?;
      }
      "$og" => {
        self.execute_extract_og()?;
      }
      "$json-ld" => {
        self.execute_extract_jsonld()?;
      }
      "$scripts" => {
        self.execute_extract_scripts()?;
      }
      "$css" => {
        self.execute_extract_css()?;
      }
      "$table" => {
        self.execute_extract_table()?;
      }
      // ========== Graph Exploration Commands ==========
      "graph" => {
        self.switch_view(ViewMode::Graph)?;
        self.execute_graph_stats()?;
      }
      "nodes" => {
        self.execute_graph_nodes()?;
      }
      "node" => {
        if parts.len() < 2 {
          // Show current node context
          if let Some(ref node) = self.graph_current_node {
            self.scan_activity.push(format!("Current node: {}", node));
          } else {
            self
              .scan_activity
              .push("No node selected. Use: node <id>".to_string());
          }
        } else {
          let node_id = parts[1..].join(" ");
          self.execute_graph_select_node(&node_id)?;
        }
      }
      "neighbors" => {
        let node_id = if parts.len() > 1 {
          Some(parts[1..].join(" "))
        } else {
          self.graph_current_node.clone()
        };
        if let Some(id) = node_id {
          self.execute_graph_neighbors(&id)?;
        } else {
          return Err(
            "No node specified and no current node context. Use: neighbors <id>".to_string(),
          );
        }
      }
      "reach" => {
        if let Some(ref node) = self.graph_current_node.clone() {
          self.execute_graph_reach(node)?;
        } else {
          return Err("No current node. Use: node <id> to select first".to_string());
        }
      }
      "paths" => {
        if parts.len() < 3 {
          return Err("Usage: paths <from> <to>".to_string());
        }
        self.execute_graph_paths(parts[1], parts[2])?;
      }
      "pagerank" => {
        self.execute_graph_pagerank()?;
      }
      "components" => {
        self.execute_graph_components()?;
      }
      "target" => {
        // Change target context dynamically
        if parts.len() < 2 {
          // Show current target
          self
            .scan_activity
            .push(format!("Current target: {}", self.target));
          return Ok(());
        }

        let new_target = parts[1..].join(" ");
        self.change_target(&new_target)?;
        return Ok(());
      }
      "help" | "?" => {
        self.scan_activity.push("Available commands:".to_string());
        self.scan_activity.push("  Target:".to_string());
        self
          .scan_activity
          .push("    target <host>  - Change target context".to_string());
        self
          .scan_activity
          .push("    target         - Show current target".to_string());
        self.scan_activity.push("  Variables:".to_string());
        self
          .scan_activity
          .push("    set VAR=value  - Set a session variable".to_string());
        self
          .scan_activity
          .push("    get VAR        - Get variable value".to_string());
        self
          .scan_activity
          .push("    unset VAR      - Remove variable".to_string());
        self
          .scan_activity
          .push("    vars           - List all variables".to_string());
        self.scan_activity.push("  Scans:".to_string());
        self
          .scan_activity
          .push("    scan ports     - Port scan on target".to_string());
        self
          .scan_activity
          .push("    scan subdomains - Subdomain enumeration".to_string());
        self
          .scan_activity
          .push("    scan network   - Network discovery".to_string());
        self
          .scan_activity
          .push("    add <ip> [status] - Add manual network host".to_string());
        self.scan_activity.push("  Recon:".to_string());
        self
          .scan_activity
          .push("    recon domain whois      - WHOIS lookup".to_string());
        self
          .scan_activity
          .push("    recon domain subdomains - Subdomain enum".to_string());
        self.scan_activity.push("  Scraping:".to_string());
        self
          .scan_activity
          .push("    scrap <url>       - Fetch and parse HTML".to_string());
        self
          .scan_activity
          .push("    $ <selector>      - Query CSS selector".to_string());
        self
          .scan_activity
          .push("    $text             - Extract text from results".to_string());
        self
          .scan_activity
          .push("    $attr <name>      - Extract attribute".to_string());
        self
          .scan_activity
          .push("    $html             - Extract inner HTML".to_string());
        self
          .scan_activity
          .push("    $links            - Extract all links".to_string());
        self
          .scan_activity
          .push("    $images           - Extract all images".to_string());
        self
          .scan_activity
          .push("    $forms            - Extract all forms".to_string());
        self
          .scan_activity
          .push("    $meta             - Extract meta tags".to_string());
        self
          .scan_activity
          .push("    $og               - Extract Open Graph".to_string());
        self
          .scan_activity
          .push("    $json-ld          - Extract JSON-LD".to_string());
        self
          .scan_activity
          .push("    $scripts          - Extract scripts".to_string());
        self
          .scan_activity
          .push("    $css              - Extract stylesheets".to_string());
        self
          .scan_activity
          .push("    $table            - Extract tables".to_string());
        self.scan_activity.push("  Graph:".to_string());
        self
          .scan_activity
          .push("    graph             - Switch to Graph view & show stats".to_string());
        self
          .scan_activity
          .push("    nodes             - List all nodes in graph".to_string());
        self
          .scan_activity
          .push("    node <id>         - Select node as context".to_string());
        self
          .scan_activity
          .push("    neighbors [id]    - Show neighbors (uses context if no id)".to_string());
        self
          .scan_activity
          .push("    reach             - What can I reach from current node?".to_string());
        self
          .scan_activity
          .push("    paths <from> <to> - Find paths between nodes".to_string());
        self
          .scan_activity
          .push("    pagerank          - Calculate node importance".to_string());
        self
          .scan_activity
          .push("    components        - Find connected components".to_string());
        self.scan_activity.push("  Other:".to_string());
        self
          .scan_activity
          .push("    run <preset>   - Run scan preset".to_string());
        self
          .scan_activity
          .push("    reload         - Reload session".to_string());
        self
          .scan_activity
          .push("    quit           - Exit TUI".to_string());
        self
          .scan_activity
          .push("  Note: Variables are expanded in commands ($VAR or ${VAR})".to_string());
      }
      _ => {
        return Err(format!(
          "Unknown command: {}. Type 'help' for available commands",
          parts[0]
        ));
      }
    }

    Ok(())
  }

  /// Execute port scan
  fn execute_port_scan(&mut self) -> Result<(), String> {
    let args = vec![
      "network".to_string(),
      "ports".to_string(),
      "scan".to_string(),
      self.target.clone(),
      "--preset".to_string(),
      "common".to_string(),
    ];
    self.run_external_command(&args)
  }

  /// Execute subdomain enumeration scan
  fn execute_subdomain_scan(&mut self) -> Result<(), String> {
    let args = vec![
      "recon".to_string(),
      "domain".to_string(),
      "subdomains".to_string(),
      self.target.clone(),
    ];
    self.run_external_command(&args)
  }

  /// Execute network discovery scan
  fn execute_network_scan(&mut self) -> Result<(), String> {
    let args = vec![
      "network".to_string(),
      "host".to_string(),
      "discover".to_string(),
      "192.168.1.0/24".to_string(),
    ];
    self.run_external_command(&args)
  }

  /// Execute WHOIS lookup
  fn execute_whois_lookup(&mut self) -> Result<(), String> {
    let args = vec![
      "recon".to_string(),
      "domain".to_string(),
      "whois".to_string(),
      self.target.clone(),
    ];
    self.run_external_command(&args)
  }

  /// Execute vulnerability scan
  fn execute_vuln_scan(&mut self) -> Result<(), String> {
    let target = if self.target.starts_with("http://") || self.target.starts_with("https://") {
      self.target.clone()
    } else {
      format!("http://{}", self.target)
    };

    let args = vec![
      "recon".to_string(),
      "domain".to_string(),
      "vuln".to_string(),
      target,
    ];
    self.run_external_command(&args)
  }

  /// Add a manual network host
  fn add_network_host(&mut self, host: String, status: String) -> Result<(), String> {
    if host.trim().is_empty() {
      return Err("Host cannot be empty".to_string());
    }

    if self.network_data.iter().any(|row| row.module == host) {
      self
        .scan_activity
        .push(format!("Device {} already exists", host));
      return Ok(());
    }

    self.network_data.push(TableRow {
      module: host.clone(),
      status,
      data: "Manually added from TUI".to_string(),
      timestamp: now_secs(),
    });

    self.network_data.sort_by(|a, b| a.module.cmp(&b.module));

    self
      .scan_activity
      .push(format!("Added manual device: {}", host));
    Ok(())
  }

  /// Push selected row details into activity log
  fn push_row_details(&mut self, row: &TableRow) {
    self.scan_activity.push(format!(
      "Details: {} | status={} | data={}",
      row.module, row.status, row.data
    ));
  }

  // ========== Dynamic Target ==========

  /// Change the target context dynamically
  fn change_target(&mut self, new_target: &str) -> Result<(), String> {
    use crate::storage::service::StorageService;

    let old_target = self.target.clone();

    // Update target and associated paths
    self.target = new_target.to_string();

    // Recalculate session and database paths
    let identifier = SessionFile::identifier_for(new_target);
    self.session_path = format!("{}{}", identifier, SessionFile::EXTENSION);
    self.db_path = StorageService::db_path(new_target)
      .to_string_lossy()
      .to_string();

    // Log the change
    self
      .scan_activity
      .push(format!("Target changed: {} → {}", old_target, new_target));

    // Clear existing data for fresh start with new target
    self.network_data.clear();
    self.ports_data.clear();
    self.subdomains_data.clear();
    self.whois_data.clear();
    self.certs_data.clear();
    self.metadata = None;

    // Try to load existing session/database for the new target
    if std::path::Path::new(&self.session_path).exists() {
      self
        .scan_activity
        .push(format!("Found existing session: {}", self.session_path));
      let _ = self.load_session();
    }

    if std::path::Path::new(&self.db_path).exists() {
      self
        .scan_activity
        .push(format!("Found existing database: {}", self.db_path));
      let _ = self.load_database_data();
    } else {
      self
        .scan_activity
        .push("No existing data for this target".to_string());
    }

    // Also set target as a session variable for easy reference
    self
      .session_variables
      .insert("TARGET".to_string(), new_target.to_string());

    Ok(())
  }

  // ========== Session Variables ==========

  /// Set a session variable
  fn set_variable(&mut self, name: &str, value: &str) {
    self
      .session_variables
      .insert(name.to_string(), value.to_string());
    self
      .scan_activity
      .push(format!("Set ${} = {}", name, value));
  }

  /// Get a session variable
  fn get_variable(&self, name: &str) -> Option<&String> {
    self.session_variables.get(name)
  }

  /// Unset (remove) a session variable
  fn unset_variable(&mut self, name: &str) -> bool {
    let existed = self.session_variables.remove(name).is_some();
    if existed {
      self.scan_activity.push(format!("Unset ${}", name));
    }
    existed
  }

  /// List all session variables
  fn list_variables(&self) -> Vec<(&String, &String)> {
    let mut vars: Vec<_> = self.session_variables.iter().collect();
    vars.sort_by(|a, b| a.0.cmp(b.0));
    vars
  }

  /// Expand variables in a string ($VAR or ${VAR} syntax)
  fn expand_variables(&self, input: &str) -> String {
    let mut result = input.to_string();

    // First expand ${VAR} syntax (more specific)
    for (name, value) in &self.session_variables {
      let pattern = format!("${{{}}}", name);
      result = result.replace(&pattern, value);
    }

    // Then expand $VAR syntax (simpler)
    // Sort by name length descending to match longer names first
    let mut sorted_vars: Vec<_> = self.session_variables.iter().collect();
    sorted_vars.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    for (name, value) in sorted_vars {
      let pattern = format!("${}", name);
      result = result.replace(&pattern, value);
    }

    result
  }

  /// Run a scan
  fn run_scan(&mut self, preset: &str) -> Result<(), String> {
    // Exit TUI temporarily
    self.exit_alternate_screen()?;
    self.disable_raw_mode()?;

    // Run scan
    use crate::cli::commands::magic;
    use crate::cli::CliContext;

    let mut ctx = CliContext::new();
    ctx.domain = Some(self.target.clone());
    ctx.raw = vec![
      self.target.clone(),
      "--preset".to_string(),
      preset.to_string(),
    ];
    ctx.flags.insert("preset".to_string(), preset.to_string());

    magic::execute(&ctx)?;

    // Re-enter TUI
    self.enable_raw_mode()?;
    self.enter_alternate_screen()?;
    self.load_session()?;

    Ok(())
  }

  // ========== View & Scraping Methods ==========

  fn switch_view(&mut self, mode: ViewMode) -> Result<(), String> {
    self.mode = mode;
    self.scroll_offset = 0;
    self.selected_row = 0;
    self.load_database_data()
  }

  fn refresh_current_view(&mut self) -> Result<(), String> {
    self.load_session()?;
    self.load_database_data()
  }

  fn execute_scrap(&mut self, url: &str) -> Result<(), String> {
    use crate::protocols::http::{HttpClient, HttpRequest};
    self.scan_activity.push(format!("Fetching: {}", url));
    let client = HttpClient::new();
    let req = HttpRequest::get(url);
    match client.send(&req) {
      Ok(resp) => {
        let body = String::from_utf8_lossy(&resp.body).to_string();
        self.current_doc = Some(body.clone());
        self.current_doc_url = url.to_string();
        self
          .scan_activity
          .push(format!("Loaded {} bytes", body.len()));
        Ok(())
      }
      Err(e) => {
        self.scan_activity.push(format!("Failed: {}", e));
        Err(e)
      }
    }
  }

  fn execute_selector_query(&mut self, selector: &str) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document loaded")?;
    self.last_selector_results.clear();
    let open_tag = format!("<{}", selector.to_lowercase());
    let mut count = 0;
    for (i, _) in doc.to_lowercase().match_indices(&open_tag) {
      count += 1;
      if count <= 10 {
        self
          .last_selector_results
          .push(doc[i..(i + 100).min(doc.len())].to_string());
      }
    }
    self.scan_activity.push(format!("Found {} matches", count));
    Ok(())
  }

  fn execute_selector_text(&mut self) -> Result<(), String> {
    if self.last_selector_results.is_empty() {
      return Err("No results".to_string());
    }
    for (i, r) in self.last_selector_results.iter().enumerate() {
      let text: String = r
        .chars()
        .fold((String::new(), false), |(mut a, t), c| {
          if c == '<' {
            (a, true)
          } else if c == '>' {
            (a, false)
          } else if !t {
            a.push(c);
            (a, false)
          } else {
            (a, true)
          }
        })
        .0;
      self.scan_activity.push(format!("[{}] {}", i, text.trim()));
    }
    Ok(())
  }

  fn execute_selector_attr(&mut self, attr: &str) -> Result<(), String> {
    if self.last_selector_results.is_empty() {
      return Err("No results".to_string());
    }
    let pat = format!("{}=\"", attr);
    for (i, r) in self.last_selector_results.iter().enumerate() {
      if let Some(s) = r.find(&pat) {
        let vs = s + pat.len();
        if let Some(e) = r[vs..].find('"') {
          self
            .scan_activity
            .push(format!("[{}] {}={}", i, attr, &r[vs..vs + e]));
        }
      }
    }
    Ok(())
  }

  fn execute_selector_html(&mut self) -> Result<(), String> {
    if self.last_selector_results.is_empty() {
      return Err("No results".to_string());
    }
    for (i, r) in self.last_selector_results.iter().enumerate() {
      self.scan_activity.push(format!("[{}] {}", i, r));
    }
    Ok(())
  }

  fn execute_extract_links(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    let mut links = Vec::new();
    let mut pos = 0;
    while let Some(s) = doc[pos..].find("href=\"") {
      let vs = pos + s + 6;
      if let Some(e) = doc[vs..].find('"') {
        if !links.contains(&doc[vs..vs + e].to_string()) {
          links.push(doc[vs..vs + e].to_string());
        }
      }
      pos = vs + 1;
    }
    self
      .scan_activity
      .push(format!("Found {} links", links.len()));
    for l in links.iter().take(20) {
      self.scan_activity.push(format!("  {}", l));
    }
    Ok(())
  }

  fn execute_extract_images(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    self
      .scan_activity
      .push(format!("Images: {} found", doc.matches("<img").count()));
    Ok(())
  }

  fn execute_extract_forms(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    self
      .scan_activity
      .push(format!("Forms: {} found", doc.matches("<form").count()));
    Ok(())
  }

  fn execute_extract_meta(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    self
      .scan_activity
      .push(format!("Meta tags: {} found", doc.matches("<meta").count()));
    Ok(())
  }

  fn execute_extract_og(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    self.scan_activity.push(format!(
      "OG tags: {} found",
      doc.matches("property=\"og:").count()
    ));
    Ok(())
  }

  fn execute_extract_jsonld(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    self.scan_activity.push(format!(
      "JSON-LD: {} found",
      doc.matches("application/ld+json").count()
    ));
    Ok(())
  }

  fn execute_extract_scripts(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    self
      .scan_activity
      .push(format!("Scripts: {} found", doc.matches("<script").count()));
    Ok(())
  }

  fn execute_extract_css(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    self.scan_activity.push(format!(
      "Stylesheets: {} found",
      doc.matches("rel=\"stylesheet\"").count()
    ));
    Ok(())
  }

  fn execute_extract_table(&mut self) -> Result<(), String> {
    let doc = self.current_doc.as_ref().ok_or("No document")?;
    self
      .scan_activity
      .push(format!("Tables: {} found", doc.matches("<table").count()));
    Ok(())
  }

  // ========== Graph Exploration Methods ==========

  // Show graph statistics

}
