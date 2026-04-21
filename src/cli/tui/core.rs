// TUI - Full-screen Text User Interface (k9s-style)
// ZERO external dependencies - pure Rust std only

use crate::storage::engine::{
  ConnectedComponents, GraphNodeType, GraphStore, PageRank, StoredNode,
};
use crate::storage::session::SessionFile;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

/// Truncate a string to max_len characters, adding "..." if truncated
fn truncate_str(s: &str, max_len: usize) -> String {
  if s.len() <= max_len {
    s.to_string()
  } else if max_len > 3 {
    format!("{}...", &s[..max_len - 3])
  } else {
    s[..max_len].to_string()
  }
}

/// Get current time in seconds since UNIX epoch
fn now_secs() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
}

/// TUI Input Key
#[derive(Debug, Clone, Copy)]
pub enum Key {
  Char(char),
  Up,
  Down,
  Left,
  Right,
  PageUp,
  PageDown,
  Home,
  End,
  Esc,
  Enter,
  Backspace,
  Delete,
  Tab,
  Unknown(u8),
}

/// TUI Event
pub enum Event {
  Input(Key),
  Log(String),
  Tick,
}

#[cfg(unix)]
extern "C" {
  fn ioctl(fd: i32, request: u64, ...) -> i32;
  fn tcgetattr(fd: i32, termios_p: *mut Termios) -> i32;
  fn tcsetattr(fd: i32, optional_actions: i32, termios_p: *const Termios) -> i32;
}

#[cfg(unix)]
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
  c_iflag: u32,
  c_oflag: u32,
  c_cflag: u32,
  c_lflag: u32,
  c_line: u8,
  c_cc: [u8; 32],
  c_ispeed: u32,
  c_ospeed: u32,
}

#[cfg(unix)]
const ICANON: u32 = 0x00000002;
#[cfg(unix)]
const ECHO: u32 = 0x00000008;
#[cfg(unix)]
const TCSANOW: i32 = 0;

/// ANSI escape codes for terminal control
mod ansi {
  // Cursor control
  pub const HIDE_CURSOR: &str = "\x1b[?25l";
  pub const SHOW_CURSOR: &str = "\x1b[?25h";
  pub const CLEAR_SCREEN: &str = "\x1b[2J";
  pub const MOVE_HOME: &str = "\x1b[H";

  // Screen control
  pub const ALTERNATE_SCREEN: &str = "\x1b[?1049h";
  pub const MAIN_SCREEN: &str = "\x1b[?1049l";

  // Mouse tracking (SGR mode for better compatibility)
  pub const ENABLE_MOUSE: &str = "\x1b[?1006h\x1b[?1003h";
  pub const DISABLE_MOUSE: &str = "\x1b[?1006l\x1b[?1003l";

  // Colors (k9s theme)
  pub const RESET: &str = "\x1b[0m";
  pub const BOLD: &str = "\x1b[1m";
  pub const DIM: &str = "\x1b[2m";
  pub const REVERSE: &str = "\x1b[7m";
  pub const BLACK: &str = "\x1b[30m";
  pub const RED: &str = "\x1b[31m"; // Error/CrashLoopBackOff
  pub const GREEN: &str = "\x1b[32m"; // Running/Success
  pub const YELLOW: &str = "\x1b[33m"; // Warning/Pending
  pub const BLUE: &str = "\x1b[34m"; // Info
  pub const CYAN: &str = "\x1b[36m"; // Headers/Selected (k9s primary)
  pub const BRIGHT_CYAN: &str = "\x1b[96m"; // k9s highlight
  pub const ORANGE: &str = "\x1b[38;5;208m"; // k9s footer (256-color)

  // Background colors
  pub const BG_BLACK: &str = "\x1b[40m";
  pub const BG_DARK_GRAY: &str = "\x1b[100m"; // k9s header background
  pub const BG_ORANGE: &str = "\x1b[48;5;208m"; // k9s footer background
  pub const BG_BRIGHT_CYAN: &str = "\x1b[106m"; // k9s selection

  // Move cursor to position (1-indexed)
  pub fn move_to(row: u16, col: u16) -> String {
    format!("\x1b[{};{}H", row, col)
  }

  // Clear from cursor to end of line
  pub const CLEAR_LINE: &str = "\x1b[K";
}

/// Terminal size
#[derive(Debug, Clone, Copy)]
pub struct TermSize {
  pub rows: u16,
  pub cols: u16,
}

impl TermSize {
  /// Get current terminal size
  pub fn get() -> io::Result<Self> {
    // Try to get size from ioctl
    #[cfg(unix)]
    {
      use std::os::unix::io::AsRawFd;
      let fd = io::stdout().as_raw_fd();

      // winsize struct from libc
      #[repr(C)]
      struct WinSize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
      }

      const TIOCGWINSZ: u64 = 0x5413;

      let mut size = WinSize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
      };

      unsafe {
        if ioctl(fd, TIOCGWINSZ, &mut size as *mut _) == 0 {
          return Ok(TermSize {
            rows: size.ws_row,
            cols: size.ws_col,
          });
        }
      }
    }

    // Fallback to default size
    Ok(TermSize { rows: 24, cols: 80 })
  }
}

/// TUI View mode (k9s-style resource navigation)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ViewMode {
  Overview,   // [1] Target overview & scan summary (first tab)
  Network,    // Network discovery results
  Subdomains, // [2] Subdomain enumeration results
  Ports,      // [3] Port scan results
  Services,   // [4] Service detection & fingerprinting
  Certs,      // [5] TLS certificates & SSL info
  Whois,      // [6] WHOIS & domain registration
  Sessions,   // Session metadata & history
  DNS,        // [7] DNS records (A, MX, NS, TXT, etc)
  HTTP,       // [8] HTTP headers & web security
  Vuln,       // [V] Vulnerabilities & CVEs
  Mitre,      // [M] MITRE ATT&CK Mapping
  IOC,        // [I] Indicators of Compromise
  Graph,      // [G] Intel Graph - nodes, edges, paths, attack surface
  RBB,        // [R] RedBlue Browser - hooked browsers C2 dashboard
  Activity,   // [0] Scan activity log (last tab)
  Normal,     // Scan activity: normal profile timeline
  Stealth,    // Scan activity: stealth profile timeline
  Aggressive, // Scan activity: aggressive profile timeline
}

impl ViewMode {
  pub fn title(&self) -> &'static str {
    match self {
      ViewMode::Overview => "Overview",
      ViewMode::Network => "Network",
      ViewMode::Subdomains => "Subdomains",
      ViewMode::Ports => "Ports",
      ViewMode::Services => "Services",
      ViewMode::Certs => "Certificates",
      ViewMode::Whois => "WHOIS",
      ViewMode::Sessions => "Sessions",
      ViewMode::DNS => "DNS Records",
      ViewMode::HTTP => "HTTP Security",
      ViewMode::Vuln => "Vulnerabilities",
      ViewMode::Mitre => "MITRE ATT&CK",
      ViewMode::IOC => "IOCs",
      ViewMode::Graph => "Intel Graph",
      ViewMode::RBB => "RBB Zombies",
      ViewMode::Activity => "Activity Log",
      ViewMode::Normal => "Normal Profile",
      ViewMode::Stealth => "Stealth Profile",
      ViewMode::Aggressive => "Aggressive Profile",
    }
  }

  pub fn next(&self) -> Self {
    match self {
      ViewMode::Overview => ViewMode::Network,
      ViewMode::Network => ViewMode::Subdomains,
      ViewMode::Subdomains => ViewMode::Ports,
      ViewMode::Ports => ViewMode::Services,
      ViewMode::Services => ViewMode::Certs,
      ViewMode::Certs => ViewMode::Whois,
      ViewMode::Whois => ViewMode::Sessions,
      ViewMode::Sessions => ViewMode::DNS,
      ViewMode::DNS => ViewMode::HTTP,
      ViewMode::HTTP => ViewMode::Vuln,
      ViewMode::Vuln => ViewMode::Mitre,
      ViewMode::Mitre => ViewMode::IOC,
      ViewMode::IOC => ViewMode::Graph,
      ViewMode::Graph => ViewMode::RBB,
      ViewMode::RBB => ViewMode::Activity,
      ViewMode::Activity => ViewMode::Overview,
      ViewMode::Normal => ViewMode::Stealth,
      ViewMode::Stealth => ViewMode::Aggressive,
      ViewMode::Aggressive => ViewMode::Activity,
    }
  }

  pub fn prev(&self) -> Self {
    match self {
      ViewMode::Overview => ViewMode::Activity,
      ViewMode::Network => ViewMode::Overview,
      ViewMode::Subdomains => ViewMode::Network,
      ViewMode::Ports => ViewMode::Subdomains,
      ViewMode::Services => ViewMode::Ports,
      ViewMode::Certs => ViewMode::Services,
      ViewMode::Whois => ViewMode::Certs,
      ViewMode::Sessions => ViewMode::Whois,
      ViewMode::DNS => ViewMode::Sessions,
      ViewMode::HTTP => ViewMode::DNS,
      ViewMode::Vuln => ViewMode::HTTP,
      ViewMode::Mitre => ViewMode::Vuln,
      ViewMode::IOC => ViewMode::Mitre,
      ViewMode::Graph => ViewMode::IOC,
      ViewMode::RBB => ViewMode::Graph,
      ViewMode::Activity => ViewMode::RBB,
      ViewMode::Normal => ViewMode::Activity,
      ViewMode::Stealth => ViewMode::Normal,
      ViewMode::Aggressive => ViewMode::Stealth,
    }
  }
}

/// Table row for display
#[derive(Debug, Clone)]
pub struct TableRow {
  pub module: String,
  pub status: String,
  pub data: String,
  pub timestamp: u64,
}

/// TUI Application state
pub struct TuiApp {
  target: String,
  session_path: String,
  db_path: String,
  mode: ViewMode,
  scroll_offset: usize,
  selected_row: usize,
  command_buffer: String,
  command_mode: bool,
  running: bool,
  size: TermSize,
  metadata: Option<crate::storage::session::SessionMetadata>,
  // Data for different views
  network_data: Vec<TableRow>, // Network devices
  ports_data: Vec<TableRow>,
  subdomains_data: Vec<TableRow>,
  whois_data: Vec<(String, String)>,    // Key-value pairs
  certs_data: Vec<(String, String)>,    // Key-value pairs
  sessions_data: Vec<(String, String)>, // Key-value pairs
  vuln_data: Vec<TableRow>,             // Vulnerabilities
  mitre_data: Vec<TableRow>,            // MITRE techniques
  ioc_data: Vec<TableRow>,              // IOCs
  // Graph exploration state
  graph: Arc<RwLock<GraphStore>>,       // Intel graph store
  graph_current_node: Option<String>,   // Current node context for contextual queries
  graph_data: Vec<TableRow>,            // Graph nodes/edges for display
  graph_path_results: Vec<Vec<String>>, // Path finding results
  scan_activity: Vec<String>,           // Real-time scan logs
  // RBB (RedBlue Browser) zombie tracking
  rbb_zombies: Vec<TableRow>,      // Hooked browser zombies
  rbb_server_addr: Option<String>, // RBB server address if running
  // Auto-refresh and background scanning
  last_refresh: std::time::Instant, // Last time data was refreshed
  auto_refresh_enabled: bool,       // Enable auto-refresh on tab switch
  network_scan_running: bool,       // Network discovery running in background
  // Terminal state management
  #[cfg(unix)]
  original_termios: Option<Termios>, // Save original terminal state
  // Session variables (in-memory only, not persisted)
  session_variables: HashMap<String, String>,
  // Scraping state
  current_doc: Option<String>, // Currently loaded HTML document (raw HTML)
  current_doc_url: String,     // URL of the current document
  last_selector_results: Vec<String>, // Snippets from last $ command
  // Event channel
  tx: Sender<Event>,
  rx: Receiver<Event>,
}

impl TuiApp {
  /// Create new TUI application
  pub fn new(target: String) -> Result<Self, String> {
    use crate::storage::service::StorageService;

    let (session_target, db_path) = if target.ends_with(SessionFile::EXTENSION) {
      let trimmed = target.trim_end_matches(SessionFile::EXTENSION).to_string();
      (
        trimmed.clone(),
        StorageService::db_path(&trimmed)
          .to_string_lossy()
          .to_string(),
      )
    } else if target.ends_with(".json") || target.ends_with(".rdb") {
      let trimmed = target
        .trim_end_matches(".json")
        .trim_end_matches(".rdb")
        .to_string();
      (trimmed, target.clone())
    } else {
      (
        target.clone(),
        StorageService::db_path(&target)
          .to_string_lossy()
          .to_string(),
      )
    };

    let identifier = SessionFile::identifier_for(&session_target);
    let session_path = if target.ends_with(SessionFile::EXTENSION) {
      target.clone()
    } else {
      format!("{}{}", identifier, SessionFile::EXTENSION)
    };

    let size = TermSize::get().unwrap_or(TermSize { rows: 24, cols: 80 });
    let (tx, rx) = mpsc::channel();

    let mut app = Self {
      target: target.clone(),
      session_path,
      db_path,
      mode: ViewMode::Overview,
      scroll_offset: 0,
      selected_row: 0,
      command_buffer: String::new(),
      command_mode: false,
      running: false,
      size,
      metadata: None,
      network_data: Vec::new(),
      ports_data: Vec::new(),
      subdomains_data: Vec::new(),
      whois_data: Vec::new(),
      certs_data: Vec::new(),
      sessions_data: Vec::new(),
      vuln_data: Vec::new(),
      mitre_data: Vec::new(),
      ioc_data: Vec::new(),
      // Graph exploration state
      graph: Arc::new(RwLock::new(GraphStore::new())),
      graph_current_node: None,
      graph_data: Vec::new(),
      graph_path_results: Vec::new(),
      scan_activity: Vec::new(),
      rbb_zombies: Vec::new(),
      rbb_server_addr: None,
      last_refresh: std::time::Instant::now(),
      auto_refresh_enabled: true,
      network_scan_running: false,
      #[cfg(unix)]
      original_termios: None,
      session_variables: HashMap::new(),
      // Scraping state
      current_doc: None,
      current_doc_url: String::new(),
      last_selector_results: Vec::new(),
      tx,
      rx,
    };

    // Initialize TARGET variable with the initial target
    app.session_variables.insert("TARGET".to_string(), target);

    app.load_session()?;
    app.load_database_data()?;

    Ok(app)
  }

  /// Run external command (subprocess) and stream output to logs
  fn run_external_command(&self, args: &[String]) -> Result<(), String> {
    let tx = self.tx.clone();
    let args = args.to_vec();
    let _target = self.target.clone();

    thread::spawn(move || {
      // Determine executable path
      let exe = std::env::current_exe().unwrap_or_else(|_| "rb".into());

      tx.send(Event::Log(format!("Running: rb {}", args.join(" "))))
        .ok();

      let child = ProcessCommand::new(exe)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

      match child {
        Ok(mut child) => {
          if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
              if let Ok(line) = line {
                // Remove ANSI codes for cleaner log in TUI (optional)
                // For now, keep them as TUI might handle them or strip them
                tx.send(Event::Log(line)).ok();
              }
            }
          }

          // Also capture stderr
          if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
              if let Ok(line) = line {
                tx.send(Event::Log(format!("ERR: {}", line))).ok();
              }
            }
          }

          let _ = child.wait();
          tx.send(Event::Log("Command finished".to_string())).ok();
        }
        Err(e) => {
          tx.send(Event::Log(format!("Failed to start command: {}", e)))
            .ok();
        }
      }
    });

    Ok(())
  }

  /// Load session from disk
  fn load_session(&mut self) -> Result<(), String> {
    if std::path::Path::new(&self.session_path).exists() {
      self.metadata =
        Some(crate::storage::session::SessionFile::load_metadata_from_path(&self.session_path)?);

      // Load session metadata as key-value pairs
      if let Some(ref meta) = self.metadata {
        self.sessions_data.clear();
        self
          .sessions_data
          .push(("Target".to_string(), meta.target.clone()));
        self
          .sessions_data
          .push(("Identifier".to_string(), meta.identifier.clone()));
        self
          .sessions_data
          .push(("Command".to_string(), meta.command.clone()));
        self
          .sessions_data
          .push(("Created At".to_string(), meta.created_at.to_string()));
        if meta.is_complete() {
          self
            .sessions_data
            .push(("Status".to_string(), "✓ Complete".to_string()));
          if let Some(dur) = meta.duration_secs {
            self
              .sessions_data
              .push(("Duration".to_string(), format!("{:.2}s", dur)));
          }
        } else {
          self
            .sessions_data
            .push(("Status".to_string(), "⚠ Incomplete".to_string()));
        }
        self
          .sessions_data
          .push(("Age".to_string(), format!("{}s ago", meta.age_secs())));
      }
    }
    Ok(())
  }

  /// Load data from unified database
  fn load_database_data(&mut self) -> Result<(), String> {
    // Only load if database file exists
    if !std::path::Path::new(&self.db_path).exists() {
      self
        .scan_activity
        .push("No database found - run scans to populate".to_string());
      return Ok(());
    }

    // Detect legacy session stub accidentally saved with .rdb extension
    if let Ok(mut file) = std::fs::File::open(&self.db_path) {
      use std::io::Read;
      let mut prefix = [0u8; 24];
      let len = file.read(&mut prefix).unwrap_or(0);
      if len > 0 && prefix[..len].starts_with(b"# redblue session") {
        self
          .scan_activity
          .push("Database stub found - run scans to generate binary data".to_string());
        return Ok(());
      }
    }

    use crate::storage::service::StorageService;

    let mut db = StorageService::global()
      .open_query_manager(&self.db_path)
      .map_err(|e| format!("Failed to open database: {}", e))?;

    // Clear existing data
    self.network_data.clear();
    self.ports_data.clear();
    self.subdomains_data.clear();
    self.whois_data.clear();
    self.certs_data.clear();
    self.vuln_data.clear();
    self.mitre_data.clear();
    self.ioc_data.clear();
    self.scan_activity.clear();

    // Load port scan data once and reuse for multiple views
    let port_scans = db
      .list_port_scans()
      .map_err(|e| format!("Failed to load port scans: {}", e))?;

    self.network_data = Self::build_network_rows(&port_scans);

    for scan in &port_scans {
      let status_str = match scan.status {
        crate::storage::records::PortStatus::Open => "Open",
        crate::storage::records::PortStatus::Closed => "Closed",
        crate::storage::records::PortStatus::Filtered => "Filtered",
        crate::storage::records::PortStatus::OpenFiltered => "Open|Filtered",
      };

      self.ports_data.push(TableRow {
        module: scan.ip.to_string(),
        status: status_str.to_string(),
        data: format!("{}/tcp", scan.port),
        timestamp: scan.timestamp as u64,
      });
    }

    // Load subdomain data
    let subdomains = db
      .list_subdomain_records(&self.target)
      .map_err(|e| format!("Failed to load subdomains: {}", e))?;

    for sub in subdomains {
      let ips_str = sub
        .ips
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");

      let source_str = match sub.source {
        crate::storage::records::SubdomainSource::DnsBruteforce => "DNS",
        crate::storage::records::SubdomainSource::CertTransparency => "CT",
        crate::storage::records::SubdomainSource::SearchEngine => "Search",
        crate::storage::records::SubdomainSource::WebCrawl => "Crawl",
      };

      self.subdomains_data.push(TableRow {
        module: sub.subdomain.clone(),
        status: source_str.to_string(),
        data: ips_str,
        timestamp: sub.timestamp as u64,
      });
    }

    self
      .scan_activity
      .push(format!("Loaded {} port scans", self.ports_data.len()));
    self
      .scan_activity
      .push(format!("Loaded {} subdomains", self.subdomains_data.len()));
    // Load vulnerabilities
    let vuln_records = db
      .list_vulnerabilities()
      .map_err(|e| format!("Failed to load vulnerability records: {}", e))?;

    for rec in vuln_records {
      let status = match rec.severity {
        crate::modules::common::Severity::Critical => "Critical",
        crate::modules::common::Severity::High => "High",
        crate::modules::common::Severity::Medium => "Medium",
        crate::modules::common::Severity::Low => "Low",
        crate::modules::common::Severity::Info => "Info",
      };

      self.vuln_data.push(TableRow {
        module: rec.cve_id.clone(),
        status: status.to_string(),
        data: format!("{} ({})", rec.description, rec.technology),
        timestamp: rec.discovered_at as u64,
      });
    }

    self
      .scan_activity
      .push(format!("Loaded {} vulnerabilities", self.vuln_data.len()));
    self
      .scan_activity
      .push("Database loaded successfully".to_string());
    self
      .scan_activity
      .push(format!("Database: {}", self.db_path));

    Ok(())
  }

  fn build_network_rows(port_scans: &[crate::storage::records::PortScanRecord]) -> Vec<TableRow> {
    #[derive(Default)]
    struct Aggregate {
      open_ports: Vec<u16>,
      filtered_ports: Vec<u16>,
      closed_count: u32,
      last_seen: u64,
    }

    let mut devices: HashMap<String, Aggregate> = HashMap::new();

    for scan in port_scans {
      let entry = devices
        .entry(scan.ip.to_string())
        .or_insert_with(Aggregate::default);
      entry.last_seen = entry.last_seen.max(scan.timestamp as u64);

      match scan.status {
        crate::storage::records::PortStatus::Open => {
          entry.open_ports.push(scan.port);
        }
        crate::storage::records::PortStatus::Filtered
        | crate::storage::records::PortStatus::OpenFiltered => {
          entry.filtered_ports.push(scan.port);
        }
        crate::storage::records::PortStatus::Closed => {
          entry.closed_count += 1;
        }
      }
    }

    let mut rows: Vec<TableRow> = devices
      .into_iter()
      .map(|(ip, mut agg)| {
        agg.open_ports.sort_unstable();
        agg.open_ports.dedup();
        agg.filtered_ports.sort_unstable();
        agg.filtered_ports.dedup();

        let status = if !agg.open_ports.is_empty() {
          "Online"
        } else if !agg.filtered_ports.is_empty() {
          "Filtered"
        } else if agg.closed_count > 0 {
          "Closed"
        } else {
          "Scanned"
        };

        let mut details = Vec::new();
        if !agg.open_ports.is_empty() {
          details.push(format!(
            "open {}",
            Self::format_port_sample(&agg.open_ports)
          ));
        }
        if !agg.filtered_ports.is_empty() {
          details.push(format!(
            "filtered {}",
            Self::format_port_sample(&agg.filtered_ports)
          ));
        }
        if agg.closed_count > 0 {
          details.push(format!("closed {}", agg.closed_count));
        }

        let data = if details.is_empty() {
          "no port data".to_string()
        } else {
          details.join(" | ")
        };

        TableRow {
          module: ip,
          status: status.to_string(),
          data,
          timestamp: agg.last_seen,
        }
      })
      .collect();

    rows.sort_by(|a, b| a.module.cmp(&b.module));
    rows
  }

  fn format_port_sample(ports: &[u16]) -> String {
    const MAX_SAMPLE: usize = 6;
    if ports.len() <= MAX_SAMPLE {
      return ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    }

    let sample = ports[..MAX_SAMPLE]
      .iter()
      .map(|p| p.to_string())
      .collect::<Vec<_>>()
      .join(",");
    format!("{}(+{})", sample, ports.len() - MAX_SAMPLE)
  }

  /// Get current view rows (for table views)
  fn current_rows(&self) -> &[TableRow] {
    match self.mode {
      ViewMode::Network => &self.network_data,
      ViewMode::Ports => &self.ports_data,
      ViewMode::Subdomains => &self.subdomains_data,
      ViewMode::Vuln => &self.vuln_data,
      ViewMode::Mitre => &self.mitre_data,
      ViewMode::IOC => &self.ioc_data,
      ViewMode::RBB => &self.rbb_zombies,
      _ => &[], // Non-table views
    }
  }

  /// Get current key-value data (for detail views)
  fn current_keyvalue(&self) -> &[(String, String)] {
    match self.mode {
      ViewMode::Whois => &self.whois_data,
      ViewMode::Certs => &self.certs_data,
      ViewMode::Sessions => &self.sessions_data,
      _ => &[],
    }
  }

  /// Start the TUI
  pub fn run(&mut self) -> Result<(), String> {
    self.running = true;
    self.enter_alternate_screen()?;

    // Set terminal to raw mode
    self.enable_raw_mode()?;

    // Spawn input handling thread
    let tx = self.tx.clone();
    thread::spawn(move || {
      let mut buffer = [0u8; 1];
      let mut stdin = io::stdin();

      loop {
        if stdin.read_exact(&mut buffer).is_ok() {
          let ch = buffer[0];

          // Parse ANSI escape sequences
          if ch == 0x1b {
            // Non-blocking check for sequence would be ideal,
            // but for now we'll use a small timeout logic or just blocking read
            // since we are in a dedicated thread.

            // Try to read next byte with a very short timeout?
            // Standard Stdin doesn't support timeout easily.
            // We'll assume if we got ESC, we check if more bytes follow immediately.
            // Actually, robust ANSI parsing usually blocks for a few ms.

            // Simplified ANSI parser for this thread
            // We can reuse the logic from the original handle_input but adapted
            let _seq = vec![ch];
            // We'll optimistically read a few bytes if available
            // Since we can't peek, this is tricky without "crossterm".
            // Hack: Just assume manual ESC press is rare and fast,
            // while ANSI sequences come in bursts.

            // For now, let's just forward the ESC and let the main loop handle state?
            // No, main loop shouldn't block.

            // Let's implement a simple blocking parser here.
            // It might block the input thread if user presses ESC and waits,
            // but that's acceptable for the input thread.

            // Read next byte
            let _next = [0u8; 1];
            // We assume if it's a sequence, bytes are ready.
            // Real raw mode might need poll/select.
            // Given "ZERO dependencies", we'll try a best effort.

            // Key mapping
            tx.send(Event::Input(Key::Esc)).ok();
          } else {
            match ch {
              10 | 13 => tx.send(Event::Input(Key::Enter)).ok(),
              127 | 8 => tx.send(Event::Input(Key::Backspace)).ok(),
              9 => tx.send(Event::Input(Key::Tab)).ok(),
              _ => tx.send(Event::Input(Key::Char(ch as char))).ok(),
            };
          }
        } else {
          break; // EOF
        }
      }
    });

    // We need a better input thread that handles sequences properly.
    // Let's overwrite the thread above with a better one.
    let tx_input = self.tx.clone();
    thread::spawn(move || {
      Self::input_loop(tx_input);
    });

    // Spawn tick thread
    let tx_tick = self.tx.clone();
    thread::spawn(move || loop {
      tx_tick.send(Event::Tick).ok();
      thread::sleep(Duration::from_millis(100));
    });

    while self.running {
      // Render only on events to save CPU, but ensure we render at least once
      self.render()?;

      if let Ok(event) = self.rx.recv() {
        match event {
          Event::Input(key) => self.process_key(key)?,
          Event::Log(line) => {
            self.scan_activity.push(line);
            // Auto-scroll if at bottom?
            // For now just append.
          }
          Event::Tick => {
            // Animation updates
          }
        }

        // Drain pending events to avoid lag
        while let Ok(event) = self.rx.try_recv() {
          match event {
            Event::Input(key) => self.process_key(key)?,
            Event::Log(line) => self.scan_activity.push(line),
            Event::Tick => {}
          }
        }
      }
    }

    self.exit_alternate_screen()?;
    self.disable_raw_mode()?;

    Ok(())
  }

  fn input_loop(tx: Sender<Event>) {
    let mut stdin = io::stdin();
    let mut buffer = [0u8; 1];

    while stdin.read_exact(&mut buffer).is_ok() {
      let ch = buffer[0];

      if ch == 0x1b {
        // Start of escape sequence
        let mut seq = Vec::new();
        seq.push(ch);

        // Read next byte
        let mut next = [0u8; 1];
        if stdin.read_exact(&mut next).is_ok() {
          seq.push(next[0]);

          if next[0] == b'[' {
            // CSI sequence
            let mut final_byte = [0u8; 1];
            if stdin.read_exact(&mut final_byte).is_ok() {
              seq.push(final_byte[0]);
              match final_byte[0] {
                b'A' => {
                  tx.send(Event::Input(Key::Up)).ok();
                  continue;
                }
                b'B' => {
                  tx.send(Event::Input(Key::Down)).ok();
                  continue;
                }
                b'C' => {
                  tx.send(Event::Input(Key::Right)).ok();
                  continue;
                }
                b'D' => {
                  tx.send(Event::Input(Key::Left)).ok();
                  continue;
                }
                b'H' => {
                  tx.send(Event::Input(Key::Home)).ok();
                  continue;
                }
                b'F' => {
                  tx.send(Event::Input(Key::End)).ok();
                  continue;
                }
                b'5' => {
                  // PageUp/Down usually ~
                  let mut t = [0u8; 1];
                  if stdin.read_exact(&mut t).is_ok() && t[0] == b'~' {
                    tx.send(Event::Input(Key::PageUp)).ok();
                    continue;
                  }
                }
                b'6' => {
                  let mut t = [0u8; 1];
                  if stdin.read_exact(&mut t).is_ok() && t[0] == b'~' {
                    tx.send(Event::Input(Key::PageDown)).ok();
                    continue;
                  }
                }
                _ => {}
              }
            }
          }
        }
        // If we failed to parse, just send Esc
        tx.send(Event::Input(Key::Esc)).ok();
      } else {
        let key = match ch {
          10 | 13 => Key::Enter,
          127 | 8 => Key::Backspace,
          9 => Key::Tab,
          c => Key::Char(c as char),
        };
        tx.send(Event::Input(key)).ok();
      }
    }
  }

  /// Enter alternate screen
  fn enter_alternate_screen(&self) -> Result<(), String> {
    print!(
      "{}{}{}{}",
      ansi::ALTERNATE_SCREEN,
      ansi::HIDE_CURSOR,
      ansi::CLEAR_SCREEN,
      ansi::ENABLE_MOUSE
    );
    io::stdout().flush().map_err(|e| e.to_string())?;
    Ok(())
  }

  /// Exit alternate screen
  fn exit_alternate_screen(&self) -> Result<(), String> {
    // CRITICAL: Proper cleanup sequence
    // 1. Disable mouse tracking
    // 2. Show cursor
    // 3. Clear screen
    // 4. Exit alternate screen buffer
    // 5. Reset all attributes
    print!(
      "{}{}{}{}{}",
      ansi::DISABLE_MOUSE,
      ansi::SHOW_CURSOR,
      ansi::CLEAR_SCREEN,
      ansi::MAIN_SCREEN,
      ansi::RESET
    );
    io::stdout().flush().map_err(|e| e.to_string())?;
    Ok(())
  }

  /// Enable raw mode (no echo, no line buffering)
  fn enable_raw_mode(&mut self) -> Result<(), String> {
    #[cfg(unix)]
    unsafe {
      use std::os::unix::io::AsRawFd;
      let fd = io::stdin().as_raw_fd();

      let mut termios: Termios = std::mem::zeroed();
      tcgetattr(fd, &mut termios);

      // CRITICAL: Save original terminal state BEFORE modifying
      self.original_termios = Some(termios);

      // Disable canonical mode and echo
      termios.c_lflag &= !(ICANON | ECHO);

      tcsetattr(fd, TCSANOW, &termios);
    }
    Ok(())
  }

  /// Disable raw mode
  fn disable_raw_mode(&self) -> Result<(), String> {
    #[cfg(unix)]
    unsafe {
      use std::os::unix::io::AsRawFd;
      let fd = io::stdin().as_raw_fd();

      // CRITICAL: Restore the ORIGINAL terminal state that we saved
      if let Some(ref original) = self.original_termios {
        tcsetattr(fd, TCSANOW, original as *const Termios);
      } else {
        // Fallback: if we somehow don't have the original, manually restore
        let mut termios: Termios = std::mem::zeroed();
        tcgetattr(fd, &mut termios);
        termios.c_lflag |= ICANON | ECHO;
        tcsetattr(fd, TCSANOW, &termios);
      }
    }
    Ok(())
  }

  /// Render the TUI
  fn render(&mut self) -> Result<(), String> {
    // CRITICAL: Clear entire screen before rendering
    // This prevents artifacts from previous views
    print!("{}{}", ansi::CLEAR_SCREEN, ansi::MOVE_HOME);

    self.render_header()?;
    self.render_tabs()?; // NEW: Tab navigation bar
    self.render_command_bar()?;
    self.render_content()?;
    self.render_footer()?;

    io::stdout().flush().map_err(|e| e.to_string())?;
    Ok(())
  }

  /// Render header bar (k9s style: dark background with cyan text)
  fn render_header(&self) -> Result<(), String> {
    // First line: "redblue v1" with black background and fluorescent orange text
    const BG_BLACK: &str = "\x1b[40m";
    const ORANGE_FLUORESCENT: &str = "\x1b[38;5;208;1m";

    let text = "redblue v1";
    let padding_total = (self.size.cols as usize).saturating_sub(text.len());
    let padding_left = padding_total / 2;
    let padding_right = padding_total - padding_left;

    print!("{}{}", BG_BLACK, ORANGE_FLUORESCENT);
    print!(
      "{}{}{}",
      " ".repeat(padding_left),
      text,
      " ".repeat(padding_right)
    );
    println!("{}", ansi::RESET);

    // Second line: Original header (Context and view)
    let title = format!("Context: {} [RW]", self.target);
    let view = format!("<{}>", self.mode.title().to_lowercase());

    print!("{}{}{}", ansi::BG_DARK_GRAY, ansi::BRIGHT_CYAN, ansi::BOLD);
    print!(" {}", title);

    // Add view indicator
    print!("  {}{}{}", ansi::RESET, ansi::BG_DARK_GRAY, ansi::ORANGE);
    print!(" {}", view);

    // Show scan status indicator
    let mut status_indicator = String::new();
    if self.network_scan_running {
      status_indicator = format!("  {}🔄 Scanning{}", ansi::GREEN, ansi::RESET);
    }

    // Pad to right side (saturating to prevent underflow)
    let used = title.len() + view.len() + 6 + if self.network_scan_running { 12 } else { 0 };
    let padding = (self.size.cols as usize).saturating_sub(used);
    print!("{}{}", ansi::RESET, ansi::BG_DARK_GRAY);
    print!("{}", status_indicator);
    print!("{}", " ".repeat(padding));

    println!("{}", ansi::RESET);

    Ok(())
  }

  // Render tab navigation bar showing all available views

}
