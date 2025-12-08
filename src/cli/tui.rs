// TUI - Full-screen Text User Interface (k9s-style)
// ZERO external dependencies - pure Rust std only

use crate::modules::web::dom::Document;
use crate::storage::session::SessionFile;
use std::collections::HashMap;
use std::io::{self, Read, Write, BufRead, BufReader};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

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
            ViewMode::HTTP => ViewMode::Activity,
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
            ViewMode::Activity => ViewMode::HTTP,
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
    network_data: Vec<TableRow>, // Network devices (NEW!)
    ports_data: Vec<TableRow>,
    subdomains_data: Vec<TableRow>,
    whois_data: Vec<(String, String)>,    // Key-value pairs
    certs_data: Vec<(String, String)>,    // Key-value pairs
    sessions_data: Vec<(String, String)>, // Key-value pairs
    scan_activity: Vec<String>,           // Real-time scan logs
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
    current_doc: Option<Document>,      // Currently loaded HTML document
    current_doc_url: String,            // URL of the current document
    last_selector_results: Vec<usize>,  // Element indices from last $ command
    // Event channel
    tx: Sender<Event>,
    rx: Receiver<Event>,
}

impl TuiApp {
    /// Create new TUI application
    pub fn new(target: String) -> Result<Self, String> {
        let (session_path, db_path) = if target.ends_with(SessionFile::EXTENSION) {
            let trimmed = target.trim_end_matches(SessionFile::EXTENSION).to_string();
            (target.clone(), format!("{}.rdb", trimmed))
        } else if target.ends_with(".rdb") {
            let trimmed = target.trim_end_matches(".rdb").to_string();
            (
                format!("{}{}", trimmed, SessionFile::EXTENSION),
                target.clone(),
            )
        } else {
            let identifier = SessionFile::identifier_for(&target);
            (
                format!("{}{}", identifier, SessionFile::EXTENSION),
                format!("{}.rdb", identifier),
            )
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
            scan_activity: Vec::new(),
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
        let target = self.target.clone();

        thread::spawn(move || {
            // Determine executable path
            let exe = std::env::current_exe().unwrap_or_else(|_| "rb".into());
            
            tx.send(Event::Log(format!("Running: rb {}", args.join(" ")))).ok();

            let mut child = ProcessCommand::new(exe)
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
                    tx.send(Event::Log(format!("Failed to start command: {}", e))).ok();
                }
            }
        });

        Ok(())
    }

    /// Load session from disk
    fn load_session(&mut self) -> Result<(), String> {
        if std::path::Path::new(&self.session_path).exists() {
            self.metadata = Some(
                crate::storage::session::SessionFile::load_metadata_from_path(&self.session_path)?,
            );

            // Load session metadata as key-value pairs
            if let Some(ref meta) = self.metadata {
                self.sessions_data.clear();
                self.sessions_data
                    .push(("Target".to_string(), meta.target.clone()));
                self.sessions_data
                    .push(("Identifier".to_string(), meta.identifier.clone()));
                self.sessions_data
                    .push(("Command".to_string(), meta.command.clone()));
                self.sessions_data
                    .push(("Created At".to_string(), meta.created_at.to_string()));
                if meta.is_complete() {
                    self.sessions_data
                        .push(("Status".to_string(), "✓ Complete".to_string()));
                    if let Some(dur) = meta.duration_secs {
                        self.sessions_data
                            .push(("Duration".to_string(), format!("{:.2}s", dur)));
                    }
                } else {
                    self.sessions_data
                        .push(("Status".to_string(), "⚠ Incomplete".to_string()));
                }
                self.sessions_data
                    .push(("Age".to_string(), format!("{}s ago", meta.age_secs())));
            }
        }
        Ok(())
    }

    /// Load data from RedDb database
    fn load_database_data(&mut self) -> Result<(), String> {
        // Only load if database file exists
        if !std::path::Path::new(&self.db_path).exists() {
            self.scan_activity
                .push("No database found - run scans to populate".to_string());
            return Ok(());
        }

        // Detect legacy session stub accidentally saved with .rdb extension
        if let Ok(mut file) = std::fs::File::open(&self.db_path) {
            use std::io::Read;
            let mut prefix = [0u8; 24];
            let len = file.read(&mut prefix).unwrap_or(0);
            if len > 0 && prefix[..len].starts_with(b"# redblue session") {
                self.scan_activity
                    .push("Database stub found - run scans to generate binary data".to_string());
                return Ok(());
            }
        }

        // Open RedDb and load real data
        use crate::storage::RedDb;

        let mut db =
            RedDb::open(&self.db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        // Clear existing data
        self.network_data.clear();
        self.ports_data.clear();
        self.subdomains_data.clear();
        self.whois_data.clear();
        self.certs_data.clear();
        self.scan_activity.clear();

        // Load port scan data once and reuse for multiple views
        let port_scans = db
            .ports()
            .get_all()
            .map_err(|e| format!("Failed to load port scans: {}", e))?;

        self.network_data = Self::build_network_rows(&port_scans);

        for scan in &port_scans {
            let status_str = match scan.status {
                crate::storage::schema::PortStatus::Open => "Open",
                crate::storage::schema::PortStatus::Closed => "Closed",
                crate::storage::schema::PortStatus::Filtered => "Filtered",
                crate::storage::schema::PortStatus::OpenFiltered => "Open|Filtered",
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
            .subdomains()
            .get_all()
            .map_err(|e| format!("Failed to load subdomains: {}", e))?;

        for sub in subdomains {
            let ips_str = sub
                .ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            let source_str = match sub.source {
                crate::storage::schema::SubdomainSource::DnsBruteforce => "DNS",
                crate::storage::schema::SubdomainSource::CertTransparency => "CT",
                crate::storage::schema::SubdomainSource::SearchEngine => "Search",
                crate::storage::schema::SubdomainSource::WebCrawl => "Crawl",
            };

            self.subdomains_data.push(TableRow {
                module: sub.subdomain.clone(),
                status: source_str.to_string(),
                data: ips_str,
                timestamp: sub.timestamp as u64,
            });
        }

        self.scan_activity
            .push(format!("Loaded {} port scans", self.ports_data.len()));
        self.scan_activity
            .push(format!("Loaded {} subdomains", self.subdomains_data.len()));
        self.scan_activity
            .push("Database loaded successfully".to_string());
        self.scan_activity
            .push(format!("Database: {}", self.db_path));

        Ok(())
    }

    fn build_network_rows(port_scans: &[crate::storage::schema::PortScanRecord]) -> Vec<TableRow> {
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
                crate::storage::schema::PortStatus::Open => {
                    entry.open_ports.push(scan.port);
                }
                crate::storage::schema::PortStatus::Filtered
                | crate::storage::schema::PortStatus::OpenFiltered => {
                    entry.filtered_ports.push(scan.port);
                }
                crate::storage::schema::PortStatus::Closed => {
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
                        let mut seq = vec![ch];
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
                        let mut next = [0u8; 1];
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
        thread::spawn(move || {
            loop {
                tx_tick.send(Event::Tick).ok();
                thread::sleep(Duration::from_millis(100));
            }
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
                        Event::Tick => {},
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
                                b'A' => { tx.send(Event::Input(Key::Up)).ok(); continue; }
                                b'B' => { tx.send(Event::Input(Key::Down)).ok(); continue; }
                                b'C' => { tx.send(Event::Input(Key::Right)).ok(); continue; }
                                b'D' => { tx.send(Event::Input(Key::Left)).ok(); continue; }
                                b'H' => { tx.send(Event::Input(Key::Home)).ok(); continue; }
                                b'F' => { tx.send(Event::Input(Key::End)).ok(); continue; }
                                b'5' => { // PageUp/Down usually ~
                                    let mut t = [0u8; 1];
                                    if stdin.read_exact(&mut t).is_ok() && t[0] == b'~' {
                                        tx.send(Event::Input(Key::PageUp)).ok(); continue;
                                    }
                                }
                                b'6' => { 
                                    let mut t = [0u8; 1];
                                    if stdin.read_exact(&mut t).is_ok() && t[0] == b'~' {
                                        tx.send(Event::Input(Key::PageDown)).ok(); continue;
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

    /// Render tab navigation bar showing all available views
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
            (0, "Activity", ViewMode::Activity), // Last tab
        ];

        print!("{}", ansi::move_to(2, 1));

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
            | ViewMode::HTTP => self.render_table(content_start_row, available_rows)?,
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

        let mut row = start_row + 1;

        if rows.is_empty() {
            println!(
                "{}{}{}",
                ansi::move_to(row + 1, 4),
                ansi::DIM,
                "No results found"
            );

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

        for (idx, table_row) in rows[self.scroll_offset..end_idx].iter().enumerate() {
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
            row += 1;
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
            println!(
                "{}{}{}",
                ansi::move_to(row, 4),
                ansi::DIM,
                "No data available"
            );
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

    /// Render scan activity (for Normal, Stealth, Aggressive modes)
    fn render_scan_activity(&self, start_row: u16, available_rows: usize) -> Result<(), String> {
        let mut row = start_row;

        // Header
        println!("{}{}{}", ansi::move_to(row, 2), ansi::BOLD, ansi::CYAN);
        println!("Scan Activity - {} Mode", self.mode.title());
        println!("{}", ansi::RESET);
        row += 2;

        if self.scan_activity.is_empty() {
            println!(
                "{}{}{}",
                ansi::move_to(row, 4),
                ansi::DIM,
                "No activity logged"
            );
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
                self.scan_activity.push("Starting network discovery scan...".to_string());
                self.execute_network_scan()?;
            }
            ViewMode::Ports => {
                self.scan_activity.push("Starting port scan...".to_string());
                self.execute_port_scan()?;
            }
            ViewMode::Subdomains => {
                self.scan_activity.push("Starting subdomain enumeration...".to_string());
                self.execute_subdomain_scan()?;
            }
            ViewMode::Overview => {
                self.scan_activity.push("Starting WHOIS lookup...".to_string());
                self.execute_whois_lookup()?;
            }
            _ => {
                self.scan_activity.push("No scan action available for this view".to_string());
            }
        }
        Ok(())
    }

    /// Handle add action (view-specific)
    fn handle_add_action(&mut self) -> Result<(), String> {
        match self.mode {
            ViewMode::Network => {
                // TODO: Open input dialog to add device manually
                self.scan_activity
                    .push("Manual device add: not yet implemented".to_string());
                self.scan_activity.push("Feature coming soon!".to_string());
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
                    self.scan_activity
                        .push(format!("Removed device: {}", removed.module));
                    if self.selected_row > 0 {
                        self.selected_row -= 1;
                    }
                }
            }
            ViewMode::Ports => {
                if !self.ports_data.is_empty() && self.selected_row < self.ports_data.len() {
                    let removed = self.ports_data.remove(self.selected_row);
                    self.scan_activity
                        .push(format!("Removed port: {}", removed.module));
                    if self.selected_row > 0 {
                        self.selected_row -= 1;
                    }
                }
            }
            ViewMode::Subdomains => {
                if !self.subdomains_data.is_empty()
                    && self.selected_row < self.subdomains_data.len()
                {
                    let removed = self.subdomains_data.remove(self.selected_row);
                    self.scan_activity
                        .push(format!("Removed subdomain: {}", removed.module));
                    if self.selected_row > 0 {
                        self.selected_row -= 1;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle Enter key (view-specific)
    fn handle_enter_action(&mut self) -> Result<(), String> {
        match self.mode {
            ViewMode::Network => {
                // Enter on a network device = switch to Ports view for that IP
                if !self.network_data.is_empty() && self.selected_row < self.network_data.len() {
                    let device_ip = &self.network_data[self.selected_row].module;
                    self.scan_activity
                        .push(format!("Starting port scan on {}...", device_ip));

                    // TODO: Actually trigger port scan
                    // For now, just switch to Ports view
                    self.mode = ViewMode::Ports;
                    self.scroll_offset = 0;
                    self.selected_row = 0;
                }
            }
            ViewMode::Ports | ViewMode::Subdomains => {
                // TODO: Show details view
                self.scan_activity
                    .push("Details view not yet implemented".to_string());
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
                let vars: Vec<(String, String)> = self.session_variables
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if vars.is_empty() {
                    self.scan_activity.push("No session variables set".to_string());
                } else {
                    self.scan_activity.push(format!("Session variables ({}):", vars.len()));
                    for (name, value) in vars {
                        self.scan_activity.push(format!("  ${} = {}", name, value));
                    }
                }
                return Ok(());
            }
            "run" => {
                if parts.len() < 2 {
                    return Err("Usage: run <preset>".to_string());
                }
                self.run_scan(parts[1])?;
            }
            "exec" => {
                if parts.len() < 2 {
                    return Err("Usage: exec <command> [args...]".to_string());
                }
                // Reconstruct arguments properly handling quotes? 
                // For now simple split is enough for basic commands
                let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
                self.scan_activity.push(format!("Executing: rb {}", args.join(" ")));
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
                        self.scan_activity
                            .push(format!("Command: Scanning ports on {}", self.target));
                        self.execute_port_scan()?;
                    }
                    "subdomains" => {
                        self.scan_activity
                            .push(format!("Command: Scanning subdomains for {}", self.target));
                        self.execute_subdomain_scan()?;
                    }
                    "network" => {
                        self.scan_activity
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
                            self.scan_activity
                                .push(format!("Command: Subdomain recon for {}", self.target));
                            self.execute_subdomain_scan()?;
                        }
                        "whois" => {
                            self.scan_activity
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
            "target" => {
                // Change target context dynamically
                if parts.len() < 2 {
                    // Show current target
                    self.scan_activity.push(format!("Current target: {}", self.target));
                    return Ok(());
                }

                let new_target = parts[1..].join(" ");
                self.change_target(&new_target)?;
                return Ok(());
            }
            "help" | "?" => {
                self.scan_activity.push("Available commands:".to_string());
                self.scan_activity.push("  Target:".to_string());
                self.scan_activity.push("    target <host>  - Change target context".to_string());
                self.scan_activity.push("    target         - Show current target".to_string());
                self.scan_activity.push("  Variables:".to_string());
                self.scan_activity.push("    set VAR=value  - Set a session variable".to_string());
                self.scan_activity.push("    get VAR        - Get variable value".to_string());
                self.scan_activity.push("    unset VAR      - Remove variable".to_string());
                self.scan_activity.push("    vars           - List all variables".to_string());
                self.scan_activity.push("  Scans:".to_string());
                self.scan_activity.push("    scan ports     - Port scan on target".to_string());
                self.scan_activity.push("    scan subdomains - Subdomain enumeration".to_string());
                self.scan_activity.push("    scan network   - Network discovery".to_string());
                self.scan_activity.push("  Recon:".to_string());
                self.scan_activity.push("    recon domain whois      - WHOIS lookup".to_string());
                self.scan_activity.push("    recon domain subdomains - Subdomain enum".to_string());
                self.scan_activity.push("  Scraping:".to_string());
                self.scan_activity.push("    scrap <url>       - Fetch and parse HTML".to_string());
                self.scan_activity.push("    $ <selector>      - Query CSS selector".to_string());
                self.scan_activity.push("    $text             - Extract text from results".to_string());
                self.scan_activity.push("    $attr <name>      - Extract attribute".to_string());
                self.scan_activity.push("    $html             - Extract inner HTML".to_string());
                self.scan_activity.push("    $links            - Extract all links".to_string());
                self.scan_activity.push("    $images           - Extract all images".to_string());
                self.scan_activity.push("    $forms            - Extract all forms".to_string());
                self.scan_activity.push("    $meta             - Extract meta tags".to_string());
                self.scan_activity.push("    $og               - Extract Open Graph".to_string());
                self.scan_activity.push("    $json-ld          - Extract JSON-LD".to_string());
                self.scan_activity.push("    $scripts          - Extract scripts".to_string());
                self.scan_activity.push("    $css              - Extract stylesheets".to_string());
                self.scan_activity.push("    $table            - Extract tables".to_string());
                self.scan_activity.push("  Other:".to_string());
                self.scan_activity.push("    run <preset>   - Run scan preset".to_string());
                self.scan_activity.push("    reload         - Reload session".to_string());
                self.scan_activity.push("    quit           - Exit TUI".to_string());
                self.scan_activity.push("  Note: Variables are expanded in commands ($VAR or ${VAR})".to_string());
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

    // ========== Dynamic Target ==========

    /// Change the target context dynamically
    fn change_target(&mut self, new_target: &str) -> Result<(), String> {
        let old_target = self.target.clone();

        // Update target and associated paths
        self.target = new_target.to_string();

        // Recalculate session and database paths
        let identifier = SessionFile::identifier_for(new_target);
        self.session_path = format!("{}{}", identifier, SessionFile::EXTENSION);
        self.db_path = format!("{}.rdb", identifier);

        // Log the change
        self.scan_activity.push(format!(
            "Target changed: {} → {}",
            old_target, new_target
        ));

        // Clear existing data for fresh start with new target
        self.network_data.clear();
        self.ports_data.clear();
        self.subdomains_data.clear();
        self.whois_data.clear();
        self.certs_data.clear();
        self.metadata = None;

        // Try to load existing session/database for the new target
        if std::path::Path::new(&self.session_path).exists() {
            self.scan_activity.push(format!(
                "Found existing session: {}",
                self.session_path
            ));
            let _ = self.load_session();
        }

        if std::path::Path::new(&self.db_path).exists() {
            self.scan_activity.push(format!(
                "Found existing database: {}",
                self.db_path
            ));
            let _ = self.load_database_data();
        } else {
            self.scan_activity.push("No existing data for this target".to_string());
        }

        // Also set target as a session variable for easy reference
        self.session_variables.insert("TARGET".to_string(), new_target.to_string());

        Ok(())
    }

    // ========== Session Variables ==========

    /// Set a session variable
    fn set_variable(&mut self, name: &str, value: &str) {
        self.session_variables.insert(name.to_string(), value.to_string());
        self.scan_activity.push(format!("Set ${} = {}", name, value));
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
}

#[cfg(test)]
mod tests {
    use super::TuiApp;
    use crate::storage::schema::{PortScanRecord, PortStatus};
    use std::net::{IpAddr, Ipv4Addr};

    fn port_scan(ip: [u8; 4], port: u16, status: PortStatus, ts: u32) -> PortScanRecord {
        PortScanRecord {
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            port,
            status,
            service_id: 0,
            timestamp: ts,
        }
    }

    #[test]
    fn build_network_rows_groups_by_host() {
        let scans = vec![
            port_scan([10, 0, 0, 1], 22, PortStatus::Open, 100),
            port_scan([10, 0, 0, 1], 80, PortStatus::Open, 105),
            port_scan([10, 0, 0, 1], 443, PortStatus::Filtered, 110),
            port_scan([10, 0, 0, 2], 8080, PortStatus::Closed, 200),
        ];

        let rows = TuiApp::build_network_rows(&scans);
        assert_eq!(rows.len(), 2);

        let host1 = rows
            .iter()
            .find(|row| row.module == "10.0.0.1")
            .expect("missing host 10.0.0.1");

        assert_eq!(host1.status, "Online");
        assert!(host1.data.contains("open 22,80"), "{}", host1.data);
        assert!(host1.data.contains("filtered 443"), "{}", host1.data);
        assert_eq!(host1.timestamp, 110);

        let host2 = rows
            .iter()
            .find(|row| row.module == "10.0.0.2")
            .expect("missing host 10.0.0.2");
        assert_eq!(host2.status, "Closed");
        assert!(host2.data.contains("closed 1"), "{}", host2.data);
        assert_eq!(host2.timestamp, 200);
    }

    #[test]
    fn format_port_sample_limits_length() {
        let small = vec![21u16, 22, 23];
        assert_eq!(TuiApp::format_port_sample(&small), "21,22,23");

        let large = vec![1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(TuiApp::format_port_sample(&large), "1,2,3,4,5,6(+2)");
    }
}

/// Truncate string to max length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Helper trait for session file
trait SessionFileExt {
    fn load_metadata_from_path(
        path: &str,
    ) -> Result<crate::storage::session::SessionMetadata, String>;
}

impl SessionFileExt for crate::storage::session::SessionFile {
    fn load_metadata_from_path(
        path: &str,
    ) -> Result<crate::storage::session::SessionMetadata, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read session: {}", e))?;
        Self::parse_metadata(&content)
    }
}

/// Drop implementation to ensure terminal cleanup even on panic
impl Drop for TuiApp {
    fn drop(&mut self) {
        // CRITICAL: Always restore terminal state when TUI is dropped
        // This ensures cleanup happens even if there's a panic or early exit
        let _ = self.exit_alternate_screen();
        let _ = self.disable_raw_mode();

        // Extra safety: print a newline to ensure clean exit
        println!();
    }
}

/// Start fullscreen TUI
pub fn start_tui(target: String) -> Result<(), String> {
    let mut app = TuiApp::new(target)?;
    app.run()
}
