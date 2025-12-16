//! Main MITM Shell application

use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use super::input::{key_to_action, Action, InputReader, Key, RawMode};
use super::interceptor::{ShellEvent, ShellInterceptor};
use super::state::{DetailTab, HttpExchange, RequestFilter, ShellState, ShellViewMode};
use super::ui::ShellUI;
use crate::crypto::certs::ca::CertificateAuthority;
use crate::modules::proxy::mitm::{MitmConfig, MitmProxy};

/// MITM Shell application
pub struct MitmShell {
    state: ShellState,
    ui: ShellUI,
    proxy_addr: SocketAddr,
    event_rx: Receiver<ShellEvent>,
    event_tx: Sender<ShellEvent>,
    running: bool,
    _raw_mode: RawMode,
}

impl MitmShell {
    /// Create new MITM shell
    pub fn new(proxy_addr: SocketAddr) -> io::Result<Self> {
        let (event_tx, event_rx) = mpsc::channel();
        let raw_mode = RawMode::enable()?;

        Ok(Self {
            state: ShellState::new(),
            ui: ShellUI::new()?,
            proxy_addr,
            event_rx,
            event_tx,
            running: false,
            _raw_mode: raw_mode,
        })
    }

    /// Get event sender for the interceptor
    pub fn event_sender(&self) -> Sender<ShellEvent> {
        self.event_tx.clone()
    }

    /// Run the shell with proxy
    pub fn run_with_proxy(mut self, ca: CertificateAuthority) -> io::Result<()> {
        // Create interceptor
        let interceptor = ShellInterceptor::new(self.event_tx.clone());

        // Create proxy config with our interceptor
        let config = MitmConfig::new(self.proxy_addr, ca)
            .with_timeout(Duration::from_secs(30))
            .with_interceptor(interceptor);

        // Start proxy in background thread
        let proxy = MitmProxy::new(config);
        let _proxy_addr = self.proxy_addr;

        thread::spawn(move || {
            if let Err(e) = proxy.run() {
                eprintln!("Proxy error: {}", e);
            }
        });

        // Small delay to let proxy start
        thread::sleep(Duration::from_millis(100));

        // Run the UI
        self.run()
    }

    /// Run the shell (main loop)
    pub fn run(&mut self) -> io::Result<()> {
        self.running = true;
        self.ui.enter()?;

        let mut input = InputReader::new();
        let mut last_render = Instant::now();
        let render_interval = Duration::from_millis(50);

        while self.running {
            // Process incoming events from proxy
            self.process_events();

            // Handle input
            if let Ok(Some(key)) = input.read_key() {
                self.handle_key(key);
            }

            // Render at fixed interval
            if last_render.elapsed() >= render_interval {
                self.ui
                    .render(&mut self.state, &self.proxy_addr.to_string())?;
                last_render = Instant::now();
            }

            // Small sleep to prevent busy loop
            thread::sleep(Duration::from_millis(10));
        }

        self.ui.exit()?;
        Ok(())
    }

    /// Process events from the interceptor
    fn process_events(&mut self) {
        loop {
            match self.event_rx.try_recv() {
                Ok(event) => self.handle_event(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.running = false;
                    break;
                }
            }
        }
    }

    /// Handle a shell event
    fn handle_event(&mut self, event: ShellEvent) {
        match event {
            ShellEvent::NewRequest {
                id,
                source_ip,
                method,
                host,
                path,
                version,
                headers,
                body,
            } => {
                let exchange = HttpExchange::from_request(
                    id, &source_ip, &method, &host, &path, &version, headers, body,
                );
                self.state.add_exchange(exchange);
            }
            ShellEvent::ResponseReceived {
                id,
                status_code,
                status_text,
                headers,
                body,
                duration_ms,
            } => {
                self.state.update_response(
                    id,
                    status_code,
                    &status_text,
                    headers,
                    body,
                    duration_ms,
                );
            }
            ShellEvent::RequestDropped { id } => {
                if let Some(ex) = self.state.exchanges.iter_mut().find(|e| e.id == id) {
                    ex.was_dropped = true;
                }
            }
        }
    }

    /// Handle a key press
    fn handle_key(&mut self, key: Key) {
        let in_text_mode = matches!(
            self.state.view_mode,
            ShellViewMode::Command | ShellViewMode::Search
        );

        let action = key_to_action(key, in_text_mode);
        self.handle_action(action);
    }

    /// Handle an action
    fn handle_action(&mut self, action: Action) {
        match action {
            Action::Quit => {
                self.running = false;
            }
            Action::SelectPrev => {
                self.state.select_prev();
            }
            Action::SelectNext => {
                let visible = self.ui.visible_list_rows();
                self.state.select_next(visible);
            }
            Action::PageUp => {
                let visible = self.ui.visible_list_rows();
                for _ in 0..visible {
                    self.state.select_prev();
                }
            }
            Action::PageDown => {
                let visible = self.ui.visible_list_rows();
                for _ in 0..visible {
                    self.state.select_next(visible);
                }
            }
            Action::GoFirst => {
                self.state.selected_idx = 0;
                self.state.scroll_offset = 0;
            }
            Action::GoLast => {
                let count = self.state.filtered_count();
                if count > 0 {
                    self.state.selected_idx = count - 1;
                    let visible = self.ui.visible_list_rows();
                    if count > visible {
                        self.state.scroll_offset = count - visible;
                    }
                }
            }
            Action::ToggleDetails => {
                self.state.view_mode = match self.state.view_mode {
                    ShellViewMode::Details => ShellViewMode::List,
                    _ => ShellViewMode::Details,
                };
            }
            Action::ToggleIntercept => {
                self.state.intercept_enabled = !self.state.intercept_enabled;
            }
            Action::NextTab => {
                self.state.detail_tab = match self.state.detail_tab {
                    DetailTab::Headers => DetailTab::Body,
                    DetailTab::Body => DetailTab::Raw,
                    DetailTab::Raw => DetailTab::Headers,
                };
            }
            Action::PrevTab => {
                self.state.detail_tab = match self.state.detail_tab {
                    DetailTab::Headers => DetailTab::Raw,
                    DetailTab::Body => DetailTab::Headers,
                    DetailTab::Raw => DetailTab::Body,
                };
            }
            Action::EnterCommand => {
                self.state.view_mode = ShellViewMode::Command;
                self.state.command_buffer.clear();
            }
            Action::EnterSearch => {
                self.state.view_mode = ShellViewMode::Search;
                self.state.search_buffer.clear();
            }
            Action::TextInput(c) => match self.state.view_mode {
                ShellViewMode::Command => self.state.command_buffer.push(c),
                ShellViewMode::Search => self.state.search_buffer.push(c),
                _ => {}
            },
            Action::TextBackspace => match self.state.view_mode {
                ShellViewMode::Command => {
                    self.state.command_buffer.pop();
                }
                ShellViewMode::Search => {
                    self.state.search_buffer.pop();
                }
                _ => {}
            },
            Action::TextSubmit => match self.state.view_mode {
                ShellViewMode::Command => {
                    self.execute_command();
                    self.state.view_mode = ShellViewMode::List;
                }
                ShellViewMode::Search => {
                    self.execute_search();
                    self.state.view_mode = ShellViewMode::List;
                }
                _ => {}
            },
            Action::TextCancel => {
                self.state.view_mode = ShellViewMode::List;
                self.state.command_buffer.clear();
                self.state.search_buffer.clear();
            }
            Action::ClearHistory => {
                self.state.clear();
            }
            Action::ShowHelp => {
                self.state.view_mode = ShellViewMode::Help;
            }
            Action::EditRequest => {
                // TODO: Open editor for selected request
            }
            Action::ReplayRequest => {
                // TODO: Replay selected request
            }
            Action::ForwardRequest => {
                // TODO: Forward intercepted request
            }
            Action::DropRequest => {
                // TODO: Drop intercepted request
            }
            Action::None => {}
        }
    }

    /// Execute a command (from : mode)
    fn execute_command(&mut self) {
        let cmd = self.state.command_buffer.trim().to_string();
        let parts: Vec<&str> = cmd.split_whitespace().collect();

        if parts.is_empty() {
            return;
        }

        match parts[0] {
            "filter" | "f" => {
                if parts.len() > 1 {
                    if parts[1] == "clear" {
                        self.state.filter.clear();
                    } else {
                        let filter_str = parts[1..].join(" ");
                        self.state.set_filter(RequestFilter::parse(&filter_str));
                    }
                }
            }
            "clear" | "c" => {
                self.state.clear();
            }
            "autoscroll" | "scroll" => {
                if parts.len() > 1 {
                    self.state.auto_scroll = parts[1] == "on" || parts[1] == "true";
                } else {
                    self.state.auto_scroll = !self.state.auto_scroll;
                }
            }
            "intercept" | "i" => {
                if parts.len() > 1 {
                    self.state.intercept_enabled = parts[1] == "on" || parts[1] == "true";
                } else {
                    self.state.intercept_enabled = !self.state.intercept_enabled;
                }
            }
            "q" | "quit" | "exit" => {
                self.running = false;
            }
            _ => {}
        }
    }

    /// Execute a search
    fn execute_search(&mut self) {
        let search = self.state.search_buffer.trim().to_lowercase();
        if search.is_empty() {
            return;
        }

        // Find next matching exchange
        let start = self.state.selected_idx + 1;
        let count = self.state.exchanges.len();

        for i in 0..count {
            let idx = (start + i) % count;
            let ex = &self.state.exchanges[idx];

            // Search in method, host, path, and body
            if ex.method.to_lowercase().contains(&search)
                || ex.host.to_lowercase().contains(&search)
                || ex.path.to_lowercase().contains(&search)
                || String::from_utf8_lossy(&ex.request_body)
                    .to_lowercase()
                    .contains(&search)
                || String::from_utf8_lossy(&ex.response_body)
                    .to_lowercase()
                    .contains(&search)
            {
                self.state.selected_idx = idx;
                // Adjust scroll to show selection
                let visible = self.ui.visible_list_rows();
                if idx < self.state.scroll_offset {
                    self.state.scroll_offset = idx;
                } else if idx >= self.state.scroll_offset + visible {
                    self.state.scroll_offset = idx - visible + 1;
                }
                break;
            }
        }
    }
}
