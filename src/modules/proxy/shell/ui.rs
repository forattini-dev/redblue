//! UI rendering for the MITM shell - k9s-style split panes

use super::state::{DetailTab, HttpExchange, ShellState, ShellViewMode};
use std::io::{self, Write};

/// Terminal size
#[derive(Debug, Clone, Copy)]
pub struct TermSize {
    pub rows: u16,
    pub cols: u16,
}

impl TermSize {
    pub fn get() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = io::stdout().as_raw_fd();

            #[repr(C)]
            struct WinSize {
                ws_row: u16,
                ws_col: u16,
                ws_xpixel: u16,
                ws_ypixel: u16,
            }

            extern "C" {
                fn ioctl(fd: i32, request: u64, ...) -> i32;
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

        Ok(TermSize { rows: 24, cols: 80 })
    }
}

/// ANSI escape codes
pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const REVERSE: &str = "\x1b[7m";

    pub const BLACK: &str = "\x1b[30m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    pub const GRAY: &str = "\x1b[90m";

    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";

    pub const BG_BLACK: &str = "\x1b[40m";
    pub const BG_BLUE: &str = "\x1b[44m";
    pub const BG_CYAN: &str = "\x1b[46m";
    pub const BG_DARK_GRAY: &str = "\x1b[100m";

    pub const HIDE_CURSOR: &str = "\x1b[?25l";
    pub const SHOW_CURSOR: &str = "\x1b[?25h";
    pub const CLEAR_SCREEN: &str = "\x1b[2J";
    pub const MOVE_HOME: &str = "\x1b[H";
    pub const CLEAR_LINE: &str = "\x1b[K";
    pub const ALTERNATE_SCREEN: &str = "\x1b[?1049h";
    pub const MAIN_SCREEN: &str = "\x1b[?1049l";

    pub fn move_to(row: u16, col: u16) -> String {
        format!("\x1b[{};{}H", row, col)
    }
}

/// Box drawing characters
pub mod box_chars {
    pub const HORIZONTAL: char = '─';
    pub const VERTICAL: char = '│';
    pub const TOP_LEFT: char = '┌';
    pub const TOP_RIGHT: char = '┐';
    pub const BOTTOM_LEFT: char = '└';
    pub const BOTTOM_RIGHT: char = '┘';
    pub const T_DOWN: char = '┬';
    pub const T_UP: char = '┴';
    pub const T_RIGHT: char = '├';
    pub const T_LEFT: char = '┤';
    pub const CROSS: char = '┼';
}

/// UI renderer for the MITM shell
pub struct ShellUI {
    size: TermSize,
    /// Height of the request list (top pane)
    list_height: u16,
    /// Height of the detail pane (bottom)
    detail_height: u16,
}

impl ShellUI {
    pub fn new() -> io::Result<Self> {
        let size = TermSize::get()?;
        let list_height = (size.rows as f32 * 0.5) as u16;
        let detail_height = size.rows - list_height - 4; // 4 for header, footer, separators

        Ok(Self {
            size,
            list_height,
            detail_height,
        })
    }

    /// Get visible row count for the list
    pub fn visible_list_rows(&self) -> usize {
        self.list_height.saturating_sub(2) as usize // -2 for header row and border
    }

    /// Refresh terminal size
    pub fn refresh_size(&mut self) -> io::Result<()> {
        self.size = TermSize::get()?;
        self.list_height = (self.size.rows as f32 * 0.5) as u16;
        self.detail_height = self.size.rows - self.list_height - 4;
        Ok(())
    }

    /// Enter alternate screen and hide cursor
    pub fn enter(&self) -> io::Result<()> {
        let mut stdout = io::stdout();
        write!(
            stdout,
            "{}{}{}",
            ansi::ALTERNATE_SCREEN,
            ansi::HIDE_CURSOR,
            ansi::CLEAR_SCREEN
        )?;
        stdout.flush()
    }

    /// Exit alternate screen and show cursor
    pub fn exit(&self) -> io::Result<()> {
        let mut stdout = io::stdout();
        write!(stdout, "{}{}", ansi::SHOW_CURSOR, ansi::MAIN_SCREEN)?;
        stdout.flush()
    }

    /// Render the full UI
    pub fn render(&self, state: &mut ShellState, proxy_addr: &str) -> io::Result<()> {
        let mut stdout = io::stdout();
        let mut buffer = String::with_capacity(8192);

        // Move to home
        buffer.push_str(ansi::MOVE_HOME);

        // 1. Render header bar
        self.render_header(&mut buffer, state, proxy_addr);

        // 2. Render request list
        self.render_list(&mut buffer, state);

        // 3. Render separator
        self.render_separator(&mut buffer, state);

        // 4. Render detail pane
        self.render_detail(&mut buffer, state);

        // 5. Render footer/status bar
        self.render_footer(&mut buffer, state);

        write!(stdout, "{}", buffer)?;
        stdout.flush()
    }

    fn render_header(&self, buf: &mut String, state: &ShellState, proxy_addr: &str) {
        // Header bar with status
        buf.push_str(ansi::BG_DARK_GRAY);
        buf.push_str(ansi::BRIGHT_CYAN);
        buf.push_str(ansi::BOLD);

        let intercept_status = if state.intercept_enabled {
            format!("{}INTERCEPT: ON{}", ansi::BRIGHT_GREEN, ansi::BRIGHT_CYAN)
        } else {
            format!("{}INTERCEPT: OFF{}", ansi::GRAY, ansi::BRIGHT_CYAN)
        };

        let filter_display = state.filter.display();
        let count = format!("Requests: {}", state.exchanges.len());

        let header = format!(
            " MITM Shell {} {} {} {} {} Filter: {} ",
            ansi::GRAY,
            ansi::BRIGHT_CYAN,
            proxy_addr,
            ansi::GRAY,
            ansi::BRIGHT_CYAN,
            filter_display
        );

        // Center and pad
        let padded = format!("{:<width$}", header, width = self.size.cols as usize);
        buf.push_str(&padded[..(self.size.cols as usize).min(padded.len())]);
        buf.push_str(ansi::RESET);
        buf.push('\n');
    }

    fn render_list(&self, buf: &mut String, state: &mut ShellState) {
        // Column headers
        buf.push_str(ansi::BOLD);
        buf.push_str(ansi::CYAN);
        let header = format!(
            " {:>4} {:^15} {:>6} {:^20} {:^24} {:>6} {:>7}",
            "#", "Source", "Method", "Host", "Path", "Status", "Time"
        );
        buf.push_str(&header[..(self.size.cols as usize).min(header.len())]);
        buf.push_str(ansi::CLEAR_LINE);
        buf.push_str(ansi::RESET);
        buf.push('\n');

        // Separator
        buf.push_str(ansi::DIM);
        for _ in 0..self.size.cols {
            buf.push(box_chars::HORIZONTAL);
        }
        buf.push_str(ansi::RESET);
        buf.push('\n');

        // Get filtered exchanges
        let visible_rows = self.visible_list_rows();
        let scroll_offset = state.scroll_offset;
        let selected = state.selected_idx;

        // Clone the data we need to avoid borrow issues
        let filtered: Vec<_> = state
            .filtered_exchanges()
            .into_iter()
            .skip(scroll_offset)
            .take(visible_rows)
            .map(|e| {
                (
                    e.id,
                    e.source_ip.clone(),
                    e.method.clone(),
                    e.host.clone(),
                    e.path.clone(),
                    e.status_code,
                    e.duration_ms,
                    e.was_dropped,
                )
            })
            .collect();

        for (row_idx, (id, source_ip, method, host, path, status_code, duration_ms, was_dropped)) in
            filtered.iter().enumerate()
        {
            let actual_idx = scroll_offset + row_idx;
            let is_selected = actual_idx == selected;

            if is_selected {
                buf.push_str(ansi::REVERSE);
                buf.push_str(ansi::BOLD);
            }

            // Method color
            let method_color = match method.as_str() {
                "GET" => ansi::GREEN,
                "POST" => ansi::YELLOW,
                "PUT" => ansi::BLUE,
                "DELETE" => ansi::RED,
                "PATCH" => ansi::MAGENTA,
                _ => ansi::WHITE,
            };

            // Status color
            let (status_str, status_color) = if *was_dropped {
                ("DROP".to_string(), ansi::RED)
            } else {
                match status_code {
                    Some(code) if *code >= 500 => (code.to_string(), ansi::RED),
                    Some(code) if *code >= 400 => (code.to_string(), ansi::YELLOW),
                    Some(code) if *code >= 300 => (code.to_string(), ansi::CYAN),
                    Some(code) if *code >= 200 => (code.to_string(), ansi::GREEN),
                    Some(code) => (code.to_string(), ansi::WHITE),
                    None => ("...".to_string(), ansi::GRAY),
                }
            };

            // Duration
            let duration_str = match duration_ms {
                Some(ms) if *ms < 1000 => format!("{}ms", ms),
                Some(ms) => format!("{:.1}s", *ms as f64 / 1000.0),
                None => "-".to_string(),
            };

            // Truncate long values - extract just IP from socket addr if possible
            let source_trunc = source_ip.split(':').next().unwrap_or(source_ip);
            let source_trunc = truncate(source_trunc, 15);
            let host_trunc = truncate(&host, 20);
            let path_trunc = truncate(&path, 24);

            let line = format!(
                " {:>4} {:^15} {}{:>6}{} {:^20} {:^24} {}{:>6}{} {:>7}",
                id,
                source_trunc,
                method_color,
                method,
                ansi::RESET,
                host_trunc,
                path_trunc,
                status_color,
                status_str,
                ansi::RESET,
                duration_str
            );

            if is_selected {
                buf.push_str(&format!("{}{}", ansi::REVERSE, ansi::BOLD));
            }

            buf.push_str(&line);
            buf.push_str(ansi::CLEAR_LINE);
            buf.push_str(ansi::RESET);
            buf.push('\n');
        }

        // Fill remaining rows with empty lines
        let remaining = visible_rows.saturating_sub(filtered.len());
        for _ in 0..remaining {
            buf.push_str(ansi::CLEAR_LINE);
            buf.push('\n');
        }
    }

    fn render_separator(&self, buf: &mut String, state: &ShellState) {
        buf.push_str(ansi::DIM);
        buf.push(box_chars::T_RIGHT);

        // Show detail tab indicator
        let tabs = format!(
            " [{}Headers{}] [{}Body{}] [{}Raw{}] ",
            if state.detail_tab == DetailTab::Headers {
                ansi::BOLD
            } else {
                ""
            },
            ansi::RESET,
            if state.detail_tab == DetailTab::Body {
                ansi::BOLD
            } else {
                ""
            },
            ansi::RESET,
            if state.detail_tab == DetailTab::Raw {
                ansi::BOLD
            } else {
                ""
            },
            ansi::RESET,
        );
        buf.push_str(&tabs);

        for _ in (tabs.len() - 30)..self.size.cols as usize - 1 {
            buf.push(box_chars::HORIZONTAL);
        }
        buf.push(box_chars::T_LEFT);
        buf.push_str(ansi::RESET);
        buf.push('\n');
    }

    fn render_detail(&self, buf: &mut String, state: &mut ShellState) {
        // Copy detail_tab first to avoid borrow issues
        let tab = state.detail_tab;
        let exchange = state.selected_exchange();

        if let Some(ex) = exchange {
            match tab {
                DetailTab::Headers => self.render_headers(buf, ex),
                DetailTab::Body => self.render_body(buf, ex),
                DetailTab::Raw => self.render_raw(buf, ex),
            }
        } else {
            // No selection
            buf.push_str(ansi::DIM);
            buf.push_str("  No request selected");
            buf.push_str(ansi::CLEAR_LINE);
            buf.push_str(ansi::RESET);
            buf.push('\n');

            for _ in 1..self.detail_height {
                buf.push_str(ansi::CLEAR_LINE);
                buf.push('\n');
            }
        }
    }

    fn render_headers(&self, buf: &mut String, ex: &HttpExchange) {
        let mut lines_used = 0;

        // Request info
        buf.push_str(ansi::BOLD);
        buf.push_str(ansi::CYAN);
        buf.push_str(&format!(
            "  Request: {} {} {}",
            ex.method, ex.path, ex.version
        ));
        buf.push_str(ansi::CLEAR_LINE);
        buf.push_str(ansi::RESET);
        buf.push('\n');
        lines_used += 1;

        // Request headers (first few)
        for (key, value) in ex.request_headers.iter().take(3) {
            buf.push_str(ansi::DIM);
            buf.push_str(&format!("    {}: ", key));
            buf.push_str(ansi::RESET);
            buf.push_str(&truncate(value, 60));
            buf.push_str(ansi::CLEAR_LINE);
            buf.push('\n');
            lines_used += 1;
        }

        // Separator
        buf.push('\n');
        lines_used += 1;

        // Response info
        if let Some(code) = ex.status_code {
            let status_color = match code {
                c if c >= 500 => ansi::RED,
                c if c >= 400 => ansi::YELLOW,
                c if c >= 300 => ansi::CYAN,
                _ => ansi::GREEN,
            };
            buf.push_str(ansi::BOLD);
            buf.push_str(status_color);
            buf.push_str(&format!(
                "  Response: {} {} ({})",
                code,
                ex.status_text.as_deref().unwrap_or(""),
                ex.duration_display()
            ));
            buf.push_str(ansi::CLEAR_LINE);
            buf.push_str(ansi::RESET);
            buf.push('\n');
            lines_used += 1;

            // Response headers (first few)
            for (key, value) in ex.response_headers.iter().take(3) {
                buf.push_str(ansi::DIM);
                buf.push_str(&format!("    {}: ", key));
                buf.push_str(ansi::RESET);
                buf.push_str(&truncate(value, 60));
                buf.push_str(ansi::CLEAR_LINE);
                buf.push('\n');
                lines_used += 1;
            }
        } else {
            buf.push_str(ansi::DIM);
            buf.push_str("  Response: pending...");
            buf.push_str(ansi::CLEAR_LINE);
            buf.push_str(ansi::RESET);
            buf.push('\n');
            lines_used += 1;
        }

        // Fill remaining
        for _ in lines_used..self.detail_height as usize {
            buf.push_str(ansi::CLEAR_LINE);
            buf.push('\n');
        }
    }

    fn render_body(&self, buf: &mut String, ex: &HttpExchange) {
        let mut lines_used = 0;

        // Request body
        buf.push_str(ansi::BOLD);
        buf.push_str(ansi::CYAN);
        buf.push_str(&format!(
            "  Request Body ({} bytes):",
            ex.request_body.len()
        ));
        buf.push_str(ansi::CLEAR_LINE);
        buf.push_str(ansi::RESET);
        buf.push('\n');
        lines_used += 1;

        if !ex.request_body.is_empty() {
            let body_str = String::from_utf8_lossy(&ex.request_body);
            for line in body_str.lines().take(3) {
                buf.push_str("    ");
                buf.push_str(&truncate(line, self.size.cols as usize - 6));
                buf.push_str(ansi::CLEAR_LINE);
                buf.push('\n');
                lines_used += 1;
            }
        } else {
            buf.push_str(ansi::DIM);
            buf.push_str("    (empty)");
            buf.push_str(ansi::CLEAR_LINE);
            buf.push_str(ansi::RESET);
            buf.push('\n');
            lines_used += 1;
        }

        buf.push('\n');
        lines_used += 1;

        // Response body
        buf.push_str(ansi::BOLD);
        buf.push_str(ansi::CYAN);
        buf.push_str(&format!(
            "  Response Body ({} bytes):",
            ex.response_body.len()
        ));
        buf.push_str(ansi::CLEAR_LINE);
        buf.push_str(ansi::RESET);
        buf.push('\n');
        lines_used += 1;

        if !ex.response_body.is_empty() {
            let body_str = String::from_utf8_lossy(&ex.response_body);
            let max_lines = (self.detail_height as usize).saturating_sub(lines_used + 1);
            for line in body_str.lines().take(max_lines) {
                buf.push_str("    ");
                buf.push_str(&truncate(line, self.size.cols as usize - 6));
                buf.push_str(ansi::CLEAR_LINE);
                buf.push('\n');
                lines_used += 1;
            }
        } else {
            buf.push_str(ansi::DIM);
            buf.push_str("    (empty)");
            buf.push_str(ansi::CLEAR_LINE);
            buf.push_str(ansi::RESET);
            buf.push('\n');
            lines_used += 1;
        }

        // Fill remaining
        for _ in lines_used..self.detail_height as usize {
            buf.push_str(ansi::CLEAR_LINE);
            buf.push('\n');
        }
    }

    fn render_raw(&self, buf: &mut String, ex: &HttpExchange) {
        let raw = ex.request_raw();
        let mut lines_used = 0;

        for line in raw.lines().take(self.detail_height as usize - 1) {
            buf.push_str("  ");
            buf.push_str(&truncate(line, self.size.cols as usize - 4));
            buf.push_str(ansi::CLEAR_LINE);
            buf.push('\n');
            lines_used += 1;
        }

        // Fill remaining
        for _ in lines_used..self.detail_height as usize {
            buf.push_str(ansi::CLEAR_LINE);
            buf.push('\n');
        }
    }

    fn render_footer(&self, buf: &mut String, state: &ShellState) {
        buf.push_str(ansi::BG_DARK_GRAY);
        buf.push_str(ansi::WHITE);

        let help = match state.view_mode {
            ShellViewMode::Command => {
                format!(":{}{}", state.command_buffer, ansi::SHOW_CURSOR)
            }
            ShellViewMode::Search => {
                format!("/{}{}", state.search_buffer, ansi::SHOW_CURSOR)
            }
            _ => {
                format!(
                    " [i]ntercept [e]dit [r]eplay [f]ilter [/]search [Tab]tabs [q]uit {}",
                    ansi::HIDE_CURSOR
                )
            }
        };

        let padded = format!("{:<width$}", help, width = self.size.cols as usize);
        buf.push_str(&padded[..(self.size.cols as usize).min(padded.len())]);
        buf.push_str(ansi::RESET);
    }
}

impl Default for ShellUI {
    fn default() -> Self {
        Self::new().unwrap_or(Self {
            size: TermSize { rows: 24, cols: 80 },
            list_height: 12,
            detail_height: 8,
        })
    }
}

/// Truncate a string to max length with ellipsis
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max > 3 {
        format!("{}...", &s[..max - 3])
    } else {
        s[..max].to_string()
    }
}
