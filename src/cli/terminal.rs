// Terminal utilities for interactive shell (readline-like)
// ZERO external dependencies - pure Rust + libc only
//
// Features:
// - Raw mode handling
// - Arrow key detection (history, cursor movement)
// - Line editing (backspace, delete, home, end)
// - Command history with persistence
// - Tab completion hooks
// - Scroll buffer for output

use std::collections::VecDeque;
use std::io::{self, Read, Write};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

// ============================================================================
// ANSI Escape Codes
// ============================================================================

pub mod ansi {
    // Cursor control
    pub const HIDE_CURSOR: &str = "\x1b[?25l";
    pub const SHOW_CURSOR: &str = "\x1b[?25h";
    pub const SAVE_CURSOR: &str = "\x1b[s";
    pub const RESTORE_CURSOR: &str = "\x1b[u";

    // Screen control
    pub const CLEAR_SCREEN: &str = "\x1b[2J";
    pub const CLEAR_LINE: &str = "\x1b[2K";
    pub const CLEAR_TO_END: &str = "\x1b[K";
    pub const MOVE_HOME: &str = "\x1b[H";
    pub const ALTERNATE_SCREEN: &str = "\x1b[?1049h";
    pub const MAIN_SCREEN: &str = "\x1b[?1049l";

    // Colors
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const ITALIC: &str = "\x1b[3m";
    pub const UNDERLINE: &str = "\x1b[4m";

    // Foreground colors
    pub const BLACK: &str = "\x1b[30m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    pub const GRAY: &str = "\x1b[90m";

    // Bright colors
    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_BLUE: &str = "\x1b[94m";
    pub const BRIGHT_MAGENTA: &str = "\x1b[95m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";

    // Background colors
    pub const BG_BLACK: &str = "\x1b[40m";
    pub const BG_RED: &str = "\x1b[41m";
    pub const BG_GREEN: &str = "\x1b[42m";
    pub const BG_YELLOW: &str = "\x1b[43m";
    pub const BG_BLUE: &str = "\x1b[44m";
    pub const BG_MAGENTA: &str = "\x1b[45m";
    pub const BG_CYAN: &str = "\x1b[46m";
    pub const BG_WHITE: &str = "\x1b[47m";

    // 256-color mode
    pub fn fg_256(code: u8) -> String {
        format!("\x1b[38;5;{}m", code)
    }

    pub fn bg_256(code: u8) -> String {
        format!("\x1b[48;5;{}m", code)
    }

    // TrueColor (24-bit)
    pub fn fg_rgb(r: u8, g: u8, b: u8) -> String {
        format!("\x1b[38;2;{};{};{}m", r, g, b)
    }

    pub fn bg_rgb(r: u8, g: u8, b: u8) -> String {
        format!("\x1b[48;2;{};{};{}m", r, g, b)
    }

    // Cursor movement
    pub fn move_to(row: u16, col: u16) -> String {
        format!("\x1b[{};{}H", row, col)
    }

    pub fn move_up(n: u16) -> String {
        format!("\x1b[{}A", n)
    }

    pub fn move_down(n: u16) -> String {
        format!("\x1b[{}B", n)
    }

    pub fn move_right(n: u16) -> String {
        format!("\x1b[{}C", n)
    }

    pub fn move_left(n: u16) -> String {
        format!("\x1b[{}D", n)
    }

    pub fn move_to_col(col: u16) -> String {
        format!("\x1b[{}G", col)
    }

    // Mouse support
    pub const ENABLE_MOUSE: &str = "\x1b[?1000h\x1b[?1006h"; // Basic + SGR extended
    pub const DISABLE_MOUSE: &str = "\x1b[?1000l\x1b[?1006l";
}

// ============================================================================
// Box Drawing Characters
// ============================================================================

pub mod box_chars {
    // Single line
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

    // Double line
    pub const DOUBLE_HORIZONTAL: char = '═';
    pub const DOUBLE_VERTICAL: char = '║';
    pub const DOUBLE_TOP_LEFT: char = '╔';
    pub const DOUBLE_TOP_RIGHT: char = '╗';
    pub const DOUBLE_BOTTOM_LEFT: char = '╚';
    pub const DOUBLE_BOTTOM_RIGHT: char = '╝';

    // Rounded corners
    pub const ROUND_TOP_LEFT: char = '╭';
    pub const ROUND_TOP_RIGHT: char = '╮';
    pub const ROUND_BOTTOM_LEFT: char = '╰';
    pub const ROUND_BOTTOM_RIGHT: char = '╯';

    // Block elements
    pub const FULL_BLOCK: char = '█';
    pub const LIGHT_SHADE: char = '░';
    pub const MEDIUM_SHADE: char = '▒';
    pub const DARK_SHADE: char = '▓';

    // Sparkline characters (8 levels)
    pub const SPARK: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    /// Draw a horizontal line
    pub fn hline(width: usize) -> String {
        HORIZONTAL.to_string().repeat(width)
    }

    /// Draw a box with title
    pub fn titled_box(title: &str, width: usize) -> (String, String, String) {
        let title_len = title.chars().count();
        let padding = width.saturating_sub(title_len + 4);
        let left_pad = padding / 2;
        let right_pad = padding - left_pad;

        let top = format!(
            "{}{}{}{}{}",
            TOP_LEFT,
            HORIZONTAL.to_string().repeat(left_pad + 1),
            title,
            HORIZONTAL.to_string().repeat(right_pad + 1),
            TOP_RIGHT
        );
        let bottom = format!(
            "{}{}{}",
            BOTTOM_LEFT,
            HORIZONTAL.to_string().repeat(width),
            BOTTOM_RIGHT
        );
        let side = format!("{}{}{}", VERTICAL, " ".repeat(width), VERTICAL);

        (top, side, bottom)
    }
}

// ============================================================================
// Terminal Raw Mode (Unix)
// ============================================================================

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
extern "C" {
    fn tcgetattr(fd: i32, termios_p: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, optional_actions: i32, termios_p: *const Termios) -> i32;
}

#[cfg(unix)]
const ICANON: u32 = 0x00000002;
#[cfg(unix)]
const ECHO: u32 = 0x00000008;
#[cfg(unix)]
const ISIG: u32 = 0x00000001;
#[cfg(unix)]
const TCSANOW: i32 = 0;

/// Raw terminal mode guard - restores on drop
pub struct RawMode {
    #[cfg(unix)]
    original: Termios,
    #[cfg(unix)]
    fd: i32,
}

impl RawMode {
    /// Enable raw mode (no echo, no line buffering, no signals)
    pub fn enable() -> io::Result<Self> {
        #[cfg(unix)]
        {
            let fd = io::stdin().as_raw_fd();
            let mut termios: Termios = unsafe { std::mem::zeroed() };

            if unsafe { tcgetattr(fd, &mut termios) } != 0 {
                return Err(io::Error::last_os_error());
            }

            let original = termios;

            // Disable canonical mode, echo, and signal generation
            termios.c_lflag &= !(ICANON | ECHO | ISIG);

            if unsafe { tcsetattr(fd, TCSANOW, &termios) } != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self { original, fd })
        }

        #[cfg(not(unix))]
        Ok(Self {})
    }

    /// Restore original terminal mode
    fn restore(&self) {
        #[cfg(unix)]
        unsafe {
            tcsetattr(self.fd, TCSANOW, &self.original);
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        self.restore();
    }
}

// ============================================================================
// Key Events
// ============================================================================

/// Keyboard/mouse event
#[derive(Debug, Clone, PartialEq)]
pub enum Key {
    Char(char),
    Enter,
    Tab,
    Backspace,
    Delete,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    F(u8), // F1-F12
    CtrlC,
    CtrlD,
    CtrlL,
    CtrlU,
    CtrlW,
    CtrlA,
    CtrlE,
    CtrlK,
    CtrlR, // Reverse search
    MouseScroll { up: bool },
    Unknown(Vec<u8>),
}

/// Read a single key event (blocking)
pub fn read_key() -> io::Result<Key> {
    let mut buf = [0u8; 1];
    io::stdin().read_exact(&mut buf)?;

    match buf[0] {
        // Control characters
        0 => Ok(Key::CtrlC), // Ctrl+@ or Ctrl+Space
        1 => Ok(Key::CtrlA),
        3 => Ok(Key::CtrlC),
        4 => Ok(Key::CtrlD),
        5 => Ok(Key::CtrlE),
        11 => Ok(Key::CtrlK),
        12 => Ok(Key::CtrlL),
        18 => Ok(Key::CtrlR),
        21 => Ok(Key::CtrlU),
        23 => Ok(Key::CtrlW),
        9 => Ok(Key::Tab),
        10 | 13 => Ok(Key::Enter),
        27 => read_escape_sequence(),
        127 => Ok(Key::Backspace),
        // Printable ASCII
        c if c >= 32 && c < 127 => Ok(Key::Char(c as char)),
        // UTF-8 multi-byte
        c if c >= 0xC0 => read_utf8_char(c),
        _ => Ok(Key::Unknown(buf.to_vec())),
    }
}

/// Read escape sequence (arrow keys, function keys, etc.)
fn read_escape_sequence() -> io::Result<Key> {
    let mut buf = [0u8; 1];

    // Try to read next byte with timeout
    // For simplicity, we'll just try to read immediately
    if io::stdin().read(&mut buf)? == 0 {
        return Ok(Key::Escape);
    }

    match buf[0] {
        b'[' => {
            // CSI sequence
            let mut seq = Vec::new();
            loop {
                if io::stdin().read(&mut buf)? == 0 {
                    break;
                }
                seq.push(buf[0]);
                // CSI sequences end with a letter or ~
                if buf[0].is_ascii_alphabetic() || buf[0] == b'~' || buf[0] == b'M' {
                    break;
                }
                // SGR mouse sequences end with m or M
                if buf[0] == b'm' || buf[0] == b'M' {
                    break;
                }
            }

            parse_csi_sequence(&seq)
        }
        b'O' => {
            // SS3 sequence (F1-F4, etc.)
            if io::stdin().read(&mut buf)? == 0 {
                return Ok(Key::Escape);
            }
            match buf[0] {
                b'P' => Ok(Key::F(1)),
                b'Q' => Ok(Key::F(2)),
                b'R' => Ok(Key::F(3)),
                b'S' => Ok(Key::F(4)),
                b'H' => Ok(Key::Home),
                b'F' => Ok(Key::End),
                _ => Ok(Key::Unknown(vec![27, b'O', buf[0]])),
            }
        }
        _ => Ok(Key::Unknown(vec![27, buf[0]])),
    }
}

/// Parse CSI sequence
fn parse_csi_sequence(seq: &[u8]) -> io::Result<Key> {
    if seq.is_empty() {
        return Ok(Key::Unknown(vec![27, b'[']));
    }

    // Check for mouse event (SGR extended format: \x1b[<...m or \x1b[<...M)
    if seq.len() > 1 && seq[0] == b'<' {
        return parse_sgr_mouse(seq);
    }

    let last = *seq.last().unwrap();

    match last {
        b'A' => Ok(Key::Up),
        b'B' => Ok(Key::Down),
        b'C' => Ok(Key::Right),
        b'D' => Ok(Key::Left),
        b'H' => Ok(Key::Home),
        b'F' => Ok(Key::End),
        b'~' => {
            // Parse number before ~
            let num_str: String = seq
                .iter()
                .take(seq.len() - 1)
                .filter(|b| b.is_ascii_digit())
                .map(|b| *b as char)
                .collect();
            let num: u8 = num_str.parse().unwrap_or(0);
            match num {
                1 => Ok(Key::Home),
                2 => Ok(Key::Insert),
                3 => Ok(Key::Delete),
                4 => Ok(Key::End),
                5 => Ok(Key::PageUp),
                6 => Ok(Key::PageDown),
                15 => Ok(Key::F(5)),
                17 => Ok(Key::F(6)),
                18 => Ok(Key::F(7)),
                19 => Ok(Key::F(8)),
                20 => Ok(Key::F(9)),
                21 => Ok(Key::F(10)),
                23 => Ok(Key::F(11)),
                24 => Ok(Key::F(12)),
                _ => Ok(Key::Unknown([&[27u8, b'['], seq].concat())),
            }
        }
        _ => Ok(Key::Unknown([&[27u8, b'['], seq].concat())),
    }
}

/// Parse SGR mouse event
fn parse_sgr_mouse(seq: &[u8]) -> io::Result<Key> {
    // Format: <button;x;yM or <button;x;ym
    // Button 64 = scroll up, 65 = scroll down
    let parts: Vec<&[u8]> = seq[1..seq.len() - 1].split(|b| *b == b';').collect();

    if parts.is_empty() {
        return Ok(Key::Unknown(seq.to_vec()));
    }

    let button_str: String = parts[0].iter().map(|b| *b as char).collect();
    let button: u8 = button_str.parse().unwrap_or(0);

    match button {
        64 => Ok(Key::MouseScroll { up: true }),
        65 => Ok(Key::MouseScroll { up: false }),
        _ => Ok(Key::Unknown(seq.to_vec())),
    }
}

/// Read UTF-8 multi-byte character
fn read_utf8_char(first: u8) -> io::Result<Key> {
    let mut bytes = vec![first];
    let len = if first & 0xE0 == 0xC0 {
        2
    } else if first & 0xF0 == 0xE0 {
        3
    } else if first & 0xF8 == 0xF0 {
        4
    } else {
        return Ok(Key::Unknown(bytes));
    };

    for _ in 1..len {
        let mut buf = [0u8; 1];
        io::stdin().read_exact(&mut buf)?;
        bytes.push(buf[0]);
    }

    match String::from_utf8(bytes.clone()) {
        Ok(s) => {
            if let Some(c) = s.chars().next() {
                Ok(Key::Char(c))
            } else {
                Ok(Key::Unknown(bytes))
            }
        }
        Err(_) => Ok(Key::Unknown(bytes)),
    }
}

// ============================================================================
// Command History
// ============================================================================

/// Command history with navigation
pub struct History {
    entries: VecDeque<String>,
    max_size: usize,
    position: usize, // Current position when navigating
    search_term: Option<String>,
}

impl History {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_size,
            position: 0,
            search_term: None,
        }
    }

    /// Add entry to history
    pub fn push(&mut self, entry: String) {
        // Don't add empty or duplicate entries
        if entry.is_empty() {
            return;
        }
        if self.entries.front() == Some(&entry) {
            return;
        }

        self.entries.push_front(entry);
        if self.entries.len() > self.max_size {
            self.entries.pop_back();
        }
        self.reset_position();
    }

    /// Reset navigation position
    pub fn reset_position(&mut self) {
        self.position = 0;
        self.search_term = None;
    }

    /// Get previous entry (up arrow)
    pub fn prev(&mut self) -> Option<&str> {
        if self.position < self.entries.len() {
            let entry = self.entries.get(self.position)?;
            self.position += 1;
            Some(entry)
        } else {
            None
        }
    }

    /// Get next entry (down arrow)
    pub fn next(&mut self) -> Option<&str> {
        if self.position > 1 {
            self.position -= 1;
            self.entries.get(self.position - 1).map(|s| s.as_str())
        } else {
            self.position = 0;
            None
        }
    }

    /// Search history (Ctrl+R style)
    pub fn search(&self, term: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.contains(term))
            .map(|s| s.as_str())
    }

    /// Get all entries
    pub fn entries(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|s| s.as_str())
    }

    /// Load history from file
    pub fn load_from_file(path: &str, max_size: usize) -> Self {
        let mut history = Self::new(max_size);

        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().rev().take(max_size) {
                if !line.is_empty() {
                    history.entries.push_back(line.to_string());
                }
            }
        }

        history
    }

    /// Save history to file
    pub fn save_to_file(&self, path: &str) -> io::Result<()> {
        let content: String = self
            .entries
            .iter()
            .rev()
            .map(|s| format!("{}\n", s))
            .collect();
        std::fs::write(path, content)
    }
}

// ============================================================================
// Line Editor (readline-like)
// ============================================================================

/// Interactive line editor with history and completion
pub struct LineEditor {
    pub buffer: String,
    pub cursor: usize, // Cursor position in buffer (byte index)
    pub history: History,
    saved_buffer: String, // Buffer saved when navigating history
}

impl LineEditor {
    pub fn new(history_size: usize) -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
            history: History::new(history_size),
            saved_buffer: String::new(),
        }
    }

    /// Clear the current line
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
        self.history.reset_position();
    }

    /// Insert character at cursor
    pub fn insert(&mut self, c: char) {
        if self.cursor == self.buffer.len() {
            self.buffer.push(c);
        } else {
            self.buffer.insert(self.cursor, c);
        }
        self.cursor += c.len_utf8();
    }

    /// Insert string at cursor
    pub fn insert_str(&mut self, s: &str) {
        if self.cursor == self.buffer.len() {
            self.buffer.push_str(s);
        } else {
            self.buffer.insert_str(self.cursor, s);
        }
        self.cursor += s.len();
    }

    /// Delete character before cursor (backspace)
    pub fn backspace(&mut self) -> bool {
        if self.cursor > 0 {
            // Find the previous character boundary
            let prev = self.buffer[..self.cursor]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.buffer.remove(prev);
            self.cursor = prev;
            true
        } else {
            false
        }
    }

    /// Delete character at cursor (delete key)
    pub fn delete(&mut self) -> bool {
        if self.cursor < self.buffer.len() {
            self.buffer.remove(self.cursor);
            true
        } else {
            false
        }
    }

    /// Move cursor left
    pub fn move_left(&mut self) -> bool {
        if self.cursor > 0 {
            let prev = self.buffer[..self.cursor]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.cursor = prev;
            true
        } else {
            false
        }
    }

    /// Move cursor right
    pub fn move_right(&mut self) -> bool {
        if self.cursor < self.buffer.len() {
            let c = self.buffer[self.cursor..].chars().next().unwrap();
            self.cursor += c.len_utf8();
            true
        } else {
            false
        }
    }

    /// Move cursor to start (Home)
    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    /// Move cursor to end (End)
    pub fn move_end(&mut self) {
        self.cursor = self.buffer.len();
    }

    /// Delete word before cursor (Ctrl+W)
    pub fn delete_word(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }

        // Find word boundary
        let before = &self.buffer[..self.cursor];
        let trimmed = before.trim_end();
        let new_cursor = trimmed
            .rfind(|c: char| c.is_whitespace())
            .map(|i| i + 1)
            .unwrap_or(0);

        self.buffer.replace_range(new_cursor..self.cursor, "");
        self.cursor = new_cursor;
        true
    }

    /// Delete from cursor to end (Ctrl+K)
    pub fn delete_to_end(&mut self) -> bool {
        if self.cursor < self.buffer.len() {
            self.buffer.truncate(self.cursor);
            true
        } else {
            false
        }
    }

    /// Clear line (Ctrl+U)
    pub fn clear_line(&mut self) -> bool {
        if !self.buffer.is_empty() {
            self.buffer.clear();
            self.cursor = 0;
            true
        } else {
            false
        }
    }

    /// Navigate to previous history entry
    pub fn history_prev(&mut self) -> bool {
        // Save current buffer on first navigation
        if self.history.position == 0 && !self.buffer.is_empty() {
            self.saved_buffer = self.buffer.clone();
        }

        if let Some(entry) = self.history.prev() {
            self.buffer = entry.to_string();
            self.cursor = self.buffer.len();
            true
        } else {
            false
        }
    }

    /// Navigate to next history entry
    pub fn history_next(&mut self) -> bool {
        if let Some(entry) = self.history.next() {
            self.buffer = entry.to_string();
            self.cursor = self.buffer.len();
            true
        } else {
            // Restore saved buffer
            self.buffer = std::mem::take(&mut self.saved_buffer);
            self.cursor = self.buffer.len();
            true
        }
    }

    /// Accept current line and add to history
    pub fn accept(&mut self) -> String {
        let line = std::mem::take(&mut self.buffer);
        self.cursor = 0;
        self.history.push(line.clone());
        self.history.reset_position();
        self.saved_buffer.clear();
        line
    }

    /// Get cursor position in displayed characters (not bytes)
    pub fn display_cursor(&self) -> usize {
        self.buffer[..self.cursor].chars().count()
    }

    /// Get displayed width of buffer
    pub fn display_width(&self) -> usize {
        self.buffer.chars().count()
    }
}

// ============================================================================
// Scroll Buffer
// ============================================================================

/// Circular buffer for terminal output with scrolling support
pub struct ScrollBuffer {
    lines: VecDeque<String>,
    max_lines: usize,
    scroll_offset: usize, // 0 = bottom (most recent)
}

impl ScrollBuffer {
    pub fn new(max_lines: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            max_lines,
            scroll_offset: 0,
        }
    }

    /// Add line to buffer
    pub fn push(&mut self, line: String) {
        self.lines.push_back(line);
        if self.lines.len() > self.max_lines {
            self.lines.pop_front();
        }
        // Reset scroll when new content arrives
        if self.scroll_offset > 0 {
            self.scroll_offset = 0;
        }
    }

    /// Add multiple lines
    pub fn push_str(&mut self, content: &str) {
        for line in content.lines() {
            self.push(line.to_string());
        }
    }

    /// Scroll up by n lines
    pub fn scroll_up(&mut self, n: usize) -> bool {
        let max_scroll = self.lines.len().saturating_sub(1);
        let new_offset = (self.scroll_offset + n).min(max_scroll);
        if new_offset != self.scroll_offset {
            self.scroll_offset = new_offset;
            true
        } else {
            false
        }
    }

    /// Scroll down by n lines
    pub fn scroll_down(&mut self, n: usize) -> bool {
        if self.scroll_offset > 0 {
            self.scroll_offset = self.scroll_offset.saturating_sub(n);
            true
        } else {
            false
        }
    }

    /// Page up
    pub fn page_up(&mut self, page_size: usize) -> bool {
        self.scroll_up(page_size)
    }

    /// Page down
    pub fn page_down(&mut self, page_size: usize) -> bool {
        self.scroll_down(page_size)
    }

    /// Go to top
    pub fn scroll_to_top(&mut self) {
        self.scroll_offset = self.lines.len().saturating_sub(1);
    }

    /// Go to bottom
    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
    }

    /// Get visible lines for display
    pub fn visible_lines(&self, height: usize) -> impl Iterator<Item = &str> {
        let total = self.lines.len();
        let start = total.saturating_sub(height + self.scroll_offset);
        let end = total.saturating_sub(self.scroll_offset);

        self.lines.range(start..end).map(|s| s.as_str())
    }

    /// Check if scrolled (not at bottom)
    pub fn is_scrolled(&self) -> bool {
        self.scroll_offset > 0
    }

    /// Get scroll indicator text
    pub fn scroll_indicator(&self) -> String {
        if self.is_scrolled() {
            format!("[↑{} more]", self.scroll_offset)
        } else {
            String::new()
        }
    }

    /// Total lines in buffer
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Clear buffer
    pub fn clear(&mut self) {
        self.lines.clear();
        self.scroll_offset = 0;
    }
}

// ============================================================================
// Terminal Size
// ============================================================================

/// Get terminal size
#[cfg(unix)]
pub fn terminal_size() -> Option<(u16, u16)> {
    use std::os::unix::io::AsRawFd;

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

    let fd = io::stdout().as_raw_fd();
    let mut size = WinSize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    unsafe {
        if ioctl(fd, TIOCGWINSZ, &mut size as *mut _) == 0 {
            Some((size.ws_col, size.ws_row))
        } else {
            None
        }
    }
}

#[cfg(not(unix))]
pub fn terminal_size() -> Option<(u16, u16)> {
    Some((80, 24))
}

// ============================================================================
// Sparkline Rendering
// ============================================================================

/// Render a sparkline from values
pub fn sparkline(values: &[f64], width: usize) -> String {
    if values.is_empty() || width == 0 {
        return String::new();
    }

    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = max - min;

    // Sample values to fit width
    let step = values.len() as f64 / width as f64;
    let mut result = String::with_capacity(width * 4); // UTF-8 chars can be up to 4 bytes

    for i in 0..width {
        let idx = (i as f64 * step) as usize;
        let val = values.get(idx).copied().unwrap_or(min);

        let level = if range > 0.0 {
            ((val - min) / range * 7.0).round() as usize
        } else {
            4 // Middle level if all values are the same
        };

        result.push(box_chars::SPARK[level.min(7)]);
    }

    result
}

// ============================================================================
// Password Input (Hidden)
// ============================================================================

/// Read password from terminal without echoing characters
/// Shows asterisks (*) for each character typed
pub fn read_password(prompt: &str) -> io::Result<String> {
    let mut stdout = io::stdout();

    // Print prompt
    write!(stdout, "{}", prompt)?;
    stdout.flush()?;

    // Enable raw mode to suppress echo
    let _raw = RawMode::enable()?;

    let mut password = String::new();

    loop {
        let key = read_key()?;
        match key {
            Key::Enter => {
                writeln!(stdout)?;
                break;
            }
            Key::Backspace => {
                if !password.is_empty() {
                    password.pop();
                    // Erase the asterisk
                    write!(stdout, "\x08 \x08")?;
                    stdout.flush()?;
                }
            }
            Key::Char(c) => {
                password.push(c);
                // Show asterisk
                write!(stdout, "*")?;
                stdout.flush()?;
            }
            Key::CtrlC | Key::CtrlD => {
                writeln!(stdout)?;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "User cancelled"));
            }
            Key::CtrlU => {
                // Clear entire password
                for _ in 0..password.len() {
                    write!(stdout, "\x08 \x08")?;
                }
                password.clear();
                stdout.flush()?;
            }
            _ => {}
        }
    }

    Ok(password)
}

/// Read password with confirmation (asks twice)
/// Returns Ok(password) if both entries match, Err otherwise
pub fn read_password_with_confirm(prompt: &str) -> io::Result<String> {
    let password = read_password(prompt)?;

    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password cannot be empty",
        ));
    }

    let confirm = read_password("Confirm password: ")?;

    if password != confirm {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passwords do not match",
        ));
    }

    Ok(password)
}

/// Interactive yes/no prompt
/// Returns true for yes, false for no
pub fn confirm(prompt: &str, default: bool) -> io::Result<bool> {
    let mut stdout = io::stdout();
    let suffix = if default { " [Y/n]: " } else { " [y/N]: " };

    write!(stdout, "{}{}", prompt, suffix)?;
    stdout.flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let input = input.trim().to_lowercase();

    if input.is_empty() {
        return Ok(default);
    }

    match input.as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Ok(default),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_editor_insert() {
        let mut editor = LineEditor::new(100);
        editor.insert('h');
        editor.insert('i');
        assert_eq!(editor.buffer, "hi");
        assert_eq!(editor.cursor, 2);
    }

    #[test]
    fn test_line_editor_backspace() {
        let mut editor = LineEditor::new(100);
        editor.insert_str("hello");
        editor.backspace();
        assert_eq!(editor.buffer, "hell");
    }

    #[test]
    fn test_line_editor_cursor_movement() {
        let mut editor = LineEditor::new(100);
        editor.insert_str("hello");
        editor.move_home();
        assert_eq!(editor.cursor, 0);
        editor.move_end();
        assert_eq!(editor.cursor, 5);
        editor.move_left();
        assert_eq!(editor.cursor, 4);
    }

    #[test]
    fn test_history() {
        let mut history = History::new(10);
        history.push("first".to_string());
        history.push("second".to_string());

        assert_eq!(history.prev(), Some("second"));
        assert_eq!(history.prev(), Some("first"));
        assert_eq!(history.next(), Some("second"));
    }

    #[test]
    fn test_scroll_buffer() {
        let mut buffer = ScrollBuffer::new(100);
        buffer.push("line 1".to_string());
        buffer.push("line 2".to_string());
        buffer.push("line 3".to_string());

        assert_eq!(buffer.len(), 3);
        assert!(!buffer.is_scrolled());

        buffer.scroll_up(1);
        assert!(buffer.is_scrolled());
        assert_eq!(buffer.scroll_offset, 1);
    }

    #[test]
    fn test_sparkline() {
        let values = vec![0.0, 25.0, 50.0, 75.0, 100.0];
        let result = sparkline(&values, 5);
        assert_eq!(result.chars().count(), 5);
    }

    #[test]
    fn test_box_chars_hline() {
        let line = box_chars::hline(5);
        assert_eq!(line, "─────");
    }
}
