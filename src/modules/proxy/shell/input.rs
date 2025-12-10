//! Keyboard input handling for the MITM shell

use std::io::{self, Read};

/// Input key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Enter,
    Backspace,
    Delete,
    Tab,
    Esc,
    F(u8), // F1-F12
    Unknown(u8),
}

/// Terminal raw mode handler
#[cfg(unix)]
pub struct RawMode {
    original: libc::termios,
}

#[cfg(unix)]
impl RawMode {
    /// Enter raw mode
    pub fn enable() -> io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let fd = io::stdin().as_raw_fd();

        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut original) != 0 {
                return Err(io::Error::last_os_error());
            }

            let mut raw = original;
            // Disable canonical mode and echo
            raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
            // Disable input processing
            raw.c_iflag &= !(libc::IXON | libc::ICRNL);
            // Set minimum bytes and timeout for read
            raw.c_cc[libc::VMIN] = 0;
            raw.c_cc[libc::VTIME] = 1; // 100ms timeout

            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self { original })
        }
    }
}

#[cfg(unix)]
impl Drop for RawMode {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        let fd = io::stdin().as_raw_fd();
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(not(unix))]
pub struct RawMode;

#[cfg(not(unix))]
impl RawMode {
    pub fn enable() -> io::Result<Self> {
        Ok(Self)
    }
}

/// Input reader
pub struct InputReader {
    stdin: io::Stdin,
    buf: [u8; 8],
}

impl InputReader {
    pub fn new() -> Self {
        Self {
            stdin: io::stdin(),
            buf: [0u8; 8],
        }
    }

    /// Read a key (non-blocking)
    pub fn read_key(&mut self) -> io::Result<Option<Key>> {
        let n = {
            let mut handle = self.stdin.lock();
            handle.read(&mut self.buf)?
        };

        if n == 0 {
            return Ok(None);
        }

        Ok(Some(self.parse_key(n)))
    }

    fn parse_key(&self, n: usize) -> Key {
        match n {
            1 => self.parse_single_byte(self.buf[0]),
            2 => self.parse_two_bytes(),
            3.. => self.parse_escape_sequence(n),
            _ => Key::Unknown(0),
        }
    }

    fn parse_single_byte(&self, byte: u8) -> Key {
        match byte {
            0x1b => Key::Esc,
            0x0d | 0x0a => Key::Enter,
            0x7f | 0x08 => Key::Backspace,
            0x09 => Key::Tab,
            0x01..=0x1a => Key::Char((byte + 0x60) as char), // Ctrl+A to Ctrl+Z
            c => Key::Char(c as char),
        }
    }

    fn parse_two_bytes(&self) -> Key {
        if self.buf[0] == 0x1b {
            // Alt+key
            Key::Char(self.buf[1] as char)
        } else {
            Key::Unknown(self.buf[0])
        }
    }

    fn parse_escape_sequence(&self, n: usize) -> Key {
        if self.buf[0] != 0x1b {
            return Key::Unknown(self.buf[0]);
        }

        match &self.buf[1..n] {
            [b'[', b'A'] => Key::Up,
            [b'[', b'B'] => Key::Down,
            [b'[', b'C'] => Key::Right,
            [b'[', b'D'] => Key::Left,
            [b'[', b'H'] => Key::Home,
            [b'[', b'F'] => Key::End,
            [b'[', b'5', b'~'] => Key::PageUp,
            [b'[', b'6', b'~'] => Key::PageDown,
            [b'[', b'3', b'~'] => Key::Delete,
            // Function keys
            [b'O', b'P'] => Key::F(1),
            [b'O', b'Q'] => Key::F(2),
            [b'O', b'R'] => Key::F(3),
            [b'O', b'S'] => Key::F(4),
            [b'[', b'1', b'5', b'~'] => Key::F(5),
            [b'[', b'1', b'7', b'~'] => Key::F(6),
            [b'[', b'1', b'8', b'~'] => Key::F(7),
            [b'[', b'1', b'9', b'~'] => Key::F(8),
            [b'[', b'2', b'0', b'~'] => Key::F(9),
            [b'[', b'2', b'1', b'~'] => Key::F(10),
            [b'[', b'2', b'3', b'~'] => Key::F(11),
            [b'[', b'2', b'4', b'~'] => Key::F(12),
            _ => Key::Unknown(self.buf[1]),
        }
    }
}

impl Default for InputReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Input action (higher-level commands)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Move selection up
    SelectPrev,
    /// Move selection down
    SelectNext,
    /// Page up
    PageUp,
    /// Page down
    PageDown,
    /// Go to first item
    GoFirst,
    /// Go to last item
    GoLast,
    /// Toggle details view
    ToggleDetails,
    /// Toggle intercept mode
    ToggleIntercept,
    /// Start editing selected request
    EditRequest,
    /// Replay selected request
    ReplayRequest,
    /// Forward intercepted request
    ForwardRequest,
    /// Drop intercepted request
    DropRequest,
    /// Next detail tab
    NextTab,
    /// Previous detail tab
    PrevTab,
    /// Enter command mode
    EnterCommand,
    /// Enter search mode
    EnterSearch,
    /// Clear history
    ClearHistory,
    /// Show help
    ShowHelp,
    /// Quit
    Quit,
    /// Key input for text entry
    TextInput(char),
    /// Backspace in text mode
    TextBackspace,
    /// Submit text (Enter in command/search mode)
    TextSubmit,
    /// Cancel text entry
    TextCancel,
    /// No action
    None,
}

/// Map a key to an action based on current mode
pub fn key_to_action(key: Key, in_text_mode: bool) -> Action {
    if in_text_mode {
        match key {
            Key::Enter => Action::TextSubmit,
            Key::Esc => Action::TextCancel,
            Key::Backspace => Action::TextBackspace,
            Key::Char(c) => Action::TextInput(c),
            _ => Action::None,
        }
    } else {
        match key {
            Key::Char('q') | Key::Char('Q') => Action::Quit,
            Key::Char('j') | Key::Down => Action::SelectNext,
            Key::Char('k') | Key::Up => Action::SelectPrev,
            Key::PageDown | Key::Char('d') => Action::PageDown,
            Key::PageUp | Key::Char('u') => Action::PageUp,
            Key::Home | Key::Char('g') => Action::GoFirst,
            Key::End | Key::Char('G') => Action::GoLast,
            Key::Enter => Action::ToggleDetails,
            Key::Char('i') => Action::ToggleIntercept,
            Key::Char('e') => Action::EditRequest,
            Key::Char('r') => Action::ReplayRequest,
            Key::Char('f') => Action::ForwardRequest,
            Key::Char('D') => Action::DropRequest,
            Key::Tab => Action::NextTab,
            Key::Char(':') => Action::EnterCommand,
            Key::Char('/') => Action::EnterSearch,
            Key::Char('c') => Action::ClearHistory,
            Key::Char('?') => Action::ShowHelp,
            Key::Esc => Action::TextCancel,
            _ => Action::None,
        }
    }
}
